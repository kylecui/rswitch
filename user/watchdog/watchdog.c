// SPDX-License-Identifier: GPL-2.0

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#if __has_include("rs_log.h")
#include "rs_log.h"
#else
#include "../common/rs_log.h"
#endif

#include "watchdog.h"

#define RS_BPF_PIN_BASE "/sys/fs/bpf"
#define RS_WATCHDOG_DEFAULT_INTERVAL_SEC 10
#define RS_WATCHDOG_MAX_IFINDEX 256
#define RS_WATCHDOG_MAX_MODULES 64

struct rs_stats_entry {
	uint64_t rx_packets;
	uint64_t rx_bytes;
	uint64_t tx_packets;
	uint64_t tx_bytes;
	uint64_t rx_drops;
	uint64_t tx_drops;
	uint64_t rx_errors;
	uint64_t tx_errors;
};

struct rs_module_stats_entry {
	uint64_t packets_processed;
	uint64_t packets_forwarded;
	uint64_t packets_dropped;
	uint64_t packets_error;
	uint64_t bytes_processed;
	uint64_t last_seen_ns;
	uint32_t module_id;
	char name[32];
};

struct rs_counter_snapshot {
	bool valid;
	uint64_t sample_ns;
	uint64_t per_if_packets[RS_WATCHDOG_MAX_IFINDEX];
};

static uint64_t g_watchdog_start_ns;
static uint32_t g_check_interval_sec = RS_WATCHDOG_DEFAULT_INTERVAL_SEC;
static struct rs_counter_snapshot g_counter_snapshot;

static uint64_t monotonic_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;

	return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
}

static void status_add_detail(struct rs_health_status *status, const char *fmt, ...)
{
	va_list ap;

	if (!status || status->detail_count >= 16)
		return;

	va_start(ap, fmt);
	vsnprintf(status->details[status->detail_count], sizeof(status->details[status->detail_count]), fmt, ap);
	va_end(ap);
	status->detail_count++;
}

static int file_exists(const char *path)
{
	struct stat st;

	if (!path)
		return 0;

	return stat(path, &st) == 0;
}

static int open_map_fd(const char *name)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/%s", RS_BPF_PIN_BASE, name);
	return bpf_obj_get(path);
}

static int read_process_name(pid_t pid, char *buf, size_t size)
{
	char path[PATH_MAX];
	int fd;
	ssize_t n;

	if (!buf || size == 0)
		return -EINVAL;

	snprintf(path, sizeof(path), "/proc/%d/comm", pid);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;

	n = read(fd, buf, size - 1);
	close(fd);
	if (n <= 0)
		return -EIO;

	buf[n] = '\0';
	for (ssize_t i = 0; i < n; i++) {
		if (buf[i] == '\n') {
			buf[i] = '\0';
			break;
		}
	}

	return 0;
}

static int find_process_by_name(const char *name)
{
	DIR *proc;
	struct dirent *ent;
	char comm[128];

	if (!name || !name[0])
		return 0;

	proc = opendir("/proc");
	if (!proc)
		return 0;

	while ((ent = readdir(proc)) != NULL) {
		pid_t pid;
		char *end = NULL;

		if (!isdigit((unsigned char)ent->d_name[0]))
			continue;

		pid = (pid_t)strtol(ent->d_name, &end, 10);
		if (!end || *end != '\0' || pid <= 0)
			continue;

		if (read_process_name(pid, comm, sizeof(comm)) != 0)
			continue;

		if (strcmp(comm, name) == 0) {
			closedir(proc);
			return 1;
		}
	}

	closedir(proc);
	return 0;
}

static int aggregate_stats_entry(int map_fd, uint32_t ifindex, struct rs_stats_entry *out)
{
	int ncpus;
	struct rs_stats_entry *cpu_values;

	if (!out)
		return -EINVAL;

	ncpus = libbpf_num_possible_cpus();
	if (ncpus <= 0)
		return -EINVAL;

	cpu_values = calloc((size_t)ncpus, sizeof(*cpu_values));
	if (!cpu_values)
		return -ENOMEM;

	if (bpf_map_lookup_elem(map_fd, &ifindex, cpu_values) != 0) {
		free(cpu_values);
		return -errno;
	}

	memset(out, 0, sizeof(*out));
	for (int i = 0; i < ncpus; i++) {
		out->rx_packets += cpu_values[i].rx_packets;
		out->rx_bytes += cpu_values[i].rx_bytes;
		out->tx_packets += cpu_values[i].tx_packets;
		out->tx_bytes += cpu_values[i].tx_bytes;
		out->rx_drops += cpu_values[i].rx_drops;
		out->tx_drops += cpu_values[i].tx_drops;
		out->rx_errors += cpu_values[i].rx_errors;
		out->tx_errors += cpu_values[i].tx_errors;
	}

	free(cpu_values);
	return 0;
}

static int aggregate_module_stats_entry(int map_fd, uint32_t key, struct rs_module_stats_entry *out)
{
	int ncpus;
	struct rs_module_stats_entry *cpu_values;

	if (!out)
		return -EINVAL;

	ncpus = libbpf_num_possible_cpus();
	if (ncpus <= 0)
		return -EINVAL;

	cpu_values = calloc((size_t)ncpus, sizeof(*cpu_values));
	if (!cpu_values)
		return -ENOMEM;

	if (bpf_map_lookup_elem(map_fd, &key, cpu_values) != 0) {
		free(cpu_values);
		return -errno;
	}

	memset(out, 0, sizeof(*out));
	for (int i = 0; i < ncpus; i++) {
		out->packets_processed += cpu_values[i].packets_processed;
		out->packets_forwarded += cpu_values[i].packets_forwarded;
		out->packets_dropped += cpu_values[i].packets_dropped;
		out->packets_error += cpu_values[i].packets_error;
		out->bytes_processed += cpu_values[i].bytes_processed;
		if (cpu_values[i].last_seen_ns > out->last_seen_ns)
			out->last_seen_ns = cpu_values[i].last_seen_ns;
		if (out->name[0] == '\0' && cpu_values[i].name[0] != '\0')
			memcpy(out->name, cpu_values[i].name, sizeof(out->name));
		if (cpu_values[i].module_id != 0)
			out->module_id = cpu_values[i].module_id;
	}

	free(cpu_values);
	return 0;
}

static void check_pinned_programs(struct rs_health_status *status)
{
	static const char *core_programs[] = {
		"dispatcher.bpf.o",
		"egress.bpf.o",
	};
	char path[PATH_MAX];
	int ok = 1;
	int module_map_fd;

	for (size_t i = 0; i < sizeof(core_programs) / sizeof(core_programs[0]); i++) {
		snprintf(path, sizeof(path), "%s/%s", RS_BPF_PIN_BASE, core_programs[i]);
		if (!file_exists(path)) {
			ok = 0;
			status_add_detail(status, "missing pinned prog: %s", core_programs[i]);
		}
	}

	module_map_fd = open_map_fd("rs_module_stats_map");
	if (module_map_fd >= 0) {
		for (uint32_t i = 0; i < RS_WATCHDOG_MAX_MODULES; i++) {
			struct rs_module_stats_entry stats;

			if (aggregate_module_stats_entry(module_map_fd, i, &stats) != 0)
				continue;
			if (!stats.name[0])
				continue;

			snprintf(path, sizeof(path), "%s/%s.bpf.o", RS_BPF_PIN_BASE, stats.name);
			if (!file_exists(path)) {
				ok = 0;
				status_add_detail(status, "module pin missing: %s", stats.name);
			}
		}
		close(module_map_fd);
	}

	status->bpf_programs_ok = ok;
}

static void check_maps_accessible(struct rs_health_status *status)
{
	static const char *maps[] = {
		"rs_stats_map",
		"rs_module_stats_map",
		"voqd_state_map",
		"rs_port_config_map",
		"prog_array",
	};
	int ok = 1;

	for (size_t i = 0; i < sizeof(maps) / sizeof(maps[0]); i++) {
		int fd = open_map_fd(maps[i]);

		if (fd < 0) {
			ok = 0;
			status_add_detail(status, "map unreadable: %s (%s)", maps[i], strerror(errno));
			continue;
		}
		close(fd);
	}

	status->maps_accessible = ok;
}

static void check_voqd_process(struct rs_health_status *status)
{
	status->voqd_running = find_process_by_name("rswitch-voqd");
	if (!status->voqd_running)
		status_add_detail(status, "process not running: rswitch-voqd");
}

static void check_counter_progress(struct rs_health_status *status)
{
	int map_fd;
	struct rs_counter_snapshot current = {0};
	int any_counter = 0;
	int incrementing = 0;

	map_fd = open_map_fd("rs_stats_map");
	if (map_fd < 0) {
		status->counters_incrementing = 0;
		status_add_detail(status, "counter check skipped: rs_stats_map unavailable");
		return;
	}

	for (uint32_t ifindex = 0; ifindex < RS_WATCHDOG_MAX_IFINDEX; ifindex++) {
		struct rs_stats_entry agg;
		uint64_t total;

		if (aggregate_stats_entry(map_fd, ifindex, &agg) != 0)
			continue;

		total = agg.rx_packets + agg.tx_packets;
		current.per_if_packets[ifindex] = total;
		if (total > 0)
			any_counter = 1;

		if (g_counter_snapshot.valid && total > g_counter_snapshot.per_if_packets[ifindex])
			incrementing = 1;
	}

	close(map_fd);
	current.sample_ns = monotonic_ns();
	current.valid = true;

	if (!g_counter_snapshot.valid) {
		status->counters_incrementing = 1;
		status_add_detail(status, "counter baseline captured");
	} else if (!any_counter) {
		status->counters_incrementing = 0;
		status_add_detail(status, "all packet counters are zero");
	} else if (incrementing) {
		status->counters_incrementing = 1;
	} else {
		status->counters_incrementing = 0;
		status_add_detail(status, "packet counters stalled since last check");
	}

	g_counter_snapshot = current;
}

static void check_module_staleness(struct rs_health_status *status)
{
	int fd;
	uint64_t now_ns = monotonic_ns();
	uint64_t stale_after_ns = (uint64_t)(g_check_interval_sec * 3) * 1000000000ULL;
	int stale_modules = 0;

	if (stale_after_ns < 30000000000ULL)
		stale_after_ns = 30000000000ULL;

	fd = open_map_fd("rs_module_stats_map");
	if (fd < 0)
		return;

	for (uint32_t i = 0; i < RS_WATCHDOG_MAX_MODULES; i++) {
		struct rs_module_stats_entry stats;

		if (aggregate_module_stats_entry(fd, i, &stats) != 0)
			continue;
		if (!stats.name[0] || stats.last_seen_ns == 0)
			continue;

		if (now_ns > stats.last_seen_ns && (now_ns - stats.last_seen_ns) > stale_after_ns) {
			stale_modules++;
			status_add_detail(status, "stale module: %s", stats.name);
		}
	}

	if (stale_modules > 0)
		status->counters_incrementing = 0;

	close(fd);
}

static int watchdog_spawn_and_wait(char *const argv[])
{
	pid_t pid;
	int status;

	pid = fork();
	if (pid < 0)
		return -errno;

	if (pid == 0) {
		execvp(argv[0], argv);
		_exit(127);
	}

	if (waitpid(pid, &status, 0) < 0)
		return -errno;

	if (WIFEXITED(status))
		return WEXITSTATUS(status);

	return -ECHILD;
}

static int watchdog_spawn_detached(char *const argv[])
{
	pid_t pid;

	pid = fork();
	if (pid < 0)
		return -errno;

	if (pid == 0) {
		setsid();
		execvp(argv[0], argv);
		_exit(127);
	}

	return 0;
}

static int recover_bpf_stack(void)
{
	const char *ifaces = getenv("RSWITCH_WATCHDOG_IFACES");
	const char *mode = getenv("RSWITCH_WATCHDOG_MODE");
	char *argv_loader[8] = {0};
	int rc;

	if (!ifaces || !ifaces[0]) {
		RS_LOG_WARN("recovery skipped: RSWITCH_WATCHDOG_IFACES not set");
		return -EINVAL;
	}

	if (!mode || !mode[0])
		mode = "dumb";

	if (!file_exists("./build/bpf/dispatcher.bpf.o") || !file_exists("./build/bpf/egress.bpf.o")) {
		RS_LOG_ERROR("recovery failed: build/bpf core objects missing");
		return -ENOENT;
	}

	argv_loader[0] = "./build/rswitch_loader";
	argv_loader[1] = "-i";
	argv_loader[2] = (char *)ifaces;
	argv_loader[3] = "-m";
	argv_loader[4] = (char *)mode;
	argv_loader[5] = "-v";
	argv_loader[6] = NULL;

	RS_LOG_WARN("attempting BPF recovery with rswitch_loader (ifaces=%s, mode=%s)", ifaces, mode);
	rc = watchdog_spawn_and_wait(argv_loader);
	if (rc == 127) {
		argv_loader[0] = "rswitch_loader";
		rc = watchdog_spawn_and_wait(argv_loader);
	}

	if (rc != 0)
		RS_LOG_ERROR("BPF recovery failed with code %d", rc);
	else
		RS_LOG_INFO("BPF recovery completed successfully");

	return rc;
}

static int recover_voqd(void)
{
	char *argv_voqd[] = {"./build/rswitch-voqd", NULL};
	int rc;

	RS_LOG_WARN("attempting to restart rswitch-voqd");
	rc = watchdog_spawn_detached(argv_voqd);
	if (rc == 0)
		return 0;

	argv_voqd[0] = "rswitch-voqd";
	rc = watchdog_spawn_detached(argv_voqd);
	if (rc == 0)
		RS_LOG_INFO("rswitch-voqd restart requested");
	else
		RS_LOG_ERROR("failed to restart rswitch-voqd: %s", strerror(-rc));

	return rc;
}

static void perform_recovery(const struct rs_health_status *status)
{
	if (!status)
		return;

	if (!status->bpf_programs_ok)
		recover_bpf_stack();

	if (!status->voqd_running)
		recover_voqd();

	if (!status->maps_accessible)
		RS_LOG_ERROR("map accessibility failure requires manual intervention");
}

static void clear_status(struct rs_health_status *status)
{
	if (!status)
		return;

	memset(status, 0, sizeof(*status));
	status->overall = 2;
}

int rs_watchdog_check_health(struct rs_health_status *status)
{
	if (!status)
		return -EINVAL;

	clear_status(status);
	if (g_watchdog_start_ns == 0)
		g_watchdog_start_ns = monotonic_ns();

	status->last_check_ns = monotonic_ns();
	if (status->last_check_ns >= g_watchdog_start_ns)
		status->uptime_sec = (status->last_check_ns - g_watchdog_start_ns) / 1000000000ULL;

	status->bpf_programs_ok = 1;
	status->maps_accessible = 1;
	status->voqd_running = 1;
	status->counters_incrementing = 1;

	check_pinned_programs(status);
	check_maps_accessible(status);
	check_voqd_process(status);
	check_counter_progress(status);
	check_module_staleness(status);

	if (!status->bpf_programs_ok || !status->maps_accessible)
		status->overall = 2;
	else if (!status->voqd_running || !status->counters_incrementing)
		status->overall = 1;
	else
		status->overall = 0;

	return 0;
}

static int json_append(char *buf, size_t size, size_t *off, const char *fmt, ...)
{
	va_list ap;
	int n;

	if (!buf || !off || *off >= size)
		return -ENOSPC;

	va_start(ap, fmt);
	n = vsnprintf(buf + *off, size - *off, fmt, ap);
	va_end(ap);

	if (n < 0)
		return -EINVAL;

	if ((size_t)n >= size - *off) {
		*off = size;
		return -ENOSPC;
	}

	*off += (size_t)n;
	return 0;
}

int rs_watchdog_export_json(const struct rs_health_status *status, char *buf, size_t size)
{
	size_t off = 0;

	if (!status || !buf || size == 0)
		return -EINVAL;

	if (json_append(buf, size, &off,
		"{\"overall\":%d,\"bpf_programs_ok\":%d,\"maps_accessible\":%d,"
		"\"voqd_running\":%d,\"counters_incrementing\":%d,\"uptime_sec\":%llu,"
		"\"last_check_ns\":%llu,\"details\":[",
		status->overall,
		status->bpf_programs_ok,
		status->maps_accessible,
		status->voqd_running,
		status->counters_incrementing,
		(unsigned long long)status->uptime_sec,
		(unsigned long long)status->last_check_ns) != 0)
		return -ENOSPC;

	for (int i = 0; i < status->detail_count; i++) {
		if (json_append(buf, size, &off, "%s\"", i == 0 ? "" : ",") != 0)
			return -ENOSPC;

		for (size_t j = 0; j < sizeof(status->details[i]) && status->details[i][j]; j++) {
			char ch = status->details[i][j];

			if (ch == '"' || ch == '\\') {
				if (json_append(buf, size, &off, "\\%c", ch) != 0)
					return -ENOSPC;
			} else if ((unsigned char)ch < 0x20) {
				if (json_append(buf, size, &off, "\\u%04x", (unsigned char)ch) != 0)
					return -ENOSPC;
			} else {
				if (json_append(buf, size, &off, "%c", ch) != 0)
					return -ENOSPC;
			}
		}

		if (json_append(buf, size, &off, "\"") != 0)
			return -ENOSPC;
	}

	if (json_append(buf, size, &off, "]}") != 0)
		return -ENOSPC;

	return 0;
}

static int sd_notify_send(const char *msg)
{
	const char *notify_socket = getenv("NOTIFY_SOCKET");
	struct sockaddr_un addr;
	int fd;
	socklen_t addr_len;

	if (!notify_socket || !notify_socket[0] || !msg)
		return -EINVAL;

	if (strlen(notify_socket) >= sizeof(addr.sun_path))
		return -ENAMETOOLONG;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;

	if (notify_socket[0] == '@') {
		addr.sun_path[0] = '\0';
		strncpy(addr.sun_path + 1, notify_socket + 1, sizeof(addr.sun_path) - 2);
		addr_len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + strlen(notify_socket + 1));
	} else {
		strncpy(addr.sun_path, notify_socket, sizeof(addr.sun_path) - 1);
		addr_len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + strlen(addr.sun_path));
	}

	fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;

	if (sendto(fd, msg, strlen(msg), 0, (struct sockaddr *)&addr, addr_len) < 0) {
		int ret = -errno;
		close(fd);
		return ret;
	}

	close(fd);
	return 0;
}

#ifdef RSWITCH_WATCHDOG_STANDALONE

static volatile sig_atomic_t g_running = 1;

static void watchdog_signal_handler(int signo)
{
	(void)signo;
	g_running = 0;
}

static void watchdog_usage(const char *prog)
{
	printf("Usage: %s [-i INTERVAL] [-r] [-h]\n", prog);
	printf("  -i INTERVAL  Health check interval in seconds (default: 10)\n");
	printf("  -r           Enable auto-recovery for failed components\n");
	printf("  -h           Show this help\n");
}

static void log_health(const struct rs_health_status *status)
{
	const char *label;

	if (!status)
		return;

	if (status->overall == 0)
		label = "healthy";
	else if (status->overall == 1)
		label = "degraded";
	else
		label = "critical";

	if (status->overall == 0) {
		RS_LOG_INFO("health=%s bpf=%d maps=%d voqd=%d counters=%d uptime=%llus",
			label,
			status->bpf_programs_ok,
			status->maps_accessible,
			status->voqd_running,
			status->counters_incrementing,
			(unsigned long long)status->uptime_sec);
	} else if (status->overall == 1) {
		RS_LOG_WARN("health=%s bpf=%d maps=%d voqd=%d counters=%d uptime=%llus",
			label,
			status->bpf_programs_ok,
			status->maps_accessible,
			status->voqd_running,
			status->counters_incrementing,
			(unsigned long long)status->uptime_sec);
	} else {
		RS_LOG_ERROR("health=%s bpf=%d maps=%d voqd=%d counters=%d uptime=%llus",
			label,
			status->bpf_programs_ok,
			status->maps_accessible,
			status->voqd_running,
			status->counters_incrementing,
			(unsigned long long)status->uptime_sec);
	}

	for (int i = 0; i < status->detail_count; i++) {
		if (status->overall == 2)
			RS_LOG_ERROR("detail: %s", status->details[i]);
		else if (status->overall == 1)
			RS_LOG_WARN("detail: %s", status->details[i]);
		else
			RS_LOG_INFO("detail: %s", status->details[i]);
	}
}

int main(int argc, char **argv)
{
	int recovery_enabled = 0;
	uint64_t watchdog_usecs = 0;
	uint64_t last_watchdog_ping_ns = 0;
	int opt;
	struct rs_health_status status;

	while ((opt = getopt(argc, argv, "i:rh")) != -1) {
		switch (opt) {
		case 'i':
			g_check_interval_sec = (uint32_t)strtoul(optarg, NULL, 10);
			if (g_check_interval_sec == 0)
				g_check_interval_sec = RS_WATCHDOG_DEFAULT_INTERVAL_SEC;
			break;
		case 'r':
			recovery_enabled = 1;
			break;
		case 'h':
		default:
			watchdog_usage(argv[0]);
			return opt == 'h' ? 0 : 1;
		}
	}

	rs_log_init("rswitch-watchdog", RS_LOG_LEVEL_INFO);
	g_watchdog_start_ns = monotonic_ns();

	signal(SIGINT, watchdog_signal_handler);
	signal(SIGTERM, watchdog_signal_handler);

	if (getenv("WATCHDOG_USEC"))
		watchdog_usecs = strtoull(getenv("WATCHDOG_USEC"), NULL, 10);

	if (sd_notify_send("READY=1") == 0)
		RS_LOG_INFO("systemd READY=1 notified");

	RS_LOG_INFO("watchdog started (interval=%us, recovery=%s)",
		g_check_interval_sec,
		recovery_enabled ? "enabled" : "disabled");

	while (g_running) {
		if (rs_watchdog_check_health(&status) != 0) {
			RS_LOG_ERROR("health check failed");
		} else {
			log_health(&status);
			if (recovery_enabled && status.overall != 0)
				perform_recovery(&status);
		}

		if (watchdog_usecs > 0) {
			uint64_t now_ns = monotonic_ns();
			uint64_t watchdog_ns = watchdog_usecs * 1000ULL;

			if (last_watchdog_ping_ns == 0 || (now_ns - last_watchdog_ping_ns) >= (watchdog_ns / 2)) {
				if (sd_notify_send("WATCHDOG=1") == 0)
					last_watchdog_ping_ns = now_ns;
			}
		}

		for (uint32_t i = 0; i < g_check_interval_sec && g_running; i++)
			sleep(1);
	}

	RS_LOG_INFO("watchdog stopped");
	return 0;
}

#endif
