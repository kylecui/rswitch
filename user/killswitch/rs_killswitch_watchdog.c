// SPDX-License-Identifier: LGPL-2.1-or-later

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>

#include "rswitch_killswitch.h"

static volatile sig_atomic_t g_running = 1;

static void signal_handler(int signo)
{
	(void)signo;
	g_running = 0;
}

static void log_msg(const char *level, const char *fmt, ...)
{
	struct timespec ts;
	struct tm *tm_info;
	char time_buf[32];
	va_list ap;

	if (clock_gettime(CLOCK_REALTIME, &ts) == 0) {
		tm_info = localtime(&ts.tv_sec);
		strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);
		fprintf(stderr, "[%s.%03ld] [%s] ", time_buf, ts.tv_nsec / 1000000, level);
	} else {
		fprintf(stderr, "[%s] ", level);
	}

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
	fflush(stderr);
}

static int hex_to_bytes(const char *hex, uint8_t *bytes, size_t max_len)
{
	size_t len = 0;

	if (!hex || !bytes)
		return -EINVAL;

	while (*hex && len < max_len) {
		unsigned int val;
		int ret;

		ret = sscanf(hex, "%2x", &val);
		if (ret != 1)
			return -EINVAL;

		bytes[len++] = (uint8_t)val;
		hex += 2;
	}

	return (int)len;
}

static int read_keys_from_file(const char *path, uint8_t *stop_key, uint8_t *reboot_key)
{
	FILE *f;
	char line[128];
	int ret = 0;

	if (!path || !stop_key || !reboot_key)
		return -EINVAL;

	f = fopen(path, "r");
	if (!f) {
		log_msg("ERROR", "failed to open key file: %s", path);
		return -errno;
	}

	if (!fgets(line, sizeof(line), f)) {
		log_msg("ERROR", "failed to read first key line from %s", path);
		fclose(f);
		return -EIO;
	}

	line[strcspn(line, "\n")] = '\0';
	if (hex_to_bytes(line, stop_key, RS_KILLSWITCH_KEY_LEN) != RS_KILLSWITCH_KEY_LEN) {
		log_msg("ERROR", "invalid stop key format (expected 64 hex chars)");
		fclose(f);
		return -EINVAL;
	}

	if (!fgets(line, sizeof(line), f)) {
		log_msg("ERROR", "failed to read second key line from %s", path);
		fclose(f);
		return -EIO;
	}

	line[strcspn(line, "\n")] = '\0';
	if (hex_to_bytes(line, reboot_key, RS_KILLSWITCH_KEY_LEN) != RS_KILLSWITCH_KEY_LEN) {
		log_msg("ERROR", "invalid reboot key format (expected 64 hex chars)");
		fclose(f);
		return -EINVAL;
	}

	fclose(f);
	return 0;
}

static int open_pinned_map(const char *pin_path)
{
	int fd;

	if (!pin_path)
		return -EINVAL;

	fd = bpf_obj_get(pin_path);
	if (fd < 0) {
		log_msg("ERROR", "failed to open pinned map %s: %s", pin_path, strerror(errno));
		return -errno;
	}

	return fd;
}

static int write_config(int cfg_map_fd, uint16_t port, const uint8_t *stop_key,
		const uint8_t *reboot_key)
{
	struct rs_killswitch_cfg cfg;
	uint32_t key = 0;
	int ret;

	if (cfg_map_fd < 0 || !stop_key || !reboot_key)
		return -EINVAL;

	memset(&cfg, 0, sizeof(cfg));
	cfg.udp_port = htons(port);
	memcpy(cfg.stop_key, stop_key, RS_KILLSWITCH_KEY_LEN);
	memcpy(cfg.reboot_key, reboot_key, RS_KILLSWITCH_KEY_LEN);
	cfg.enabled = 1;

	ret = bpf_map_update_elem(cfg_map_fd, &key, &cfg, 0);
	if (ret != 0) {
		log_msg("ERROR", "failed to write killswitch config: %s", strerror(errno));
		return -errno;
	}

	log_msg("INFO", "killswitch config written (port=%u)", port);
	return 0;
}

static int execute_command(const char *cmd)
{
	int ret;

	if (!cmd)
		return -EINVAL;

	log_msg("INFO", "executing: %s", cmd);
	ret = system(cmd);
	if (ret == -1) {
		log_msg("ERROR", "failed to execute command: %s", strerror(errno));
		return -errno;
	}

	if (WIFEXITED(ret) && WEXITSTATUS(ret) != 0) {
		log_msg("WARN", "command exited with status %d", WEXITSTATUS(ret));
		return -ECHILD;
	}

	return 0;
}

static int handle_action(int action_map_fd, uint32_t action, bool dry_run)
{
	uint32_t key = 0;
	uint32_t zero = RS_KILLSWITCH_ACTION_NONE;
	int ret;

	if (action_map_fd < 0)
		return -EINVAL;

	if (action == RS_KILLSWITCH_ACTION_STOP) {
		log_msg("WARN", "STOP action triggered");
		if (!dry_run) {
			execute_command("systemctl stop rswitch");
			execute_command("/opt/rswitch/scripts/rswitch-failsafe.sh setup");
		}
	} else if (action == RS_KILLSWITCH_ACTION_REBOOT) {
		log_msg("WARN", "REBOOT action triggered");
		if (!dry_run) {
			execute_command("systemctl reboot");
		}
	}

	/* Always reset the map to prevent re-triggering */
	ret = bpf_map_update_elem(action_map_fd, &key, &zero, 0);
	if (ret != 0) {
		log_msg("ERROR", "failed to reset action: %s", strerror(errno));
		return -errno;
	}

	return 0;
}

static void usage(const char *prog)
{
	printf("Usage: %s [options]\n", prog);
	printf("  --key-file PATH    Path to killswitch keys file (default: %s)\n",
		RS_KILLSWITCH_KEY_PATH);
	printf("  --port NUM         UDP port for killswitch (default: %u)\n",
		RS_KILLSWITCH_PORT_DEFAULT);
	printf("  --poll-ms NUM      Poll interval in milliseconds (default: 500)\n");
	printf("  --dry-run          Don't execute actions, just log them\n");
	printf("  -h, --help         Show this help\n");
}

int main(int argc, char **argv)
{
	const char *key_file = RS_KILLSWITCH_KEY_PATH;
	uint16_t port = RS_KILLSWITCH_PORT_DEFAULT;
	uint32_t poll_ms = 500;
	bool dry_run = false;
	uint8_t stop_key[RS_KILLSWITCH_KEY_LEN];
	uint8_t reboot_key[RS_KILLSWITCH_KEY_LEN];
	int cfg_map_fd = -1;
	int state_map_fd = -1;
	uint32_t key = 0;
	struct rs_killswitch_state state;
	struct timespec ts;
	int ret;
	int opt;

	struct option long_opts[] = {
		{"key-file", required_argument, NULL, 'k'},
		{"port", required_argument, NULL, 'p'},
		{"poll-ms", required_argument, NULL, 'P'},
		{"dry-run", no_argument, NULL, 'd'},
		{"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0},
	};

	while ((opt = getopt_long(argc, argv, "k:p:P:dh", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'k':
			key_file = optarg;
			break;
		case 'p':
			port = (uint16_t)strtoul(optarg, NULL, 10);
			if (port == 0)
				port = RS_KILLSWITCH_PORT_DEFAULT;
			break;
		case 'P':
			poll_ms = (uint32_t)strtoul(optarg, NULL, 10);
			if (poll_ms == 0)
				poll_ms = 500;
			break;
		case 'd':
			dry_run = true;
			break;
		case 'h':
		default:
			usage(argv[0]);
			return opt == 'h' ? 0 : 1;
		}
	}

	log_msg("INFO", "killswitch watchdog starting (key_file=%s, port=%u, poll_ms=%u, dry_run=%d)",
		key_file, port, poll_ms, dry_run);

	ret = read_keys_from_file(key_file, stop_key, reboot_key);
	if (ret != 0) {
		log_msg("ERROR", "failed to read keys");
		return 1;
	}

	cfg_map_fd = open_pinned_map(RS_KILLSWITCH_CFG_MAP_PIN);
	if (cfg_map_fd < 0) {
		log_msg("ERROR", "failed to open config map");
		return 1;
	}

	state_map_fd = open_pinned_map(RS_KILLSWITCH_MAP_PIN);
	if (state_map_fd < 0) {
		log_msg("ERROR", "failed to open state map");
		close(cfg_map_fd);
		return 1;
	}

	ret = write_config(cfg_map_fd, port, stop_key, reboot_key);
	if (ret != 0) {
		log_msg("ERROR", "failed to configure killswitch");
		close(cfg_map_fd);
		close(state_map_fd);
		return 1;
	}

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	log_msg("INFO", "watchdog ready, polling state map");

	while (g_running) {
		ret = bpf_map_lookup_elem(state_map_fd, &key, &state);
		if (ret != 0) {
			log_msg("ERROR", "failed to read state map: %s", strerror(errno));
			usleep(poll_ms * 1000);
			continue;
		}

		if (state.action != RS_KILLSWITCH_ACTION_NONE) {
			log_msg("WARN", "action detected: action=%u, ifindex=%u, count=%u",
				state.action, state.trigger_ifindex, state.trigger_count);
			handle_action(state_map_fd, state.action, dry_run);
		}

		ts.tv_sec = poll_ms / 1000;
		ts.tv_nsec = (poll_ms % 1000) * 1000000;
		nanosleep(&ts, NULL);
	}

	log_msg("INFO", "watchdog shutting down");
	close(cfg_map_fd);
	close(state_map_fd);
	return 0;
}
