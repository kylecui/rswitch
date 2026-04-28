// SPDX-License-Identifier: GPL-2.0

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <ctype.h>
#include <limits.h>
#include <dirent.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#if __has_include("rs_log.h")
#include "rs_log.h"
#else
#include "../common/rs_log.h"
#endif

#include "../../bpf/core/module_abi.h"

#define BPF_PIN_PATH "/sys/fs/bpf"
#define DEV_MAX_CAPTURE_PKTS 64
#define DEV_MAX_PKT_SIZE 2048
#define RS_EVENT_L2_BASE 0x0100
#define RS_EVENT_ACL_BASE 0x0200
#define RS_EVENT_ROUTE_BASE 0x0300
#define RS_EVENT_MIRROR_BASE 0x0400
#define RS_EVENT_QOS_BASE 0x0500
#define RS_EVENT_ERROR_BASE 0xFF00

#define RS_MODULE_CONFIG_KEY_LEN 32

struct rs_module_stats {
	__u64 packets_processed;
	__u64 packets_forwarded;
	__u64 packets_dropped;
	__u64 packets_error;
	__u64 bytes_processed;
	__u64 last_seen_ns;
	__u32 module_id;
	char name[32];
};

struct rs_module_config_key {
	char module_name[RS_MODULE_CONFIG_KEY_LEN];
	char param_name[RS_MODULE_CONFIG_KEY_LEN];
};

struct rs_module_config_value {
	__u32 type;
	union {
		__s64 int_val;
		__u32 bool_val;
		char str_val[56];
	};
};

int cmd_dev_watch(const char *module_name);
int cmd_dev_trace(const char *module_name);
int cmd_dev_inspect(const char *module_name);
int cmd_dev_benchmark(const char *profile_path);
int cmd_dev_verify(const char *obj_path);
int cmd_dev_debug(const char *obj_path, const char *pcap_path);

static volatile sig_atomic_t g_dev_stop;

struct test_xdp_md {
	__u32 data;
	__u32 data_meta;
	__u32 data_end;
	__u32 ingress_ifindex;
	__u32 rx_queue_index;
	__u32 egress_ifindex;
};

struct dev_trace_ctx {
	const char *module_name;
	unsigned long long seen;
};

struct dev_event_header {
	__u32 event_type;
	__u64 timestamp_ns;
	char module_name[32];
};

struct module_total_stats {
	char name[32];
	__u64 packets_processed;
	__u64 packets_forwarded;
	__u64 packets_dropped;
	__u64 packets_error;
	__u64 bytes_processed;
	__u64 last_seen_ns;
	__u32 module_id;
};

struct packet_buf {
	__u8 data[DEV_MAX_PKT_SIZE];
	__u32 len;
	char label[32];
};

static char g_verify_log[65536];
static size_t g_verify_log_len;

static void dev_signal_handler(int signo)
{
	(void)signo;
	g_dev_stop = 1;
}

static const char *prog_type_str(enum bpf_prog_type type)
{
	switch (type) {
	case BPF_PROG_TYPE_XDP:
		return "XDP";
	case BPF_PROG_TYPE_SCHED_CLS:
		return "SCHED_CLS";
	default:
		return "OTHER";
	}
}

static int shell_quote(const char *src, char *dst, size_t dst_sz)
{
	size_t d = 0;

	if (!src || !dst || dst_sz < 3)
		return -1;

	dst[d++] = '\'';
	for (size_t i = 0; src[i] != '\0'; i++) {
		if (src[i] == '\'') {
			if (d + 4 >= dst_sz)
				return -1;
			dst[d++] = '\'';
			dst[d++] = '\\';
			dst[d++] = '\'';
			dst[d++] = '\'';
		} else {
			if (d + 1 >= dst_sz)
				return -1;
			dst[d++] = src[i];
		}
	}

	if (d + 2 > dst_sz)
		return -1;

	dst[d++] = '\'';
	dst[d] = '\0';
	return 0;
}

static int run_stream_command(const char *cmd)
{
	char buf[512];
	int rc;
	FILE *fp = popen(cmd, "r");

	if (!fp) {
		fprintf(stderr, "Failed to run command '%s': %s\n", cmd, strerror(errno));
		return 1;
	}

	while (fgets(buf, sizeof(buf), fp) != NULL)
		fputs(buf, stdout);

	rc = pclose(fp);
	if (rc < 0)
		return 1;
	if (WIFEXITED(rc))
		return WEXITSTATUS(rc);
	return 1;
}

static int module_name_matches(const char *expected, const char *prog_name)
{
	size_t n;

	if (!expected || !prog_name)
		return 0;
	if (strcmp(expected, prog_name) == 0)
		return 1;

	n = strlen(expected);
	if (strncmp(expected, prog_name, n) == 0 && (prog_name[n] == '_' || prog_name[n] == '\0'))
		return 1;

	return 0;
}

static const char *module_from_event_type(__u32 event_type)
{
	switch (event_type & 0xFF00) {
	case RS_EVENT_L2_BASE:
		return "l2learn";
	case RS_EVENT_ACL_BASE:
		return "acl";
	case RS_EVENT_ROUTE_BASE:
		return "route";
	case RS_EVENT_MIRROR_BASE:
		return "mirror";
	case RS_EVENT_QOS_BASE:
		return "qos";
	case RS_EVENT_ERROR_BASE:
		return "core";
	default:
		return "unknown";
	}
}

static void format_wallclock(char *buf, size_t sz)
{
	time_t now = time(NULL);
	struct tm tmv;

	if (!buf || sz == 0)
		return;

	localtime_r(&now, &tmv);
	strftime(buf, sz, "%Y-%m-%d %H:%M:%S", &tmv);
}

static int trace_ringbuf_cb(void *ctx, void *data, size_t size)
{
	char ts[64];
	const char *module = NULL;
	const struct dev_event_header *hdr = data;
	struct dev_trace_ctx *tctx = ctx;
	__u32 event_type;

	if (size < sizeof(__u32))
		return 0;

	event_type = *(__u32 *)data;

	if (size >= sizeof(*hdr) && hdr->module_name[0] != '\0') {
		int printable = 1;
		for (size_t i = 0; i < sizeof(hdr->module_name); i++) {
			unsigned char c = (unsigned char)hdr->module_name[i];
			if (c == '\0')
				break;
			if (!isprint(c)) {
				printable = 0;
				break;
			}
		}
		if (printable)
			module = hdr->module_name;
	}

	if (!module)
		module = module_from_event_type(event_type);

	if (tctx->module_name && strcmp(tctx->module_name, module) != 0)
		return 0;

	format_wallclock(ts, sizeof(ts));
	printf("[%s] module=%s event=0x%04x size=%zu\n", ts, module, event_type, size);
	tctx->seen++;
	return 0;
}

static int ncpus_possible(void)
{
	int n = libbpf_num_possible_cpus();
	return n > 0 ? n : 1;
}

static int read_module_stats_totals(int map_fd, struct module_total_stats *out, size_t max_out, size_t *out_count)
{
	int ncpus;

	if (!out || max_out == 0 || !out_count)
		return -EINVAL;

	ncpus = ncpus_possible();
	*out_count = 0;

	for (__u32 i = 0; i < 64 && *out_count < max_out; i++) {
		struct rs_module_stats total = {0};
		struct rs_module_stats *values;
		const char *name = NULL;

		values = calloc((size_t)ncpus, sizeof(*values));
		if (!values)
			return -ENOMEM;

		if (bpf_map_lookup_elem(map_fd, &i, values) < 0) {
			free(values);
			continue;
		}

		for (int c = 0; c < ncpus; c++) {
			total.packets_processed += values[c].packets_processed;
			total.packets_forwarded += values[c].packets_forwarded;
			total.packets_dropped += values[c].packets_dropped;
			total.packets_error += values[c].packets_error;
			total.bytes_processed += values[c].bytes_processed;
			if (values[c].last_seen_ns > total.last_seen_ns)
				total.last_seen_ns = values[c].last_seen_ns;
			if (!name && values[c].name[0] != '\0')
				name = values[c].name;
		}

		if (total.packets_processed == 0) {
			free(values);
			continue;
		}

		if (!name)
			name = "(unknown)";

		snprintf(out[*out_count].name, sizeof(out[*out_count].name), "%s", name);
		out[*out_count].packets_processed = total.packets_processed;
		out[*out_count].packets_forwarded = total.packets_forwarded;
		out[*out_count].packets_dropped = total.packets_dropped;
		out[*out_count].packets_error = total.packets_error;
		out[*out_count].bytes_processed = total.bytes_processed;
		out[*out_count].last_seen_ns = total.last_seen_ns;
		out[*out_count].module_id = i;
		(*out_count)++;
		free(values);
	}

	return 0;
}

static int find_module_prog_fd(const char *module_name, struct bpf_prog_info *out_info)
{
	DIR *dir;
	struct dirent *entry;
	char path[PATH_MAX];

	if (!module_name || !out_info)
		return -EINVAL;

	dir = opendir(BPF_PIN_PATH);
	if (!dir)
		return -errno;

	while ((entry = readdir(dir)) != NULL) {
		int fd;
		struct bpf_prog_info info = {};
		__u32 info_len = sizeof(info);

		if (entry->d_name[0] == '.')
			continue;

		snprintf(path, sizeof(path), "%s/%s", BPF_PIN_PATH, entry->d_name);
		fd = bpf_obj_get(path);
		if (fd < 0)
			continue;

		if (bpf_obj_get_info_by_fd(fd, &info, &info_len) == 0 &&
		    info.type == BPF_PROG_TYPE_XDP &&
		    module_name_matches(module_name, (const char *)info.name)) {
			*out_info = info;
			closedir(dir);
			return fd;
		}

		close(fd);
	}

	closedir(dir);
	return -ENOENT;
}

static int libbpf_log_capture(enum libbpf_print_level level, const char *fmt, va_list args)
{
	int n;

	if (level == LIBBPF_DEBUG)
		return 0;

	if (g_verify_log_len >= sizeof(g_verify_log) - 2)
		return 0;

	n = vsnprintf(g_verify_log + g_verify_log_len, sizeof(g_verify_log) - g_verify_log_len, fmt, args);
	if (n > 0) {
		size_t used = (size_t)n;
		if (used > sizeof(g_verify_log) - g_verify_log_len - 1)
			used = sizeof(g_verify_log) - g_verify_log_len - 1;
		g_verify_log_len += used;
	}

	return 0;
}

static int map_snapshot_json(FILE *out, struct bpf_object *obj)
{
	struct bpf_map *map;
	int first = 1;

	fprintf(out, "[");
	bpf_object__for_each_map(map, obj) {
		int fd = bpf_map__fd(map);
		struct bpf_map_info info = {};
		__u32 info_len = sizeof(info);

		if (fd < 0)
			continue;
		if (bpf_obj_get_info_by_fd(fd, &info, &info_len) < 0)
			continue;

		fprintf(out, "%s{\"name\":\"%s\",\"type\":%u,\"id\":%u,\"max_entries\":%u}",
			first ? "" : ",",
			bpf_map__name(map),
			info.type,
			info.id,
			info.max_entries);
		first = 0;
	}
	fprintf(out, "]");
	return 0;
}

static int read_rs_ctx_first_cpu(struct bpf_object *obj, struct rs_ctx *ctx)
{
	struct bpf_map *map;
	int fd;
	__u32 key = 0;
	int ncpus;
	struct rs_ctx *values;
	int ret;

	if (!ctx)
		return -EINVAL;

	map = bpf_object__find_map_by_name(obj, "rs_ctx_map");
	if (!map)
		return -ENOENT;

	fd = bpf_map__fd(map);
	if (fd < 0)
		return -EINVAL;

	ncpus = ncpus_possible();
	values = calloc((size_t)ncpus, sizeof(*values));
	if (!values)
		return -ENOMEM;

	ret = bpf_map_lookup_elem(fd, &key, values);
	if (ret == 0)
		*ctx = values[0];
	free(values);
	return ret;
}

static int append_generated_packets(struct packet_buf *pkts, size_t max_pkts)
{
	struct {
		__u8 dst[6];
		__u8 src[6];
		__be16 eth;
	} __attribute__((packed)) eth = {
		.dst = {0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee},
		.src = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55},
	};
	size_t count = 0;

	if (max_pkts < 4)
		return -EINVAL;

	eth.eth = htons(0x0800);
	memcpy(pkts[count].data, &eth, sizeof(eth));
	pkts[count].len = sizeof(eth) + 40;
	memset(pkts[count].data + sizeof(eth), 0, 40);
	pkts[count].data[14] = 0x45;
	pkts[count].data[23] = IPPROTO_TCP;
	pkts[count].data[34] = 0x12;
	pkts[count].data[35] = 0x34;
	pkts[count].data[47] = 0x02;
	snprintf(pkts[count].label, sizeof(pkts[count].label), "tcp_syn");
	count++;

	memcpy(pkts[count].data, &eth, sizeof(eth));
	pkts[count].len = sizeof(eth) + 28;
	memset(pkts[count].data + sizeof(eth), 0, 28);
	pkts[count].data[14] = 0x45;
	pkts[count].data[23] = IPPROTO_UDP;
	snprintf(pkts[count].label, sizeof(pkts[count].label), "udp");
	count++;

	memcpy(pkts[count].data, &eth, sizeof(eth));
	pkts[count].len = sizeof(eth) + 28;
	memset(pkts[count].data + sizeof(eth), 0, 28);
	pkts[count].data[14] = 0x45;
	pkts[count].data[23] = IPPROTO_ICMP;
	pkts[count].data[34] = 8;
	snprintf(pkts[count].label, sizeof(pkts[count].label), "icmp");
	count++;

	eth.eth = htons(0x0806);
	memcpy(pkts[count].data, &eth, sizeof(eth));
	pkts[count].len = sizeof(eth) + 28;
	memset(pkts[count].data + sizeof(eth), 0, 28);
	snprintf(pkts[count].label, sizeof(pkts[count].label), "arp");
	count++;

	return (int)count;
}

static int read_pcap_packets(const char *pcap_path, struct packet_buf *pkts, size_t max_pkts)
{
	struct pcap_file_hdr {
		__u32 magic;
		__u16 major;
		__u16 minor;
		__u32 thiszone;
		__u32 sigfigs;
		__u32 snaplen;
		__u32 network;
	} __attribute__((packed)) fh;
	struct pcap_pkt_hdr {
		__u32 ts_sec;
		__u32 ts_usec;
		__u32 incl_len;
		__u32 orig_len;
	} __attribute__((packed)) ph;
	FILE *f;
	size_t count = 0;
	int swap = 0;

	f = fopen(pcap_path, "rb");
	if (!f)
		return -errno;

	if (fread(&fh, sizeof(fh), 1, f) != 1) {
		fclose(f);
		return -EINVAL;
	}

	if (fh.magic == 0xd4c3b2a1)
		swap = 1;
	else if (fh.magic != 0xa1b2c3d4) {
		fclose(f);
		return -EINVAL;
	}

	while (!g_dev_stop && count < max_pkts && fread(&ph, sizeof(ph), 1, f) == 1) {
		__u32 incl_len = ph.incl_len;

		if (swap)
			incl_len = __builtin_bswap32(incl_len);

		if (incl_len == 0) {
			continue;
		} else if (incl_len > DEV_MAX_PKT_SIZE) {
			fseek(f, incl_len, SEEK_CUR);
			continue;
		}

		if (fread(pkts[count].data, incl_len, 1, f) != 1)
			break;

		pkts[count].len = incl_len;
		snprintf(pkts[count].label, sizeof(pkts[count].label), "pcap_%zu", count);
		count++;
	}

	fclose(f);
	return (int)count;
}

int cmd_dev_watch(const char *module_name)
{
	char src_path[PATH_MAX];
	char make_cmd[512];
	char reload_cmd[512];
	char q_module[128];
	int ifd = -1;
	int wd = -1;
	char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
	int ret = 1;

	if (!module_name || module_name[0] == '\0') {
		fprintf(stderr, "Usage: rswitchctl dev watch <module>\n");
		return 1;
	}

	snprintf(src_path, sizeof(src_path), "bpf/modules/%s.bpf.c", module_name);
	if (access(src_path, R_OK) != 0) {
		fprintf(stderr, "Module source not found: %s\n", src_path);
		return 1;
	}

	if (shell_quote(module_name, q_module, sizeof(q_module)) != 0) {
		fprintf(stderr, "Module name too long\n");
		return 1;
	}

	ifd = inotify_init1(0);
	if (ifd < 0) {
		fprintf(stderr, "inotify_init1 failed: %s\n", strerror(errno));
		return 1;
	}

	wd = inotify_add_watch(ifd, src_path, IN_MODIFY | IN_CLOSE_WRITE | IN_MOVED_TO);
	if (wd < 0) {
		fprintf(stderr, "inotify_add_watch failed for %s: %s\n", src_path, strerror(errno));
		close(ifd);
		return 1;
	}

	signal(SIGINT, dev_signal_handler);
	signal(SIGTERM, dev_signal_handler);

	printf("Watching %s (Ctrl+C to stop)\n", src_path);

	while (!g_dev_stop) {
		ssize_t len = read(ifd, buf, sizeof(buf));
		if (len < 0) {
			if (errno == EINTR)
				continue;
			fprintf(stderr, "inotify read error: %s\n", strerror(errno));
			goto out;
		}

		snprintf(make_cmd, sizeof(make_cmd), "make build/bpf/%s.bpf.o 2>&1", module_name);
		snprintf(reload_cmd, sizeof(reload_cmd), "./build/hot_reload -r %s 2>&1", q_module);

		printf("\n[dev watch] change detected -> rebuild %s\n", module_name);
		if (run_stream_command(make_cmd) != 0) {
			printf("[dev watch] build failed\n");
			continue;
		}

		printf("[dev watch] hot-reload %s\n", module_name);
		if (run_stream_command(reload_cmd) != 0)
			printf("[dev watch] reload failed\n");
		else
			printf("[dev watch] reload succeeded\n");
	}

	ret = 0;

out:
	if (wd >= 0)
		inotify_rm_watch(ifd, wd);
	if (ifd >= 0)
		close(ifd);
	printf("\nStopped dev watch for %s\n", module_name);
	return ret;
}

int cmd_dev_trace(const char *module_name)
{
	char path[PATH_MAX];
	int fd;
	struct ring_buffer *rb;
	struct dev_trace_ctx ctx = {
		.module_name = module_name,
		.seen = 0,
	};

	snprintf(path, sizeof(path), "%s/rs_event_bus", BPF_PIN_PATH);
	fd = bpf_obj_get(path);
	if (fd < 0) {
		fprintf(stderr, "Failed to open rs_event_bus: %s\n", strerror(errno));
		return 1;
	}

	rb = ring_buffer__new(fd, trace_ringbuf_cb, &ctx, NULL);
	if (!rb) {
		fprintf(stderr, "Failed to create ring buffer: %s\n", strerror(errno));
		close(fd);
		return 1;
	}

	signal(SIGINT, dev_signal_handler);
	signal(SIGTERM, dev_signal_handler);

	printf("Tracing module=%s from rs_event_bus (Ctrl+C to stop)\n",
		module_name ? module_name : "*");

	while (!g_dev_stop) {
		int err = ring_buffer__poll(rb, 100);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "ring_buffer__poll failed: %d\n", err);
			break;
		}
	}

	printf("Trace complete, events=%llu\n", ctx.seen);
	ring_buffer__free(rb);
	close(fd);
	return 0;
}

int cmd_dev_inspect(const char *module_name)
{
	struct bpf_prog_info pinfo = {};
	int prog_fd;
	int stats_fd = -1;
	int config_fd = -1;
	char path[PATH_MAX];
	struct module_total_stats totals[64];
	size_t total_cnt = 0;

	if (!module_name || module_name[0] == '\0') {
		fprintf(stderr, "Usage: rswitchctl dev inspect <module>\n");
		return 1;
	}

	prog_fd = find_module_prog_fd(module_name, &pinfo);
	if (prog_fd < 0) {
		fprintf(stderr, "Module '%s' not found among pinned XDP programs\n", module_name);
		return 1;
	}

	printf("Module: %s\n", module_name);
	printf("Program info:\n");
	printf("  name: %s\n", pinfo.name);
	printf("  id: %u\n", pinfo.id);
	printf("  type: %s (%u)\n", prog_type_str(pinfo.type), pinfo.type);
	printf("  tag: %02x%02x%02x%02x%02x%02x%02x%02x\n",
		pinfo.tag[0], pinfo.tag[1], pinfo.tag[2], pinfo.tag[3],
		pinfo.tag[4], pinfo.tag[5], pinfo.tag[6], pinfo.tag[7]);
	printf("  loaded_at_ns: %llu\n", (unsigned long long)pinfo.load_time);
	printf("  jited_size: %u bytes\n", pinfo.jited_prog_len);
	printf("  xlated_size: %u bytes\n", pinfo.xlated_prog_len);
	printf("  map_count: %u\n", pinfo.nr_map_ids);

	if (pinfo.nr_map_ids > 0) {
		__u32 *map_ids = calloc(pinfo.nr_map_ids, sizeof(*map_ids));
		if (map_ids) {
			struct bpf_prog_info mi = {};
			__u32 len = sizeof(mi);
			mi.nr_map_ids = pinfo.nr_map_ids;
			mi.map_ids = (__u64)(uintptr_t)map_ids;
			if (bpf_obj_get_info_by_fd(prog_fd, &mi, &len) == 0) {
				printf("  maps:\n");
				for (__u32 i = 0; i < mi.nr_map_ids; i++) {
					int map_fd = bpf_map_get_fd_by_id(map_ids[i]);
					if (map_fd >= 0) {
						struct bpf_map_info minfo = {};
						__u32 mlen = sizeof(minfo);
						if (bpf_obj_get_info_by_fd(map_fd, &minfo, &mlen) == 0) {
							printf("    - id=%u name=%s type=%u max_entries=%u\n",
							       minfo.id, minfo.name, minfo.type, minfo.max_entries);
						}
						close(map_fd);
					}
				}
			}
			free(map_ids);
		}
	}

	snprintf(path, sizeof(path), "%s/rs_module_stats_map", BPF_PIN_PATH);
	stats_fd = bpf_obj_get(path);
	if (stats_fd >= 0) {
		if (read_module_stats_totals(stats_fd, totals, 64, &total_cnt) == 0) {
			printf("Module stats:\n");
			for (size_t i = 0; i < total_cnt; i++) {
				if (strcmp(totals[i].name, module_name) != 0)
					continue;
				printf("  module_id=%u processed=%llu forwarded=%llu dropped=%llu errors=%llu bytes=%llu\n",
				       totals[i].module_id,
				       (unsigned long long)totals[i].packets_processed,
				       (unsigned long long)totals[i].packets_forwarded,
				       (unsigned long long)totals[i].packets_dropped,
				       (unsigned long long)totals[i].packets_error,
				       (unsigned long long)totals[i].bytes_processed);
			}
		}
	}

	snprintf(path, sizeof(path), "%s/rs_module_config_map", BPF_PIN_PATH);
	config_fd = bpf_obj_get(path);
	if (config_fd >= 0) {
		struct rs_module_config_key key;
		struct rs_module_config_key next;
		struct rs_module_config_value val;
		int has = bpf_map_get_next_key(config_fd, NULL, &next);
		int printed = 0;

		printf("Module config:\n");
		while (has == 0) {
			if (bpf_map_lookup_elem(config_fd, &next, &val) == 0 &&
			    strncmp(next.module_name, module_name, sizeof(next.module_name)) == 0) {
				printf("  %s.%s = ", next.module_name, next.param_name);
				switch (val.type) {
				case 0:
					printf("%lld", (long long)val.int_val);
					break;
				case 1:
					printf("%u", val.bool_val);
					break;
				default:
					printf("%s", val.str_val);
					break;
				}
				printf(" (type=%u)\n", val.type);
				printed = 1;
			}
			key = next;
			has = bpf_map_get_next_key(config_fd, &key, &next);
		}
		if (!printed)
			printf("  (no config entries)\n");
	}

	if (config_fd >= 0)
		close(config_fd);
	if (stats_fd >= 0)
		close(stats_fd);
	close(prog_fd);
	return 0;
}

int cmd_dev_benchmark(const char *profile_path)
{
	char q_profile[PATH_MAX * 2];
	char cmd[PATH_MAX * 2 + 64];
	char path[PATH_MAX];
	int stats_fd = -1;
	struct module_total_stats before[64];
	struct module_total_stats after[64];
	size_t bcnt = 0;
	size_t acnt = 0;
	struct timespec t0, t1;

	if (!profile_path || profile_path[0] == '\0') {
		fprintf(stderr, "Usage: rswitchctl dev benchmark <profile>\n");
		return 1;
	}

	if (shell_quote(profile_path, q_profile, sizeof(q_profile)) != 0) {
		fprintf(stderr, "Profile path too long\n");
		return 1;
	}

	clock_gettime(CLOCK_MONOTONIC, &t0);
	snprintf(cmd, sizeof(cmd), "./build/rswitch_loader -p %s 2>&1", q_profile);
	if (run_stream_command(cmd) != 0) {
		fprintf(stderr, "Benchmark setup failed: profile load failed\n");
		return 1;
	}
	clock_gettime(CLOCK_MONOTONIC, &t1);

	snprintf(path, sizeof(path), "%s/rs_module_stats_map", BPF_PIN_PATH);
	stats_fd = bpf_obj_get(path);
	if (stats_fd < 0) {
		fprintf(stderr, "Failed to open rs_module_stats_map: %s\n", strerror(errno));
		return 1;
	}

	read_module_stats_totals(stats_fd, before, 64, &bcnt);
	sleep(5);
	read_module_stats_totals(stats_fd, after, 64, &acnt);

	printf("Benchmark results (%s)\n", profile_path);
	printf("  module_load_time_ms: %.3f\n",
	       (t1.tv_sec - t0.tv_sec) * 1000.0 + (t1.tv_nsec - t0.tv_nsec) / 1000000.0);

	{
		unsigned long long total_delta = 0;
		for (size_t i = 0; i < acnt; i++) {
			for (size_t j = 0; j < bcnt; j++) {
				if (strcmp(after[i].name, before[j].name) == 0) {
					if (after[i].packets_processed > before[j].packets_processed)
						total_delta += after[i].packets_processed - before[j].packets_processed;
					break;
				}
			}
		}
		printf("  pipeline_throughput_pps: %.2f\n", total_delta / 5.0);
	}

	printf("  per_module:\n");
	for (size_t i = 0; i < acnt; i++) {
		unsigned long long prev = 0;
		for (size_t j = 0; j < bcnt; j++) {
			if (strcmp(after[i].name, before[j].name) == 0) {
				prev = before[j].packets_processed;
				break;
			}
		}
		printf("    - %s: processed=%llu forwarded=%llu dropped=%llu errors=%llu delta_pps=%.2f\n",
		       after[i].name,
		       (unsigned long long)after[i].packets_processed,
		       (unsigned long long)after[i].packets_forwarded,
		       (unsigned long long)after[i].packets_dropped,
		       (unsigned long long)after[i].packets_error,
		       after[i].packets_processed > prev ? (after[i].packets_processed - prev) / 5.0 : 0.0);
	}

	close(stats_fd);
	return 0;
}

int cmd_dev_verify(const char *obj_path)
{
	struct bpf_object *obj;
	libbpf_print_fn_t old_print;

	if (!obj_path || obj_path[0] == '\0') {
		fprintf(stderr, "Usage: rswitchctl dev verify <module.bpf.o>\n");
		return 1;
	}

	g_verify_log_len = 0;
	g_verify_log[0] = '\0';
	old_print = libbpf_set_print(libbpf_log_capture);

	obj = bpf_object__open(obj_path);
	if (libbpf_get_error(obj)) {
		libbpf_set_print(old_print);
		fprintf(stderr, "Verifier check failed: cannot open %s\n", obj_path);
		if (g_verify_log[0] != '\0')
			fprintf(stderr, "%s\n", g_verify_log);
		return 1;
	}

	if (bpf_object__load(obj) < 0) {
		libbpf_set_print(old_print);
		fprintf(stderr, "Verifier check FAILED for %s\n", obj_path);
		if (g_verify_log[0] != '\0')
			fprintf(stderr, "%s\n", g_verify_log);
		bpf_object__close(obj);
		return 1;
	}

	libbpf_set_print(old_print);
	printf("Verifier check PASSED for %s\n", obj_path);
	if (g_verify_log[0] != '\0')
		printf("%s\n", g_verify_log);
	bpf_object__close(obj);
	return 0;
}

int cmd_dev_debug(const char *obj_path, const char *pcap_path)
{
	struct bpf_object *obj;
	struct bpf_program *prog = NULL;
	struct packet_buf packets[DEV_MAX_CAPTURE_PKTS];
	int pkt_count;
	int rc = 1;
	int prog_fd;
	FILE *out = stdout;

	if (!obj_path || obj_path[0] == '\0') {
		fprintf(stderr, "Usage: rswitchctl dev debug <module.bpf.o> [pcap]\n");
		return 1;
	}

	if (pcap_path)
		pkt_count = read_pcap_packets(pcap_path, packets, DEV_MAX_CAPTURE_PKTS);
	else
		pkt_count = append_generated_packets(packets, DEV_MAX_CAPTURE_PKTS);

	if (pkt_count <= 0) {
		fprintf(stderr, "No packets available for debug run\n");
		return 1;
	}

	obj = bpf_object__open_file(obj_path, NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "Failed to open object %s\n", obj_path);
		return 1;
	}

	if (bpf_object__load(obj) < 0) {
		fprintf(stderr, "Failed to load object %s\n", obj_path);
		bpf_object__close(obj);
		return 1;
	}

	bpf_object__for_each_program(prog, obj) {
		if (bpf_program__type(prog) == BPF_PROG_TYPE_XDP) {
			break;
		}
	}
	if (!prog) {
		fprintf(stderr, "No XDP program found in %s\n", obj_path);
		goto out;
	}

	prog_fd = bpf_program__fd(prog);
	if (prog_fd < 0) {
		fprintf(stderr, "Failed to get prog fd\n");
		goto out;
	}

	fprintf(out, "{\"object\":\"%s\",\"pcap\":\"%s\",\"traces\":[",
		obj_path,
		pcap_path ? pcap_path : "generated");

	for (int i = 0; i < pkt_count; i++) {
		struct rs_ctx ctx_before = {};
		struct rs_ctx ctx_after = {};
		struct test_xdp_md xdp_ctx = {
			.data = 0,
			.data_meta = 0,
			.data_end = packets[i].len,
			.ingress_ifindex = 1,
			.rx_queue_index = 0,
			.egress_ifindex = 0,
		};
		__u8 out_pkt[DEV_MAX_PKT_SIZE] = {0};
		LIBBPF_OPTS(bpf_test_run_opts, topts,
			.data_in = packets[i].data,
			.data_size_in = packets[i].len,
			.data_out = out_pkt,
			.data_size_out = sizeof(out_pkt),
			.ctx_in = &xdp_ctx,
			.ctx_size_in = sizeof(xdp_ctx),
			.repeat = 1,
		);
		int err;

		read_rs_ctx_first_cpu(obj, &ctx_before);

		fprintf(out, "%s{\"packet\":%d,\"label\":\"%s\",", i == 0 ? "" : ",", i, packets[i].label);
		fprintf(out, "\"maps_before\":");
		map_snapshot_json(out, obj);

		err = bpf_prog_test_run_opts(prog_fd, &topts);
		read_rs_ctx_first_cpu(obj, &ctx_after);

		fprintf(out, ",\"result\":{\"err\":%d,\"retval\":%u,\"duration\":%u,\"out_len\":%u}",
			err,
			topts.retval,
			topts.duration,
			topts.data_size_out);

		fprintf(out, ",\"ctx_before\":{\"ifindex\":%u,\"parsed\":%u,\"egress_ifindex\":%u,\"action\":%u,\"error\":%u,\"drop_reason\":%u}",
			ctx_before.ifindex,
			ctx_before.parsed,
			ctx_before.egress_ifindex,
			ctx_before.action,
			ctx_before.error,
			ctx_before.drop_reason);

		fprintf(out, ",\"ctx_after\":{\"ifindex\":%u,\"parsed\":%u,\"egress_ifindex\":%u,\"action\":%u,\"error\":%u,\"drop_reason\":%u}",
			ctx_after.ifindex,
			ctx_after.parsed,
			ctx_after.egress_ifindex,
			ctx_after.action,
			ctx_after.error,
			ctx_after.drop_reason);

		fprintf(out, ",\"maps_after\":");
		map_snapshot_json(out, obj);
		fprintf(out, "}");
	}

	fprintf(out, "]}\n");
	rc = 0;

out:
	bpf_object__close(obj);
	return rc;
}
