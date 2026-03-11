// SPDX-License-Identifier: GPL-2.0
/*
 * rswitchctl - rSwitch Control Utility
 * 
 * Runtime control for VOQd state machine transitions and configuration.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <getopt.h>
#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdint.h>
#include <time.h>
#include <dirent.h>
#include <limits.h>
#include <net/if.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#if __has_include("rs_log.h")
#include "rs_log.h"
#else
#include "../common/rs_log.h"
#endif
#include "../watchdog/watchdog.h"
#include "../loader/profile_parser.h"
#include "../registry/registry.h"
#include "../rollback/rollback.h"
#include "../audit/audit.h"
#include "../topology/topology.h"
#include "../lldpd/lldpd.h"
#include "../../bpf/core/afxdp_common.h"
#include "../../bpf/core/module_abi.h"

#define DEFAULT_STATE_MAP_PIN  "/sys/fs/bpf/voqd_state_map"
#define DEFAULT_QOS_MAP_PIN    "/sys/fs/bpf/qos_config_map"
#define MODULE_BUILD_DIR        "./build/bpf"
#define DEFAULT_MIRROR_CONFIG_MAP "/sys/fs/bpf/mirror_config_map"
#define DEFAULT_MIRROR_SESSION_STATS_MAP "/sys/fs/bpf/mirror_session_stats"
#define MIRROR_MAX_SESSIONS     4
#define RSWITCH_PID_FILE        "/var/run/rswitch.pid"
#define RSWITCH_SHUTDOWN_OVERRIDE_FILE "/var/lib/rswitch/shutdown_override.cfg"

#define PACK_FORMAT_VERSION     1

/* Forward declarations for extended commands */
extern int cmd_list_modules(void);
extern int cmd_show_pipeline(void);
extern int cmd_show_ports(void);
extern int cmd_show_macs(int limit);
extern int cmd_show_stats(const char *module_filter, const char *format);
extern int cmd_flush_macs(void);
extern int cmd_get_telemetry(void);

/* ACL commands */
extern int cmd_acl_add_rule(int argc, char **argv);
extern int cmd_acl_del_rule(uint32_t rule_id);
extern int cmd_acl_show_rules(void);
extern int cmd_acl_show_stats(void);
extern int cmd_acl_enable(int enable);

/* Mirror commands */
extern int cmd_mirror_enable(int enable, uint32_t span_port);
extern int cmd_mirror_set_span_port(uint32_t span_port);
extern int cmd_mirror_set_port(uint32_t ifindex, int ingress, int egress);
extern int cmd_mirror_show_config(void);
extern int cmd_mirror_show_stats(void);

extern int cmd_dev_watch(const char *module_name);
extern int cmd_dev_trace(const char *module_name);
extern int cmd_dev_inspect(const char *module_name);
extern int cmd_dev_benchmark(const char *profile_path);
extern int cmd_dev_verify(const char *obj_path);
extern int cmd_dev_debug(const char *obj_path, const char *pcap_path);

struct validation_result {
	int errors;
	int warnings;
	char messages[64][256];
	int msg_count;
	int is_error[64];
};

struct rsmod_metadata {
	char name[sizeof(((struct rs_module_desc *)0)->name)];
	char abi_version[32];
	char hook[16];
	unsigned int stage;
	unsigned int flags;
	char description[sizeof(((struct rs_module_desc *)0)->description)];
	unsigned int format_version;
};

enum mirror_session_type {
	MIRROR_TYPE_SPAN = 0,
	MIRROR_TYPE_RSPAN = 1,
	MIRROR_TYPE_ERSPAN = 2,
};

struct mirror_config_v2 {
	uint32_t enabled;
	uint32_t span_port;

	uint8_t ingress_enabled;
	uint8_t egress_enabled;
	uint8_t pcap_enabled;
	uint8_t filter_mode;

	uint16_t vlan_filter;
	uint16_t protocol_filter;

	uint8_t mirror_type;
	uint8_t rspan_pad[3];
	uint16_t rspan_vlan_id;
	uint16_t truncate_size;

	uint64_t ingress_mirrored_packets;
	uint64_t ingress_mirrored_bytes;
	uint64_t egress_mirrored_packets;
	uint64_t egress_mirrored_bytes;
	uint64_t mirror_drops;
	uint64_t pcap_packets;
};

struct mirror_session_stats_v2 {
	uint64_t pkts;
	uint64_t bytes;
	uint64_t drops;
};

static const char *mirror_type_to_str(uint8_t type)
{
	switch (type) {
	case MIRROR_TYPE_SPAN:
		return "span";
	case MIRROR_TYPE_RSPAN:
		return "rspan";
	case MIRROR_TYPE_ERSPAN:
		return "erspan";
	default:
		return "unknown";
	}
}

static int mirror_type_from_str(const char *type_str, uint8_t *type)
{
	if (!type_str || !type)
		return -1;

	if (strcmp(type_str, "span") == 0)
		*type = MIRROR_TYPE_SPAN;
	else if (strcmp(type_str, "rspan") == 0)
		*type = MIRROR_TYPE_RSPAN;
	else if (strcmp(type_str, "erspan") == 0)
		*type = MIRROR_TYPE_ERSPAN;
	else
		return -1;

	return 0;
}

static uint32_t parse_ifname_or_ifindex(const char *value)
{
	char *end = NULL;
	unsigned long parsed;
	uint32_t ifindex;

	if (!value || value[0] == '\0')
		return 0;

	ifindex = if_nametoindex(value);
	if (ifindex > 0)
		return ifindex;

	errno = 0;
	parsed = strtoul(value, &end, 10);
	if (errno != 0 || !end || *end != '\0' || parsed == 0 || parsed > UINT32_MAX)
		return 0;

	return (uint32_t)parsed;
}

static int read_percpu_session_stats(int stats_fd, uint32_t session_id,
				      struct mirror_session_stats_v2 *out)
{
	int cpu_count;
	struct mirror_session_stats_v2 *percpu;

	if (!out)
		return -1;

	memset(out, 0, sizeof(*out));
	cpu_count = libbpf_num_possible_cpus();
	if (cpu_count <= 0)
		return -1;

	percpu = calloc((size_t)cpu_count, sizeof(*percpu));
	if (!percpu)
		return -1;

	if (bpf_map_lookup_elem(stats_fd, &session_id, percpu) < 0) {
		free(percpu);
		return -1;
	}

	for (int i = 0; i < cpu_count; i++) {
		out->pkts += percpu[i].pkts;
		out->bytes += percpu[i].bytes;
		out->drops += percpu[i].drops;
	}

	free(percpu);
	return 0;
}

static int cmd_mirror_session(int argc, char **argv)
{
	int cfg_fd;
	const char *subcmd;

	if (argc < 3) {
		RS_LOG_ERROR("Usage: %s mirror-session <add|del|show|stats> ...", argv[0]);
		return 1;
	}

	subcmd = argv[2];
	cfg_fd = bpf_obj_get(DEFAULT_MIRROR_CONFIG_MAP);
	if (cfg_fd < 0) {
		RS_LOG_ERROR("Failed to open mirror config map: %s", strerror(errno));
		return 1;
	}

	if (strcmp(subcmd, "add") == 0) {
		struct mirror_config_v2 cfg;
		char *end = NULL;
		unsigned long parsed;
		uint32_t session_id;
		const char *type_str = NULL;
		const char *dest_port_arg = NULL;
		uint16_t rspan_vlan = 0;
		int have_rspan_vlan = 0;
		uint16_t truncate_size = 0;
		uint8_t mirror_type;
		uint32_t dest_ifindex;

		if (argc < 5) {
			RS_LOG_ERROR("Usage: %s mirror-session add <session_id> --type <span|rspan|erspan> --dest-port <ifname|ifindex> [--rspan-vlan <id>] [--truncate <bytes>]", argv[0]);
			close(cfg_fd);
			return 1;
		}

		errno = 0;
		parsed = strtoul(argv[3], &end, 10);
		if (errno != 0 || !end || *end != '\0' || parsed >= MIRROR_MAX_SESSIONS) {
			RS_LOG_ERROR("session_id must be 0-%d", MIRROR_MAX_SESSIONS - 1);
			close(cfg_fd);
			return 1;
		}
		session_id = (uint32_t)parsed;

		for (int i = 4; i < argc; i++) {
			if (strcmp(argv[i], "--type") == 0 && i + 1 < argc) {
				type_str = argv[++i];
			} else if (strcmp(argv[i], "--dest-port") == 0 && i + 1 < argc) {
				dest_port_arg = argv[++i];
			} else if (strcmp(argv[i], "--rspan-vlan") == 0 && i + 1 < argc) {
				unsigned long v;

				errno = 0;
				v = strtoul(argv[++i], &end, 10);
				if (errno != 0 || !end || *end != '\0' || v == 0 || v > 4094) {
					RS_LOG_ERROR("--rspan-vlan must be 1-4094");
					close(cfg_fd);
					return 1;
				}
				rspan_vlan = (uint16_t)v;
				have_rspan_vlan = 1;
			} else if (strcmp(argv[i], "--truncate") == 0 && i + 1 < argc) {
				unsigned long t;

				errno = 0;
				t = strtoul(argv[++i], &end, 10);
				if (errno != 0 || !end || *end != '\0' || t > UINT16_MAX) {
					RS_LOG_ERROR("--truncate must be 0-%u", UINT16_MAX);
					close(cfg_fd);
					return 1;
				}
				truncate_size = (uint16_t)t;
			} else {
				RS_LOG_ERROR("Unknown or incomplete option: %s", argv[i]);
				close(cfg_fd);
				return 1;
			}
		}

		if (!type_str || !dest_port_arg) {
			RS_LOG_ERROR("--type and --dest-port are required");
			close(cfg_fd);
			return 1;
		}

		if (mirror_type_from_str(type_str, &mirror_type) != 0) {
			RS_LOG_ERROR("Invalid --type: %s (expected span|rspan|erspan)", type_str);
			close(cfg_fd);
			return 1;
		}

		dest_ifindex = parse_ifname_or_ifindex(dest_port_arg);
		if (dest_ifindex == 0) {
			RS_LOG_ERROR("Invalid --dest-port: %s", dest_port_arg);
			close(cfg_fd);
			return 1;
		}

		if (mirror_type == MIRROR_TYPE_RSPAN && !have_rspan_vlan) {
			RS_LOG_ERROR("--rspan-vlan is required for rspan type");
			close(cfg_fd);
			return 1;
		}

		if (bpf_map_lookup_elem(cfg_fd, &session_id, &cfg) < 0)
			memset(&cfg, 0, sizeof(cfg));

		cfg.enabled = 1;
		cfg.ingress_enabled = 1;
		cfg.egress_enabled = 1;
		cfg.span_port = dest_ifindex;
		cfg.mirror_type = mirror_type;
		cfg.rspan_vlan_id = have_rspan_vlan ? rspan_vlan : 0;
		cfg.truncate_size = truncate_size;

		if (bpf_map_update_elem(cfg_fd, &session_id, &cfg, BPF_ANY) < 0) {
			RS_LOG_ERROR("Failed to update mirror session %u: %s", session_id, strerror(errno));
			close(cfg_fd);
			return 1;
		}

		RS_LOG_INFO("Mirror session %u configured: type=%s dest_ifindex=%u%s truncate=%u",
			session_id,
			mirror_type_to_str(cfg.mirror_type),
			cfg.span_port,
			cfg.mirror_type == MIRROR_TYPE_RSPAN ? " (RSPAN VLAN set)" : "",
			cfg.truncate_size);
		if (cfg.mirror_type == MIRROR_TYPE_RSPAN)
			RS_LOG_INFO("RSPAN VLAN ID: %u", cfg.rspan_vlan_id);

		close(cfg_fd);
		return 0;
	}

	if (strcmp(subcmd, "del") == 0) {
		char *end = NULL;
		unsigned long parsed;
		uint32_t session_id;
		struct mirror_config_v2 cfg = {0};

		if (argc < 4) {
			RS_LOG_ERROR("Usage: %s mirror-session del <session_id>", argv[0]);
			close(cfg_fd);
			return 1;
		}

		errno = 0;
		parsed = strtoul(argv[3], &end, 10);
		if (errno != 0 || !end || *end != '\0' || parsed >= MIRROR_MAX_SESSIONS) {
			RS_LOG_ERROR("session_id must be 0-%d", MIRROR_MAX_SESSIONS - 1);
			close(cfg_fd);
			return 1;
		}
		session_id = (uint32_t)parsed;

		if (bpf_map_update_elem(cfg_fd, &session_id, &cfg, BPF_ANY) < 0) {
			RS_LOG_ERROR("Failed to delete mirror session %u: %s", session_id, strerror(errno));
			close(cfg_fd);
			return 1;
		}

		RS_LOG_INFO("Mirror session %u deleted", session_id);
		close(cfg_fd);
		return 0;
	}

	if (strcmp(subcmd, "show") == 0) {
		printf("Mirror Sessions:\n");
		printf("%-8s %-9s %-8s %-11s %-11s %-11s %-8s\n",
		       "Session", "Enabled", "Type", "DestPort", "RSPAN VLAN", "Truncate", "PCAP");
		printf("-----------------------------------------------------------------------\n");

		for (uint32_t session_id = 0; session_id < MIRROR_MAX_SESSIONS; session_id++) {
			struct mirror_config_v2 cfg;

			if (bpf_map_lookup_elem(cfg_fd, &session_id, &cfg) < 0)
				memset(&cfg, 0, sizeof(cfg));

			printf("%-8u %-9s %-8s %-11u %-11u %-11u %-8s\n",
			       session_id,
			       cfg.enabled ? "yes" : "no",
			       mirror_type_to_str(cfg.mirror_type),
			       cfg.span_port,
			       cfg.rspan_vlan_id,
			       cfg.truncate_size,
			       cfg.pcap_enabled ? "yes" : "no");
		}

		close(cfg_fd);
		return 0;
	}

	if (strcmp(subcmd, "stats") == 0) {
		int stats_fd;

		stats_fd = bpf_obj_get(DEFAULT_MIRROR_SESSION_STATS_MAP);
		if (stats_fd < 0) {
			RS_LOG_ERROR("Failed to open mirror session stats map: %s", strerror(errno));
			close(cfg_fd);
			return 1;
		}

		printf("Mirror Session Statistics:\n");
		printf("%-8s %-12s %-12s %-12s\n", "Session", "Packets", "Bytes", "Drops");
		printf("------------------------------------------------\n");

		for (uint32_t session_id = 0; session_id < MIRROR_MAX_SESSIONS; session_id++) {
			struct mirror_session_stats_v2 stats;

			if (read_percpu_session_stats(stats_fd, session_id, &stats) < 0)
				memset(&stats, 0, sizeof(stats));

			printf("%-8u %-12lu %-12lu %-12lu\n",
			       session_id, stats.pkts, stats.bytes, stats.drops);
		}

		close(stats_fd);
		close(cfg_fd);
		return 0;
	}

	RS_LOG_ERROR("Unknown mirror-session command: %s", subcmd);
	close(cfg_fd);
	return 1;
}

static int read_module_metadata_from_obj(const char *path, struct rs_module_desc *desc, int verbose)
{
	struct bpf_object *obj;
	struct bpf_map *map;
	const void *data;
	size_t size;
	int err;

	obj = bpf_object__open(path);
	err = libbpf_get_error(obj);
	if (err) {
		if (verbose)
			fprintf(stderr, "Error: Failed to open %s: %s\n", path, strerror(-err));
		return -1;
	}

	bpf_object__for_each_map(map, obj) {
		const char *map_name = bpf_map__name(map);

		if (!strstr(map_name, ".rodata.mod"))
			continue;

		data = bpf_map__initial_value(map, &size);
		if (!data) {
			if (verbose)
				fprintf(stderr, "Error: No data in .rodata.mod section of %s\n", path);
			bpf_object__close(obj);
			return -1;
		}

		if (size == 0 || size < sizeof(*desc))
			size = sizeof(*desc);

		memcpy(desc, data, sizeof(*desc));
		bpf_object__close(obj);
		return 0;
	}

	bpf_object__close(obj);
	if (verbose)
		fprintf(stderr, "Error: No .rodata.mod section found in %s\n", path);
	return -1;
}

static void json_fprint_escaped(FILE *f, const char *s)
{
	const unsigned char *p = (const unsigned char *)s;

	while (p && *p) {
		switch (*p) {
		case '\\':
			fputs("\\\\", f);
			break;
		case '"':
			fputs("\\\"", f);
			break;
		case '\n':
			fputs("\\n", f);
			break;
		case '\r':
			fputs("\\r", f);
			break;
		case '\t':
			fputs("\\t", f);
			break;
		default:
			if (*p < 0x20)
				fprintf(f, "\\u%04x", *p);
			else
				fputc(*p, f);
			break;
		}
		p++;
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

static int parse_json_string_field(const char *buf, const char *key, char *out, size_t out_sz)
{
	char pattern[64];
	const char *p;
	const char *start;
	size_t i = 0;

	if (!buf || !key || !out || out_sz == 0)
		return -1;

	snprintf(pattern, sizeof(pattern), "\"%s\"", key);
	p = strstr(buf, pattern);
	if (!p)
		return -1;
	p = strchr(p, ':');
	if (!p)
		return -1;
	start = strchr(p, '"');
	if (!start)
		return -1;
	start++;

	while (*start && *start != '"' && i + 1 < out_sz) {
		if (*start == '\\' && start[1] != '\0') {
			start++;
			switch (*start) {
			case 'n':
				out[i++] = '\n';
				break;
			case 'r':
				out[i++] = '\r';
				break;
			case 't':
				out[i++] = '\t';
				break;
			default:
				out[i++] = *start;
				break;
			}
		} else {
			out[i++] = *start;
		}
		start++;
	}

	out[i] = '\0';
	return (*start == '"') ? 0 : -1;
}

static int parse_json_uint_field(const char *buf, const char *key, unsigned int *value)
{
	char pattern[64];
	const char *p;

	if (!buf || !key || !value)
		return -1;

	snprintf(pattern, sizeof(pattern), "\"%s\"", key);
	p = strstr(buf, pattern);
	if (!p)
		return -1;
	p = strchr(p, ':');
	if (!p)
		return -1;
	p++;
	while (*p == ' ' || *p == '\t')
		p++;

	if (sscanf(p, "%u", value) != 1)
		return -1;

	return 0;
}

static int parse_abi_version(const char *abi, unsigned int *major, unsigned int *minor)
{
	if (!abi || !major || !minor)
		return -1;
	if (sscanf(abi, "%u.%u", major, minor) != 2)
		return -1;
	return 0;
}

static int cmd_pack_module(const char *bpf_obj_path, const char *output_path)
{
	struct rs_module_desc desc = {0};
	char meta_tpl[] = "/tmp/rsmod_meta_XXXXXX";
	char tmp_tpl[] = "/tmp/rsmod_pack_XXXXXX";
	char meta_json_path[PATH_MAX];
	char module_dst_path[PATH_MAX];
	char metadata_dst_path[PATH_MAX];
	char readme_src_path[PATH_MAX];
	char readme_dst_path[PATH_MAX];
	char obj_dir[PATH_MAX];
	char pkg_name[PATH_MAX];
	char q_tmp[PATH_MAX * 2];
	char q_obj[PATH_MAX * 2];
	char q_meta[PATH_MAX * 2];
	char q_pkg[PATH_MAX * 2];
	char q_module_dst[PATH_MAX * 2];
	char q_metadata_dst[PATH_MAX * 2];
	char q_readme_src[PATH_MAX * 2];
	char q_readme_dst[PATH_MAX * 2];
	char cmd[4096];
	int meta_fd = -1;
	char *tmp_dir = NULL;
	FILE *f = NULL;
	int has_readme = 0;
	int ret;

	if (access(bpf_obj_path, F_OK) != 0) {
		fprintf(stderr, "Error: BPF object not found: %s\n", bpf_obj_path);
		return 1;
	}

	if (read_module_metadata_from_obj(bpf_obj_path, &desc, 1) != 0)
		return 1;

	desc.name[sizeof(desc.name) - 1] = '\0';
	desc.description[sizeof(desc.description) - 1] = '\0';

	meta_fd = mkstemp(meta_tpl);
	if (meta_fd < 0) {
		fprintf(stderr, "Error: Failed to create temporary metadata file: %s\n", strerror(errno));
		return 1;
	}
	close(meta_fd);

	snprintf(meta_json_path, sizeof(meta_json_path), "%s.json", meta_tpl);
	if (rename(meta_tpl, meta_json_path) != 0) {
		fprintf(stderr, "Error: Failed to create metadata path: %s\n", strerror(errno));
		unlink(meta_tpl);
		return 1;
	}

	f = fopen(meta_json_path, "w");
	if (!f) {
		fprintf(stderr, "Error: Failed to write metadata: %s\n", strerror(errno));
		unlink(meta_json_path);
		return 1;
	}

	fprintf(f, "{\n");
	fprintf(f, "  \"name\": \"");
	json_fprint_escaped(f, desc.name);
	fprintf(f, "\",\n");
	fprintf(f, "  \"abi_version\": \"%u.%u\",\n",
		RS_ABI_MAJOR(desc.abi_version), RS_ABI_MINOR(desc.abi_version));
	fprintf(f, "  \"hook\": \"%s\",\n", desc.hook == RS_HOOK_XDP_EGRESS ? "egress" : "ingress");
	fprintf(f, "  \"stage\": %u,\n", desc.stage);
	fprintf(f, "  \"flags\": %u,\n", desc.flags);
	fprintf(f, "  \"description\": \"");
	json_fprint_escaped(f, desc.description);
	fprintf(f, "\",\n");
	fprintf(f, "  \"format_version\": %u\n", PACK_FORMAT_VERSION);
	fprintf(f, "}\n");
	fclose(f);
	f = NULL;

	tmp_dir = mkdtemp(tmp_tpl);
	if (!tmp_dir) {
		fprintf(stderr, "Error: Failed to create temporary directory: %s\n", strerror(errno));
		unlink(meta_json_path);
		return 1;
	}

	snprintf(module_dst_path, sizeof(module_dst_path), "%s/module.bpf.o", tmp_dir);
	snprintf(metadata_dst_path, sizeof(metadata_dst_path), "%s/metadata.json", tmp_dir);

	if (output_path) {
		snprintf(pkg_name, sizeof(pkg_name), "%s", output_path);
	} else {
		const char *name = desc.name[0] ? desc.name : "module";
		snprintf(pkg_name, sizeof(pkg_name), "%s.rsmod", name);
	}

	if (shell_quote(tmp_dir, q_tmp, sizeof(q_tmp)) != 0 ||
	    shell_quote(bpf_obj_path, q_obj, sizeof(q_obj)) != 0 ||
	    shell_quote(meta_json_path, q_meta, sizeof(q_meta)) != 0 ||
	    shell_quote(module_dst_path, q_module_dst, sizeof(q_module_dst)) != 0 ||
	    shell_quote(metadata_dst_path, q_metadata_dst, sizeof(q_metadata_dst)) != 0 ||
	    shell_quote(pkg_name, q_pkg, sizeof(q_pkg)) != 0) {
		fprintf(stderr, "Error: path too long for packaging\n");
		unlink(meta_json_path);
		snprintf(cmd, sizeof(cmd), "rm -rf '%s'", tmp_dir);
		system(cmd);
		return 1;
	}

	ret = snprintf(cmd, sizeof(cmd), "cp %s %s && cp %s %s",
		q_obj, q_module_dst, q_meta, q_metadata_dst);
	if (ret < 0 || ret >= (int)sizeof(cmd) || system(cmd) != 0) {
		fprintf(stderr, "Error: Failed to stage package files\n");
		unlink(meta_json_path);
		snprintf(cmd, sizeof(cmd), "rm -rf %s", q_tmp);
		system(cmd);
		return 1;
	}

	obj_dir[0] = '\0';
	{
		const char *slash = strrchr(bpf_obj_path, '/');
		if (slash) {
			size_t dlen = (size_t)(slash - bpf_obj_path);
			if (dlen >= sizeof(obj_dir))
				dlen = sizeof(obj_dir) - 1;
			memcpy(obj_dir, bpf_obj_path, dlen);
			obj_dir[dlen] = '\0';
		}
	}
	if (obj_dir[0] == '\0')
		snprintf(obj_dir, sizeof(obj_dir), ".");

	snprintf(readme_src_path, sizeof(readme_src_path), "%s/README.md", obj_dir);
	snprintf(readme_dst_path, sizeof(readme_dst_path), "%s/README.md", tmp_dir);
	if (access(readme_src_path, F_OK) == 0) {
		if (shell_quote(readme_src_path, q_readme_src, sizeof(q_readme_src)) == 0 &&
		    shell_quote(readme_dst_path, q_readme_dst, sizeof(q_readme_dst)) == 0) {
			snprintf(cmd, sizeof(cmd), "cp %s %s", q_readme_src, q_readme_dst);
			if (system(cmd) == 0)
				has_readme = 1;
		}
	}

	ret = snprintf(cmd, sizeof(cmd), "tar czf %s -C %s .", q_pkg, q_tmp);
	if (ret < 0 || ret >= (int)sizeof(cmd) || system(cmd) != 0) {
		fprintf(stderr, "Error: Failed to create package\n");
		unlink(meta_json_path);
		snprintf(cmd, sizeof(cmd), "rm -rf %s", q_tmp);
		system(cmd);
		return 1;
	}

	unlink(meta_json_path);
	snprintf(cmd, sizeof(cmd), "rm -rf %s", q_tmp);
	system(cmd);

	printf("Created: %s\n", pkg_name);
	if (has_readme)
		printf("Included: README.md\n");
	return 0;
}

static int cmd_install_module(const char *rsmod_path)
{
	char tmp_tpl[] = "/tmp/rsmod_install_XXXXXX";
	char meta_path[PATH_MAX];
	char obj_path[PATH_MAX];
	char dst_path[PATH_MAX];
	char q_tmp[PATH_MAX * 2];
	char q_pkg[PATH_MAX * 2];
	char q_src_obj[PATH_MAX * 2];
	char q_dst_obj[PATH_MAX * 2];
	char cmd[4096];
	char json_buf[8192];
	char cleanup_cmd[PATH_MAX * 2 + 32];
	FILE *f = NULL;
	char *tmp_dir = NULL;
	struct rsmod_metadata meta = {0};
	unsigned int pkg_abi_major = 0;
	unsigned int pkg_abi_minor = 0;
	int ret = 1;

	q_tmp[0] = '\0';

	if (access(rsmod_path, F_OK) != 0) {
		fprintf(stderr, "Error: Package not found: %s\n", rsmod_path);
		return 1;
	}

	tmp_dir = mkdtemp(tmp_tpl);
	if (!tmp_dir) {
		fprintf(stderr, "Error: Failed to create temporary directory: %s\n", strerror(errno));
		return 1;
	}

	if (shell_quote(tmp_dir, q_tmp, sizeof(q_tmp)) != 0 ||
	    shell_quote(rsmod_path, q_pkg, sizeof(q_pkg)) != 0) {
		fprintf(stderr, "Error: path too long\n");
		goto cleanup;
	}

	snprintf(cmd, sizeof(cmd), "tar xzf %s -C %s", q_pkg, q_tmp);
	if (system(cmd) != 0) {
		fprintf(stderr, "Error: Failed to extract package\n");
		goto cleanup;
	}

	snprintf(meta_path, sizeof(meta_path), "%s/metadata.json", tmp_dir);
	f = fopen(meta_path, "r");
	if (!f) {
		fprintf(stderr, "Error: metadata.json missing in package\n");
		goto cleanup;
	}

	if (!fgets(json_buf, sizeof(json_buf), f)) {
		size_t n;
		clearerr(f);
		fseek(f, 0, SEEK_SET);
		n = fread(json_buf, 1, sizeof(json_buf) - 1, f);
		json_buf[n] = '\0';
	} else {
		size_t used = strlen(json_buf);
		size_t n = fread(json_buf + used, 1, sizeof(json_buf) - used - 1, f);
		json_buf[used + n] = '\0';
	}
	fclose(f);
	f = NULL;

	if (parse_json_string_field(json_buf, "name", meta.name, sizeof(meta.name)) != 0 ||
	    parse_json_string_field(json_buf, "abi_version", meta.abi_version, sizeof(meta.abi_version)) != 0 ||
	    parse_json_string_field(json_buf, "hook", meta.hook, sizeof(meta.hook)) != 0 ||
	    parse_json_uint_field(json_buf, "stage", &meta.stage) != 0 ||
	    parse_json_uint_field(json_buf, "flags", &meta.flags) != 0 ||
	    parse_json_string_field(json_buf, "description", meta.description, sizeof(meta.description)) != 0 ||
	    parse_json_uint_field(json_buf, "format_version", &meta.format_version) != 0) {
		fprintf(stderr, "Error: metadata.json is invalid\n");
		goto cleanup;
	}

	if (meta.format_version != PACK_FORMAT_VERSION) {
		fprintf(stderr, "Error: Unsupported package format version: %u\n", meta.format_version);
		goto cleanup;
	}

	if (meta.name[0] == '\0') {
		fprintf(stderr, "Error: metadata name is empty\n");
		goto cleanup;
	}

	if (parse_abi_version(meta.abi_version, &pkg_abi_major, &pkg_abi_minor) != 0) {
		fprintf(stderr, "Error: Invalid abi_version in metadata: %s\n", meta.abi_version);
		goto cleanup;
	}

	printf("Package metadata:\n");
	printf("  Name: %s\n", meta.name);
	printf("  ABI: %s\n", meta.abi_version);
	printf("  Hook: %s\n", meta.hook);
	printf("  Stage: %u\n", meta.stage);
	printf("  Flags: %u\n", meta.flags);
	printf("  Description: %s\n", meta.description);

	if (pkg_abi_major != RS_ABI_VERSION_MAJOR || pkg_abi_minor > RS_ABI_VERSION_MINOR) {
		fprintf(stderr,
			"Error: ABI mismatch (platform %u.%u, package %u.%u)\n",
			RS_ABI_VERSION_MAJOR, RS_ABI_VERSION_MINOR,
			pkg_abi_major, pkg_abi_minor);
		goto cleanup;
	}

	snprintf(obj_path, sizeof(obj_path), "%s/module.bpf.o", tmp_dir);
	if (access(obj_path, F_OK) != 0) {
		fprintf(stderr, "Error: module.bpf.o missing in package\n");
		goto cleanup;
	}

	if (access(MODULE_BUILD_DIR, F_OK) != 0) {
		fprintf(stderr, "Error: %s not found (run make all first)\n", MODULE_BUILD_DIR);
		goto cleanup;
	}

	snprintf(dst_path, sizeof(dst_path), "%s/%s.bpf.o", MODULE_BUILD_DIR, meta.name);
	if (shell_quote(obj_path, q_src_obj, sizeof(q_src_obj)) != 0 ||
	    shell_quote(dst_path, q_dst_obj, sizeof(q_dst_obj)) != 0) {
		fprintf(stderr, "Error: path too long\n");
		goto cleanup;
	}

	snprintf(cmd, sizeof(cmd), "cp %s %s", q_src_obj, q_dst_obj);
	if (system(cmd) != 0) {
		fprintf(stderr, "Error: Failed to install module object\n");
		goto cleanup;
	}

	printf("Installed: %s\n", dst_path);
	printf("Module installed successfully\n");
	printf("Add to a profile's ingress/egress list to use\n");
	ret = 0;

cleanup:
	if (q_tmp[0] != '\0') {
		snprintf(cleanup_cmd, sizeof(cleanup_cmd), "rm -rf %s", q_tmp);
		system(cleanup_cmd);
	} else if (tmp_dir) {
		snprintf(cleanup_cmd, sizeof(cleanup_cmd), "rm -rf '%s'", tmp_dir);
		system(cleanup_cmd);
	}
	if (f)
		fclose(f);
	return ret;
}

static int cmd_list_available_modules(void)
{
	DIR *dir;
	struct dirent *entry;

	dir = opendir(MODULE_BUILD_DIR);
	if (!dir) {
		fprintf(stderr, "Error: Cannot open %s\n", MODULE_BUILD_DIR);
		return 1;
	}

	printf("%-20s %6s %-8s %8s %s\n", "Name", "Stage", "Hook", "Flags", "Description");
	printf("%-20s %6s %-8s %8s %s\n", "----", "-----", "----", "-----", "-----------");

	while ((entry = readdir(dir)) != NULL) {
		char path[PATH_MAX];
		struct rs_module_desc desc = {0};
		size_t len;

		if (entry->d_name[0] == '.')
			continue;

		len = strlen(entry->d_name);
		if (len < 6 || strcmp(entry->d_name + len - 6, ".bpf.o") != 0)
			continue;

		if (strcmp(entry->d_name, "dispatcher.bpf.o") == 0 ||
		    strcmp(entry->d_name, "egress.bpf.o") == 0)
			continue;

		snprintf(path, sizeof(path), "%s/%s", MODULE_BUILD_DIR, entry->d_name);
		if (read_module_metadata_from_obj(path, &desc, 0) != 0)
			continue;

		desc.name[sizeof(desc.name) - 1] = '\0';
		desc.description[sizeof(desc.description) - 1] = '\0';

		printf("%-20s %6u %-8s %8u %s\n",
		       desc.name,
		       desc.stage,
		       desc.hook == RS_HOOK_XDP_EGRESS ? "egress" : "ingress",
		       desc.flags,
		       desc.description);
	}

	closedir(dir);
	return 0;
}

static void add_validation_msg(struct validation_result *res, int is_err,
			       const char *fmt, ...)
{
	va_list args;

	if (!res || !fmt || res->msg_count >= 64)
		return;

	va_start(args, fmt);
	vsnprintf(res->messages[res->msg_count], sizeof(res->messages[res->msg_count]),
		  fmt, args);
	va_end(args);

	res->is_error[res->msg_count] = is_err ? 1 : 0;
	if (is_err)
		res->errors++;
	else
		res->warnings++;
	res->msg_count++;
}

static int is_valid_optional_condition(const char *condition)
{
	static const char *valid_conditions[] = {
		"debug_mode", "debug", "stats_enabled", "ringbuf_enabled",
		"mac_learning", "vlan_enforcement", NULL
	};

	if (!condition || condition[0] == '\0')
		return 1;

	for (int i = 0; valid_conditions[i]; i++) {
		if (strcmp(condition, valid_conditions[i]) == 0)
			return 1;
	}

	return 0;
}

static void json_print_escaped(const char *s)
{
	const unsigned char *p = (const unsigned char *)s;

	if (!s)
		return;

	while (*p) {
		switch (*p) {
		case '\\':
			fputs("\\\\", stdout);
			break;
		case '"':
			fputs("\\\"", stdout);
			break;
		case '\n':
			fputs("\\n", stdout);
			break;
		case '\r':
			fputs("\\r", stdout);
			break;
		case '\t':
			fputs("\\t", stdout);
			break;
		default:
			if (*p < 0x20)
				printf("\\u%04x", *p);
			else
				putchar(*p);
			break;
		}
		p++;
	}
}

static int cmd_validate_profile(const char *profile_path, int json_output)
{
	struct rs_profile profile;
	struct validation_result result = {0};

	profile_init(&profile);

	if (profile_load(profile_path, &profile) != 0) {
		add_validation_msg(&result, 1, "Failed to parse profile: %s", profile_path);
		goto output;
	}

	for (int i = 0; i < profile.ingress_count; i++) {
		int stage = profile.ingress_modules[i].stage_override;
		if (stage >= 0 && (stage < 10 || stage > 99)) {
			add_validation_msg(&result, 1,
				"Ingress module '%s' has invalid stage %d (valid: 10-99)",
				profile.ingress_modules[i].name, stage);
		}
	}

	for (int i = 0; i < profile.egress_count; i++) {
		int stage = profile.egress_modules[i].stage_override;
		if (stage >= 0 && (stage < 100 || stage > 199)) {
			add_validation_msg(&result, 1,
				"Egress module '%s' has invalid stage %d (valid: 100-199)",
				profile.egress_modules[i].name, stage);
		}
	}

	for (int i = 0; i < profile.ingress_count; i++) {
		for (int j = i + 1; j < profile.ingress_count; j++) {
			int si = profile.ingress_modules[i].stage_override;
			int sj = profile.ingress_modules[j].stage_override;
			if (si >= 0 && sj >= 0 && si == sj) {
				add_validation_msg(&result, 1,
					"Stage conflict: ingress modules '%s' and '%s' both override to stage %d",
					profile.ingress_modules[i].name,
					profile.ingress_modules[j].name, si);
			}
		}
	}

	for (int i = 0; i < profile.egress_count; i++) {
		for (int j = i + 1; j < profile.egress_count; j++) {
			int si = profile.egress_modules[i].stage_override;
			int sj = profile.egress_modules[j].stage_override;
			if (si >= 0 && sj >= 0 && si == sj) {
				add_validation_msg(&result, 1,
					"Stage conflict: egress modules '%s' and '%s' both override to stage %d",
					profile.egress_modules[i].name,
					profile.egress_modules[j].name, si);
			}
		}
	}

	for (int i = 0; i < profile.ingress_count; i++) {
		char path[512];
		snprintf(path, sizeof(path), "./build/bpf/%s.bpf.o", profile.ingress_modules[i].name);
		if (access(path, F_OK) != 0) {
			add_validation_msg(&result, 0,
				"Ingress module '%s' BPF object not found at %s (may not be built yet)",
				profile.ingress_modules[i].name, path);
		}
	}

	for (int i = 0; i < profile.egress_count; i++) {
		char path[512];
		snprintf(path, sizeof(path), "./build/bpf/%s.bpf.o", profile.egress_modules[i].name);
		if (access(path, F_OK) != 0) {
			add_validation_msg(&result, 0,
				"Egress module '%s' BPF object not found at %s (may not be built yet)",
				profile.egress_modules[i].name, path);
		}
	}

	for (int i = 0; i < profile.port_count; i++) {
		struct rs_profile_port *port = &profile.ports[i];
		if (port->interface[0] == '\0') {
			add_validation_msg(&result, 1, "Port %d has empty interface name", i);
		}

		if (port->vlan_mode > 0) {
			int has_vlan = 0;
			for (int j = 0; j < profile.ingress_count; j++) {
				if (strcmp(profile.ingress_modules[j].name, "vlan") == 0) {
					has_vlan = 1;
					break;
				}
			}
			if (!has_vlan) {
				add_validation_msg(&result, 0,
					"Port '%s' has VLAN mode %d but no 'vlan' module in ingress pipeline",
					port->interface, port->vlan_mode);
			}
		}
	}

	for (int i = 0; i < profile.vlan_count; i++) {
		if (profile.vlans[i].vlan_id == 0 || profile.vlans[i].vlan_id > 4094)
			add_validation_msg(&result, 1, "Invalid VLAN ID %u", profile.vlans[i].vlan_id);
	}

	for (int i = 0; i < profile.ingress_count; i++) {
		for (int j = i + 1; j < profile.ingress_count; j++) {
			if (strcmp(profile.ingress_modules[i].name, profile.ingress_modules[j].name) == 0) {
				add_validation_msg(&result, 1,
					"Duplicate ingress module: '%s'",
					profile.ingress_modules[i].name);
			}
		}
	}

	for (int i = 0; i < profile.egress_count; i++) {
		for (int j = i + 1; j < profile.egress_count; j++) {
			if (strcmp(profile.egress_modules[i].name, profile.egress_modules[j].name) == 0) {
				add_validation_msg(&result, 1,
					"Duplicate egress module: '%s'",
					profile.egress_modules[i].name);
			}
		}
	}

	for (int i = 0; i < profile.ingress_count; i++) {
		if (profile.ingress_modules[i].optional &&
		    profile.ingress_modules[i].condition[0] != '\0' &&
		    !is_valid_optional_condition(profile.ingress_modules[i].condition)) {
			add_validation_msg(&result, 0,
				"Module '%s' uses unknown condition '%s'",
				profile.ingress_modules[i].name,
				profile.ingress_modules[i].condition);
		}
	}

	for (int i = 0; i < profile.egress_count; i++) {
		if (profile.egress_modules[i].optional &&
		    profile.egress_modules[i].condition[0] != '\0' &&
		    !is_valid_optional_condition(profile.egress_modules[i].condition)) {
			add_validation_msg(&result, 0,
				"Module '%s' uses unknown condition '%s'",
				profile.egress_modules[i].name,
				profile.egress_modules[i].condition);
		}
	}

output:
	if (json_output) {
		printf("{\"profile\":\"");
		json_print_escaped(profile_path);
		printf("\",\"valid\":%s,\"errors\":%d,\"warnings\":%d,\"messages\":[",
		       result.errors == 0 ? "true" : "false", result.errors, result.warnings);
		for (int i = 0; i < result.msg_count; i++) {
			printf("%s{\"level\":\"%s\",\"message\":\"",
			       i > 0 ? "," : "", result.is_error[i] ? "error" : "warning");
			json_print_escaped(result.messages[i]);
			printf("\"}");
		}
		printf("]}\n");
	} else {
		printf("Profile: %s\n", profile_path);
		printf("Name: %s\n", profile.name);
		printf("Modules: %d ingress, %d egress\n", profile.ingress_count,
		       profile.egress_count);
		printf("Ports: %d, VLANs: %d\n\n", profile.port_count, profile.vlan_count);

		for (int i = 0; i < result.msg_count; i++) {
			printf("  %s: %s\n", result.is_error[i] ? "ERROR" : "WARN",
			       result.messages[i]);
		}

		if (result.errors == 0 && result.warnings == 0) {
			printf("Profile is valid\n");
		} else {
			printf("\nResult: %d errors, %d warnings\n", result.errors, result.warnings);
		}
	}

	profile_free(&profile);
	return result.errors > 0 ? 1 : 0;
}

/* Show current state */
static int cmd_show_state(const char *state_map_pin)
{
	int fd = bpf_obj_get(state_map_pin);
	if (fd < 0) {
		RS_LOG_ERROR("Failed to open state_map: %s", strerror(errno));
		return -1;
	}
	
	struct voqd_state state;
	uint32_t key = 0;
	
	int ret = bpf_map_lookup_elem(fd, &key, &state);
	if (ret < 0) {
		RS_LOG_ERROR("Failed to read state: %s", strerror(errno));
		close(fd);
		return -1;
	}
	
	const char *mode_str[] = {"BYPASS", "SHADOW", "ACTIVE"};
	printf("VOQd State:\n");
	printf("  Mode: %s\n", mode_str[state.mode]);
	printf("  Running: %s\n", state.running ? "yes" : "no");
	printf("  Priority Mask: 0x%02x (", state.prio_mask);
	for (int i = 0; i < 4; i++) {
		if (state.prio_mask & (1 << i))
			printf("%d ", i);
	}
	printf(")\n");
	printf("  Flags: 0x%02x\n", state.flags);
	printf("    - Auto-failover: %s\n", (state.flags & VOQD_FLAG_AUTO_FAILOVER) ? "enabled" : "disabled");
	printf("    - Degrade on overload: %s\n", (state.flags & VOQD_FLAG_DEGRADE_ON_OVERLOAD) ? "enabled" : "disabled");
	printf("  Failover Count: %u\n", state.failover_count);
	printf("  Overload Drops: %u\n", state.overload_drops);
	
	close(fd);
	return 0;
}

static int cmd_show_neighbors(void)
{
	int fd;
	__u32 key;
	__u32 next;
	int has_key = 0;
	int count = 0;

	fd = bpf_obj_get(LLDP_NEIGHBOR_MAP_PATH);
	if (fd < 0) {
		RS_LOG_ERROR("Failed to open %s: %s", LLDP_NEIGHBOR_MAP_PATH, strerror(errno));
		return 1;
	}

	printf("LLDP Neighbors:\n\n");
	printf("%-8s %-18s %-18s %-20s %-6s %-18s\n",
	       "Ifindex", "Chassis ID", "Port ID", "System Name", "TTL", "Last Seen (ns)");
	printf("-----------------------------------------------------------------------------------------------\n");

	while (bpf_map_get_next_key(fd, has_key ? &key : NULL, &next) == 0) {
		struct lldp_neighbor neigh;

		if (bpf_map_lookup_elem(fd, &next, &neigh) == 0) {
			printf("%-8u %-18s %-18s %-20s %-6u %-18llu\n",
			       next,
			       neigh.chassis_id[0] ? neigh.chassis_id : "-",
			       neigh.port_id[0] ? neigh.port_id : "-",
			       neigh.system_name[0] ? neigh.system_name : "-",
			       neigh.ttl,
			       (unsigned long long)neigh.last_seen_ns);
			count++;
		}

		key = next;
		has_key = 1;
	}

	printf("\nTotal neighbors: %d\n", count);
	close(fd);
	return 0;
}

static int cmd_show_abi(void)
{
    printf("rSwitch ABI Version: %u.%u\n", RS_ABI_VERSION_MAJOR, RS_ABI_VERSION_MINOR);
    printf("Supported range: %u.%u - %u.%u\n",
           RS_ABI_VERSION_MAJOR, RS_ABI_VERSION_MINOR,
           RS_ABI_VERSION_MAJOR, RS_ABI_VERSION_MINOR);
    return 0;
}

static int read_loader_pid(pid_t *pid)
{
    FILE *fp;
    long val;

    if (!pid)
        return -1;

    fp = fopen(RSWITCH_PID_FILE, "r");
    if (!fp) {
        RS_LOG_ERROR("Failed to open %s: %s", RSWITCH_PID_FILE, strerror(errno));
        return -1;
    }

    if (fscanf(fp, "%ld", &val) != 1 || val <= 0) {
        fclose(fp);
        RS_LOG_ERROR("Invalid PID contents in %s", RSWITCH_PID_FILE);
        return -1;
    }

    fclose(fp);
    *pid = (pid_t)val;
    return 0;
}

static int write_shutdown_override(int drain_timeout)
{
    struct shutdown_override {
        uint32_t drain_timeout_sec;
        uint32_t reserved;
    } ov;
    FILE *fp;

    if (drain_timeout <= 0)
        return 0;

    memset(&ov, 0, sizeof(ov));
    ov.drain_timeout_sec = (uint32_t)drain_timeout;

    fp = fopen(RSWITCH_SHUTDOWN_OVERRIDE_FILE, "wb");
    if (!fp) {
        RS_LOG_WARN("Failed to write shutdown override %s: %s",
                    RSWITCH_SHUTDOWN_OVERRIDE_FILE, strerror(errno));
        return -1;
    }

    if (fwrite(&ov, sizeof(ov), 1, fp) != 1) {
        fclose(fp);
        RS_LOG_WARN("Failed to persist shutdown override to %s", RSWITCH_SHUTDOWN_OVERRIDE_FILE);
        return -1;
    }

    fclose(fp);
    return 0;
}

static int cmd_shutdown_loader(int argc, char **argv)
{
    int force = 0;
    int drain_timeout = -1;
    pid_t pid;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--force") == 0) {
            force = 1;
        } else if (strcmp(argv[i], "--drain-timeout") == 0 && i + 1 < argc) {
            drain_timeout = atoi(argv[++i]);
            if (drain_timeout <= 0) {
                RS_LOG_ERROR("--drain-timeout must be > 0");
                return 1;
            }
        } else {
            RS_LOG_ERROR("Unknown shutdown option: %s", argv[i]);
            return 1;
        }
    }

    if (read_loader_pid(&pid) != 0)
        return 1;

    if (kill(pid, 0) != 0) {
        RS_LOG_ERROR("rswitch_loader PID %d is not running", pid);
        return 1;
    }

    if (!force)
        write_shutdown_override(drain_timeout);

    if (kill(pid, force ? SIGKILL : SIGTERM) != 0) {
        RS_LOG_ERROR("Failed to send %s to PID %d: %s",
                     force ? "SIGKILL" : "SIGTERM", pid, strerror(errno));
        return 1;
    }

    RS_LOG_INFO("Sent %s to rswitch_loader PID %d%s",
                force ? "SIGKILL" : "SIGTERM",
                pid,
                (!force && drain_timeout > 0) ? " with drain override" : "");
    return 0;
}

static int cmd_show_profile(const char *profile_path, int resolved)
{
    struct rs_profile profile;
    int ret;

    if (!profile_path || profile_path[0] == '\0') {
        RS_LOG_ERROR("profile path required");
        return 1;
    }

    if (resolved)
        ret = profile_load_with_inheritance(profile_path, &profile);
    else
        ret = profile_load(profile_path, &profile);

    if (ret < 0) {
        RS_LOG_ERROR("Failed to load profile: %s", profile_path);
        return 1;
    }

    profile_print(&profile);
    if (resolved && profile.extends[0] != '\0')
        printf("\nResolved from: %s -> %s\n", profile.extends, profile_path);

    profile_free(&profile);
    return 0;
}

static int cmd_reload_module(const char *module_name, int dry_run)
{
    char cmd[512];
    int n;
    int rc;

    if (!module_name || module_name[0] == '\0') {
        RS_LOG_ERROR("module name required");
        return 1;
    }

    n = snprintf(cmd, sizeof(cmd), "./build/hot_reload -r %s%s",
                 module_name, dry_run ? " --dry-run" : "");
    if (n < 0 || n >= (int)sizeof(cmd)) {
        RS_LOG_ERROR("reload command too long for module: %s", module_name);
        return 1;
    }

    rc = system(cmd);
    if (rc < 0) {
        RS_LOG_ERROR("failed to execute hot_reload: %s", strerror(errno));
        return 1;
    }

    if (WIFEXITED(rc)) {
        return WEXITSTATUS(rc);
    }

    return 1;
}

static const char *map_flag_name(const char *name)
{
    if (strcmp(name, "NEED_L2L3_PARSE") == 0)
        return "RS_FLAG_NEED_L2L3_PARSE";
    if (strcmp(name, "NEED_VLAN_INFO") == 0)
        return "RS_FLAG_NEED_VLAN_INFO";
    if (strcmp(name, "NEED_FLOW_INFO") == 0)
        return "RS_FLAG_NEED_FLOW_INFO";
    if (strcmp(name, "MODIFIES_PACKET") == 0)
        return "RS_FLAG_MODIFIES_PACKET";
    if (strcmp(name, "MAY_DROP") == 0)
        return "RS_FLAG_MAY_DROP";
    if (strcmp(name, "CREATES_EVENTS") == 0)
        return "RS_FLAG_CREATES_EVENTS";
    return NULL;
}

static int cmd_new_module(const char *name, int stage, const char *hook, const char *flags_str)
{
    char bpf_path[512];
    char test_path[512];
    char profile_path[512];
    char flags_expr[512] = {0};
    FILE *f;
    int is_ingress;
    int is_egress;

    if (!name || strlen(name) == 0 || strlen(name) > 31) {
        fprintf(stderr, "Error: Module name must be 1-31 characters\n");
        return 1;
    }

    is_ingress = (strcmp(hook, "ingress") == 0);
    is_egress = (strcmp(hook, "egress") == 0);
    if (!is_ingress && !is_egress) {
        fprintf(stderr, "Error: hook must be 'ingress' or 'egress'\n");
        return 1;
    }
    if (is_ingress && (stage < 10 || stage > 99)) {
        fprintf(stderr, "Error: Ingress stage must be 10-99\n");
        return 1;
    }
    if (is_egress && (stage < 100 || stage > 199)) {
        fprintf(stderr, "Error: Egress stage must be 100-199\n");
        return 1;
    }

    if (flags_str && flags_str[0] != '\0') {
        char flags_copy[512];
        char *token;
        char *saveptr = NULL;
        int first = 1;

        if (strlen(flags_str) >= sizeof(flags_copy)) {
            fprintf(stderr, "Error: --flags string too long\n");
            return 1;
        }

        snprintf(flags_copy, sizeof(flags_copy), "%s", flags_str);
        token = strtok_r(flags_copy, ",", &saveptr);
        while (token) {
            const char *mapped = map_flag_name(token);
            size_t used = strlen(flags_expr);
            int n;

            if (!mapped) {
                fprintf(stderr, "Error: Unknown flag '%s'\n", token);
                return 1;
            }

            n = snprintf(flags_expr + used, sizeof(flags_expr) - used,
                         "%s%s", first ? "" : " | ", mapped);
            if (n < 0 || (size_t)n >= sizeof(flags_expr) - used) {
                fprintf(stderr, "Error: Parsed flags exceed internal buffer\n");
                return 1;
            }

            first = 0;
            token = strtok_r(NULL, ",", &saveptr);
        }
    }

    snprintf(bpf_path, sizeof(bpf_path), "bpf/modules/%s.bpf.c", name);
    if (access(bpf_path, F_OK) == 0) {
        fprintf(stderr, "Error: Module %s already exists at %s\n", name, bpf_path);
        return 1;
    }

    f = fopen(bpf_path, "w");
    if (!f) {
        fprintf(stderr, "Error: Cannot create %s: %s\n", bpf_path, strerror(errno));
        return 1;
    }

    fprintf(f, "// SPDX-License-Identifier: GPL-2.0\n");
    fprintf(f, "/*\n");
    fprintf(f, " * rSwitch Module: %s\n", name);
    fprintf(f, " * Generated by rswitchctl new-module\n");
    fprintf(f, " */\n\n");
    fprintf(f, "#include \"../include/rswitch_common.h\"\n");
    fprintf(f, "#include \"../core/module_abi.h\"\n\n");
    fprintf(f, "char _license[] SEC(\"license\") = \"GPL\";\n\n");

    fprintf(f, "RS_DECLARE_MODULE(\"%s\", %s, %d,\n",
            name,
            is_ingress ? "RS_HOOK_XDP_INGRESS" : "RS_HOOK_XDP_EGRESS",
            stage);
    if (flags_expr[0] != '\0')
        fprintf(f, "                  %s,\n", flags_expr);
    else
        fprintf(f, "                  0,\n");
    fprintf(f, "                  \"%s module\");\n\n", name);

    fprintf(f, "SEC(\"xdp\")\n");
    fprintf(f, "int %s_func(struct xdp_md *xdp_ctx)\n", name);
    fprintf(f, "{\n");
    fprintf(f, "    struct rs_ctx *ctx = RS_GET_CTX();\n");
    fprintf(f, "    if (!ctx)\n");
    fprintf(f, "        return XDP_DROP;\n\n");
    fprintf(f, "    /* TODO: Implement %s logic */\n\n", name);

    if (is_ingress) {
        fprintf(f, "    RS_TAIL_CALL_NEXT(xdp_ctx, ctx);\n");
        fprintf(f, "    return XDP_DROP;\n");
    } else {
        fprintf(f, "    RS_TAIL_CALL_EGRESS(xdp_ctx, ctx);\n");
        fprintf(f, "    return XDP_PASS;\n");
    }
    fprintf(f, "}\n");
    fclose(f);

    printf("Created: %s\n", bpf_path);

    snprintf(test_path, sizeof(test_path), "test/unit/test_%s.c", name);
    f = fopen(test_path, "w");
    if (!f) {
        fprintf(stderr, "Error: Cannot create %s: %s\n", test_path, strerror(errno));
        return 1;
    }
    fprintf(f, "// SPDX-License-Identifier: GPL-2.0\n");
    fprintf(f, "/* Unit tests for %s module */\n\n", name);
    fprintf(f, "#include \"rs_test.h\"\n");
    fprintf(f, "#include \"test_packets.h\"\n\n");
    fprintf(f, "static const char *MODULE_OBJ = \"build/bpf/%s.bpf.o\";\n\n", name);
    fprintf(f, "/* TODO: Add test cases for %s */\n\n", name);
    fprintf(f, "int main(void)\n");
    fprintf(f, "{\n");
    fprintf(f, "    printf(\"Tests for %s module (not yet implemented)\\n\");\n", name);
    fprintf(f, "    return 0;\n");
    fprintf(f, "}\n");
    fclose(f);
    printf("Created: %s\n", test_path);

    snprintf(profile_path, sizeof(profile_path), "etc/profiles/%s-example.yaml", name);
    f = fopen(profile_path, "w");
    if (!f) {
        fprintf(stderr, "Error: Cannot create %s: %s\n", profile_path, strerror(errno));
        return 1;
    }
    fprintf(f, "# Example profile using %s module\n", name);
    fprintf(f, "name: \"%s example\"\n", name);
    fprintf(f, "description: \"Profile demonstrating %s module\"\n\n", name);
    if (is_ingress) {
        fprintf(f, "ingress:\n");
        fprintf(f, "  - %s\n", name);
        fprintf(f, "  - lastcall\n\n");
    } else {
        fprintf(f, "egress:\n");
        fprintf(f, "  - %s\n", name);
        fprintf(f, "  - egress_final\n\n");
    }
    fprintf(f, "settings:\n");
    fprintf(f, "  stats_enabled: true\n");
    fclose(f);
    printf("Created: %s\n", profile_path);

    printf("\nNext steps:\n");
    printf("  1. Edit %s to implement your module logic\n", bpf_path);
    printf("  2. Add to Makefile BPF targets\n");
    printf("  3. Build: make all\n");
    printf("  4. Test: ./build/rswitch_loader -p etc/profiles/%s-example.yaml\n", name);

    return 0;
}

/* Set operating mode */
static int cmd_set_mode(const char *state_map_pin, const char *mode_str, int prio_mask)
{
	uint32_t mode;
	
	if (strcmp(mode_str, "bypass") == 0)
		mode = VOQD_MODE_BYPASS;
	else if (strcmp(mode_str, "shadow") == 0)
		mode = VOQD_MODE_SHADOW;
	else if (strcmp(mode_str, "active") == 0)
		mode = VOQD_MODE_ACTIVE;
	else {
		RS_LOG_ERROR("Invalid mode: %s (use bypass/shadow/active)", mode_str);
		return -1;
	}
	
	int fd = bpf_obj_get(state_map_pin);
	if (fd < 0) {
		RS_LOG_ERROR("Failed to open state_map: %s", strerror(errno));
		return -1;
	}
	
	struct voqd_state state;
	uint32_t key = 0;
	
	/* Read current state to preserve fields */
	int ret = bpf_map_lookup_elem(fd, &key, &state);
	if (ret < 0) {
		/* Initialize if not exists */
		memset(&state, 0, sizeof(state));
		state.flags = VOQD_FLAG_AUTO_FAILOVER | VOQD_FLAG_DEGRADE_ON_OVERLOAD;
	}
	
	/* Update mode */
	state.mode = mode;
	if (prio_mask >= 0)
		state.prio_mask = prio_mask;
	state.running = 1;  /* Assume VOQd is running if setting non-BYPASS mode */
	state.overload_drops = 0;  /* Reset on manual mode change */
	
	ret = bpf_map_update_elem(fd, &key, &state, BPF_ANY);
	if (ret < 0) {
		RS_LOG_ERROR("Failed to update state: %s", strerror(errno));
		close(fd);
		return -1;
	}
	
	printf("Mode set to %s", mode_str);
	if (prio_mask >= 0)
		printf(", priority mask=0x%02x", prio_mask);
	printf("\n");
	
	close(fd);
	return 0;
}

/* Set control flags */
static int cmd_set_flags(const char *state_map_pin, uint32_t flags)
{
	int fd = bpf_obj_get(state_map_pin);
	if (fd < 0) {
		RS_LOG_ERROR("Failed to open state_map: %s", strerror(errno));
		return -1;
	}
	
	struct voqd_state state;
	uint32_t key = 0;
	
	int ret = bpf_map_lookup_elem(fd, &key, &state);
	if (ret < 0) {
		RS_LOG_ERROR("Failed to read state: %s", strerror(errno));
		close(fd);
		return -1;
	}
	
	state.flags = flags;
	
	ret = bpf_map_update_elem(fd, &key, &state, BPF_ANY);
	if (ret < 0) {
		RS_LOG_ERROR("Failed to update state: %s", strerror(errno));
		close(fd);
		return -1;
	}
	
	printf("Flags set to 0x%02x\n", flags);
	printf("  Auto-failover: %s\n", (flags & VOQD_FLAG_AUTO_FAILOVER) ? "enabled" : "disabled");
	printf("  Degrade on overload: %s\n", (flags & VOQD_FLAG_DEGRADE_ON_OVERLOAD) ? "enabled" : "disabled");
	
	close(fd);
	return 0;
}

/* Reset failover statistics */
static int cmd_reset_stats(const char *state_map_pin)
{
	int fd = bpf_obj_get(state_map_pin);
	if (fd < 0) {
		RS_LOG_ERROR("Failed to open state_map: %s", strerror(errno));
		return -1;
	}
	
	struct voqd_state state;
	uint32_t key = 0;
	
	int ret = bpf_map_lookup_elem(fd, &key, &state);
	if (ret < 0) {
		RS_LOG_ERROR("Failed to read state: %s", strerror(errno));
		close(fd);
		return -1;
	}
	
	state.failover_count = 0;
	state.overload_drops = 0;
	
	ret = bpf_map_update_elem(fd, &key, &state, BPF_ANY);
	if (ret < 0) {
		RS_LOG_ERROR("Failed to update state: %s", strerror(errno));
		close(fd);
		return -1;
	}
	
	printf("Failover statistics reset\n");
	
	close(fd);
	return 0;
}

static int cmd_health(int json_output)
{
	struct rs_health_status status;
	char json_buf[4096];

	if (rs_watchdog_check_health(&status) != 0) {
		RS_LOG_ERROR("Health check failed");
		return 2;
	}

	if (json_output) {
		if (rs_watchdog_export_json(&status, json_buf, sizeof(json_buf)) != 0) {
			RS_LOG_ERROR("Failed to export health JSON");
			return 2;
		}
		printf("%s\n", json_buf);
		return status.overall;
	}

	printf("Health status: %s\n",
		status.overall == 0 ? "healthy" :
		(status.overall == 1 ? "degraded" : "critical"));
	printf("  BPF programs: %s\n", status.bpf_programs_ok ? "ok" : "failed");
	printf("  Maps: %s\n", status.maps_accessible ? "ok" : "failed");
	printf("  VOQd process: %s\n", status.voqd_running ? "running" : "not running");
	printf("  Counters: %s\n", status.counters_incrementing ? "incrementing" : "stalled");
	printf("  Uptime: %llu sec\n", (unsigned long long)status.uptime_sec);

	if (status.detail_count > 0) {
		printf("Details:\n");
		for (int i = 0; i < status.detail_count; i++)
			printf("  - %s\n", status.details[i]);
	}

	return status.overall;
}

int main(int argc, char **argv)
{
	const char *state_map_pin = DEFAULT_STATE_MAP_PIN;
	const char *command = NULL;
	const char *mode = NULL;
	int prio_mask = -1;
	uint32_t flags = 0;
	int mac_limit = 100;  /* Default limit for show-macs */
	int dry_run = 0;
	int json_output = 0;
	const char *module_filter = NULL;

	rs_log_init("rswitchctl", RS_LOG_LEVEL_INFO);
	
	static struct option long_options[] = {
		{"state-map", required_argument, 0, 's'},
		{"mode",      required_argument, 0, 'm'},
		{"prio-mask", required_argument, 0, 'p'},
		{"flags",     required_argument, 0, 'f'},
		{"limit",     required_argument, 0, 'l'},
		{"module",    required_argument, 0, 'M'},
		{"dry-run",   no_argument,       0, 'n'},
		{"json",      no_argument,       0, 'j'},
		{"help",      no_argument,       0, 'h'},
		{0, 0, 0, 0}
	};
	
	if (argc < 2) {
		goto usage;
	}
	
	command = argv[1];
	if (strcmp(command, "dev") == 0) {
		if (argc < 3) {
			fprintf(stderr,
				"Usage: %s dev <watch|trace|inspect|benchmark|verify|debug> [args]\n",
				argv[0]);
			return 1;
		}

		const char *dev_cmd = argv[2];
		if (strcmp(dev_cmd, "watch") == 0)
			return cmd_dev_watch(argc > 3 ? argv[3] : NULL);
		if (strcmp(dev_cmd, "trace") == 0)
			return cmd_dev_trace(argc > 3 ? argv[3] : NULL);
		if (strcmp(dev_cmd, "inspect") == 0)
			return cmd_dev_inspect(argc > 3 ? argv[3] : NULL);
		if (strcmp(dev_cmd, "benchmark") == 0)
			return cmd_dev_benchmark(argc > 3 ? argv[3] : NULL);
		if (strcmp(dev_cmd, "verify") == 0)
			return cmd_dev_verify(argc > 3 ? argv[3] : NULL);
		if (strcmp(dev_cmd, "debug") == 0)
			return cmd_dev_debug(argc > 3 ? argv[3] : NULL, argc > 4 ? argv[4] : NULL);

		fprintf(stderr, "Unknown dev command: %s\n", dev_cmd);
		fprintf(stderr,
			"Usage: %s dev <watch|trace|inspect|benchmark|verify|debug> [args]\n",
			argv[0]);
		return 1;
	}

	if (strcmp(command, "show-profile") == 0) {
		if (argc < 3) {
			fprintf(stderr, "Usage: %s show-profile <profile.yaml> [--resolved]\n", argv[0]);
			return 1;
		}
		return cmd_show_profile(argv[2], argc > 3 && strcmp(argv[3], "--resolved") == 0);
	}
	if (strcmp(command, "pack-module") == 0) {
		const char *output = NULL;

		if (argc < 3) {
			fprintf(stderr, "Usage: %s pack-module <module.bpf.o> [-o output.rsmod]\n", argv[0]);
			return 1;
		}

		for (int i = 3; i < argc; i++) {
			if (strcmp(argv[i], "-o") == 0 && i + 1 < argc)
				output = argv[++i];
		}

		return cmd_pack_module(argv[2], output);
	}
	if (strcmp(command, "install-module") == 0) {
		if (argc < 3) {
			fprintf(stderr, "Usage: %s install-module <package.rsmod>\n", argv[0]);
			return 1;
		}
		return cmd_install_module(argv[2]);
	}
	if (strcmp(command, "apply") == 0) {
		int timeout = ROLLBACK_DEFAULT_CONFIRM_TIMEOUT;
		if (argc < 3) {
			fprintf(stderr, "Usage: %s apply <profile.yaml> [--confirm-timeout <seconds>]\n", argv[0]);
			return 1;
		}
		for (int i = 3; i < argc; i++) {
			if (strcmp(argv[i], "--confirm-timeout") == 0 && i + 1 < argc)
				timeout = atoi(argv[++i]);
		}
		return rs_rollback_apply(argv[2], timeout);
	}
	if (strcmp(command, "confirm") == 0) {
		return rs_rollback_confirm();
	}
	if (strcmp(command, "rollback") == 0) {
		const char *sid = (argc >= 3) ? argv[2] : NULL;
		return rs_rollback_to(sid);
	}
	if (strcmp(command, "snapshot-list") == 0) {
		struct rs_snapshot_info snaps[ROLLBACK_MAX_SNAPSHOTS];
		int count = rs_rollback_list_snapshots(snaps, ROLLBACK_MAX_SNAPSHOTS);
		if (count < 0) {
			RS_LOG_ERROR("Failed to list snapshots");
			return 1;
		}
		if (count == 0) {
			printf("No snapshots found\n");
			return 0;
		}
		printf("%-20s %-10s %s\n", "Snapshot ID", "Confirmed", "Description");
		printf("%-20s %-10s %s\n", "---", "---", "---");
		for (int i = 0; i < count; i++) {
			printf("%-20s %-10s %s\n", snaps[i].id,
			       snaps[i].confirmed ? "yes" : "no",
			       snaps[i].description);
		}
		return 0;
	}
	if (strcmp(command, "snapshot-create") == 0) {
		const char *desc = (argc >= 3) ? argv[2] : "manual snapshot";
		return rs_rollback_create_snapshot(desc);
	}
	if (strcmp(command, "show-topology") == 0) {
		struct rs_topology topo;
		memset(&topo, 0, sizeof(topo));
		if (rs_topology_discover(&topo) < 0) {
			RS_LOG_ERROR("Topology discovery failed");
			return 1;
		}
		int json = 0;
		for (int i = 2; i < argc; i++) {
			if (strcmp(argv[i], "--json") == 0) json = 1;
		}
		if (json)
			rs_topology_print_json(&topo);
		else
			rs_topology_print(&topo);
		return 0;
	}
	if (strcmp(command, "audit-log") == 0) {
		int max_entries = 50;
		if (argc >= 3) max_entries = atoi(argv[2]);
		if (max_entries <= 0) max_entries = 50;
		if (max_entries > 100) max_entries = 100;
		struct rs_audit_entry entries[100];
		int count = rs_audit_read(entries, max_entries);
		if (count < 0) {
			RS_LOG_ERROR("Failed to read audit log");
			return 1;
		}
		if (count == 0) {
			printf("No audit entries found\n");
			return 0;
		}
		printf("%-20s %-8s %-10s %-16s %-8s %s\n",
		       "Timestamp", "Sev", "Category", "Action", "Result", "Detail");
		printf("%-20s %-8s %-10s %-16s %-8s %s\n",
		       "---", "---", "---", "---", "---", "---");
		for (int i = 0; i < count; i++) {
			char ts[32];
			time_t t = (time_t)entries[i].timestamp;
			struct tm *tm = localtime(&t);
			strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm);
			const char *sev = entries[i].severity == AUDIT_SEV_CRITICAL ? "CRIT" :
			                  entries[i].severity == AUDIT_SEV_WARNING ? "WARN" : "INFO";
			printf("%-20s %-8s %-10s %-16s %-8s %s\n",
			       ts, sev, entries[i].category, entries[i].action,
			       entries[i].success ? "OK" : "FAIL",
			       entries[i].detail);
		}
		return 0;
	}
	if (strcmp(command, "audit-rotate") == 0) {
		return rs_audit_rotate();
	}
	if (strcmp(command, "module") == 0) {
		if (argc < 3) {
			fprintf(stderr, "Usage: %s module <search|install|publish|info|update-index> [args]\n", argv[0]);
			return 1;
		}
		const char *mod_cmd = argv[2];
		if (strcmp(mod_cmd, "search") == 0) {
			if (argc < 4) {
				fprintf(stderr, "Usage: %s module search <query>\n", argv[0]);
				return 1;
			}
			struct rs_registry_entry results[REGISTRY_MAX_RESULTS];
			int count = rs_registry_search(argv[3], results, REGISTRY_MAX_RESULTS);
			if (count < 0) {
				RS_LOG_ERROR("Registry search failed");
				return 1;
			}
			if (count == 0) {
				printf("No modules found matching '%s'\n", argv[3]);
				return 0;
			}
			printf("%-20s %-10s %-8s %6s %-8s %s\n", "Name", "Version", "ABI", "Stage", "Hook", "Description");
			printf("%-20s %-10s %-8s %6s %-8s %s\n", "----", "-------", "---", "-----", "----", "-----------");
			for (int i = 0; i < count; i++) {
				printf("%-20s %-10s %-8s %6u %-8s %s\n",
					results[i].name, results[i].version, results[i].abi_version,
					results[i].stage, results[i].hook, results[i].description);
			}
			printf("\n%d module(s) found\n", count);
			return 0;
		}
		if (strcmp(mod_cmd, "install") == 0) {
			const char *ver = NULL;
			if (argc < 4) {
				fprintf(stderr, "Usage: %s module install <name>[@version]\n", argv[0]);
				return 1;
			}
			char name_buf[64];
			strncpy(name_buf, argv[3], sizeof(name_buf) - 1);
			name_buf[sizeof(name_buf) - 1] = '\0';
			char *at = strchr(name_buf, '@');
			if (at) {
				*at = '\0';
				ver = at + 1;
			}
			return rs_registry_install(name_buf, ver);
		}
		if (strcmp(mod_cmd, "publish") == 0) {
			if (argc < 4) {
				fprintf(stderr, "Usage: %s module publish <package.rsmod>\n", argv[0]);
				return 1;
			}
			return rs_registry_publish(argv[3]);
		}
		if (strcmp(mod_cmd, "info") == 0) {
			if (argc < 4) {
				fprintf(stderr, "Usage: %s module info <name>\n", argv[0]);
				return 1;
			}
			struct rs_registry_entry entry;
			if (rs_registry_info(argv[3], &entry) != 0) {
				RS_LOG_ERROR("Module '%s' not found in registry", argv[3]);
				return 1;
			}
			printf("Name: %s\nVersion: %s\nABI: %s\nAuthor: %s\nStage: %u\nHook: %s\nFlags: %u\nLicense: %s\nDescription: %s\nChecksum: %s\n",
				entry.name, entry.version, entry.abi_version, entry.author,
				entry.stage, entry.hook, entry.flags, entry.license,
				entry.description, entry.checksum);
			return 0;
		}
		if (strcmp(mod_cmd, "update-index") == 0)
			return rs_registry_update_index();

		fprintf(stderr, "Unknown module command: %s\n", mod_cmd);
		return 1;
	}
	if (strcmp(command, "new-module") == 0) {
		const char *mod_name;
		int stage = -1;
		const char *hook = "ingress";
		const char *module_flags = "";

		if (argc < 3) {
			fprintf(stderr, "Usage: %s new-module <name> --stage <N> --hook <ingress|egress> [--flags FLAG1,FLAG2]\n", argv[0]);
			return 1;
		}

		mod_name = argv[2];
		for (int i = 3; i < argc; i++) {
			if (strcmp(argv[i], "--stage") == 0 && i + 1 < argc) {
				stage = atoi(argv[++i]);
			} else if (strcmp(argv[i], "--hook") == 0 && i + 1 < argc) {
				hook = argv[++i];
			} else if (strcmp(argv[i], "--flags") == 0 && i + 1 < argc) {
				module_flags = argv[++i];
			} else {
				fprintf(stderr, "Error: Unknown argument '%s'\n", argv[i]);
				fprintf(stderr, "Usage: %s new-module <name> --stage <N> --hook <ingress|egress> [--flags FLAG1,FLAG2]\n", argv[0]);
				return 1;
			}
		}

		if (stage < 0) {
			fprintf(stderr, "Error: --stage is required\n");
			return 1;
		}

		return cmd_new_module(mod_name, stage, hook, module_flags);
	}

	if (strcmp(command, "mirror-session") == 0)
		return cmd_mirror_session(argc, argv);

	if (strcmp(command, "shutdown") == 0)
		return cmd_shutdown_loader(argc - 2, argv + 2);

	optind = 2;  /* Start parsing from second argument */
	
	int opt;
	while ((opt = getopt_long(argc, argv, "s:m:p:f:l:M:njh", long_options, NULL)) != -1) {
		switch (opt) {
		case 's':
			state_map_pin = optarg;
			break;
		case 'm':
			mode = optarg;
			break;
		case 'p':
			prio_mask = strtoul(optarg, NULL, 0);
			break;
		case 'f':
			flags = strtoul(optarg, NULL, 0);
			break;
		case 'l':
			mac_limit = atoi(optarg);
			break;
		case 'M':
			module_filter = optarg;
			break;
		case 'n':
			dry_run = 1;
			break;
		case 'j':
			json_output = 1;
			break;
		case 'h':
		default:
			goto usage;
		}
	}
	
	/* Execute command */
	if (strcmp(command, "show") == 0 || strcmp(command, "status") == 0) {
		return cmd_show_state(state_map_pin);
	}
	else if (strcmp(command, "set-mode") == 0) {
		if (!mode) {
			RS_LOG_ERROR("--mode required");
			return 1;
		}
		return cmd_set_mode(state_map_pin, mode, prio_mask);
	}
	else if (strcmp(command, "set-flags") == 0) {
		return cmd_set_flags(state_map_pin, flags);
	}
	else if (strcmp(command, "reset-stats") == 0) {
		return cmd_reset_stats(state_map_pin);
	}
	/* Extended commands */
	else if (strcmp(command, "list-modules") == 0) {
		return cmd_list_available_modules();
	}
	else if (strcmp(command, "list-loaded-modules") == 0) {
		return cmd_list_modules();
	}
	else if (strcmp(command, "show-pipeline") == 0) {
		return cmd_show_pipeline();
	}
	else if (strcmp(command, "show-ports") == 0) {
		return cmd_show_ports();
	}
	else if (strcmp(command, "show-macs") == 0) {
		return cmd_show_macs(mac_limit);
	}
	else if (strcmp(command, "show-neighbors") == 0) {
		return cmd_show_neighbors();
	}
	else if (strcmp(command, "show-stats") == 0) {
		return cmd_show_stats(module_filter, json_output ? "json" : "text");
	}
	else if (strcmp(command, "health") == 0) {
		return cmd_health(json_output);
	}
	else if (strcmp(command, "flush-macs") == 0) {
		return cmd_flush_macs();
	}
	else if (strcmp(command, "get-telemetry") == 0) {
		return cmd_get_telemetry();
	}
	else if (strcmp(command, "show-abi") == 0) {
		return cmd_show_abi();
	}
	else if (strcmp(command, "reload") == 0) {
		if (optind >= argc) {
			fprintf(stderr, "Usage: %s reload <module_name> [--dry-run]\n", argv[0]);
			return 1;
		}
		return cmd_reload_module(argv[optind], dry_run);
	}
	else if (strcmp(command, "validate-profile") == 0) {
		if (optind >= argc) {
			fprintf(stderr, "Usage: %s validate-profile <profile.yaml> [--json]\n", argv[0]);
			return 1;
		}
		return cmd_validate_profile(argv[optind], json_output);
	}
	/* ACL commands */
	else if (strcmp(command, "acl-add-rule") == 0) {
		return cmd_acl_add_rule(argc - optind, argv + optind);
	}
	else if (strcmp(command, "acl-del-rule") == 0) {
		if (optind >= argc) {
			RS_LOG_ERROR("rule ID required");
			return 1;
		}
		return cmd_acl_del_rule(atoi(argv[optind]));
	}
	else if (strcmp(command, "acl-show-rules") == 0) {
		return cmd_acl_show_rules();
	}
	else if (strcmp(command, "acl-show-stats") == 0) {
		return cmd_acl_show_stats();
	}
	else if (strcmp(command, "acl-enable") == 0) {
		return cmd_acl_enable(1);
	}
	else if (strcmp(command, "acl-disable") == 0) {
		return cmd_acl_enable(0);
	}
	/* Mirror commands */
	else if (strcmp(command, "mirror-enable") == 0) {
		uint32_t span_port = 0;
		if (optind < argc)
			span_port = atoi(argv[optind]);
		return cmd_mirror_enable(1, span_port);
	}
	else if (strcmp(command, "mirror-disable") == 0) {
		return cmd_mirror_enable(0, 0);
	}
	else if (strcmp(command, "mirror-set-span") == 0) {
		if (optind >= argc) {
			RS_LOG_ERROR("SPAN port required");
			return 1;
		}
		return cmd_mirror_set_span_port(atoi(argv[optind]));
	}
	else if (strcmp(command, "mirror-set-port") == 0) {
		if (optind >= argc) {
			RS_LOG_ERROR("port ifindex required");
			return 1;
		}
		uint32_t ifindex = atoi(argv[optind]);
		int ingress = -1, egress = -1;
		
		for (int i = optind + 1; i < argc; i++) {
			if (strcmp(argv[i], "--ingress") == 0)
				ingress = 1;
			else if (strcmp(argv[i], "--no-ingress") == 0)
				ingress = 0;
			else if (strcmp(argv[i], "--egress") == 0)
				egress = 1;
			else if (strcmp(argv[i], "--no-egress") == 0)
				egress = 0;
		}
		return cmd_mirror_set_port(ifindex, ingress, egress);
	}
	else if (strcmp(command, "mirror-show-config") == 0) {
		return cmd_mirror_show_config();
	}
	else if (strcmp(command, "mirror-show-stats") == 0) {
		return cmd_mirror_show_stats();
	}
	else {
		RS_LOG_ERROR("Unknown command: %s", command);
		goto usage;
	}
	
usage:
	printf("Usage: %s <command> [options]\n", argv[0]);
	printf("\n");
	printf("VOQd State Commands:\n");
	printf("  show, status              Show current VOQd state\n");
	printf("  set-mode                  Set operating mode\n");
	printf("  set-flags                 Set control flags\n");
	printf("  reset-stats               Reset failover statistics\n");
	printf("\n");
	printf("Inspection Commands:\n");
	printf("  list-modules              List available module objects in build/bpf\n");
	printf("  list-loaded-modules       List loaded BPF programs from bpffs\n");
	printf("  pack-module <obj> [-o p]  Package module object into .rsmod\n");
	printf("  install-module <pkg>      Install .rsmod into build/bpf\n");
	printf("\n");
	printf("Configuration Rollback Commands:\n");
	printf("  apply <profile> [--confirm-timeout <sec>]  Apply profile with auto-rollback safety\n");
	printf("  confirm                    Confirm applied config (cancel auto-rollback)\n");
	printf("  rollback [snapshot-id]     Rollback to snapshot (latest if no ID)\n");
	printf("  snapshot-list              List configuration snapshots\n");
	printf("  snapshot-create [desc]     Create manual snapshot of current config\n");
	printf("\n");
	printf("Module Registry Commands:\n");
	printf("  module search <query>     Search module registry index\n");
	printf("  module info <name>        Show detailed module metadata\n");
	printf("  module install <n[@v]>    Install module from registry\n");
	printf("  module publish <pkg>      Publish .rsmod into local registry\n");
	printf("  module update-index       Refresh registry index from local sources\n");
	printf("\n");
	printf("Audit Commands:\n");
	printf("  audit-log [max]           Show recent audit log entries (default: 50)\n");
	printf("  audit-rotate              Rotate audit log (archive current)\n");
	printf("Topology Commands:\n");
	printf("  show-topology [--json]    Show discovered network topology\n");
	printf("\n");
	printf("  show-pipeline             Show tail-call pipeline\n");
	printf("  show-ports                Show port configurations\n");
	printf("  show-macs                 Show MAC table (use --limit N)\n");
	printf("  show-neighbors            Show LLDP neighbors learned by lldpd\n");
	printf("  shutdown [--drain-timeout N] [--force]  Shutdown rswitch_loader\n");
	printf("  show-stats                Show interface and module statistics\n");
	printf("  health                    Run health checks for core components\n");
	printf("  flush-macs                Flush dynamic MAC entries\n");
	printf("  get-telemetry             Get comprehensive telemetry\n");
	printf("  show-abi                  Show platform ABI version support\n");
	printf("  show-profile <file> [--resolved]  Show profile YAML contents\n");
	printf("  new-module <name> --stage <N> --hook <ingress|egress> [--flags A,B]  Generate module scaffolding\n");
	printf("  reload <module>           Hot-reload module via hot_reload binary\n");
	printf("  validate-profile <file>   Offline profile validation (use --json for CI)\n");
	printf("\n");
	printf("Developer Commands:\n");
	printf("  dev watch <module>        Auto-rebuild and hot-reload module source changes\n");
	printf("  dev trace <module>        Stream module events from rs_event_bus\n");
	printf("  dev inspect <module>      Show loaded program info, maps, stats, config\n");
	printf("  dev benchmark <profile>   Run 5-second profile throughput benchmark\n");
	printf("  dev verify <module.o>     Offline verifier check and verifier logs\n");
	printf("  dev debug <module.o> [pcap]  Interactive module debugger with JSON trace\n");
	printf("\n");
	printf("ACL Commands:\n");
	printf("  acl-add-rule              Add ACL rule (use --id, --src, --dst, --action, etc.)\n");
	printf("  acl-del-rule <id>         Delete ACL rule by ID\n");
	printf("  acl-show-rules            Show all ACL rules\n");
	printf("  acl-show-stats            Show ACL statistics\n");
	printf("  acl-enable                Enable ACL processing\n");
	printf("  acl-disable               Disable ACL processing\n");
	printf("\n");
	printf("Mirror Commands:\n");
	printf("  mirror-enable [port]      Enable mirroring with optional SPAN port\n");
	printf("  mirror-disable            Disable mirroring\n");
	printf("  mirror-set-span <port>    Set SPAN destination port\n");
	printf("  mirror-set-port <if> ...  Configure per-port mirroring (--ingress, --egress)\n");
	printf("  mirror-show-config        Show mirror configuration\n");
	printf("  mirror-show-stats         Show mirror statistics\n");
	printf("  mirror-session add <id> --type <span|rspan|erspan> --dest-port <if> [--rspan-vlan <id>] [--truncate <bytes>]\n");
	printf("  mirror-session del <id>   Delete mirror session\n");
	printf("  mirror-session show       Show all mirror sessions\n");
	printf("  mirror-session stats      Show per-session mirror counters\n");
	printf("\n");
	printf("Options:\n");
	printf("  -s, --state-map PATH      Path to pinned state_map (default: %s)\n", DEFAULT_STATE_MAP_PIN);
	printf("  -m, --mode MODE           Operating mode: bypass/shadow/active\n");
	printf("  -p, --prio-mask MASK      Priority interception mask (hex)\n");
	printf("  -f, --flags FLAGS         Control flags (hex)\n");
	printf("  -l, --limit N             Limit for show-macs (default: 100)\n");
	printf("  -M, --module NAME         Filter show-stats output to one module\n");
	printf("  -n, --dry-run             Validate reload without applying\n");
	printf("  -j, --json                Output JSON where supported (health, validate-profile)\n");
	printf("  -h, --help                Show this help\n");
	printf("\n");
	printf("Examples:\n");
	printf("  %s show\n", argv[0]);
	printf("  %s set-mode --mode shadow --prio-mask 0x0C\n", argv[0]);
	printf("  %s set-mode --mode active --prio-mask 0x0F\n", argv[0]);
	printf("  %s set-flags --flags 0x03  # Enable auto-failover + degrade-on-overload\n", argv[0]);
	printf("  %s reset-stats\n", argv[0]);
	printf("  %s list-modules\n", argv[0]);
	printf("  %s list-loaded-modules\n", argv[0]);
	printf("  %s health\n", argv[0]);
	printf("  %s health --json\n", argv[0]);
	printf("  %s pack-module ./build/bpf/vlan.bpf.o\n", argv[0]);
	printf("  %s pack-module ./build/bpf/vlan.bpf.o -o vlan.rsmod\n", argv[0]);
	printf("  %s install-module ./vlan.rsmod\n", argv[0]);
	printf("  %s show-pipeline\n", argv[0]);
	printf("  %s show-macs --limit 50\n", argv[0]);
	printf("  %s show-stats --module acl\n", argv[0]);
	printf("  %s shutdown\n", argv[0]);
	printf("  %s shutdown --drain-timeout 60\n", argv[0]);
	printf("  %s shutdown --force\n", argv[0]);
	printf("  %s show-stats --json\n", argv[0]);
	printf("  %s show-profile ./etc/profiles/l3.yaml\n", argv[0]);
	printf("  %s show-profile ./etc/profiles/l3.yaml --resolved\n", argv[0]);
	printf("  %s new-module sample --stage 35 --hook ingress --flags NEED_L2L3_PARSE,MAY_DROP\n", argv[0]);
	printf("  %s reload vlan\n", argv[0]);
	printf("  %s reload vlan --dry-run\n", argv[0]);
	printf("  %s validate-profile ./etc/profiles/l2.yaml\n", argv[0]);
	printf("  %s validate-profile ./etc/profiles/l2.yaml --json\n", argv[0]);
	printf("  %s dev watch vlan\n", argv[0]);
	printf("  %s dev trace acl\n", argv[0]);
	printf("  %s dev inspect mirror\n", argv[0]);
	printf("  %s dev benchmark ./etc/profiles/l3.yaml\n", argv[0]);
	printf("  %s dev verify ./build/bpf/vlan.bpf.o\n", argv[0]);
	printf("  %s dev debug ./build/bpf/acl.bpf.o ./tmp/test.pcap\n", argv[0]);
	printf("  %s flush-macs\n", argv[0]);
	printf("\n");
	printf("ACL Examples:\n");
	printf("  %s acl-add-rule --id 10 --src 192.168.1.0/24 --dst-port 80 --action pass --priority 100\n", argv[0]);
	printf("  %s acl-add-rule --id 20 --src 10.0.0.0/8 --action drop --priority 200\n", argv[0]);
	printf("  %s acl-del-rule 10\n", argv[0]);
	printf("  %s acl-show-rules\n", argv[0]);
	printf("  %s acl-enable\n", argv[0]);
	printf("\n");
	printf("Mirror Examples:\n");
	printf("  %s mirror-enable 5  # Enable with SPAN port 5\n", argv[0]);
	printf("  %s mirror-set-port 3 --ingress --egress\n", argv[0]);
	printf("  %s mirror-show-config\n", argv[0]);
	printf("  %s mirror-session add 0 --type span --dest-port eth1\n", argv[0]);
	printf("  %s mirror-session add 1 --type rspan --dest-port eth2 --rspan-vlan 200 --truncate 256\n", argv[0]);
	printf("  %s mirror-session show\n", argv[0]);
	printf("  %s mirror-session stats\n", argv[0]);
	printf("  %s mirror-disable\n", argv[0]);
	printf("\n");
	printf("Flags:\n");
	printf("  0x01  VOQD_FLAG_AUTO_FAILOVER       Auto-failover on heartbeat timeout\n");
	printf("  0x02  VOQD_FLAG_DEGRADE_ON_OVERLOAD Degrade to BYPASS on overload\n");
	printf("  0x04  VOQD_FLAG_STRICT_PRIORITY     Enforce strict priority\n");
	return 1;
}
