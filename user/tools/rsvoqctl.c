/* SPDX-License-Identifier: GPL-2.0 */
/* rsvoqctl - VOQd Control Tool for rSwitch
 * 
 * Manages AF_XDP Virtual Output Queue daemon:
 * - Start/stop VOQd
 * - Change operating mode (BYPASS/SHADOW/ACTIVE)
 * - Configure priority mask
 * - View queue statistics
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <ctype.h>
#if __has_include("rs_log.h")
#include "rs_log.h"
#else
#include "../common/rs_log.h"
#endif

#include "../../bpf/core/afxdp_common.h"
#include "../voqd/shaper.h"

#define PIN_BASE_DIR "/sys/fs/bpf"
#define VOQD_STATE_MAP_PATH PIN_BASE_DIR "/voqd_state_map"
#define QDEPTH_MAP_PATH PIN_BASE_DIR "/qdepth_map"

static const char *mode_to_str(__u32 mode)
{
	switch (mode) {
	case VOQD_MODE_BYPASS: return "BYPASS";
	case VOQD_MODE_SHADOW: return "SHADOW";
	case VOQD_MODE_ACTIVE: return "ACTIVE";
	default: return "UNKNOWN";
	}
}

static const char *priority_to_str(int prio)
{
	switch (prio) {
	case QOS_PRIO_LOW: return "low";
	case QOS_PRIO_NORMAL: return "normal";
	case QOS_PRIO_HIGH: return "high";
	case QOS_PRIO_CRITICAL: return "critical";
	default: return "unknown";
	}
}

static void usage(const char *prog)
{
	fprintf(stderr, "Usage: %s <command> [options]\n\n", prog);
	fprintf(stderr, "Commands:\n");
	fprintf(stderr, "  bypass                   Set BYPASS mode (fast-path only)\n");
	fprintf(stderr, "  shadow                   Set SHADOW mode (observe, don't intercept)\n");
	fprintf(stderr, "  activate <prio-mask>     Set ACTIVE mode with priority mask\n");
	fprintf(stderr, "                           prio-mask: hex (e.g., 0xC for HIGH+CRITICAL)\n");
	fprintf(stderr, "  status                   Show VOQd status\n");
	fprintf(stderr, "  queues                   Show per-priority queue depths\n");
	fprintf(stderr, "  heartbeat                Send heartbeat (update timestamp)\n");
	fprintf(stderr, "  set-shaper ...           Configure port/queue traffic shaper\n");
	fprintf(stderr, "  disable-shaper ...       Disable shaper for a port\n");
	fprintf(stderr, "  show-shaper [opts]       Show shaper configuration\n");
	fprintf(stderr, "  set-wfq ...              Configure WFQ weights for a port\n");
	fprintf(stderr, "  show-wfq                 Show WFQ configuration\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Priority Mask (bitmask):\n");
	fprintf(stderr, "  0x1 (0b0001) - LOW\n");
	fprintf(stderr, "  0x2 (0b0010) - NORMAL\n");
	fprintf(stderr, "  0x4 (0b0100) - HIGH\n");
	fprintf(stderr, "  0x8 (0b1000) - CRITICAL\n");
	fprintf(stderr, "  0xC (0b1100) - HIGH + CRITICAL (typical)\n");
	fprintf(stderr, "  0xF (0b1111) - All priorities\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Examples:\n");
	fprintf(stderr, "  %s bypass\n", prog);
	fprintf(stderr, "  %s shadow\n", prog);
	fprintf(stderr, "  %s activate 0xC\n", prog);
	fprintf(stderr, "  %s status\n", prog);
	fprintf(stderr, "  %s set-shaper --port port0 --rate 1000 --burst 256\n", prog);
	fprintf(stderr, "  %s set-shaper --port port0 --queue 2 --rate 200 --burst 64\n", prog);
	fprintf(stderr, "  %s set-wfq --port port0 --weights 1,2,4,8\n", prog);
}

static int parse_port_idx(const char *ifname, uint32_t *port_idx)
{
	if (!ifname || !port_idx) {
		return -1;
	}

	if (strncmp(ifname, "port", 4) == 0) {
		char *end = NULL;
		unsigned long val = strtoul(ifname + 4, &end, 10);
		if (!end || *end != '\0' || val >= RS_SHAPER_MAX_PORTS) {
			return -1;
		}
		*port_idx = (uint32_t)val;
		return 0;
	}

	if (isdigit((unsigned char)ifname[0])) {
		char *end = NULL;
		unsigned long val = strtoul(ifname, &end, 10);
		if (!end || *end != '\0' || val >= RS_SHAPER_MAX_PORTS) {
			return -1;
		}
		*port_idx = (uint32_t)val;
		return 0;
	}

	return -1;
}

static int parse_weights(const char *weights_str, uint32_t weights[RS_SHAPER_WFQ_MAX_QUEUES], int *count)
{
	char *input;
	char *tok;
	int idx = 0;

	if (!weights_str || !weights || !count) {
		return -1;
	}

	input = strdup(weights_str);
	if (!input) {
		return -1;
	}

	tok = strtok(input, ",");
	while (tok && idx < RS_SHAPER_WFQ_MAX_QUEUES) {
		unsigned long w = strtoul(tok, NULL, 10);
		if (w == 0 || w > 1000000UL) {
			free(input);
			return -1;
		}
		weights[idx++] = (uint32_t)w;
		tok = strtok(NULL, ",");
	}

	free(input);
	*count = idx;
	return idx > 0 ? 0 : -1;
}

static int cmd_set_shaper(int argc, char **argv)
{
	const char *port_name = NULL;
	uint32_t port_idx = 0;
	int queue = -1;
	uint64_t rate_mbps = 0;
	uint64_t burst_kb = 0;
	struct rs_shaper_shared_cfg *cfg = NULL;

	for (int i = 0; i < argc; i++) {
		if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
			port_name = argv[++i];
		} else if (strcmp(argv[i], "--queue") == 0 && i + 1 < argc) {
			queue = atoi(argv[++i]);
		} else if (strcmp(argv[i], "--rate") == 0 && i + 1 < argc) {
			rate_mbps = strtoull(argv[++i], NULL, 10);
		} else if (strcmp(argv[i], "--burst") == 0 && i + 1 < argc) {
			burst_kb = strtoull(argv[++i], NULL, 10);
		} else {
			RS_LOG_ERROR("Unknown set-shaper option: %s", argv[i]);
			return -1;
		}
	}

	if (!port_name || rate_mbps == 0 || burst_kb == 0) {
		RS_LOG_ERROR("set-shaper requires --port --rate --burst");
		return -1;
	}
	if (queue >= RS_SHAPER_WFQ_MAX_QUEUES) {
		RS_LOG_ERROR("queue must be in range 0-%d", RS_SHAPER_WFQ_MAX_QUEUES - 1);
		return -1;
	}
	if (parse_port_idx(port_name, &port_idx) < 0) {
		RS_LOG_ERROR("Invalid port name '%s' (use portN or index)", port_name);
		return -1;
	}

	if (rs_shaper_shared_open(&cfg, 1) < 0 || !cfg) {
		return -1;
	}

	if (port_idx >= cfg->num_ports) {
		RS_LOG_ERROR("Port index %u out of range (num_ports=%u)", port_idx, cfg->num_ports);
		rs_shaper_shared_close(cfg);
		return -1;
	}

	uint64_t rate_bps = rate_mbps * 1000000ULL;
	uint64_t burst_bytes = burst_kb * 1024ULL;

	if (queue >= 0) {
		cfg->ports[port_idx].queue_cfg[queue].rate_bps = rate_bps;
		cfg->ports[port_idx].queue_cfg[queue].burst_bytes = burst_bytes;
		cfg->ports[port_idx].queue_cfg[queue].enabled = 1;
		printf("Queue shaper set: port=%u queue=%d rate=%lu Mbps burst=%lu KB\n",
		       port_idx, queue, rate_mbps, burst_kb);
	} else {
		cfg->ports[port_idx].rate_bps = rate_bps;
		cfg->ports[port_idx].burst_bytes = burst_bytes;
		cfg->ports[port_idx].enabled = 1;
		printf("Port shaper set: port=%u rate=%lu Mbps burst=%lu KB\n",
		       port_idx, rate_mbps, burst_kb);
	}

	cfg->generation++;
	rs_shaper_shared_close(cfg);
	return 0;
}

static int cmd_disable_shaper(int argc, char **argv)
{
	const char *port_name = NULL;
	uint32_t port_idx = 0;
	struct rs_shaper_shared_cfg *cfg = NULL;

	for (int i = 0; i < argc; i++) {
		if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
			port_name = argv[++i];
		}
	}

	if (!port_name || parse_port_idx(port_name, &port_idx) < 0) {
		RS_LOG_ERROR("disable-shaper requires --port <portN>");
		return -1;
	}

	if (rs_shaper_shared_open(&cfg, 1) < 0 || !cfg) {
		return -1;
	}

	if (port_idx >= cfg->num_ports) {
		RS_LOG_ERROR("Port index %u out of range (num_ports=%u)", port_idx, cfg->num_ports);
		rs_shaper_shared_close(cfg);
		return -1;
	}

	memset(&cfg->ports[port_idx], 0, sizeof(cfg->ports[port_idx]));
	cfg->generation++;
	printf("Disabled all shapers/WFQ on port=%u\n", port_idx);
	rs_shaper_shared_close(cfg);
	return 0;
}

static int cmd_show_shaper(int argc, char **argv)
{
	const char *port_name = NULL;
	uint32_t req_port = 0;
	struct rs_shaper_shared_cfg *cfg = NULL;

	for (int i = 0; i < argc; i++) {
		if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
			port_name = argv[++i];
		}
	}

	if (port_name && parse_port_idx(port_name, &req_port) < 0) {
		RS_LOG_ERROR("Invalid port name '%s'", port_name);
		return -1;
	}

	if (rs_shaper_shared_open(&cfg, 0) < 0 || !cfg) {
		RS_LOG_ERROR("No shaper configuration found");
		return -1;
	}

	printf("Shaper Config: version=%u generation=%u num_ports=%u\n",
	       cfg->version, cfg->generation, cfg->num_ports);

	for (uint32_t p = 0; p < cfg->num_ports; p++) {
		if (port_name && p != req_port) {
			continue;
		}
		struct rs_shaper_port_cfg *pcfg = &cfg->ports[p];
		if (!pcfg->enabled && !port_name) {
			int queue_enabled = 0;
			for (int q = 0; q < RS_SHAPER_WFQ_MAX_QUEUES; q++) {
				if (pcfg->queue_cfg[q].enabled) {
					queue_enabled = 1;
					break;
				}
			}
			if (!queue_enabled) {
				continue;
			}
		}

		printf("  port=%u enabled=%d rate=%lluMbps burst=%lluKB\n",
		       p, pcfg->enabled,
		       (unsigned long long)(pcfg->rate_bps / 1000000ULL),
		       (unsigned long long)(pcfg->burst_bytes / 1024ULL));

		for (int q = 0; q < RS_SHAPER_WFQ_MAX_QUEUES; q++) {
			if (!pcfg->queue_cfg[q].enabled)
				continue;
			printf("    queue=%d enabled=%d rate=%lluMbps burst=%lluKB\n",
			       q, pcfg->queue_cfg[q].enabled,
			       (unsigned long long)(pcfg->queue_cfg[q].rate_bps / 1000000ULL),
			       (unsigned long long)(pcfg->queue_cfg[q].burst_bytes / 1024ULL));
		}
	}

	rs_shaper_shared_close(cfg);
	return 0;
}

static int cmd_set_wfq(int argc, char **argv)
{
	const char *port_name = NULL;
	const char *weights_str = NULL;
	uint32_t port_idx = 0;
	uint32_t weights[RS_SHAPER_WFQ_MAX_QUEUES] = {0};
	int count = 0;
	struct rs_shaper_shared_cfg *cfg = NULL;

	for (int i = 0; i < argc; i++) {
		if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
			port_name = argv[++i];
		} else if (strcmp(argv[i], "--weights") == 0 && i + 1 < argc) {
			weights_str = argv[++i];
		}
	}

	if (!port_name || !weights_str) {
		RS_LOG_ERROR("set-wfq requires --port and --weights");
		return -1;
	}
	if (parse_port_idx(port_name, &port_idx) < 0) {
		RS_LOG_ERROR("Invalid port name '%s'", port_name);
		return -1;
	}
	if (parse_weights(weights_str, weights, &count) < 0) {
		RS_LOG_ERROR("Invalid weights list '%s'", weights_str);
		return -1;
	}

	if (rs_shaper_shared_open(&cfg, 1) < 0 || !cfg) {
		return -1;
	}
	if (port_idx >= cfg->num_ports) {
		RS_LOG_ERROR("Port index %u out of range (num_ports=%u)", port_idx, cfg->num_ports);
		rs_shaper_shared_close(cfg);
		return -1;
	}

	for (int i = 0; i < RS_SHAPER_WFQ_MAX_QUEUES; i++) {
		cfg->ports[port_idx].wfq.queue_weights[i] = (i < count) ? weights[i] : 1;
		cfg->ports[port_idx].wfq.virtual_time[i] = 0;
	}
	cfg->ports[port_idx].wfq.num_queues = count;
	cfg->ports[port_idx].wfq.enabled = 1;
	cfg->generation++;

	printf("WFQ set on port=%u weights=", port_idx);
	for (int i = 0; i < count; i++) {
		printf("%u%s", weights[i], (i == count - 1) ? "\n" : ",");
	}

	rs_shaper_shared_close(cfg);
	return 0;
}

static int cmd_show_wfq(void)
{
	struct rs_shaper_shared_cfg *cfg = NULL;

	if (rs_shaper_shared_open(&cfg, 0) < 0 || !cfg) {
		RS_LOG_ERROR("No WFQ configuration found");
		return -1;
	}

	printf("WFQ Config (generation=%u):\n", cfg->generation);
	for (uint32_t p = 0; p < cfg->num_ports; p++) {
		struct rs_wfq_scheduler *wfq = &cfg->ports[p].wfq;
		if (!wfq->enabled)
			continue;
		printf("  port=%u num_queues=%d weights=", p, wfq->num_queues);
		for (int i = 0; i < wfq->num_queues && i < RS_SHAPER_WFQ_MAX_QUEUES; i++) {
			printf("%u%s", wfq->queue_weights[i], (i == wfq->num_queues - 1) ? "\n" : ",");
		}
	}

	rs_shaper_shared_close(cfg);
	return 0;
}

static __u64 get_time_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static int get_voqd_state(struct voqd_state *state)
{
	int fd, ret;
	__u32 key = 0;
	
	fd = bpf_obj_get(VOQD_STATE_MAP_PATH);
	if (fd < 0) {
		RS_LOG_ERROR("Cannot open VOQd state map: %s", strerror(errno));
		RS_LOG_ERROR("Is rSwitch loaded with AF_XDP module?");
		return -1;
	}
	
	ret = bpf_map_lookup_elem(fd, &key, state);
	close(fd);
	
	if (ret < 0) {
		RS_LOG_ERROR("Cannot read VOQd state: %s", strerror(errno));
		return -1;
	}
	
	return 0;
}

static int set_voqd_state(struct voqd_state *state)
{
	int fd, ret;
	__u32 key = 0;
	
	fd = bpf_obj_get(VOQD_STATE_MAP_PATH);
	if (fd < 0) {
		RS_LOG_ERROR("Cannot open VOQd state map: %s", strerror(errno));
		return -1;
	}
	
	ret = bpf_map_update_elem(fd, &key, state, BPF_ANY);
	close(fd);
	
	if (ret < 0) {
		RS_LOG_ERROR("Cannot update VOQd state: %s", strerror(errno));
		return -1;
	}
	
	return 0;
}

static int cmd_bypass(void)
{
	struct voqd_state state;
	
	if (get_voqd_state(&state) < 0)
		return -1;
	
	state.mode = VOQD_MODE_BYPASS;
	state.running = 0;
	
	if (set_voqd_state(&state) < 0)
		return -1;
	
	printf("VOQd mode: BYPASS\n");
	printf("All traffic uses XDP fast-path\n");
	return 0;
}

static int cmd_shadow(void)
{
	struct voqd_state state;
	
	if (get_voqd_state(&state) < 0)
		return -1;
	
	state.mode = VOQD_MODE_SHADOW;
	state.running = 1;
	state.last_heartbeat_ns = get_time_ns();
	
	if (set_voqd_state(&state) < 0)
		return -1;
	
	printf("VOQd mode: SHADOW\n");
	printf("Observing traffic, not intercepting\n");
	printf("Priority mask: 0x%X\n", state.prio_mask);
	return 0;
}

static int cmd_activate(int argc, char **argv)
{
	struct voqd_state state;
	__u32 prio_mask;
	
	if (argc < 1) {
		RS_LOG_ERROR("Missing priority mask");
		usage(argv[0]);
		return -1;
	}
	
	prio_mask = strtoul(argv[0], NULL, 0);
	if (prio_mask == 0 || prio_mask > 0xF) {
		RS_LOG_ERROR("Invalid priority mask 0x%X (must be 0x1-0xF)", prio_mask);
		return -1;
	}
	
	if (get_voqd_state(&state) < 0)
		return -1;
	
	state.mode = VOQD_MODE_ACTIVE;
	state.running = 1;
	state.prio_mask = prio_mask;
	state.last_heartbeat_ns = get_time_ns();
	state.flags |= VOQD_FLAG_AUTO_FAILOVER;  /* Enable automatic failover */
	
	if (set_voqd_state(&state) < 0)
		return -1;
	
	printf("VOQd mode: ACTIVE\n");
	printf("Intercepting priorities: 0x%X (", prio_mask);
	
	int first = 1;
	for (int i = 0; i < QOS_MAX_PRIORITIES; i++) {
		if (prio_mask & (1 << i)) {
			if (!first) printf(", ");
			printf("%s", priority_to_str(i));
			first = 0;
		}
	}
	printf(")\n");
	
	printf("Auto-failover: enabled (5s heartbeat timeout)\n");
	return 0;
}

static int cmd_status(void)
{
	struct voqd_state state;
	__u64 now_ns;
	
	if (get_voqd_state(&state) < 0)
		return -1;
	
	now_ns = get_time_ns();
	
	printf("VOQd Status:\n");
	printf("  Mode: %s\n", mode_to_str(state.mode));
	printf("  Running: %s\n", state.running ? "yes" : "no");
	printf("  Priority Mask: 0x%X (", state.prio_mask);
	
	int first = 1;
	for (int i = 0; i < QOS_MAX_PRIORITIES; i++) {
		if (state.prio_mask & (1 << i)) {
			if (!first) printf(", ");
			printf("%s", priority_to_str(i));
			first = 0;
		}
	}
	printf(")\n");
	
	/* Heartbeat status */
	if (state.last_heartbeat_ns > 0) {
		__u64 age_ns = now_ns - state.last_heartbeat_ns;
		double age_s = age_ns / 1000000000.0;
		printf("  Last Heartbeat: %.2f seconds ago\n", age_s);
		
		if (age_s > 5.0 && state.mode != VOQD_MODE_BYPASS) {
			printf("  WARNING: Heartbeat timeout (>5s), failover imminent!\n");
		}
	} else {
		printf("  Last Heartbeat: never\n");
	}
	
	printf("  Failover Count: %u\n", state.failover_count);
	printf("  Overload Drops: %u\n", state.overload_drops);
	
	/* Flags */
	printf("  Flags:\n");
	printf("    Auto-Failover: %s\n", 
	       (state.flags & VOQD_FLAG_AUTO_FAILOVER) ? "enabled" : "disabled");
	printf("    Degrade on Overload: %s\n", 
	       (state.flags & VOQD_FLAG_DEGRADE_ON_OVERLOAD) ? "enabled" : "disabled");
	printf("    Strict Priority: %s\n", 
	       (state.flags & VOQD_FLAG_STRICT_PRIORITY) ? "enabled" : "disabled");
	
	return 0;
}

static int cmd_queues(void)
{
	int fd, ret;
	struct qdepth_key key, next_key;
	__u32 qdepth;
	int found = 0;
	
	fd = bpf_obj_get(QDEPTH_MAP_PATH);
	if (fd < 0) {
		RS_LOG_ERROR("Cannot open queue depth map: %s", strerror(errno));
		return -1;
	}
	
	printf("Queue Depths (per-port, per-priority):\n");
	printf("  %-10s %-10s %s\n", "Port", "Priority", "Depth");
	printf("  %-10s %-10s %s\n", "----", "--------", "-----");
	
	/* Iterate over all queue depth entries */
	memset(&key, 0, sizeof(key));
	while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
		ret = bpf_map_lookup_elem(fd, &next_key, &qdepth);
		if (ret == 0 && qdepth > 0) {
			printf("  %-10u %-10s %u\n", 
			       next_key.port, 
			       priority_to_str(next_key.prio), 
			       qdepth);
			found = 1;
		}
		key = next_key;
	}
	
	if (!found) {
		printf("  (no queued packets)\n");
	}
	
	close(fd);
	return 0;
}

static int cmd_heartbeat(void)
{
	struct voqd_state state;
	
	if (get_voqd_state(&state) < 0)
		return -1;
	
	state.last_heartbeat_ns = get_time_ns();
	state.running = 1;
	
	if (set_voqd_state(&state) < 0)
		return -1;
	
	printf("Heartbeat sent (timestamp updated)\n");
	return 0;
}

int main(int argc, char **argv)
{
    rs_log_init("rsvoqctl", RS_LOG_LEVEL_INFO);

	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}
	
	const char *cmd = argv[1];
	
	if (strcmp(cmd, "bypass") == 0) {
		return cmd_bypass() < 0 ? 1 : 0;
	} else if (strcmp(cmd, "shadow") == 0) {
		return cmd_shadow() < 0 ? 1 : 0;
	} else if (strcmp(cmd, "activate") == 0) {
		return cmd_activate(argc - 2, argv + 2) < 0 ? 1 : 0;
	} else if (strcmp(cmd, "status") == 0) {
		return cmd_status() < 0 ? 1 : 0;
	} else if (strcmp(cmd, "queues") == 0) {
		return cmd_queues() < 0 ? 1 : 0;
	} else if (strcmp(cmd, "heartbeat") == 0) {
		return cmd_heartbeat() < 0 ? 1 : 0;
	} else if (strcmp(cmd, "set-shaper") == 0) {
		return cmd_set_shaper(argc - 2, argv + 2) < 0 ? 1 : 0;
	} else if (strcmp(cmd, "disable-shaper") == 0) {
		return cmd_disable_shaper(argc - 2, argv + 2) < 0 ? 1 : 0;
	} else if (strcmp(cmd, "show-shaper") == 0) {
		return cmd_show_shaper(argc - 2, argv + 2) < 0 ? 1 : 0;
	} else if (strcmp(cmd, "set-wfq") == 0) {
		return cmd_set_wfq(argc - 2, argv + 2) < 0 ? 1 : 0;
	} else if (strcmp(cmd, "show-wfq") == 0) {
		return cmd_show_wfq() < 0 ? 1 : 0;
	} else {
		RS_LOG_ERROR("Unknown command '%s'", cmd);
		usage(argv[0]);
		return 1;
	}
}
