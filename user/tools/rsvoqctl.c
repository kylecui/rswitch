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

#include "../../bpf/core/afxdp_common.h"

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
		fprintf(stderr, "Error: Cannot open VOQd state map: %s\n", strerror(errno));
		fprintf(stderr, "Is rSwitch loaded with AF_XDP module?\n");
		return -1;
	}
	
	ret = bpf_map_lookup_elem(fd, &key, state);
	close(fd);
	
	if (ret < 0) {
		fprintf(stderr, "Error: Cannot read VOQd state: %s\n", strerror(errno));
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
		fprintf(stderr, "Error: Cannot open VOQd state map: %s\n", strerror(errno));
		return -1;
	}
	
	ret = bpf_map_update_elem(fd, &key, state, BPF_ANY);
	close(fd);
	
	if (ret < 0) {
		fprintf(stderr, "Error: Cannot update VOQd state: %s\n", strerror(errno));
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
		fprintf(stderr, "Error: Missing priority mask\n");
		usage(argv[0]);
		return -1;
	}
	
	prio_mask = strtoul(argv[0], NULL, 0);
	if (prio_mask == 0 || prio_mask > 0xF) {
		fprintf(stderr, "Error: Invalid priority mask 0x%X (must be 0x1-0xF)\n", prio_mask);
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
		fprintf(stderr, "Error: Cannot open queue depth map: %s\n", strerror(errno));
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
	} else {
		fprintf(stderr, "Error: Unknown command '%s'\n", cmd);
		usage(argv[0]);
		return 1;
	}
}
