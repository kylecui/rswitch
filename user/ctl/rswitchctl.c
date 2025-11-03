// SPDX-License-Identifier: GPL-2.0
/*
 * rswitchctl - rSwitch Control Utility
 * 
 * Runtime control for VOQd state machine transitions and configuration.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "../../bpf/core/afxdp_common.h"

#define DEFAULT_STATE_MAP_PIN  "/sys/fs/bpf/rswitch/voqd_state_map"
#define DEFAULT_QOS_MAP_PIN    "/sys/fs/bpf/rswitch/qos_config_map"

/* Forward declarations for extended commands */
extern int cmd_list_modules(void);
extern int cmd_show_pipeline(void);
extern int cmd_show_ports(void);
extern int cmd_show_macs(int limit);
extern int cmd_show_stats(void);
extern int cmd_flush_macs(void);
extern int cmd_get_telemetry(void);

/* Show current state */
static int cmd_show_state(const char *state_map_pin)
{
	int fd = bpf_obj_get(state_map_pin);
	if (fd < 0) {
		fprintf(stderr, "Failed to open state_map: %s\n", strerror(errno));
		return -1;
	}
	
	struct voqd_state state;
	uint32_t key = 0;
	
	int ret = bpf_map_lookup_elem(fd, &key, &state);
	if (ret < 0) {
		fprintf(stderr, "Failed to read state: %s\n", strerror(errno));
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
		fprintf(stderr, "Invalid mode: %s (use bypass/shadow/active)\n", mode_str);
		return -1;
	}
	
	int fd = bpf_obj_get(state_map_pin);
	if (fd < 0) {
		fprintf(stderr, "Failed to open state_map: %s\n", strerror(errno));
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
		fprintf(stderr, "Failed to update state: %s\n", strerror(errno));
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
		fprintf(stderr, "Failed to open state_map: %s\n", strerror(errno));
		return -1;
	}
	
	struct voqd_state state;
	uint32_t key = 0;
	
	int ret = bpf_map_lookup_elem(fd, &key, &state);
	if (ret < 0) {
		fprintf(stderr, "Failed to read state: %s\n", strerror(errno));
		close(fd);
		return -1;
	}
	
	state.flags = flags;
	
	ret = bpf_map_update_elem(fd, &key, &state, BPF_ANY);
	if (ret < 0) {
		fprintf(stderr, "Failed to update state: %s\n", strerror(errno));
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
		fprintf(stderr, "Failed to open state_map: %s\n", strerror(errno));
		return -1;
	}
	
	struct voqd_state state;
	uint32_t key = 0;
	
	int ret = bpf_map_lookup_elem(fd, &key, &state);
	if (ret < 0) {
		fprintf(stderr, "Failed to read state: %s\n", strerror(errno));
		close(fd);
		return -1;
	}
	
	state.failover_count = 0;
	state.overload_drops = 0;
	
	ret = bpf_map_update_elem(fd, &key, &state, BPF_ANY);
	if (ret < 0) {
		fprintf(stderr, "Failed to update state: %s\n", strerror(errno));
		close(fd);
		return -1;
	}
	
	printf("Failover statistics reset\n");
	
	close(fd);
	return 0;
}

int main(int argc, char **argv)
{
	const char *state_map_pin = DEFAULT_STATE_MAP_PIN;
	const char *command = NULL;
	const char *mode = NULL;
	int prio_mask = -1;
	uint32_t flags = 0;
	int mac_limit = 100;  /* Default limit for show-macs */
	
	static struct option long_options[] = {
		{"state-map", required_argument, 0, 's'},
		{"mode",      required_argument, 0, 'm'},
		{"prio-mask", required_argument, 0, 'p'},
		{"flags",     required_argument, 0, 'f'},
		{"limit",     required_argument, 0, 'l'},
		{"help",      no_argument,       0, 'h'},
		{0, 0, 0, 0}
	};
	
	if (argc < 2) {
		goto usage;
	}
	
	command = argv[1];
	optind = 2;  /* Start parsing from second argument */
	
	int opt;
	while ((opt = getopt_long(argc, argv, "s:m:p:f:l:h", long_options, NULL)) != -1) {
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
			fprintf(stderr, "Error: --mode required\n");
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
	else if (strcmp(command, "show-stats") == 0) {
		return cmd_show_stats();
	}
	else if (strcmp(command, "flush-macs") == 0) {
		return cmd_flush_macs();
	}
	else if (strcmp(command, "get-telemetry") == 0) {
		return cmd_get_telemetry();
	}
	else {
		fprintf(stderr, "Unknown command: %s\n", command);
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
	printf("  list-modules              List loaded BPF modules\n");
	printf("  show-pipeline             Show tail-call pipeline\n");
	printf("  show-ports                Show port configurations\n");
	printf("  show-macs                 Show MAC table (use --limit N)\n");
	printf("  show-stats                Show interface statistics\n");
	printf("  flush-macs                Flush dynamic MAC entries\n");
	printf("  get-telemetry             Get comprehensive telemetry\n");
	printf("\n");
	printf("Options:\n");
	printf("  -s, --state-map PATH      Path to pinned state_map (default: %s)\n", DEFAULT_STATE_MAP_PIN);
	printf("  -m, --mode MODE           Operating mode: bypass/shadow/active\n");
	printf("  -p, --prio-mask MASK      Priority interception mask (hex)\n");
	printf("  -f, --flags FLAGS         Control flags (hex)\n");
	printf("  -l, --limit N             Limit for show-macs (default: 100)\n");
	printf("  -h, --help                Show this help\n");
	printf("\n");
	printf("Examples:\n");
	printf("  %s show\n", argv[0]);
	printf("  %s set-mode --mode shadow --prio-mask 0x0C\n", argv[0]);
	printf("  %s set-mode --mode active --prio-mask 0x0F\n", argv[0]);
	printf("  %s set-flags --flags 0x03  # Enable auto-failover + degrade-on-overload\n", argv[0]);
	printf("  %s reset-stats\n", argv[0]);
	printf("  %s list-modules\n", argv[0]);
	printf("  %s show-pipeline\n", argv[0]);
	printf("  %s show-macs --limit 50\n", argv[0]);
	printf("  %s flush-macs\n", argv[0]);
	printf("\n");
	printf("Flags:\n");
	printf("  0x01  VOQD_FLAG_AUTO_FAILOVER       Auto-failover on heartbeat timeout\n");
	printf("  0x02  VOQD_FLAG_DEGRADE_ON_OVERLOAD Degrade to BYPASS on overload\n");
	printf("  0x04  VOQD_FLAG_STRICT_PRIORITY     Enforce strict priority\n");
	return 1;
}
