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

#define DEFAULT_STATE_MAP_PIN  "/sys/fs/bpf/voqd_state_map"
#define DEFAULT_QOS_MAP_PIN    "/sys/fs/bpf/qos_config_map"

/* Forward declarations for extended commands */
extern int cmd_list_modules(void);
extern int cmd_show_pipeline(void);
extern int cmd_show_ports(void);
extern int cmd_show_macs(int limit);
extern int cmd_show_stats(void);
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
	/* ACL commands */
	else if (strcmp(command, "acl-add-rule") == 0) {
		return cmd_acl_add_rule(argc - optind, argv + optind);
	}
	else if (strcmp(command, "acl-del-rule") == 0) {
		if (optind >= argc) {
			fprintf(stderr, "Error: rule ID required\n");
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
			fprintf(stderr, "Error: SPAN port required\n");
			return 1;
		}
		return cmd_mirror_set_span_port(atoi(argv[optind]));
	}
	else if (strcmp(command, "mirror-set-port") == 0) {
		if (optind >= argc) {
			fprintf(stderr, "Error: port ifindex required\n");
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
	printf("  %s mirror-disable\n", argv[0]);
	printf("\n");
	printf("Flags:\n");
	printf("  0x01  VOQD_FLAG_AUTO_FAILOVER       Auto-failover on heartbeat timeout\n");
	printf("  0x02  VOQD_FLAG_DEGRADE_ON_OVERLOAD Degrade to BYPASS on overload\n");
	printf("  0x04  VOQD_FLAG_STRICT_PRIORITY     Enforce strict priority\n");
	return 1;
}
