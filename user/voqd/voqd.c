// SPDX-License-Identifier: GPL-2.0
/*
 * rSwitch VOQd - Virtual Output Queue Daemon
 * 
 * User-space daemon implementing VOQ scheduling with DRR/WFQ,
 * token bucket rate limiting, and hybrid XDP/AF_XDP data plane.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>

#include "voq.h"
#include "ringbuf_consumer.h"
#include "state_ctrl.h"
#include "../../bpf/core/afxdp_common.h"

#define DEFAULT_RINGBUF_PIN    "/sys/fs/bpf/rswitch/voq_ringbuf"
#define DEFAULT_STATE_MAP_PIN  "/sys/fs/bpf/rswitch/voqd_state_map"
#define DEFAULT_QOS_MAP_PIN    "/sys/fs/bpf/rswitch/qos_config_map"

/* Global daemon context */
struct voqd_ctx {
	struct voq_mgr voq;
	struct rb_consumer ringbuf;
	struct state_ctrl state;
	
	/* Configuration */
	uint32_t num_ports;
	uint32_t mode;           /* BYPASS/SHADOW/ACTIVE */
	uint32_t prio_mask;      /* Priority interception mask */
	
	/* Runtime flags */
	volatile bool running;
	bool scheduler_enabled;
	
	/* Statistics reporting */
	uint32_t stats_interval_sec;
	time_t last_stats_print;
};

static struct voqd_ctx g_ctx;

/* Signal handler */
static void signal_handler(int sig)
{
	printf("\nReceived signal %d, shutting down...\n", sig);
	g_ctx.running = false;
}

/* Ringbuf event handler - enqueue metadata into VOQ */
static int handle_voq_meta(void *ctx, const struct voq_meta *meta)
{
	struct voqd_ctx *daemon = ctx;
	
	/* Validate metadata */
	if (meta->eg_port >= daemon->num_ports) {
		fprintf(stderr, "Invalid eg_port: %u\n", meta->eg_port);
		return -EINVAL;
	}
	
	if (meta->prio >= MAX_PRIORITIES) {
		fprintf(stderr, "Invalid priority: %u\n", meta->prio);
		return -EINVAL;
	}
	
	/* Enqueue into VOQ */
	int ret = voq_enqueue(&daemon->voq, meta->eg_port, meta->prio,
	                      meta->ts_ns, meta->len, meta->flow_hash,
	                      meta->ecn_hint, meta->drop_hint, 0);
	
	if (ret < 0 && ret != -ENOSPC) {
		fprintf(stderr, "VOQ enqueue failed: %s\n", strerror(-ret));
	}
	
	return ret;
}

/* Print statistics */
static void print_stats(struct voqd_ctx *ctx)
{
	time_t now = time(NULL);
	if (now - ctx->last_stats_print < ctx->stats_interval_sec)
		return;
	
	ctx->last_stats_print = now;
	
	/* Check for auto-degradation */
	uint32_t current_mode;
	int degraded = state_ctrl_check_degradation(&ctx->state, &current_mode);
	if (degraded) {
		/* Update local mode */
		ctx->mode = current_mode;
	}
	
	const char *mode_str[] = {"BYPASS", "SHADOW", "ACTIVE"};
	printf("\n=== VOQd Statistics (mode=%s, prio_mask=0x%02x) ===\n",
	       mode_str[ctx->mode], ctx->prio_mask);
	
	/* Failover statistics */
	uint32_t failover_count, overload_drops;
	state_ctrl_get_failover_stats(&ctx->state, &failover_count, &overload_drops);
	if (failover_count > 0 || overload_drops > 0) {
		printf("Failover: count=%u, overload_drops=%u%s\n",
		       failover_count, overload_drops,
		       degraded ? " [DEGRADED]" : "");
	}
	
	/* Ringbuf stats */
	uint64_t rb_recv, rb_proc, rb_drop;
	rb_consumer_get_stats(&ctx->ringbuf, &rb_recv, &rb_proc, &rb_drop);
	printf("Ringbuf: received=%lu, processed=%lu, dropped=%lu\n",
	       rb_recv, rb_proc, rb_drop);
	
	/* VOQ stats */
	voq_print_stats(&ctx->voq);
	
	/* State controller stats */
	printf("State: heartbeats=%lu, transitions=%lu\n",
	       ctx->state.heartbeats_sent, ctx->state.mode_transitions);
}

/* Configuration - default QoS config */
static void setup_default_qos(struct voqd_ctx *ctx)
{
	struct qos_config cfg = {
		.drop_threshold = 4096,   /* Drop above 4K packets */
		.ecn_threshold = 2048,    /* ECN mark above 2K packets */
	};
	
	/* Default DSCP → priority mapping (simplified) */
	for (int i = 0; i < 64; i++) {
		if (i >= 48)          /* CS6, CS7, EF */
			cfg.dscp2prio[i] = 3;
		else if (i >= 32)     /* CS4, CS5, AF4x */
			cfg.dscp2prio[i] = 2;
		else if (i >= 16)     /* CS2, CS3, AF2x, AF3x */
			cfg.dscp2prio[i] = 1;
		else                  /* BE, CS0, CS1, AF1x */
			cfg.dscp2prio[i] = 0;
	}
	
	state_ctrl_set_qos_config(&ctx->state, &cfg);
}

/* Configuration - setup VOQ parameters */
static void setup_voq_params(struct voqd_ctx *ctx)
{
	/* Configure quantum per priority (higher prio = larger quantum) */
	for (int prio = 0; prio < MAX_PRIORITIES; prio++) {
		uint32_t quantum = DEFAULT_QUANTUM * (prio + 1);
		uint32_t max_depth = MAX_QUEUE_DEPTH / (MAX_PRIORITIES - prio);  /* Higher prio = deeper queue */
		
		voq_set_queue_params(&ctx->voq, prio, quantum, max_depth);
	}
	
	/* Add ports (example: 4 ports) */
	for (uint32_t p = 0; p < ctx->num_ports; p++) {
		char ifname[16];
		snprintf(ifname, sizeof(ifname), "port%u", p);
		voq_add_port(&ctx->voq, p, p + 1, ifname);
		
		/* Example: 1 Gbps rate limit on port 0 */
		if (p == 0) {
			voq_set_port_rate(&ctx->voq, p, 1000000000ULL, 128 * 1024);
		}
	}
}

/* Initialize daemon */
static int voqd_init(struct voqd_ctx *ctx, int argc, char **argv)
{
	int ret;
	
	/* Default configuration */
	ctx->num_ports = 4;
	ctx->mode = VOQD_MODE_BYPASS;
	ctx->prio_mask = 0x00;
	ctx->scheduler_enabled = false;
	ctx->stats_interval_sec = 10;
	ctx->running = true;
	ctx->last_stats_print = time(NULL);
	
	/* Parse command-line options */
	static struct option long_options[] = {
		{"ports",     required_argument, 0, 'p'},
		{"mode",      required_argument, 0, 'm'},
		{"prio-mask", required_argument, 0, 'P'},
		{"scheduler", no_argument,       0, 's'},
		{"stats",     required_argument, 0, 'S'},
		{"help",      no_argument,       0, 'h'},
		{0, 0, 0, 0}
	};
	
	int opt;
	while ((opt = getopt_long(argc, argv, "p:m:P:sS:h", long_options, NULL)) != -1) {
		switch (opt) {
		case 'p':
			ctx->num_ports = atoi(optarg);
			if (ctx->num_ports == 0 || ctx->num_ports > MAX_PORTS) {
				fprintf(stderr, "Invalid num_ports: %s\n", optarg);
				return -EINVAL;
			}
			break;
		case 'm':
			if (strcmp(optarg, "bypass") == 0)
				ctx->mode = VOQD_MODE_BYPASS;
			else if (strcmp(optarg, "shadow") == 0)
				ctx->mode = VOQD_MODE_SHADOW;
			else if (strcmp(optarg, "active") == 0)
				ctx->mode = VOQD_MODE_ACTIVE;
			else {
				fprintf(stderr, "Invalid mode: %s (use bypass/shadow/active)\n", optarg);
				return -EINVAL;
			}
			break;
		case 'P':
			ctx->prio_mask = strtoul(optarg, NULL, 0);
			break;
		case 's':
			ctx->scheduler_enabled = true;
			break;
		case 'S':
			ctx->stats_interval_sec = atoi(optarg);
			break;
		case 'h':
		default:
			printf("Usage: %s [options]\n", argv[0]);
			printf("Options:\n");
			printf("  -p, --ports NUM         Number of ports (default: 4)\n");
			printf("  -m, --mode MODE         Operating mode: bypass/shadow/active (default: bypass)\n");
			printf("  -P, --prio-mask MASK    Priority interception mask (default: 0x00)\n");
			printf("  -s, --scheduler         Enable VOQ scheduler thread\n");
			printf("  -S, --stats INTERVAL    Stats print interval in seconds (default: 10)\n");
			printf("  -h, --help              Show this help\n");
			printf("\n");
			printf("State Machine Features:\n");
			printf("  - Auto-failover: ACTIVE/SHADOW -> BYPASS on heartbeat timeout (5s)\n");
			printf("  - Graceful degradation: ACTIVE -> BYPASS on sustained overload\n");
			printf("  - Failover detection: VOQd detects and logs auto-degradation\n");
			return opt == 'h' ? 1 : -EINVAL;
		}
	}
	
	/* Initialize VOQ manager */
	ret = voq_mgr_init(&ctx->voq, ctx->num_ports);
	if (ret < 0) {
		fprintf(stderr, "Failed to initialize VOQ manager: %s\n", strerror(-ret));
		return ret;
	}
	
	setup_voq_params(ctx);
	
	/* Initialize state controller */
	ret = state_ctrl_init(&ctx->state, DEFAULT_STATE_MAP_PIN, DEFAULT_QOS_MAP_PIN);
	if (ret < 0) {
		fprintf(stderr, "Failed to initialize state controller: %s\n", strerror(-ret));
		voq_mgr_destroy(&ctx->voq);
		return ret;
	}
	
	setup_default_qos(ctx);
	
	/* Set initial mode */
	ret = state_ctrl_set_mode(&ctx->state, ctx->mode, ctx->prio_mask);
	if (ret < 0) {
		fprintf(stderr, "Failed to set mode: %s\n", strerror(-ret));
		state_ctrl_destroy(&ctx->state);
		voq_mgr_destroy(&ctx->voq);
		return ret;
	}
	
	/* Initialize ringbuf consumer */
	ret = rb_consumer_init(&ctx->ringbuf, DEFAULT_RINGBUF_PIN, handle_voq_meta, ctx);
	if (ret < 0) {
		fprintf(stderr, "Failed to initialize ringbuf consumer: %s\n", strerror(-ret));
		state_ctrl_destroy(&ctx->state);
		voq_mgr_destroy(&ctx->voq);
		return ret;
	}
	
	/* Start heartbeat */
	ret = state_ctrl_start_heartbeat(&ctx->state);
	if (ret < 0) {
		fprintf(stderr, "Failed to start heartbeat: %s\n", strerror(-ret));
		rb_consumer_destroy(&ctx->ringbuf);
		state_ctrl_destroy(&ctx->state);
		voq_mgr_destroy(&ctx->voq);
		return ret;
	}
	
	/* Start scheduler if enabled */
	if (ctx->scheduler_enabled) {
		ret = voq_start_scheduler(&ctx->voq);
		if (ret < 0) {
			fprintf(stderr, "Failed to start scheduler: %s\n", strerror(-ret));
			state_ctrl_stop_heartbeat(&ctx->state);
			rb_consumer_destroy(&ctx->ringbuf);
			state_ctrl_destroy(&ctx->state);
			voq_mgr_destroy(&ctx->voq);
			return ret;
		}
	}
	
	printf("VOQd initialized: ports=%u, mode=%s, prio_mask=0x%02x, scheduler=%s\n",
	       ctx->num_ports,
	       ctx->mode == VOQD_MODE_BYPASS ? "BYPASS" :
	       ctx->mode == VOQD_MODE_SHADOW ? "SHADOW" : "ACTIVE",
	       ctx->prio_mask,
	       ctx->scheduler_enabled ? "enabled" : "disabled");
	
	return 0;
}

/* Cleanup daemon */
static void voqd_cleanup(struct voqd_ctx *ctx)
{
	printf("Cleaning up...\n");
	
	/* Stop scheduler */
	if (ctx->scheduler_enabled) {
		voq_stop_scheduler(&ctx->voq);
	}
	
	/* Stop heartbeat */
	state_ctrl_stop_heartbeat(&ctx->state);
	
	/* Set mode to BYPASS on exit (safe fallback) */
	state_ctrl_set_mode(&ctx->state, VOQD_MODE_BYPASS, 0);
	
	/* Destroy components */
	rb_consumer_destroy(&ctx->ringbuf);
	state_ctrl_destroy(&ctx->state);
	voq_mgr_destroy(&ctx->voq);
	
	printf("VOQd shutdown complete\n");
}

/* Main event loop */
static int voqd_run(struct voqd_ctx *ctx)
{
	printf("VOQd running... (Ctrl+C to stop)\n");
	
	while (ctx->running) {
		/* Poll ringbuf for metadata events */
		int ret = rb_consumer_poll(&ctx->ringbuf, 100);  /* 100ms timeout */
		
		if (ret < 0 && ret != -EINTR) {
			fprintf(stderr, "Ringbuf poll error: %d\n", ret);
			break;
		}
		
		/* Print stats periodically */
		print_stats(ctx);
	}
	
	/* Final stats */
	print_stats(ctx);
	
	return 0;
}

int main(int argc, char **argv)
{
	int ret;
	
	/* Install signal handlers */
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
	
	/* Initialize daemon */
	ret = voqd_init(&g_ctx, argc, argv);
	if (ret != 0) {
		return ret > 0 ? 0 : 1;  /* 1 = help message, 0 = success */
	}
	
	/* Run main loop */
	ret = voqd_run(&g_ctx);
	
	/* Cleanup */
	voqd_cleanup(&g_ctx);
	
	return ret;
}
