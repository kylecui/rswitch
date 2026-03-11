// SPDX-License-Identifier: GPL-2.0
#include "state_ctrl.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <bpf/bpf.h>
#if __has_include("rs_log.h")
#include "rs_log.h"
#else
#include "../common/rs_log.h"
#endif

#define NSEC_PER_SEC 1000000000ULL

static uint64_t get_time_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec;
}

/* Initialize state controller */
int state_ctrl_init(struct state_ctrl *ctrl, const char *state_map_pin,
                    const char *qos_config_pin)
{
	if (!ctrl || !state_map_pin)
		return -EINVAL;
	
	memset(ctrl, 0, sizeof(*ctrl));
	
	/* Open pinned maps */
	ctrl->voqd_state_fd = bpf_obj_get(state_map_pin);
	if (ctrl->voqd_state_fd < 0) {
		RS_LOG_ERROR("Failed to open state_map at %s: %s",
		             state_map_pin, strerror(errno));
		return -errno;
	}
	
	if (qos_config_pin) {
		ctrl->qos_config_fd = bpf_obj_get(qos_config_pin);
		if (ctrl->qos_config_fd < 0) {
			RS_LOG_ERROR("Failed to open qos_config_map at %s: %s",
			             qos_config_pin, strerror(errno));
			close(ctrl->voqd_state_fd);
			return -errno;
		}
	}
	
	/* Default: BYPASS mode */
	ctrl->mode = VOQD_MODE_BYPASS;
	ctrl->prio_mask = 0;
	ctrl->running = false;
	ctrl->last_heartbeat_ns = get_time_ns();
	
	return 0;
}

/* Destroy state controller */
void state_ctrl_destroy(struct state_ctrl *ctrl)
{
	if (!ctrl)
		return;
	
	if (ctrl->voqd_state_fd >= 0) {
		close(ctrl->voqd_state_fd);
		ctrl->voqd_state_fd = -1;
	}
	
	if (ctrl->qos_config_fd >= 0) {
		close(ctrl->qos_config_fd);
		ctrl->qos_config_fd = -1;
	}
}

/* Set operating mode */
int state_ctrl_set_mode(struct state_ctrl *ctrl, uint32_t mode, uint32_t prio_mask)
{
	if (!ctrl || ctrl->voqd_state_fd < 0)
		return -EINVAL;
	
	if (mode >= 3) {  /* BYPASS=0, SHADOW=1, ACTIVE=2 */
		RS_LOG_ERROR("Invalid mode: %u", mode);
		return -EINVAL;
	}
	
	struct voqd_state state;
	uint32_t key = 0;
	
	/* Read current state first to preserve failover_count and other fields */
	int ret = bpf_map_lookup_elem(ctrl->voqd_state_fd, &key, &state);
	if (ret < 0) {
		/* Initialize if not exists */
		memset(&state, 0, sizeof(state));
	}
	
	/* Update mode and control fields */
	state.running = 1;
	state.prio_mask = prio_mask;
	state.mode = mode;
	state.last_heartbeat_ns = get_time_ns();
	state.flags |= VOQD_FLAG_AUTO_FAILOVER | VOQD_FLAG_DEGRADE_ON_OVERLOAD;
	/* Reset overload counter on mode change */
	state.overload_drops = 0;
	
	ret = bpf_map_update_elem(ctrl->voqd_state_fd, &key, &state, BPF_ANY);
	if (ret < 0) {
		RS_LOG_ERROR("Failed to update voqd_state_map: %s", strerror(errno));
		return -errno;
	}
	
	ctrl->mode = mode;
	ctrl->prio_mask = prio_mask;
	ctrl->mode_transitions++;
	
	const char *mode_str[] = {"BYPASS", "SHADOW", "ACTIVE"};
	printf("State transition: mode=%s, prio_mask=0x%02x, flags=0x%02x\n", 
	       mode_str[mode], prio_mask, state.flags);
	
	return 0;
}

/* Get current mode */
int state_ctrl_get_mode(struct state_ctrl *ctrl, uint32_t *mode, uint32_t *prio_mask)
{
	if (!ctrl || ctrl->voqd_state_fd < 0)
		return -EINVAL;
	
	struct voqd_state state;
	uint32_t key = 0;
	
	int ret = bpf_map_lookup_elem(ctrl->voqd_state_fd, &key, &state);
	if (ret < 0) {
		RS_LOG_ERROR("Failed to lookup voqd_state_map: %s", strerror(errno));
		return -errno;
	}
	
	if (mode) *mode = state.mode;
	if (prio_mask) *prio_mask = state.prio_mask;
	
	return 0;
}

/* Update QoS configuration */
int state_ctrl_set_qos_config(struct state_ctrl *ctrl, const struct qos_config *cfg)
{
	if (!ctrl || !cfg || ctrl->qos_config_fd < 0)
		return -EINVAL;
	
	uint32_t key = 0;
	int ret = bpf_map_update_elem(ctrl->qos_config_fd, &key, cfg, BPF_ANY);
	if (ret < 0) {
		RS_LOG_ERROR("Failed to update qos_config_map: %s", strerror(errno));
		return -errno;
	}
	
	printf("QoS config updated: drop_thresh=%u, ecn_thresh=%u\n",
	       cfg->drop_threshold, cfg->ecn_threshold);
	
	return 0;
}

/* Get QoS configuration */
int state_ctrl_get_qos_config(struct state_ctrl *ctrl, struct qos_config *cfg)
{
	if (!ctrl || !cfg || ctrl->qos_config_fd < 0)
		return -EINVAL;
	
	uint32_t key = 0;
	int ret = bpf_map_lookup_elem(ctrl->qos_config_fd, &key, cfg);
	if (ret < 0) {
		RS_LOG_ERROR("Failed to lookup qos_config_map: %s", strerror(errno));
		return -errno;
	}
	
	return 0;
}

/* Manual heartbeat update */
int state_ctrl_heartbeat(struct state_ctrl *ctrl)
{
	if (!ctrl || ctrl->voqd_state_fd < 0)
		return -EINVAL;
	
	struct voqd_state state;
	uint32_t key = 0;
	
	/* Read current state */
	int ret = bpf_map_lookup_elem(ctrl->voqd_state_fd, &key, &state);
	if (ret < 0)
		return -errno;
	
	/* Update running flag and heartbeat timestamp */
	state.running = 1;
	state.last_heartbeat_ns = get_time_ns();
	
	ret = bpf_map_update_elem(ctrl->voqd_state_fd, &key, &state, BPF_ANY);
	if (ret < 0)
		return -errno;
	
	ctrl->last_heartbeat_ns = state.last_heartbeat_ns;
	ctrl->heartbeats_sent++;
	
	return 0;
}

/* Heartbeat thread */
static void *heartbeat_thread_fn(void *arg)
{
	struct state_ctrl *ctrl = arg;
	
	while (ctrl->running) {
		state_ctrl_heartbeat(ctrl);
		usleep(HEARTBEAT_INTERVAL_MS * 1000);
	}
	
	return NULL;
}

/* Start heartbeat thread */
int state_ctrl_start_heartbeat(struct state_ctrl *ctrl)
{
	if (!ctrl)
		return -EINVAL;
	
	ctrl->running = true;
	
	int ret = pthread_create(&ctrl->heartbeat_thread, NULL, heartbeat_thread_fn, ctrl);
	if (ret != 0) {
		RS_LOG_ERROR("Failed to create heartbeat thread: %s", strerror(ret));
		return -ret;
	}
	
	return 0;
}

/* Stop heartbeat thread */
void state_ctrl_stop_heartbeat(struct state_ctrl *ctrl)
{
	if (!ctrl)
		return;
	
	ctrl->running = false;
	pthread_join(ctrl->heartbeat_thread, NULL);
}

/* Get failover statistics */
int state_ctrl_get_failover_stats(struct state_ctrl *ctrl, uint32_t *failover_count,
                                   uint32_t *overload_drops)
{
	if (!ctrl || ctrl->voqd_state_fd < 0)
		return -EINVAL;
	
	struct voqd_state state;
	uint32_t key = 0;
	
	int ret = bpf_map_lookup_elem(ctrl->voqd_state_fd, &key, &state);
	if (ret < 0)
		return -errno;
	
	if (failover_count) *failover_count = state.failover_count;
	if (overload_drops) *overload_drops = state.overload_drops;
	
	return 0;
}

/* Set control flags */
int state_ctrl_set_flags(struct state_ctrl *ctrl, uint32_t flags)
{
	if (!ctrl || ctrl->voqd_state_fd < 0)
		return -EINVAL;
	
	struct voqd_state state;
	uint32_t key = 0;
	
	int ret = bpf_map_lookup_elem(ctrl->voqd_state_fd, &key, &state);
	if (ret < 0)
		return -errno;
	
	state.flags = flags;
	
	ret = bpf_map_update_elem(ctrl->voqd_state_fd, &key, &state, BPF_ANY);
	if (ret < 0)
		return -errno;
	
	printf("State flags updated: 0x%02x (auto_failover=%d, degrade_on_overload=%d)\n",
	       flags,
	       !!(flags & VOQD_FLAG_AUTO_FAILOVER),
	       !!(flags & VOQD_FLAG_DEGRADE_ON_OVERLOAD));
	
	return 0;
}

/* Get control flags */
int state_ctrl_get_flags(struct state_ctrl *ctrl, uint32_t *flags)
{
	if (!ctrl || ctrl->voqd_state_fd < 0 || !flags)
		return -EINVAL;
	
	struct voqd_state state;
	uint32_t key = 0;
	
	int ret = bpf_map_lookup_elem(ctrl->voqd_state_fd, &key, &state);
	if (ret < 0)
		return -errno;
	
	*flags = state.flags;
	return 0;
}

/* Check if mode was auto-downgraded (detect failover) */
int state_ctrl_check_degradation(struct state_ctrl *ctrl, uint32_t *current_mode)
{
	if (!ctrl || ctrl->voqd_state_fd < 0)
		return -EINVAL;
	
	struct voqd_state state;
	uint32_t key = 0;
	
	int ret = bpf_map_lookup_elem(ctrl->voqd_state_fd, &key, &state);
	if (ret < 0)
		return -errno;
	
	if (current_mode) *current_mode = state.mode;
	
	/* Check if mode changed from what we expect */
	if (state.mode != ctrl->mode) {
		const char *mode_str[] = {"BYPASS", "SHADOW", "ACTIVE"};
		RS_LOG_WARN("Auto-failover detected! Expected %s, but XDP set %s",
		            mode_str[ctrl->mode], mode_str[state.mode]);
		RS_LOG_WARN("Failover count: %u, Overload drops: %u",
		            state.failover_count, state.overload_drops);
		
		/* Update local state */
		ctrl->mode = state.mode;
		
		return 1;  /* Degradation detected */
	}
	
	return 0;  /* No degradation */
}
