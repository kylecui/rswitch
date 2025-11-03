/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __STATE_CTRL_H__
#define __STATE_CTRL_H__

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include "../../bpf/core/afxdp_common.h"

/*
 * State Machine Controller
 * 
 * Manages BYPASS → SHADOW → ACTIVE transitions and heartbeat.
 */

#define HEARTBEAT_INTERVAL_MS 1000
#define HEARTBEAT_TIMEOUT_MS 5000

/* State controller */
struct state_ctrl {
	int voqd_state_fd;     /* state_map BPF map */
	int qos_config_fd;     /* qos_config_map */
	
	/* Current state */
	uint32_t mode;         /* VOQD_MODE_* */
	uint32_t prio_mask;    /* Priority interception mask */
	
	/* Heartbeat */
	pthread_t heartbeat_thread;
	volatile bool running;
	uint64_t last_heartbeat_ns;
	
	/* Statistics */
	uint64_t heartbeats_sent;
	uint64_t mode_transitions;
};

/* Initialize state controller */
int state_ctrl_init(struct state_ctrl *ctrl, const char *state_map_pin,
                    const char *qos_config_pin);

/* Destroy state controller */
void state_ctrl_destroy(struct state_ctrl *ctrl);

/* Set operating mode */
int state_ctrl_set_mode(struct state_ctrl *ctrl, uint32_t mode, uint32_t prio_mask);

/* Get current mode */
int state_ctrl_get_mode(struct state_ctrl *ctrl, uint32_t *mode, uint32_t *prio_mask);

/* Update QoS configuration (DSCP → priority mapping) */
int state_ctrl_set_qos_config(struct state_ctrl *ctrl, const struct qos_config *cfg);

/* Get QoS configuration */
int state_ctrl_get_qos_config(struct state_ctrl *ctrl, struct qos_config *cfg);

/* Start heartbeat thread */
int state_ctrl_start_heartbeat(struct state_ctrl *ctrl);

/* Stop heartbeat thread */
void state_ctrl_stop_heartbeat(struct state_ctrl *ctrl);

/* Manual heartbeat update */
int state_ctrl_heartbeat(struct state_ctrl *ctrl);

/* Get failover statistics */
int state_ctrl_get_failover_stats(struct state_ctrl *ctrl, uint32_t *failover_count,
                                   uint32_t *overload_drops);

/* Set control flags */
int state_ctrl_set_flags(struct state_ctrl *ctrl, uint32_t flags);

/* Get control flags */
int state_ctrl_get_flags(struct state_ctrl *ctrl, uint32_t *flags);

/* Check if mode was auto-downgraded (detect failover) */
int state_ctrl_check_degradation(struct state_ctrl *ctrl, uint32_t *current_mode);

#endif /* __STATE_CTRL_H__ */
