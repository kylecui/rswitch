/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __RS_VOQ_SHAPER_H__
#define __RS_VOQ_SHAPER_H__

#include <stdint.h>

#define RS_SHAPER_WFQ_MAX_QUEUES 8
#define RS_SHAPER_MAX_PORTS 64
#define RS_SHAPER_CFG_VERSION 1
#define RS_SHAPER_SHM_PATH "/rswitch_voqd_shaper"

struct rs_shaper {
	uint64_t rate_bps;
	uint64_t burst_bytes;
	uint64_t tokens;
	uint64_t last_refill_ns;
	uint64_t shaped_packets;
	uint64_t shaped_bytes;
	uint64_t delay_ns_total;
	int enabled;
};

struct rs_shaper_stats {
	uint64_t shaped_packets;
	uint64_t shaped_bytes;
	uint64_t delay_ns_total;
	uint64_t tokens;
	uint64_t rate_bps;
	uint64_t burst_bytes;
	int enabled;
};

struct rs_wfq_scheduler {
	uint32_t queue_weights[RS_SHAPER_WFQ_MAX_QUEUES];
	uint64_t virtual_time[RS_SHAPER_WFQ_MAX_QUEUES];
	int num_queues;
	int enabled;
};

struct rs_shaper_queue_cfg {
	uint64_t rate_bps;
	uint64_t burst_bytes;
	int enabled;
};

struct rs_shaper_port_cfg {
	uint64_t rate_bps;
	uint64_t burst_bytes;
	int enabled;
	struct rs_shaper_queue_cfg queue_cfg[RS_SHAPER_WFQ_MAX_QUEUES];
	struct rs_wfq_scheduler wfq;
};

struct rs_shaper_shared_cfg {
	uint32_t version;
	uint32_t generation;
	uint32_t num_ports;
	struct rs_shaper_port_cfg ports[RS_SHAPER_MAX_PORTS];
};

void rs_shaper_init(struct rs_shaper *shaper, uint64_t now_ns);
void rs_shaper_configure(struct rs_shaper *shaper, uint64_t rate_bps, uint64_t burst_bytes, int enabled, uint64_t now_ns);
int rs_shaper_admit(struct rs_shaper *shaper, uint32_t pkt_len, uint64_t now_ns);
void rs_shaper_refill(struct rs_shaper *shaper, uint64_t now_ns);
void rs_shaper_stats(const struct rs_shaper *shaper, struct rs_shaper_stats *stats);

void rs_wfq_init(struct rs_wfq_scheduler *sched, int num_queues);
void rs_wfq_set_weights(struct rs_wfq_scheduler *sched, const uint32_t *weights, int num_queues);
int rs_wfq_select_queue(struct rs_wfq_scheduler *sched, const uint32_t *queue_depths, int num_queues);

int rs_shaper_shared_open(struct rs_shaper_shared_cfg **cfg, int create_if_missing);
void rs_shaper_shared_close(struct rs_shaper_shared_cfg *cfg);

#endif
