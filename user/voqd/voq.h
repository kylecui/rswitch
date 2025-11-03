/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __VOQ_H__
#define __VOQ_H__

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <time.h>

/*
 * Virtual Output Queue (VOQ) Definitions
 * 
 * Per-port, per-priority queuing with DRR/WFQ scheduling.
 * Designed for high-priority traffic isolation and QoS guarantees.
 */

#define MAX_PORTS 64
#define MAX_PRIORITIES 4
#define MAX_QUEUE_DEPTH 8192
#define DEFAULT_QUANTUM 1500  /* Bytes per round (MTU) */

/* VOQ Entry - Single queued packet metadata */
struct voq_entry {
	uint64_t ts_ns;           /* Timestamp */
	uint32_t eg_port;         /* Egress port */
	uint32_t prio;            /* Priority (0-3) */
	uint32_t len;             /* Packet length */
	uint32_t flow_hash;       /* Flow hash for fairness */
	uint8_t  ecn_hint;        /* ECN marking hint */
	uint8_t  drop_hint;       /* Drop recommendation */
	uint8_t  _pad[2];
	
	/* AF_XDP frame reference (for ACTIVE mode) */
	uint64_t xdp_frame_addr;  /* UMEM offset (0 = metadata-only) */
	
	struct voq_entry *next;   /* Linked list */
};

/* Per-priority queue */
struct voq_queue {
	struct voq_entry *head;
	struct voq_entry *tail;
	uint32_t depth;           /* Current queue depth (packets) */
	uint32_t max_depth;       /* Maximum depth before drop */
	
	/* DRR state */
	int32_t deficit;          /* Deficit counter (bytes) */
	uint32_t quantum;         /* Quantum (bytes per round) */
	
	/* Statistics */
	uint64_t enqueued;
	uint64_t dequeued;
	uint64_t dropped;
	uint64_t bytes_enq;
	uint64_t bytes_deq;
	
	/* Latency tracking */
	uint64_t latency_sum_ns;
	uint64_t latency_count;
	uint64_t latency_p99_ns;  /* Updated periodically */
	
	pthread_mutex_t lock;
};

/* Per-port VOQ (4 priority queues per port) */
struct voq_port {
	struct voq_queue queues[MAX_PRIORITIES];
	
	/* Token bucket for rate limiting */
	uint64_t tokens;          /* Current token count (bytes) */
	uint64_t rate_bps;        /* Rate limit (bits per second) */
	uint64_t burst_bytes;     /* Burst size (bytes) */
	uint64_t last_refill_ns;  /* Last token refill time */
	
	/* Port state */
	bool enabled;
	uint32_t ifindex;
	char ifname[16];
	
	pthread_mutex_t lock;
};

/* VOQ Manager - Global state */
struct voq_mgr {
	struct voq_port ports[MAX_PORTS];
	uint32_t num_ports;
	
	/* Scheduler state */
	uint32_t current_port;    /* Round-robin port index */
	uint32_t current_prio;    /* Current priority being served */
	
	/* Memory pool for voq_entry */
	struct voq_entry *free_entries;
	uint32_t num_free_entries;
	uint32_t total_entries;
	pthread_mutex_t pool_lock;
	
	/* Configuration */
	uint32_t quantum[MAX_PRIORITIES];  /* Quantum per priority */
	uint32_t max_depth[MAX_PRIORITIES]; /* Max queue depth per priority */
	
	/* Statistics */
	uint64_t total_enqueued;
	uint64_t total_dequeued;
	uint64_t total_dropped;
	uint64_t scheduler_rounds;
	
	/* Control */
	volatile bool running;
	pthread_t scheduler_thread;
};

/*
 * VOQ Manager Functions
 */

/* Initialize VOQ manager */
int voq_mgr_init(struct voq_mgr *mgr, uint32_t num_ports);

/* Destroy VOQ manager and free resources */
void voq_mgr_destroy(struct voq_mgr *mgr);

/* Add port to VOQ manager */
int voq_add_port(struct voq_mgr *mgr, uint32_t port_idx, uint32_t ifindex, const char *ifname);

/* Configure port rate limiting */
int voq_set_port_rate(struct voq_mgr *mgr, uint32_t port_idx, uint64_t rate_bps, uint64_t burst_bytes);

/* Configure queue parameters */
int voq_set_queue_params(struct voq_mgr *mgr, uint32_t prio, uint32_t quantum, uint32_t max_depth);

/*
 * Queue Operations
 */

/* Enqueue packet metadata */
int voq_enqueue(struct voq_mgr *mgr, uint32_t port_idx, uint32_t prio,
                uint64_t ts_ns, uint32_t len, uint32_t flow_hash,
                uint8_t ecn_hint, uint8_t drop_hint, uint64_t xdp_frame);

/* Dequeue packet for transmission (DRR scheduler) */
struct voq_entry *voq_dequeue(struct voq_mgr *mgr, uint32_t *port_idx);

/* Free dequeued entry back to pool */
void voq_free_entry(struct voq_mgr *mgr, struct voq_entry *entry);

/* Get queue statistics */
void voq_get_queue_stats(struct voq_mgr *mgr, uint32_t port_idx, uint32_t prio,
                         uint64_t *enqueued, uint64_t *dequeued, uint64_t *dropped,
                         uint64_t *depth, uint64_t *latency_p99_ns);

/* Get port statistics */
void voq_get_port_stats(struct voq_mgr *mgr, uint32_t port_idx,
                        uint64_t *total_enq, uint64_t *total_deq, uint64_t *total_drop);

/* Print statistics */
void voq_print_stats(struct voq_mgr *mgr);

/*
 * Scheduler
 */

/* Start scheduler thread */
int voq_start_scheduler(struct voq_mgr *mgr);

/* Stop scheduler thread */
void voq_stop_scheduler(struct voq_mgr *mgr);

/* Single scheduler iteration (for manual control) */
int voq_scheduler_step(struct voq_mgr *mgr);

#endif /* __VOQ_H__ */
