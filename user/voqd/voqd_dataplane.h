/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __VOQD_DATAPLANE_H__
#define __VOQD_DATAPLANE_H__

#include <stdint.h>
#include <stdbool.h>

#include "voq.h"
#include "afxdp_socket.h"

/*
 * VOQd Data Plane - AF_XDP Integration
 * 
 * Connects AF_XDP sockets with VOQ scheduler for complete data plane.
 * Handles packet reception, queuing, scheduling, and transmission.
 */

/* Data plane configuration */
struct voqd_dataplane_config {
	/* AF_XDP configuration */
	bool enable_afxdp;         /* Enable AF_XDP sockets */
	bool zero_copy;            /* Use zero-copy mode */
	uint32_t rx_ring_size;     /* RX ring size (power of 2) */
	uint32_t tx_ring_size;     /* TX ring size */
	uint32_t frame_size;       /* UMEM frame size (2048/4096) */
	
	/* Scheduler configuration */
	bool enable_scheduler;     /* Enable TX scheduler thread */
	uint32_t batch_size;       /* RX/TX batch size */
	uint32_t poll_timeout_ms;  /* Poll timeout */
	
	/* Performance tuning */
	bool busy_poll;            /* Use busy polling (lower latency) */
	bool adaptive_batch;       /* Adaptive batch sizing */
	uint32_t cpu_affinity;     /* CPU to pin threads to (0 = no pinning) */
};

/* Data plane runtime state */
struct voqd_dataplane {
	/* Components */
	struct voq_mgr *voq;              /* VOQ manager */
	struct xsk_manager xsk_mgr;       /* AF_XDP manager */
	
	/* Configuration */
	struct voqd_dataplane_config config;
	uint32_t num_ports;
	
	/* Runtime state */
	volatile bool running;
	pthread_t rx_thread;              /* RX processing thread */
	pthread_t tx_thread;              /* TX scheduling thread */
	
	/* Packet buffers */
	uint64_t rx_frames[256];          /* RX frame addresses */
	uint32_t rx_lengths[256];         /* RX packet lengths */
	uint64_t tx_frames[256];          /* TX frame addresses */
	uint32_t tx_lengths[256];         /* TX packet lengths */
	
	/* Statistics */
	uint64_t rx_packets;
	uint64_t rx_bytes;
	uint64_t tx_packets;
	uint64_t tx_bytes;
	uint64_t enqueue_errors;
	uint64_t tx_errors;
	uint64_t scheduler_rounds;
	
	/* Performance metrics */
	uint64_t rx_batch_sum;
	uint64_t rx_batch_count;
	uint64_t tx_batch_sum;
	uint64_t tx_batch_count;
};

/*
 * Data Plane Functions
 */

/* Initialize data plane */
int voqd_dataplane_init(struct voqd_dataplane *dp, struct voq_mgr *voq,
                        struct voqd_dataplane_config *config);

/* Destroy data plane */
void voqd_dataplane_destroy(struct voqd_dataplane *dp);

/* Start data plane (RX and TX threads) */
int voqd_dataplane_start(struct voqd_dataplane *dp);

/* Stop data plane */
void voqd_dataplane_stop(struct voqd_dataplane *dp);

/* Add AF_XDP socket for port */
int voqd_dataplane_add_port(struct voqd_dataplane *dp, const char *ifname,
                            uint32_t port_idx, uint32_t queue_id);

/* Get data plane statistics */
void voqd_dataplane_get_stats(struct voqd_dataplane *dp,
                              uint64_t *rx_pkts, uint64_t *rx_bytes,
                              uint64_t *tx_pkts, uint64_t *tx_bytes);

/* Print data plane statistics */
void voqd_dataplane_print_stats(struct voqd_dataplane *dp);

/*
 * Internal RX/TX Processing (exposed for testing)
 */

/* Process RX batch from AF_XDP socket */
int voqd_dataplane_rx_process(struct voqd_dataplane *dp, uint32_t port_idx);

/* Process TX scheduling and transmission */
int voqd_dataplane_tx_process(struct voqd_dataplane *dp);

/* RX thread function */
void *voqd_dataplane_rx_thread(void *arg);

/* TX thread function */
void *voqd_dataplane_tx_thread(void *arg);

#endif /* __VOQD_DATAPLANE_H__ */
