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

/* Software queue entry for queue-constrained NICs */
struct sw_queue_entry {
	uint8_t *data;           /* Packet data buffer */
	uint32_t len;            /* Packet length */
	uint64_t ts_ns;          /* Timestamp */
	uint32_t flow_hash;      /* Flow hash for scheduling */
	uint8_t priority;        /* Packet priority */
	struct sw_queue_entry *next; /* Next entry in queue */
};

/* Software queue for each port/priority combination */
struct sw_queue {
	struct sw_queue_entry *head;    /* Queue head */
	struct sw_queue_entry *tail;    /* Queue tail */
	uint32_t depth;                 /* Current queue depth */
	uint32_t max_depth;             /* Maximum queue depth */
	uint64_t enqueued;              /* Total enqueued packets */
	uint64_t dequeued;              /* Total dequeued packets */
	uint64_t dropped;               /* Total dropped packets */
};

/* Software queue manager */
struct sw_queue_mgr {
	struct sw_queue **queues;       /* 2D array: [port][priority] */
	uint32_t num_ports;             /* Number of ports */
	uint32_t num_priorities;        /* Number of priorities */
	uint32_t total_depth;           /* Total current depth across all queues */
	uint32_t max_total_depth;       /* Maximum total depth */
	
	/* Memory pool for queue entries */
	struct sw_queue_entry *pool;    /* Pre-allocated entry pool */
	uint32_t pool_size;             /* Pool size */
	uint32_t pool_used;             /* Used entries in pool */
	
	/* Packet buffer pool */
	uint8_t *buffer_pool;           /* Pre-allocated packet buffers */
	uint32_t buffer_size;           /* Size of each buffer */
	uint32_t buffers_used;          /* Used buffers */
};

/* Data plane configuration */
struct voqd_dataplane_config {
	/* AF_XDP configuration */
	bool enable_afxdp;         /* Enable AF_XDP sockets */
	bool zero_copy;            /* Use zero-copy mode */
	uint32_t rx_ring_size;     /* RX ring size (power of 2) */
	uint32_t tx_ring_size;     /* TX ring size */
	uint32_t frame_size;       /* UMEM frame size (2048/4096) */
	
	/* Software queue simulation (for queue-constrained NICs) */
	bool enable_sw_queues;     /* Enable software queue simulation */
	uint32_t sw_queue_depth;   /* Software queue depth per port/priority */
	
	/* Scheduler configuration */
	bool enable_scheduler;     /* Enable TX scheduler thread */
	uint32_t batch_size;       /* RX/TX batch size */
	uint32_t poll_timeout_ms;  /* Poll timeout */
	
	/* Performance tuning */
	bool busy_poll;            /* Use busy polling (lower latency) */
	bool adaptive_batch;       /* Adaptive batch sizing */
	uint32_t cpu_affinity;     /* CPU to pin threads to (0 = no pinning) */
	
	/* QoS classification */
	uint8_t dscp_to_prio[64];  /* DSCP value (0-63) to priority mapping */
	uint8_t default_prio;      /* Default priority for unmapped DSCP */
	
	/* Veth egress configuration (for XDP egress processing) */
	bool use_veth_egress;      /* Enable veth egress path */
	char veth_in_ifname[16];   /* Veth inside interface (e.g., "veth_voq_in") */
	uint32_t veth_in_ifindex;  /* Veth inside interface index */
	uint32_t veth_queue_id;    /* Queue ID for veth AF_XDP socket */
};

/* Data plane runtime state */
struct voqd_dataplane {
	/* Components */
	struct voq_mgr *voq;              /* VOQ manager */
	struct xsk_manager xsk_mgr;       /* AF_XDP manager (RX from physical NICs) */
	struct xsk_manager veth_xsk_mgr;  /* AF_XDP manager (TX to veth) */
	struct sw_queue_mgr sw_mgr;       /* Software queue manager */
	
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
	
	/* Debug counters */
	uint32_t rx_debug_count;
	uint32_t tx_debug_count;
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
 * QoS Classification Functions
 */

/* Extract priority from packet using IP DSCP or fallback to default */
uint8_t voqd_extract_priority_from_packet(const uint8_t *packet, size_t len, 
                                         const uint8_t *dscp_to_prio, uint8_t default_prio);

/* Parse DSCP value from IP packet header */
uint8_t voqd_parse_ip_dscp(const uint8_t *packet, size_t len);

/* Check if packet is IPv4 */
bool voqd_is_ipv4_packet(const uint8_t *packet, size_t len);

/* Check if packet is IPv6 */
bool voqd_is_ipv6_packet(const uint8_t *packet, size_t len);

/*
 * Software Queue Functions (for queue-constrained NICs)
 */

/* Initialize software queue manager */
int sw_queue_mgr_init(struct sw_queue_mgr *mgr, uint32_t num_ports, 
                      uint32_t num_priorities, uint32_t queue_depth,
                      uint32_t max_frame_size);

/* Destroy software queue manager */
void sw_queue_mgr_destroy(struct sw_queue_mgr *mgr);

/* Enqueue packet into software queue */
int sw_queue_enqueue(struct sw_queue_mgr *mgr, uint32_t port_idx, uint8_t priority,
                     const uint8_t *data, uint32_t len, uint64_t ts_ns, uint32_t flow_hash);

/* Dequeue packet from software queue (priority-based) */
struct sw_queue_entry *sw_queue_dequeue(struct sw_queue_mgr *mgr, uint32_t *port_idx);

/* Free software queue entry */
void sw_queue_free_entry(struct sw_queue_mgr *mgr, struct sw_queue_entry *entry);

/* Get software queue statistics */
void sw_queue_get_stats(struct sw_queue_mgr *mgr, uint32_t port_idx, uint8_t priority,
                        uint64_t *enqueued, uint64_t *dequeued, uint64_t *dropped);

/* Process RX batch from AF_XDP socket */
int voqd_dataplane_rx_process(struct voqd_dataplane *dp, uint32_t port_idx);

/* Process TX scheduling and transmission */
int voqd_dataplane_tx_process(struct voqd_dataplane *dp);

/* RX thread function */
void *voqd_dataplane_rx_thread(void *arg);

/* TX thread function */
void *voqd_dataplane_tx_thread(void *arg);

#endif /* __VOQD_DATAPLANE_H__ */
