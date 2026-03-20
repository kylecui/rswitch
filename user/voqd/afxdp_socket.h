/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __AFXDP_SOCKET_H__
#define __AFXDP_SOCKET_H__

#include <stdint.h>
#include <stdbool.h>
#include <linux/if_link.h>

/* Use libxdp's definitions if available, otherwise define our own */
#ifdef HAVE_LIBBPF_XSK
#include <xdp/xsk.h>
#else

/*
 * AF_XDP Socket Management for VOQd
 * 
 * Handles XDP socket setup, UMEM management, and packet RX/TX.
 * Integrates with VOQ manager for priority-based queuing.
 * 
 * NOTE: These are fallback definitions when libxdp is not available.
 * With libxdp, use the official xsk.h structures.
 */

/* AF_XDP configuration */
struct xsk_socket_config {
	uint32_t rx_size;           /* RX ring size (power of 2) */
	uint32_t tx_size;           /* TX ring size (power of 2) */
	uint32_t fill_size;         /* Fill ring size */
	uint32_t comp_size;         /* Completion ring size */
	uint32_t frame_size;        /* UMEM frame size (2048 or 4096) */
	uint32_t frame_headroom;    /* Headroom per frame */
	uint16_t bind_flags;        /* XDP bind flags */
	uint16_t xdp_flags;         /* XDP attach flags */
	uint32_t queue_id;          /* NIC queue ID */
};

/* UMEM configuration */
struct xsk_umem_config {
	uint64_t size;              /* Total UMEM size */
	uint32_t frame_size;        /* Frame size */
	uint32_t frame_headroom;    /* Headroom */
	uint32_t fill_size;         /* Fill ring size */
	uint32_t comp_size;         /* Completion ring size */
	uint32_t flags;             /* UMEM flags */
};

#endif /* HAVE_LIBBPF_XSK */

/* AF_XDP socket instance */
struct xsk_socket {
	int xsk_fd;                 /* AF_XDP socket fd */
	int ifindex;                /* Interface index */
	uint32_t queue_id;          /* Queue ID */
	
	/* UMEM (shared memory for packets) */
	void *umem_area;            /* UMEM base address */
	uint64_t umem_size;         /* UMEM total size */
	uint32_t frame_size;        /* Per-frame size */
	uint32_t num_frames;        /* Total number of frames */
	
	/* libxdp structures */
	struct xsk_socket *xsk_sock; /* libxdp socket */
	struct xsk_umem *umem;      /* libxdp UMEM */
	
	/* Ring buffers (kernel shared) */
	struct xsk_ring_cons rx_ring;    /* RX ring */
	struct xsk_ring_prod tx_ring;    /* TX ring */
	struct xsk_ring_prod fill_ring;  /* Fill queue */
	struct xsk_ring_cons comp_ring;  /* Completion queue */
	
	/* Ring metadata */
	uint32_t rx_size;
	uint32_t tx_size;
	uint32_t fill_size;
	uint32_t comp_size;
	
	/* Producer/Consumer indices (cached) */
	uint32_t rx_cached_prod;
	uint32_t rx_cached_cons;
	uint32_t tx_cached_prod;
	uint32_t tx_cached_cons;
	
	/* Frame management (stack-based free pool) */
	uint64_t *free_frame_stack; /* Stack of free frame addresses */
	uint32_t free_stack_size;   /* Current number of free frames on stack */
	uint32_t free_stack_cap;    /* Capacity of free_frame_stack array */
	
	/* Statistics */
	uint64_t rx_packets;
	uint64_t rx_bytes;
	uint64_t tx_packets;
	uint64_t tx_bytes;
	uint64_t rx_drops;
	uint64_t tx_drops;
	
	/* Configuration */
	struct xsk_socket_config config;
};

/* AF_XDP manager (multi-port support) */
struct xsk_manager {
	struct xsk_socket *sockets[64];  /* One per port/queue */
	uint32_t num_sockets;
	
	/* Global UMEM (shared across sockets if desired) */
	void *global_umem;
	uint64_t global_umem_size;
	
	/* Configuration */
	bool use_shared_umem;
	bool zero_copy;
	
	/* Statistics */
	uint64_t total_rx;
	uint64_t total_tx;
};

/*
 * AF_XDP Socket Functions
 */

/* Create AF_XDP socket on interface and queue */
int xsk_socket_create(struct xsk_socket **xsk_out, const char *ifname,
                      uint32_t queue_id, struct xsk_socket_config *config);

/* Destroy AF_XDP socket and free resources */
void xsk_socket_destroy(struct xsk_socket *xsk);

/* Receive packets from AF_XDP socket */
int xsk_socket_rx_batch(struct xsk_socket *xsk, uint64_t *frames,
                        uint32_t *lengths, uint32_t max_batch);

/* Transmit packets via AF_XDP socket */
int xsk_socket_tx_batch(struct xsk_socket *xsk, uint64_t *frames,
                        uint32_t *lengths, uint32_t num_frames);

/* Refill Fill ring with free frames */
int xsk_socket_fill_ring(struct xsk_socket *xsk, uint32_t num_frames);

/* Process Completion ring (reclaim transmitted frames) */
int xsk_socket_complete_tx(struct xsk_socket *xsk);

/* Get socket statistics */
void xsk_socket_get_stats(struct xsk_socket *xsk,
                          uint64_t *rx_pkts, uint64_t *rx_bytes,
                          uint64_t *tx_pkts, uint64_t *tx_bytes,
                          uint64_t *rx_drops, uint64_t *tx_drops);

/* Allocate free frame from UMEM */
uint64_t xsk_alloc_frame(struct xsk_socket *xsk);

/* Free frame back to UMEM pool */
void xsk_free_frame(struct xsk_socket *xsk, uint64_t frame_addr);

/* Get packet data pointer from frame address */
void *xsk_get_frame_data(struct xsk_socket *xsk, uint64_t frame_addr);

/*
 * AF_XDP Manager Functions
 */

/* Initialize AF_XDP manager */
int xsk_manager_init(struct xsk_manager *mgr, bool use_shared_umem, bool zero_copy);

/* Destroy AF_XDP manager */
void xsk_manager_destroy(struct xsk_manager *mgr);

/* Add socket to manager */
int xsk_manager_add_socket(struct xsk_manager *mgr, const char *ifname,
                           uint32_t queue_id, struct xsk_socket_config *config);

/* Get socket by index */
struct xsk_socket *xsk_manager_get_socket(struct xsk_manager *mgr, uint32_t idx);

/* Poll all sockets for RX */
int xsk_manager_poll_rx(struct xsk_manager *mgr, int timeout_ms);

/* Process TX completions for all sockets */
void xsk_manager_complete_all_tx(struct xsk_manager *mgr);

/* Get manager statistics */
void xsk_manager_get_stats(struct xsk_manager *mgr,
                           uint64_t *total_rx, uint64_t *total_tx);

#endif /* __AFXDP_SOCKET_H__ */
