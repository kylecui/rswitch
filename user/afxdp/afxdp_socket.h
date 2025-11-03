/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __AFXDP_SOCKET_H__
#define __AFXDP_SOCKET_H__

#include <stdint.h>
#include <stdbool.h>
#include <net/if.h>
#include <linux/if_xdp.h>
#include <bpf/xsk.h>

/*
 * AF_XDP Socket Interface
 * 
 * Provides zero-copy packet I/O using AF_XDP sockets.
 * Supports UMEM allocation, Rx/Tx ring management, and poll-based I/O.
 */

#define FRAME_SIZE 2048
#define NUM_FRAMES 4096
#define BATCH_SIZE 64

/* UMEM (User Memory) - Shared packet buffer pool */
struct xsk_umem {
	void *buffer;              /* mmap'd memory region */
	uint64_t size;             /* Total size in bytes */
	uint32_t frame_size;       /* Size of each frame */
	uint32_t num_frames;       /* Total number of frames */
	
	/* UMEM fill and completion rings */
	struct xsk_ring_prod fq;   /* Fill queue (kernel -> user, gives frames to fill) */
	struct xsk_ring_cons cq;   /* Completion queue (kernel -> user, completed TX frames) */
	
	int fd;                    /* UMEM file descriptor */
};

/* AF_XDP Socket */
struct xsk_socket {
	struct xsk_socket__rx *rx;  /* RX socket (libbpf) */
	struct xsk_socket__tx *tx;  /* TX socket (libbpf) */
	int fd;                     /* Socket file descriptor */
	char ifname[IFNAMSIZ];      /* Interface name */
	uint32_t queue_id;          /* RX queue ID */
	
	struct xsk_umem *umem;      /* Associated UMEM */
	
	/* Frame management */
	uint64_t *free_frames;      /* Free frame pool (UMEM offsets) */
	uint32_t num_free_frames;   /* Number of available frames */
	uint32_t free_idx;          /* Current index in free pool */
	
	/* Statistics */
	uint64_t rx_packets;
	uint64_t rx_bytes;
	uint64_t tx_packets;
	uint64_t tx_bytes;
	uint64_t rx_dropped;
	uint64_t tx_failed;
};

/* Configuration for socket creation */
struct xsk_config {
	uint32_t rx_size;          /* RX ring size (power of 2) */
	uint32_t tx_size;          /* TX ring size (power of 2) */
	uint32_t frame_size;       /* Frame size in bytes */
	uint32_t num_frames;       /* Total UMEM frames */
	uint32_t bind_flags;       /* XDP_ZEROCOPY, XDP_COPY */
	uint32_t xdp_flags;        /* XDP_FLAGS_DRV_MODE, XDP_FLAGS_SKB_MODE */
	bool shared_umem;          /* Share UMEM with other sockets */
};

/* Packet buffer - Points to frame in UMEM */
struct xsk_packet {
	void *data;                /* Pointer to packet data */
	uint32_t len;              /* Packet length */
	uint64_t addr;             /* UMEM offset */
};

/*
 * UMEM Management
 */

/* Create and initialize UMEM */
int xsk_umem_create(struct xsk_umem **umem_out, 
                    uint32_t frame_size, 
                    uint32_t num_frames);

/* Destroy UMEM and free resources */
void xsk_umem_destroy(struct xsk_umem *umem);

/* Get frame address in UMEM */
static inline void *xsk_umem_get_frame(struct xsk_umem *umem, uint64_t addr)
{
	return (void *)((uint8_t *)umem->buffer + addr);
}

/*
 * Socket Management
 */

/* Create AF_XDP socket */
int xsk_socket_create(struct xsk_socket **xsk_out,
                      const char *ifname,
                      uint32_t queue_id,
                      struct xsk_umem *umem,
                      struct xsk_config *config);

/* Destroy socket */
void xsk_socket_destroy(struct xsk_socket *xsk);

/* Get socket file descriptor for polling */
static inline int xsk_socket_get_fd(struct xsk_socket *xsk)
{
	return xsk->fd;
}

/*
 * Frame Management
 */

/* Allocate a frame from free pool */
uint64_t xsk_alloc_frame(struct xsk_socket *xsk);

/* Free a frame back to pool */
void xsk_free_frame(struct xsk_socket *xsk, uint64_t addr);

/* Reclaim completed TX frames */
void xsk_reclaim_tx_frames(struct xsk_socket *xsk);

/*
 * Packet I/O
 */

/* Receive packets (returns number of packets received) */
uint32_t xsk_rx_batch(struct xsk_socket *xsk, 
                      struct xsk_packet *pkts,
                      uint32_t batch_size);

/* Transmit packets (returns number of packets sent) */
uint32_t xsk_tx_batch(struct xsk_socket *xsk,
                      struct xsk_packet *pkts,
                      uint32_t num_pkts);

/* Kick TX (trigger kernel to process TX ring) */
int xsk_tx_kick(struct xsk_socket *xsk);

/* Fill the fill queue with frames */
void xsk_fill_fq(struct xsk_socket *xsk, uint32_t num_frames);

/*
 * Statistics
 */

/* Get socket statistics */
void xsk_get_stats(struct xsk_socket *xsk,
                   uint64_t *rx_packets,
                   uint64_t *rx_bytes,
                   uint64_t *tx_packets,
                   uint64_t *tx_bytes);

/* Print socket statistics */
void xsk_print_stats(struct xsk_socket *xsk);

#endif /* __AFXDP_SOCKET_H__ */
