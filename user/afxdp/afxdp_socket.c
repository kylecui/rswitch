/* SPDX-License-Identifier: GPL-2.0 */
/*
 * AF_XDP Socket Implementation
 * 
 * Provides zero-copy packet I/O using AF_XDP sockets with UMEM management.
 * Based on libbpf's xsk API but simplified for rSwitch use case.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <poll.h>

#include <bpf/libbpf.h>
#include <bpf/xsk.h>

#include "afxdp_socket.h"

/*
 * UMEM Management
 */

int xsk_umem_create(struct xsk_umem **umem_out, 
                    uint32_t frame_size, 
                    uint32_t num_frames)
{
	struct xsk_umem *umem;
	struct xsk_umem_config cfg = {
		.fill_size = num_frames / 2,
		.comp_size = num_frames / 2,
		.frame_size = frame_size,
		.frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
		.flags = 0,
	};
	size_t size = num_frames * frame_size;
	void *buffer;
	int ret;
	struct xsk_umem_info *umem_info;
	
	/* Allocate UMEM structure */
	umem = calloc(1, sizeof(*umem));
	if (!umem)
		return -ENOMEM;
	
	/* Allocate memory-mapped buffer */
	buffer = mmap(NULL, size, PROT_READ | PROT_WRITE,
	              MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB,
	              -1, 0);
	if (buffer == MAP_FAILED) {
		/* Fallback to regular pages if huge pages fail */
		buffer = mmap(NULL, size, PROT_READ | PROT_WRITE,
		              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (buffer == MAP_FAILED) {
			ret = -errno;
			free(umem);
			return ret;
		}
	}
	
	umem->buffer = buffer;
	umem->size = size;
	umem->frame_size = frame_size;
	umem->num_frames = num_frames;
	
	/* Create UMEM using libbpf xsk API */
	ret = xsk_umem__create(&umem_info, buffer, size, &umem->fq, &umem->cq, &cfg);
	if (ret) {
		munmap(buffer, size);
		free(umem);
		return ret;
	}
	
	*umem_out = umem;
	return 0;
}

void xsk_umem_destroy(struct xsk_umem *umem)
{
	if (!umem)
		return;
	
	if (umem->buffer)
		munmap(umem->buffer, umem->size);
	
	free(umem);
}

/*
 * Socket Management
 */

int xsk_socket_create(struct xsk_socket **xsk_out,
                      const char *ifname,
                      uint32_t queue_id,
                      struct xsk_umem *umem,
                      struct xsk_config *config)
{
	struct xsk_socket *xsk;
	struct xsk_socket_config xsk_cfg = {0};
	struct xsk_socket *xsk_socket;
	int ret, i;
	uint32_t ifindex;
	
	if (!umem || !ifname || !config)
		return -EINVAL;
	
	/* Allocate socket structure */
	xsk = calloc(1, sizeof(*xsk));
	if (!xsk)
		return -ENOMEM;
	
	strncpy(xsk->ifname, ifname, IFNAMSIZ - 1);
	xsk->queue_id = queue_id;
	xsk->umem = umem;
	
	/* Get interface index */
	ifindex = if_nametoindex(ifname);
	if (!ifindex) {
		ret = -errno;
		free(xsk);
		return ret;
	}
	
	/* Configure socket */
	xsk_cfg.rx_size = config->rx_size;
	xsk_cfg.tx_size = config->tx_size;
	xsk_cfg.bind_flags = config->bind_flags;
	xsk_cfg.xdp_flags = config->xdp_flags;
	
	/* Create socket using libbpf xsk API */
	ret = xsk_socket__create(&xsk_socket, ifname, queue_id,
	                          NULL,  /* Will use umem's fq/cq */
	                          NULL, NULL, &xsk_cfg);
	if (ret) {
		free(xsk);
		return ret;
	}
	
	xsk->rx = (struct xsk_socket__rx *)xsk_socket;
	xsk->tx = (struct xsk_socket__tx *)xsk_socket;
	xsk->fd = xsk_socket__fd(xsk_socket);
	
	/* Initialize free frame pool */
	xsk->free_frames = calloc(config->num_frames, sizeof(uint64_t));
	if (!xsk->free_frames) {
		xsk_socket__delete(xsk_socket);
		free(xsk);
		return -ENOMEM;
	}
	
	/* Populate free frame pool with UMEM offsets */
	xsk->num_free_frames = config->num_frames;
	xsk->free_idx = 0;
	for (i = 0; i < config->num_frames; i++) {
		xsk->free_frames[i] = i * config->frame_size;
	}
	
	*xsk_out = xsk;
	return 0;
}

void xsk_socket_destroy(struct xsk_socket *xsk)
{
	if (!xsk)
		return;
	
	if (xsk->rx)
		xsk_socket__delete((struct xsk_socket *)xsk->rx);
	
	if (xsk->free_frames)
		free(xsk->free_frames);
	
	free(xsk);
}

/*
 * Frame Management
 */

uint64_t xsk_alloc_frame(struct xsk_socket *xsk)
{
	if (xsk->free_idx >= xsk->num_free_frames)
		return UINT64_MAX;  /* No free frames */
	
	return xsk->free_frames[xsk->free_idx++];
}

void xsk_free_frame(struct xsk_socket *xsk, uint64_t addr)
{
	if (xsk->free_idx == 0)
		return;  /* Frame pool full (should never happen) */
	
	xsk->free_frames[--xsk->free_idx] = addr;
}

void xsk_reclaim_tx_frames(struct xsk_socket *xsk)
{
	uint32_t idx_cq = 0;
	uint32_t rcvd;
	
	/* Get the raw xsk_socket from our wrapper */
	struct xsk_socket *raw_xsk = (struct xsk_socket *)xsk->rx;
	
	/* Consume completion queue - uses parent umem */
	rcvd = xsk_ring_cons__peek(&xsk->umem->cq, xsk->num_free_frames - xsk->free_idx, &idx_cq);
	if (rcvd == 0)
		return;
	
	/* Return frames to free pool */
	for (uint32_t i = 0; i < rcvd; i++) {
		uint64_t addr = *xsk_ring_cons__comp_addr(&xsk->umem->cq, idx_cq++);
		xsk_free_frame(xsk, addr);
	}
	
	xsk_ring_cons__release(&xsk->umem->cq, rcvd);
}

/*
 * Packet I/O
 */

void xsk_fill_fq(struct xsk_socket *xsk, uint32_t num_frames)
{
	uint32_t idx_fq = 0;
	uint32_t avail;
	
	/* Reserve space in fill queue */
	avail = xsk_ring_prod__reserve(&xsk->umem->fq, num_frames, &idx_fq);
	if (avail == 0)
		return;
	
	/* Fill with free frames */
	for (uint32_t i = 0; i < avail; i++) {
		uint64_t addr = xsk_alloc_frame(xsk);
		if (addr == UINT64_MAX)
			break;
		*xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq++) = addr;
	}
	
	xsk_ring_prod__submit(&xsk->umem->fq, avail);
}

uint32_t xsk_rx_batch(struct xsk_socket *xsk, 
                      struct xsk_packet *pkts,
                      uint32_t batch_size)
{
	uint32_t idx_rx = 0;
	uint32_t rcvd;
	struct xsk_socket *raw_xsk = (struct xsk_socket *)xsk->rx;
	struct xsk_ring_cons *rx_ring = xsk_socket__get_rx_ring(raw_xsk);
	
	/* Peek RX ring */
	rcvd = xsk_ring_cons__peek(rx_ring, batch_size, &idx_rx);
	if (rcvd == 0)
		return 0;
	
	/* Extract packets */
	for (uint32_t i = 0; i < rcvd; i++) {
		const struct xdp_desc *desc = xsk_ring_cons__rx_desc(rx_ring, idx_rx++);
		pkts[i].addr = desc->addr;
		pkts[i].len = desc->len;
		pkts[i].data = xsk_umem_get_frame(xsk->umem, desc->addr);
		
		xsk->rx_packets++;
		xsk->rx_bytes += desc->len;
	}
	
	/* Release RX descriptors */
	xsk_ring_cons__release(rx_ring, rcvd);
	
	/* Refill fill queue */
	xsk_fill_fq(xsk, rcvd);
	
	return rcvd;
}

uint32_t xsk_tx_batch(struct xsk_socket *xsk,
                      struct xsk_packet *pkts,
                      uint32_t num_pkts)
{
	uint32_t idx_tx = 0;
	uint32_t sent;
	struct xsk_socket *raw_xsk = (struct xsk_socket *)xsk->rx;
	struct xsk_ring_prod *tx_ring = xsk_socket__get_tx_ring(raw_xsk);
	
	/* Reclaim completed TX frames first */
	xsk_reclaim_tx_frames(xsk);
	
	/* Reserve space in TX ring */
	sent = xsk_ring_prod__reserve(tx_ring, num_pkts, &idx_tx);
	if (sent == 0)
		return 0;
	
	/* Populate TX descriptors */
	for (uint32_t i = 0; i < sent; i++) {
		struct xdp_desc *desc = xsk_ring_prod__tx_desc(tx_ring, idx_tx++);
		desc->addr = pkts[i].addr;
		desc->len = pkts[i].len;
		
		xsk->tx_packets++;
		xsk->tx_bytes += pkts[i].len;
	}
	
	/* Submit to kernel */
	xsk_ring_prod__submit(tx_ring, sent);
	
	return sent;
}

int xsk_tx_kick(struct xsk_socket *xsk)
{
	return sendto(xsk->fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
}

/*
 * Statistics
 */

void xsk_get_stats(struct xsk_socket *xsk,
                   uint64_t *rx_packets,
                   uint64_t *rx_bytes,
                   uint64_t *tx_packets,
                   uint64_t *tx_bytes)
{
	if (rx_packets)
		*rx_packets = xsk->rx_packets;
	if (rx_bytes)
		*rx_bytes = xsk->rx_bytes;
	if (tx_packets)
		*tx_packets = xsk->tx_packets;
	if (tx_bytes)
		*tx_bytes = xsk->tx_bytes;
}

void xsk_print_stats(struct xsk_socket *xsk)
{
	printf("AF_XDP Socket Stats (%s queue %u):\n", xsk->ifname, xsk->queue_id);
	printf("  RX: %lu packets, %lu bytes\n", xsk->rx_packets, xsk->rx_bytes);
	printf("  TX: %lu packets, %lu bytes\n", xsk->tx_packets, xsk->tx_bytes);
	printf("  Dropped: %lu\n", xsk->rx_dropped);
	printf("  TX failed: %lu\n", xsk->tx_failed);
}
