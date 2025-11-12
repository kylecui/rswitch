// SPDX-License-Identifier: GPL-2.0
/*
 * AF_XDP Socket Implementation for VOQd
 * 
 * NOTE: This is a simplified implementation demonstrating the structure.
 * Full implementation requires libbpf >= 1.0 with xsk.h support.
 * 
 * For production use, link against libbpf and use:
 *   #include <xsk.h>
 *   xsk_socket__create(), xsk_umem__create(), etc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_xdp.h>
#include <net/if.h>
#include <poll.h>

#include "afxdp_socket.h"

/* Feature check at compile time */
#ifdef HAVE_LIBBPF_XSK

/*
 * Full AF_XDP implementation using libbpf xsk helpers
 */

#include <bpf/xsk.h>

int xsk_socket_create(struct xsk_socket **xsk_out, const char *ifname,
                      uint32_t queue_id, struct xsk_socket_config *config)
{
	struct xsk_socket *xsk;
	struct xsk_umem_config umem_cfg;
	struct xsk_socket_config xsk_cfg;
	struct xsk_ring_cons *rx;
	struct xsk_ring_prod *tx;
	struct xsk_umem *umem;
	void *umem_area;
	int ret;
	
	/* Allocate socket structure */
	xsk = calloc(1, sizeof(*xsk));
	if (!xsk)
		return -ENOMEM;
	
	/* Get interface index */
	xsk->ifindex = if_nametoindex(ifname);
	if (!xsk->ifindex) {
		fprintf(stderr, "Interface %s not found\n", ifname);
		free(xsk);
		return -ENODEV;
	}
	
	xsk->queue_id = queue_id;
	xsk->frame_size = config->frame_size;
	xsk->num_frames = config->rx_size + config->tx_size;
	xsk->umem_size = xsk->num_frames * xsk->frame_size;
	
	/* Allocate UMEM (huge pages preferred for performance) */
	umem_area = mmap(NULL, xsk->umem_size,
	                 PROT_READ | PROT_WRITE,
	                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB,
	                 -1, 0);
	
	if (umem_area == MAP_FAILED) {
		/* Fallback to regular pages */
		umem_area = mmap(NULL, xsk->umem_size,
		                 PROT_READ | PROT_WRITE,
		                 MAP_PRIVATE | MAP_ANONYMOUS,
		                 -1, 0);
		
		if (umem_area == MAP_FAILED) {
			fprintf(stderr, "Failed to allocate UMEM: %s\n", strerror(errno));
			free(xsk);
			return -ENOMEM;
		}
	}
	
	xsk->umem_area = umem_area;
	
	/* Configure UMEM */
	umem_cfg.fill_size = config->fill_size;
	umem_cfg.comp_size = config->comp_size;
	umem_cfg.frame_size = config->frame_size;
	umem_cfg.frame_headroom = config->frame_headroom;
	umem_cfg.flags = 0;
	
	/* Create UMEM */
	ret = xsk_umem__create(&umem, umem_area, xsk->umem_size,
	                       &xsk->fill_ring, &xsk->comp_ring, &umem_cfg);
	if (ret) {
		fprintf(stderr, "Failed to create UMEM: %s\n", strerror(-ret));
		munmap(umem_area, xsk->umem_size);
		free(xsk);
		return ret;
	}
	
	/* Configure socket */
	xsk_cfg.rx_size = config->rx_size;
	xsk_cfg.tx_size = config->tx_size;
	xsk_cfg.libbpf_flags = 0;
	xsk_cfg.xdp_flags = config->xdp_flags;
	xsk_cfg.bind_flags = config->bind_flags;
	
	/* Create socket */
	ret = xsk_socket__create(&xsk->xsk, ifname, queue_id, umem,
	                         &xsk->rx_ring, &xsk->tx_ring, &xsk_cfg);
	if (ret) {
		fprintf(stderr, "Failed to create XSK socket: %s\n", strerror(-ret));
		xsk_umem__delete(umem);
		munmap(umem_area, xsk->umem_size);
		free(xsk);
		return ret;
	}
	
	/* Store ring sizes */
	xsk->rx_size = config->rx_size;
	xsk->tx_size = config->tx_size;
	xsk->fill_size = config->fill_size;
	xsk->comp_size = config->comp_size;
	
	/* Get socket FD for polling */
	xsk->xsk_fd = xsk_socket__fd(xsk->xsk);
	
	/* Initialize Fill ring with all frames */
	xsk_socket_fill_ring(xsk, xsk->num_frames);
	
	*xsk_out = xsk;
	
	printf("Created AF_XDP socket: %s queue %u (fd=%d, frames=%u)\n",
	       ifname, queue_id, xsk->xsk_fd, xsk->num_frames);
	
	return 0;
}

void xsk_socket_destroy(struct xsk_socket *xsk)
{
	if (!xsk)
		return;
	
	printf("Destroying AF_XDP socket: ifindex=%u queue=%u\n",
	       xsk->ifindex, xsk->queue_id);
	
	if (xsk->xsk)
		xsk_socket__delete(xsk->xsk);
	
	if (xsk->umem_area)
		munmap(xsk->umem_area, xsk->umem_size);
	
	free(xsk);
}

int xsk_socket_rx_batch(struct xsk_socket *xsk, uint64_t *frames,
                        uint32_t *lengths, uint32_t max_batch)
{
	struct xsk_ring_cons *rx = &xsk->rx_ring;
	uint32_t idx_rx = 0;
	uint32_t rcvd = xsk_ring_cons__peek(rx, max_batch, &idx_rx);
	
	if (rcvd == 0)
		return 0;
	
	for (uint32_t i = 0; i < rcvd; i++) {
		const struct xdp_desc *desc = xsk_ring_cons__rx_desc(rx, idx_rx++);
		frames[i] = desc->addr;
		lengths[i] = desc->len;
	}
	
	xsk_ring_cons__release(rx, rcvd);
	
	xsk->rx_packets += rcvd;
	for (uint32_t i = 0; i < rcvd; i++)
		xsk->rx_bytes += lengths[i];
	
	return rcvd;
}

int xsk_socket_tx_batch(struct xsk_socket *xsk, uint64_t *frames,
                        uint32_t *lengths, uint32_t num_frames)
{
	struct xsk_ring_prod *tx = &xsk->tx_ring;
	uint32_t idx_tx = 0;
	uint32_t sent = xsk_ring_prod__reserve(tx, num_frames, &idx_tx);
	
	if (sent == 0)
		return -ENOSPC;
	
	for (uint32_t i = 0; i < sent; i++) {
		struct xdp_desc *desc = xsk_ring_prod__tx_desc(tx, idx_tx++);
		desc->addr = frames[i];
		desc->len = lengths[i];
	}
	
	xsk_ring_prod__submit(tx, sent);
	
	/* Kick TX */
	sendto(xsk->xsk_fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
	
	xsk->tx_packets += sent;
	for (uint32_t i = 0; i < sent; i++)
		xsk->tx_bytes += lengths[i];
	
	if (sent < num_frames)
		xsk->tx_drops += (num_frames - sent);
	
	return sent;
}

int xsk_socket_fill_ring(struct xsk_socket *xsk, uint32_t num_frames)
{
	struct xsk_ring_prod *fill = &xsk->fill_ring;
	uint32_t idx = 0;
	uint32_t filled = xsk_ring_prod__reserve(fill, num_frames, &idx);
	
	for (uint32_t i = 0; i < filled; i++) {
		*xsk_ring_prod__fill_addr(fill, idx++) = i * xsk->frame_size;
	}
	
	xsk_ring_prod__submit(fill, filled);
	
	return filled;
}

int xsk_socket_complete_tx(struct xsk_socket *xsk)
{
	struct xsk_ring_cons *comp = &xsk->comp_ring;
	uint32_t idx = 0;
	uint32_t completed = xsk_ring_cons__peek(comp, xsk->comp_size, &idx);
	
	if (completed > 0) {
		xsk_ring_cons__release(comp, completed);
		
		/* Recycle frames to Fill ring */
		xsk_socket_fill_ring(xsk, completed);
	}
	
	return completed;
}

void *xsk_get_frame_data(struct xsk_socket *xsk, uint64_t frame_addr)
{
	return (char *)xsk->umem_area + frame_addr + XDP_PACKET_HEADROOM;
}

#else /* !HAVE_LIBBPF_XSK */

/*
 * Stub implementation for systems without AF_XDP support
 * 
 * This allows VOQd to compile and run in SHADOW mode without AF_XDP.
 * ACTIVE mode will not work without proper AF_XDP support.
 */

int xsk_socket_create(struct xsk_socket **xsk_out, const char *ifname,
                      uint32_t queue_id, struct xsk_socket_config *config)
{
	fprintf(stderr, "AF_XDP not supported: libbpf xsk.h not available\n");
	fprintf(stderr, "Rebuild with libbpf >= 1.0 for AF_XDP support\n");
	fprintf(stderr, "VOQd can run in SHADOW mode for testing\n");
	return -ENOTSUP;
}

void xsk_socket_destroy(struct xsk_socket *xsk)
{
	/* No-op */
}

int xsk_socket_rx_batch(struct xsk_socket *xsk, uint64_t *frames,
                        uint32_t *lengths, uint32_t max_batch)
{
	return -ENOTSUP;
}

int xsk_socket_tx_batch(struct xsk_socket *xsk, uint64_t *frames,
                        uint32_t *lengths, uint32_t num_frames)
{
	return -ENOTSUP;
}

int xsk_socket_fill_ring(struct xsk_socket *xsk, uint32_t num_frames)
{
	return -ENOTSUP;
}

int xsk_socket_complete_tx(struct xsk_socket *xsk)
{
	return -ENOTSUP;
}

void *xsk_get_frame_data(struct xsk_socket *xsk, uint64_t frame_addr)
{
	(void)xsk;
	(void)frame_addr;
	return NULL;
}

#endif /* HAVE_LIBBPF_XSK */

/*
 * Common functions (work with or without AF_XDP)
 */

void xsk_socket_get_stats(struct xsk_socket *xsk,
                          uint64_t *rx_pkts, uint64_t *rx_bytes,
                          uint64_t *tx_pkts, uint64_t *tx_bytes,
                          uint64_t *rx_drops, uint64_t *tx_drops)
{
	if (!xsk)
		return;
	
	if (rx_pkts) *rx_pkts = xsk->rx_packets;
	if (rx_bytes) *rx_bytes = xsk->rx_bytes;
	if (tx_pkts) *tx_pkts = xsk->tx_packets;
	if (tx_bytes) *tx_bytes = xsk->tx_bytes;
	if (rx_drops) *rx_drops = xsk->rx_drops;
	if (tx_drops) *tx_drops = xsk->tx_drops;
}

uint64_t xsk_alloc_frame(struct xsk_socket *xsk)
{
	/* Simplified: return next free frame offset */
	static uint32_t next_frame = 0;
	uint64_t frame = next_frame * xsk->frame_size;
	next_frame = (next_frame + 1) % xsk->num_frames;
	return frame;
}

void xsk_free_frame(struct xsk_socket *xsk, uint64_t frame_addr)
{
	/* In full implementation, return to free list */
	/* For now, frames are recycled via Fill ring */
}

/*
 * AF_XDP Manager Implementation
 */

int xsk_manager_init(struct xsk_manager *mgr, bool use_shared_umem, bool zero_copy)
{
	memset(mgr, 0, sizeof(*mgr));
	mgr->use_shared_umem = use_shared_umem;
	mgr->zero_copy = zero_copy;
	
	printf("XSK Manager initialized: shared_umem=%d, zero_copy=%d\n",
	       use_shared_umem, zero_copy);
	
	return 0;
}

void xsk_manager_destroy(struct xsk_manager *mgr)
{
	if (!mgr)
		return;
	
	printf("Destroying XSK Manager (%u sockets)\n", mgr->num_sockets);
	
	for (uint32_t i = 0; i < mgr->num_sockets; i++) {
		if (mgr->sockets[i])
			xsk_socket_destroy(mgr->sockets[i]);
	}
	
	if (mgr->global_umem)
		munmap(mgr->global_umem, mgr->global_umem_size);
}

int xsk_manager_add_socket(struct xsk_manager *mgr, const char *ifname,
                           uint32_t queue_id, struct xsk_socket_config *config)
{
	if (mgr->num_sockets >= 64) {
		fprintf(stderr, "Maximum number of sockets reached\n");
		return -ENOMEM;
	}
	
	struct xsk_socket *xsk;
	int ret = xsk_socket_create(&xsk, ifname, queue_id, config);
	if (ret < 0)
		return ret;
	
	mgr->sockets[mgr->num_sockets++] = xsk;
	
	return mgr->num_sockets - 1;
}

struct xsk_socket *xsk_manager_get_socket(struct xsk_manager *mgr, uint32_t idx)
{
	if (idx >= mgr->num_sockets)
		return NULL;
	
	return mgr->sockets[idx];
}

int xsk_manager_poll_rx(struct xsk_manager *mgr, int timeout_ms)
{
	struct pollfd fds[64];
	uint32_t nfds = 0;
	
	for (uint32_t i = 0; i < mgr->num_sockets; i++) {
		if (mgr->sockets[i]) {
			fds[nfds].fd = mgr->sockets[i]->xsk_fd;
			fds[nfds].events = POLLIN;
			nfds++;
		}
	}
	
	if (nfds == 0)
		return 0;
	
	int ret = poll(fds, nfds, timeout_ms);
	if (ret < 0 && errno != EINTR) {
		fprintf(stderr, "Poll error: %s\n", strerror(errno));
		return -errno;
	}
	
	return ret;
}

void xsk_manager_complete_all_tx(struct xsk_manager *mgr)
{
	for (uint32_t i = 0; i < mgr->num_sockets; i++) {
		if (mgr->sockets[i])
			xsk_socket_complete_tx(mgr->sockets[i]);
	}
}

void xsk_manager_get_stats(struct xsk_manager *mgr,
                           uint64_t *total_rx, uint64_t *total_tx)
{
	uint64_t rx = 0, tx = 0;
	
	for (uint32_t i = 0; i < mgr->num_sockets; i++) {
		if (mgr->sockets[i]) {
			rx += mgr->sockets[i]->rx_packets;
			tx += mgr->sockets[i]->tx_packets;
		}
	}
	
	if (total_rx) *total_rx = rx;
	if (total_tx) *total_tx = tx;
	
	mgr->total_rx = rx;
	mgr->total_tx = tx;
}
