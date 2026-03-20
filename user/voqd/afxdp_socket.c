// SPDX-License-Identifier: GPL-2.0
/*
 * AF_XDP Socket Implementation for VOQd
 * 
 * NOTE: This is a simplified implementation demonstrating the structure.
 * Full implementation requires libxdp >= 1.0 (xsk.h moved from libbpf to libxdp).
 * 
 * For production use, link against libxdp and use:
 *   #include <xdp/xsk.h>
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

#if __has_include("rs_log.h")
#include "rs_log.h"
#else
#include "../common/rs_log.h"
#endif
#include "afxdp_socket.h"

/* Feature check at compile time */
#ifdef HAVE_LIBBPF_XSK

/*
 * Full AF_XDP implementation using libxdp xsk helpers
 * Note: AF_XDP API moved from libbpf to libxdp since libbpf 1.0
 */

#include <xdp/xsk.h>
#include <bpf/bpf.h>  /* For bpf_obj_get, bpf_map_update_elem */
#include <linux/if_xdp.h>  // 推荐加上：确保 ABI 完整

int xsk_socket_create(struct xsk_socket **xsk_out, const char *ifname,
                      uint32_t queue_id, struct xsk_socket_config *config)
{
	struct xsk_socket *xsk = NULL;
	struct xsk_umem *umem = NULL;
	struct xsk_ring_cons rx = {};
	struct xsk_ring_prod tx = {};
	struct xsk_ring_prod fill = {};
	struct xsk_ring_cons comp = {};
	struct xsk_umem_config umem_cfg = {};
	struct xsk_socket_config xsk_cfg = {};
	void *umem_area;
	size_t umem_size;
	int ret;
	int ifindex;
	int xsks_map_fd = -1;
	
	/* Allocate our custom socket structure */
	xsk = calloc(1, sizeof(*xsk));
	if (!xsk) {
		return -ENOMEM;
	}
	
	/* Get interface index */
	ifindex = if_nametoindex(ifname);
	if (!ifindex) {
		RS_LOG_ERROR("Interface %s not found", ifname);
		free(xsk);
		return -ENODEV;
	}
	
	/* Open xsks_map from standard rSwitch BPF pin path */
	xsks_map_fd = bpf_obj_get("/sys/fs/bpf/rswitch/xsks_map");
	if (xsks_map_fd < 0) {
		RS_LOG_WARN("Could not open xsks_map at /sys/fs/bpf/rswitch/xsks_map: %s (errno=%d). "
		            "Ensure afxdp_redirect module is loaded and xsks_map is pinned.",
		            strerror(errno), errno);
	} else {
		RS_LOG_INFO("Opened xsks_map fd=%d", xsks_map_fd);
	}
	
	/* Calculate UMEM size */
	uint32_t frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE;  /* 4096 bytes */
	uint32_t num_frames = config->rx_size + config->tx_size;
	umem_size = num_frames * frame_size;
	
	/* Allocate UMEM */
	umem_area = mmap(NULL, umem_size,
	                 PROT_READ | PROT_WRITE,
	                 MAP_PRIVATE | MAP_ANONYMOUS,
	                 -1, 0);
	
	if (umem_area == MAP_FAILED) {
		RS_LOG_ERROR("Failed to allocate UMEM: %s", strerror(errno));
		free(xsk);
		return -ENOMEM;
	}
	
	/* Configure UMEM with default values */
	umem_cfg.fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
	umem_cfg.comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
	umem_cfg.frame_size = frame_size;
	umem_cfg.frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM;
	umem_cfg.flags = 0;
	
	/* Create UMEM */
	ret = xsk_umem__create(&umem, umem_area, umem_size, &fill, &comp, &umem_cfg);
	if (ret) {
		RS_LOG_ERROR("Failed to create UMEM for %s queue %u: %s",
		             ifname, queue_id, strerror(-ret));
		munmap(umem_area, umem_size);
		free(xsk);
		return ret;
	}
	
	/* Configure socket */
	xsk_cfg.rx_size = config->rx_size ? config->rx_size : XSK_RING_CONS__DEFAULT_NUM_DESCS;
	xsk_cfg.tx_size = config->tx_size ? config->tx_size : XSK_RING_PROD__DEFAULT_NUM_DESCS;
	
	/* CRITICAL: XDP program already loaded by rswitch_loader
	 * Use XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD to skip XDP program loading
	 * bind_flags: 0 means use default (no special flags) */
	xsk_cfg.libxdp_flags = XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD;
	xsk_cfg.xdp_flags = 0;
	xsk_cfg.bind_flags = 0;  /* Start with no flags - let libxdp use defaults */
	
	printf("Creating AF_XDP socket: %s queue %u (rx=%u, tx=%u, flags=0x%x, libxdp_flags=0x%x)\n",
	       ifname, queue_id, xsk_cfg.rx_size, xsk_cfg.tx_size, xsk_cfg.bind_flags, xsk_cfg.libxdp_flags);
	
	/* Create socket with shared rings - we need to manage rings ourselves */
	struct xsk_socket *xsk_sock = NULL;
	ret = xsk_socket__create_shared(&xsk_sock, ifname, queue_id, umem, &rx, &tx, &fill, &comp, &xsk_cfg);
	if (ret) {
		RS_LOG_ERROR("Failed to add socket for %s queue %u: %s (errno=%d, ret=%d)",
		             ifname, queue_id, strerror(-ret), errno, ret);
		xsk_umem__delete(umem);
		munmap(umem_area, umem_size);
		free(xsk);
		return ret;
	}
	
	/* Store libxdp socket and rings in our custom structure */
	xsk->xsk_sock = xsk_sock;
	xsk->umem = umem;
	xsk->umem_area = umem_area;
	xsk->umem_size = umem_size;
	xsk->frame_size = frame_size;
	xsk->num_frames = num_frames;
	xsk->ifindex = ifindex;
	xsk->queue_id = queue_id;
	xsk->xsk_fd = xsk_socket__fd(xsk_sock);
	
	/* Copy ring structures */
	xsk->rx_ring = rx;
	xsk->tx_ring = tx;
	xsk->fill_ring = fill;
	xsk->comp_ring = comp;
	
	/* Initialize ring sizes */
	xsk->rx_size = xsk_cfg.rx_size;
	xsk->tx_size = xsk_cfg.tx_size;
	xsk->fill_size = umem_cfg.fill_size;
	xsk->comp_size = umem_cfg.comp_size;
	
	/* Initialize cached indices */
	xsk->rx_cached_prod = 0;
	xsk->rx_cached_cons = 0;
	xsk->tx_cached_prod = 0;
	xsk->tx_cached_cons = 0;
	
	/* Manually insert socket FD into xsks_map if we have it */
	if (xsks_map_fd >= 0) {
		ret = bpf_map_update_elem(xsks_map_fd, &queue_id, &xsk->xsk_fd, BPF_ANY);
		if (ret < 0) {
			RS_LOG_WARN("Failed to update xsks_map[%u]: %s",
			            queue_id, strerror(errno));
		} else {
			printf("Registered AF_XDP socket in xsks_map[%u] = fd %d\n",
			       queue_id, xsk->xsk_fd);
		}
		close(xsks_map_fd);
	}
	
	/* Initialize stack-based free frame pool */
	xsk->free_stack_cap = num_frames;
	xsk->free_frame_stack = calloc(num_frames, sizeof(uint64_t));
	if (!xsk->free_frame_stack) {
		RS_LOG_ERROR("Failed to allocate free frame stack");
		xsk_socket__delete(xsk_sock);
		xsk_umem__delete(umem);
		munmap(umem_area, umem_size);
		free(xsk);
		return -ENOMEM;
	}
	
	/* Split frames: RX half to fill ring, TX half to free stack */
	uint32_t rx_frames = num_frames / 2;
	uint32_t tx_frames = num_frames - rx_frames;
	
	/* Fill the fill ring with RX frames */
	uint32_t fill_idx = 0;
	uint32_t fill_reserved = xsk_ring_prod__reserve(&xsk->fill_ring, rx_frames, &fill_idx);
	if (fill_reserved > 0) {
		for (uint32_t i = 0; i < fill_reserved; i++) {
			*xsk_ring_prod__fill_addr(&xsk->fill_ring, fill_idx + i) = i * frame_size;
		}
		xsk_ring_prod__submit(&xsk->fill_ring, fill_reserved);
	}
	
	/* Pre-populate free stack with TX frames */
	xsk->free_stack_size = 0;
	for (uint32_t i = 0; i < tx_frames; i++) {
		xsk->free_frame_stack[xsk->free_stack_size++] = (rx_frames + i) * frame_size;
	}
	
	printf("Created AF_XDP socket: %s queue %u (frames=%u, fill=%u, free_stack=%u)\n",
	       ifname, queue_id, num_frames, fill_reserved, xsk->free_stack_size);
	
	*xsk_out = xsk;
	
	return 0;
}

void xsk_socket_destroy(struct xsk_socket *xsk)
{
	if (!xsk)
		return;
	
	printf("Destroying AF_XDP socket\n");
	
	/* Delete libxdp socket */
	if (xsk->xsk_sock)
		xsk_socket__delete(xsk->xsk_sock);
	
	/* Delete UMEM */
	if (xsk->umem)
		xsk_umem__delete(xsk->umem);
	
	/* Unmap UMEM area */
	if (xsk->umem_area)
		munmap(xsk->umem_area, xsk->umem_size);
	
	/* Free frame pool stack */
	free(xsk->free_frame_stack);
	
	/* Free our custom structure */
	free(xsk);
}

int xsk_socket_rx_batch(struct xsk_socket *xsk, uint64_t *frames,
                        uint32_t *lengths, uint32_t max_batch)
{
	if (!xsk || !frames || !lengths)
		return -EINVAL;
	
	/* Peek available packets in RX ring */
	uint32_t rx_idx = 0;
	uint32_t rcvd = xsk_ring_cons__peek(&xsk->rx_ring, max_batch, &rx_idx);
	
	if (rcvd == 0)
		return 0;
	
	/* Process received packets */
	for (uint32_t i = 0; i < rcvd; i++) {
		const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&xsk->rx_ring, rx_idx + i);
		frames[i] = desc->addr;
		lengths[i] = desc->len;
		
		/* Update statistics */
		xsk->rx_packets++;
		xsk->rx_bytes += desc->len;
	}
	
	/* Release packets from RX ring */
	xsk_ring_cons__release(&xsk->rx_ring, rcvd);
	
	return rcvd;
}

int xsk_socket_tx_batch(struct xsk_socket *xsk, uint64_t *frames,
                        uint32_t *lengths, uint32_t num_frames)
{
	if (!xsk || !frames || !lengths || num_frames == 0)
		return -EINVAL;
	
	/* Reserve space in TX ring */
	uint32_t tx_idx = 0;
	uint32_t reserved = xsk_ring_prod__reserve(&xsk->tx_ring, num_frames, &tx_idx);
	
	if (reserved == 0)
		return 0;  /* No space available */
	
	/* Fill TX descriptors */
	for (uint32_t i = 0; i < reserved; i++) {
		struct xdp_desc *desc = xsk_ring_prod__tx_desc(&xsk->tx_ring, tx_idx + i);
		desc->addr = frames[i];
		desc->len = lengths[i];
		
		/* Update statistics */
		xsk->tx_packets++;
		xsk->tx_bytes += lengths[i];
	}
	
	/* Submit packets to kernel */
	xsk_ring_prod__submit(&xsk->tx_ring, reserved);
	
	/* Wake up kernel if needed */
	if (xsk_ring_prod__needs_wakeup(&xsk->tx_ring)) {
		if (sendto(xsk->xsk_fd, NULL, 0, MSG_DONTWAIT, NULL, 0) < 0 &&
		    errno != ENOBUFS && errno != EAGAIN && errno != EBUSY &&
		    errno != ENETDOWN) {
			RS_LOG_WARN("AF_XDP TX wakeup failed: %s", strerror(errno));
		}
	}
	
	return reserved;
}

int xsk_socket_fill_ring(struct xsk_socket *xsk, uint32_t num_frames)
{
	if (!xsk || num_frames == 0)
		return 0;
	
	if (num_frames > xsk->free_stack_size)
		num_frames = xsk->free_stack_size;
	
	uint32_t fill_idx = 0;
	uint32_t reserved = xsk_ring_prod__reserve(&xsk->fill_ring, num_frames, &fill_idx);
	
	for (uint32_t i = 0; i < reserved; i++) {
		uint64_t addr = xsk->free_frame_stack[--xsk->free_stack_size];
		*xsk_ring_prod__fill_addr(&xsk->fill_ring, fill_idx + i) = addr;
	}
	
	xsk_ring_prod__submit(&xsk->fill_ring, reserved);
	
	return reserved;
}

int xsk_socket_complete_tx(struct xsk_socket *xsk)
{
	if (!xsk)
		return -EINVAL;
	
	uint32_t comp_idx = 0;
	uint32_t completed = xsk_ring_cons__peek(&xsk->comp_ring, xsk->comp_size, &comp_idx);
	
	if (completed == 0)
		return 0;
	
	for (uint32_t i = 0; i < completed; i++) {
		uint64_t addr = *xsk_ring_cons__comp_addr(&xsk->comp_ring, comp_idx + i);
		xsk_free_frame(xsk, addr);
	}
	
	xsk_ring_cons__release(&xsk->comp_ring, completed);
	
	return completed;
}

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
	if (!xsk)
		return 0;
	
	if (xsk->free_stack_size > 0) {
		xsk->free_stack_size--;
		return xsk->free_frame_stack[xsk->free_stack_size];
	}
	
	return 0;
}

void xsk_free_frame(struct xsk_socket *xsk, uint64_t frame_addr)
{
	if (!xsk || frame_addr == 0)
		return;
	
	if (xsk->free_stack_size < xsk->free_stack_cap) {
		xsk->free_frame_stack[xsk->free_stack_size] = frame_addr;
		xsk->free_stack_size++;
	}
}

void *xsk_get_frame_data(struct xsk_socket *xsk, uint64_t frame_addr)
{
	if (!xsk || !xsk->umem_area || frame_addr >= xsk->umem_size)
		return NULL;
	
	return (uint8_t *)xsk->umem_area + frame_addr;
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
	RS_LOG_ERROR("AF_XDP not supported: libbpf xsk.h not available");
	RS_LOG_WARN("Rebuild with libbpf >= 1.0 for AF_XDP support");
	RS_LOG_WARN("VOQd can run in SHADOW mode for testing");
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

void xsk_socket_get_stats(struct xsk_socket *xsk,
                          uint64_t *rx_pkts, uint64_t *rx_bytes,
                          uint64_t *tx_pkts, uint64_t *tx_bytes,
                          uint64_t *rx_drops, uint64_t *tx_drops)
{
	/* Stub */
	if (rx_pkts) *rx_pkts = 0;
	if (rx_bytes) *rx_bytes = 0;
	if (tx_pkts) *tx_pkts = 0;
	if (tx_bytes) *tx_bytes = 0;
	if (rx_drops) *rx_drops = 0;
	if (tx_drops) *tx_drops = 0;
}

uint64_t xsk_alloc_frame(struct xsk_socket *xsk)
{
	return 0;
}

void xsk_free_frame(struct xsk_socket *xsk, uint64_t frame_addr)
{
	/* No-op */
}

void *xsk_get_frame_data(struct xsk_socket *xsk, uint64_t frame_addr)
{
	return NULL;
}

#endif /* HAVE_LIBBPF_XSK */

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
		RS_LOG_ERROR("Maximum number of sockets reached");
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
		RS_LOG_ERROR("Poll error: %s", strerror(errno));
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
	
	/* Note: mgr->sockets[] contains libxdp's xsk_socket pointers,
	 * which don't have rx_packets/tx_packets fields.
	 * For now, we just report the number of active sockets.
	 * TODO: Track statistics separately or use xsk_socket__get_stats() */
	 
	if (total_rx) *total_rx = mgr->num_sockets;  /* Number of RX sockets */
	if (total_tx) *total_tx = mgr->num_sockets;  /* Number of TX sockets */
	
	mgr->total_rx = mgr->num_sockets;
	mgr->total_tx = mgr->num_sockets;
}
