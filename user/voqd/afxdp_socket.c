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
	struct xsk_socket *xsk_sock = NULL;
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
	
	/* Get interface index */
	ifindex = if_nametoindex(ifname);
	if (!ifindex) {
		fprintf(stderr, "Interface %s not found\n", ifname);
		return -ENODEV;
	}
	
	/* Try to open xsks_map from BPF filesystem */
	xsks_map_fd = bpf_obj_get("/sys/fs/bpf/rswitch/xsks_map");
	if (xsks_map_fd < 0) {
		/* Try without rswitch subdirectory */
		xsks_map_fd = bpf_obj_get("/sys/fs/bpf/xsks_map");
	}
	
	if (xsks_map_fd < 0) {
		fprintf(stderr, "Warning: Could not open xsks_map (will use default)\n");
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
		fprintf(stderr, "Failed to allocate UMEM: %s\n", strerror(errno));
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
		fprintf(stderr, "Failed to create UMEM for %s queue %u: %s\n",
		        ifname, queue_id, strerror(-ret));
		munmap(umem_area, umem_size);
		return ret;
	}
	
	/* Configure socket */
	xsk_cfg.rx_size = config->rx_size ? config->rx_size : XSK_RING_CONS__DEFAULT_NUM_DESCS;
	xsk_cfg.tx_size = config->tx_size ? config->tx_size : XSK_RING_PROD__DEFAULT_NUM_DESCS;
	xsk_cfg.bind_flags = config->bind_flags;
	
	/* CRITICAL: XDP program already loaded by rswitch_loader
	 * Use XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD to skip XDP program loading */
	xsk_cfg.libxdp_flags = XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD;
	xsk_cfg.xdp_flags = 0;
	xsk_cfg.bind_flags |= XDP_COPY;  /* Force copy mode for compatibility */
	
	/* Create socket - will bind to existing XDP program */
	ret = xsk_socket__create(&xsk_sock, ifname, queue_id, umem, &rx, &tx, &xsk_cfg);
	if (ret) {
		fprintf(stderr, "Failed to add socket for %s queue %u: %s\n",
		        ifname, queue_id, strerror(-ret));
		xsk_umem__delete(umem);
		munmap(umem_area, umem_size);
		if (xsks_map_fd >= 0) close(xsks_map_fd);
		return ret;
	}
	
	/* Manually insert socket FD into xsks_map if we have it */
	if (xsks_map_fd >= 0) {
		int xsk_fd = xsk_socket__fd(xsk_sock);
		ret = bpf_map_update_elem(xsks_map_fd, &queue_id, &xsk_fd, BPF_ANY);
		if (ret < 0) {
			fprintf(stderr, "Warning: Failed to update xsks_map[%u]: %s\n",
			        queue_id, strerror(errno));
		} else {
			printf("Registered AF_XDP socket in xsks_map[%u] = fd %d\n",
			       queue_id, xsk_fd);
		}
		close(xsks_map_fd);
	}
	
	/* For now, return success but note we're using simplified struct */
	printf("Created AF_XDP socket: %s queue %u (frames=%u)\n",
	       ifname, queue_id, num_frames);
	
	*xsk_out = (struct xsk_socket *)xsk_sock;  /* Cast to our internal struct */
	
	return 0;
}

void xsk_socket_destroy(struct xsk_socket *xsk)
{
	if (!xsk)
		return;
	
	printf("Destroying AF_XDP socket\n");
	
	/* Note: Full cleanup would require tracking umem and other resources */
	/* For now, rely on OS cleanup on process exit */
	xsk_socket__delete((struct xsk_socket *)xsk);
}

int xsk_socket_rx_batch(struct xsk_socket *xsk, uint64_t *frames,
                        uint32_t *lengths, uint32_t max_batch)
{
	/* Stub implementation - requires proper ring buffer handling */
	return 0;
}

int xsk_socket_tx_batch(struct xsk_socket *xsk, uint64_t *frames,
                        uint32_t *lengths, uint32_t num_frames)
{
	/* Stub - requires proper TX ring implementation with libxdp */
	return -ENOTSUP;
}

int xsk_socket_fill_ring(struct xsk_socket *xsk, uint32_t num_frames)
{
	/* Stub - requires proper Fill ring implementation with libxdp */
	return 0;
}

int xsk_socket_complete_tx(struct xsk_socket *xsk)
{
	/* Stub - requires proper Completion ring implementation with libxdp */
	return 0;
}

void xsk_socket_get_stats(struct xsk_socket *xsk,
                          uint64_t *rx_pkts, uint64_t *rx_bytes,
                          uint64_t *tx_pkts, uint64_t *tx_bytes,
                          uint64_t *rx_drops, uint64_t *tx_drops)
{
	/* Stub - statistics not tracked in minimal implementation */
	if (rx_pkts) *rx_pkts = 0;
	if (rx_bytes) *rx_bytes = 0;
	if (tx_pkts) *tx_pkts = 0;
	if (tx_bytes) *tx_bytes = 0;
	if (rx_drops) *rx_drops = 0;
	if (tx_drops) *tx_drops = 0;
}

uint64_t xsk_alloc_frame(struct xsk_socket *xsk)
{
	/* Stub */
	return 0;
}

void xsk_free_frame(struct xsk_socket *xsk, uint64_t frame_addr)
{
	/* Stub */
}

void *xsk_get_frame_data(struct xsk_socket *xsk, uint64_t frame_addr)
{
	/* Stub */
	return NULL;
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
