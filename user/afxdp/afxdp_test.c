/* SPDX-License-Identifier: GPL-2.0 */
/*
 * AF_XDP Socket Test
 * 
 * Simple test program demonstrating AF_XDP socket creation and packet I/O.
 * Usage: sudo ./afxdp_test <interface> [queue_id]
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <poll.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/ip.h>
#include "afxdp_socket.h"
#if __has_include("rs_log.h")
#include "rs_log.h"
#else
#include "../common/rs_log.h"
#endif

/* Default ring sizes from libbpf */
#ifndef XSK_RING_CONS__DEFAULT_NUM_DESCS
#define XSK_RING_CONS__DEFAULT_NUM_DESCS 2048
#endif
#ifndef XSK_RING_PROD__DEFAULT_NUM_DESCS
#define XSK_RING_PROD__DEFAULT_NUM_DESCS 2048
#endif

static volatile bool running = true;

static void sig_handler(int sig)
{
	running = false;
}

static void print_packet_info(struct xsk_packet *pkt)
{
	struct ethhdr *eth = (struct ethhdr *)pkt->data;
	
	printf("  Packet: len=%u, src=%02x:%02x:%02x:%02x:%02x:%02x, "
	       "dst=%02x:%02x:%02x:%02x:%02x:%02x, proto=0x%04x\n",
	       pkt->len,
	       eth->h_source[0], eth->h_source[1], eth->h_source[2],
	       eth->h_source[3], eth->h_source[4], eth->h_source[5],
	       eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
	       eth->h_dest[3], eth->h_dest[4], eth->h_dest[5],
	       ntohs(eth->h_proto));
	
	/* Print IP header if available */
	if (ntohs(eth->h_proto) == ETH_P_IP && pkt->len >= sizeof(*eth) + sizeof(struct iphdr)) {
		struct iphdr *iph = (struct iphdr *)(eth + 1);
		char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
		
		inet_ntop(AF_INET, &iph->saddr, src, sizeof(src));
		inet_ntop(AF_INET, &iph->daddr, dst, sizeof(dst));
		
		printf("    IP: %s -> %s, proto=%u, tos=0x%02x\n",
		       src, dst, iph->protocol, iph->tos);
	}
}

int main(int argc, char **argv)
{
	rs_log_init("afxdp-test", RS_LOG_LEVEL_INFO);

	const char *ifname;
	uint32_t queue_id = 0;
	struct xsk_umem *umem = NULL;
	struct xsk_socket *xsk = NULL;
	struct xsk_config config = {
		.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
		.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
		.frame_size = FRAME_SIZE,
		.num_frames = NUM_FRAMES,
		.bind_flags = XDP_ZEROCOPY,  /* Try zero-copy first */
		.xdp_flags = XDP_FLAGS_DRV_MODE,
		.shared_umem = false,
	};
	struct xsk_packet pkts[BATCH_SIZE];
	struct pollfd fds[1];
	uint64_t total_pkts = 0;
	int ret;
	
	if (argc < 2) {
		RS_LOG_ERROR("Usage: %s <interface> [queue_id]", argv[0]);
		return 1;
	}
	
	ifname = argv[1];
	if (argc >= 3)
		queue_id = atoi(argv[2]);
	
	/* Setup signal handler */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
	
	printf("Starting AF_XDP test on %s queue %u\n", ifname, queue_id);
	
	/* Create UMEM */
	printf("Creating UMEM (%u frames of %u bytes)...\n", 
	       config.num_frames, config.frame_size);
	ret = xsk_umem_create(&umem, config.frame_size, config.num_frames);
	if (ret) {
		RS_LOG_ERROR("Failed to create UMEM: %s", strerror(-ret));
		return 1;
	}
	printf("UMEM created: %lu bytes\n", umem->size);
	
	/* Create AF_XDP socket */
	printf("Creating AF_XDP socket...\n");
	ret = xsk_socket_create(&xsk, ifname, queue_id, umem, &config);
	if (ret) {
		if (ret == -EOPNOTSUPP && config.bind_flags == XDP_ZEROCOPY) {
			RS_LOG_WARN("Zero-copy not supported, trying copy mode...");
			config.bind_flags = XDP_COPY;
			ret = xsk_socket_create(&xsk, ifname, queue_id, umem, &config);
		}
		
		if (ret) {
			RS_LOG_ERROR("Failed to create socket: %s", strerror(-ret));
			xsk_umem_destroy(umem);
			return 1;
		}
	}
	
	printf("AF_XDP socket created (fd=%d, mode=%s)\n", 
	       xsk_socket_get_fd(xsk),
	       config.bind_flags == XDP_ZEROCOPY ? "zero-copy" : "copy");
	
	/* Setup poll */
	fds[0].fd = xsk_socket_get_fd(xsk);
	fds[0].events = POLLIN;
	
	/* Main packet processing loop */
	printf("\nReceiving packets (press Ctrl-C to stop)...\n\n");
	
	while (running) {
		uint32_t rcvd;
		
		/* Poll for packets */
		ret = poll(fds, 1, 1000);  /* 1 second timeout */
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			RS_LOG_ERROR("Poll error: %s", strerror(errno));
			break;
		}
		
		if (ret == 0)
			continue;  /* Timeout */
		
		/* Receive batch */
		rcvd = xsk_rx_batch(xsk, pkts, BATCH_SIZE);
		if (rcvd == 0)
			continue;
		
		total_pkts += rcvd;
		printf("Received %u packets (total: %lu):\n", rcvd, total_pkts);
		
		/* Print first few packets */
		for (uint32_t i = 0; i < rcvd && i < 5; i++) {
			print_packet_info(&pkts[i]);
		}
		
		if (rcvd > 5)
			printf("  ... and %u more packets\n", rcvd - 5);
		printf("\n");
		
		/* Echo packets back (simple L2 forwarding test) */
		if (xsk_tx_batch(xsk, pkts, rcvd) > 0) {
			xsk_tx_kick(xsk);
		}
	}
	
	printf("\nShutting down...\n");
	xsk_print_stats(xsk);
	
	/* Cleanup */
	xsk_socket_destroy(xsk);
	xsk_umem_destroy(umem);
	
	printf("AF_XDP test completed\n");
	return 0;
}
