// SPDX-License-Identifier: GPL-2.0
/*
 * VOQd Data Plane Implementation
 * 
 * Integrates AF_XDP packet reception with VOQ scheduling and transmission.
 * Provides complete user-space data plane for high-priority traffic.
 */

#define _GNU_SOURCE  /* For CPU_ZERO, CPU_SET, pthread_setaffinity_np */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <arpa/inet.h>      /* For ntohs, ntohl */
#include <linux/if_xdp.h>  /* For XDP_ZEROCOPY, XDP_COPY, XDP_PACKET_HEADROOM */

#if __has_include("rs_log.h")
#include "rs_log.h"
#else
#include "../common/rs_log.h"
#endif
#include "voqd_dataplane.h"
#include "../../bpf/core/afxdp_common.h"
#include "../../bpf/core/veth_egress_common.h"

/* AF_XDP constants (fallback if not defined) */
#ifndef XDP_PACKET_HEADROOM
#define XDP_PACKET_HEADROOM 256
#endif
#ifndef XDP_ZEROCOPY
#define XDP_ZEROCOPY (1 << 2)
#endif
#ifndef XDP_COPY
#define XDP_COPY (1 << 3)
#endif

/* Helper: Pin thread to CPU */
static int pin_thread_to_cpu(int cpu)
{
	cpu_set_t cpuset;
	CPU_ZERO(&cpuset);
	CPU_SET(cpu, &cpuset);
	
	return pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
}
int sw_queue_mgr_init(struct sw_queue_mgr *mgr, uint32_t num_ports, 
                      uint32_t num_priorities, uint32_t queue_depth,
                      uint32_t max_frame_size)
{
	if (!mgr || num_ports == 0 || num_priorities == 0)
		return -EINVAL;
	
	memset(mgr, 0, sizeof(*mgr));
	mgr->num_ports = num_ports;
	mgr->num_priorities = num_priorities;
	
	/* Calculate memory requirements */
	uint32_t total_queues = num_ports * num_priorities;
	uint32_t pool_size = total_queues * queue_depth * 2;  /* 2x for safety */
	uint32_t buffer_pool_size = pool_size;
	
	/* Allocate queue array */
	mgr->queues = calloc(num_ports, sizeof(struct sw_queue *));
	if (!mgr->queues)
		return -ENOMEM;
	
	for (uint32_t p = 0; p < num_ports; p++) {
		mgr->queues[p] = calloc(num_priorities, sizeof(struct sw_queue));
		if (!mgr->queues[p]) {
			sw_queue_mgr_destroy(mgr);
			return -ENOMEM;
		}
		
		for (uint32_t prio = 0; prio < num_priorities; prio++) {
			mgr->queues[p][prio].max_depth = queue_depth;
		}
	}
	
	/* Allocate entry pool */
	mgr->pool = calloc(pool_size, sizeof(struct sw_queue_entry));
	if (!mgr->pool) {
		sw_queue_mgr_destroy(mgr);
		return -ENOMEM;
	}
	mgr->pool_size = pool_size;
	
	/* Allocate buffer pool */
	mgr->buffer_pool = calloc(buffer_pool_size, max_frame_size);
	if (!mgr->buffer_pool) {
		sw_queue_mgr_destroy(mgr);
		return -ENOMEM;
	}
	mgr->buffer_size = max_frame_size;
	mgr->max_total_depth = total_queues * queue_depth;
	
	printf("Software queue manager initialized: %u ports, %u priorities, depth=%u, pool=%u\n",
	       num_ports, num_priorities, queue_depth, pool_size);
	
	return 0;
}

/* Destroy software queue manager */
void sw_queue_mgr_destroy(struct sw_queue_mgr *mgr)
{
	if (!mgr)
		return;
	
	/* Free queues */
	if (mgr->queues) {
		for (uint32_t p = 0; p < mgr->num_ports; p++) {
			free(mgr->queues[p]);
		}
		free(mgr->queues);
	}
	
	/* Free pools */
	free(mgr->pool);
	free(mgr->buffer_pool);
	
	memset(mgr, 0, sizeof(*mgr));
}

/* Enqueue packet into software queue */
int sw_queue_enqueue(struct sw_queue_mgr *mgr, uint32_t port_idx, uint8_t priority,
                     const uint8_t *data, uint32_t len, uint64_t ts_ns, uint32_t flow_hash)
{
	if (!mgr || port_idx >= mgr->num_ports || priority >= mgr->num_priorities)
		return -EINVAL;
	
	struct sw_queue *queue = &mgr->queues[port_idx][priority];
	
	/* Check if queue is full */
	if (queue->depth >= queue->max_depth) {
		queue->dropped++;
		return -ENOSPC;
	}
	
	/* Check if we have free entries */
	if (mgr->pool_used >= mgr->pool_size) {
		queue->dropped++;
		return -ENOSPC;
	}
	
	/* Check if we have free buffers */
	if (mgr->buffers_used >= mgr->pool_size) {
		queue->dropped++;
		return -ENOSPC;
	}
	
	/* Get free entry */
	struct sw_queue_entry *entry = &mgr->pool[mgr->pool_used++];
	
	/* Get free buffer */
	uint8_t *buffer = mgr->buffer_pool + (mgr->buffers_used++ * mgr->buffer_size);
	
	/* Copy packet data */
	if (len > mgr->buffer_size)
		len = mgr->buffer_size;  /* Truncate if too large */
	memcpy(buffer, data, len);
	
	/* Initialize entry */
	entry->data = buffer;
	entry->len = len;
	entry->ts_ns = ts_ns;
	entry->flow_hash = flow_hash;
	entry->priority = priority;
	entry->next = NULL;
	
	/* Add to queue */
	if (queue->tail) {
		queue->tail->next = entry;
		queue->tail = entry;
	} else {
		queue->head = queue->tail = entry;
	}
	
	queue->depth++;
	mgr->total_depth++;
	queue->enqueued++;
	
	return 0;
}

/* Dequeue packet from software queue (priority-based) */
struct sw_queue_entry *sw_queue_dequeue(struct sw_queue_mgr *mgr, uint32_t *port_idx)
{
	if (!mgr || !port_idx)
		return NULL;
	
	/* Priority-based dequeue: check all ports for highest priority packets */
	for (uint8_t prio = 0; prio < mgr->num_priorities; prio++) {
		for (uint32_t port = 0; port < mgr->num_ports; port++) {
			struct sw_queue *queue = &mgr->queues[port][prio];
			
			if (queue->head) {
				/* Found packet */
				struct sw_queue_entry *entry = queue->head;
				queue->head = entry->next;
				if (!queue->head)
					queue->tail = NULL;
				
				queue->depth--;
				mgr->total_depth--;
				queue->dequeued++;
				
				*port_idx = port;
				return entry;
			}
		}
	}
	
	return NULL;  /* No packets available */
}

/* Free software queue entry */
void sw_queue_free_entry(struct sw_queue_mgr *mgr, struct sw_queue_entry *entry)
{
	if (!mgr || !entry)
		return;
	
	/* Mark entry as free (simple pool management) */
	mgr->pool_used--;
	mgr->buffers_used--;
}

/* Get software queue statistics */
void sw_queue_get_stats(struct sw_queue_mgr *mgr, uint32_t port_idx, uint8_t priority,
                        uint64_t *enqueued, uint64_t *dequeued, uint64_t *dropped)
{
	if (!mgr || port_idx >= mgr->num_ports || priority >= mgr->num_priorities)
		return;
	
	struct sw_queue *queue = &mgr->queues[port_idx][priority];
	
	if (enqueued) *enqueued = queue->enqueued;
	if (dequeued) *dequeued = queue->dequeued;
	if (dropped) *dropped = queue->dropped;
}

/* Initialize data plane */
int voqd_dataplane_init(struct voqd_dataplane *dp, struct voq_mgr *voq,
                        struct voqd_dataplane_config *config)
{
	int ret;
	
	if (!dp || !voq || !config)
		return -EINVAL;
	
	memset(dp, 0, sizeof(*dp));
	dp->voq = voq;
	dp->config = *config;
	dp->num_ports = voq->num_ports;
	dp->running = false;
	
	/* Initialize AF_XDP manager if enabled */
	if (config->enable_afxdp) {
		ret = xsk_manager_init(&dp->xsk_mgr, false, config->zero_copy);
		if (ret < 0) {
			RS_LOG_ERROR("Failed to initialize XSK manager: %s", strerror(-ret));
			return ret;
		}
		
		printf("Data plane initialized: AF_XDP enabled, zero_copy=%d\n",
		       config->zero_copy);
	} else {
		printf("Data plane initialized: AF_XDP disabled (metadata-only mode)\n");
	}
	
	/* Initialize veth egress socket manager if enabled */
	if (config->use_veth_egress && config->enable_afxdp) {
		ret = xsk_manager_init(&dp->veth_xsk_mgr, false, false);
		if (ret < 0) {
			RS_LOG_ERROR("Failed to initialize veth XSK manager: %s", strerror(-ret));
			if (config->enable_afxdp)
				xsk_manager_destroy(&dp->xsk_mgr);
			return ret;
		}
		
		struct xsk_socket_config veth_cfg = {
			.rx_size = 0,
			.tx_size = config->tx_ring_size,
			.bind_flags = XDP_COPY,
			.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST,
		};
		
		ret = xsk_manager_add_socket(&dp->veth_xsk_mgr, config->veth_in_ifname,
		                             config->veth_queue_id, &veth_cfg);
		if (ret < 0) {
			RS_LOG_ERROR("Failed to add veth socket for %s: %s",
			            config->veth_in_ifname, strerror(-ret));
			xsk_manager_destroy(&dp->veth_xsk_mgr);
			if (config->enable_afxdp)
				xsk_manager_destroy(&dp->xsk_mgr);
			return ret;
		}
		
		printf("Veth egress enabled: TX to %s (ifindex=%u)\n",
		       config->veth_in_ifname, config->veth_in_ifindex);
	}
	
	/* Initialize software queue manager if enabled */
	if (config->enable_sw_queues) {
		uint32_t num_priorities = 8;  /* Default: 8 priority levels */
		ret = sw_queue_mgr_init(&dp->sw_mgr, voq->num_ports, num_priorities,
		                        config->sw_queue_depth, config->frame_size);
		if (ret < 0) {
			RS_LOG_ERROR("Failed to initialize software queue manager: %s", strerror(-ret));
			if (config->enable_afxdp)
				xsk_manager_destroy(&dp->xsk_mgr);
			return ret;
		}
		
		printf("Software queue simulation enabled: depth=%u per queue\n",
		       config->sw_queue_depth);
	}
	
	return 0;
}

/* Destroy data plane */
void voqd_dataplane_destroy(struct voqd_dataplane *dp)
{
	if (!dp)
		return;
	
	/* Ensure threads are stopped */
	if (dp->running)
		voqd_dataplane_stop(dp);
	
	/* Destroy AF_XDP manager */
	if (dp->config.enable_afxdp)
		xsk_manager_destroy(&dp->xsk_mgr);
	
	/* Destroy veth egress socket manager */
	if (dp->config.use_veth_egress)
		xsk_manager_destroy(&dp->veth_xsk_mgr);
	
	/* Destroy software queue manager */
	if (dp->config.enable_sw_queues)
		sw_queue_mgr_destroy(&dp->sw_mgr);
	
	printf("Data plane destroyed\n");
}

/* Add AF_XDP socket for port */
int voqd_dataplane_add_port(struct voqd_dataplane *dp, const char *ifname,
                            uint32_t port_idx, uint32_t queue_id)
{
	if (!dp || !dp->config.enable_afxdp)
		return -EINVAL;
	
	if (port_idx >= dp->num_ports) {
		RS_LOG_ERROR("Invalid port index: %u", port_idx);
		return -EINVAL;
	}
	
	/* Configure socket for libxdp API */
	struct xsk_socket_config config = {
		.rx_size = dp->config.rx_ring_size,
		.tx_size = dp->config.tx_ring_size,
		.bind_flags = dp->config.zero_copy ? XDP_ZEROCOPY : XDP_COPY,
		.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST,
	};
	
	/* Note: fill_size, comp_size, frame_size are in xsk_umem_config, not xsk_socket_config */
	/* These would be configured in xsk_socket_create() when creating the UMEM */
	
	int ret = xsk_manager_add_socket(&dp->xsk_mgr, ifname, queue_id, &config);
	if (ret < 0) {
		RS_LOG_ERROR("Failed to add socket for %s queue %u: %s",
		            ifname, queue_id, strerror(-ret));
		return ret;
	}
	
	printf("Added AF_XDP socket: %s queue %u -> port %u (socket_idx=%d)\n",
	       ifname, queue_id, port_idx, ret);
	
	return 0;
}

/* Process RX batch from AF_XDP socket */
int voqd_dataplane_rx_process(struct voqd_dataplane *dp, uint32_t port_idx)
{
	if (!dp->config.enable_afxdp)
		return 0;
	
	struct xsk_socket *xsk = xsk_manager_get_socket(&dp->xsk_mgr, port_idx);
	if (!xsk) {
		if (dp->rx_debug_count++ < 5) {  /* Only print first few times */
			RS_LOG_DEBUG("RX: No AF_XDP socket for port %u", port_idx);
		}
		return 0;
	}
	
	/* Receive batch */
	int rcvd = xsk_socket_rx_batch(xsk, dp->rx_frames, dp->rx_lengths,
	                                dp->config.batch_size);
	
	if (rcvd < 0) {
		if (dp->rx_debug_count++ < 5) {
			RS_LOG_ERROR("RX: xsk_socket_rx_batch failed for port %u: %d", port_idx, rcvd);
		}
		return rcvd;
	}
	
	if (rcvd > 0 && dp->rx_debug_count < 10) {
		RS_LOG_DEBUG("RX: Port %u received %d packets", port_idx, rcvd);
		dp->rx_debug_count++;
	}
	
	/* Enqueue packets into VOQ based on priority */
	for (int i = 0; i < rcvd; i++) {
		uint64_t frame_addr = dp->rx_frames[i];
		uint32_t len = dp->rx_lengths[i];
		
		/* Get packet data */
		void *pkt_data = xsk_get_frame_data(xsk, frame_addr);
		if (!pkt_data) {
			dp->enqueue_errors++;
			xsk_free_frame(xsk, frame_addr);
			continue;
		}
		
		/* Extract priority from packet using IP DSCP */
		uint32_t prio = voqd_extract_priority_from_packet(pkt_data, len,
		                                                 dp->config.dscp_to_prio,
		                                                 dp->config.default_prio);
		
		if (dp->config.enable_sw_queues) {
			/* Software queue mode: copy packet data */
			uint64_t ts_ns = 0;  /* TODO: Get current timestamp */
			uint32_t flow_hash = 0;  /* TODO: Extract from packet header */
			
			int ret = sw_queue_enqueue(&dp->sw_mgr, port_idx, prio, pkt_data, len,
			                           ts_ns, flow_hash);
			
			if (ret < 0) {
				dp->enqueue_errors++;
			} else {
				dp->rx_packets++;
				dp->rx_bytes += len;
			}
			
			/* Always return frame to AF_XDP pool */
			xsk_free_frame(xsk, frame_addr);
			
		} else {
			/* Traditional AF_XDP mode: enqueue frame reference */
			uint64_t ts_ns = 0;  /* TODO: Get timestamp from packet or use current time */
			uint32_t flow_hash = 0;  /* TODO: Extract from packet header */
			
			int ret = voq_enqueue(dp->voq, port_idx, prio, ts_ns, len,
			                      flow_hash, 0, 0, frame_addr);
			
			if (ret < 0) {
				dp->enqueue_errors++;
				/* Return frame to pool on error */
				xsk_free_frame(xsk, frame_addr);
			} else {
				dp->rx_packets++;
				dp->rx_bytes += len;
			}
		}
	}
	
	/* Update stats */
	dp->rx_batch_sum += rcvd;
	dp->rx_batch_count++;
	
	/* Refill the fill ring so kernel can deliver more RX packets */
	if (rcvd > 0)
		xsk_socket_fill_ring(xsk, rcvd);
	
	return rcvd;
}

/* Process TX scheduling and transmission */
int voqd_dataplane_tx_process(struct voqd_dataplane *dp)
{
	uint32_t tx_count = 0;
	uint32_t max_batch = dp->config.batch_size;
	bool use_veth = dp->config.use_veth_egress && dp->config.enable_afxdp;
	
	struct xsk_socket *veth_xsk = NULL;
	if (use_veth) {
		veth_xsk = xsk_manager_get_socket(&dp->veth_xsk_mgr, 0);
		if (!veth_xsk) {
			use_veth = false;
		}
	}
	
	if (dp->config.enable_sw_queues) {
		/* Software queue mode: dequeue from software queues */
		for (uint32_t i = 0; i < max_batch; i++) {
			uint32_t port_idx;
			struct sw_queue_entry *entry = sw_queue_dequeue(&dp->sw_mgr, &port_idx);
			
			if (!entry)
				break;
			
			if (!dp->config.enable_afxdp) {
				dp->tx_packets++;
				dp->tx_bytes += entry->len;
				sw_queue_free_entry(&dp->sw_mgr, entry);
				tx_count++;
				continue;
			}
			
			struct xsk_socket *xsk = use_veth ? veth_xsk : 
			                         xsk_manager_get_socket(&dp->xsk_mgr, port_idx);
			if (!xsk) {
				dp->tx_errors++;
				sw_queue_free_entry(&dp->sw_mgr, entry);
				continue;
			}
			
			uint64_t frame_addr = xsk_alloc_frame(xsk);
			if (frame_addr == 0) {
				dp->tx_errors++;
				sw_queue_free_entry(&dp->sw_mgr, entry);
				continue;
			}
			
			uint8_t *frame_data = xsk_get_frame_data(xsk, frame_addr);
			if (!frame_data) {
				dp->tx_errors++;
				xsk_free_frame(xsk, frame_addr);
				sw_queue_free_entry(&dp->sw_mgr, entry);
				continue;
			}
			
			uint32_t total_len = entry->len;
			
			if (use_veth) {
				struct voq_tx_meta meta = {
					.egress_ifindex = dp->voq->ports[port_idx].ifindex,
					.ingress_ifindex = 0,
					.prio = entry->priority,
					.flags = VOQ_TX_FLAG_FROM_VOQ,
					.vlan_id = 0,
					.reserved = 0,
				};
				memcpy(frame_data, &meta, VOQ_TX_META_SIZE);
				memcpy(frame_data + VOQ_TX_META_SIZE, entry->data, entry->len);
				total_len = entry->len + VOQ_TX_META_SIZE;
			} else {
				memcpy(frame_data, entry->data, entry->len);
			}
			
			dp->tx_frames[tx_count] = frame_addr;
			dp->tx_lengths[tx_count] = total_len;
			
			sw_queue_free_entry(&dp->sw_mgr, entry);
			tx_count++;
		}
	} else {
		/* Traditional AF_XDP mode: dequeue from VOQ */
		for (uint32_t i = 0; i < max_batch; i++) {
			uint32_t port_idx;
			struct voq_entry *entry = voq_dequeue(dp->voq, &port_idx);
			
			if (!entry)
				break;
			
			if (!dp->config.enable_afxdp || port_idx >= dp->num_ports) {
				dp->tx_packets++;
				dp->tx_bytes += entry->len;
				voq_free_entry(dp->voq, entry);
				tx_count++;
				continue;
			}
			
			if (use_veth) {
				uint64_t frame_addr = xsk_alloc_frame(veth_xsk);
				if (frame_addr == 0) {
					dp->tx_errors++;
					voq_free_entry(dp->voq, entry);
					continue;
				}
				
				uint8_t *frame_data = xsk_get_frame_data(veth_xsk, frame_addr);
				if (!frame_data) {
					dp->tx_errors++;
					xsk_free_frame(veth_xsk, frame_addr);
					voq_free_entry(dp->voq, entry);
					continue;
				}
				
				struct voq_tx_meta meta = {
					.egress_ifindex = entry->eg_port,
					.ingress_ifindex = 0,
					.prio = entry->prio,
					.flags = VOQ_TX_FLAG_FROM_VOQ,
					.vlan_id = 0,
					.reserved = 0,
				};
				
				uint8_t *orig_data = xsk_get_frame_data(
					xsk_manager_get_socket(&dp->xsk_mgr, 0), entry->xdp_frame_addr);
				if (!orig_data) {
					dp->tx_errors++;
					xsk_free_frame(veth_xsk, frame_addr);
					voq_free_entry(dp->voq, entry);
					continue;
				}
				
				memcpy(frame_data, &meta, VOQ_TX_META_SIZE);
				memcpy(frame_data + VOQ_TX_META_SIZE, orig_data, entry->len);
				
				dp->tx_frames[tx_count] = frame_addr;
				dp->tx_lengths[tx_count] = entry->len + VOQ_TX_META_SIZE;
			} else {
				struct xsk_socket *xsk = xsk_manager_get_socket(&dp->xsk_mgr, port_idx);
				if (!xsk) {
					dp->tx_errors++;
					voq_free_entry(dp->voq, entry);
					continue;
				}
				
				dp->tx_frames[tx_count] = entry->xdp_frame_addr;
				dp->tx_lengths[tx_count] = entry->len;
			}
			
			voq_free_entry(dp->voq, entry);
			tx_count++;
		}
	}
	
	if (tx_count == 0)
		return 0;
	
	if (dp->config.enable_afxdp) {
		struct xsk_socket *xsk = use_veth ? veth_xsk :
		                         xsk_manager_get_socket(&dp->xsk_mgr, 0);
		if (xsk) {
			int sent = xsk_socket_tx_batch(xsk, dp->tx_frames,
			                               dp->tx_lengths, tx_count);
			
			if (sent > 0) {
				dp->tx_packets += sent;
				for (int i = 0; i < sent; i++)
					dp->tx_bytes += dp->tx_lengths[i];
			}
			
			if (sent < (int)tx_count)
				dp->tx_errors += (tx_count - sent);
		} else {
			dp->tx_errors += tx_count;
		}
	}
	
	dp->tx_batch_sum += tx_count;
	dp->tx_batch_count++;
	dp->scheduler_rounds++;
	
	return tx_count;
}

/* RX thread function */
void *voqd_dataplane_rx_thread(void *arg)
{
	struct voqd_dataplane *dp = arg;
	
	printf("RX thread started (CPU affinity=%u)\n", dp->config.cpu_affinity);
	
	/* Pin to CPU if configured */
	if (dp->config.cpu_affinity > 0) {
		if (pin_thread_to_cpu(dp->config.cpu_affinity) < 0)
			RS_LOG_WARN("Failed to pin RX thread to CPU %u",
			            dp->config.cpu_affinity);
	}
	
	while (dp->running) {
		int activity = 0;
		
		/* Poll all ports for RX */
		if (dp->config.enable_afxdp) {
			int ret = xsk_manager_poll_rx(&dp->xsk_mgr, dp->config.poll_timeout_ms);
			if (ret < 0 && ret != -EINTR) {
				RS_LOG_ERROR("RX poll error: %d", ret);
				break;
			}
		}
		
		/* Process RX for each port */
		for (uint32_t p = 0; p < dp->num_ports; p++) {
			int rcvd = voqd_dataplane_rx_process(dp, p);
			if (rcvd > 0)
				activity += rcvd;
		}
		
		/* Busy poll mode: no sleep */
		if (!dp->config.busy_poll && activity == 0)
			usleep(100);  /* 100us sleep when idle */
	}
	
	printf("RX thread stopped\n");
	return NULL;
}

/* TX thread function */
void *voqd_dataplane_tx_thread(void *arg)
{
	struct voqd_dataplane *dp = arg;
	
	printf("TX thread started (CPU affinity=%u)\n",
	       dp->config.cpu_affinity ? dp->config.cpu_affinity + 1 : 0);
	
	/* Pin to CPU if configured (use next CPU after RX) */
	if (dp->config.cpu_affinity > 0) {
		if (pin_thread_to_cpu(dp->config.cpu_affinity + 1) < 0)
			RS_LOG_WARN("Failed to pin TX thread to CPU %u",
			            dp->config.cpu_affinity + 1);
	}
	
	while (dp->running) {
		if (dp->config.enable_afxdp) {
			xsk_manager_complete_all_tx(&dp->xsk_mgr);
			if (dp->config.use_veth_egress)
				xsk_manager_complete_all_tx(&dp->veth_xsk_mgr);
		}
		
		int sent = voqd_dataplane_tx_process(dp);
		
		if (!dp->config.busy_poll && sent == 0)
			usleep(100);
	}
	
	printf("TX thread stopped\n");
	return NULL;
}

/* Start data plane */
int voqd_dataplane_start(struct voqd_dataplane *dp)
{
	if (!dp || dp->running)
		return -EINVAL;
	
	dp->running = true;
	
	/* Start RX thread */
	if (pthread_create(&dp->rx_thread, NULL, voqd_dataplane_rx_thread, dp) != 0) {
		RS_LOG_ERROR("Failed to create RX thread");
		dp->running = false;
		return -1;
	}
	
	/* Start TX thread if scheduler enabled */
	if (dp->config.enable_scheduler) {
		if (pthread_create(&dp->tx_thread, NULL, voqd_dataplane_tx_thread, dp) != 0) {
			RS_LOG_ERROR("Failed to create TX thread");
			dp->running = false;
			pthread_cancel(dp->rx_thread);
			pthread_join(dp->rx_thread, NULL);
			return -1;
		}
	}
	
	printf("Data plane started: RX thread + %s\n",
	       dp->config.enable_scheduler ? "TX thread" : "no TX thread");
	
	return 0;
}

/* Stop data plane */
void voqd_dataplane_stop(struct voqd_dataplane *dp)
{
	if (!dp || !dp->running)
		return;
	
	printf("Stopping data plane...\n");
	
	dp->running = false;
	
	/* Wait for threads */
	pthread_join(dp->rx_thread, NULL);
	
	if (dp->config.enable_scheduler)
		pthread_join(dp->tx_thread, NULL);
	
	printf("Data plane stopped\n");
}

/* Get data plane statistics */
void voqd_dataplane_get_stats(struct voqd_dataplane *dp,
                              uint64_t *rx_pkts, uint64_t *rx_bytes,
                              uint64_t *tx_pkts, uint64_t *tx_bytes)
{
	if (!dp)
		return;
	
	if (rx_pkts) *rx_pkts = dp->rx_packets;
	if (rx_bytes) *rx_bytes = dp->rx_bytes;
	if (tx_pkts) *tx_pkts = dp->tx_packets;
	if (tx_bytes) *tx_bytes = dp->tx_bytes;
}

/* Print data plane statistics */
void voqd_dataplane_print_stats(struct voqd_dataplane *dp)
{
	if (!dp)
		return;
	
	printf("\n=== Data Plane Statistics ===\n");
	printf("RX: %lu packets, %lu bytes",
	       dp->rx_packets, dp->rx_bytes);
	
	if (dp->rx_batch_count > 0) {
		double avg_batch = (double)dp->rx_batch_sum / dp->rx_batch_count;
		printf(" (avg batch: %.1f)", avg_batch);
	}
	printf("\n");
	
	printf("TX: %lu packets, %lu bytes",
	       dp->tx_packets, dp->tx_bytes);
	
	if (dp->tx_batch_count > 0) {
		double avg_batch = (double)dp->tx_batch_sum / dp->tx_batch_count;
		printf(" (avg batch: %.1f)", avg_batch);
	}
	printf("\n");
	
	printf("Errors: enqueue=%lu, tx=%lu\n",
	       dp->enqueue_errors, dp->tx_errors);
	
	printf("Scheduler: %lu rounds\n", dp->scheduler_rounds);
	
	/* AF_XDP stats */
	if (dp->config.enable_afxdp) {
		uint64_t xsk_rx, xsk_tx;
		xsk_manager_get_stats(&dp->xsk_mgr, &xsk_rx, &xsk_tx);
		printf("AF_XDP: RX=%lu packets, TX=%lu packets (%u sockets)\n", 
		       xsk_rx, xsk_tx, dp->xsk_mgr.num_sockets);
	}
}

/*
 * QoS Classification Functions
 */

/* Ethernet frame types */
#define ETH_P_IP    0x0800  /* IPv4 */
#define ETH_P_IPV6  0x86DD  /* IPv6 */

/* IPv4 header structure (simplified) */
struct ipv4_hdr {
	uint8_t version_ihl;     /* Version (4 bits) + IHL (4 bits) */
	uint8_t tos;             /* Type of Service (DSCP + ECN) */
	uint16_t tot_len;        /* Total Length */
	uint16_t id;             /* Identification */
	uint16_t frag_off;       /* Fragment Offset */
	uint8_t ttl;             /* Time to Live */
	uint8_t protocol;        /* Protocol */
	uint16_t check;          /* Header Checksum */
	uint32_t saddr;          /* Source Address */
	uint32_t daddr;          /* Destination Address */
} __attribute__((packed));

/* IPv6 header structure (simplified) */
struct ipv6_hdr {
	uint32_t version_tc_fl;  /* Version (4) + Traffic Class (8) + Flow Label (20) */
	uint16_t payload_len;    /* Payload Length */
	uint8_t next_hdr;        /* Next Header */
	uint8_t hop_limit;       /* Hop Limit */
	uint8_t saddr[16];       /* Source Address */
	uint8_t daddr[16];       /* Destination Address */
} __attribute__((packed));

/* Ethernet header structure */
struct eth_hdr {
	uint8_t dmac[6];         /* Destination MAC */
	uint8_t smac[6];         /* Source MAC */
	uint16_t eth_type;       /* Ethernet Type */
} __attribute__((packed));

/* VLAN header structure (802.1Q) */
struct vlan_hdr {
	uint16_t tci;            /* Tag Control Information */
	uint16_t eth_type;       /* Ethernet Type */
} __attribute__((packed));

/* Check if packet is IPv4 */
bool voqd_is_ipv4_packet(const uint8_t *packet, size_t len)
{
	if (len < sizeof(struct eth_hdr) + sizeof(struct ipv4_hdr))
		return false;
	
	const struct eth_hdr *eth = (const struct eth_hdr *)packet;
	uint16_t eth_type = ntohs(eth->eth_type);
	
	/* Handle VLAN tags */
	if (eth_type == 0x8100 || eth_type == 0x88A8) {  /* VLAN */
		if (len < sizeof(struct eth_hdr) + sizeof(struct vlan_hdr) + sizeof(struct ipv4_hdr))
			return false;
		const struct vlan_hdr *vlan = (const struct vlan_hdr *)(packet + sizeof(struct eth_hdr));
		eth_type = ntohs(vlan->eth_type);
	}
	
	return (eth_type == ETH_P_IP);
}

/* Check if packet is IPv6 */
bool voqd_is_ipv6_packet(const uint8_t *packet, size_t len)
{
	if (len < sizeof(struct eth_hdr) + sizeof(struct ipv6_hdr))
		return false;
	
	const struct eth_hdr *eth = (const struct eth_hdr *)packet;
	uint16_t eth_type = ntohs(eth->eth_type);
	
	/* Handle VLAN tags */
	if (eth_type == 0x8100 || eth_type == 0x88A8) {  /* VLAN */
		if (len < sizeof(struct eth_hdr) + sizeof(struct vlan_hdr) + sizeof(struct ipv6_hdr))
			return false;
		const struct vlan_hdr *vlan = (const struct vlan_hdr *)(packet + sizeof(struct eth_hdr));
		eth_type = ntohs(vlan->eth_type);
	}
	
	return (eth_type == ETH_P_IPV6);
}

/* Parse DSCP value from IP packet header */
uint8_t voqd_parse_ip_dscp(const uint8_t *packet, size_t len)
{
	uint8_t dscp = 0;
	
	if (voqd_is_ipv4_packet(packet, len)) {
		/* IPv4: DSCP is in TOS field (bits 0-5) */
		const struct eth_hdr *eth = (const struct eth_hdr *)packet;
		size_t ip_offset = sizeof(struct eth_hdr);
		
		/* Skip VLAN header if present */
		uint16_t eth_type = ntohs(eth->eth_type);
		if (eth_type == 0x8100 || eth_type == 0x88A8) {  /* VLAN */
			ip_offset += sizeof(struct vlan_hdr);
		}
		
		if (ip_offset + sizeof(struct ipv4_hdr) <= len) {
			const struct ipv4_hdr *ip = (const struct ipv4_hdr *)(packet + ip_offset);
			dscp = (ip->tos >> 2) & 0x3F;  /* DSCP is bits 2-7 of TOS */
		}
		
	} else if (voqd_is_ipv6_packet(packet, len)) {
		/* IPv6: DSCP is in Traffic Class field (bits 4-9 of first 32-bit word) */
		const struct eth_hdr *eth = (const struct eth_hdr *)packet;
		size_t ip_offset = sizeof(struct eth_hdr);
		
		/* Skip VLAN header if present */
		uint16_t eth_type = ntohs(eth->eth_type);
		if (eth_type == 0x8100 || eth_type == 0x88A8) {  /* VLAN */
			ip_offset += sizeof(struct vlan_hdr);
		}
		
		if (ip_offset + sizeof(struct ipv6_hdr) <= len) {
			const struct ipv6_hdr *ip = (const struct ipv6_hdr *)(packet + ip_offset);
			/* Extract traffic class from bytes (RFC 2460 format) */
			const uint8_t *bytes = (const uint8_t *)&ip->version_tc_fl;
			uint8_t traffic_class = ((bytes[0] & 0x0F) << 4) | ((bytes[1] >> 4) & 0x0F);
			dscp = (traffic_class >> 2) & 0x3F;
		}
	}
	
	return dscp;
}

/* Extract priority from packet using IP DSCP or fallback to default */
uint8_t voqd_extract_priority_from_packet(const uint8_t *packet, size_t len, 
                                         const uint8_t *dscp_to_prio, uint8_t default_prio)
{
	/* Check if this is an IP packet */
	if (!voqd_is_ipv4_packet(packet, len) && !voqd_is_ipv6_packet(packet, len)) {
		/* Non-IP packet: use default priority */
		return default_prio;
	}
	
	/* Try to parse DSCP from IP header */
	uint8_t dscp = voqd_parse_ip_dscp(packet, len);
	
	/* Map DSCP to priority using lookup table */
	if (dscp_to_prio && dscp < 64) {
		return dscp_to_prio[dscp];
	}
	
	/* Fallback to default priority */
	return default_prio;
}
