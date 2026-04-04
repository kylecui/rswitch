// SPDX-License-Identifier: GPL-2.0
#include "voq.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#if __has_include("rs_log.h")
#include "rs_log.h"
#else
#include "../common/rs_log.h"
#endif

/*
 * VOQ Manager Implementation
 * 
 * Implements Virtual Output Queuing with DRR scheduling and token bucket rate limiting.
 */

#define POOL_CHUNK_SIZE 1024
#define NSEC_PER_SEC 1000000000ULL

/* Helper: Get current time in nanoseconds */
static uint64_t get_time_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec;
}

static void voq_apply_shaper_config(struct voq_mgr *mgr, uint64_t now_ns)
{
	if (!mgr || !mgr->shaper_cfg) {
		return;
	}

	struct rs_shaper_shared_cfg *cfg = mgr->shaper_cfg;
	uint32_t max_ports = mgr->num_ports;

	if (cfg->version != RS_SHAPER_CFG_VERSION) {
		return;
	}

	if (cfg->generation == mgr->shaper_cfg_generation) {
		return;
	}

	if (max_ports > cfg->num_ports) {
		max_ports = cfg->num_ports;
	}

	for (uint32_t p = 0; p < max_ports; p++) {
		struct voq_port *port = &mgr->ports[p];
		struct rs_shaper_port_cfg *port_cfg = &cfg->ports[p];
		uint32_t weights[RS_SHAPER_WFQ_MAX_QUEUES] = {0};

		pthread_mutex_lock(&port->lock);
		rs_shaper_configure(&port->shaper, port_cfg->rate_bps, port_cfg->burst_bytes,
		                    port_cfg->enabled, now_ns);

		for (int q = 0; q < MAX_PRIORITIES && q < RS_SHAPER_WFQ_MAX_QUEUES; q++) {
			struct voq_queue *queue = &port->queues[q];
			struct rs_shaper_queue_cfg *queue_cfg = &port_cfg->queue_cfg[q];

			pthread_mutex_lock(&queue->lock);
			rs_shaper_configure(&queue->shaper, queue_cfg->rate_bps, queue_cfg->burst_bytes,
			                    queue_cfg->enabled, now_ns);
			pthread_mutex_unlock(&queue->lock);
			weights[q] = port_cfg->wfq.queue_weights[q];
		}

		rs_wfq_set_weights(&port->wfq, weights, MAX_PRIORITIES);
		port->wfq.enabled = port_cfg->wfq.enabled;
		pthread_mutex_unlock(&port->lock);
	}

	mgr->shaper_cfg_generation = cfg->generation;
	RS_LOG_INFO("Applied shaper config generation=%u", cfg->generation);
}

/* Allocate entry from pool */
static struct voq_entry *alloc_entry(struct voq_mgr *mgr)
{
	struct voq_entry *entry;
	
	pthread_mutex_lock(&mgr->pool_lock);
	
	if (!mgr->free_entries) {
		/* Allocate new chunk */
		struct voq_entry *chunk = calloc(POOL_CHUNK_SIZE, sizeof(struct voq_entry));
		if (!chunk) {
			pthread_mutex_unlock(&mgr->pool_lock);
			return NULL;
		}

		if (mgr->num_chunks == mgr->max_chunks) {
			uint32_t new_max = mgr->max_chunks ? mgr->max_chunks * 2 : 4;
			struct voq_entry **new_chunk_ptrs = realloc(mgr->chunk_ptrs,
			                                           new_max * sizeof(*new_chunk_ptrs));
			if (!new_chunk_ptrs) {
				free(chunk);
				pthread_mutex_unlock(&mgr->pool_lock);
				return NULL;
			}
			mgr->chunk_ptrs = new_chunk_ptrs;
			mgr->max_chunks = new_max;
		}
		mgr->chunk_ptrs[mgr->num_chunks++] = chunk;
		
		/* Link chunk into free list */
		for (int i = 0; i < POOL_CHUNK_SIZE - 1; i++) {
			chunk[i].next = &chunk[i + 1];
		}
		chunk[POOL_CHUNK_SIZE - 1].next = NULL;
		
		mgr->free_entries = chunk;
		mgr->num_free_entries += POOL_CHUNK_SIZE;
		mgr->total_entries += POOL_CHUNK_SIZE;
	}
	
	entry = mgr->free_entries;
	mgr->free_entries = entry->next;
	mgr->num_free_entries--;
	
	pthread_mutex_unlock(&mgr->pool_lock);
	
	memset(entry, 0, sizeof(*entry));
	return entry;
}

/* Return entry to pool */
void voq_free_entry(struct voq_mgr *mgr, struct voq_entry *entry)
{
	if (!entry)
		return;
	
	pthread_mutex_lock(&mgr->pool_lock);
	entry->next = mgr->free_entries;
	mgr->free_entries = entry;
	mgr->num_free_entries++;
	pthread_mutex_unlock(&mgr->pool_lock);
}

/* Initialize VOQ manager */
int voq_mgr_init(struct voq_mgr *mgr, uint32_t num_ports)
{
	if (!mgr || num_ports == 0 || num_ports > MAX_PORTS)
		return -EINVAL;
	
	memset(mgr, 0, sizeof(*mgr));
	mgr->num_ports = num_ports;
	mgr->running = true;
	mgr->chunk_ptrs = NULL;
	mgr->num_chunks = 0;
	mgr->max_chunks = 0;
	
	/* Initialize pool lock */
	pthread_mutex_init(&mgr->pool_lock, NULL);

	int shm_ret = rs_shaper_shared_open(&mgr->shaper_cfg, 1);
	if (shm_ret < 0) {
		RS_LOG_WARN("Shaper shared memory unavailable: %d", shm_ret);
		mgr->shaper_cfg = NULL;
	} else {
		mgr->shaper_cfg_generation = 0;
	}
	
	/* Default quantum and max_depth per priority */
	for (int i = 0; i < MAX_PRIORITIES; i++) {
		mgr->quantum[i] = DEFAULT_QUANTUM * (i + 1);  /* Higher prio = larger quantum */
		mgr->max_depth[i] = MAX_QUEUE_DEPTH;
	}
	
	/* Initialize ports */
	for (uint32_t p = 0; p < num_ports; p++) {
		struct voq_port *port = &mgr->ports[p];
		pthread_mutex_init(&port->lock, NULL);
		
		for (int q = 0; q < MAX_PRIORITIES; q++) {
			struct voq_queue *queue = &port->queues[q];
			pthread_mutex_init(&queue->lock, NULL);
			queue->quantum = mgr->quantum[q];
			queue->max_depth = mgr->max_depth[q];
			rs_shaper_init(&queue->shaper, get_time_ns());
		}
		rs_shaper_init(&port->shaper, get_time_ns());
		rs_wfq_init(&port->wfq, MAX_PRIORITIES);
	}

	voq_apply_shaper_config(mgr, get_time_ns());
	
	return 0;
}

/* Destroy VOQ manager */
void voq_mgr_destroy(struct voq_mgr *mgr)
{
	if (!mgr)
		return;
	
	mgr->running = false;

	if (mgr->shaper_cfg) {
		rs_shaper_shared_close(mgr->shaper_cfg);
		mgr->shaper_cfg = NULL;
	}
	
	/* Free all queued entries */
	for (uint32_t p = 0; p < mgr->num_ports; p++) {
		struct voq_port *port = &mgr->ports[p];
		
		for (int q = 0; q < MAX_PRIORITIES; q++) {
			struct voq_queue *queue = &port->queues[q];
			struct voq_entry *entry = queue->head;
			
			while (entry) {
				struct voq_entry *next = entry->next;
				voq_free_entry(mgr, entry);
				entry = next;
			}
			
			pthread_mutex_destroy(&queue->lock);
		}
		
		pthread_mutex_destroy(&port->lock);
	}
	
	for (uint32_t i = 0; i < mgr->num_chunks; i++)
		free(mgr->chunk_ptrs[i]);
	free(mgr->chunk_ptrs);
	
	pthread_mutex_destroy(&mgr->pool_lock);
}

/* Add port to VOQ manager */
int voq_add_port(struct voq_mgr *mgr, uint32_t port_idx, uint32_t ifindex, const char *ifname)
{
	if (!mgr || port_idx >= mgr->num_ports || !ifname)
		return -EINVAL;
	
	struct voq_port *port = &mgr->ports[port_idx];
	port->enabled = true;
	port->ifindex = ifindex;
	snprintf(port->ifname, sizeof(port->ifname), "%s", ifname);
	
	return 0;
}

/* Configure port rate limiting */
int voq_set_port_rate(struct voq_mgr *mgr, uint32_t port_idx, uint64_t rate_bps, uint64_t burst_bytes)
{
	if (!mgr || port_idx >= mgr->num_ports)
		return -EINVAL;
	
	struct voq_port *port = &mgr->ports[port_idx];
	uint64_t now_ns = get_time_ns();

	pthread_mutex_lock(&port->lock);
	rs_shaper_configure(&port->shaper, rate_bps, burst_bytes,
	                    (rate_bps > 0 && burst_bytes > 0), now_ns);
	pthread_mutex_unlock(&port->lock);
	
	return 0;
}

/* Configure queue parameters */
int voq_set_queue_params(struct voq_mgr *mgr, uint32_t prio, uint32_t quantum, uint32_t max_depth)
{
	if (!mgr || prio >= MAX_PRIORITIES)
		return -EINVAL;
	
	mgr->quantum[prio] = quantum;
	mgr->max_depth[prio] = max_depth;
	
	/* Update all queues */
	for (uint32_t p = 0; p < mgr->num_ports; p++) {
		struct voq_queue *queue = &mgr->ports[p].queues[prio];
		pthread_mutex_lock(&queue->lock);
		queue->quantum = quantum;
		queue->max_depth = max_depth;
		pthread_mutex_unlock(&queue->lock);
	}
	
	return 0;
}

/* Enqueue packet metadata */
int voq_enqueue(struct voq_mgr *mgr, uint32_t port_idx, uint32_t prio,
                uint64_t ts_ns, uint32_t len, uint32_t flow_hash,
                uint8_t ecn_hint, uint8_t drop_hint, uint64_t xdp_frame)
{
	if (!mgr || port_idx >= mgr->num_ports || prio >= MAX_PRIORITIES)
		return -EINVAL;
	
	struct voq_port *port = &mgr->ports[port_idx];
	if (!port->enabled)
		return -ENODEV;
	
	struct voq_queue *queue = &port->queues[prio];
	
	/* Check drop hint or queue full */
	pthread_mutex_lock(&queue->lock);
	if (drop_hint || queue->depth >= queue->max_depth) {
		queue->dropped++;
		pthread_mutex_unlock(&queue->lock);
		return -ENOSPC;
	}
	
	/* Allocate entry */
	struct voq_entry *entry = alloc_entry(mgr);
	if (!entry) {
		queue->dropped++;
		pthread_mutex_unlock(&queue->lock);
		return -ENOMEM;
	}
	
	/* Fill entry */
	entry->ts_ns = ts_ns;
	entry->eg_port = port_idx;
	entry->prio = prio;
	entry->len = len;
	entry->flow_hash = flow_hash;
	entry->ecn_hint = ecn_hint;
	entry->drop_hint = drop_hint;
	entry->xdp_frame_addr = xdp_frame;
	entry->next = NULL;
	
	/* Enqueue at tail */
	if (queue->tail) {
		queue->tail->next = entry;
	} else {
		queue->head = entry;
	}
	queue->tail = entry;
	queue->depth++;
	
	/* Update stats */
	queue->enqueued++;
	queue->bytes_enq += len;
	mgr->total_enqueued++;
	
	pthread_mutex_unlock(&queue->lock);
	return 0;
}

/* Dequeue packet using DRR scheduler */
struct voq_entry *voq_dequeue(struct voq_mgr *mgr, uint32_t *out_port_idx)
{
	if (!mgr || !out_port_idx)
		return NULL;
	
	uint64_t now_ns = get_time_ns();
	uint32_t start_port = mgr->current_port;
	voq_apply_shaper_config(mgr, now_ns);
	
	/* Round-robin over ports */
	for (uint32_t p_iter = 0; p_iter < mgr->num_ports; p_iter++) {
		uint32_t p = (start_port + p_iter) % mgr->num_ports;
		struct voq_port *port = &mgr->ports[p];
		
		if (!port->enabled)
			continue;
		
		pthread_mutex_lock(&port->lock);

		rs_shaper_refill(&port->shaper, now_ns);

		for (int attempts = 0; attempts < MAX_PRIORITIES; attempts++) {
			int prio = -1;
			if (port->wfq.enabled) {
				uint32_t depths[RS_SHAPER_WFQ_MAX_QUEUES] = {0};
				for (int q = 0; q < MAX_PRIORITIES; q++) {
					depths[q] = port->queues[q].depth;
				}
				prio = rs_wfq_select_queue(&port->wfq, depths, MAX_PRIORITIES);
				if (prio < 0) {
					break;
				}
			} else {
				prio = MAX_PRIORITIES - 1 - attempts;
			}

			struct voq_queue *queue = &port->queues[prio];
			pthread_mutex_lock(&queue->lock);

			if (!queue->head) {
				pthread_mutex_unlock(&queue->lock);
				continue;
			}

			rs_shaper_refill(&queue->shaper, now_ns);
			queue->deficit += queue->quantum;

			if (queue->deficit < (int32_t)queue->head->len) {
				pthread_mutex_unlock(&queue->lock);
				continue;
			}

			if (!rs_shaper_admit(&port->shaper, queue->head->len, now_ns) ||
			    !rs_shaper_admit(&queue->shaper, queue->head->len, now_ns)) {
				pthread_mutex_unlock(&queue->lock);
				continue;
			}

			struct voq_entry *entry = queue->head;
			queue->head = entry->next;
			if (!queue->head) {
				queue->tail = NULL;
			}
			queue->depth--;
			queue->deficit -= entry->len;
			queue->dequeued++;
			queue->bytes_deq += entry->len;
			mgr->total_dequeued++;

			uint64_t latency_ns = now_ns - entry->ts_ns;
			queue->latency_sum_ns += latency_ns;
			queue->latency_count++;

			pthread_mutex_unlock(&queue->lock);
			pthread_mutex_unlock(&port->lock);

			*out_port_idx = p;
			mgr->current_port = (p + 1) % mgr->num_ports;
			mgr->scheduler_rounds++;

			return entry;
		}
		
		pthread_mutex_unlock(&port->lock);
	}
	
	/* No packets available */
	return NULL;
}

/* Get queue statistics */
void voq_get_queue_stats(struct voq_mgr *mgr, uint32_t port_idx, uint32_t prio,
                         uint64_t *enqueued, uint64_t *dequeued, uint64_t *dropped,
                         uint64_t *depth, uint64_t *latency_p99_ns)
{
	if (!mgr || port_idx >= mgr->num_ports || prio >= MAX_PRIORITIES)
		return;
	
	struct voq_queue *queue = &mgr->ports[port_idx].queues[prio];
	
	pthread_mutex_lock(&queue->lock);
	if (enqueued) *enqueued = queue->enqueued;
	if (dequeued) *dequeued = queue->dequeued;
	if (dropped) *dropped = queue->dropped;
	if (depth) *depth = queue->depth;
	if (latency_p99_ns) *latency_p99_ns = queue->latency_p99_ns;
	pthread_mutex_unlock(&queue->lock);
}

/* Get port statistics */
void voq_get_port_stats(struct voq_mgr *mgr, uint32_t port_idx,
                        uint64_t *total_enq, uint64_t *total_deq, uint64_t *total_drop)
{
	if (!mgr || port_idx >= mgr->num_ports)
		return;
	
	struct voq_port *port = &mgr->ports[port_idx];
	uint64_t enq = 0, deq = 0, drop = 0;
	
	for (int q = 0; q < MAX_PRIORITIES; q++) {
		struct voq_queue *queue = &port->queues[q];
		pthread_mutex_lock(&queue->lock);
		enq += queue->enqueued;
		deq += queue->dequeued;
		drop += queue->dropped;
		pthread_mutex_unlock(&queue->lock);
	}
	
	if (total_enq) *total_enq = enq;
	if (total_deq) *total_deq = deq;
	if (total_drop) *total_drop = drop;
}

/* Print statistics */
void voq_print_stats(struct voq_mgr *mgr)
{
	if (!mgr)
		return;
	
	printf("\n=== VOQ Manager Statistics ===\n");
	printf("Total: enqueued=%lu, dequeued=%lu, dropped=%lu, rounds=%lu\n",
	       mgr->total_enqueued, mgr->total_dequeued, mgr->total_dropped, mgr->scheduler_rounds);
	printf("Memory pool: free=%u, total=%u\n", mgr->num_free_entries, mgr->total_entries);
	
	for (uint32_t p = 0; p < mgr->num_ports; p++) {
		struct voq_port *port = &mgr->ports[p];
		if (!port->enabled)
			continue;
		
		printf("\nPort %u (%s, ifindex=%u):\n", p, port->ifname, port->ifindex);
		if (port->shaper.enabled) {
			printf("  Rate limit: %lu Mbps, burst=%lu KB, tokens=%lu\n",
			       port->shaper.rate_bps / 1000000, port->shaper.burst_bytes / 1024, port->shaper.tokens);
		}
		
		for (int q = 0; q < MAX_PRIORITIES; q++) {
			struct voq_queue *queue = &port->queues[q];
			pthread_mutex_lock(&queue->lock);
			
			printf("  Prio %d: depth=%u/%u, enq=%lu (%lu KB), deq=%lu (%lu KB), drop=%lu\n",
			       q, queue->depth, queue->max_depth,
			       queue->enqueued, queue->bytes_enq / 1024,
			       queue->dequeued, queue->bytes_deq / 1024,
			       queue->dropped);
			
			if (queue->latency_count > 0) {
				uint64_t avg_ns = queue->latency_sum_ns / queue->latency_count;
				printf("    Latency: avg=%lu us, p99=%lu us\n",
				       avg_ns / 1000, queue->latency_p99_ns / 1000);
			}
			
			pthread_mutex_unlock(&queue->lock);
		}
	}
	
	printf("\n");
}

/* Single scheduler iteration */
int voq_scheduler_step(struct voq_mgr *mgr)
{
	uint32_t port_idx;
	struct voq_entry *entry = voq_dequeue(mgr, &port_idx);
	
	if (entry) {
		/* In production, this would trigger AF_XDP TX */
		voq_free_entry(mgr, entry);
		return 1;  /* Packet dequeued */
	}
	
	return 0;  /* No packets */
}

/* Scheduler thread */
static void *scheduler_thread(void *arg)
{
	struct voq_mgr *mgr = arg;
	
	while (mgr->running) {
		int dequeued = voq_scheduler_step(mgr);
		
		if (!dequeued) {
			/* No packets - sleep briefly */
			usleep(10);
		}
	}
	
	return NULL;
}

/* Start scheduler thread */
int voq_start_scheduler(struct voq_mgr *mgr)
{
	if (!mgr)
		return -EINVAL;
	
	mgr->running = true;
	return pthread_create(&mgr->scheduler_thread, NULL, scheduler_thread, mgr);
}

/* Stop scheduler thread */
void voq_stop_scheduler(struct voq_mgr *mgr)
{
	if (!mgr)
		return;
	
	mgr->running = false;
	pthread_join(mgr->scheduler_thread, NULL);
}
