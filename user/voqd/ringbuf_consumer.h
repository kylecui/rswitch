/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __RINGBUF_CONSUMER_H__
#define __RINGBUF_CONSUMER_H__

#include <stdint.h>
#include <stdbool.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "../../bpf/core/afxdp_common.h"

/*
 * Ringbuf Consumer for VOQ Metadata
 * 
 * Consumes voq_meta events from XDP and enqueues into VOQ manager.
 */

/* Ringbuf consumer context */
struct rb_consumer {
	struct ring_buffer *rb;
	int ringbuf_fd;
	
	/* Callback for each event */
	int (*handle_event)(void *ctx, const struct voq_meta *meta);
	void *callback_ctx;
	
	/* Statistics */
	uint64_t events_received;
	uint64_t events_processed;
	uint64_t events_dropped;
	
	volatile bool running;
};

/* Initialize ringbuf consumer */
int rb_consumer_init(struct rb_consumer *consumer, const char *pin_path,
                     int (*handle_fn)(void *ctx, const struct voq_meta *meta),
                     void *callback_ctx);

/* Destroy ringbuf consumer */
void rb_consumer_destroy(struct rb_consumer *consumer);

/* Poll for events (blocking with timeout_ms) */
int rb_consumer_poll(struct rb_consumer *consumer, int timeout_ms);

/* Start consumer in separate thread */
int rb_consumer_start_thread(struct rb_consumer *consumer);

/* Stop consumer thread */
void rb_consumer_stop_thread(struct rb_consumer *consumer);

/* Get statistics */
void rb_consumer_get_stats(struct rb_consumer *consumer,
                           uint64_t *received, uint64_t *processed, uint64_t *dropped);

#endif /* __RINGBUF_CONSUMER_H__ */
