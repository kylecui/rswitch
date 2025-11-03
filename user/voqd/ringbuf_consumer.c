// SPDX-License-Identifier: GPL-2.0
#include "ringbuf_consumer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>

/*
 * Ringbuf Consumer Implementation
 */

/* Internal callback wrapper */
static int rb_event_handler(void *ctx, void *data, size_t data_sz)
{
	struct rb_consumer *consumer = ctx;
	
	if (data_sz != sizeof(struct voq_meta)) {
		fprintf(stderr, "Invalid event size: %zu (expected %zu)\n",
		        data_sz, sizeof(struct voq_meta));
		consumer->events_dropped++;
		return 0;
	}
	
	consumer->events_received++;
	
	const struct voq_meta *meta = data;
	
	/* Call user handler */
	if (consumer->handle_event) {
		int ret = consumer->handle_event(consumer->callback_ctx, meta);
		if (ret == 0) {
			consumer->events_processed++;
		} else {
			consumer->events_dropped++;
		}
		return ret;
	}
	
	consumer->events_processed++;
	return 0;
}

/* Initialize ringbuf consumer */
int rb_consumer_init(struct rb_consumer *consumer, const char *pin_path,
                     int (*handle_fn)(void *ctx, const struct voq_meta *meta),
                     void *callback_ctx)
{
	if (!consumer || !pin_path)
		return -EINVAL;
	
	memset(consumer, 0, sizeof(*consumer));
	consumer->handle_event = handle_fn;
	consumer->callback_ctx = callback_ctx;
	consumer->running = false;
	
	/* Open pinned ringbuf map */
	consumer->ringbuf_fd = bpf_obj_get(pin_path);
	if (consumer->ringbuf_fd < 0) {
		fprintf(stderr, "Failed to open pinned ringbuf at %s: %s\n",
		        pin_path, strerror(errno));
		return -errno;
	}
	
	/* Create ring_buffer consumer */
	consumer->rb = ring_buffer__new(consumer->ringbuf_fd, rb_event_handler, consumer, NULL);
	if (!consumer->rb) {
		fprintf(stderr, "Failed to create ring_buffer: %s\n", strerror(errno));
		close(consumer->ringbuf_fd);
		return -errno;
	}
	
	return 0;
}

/* Destroy ringbuf consumer */
void rb_consumer_destroy(struct rb_consumer *consumer)
{
	if (!consumer)
		return;
	
	if (consumer->rb) {
		ring_buffer__free(consumer->rb);
		consumer->rb = NULL;
	}
	
	if (consumer->ringbuf_fd >= 0) {
		close(consumer->ringbuf_fd);
		consumer->ringbuf_fd = -1;
	}
}

/* Poll for events */
int rb_consumer_poll(struct rb_consumer *consumer, int timeout_ms)
{
	if (!consumer || !consumer->rb)
		return -EINVAL;
	
	return ring_buffer__poll(consumer->rb, timeout_ms);
}

/* Consumer thread */
static void *consumer_thread(void *arg)
{
	struct rb_consumer *consumer = arg;
	
	while (consumer->running) {
		int ret = rb_consumer_poll(consumer, 100);  /* 100ms timeout */
		if (ret < 0 && ret != -EINTR) {
			fprintf(stderr, "Ringbuf poll error: %d\n", ret);
			break;
		}
	}
	
	return NULL;
}

/* Start consumer thread */
int rb_consumer_start_thread(struct rb_consumer *consumer)
{
	if (!consumer)
		return -EINVAL;
	
	consumer->running = true;
	
	pthread_t thread;
	int ret = pthread_create(&thread, NULL, consumer_thread, consumer);
	if (ret != 0)
		return -ret;
	
	pthread_detach(thread);
	return 0;
}

/* Stop consumer thread */
void rb_consumer_stop_thread(struct rb_consumer *consumer)
{
	if (!consumer)
		return;
	
	consumer->running = false;
	/* Thread will exit on next poll timeout */
}

/* Get statistics */
void rb_consumer_get_stats(struct rb_consumer *consumer,
                           uint64_t *received, uint64_t *processed, uint64_t *dropped)
{
	if (!consumer)
		return;
	
	if (received) *received = consumer->events_received;
	if (processed) *processed = consumer->events_processed;
	if (dropped) *dropped = consumer->events_dropped;
}
