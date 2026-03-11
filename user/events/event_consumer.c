// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Event Consumer Implementation
 * 
 * Consumes events from BPF ringbufs and dispatches to registered handlers.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "event_consumer.h"
#if __has_include("rs_log.h")
#include "rs_log.h"
#else
#include "../common/rs_log.h"
#endif

#define BPF_PIN_PATH "/sys/fs/bpf"

/* Event type range bases (must match uapi.h) */
#define RS_EVENT_L2_BASE        0x0100
#define RS_EVENT_ACL_BASE       0x0200
#define RS_EVENT_ROUTE_BASE     0x0300
#define RS_EVENT_MIRROR_BASE    0x0400
#define RS_EVENT_QOS_BASE       0x0500
#define RS_EVENT_ERROR_BASE     0xFF00

/* Unified ringbuf callback - dispatches based on event type */
static int unified_ringbuf_callback(void *ctx, void *data, size_t size)
{
    struct event_consumer *consumer = ctx;
    uint32_t *event_type_ptr = (uint32_t *)data;
    enum event_type mapped_type;
    
    if (size < sizeof(uint32_t)) {
        __sync_fetch_and_add(&consumer->events_dropped, 1);
        return 0;
    }
    
    __sync_fetch_and_add(&consumer->events_received, 1);
    
    /* Map BPF event type to consumer event type */
    uint32_t event_type = *event_type_ptr;
    switch (event_type & 0xFF00) {
    case RS_EVENT_L2_BASE:
        if (event_type == (RS_EVENT_L2_BASE + 1))
            mapped_type = EVENT_MAC_LEARNED;
        else if (event_type == (RS_EVENT_L2_BASE + 3))
            mapped_type = EVENT_MAC_AGED;
        else
            mapped_type = EVENT_MAC_LEARNED;  /* Default */
        break;
    case RS_EVENT_ACL_BASE:
        mapped_type = EVENT_POLICY_HIT;
        break;
    case RS_EVENT_ERROR_BASE:
        mapped_type = EVENT_ERROR;
        break;
    default:
        mapped_type = EVENT_MAC_LEARNED;  /* Default fallback */
    }
    
    /* Dispatch to all registered handlers */
    for (int i = 0; i < consumer->num_handlers; i++) {
        if (consumer->handlers[i].handler) {
            int ret = consumer->handlers[i].handler(
                consumer->handlers[i].ctx,
                mapped_type,
                data,
                size
            );
            if (ret < 0) {
                __sync_fetch_and_add(&consumer->events_dropped, 1);
            }
        }
    }
    
    __sync_fetch_and_add(&consumer->events_processed, 1);
    return 0;
}

/* Consumer thread */
static void *consumer_thread(void *arg)
{
    struct event_consumer *consumer = arg;
    struct ring_buffer *event_rb = NULL;
    
    /* Create unified ringbuf consumer */
    if (consumer->event_bus_fd >= 0) {
        event_rb = ring_buffer__new(consumer->event_bus_fd,
                                     unified_ringbuf_callback,
                                     consumer, NULL);
        if (!event_rb) {
            RS_LOG_ERROR("Failed to create event bus ringbuf consumer");
            return NULL;
        }
    } else {
        RS_LOG_ERROR("Event bus FD not available");
        return NULL;
    }
    
    printf("Event consumer thread started (polling rs_event_bus)\n");
    
    /* Poll unified event bus */
    while (consumer->running) {
        ring_buffer__poll(event_rb, 100);  /* 100ms timeout */
    }
    
    /* Cleanup */
    if (event_rb)
        ring_buffer__free(event_rb);
    
    return NULL;
}

int event_consumer_init(struct event_consumer *consumer)
{
    char path[256];
    
    memset(consumer, 0, sizeof(*consumer));
    consumer->event_bus_fd = -1;
    
    /* Open unified event bus */
    snprintf(path, sizeof(path), "%s/rs_event_bus", BPF_PIN_PATH);
    consumer->event_bus_fd = bpf_obj_get(path);
    if (consumer->event_bus_fd < 0) {
        RS_LOG_ERROR("Failed to open rs_event_bus: %s", strerror(errno));
        RS_LOG_ERROR("Make sure rSwitch is loaded and rs_event_bus is pinned.");
        return -errno;
    }
    
    printf("Event consumer initialized (event_bus_fd=%d)\n", consumer->event_bus_fd);
    return 0;
}

int event_consumer_register_handler(struct event_consumer *consumer,
                                     event_handler_fn handler,
                                     void *ctx)
{
    if (consumer->num_handlers >= MAX_EVENT_HANDLERS) {
        return -ENOMEM;
    }
    
    consumer->handlers[consumer->num_handlers].handler = handler;
    consumer->handlers[consumer->num_handlers].ctx = ctx;
    consumer->num_handlers++;
    
    return 0;
}

int event_consumer_start(struct event_consumer *consumer)
{
    consumer->running = 1;
    
    if (pthread_create(&consumer->thread, NULL, consumer_thread, consumer) != 0) {
        RS_LOG_ERROR("Failed to create consumer thread");
        return -errno;
    }
    
    return 0;
}

void event_consumer_stop(struct event_consumer *consumer)
{
    consumer->running = 0;
    pthread_join(consumer->thread, NULL);
}

void event_consumer_destroy(struct event_consumer *consumer)
{
    if (consumer->event_bus_fd >= 0)
        close(consumer->event_bus_fd);
}

void event_consumer_get_stats(struct event_consumer *consumer,
                               uint64_t *received,
                               uint64_t *processed,
                               uint64_t *dropped)
{
    if (received)
        *received = consumer->events_received;
    if (processed)
        *processed = consumer->events_processed;
    if (dropped)
        *dropped = consumer->events_dropped;
}

/* Built-in handlers */

int mac_learn_logger_handler(void *ctx, enum event_type type, const void *data, size_t size)
{
    if (type != EVENT_MAC_LEARNED && type != EVENT_MAC_AGED)
        return 0;
    
    const struct mac_learn_event *event = data;
    
    if (size < sizeof(*event))
        return -EINVAL;
    
    time_t t = event->timestamp_ns / 1000000000ULL;
    struct tm *tm_info = localtime(&t);
    char time_buf[64];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);
    
    printf("[%s] MAC %s: %02x:%02x:%02x:%02x:%02x:%02x VLAN=%u Port=%u Type=%s\n",
           time_buf,
           type == EVENT_MAC_LEARNED ? "LEARNED" : "AGED",
           event->mac[0], event->mac[1], event->mac[2],
           event->mac[3], event->mac[4], event->mac[5],
           event->vlan,
           event->ifindex,
           event->is_static ? "static" : "dynamic");
    
    return 0;
}

int policy_logger_handler(void *ctx, enum event_type type, const void *data, size_t size)
{
    if (type != EVENT_POLICY_HIT && type != EVENT_POLICY_VIOLATION)
        return 0;
    
    const struct policy_event *event = data;
    
    if (size < sizeof(*event))
        return -EINVAL;
    
    const char *action_str[] = {"PERMIT", "DENY", "MIRROR"};
    
    printf("[POLICY] Rule=%u Action=%s Port=%u SRC=%02x:%02x:%02x:%02x:%02x:%02x DST=%02x:%02x:%02x:%02x:%02x:%02x\n",
           event->rule_id,
           event->action < 3 ? action_str[event->action] : "UNKNOWN",
           event->ifindex,
           event->src_mac[0], event->src_mac[1], event->src_mac[2],
           event->src_mac[3], event->src_mac[4], event->src_mac[5],
           event->dst_mac[0], event->dst_mac[1], event->dst_mac[2],
           event->dst_mac[3], event->dst_mac[4], event->dst_mac[5]);
    
    return 0;
}

int telemetry_aggregator_handler(void *ctx, enum event_type type, const void *data, size_t size)
{
    /* Aggregate metrics for telemetry export */
    /* Implementation would update telemetry_ctx snapshot */
    return 0;
}

/* Main entry point - standalone event consumer daemon */
int main(int argc, char **argv)
{
    int log_macs = 0;
    int log_policy = 0;
    int log_errors = 1;  /* Always log errors by default */

    rs_log_init("rswitch-events", RS_LOG_LEVEL_INFO);
    
    int opt;
    while ((opt = getopt(argc, argv, "mpeh")) != -1) {
        switch (opt) {
        case 'm':
            log_macs = 1;
            break;
        case 'p':
            log_policy = 1;
            break;
        case 'e':
            log_errors = 1;
            break;
        case 'h':
        default:
            printf("Usage: %s [options]\n", argv[0]);
            printf("\n");
            printf("Options:\n");
            printf("  -m  Enable MAC learning event logging\n");
            printf("  -p  Enable policy event logging\n");
            printf("  -e  Enable error event logging (default: on)\n");
            printf("  -h  Show this help\n");
            printf("\n");
            printf("Examples:\n");
            printf("  %s -m          # Log MAC learning events only\n", argv[0]);
            printf("  %s -m -p       # Log MAC and policy events\n", argv[0]);
            printf("  %s -m -p -e    # Log all event types\n", argv[0]);
            return (opt == 'h') ? 0 : 1;
        }
    }
    
    printf("rSwitch Event Consumer\n");
    printf("  MAC learning: %s\n", log_macs ? "enabled" : "disabled");
    printf("  Policy events: %s\n", log_policy ? "enabled" : "disabled");
    printf("  Error events: %s\n", log_errors ? "enabled" : "disabled");
    printf("\n");
    
    struct event_consumer consumer;
    if (event_consumer_init(&consumer) < 0) {
        RS_LOG_ERROR("Failed to initialize event consumer");
        return 1;
    }
    
    /* Register handlers based on command-line options */
    if (log_macs) {
        event_consumer_register_handler(&consumer, mac_learn_logger_handler, NULL);
    }
    
    if (log_policy) {
        event_consumer_register_handler(&consumer, policy_logger_handler, NULL);
    }
    
    if (log_errors) {
        event_consumer_register_handler(&consumer, mac_learn_logger_handler, NULL);
    }
    
    if (event_consumer_start(&consumer) < 0) {
        RS_LOG_ERROR("Failed to start event consumer");
        event_consumer_destroy(&consumer);
        return 1;
    }
    
    printf("Event consumer running. Press Ctrl+C to stop.\n");
    
    /* Run until interrupted */
    while (1) {
        sleep(10);
        
        /* Print stats periodically */
        printf("[Stats] Received: %lu, Processed: %lu\n",
               consumer.events_received, consumer.events_processed);
    }
    
    event_consumer_stop(&consumer);
    event_consumer_destroy(&consumer);
    return 0;
}
