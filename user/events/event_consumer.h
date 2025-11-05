/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __EVENT_CONSUMER_H
#define __EVENT_CONSUMER_H

#include <stdint.h>
#include <pthread.h>

/*
 * Event Consumer for rSwitch
 * 
 * Consumes events from multiple ringbufs:
 * - MAC learning events
 * - Policy hits/violations
 * - Error conditions
 * - Telemetry samples
 */

#define MAX_EVENT_HANDLERS 16

/* Event types */
enum event_type {
    EVENT_MAC_LEARNED = 1,
    EVENT_MAC_AGED = 2,
    EVENT_POLICY_HIT = 3,
    EVENT_POLICY_VIOLATION = 4,
    EVENT_ERROR = 5,
    EVENT_TELEMETRY = 6,
};

/* MAC learning event */
struct mac_learn_event {
    uint64_t timestamp_ns;
    uint8_t mac[6];
    uint16_t vlan;
    uint32_t ifindex;
    uint8_t is_static;
} __attribute__((packed));

/* Policy event */
struct policy_event {
    uint64_t timestamp_ns;
    uint32_t rule_id;
    uint32_t ifindex;
    uint32_t action;        /* 0=permit, 1=deny, 2=mirror */
    uint8_t src_mac[6];
    uint8_t dst_mac[6];
    uint16_t vlan;
    uint8_t protocol;
} __attribute__((packed));

/* Error event */
struct error_event {
    uint64_t timestamp_ns;
    uint32_t error_code;
    uint32_t ifindex;
    char message[64];
} __attribute__((packed));

/* Event handler callback */
typedef int (*event_handler_fn)(void *ctx, enum event_type type, const void *data, size_t size);

/* Event consumer context */
struct event_consumer {
    /* Unified event bus file descriptor */
    int event_bus_fd;
    
    /* Event handlers */
    struct {
        event_handler_fn handler;
        void *ctx;
    } handlers[MAX_EVENT_HANDLERS];
    int num_handlers;
    
    /* Consumer thread */
    pthread_t thread;
    volatile int running;
    
    /* Statistics */
    uint64_t events_received;
    uint64_t events_processed;
    uint64_t events_dropped;
};

/**
 * event_consumer_init - Initialize event consumer
 * @consumer: Event consumer context
 * 
 * Returns 0 on success, -errno on error.
 */
int event_consumer_init(struct event_consumer *consumer);

/**
 * event_consumer_register_handler - Register event handler
 * @consumer: Event consumer context
 * @handler: Handler function
 * @ctx: Handler context
 * 
 * Returns 0 on success, -errno on error.
 */
int event_consumer_register_handler(struct event_consumer *consumer,
                                     event_handler_fn handler,
                                     void *ctx);

/**
 * event_consumer_start - Start event consumption
 * @consumer: Event consumer context
 * 
 * Returns 0 on success, -errno on error.
 */
int event_consumer_start(struct event_consumer *consumer);

/**
 * event_consumer_stop - Stop event consumption
 * @consumer: Event consumer context
 */
void event_consumer_stop(struct event_consumer *consumer);

/**
 * event_consumer_destroy - Cleanup resources
 * @consumer: Event consumer context
 */
void event_consumer_destroy(struct event_consumer *consumer);

/**
 * event_consumer_get_stats - Get event statistics
 * @consumer: Event consumer context
 * @received: Output received count
 * @processed: Output processed count
 * @dropped: Output dropped count
 */
void event_consumer_get_stats(struct event_consumer *consumer,
                               uint64_t *received,
                               uint64_t *processed,
                               uint64_t *dropped);

/* Built-in event handlers */

/**
 * mac_learn_logger_handler - Log MAC learning events
 * 
 * Built-in handler that logs MAC learning to stdout/file.
 */
int mac_learn_logger_handler(void *ctx, enum event_type type, const void *data, size_t size);

/**
 * policy_logger_handler - Log policy events
 * 
 * Built-in handler that logs policy hits/violations.
 */
int policy_logger_handler(void *ctx, enum event_type type, const void *data, size_t size);

/**
 * telemetry_aggregator_handler - Aggregate telemetry events
 * 
 * Built-in handler that aggregates metrics for export.
 */
int telemetry_aggregator_handler(void *ctx, enum event_type type, const void *data, size_t size);

#endif /* __EVENT_CONSUMER_H */
