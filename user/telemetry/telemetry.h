/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __TELEMETRY_H
#define __TELEMETRY_H

#include <stdint.h>
#include <time.h>

/*
 * rSwitch Telemetry System
 * 
 * Exports metrics to Prometheus and Kafka for monitoring and ML analysis.
 * Based on schema from docs/data_plane_desgin_with_af_XDP.md.
 */

#define MAX_PORTS 64
#define MAX_PRIORITIES 4

/* Telemetry snapshot - collected periodically */
struct telemetry_snapshot {
    /* Timestamp */
    uint64_t timestamp_ns;
    char timestamp_iso8601[32];
    
    /* Node identification */
    char node[64];
    char version[32];
    
    /* Per-interface metrics */
    struct {
        char ifname[16];
        uint32_t ifindex;
        
        /* Packet counters */
        uint64_t rx_packets;
        uint64_t rx_bytes;
        uint64_t tx_packets;
        uint64_t tx_bytes;
        uint64_t rx_drops;
        uint64_t tx_drops;
        
        /* XDP/BPF stats */
        uint64_t xdp_pass;
        uint64_t xdp_drop;
        uint64_t xdp_redirect;
        uint64_t xdp_tx;
        
        /* VOQ stats (per-port, per-priority) */
        struct {
            uint32_t qdepth;        /* Current queue depth */
            uint64_t enqueued;      /* Total enqueued */
            uint64_t dequeued;      /* Total dequeued */
            uint64_t drops;         /* Dropped packets */
            uint32_t latency_usec_p50;
            uint32_t latency_usec_p99;
        } voq[MAX_PRIORITIES];
        
        /* VLAN stats */
        uint64_t vlan_tagged;
        uint64_t vlan_untagged;
        uint64_t vlan_drops;
        
        /* MAC learning stats */
        uint32_t mac_learned;
        uint32_t mac_aged;
    } iface[MAX_PORTS];
    
    uint32_t num_ifaces;
    
    /* Global VOQd stats */
    struct {
        uint32_t mode;              /* BYPASS/SHADOW/ACTIVE */
        uint32_t running;
        uint32_t prio_mask;
        uint64_t heartbeats_sent;
        uint32_t failover_count;
        uint32_t overload_drops;
        
        /* Ringbuf stats */
        uint64_t ringbuf_received;
        uint64_t ringbuf_processed;
        uint64_t ringbuf_dropped;
        
        /* Scheduler stats */
        uint64_t scheduled_packets;
        uint64_t scheduled_bytes;
        uint32_t active_queues;
    } voqd;
    
    /* Policy enforcement stats */
    struct {
        uint64_t egress_check_blocks;
        uint64_t mirror_out;
        uint64_t rate_limit_drops;
        uint64_t acl_drops;
    } policy;
    
    /* System resource usage */
    struct {
        float cpu_percent;
        uint64_t rss_mb;
        uint32_t threads;
        float cpu_steal;
    } system;
};

/* Prometheus metric types */
enum metric_type {
    METRIC_COUNTER = 0,
    METRIC_GAUGE = 1,
    METRIC_HISTOGRAM = 2,
};

/* Telemetry exporter configuration */
struct telemetry_config {
    /* Prometheus HTTP server */
    int prometheus_enabled;
    char prometheus_bind[64];   /* e.g., "0.0.0.0:9090" */
    
    /* Kafka producer */
    int kafka_enabled;
    char kafka_brokers[256];    /* e.g., "localhost:9092" */
    char kafka_topic[64];       /* e.g., "rswitch.telemetry" */
    
    /* Collection interval */
    uint32_t interval_sec;
    
    /* Node identification */
    char node_name[64];
};

/* Telemetry context */
struct telemetry_ctx {
    struct telemetry_config config;
    struct telemetry_snapshot snapshot;
    
    /* Prometheus HTTP server fd */
    int prometheus_fd;
    
    /* Kafka producer handle (opaque) */
    void *kafka_producer;
    
    /* Collection thread */
    pthread_t thread;
    volatile int running;
};

/**
 * telemetry_init - Initialize telemetry system
 * @ctx: Telemetry context
 * @config: Configuration
 * 
 * Returns 0 on success, -errno on error.
 */
int telemetry_init(struct telemetry_ctx *ctx, const struct telemetry_config *config);

/**
 * telemetry_start - Start telemetry collection and export
 * @ctx: Telemetry context
 * 
 * Starts background thread for periodic metric collection.
 * Returns 0 on success, -errno on error.
 */
int telemetry_start(struct telemetry_ctx *ctx);

/**
 * telemetry_stop - Stop telemetry collection
 * @ctx: Telemetry context
 */
void telemetry_stop(struct telemetry_ctx *ctx);

/**
 * telemetry_destroy - Cleanup telemetry resources
 * @ctx: Telemetry context
 */
void telemetry_destroy(struct telemetry_ctx *ctx);

/**
 * telemetry_collect_snapshot - Manually trigger snapshot collection
 * @ctx: Telemetry context
 * 
 * Collects current metrics from BPF maps, VOQd state, system stats.
 * Returns 0 on success, -errno on error.
 */
int telemetry_collect_snapshot(struct telemetry_ctx *ctx);

/**
 * telemetry_export_prometheus - Export metrics in Prometheus format
 * @ctx: Telemetry context
 * @buf: Output buffer
 * @size: Buffer size
 * 
 * Returns number of bytes written, or -errno on error.
 */
int telemetry_export_prometheus(struct telemetry_ctx *ctx, char *buf, size_t size);

/**
 * telemetry_export_json - Export metrics as JSON
 * @ctx: Telemetry context
 * @buf: Output buffer
 * @size: Buffer size
 * 
 * Returns number of bytes written, or -errno on error.
 */
int telemetry_export_json(struct telemetry_ctx *ctx, char *buf, size_t size);

/**
 * telemetry_send_kafka - Send snapshot to Kafka
 * @ctx: Telemetry context
 * 
 * Returns 0 on success, -errno on error.
 */
int telemetry_send_kafka(struct telemetry_ctx *ctx);

#endif /* __TELEMETRY_H */
