// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * rSwitch Telemetry Implementation
 * 
 * Collects metrics from BPF maps and exports to Prometheus/Kafka.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include "telemetry.h"

/* BPF map paths */
#define BPF_PIN_PATH "/sys/fs/bpf"

/* Get current time in ISO8601 format */
static void get_iso8601_timestamp(char *buf, size_t size)
{
    time_t now = time(NULL);
    struct tm *tm_info = gmtime(&now);
    strftime(buf, size, "%Y-%m-%dT%H:%M:%SZ", tm_info);
}

/* Get current time in nanoseconds */
static uint64_t get_time_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

/* Collect BPF map statistics */
static int collect_bpf_stats(struct telemetry_ctx *ctx)
{
    char path[256];
    int fd;
    
    /* Open rs_stats_map */
    snprintf(path, sizeof(path), "%s/rs_stats_map", BPF_PIN_PATH);
    fd = bpf_obj_get(path);
    if (fd < 0) {
        fprintf(stderr, "Warning: Failed to open rs_stats_map\n");
        return -errno;
    }
    
    /* Iterate through per-CPU stats */
    for (uint32_t i = 0; i < ctx->snapshot.num_ifaces; i++) {
        uint32_t ifindex = ctx->snapshot.iface[i].ifindex;
        
        /* Read per-CPU array and aggregate */
        struct rs_stats {
            uint64_t rx_packets;
            uint64_t rx_bytes;
            uint64_t tx_packets;
            uint64_t tx_bytes;
            uint64_t rx_drops;
            uint64_t tx_drops;
            uint64_t rx_errors;
            uint64_t tx_errors;
        } stats = {0};
        
        /* For simplicity, read key=ifindex (needs per-CPU aggregation in production) */
        if (bpf_map_lookup_elem(fd, &ifindex, &stats) == 0) {
            ctx->snapshot.iface[i].rx_packets = stats.rx_packets;
            ctx->snapshot.iface[i].rx_bytes = stats.rx_bytes;
            ctx->snapshot.iface[i].tx_packets = stats.tx_packets;
            ctx->snapshot.iface[i].tx_bytes = stats.tx_bytes;
            ctx->snapshot.iface[i].rx_drops = stats.rx_drops;
            ctx->snapshot.iface[i].tx_drops = stats.tx_drops;
        }
    }
    
    close(fd);
    return 0;
}

/* Collect VOQd statistics */
static int collect_voqd_stats(struct telemetry_ctx *ctx)
{
    char path[256];
    int fd;
    uint32_t key = 0;
    
    /* Open voqd_state_map */
    snprintf(path, sizeof(path), "%s/voqd_state_map", BPF_PIN_PATH);
    fd = bpf_obj_get(path);
    if (fd < 0) {
        /* VOQd may not be running */
        return 0;
    }
    
    struct voqd_state {
        uint32_t running;
        uint32_t prio_mask;
        uint32_t mode;
        uint64_t last_heartbeat_ns;
        uint32_t failover_count;
        uint32_t overload_drops;
        uint32_t flags;
        uint32_t _reserved;
    } state;
    
    if (bpf_map_lookup_elem(fd, &key, &state) == 0) {
        ctx->snapshot.voqd.mode = state.mode;
        ctx->snapshot.voqd.running = state.running;
        ctx->snapshot.voqd.prio_mask = state.prio_mask;
        ctx->snapshot.voqd.failover_count = state.failover_count;
        ctx->snapshot.voqd.overload_drops = state.overload_drops;
    }
    
    close(fd);
    return 0;
}

/* Collect system resource usage */
static int collect_system_stats(struct telemetry_ctx *ctx)
{
    FILE *fp;
    char line[256];
    
    /* Read /proc/self/status for memory usage */
    fp = fopen("/proc/self/status", "r");
    if (fp) {
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "VmRSS:", 6) == 0) {
                uint64_t rss_kb;
                sscanf(line + 6, "%lu", &rss_kb);
                ctx->snapshot.system.rss_mb = rss_kb / 1024;
                break;
            }
        }
        fclose(fp);
    }
    
    /* Read /proc/stat for CPU usage (simplified) */
    fp = fopen("/proc/stat", "r");
    if (fp) {
        if (fgets(line, sizeof(line), fp)) {
            /* Parse "cpu  user nice system idle ..." */
            uint64_t user, nice, system, idle;
            if (sscanf(line, "cpu  %lu %lu %lu %lu", &user, &nice, &system, &idle) == 4) {
                uint64_t total = user + nice + system + idle;
                uint64_t used = user + nice + system;
                ctx->snapshot.system.cpu_percent = (float)used / total * 100.0f;
            }
        }
        fclose(fp);
    }
    
    return 0;
}

int telemetry_collect_snapshot(struct telemetry_ctx *ctx)
{
    /* Update timestamp */
    ctx->snapshot.timestamp_ns = get_time_ns();
    get_iso8601_timestamp(ctx->snapshot.timestamp_iso8601, 
                          sizeof(ctx->snapshot.timestamp_iso8601));
    
    /* Collect from various sources */
    collect_bpf_stats(ctx);
    collect_voqd_stats(ctx);
    collect_system_stats(ctx);
    
    return 0;
}

int telemetry_export_prometheus(struct telemetry_ctx *ctx, char *buf, size_t size)
{
    int offset = 0;
    
    /* Prometheus text exposition format */
    offset += snprintf(buf + offset, size - offset,
        "# HELP rswitch_rx_packets Total received packets\n"
        "# TYPE rswitch_rx_packets counter\n");
    
    for (uint32_t i = 0; i < ctx->snapshot.num_ifaces; i++) {
        offset += snprintf(buf + offset, size - offset,
            "rswitch_rx_packets{node=\"%s\",iface=\"%s\"} %lu\n",
            ctx->snapshot.node,
            ctx->snapshot.iface[i].ifname,
            ctx->snapshot.iface[i].rx_packets);
    }
    
    offset += snprintf(buf + offset, size - offset,
        "# HELP rswitch_rx_bytes Total received bytes\n"
        "# TYPE rswitch_rx_bytes counter\n");
    
    for (uint32_t i = 0; i < ctx->snapshot.num_ifaces; i++) {
        offset += snprintf(buf + offset, size - offset,
            "rswitch_rx_bytes{node=\"%s\",iface=\"%s\"} %lu\n",
            ctx->snapshot.node,
            ctx->snapshot.iface[i].ifname,
            ctx->snapshot.iface[i].rx_bytes);
    }
    
    /* VOQd metrics */
    offset += snprintf(buf + offset, size - offset,
        "# HELP rswitch_voqd_mode VOQd operating mode (0=BYPASS, 1=SHADOW, 2=ACTIVE)\n"
        "# TYPE rswitch_voqd_mode gauge\n"
        "rswitch_voqd_mode{node=\"%s\"} %u\n",
        ctx->snapshot.node, ctx->snapshot.voqd.mode);
    
    offset += snprintf(buf + offset, size - offset,
        "# HELP rswitch_voqd_failovers Total automatic failovers\n"
        "# TYPE rswitch_voqd_failovers counter\n"
        "rswitch_voqd_failovers{node=\"%s\"} %u\n",
        ctx->snapshot.node, ctx->snapshot.voqd.failover_count);
    
    /* System metrics */
    offset += snprintf(buf + offset, size - offset,
        "# HELP rswitch_cpu_percent CPU usage percentage\n"
        "# TYPE rswitch_cpu_percent gauge\n"
        "rswitch_cpu_percent{node=\"%s\"} %.2f\n",
        ctx->snapshot.node, ctx->snapshot.system.cpu_percent);
    
    offset += snprintf(buf + offset, size - offset,
        "# HELP rswitch_memory_mb Memory usage in MB\n"
        "# TYPE rswitch_memory_mb gauge\n"
        "rswitch_memory_mb{node=\"%s\"} %lu\n",
        ctx->snapshot.node, ctx->snapshot.system.rss_mb);
    
    return offset;
}

int telemetry_export_json(struct telemetry_ctx *ctx, char *buf, size_t size)
{
    int offset = 0;
    
    offset += snprintf(buf + offset, size - offset,
        "{\n"
        "  \"ts\": \"%s\",\n"
        "  \"node\": \"%s\",\n"
        "  \"version\": \"%s\",\n"
        "  \"ifaces\": [\n",
        ctx->snapshot.timestamp_iso8601,
        ctx->snapshot.node,
        ctx->snapshot.version);
    
    for (uint32_t i = 0; i < ctx->snapshot.num_ifaces; i++) {
        offset += snprintf(buf + offset, size - offset,
            "    {\n"
            "      \"name\": \"%s\",\n"
            "      \"ifindex\": %u,\n"
            "      \"rx_packets\": %lu,\n"
            "      \"rx_bytes\": %lu,\n"
            "      \"tx_packets\": %lu,\n"
            "      \"tx_bytes\": %lu,\n"
            "      \"rx_drops\": %lu,\n"
            "      \"tx_drops\": %lu\n"
            "    }%s\n",
            ctx->snapshot.iface[i].ifname,
            ctx->snapshot.iface[i].ifindex,
            ctx->snapshot.iface[i].rx_packets,
            ctx->snapshot.iface[i].rx_bytes,
            ctx->snapshot.iface[i].tx_packets,
            ctx->snapshot.iface[i].tx_bytes,
            ctx->snapshot.iface[i].rx_drops,
            ctx->snapshot.iface[i].tx_drops,
            (i < ctx->snapshot.num_ifaces - 1) ? "," : "");
    }
    
    offset += snprintf(buf + offset, size - offset,
        "  ],\n"
        "  \"voqd\": {\n"
        "    \"mode\": %u,\n"
        "    \"running\": %u,\n"
        "    \"prio_mask\": \"0x%02x\",\n"
        "    \"failover_count\": %u,\n"
        "    \"overload_drops\": %u\n"
        "  },\n"
        "  \"system\": {\n"
        "    \"cpu_pct\": %.2f,\n"
        "    \"rss_mb\": %lu\n"
        "  }\n"
        "}\n",
        ctx->snapshot.voqd.mode,
        ctx->snapshot.voqd.running,
        ctx->snapshot.voqd.prio_mask,
        ctx->snapshot.voqd.failover_count,
        ctx->snapshot.voqd.overload_drops,
        ctx->snapshot.system.cpu_percent,
        ctx->snapshot.system.rss_mb);
    
    return offset;
}

/* Prometheus HTTP server - simple implementation */
static void *prometheus_server_thread(void *arg)
{
    struct telemetry_ctx *ctx = arg;
    struct sockaddr_in addr;
    int server_fd, client_fd;
    char buf[65536];
    char response[65536];
    
    /* Create socket */
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return NULL;
    }
    
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    /* Parse bind address */
    char *colon = strchr(ctx->config.prometheus_bind, ':');
    int port = 9090;
    if (colon) {
        port = atoi(colon + 1);
    }
    
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(server_fd);
        return NULL;
    }
    
    listen(server_fd, 5);
    printf("Prometheus exporter listening on :%d\n", port);
    
    while (ctx->running) {
        client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0)
            continue;
        
        /* Read HTTP request (we don't parse it, just respond) */
        read(client_fd, buf, sizeof(buf));
        
        /* Collect fresh metrics */
        telemetry_collect_snapshot(ctx);
        
        /* Export as Prometheus format */
        int len = telemetry_export_prometheus(ctx, response, sizeof(response));
        
        /* Send HTTP response */
        char header[512];
        snprintf(header, sizeof(header),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain; version=0.0.4\r\n"
            "Content-Length: %d\r\n"
            "\r\n", len);
        
        write(client_fd, header, strlen(header));
        write(client_fd, response, len);
        
        close(client_fd);
    }
    
    close(server_fd);
    return NULL;
}

/* Collection thread */
static void *collection_thread(void *arg)
{
    struct telemetry_ctx *ctx = arg;
    
    while (ctx->running) {
        telemetry_collect_snapshot(ctx);
        
        /* Send to Kafka if enabled */
        if (ctx->config.kafka_enabled) {
            telemetry_send_kafka(ctx);
        }
        
        sleep(ctx->config.interval_sec);
    }
    
    return NULL;
}

int telemetry_init(struct telemetry_ctx *ctx, const struct telemetry_config *config)
{
    memset(ctx, 0, sizeof(*ctx));
    memcpy(&ctx->config, config, sizeof(*config));
    
    /* Set node name */
    if (strlen(config->node_name) > 0) {
        strncpy(ctx->snapshot.node, config->node_name, sizeof(ctx->snapshot.node) - 1);
    } else {
        gethostname(ctx->snapshot.node, sizeof(ctx->snapshot.node) - 1);
    }
    
    strncpy(ctx->snapshot.version, "1.0.0", sizeof(ctx->snapshot.version) - 1);
    
    return 0;
}

int telemetry_start(struct telemetry_ctx *ctx)
{
    ctx->running = 1;
    
    /* Start Prometheus HTTP server */
    if (ctx->config.prometheus_enabled) {
        pthread_create(&ctx->thread, NULL, prometheus_server_thread, ctx);
    }
    
    /* Start collection thread for Kafka */
    if (ctx->config.kafka_enabled) {
        /* Kafka implementation would go here */
        fprintf(stderr, "Warning: Kafka export not yet implemented\n");
    }
    
    return 0;
}

void telemetry_stop(struct telemetry_ctx *ctx)
{
    ctx->running = 0;
    
    if (ctx->config.prometheus_enabled) {
        pthread_join(ctx->thread, NULL);
    }
}

void telemetry_destroy(struct telemetry_ctx *ctx)
{
    /* Cleanup resources */
    if (ctx->kafka_producer) {
        /* Free Kafka producer */
    }
}

int telemetry_send_kafka(struct telemetry_ctx *ctx)
{
    /* Kafka implementation requires librdkafka */
    /* For now, just export JSON to stdout */
    char buf[65536];
    telemetry_export_json(ctx, buf, sizeof(buf));
    
    /* In production, send via Kafka producer */
    // rd_kafka_produce(...);
    
    return 0;
}

/* Main entry point - standalone telemetry exporter */
int main(int argc, char **argv)
{
    struct telemetry_config config = {
        .prometheus_enabled = 1,
        .kafka_enabled = 0,
        .interval_sec = 5,
    };
    
    strncpy(config.prometheus_bind, "0.0.0.0:9090", sizeof(config.prometheus_bind) - 1);
    strncpy(config.kafka_topic, "rswitch-metrics", sizeof(config.kafka_topic) - 1);
    
    /* Get hostname */
    gethostname(config.node_name, sizeof(config.node_name) - 1);
    
    int opt;
    while ((opt = getopt(argc, argv, "p:i:h")) != -1) {
        switch (opt) {
        case 'p':
            strncpy(config.prometheus_bind, optarg, sizeof(config.prometheus_bind) - 1);
            break;
        case 'i':
            config.interval_sec = atoi(optarg);
            break;
        case 'h':
        default:
            printf("Usage: %s [options]\n", argv[0]);
            printf("\n");
            printf("Options:\n");
            printf("  -p ADDR:PORT  Prometheus bind address (default: %s)\n", config.prometheus_bind);
            printf("  -i INTERVAL   Collection interval in seconds (default: %u)\n", config.interval_sec);
            printf("  -h            Show this help\n");
            printf("\n");
            printf("Examples:\n");
            printf("  %s                      # Prometheus on default port 9090\n", argv[0]);
            printf("  %s -p 127.0.0.1:9090   # Bind to localhost\n", argv[0]);
            printf("  %s -i 10               # Collect every 10 seconds\n", argv[0]);
            return (opt == 'h') ? 0 : 1;
        }
    }
    
    printf("rSwitch Telemetry Exporter\n");
    printf("  Node: %s\n", config.node_name);
    printf("  Prometheus: http://%s/metrics\n", config.prometheus_bind);
    printf("  Collection interval: %u sec\n", config.interval_sec);
    printf("\n");
    
    struct telemetry_ctx ctx;
    if (telemetry_init(&ctx, &config) < 0) {
        fprintf(stderr, "Failed to initialize telemetry\n");
        return 1;
    }
    
    if (telemetry_start(&ctx) < 0) {
        fprintf(stderr, "Failed to start telemetry exporter\n");
        telemetry_destroy(&ctx);
        return 1;
    }
    
    printf("Telemetry exporter running. Press Ctrl+C to stop.\n");
    
    /* Run until interrupted */
    while (1) {
        sleep(60);
    }
    
    telemetry_stop(&ctx);
    telemetry_destroy(&ctx);
    return 0;
}
