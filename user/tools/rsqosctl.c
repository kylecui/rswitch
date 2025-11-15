// SPDX-License-Identifier: GPL-2.0
/*
 * rsqosctl - rSwitch QoS Control Tool
 * 
 * Manages Quality of Service policies:
 * - Traffic classification rules (proto+port+dscp → priority)
 * - Rate limiting configuration (per-priority token buckets)
 * - DSCP remarking policies
 * - Congestion control thresholds
 * 
 * Usage:
 *   rsqosctl add-class --proto tcp --dport 22 --priority 3
 *   rsqosctl set-rate-limit --priority 0 --rate 1000000 --burst 64000
 *   rsqosctl set-dscp --priority 3 --dscp 46  # EF (Expedited Forwarding)
 *   rsqosctl set-congestion --threshold 75
 *   rsqosctl enable / disable
 *   rsqosctl stats / clear
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

// Match BPF structures from qos.bpf.c
#define QOS_PRIO_CRITICAL   3
#define QOS_PRIO_HIGH       2
#define QOS_PRIO_NORMAL     1
#define QOS_PRIO_LOW        0
#define QOS_MAX_PRIORITIES  4

#define QOS_FLAG_ENABLED            (1 << 0)
#define QOS_FLAG_RATE_LIMIT_ENABLED (1 << 1)
#define QOS_FLAG_ECN_ENABLED        (1 << 2)
#define QOS_FLAG_DSCP_REWRITE       (1 << 3)

struct qos_class_key {
    __u8  proto;
    __u8  dscp;
    __u16 dport;
} __attribute__((packed));

struct qos_class_result {
    __u8  priority;
    __u8  drop_precedence;
    __u8  rate_limit_id;
    __u8  flags;
    __u32 rate_limit_bps;
} __attribute__((packed));

struct qos_rate_limiter {
    __u32 rate_bps;
    __u32 burst_bytes;
    __u64 tokens;
    __u64 last_update_ns;
    __u64 total_bytes;
    __u64 dropped_bytes;
    __u32 dropped_packets;
    __u32 pad;
} __attribute__((aligned(8)));

struct qos_congestion_state {
    __u32 queue_depth;
    __u32 queue_bytes;
    __u32 threshold_packets;
    __u32 threshold_bytes;
    __u64 congestion_events;
    __u64 ecn_marked;
    __u64 early_drops;
    __u32 flags;
} __attribute__((aligned(8)));

struct qos_config {
    __u32 flags;
    __u8  default_priority;
    __u8  congestion_threshold_pct;
    __u16 queue_size_packets;
    __u8  dscp_map[QOS_MAX_PRIORITIES];
    __u32 pad;
};

enum qos_stat_type {
    QOS_STAT_CLASSIFIED_PACKETS = 0,
    QOS_STAT_UNCLASSIFIED_PACKETS = 1,
    QOS_STAT_RATE_LIMITED_PACKETS = 2,
    QOS_STAT_CONGESTION_DROPS = 3,
    QOS_STAT_ECN_MARKED = 4,
    QOS_STAT_DSCP_REMARKED = 5,
    QOS_STAT_PRIORITY_0 = 6,
    QOS_STAT_PRIORITY_1 = 7,
    QOS_STAT_PRIORITY_2 = 8,
    QOS_STAT_PRIORITY_3 = 9,
    QOS_STAT_MAX = 10,
};

#define PIN_BASE_DIR "/sys/fs/bpf"

static const char *priority_names[] = {
    [QOS_PRIO_LOW] = "LOW",
    [QOS_PRIO_NORMAL] = "NORMAL", 
    [QOS_PRIO_HIGH] = "HIGH",
    [QOS_PRIO_CRITICAL] = "CRITICAL",
};

static const char *stat_names[] = {
    [QOS_STAT_CLASSIFIED_PACKETS] = "Classified packets",
    [QOS_STAT_UNCLASSIFIED_PACKETS] = "Unclassified packets",
    [QOS_STAT_RATE_LIMITED_PACKETS] = "Rate limited packets",
    [QOS_STAT_CONGESTION_DROPS] = "Congestion drops",
    [QOS_STAT_ECN_MARKED] = "ECN marked packets",
    [QOS_STAT_DSCP_REMARKED] = "DSCP remarked packets",
    [QOS_STAT_PRIORITY_0] = "Priority 0 (LOW) packets",
    [QOS_STAT_PRIORITY_1] = "Priority 1 (NORMAL) packets",
    [QOS_STAT_PRIORITY_2] = "Priority 2 (HIGH) packets",
    [QOS_STAT_PRIORITY_3] = "Priority 3 (CRITICAL) packets",
};

// Parse protocol name to number
static int parse_protocol(const char *proto_str)
{
    if (strcasecmp(proto_str, "tcp") == 0)
        return 6;
    if (strcasecmp(proto_str, "udp") == 0)
        return 17;
    if (strcasecmp(proto_str, "icmp") == 0)
        return 1;
    if (strcasecmp(proto_str, "any") == 0)
        return 0;
    
    return atoi(proto_str);
}

// Parse priority name to number
static int parse_priority(const char *prio_str)
{
    if (strcasecmp(prio_str, "critical") == 0)
        return QOS_PRIO_CRITICAL;
    if (strcasecmp(prio_str, "high") == 0)
        return QOS_PRIO_HIGH;
    if (strcasecmp(prio_str, "normal") == 0 || strcasecmp(prio_str, "default") == 0)
        return QOS_PRIO_NORMAL;
    if (strcasecmp(prio_str, "low") == 0 || strcasecmp(prio_str, "background") == 0)
        return QOS_PRIO_LOW;
    
    int prio = atoi(prio_str);
    if (prio >= 0 && prio < QOS_MAX_PRIORITIES)
        return prio;
    
    fprintf(stderr, "Invalid priority: %s (must be 0-3 or low/normal/high/critical)\n", prio_str);
    return -1;
}

// Parse rate in human-readable format (e.g., "1M", "500K", "100")
static uint64_t parse_rate(const char *rate_str)
{
    char *endptr;
    uint64_t rate = strtoull(rate_str, &endptr, 10);
    
    if (*endptr != '\0') {
        switch (*endptr) {
        case 'k':
        case 'K':
            rate *= 1000;
            break;
        case 'm':
        case 'M':
            rate *= 1000000;
            break;
        case 'g':
        case 'G':
            rate *= 1000000000;
            break;
        default:
            fprintf(stderr, "Invalid rate suffix: %c (use K, M, G)\n", *endptr);
            return 0;
        }
    }
    
    return rate;
}

// Add traffic classification rule
static int cmd_add_class(int argc, char **argv)
{
    struct qos_class_key key = {0};
    struct qos_class_result result = {0};
    char *proto_str = NULL, *prio_str = NULL;
    int dport = 0, dscp = 0;
    int fd, ret;
    
    struct option long_opts[] = {
        {"proto", required_argument, 0, 'p'},
        {"dport", required_argument, 0, 'P'},
        {"dscp", required_argument, 0, 'd'},
        {"priority", required_argument, 0, 'r'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "p:P:d:r:", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'p':
            proto_str = optarg;
            break;
        case 'P':
            dport = atoi(optarg);
            break;
        case 'd':
            dscp = atoi(optarg);
            break;
        case 'r':
            prio_str = optarg;
            break;
        default:
            fprintf(stderr, "Usage: rsqosctl add-class --proto <proto> [--dport <port>] [--dscp <dscp>] --priority <priority>\n");
            return -1;
        }
    }
    
    if (!proto_str || !prio_str) {
        fprintf(stderr, "Missing required arguments (need --proto and --priority)\n");
        return -1;
    }
    
    key.proto = parse_protocol(proto_str);
    key.dport = htons(dport);
    key.dscp = dscp & 0x3F;  // 6 bits
    
    result.priority = parse_priority(prio_str);
    if (result.priority < 0)
        return -1;
    
    char map_path[256];
    snprintf(map_path, sizeof(map_path), "%s/qos_class_map", PIN_BASE_DIR);
    fd = bpf_obj_get(map_path);
    if (fd < 0) {
        fprintf(stderr, "Failed to open QoS class map: %s\n", strerror(errno));
        return -1;
    }
    
    ret = bpf_map_update_elem(fd, &key, &result, BPF_ANY);
    if (ret < 0) {
        fprintf(stderr, "Failed to add classification rule: %s\n", strerror(errno));
        close(fd);
        return -1;
    }
    
    printf("Added classification rule: proto=%u dport=%u dscp=%u → priority=%s\n",
           key.proto, ntohs(key.dport), key.dscp, priority_names[result.priority]);
    
    close(fd);
    return 0;
}

// Set rate limiting for priority
static int cmd_set_rate_limit(int argc, char **argv)
{
    char *prio_str = NULL, *rate_str = NULL, *burst_str = NULL;
    int priority;
    uint64_t rate_bps, burst_bytes;
    int fd, ret;
    
    struct option long_opts[] = {
        {"priority", required_argument, 0, 'p'},
        {"rate", required_argument, 0, 'r'},
        {"burst", required_argument, 0, 'b'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "p:r:b:", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'p':
            prio_str = optarg;
            break;
        case 'r':
            rate_str = optarg;
            break;
        case 'b':
            burst_str = optarg;
            break;
        default:
            fprintf(stderr, "Usage: rsqosctl set-rate-limit --priority <priority> --rate <rate> [--burst <burst>]\n");
            return -1;
        }
    }
    
    if (!prio_str || !rate_str) {
        fprintf(stderr, "Missing required arguments (need --priority and --rate)\n");
        return -1;
    }
    
    priority = parse_priority(prio_str);
    if (priority < 0)
        return -1;
    
    rate_bps = parse_rate(rate_str);
    if (rate_bps == 0) {
        fprintf(stderr, "Invalid rate: %s\n", rate_str);
        return -1;
    }
    
    // Default burst = 10% of rate (min 1KB)
    if (burst_str) {
        burst_bytes = parse_rate(burst_str);
    } else {
        burst_bytes = rate_bps / 10;
        if (burst_bytes < 1024)
            burst_bytes = 1024;
    }
    
    char map_path[256];
    snprintf(map_path, sizeof(map_path), "%s/qos_rate_limiters", PIN_BASE_DIR);
    fd = bpf_obj_get(map_path);
    if (fd < 0) {
        fprintf(stderr, "Failed to open rate limiter map: %s\n", strerror(errno));
        return -1;
    }
    
    struct qos_rate_limiter limiter = {
        .rate_bps = (uint32_t)rate_bps,
        .burst_bytes = (uint32_t)burst_bytes,
        .tokens = burst_bytes,  // Start with full bucket
        .last_update_ns = 0,
        .total_bytes = 0,
        .dropped_bytes = 0,
        .dropped_packets = 0,
    };
    
    uint32_t key = priority;
    ret = bpf_map_update_elem(fd, &key, &limiter, BPF_ANY);
    if (ret < 0) {
        fprintf(stderr, "Failed to set rate limit: %s\n", strerror(errno));
        close(fd);
        return -1;
    }
    
    printf("Set rate limit for priority %s: %lu bps, burst %lu bytes\n",
           priority_names[priority], rate_bps, burst_bytes);
    
    close(fd);
    return 0;
}

// Set DSCP remarking for priority
static int cmd_set_dscp(int argc, char **argv)
{
    char *prio_str = NULL;
    int priority, dscp;
    int fd, ret;
    
    if (argc < 5 || strcmp(argv[1], "--priority") != 0 || strcmp(argv[3], "--dscp") != 0) {
        fprintf(stderr, "Usage: rsqosctl set-dscp --priority <priority> --dscp <dscp>\n");
        fprintf(stderr, "Common DSCP values:\n");
        fprintf(stderr, "  0  = Best Effort (BE)\n");
        fprintf(stderr, "  10 = AF11 (Low priority data)\n");
        fprintf(stderr, "  18 = AF21 (Standard data)\n");
        fprintf(stderr, "  26 = AF31 (High priority data)\n");
        fprintf(stderr, "  34 = AF41 (Video)\n");
        fprintf(stderr, "  46 = EF (Voice, critical)\n");
        return -1;
    }
    
    prio_str = argv[2];
    dscp = atoi(argv[4]);
    
    priority = parse_priority(prio_str);
    if (priority < 0)
        return -1;
    
    if (dscp < 0 || dscp > 63) {
        fprintf(stderr, "Invalid DSCP: %d (must be 0-63)\n", dscp);
        return -1;
    }
    
    char map_path[256];
    snprintf(map_path, sizeof(map_path), "%s/qos_config_map", PIN_BASE_DIR);
    fd = bpf_obj_get(map_path);
    if (fd < 0) {
        fprintf(stderr, "Failed to open QoS config map: %s\n", strerror(errno));
        return -1;
    }
    
    uint32_t key = 0;
    struct qos_config cfg;
    
    // Read current config
    ret = bpf_map_lookup_elem(fd, &key, &cfg);
    if (ret < 0) {
        // Initialize if not exists
        memset(&cfg, 0, sizeof(cfg));
        cfg.flags = QOS_FLAG_ENABLED;
        cfg.default_priority = QOS_PRIO_NORMAL;
        cfg.congestion_threshold_pct = 75;
        cfg.queue_size_packets = 1000;
    }
    
    cfg.dscp_map[priority] = dscp;
    cfg.flags |= QOS_FLAG_DSCP_REWRITE;
    
    ret = bpf_map_update_elem(fd, &key, &cfg, BPF_ANY);
    if (ret < 0) {
        fprintf(stderr, "Failed to set DSCP mapping: %s\n", strerror(errno));
        close(fd);
        return -1;
    }
    
    printf("Set DSCP mapping: priority %s → DSCP %d\n", priority_names[priority], dscp);
    
    close(fd);
    return 0;
}

// Set congestion control threshold
static int cmd_set_congestion(int argc, char **argv)
{
    int threshold_pct;
    int fd, ret;
    
    if (argc < 3 || strcmp(argv[1], "--threshold") != 0) {
        fprintf(stderr, "Usage: rsqosctl set-congestion --threshold <percentage>\n");
        fprintf(stderr, "Example: rsqosctl set-congestion --threshold 75\n");
        return -1;
    }
    
    threshold_pct = atoi(argv[2]);
    if (threshold_pct < 1 || threshold_pct > 100) {
        fprintf(stderr, "Invalid threshold: %d (must be 1-100)\n", threshold_pct);
        return -1;
    }
    
    char map_path[256];
    snprintf(map_path, sizeof(map_path), "%s/qos_config_map", PIN_BASE_DIR);
    fd = bpf_obj_get(map_path);
    if (fd < 0) {
        fprintf(stderr, "Failed to open QoS config map: %s\n", strerror(errno));
        return -1;
    }
    
    uint32_t key = 0;
    struct qos_config cfg;
    
    ret = bpf_map_lookup_elem(fd, &key, &cfg);
    if (ret < 0) {
        memset(&cfg, 0, sizeof(cfg));
        cfg.flags = QOS_FLAG_ENABLED;
        cfg.default_priority = QOS_PRIO_NORMAL;
        cfg.queue_size_packets = 1000;
    }
    
    cfg.congestion_threshold_pct = threshold_pct;
    cfg.flags |= QOS_FLAG_ECN_ENABLED;
    
    ret = bpf_map_update_elem(fd, &key, &cfg, BPF_ANY);
    if (ret < 0) {
        fprintf(stderr, "Failed to set congestion threshold: %s\n", strerror(errno));
        close(fd);
        return -1;
    }
    
    printf("Set congestion threshold: %d%%\n", threshold_pct);
    
    close(fd);
    return 0;
}

// Enable/disable QoS
static int cmd_set_enabled(int enable)
{
    struct qos_config cfg;
    uint32_t key = 0;
    int fd, ret;
    
    char map_path[256];
    snprintf(map_path, sizeof(map_path), "%s/qos_config_map", PIN_BASE_DIR);
    fd = bpf_obj_get(map_path);
    if (fd < 0) {
        fprintf(stderr, "Failed to open QoS config map: %s\n", strerror(errno));
        return -1;
    }
    
    ret = bpf_map_lookup_elem(fd, &key, &cfg);
    if (ret < 0) {
        memset(&cfg, 0, sizeof(cfg));
        cfg.default_priority = QOS_PRIO_NORMAL;
        cfg.congestion_threshold_pct = 75;
        cfg.queue_size_packets = 1000;
    }
    
    if (enable) {
        cfg.flags |= QOS_FLAG_ENABLED;
    } else {
        cfg.flags &= ~QOS_FLAG_ENABLED;
    }
    
    ret = bpf_map_update_elem(fd, &key, &cfg, BPF_ANY);
    if (ret < 0) {
        fprintf(stderr, "Failed to update QoS state: %s\n", strerror(errno));
        close(fd);
        return -1;
    }
    
    printf("QoS %s\n", enable ? "enabled" : "disabled");
    
    close(fd);
    return 0;
}

// Show statistics
static int cmd_stats(void)
{
    uint64_t stats[QOS_STAT_MAX] = {0};
    int fd, i;
    
    char map_path[256];
    snprintf(map_path, sizeof(map_path), "%s/qos_stats_map", PIN_BASE_DIR);
    fd = bpf_obj_get(map_path);
    if (fd < 0) {
        fprintf(stderr, "Failed to open QoS stats map: %s\n", strerror(errno));
        return -1;
    }
    
    printf("\nQoS Statistics:\n");
    printf("═══════════════════════════════════════\n");
    
    for (i = 0; i < QOS_STAT_MAX; i++) {
        uint32_t key = i;
        uint64_t val = 0;
        
        if (bpf_map_lookup_elem(fd, &key, &val) == 0) {
            stats[i] = val;
            printf("  %-25s: %llu\n", stat_names[i], (unsigned long long)val);
        }
    }
    
    close(fd);
    
    // Show rate limiter statistics
    printf("\nRate Limiter Statistics:\n");
    printf("───────────────────────────────────────\n");
    
    snprintf(map_path, sizeof(map_path), "%s/qos_rate_limiters", PIN_BASE_DIR);
    fd = bpf_obj_get(map_path);
    if (fd >= 0) {
        for (i = 0; i < QOS_MAX_PRIORITIES; i++) {
            uint32_t key = i;
            struct qos_rate_limiter limiter;
            
            if (bpf_map_lookup_elem(fd, &key, &limiter) == 0 && limiter.rate_bps > 0) {
                printf("  Priority %s:\n", priority_names[i]);
                printf("    Rate: %u bps, Burst: %u bytes\n", limiter.rate_bps, limiter.burst_bytes);
                printf("    Total: %llu bytes, Dropped: %llu bytes (%u packets)\n",
                       (unsigned long long)limiter.total_bytes,
                       (unsigned long long)limiter.dropped_bytes,
                       limiter.dropped_packets);
                printf("    Current tokens: %llu bytes\n\n",
                       (unsigned long long)limiter.tokens);
            }
        }
        close(fd);
    }
    
    printf("\n");
    return 0;
}

// List configuration
static int cmd_list(void)
{
    printf("\nQoS Configuration:\n");
    printf("═══════════════════════════════════════\n");
    
    // Show global config
    char map_path[256];
    snprintf(map_path, sizeof(map_path), "%s/qos_config_map", PIN_BASE_DIR);
    int cfg_fd = bpf_obj_get(map_path);
    if (cfg_fd >= 0) {
        uint32_t key = 0;
        struct qos_config cfg;
        if (bpf_map_lookup_elem(cfg_fd, &key, &cfg) == 0) {
            printf("Status: %s\n", (cfg.flags & QOS_FLAG_ENABLED) ? "ENABLED" : "DISABLED");
            printf("Features:\n");
            printf("  - Rate limiting: %s\n", (cfg.flags & QOS_FLAG_RATE_LIMIT_ENABLED) ? "ON" : "OFF");
            printf("  - ECN marking: %s\n", (cfg.flags & QOS_FLAG_ECN_ENABLED) ? "ON" : "OFF");
            printf("  - DSCP rewrite: %s\n", (cfg.flags & QOS_FLAG_DSCP_REWRITE) ? "ON" : "OFF");
            printf("Default Priority: %s\n", priority_names[cfg.default_priority]);
            printf("Congestion Threshold: %u%%\n", cfg.congestion_threshold_pct);
            printf("Queue Size: %u packets\n\n", cfg.queue_size_packets);
            
            printf("DSCP Remarking:\n");
            for (int i = 0; i < QOS_MAX_PRIORITIES; i++) {
                if (cfg.dscp_map[i] != 0) {
                    printf("  Priority %s → DSCP %u\n", priority_names[i], cfg.dscp_map[i]);
                }
            }
            printf("\n");
        }
        close(cfg_fd);
    }
    
    printf("Classification Rules:\n");
    printf("───────────────────────────────────────\n");
    
    snprintf(map_path, sizeof(map_path), "%s/qos_class_map", PIN_BASE_DIR);
    int class_fd = bpf_obj_get(map_path);
    if (class_fd >= 0) {
        struct qos_class_key key = {0}, next_key;
        struct qos_class_result result;
        int count = 0;
        
        while (bpf_map_get_next_key(class_fd, &key, &next_key) == 0) {
            if (bpf_map_lookup_elem(class_fd, &next_key, &result) == 0) {
                printf("  proto=%u dport=%u dscp=%u → %s\n",
                       next_key.proto, ntohs(next_key.dport), next_key.dscp,
                       priority_names[result.priority]);
                count++;
            }
            key = next_key;
        }
        
        if (count == 0)
            printf("  (none - using built-in defaults)\n");
        
        close(class_fd);
    }
    
    printf("\n");
    return 0;
}

// Clear all rules
static int cmd_clear(void)
{
    char map_path[256];
    
    // Clear classification rules
    snprintf(map_path, sizeof(map_path), "%s/qos_class_map", PIN_BASE_DIR);
    int fd = bpf_obj_get(map_path);
    if (fd >= 0) {
        struct qos_class_key key = {0}, next_key;
        int count = 0;
        
        while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
            bpf_map_delete_elem(fd, &next_key);
            key = next_key;
            count++;
        }
        
        printf("Cleared %d classification rules\n", count);
        close(fd);
    }
    
    // Clear rate limiters
    snprintf(map_path, sizeof(map_path), "%s/qos_rate_limiters", PIN_BASE_DIR);
    fd = bpf_obj_get(map_path);
    if (fd >= 0) {
        for (int i = 0; i < QOS_MAX_PRIORITIES; i++) {
            uint32_t key = i;
            struct qos_rate_limiter zero = {0};
            bpf_map_update_elem(fd, &key, &zero, BPF_ANY);
        }
        printf("Cleared all rate limiters\n");
        close(fd);
    }
    
    return 0;
}

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s <command> [options]\n\n", prog);
    fprintf(stderr, "Commands:\n");
    fprintf(stderr, "  add-class       Add traffic classification rule\n");
    fprintf(stderr, "  set-rate-limit  Configure per-priority rate limiting\n");
    fprintf(stderr, "  set-dscp        Configure DSCP remarking\n");
    fprintf(stderr, "  set-congestion  Configure congestion control threshold\n");
    fprintf(stderr, "  enable          Enable QoS\n");
    fprintf(stderr, "  disable         Disable QoS\n");
    fprintf(stderr, "  list            List configuration\n");
    fprintf(stderr, "  stats           Show statistics\n");
    fprintf(stderr, "  clear           Clear all rules\n\n");
    fprintf(stderr, "Examples:\n");
    fprintf(stderr, "  # Classify SSH as critical priority\n");
    fprintf(stderr, "  %s add-class --proto tcp --dport 22 --priority critical\n\n", prog);
    fprintf(stderr, "  # Rate limit background traffic to 1 Mbps\n");
    fprintf(stderr, "  %s set-rate-limit --priority low --rate 1M --burst 64K\n\n", prog);
    fprintf(stderr, "  # Mark critical traffic with EF DSCP (46)\n");
    fprintf(stderr, "  %s set-dscp --priority critical --dscp 46\n\n", prog);
    fprintf(stderr, "  # Set congestion threshold to 75%% of queue\n");
    fprintf(stderr, "  %s set-congestion --threshold 75\n\n", prog);
    fprintf(stderr, "  # Enable QoS processing\n");
    fprintf(stderr, "  %s enable\n", prog);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }
    
    const char *cmd = argv[1];
    
    if (strcmp(cmd, "add-class") == 0) {
        return cmd_add_class(argc - 1, argv + 1);
    } else if (strcmp(cmd, "set-rate-limit") == 0) {
        return cmd_set_rate_limit(argc - 1, argv + 1);
    } else if (strcmp(cmd, "set-dscp") == 0) {
        return cmd_set_dscp(argc - 1, argv + 1);
    } else if (strcmp(cmd, "set-congestion") == 0) {
        return cmd_set_congestion(argc - 1, argv + 1);
    } else if (strcmp(cmd, "enable") == 0) {
        return cmd_set_enabled(1);
    } else if (strcmp(cmd, "disable") == 0) {
        return cmd_set_enabled(0);
    } else if (strcmp(cmd, "list") == 0) {
        return cmd_list();
    } else if (strcmp(cmd, "stats") == 0) {
        return cmd_stats();
    } else if (strcmp(cmd, "clear") == 0) {
        return cmd_clear();
    } else {
        fprintf(stderr, "Unknown command: %s\n\n", cmd);
        usage(argv[0]);
        return 1;
    }
}