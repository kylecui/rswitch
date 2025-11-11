// SPDX-License-Identifier: GPL-2.0
/*
 * rSwitch QoS (Quality of Service) Module
 * 
 * Architecture: Priority Classification + Congestion Control
 * 
 * Functions:
 * 1. Traffic Classification (5-tuple → priority)
 * 2. Priority queue mapping (priority → egress queue)
 * 3. Congestion detection (queue depth monitoring)
 * 4. Rate limiting (token bucket per-priority)
 * 5. DSCP marking (IP ToS field modification)
 * 
 * Priority Levels:
 * - 0: Best effort (default)
 * - 1: Low (background)
 * - 2: High (interactive)
 * - 3: Critical (real-time, management)
 * 
 * Congestion Actions:
 * - ECN marking (if supported)
 * - Selective drop (drop lower priority first)
 * - Redirect to VOQd for sophisticated scheduling
 * 
 * Performance:
 * - O(1) priority lookup via hash table
 * - O(1) rate limiting via token bucket
 * - Minimal per-packet overhead (~20ns)
 */

#include "../include/rswitch_common.h"
#include "../core/module_abi.h"
#include "../core/afxdp_common.h"

char _license[] SEC("license") = "GPL";

// Module metadata
RS_DECLARE_MODULE(
    "qos",                          // Module name
    RS_HOOK_XDP_EGRESS,            // Hook point: egress processing
    170,                           // Stage (before egress_final at 190)
    RS_FLAG_NEED_L2L3_PARSE | RS_FLAG_MODIFIES_PACKET | RS_FLAG_CREATES_EVENTS,
    "QoS - Priority classification and congestion control"
);

//
// Priority Classification
// Note: Priority level constants now defined in afxdp_common.h
//

#define QOS_DEFAULT_PRIO    QOS_PRIO_NORMAL

/* Priority classification key */
struct qos_class_key {
    __u8  proto;           // IPPROTO_TCP, IPPROTO_UDP, etc.
    __u8  dscp;            // DSCP field from IP header (6 bits)
    __u16 dport;           // Destination port (network byte order)
} __attribute__((packed));

/* Priority classification result */
struct qos_class_result {
    __u8  priority;        // 0-3 priority level
    __u8  drop_precedence; // Drop precedence within priority (0-2)
    __u8  rate_limit_id;   // Rate limiter ID (0=no limit)
    __u8  flags;           // QoS flags
    __u32 rate_limit_bps;  // Rate limit in bytes/sec (0=unlimited)
} __attribute__((packed));

/* QoS classification table
 * Maps {proto, dscp, dport} → priority
 * Examples:
 *   {TCP, 0, 22} → priority=3 (SSH)
 *   {UDP, 0, 53} → priority=3 (DNS)
 *   {TCP, 0, 80} → priority=2 (HTTP)
 *   {TCP, 0, 443} → priority=2 (HTTPS)
 *   {TCP, 0, 20/21} → priority=0 (FTP data)
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct qos_class_key);
    __type(value, struct qos_class_result);
    __uint(max_entries, 4096);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} qos_class_map SEC(".maps");

//
// Per-Priority Rate Limiting (Token Bucket)
//

struct qos_rate_limiter {
    __u32 rate_bps;            // Rate in bytes per second
    __u32 burst_bytes;         // Burst allowance
    __u64 tokens;              // Current token count (in bytes)
    __u64 last_update_ns;      // Last token refill timestamp
    __u64 total_bytes;         // Total bytes processed
    __u64 dropped_bytes;       // Total bytes dropped
    __u32 dropped_packets;     // Total packets dropped
    __u32 pad;
} __attribute__((aligned(8)));

/* Per-priority rate limiters
 * Key: priority level (0-3)
 * Value: token bucket state
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct qos_rate_limiter);
    __uint(max_entries, QOS_MAX_PRIORITIES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} qos_rate_limiters SEC(".maps");

//
// Congestion Detection
//
// Note: Congestion tracking moved to shared qdepth_map (from afxdp_common.h)
// This allows coordination between QoS module and AF_XDP VOQd scheduler

//
// QoS Configuration
//

/* QoS Configuration Flags - Local to this module
 * Note: struct qos_config itself is defined in afxdp_common.h
 */
#define QOS_FLAG_ENABLED            (1 << 0)
#define QOS_FLAG_RATE_LIMIT_ENABLED (1 << 1)
#define QOS_FLAG_ECN_ENABLED        (1 << 2)
#define QOS_FLAG_DSCP_REWRITE       (1 << 3)

/* Extended QoS config for local use */
struct qos_config_ext {
    __u32 flags;               // Configuration flags
    __u8  default_priority;    // Default priority for unclassified traffic
    __u8  pad[3];
    
    /* DSCP remarking table: priority → DSCP value */
    __u8  dscp_map[QOS_MAX_PRIORITIES];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct qos_config_ext);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} qos_config_ext_map SEC(".maps");

/* QoS configuration map - shared with afxdp_redirect module
 * Stores DSCP→priority mapping and thresholds
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct qos_config);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} qos_config_map SEC(".maps");

/* Queue depth map - shared with afxdp_redirect for congestion detection */
extern struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct qdepth_key);
    __type(value, __u32);
} qdepth_map SEC(".maps");

//
// Statistics (per-CPU for performance)
//

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

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, QOS_STAT_MAX);
} qos_stats_map SEC(".maps");

//
// Helper Functions
//

static __always_inline void update_stat(__u32 stat_id)
{
    __u64 *counter = bpf_map_lookup_elem(&qos_stats_map, &stat_id);
    if (counter) {
        __sync_fetch_and_add(counter, 1);
    }
}

/* Extract DSCP from IP header */
static __always_inline __u8 get_dscp_from_iph(struct iphdr *iph)
{
    return (iph->tos >> 2) & 0x3F;  // Upper 6 bits of ToS field
}

/* Set DSCP in IP header and update checksum */
static __always_inline void set_dscp_in_iph(struct iphdr *iph, __u8 dscp)
{
    __u8 old_tos = iph->tos;
    __u8 new_tos = (dscp << 2) | (old_tos & 0x03);  // Preserve ECN bits
    
    if (old_tos != new_tos) {
        /* Incremental checksum update for ToS field change */
        __u32 sum = ~bpf_ntohs(iph->check) & 0xffff;
        sum += (~(__u32)old_tos) & 0xff;
        sum += (__u32)new_tos & 0xff;
        sum = (sum & 0xffff) + (sum >> 16);
        sum = (sum & 0xffff) + (sum >> 16);
        iph->check = bpf_htons(~sum & 0xffff);
        
        iph->tos = new_tos;
        
        rs_debug("QoS: DSCP rewrite %u → %u", old_tos >> 2, dscp);
    }
}

/* Mark ECN in IP header (Congestion Experienced) */
static __always_inline void mark_ecn_ce(struct iphdr *iph)
{
    __u8 old_tos = iph->tos;
    __u8 ecn = old_tos & 0x03;
    
    /* Only mark if ECN-capable (ECT) */
    if (ecn == 0x01 || ecn == 0x02) {  // ECT(0) or ECT(1)
        __u8 new_tos = (old_tos & 0xFC) | 0x03;  // Set CE (Congestion Experienced)
        
        /* Update checksum */
        __u32 sum = ~bpf_ntohs(iph->check) & 0xffff;
        sum += (~(__u32)old_tos) & 0xff;
        sum += (__u32)new_tos & 0xff;
        sum = (sum & 0xffff) + (sum >> 16);
        sum = (sum & 0xffff) + (sum >> 16);
        iph->check = bpf_htons(~sum & 0xffff);
        
        iph->tos = new_tos;
        
        rs_debug("QoS: ECN marked (CE)");
        update_stat(QOS_STAT_ECN_MARKED);
    }
}

/* Token bucket rate limiting */
static __always_inline int check_rate_limit(__u32 priority, __u32 packet_len)
{
    struct qos_rate_limiter *limiter = bpf_map_lookup_elem(&qos_rate_limiters, &priority);
    if (!limiter || limiter->rate_bps == 0)
        return 0;  // No rate limit
    
    __u64 now_ns = bpf_ktime_get_ns();
    __u64 elapsed_ns = now_ns - limiter->last_update_ns;
    
    /* Refill tokens based on elapsed time */
    if (elapsed_ns > 0) {
        __u64 new_tokens = (elapsed_ns * limiter->rate_bps) / 1000000000ULL;  // ns→sec conversion
        __u64 max_tokens = limiter->tokens + new_tokens;
        if (max_tokens > (__u64)limiter->burst_bytes) {
            limiter->tokens = (__u64)limiter->burst_bytes;
        } else {
            limiter->tokens = max_tokens;
        }
        limiter->last_update_ns = now_ns;
    }
    
    /* Check if packet fits in bucket */
    if (limiter->tokens >= packet_len) {
        limiter->tokens -= packet_len;
        limiter->total_bytes += packet_len;
        return 0;  // Allow
    } else {
        limiter->dropped_bytes += packet_len;
        limiter->dropped_packets++;
        return 1;  // Drop
    }
}

/* Classify packet priority */
static __always_inline __u8 classify_packet_priority(struct xdp_md *xdp_ctx, struct rs_ctx *ctx)
{
    /* Try classification map lookup first */
    struct qos_class_key key = {
        .proto = ctx->layers.ip_proto,
        .dscp = 0,  // Will be filled from IP header
        .dport = ctx->layers.dport,
    };
    
    /* Extract DSCP if available */
    if (ctx->layers.l3_offset != 0) {
        void *data = (void *)(long)xdp_ctx->data;
        void *data_end = (void *)(long)xdp_ctx->data_end;
        struct iphdr *iph = data + (ctx->layers.l3_offset & RS_L3_OFFSET_MASK);
        
        if ((void *)(iph + 1) <= data_end) {
            key.dscp = get_dscp_from_iph(iph);
        }
    }
    
    struct qos_class_result *result = bpf_map_lookup_elem(&qos_class_map, &key);
    if (result) {
        rs_debug("QoS: Classified proto=%u dport=%u dscp=%u → priority=%u", 
                 key.proto, bpf_ntohs(key.dport), key.dscp, result->priority);
        update_stat(QOS_STAT_CLASSIFIED_PACKETS);
        return result->priority;
    }
    
    /* Default classification based on well-known ports */
    __u16 port = bpf_ntohs(ctx->layers.dport);
    
    if (ctx->layers.ip_proto == IPPROTO_TCP) {
        switch (port) {
        case 22:    // SSH
        case 23:    // Telnet
        case 161:   // SNMP
        case 162:   // SNMP trap
            return QOS_PRIO_CRITICAL;
        case 80:    // HTTP
        case 443:   // HTTPS
        case 8080:  // HTTP-alt
            return QOS_PRIO_HIGH;
        case 20:    // FTP-data
        case 21:    // FTP
        case 25:    // SMTP
            return QOS_PRIO_LOW;
        default:
            return QOS_PRIO_NORMAL;
        }
    } else if (ctx->layers.ip_proto == IPPROTO_UDP) {
        switch (port) {
        case 53:    // DNS
        case 123:   // NTP
        case 161:   // SNMP
        case 162:   // SNMP trap
            return QOS_PRIO_CRITICAL;
        case 67:    // DHCP server
        case 68:    // DHCP client
            return QOS_PRIO_HIGH;
        default:
            return QOS_PRIO_NORMAL;
        }
    } else if (ctx->layers.ip_proto == IPPROTO_ICMP) {
        return QOS_PRIO_HIGH;  // ICMP is important for network diagnostics
    }
    
    update_stat(QOS_STAT_UNCLASSIFIED_PACKETS);
    return QOS_PRIO_NORMAL;
}

//
// Main QoS Processing
//

SEC("xdp")
int qos_process(struct xdp_md *xdp_ctx)
{
    struct rs_ctx *ctx = RS_GET_CTX();
    if (!ctx) {
        return XDP_DROP;
    }
    
    /* Get shared QoS configuration (for DSCP mapping) */
    __u32 cfg_key = 0;
    struct qos_config *qos_cfg = bpf_map_lookup_elem(&qos_config_map, &cfg_key);
    
    /* Get extended local configuration (for flags and DSCP remarking) */
    struct qos_config_ext *cfg = bpf_map_lookup_elem(&qos_config_ext_map, &cfg_key);
    if (!cfg || !(cfg->flags & QOS_FLAG_ENABLED)) {
        rs_debug("QoS: disabled, passing through");
        RS_TAIL_CALL_EGRESS(xdp_ctx, ctx, 170);  // Continue to next egress module
        return XDP_DROP;
    }
    
    /* Only process IPv4 for now */
    if (ctx->layers.eth_proto != ETH_P_IP) {
        RS_TAIL_CALL_EGRESS(xdp_ctx, ctx, 170);
        return XDP_DROP;
    }
    
    void *data = (void *)(long)xdp_ctx->data;
    void *data_end = (void *)(long)xdp_ctx->data_end;
    
    /* Get IP header for DSCP manipulation */
    struct iphdr *iph = data + (ctx->layers.l3_offset & RS_L3_OFFSET_MASK);
    if ((void *)(iph + 1) > data_end) {
        RS_TAIL_CALL_EGRESS(xdp_ctx, ctx, 170);
        return XDP_DROP;
    }
    
    /* Classify packet priority */
    __u8 priority = classify_packet_priority(xdp_ctx, ctx);
    
    /* Update priority statistics */
    if (priority < QOS_MAX_PRIORITIES) {
        update_stat(QOS_STAT_PRIORITY_0 + priority);
    }
    
    rs_debug("QoS: proto=%u dport=%u → priority=%u", 
             ctx->layers.ip_proto, bpf_ntohs(ctx->layers.dport), priority);
    
    /* Store priority in context for downstream modules
     * This is critical for afxdp_redirect module to intercept high-priority flows
     */
    ctx->prio = priority;
    
    /* Rate limiting check */
    if (cfg->flags & QOS_FLAG_RATE_LIMIT_ENABLED) {
        __u32 packet_len = data_end - data;
        if (check_rate_limit(priority, packet_len)) {
            rs_debug("QoS: Rate limited priority=%u len=%u", priority, packet_len);
            update_stat(QOS_STAT_RATE_LIMITED_PACKETS);
            ctx->drop_reason = RS_DROP_RATE_LIMIT;
            return XDP_DROP;
        }
    }
    
    /* Congestion detection and ECN marking
     * Uses shared qdepth_map for coordination with afxdp_redirect module
     */
    if (cfg->flags & QOS_FLAG_ECN_ENABLED) {
        __u32 egress_ifindex = ctx->egress_ifindex;
        if (egress_ifindex != 0 && priority < QOS_MAX_PRIORITIES && qos_cfg) {
            /* Build queue depth key */
            struct qdepth_key qkey = {
                .port = (__u16)egress_ifindex,
                .prio = (__u8)priority,
                ._pad = 0,
            };
            
            __u32 *qdepth = bpf_map_lookup_elem(&qdepth_map, &qkey);
            if (qdepth && *qdepth > 0) {
                /* Congestion detected based on queue depth */
                __u32 threshold = qos_cfg->ecn_threshold;
                
                if (*qdepth >= threshold) {
                    /* Congestion detected - mark ECN if possible, otherwise drop low priority */
                    if (priority >= QOS_PRIO_HIGH) {
                        mark_ecn_ce(iph);  // Mark high-priority traffic with ECN
                        update_stat(QOS_STAT_ECN_MARKED);
                        rs_debug("QoS: ECN marked priority=%u qdepth=%u", priority, *qdepth);
                    } else {
                        /* Drop low-priority traffic during congestion */
                        rs_debug("QoS: Congestion drop priority=%u qdepth=%u", priority, *qdepth);
                        update_stat(QOS_STAT_CONGESTION_DROPS);
                        ctx->drop_reason = RS_DROP_CONGESTION;
                        return XDP_DROP;
                    }
                }
                
                /* Increment queue depth for this packet */
                __sync_fetch_and_add(qdepth, 1);
            }
        }
    }
    
    /* DSCP remarking */
    if (cfg->flags & QOS_FLAG_DSCP_REWRITE) {
        if (priority < QOS_MAX_PRIORITIES) {
            __u8 new_dscp = cfg->dscp_map[priority];
            if (new_dscp != 0) {
                set_dscp_in_iph(iph, new_dscp);
                update_stat(QOS_STAT_DSCP_REMARKED);
            }
        }
    }
    
    rs_debug("QoS: processed priority=%u egress=%u", priority, ctx->egress_ifindex);
    
    /* Continue to next egress module */
    RS_TAIL_CALL_EGRESS(xdp_ctx, ctx, 170);
    return XDP_DROP;
}