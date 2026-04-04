// SPDX-License-Identifier: GPL-2.0
/* 
 * rSwitch ACL (Access Control List) Module - Priority-based Multi-Map Design
 * 
 * Architecture: Two-Phase Priority Lookup
 * 
 * Phase 1: Check all 6 map types for matches:
 *   - 5-tuple exact match {proto, src_ip, dst_ip, sport, dport}
 *   - Proto + Dst IP + Dst Port {proto, dst_ip, dport}
 *   - Proto + Src IP + Dst Port {proto, src_ip, dport}
 *   - Proto + Dst Port {proto, dport}
 *   - Src IP prefix (LPM)
 *   - Dst IP prefix (LPM)
 * 
 * Phase 2: Select match with highest priority (0-7, where 7 is highest)
 * 
 * Priority Semantics:
 *   - User-defined priority (0-7) determines which rule wins
 *   - Higher priority rules ALWAYS win, regardless of map type
 *   - Same priority: more specific match wins (5-tuple > partial > LPM)
 * 
 * Example: permit 10.174.129.0/24 → 10.174.1.5 ICMP @ priority=7
 *          deny any → 10.174.1.5 ICMP @ priority=0
 *          → permit wins because priority 7 > priority 0
 * 
 * Performance:
 * - Fixed 6 lookups per packet (all maps checked)
 * - All O(1) or O(log N), NO linear iteration
 */

#include "../include/rswitch_common.h"

enum {
    RS_THIS_STAGE_ID  = 30,
    RS_THIS_MODULE_ID = RS_MOD_ACL,
};


char _license[] SEC("license") = "GPL";

// Module metadata
RS_DECLARE_MODULE(
    "acl",                           // Module name
    RS_HOOK_XDP_INGRESS,            // Hook point
    30,                              // Stage (after VLAN=10, before L2Learn=80)
    RS_FLAG_NEED_L2L3_PARSE | RS_FLAG_MAY_DROP | RS_FLAG_CREATES_EVENTS,
    "ACL - Multi-level indexed packet filtering (5-tuple + LPM)"
);

//
// ACL Actions
//

enum acl_action {
    ACL_ACTION_PASS = 0,
    ACL_ACTION_DROP = 1,
    ACL_ACTION_REDIRECT = 2,  // Redirect to another port or AF_XDP
};

/* ACL Action Result - stored in all ACL maps
 * priority field determines which match wins when multiple rules match
 */
struct acl_result {
    __u8 action;           // enum acl_action
    __u8 log_event;        // Whether to emit event to ringbuf
    __u16 redirect_ifindex; // Target ifindex (0 = AF_XDP via queue)
    __u32 stats_id;        // Statistics counter ID (rule ID for display)
    __u8  priority;        // User priority 0-7 (7 = highest)
    __u8  pad[3];
} __attribute__((packed));

//
// Level 1: Exact 5-Tuple Match (HASH)
//

struct acl_5tuple_key {
    __u8  proto;           // IPPROTO_TCP, IPPROTO_UDP, etc.
    __u8  pad[3];
    __u32 src_ip;          // Network byte order
    __u32 dst_ip;
    __u16 sport;           // Network byte order
    __u16 dport;
} __attribute__((packed));

/* 5-tuple ACL table
 * Exact match for specific flows
 * Example: Block SSH from 10.1.2.3:* to 192.168.1.100:22
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct acl_5tuple_key);
    __type(value, struct acl_result);
    __uint(max_entries, 65536);  // Reasonable for exact flows
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} acl_5tuple_map SEC(".maps");

//
// Level 2: Proto + Dst IP + Dst Port (HASH)
//

struct acl_proto_dstip_port_key {
    __u8  proto;           // Protocol
    __u8  pad[3];
    __u32 dst_ip;          // Destination IP
    __u16 dst_port;        // Destination port
    __u16 pad2;
} __attribute__((packed));

/* Proto + Dst IP + Dst Port table
 * Match any source to specific destination
 * Example: Block HTTPS to malicious site (* → 203.0.113.5:443/TCP)
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct acl_proto_dstip_port_key);
    __type(value, struct acl_result);
    __uint(max_entries, 65536);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} acl_pdp_map SEC(".maps");

//
// Level 3: Proto + Src IP + Dst Port (HASH)
//

struct acl_proto_srcip_port_key {
    __u8  proto;           // Protocol
    __u8  pad[3];
    __u32 src_ip;          // Source IP
    __u16 dst_port;        // Destination port
    __u16 pad2;
} __attribute__((packed));

/* Proto + Src IP + Dst Port table
 * Match specific source to any destination on specific port
 * Example: Block SSH from attacker (10.1.2.3:* → *:22/TCP)
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct acl_proto_srcip_port_key);
    __type(value, struct acl_result);
    __uint(max_entries, 65536);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} acl_psp_map SEC(".maps");

//
// Level 4: Proto + Dst Port (HASH)
//

struct acl_proto_port_key {
    __u8  proto;           // Protocol
    __u8  pad;
    __u16 dst_port;        // Destination port
} __attribute__((packed));

/* Proto + Dst Port table
 * Global port filtering regardless of IP
 * Example: Block QUIC globally (* → *:443/UDP)
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct acl_proto_port_key);
    __type(value, struct acl_result);
    __uint(max_entries, 4096);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} acl_pp_map SEC(".maps");

//
// Level 5/6: LPM Prefix Match (TRIE)
//

struct acl_lpm_key {
    __u32 prefixlen;       // In bits (e.g., 24 for /24)
    __u32 ip;              // Network byte order
};

/* Extended LPM value with priority and additional match criteria */
struct acl_lpm_value {
    __u8 action;           // enum acl_action
    __u8 log_event;        // Whether to emit event to ringbuf
    __u16 redirect_ifindex; // Target ifindex (0 = AF_XDP via queue)
    __u32 stats_id;        // Statistics counter ID (rule ID for display)
    __u8  priority;        // User priority 0-7 (7 = highest)
    __u8  proto;           // Protocol to match (0 = any)
    __u16 sport;           // Source port to match (0 = any, network byte order)
    __u16 dport;           // Dest port to match (0 = any, network byte order)
    __u16 pad;
    __u32 other_ip;        // For src LPM: dst_ip to match; for dst LPM: src_ip (0 = any)
} __attribute__((packed));

/* Source IP prefix match
 * Example: Block all traffic from 10.0.0.0/8
 * With extended value: Block 10.0.0.0/8 → 192.168.1.5:22 TCP
 */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct acl_lpm_key);
    __type(value, struct acl_lpm_value);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 16384);  // Reasonable for prefix rules
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} acl_lpm_src_map SEC(".maps");

/* Destination IP prefix match
 * Example: Allow all traffic to 192.168.0.0/16
 * With extended value: Allow 10.1.2.3 → 192.168.0.0/16:443 TCP
 */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct acl_lpm_key);
    __type(value, struct acl_lpm_value);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 16384);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} acl_lpm_dst_map SEC(".maps");

//
// Global Configuration
//

struct acl_config {
    __u8 default_action;   // ACL_ACTION_PASS or ACL_ACTION_DROP
    __u8 enabled;          // 0=disabled, 1=enabled
    __u8 log_drops;        // Log dropped packets to ringbuf
    __u8 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct acl_config);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} acl_config_map SEC(".maps");

//
// Statistics (per-CPU for lock-free updates)
//

enum acl_stat_type {
    ACL_STAT_L1_5TUPLE_HIT = 0,
    ACL_STAT_L2_PROTO_DSTIP_PORT_HIT = 1,
    ACL_STAT_L3_PROTO_SRCIP_PORT_HIT = 2,
    ACL_STAT_L4_PROTO_PORT_HIT = 3,
    ACL_STAT_L5_LPM_SRC_HIT = 4,
    ACL_STAT_L6_LPM_DST_HIT = 5,
    ACL_STAT_L7_DEFAULT_PASS = 6,
    ACL_STAT_L7_DEFAULT_DROP = 7,
    ACL_STAT_TOTAL_DROPS = 8,
    ACL_STAT_MAX = 9,
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, ACL_STAT_MAX);
} acl_stats_map SEC(".maps");

//
// Helper Functions
//

static __always_inline void update_stat(__u32 stat_id)
{
    __u64 *counter = bpf_map_lookup_elem(&acl_stats_map, &stat_id);
    if (counter) {
        __sync_fetch_and_add(counter, 1);
    }
}

static __always_inline int apply_acl_action(struct xdp_md *xdp_ctx, 
                                             struct rs_ctx *ctx,
                                             struct acl_result *result,
                                             __u32 stat_id,
                                             __u32 pkt_len)
{
    update_stat(stat_id);
    
    switch (result->action) {
    case ACL_ACTION_DROP:
        RS_RECORD_DROP(xdp_ctx, ctx, RS_DROP_ACL_BLOCK);
        update_stat(ACL_STAT_TOTAL_DROPS);

        {
            struct rs_obs_event evt = {0};
            rs_obs_build_event(xdp_ctx, ctx, &evt, RS_EVENT_OBS_DROP, RS_OBS_F_DROP,
                               RS_DROP_ACL_BLOCK, pkt_len);
            RS_EMIT_SAMPLED_EVENT(ctx, &evt, sizeof(evt));
        }
        
        /* Optional: Emit event for logging */
        if (result->log_event) {
            // TODO: Emit to rs_event_bus
            // struct acl_drop_event { ... };
            // RS_EMIT_EVENT(&evt, sizeof(evt));
        }
        
        rs_debug("ACL: DROP packet proto=%u %pI4:%u -> %pI4:%u",
                 ctx->layers.ip_proto,
                 &ctx->layers.saddr, bpf_ntohs(ctx->layers.sport),
                 &ctx->layers.daddr, bpf_ntohs(ctx->layers.dport));
        
        return XDP_DROP;
        
    case ACL_ACTION_REDIRECT:
        /* Redirect to another port or AF_XDP */
        if (result->redirect_ifindex == 0) {
            /* Redirect to AF_XDP - handled by afxdp_redirect module */
            ctx->mirror = 1;  // Mark for AF_XDP interception
        } else {
            /* Redirect to specific egress port */
            ctx->egress_ifindex = result->redirect_ifindex;
        }
        
        rs_debug("ACL: REDIRECT to ifindex=%u", result->redirect_ifindex);
        return -1;  // Continue pipeline (not XDP_DROP/PASS)
        
    case ACL_ACTION_PASS:
    default:
        rs_debug("ACL: PASS packet");
        return -1;  // Continue to next module
    }
}

//
// Main ACL Processing
//

SEC("xdp")
int acl_filter(struct xdp_md *xdp_ctx)
{
    struct rs_ctx *ctx = RS_GET_CTX();
    if (!ctx) {
        return XDP_DROP;
    }

    void *data_end = (void *)(long)xdp_ctx->data_end;
    void *data = (void *)(long)xdp_ctx->data;
    __u32 pkt_len = data_end - data;
    RS_OBS_STAGE_HIT(xdp_ctx, ctx, pkt_len);
    
    __u32 cfg_key = 0;
    struct acl_config *cfg = bpf_map_lookup_elem(&acl_config_map, &cfg_key);
    if (!cfg || !cfg->enabled) {
        rs_debug("ACL: disabled, passing through. target=%d", ctx->egress_ifindex);
        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_DROP;
    }
    
    if (ctx->layers.eth_proto != 0x0800) {
        rs_debug("ACL: non-IPv4 packet, skipping");
        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_DROP;
    }
    
    /* Two-phase priority lookup:
     * Phase 1: Check all maps, track best (highest priority) match
     * Phase 2: Apply the winning rule
     * Specificity order within same priority: 5tuple > pdp > psp > pp > lpm_src > lpm_dst
     */
    struct acl_result best_match = {0};
    __s8 best_priority = -1;
    __u32 best_stat_id = 0;
    struct acl_result *result;
    
    struct acl_5tuple_key key_5t = {
        .proto = ctx->layers.ip_proto,
        .src_ip = ctx->layers.saddr,
        .dst_ip = ctx->layers.daddr,
        .sport = ctx->layers.sport,
        .dport = ctx->layers.dport,
    };
    result = bpf_map_lookup_elem(&acl_5tuple_map, &key_5t);
    if (result && (__s8)result->priority > best_priority) {
        best_match = *result;
        best_priority = result->priority;
        best_stat_id = ACL_STAT_L1_5TUPLE_HIT;
    }
    
    struct acl_proto_dstip_port_key key_pdp = {
        .proto = ctx->layers.ip_proto,
        .dst_ip = ctx->layers.daddr,
        .dst_port = ctx->layers.dport,
    };
    result = bpf_map_lookup_elem(&acl_pdp_map, &key_pdp);
    if (result && (__s8)result->priority > best_priority) {
        best_match = *result;
        best_priority = result->priority;
        best_stat_id = ACL_STAT_L2_PROTO_DSTIP_PORT_HIT;
    }
    
    struct acl_proto_srcip_port_key key_psp = {
        .proto = ctx->layers.ip_proto,
        .src_ip = ctx->layers.saddr,
        .dst_port = ctx->layers.dport,
    };
    result = bpf_map_lookup_elem(&acl_psp_map, &key_psp);
    if (result && (__s8)result->priority > best_priority) {
        best_match = *result;
        best_priority = result->priority;
        best_stat_id = ACL_STAT_L3_PROTO_SRCIP_PORT_HIT;
    }
    
    struct acl_proto_port_key key_pp = {
        .proto = ctx->layers.ip_proto,
        .dst_port = ctx->layers.dport,
    };
    result = bpf_map_lookup_elem(&acl_pp_map, &key_pp);
    if (result && (__s8)result->priority > best_priority) {
        best_match = *result;
        best_priority = result->priority;
        best_stat_id = ACL_STAT_L4_PROTO_PORT_HIT;
    }
    
    struct acl_lpm_key lpm_key = {
        .prefixlen = 32,
        .ip = ctx->layers.saddr,
    };
    struct acl_lpm_value *lpm_val = bpf_map_lookup_elem(&acl_lpm_src_map, &lpm_key);
    if (lpm_val) {
        int match = 1;
        if (lpm_val->other_ip != 0 && lpm_val->other_ip != ctx->layers.daddr)
            match = 0;
        if (lpm_val->proto != 0 && lpm_val->proto != ctx->layers.ip_proto)
            match = 0;
        if (lpm_val->sport != 0 && lpm_val->sport != ctx->layers.sport)
            match = 0;
        if (lpm_val->dport != 0 && lpm_val->dport != ctx->layers.dport)
            match = 0;
        
        if (match && (__s8)lpm_val->priority > best_priority) {
            best_match.action = lpm_val->action;
            best_match.log_event = lpm_val->log_event;
            best_match.redirect_ifindex = lpm_val->redirect_ifindex;
            best_match.stats_id = lpm_val->stats_id;
            best_match.priority = lpm_val->priority;
            best_priority = lpm_val->priority;
            best_stat_id = ACL_STAT_L5_LPM_SRC_HIT;
        }
    }
    
    lpm_key.ip = ctx->layers.daddr;
    lpm_val = bpf_map_lookup_elem(&acl_lpm_dst_map, &lpm_key);
    if (lpm_val) {
        int match = 1;
        if (lpm_val->other_ip != 0 && lpm_val->other_ip != ctx->layers.saddr)
            match = 0;
        if (lpm_val->proto != 0 && lpm_val->proto != ctx->layers.ip_proto)
            match = 0;
        if (lpm_val->sport != 0 && lpm_val->sport != ctx->layers.sport)
            match = 0;
        if (lpm_val->dport != 0 && lpm_val->dport != ctx->layers.dport)
            match = 0;
        
        if (match && (__s8)lpm_val->priority > best_priority) {
            best_match.action = lpm_val->action;
            best_match.log_event = lpm_val->log_event;
            best_match.redirect_ifindex = lpm_val->redirect_ifindex;
            best_match.stats_id = lpm_val->stats_id;
            best_match.priority = lpm_val->priority;
            best_priority = lpm_val->priority;
            best_stat_id = ACL_STAT_L6_LPM_DST_HIT;
        }
    }
    
    if (best_priority >= 0) {
        rs_debug("ACL: matched priority=%d action=%d", best_priority, best_match.action);
        int ret = apply_acl_action(xdp_ctx, ctx, &best_match, best_stat_id, pkt_len);
        if (ret == XDP_DROP) {
            return XDP_DROP;
        }
        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_DROP;
    }
    
    if (cfg->default_action == ACL_ACTION_DROP) {
        rs_debug("ACL: default DROP");
        RS_RECORD_DROP(xdp_ctx, ctx, RS_DROP_ACL_BLOCK);
        update_stat(ACL_STAT_L7_DEFAULT_DROP);
        update_stat(ACL_STAT_TOTAL_DROPS);

        {
            struct rs_obs_event evt = {0};
            rs_obs_build_event(xdp_ctx, ctx, &evt, RS_EVENT_OBS_DROP, RS_OBS_F_DROP,
                               RS_DROP_ACL_BLOCK, pkt_len);
            RS_EMIT_SAMPLED_EVENT(ctx, &evt, sizeof(evt));
        }
        return XDP_DROP;
    }
    
    rs_debug("ACL: default PASS");
    update_stat(ACL_STAT_L7_DEFAULT_PASS);
    RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
    return XDP_DROP;
}
