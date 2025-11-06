// SPDX-License-Identifier: GPL-2.0
/* 
 * rSwitch ACL (Access Control List) Module
 * 
 * Implements stateless packet filtering based on L3/L4 criteria:
 * - Source/Destination IP addresses (IPv4/IPv6)
 * - Source/Destination ports (TCP/UDP)
 * - Protocol type
 * - VLAN ID
 * 
 * Actions:
 * - PASS: Allow packet to continue
 * - DROP: Drop packet
 * - RATE_LIMIT: Apply rate limiting (basic token bucket)
 * 
 * Features:
 * - Rule priority (lower value = higher priority)
 * - Per-rule statistics (matches, bytes)
 * - Default policy (allow/deny)
 */

#include "../include/rswitch_common.h"
#include "../core/module_abi.h"

char _license[] SEC("license") = "GPL";

// Module metadata
RS_DECLARE_MODULE(
    "acl",                           // Module name
    RS_HOOK_XDP_INGRESS,            // Hook point
    30,                              // Stage (after VLAN, before routing)
    RS_FLAG_NEED_FLOW_INFO | RS_FLAG_MAY_DROP | RS_FLAG_CREATES_EVENTS,
    "Access Control List (ACL) - L3/L4 packet filtering"
);

//
// Data Structures
//

// ACL rule actions
enum acl_action {
    ACL_ACTION_PASS = 0,
    ACL_ACTION_DROP = 1,
    ACL_ACTION_RATE_LIMIT = 2,
};

// ACL rule definition
struct acl_rule {
    // Match criteria
    __u32 src_ip;           // Source IP (IPv4, network byte order)
    __u32 src_ip_mask;      // Source IP mask
    __u32 dst_ip;           // Destination IP
    __u32 dst_ip_mask;      // Destination IP mask
    
    __u16 src_port_min;     // Source port range minimum
    __u16 src_port_max;     // Source port range maximum
    __u16 dst_port_min;     // Destination port range minimum
    __u16 dst_port_max;     // Destination port range maximum
    
    __u8 protocol;          // IP protocol (0 = any)
    __u8 action;            // Action to take (enum acl_action)
    __u16 priority;         // Rule priority (lower = higher priority)
    
    __u16 vlan_id;          // VLAN ID filter (0 = any)
    __u8 ingress_port;      // Ingress port filter (0 = any)
    __u8 _pad;
    
    // Rate limiting (for RATE_LIMIT action)
    __u32 rate_limit_bps;   // Bits per second
    __u32 burst_size;       // Burst size in bytes
    
    // Statistics
    __u64 match_count;      // Number of matches
    __u64 match_bytes;      // Bytes matched
    __u64 last_match_ts;    // Last match timestamp (nanoseconds)
} __attribute__((aligned(8)));

// Rule key (priority-based lookup)
struct acl_rule_key {
    __u32 rule_id;          // Unique rule ID
};

// Rate limiting state (per-rule)
struct acl_rate_limit_state {
    __u64 tokens;           // Current token count (in bytes)
    __u64 last_update;      // Last token update timestamp (ns)
};

// ACL configuration
struct acl_config {
    __u8 default_action;    // Default action if no rule matches
    __u8 enabled;           // ACL enabled/disabled
    __u16 rule_count;       // Number of active rules
    __u64 total_matches;    // Total matches across all rules
    __u64 total_drops;      // Total drops
};

//
// BPF Maps
//

// ACL rules table (hash map for flexible rule management)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);              // Up to 1024 rules
    __type(key, struct acl_rule_key);
    __type(value, struct acl_rule);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} acl_rules SEC(".maps");

// Rule IDs sorted by priority (array for ordered iteration)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1024);
    __type(key, __u32);                     // Index
    __type(value, __u32);                   // Rule ID
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} acl_rule_order SEC(".maps");

// Rate limiting state per rule
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct acl_rule_key);
    __type(value, struct acl_rate_limit_state);
} acl_rate_limit_state SEC(".maps");

// Global ACL configuration
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct acl_config);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} acl_config_map SEC(".maps");

// Per-CPU statistics
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rs_stats);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} acl_stats SEC(".maps");

//
// Helper Functions
//

// Check if IP matches rule (considering mask)
static __always_inline int match_ip(__u32 packet_ip, __u32 rule_ip, __u32 mask)
{
    if (mask == 0)
        return 1;  // Match any
    
    return (packet_ip & mask) == (rule_ip & mask);
}

// Check if port is in range
static __always_inline int match_port(__u16 packet_port, __u16 min, __u16 max)
{
    if (min == 0 && max == 0)
        return 1;  // Match any
    
    if (max == 0)
        max = 65535;  // If only min specified, match min to max
    
    return (packet_port >= min && packet_port <= max);
}

// Check if protocol matches
static __always_inline int match_protocol(__u8 packet_proto, __u8 rule_proto)
{
    if (rule_proto == 0)
        return 1;  // Match any
    
    return packet_proto == rule_proto;
}

// Check if packet matches ACL rule
static __always_inline int match_rule(struct acl_rule *rule,
                                      __u32 src_ip, __u32 dst_ip,
                                      __u16 src_port, __u16 dst_port,
                                      __u8 protocol, __u16 vlan_id,
                                      __u8 ingress_port)
{
    // Check IP addresses
    if (!match_ip(src_ip, rule->src_ip, rule->src_ip_mask))
        return 0;
    
    if (!match_ip(dst_ip, rule->dst_ip, rule->dst_ip_mask))
        return 0;
    
    // Check ports
    if (!match_port(src_port, rule->src_port_min, rule->src_port_max))
        return 0;
    
    if (!match_port(dst_port, rule->dst_port_min, rule->dst_port_max))
        return 0;
    
    // Check protocol
    if (!match_protocol(protocol, rule->protocol))
        return 0;
    
    // Check VLAN
    if (rule->vlan_id != 0 && rule->vlan_id != vlan_id)
        return 0;
    
    // Check ingress port
    if (rule->ingress_port != 0 && rule->ingress_port != ingress_port)
        return 0;
    
    return 1;  // All criteria match
}

// Apply rate limiting (simple token bucket)
static __always_inline int apply_rate_limit(struct acl_rule_key *key,
                                            struct acl_rule *rule,
                                            __u32 packet_len)
{
    struct acl_rate_limit_state *state;
    __u64 now = bpf_ktime_get_ns();
    __u64 elapsed_ns, tokens_to_add;
    
    state = bpf_map_lookup_elem(&acl_rate_limit_state, key);
    if (!state) {
        // Initialize state on first packet
        struct acl_rate_limit_state init_state = {
            .tokens = rule->burst_size,
            .last_update = now,
        };
        bpf_map_update_elem(&acl_rate_limit_state, key, &init_state, BPF_ANY);
        state = bpf_map_lookup_elem(&acl_rate_limit_state, key);
        if (!state)
            return 1;  // Allow on error
    }
    
    // Calculate time elapsed since last update
    elapsed_ns = now - state->last_update;
    
    // Add tokens based on rate (tokens = bytes)
    // rate_limit_bps = bits per second
    // tokens_per_ns = (rate_limit_bps / 8) / 1000000000
    // tokens_to_add = tokens_per_ns * elapsed_ns
    tokens_to_add = (rule->rate_limit_bps * elapsed_ns) / (8ULL * 1000000000ULL);
    
    state->tokens += tokens_to_add;
    if (state->tokens > rule->burst_size)
        state->tokens = rule->burst_size;  // Cap at burst size
    
    state->last_update = now;
    
    // Check if we have enough tokens
    if (state->tokens >= packet_len) {
        state->tokens -= packet_len;
        return 1;  // Allow
    }
    
    return 0;  // Drop (rate limit exceeded)
}

// Update rule statistics
static __always_inline void update_rule_stats(struct acl_rule *rule, __u32 packet_len)
{
    __u64 now = bpf_ktime_get_ns();
    
    __sync_fetch_and_add(&rule->match_count, 1);
    __sync_fetch_and_add(&rule->match_bytes, packet_len);
    rule->last_match_ts = now;
}

// Update global statistics
static __always_inline void update_global_stats(__u32 action, __u32 packet_len)
{
    __u32 key = 0;
    struct rs_stats *stats;
    
    stats = bpf_map_lookup_elem(&acl_stats, &key);
    if (!stats)
        return;
    
    __sync_fetch_and_add(&stats->rx_packets, 1);
    __sync_fetch_and_add(&stats->rx_bytes, packet_len);
    
    if (action == ACL_ACTION_DROP)
        __sync_fetch_and_add(&stats->rx_drops, 1);
}

//
// Main ACL Processing
//

SEC("xdp")
int acl_ingress(struct xdp_md *xdp_ctx)
{
    void *data_end = (void *)(long)xdp_ctx->data_end;
    void *data = (void *)(long)xdp_ctx->data;
    __u32 packet_len = data_end - data;
    
    // Get per-CPU context (already parsed by dispatcher)
    struct rs_ctx *ctx = RS_GET_CTX();
    if (!ctx || !ctx->parsed) {
        rs_debug("ACL: No parsed context, skipping");
        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_PASS;
    }
    
    // Get global config
    __u32 cfg_key = 0;
    struct acl_config *config = bpf_map_lookup_elem(&acl_config_map, &cfg_key);
    if (!config || !config->enabled) {
        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_PASS;  // ACL disabled
    }
    
    // Only process IPv4 for now (IPv6 support can be added later)
    if (ctx->layers.eth_proto != 0x0800) {
        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_PASS;
    }
    
    // Extract parsed packet fields from context
    __u32 src_ip = ctx->layers.saddr;
    __u32 dst_ip = ctx->layers.daddr;
    __u8 protocol = ctx->layers.ip_proto;
    __u16 src_port = bpf_ntohs(ctx->layers.sport);
    __u16 dst_port = bpf_ntohs(ctx->layers.dport);
    __u16 vlan_id = ctx->ingress_vlan;
    __u8 ingress_port = (__u8)(ctx->ifindex & 0xFF);
    
    // Iterate through rules in priority order
    int matched = 0;
    __u8 action = config->default_action;
    
    #pragma unroll
    for (__u32 i = 0; i < 64; i++) {  // Limit to 64 rules for verifier
        if (i >= config->rule_count)
            break;
        
        // Get rule ID from ordered list
        __u32 *rule_id_ptr = bpf_map_lookup_elem(&acl_rule_order, &i);
        if (!rule_id_ptr)
            continue;
        
        // Get rule
        struct acl_rule_key rule_key = { .rule_id = *rule_id_ptr };
        struct acl_rule *rule = bpf_map_lookup_elem(&acl_rules, &rule_key);
        if (!rule)
            continue;
        
        // Check if packet matches rule
        if (match_rule(rule, src_ip, dst_ip, src_port, dst_port,
                      protocol, vlan_id, ingress_port)) {
            // Rule matched!
            matched = 1;
            action = rule->action;
            
            // Update statistics
            update_rule_stats(rule, packet_len);
            
            // Apply action-specific logic
            if (action == ACL_ACTION_RATE_LIMIT) {
                // Check rate limit
                if (!apply_rate_limit(&rule_key, rule, packet_len)) {
                    action = ACL_ACTION_DROP;  // Rate limit exceeded
                }
            }
            
            rs_debug("ACL match: rule_id=%u, action=%u, src=%pI4, dst=%pI4, proto=%u",
                    rule_key.rule_id, action, &src_ip, &dst_ip, protocol);
            
            break;  // Stop at first matching rule (highest priority)
        }
    }
    
    // Update global statistics
    update_global_stats(action, packet_len);
    
    if (action == ACL_ACTION_DROP) {
        rs_debug("ACL DROP: src=%pI4, dst=%pI4, proto=%u", &src_ip, &dst_ip, protocol);
        ctx->drop_reason = RS_DROP_ACL_BLOCK;
        return XDP_DROP;
    }
    
    // Continue to next module
    RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
    return XDP_PASS;
}
