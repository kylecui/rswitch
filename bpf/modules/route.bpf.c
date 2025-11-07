// SPDX-License-Identifier: GPL-2.0
/*
 * rSwitch Route Module - IPv4 LPM Routing
 * 
 * Layer 3 routing with longest prefix match (LPM):
 * - IPv4 routing table using BPF_MAP_TYPE_LPM_TRIE
 * - ARP table for next-hop MAC resolution
 * - TTL decrement and validation
 * - L3 header rewrite (src/dst MAC, TTL, checksum)
 * 
 * Pipeline position: Stage 50 (after ACL, before L2Learn)
 * 
 * Forwarding logic:
 * 1. Check if packet destined to router MAC
 * 2. Validate IPv4 and check TTL > 1
 * 3. Decrement TTL and update checksum
 * 4. LPM route lookup (longest prefix match)
 * 5. ARP lookup for next-hop MAC
 * 6. Rewrite L2 headers (src/dst MAC)
 * 7. Set egress_ifindex
 * 
 * Limitations (v1.0):
 * - IPv4 only
 * - Static routes only
 * - Simplified ARP (no requests)
 * - No ICMP Redirect
 */

#include "../include/rswitch_common.h"

char _license[] SEC("license") = "GPL";

/* Module metadata */
RS_DECLARE_MODULE("route", RS_HOOK_XDP_INGRESS, 50,
                  RS_FLAG_NEED_L2L3_PARSE | RS_FLAG_MODIFIES_PACKET,
                  "IPv4 LPM routing");

//
// Constants
//

#define ROUTE_MAX_ENTRIES   10000
#define ARP_MAX_ENTRIES     4096
#define MAX_IFACES          256

//
// Data Structures
//

/* LPM key - prefixlen MUST be first! */
struct lpm_key {
    __u32 prefixlen;
    __be32 addr;
};

/* Route entry */
struct route_entry {
    __be32 nexthop;   // 0.0.0.0 = direct
    __u32  ifindex;
    __u32  metric;
    __u8   type;      // 0=direct, 1=static
    __u8   pad[3];
};

/* ARP entry */
struct arp_entry {
    __u8  mac[6];
    __u16 pad;
    __u32 ifindex;
    __u64 timestamp;
};

/* Per-interface config */
struct iface_config {
    __u8  mac[6];
    __u16 pad;
    __u8  is_router;
    __u8  pad2[3];
};

/* Global config */
struct route_config {
    __u8 enabled;
    __u8 pad[3];
};

//
// Statistics
//

enum route_stat_type {
    ROUTE_STAT_LOOKUP = 0,
    ROUTE_STAT_HIT = 1,
    ROUTE_STAT_MISS = 2,
    ROUTE_STAT_ARP_HIT = 3,
    ROUTE_STAT_ARP_MISS = 4,
    ROUTE_STAT_TTL_EXCEEDED = 5,
    ROUTE_STAT_DIRECT = 6,
    ROUTE_STAT_STATIC = 7,
    ROUTE_STAT_MAX = 8,
};

//
// BPF Maps
//

/* IPv4 routing table (LPM trie) */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, ROUTE_MAX_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_key);
    __type(value, struct route_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} route_tbl SEC(".maps");

/* ARP table */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, ARP_MAX_ENTRIES);
    __type(key, __be32);
    __type(value, struct arp_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} arp_tbl SEC(".maps");

/* Interface config */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_IFACES);
    __type(key, __u32);
    __type(value, struct iface_config);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} iface_cfg SEC(".maps");

/* Statistics */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, ROUTE_STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} route_stats SEC(".maps");

/* Configuration */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct route_config);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} route_cfg SEC(".maps");

//
// Helper Functions
//

static __always_inline void update_stat(enum route_stat_type stat)
{
    __u32 key = stat;
    __u64 *val = bpf_map_lookup_elem(&route_stats, &key);
    if (val)
        __sync_fetch_and_add(val, 1);
}

/* Check if packet is for router */
static __always_inline int is_for_router(void *data, void *data_end,
                                         struct rs_ctx *rs_ctx)
{
    __u32 ifkey = rs_ctx->ifindex;
    struct iface_config *cfg = bpf_map_lookup_elem(&iface_cfg, &ifkey);
    if (!cfg || !cfg->is_router)
        return 0;
    
    struct ethhdr *eth = data + rs_ctx->layers.l2_offset;
    
    // Bounds check: eth + sizeof(*eth) must not exceed data_end
    // This check allows verifier to track eth as valid pointer with range
    if ((void *)(eth + 1) > data_end)
        return 0;
    
    // Direct MAC comparison using memcmp (verifier-friendly)
    if (__builtin_memcmp(eth->h_dest, cfg->mac, 6) != 0)
        return 0;
    
    return 1;
}

/* RFC 1624 incremental checksum update */
static __always_inline void update_ipv4_checksum(struct iphdr *iph, __u8 old_ttl)
{
    __u32 sum = ~bpf_ntohs(iph->check) & 0xffff;
    sum += (~old_ttl & 0xff) << 8;
    sum += (iph->ttl & 0xff) << 8;
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    iph->check = bpf_htons(~sum & 0xffff);
}

//
// Main Module Logic
//

SEC("xdp")
int route_ipv4(struct xdp_md *xdp_ctx)
{
    void *data = (void *)(long)xdp_ctx->data;
    void *data_end = (void *)(long)xdp_ctx->data_end;
    
    // Get context
    struct rs_ctx *ctx = RS_GET_CTX();
    if (!ctx)
        return XDP_PASS;
    
    // Check if enabled
    __u32 cfg_key = 0;
    struct route_config *cfg = bpf_map_lookup_elem(&route_cfg, &cfg_key);
    if (!cfg || !cfg->enabled) {
        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_PASS;
    }
    
    // Only route packets for router
    if (!is_for_router(data, data_end, ctx)) {
        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_PASS;
    }
    
    // Only IPv4
    if (ctx->layers.eth_proto != bpf_htons(ETH_P_IP)) {
        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_PASS;
    }
    
    // Get IP header
    struct iphdr *iph = data + ctx->layers.l3_offset;
    if ((void *)(iph + 1) > data_end) {
        ctx->error = RS_ERROR_PARSE_FAILED;
        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_PASS;
    }
    
    // TTL check
    if (iph->ttl <= 1) {
        update_stat(ROUTE_STAT_TTL_EXCEEDED);
        ctx->drop_reason = RS_DROP_TTL_EXCEEDED;
        return XDP_DROP;
    }
    
    // Decrement TTL
    __u8 old_ttl = iph->ttl;
    iph->ttl--;
    update_ipv4_checksum(iph, old_ttl);
    ctx->modified = 1;
    
    // LPM route lookup
    struct lpm_key route_key = {
        .prefixlen = 32,
        .addr = iph->daddr,
    };
    
    update_stat(ROUTE_STAT_LOOKUP);
    struct route_entry *route = bpf_map_lookup_elem(&route_tbl, &route_key);
    if (!route) {
        update_stat(ROUTE_STAT_MISS);
        ctx->error = RS_ERROR_NO_ROUTE;
        ctx->drop_reason = RS_DROP_NO_FWD_ENTRY;
        return XDP_DROP;
    }
    
    update_stat(ROUTE_STAT_HIT);
    if (route->type == 0)
        update_stat(ROUTE_STAT_DIRECT);
    else
        update_stat(ROUTE_STAT_STATIC);
    
    // Determine next-hop
    __be32 nexthop_ip = route->nexthop ? route->nexthop : iph->daddr;
    
    // ARP lookup
    struct arp_entry *arp = bpf_map_lookup_elem(&arp_tbl, &nexthop_ip);
    if (!arp) {
        update_stat(ROUTE_STAT_ARP_MISS);
        ctx->drop_reason = RS_DROP_NO_FWD_ENTRY;
        return XDP_DROP;
    }
    
    update_stat(ROUTE_STAT_ARP_HIT);
    
    // Get egress iface config
    __u32 eg_ifkey = route->ifindex;
    struct iface_config *egress_cfg = bpf_map_lookup_elem(&iface_cfg, &eg_ifkey);
    if (!egress_cfg) {
        return XDP_DROP;
    }
    
    // Rewrite L2 header
    struct ethhdr *eth = data + ctx->layers.l2_offset;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;
    
    __builtin_memcpy(eth->h_source, egress_cfg->mac, 6);
    __builtin_memcpy(eth->h_dest, arp->mac, 6);
    
    // Set forwarding decision
    ctx->egress_ifindex = route->ifindex;
    ctx->action = XDP_REDIRECT;
    
    // Next module
    RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
    return XDP_PASS;
}
