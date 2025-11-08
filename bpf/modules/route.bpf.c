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
struct loop_ctx {
    const struct ethhdr *eth;
    int found;
};

/* 6 字节 MAC 比较：编译成直白的逐字节比较，verifier 友好 */
static __always_inline bool mac_equal6(const __u8 *a, const __u8 *b) {
#pragma clang loop unroll(full)
    for (int k = 0; k < 6; k++) {
        if (a[k] != b[k]) return false;
    }
    return true;
}

static int scan_cb(__u32 i, void *data)
{
    struct loop_ctx *lc = data;
    __u32 key = i;
    struct iface_config *cfg = bpf_map_lookup_elem(&iface_cfg, &key);
    if (cfg && cfg->is_router) {
        if (mac_equal6(lc->eth->h_dest, cfg->mac)) {
            lc->found = 1;
            return 1; /* 非 0 → 终止循环 */
        }
    }
    return 0; /* 继续循环 */
}

static __always_inline int is_for_router_fast(const struct ethhdr *eth)
{
    struct loop_ctx lc = { .eth = eth, .found = 0 };
    /* 第 4 个参数 flags=0；bpf_loop 返回迭代次数或负值错误 */
    bpf_loop(RS_MAX_INTERFACES, scan_cb, &lc, 0);
    return lc.found;
}

static __always_inline void update_stat(enum route_stat_type stat)
{
    __u32 key = stat;
    __u64 *val = bpf_map_lookup_elem(&route_stats, &key);
    if (val)
        __sync_fetch_and_add(val, 1);
}

/* Check if packet is for router (dest MAC matches any router interface) */
static __always_inline int is_for_router(void *data, void *data_end,
                                         struct rs_ctx *rs_ctx)
{
    // Bounds check first (l2_offset is always 0 in our system)
    if (data + sizeof(struct ethhdr) > data_end)
        return 0;
    
    struct ethhdr *eth = data;
    
    // Check if dest MAC matches any router interface
    // Use bounded loop (verifier-friendly, no unroll)
    // Typical switch has < 32 interfaces, this covers realistic deployments
    // #pragma unroll
    // for (__u32 ifkey = 0; ifkey < RS_MAX_INTERFACES; ifkey++) {
    //     struct iface_config *cfg = bpf_map_lookup_elem(&iface_cfg, &ifkey);
    //     if (!cfg || !cfg->is_router)
    //         continue;
        
    //     // Direct MAC comparison using memcmp (verifier-friendly)
    //     if (__builtin_memcmp(eth->h_dest, cfg->mac, 6) == 0)
    //         return 1;
    // }
    
    // return 0;
    return is_for_router_fast(eth);
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
    if (!ctx) {
        rs_debug("Route: No context, passing");
        return XDP_PASS;
    }
    
    rs_debug("Route: Entry on ifindex=%u, proto=0x%x", ctx->ifindex, ctx->layers.eth_proto);
    
    // Check if enabled
    __u32 cfg_key = 0;
    struct route_config *cfg = bpf_map_lookup_elem(&route_cfg, &cfg_key);
    if (!cfg || !cfg->enabled) {
        rs_debug("Route: Disabled, passing through");
        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_PASS;
    }
    
    // Only route packets for router
    if (!is_for_router(data, data_end, ctx)) {
        rs_debug("Route: Packet not for router (dest MAC mismatch), passing");
        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_PASS;
    }
    
    rs_debug("Route: Packet IS for router, processing");
    
    // Only IPv4 (eth_proto already in host byte order from dispatcher)
    if (ctx->layers.eth_proto != ETH_P_IP) {
        rs_debug("Route: Not IPv4 (proto=0x%x), passing", ctx->layers.eth_proto);
        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_PASS;
    }
    
    // Check if L3 layer has been parsed (PoC pattern)
    if (!ctx->layers.l3_offset) {
        rs_debug("Route: L3 not parsed (l3_offset=0), passing");
        ctx->error = RS_ERROR_PARSE_FAILED;
        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_PASS;
    }
    
    /* Get IP header with verifier-friendly offset masking
     * 
     * CRITICAL VERIFIER WORKAROUND:
     * - l3_offset is __u16 (0-65535), too large for verifier to prove safety
     * - Masking with RS_L3_OFFSET_MASK limits range to realistic L3 offset values
     * - Allows verifier to prove that pointer arithmetic stays within packet bounds
     * 
     * This pattern is required because BPF verifier cannot track dynamic offsets from maps
     * without explicit range constraints. See eBPF verifier documentation on pointer arithmetic.
     */
    struct iphdr *iph = data + (ctx->layers.l3_offset & RS_L3_OFFSET_MASK);
    
    // Bounds check: verify full IP header is accessible
    if ((void *)&iph[1] > data_end) {
        rs_debug("Route: IP header bounds check failed");
        ctx->error = RS_ERROR_PARSE_FAILED;
        ctx->drop_reason = RS_DROP_PARSE_ERROR;
        return XDP_DROP;
    }

    rs_debug("Route: IP pkt saddr=%pI4 daddr=%pI4 ttl=%u", &iph->saddr, &iph->daddr, iph->ttl);

    // TTL check
    if (iph->ttl <= 1) {
        rs_debug("Route: TTL exhausted, dropping");
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
        rs_debug("Route: No route found for %pI4, dropping", &iph->daddr);
        update_stat(ROUTE_STAT_MISS);
        ctx->error = RS_ERROR_NO_ROUTE;
        ctx->drop_reason = RS_DROP_NO_FWD_ENTRY;
        return XDP_DROP;
    }
    
    rs_debug("Route: Found route type=%u ifindex=%u nexthop=%pI4", 
             route->type, route->ifindex, &route->nexthop);
    update_stat(ROUTE_STAT_HIT);
    if (route->type == 0)
        update_stat(ROUTE_STAT_DIRECT);
    else
        update_stat(ROUTE_STAT_STATIC);
    
    // Determine next-hop
    __be32 nexthop_ip = route->nexthop ? route->nexthop : iph->daddr;
    
    // Get egress iface config first (needed for both ARP hit and miss cases)
    __u32 eg_ifkey = route->ifindex;
    struct iface_config *egress_cfg = bpf_map_lookup_elem(&iface_cfg, &eg_ifkey);
    if (!egress_cfg) {
        rs_debug("Route: No egress iface config for ifindex=%u", eg_ifkey);
        return XDP_DROP;
    }
    
    // ARP lookup
    rs_debug("Route: ARP lookup for %pI4", &nexthop_ip);
    struct arp_entry *arp = bpf_map_lookup_elem(&arp_tbl, &nexthop_ip);
    
    // Rewrite L2 header (l2_offset is always 0)
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_DROP;
    struct ethhdr *eth = data;
    
    if (!arp) {
        /* ARP Miss: For direct routes, flood with broadcast MAC
         * 
         * This mimics traditional router behavior when next-hop MAC is unknown:
         * - Send packet with dst MAC = FF:FF:FF:FF:FF:FF (broadcast)
         * - Target host will receive it and may respond with ARP reply
         * - Future packets will use learned ARP entry
         * 
         * Note: This is a simplified approach. Full ARP implementation would:
         * 1. Generate ARP request packet
         * 2. Cache the original IP packet
         * 3. Wait for ARP reply
         * 4. Forward cached packet
         * 
         * Current approach: Let the first packet "probe" with broadcast MAC.
         * Works for many network stacks (they'll accept broadcast and respond).
         */
        rs_debug("Route: ARP miss for %pI4, using broadcast MAC for direct route", &nexthop_ip);
        update_stat(ROUTE_STAT_ARP_MISS);
        
        /* Only flood for direct routes (type=0)
         * Static routes (type=1) with missing next-hop should drop
         */
        if (route->type != 0) {
            rs_debug("Route: Static route requires explicit ARP entry, dropping");
            ctx->drop_reason = RS_DROP_NO_FWD_ENTRY;
            return XDP_DROP;
        }
        
        // Set source MAC to egress interface, dest MAC to broadcast
        __builtin_memcpy(eth->h_source, egress_cfg->mac, 6);
        __builtin_memset(eth->h_dest, 0xff, 6);  // Broadcast: ff:ff:ff:ff:ff:ff
        
        rs_debug("Route: L2 rewrite src=%02x:%02x:%02x:%02x:%02x:%02x dst=ff:ff:ff:ff:ff:ff",
                 egress_cfg->mac[0], egress_cfg->mac[1], egress_cfg->mac[2],
                 egress_cfg->mac[3], egress_cfg->mac[4], egress_cfg->mac[5]);
    } else {
        /* ARP Hit: Normal unicast forwarding */
        rs_debug("Route: ARP hit, MAC=%02x:%02x:%02x:%02x:%02x:%02x",
                 arp->mac[0], arp->mac[1], arp->mac[2], 
                 arp->mac[3], arp->mac[4], arp->mac[5]);
        update_stat(ROUTE_STAT_ARP_HIT);
        
        __builtin_memcpy(eth->h_source, egress_cfg->mac, 6);
        __builtin_memcpy(eth->h_dest, arp->mac, 6);
        
        rs_debug("Route: L2 rewrite src=%02x:%02x:%02x:%02x:%02x:%02x dst=%02x:%02x:%02x:%02x:%02x:%02x",
                 egress_cfg->mac[0], egress_cfg->mac[1], egress_cfg->mac[2],
                 egress_cfg->mac[3], egress_cfg->mac[4], egress_cfg->mac[5],
                 arp->mac[0], arp->mac[1], arp->mac[2],
                 arp->mac[3], arp->mac[4], arp->mac[5]);
    }
    
    // Set forwarding decision
    ctx->egress_ifindex = route->ifindex;
    ctx->action = XDP_REDIRECT;
    
    rs_debug("Route: Success! Redirect to ifindex=%u", route->ifindex);
    
    // Next module
    RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
    return XDP_PASS;
}
