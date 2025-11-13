// SPDX-License-Identifier: GPL-2.0
/* 
 * rSwitch L2 MAC Learning Module
 * 
 * Performs layer 2 MAC address learning:
 * - Learns source MAC → ingress port associations
 * - Updates MAC forwarding table (rs_mac_table)
 * - Emits ringbuf events for user-space MAC table management
 * - Sets egress_ifindex for known destinations
 * 
 * This module should run late in the pipeline (stage=80) after
 * VLAN processing and ACL checks, but before final forwarding.
 */

/* Define rs_mac_table here - prevents extern declaration in map_defs.h */
#define RS_MAC_TABLE_OWNER

#include "../include/rswitch_common.h"

char _license[] SEC("license") = "GPL";

// Module metadata for auto-discovery
RS_DECLARE_MODULE(
    "l2learn",                  // Module name
    RS_HOOK_XDP_INGRESS,        // Hook point (ingress processing)
    80,                         // Stage number (learning stage, late pipeline)
    RS_FLAG_NEED_L2L3_PARSE | RS_FLAG_CREATES_EVENTS,  // Capability flags
    "Layer 2 MAC learning and forwarding table lookup"
);

/* MAC Forwarding Table - Primary Owner
 * 
 * SINGLE OWNER PATTERN:
 * - Defined here (l2learn is the primary owner/writer)
 * - Pinned (LIBBPF_PIN_BY_NAME) for user-space access and aging
 * - Other modules use 'extern' declaration to access same pinned instance
 * - Loader accesses via l2learn module object to get FD
 * 
 * Rationale:
 * - l2learn is the only module that writes (learns MACs)
 * - Other modules may read (forwarding lookups)
 * - User-space needs access for aging, static entries, telemetry
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);  /* 64K MAC entries */
    __type(key, struct rs_mac_key);
    __type(value, struct rs_mac_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);  /* Pin to /sys/fs/bpf/rs_mac_table */
} rs_mac_table SEC(".maps");

/* MAC learning event structure */
struct mac_learn_event {
    __u32 event_type;           /* RS_EVENT_MAC_* */
    __u32 ifindex;              /* Port where MAC was seen */
    __u16 vlan;                 /* VLAN ID */
    __u8  mac[6];               /* MAC address */
    __u64 timestamp;            /* Learning timestamp */
} __attribute__((packed));

// Broadcast MAC address for comparison
static const __u8 BROADCAST_MAC[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

// Helper: Check if MAC is broadcast
static __always_inline int is_broadcast_mac(const __u8 *mac)
{
    return __builtin_memcmp(mac, BROADCAST_MAC, 6) == 0;
}

// Helper: Check if MAC is multicast (first octet LSB = 1)
static __always_inline int is_multicast_mac(const __u8 *mac)
{
    return (mac[0] & 0x01) != 0;
}

// Helper: Emit MAC learning event to unified event bus
static __always_inline void emit_mac_event(struct rs_ctx *ctx, 
                                           __u32 event_type,
                                           const __u8 *mac,
                                           __u16 vlan,
                                           __u32 ifindex)
{
    struct mac_learn_event event = {
        .event_type = event_type,
        .ifindex = ifindex,
        .vlan = vlan,
        .timestamp = bpf_ktime_get_ns(),
    };
    __builtin_memcpy(event.mac, mac, 6);
    
    if (RS_EMIT_EVENT(&event, sizeof(event)) < 0) {
        rs_debug("Failed to emit MAC event to event bus");
    }
}

// Helper: Learn source MAC address
static __always_inline int learn_source_mac(struct rs_ctx *ctx, 
                                            struct xdp_md *xdp_ctx,
                                            const __u8 *smac)
{
    struct rs_mac_key key;
    struct rs_mac_entry new_entry, *existing;
    __u64 now = bpf_ktime_get_ns();
    __u16 vlan = ctx->ingress_vlan;
    
    // Build lookup key (MAC + VLAN)
    __builtin_memcpy(key.mac, smac, 6);
    key.vlan = vlan;
    
    // Lookup existing entry
    existing = bpf_map_lookup_elem(&rs_mac_table, &key);
    
    if (existing) {
        
        rs_debug("L2learn: learn source mac, key existing, egress port: %u", existing->ifindex);
        // Entry exists - check if port changed (MAC moved)
        if (existing->ifindex != ctx->ifindex) {
            rs_debug("MAC %02x:%02x:%02x:%02x:%02x:%02x moved: port %d → %d",
                     smac[0], smac[1], smac[2], smac[3], smac[4], smac[5],
                     existing->ifindex, ctx->ifindex);
            
            // Update port
            existing->ifindex = ctx->ifindex;
            existing->last_seen = now;
            existing->hit_count++;
            
            // Notify user-space
            emit_mac_event(ctx, RS_EVENT_MAC_MOVED, smac, vlan, ctx->ifindex);
        } else {
            // Same port - just refresh timestamp
            existing->last_seen = now;
            existing->hit_count++;
        }
    } else {
        // New MAC - create entry
        rs_debug("MAC learned: %02x:%02x:%02x:%02x:%02x:%02x on port %d, VLAN %d",
                 smac[0], smac[1], smac[2], smac[3], smac[4], smac[5],
                 ctx->ifindex, vlan);
        
        new_entry.ifindex = ctx->ifindex;
        new_entry.static_entry = 0;  // Dynamic (learned)
        new_entry.last_seen = now;
        new_entry.hit_count = 1;
        
        if (bpf_map_update_elem(&rs_mac_table, &key, &new_entry, BPF_ANY) < 0) {
            rs_debug("Failed to insert MAC entry (table full?)");
            return -1;
        }
        
        // Notify user-space
        emit_mac_event(ctx, RS_EVENT_MAC_LEARNED, smac, vlan, ctx->ifindex);
    }
    
    return 0;
}

// Helper: Lookup destination MAC and set egress port
static __always_inline int lookup_destination_mac(struct rs_ctx *ctx,
                                                  const __u8 *dmac)
{
    struct rs_mac_key key;
    struct rs_mac_entry *entry;
    __u16 vlan = ctx->ingress_vlan;
    
    // Broadcast/multicast → flooding (handled by lastcall)
    if (is_broadcast_mac(dmac) || is_multicast_mac(dmac)) {
        rs_debug("Broadcast/multicast destination → flood");
        ctx->egress_ifindex = 0;  // 0 = flood (lastcall will handle)
        return 0;
    }
    
    // Build lookup key
    __builtin_memcpy(key.mac, dmac, 6);
    key.vlan = vlan;
    
    // Lookup MAC table
    entry = bpf_map_lookup_elem(&rs_mac_table, &key);
    
    if (entry) {
        // Found - set egress port
        rs_debug("MAC %02x:%02x:%02x:%02x:%02x:%02x → port %d",
                 dmac[0], dmac[1], dmac[2], dmac[3], dmac[4], dmac[5],
                 entry->ifindex);
        
        ctx->egress_ifindex = entry->ifindex;
        
        // Update hit count
        entry->hit_count++;
        
        return 0;
    }
    
    // Not found → flood
    rs_debug("Unknown destination MAC → flood");
    ctx->egress_ifindex = 0;  // 0 = flood
    
    return 0;
}

// Main L2 learning function
SEC("xdp")
int l2learn_ingress(struct xdp_md *xdp_ctx)
{
    void *data_end = (void *)(long)xdp_ctx->data_end;
    void *data = (void *)(long)xdp_ctx->data;
    struct ethhdr *eth;
    
    // Get per-CPU context
    struct rs_ctx *ctx = RS_GET_CTX();
    if (!ctx) {
        rs_debug("Failed to get rs_ctx");
        return XDP_DROP;
    }
    
    rs_debug("target port: %u", ctx->egress_ifindex);

    /* Skip L2 forwarding lookup if routing already made decision
     * 
     * If Route module (or any other L3 module) has already set egress_ifindex,
     * we should NOT override it with L2 lookup. This allows proper separation:
     * - L3 routed traffic: Route module decides egress port
     * - L2 switched traffic: L2Learn module decides egress port
     * 
     * Check: egress_ifindex != 0 means forwarding decision已经被做出
     */
    bool routing_decision_made = (ctx->egress_ifindex != 0);
    
    if (routing_decision_made) {
        rs_debug("L2Learn: Routing decision already made (egress=%u), skipping L2 lookup",
                 ctx->egress_ifindex);
        /* Still do MAC learning for source, but skip destination lookup */
        goto do_learning_only;
    }
    
    // Check if packet was parsed
    if (!ctx->parsed) {
        rs_debug("Packet not parsed, skipping MAC learning");
        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_DROP;
    }
    
do_learning_only:
    ; /* Empty statement required before declaration */
    // Get port configuration
    struct rs_port_config *port = rs_get_port_config(ctx->ifindex);
    if (!port) {
        rs_debug("No port config, skipping MAC learning");
        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_DROP;
    }
    
    // Check if learning is enabled for this port
    if (!port->learning) {
        rs_debug("Learning disabled on port %d", ctx->ifindex);
        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_DROP;
    }
    
    // Bounds check for Ethernet header
    if (data + sizeof(*eth) > data_end) {
        rs_debug("Packet too short for Ethernet header");
        ctx->error = RS_ERROR_PARSE_FAILED;
        ctx->drop_reason = RS_DROP_PARSE_ERROR;
        return XDP_DROP;
    }
    eth = data;
    
    // Learn source MAC (skip broadcast/multicast sources)
    if (!is_broadcast_mac(eth->h_source) && !is_multicast_mac(eth->h_source)) {
        learn_source_mac(ctx, xdp_ctx, eth->h_source);
    }
    
    // Lookup destination MAC ONLY if routing didn't already decide
    if (!routing_decision_made) {
        lookup_destination_mac(ctx, eth->h_dest);
    }
    
    rs_debug("L2Learn: learned src=%02x:%02x:%02x:%02x:%02x:%02x",
             eth->h_source[0], eth->h_source[1], eth->h_source[2], 
             eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    
    rs_debug("L2Learn: ingress_ifindex=%d, egress_ifindex=%d",
             ctx->ifindex, ctx->egress_ifindex);             
    if (!routing_decision_made) {
        rs_debug("L2Learn: lookup dst=%02x:%02x:%02x:%02x:%02x:%02x → egress=%d",
                 eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
                 eth->h_dest[3], eth->h_dest[4], eth->h_dest[5],
                 ctx->egress_ifindex);
    }
    
    // Proceed to next module
    RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
    
    // Tail-call failed
    rs_debug("L2learn: Tail-call to next module failed");
    return XDP_DROP;
}
