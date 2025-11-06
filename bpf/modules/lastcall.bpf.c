// SPDX-License-Identifier: GPL-2.0
/* 
 * rSwitch LastCall Module - Final Forwarding Decision
 * 
 * This is the final module in the ingress pipeline (stage=90).
 * It performs the actual packet forwarding based on decisions made
 * by previous modules (VLAN, ACL, L2Learn, etc.).
 * 
 * Forwarding logic:
 * - If egress_ifindex is set (unicast): redirect to specific port
 * - If egress_ifindex is 0 (flood): broadcast to all ports except ingress
 * - Uses rs_devmap for efficient packet redirection
 * 
 * This module is intentionally simple - all complex logic (MAC learning,
 * VLAN filtering, ACL checks) should be handled by earlier modules.
 */

#include "../include/rswitch_common.h"

char _license[] SEC("license") = "GPL";

/* XDP devmap for packet forwarding
 * 
 * Following PoC egress_map pattern:
 * - Defined ONLY in lastcall (single user)
 * - Loader populates it via lastcall object
 * - NO pinning needed (not shared across modules)
 * - Uses bpf_devmap_val for potential egress hook attachment
 */
struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP_HASH);
    __uint(max_entries, RS_MAX_INTERFACES);
    __type(key, __u32);         /* ifindex */
    __type(value, struct bpf_devmap_val);
} rs_xdp_devmap SEC(".maps");

// Module metadata for auto-discovery
RS_DECLARE_MODULE(
    "lastcall",                 // Module name
    RS_HOOK_XDP_INGRESS,        // Hook point (ingress processing)
    90,                         // Stage number (MUST be last in pipeline)
    0,                          // No special flags (pure forwarding)
    "Final forwarding decision - unicast or flood"
);

// Helper: Check if action requires forwarding
static __always_inline int should_forward(struct rs_ctx *ctx)
{
    // If error occurred in pipeline, drop
    if (ctx->error != RS_ERROR_NONE) {
        rs_debug("Dropping packet due to error: %d", ctx->error);
        return 0;
    }
    
    // If action is already set to DROP, respect it
    if (ctx->action == XDP_DROP) {
        rs_debug("Dropping packet: action=XDP_DROP");
        return 0;
    }
    
    return 1;
}

/* NOTE: VLAN isolation is enforced in egress hook (egress.bpf.c), not here.
 * We use BPF_F_BROADCAST which sends to all ports, then egress hook filters
 * based on rs_vlan_map membership. This avoids the "only last redirect works"
 * problem when iterating VLAN members in a loop.
 */

// Main forwarding function
// Note: TX statistics are handled by the egress devmap hook (egress.bpf.c)
SEC("xdp")
int lastcall_forward(struct xdp_md *xdp_ctx)
{
    void *data_end = (void *)(long)xdp_ctx->data_end;
    void *data = (void *)(long)xdp_ctx->data;
    __u32 pkt_len = data_end - data;
    
    // Get per-CPU context
    struct rs_ctx *ctx = RS_GET_CTX();
    if (!ctx) {
        rs_debug("Failed to get rs_ctx");
        return XDP_DROP;
    }
    
    // Check if we should forward
    if (!should_forward(ctx)) {
        return XDP_DROP;
    }
    
    // Get egress decision from context (set by l2learn or other modules)
    __u32 egress_ifindex = ctx->egress_ifindex;
    
    rs_debug("LastCall: egress_ifindex=%d (0=flood)", egress_ifindex);
    
    // Case 1: Unicast - egress port is known
    if (egress_ifindex != 0) {
        // Avoid forwarding back to ingress port
        if (egress_ifindex == ctx->ifindex) {
            rs_debug("Dropping packet: egress == ingress (%d)", egress_ifindex);
            ctx->drop_reason = RS_DROP_NO_FWD_ENTRY;
            return XDP_DROP;
        }
        
        rs_debug("Unicast forwarding: port %d → port %d", 
                 ctx->ifindex, egress_ifindex);
        
        // Redirect to specific port via XDP devmap (queue isolation)
        // Uses rs_xdp_devmap which targets queues 1-3 (not queue 0 reserved for AF_XDP)
        // Devmap egress hook (egress.bpf.c) will:
        // - Handle VLAN tag manipulation
        // - Update TX statistics
        // - Clear parsed flag after processing completes
        return bpf_redirect_map(&rs_xdp_devmap, egress_ifindex, 0);
    }
    
    // Case 2: Flood - broadcast to all ports, egress hook will filter VLAN members
    //
    // Strategy: Use BPF_F_BROADCAST to send to all ports, then rely on
    // egress devmap hook (egress.bpf.c) to DROP packets for ports not in VLAN.
    //
    // Why not filter here?
    // - Cannot do multiple bpf_redirect() in loop (only last one takes effect)
    // - bpf_clone_redirect() is expensive and has clone limit
    // - Egress hook is the proper place for per-port filtering
    //
    // Egress hook responsibilities:
    // - Check if egress port is member of packet's VLAN (via rs_vlan_map)
    // - DROP if not a member (VLAN isolation enforcement)
    // - Handle VLAN tag manipulation (add/remove based on tagged/untagged membership)
    // - Update TX statistics
    
    __u16 vlan_id = ctx->ingress_vlan;  // Set by VLAN module
    if (vlan_id == 0) vlan_id = 1;       // Default VLAN if not set
    
    rs_debug("Flooding: VLAN %d from port %d to all ports (egress hook will filter)", 
             vlan_id, ctx->ifindex);
    
    // Broadcast to all ports (egress hook does VLAN filtering)
    // Egress hook will clear parsed flag after processing completes
    return bpf_redirect_map(&rs_xdp_devmap, 0, BPF_F_BROADCAST | BPF_F_EXCLUDE_INGRESS);
    
    // Note: We cannot update individual TX stats for broadcast here
    // as we don't know which ports will actually receive the packet.
    // Egress hook should handle per-port TX stats for broadcast.
}

/* Alternative implementation for debugging/testing:
 * This version explicitly handles broadcast by iterating ports,
 * but it's less efficient than using BPF_F_BROADCAST.
 */
#ifdef LASTCALL_MANUAL_BROADCAST
SEC("xdp")
int lastcall_forward_manual(struct xdp_md *xdp_ctx)
{
    struct rs_ctx *ctx = RS_GET_CTX();
    if (!ctx || !should_forward(ctx)) {
        return XDP_DROP;
    }
    
    __u32 egress_ifindex = ctx->egress_ifindex;
    
    if (egress_ifindex != 0) {
        // Unicast
        if (egress_ifindex == ctx->ifindex) {
            return XDP_DROP;
        }
        return bpf_redirect_map(&rs_devmap, egress_ifindex, 0);
    }
    
    // Manual broadcast - iterate all configured ports
    // This is less efficient but useful for debugging
    int forwarded = 0;
    
    #pragma unroll
    for (__u32 port = 0; port < RS_MAX_INTERFACES; port++) {
        if (port == ctx->ifindex) {
            continue;  // Skip ingress port
        }
        
        // Check if port is configured
        struct rs_port_config *cfg = rs_get_port_config(port);
        if (!cfg || !cfg->enabled) {
            continue;
        }
        
        // Redirect to this port
        // Note: Only the last redirect will take effect!
        // This is why BPF_F_BROADCAST is preferred.
        bpf_redirect_map(&rs_devmap, port, 0);
        forwarded++;
    }
    
    rs_debug("Manual broadcast forwarded to %d ports", forwarded);
    
    // Return the last redirect action
    return XDP_REDIRECT;
}
#endif /* LASTCALL_MANUAL_BROADCAST */
