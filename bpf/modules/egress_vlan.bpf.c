// SPDX-License-Identifier: GPL-2.0
/* 
 * rSwitch Egress VLAN Module
 * 
 * Handles VLAN tag manipulation on packet egress via devmap egress program:
 * - TRUNK ports: Add VLAN tag (except for native VLAN)
 * - ACCESS ports: Remove VLAN tag
 * - HYBRID ports: Add tag for tagged_vlans, remove for untagged_vlans
 * 
 * This module runs as a devmap egress program attached to tx_port devmap.
 * It receives packets after forwarding decision has been made and before
 * they are transmitted.
 */

#include "../include/rswitch_common.h"


char _license[] SEC("license") = "GPL";

/*
 * Reload ctx->data and ctx->data_end as verifier-safe direct accesses.
 *
 * After bpf_xdp_adjust_head(), the verifier requires ctx field loads via
 * constant-offset dereferences (e.g. *(u32 *)(r6 + 0)).  A compiler barrier
 * after adjust_head prevents LLVM from computing the offset via register
 * arithmetic (r2 = ctx; r2 += 4; load r2) which the verifier rejects as
 * "dereference of modified ctx ptr".
 *
 * Previously __noinline helpers were used for this purpose, but on kernel
 * 6.8.0-106 + LLVM, the __noinline call frame itself triggers the same
 * verifier error.  Direct inline access with barriers is more robust.
 */

// Module metadata
RS_DECLARE_MODULE(
    "egress_vlan",
    RS_HOOK_XDP_EGRESS,
    180,  // Stage 180: VLAN tagging in egress pipeline
    RS_FLAG_MODIFIES_PACKET,
    "VLAN tag manipulation on egress"
);

/* Check if egress port is member of packet's VLAN
 * 
 * This enforces VLAN isolation during flooding:
 * - Ingress uses BPF_F_BROADCAST to send to all ports
 * - Egress VLAN module filters out ports not in the VLAN
 * 
 * Returns:
 *   1 if port is member (allow forwarding)
 *   0 if port is not member (drop packet)
 */
static __always_inline int is_vlan_member(__u16 vlan_id, __u32 ifindex)
{
    struct rs_vlan_members *members = bpf_map_lookup_elem(&rs_vlan_map, &vlan_id);
    if (!members) {
        /* VLAN not configured - allow by default (permissive mode) */
        return 1;
    }
    
    /* Calculate bitmask position (must match loader and vlan.bpf.c) */
    __u32 word_idx = ((ifindex - 1) / 64) & 3;  // Max 4 words
    __u64 bit_mask = 1ULL << ((ifindex - 1) % 64);
    
    /* Check if port is member (either tagged or untagged) */
    return (members->tagged_members[word_idx] & bit_mask) ||
           (members->untagged_members[word_idx] & bit_mask);
}

// Helper: Check if VLAN should be sent tagged on this port
static __always_inline int should_send_tagged(struct rs_port_config *port, __u16 vlan_id)
{
    if (!port)
        return 0;
    
    switch (port->vlan_mode) {
    case RS_VLAN_MODE_ACCESS:
        // ACCESS ports: Never send tagged
        return 0;
    
    case RS_VLAN_MODE_TRUNK:
        // TRUNK ports: Send tagged except for native VLAN
        if (vlan_id == port->native_vlan)
            return 0;  // Native VLAN sent untagged
        
        // Check if VLAN is in allowed list
        #pragma unroll
        for (int i = 0; i < RS_MAX_ALLOWED_VLANS; i++) {
            if (i >= port->allowed_vlan_count)
                break;
            if (port->allowed_vlans[i] == vlan_id)
                return 1;  // Send tagged
        }
        return 0;  // Not in allowed list
    
    case RS_VLAN_MODE_HYBRID:
        // HYBRID ports: Check tagged_vlans list
        #pragma unroll
        for (int i = 0; i < RS_MAX_ALLOWED_VLANS; i++) {
            if (i >= port->tagged_vlan_count)
                break;
            if (port->tagged_vlans[i] == vlan_id)
                return 1;  // Send tagged
        }
        return 0;  // Send untagged (in untagged_vlans list)
    
    default:
        return 0;
    }
}

// Helper: Add VLAN tag to packet with PCP (using parsing_helpers)
static __always_inline int egress_add_vlan_tag(struct xdp_md *ctx, __u16 vlan_id, __u8 pcp)
{
    barrier_var(ctx);
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    
    // Bounds check
    if ((void *)(eth + 1) > data_end)
        return -1;
    
    // Build TCI: [PCP:3][DEI:1][VID:12]
    __u16 tci = ((__u16)pcp << 13) | (vlan_id & 0x0FFF);
    
    // Use parsing_helpers vlan_tag_push
    if (vlan_tag_push(ctx, eth, tci) < 0) {
        rs_debug("Failed to push VLAN tag: VID=%u, PCP=%u", vlan_id, pcp);
        return -1;
    }
    
    rs_debug("Added VLAN tag: VID=%u, PCP=%u", vlan_id, pcp);
    return 0;
}

// Helper: Remove VLAN tag from packet (egress version)
static __always_inline int egress_remove_vlan_tag(struct xdp_md *ctx)
{
    barrier_var(ctx);
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    
    if ((void *)(eth + 1) > data_end)
        return -1;
    
    // Check if packet is VLAN-tagged
    if (bpf_ntohs(eth->h_proto) != ETH_P_8021Q &&
        bpf_ntohs(eth->h_proto) != ETH_P_8021AD)
        return 0;  // Not tagged, nothing to remove
    
    // Use parsing_helpers vlan_tag_pop
    if (vlan_tag_pop(ctx, eth) < 0) {
        rs_debug("Failed to pop VLAN tag");
        return -1;
    }
    
    rs_debug("Removed VLAN tag");
    return 0;
}

static __always_inline int egress_packet_is_vlan_tagged(struct xdp_md *ctx)
{
    barrier_var(ctx);
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return 0;

    return bpf_ntohs(eth->h_proto) == ETH_P_8021Q ||
           bpf_ntohs(eth->h_proto) == ETH_P_8021AD;
}

static __always_inline int egress_add_vlan_tag_with_tpid(struct xdp_md *ctx,
                                                          __u16 vlan_id,
                                                          __u8 pcp,
                                                          __u16 tpid)
{
    barrier_var(ctx);
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct ethhdr eth_cpy;
    struct vlan_hdr *vhdr;
    __u16 tci = ((__u16)(pcp & 0x07) << 13) | (vlan_id & 0x0FFF);

    if ((void *)(eth + 1) > data_end)
        return -1;

    __builtin_memcpy(&eth_cpy, eth, sizeof(eth_cpy));

    if (bpf_xdp_adjust_head(ctx, -4))
        return -1;

    barrier_var(ctx);

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    __builtin_memcpy(eth, &eth_cpy, sizeof(*eth));

    vhdr = (void *)(eth + 1);
    if ((void *)(vhdr + 1) > data_end)
        return -1;

    vhdr->h_vlan_TCI = bpf_htons(tci);
    vhdr->h_vlan_encapsulated_proto = eth->h_proto;
    eth->h_proto = bpf_htons(tpid);

    return 0;
}

static __always_inline int egress_process_qinq(struct xdp_md *ctx,
                                               struct rs_ctx *rs_ctx,
                                               __u32 egress_ifindex,
                                               __u16 c_vlan)
{
    struct rs_qinq_config *qcfg = bpf_map_lookup_elem(&qinq_config_map, &egress_ifindex);
    __u8 pcp = rs_ctx->prio;

    if (!qcfg)
        return -1;

    if (c_vlan < qcfg->c_vlan_start || c_vlan > qcfg->c_vlan_end)
        return -1;

    if (egress_packet_is_vlan_tagged(ctx)) {
        if (egress_remove_vlan_tag(ctx) < 0)
            return -1;
        if (egress_packet_is_vlan_tagged(ctx)) {
            if (egress_remove_vlan_tag(ctx) < 0)
                return -1;
        }
    }

    if (egress_add_vlan_tag_with_tpid(ctx, c_vlan, pcp, ETH_P_8021Q) < 0)
        return -1;
    if (egress_add_vlan_tag_with_tpid(ctx, qcfg->s_vlan, pcp, ETH_P_8021AD) < 0)
        return -1;

    rs_ctx->layers.vlan_depth = 2;
    rs_ctx->layers.vlan_ids[0] = qcfg->s_vlan;
    rs_ctx->layers.vlan_ids[1] = c_vlan;

    return 0;
}

// Main egress VLAN processing (XDP tail-call module)
SEC("xdp/devmap")
int egress_vlan_xdp(struct xdp_md *ctx)
{
    // Get per-CPU context
    struct rs_ctx *rs_ctx = RS_GET_CTX();
    if (!rs_ctx) {
        rs_debug("egress_vlan: No context, dropping");
        return XDP_DROP;
    }
    
    /* Get egress port from XDP context (devmap sets this)
     * 
     * IMPORTANT: During flooding (BPF_F_BROADCAST), devmap calls this egress
     * program once per destination port. The actual egress port is in
     * ctx->egress_ifindex (set by devmap), NOT in rs_ctx->egress_ifindex
     * (which is 0 for broadcast).
     * 
     * For unicast: rs_ctx->egress_ifindex == ctx->egress_ifindex (both set)
     * For flooding: rs_ctx->egress_ifindex == 0, ctx->egress_ifindex = actual port
     */
    __u32 egress_ifindex = ctx->egress_ifindex;
    if (egress_ifindex == 0) {
        rs_debug("egress_vlan: No egress port set in ctx");
        // Continue to next module
        RS_TAIL_CALL_EGRESS(ctx, rs_ctx);
        return XDP_PASS;
    }
    
    /* VLAN isolation check - critical for L2 security!
     * 
     * During flooding (egress_ifindex=0 in ctx), ingress uses BPF_F_BROADCAST
     * which sends to ALL ports. We must filter out ports not in the packet's VLAN.
     * 
     * EXCEPTION: Routed packets (L3 forwarding)
     * - Route module modifies packet (rewrites L2 header, decrements TTL)
     * - Sets ctx->modified = 1
     * - These packets are INTENTIONALLY crossing VLAN boundaries
     * - Should NOT be subject to L2 VLAN isolation
     * 
     * Check: Skip VLAN isolation for routed traffic
     */
    if (!rs_ctx->modified) {
        __u16 vlan_id = rs_ctx->ingress_vlan;
        if (vlan_id == 0) vlan_id = RS_DEFAULT_VLAN;
        
        rs_debug("egress_vlan: Isolation check - port %u, VLAN %u", egress_ifindex, vlan_id);
        
        if (!is_vlan_member(vlan_id, egress_ifindex)) {
            rs_debug("egress_vlan: Port %u not in VLAN %u, dropping (isolation)", 
                     egress_ifindex, vlan_id);
            
            /* Update drop statistics */
            __u32 stats_key = egress_ifindex;
            struct rs_stats *stats = bpf_map_lookup_elem(&rs_stats_map, &stats_key);
            if (stats) {
                __sync_fetch_and_add(&stats->tx_drops, 1);
            }
            
            return XDP_DROP;
        }
        
        rs_debug("egress_vlan: Port %u is member of VLAN %u, allowing", egress_ifindex, vlan_id);
    } else {
        rs_debug("egress_vlan: Routed packet (modified=1), skipping VLAN isolation");
    }
    
    struct rs_port_config *port = rs_get_port_config(egress_ifindex);
    if (!port) {
        rs_debug("egress_vlan: No port config for ifindex %u", egress_ifindex);
        RS_TAIL_CALL_EGRESS(ctx, rs_ctx);
        return XDP_PASS;
    }
    
    // Determine egress VLAN ID
    __u16 egress_vlan = rs_ctx->egress_vlan;
    if (egress_vlan == 0) {
        egress_vlan = rs_ctx->ingress_vlan;  // Use ingress VLAN as default
    }
    
    if (egress_vlan == 0 || port->vlan_mode == RS_VLAN_MODE_OFF) {
        // No VLAN processing needed
        rs_debug("egress_vlan: No VLAN info or mode OFF, skipping");
        RS_TAIL_CALL_EGRESS(ctx, rs_ctx);
        return XDP_PASS;
    }

    if (port->vlan_mode == RS_VLAN_MODE_QINQ) {
        __u8 old_depth = rs_ctx->layers.vlan_depth;
        if (old_depth > 2)
            old_depth = 2;

        if (egress_process_qinq(ctx, rs_ctx, egress_ifindex, egress_vlan) < 0) {
            rs_debug("egress_vlan: QinQ tag processing failed on port %u", egress_ifindex);
            return XDP_DROP;
        }

        int delta = (2 - old_depth) * 4;
        if (delta != 0) {
            if (rs_ctx->layers.l3_offset != 0)
                rs_ctx->layers.l3_offset += delta;
            if (rs_ctx->layers.l4_offset != 0)
                rs_ctx->layers.l4_offset += delta;
        }

        RS_TAIL_CALL_EGRESS(ctx, rs_ctx);
        return XDP_PASS;
    }
    
    // Check if we need to tag or untag
    int packet_is_tagged = (rs_ctx->layers.vlan_depth > 0 && 
                            rs_ctx->layers.vlan_ids[0] > 0);
    int should_tag = should_send_tagged(port, egress_vlan);
    
    rs_debug("egress_vlan: port=%u, vlan=%u, tagged=%d, should_tag=%d, mode=%d",
             egress_ifindex, egress_vlan, packet_is_tagged, should_tag, port->vlan_mode);
    
    if (should_tag && !packet_is_tagged) {
        // Need to add VLAN tag
        __u8 pcp = rs_ctx->prio;  // Use priority from QoS module
        if (egress_add_vlan_tag(ctx, egress_vlan, pcp) < 0) {
            rs_debug("egress_vlan: Failed to add VLAN tag");
            // Continue anyway, packet will be sent untagged
        } else {
            // Update context to reflect added tag
            rs_ctx->layers.vlan_depth = 1;
            rs_ctx->layers.vlan_ids[0] = egress_vlan;
            
            /* CRITICAL: Update L3 offset after adding VLAN tag
             * VLAN tag is 4 bytes (TPID + TCI), inserted between Ethernet header and payload
             * All layer offsets after L2 must be shifted by 4 bytes */
            if (rs_ctx->layers.l3_offset != 0) {
                rs_ctx->layers.l3_offset += 4;
                rs_debug("egress_vlan: Updated L3 offset after tag add: +4 bytes");
            }
            if (rs_ctx->layers.l4_offset != 0) {
                rs_ctx->layers.l4_offset += 4;
            }
        }
    } else if (!should_tag && packet_is_tagged) {
        // Need to remove VLAN tag
        if (egress_remove_vlan_tag(ctx) < 0) {
            rs_debug("egress_vlan: Failed to remove VLAN tag");
            // Continue anyway, packet will be sent tagged
        } else {
            // Update context to reflect removed tag
            rs_ctx->layers.vlan_depth = 0;
            rs_ctx->layers.vlan_ids[0] = 0;
            
            /* CRITICAL: Update L3 offset after removing VLAN tag
             * VLAN tag removal shifts all layers 4 bytes earlier */
            if (rs_ctx->layers.l3_offset >= 4) {
                rs_ctx->layers.l3_offset -= 4;
                rs_debug("egress_vlan: Updated L3 offset after tag remove: -4 bytes");
            }
            if (rs_ctx->layers.l4_offset >= 4) {
                rs_ctx->layers.l4_offset -= 4;
            }
        }
    }
    
    // Tail-call to next egress module
    RS_TAIL_CALL_EGRESS(ctx, rs_ctx);
    
    // Fallback if tail-call fails
    return XDP_PASS;
}

