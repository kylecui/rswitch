// SPDX-License-Identifier: GPL-2.0
/* rSwitch Egress Hook - Devmap Egress Program
 * 
 * This program is attached to the devmap and runs on packet egress.
 * It's the final processing stage before packets leave the switch.
 * 
 * Responsibilities:
 *   1. VLAN tag manipulation (add/remove based on port config)
 *   2. QoS marking (DSCP, 802.1p priority)
 *   3. Egress statistics tracking
 *   4. Final packet validation
 * 
 * Design:
 *   - Runs AFTER ingress pipeline completes
 *   - Accesses rs_ctx set by ingress modules
 *   - Modifies packet headers based on egress port config
 *   - Cannot tail-call (devmap programs have restrictions)
 * 
 * Key Difference from Ingress:
 *   - No tail-call chain (single-stage processing)
 *   - Must complete quickly (affects forwarding latency)
 *   - Can call bpf_xdp_adjust_head/tail for packet modification
 */

#include "../include/rswitch_common.h"

char _license[] SEC("license") = "GPL";

/* Check if egress port is member of packet's VLAN
 * 
 * This enforces VLAN isolation during flooding:
 * - Ingress uses BPF_F_BROADCAST to send to all ports
 * - Egress hook filters out ports not in the VLAN
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

/* Add VLAN tag using parsing_helpers function
 * 
 * Returns:
 *   0 on success
 *  -1 on failure (insufficient headroom)
 */
static __always_inline int rs_vlan_push(struct xdp_md *ctx, __u16 vlan_id, __u8 prio)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    
    /* Bounds check */
    if ((void *)(eth + 1) > data_end)
        return -1;
    
    /* Use parsing_helpers vlan_tag_push - combines priority and VLAN ID in TCI field
     * TCI format: priority (3 bits) << 13 | DEI (1 bit) << 12 | VID (12 bits)
     */
    return vlan_tag_push(ctx, eth, vlan_id | ((__u16)prio << 12));
}

/* Remove VLAN tag using parsing_helpers function
 * 
 * Returns:
 *   0 on success
 *  -1 on failure (packet not tagged or invalid)
 */
static __always_inline int rs_vlan_pop(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    
    /* Bounds check */
    if ((void *)(eth + 1) > data_end)
        return -1;
    
    /* Verify packet is VLAN tagged */
    if (eth->h_proto != bpf_htons(ETH_P_8021Q) && 
        eth->h_proto != bpf_htons(ETH_P_8021AD))
        return -1;
    
    /* Use parsing_helpers vlan_tag_pop */
    return vlan_tag_pop(ctx, eth);
}

/* Update 802.1p priority in existing VLAN tag
 * 
 * Returns:
 *   0 on success
 *  -1 on failure (packet not tagged)
 */
static __always_inline int rs_vlan_set_priority(struct xdp_md *ctx, __u8 prio)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct vlan_hdr *vlan;
    __u16 tci;
    
    /* Bounds check */
    if ((void *)(eth + 1) + sizeof(*vlan) > data_end)
        return -1;
    
    /* Verify packet is VLAN tagged */
    if (eth->h_proto != bpf_htons(ETH_P_8021Q) && 
        eth->h_proto != bpf_htons(ETH_P_8021AD))
        return -1;
    
    vlan = (void *)(eth + 1);
    tci = bpf_ntohs(vlan->h_vlan_TCI);
    
    /* Clear old priority (bits 13-15) and set new */
    tci = (tci & 0x1FFF) | ((__u16)prio << 13);
    vlan->h_vlan_TCI = bpf_htons(tci);
    
    return 0;
}

/* Process VLAN tagging based on egress port configuration
 * 
 * VLAN Modes:
 *   ACCESS: Add pvid if untagged, drop if different VLAN
 *   TRUNK:  Keep tags, add native_vlan if untagged
 *   HYBRID: Complex rules (untagged_vlans vs tagged_vlans)
 */
static __always_inline int process_vlan_egress(struct xdp_md *ctx, 
                                                struct rs_ctx *rctx,
                                                struct rs_port_config *cfg)
{
    __u8 vlan_depth = rctx->layers.vlan_depth;
    
    /* No VLAN processing if mode is OFF */
    if (cfg->vlan_mode == 0)
        return 0;
    
    switch (cfg->vlan_mode) {
    case 1: /* ACCESS mode */
        if (vlan_depth > 0) {
            /* Packet is tagged - remove tag for access port */
            if (rs_vlan_pop(ctx) < 0) {
                rs_debug("Failed to pop VLAN tag on egress port %u", cfg->ifindex);
                return -1;
            }
        }
        /* Access ports always send untagged traffic */
        break;
        
    case 2: /* TRUNK mode */
        if (vlan_depth == 0) {
            /* Untagged packet going to trunk port
             * - If packet's VLAN == native_vlan: send UNTAGGED
             * - If packet's VLAN != native_vlan: add VLAN tag
             */
            __u16 pkt_vlan = rctx->ingress_vlan;
            if (pkt_vlan == 0) pkt_vlan = 1;  // Fallback to default VLAN
            
            if (pkt_vlan == cfg->native_vlan) {
                /* Native VLAN - send untagged */
                rs_debug("TRUNK port %u: VLAN %u is native VLAN, sending untagged", 
                         cfg->ifindex, pkt_vlan);
            } else {
                /* Non-native VLAN - must add tag */
                rs_debug("TRUNK port %u: VLAN %u != native VLAN %u, adding tag", 
                         cfg->ifindex, pkt_vlan, cfg->native_vlan);
                if (rs_vlan_push(ctx, pkt_vlan, rctx->prio) < 0) {
                    rs_debug("Failed to push VLAN %u tag on trunk port %u", 
                             pkt_vlan, cfg->ifindex);
                    return -1;
                }
            }
        } else {
            /* Tagged packet - check if it's native VLAN */
            __u16 pkt_vlan = rctx->ingress_vlan;
            if (pkt_vlan == 0) pkt_vlan = 1;
            
            if (pkt_vlan == cfg->native_vlan) {
                /* Native VLAN - remove tag */
                rs_debug("TRUNK port %u: tagged packet VLAN %u is native, removing tag", 
                         cfg->ifindex, pkt_vlan);
                if (rs_vlan_pop(ctx) < 0) {
                    rs_debug("Failed to pop VLAN tag on trunk port %u", cfg->ifindex);
                }
            } else {
                /* Non-native VLAN - keep tag, update priority if needed */
                rs_debug("TRUNK port %u: tagged packet VLAN %u != native %u, keeping tag", 
                         cfg->ifindex, pkt_vlan, cfg->native_vlan);
                if (rctx->prio > 0 && rs_vlan_set_priority(ctx, rctx->prio) < 0) {
                    rs_debug("Failed to set VLAN priority on trunk port %u", cfg->ifindex);
                }
            }
        }
        break;
        
    case 3: /* HYBRID mode */
        /* HYBRID logic:
         * - Check if egress_vlan is in untagged_vlans list → remove tag
         * - Check if egress_vlan is in tagged_vlans list → keep/add tag
         */
        if (vlan_depth > 0) {
            /* For now, simple implementation: keep tags on hybrid ports */
            if (rs_vlan_set_priority(ctx, rctx->prio) < 0) {
                rs_debug("Failed to set VLAN priority on hybrid port %u", cfg->ifindex);
            }
        } else {
            /* Untagged - add pvid if configured */
            if (cfg->pvid > 0) {
                if (rs_vlan_push(ctx, cfg->pvid, rctx->prio) < 0) {
                    rs_debug("Failed to push PVID %u on hybrid port %u", 
                             cfg->pvid, cfg->ifindex);
                    return -1;
                }
            }
        }
        break;
        
    default:
        break;
    }
    
    return 0;
}

/* Main egress hook - attached to devmap */
SEC("xdp/devmap")
int rswitch_egress(struct xdp_md *ctx)
{
    __u32 key = 0;
    __u32 egress_ifindex = ctx->egress_ifindex;
    
    /* Retrieve context set by ingress pipeline */
    struct rs_ctx *rctx = bpf_map_lookup_elem(&rs_ctx_map, &key);
    if (!rctx) {
        /* Context missing - should not happen in normal operation
         * Pass packet through without modification
         */
        rs_debug("WARN: No context on egress, passing through on port %u", egress_ifindex);
        return XDP_PASS;
    }
    
    /* VLAN isolation check - critical for security!
     * 
     * During flooding (egress_ifindex=0 in ctx), ingress uses BPF_F_BROADCAST
     * which sends to ALL ports. We must filter out ports not in the packet's VLAN.
     * 
     * This is the ONLY place enforcing VLAN isolation during flooding.
     */
    __u16 vlan_id = rctx->ingress_vlan;
    if (vlan_id == 0) vlan_id = 1;  // Default VLAN
    
    rs_debug("Egress check: port %u, VLAN %u", egress_ifindex, vlan_id);
    
    if (!is_vlan_member(vlan_id, egress_ifindex)) {
        rs_debug("Egress port %u not in VLAN %u, dropping (VLAN isolation)", 
                 egress_ifindex, vlan_id);
        
        /* Update drop statistics */
        __u32 stats_key = egress_ifindex;
        struct rs_stats *stats = bpf_map_lookup_elem(&rs_stats_map, &stats_key);
        if (stats) {
            __sync_fetch_and_add(&stats->tx_drops, 1);
        }
        
        return XDP_DROP;
    }
    
    rs_debug("Egress port %u is member of VLAN %u, allowing", egress_ifindex, vlan_id);
    
    /* Lookup egress port configuration */
    struct rs_port_config *cfg = rs_get_port_config(egress_ifindex);
    if (!cfg) {
        /* No config - pass through unchanged */
        rs_debug("No config for egress port %u, passing through", egress_ifindex);
        return XDP_PASS;
    }
    
    /* Process VLAN tagging based on egress port mode */
    if (process_vlan_egress(ctx, rctx, cfg) < 0) {
        rs_debug("VLAN egress processing failed on port %u", egress_ifindex);
        /* Don't drop - try to send anyway */
    }
    
    /* Update egress statistics */
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    __u32 pkt_len = data_end - data;
    
    __u32 stats_key = egress_ifindex;
    struct rs_stats *stats = bpf_map_lookup_elem(&rs_stats_map, &stats_key);
    if (stats) {
        __sync_fetch_and_add(&stats->tx_packets, 1);
        __sync_fetch_and_add(&stats->tx_bytes, pkt_len);
    }
    
    rs_debug("Egress on port %u: vlan_mode=%u, pkt_len=%u", 
             egress_ifindex, cfg->vlan_mode, pkt_len);
    
    /* Egress pipeline: Tail-call to final module
     * 
     * Stage number convention:
     *   Ingress: 10-90   (vlan=10, l2learn=80, lastcall=90)
     *   Egress:  100-190 (future: egress_qos=110, egress_mirror=120, egress_final=190)
     * 
     * Minimal egress pipeline (current):
     *   rswitch_egress (this) → egress_final (stage 190)
     * 
     * Future egress pipeline:
     *   rswitch_egress → egress_qos → egress_mirror → egress_final
     * 
     * egress_final is responsible for:
     * - Clearing parsed=0 flag (marks processing complete)
     * - Final XDP_PASS return
     */
    
    /* Tail-call to egress pipeline using RS_TAIL_CALL_NEXT macro
     * Loader inserts modules sequentially, macro auto-increments next_prog_id
     */
    RS_TAIL_CALL_NEXT(ctx, rctx);
    
    /* Tail-call failed - should not happen if egress_final is loaded
     * Fall back to direct XDP_PASS (parsed won't be cleared, but packet transmits)
     */
    rs_debug("WARN: Tail-call to egress pipeline failed, passing directly");
    return XDP_PASS;
}

/* Egress hook for mirrored traffic
 * 
 * Simplified version that doesn't modify packet headers.
 * Used when mirroring traffic to monitoring ports.
 */
SEC("xdp/devmap")
int rswitch_egress_mirror(struct xdp_md *ctx)
{
    __u32 egress_ifindex = ctx->egress_ifindex;
    
    /* Update TX statistics (mirrors count as regular TX) */
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    __u32 pkt_len = data_end - data;
    
    __u32 stats_key = egress_ifindex;
    struct rs_stats *stats = bpf_map_lookup_elem(&rs_stats_map, &stats_key);
    if (stats) {
        __sync_fetch_and_add(&stats->tx_packets, 1);
        __sync_fetch_and_add(&stats->tx_bytes, pkt_len);
    }
    
    rs_debug("Mirror egress on port %u: pkt_len=%u", egress_ifindex, pkt_len);
    
    return XDP_PASS;
}
