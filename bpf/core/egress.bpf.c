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
            /* Untagged packet - add native VLAN tag */
            if (cfg->native_vlan > 0) {
                if (rs_vlan_push(ctx, cfg->native_vlan, rctx->prio) < 0) {
                    rs_debug("Failed to push native VLAN %u on trunk port %u", 
                             cfg->native_vlan, cfg->ifindex);
                    return -1;
                }
            }
        } else {
            /* Tagged packet - update priority if QoS enabled */
            if (rctx->prio > 0 && rs_vlan_set_priority(ctx, rctx->prio) < 0) {
                rs_debug("Failed to set VLAN priority on trunk port %u", cfg->ifindex);
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
