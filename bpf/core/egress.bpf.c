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

/* REMOVED: All VLAN-specific helper functions moved to egress_vlan module
 * 
 * This devmap egress hook is now a pure entry point with minimal responsibilities:
 * 1. Statistics tracking (basic TX counters)
 * 2. Starting the egress module pipeline
 * 
 * All VLAN processing (isolation checks, tag manipulation) is now handled by
 * the optional egress_vlan module (stage 180). This allows users to choose
 * whether to enable VLAN processing or not via profile configuration.
 */

/* Main egress hook - attached to devmap
 * 
 * Pure entry point with minimal responsibilities:
 * 1. Basic statistics tracking (TX packets/bytes)
 * 2. Starting the egress module pipeline
 * 
 * All feature-specific processing (VLAN, QoS, ACL, etc.) is delegated to
 * pluggable modules loaded via the tail-call pipeline. This allows users to
 * configure which features they need via YAML profiles.
 */
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
    
    rs_debug("Egress on port %u: pkt_len=%u", egress_ifindex, pkt_len);
    
    /* Egress pipeline: Tail-call chain execution
     * 
     * Architecture:
     *   - Egress modules stored in rs_progs[255, 254, 253, ...] (high slots, descending)
     *   - prog_chain[slot] → next_slot for chaining (e.g., chain[255]=254, chain[254]=0)
     *   - prog_chain[0] = first egress module slot (entry point from devmap hook)
     * 
     * Stage conventions (for ordering in YAML profiles):
     *   Ingress: 10-90   (vlan=20, acl=30, route=50, l2learn=80, lastcall=90)
     *   Egress:  100-190 (qos=170, egress_vlan=180, egress_final=190)
     * 
     * Current egress pipeline:
     *   rswitch_egress (devmap hook) → qos (slot 255, stage 170) → 
     *   egress_final (slot 254, stage 190)
     * 
     * Future expansion:
     *   rswitch_egress → qos → egress_vlan → mirror → egress_final
     * 
     * Module responsibilities:
     *   - qos: Priority classification, rate limiting, DSCP marking
     *   - egress_vlan: VLAN tag manipulation based on port mode
     *   - egress_final: Statistics, clear parsed flag, return XDP_PASS
     */
    
    /* Tail-call to egress pipeline
     * 
     * Egress entry (this devmap program) is NOT in rs_progs array - it's attached
     * to devmap directly via bpf_devmap_val.bpf_prog.fd in populate_devmaps().
     * 
     * To enter the egress module pipeline, we:
     * 1. Read prog_chain[0] → first egress module slot (e.g., 255)
     * 2. Set rs_ctx->next_prog_id = slot (for modules to traverse chain)
     * 3. Tail-call to rs_progs[slot]
     * 
     * Loader configures:
     *   prog_chain[0] = 255          (entry: devmap → first module)
     *   prog_chain[255] = 254        (qos → egress_final)
     *   prog_chain[254] = 0          (egress_final → end)
     * 
     * Module execution:
     *   Each module reads prog_chain[current_slot] to find next_slot,
     *   updates rs_ctx->next_prog_id, and tail-calls to rs_progs[next_slot].
     * 
     * Concurrent flooding (BPF_F_BROADCAST):
     *   Multiple cores process same packet to different ports simultaneously.
     *   Each core has its own rs_ctx (per-CPU map), no race condition.
     *   All cores read same prog_chain values (read-only, no writes).
     */
    __u32 chain_key = RS_ONLYKEY;  /* Key 0: devmap entry's next hop */
    __u32 *first_egress_prog = bpf_map_lookup_elem(&rs_prog_chain, &chain_key);
    
    if (!first_egress_prog || *first_egress_prog == 0) {
        /* No egress pipeline configured - pass directly */
        rs_debug("No egress pipeline configured, passing directly");
        return XDP_PASS;
    }
    
    rs_debug("Egress tail-call to prog %u", *first_egress_prog);
    
    if (rctx->call_depth < 32) {
        rctx->call_depth++;
        /* Set next_prog_id so egress modules know their slot for chain traversal */
        rctx->next_prog_id = *first_egress_prog;
        bpf_tail_call(ctx, &rs_progs, *first_egress_prog);
    }
    
    /* Tail-call failed - should not happen if egress modules are loaded
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
