// SPDX-License-Identifier: GPL-2.0
/* 
 * rSwitch Egress Final Module - Last stage of egress pipeline
 * 
 * This is the final module in the egress pipeline (egress_stage=90).
 * It performs cleanup and returns packets to the network.
 * 
 * Responsibilities:
 * - Clear parsed flag (mark processing complete)
 * - Final statistics update (if needed)
 * - Return XDP_PASS to transmit packet
 * 
 * This module is intentionally simple - all complex egress logic
 * (VLAN manipulation, QoS, mirroring) should be in earlier modules.
 * 
 * Architecture:
 * Egress pipeline: rswitch_egress → [future modules] → egress_final
 *                  (dispatcher)                        (this module)
 */

#include "../include/rswitch_common.h"

char _license[] SEC("license") = "GPL";

// Module metadata for auto-discovery
// Stage number convention:
//   Ingress: 10-90
//   Egress:  100-190
RS_DECLARE_MODULE(
    "egress_final",             // Module name
    RS_HOOK_XDP_EGRESS,         // Hook point (egress processing)
    190,                        // Stage number (MUST be last in egress pipeline)
    0,                          // No special flags
    "Final egress processing - clear parsed flag and pass packet"
);

/* Egress final - complete packet processing and transmit */
SEC("xdp")
int egress_final(struct xdp_md *xdp_ctx)
{
    __u32 key = 0;
    
    /* Get per-CPU context */
    struct rs_ctx *ctx = bpf_map_lookup_elem(&rs_ctx_map, &key);
    if (!ctx) {
        /* Should not happen, but don't block packet */
        rs_debug("WARN: No context in egress_final");
        return XDP_PASS;
    }
    
    /* Clear parsed flag - packet processing complete
     * 
     * This is the ONLY place where parsed=0 should be set.
     * 
     * Safe to clear here because:
     * - All ingress modules have finished using the context
     * - All egress modules have finished using the context
     * - User-space tools will no longer see stale data
     * - Next packet will reinitialize the context (per-CPU isolation)
     * 
     * Why here and not earlier?
     * - Ingress dispatcher sets parsed=1 to mark "processing started"
     * - All tail-call modules need parsed=1 to know context is valid
     * - Only the FINAL module (this one) clears it to mark "processing done"
     */
    ctx->parsed = 0;
    
    /* Note: Cannot access xdp_ctx->egress_ifindex here because:
     * - This is a tail-call target (SEC("xdp"))
     * - egress_ifindex is only valid in devmap programs (SEC("xdp/devmap"))
     * - Use ctx->egress_ifindex from rs_ctx instead if needed for debugging
     */
    rs_debug("Egress final: packet processing complete");
    
    /* Transmit packet */
    return XDP_PASS;
}
