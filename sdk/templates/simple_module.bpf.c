// SPDX-License-Identifier: GPL-2.0
/*
 * rSwitch Simple Module Template
 *
 * A minimal ingress module that demonstrates the basic structure.
 * Replace 'my_module' with your module name throughout this file.
 *
 * Build: make -f Makefile.module MODULE=my_module
 */

#include "rswitch_module.h"

char _license[] SEC("license") = "GPL";

/* Module declaration:
 *   Name: "my_module"
 *   Hook: RS_HOOK_XDP_INGRESS (ingress pipeline)
 *   Stage: 35 (between ACL and mirror - adjust as needed)
 *   Flags: RS_FLAG_NEED_L2L3_PARSE (requires parsed L2/L3 headers)
 *   Description: Brief description of what this module does
 *
 * See module_abi.h for stage conventions and available flags.
 *
 * Stage ranges:
 *   Core ingress: 10-99    Core egress: 100-199
 *   User ingress: 200-299  User egress: 400-499
 */
RS_DECLARE_MODULE("my_module", RS_HOOK_XDP_INGRESS, 200,
                  RS_FLAG_NEED_L2L3_PARSE,
                  "Template module - replace with your description");

/* Optional: Declare dependencies on other modules
 * RS_DEPENDS_ON("vlan");  // This module requires VLAN processing first
 */

SEC("xdp")
int my_module_func(struct xdp_md *xdp_ctx)
{
    /* Get the rSwitch context (passed between modules via per-CPU map) */
    struct rs_ctx *ctx = RS_GET_CTX();
    if (!ctx)
        return XDP_DROP;

    /* Access parsed headers from ctx->layers:
     *   ctx->layers.l2_offset   - Ethernet header offset
     *   ctx->layers.l3_offset   - IP header offset (if parsed)
     *   ctx->layers.l4_offset   - L4 header offset (if parsed)
     *   ctx->layers.l3_proto    - L3 protocol (ETH_P_IP, ETH_P_IPV6, etc.)
     *   ctx->layers.l4_proto    - L4 protocol (IPPROTO_TCP, IPPROTO_UDP, etc.)
     *   ctx->layers.vlan_ids[0] - VLAN ID (if present)
     */

    /* === YOUR MODULE LOGIC HERE === */

    /* Example: Read packet data
     * void *data = (void *)(long)xdp_ctx->data;
     * void *data_end = (void *)(long)xdp_ctx->data_end;
     * struct ethhdr *eth = data;
     * if ((void *)(eth + 1) > data_end) return XDP_DROP;
     */

    /* === END MODULE LOGIC === */

    /* Continue to next module in pipeline */
    RS_TAIL_CALL_NEXT(xdp_ctx, ctx);

    /* If tail call fails, drop packet (should not happen in normal operation) */
    return XDP_DROP;
}
