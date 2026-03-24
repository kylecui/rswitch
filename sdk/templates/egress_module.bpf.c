// SPDX-License-Identifier: GPL-2.0
/*
 * rSwitch Egress Module Template
 *
 * Egress modules run in the devmap egress hook (after forwarding decision).
 * They process packets just before transmission on the output interface.
 */

#include "rswitch_module.h"

char _license[] SEC("license") = "GPL";

RS_DECLARE_MODULE("egress_mod", RS_HOOK_XDP_EGRESS, 400,
                  RS_FLAG_MODIFIES_PACKET,
                  "Egress module template");

SEC("xdp/devmap")
int egress_module_func(struct xdp_md *xdp_ctx)
{
    struct rs_ctx *ctx = RS_GET_CTX();
    if (!ctx)
        return XDP_PASS; /* Egress: PASS to transmit, DROP to discard */

    /* === EGRESS PROCESSING === */

    /* Egress modules can:
     *   - Modify packet headers (rewrite MACs, add/remove tags)
     *   - Apply egress ACLs
     *   - Update counters
     *   - ctx->egress_ifindex tells you the output interface
     */

    /* === END EGRESS PROCESSING === */

    /* Continue egress pipeline */
    RS_TAIL_CALL_EGRESS(xdp_ctx, ctx);

    /* Default: pass packet for transmission */
    return XDP_PASS;
}
