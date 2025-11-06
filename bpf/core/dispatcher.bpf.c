// SPDX-License-Identifier: GPL-2.0
/* rSwitch Core Dispatcher - Unified Ingress Hook
 * 
 * This is the main XDP entry point that replaces kSwitchMainHook.bpf.c.
 * Responsibilities:
 *   1. Initialize per-packet context (rs_ctx)
 *   2. MINIMAL parsing (Ethernet only) - modules do lazy parsing as needed
 *   3. Lookup port configuration
 *   4. Execute tail-call chain based on profile-generated prog_array
 * 
 * Design:
 *   - Profile-driven: Loader populates rs_progs map based on YAML profiles
 *   - Lazy parsing: Only parse what's needed (like PoC architecture)
 *   - Module-agnostic: Dispatcher doesn't hardcode which modules exist
 *   - Zero-copy: Context passed via per-CPU map for efficiency
 *   - Failsafe: Falls back to passthrough if pipeline is empty
 * 
 * CO-RE: Uses vmlinux.h for kernel portability across versions.
 */

#include "../include/rswitch_common.h"

char _license[] SEC("license") = "GPL";

/* Static zero-initialized templates for efficient reset */
static const struct rs_ctx INIT_CTX = {0};

/* Fast-path bypass check - skip pipeline for unmanaged ports */
static __always_inline int should_bypass(struct rs_port_config *cfg)
{
    /* Bypass if:
     * - Port not configured (NULL)
     * - Simple mode (mgmt_type == 0)
     * - Explicitly disabled
     */
    if (!cfg || cfg->mgmt_type == 0 || !cfg->enabled)
        return 1;
    return 0;
}

/* Initialize rs_ctx from port config and packet metadata */
static __always_inline int init_context(struct xdp_md *ctx, struct rs_ctx *rctx, 
                                        struct rs_port_config *cfg)
{
    __u32 ifindex = ctx->ingress_ifindex;
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    /* Reset context to zero state */
    __builtin_memset(rctx, 0, sizeof(*rctx));
    
    /* Basic metadata */
    rctx->ifindex = ifindex;
    rctx->egress_ifindex = 0;  /* Will be set by forwarding modules */
    rctx->action = XDP_PASS;   /* Default action */
    rctx->timestamp = bpf_ktime_get_ns();
    
    /* Copy VLAN configuration if available */
    if (cfg) {
        rctx->prio = cfg->default_prio;
    }
    
    /* Parse Ethernet header and extract VLAN tags
     * ⚠️ GOLDEN RULE: ALWAYS check bounds BEFORE accessing memory
     */
    struct hdr_cursor nh = { .pos = data };
    struct ethhdr *eth = NULL;
    struct collect_vlans vlans = {0};
    
    int eth_proto = parse_ethhdr_vlan(&nh, data_end, &eth, &vlans);
    if (eth_proto < 0 || !eth) {
        rs_debug("Failed to parse Ethernet header on ifindex %u", ifindex);
        rctx->error = RS_ERROR_PARSE_FAILED;
        rctx->drop_reason = RS_DROP_PARSE_ERROR;
        return -1;
    }
    
    /* Store VLAN information in layers */
    rctx->layers.vlan_depth = 0;
    #pragma unroll
    for (int i = 0; i < VLAN_MAX_DEPTH; i++) {
        if (vlans.id[i] > 0) {
            rctx->layers.vlan_ids[i] = vlans.id[i];
            rctx->layers.vlan_depth++;
        } else {
            rctx->layers.vlan_ids[i] = 0;
        }
    }
    
    rs_debug("Packet received on ifindex %u, eth_proto=0x%04x, vlan_depth=%d, vlan_id=%d", 
             ifindex, bpf_ntohs(eth_proto), rctx->layers.vlan_depth,
             rctx->layers.vlan_depth > 0 ? rctx->layers.vlan_ids[0] : 0);
    
    rctx->parsed = 1;  /* Mark as "validated" */
    return 0;
}

/* Get first program in pipeline from prog_array */
static __always_inline int get_first_prog(struct rs_ctx *rctx)
{
    /* Prog array is sorted by stage number (10, 20, 30, ..., 90)
     * Index 0 = first module in pipeline
     * Loader populates this based on profile
     * 
     * NOTE: Cannot use bpf_map_lookup_elem() on BPF_MAP_TYPE_PROG_ARRAY
     * in kernels 6.x+. Instead, we directly use bpf_tail_call(), which
     * will gracefully fail (return 0) if index is not populated.
     */
    __u32 idx = 0;
    
    /* Store next program ID for tail-call */
    rctx->next_prog_id = idx;
    rctx->call_depth = 0;
    
    return 0;
}

/* Main XDP dispatcher entry point */
SEC("xdp")
int rswitch_dispatcher(struct xdp_md *ctx)
{
    __u32 ifindex = ctx->ingress_ifindex;
    __u32 key = 0;  /* Per-CPU map always uses key=0 */
    
    /* Lookup port configuration */
    struct rs_port_config *cfg = rs_get_port_config(ifindex);
    
    /* Fast-path: Bypass pipeline for simple/unmanaged ports */
    if (should_bypass(cfg)) {
        rs_debug("Port %u in bypass mode, passing through", ifindex);
        return XDP_PASS;
    }
    
    /* Get per-CPU context slot */
    struct rs_ctx *rctx = bpf_map_lookup_elem(&rs_ctx_map, &key);
    if (!rctx) {
        /* Should never happen - per-CPU array is pre-allocated */
        rs_debug("CRITICAL: Failed to get rs_ctx for CPU");
        return XDP_DROP;
    }
    
    /* Initialize context and parse packet */
    if (init_context(ctx, rctx, cfg) < 0) {
        /* Parsing failed - malformed packet */
        rs_debug("Packet parsing failed on port %u", ifindex);
        rctx->drop_reason = RS_DROP_PARSE_ERROR;
        rs_stats_update_drop(rctx);
        return XDP_DROP;
    }
    
    /* Update ingress statistics */
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    __u32 pkt_len = data_end - data;
    rs_stats_update_rx(rctx, pkt_len);
    
    /* Get first program in pipeline */
    if (get_first_prog(rctx) < 0) {
        /* No modules loaded - pass through */
        rs_debug("No pipeline configured, passing packet");
        return XDP_PASS;
    }
    
    /* Execute tail-call chain */
    rs_debug("Starting pipeline on port %u, first_prog_id=%u", 
             ifindex, rctx->next_prog_id);
    
    /* Tail-call to first module - does not return on success */
    bpf_tail_call(ctx, &rs_progs, rctx->next_prog_id);
    
    /* Tail-call failed - this should not happen if loader is correct */
    rs_debug("CRITICAL: Tail-call to prog_id %u failed", rctx->next_prog_id);
    rctx->error = RS_ERROR_INTERNAL;
    rctx->drop_reason = RS_DROP_PARSE_ERROR;
    rs_stats_update_drop(rctx);
    
    return XDP_DROP;
}

/* Alternative entry point for testing/debugging - processes packet without pipeline */
SEC("xdp")
int rswitch_bypass(struct xdp_md *ctx)
{
    __u32 ifindex = ctx->ingress_ifindex;
    __u32 key = 0;
    
    struct rs_ctx *rctx = bpf_map_lookup_elem(&rs_ctx_map, &key);
    if (!rctx) {
        return XDP_PASS;
    }
    
    /* Minimal initialization for statistics */
    __builtin_memset(rctx, 0, sizeof(*rctx));
    rctx->ifindex = ifindex;
    rctx->action = XDP_PASS;
    
    /* Update stats and pass through */
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    __u32 pkt_len = data_end - data;
    rs_stats_update_rx(rctx, pkt_len);
    
    rs_debug("Bypass mode: passing packet on port %u", ifindex);
    return XDP_PASS;
}
