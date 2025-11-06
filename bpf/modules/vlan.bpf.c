// SPDX-License-Identifier: GPL-2.0
/* 
 * rSwitch VLAN Module
 * 
 * Enforces VLAN policies on ingress traffic:
 * - ACCESS mode: Accept only untagged packets, assign access_vlan
 * - TRUNK mode: Accept tagged (if in allowed list) or untagged (assign native_vlan)
 * - HYBRID mode: Complex rules with separate tagged/untagged allowed lists
 * 
 * This module:
 * 1. Validates VLAN configuration exists (checks vlan_peer_array)
 * 2. Enforces mode-specific ingress filtering
 * 3. Populates rs_ctx->vlan_peers for forwarding decisions
 * 4. Drops packets violating VLAN policy
 */

#include "../include/rswitch_common.h"

char _license[] SEC("license") = "GPL";

// Module metadata for auto-discovery
RS_DECLARE_MODULE(
    "vlan",                     // Module name
    RS_HOOK_XDP_INGRESS,        // Hook point (ingress processing)
    20,                         // Stage number (early in pipeline)
    RS_FLAG_NEED_L2L3_PARSE | RS_FLAG_MAY_DROP,  // Capability flags
    "VLAN ingress policy enforcement (ACCESS/TRUNK/HYBRID modes)"
);

// Helper: Check if VLAN ID exists in allowed list
// 
// *** GOLDEN RULE OF eBPF: ALWAYS CHECK BOUNDS BEFORE ACCESSING MEMORY ***
//
// CRITICAL: Verifier needs to see explicit bounds for each array access!
// Pattern from PoC (src/inc/defs.h:is_in_list) - use == instead of >= for early exit
// This tells verifier we won't access beyond the provided count
//
// The order MUST be: CHECK → BREAK → ACCESS (never ACCESS → CHECK)
static __always_inline int is_vlan_allowed(__u16 vlan_id, __u16 *allowed_list, __u16 count)
{
    if (count == 0)
        return 0;
    
    // PoC pattern: fixed loop bound with early exit using ==
    // This lets verifier track exact iteration count
    int i;
    for (i = 0; i < RS_MAX_ALLOWED_VLANS; i++) {
        // ⚠️ GOLDEN RULE: Check bounds FIRST, access SECOND
        // Use == instead of >= - PoC pattern that verifier understands better
        if (i == count)  // ← Bounds check (executes BEFORE array access)
            break;
        if (allowed_list[i] == vlan_id)  // ← Array access (AFTER bounds check)
            return 1;
    }
    return 0;
}

// Helper: Get effective VLAN ID (tagged or default)
static __always_inline __u16 get_effective_vlan_id(struct rs_ctx *ctx)
{
    // If packet has VLAN tag, use it
    if (ctx->layers.vlan_depth > 0 && ctx->layers.vlan_ids[0] > 0)
        return ctx->layers.vlan_ids[0];
    
    // Otherwise use port's default VLAN based on mode
    struct rs_port_config *port = rs_get_port_config(ctx->ifindex);
    if (!port)
        return 1; // Fallback to VLAN 1
    
    switch (port->vlan_mode) {
    case RS_VLAN_MODE_ACCESS:
        return port->access_vlan;
    case RS_VLAN_MODE_TRUNK:
        return port->native_vlan;
    case RS_VLAN_MODE_HYBRID:
        return port->pvid;
    default:
        return 1;
    }
}

// Helper: Check if port is member of VLAN (using bitmask)
static __always_inline int is_port_in_vlan(struct rs_vlan_members *members, __u32 ifindex, int tagged)
{
    if (!members)
        return 0;
    
    // Compute bitmask position to match loader's calculation
    // Loader uses: word_idx = (ifindex - 1) / 64, bit_idx = (ifindex - 1) % 64
    // So we must use the same formula here
    __u32 word_idx = ((ifindex - 1) / 64) & 3;  // Max 4 words, prevent overflow
    __u64 bit_mask = 1ULL << ((ifindex - 1) % 64);
    
    if (tagged) {
        return (members->tagged_members[word_idx] & bit_mask) != 0;
    } else {
        return (members->untagged_members[word_idx] & bit_mask) != 0;
    }
}

// Helper: Validate VLAN has active peers (not isolated)
static __always_inline int validate_vlan_peers(struct rs_ctx *ctx, __u16 vlan_id, int is_tagged)
{
    // Lookup vlan_peers in map
    __u16 vlan_key = vlan_id;  // Key is __u16
    struct rs_vlan_members *members = bpf_map_lookup_elem(&rs_vlan_map, &vlan_key);
    
    // Drop if VLAN not configured or no members
    if (!members) {
        rs_debug("VLAN %d not configured on switch", vlan_id);
        ctx->error = RS_ERROR_INVALID_VLAN;
        ctx->drop_reason = RS_DROP_VLAN_FILTER;
        return -1;
    }
    
    // Drop if no members
    if (members->member_count == 0) {
        rs_debug("VLAN %d has no members", vlan_id);
        ctx->error = RS_ERROR_INVALID_VLAN;
        ctx->drop_reason = RS_DROP_VLAN_FILTER;
        return -1;
    }
    
    // Check if this port is a member (either tagged or untagged)
    // Don't use is_tagged (packet state) - check if port is in EITHER list
    int is_member = is_port_in_vlan(members, ctx->ifindex, 1) ||  // Check tagged list
                    is_port_in_vlan(members, ctx->ifindex, 0);    // Check untagged list
    
    if (!is_member) {
        rs_debug("Port %d is not a member of VLAN %d", ctx->ifindex, vlan_id);
        ctx->error = RS_ERROR_INVALID_VLAN;
        ctx->drop_reason = RS_DROP_VLAN_FILTER;
        return -1;
    }
    
    // VLAN peers validated, store ingress VLAN
    ctx->ingress_vlan = vlan_id;
    
    return 0;
}

// Main VLAN processing function
SEC("xdp")
int vlan_ingress(struct xdp_md *xdp_ctx)
{
    // Get per-CPU context
    struct rs_ctx *ctx = RS_GET_CTX();
    if (!ctx) {
        rs_debug("Failed to get rs_ctx");
        return XDP_DROP;
    }
    
    // Verify packet was parsed (dispatcher should have done this)
    if (!ctx->parsed) {
        rs_debug("Packet not parsed, cannot process VLAN");
        ctx->error = RS_ERROR_PARSE_FAILED;
        ctx->drop_reason = RS_DROP_PARSE_ERROR;
        return XDP_DROP;
    }
    
    // Get port configuration
    struct rs_port_config *port = rs_get_port_config(ctx->ifindex);
    if (!port) {
        rs_debug("No port config for ifindex %d", ctx->ifindex);
        ctx->error = RS_ERROR_INVALID_VLAN;  // Use existing error code
        ctx->drop_reason = RS_DROP_VLAN_FILTER;
        return XDP_DROP;
    }
    
    // Check if packet is VLAN-tagged
    int is_tagged = (ctx->layers.vlan_depth > 0 && ctx->layers.vlan_ids[0] > 0);
    __u16 effective_vlan = get_effective_vlan_id(ctx);
    
    // DEBUG: Log all packets on trunk port to see if VLAN 10 arrives
    if (port->vlan_mode == RS_VLAN_MODE_TRUNK) {
        rs_debug("TRUNK port %d: is_tagged=%d, vlan_id=%d, effective_vlan=%d, allowed_count=%d",
                 ctx->ifindex, is_tagged, 
                 is_tagged ? ctx->layers.vlan_ids[0] : 0,
                 effective_vlan, port->allowed_vlan_count);
    }
    
    // Extract PCP (Priority Code Point) and DEI (Drop Eligible Indicator) from VLAN tag
    // IEEE 802.1Q TCI format: [PCP:3 bits][DEI:1 bit][VID:12 bits]
    if (is_tagged) {
        void *data = (void *)(long)xdp_ctx->data;
        void *data_end = (void *)(long)xdp_ctx->data_end;
        struct ethhdr *eth = data;
        
        if ((void *)(eth + 1) > data_end)
            return XDP_DROP;
        
        // VLAN header follows Ethernet header
        struct vlan_hdr {
            __be16 h_vlan_TCI;
            __be16 h_vlan_encapsulated_proto;
        } *vhdr = (void *)(eth + 1);
        
        if ((void *)(vhdr + 1) > data_end)
            return XDP_DROP;
        
        // Extract TCI (Tag Control Information)
        __u16 tci = bpf_ntohs(vhdr->h_vlan_TCI);
        
        // Extract PCP (bits 13-15) and DEI (bit 12)
        __u8 pcp = (tci >> 13) & 0x07;  // 3 bits: priority 0-7
        __u8 dei = (tci >> 12) & 0x01;  // 1 bit: drop eligible indicator
        
        // Map PCP to internal priority (0-7, where 7=highest)
        // IEEE 802.1Q default priority mapping:
        //   PCP 0 (Best Effort) -> Priority 1
        //   PCP 1 (Background)  -> Priority 0
        //   PCP 2 (Spare)       -> Priority 2
        //   PCP 3 (Excellent Effort) -> Priority 3
        //   PCP 4 (Controlled Load) -> Priority 4
        //   PCP 5 (Video)       -> Priority 5
        //   PCP 6 (Voice)       -> Priority 6
        //   PCP 7 (Network Control) -> Priority 7
        //
        // For simplicity, we use direct mapping: PCP = Priority
        ctx->prio = pcp;
        
        // Store DEI in ECN field (repurpose for now, as ECN is L3)
        // DEI=1 suggests packet can be dropped under congestion
        // Map to ECN-CE (Congestion Experienced) hint for VOQd
        if (dei) {
            ctx->ecn = 0x03;  // ECN-CE (11b) - packet eligible for drop
        } else {
            ctx->ecn = 0x00;  // Not-ECT (00b) - normal priority
        }
        
        rs_debug("VLAN tag PCP=%u, DEI=%u -> prio=%u, ecn=%u",
                 pcp, dei, ctx->prio, ctx->ecn);
    } else {
        // Untagged packets get default priority (typically 0 = best effort)
        ctx->prio = 0;
        ctx->ecn = 0;
    }
    
    // Validate VLAN has active peers (not isolated)
    if (validate_vlan_peers(ctx, effective_vlan, is_tagged) < 0) {
        // Error details already set by validate_vlan_peers
        return XDP_DROP;
    }
    
    // Mode-specific ingress filtering
    switch (port->vlan_mode) {
    case RS_VLAN_MODE_OFF:
        // VLAN processing disabled - skip validation, proceed to next module
        // This allows switch to operate in "dumb" mode without VLAN enforcement
        rs_debug("VLAN processing disabled on port %d, skipping checks", ctx->ifindex);
        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_DROP;  // Tail-call failed
    
    case RS_VLAN_MODE_ACCESS:
        // ACCESS: Only accept untagged packets
        if (is_tagged) {
            rs_debug("ACCESS port %d received tagged packet (VLAN %d), dropping",
                     ctx->ifindex, ctx->layers.vlan_ids[0]);
            ctx->error = RS_ERROR_INVALID_VLAN;
            ctx->drop_reason = RS_DROP_VLAN_FILTER;
            return XDP_DROP;
        }
        // Untagged packets get access_vlan assigned (already in effective_vlan)
        break;
    
    case RS_VLAN_MODE_TRUNK:
        if (is_tagged) {
            // Tagged: Must be in allowed list
            if (!is_vlan_allowed(ctx->layers.vlan_ids[0], 
                                 port->allowed_vlans, 
                                 port->allowed_vlan_count)) {
                rs_debug("TRUNK port %d received disallowed VLAN %d (allowed_count=%d), dropping",
                         ctx->ifindex, ctx->layers.vlan_ids[0], port->allowed_vlan_count);
                ctx->error = RS_ERROR_INVALID_VLAN;
                ctx->drop_reason = RS_DROP_VLAN_FILTER;
                return XDP_DROP;
            }
            rs_debug("TRUNK port %d: VLAN %d allowed, proceeding", ctx->ifindex, ctx->layers.vlan_ids[0]);
        } else {
            // Untagged: Native VLAN must be in allowed list
            if (!is_vlan_allowed(port->native_vlan, 
                                 port->allowed_vlans, 
                                 port->allowed_vlan_count)) {
                rs_debug("TRUNK port %d native VLAN %d not in allowed list, dropping",
                         ctx->ifindex, port->native_vlan);
                ctx->error = RS_ERROR_INVALID_VLAN;
                ctx->drop_reason = RS_DROP_VLAN_FILTER;
                return XDP_DROP;
            }
        }
        break;
    
    case RS_VLAN_MODE_HYBRID:
        if (is_tagged) {
            // Tagged: Must be in tagged allowed list
            // ⚠️ GOLDEN RULE: Clamp count to actual array size BEFORE loop
            // tagged_vlans[] is only 64 elements, but loop bound is 128
            // Verifier needs proof that we won't access beyond array bounds
            __u16 tagged_count = port->tagged_vlan_count;
            if (tagged_count > 64)  // Bounds check: ensure count ≤ array size
                tagged_count = 64;
            if (!is_vlan_allowed(ctx->layers.vlan_ids[0], 
                                 port->tagged_vlans, 
                                 tagged_count)) {
                rs_debug("HYBRID port %d received disallowed tagged VLAN %d, dropping",
                         ctx->ifindex, ctx->layers.vlan_ids[0]);
                ctx->error = RS_ERROR_INVALID_VLAN;
                ctx->drop_reason = RS_DROP_VLAN_FILTER;
                return XDP_DROP;
            }
        } else {
            // Untagged: PVID must be in untagged allowed list
            // ⚠️ GOLDEN RULE: Clamp count to actual array size BEFORE loop
            // untagged_vlans[] is only 64 elements, but loop bound is 128
            // Verifier needs proof that we won't access beyond array bounds
            __u16 untagged_count = port->untagged_vlan_count;
            if (untagged_count > 64)  // Bounds check: ensure count ≤ array size
                untagged_count = 64;
            if (!is_vlan_allowed(port->pvid, 
                                 port->untagged_vlans, 
                                 untagged_count)) {
                rs_debug("HYBRID port %d PVID %d not in untagged allowed list, dropping",
                         ctx->ifindex, port->pvid);
                ctx->error = RS_ERROR_INVALID_VLAN;
                ctx->drop_reason = RS_DROP_VLAN_FILTER;
                return XDP_DROP;
            }
        }
        break;
    
    default:
        rs_debug("Unknown VLAN mode %d on port %d", port->vlan_mode, ctx->ifindex);
        ctx->error = RS_ERROR_INVALID_VLAN;
        ctx->drop_reason = RS_DROP_VLAN_FILTER;
        return XDP_DROP;
    }
    
    // Packet passed VLAN checks, proceed to next module
    rs_debug("VLAN check passed: port %d, VLAN %d, tagged=%d, mode=%d",
             ctx->ifindex, effective_vlan, is_tagged, port->vlan_mode);
    
    RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
    
    // Tail-call failed, drop
    rs_debug("Vlan: Tail-call to next module failed");
    return XDP_DROP;
}
