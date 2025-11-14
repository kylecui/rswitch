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
// Egress modules use reconfigurable chain - loader assigns prog_id slots dynamically
RS_DECLARE_MODULE(
    "egress_final",             // Module name
    RS_HOOK_XDP_EGRESS,         // Hook point (egress processing)
    190,                        // Stage number (high value = runs last)
    0,                          // No special flags
    "Final egress: checksum validation and transmission"
);

/* Calculate IP header checksum from scratch (for verification) */
static __always_inline __u16 ip_checksum(struct iphdr *iph)
{
    __u32 sum = 0;
    __u16 *p = (__u16 *)iph;
    
    /* IP header is always 20-60 bytes (5-15 32-bit words)
     * Most common case: 20 bytes (5 words = 10 16-bit words)
     * 
     * For simplicity and BPF verifier compatibility, we always
     * process the standard 20-byte header (10 words).
     * Options (if present) are rare and not critical for checksum
     * validation in our use case.
     */
    int ihl = iph->ihl;
    if (ihl < 5)
        return 0;  /* Invalid header length */
    
    /* Checksum field should be zero for calculation */
    __u16 saved_check = iph->check;
    iph->check = 0;
    
    /* Sum standard IP header (20 bytes = 10 words)
     * This covers version+ihl, tos, total_len, id, frag_off,
     * ttl+protocol, checksum, saddr, daddr */
    sum += p[0];  /* version+ihl, tos */
    sum += p[1];  /* total_len */
    sum += p[2];  /* id */
    sum += p[3];  /* frag_off */
    sum += p[4];  /* ttl+protocol, checksum */
    sum += p[5];  /* saddr[0:1] */
    sum += p[6];  /* saddr[2:3] */
    sum += p[7];  /* daddr[0:1] */
    sum += p[8];  /* daddr[2:3] */
    sum += p[9];  /* options (if any) or padding */
    
    /* Handle options if header is larger (uncommon, but check anyway)
     * Only process if ihl > 5 (more than 20 bytes) */
    if (ihl > 5) {
        /* Options are in words 10-29 (up to 40 more bytes)
         * For performance, we only check up to ihl=10 (40 bytes total) */
        if (ihl >= 6)  sum += p[10];
        if (ihl >= 7)  sum += p[11] + p[12];
        if (ihl >= 8)  sum += p[13] + p[14];
        if (ihl >= 9)  sum += p[15] + p[16];
        if (ihl >= 10) sum += p[17] + p[18];
        /* ihl > 10 is extremely rare, skip for simplicity */
    }
    
    /* Restore original checksum */
    iph->check = saved_check;
    
    /* Fold 32-bit sum to 16 bits */
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    
    return (__u16)~sum;
}

/* Statistics for checksum validation */
enum egress_final_stat {
    EGRESS_FINAL_PACKETS = 0,
    EGRESS_FINAL_CKSUM_OK = 1,
    EGRESS_FINAL_CKSUM_FIXED = 2,
    EGRESS_FINAL_NON_IP = 3,
    EGRESS_FINAL_STAT_MAX = 4,
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, EGRESS_FINAL_STAT_MAX);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} egress_final_stats SEC(".maps");

static __always_inline void update_final_stat(__u32 stat_id)
{
    __u64 *counter = bpf_map_lookup_elem(&egress_final_stats, &stat_id);
    if (counter) {
        __sync_fetch_and_add(counter, 1);
    }
}

/* Egress final - complete packet processing and transmit */
SEC("xdp/devmap")
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
    
    update_final_stat(EGRESS_FINAL_PACKETS);
    
    /* Verify and fix IP checksum if this is an IPv4 packet
     * This catches any checksum errors from earlier modules (e.g., QoS DSCP rewriting)
     */
    if (ctx->layers.eth_proto == ETH_P_IP && ctx->layers.l3_offset != 0) {
        void *data = (void *)(long)xdp_ctx->data;
        void *data_end = (void *)(long)xdp_ctx->data_end;
        
        struct iphdr *iph = data + (ctx->layers.l3_offset & RS_L3_OFFSET_MASK);
        if ((void *)(iph + 1) <= data_end) {
            /* Calculate correct checksum */
            __u16 correct_cksum = ip_checksum(iph);
            
            if (iph->check != correct_cksum) {
                rs_debug("Egress final: Bad IP checksum 0x%04x, fixing to 0x%04x",
                         bpf_ntohs(iph->check), bpf_ntohs(correct_cksum));
                iph->check = correct_cksum;
                update_final_stat(EGRESS_FINAL_CKSUM_FIXED);
            } else {
                update_final_stat(EGRESS_FINAL_CKSUM_OK);
            }
        }
    } else {
        update_final_stat(EGRESS_FINAL_NON_IP);
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
