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
static __always_inline __u16 ip_checksum(struct iphdr *iph, void *data_end)
{
    __u32 sum = 0;
    __u16 *p = (__u16 *)iph;
    
    /* IP header is always 20-60 bytes (5-15 32-bit words)
     * Most common case: 20 bytes (5 words = 10 16-bit words)
     * 
     * For BPF verifier, we need to verify bounds for each access.
     * We always sum the standard 20-byte header, then conditionally
     * add options if present and verified.
     */
    int ihl = iph->ihl;
    if (ihl < 5)
        return 0;  /* Invalid header length */
    
    /* Checksum field should be zero for calculation */
    __u16 saved_check = iph->check;
    iph->check = 0;
    
    /* Verify we can access standard IP header (20 bytes = 10 words)
     * BPF verifier: (void *)(iph + 1) means iph[0..19] is safe */
    if ((void *)(iph + 1) > data_end) {
        iph->check = saved_check;
        return 0;
    }
    
    /* Sum standard IP header (20 bytes = 10 words)
     * Manually unrolled for BPF verifier */
    sum += p[0];  /* version+ihl, tos */
    sum += p[1];  /* total_len */
    sum += p[2];  /* id */
    sum += p[3];  /* frag_off */
    sum += p[4];  /* ttl+protocol, checksum */
    sum += p[5];  /* saddr[0:1] */
    sum += p[6];  /* saddr[2:3] */
    sum += p[7];  /* daddr[0:1] */
    sum += p[8];  /* daddr[2:3] */
    sum += p[9];  /* first 2 bytes of options (if any) */
    
    /* Handle IP options if header is larger (uncommon)
     * Must verify bounds before each access beyond standard header */
    if (ihl > 5) {
        /* Options start at byte 20 (word 10)
         * Each ihl unit = 4 bytes = 2 words
         * Max options = 40 bytes (ihl=15) = 20 additional words */
        
        /* Verify we can access up to ihl*4 bytes (ihl*2 words) */
        void *options_end = (void *)iph + (ihl * 4);
        if (options_end > data_end) {
            /* Options extend beyond packet, only checksum what we have */
            iph->check = saved_check;
            goto fold_checksum;
        }
        
        /* Now safe to access options (words 10-29)
         * Use conditional checks for each group to help verifier */
        if (ihl >= 6)  sum += p[10];
        if (ihl >= 7)  { sum += p[11]; sum += p[12]; }
        if (ihl >= 8)  { sum += p[13]; sum += p[14]; }
        if (ihl >= 9)  { sum += p[15]; sum += p[16]; }
        if (ihl >= 10) { sum += p[17]; sum += p[18]; }
        if (ihl >= 11) { sum += p[19]; sum += p[20]; }
        if (ihl >= 12) { sum += p[21]; sum += p[22]; }
        if (ihl >= 13) { sum += p[23]; sum += p[24]; }
        if (ihl >= 14) { sum += p[25]; sum += p[26]; }
        if (ihl >= 15) { sum += p[27]; sum += p[28]; sum += p[29]; }
        /* ihl > 15 is invalid per RFC 791 */
    }
    
fold_checksum:
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
        
        /* Apply mask to help verifier prove bounds (see BPF Verifier 调优技巧 doc)
         * L3 offset is typically 14-22 bytes (Ethernet + optional VLAN tags)
         * 0x3F (63) is sufficient to cover all reasonable cases */
        __u16 l3_off = ctx->layers.l3_offset & 0x3F;
        struct iphdr *iph = data + l3_off;
        
        /* Verify minimum IP header (20 bytes) is within packet bounds */
        if ((void *)(iph + 1) <= data_end) {
            /* Calculate correct checksum */
            __u16 correct_cksum = ip_checksum(iph, data_end);
            
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
