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
static __always_inline int ip_checksum(struct iphdr *iph, void *data_end, __u16 *out)
{
    __u32 sum = 0;
    __u16 *p;
    int ihl;

    /* 至少要能访问完整的 20 字节基础头 */
    if ((void *)(iph + 1) > data_end) {
        rs_debug("Egress final: IP header truncated, cannot compute checksum");
        return -1;
    }

    /* IHL 在低 4 bit */
    ihl = iph->ihl & 0x0f;
    if (ihl < 5) {
        rs_debug("Egress final: IP header IHL too small (ihl = %d), cannot compute checksum", ihl);
        return -1;
    }
    if (ihl > 15) {
        rs_debug("Egress final: IP header IHL too large, cannot compute checksum");
        return -1;   /* RFC 791 最大 60 字节 */
    }
    p = (__u16 *)iph;

    /*
     * IPv4 头部 20 字节 = 10 个 16-bit words：
     *
     *  word 0 : ver/ihl, tos
     *  word 1 : tot_len
     *  word 2 : id
     *  word 3 : frag_off
     *  word 4 : ttl, protocol
     *  word 5 : check         <-- 这里要当作 0
     *  word 6 : saddr[15:0]
     *  word 7 : saddr[31:16]
     *  word 8 : daddr[15:0]
     *  word 9 : daddr[31:16]
     */

    /* 先累加 0~4 */
    sum += p[0];
    sum += p[1];
    sum += p[2];
    sum += p[3];
    sum += p[4];

    /* word 5 (checksum) 当成 0，不累加 */

    /* 确认可以访问到 word 9 （偏移 18，最后一个字节偏移 19） */
    if ((void *)iph + 20 > data_end) { 
        rs_debug("Egress final: IP header truncated before daddr, cannot compute checksum");
        return -1;
    }

    /* 再累加 6~9（源/目的地址） */
    sum += p[6];
    sum += p[7];
    sum += p[8];
    sum += p[9];

    /* 处理 IP options（ihl > 5 的情况） */
    if (ihl > 5) {
        /*
         * 额外头长 = (ihl - 5) * 4 字节
         * 多出来的 16-bit word 下标范围：10 .. 9 + (ihl - 5) * 2
         * 为了让 verifier 好推理，每一段访问前都做“iph + 常量偏移”检查。
         */

        /* ihl >= 6 → 头长 >= 24 字节 → 额外 bytes: 20..23 → words 10, 11 */
        if (ihl >= 6) {
            if ((void *)iph + 24 > data_end) {
                rs_debug("Egress final: IP header truncated in options/6, cannot compute checksum");
                return -1;
            }
            sum += p[10];
            sum += p[11];
        }

        /* ihl >= 7 → 头长 >= 28 字节 → bytes: 24..27 → words 12, 13 */
        if (ihl >= 7) {
            if ((void *)iph + 28 > data_end) {
                rs_debug("Egress final: IP header truncated in options/7, cannot compute checksum");
                return -1;
            }
            sum += p[12];
            sum += p[13];
        }

        /* ihl >= 8 → 头长 >= 32 字节 → bytes: 28..31 → words 14, 15 */
        if (ihl >= 8) {
            if ((void *)iph + 32 > data_end) {
                rs_debug("Egress final: IP header truncated in options/8, cannot compute checksum");
                return -1;
            }
            sum += p[14];
            sum += p[15];
        }

        /* ihl >= 9 → 头长 >= 36 字节 → bytes: 32..35 → words 16, 17 */
        if (ihl >= 9) {
            if ((void *)iph + 36 > data_end) {
                rs_debug("Egress final: IP header truncated in options/9, cannot compute checksum");
                return -1;
            }
            sum += p[16];
            sum += p[17];
        }

        /* ihl >= 10 → 头长 >= 40 字节 → bytes: 36..39 → words 18, 19 */
        if (ihl >= 10) {
            if ((void *)iph + 40 > data_end) {
                rs_debug("Egress final: IP header truncated in options/10, cannot compute checksum");
                return -1;
            }
            sum += p[18];
            sum += p[19];
        }

        /* ihl >= 11 → 头长 >= 44 字节 → bytes: 40..43 → words 20, 21 */
        if (ihl >= 11) {
            if ((void *)iph + 44 > data_end) {
                rs_debug("Egress final: IP header truncated in options/11, cannot compute checksum");
                return -1;
            }
            sum += p[20];
            sum += p[21];
        }

        /* ihl >= 12 → 头长 >= 48 字节 → bytes: 44..47 → words 22, 23 */
        if (ihl >= 12) {
            if ((void *)iph + 48 > data_end) {
                rs_debug("Egress final: IP header truncated in options/12, cannot compute checksum");
                return -1;
            }
            sum += p[22];
            sum += p[23];
        }

        /* ihl >= 13 → 头长 >= 52 字节 → bytes: 48..51 → words 24, 25 */
        if (ihl >= 13) {
            if ((void *)iph + 52 > data_end) {
                rs_debug("Egress final: IP header truncated in options/13, cannot compute checksum");
                return -1;
            }   
            sum += p[24];
            sum += p[25];
        }

        /* ihl >= 14 → 头长 >= 56 字节 → bytes: 52..55 → words 26, 27 */
        if (ihl >= 14) {
            if ((void *)iph + 56 > data_end) {
                rs_debug("Egress final: IP header truncated in options/14, cannot compute checksum");
                return -1;
            }
            sum += p[26];
            sum += p[27];
        }

        /* ihl >= 15 → 头长 = 60 字节 → bytes: 56..59 → words 28, 29 */
        if (ihl >= 15) {
            if ((void *)iph + 60 > data_end) {
                rs_debug("Egress final: IP header truncated in options/15, cannot compute checksum");
                return -1;
            }
            sum += p[28];
            sum += p[29];
        }
    }

    /* 折叠 32-bit sum 到 16 bit */
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);

    /* 返回“头部 checksum（假定 checksum 字段为 0 重新计算出来的值）” */
    *out = (__u16)~sum;
    return 0;
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
    /* Get per-CPU context */
    struct rs_ctx *ctx = RS_GET_CTX();
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
            __u16 correct_cksum;
            if (ip_checksum(iph, data_end, &correct_cksum) < 0) {
                rs_debug("Egress final: Invalid IP header, cannot compute checksum");
                update_final_stat(EGRESS_FINAL_NON_IP);
                return XDP_DROP;
            }
            
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
