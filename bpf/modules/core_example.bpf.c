// SPDX-License-Identifier: GPL-2.0
/*
 * rSwitch CO-RE Example Module
 * 
 * This module demonstrates CO-RE (Compile Once - Run Everywhere) features:
 * - Using vmlinux.h for kernel type definitions
 * - BTF-based field access with automatic relocation
 * - Portable code across kernel versions
 * - Feature detection at load time
 * 
 * CO-RE Benefits:
 * - Single .bpf.o works on kernels 5.8+ (any version with BTF)
 * - No need to recompile for different kernel versions
 * - Automatic struct layout adaptation
 * - Smaller binary size
 */

#include "../include/rswitch_common.h"

enum {
    RS_THIS_STAGE_ID  = 85,
    RS_THIS_MODULE_ID = RS_MOD_USER_BASE + 11,
};

char _license[] SEC("license") = "GPL";

/*
 * Declare this as a monitoring/stats module
 * Stage 85: Runs late in pipeline, after forwarding decision
 */
RS_DECLARE_MODULE("core_stats", RS_HOOK_XDP_INGRESS, 85, 0, 
                  "CO-RE demonstration: portable packet statistics");

/*
 * Per-CPU stats map using CO-RE types
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rs_stats);
} core_stats_map SEC(".maps");

/*
 * Example: Using CO-RE to access xdp_md fields
 * 
 * The bpf_core_read() ensures portable access across kernel versions
 * where struct xdp_md layout might change.
 */
static __always_inline __u32 get_packet_length_core(struct xdp_md *xdp_ctx)
{
    __u32 data, data_end;
    
    /* CO-RE field access - automatically relocated by libbpf */
    bpf_core_read(&data, sizeof(data), &xdp_ctx->data);
    bpf_core_read(&data_end, sizeof(data_end), &xdp_ctx->data_end);
    
    return data_end - data;
}

/*
 * Example: Feature detection using CO-RE
 * 
 * Check if running kernel has specific fields/features.
 * This allows single binary to adapt behavior based on kernel capabilities.
 */
static __always_inline int detect_kernel_features(void)
{
    int features = 0;
    
    /* Check if kernel supports XDP hardware hints (5.18+) */
    if (bpf_core_field_exists(struct xdp_md, rx_queue_index)) {
        features |= (1 << 0);  /* HAS_XDP_QUEUE_INDEX */
        rs_debug("Kernel supports XDP queue index");
    }
    
    /* Check if kernel supports XDP metadata (5.18+) */
    if (bpf_core_field_exists(struct xdp_md, data_meta)) {
        features |= (1 << 1);  /* HAS_XDP_METADATA */
        rs_debug("Kernel supports XDP metadata");
    }
    
    return features;
}

/*
 * Example: Portable network header parsing with CO-RE
 * 
 * Uses CO-RE-aware bounds checking and type-safe header access.
 */
static __always_inline int parse_headers_core(struct xdp_md *xdp_ctx)
{
    void *data = (void *)(long)xdp_ctx->data;
    void *data_end = (void *)(long)xdp_ctx->data_end;
    
    /* Ethernet header - CO-RE ensures correct struct layout */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;
    
    __u16 eth_proto = bpf_ntohs(eth->h_proto);
    
    /* VLAN detection - CO-RE handles different kernel VLAN implementations */
    if (eth_proto == ETH_P_8021Q || eth_proto == ETH_P_8021AD) {
        struct vlan_hdr {
            __be16 h_vlan_TCI;
            __be16 h_vlan_encapsulated_proto;
        } *vlan = (void *)(eth + 1);
        
        if ((void *)(vlan + 1) > data_end)
            return -1;
        
        eth_proto = bpf_ntohs(vlan->h_vlan_encapsulated_proto);
        rs_debug("VLAN detected: TCI=0x%x", bpf_ntohs(vlan->h_vlan_TCI));
    }
    
    /* IPv4/IPv6 - CO-RE ensures portable struct access */
    if (eth_proto == ETH_P_IP) {
        struct iphdr *iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > data_end)
            return -1;
        
        /* CO-RE field access - handles kernel-specific iphdr layouts */
        __u8 protocol;
        bpf_core_read(&protocol, sizeof(protocol), &iph->protocol);
        
        rs_debug("IPv4 packet: proto=%u", protocol);
    } else if (eth_proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6h = (void *)(eth + 1);
        if ((void *)(ip6h + 1) > data_end)
            return -1;
        
        /* CO-RE field access for IPv6 */
        __u8 nexthdr;
        bpf_core_read(&nexthdr, sizeof(nexthdr), &ip6h->nexthdr);
        
        rs_debug("IPv6 packet: nexthdr=%u", nexthdr);
    }
    
    return 0;
}

/*
 * Main XDP program - CO-RE stats collection
 * 
 * This demonstrates a simple stats module using CO-RE for portability.
 */
SEC("xdp")
int core_stats_ingress(struct xdp_md *xdp_ctx)
{
    /* Get packet length using CO-RE helper */
    __u32 pkt_len = get_packet_length_core(xdp_ctx);
    struct rs_ctx *ctx = RS_GET_CTX();
    if (ctx)
        RS_OBS_STAGE_HIT(xdp_ctx, ctx, pkt_len);
    
    /* Parse headers with CO-RE safety */
    if (parse_headers_core(xdp_ctx) < 0) {
        rs_debug("Failed to parse headers");
        return XDP_PASS;
    }
    
    /* Update per-CPU stats */
    __u32 key = 0;
    struct rs_stats *stats = bpf_map_lookup_elem(&core_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->rx_packets, 1);
        __sync_fetch_and_add(&stats->rx_bytes, pkt_len);
    }
    
    /* Continue to next module in pipeline */
    if (ctx) {
        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
    }
    return XDP_PASS;
}

/*
 * Initialization hook (optional)
 * 
 * Could be called from user-space via BPF program test run
 * to perform one-time feature detection.
 */
SEC("xdp")
int core_stats_init(struct xdp_md *xdp_ctx)
{
    int features = detect_kernel_features();
    rs_debug("Detected kernel features: 0x%x", features);
    return XDP_PASS;
}

/*
 * CO-RE Usage Summary for rSwitch Developers:
 * 
 * 1. Include rswitch_bpf.h instead of individual kernel headers
 * 2. Use bpf_core_read() for struct field access when kernel layout might vary
 * 3. Use bpf_core_field_exists() to detect kernel features at load time
 * 4. Use GET_HEADER() macro for safe packet header access
 * 5. Let libbpf handle BTF relocation automatically
 * 
 * CO-RE Requirements:
 * - Kernel 5.8+ with CONFIG_DEBUG_INFO_BTF=y
 * - libbpf 0.6+ with CO-RE support
 * - vmlinux.h generated from target kernel's BTF
 * 
 * Build:
 *   make vmlinux  # Generate vmlinux.h once
 *   make          # Compile with CO-RE support
 * 
 * Deployment:
 *   - Single .bpf.o works on any kernel 5.8+ with BTF
 *   - No recompilation needed for kernel upgrades
 *   - Automatic struct layout adaptation via BTF
 */
