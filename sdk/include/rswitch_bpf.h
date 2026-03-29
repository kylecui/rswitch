/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __RSWITCH_BPF_H
#define __RSWITCH_BPF_H

#warning "rswitch_bpf.h is deprecated. Use #include <rswitch_module.h> instead. See sdk/docs/SDK_Migration_Guide.md"

/*
 * rSwitch BPF Common Header with CO-RE Support
 * 
 * This header provides unified kernel type definitions using vmlinux.h
 * for Compile Once - Run Everywhere (CO-RE) compatibility.
 * 
 * Benefits of CO-RE:
 * - Single BPF binary works across different kernel versions
 * - Automatic field offset relocation via BTF
 * - No dependency on kernel headers during compilation
 * - Smaller binary size (no duplicate type definitions)
 * 
 * Usage:
 *   #include "rswitch_bpf.h"  // Instead of individual kernel headers
 */

/* Core kernel types from vmlinux.h (CO-RE) */
#include "vmlinux.h"

/* libbpf helpers and macros */
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include "map_defs.h"

#ifndef RS_API_STABLE
#define RS_API_STABLE
#endif

#ifndef RS_API_EXPERIMENTAL
#define RS_API_EXPERIMENTAL
#endif

#ifndef RS_API_INTERNAL
#define RS_API_INTERNAL
#endif

#ifndef RS_DEPRECATED
#define RS_DEPRECATED(msg) __attribute__((deprecated(msg)))
#endif

/*
 * API stability annotations for symbols provided by core headers:
 * RS_API_STABLE: RS_GET_CTX, RS_TAIL_CALL_NEXT, RS_TAIL_CALL_EGRESS,
 * RS_EMIT_EVENT, rs_get_port_config, rs_mac_lookup, rs_mac_update,
 * rs_is_vlan_member, rs_stats_update_rx, rs_stats_update_drop,
 * RS_ERROR_*, RS_DROP_*
 * RS_API_INTERNAL: RS_ONLYKEY and direct internal map access patterns
 */

/* Common network protocol constants not in vmlinux.h */
#ifndef ETH_P_IP
#define ETH_P_IP    0x0800
#endif

#ifndef ETH_P_IPV6
#define ETH_P_IPV6  0x86DD
#endif

#ifndef ETH_P_ARP
#define ETH_P_ARP   0x0806
#endif

#ifndef ETH_P_8021Q
#define ETH_P_8021Q 0x8100
#endif

#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8
#endif

#ifndef IPPROTO_TCP
#define IPPROTO_TCP  6
#endif

#ifndef IPPROTO_UDP
#define IPPROTO_UDP  17
#endif

#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif

#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif

/* XDP action return codes (always available) */
#ifndef XDP_ABORTED
#define XDP_ABORTED 0
#endif

#ifndef XDP_DROP
#define XDP_DROP 1
#endif

#ifndef XDP_PASS
#define XDP_PASS 2
#endif

#ifndef XDP_TX
#define XDP_TX 3
#endif

#ifndef XDP_REDIRECT
#define XDP_REDIRECT 4
#endif

/* Common BPF map flags */
#ifndef BPF_ANY
#define BPF_ANY     0
#endif

#ifndef BPF_NOEXIST
#define BPF_NOEXIST 1
#endif

#ifndef BPF_EXIST
#define BPF_EXIST   2
#endif

/*
 * CO-RE Helper Macros
 * 
 * These macros ensure portable field access across kernel versions.
 */

/* Read field with CO-RE relocation */
#define READ_KERN(dst, src) bpf_core_read(&(dst), sizeof(dst), &(src))

/* Check if field exists in kernel struct */
#define FIELD_EXISTS(type, field) bpf_core_field_exists(((type *)0)->field)

/* Get field size with CO-RE */
#define FIELD_SIZE(type, field) bpf_core_field_size(((type *)0)->field)

/*
 * Network Packet Parsing Helpers
 * 
 * These use CO-RE-aware pointer arithmetic for portability.
 */

/* Bounds check for packet data access */
#define CHECK_BOUNDS(ctx, ptr, size) \
    ((void *)(ptr) + (size) <= (void *)(long)(ctx)->data_end)

/* Safe packet header access */
#define GET_HEADER(ctx, ptr, type) \
    ({ \
        type *_h = (type *)(ptr); \
        if (!CHECK_BOUNDS(ctx, _h, sizeof(type))) \
            _h = NULL; \
        _h; \
    })

/*
 * Debug Macros (conditional on DEBUG flag)
 */
#ifdef DEBUG
#define bpf_debug(fmt, ...) \
    bpf_printk("[rSwitch] " fmt, ##__VA_ARGS__)
#else
#define bpf_debug(fmt, ...) do { } while (0)
#endif

/*
 * Compiler Hints for BPF Verifier
 */

/* Loop unrolling hint */
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

/* Prevent inlining (for debugging) */
#ifndef __noinline
#define __noinline __attribute__((noinline))
#endif

/* Mark code as unlikely (for error paths) */
#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

/* Mark code as likely (for fast paths) */
#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif

/*
 * BPF Map Pin Path Macros
 * 
 * Using default LIBBPF path without subdirectory isolation.
 * Maps with LIBBPF_PIN_BY_NAME are pinned directly to /sys/fs/bpf/<map_name>
 */
#define BPF_PIN_PATH "/sys/fs/bpf"

/*
 * Common Network Structure Helpers
 */

/* Ethernet header wrapper with CO-RE safety */
static __always_inline struct ethhdr *
get_ethhdr(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    
    if ((void *)(eth + 1) > data_end)
        return NULL;
    
    return eth;
}

/* IPv4 header wrapper with CO-RE safety */
static __always_inline struct iphdr *
get_iphdr(struct xdp_md *ctx, void *l3_offset)
{
    void *data_end = (void *)(long)ctx->data_end;
    struct iphdr *iph = l3_offset;
    
    if ((void *)(iph + 1) > data_end)
        return NULL;
    
    /* Verify IP header length */
    if ((void *)iph + (iph->ihl * 4) > data_end)
        return NULL;
    
    return iph;
}

/* IPv6 header wrapper with CO-RE safety */
static __always_inline struct ipv6hdr *
get_ipv6hdr(struct xdp_md *ctx, void *l3_offset)
{
    void *data_end = (void *)(long)ctx->data_end;
    struct ipv6hdr *ip6h = l3_offset;
    
    if ((void *)(ip6h + 1) > data_end)
        return NULL;
    
    return ip6h;
}

/* TCP header wrapper with CO-RE safety */
static __always_inline struct tcphdr *
get_tcphdr(struct xdp_md *ctx, void *l4_offset)
{
    void *data_end = (void *)(long)ctx->data_end;
    struct tcphdr *tcph = l4_offset;
    
    if ((void *)(tcph + 1) > data_end)
        return NULL;
    
    /* Verify TCP header length (data offset field) */
    if ((void *)tcph + (tcph->doff * 4) > data_end)
        return NULL;
    
    return tcph;
}

/* UDP header wrapper with CO-RE safety */
static __always_inline struct udphdr *
get_udphdr(struct xdp_md *ctx, void *l4_offset)
{
    void *data_end = (void *)(long)ctx->data_end;
    struct udphdr *udph = l4_offset;
    
    if ((void *)(udph + 1) > data_end)
        return NULL;
    
    return udph;
}

/*
 * CO-RE Feature Detection
 * 
 * Check if kernel supports specific features at load time.
 */

/* Example: Check if sk_buff has tstamp field (for timestamping) */
#define HAS_SKB_TSTAMP() \
    bpf_core_field_exists(struct sk_buff, tstamp)

/* Example: Check if net_device has xdp_prog (for XDP detection) */
#define HAS_XDP_PROG() \
    bpf_core_field_exists(struct net_device, xdp_prog)

static __always_inline struct rs_module_config_value *
rs_get_module_config(const char *module_name, const char *param_name)
{
    struct rs_module_config_key key = {};

#pragma unroll
    for (int i = 0; i < RS_MODULE_CONFIG_KEY_LEN; i++) {
        char c = module_name[i];
        key.module_name[i] = c;
        if (c == '\0')
            break;
    }

#pragma unroll
    for (int i = 0; i < RS_MODULE_CONFIG_KEY_LEN; i++) {
        char c = param_name[i];
        key.param_name[i] = c;
        if (c == '\0')
            break;
    }

    return bpf_map_lookup_elem(&rs_module_config_map, &key);
}

RS_API_EXPERIMENTAL static __always_inline void
rs_module_stats_update(__u32 module_idx, __u64 bytes, int forwarded)
{
    struct rs_module_stats *stats;

    stats = bpf_map_lookup_elem(&rs_module_stats_map, &module_idx);
    if (!stats)
        return;

    __sync_fetch_and_add(&stats->packets_processed, 1);
    __sync_fetch_and_add(&stats->bytes_processed, bytes);
    if (forwarded)
        __sync_fetch_and_add(&stats->packets_forwarded, 1);
    else
        __sync_fetch_and_add(&stats->packets_dropped, 1);
    stats->last_seen_ns = bpf_ktime_get_ns();
}

RS_API_EXPERIMENTAL static __always_inline void
rs_module_stats_error(__u32 module_idx)
{
    struct rs_module_stats *stats;

    stats = bpf_map_lookup_elem(&rs_module_stats_map, &module_idx);
    if (!stats)
        return;

    __sync_fetch_and_add(&stats->packets_error, 1);
}

/*
 * Endianness Conversion Macros
 * (Already provided by bpf_endian.h, but listed for reference)
 * 
 * - bpf_htons(x): host to network short
 * - bpf_htonl(x): host to network long
 * - bpf_ntohs(x): network to host short
 * - bpf_ntohl(x): network to host long
 */

#endif /* __RSWITCH_BPF_H */
