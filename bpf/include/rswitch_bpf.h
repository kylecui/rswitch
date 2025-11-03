/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __RSWITCH_BPF_H
#define __RSWITCH_BPF_H

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
 */
#define BPF_PIN_PATH "/sys/fs/bpf/rswitch"

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
