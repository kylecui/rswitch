/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * rSwitch Module Helpers — BPF Helper Functions and Macros
 *
 * Provides packet parsing helpers, CO-RE macros, pipeline control macros
 * (RS_GET_CTX, RS_TAIL_CALL_NEXT, RS_TAIL_CALL_EGRESS, RS_EMIT_EVENT),
 * and compiler hints for BPF module development.
 *
 * Requires vmlinux.h and libbpf headers (included automatically).
 * Requires rswitch_abi.h for struct definitions (included automatically).
 *
 * Does NOT pull in BPF map definitions — use rswitch_maps.h for that.
 */

#ifndef __RSWITCH_HELPERS_H
#define __RSWITCH_HELPERS_H

/* ── Dependencies ──────────────────────────────────────────────── */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

#include "rswitch_abi.h"

/* ── Protocol constants (not in vmlinux.h) ─────────────────────── */

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

/* ── XDP action codes ──────────────────────────────────────────── */

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

/* ── BPF map flags ─────────────────────────────────────────────── */

#ifndef BPF_ANY
#define BPF_ANY     0
#endif

#ifndef BPF_NOEXIST
#define BPF_NOEXIST 1
#endif

#ifndef BPF_EXIST
#define BPF_EXIST   2
#endif

/* ── CO-RE helper macros ───────────────────────────────────────── */

#define READ_KERN(dst, src) bpf_core_read(&(dst), sizeof(dst), &(src))
#define FIELD_EXISTS(type, field) bpf_core_field_exists(((type *)0)->field)
#define FIELD_SIZE(type, field) bpf_core_field_size(((type *)0)->field)

/* ── Packet bounds checking ────────────────────────────────────── */

#define CHECK_BOUNDS(ctx, ptr, size) \
    ((void *)(ptr) + (size) <= (void *)(long)(ctx)->data_end)

#define GET_HEADER(ctx, ptr, type) \
    ({ \
        type *_h = (type *)(ptr); \
        if (!CHECK_BOUNDS(ctx, _h, sizeof(type))) \
            _h = NULL; \
        _h; \
    })

/* ── Compiler hints for BPF verifier ───────────────────────────── */

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#ifndef __noinline
#define __noinline __attribute__((noinline))
#endif

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif

/* ── Debug macros ──────────────────────────────────────────────── */

#ifdef DEBUG
#define bpf_debug(fmt, ...) \
    bpf_printk("[rSwitch] " fmt, ##__VA_ARGS__)
#else
#define bpf_debug(fmt, ...) do { } while (0)
#endif

/* ── Map pin path ──────────────────────────────────────────────── */

/*
 * Canonical BPF map pin path.
 * - Core rSwitch maps: pin to /sys/fs/bpf/ with rs_ prefix (flat).
 * - Downstream project maps: pin to /sys/fs/bpf/<project>/ subdirectory
 *   for namespace isolation (e.g., /sys/fs/bpf/my_project/my_map).
 * See docs/development/MAP_PINNING.md for the full convention.
 */
#define BPF_PIN_PATH "/sys/fs/bpf"

/* ── Packet parsing helpers ────────────────────────────────────── */

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

static __always_inline struct iphdr *
get_iphdr(struct xdp_md *ctx, void *l3_offset)
{
    void *data_end = (void *)(long)ctx->data_end;
    struct iphdr *iph = l3_offset;

    if ((void *)(iph + 1) > data_end)
        return NULL;

    if ((void *)iph + (iph->ihl * 4) > data_end)
        return NULL;

    return iph;
}

static __always_inline struct ipv6hdr *
get_ipv6hdr(struct xdp_md *ctx, void *l3_offset)
{
    void *data_end = (void *)(long)ctx->data_end;
    struct ipv6hdr *ip6h = l3_offset;

    if ((void *)(ip6h + 1) > data_end)
        return NULL;

    return ip6h;
}

static __always_inline struct tcphdr *
get_tcphdr(struct xdp_md *ctx, void *l4_offset)
{
    void *data_end = (void *)(long)ctx->data_end;
    struct tcphdr *tcph = l4_offset;

    if ((void *)(tcph + 1) > data_end)
        return NULL;

    if ((void *)tcph + (tcph->doff * 4) > data_end)
        return NULL;

    return tcph;
}

static __always_inline struct udphdr *
get_udphdr(struct xdp_md *ctx, void *l4_offset)
{
    void *data_end = (void *)(long)ctx->data_end;
    struct udphdr *udph = l4_offset;

    if ((void *)(udph + 1) > data_end)
        return NULL;

    return udph;
}

/* ── CO-RE feature detection ───────────────────────────────────── */

#define HAS_SKB_TSTAMP() \
    bpf_core_field_exists(struct sk_buff, tstamp)

#define HAS_XDP_PROG() \
    bpf_core_field_exists(struct net_device, xdp_prog)

/* ── Pipeline control macros ───────────────────────────────────── *
 *
 * These macros require the rs_ctx_map, rs_progs, rs_prog_chain, and
 * rs_event_bus maps to be available. They are defined as forward
 * references here; the actual map instances come from either:
 *   - rswitch_maps.h (when included directly), or
 *   - the core build system (map_defs.h / uapi.h) for core modules.
 *
 * For standalone SDK modules that don't include rswitch_maps.h,
 * these macros still work because the module's BPF object will be
 * linked against the pinned maps at load time by the rSwitch loader.
 */

/* Forward-declare the maps needed by pipeline macros.
 * If rswitch_maps.h is also included, these externs are harmless
 * because the actual definitions will take precedence. */
#ifndef __RSWITCH_MAPS_H
extern struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rs_ctx);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_ctx_map SEC(".maps");

extern struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, RS_MAX_PROGS);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_progs SEC(".maps");

extern struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, RS_MAX_PROGS);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_prog_chain SEC(".maps");

extern struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_event_bus SEC(".maps");
#endif /* !__RSWITCH_MAPS_H */

/* Get per-CPU context (call at start of each module) */
#define RS_GET_CTX() ({ \
    __u32 __key = RS_ONLYKEY; \
    bpf_map_lookup_elem(&rs_ctx_map, &__key); \
})

/*
 * Check if the rSwitch pipeline is active.
 * Returns true if rs_ctx_map is populated (pipeline initialized),
 * false if running standalone or pipeline not yet started.
 * See docs/development/DEGRADATION.md for usage patterns.
 */
#define RS_IS_PIPELINE_ACTIVE() ({ \
    __u32 __key = RS_ONLYKEY; \
    !!bpf_map_lookup_elem(&rs_ctx_map, &__key); \
})

/*
 * Tail-call to next ingress stage.
 * Auto-increments next_prog_id. Ingress modules only.
 */
#define RS_TAIL_CALL_NEXT(xdp_ctx_ptr, rs_ctx_ptr) ({ \
    if ((rs_ctx_ptr)->call_depth < 32) { \
        (rs_ctx_ptr)->call_depth++; \
        (rs_ctx_ptr)->next_prog_id++; \
        bpf_tail_call((xdp_ctx_ptr), &rs_progs, (rs_ctx_ptr)->next_prog_id); \
    } \
})

/*
 * Tail-call to next egress stage via rs_prog_chain lookup.
 * Egress modules must use this instead of RS_TAIL_CALL_NEXT to
 * avoid race conditions during concurrent flooding.
 */
#define RS_TAIL_CALL_EGRESS(xdp_ctx_ptr, rs_ctx_ptr) ({ \
    if ((rs_ctx_ptr)->call_depth < 32) { \
        (rs_ctx_ptr)->call_depth++; \
        __u32 __current_slot = (rs_ctx_ptr)->next_prog_id; \
        __u32 *__next_slot = bpf_map_lookup_elem(&rs_prog_chain, &__current_slot); \
        if (__next_slot && *__next_slot != 0) { \
            (rs_ctx_ptr)->next_prog_id = *__next_slot; \
            bpf_tail_call((xdp_ctx_ptr), &rs_progs, *__next_slot); \
        } \
    } \
})

/* Emit event to unified event bus ringbuf */
#define RS_EMIT_EVENT(event_ptr, event_size) ({ \
    void *__evt = bpf_ringbuf_reserve(&rs_event_bus, (event_size), 0); \
    int __ret = -1; \
    if (__evt) { \
        __builtin_memcpy(__evt, (event_ptr), (event_size)); \
        bpf_ringbuf_submit(__evt, 0); \
        __ret = 0; \
    } \
    __ret; \
})

#endif /* __RSWITCH_HELPERS_H */
