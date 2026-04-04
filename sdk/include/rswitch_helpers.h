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

extern struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rs_obs_cfg);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_obs_cfg_map SEC(".maps");

extern struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct rs_obs_stats_key);
    __type(value, struct rs_obs_stats_val);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_obs_stats_map SEC(".maps");

extern struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct rs_drop_stats_key);
    __type(value, struct rs_drop_stats_val);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_drop_stats_map SEC(".maps");

extern struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 32768);
    __type(key, struct rs_hist_key);
    __type(value, struct rs_hist_val);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_hist_map SEC(".maps");

extern struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 8192);
    __type(key, struct rs_stage_hit_key);
    __type(value, struct rs_stage_hit_val);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_stage_hit_map SEC(".maps");
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

/* ── Observability helpers (L0) ────────────────────────────────── */

static __always_inline struct rs_obs_cfg *rs_obs_get_cfg(void)
{
    __u32 key = 0;
    return bpf_map_lookup_elem(&rs_obs_cfg_map, &key);
}

static __always_inline __u8 rs_obs_ilog2(__u32 val)
{
    if (val == 0)
        return 0;
    __u8 bit = 31 - __builtin_clz(val);
    return bit < RS_OBS_HIST_BUCKETS ? bit : RS_OBS_HIST_BUCKETS - 1;
}

static __always_inline void rs_obs_hist_record(struct rs_ctx *rctx,
                                                __u8 metric, __u32 value)
{
    struct rs_hist_key hk = {
        .ifindex = rctx->ifindex,
        .pipeline_id = (__u16)RS_CTX_PIPELINE_ID(rctx),
        .profile_id = (__u16)RS_CTX_PROFILE_ID(rctx),
        .stage_id = RS_THIS_STAGE_ID,
        .module_id = RS_THIS_MODULE_ID,
        .metric = metric,
        .bucket = rs_obs_ilog2(value),
    };

    struct rs_hist_val *hv = bpf_map_lookup_elem(&rs_hist_map, &hk);
    if (hv) {
        RS_NO_TEAR_INC(hv->count);
    } else {
        struct rs_hist_val init = { .count = 1 };
        bpf_map_update_elem(&rs_hist_map, &hk, &init, BPF_NOEXIST);
    }
}

#define RS_OBS_HIST_RECORD(rctx, metric, value) \
    rs_obs_hist_record((rctx), (metric), (value))

static __always_inline void rs_obs_stage_hit(struct xdp_md *ctx,
                                              struct rs_ctx *rctx,
                                              __u32 pkt_len)
{
    struct rs_stage_hit_key sk = {
        .pipeline_id = (__u16)RS_CTX_PIPELINE_ID(rctx),
        .profile_id = (__u16)RS_CTX_PROFILE_ID(rctx),
        .stage_id = RS_THIS_STAGE_ID,
        .module_id = RS_THIS_MODULE_ID,
    };

    struct rs_stage_hit_val *sv = bpf_map_lookup_elem(&rs_stage_hit_map, &sk);
    if (sv) {
        RS_NO_TEAR_INC(sv->hits);
    } else {
        struct rs_stage_hit_val init = { .hits = 1 };
        bpf_map_update_elem(&rs_stage_hit_map, &sk, &init, BPF_NOEXIST);
    }

    rs_obs_hist_record(rctx, RS_OBS_HIST_PKT_LEN, pkt_len);
}

#define RS_OBS_STAGE_HIT(ctx, rctx, pkt_len) \
    rs_obs_stage_hit((ctx), (rctx), (pkt_len))

static __always_inline void rs_record_drop(struct xdp_md *ctx,
                                            struct rs_ctx *rctx,
                                            __u16 reason)
{
    rctx->drop_reason = reason;
    rctx->action = XDP_DROP;

    struct rs_drop_stats_key dk = {
        .ifindex = rctx->ifindex,
        .rxq = (__u16)ctx->rx_queue_index,
        .pipeline_id = (__u16)RS_CTX_PIPELINE_ID(rctx),
        .profile_id = (__u16)RS_CTX_PROFILE_ID(rctx),
        .stage_id = RS_THIS_STAGE_ID,
        .module_id = RS_THIS_MODULE_ID,
        .reason = reason,
    };

    struct rs_drop_stats_val *dv = bpf_map_lookup_elem(&rs_drop_stats_map, &dk);
    if (dv) {
        RS_NO_TEAR_INC(dv->packets);
    } else {
        struct rs_drop_stats_val init = { .packets = 1 };
        bpf_map_update_elem(&rs_drop_stats_map, &dk, &init, BPF_NOEXIST);
    }

    struct rs_obs_stats_key ok = {
        .ifindex = rctx->ifindex,
        .rxq = (__u16)ctx->rx_queue_index,
        .pipeline_id = (__u16)RS_CTX_PIPELINE_ID(rctx),
        .profile_id = (__u16)RS_CTX_PROFILE_ID(rctx),
        .stage_id = RS_THIS_STAGE_ID,
        .module_id = RS_THIS_MODULE_ID,
        .proto = 0,
        .action = XDP_DROP,
    };

    struct rs_obs_stats_val *ov = bpf_map_lookup_elem(&rs_obs_stats_map, &ok);
    if (ov) {
        RS_NO_TEAR_INC(ov->packets);
    } else {
        struct rs_obs_stats_val init = { .packets = 1 };
        bpf_map_update_elem(&rs_obs_stats_map, &ok, &init, BPF_NOEXIST);
    }
}

#define RS_RECORD_DROP(ctx, rctx, reason) \
    rs_record_drop((ctx), (rctx), (reason))

static __always_inline void rs_obs_final_action(struct xdp_md *ctx,
                                                 struct rs_ctx *rctx,
                                                 __u32 pkt_len)
{
    struct rs_obs_stats_key ok = {
        .ifindex = rctx->ifindex,
        .rxq = (__u16)ctx->rx_queue_index,
        .pipeline_id = (__u16)RS_CTX_PIPELINE_ID(rctx),
        .profile_id = (__u16)RS_CTX_PROFILE_ID(rctx),
        .stage_id = RS_THIS_STAGE_ID,
        .module_id = RS_THIS_MODULE_ID,
        .proto = 0,
        .action = (__u8)rctx->action,
    };

    struct rs_obs_stats_val *ov = bpf_map_lookup_elem(&rs_obs_stats_map, &ok);
    if (ov) {
        RS_NO_TEAR_INC(ov->packets);
        RS_NO_TEAR_ADD(ov->bytes, (__u64)pkt_len);
    } else {
        struct rs_obs_stats_val init = { .packets = 1, .bytes = (__u64)pkt_len };
        bpf_map_update_elem(&rs_obs_stats_map, &ok, &init, BPF_NOEXIST);
    }

    rs_obs_hist_record(rctx, RS_OBS_HIST_PKT_LEN, pkt_len);
}

#define RS_OBS_FINAL_ACTION(ctx, rctx, pkt_len) \
    rs_obs_final_action((ctx), (rctx), (pkt_len))

/* ── Observability helpers (L1 — sampled events) ───────────────── */

static __always_inline __u8 rs_obs_reason_to_gate(__u16 reason)
{
    if (reason >= RS_DROP_USER_BASE)
        return RS_OBS_GATE_USER_EVENT;
    if (reason >= RS_DROP_MAP_ERROR)
        return RS_OBS_GATE_INTERNAL_EXCEPTION;
    if (reason >= RS_DROP_MIRROR_TARGET_DOWN)
        return RS_OBS_GATE_MIRROR_EXCEPTION;
    if (reason >= RS_DROP_QUEUE_FULL)
        return RS_OBS_GATE_QOS_EXCEPTION;
    if (reason >= RS_DROP_NO_ROUTE)
        return RS_OBS_GATE_ROUTE_EXCEPTION;
    if (reason >= RS_DROP_ACL_DENY)
        return RS_OBS_GATE_ACL_DROP;
    if (reason >= RS_DROP_VLAN_FILTER)
        return RS_OBS_GATE_VLAN_EXCEPTION;
    if (reason >= RS_DROP_PARSE_ETH)
        return RS_OBS_GATE_PARSE_EXCEPTION;
    return RS_OBS_GATE_DROP_ANY;
}

static __always_inline bool rs_obs_should_emit(struct rs_obs_cfg *cfg,
                                                struct rs_obs_event *evt)
{
    if (evt->flags & RS_OBS_F_DROP) {
        __u8 gate = rs_obs_reason_to_gate(evt->reason);
        return (cfg->event_mask & (1ULL << gate)) != 0;
    }

    if (evt->action == XDP_PASS)
        return (cfg->event_mask & (1ULL << RS_OBS_GATE_PASS_SAMPLE)) != 0;

    if (evt->action == XDP_REDIRECT || evt->action == XDP_TX)
        return (cfg->event_mask & (1ULL << RS_OBS_GATE_REDIRECT_SAMPLE)) != 0;

    return false;
}

static __always_inline bool rs_obs_should_sample(struct rs_obs_cfg *cfg,
                                                  struct rs_obs_event *evt)
{
    if (cfg->level < RS_OBS_LEVEL_L1)
        return false;

    if (!rs_obs_should_emit(cfg, evt))
        return false;

    __u32 ppm = cfg->sample_ppm;

    switch (RS_THIS_MODULE_ID) {
    case RS_MOD_DISPATCHER:
        if (!(evt->flags & RS_OBS_F_EXCEPTION))
            return false;
        ppm = 1000000;
        break;
    case RS_MOD_ACL:
        ppm = cfg->sample_ppm * 10;
        if (ppm > 1000000)
            ppm = 1000000;
        break;
    case RS_MOD_MIRROR:
        ppm = cfg->sample_ppm / 10;
        if (ppm < 1)
            ppm = 1;
        break;
    default:
        break;
    }

    if (evt->flags & (RS_OBS_F_DROP | RS_OBS_F_EXCEPTION | RS_OBS_F_REDIRECT_ERR))
        ppm = 1000000;

    return (bpf_get_prng_u32() % 1000000U) < ppm;
}

static __always_inline void rs_obs_build_event(struct xdp_md *ctx,
                                                struct rs_ctx *rctx,
                                                struct rs_obs_event *evt,
                                                __u16 event_type,
                                                __u16 flags,
                                                __u16 reason,
                                                __u32 pkt_len)
{
    evt->event_type = event_type;
    evt->event_len = sizeof(*evt);
    evt->ifindex = rctx->ifindex;
    evt->rxq = ctx->rx_queue_index;
    evt->ts_ns = bpf_ktime_get_ns();
    evt->pipeline_id = (__u16)RS_CTX_PIPELINE_ID(rctx);
    evt->profile_id = (__u16)RS_CTX_PROFILE_ID(rctx);
    evt->stage_id = RS_THIS_STAGE_ID;
    evt->module_id = RS_THIS_MODULE_ID;
    evt->pkt_len = (__u16)(pkt_len > 0xFFFF ? 0xFFFF : pkt_len);
    evt->reason = reason;
    evt->ip_proto = 0;
    evt->action = (__u8)rctx->action;
    evt->flags = flags;
    evt->flow_hash = RS_CTX_OBS_FLOW_HASH(rctx);
}

static __always_inline void rs_emit_sampled_event(struct rs_ctx *rctx,
                                                   struct rs_obs_event *evt,
                                                   __u32 size)
{
    struct rs_obs_cfg *cfg = rs_obs_get_cfg();
    if (!cfg)
        return;

    if (RS_CTX_OBS_BURST_USED(rctx) >= cfg->burst_limit)
        return;

    if (!rs_obs_should_sample(cfg, evt))
        return;

    evt->flags |= RS_OBS_F_SAMPLED;

    void *buf = bpf_ringbuf_reserve(&rs_event_bus, size, 0);
    if (!buf)
        return;

    __builtin_memcpy(buf, evt, size);
    bpf_ringbuf_submit(buf, 0);

    RS_CTX_OBS_BURST_USED(rctx) += 1;
}

#define RS_EMIT_SAMPLED_EVENT(rctx, evt, size) \
    rs_emit_sampled_event((rctx), (evt), (size))

#endif /* __RSWITCH_HELPERS_H */
