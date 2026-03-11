// SPDX-License-Identifier: GPL-2.0

#ifndef __BPF__
#define __BPF__
#endif

#include "../include/rswitch_common.h"
#include "../core/module_abi.h"

char _license[] SEC("license") = "GPL";

RS_DECLARE_MODULE("source_guard", RS_HOOK_XDP_INGRESS, 18,
                  RS_FLAG_NEED_L2L3_PARSE | RS_FLAG_MAY_DROP | RS_FLAG_CREATES_EVENTS,
                  "IP-MAC-Port source validation");

struct sg_key {
    __be32 ip_addr;
} __attribute__((packed));

struct sg_entry {
    __u8 mac[6];
    __u16 pad;
    __u32 ifindex;
    __u8 type;
    __u8 pad2[3];
    __u64 last_seen_ns;
    __u64 violations;
} __attribute__((aligned(8)));

struct sg_config {
    __u8 enabled;
    __u8 strict_mode;
    __u8 check_mac;
    __u8 check_port;
} __attribute__((aligned(8)));

struct sg_violation_event {
    __u32 event_type;
    __u32 ifindex;
    __be32 src_ip;
    __u8 src_mac[6];
    __u8 expected_mac[6];
    __u32 expected_ifindex;
};

enum sg_stat_type {
    SG_STAT_TOTAL = 0,
    SG_STAT_PASSED = 1,
    SG_STAT_MAC_VIOLATIONS = 2,
    SG_STAT_PORT_VIOLATIONS = 3,
    SG_STAT_MAX = 4,
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct sg_key);
    __type(value, struct sg_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} sg_binding_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct sg_config);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} sg_config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, SG_STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} sg_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u8);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} sg_port_enable_map SEC(".maps");

static __always_inline void sg_stat_inc(__u32 stat)
{
    __u64 *counter = bpf_map_lookup_elem(&sg_stats_map, &stat);
    if (counter)
        __sync_fetch_and_add(counter, 1);
}

static __always_inline int mac_match(const __u8 *a, const __u8 *b)
{
    return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] &&
           a[3] == b[3] && a[4] == b[4] && a[5] == b[5];
}

static __always_inline void emit_violation_event(__u32 ifindex, __be32 src_ip,
                                                  const __u8 *src_mac,
                                                  const struct sg_entry *binding)
{
    struct sg_violation_event evt = {
        .event_type = RS_EVENT_ACL_BASE + 0x10,
        .ifindex = ifindex,
        .src_ip = src_ip,
        .expected_ifindex = binding ? binding->ifindex : 0,
    };

    __builtin_memcpy(evt.src_mac, src_mac, sizeof(evt.src_mac));
    if (binding)
        __builtin_memcpy(evt.expected_mac, binding->mac, sizeof(evt.expected_mac));

    RS_EMIT_EVENT(&evt, sizeof(evt));
}

SEC("xdp")
int source_guard(struct xdp_md *xdp_ctx)
{
    void *data = (void *)(long)xdp_ctx->data;
    void *data_end = (void *)(long)xdp_ctx->data_end;
    struct rs_ctx *ctx = RS_GET_CTX();
    __u32 zero = 0;

    if (!ctx)
        return XDP_DROP;

    struct sg_config *cfg = bpf_map_lookup_elem(&sg_config_map, &zero);
    if (!cfg || !cfg->enabled) {
        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_DROP;
    }

    __u8 *port_enabled = bpf_map_lookup_elem(&sg_port_enable_map, &ctx->ifindex);
    if (!port_enabled || !*port_enabled) {
        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_DROP;
    }

    if (ctx->layers.eth_proto != ETH_P_IP) {
        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_DROP;
    }

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        ctx->drop_reason = RS_DROP_PARSE_ERROR;
        return XDP_DROP;
    }

    sg_stat_inc(SG_STAT_TOTAL);

    struct sg_key key = {
        .ip_addr = ctx->layers.saddr,
    };
    struct sg_entry *entry = bpf_map_lookup_elem(&sg_binding_map, &key);

    if (!entry) {
        if (cfg->strict_mode) {
            sg_stat_inc(SG_STAT_MAC_VIOLATIONS);
            emit_violation_event(ctx->ifindex, ctx->layers.saddr, eth->h_source, NULL);
            ctx->drop_reason = RS_DROP_ACL_BLOCK;
            return XDP_DROP;
        }

        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_DROP;
    }

    int mac_violation = 0;
    int port_violation = 0;

    if (cfg->check_mac && !mac_match(eth->h_source, entry->mac))
        mac_violation = 1;

    if (cfg->check_port && entry->ifindex != 0 && entry->ifindex != ctx->ifindex)
        port_violation = 1;

    if (mac_violation || port_violation) {
        if (mac_violation)
            sg_stat_inc(SG_STAT_MAC_VIOLATIONS);
        if (port_violation)
            sg_stat_inc(SG_STAT_PORT_VIOLATIONS);

        entry->violations++;
        entry->last_seen_ns = bpf_ktime_get_ns();
        bpf_map_update_elem(&sg_binding_map, &key, entry, BPF_ANY);

        emit_violation_event(ctx->ifindex, ctx->layers.saddr, eth->h_source, entry);

        if (cfg->strict_mode) {
            ctx->drop_reason = RS_DROP_ACL_BLOCK;
            return XDP_DROP;
        }

        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_DROP;
    }

    entry->last_seen_ns = bpf_ktime_get_ns();
    sg_stat_inc(SG_STAT_PASSED);
    bpf_map_update_elem(&sg_binding_map, &key, entry, BPF_ANY);

    RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
    return XDP_DROP;
}
