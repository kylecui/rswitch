// SPDX-License-Identifier: GPL-2.0

#include "../include/rswitch_common.h"


char _license[] SEC("license") = "GPL";

RS_DECLARE_MODULE("stp", RS_HOOK_XDP_INGRESS, 12,
                  RS_FLAG_NEED_L2L3_PARSE | RS_FLAG_MAY_DROP | RS_FLAG_CREATES_EVENTS,
                  "Spanning Tree Protocol");

enum stp_port_fwd_state {
    STP_STATE_DISCARDING = 0,
    STP_STATE_LEARNING = 1,
    STP_STATE_FORWARDING = 2,
};

struct stp_port_state {
    __u32 state;
    __u32 role;
    __u32 bridge_priority;
    __u32 path_cost;
    __u64 last_bpdu_ts;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, RS_MAX_INTERFACES);
    __type(key, __u32);
    __type(value, struct stp_port_state);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} stp_port_state_map SEC(".maps");

enum stp_stats_key {
    STP_STAT_BPDU_EVENTS = 0,
    STP_STAT_BPDU_EVENT_FAIL = 1,
    STP_STAT_DROPPED_DISCARDING = 2,
    STP_STAT_PASSED_LEARNING = 3,
    STP_STAT_FORWARDED = 4,
    STP_STAT_MAX = 5,
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STP_STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} stp_stats_map SEC(".maps");

struct stp_bpdu_event {
    __u32 event_type;
    __u32 ifindex;
    __u64 timestamp_ns;
    __u32 frame_len;
    __u32 bpdu_len;
    __u8 data[128];
} __attribute__((packed));

static const __u8 stp_multicast_mac[6] = {0x01, 0x80, 0xC2, 0x00, 0x00, 0x00};

static __always_inline void stp_stat_inc(__u32 key)
{
    __u64 *counter = bpf_map_lookup_elem(&stp_stats_map, &key);
    if (counter)
        __sync_fetch_and_add(counter, 1);
}

static __always_inline int stp_is_bpdu(struct ethhdr *eth)
{
    return __builtin_memcmp(eth->h_dest, stp_multicast_mac, 6) == 0;
}

static __always_inline void stp_emit_bpdu_event(struct xdp_md *xdp_ctx, struct rs_ctx *ctx, void *data, void *data_end)
{
    struct stp_bpdu_event evt = {};
    __u32 frame_len;
    __u32 copy_len;

    frame_len = (__u32)(data_end - data);
    copy_len = frame_len;
    if (copy_len > sizeof(evt.data))
        copy_len = sizeof(evt.data);

    if (data + copy_len > data_end)
        return;

    evt.event_type = RS_EVENT_L2_BASE + 0x10;
    evt.ifindex = ctx->ifindex;
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.frame_len = frame_len;
    evt.bpdu_len = copy_len;
    copy_len &= 0x7f;
    if (copy_len < 1)
        return;
    if (bpf_xdp_load_bytes(xdp_ctx, 0, evt.data, copy_len) < 0)
        return;

    if (RS_EMIT_EVENT(&evt, sizeof(evt)) < 0) {
        stp_stat_inc(STP_STAT_BPDU_EVENT_FAIL);
        return;
    }

    stp_stat_inc(STP_STAT_BPDU_EVENTS);
}

SEC("xdp")
int stp_ingress(struct xdp_md *xdp_ctx)
{
    void *data_end = (void *)(long)xdp_ctx->data_end;
    void *data = (void *)(long)xdp_ctx->data;
    void *l2;
    struct ethhdr *eth;
    struct rs_ctx *ctx;
    struct stp_port_state *port_state;

    ctx = RS_GET_CTX();
    if (!ctx)
        return XDP_DROP;

    if (!ctx->parsed) {
        ctx->error = RS_ERROR_PARSE_FAILED;
        ctx->drop_reason = RS_DROP_PARSE_ERROR;
        return XDP_DROP;
    }

    l2 = data + (ctx->layers.l2_offset & RS_L2_OFFSET_MASK);
    if (l2 + sizeof(*eth) > data_end) {
        ctx->error = RS_ERROR_PARSE_FAILED;
        ctx->drop_reason = RS_DROP_PARSE_ERROR;
        return XDP_DROP;
    }

    eth = l2;
    if (stp_is_bpdu(eth)) {
        stp_emit_bpdu_event(xdp_ctx, ctx, data, data_end);
        return XDP_PASS;
    }

    port_state = bpf_map_lookup_elem(&stp_port_state_map, &ctx->ifindex);
    if (port_state) {
        if (port_state->state == STP_STATE_DISCARDING) {
            ctx->action = XDP_DROP;
            ctx->drop_reason = RS_DROP_NO_FWD_ENTRY;
            stp_stat_inc(STP_STAT_DROPPED_DISCARDING);
            return XDP_DROP;
        }

        if (port_state->state == STP_STATE_LEARNING) {
            ctx->action = XDP_PASS;
            stp_stat_inc(STP_STAT_PASSED_LEARNING);
            return XDP_PASS;
        }
    }

    stp_stat_inc(STP_STAT_FORWARDED);
    RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
    return XDP_DROP;
}
