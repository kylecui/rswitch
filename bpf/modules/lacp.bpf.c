// SPDX-License-Identifier: GPL-2.0

#include "../include/rswitch_common.h"

char _license[] SEC("license") = "GPL";

RS_DECLARE_MODULE("lacp", RS_HOOK_XDP_INGRESS, 11,
                  RS_FLAG_NEED_L2L3_PARSE | RS_FLAG_MAY_DROP | RS_FLAG_CREATES_EVENTS,
                  "Link Aggregation Control Protocol");

#define ETH_P_SLOW 0x8809
#define LACP_EVENT_TYPE (RS_EVENT_L2_BASE + 0x20)

enum lacp_state {
    LACP_STATE_DETACHED = 0,
    LACP_STATE_ATTACHED = 1,
    LACP_STATE_COLLECTING = 2,
    LACP_STATE_DISTRIBUTING = 3,
};

struct lacp_port_info {
    __u32 agg_id;
    __u32 partner_key;
    __u32 actor_key;
    __u8 state;
    __u8 selected;
    __u8 pad[2];
    __u64 last_lacpdu_ts;
} __attribute__((packed));

struct lacp_agg_members {
    __u32 member_count;
    __u32 members[8];
    __u32 tx_hash_mode;
} __attribute__((packed));

struct lacp_event {
    __u32 event_type;
    __u32 ifindex;
    __u64 timestamp_ns;
    __u32 pkt_len;
    __u16 partner_key;
    __u16 partner_port_priority;
    __u8 actor_state;
    __u8 partner_system_id[6];
    __u8 parsed;
    __u8 state;
    __u8 selected;
    __u8 pad[1];
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, RS_MAX_INTERFACES);
    __type(key, __u32);
    __type(value, struct lacp_port_info);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} lacp_agg_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct lacp_agg_members);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} lacp_agg_members_map SEC(".maps");

static __always_inline void emit_lacp_event(struct rs_ctx *ctx, void *data, void *data_end, __u8 state, __u8 selected)
{
    struct lacp_event event = {
        .event_type = LACP_EVENT_TYPE,
        .ifindex = ctx->ifindex,
        .timestamp_ns = bpf_ktime_get_ns(),
        .state = state,
        .selected = selected,
    };
    __u32 pkt_len = (__u32)((__u64)data_end - (__u64)data);
    __u8 *pkt = data;

    event.pkt_len = pkt_len;

    if (pkt + 56 <= (__u8 *)data_end) {
        __u8 *payload = pkt + 14;
        __u8 *actor_tlv = payload + 2;

        if (payload[0] == 0x01 && actor_tlv[0] == 0x01 && actor_tlv[1] >= 20) {
            event.partner_key = ((__u16)actor_tlv[10] << 8) | actor_tlv[11];
            event.partner_port_priority = ((__u16)actor_tlv[12] << 8) | actor_tlv[13];
            event.actor_state = actor_tlv[16];
            __builtin_memcpy(event.partner_system_id, actor_tlv + 4, 6);
            event.parsed = 1;
        }
    }

    RS_EMIT_EVENT(&event, sizeof(event));
}

SEC("xdp")
int lacp_ingress(struct xdp_md *xdp_ctx)
{
    void *data = (void *)(long)xdp_ctx->data;
    void *data_end = (void *)(long)xdp_ctx->data_end;
    struct rs_ctx *ctx = RS_GET_CTX();
    struct ethhdr *eth;
    __u16 eth_proto;
    struct lacp_port_info *port_info;

    if (!ctx)
        return XDP_DROP;

    eth = data + (ctx->layers.l2_offset & RS_L2_OFFSET_MASK);
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    eth_proto = bpf_ntohs(eth->h_proto);
    port_info = bpf_map_lookup_elem(&lacp_agg_map, &ctx->ifindex);

    if (eth_proto == ETH_P_SLOW) {
        __u8 state = port_info ? port_info->state : LACP_STATE_DETACHED;
        __u8 selected = port_info ? port_info->selected : 0;
        emit_lacp_event(ctx, data, data_end, state, selected);
        return XDP_PASS;
    }

    if (!port_info) {
        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_PASS;
    }

    if (port_info->state == LACP_STATE_DETACHED)
        return XDP_DROP;

    if (port_info->state == LACP_STATE_COLLECTING)
        return XDP_PASS;

    if (port_info->state == LACP_STATE_DISTRIBUTING) {
        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_PASS;
    }

    return XDP_PASS;
}
