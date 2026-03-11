// SPDX-License-Identifier: GPL-2.0

#include "../include/rswitch_common.h"
#include "../core/module_abi.h"

char _license[] SEC("license") = "GPL";

RS_DECLARE_MODULE("flow_table", RS_HOOK_XDP_INGRESS, 60,
                  RS_FLAG_NEED_L2L3_PARSE | RS_FLAG_NEED_FLOW_INFO |
                      RS_FLAG_MODIFIES_PACKET | RS_FLAG_MAY_DROP |
                      RS_FLAG_CREATES_EVENTS,
                  "OpenFlow-style per-flow forwarding");

#define FLOW_MAX_ENTRIES 8192
#define FLOW_ACTION_FORWARD 0
#define FLOW_ACTION_DROP 1
#define FLOW_ACTION_SET_VLAN 2
#define FLOW_ACTION_SET_DSCP 3
#define FLOW_ACTION_MIRROR 4
#define FLOW_ACTION_CONTROLLER 5

#define FLOW_STAT_MATCHES 0
#define FLOW_STAT_MISSES 1
#define FLOW_STAT_DROPS 2
#define FLOW_STAT_FORWARDS 3

#define FLOW_EVENT_CONTROLLER (RS_EVENT_QOS_BASE + 16)

struct flow_key {
    __u32 ingress_ifindex;
    __u16 vlan_id;
    __u8 ip_proto;
    __u8 pad;
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
} __attribute__((packed));

struct flow_entry {
    __u16 priority;
    __u8 action;
    __u8 enabled;
    __u32 egress_ifindex;
    __u16 set_vlan_id;
    __u8 set_dscp;
    __u8 mirror;
    __u32 idle_timeout_sec;
    __u32 hard_timeout_sec;
    __u64 created_ns;
    __u64 last_match_ns;
    __u64 match_pkts;
    __u64 match_bytes;
} __attribute__((aligned(8)));

struct flow_config {
    __u8 enabled;
    __u8 default_action;
    __u8 pad[2];
} __attribute__((aligned(8)));

struct flow_controller_event {
    __u32 event_type;
    __u32 ingress_ifindex;
    __u32 egress_ifindex;
    __u8 ip_proto;
    __u8 action;
    __u16 pad;
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u32 pkt_len;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, FLOW_MAX_ENTRIES);
    __type(key, struct flow_key);
    __type(value, struct flow_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_table_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct flow_config);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_stats_map SEC(".maps");

static __always_inline void flow_stat_inc(__u32 stat)
{
    __u64 *v = bpf_map_lookup_elem(&flow_stats_map, &stat);
    if (v)
        __sync_fetch_and_add(v, 1);
}

static __always_inline void emit_controller_event(struct rs_ctx *ctx, __u32 pkt_len, __u8 action)
{
    struct flow_controller_event evt = {
        .event_type = FLOW_EVENT_CONTROLLER,
        .ingress_ifindex = ctx->ifindex,
        .egress_ifindex = ctx->egress_ifindex,
        .ip_proto = ctx->layers.ip_proto,
        .action = action,
        .src_ip = ctx->layers.saddr,
        .dst_ip = ctx->layers.daddr,
        .src_port = ctx->layers.sport,
        .dst_port = ctx->layers.dport,
        .pkt_len = pkt_len,
    };

    RS_EMIT_EVENT(&evt, sizeof(evt));
}

SEC("xdp")
int flow_table(struct xdp_md *xdp_ctx)
{
    struct rs_ctx *ctx = RS_GET_CTX();
    __u32 cfg_key = 0;
    __u64 now = bpf_ktime_get_ns();
    void *data = (void *)(long)xdp_ctx->data;
    void *data_end = (void *)(long)xdp_ctx->data_end;
    __u32 pkt_len = (__u32)(data_end - data);
    struct flow_key key = {};
    struct flow_key matched_key = {};
    struct flow_entry *entry;

    if (!ctx)
        return XDP_DROP;

    struct flow_config *cfg = bpf_map_lookup_elem(&flow_config_map, &cfg_key);
    if (!cfg || !cfg->enabled) {
        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_PASS;
    }

    if (ctx->layers.eth_proto != ETH_P_IP) {
        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_PASS;
    }

    key.ingress_ifindex = ctx->ifindex;
    key.vlan_id = ctx->ingress_vlan;
    key.ip_proto = ctx->layers.ip_proto;
    key.src_ip = ctx->layers.saddr;
    key.dst_ip = ctx->layers.daddr;
    key.src_port = ctx->layers.sport;
    key.dst_port = ctx->layers.dport;

    matched_key = key;
    entry = bpf_map_lookup_elem(&flow_table_map, &matched_key);

    if (!entry) {
        struct flow_key wildcard_key = key;

        wildcard_key.ingress_ifindex = 0;
        entry = bpf_map_lookup_elem(&flow_table_map, &wildcard_key);
        if (entry) {
            matched_key = wildcard_key;
            goto found;
        }

        wildcard_key.vlan_id = 0;
        entry = bpf_map_lookup_elem(&flow_table_map, &wildcard_key);
        if (entry) {
            matched_key = wildcard_key;
            goto found;
        }

        wildcard_key.src_port = 0;
        wildcard_key.dst_port = 0;
        entry = bpf_map_lookup_elem(&flow_table_map, &wildcard_key);
        if (entry) {
            matched_key = wildcard_key;
            goto found;
        }

        wildcard_key.src_ip = 0;
        wildcard_key.dst_ip = 0;
        entry = bpf_map_lookup_elem(&flow_table_map, &wildcard_key);
        if (entry) {
            matched_key = wildcard_key;
            goto found;
        }
    }

found:
    if (entry && entry->enabled) {
        if (entry->idle_timeout_sec > 0 && entry->last_match_ns > 0) {
            __u64 idle_ns = (__u64)entry->idle_timeout_sec * 1000000000ULL;
            if (now > entry->last_match_ns && now - entry->last_match_ns > idle_ns) {
                bpf_map_delete_elem(&flow_table_map, &matched_key);
                entry = NULL;
            }
        }

        if (entry && entry->hard_timeout_sec > 0 && entry->created_ns > 0) {
            __u64 hard_ns = (__u64)entry->hard_timeout_sec * 1000000000ULL;
            if (now > entry->created_ns && now - entry->created_ns > hard_ns) {
                bpf_map_delete_elem(&flow_table_map, &matched_key);
                entry = NULL;
            }
        }
    }

    if (entry && entry->enabled) {
        flow_stat_inc(FLOW_STAT_MATCHES);
        __sync_fetch_and_add(&entry->match_pkts, 1);
        __sync_fetch_and_add(&entry->match_bytes, pkt_len);
        entry->last_match_ns = now;

        switch (entry->action) {
        case FLOW_ACTION_FORWARD:
            ctx->egress_ifindex = entry->egress_ifindex;
            ctx->action = XDP_REDIRECT;
            flow_stat_inc(FLOW_STAT_FORWARDS);
            RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
            return XDP_PASS;
        case FLOW_ACTION_DROP:
            ctx->drop_reason = RS_DROP_NO_FWD_ENTRY;
            flow_stat_inc(FLOW_STAT_DROPS);
            return XDP_DROP;
        case FLOW_ACTION_SET_VLAN:
            ctx->egress_vlan = entry->set_vlan_id;
            ctx->modified = 1;
            RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
            return XDP_PASS;
        case FLOW_ACTION_SET_DSCP:
            ctx->dscp = entry->set_dscp & 0x3F;
            ctx->modified = 1;
            RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
            return XDP_PASS;
        case FLOW_ACTION_MIRROR:
            ctx->mirror = entry->mirror ? 1 : 0;
            ctx->mirror_port = (__u16)entry->egress_ifindex;
            RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
            return XDP_PASS;
        case FLOW_ACTION_CONTROLLER:
            emit_controller_event(ctx, pkt_len, entry->action);
            RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
            return XDP_PASS;
        default:
            RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
            return XDP_PASS;
        }
    }

    flow_stat_inc(FLOW_STAT_MISSES);
    if (cfg->default_action == 1) {
        flow_stat_inc(FLOW_STAT_DROPS);
        return XDP_DROP;
    }

    RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
    return XDP_PASS;
}
