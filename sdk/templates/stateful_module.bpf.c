// SPDX-License-Identifier: GPL-2.0
/*
 * rSwitch Stateful Module Template
 *
 * Demonstrates a module with private BPF map state.
 * This template shows how to maintain per-flow or per-session state.
 */

#include "rswitch_module.h"

char _license[] SEC("license") = "GPL";

RS_DECLARE_MODULE("stateful_mod", RS_HOOK_XDP_INGRESS, 210,
                  RS_FLAG_NEED_L2L3_PARSE | RS_FLAG_MAY_DROP | RS_FLAG_CREATES_EVENTS,
                  "Stateful module template with private map");

#define MY_EVENT_NEW_FLOW    (RS_EVENT_USER_BASE + 0x01)
#define MY_EVENT_FLOW_EXPIRE (RS_EVENT_USER_BASE + 0x02)

/* Private map for this module - use LIBBPF_PIN_BY_NAME so the map
 * is pinned to /sys/fs/bpf/ and accessible from user-space tools.
 *
 * IMPORTANT: Always prefix map names with 'rs_' to follow rSwitch conventions.
 */
struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 pad[3];
};

struct flow_value {
    __u64 packets;
    __u64 bytes;
    __u64 first_seen;
    __u64 last_seen;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct flow_key);
    __type(value, struct flow_value);
    __uint(max_entries, 65536);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_my_flow_map SEC(".maps");

SEC("xdp")
int stateful_module_func(struct xdp_md *xdp_ctx)
{
    struct rs_ctx *ctx = RS_GET_CTX();
    if (!ctx)
        return XDP_DROP;

    void *data = (void *)(long)xdp_ctx->data;
    void *data_end = (void *)(long)xdp_ctx->data_end;

    /* Build flow key from parsed headers */
    struct flow_key key = {};
    /* ... populate key from ctx->layers ... */

    /* Lookup existing flow */
    struct flow_value *flow = bpf_map_lookup_elem(&rs_my_flow_map, &key);
    if (flow) {
        /* Update existing flow */
        __sync_fetch_and_add(&flow->packets, 1);
        __sync_fetch_and_add(&flow->bytes, data_end - data);
        flow->last_seen = bpf_ktime_get_ns();
    } else {
        /* Create new flow entry */
        struct flow_value new_flow = {
            .packets = 1,
            .bytes = data_end - data,
            .first_seen = bpf_ktime_get_ns(),
            .last_seen = bpf_ktime_get_ns(),
        };
        bpf_map_update_elem(&rs_my_flow_map, &key, &new_flow, BPF_ANY);
    }

    /* Continue pipeline */
    RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
    return XDP_DROP;
}
