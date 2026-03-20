// SPDX-License-Identifier: GPL-2.0

#include "../include/rswitch_common.h"


char _license[] SEC("license") = "GPL";

RS_DECLARE_MODULE("lldp", RS_HOOK_XDP_INGRESS, 11,
                  RS_FLAG_NEED_L2L3_PARSE | RS_FLAG_CREATES_EVENTS,
                  "Link Layer Discovery Protocol");

#define RS_EVENT_LLDP_FRAME (RS_EVENT_L2_BASE + 0x30)
#define LLDP_ETHERTYPE 0x88CC
#define LLDP_MAX_FRAME_SIZE 2048

struct lldp_neighbor {
    char chassis_id[64];
    char port_id[32];
    char system_name[64];
    char system_desc[128];
    __u16 ttl;
    __u16 pad;
    __u64 last_seen_ns;
    __u32 capabilities;
};

struct lldp_frame_event {
    __u32 event_type;
    __u32 ifindex;
    __u64 timestamp_ns;
    __u32 frame_len;
    __u32 cap_len;
    __u8 frame[LLDP_MAX_FRAME_SIZE];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, RS_MAX_INTERFACES);
    __type(key, __u32);
    __type(value, struct lldp_neighbor);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} lldp_neighbor_map SEC(".maps");

static __always_inline int is_lldp_dst_mac(const __u8 *dst)
{
    return dst[0] == 0x01 && dst[1] == 0x80 && dst[2] == 0xC2 &&
           dst[3] == 0x00 && dst[4] == 0x00 && dst[5] == 0x0E;
}

SEC("xdp")
int lldp_ingress(struct xdp_md *xdp_ctx)
{
    struct rs_ctx *ctx = RS_GET_CTX();
    void *data = (void *)(long)xdp_ctx->data;
    void *data_end = (void *)(long)xdp_ctx->data_end;
    struct ethhdr *eth = data;

    if (!ctx)
        return XDP_DROP;

    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    if (!is_lldp_dst_mac(eth->h_dest) || bpf_ntohs(eth->h_proto) != LLDP_ETHERTYPE) {
        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_DROP;
    }

    __u32 frame_len = (__u32)(data_end - data);
    __u32 cap_len = frame_len;
    struct lldp_frame_event *evt;

    if (cap_len > LLDP_MAX_FRAME_SIZE)
        cap_len = LLDP_MAX_FRAME_SIZE;

    evt = bpf_ringbuf_reserve(&rs_event_bus, sizeof(*evt), 0);
    if (evt) {
        evt->event_type = RS_EVENT_LLDP_FRAME;
        evt->ifindex = xdp_ctx->ingress_ifindex;
        evt->timestamp_ns = bpf_ktime_get_ns();
        evt->frame_len = frame_len;
        evt->cap_len = cap_len;

        if (cap_len > 0 && bpf_probe_read_kernel(evt->frame, cap_len, data) == 0)
            bpf_ringbuf_submit(evt, 0);
        else
            bpf_ringbuf_discard(evt, 0);
    }

    return XDP_DROP;
}
