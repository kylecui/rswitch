// SPDX-License-Identifier: GPL-2.0

#include "../include/rswitch_common.h"

enum {
    RS_THIS_STAGE_ID  = 25,
    RS_THIS_MODULE_ID = RS_MOD_QOS_CLASSIFY,
};


char _license[] SEC("license") = "GPL";

RS_DECLARE_MODULE("qos_classify", RS_HOOK_XDP_INGRESS, 25,
                  RS_FLAG_NEED_L2L3_PARSE | RS_FLAG_NEED_FLOW_INFO,
                  "QoS traffic classification");

struct qos_class_rule {
    __u8 match_type;
    __u8 traffic_class;
    __u8 pad[2];
    union {
        __u8 dscp;
        struct {
            __u8 proto;
            __be16 dst_port;
        } l4;
        __u16 vlan_id;
        struct {
            __be32 prefix;
            __u32 prefixlen;
        } subnet;
    };
};

struct qos_port_key {
    __u8 proto;
    __u8 pad;
    __be16 port;
} __attribute__((packed));

struct qos_subnet_key {
    __u32 prefixlen;
    __be32 addr;
};

struct qos_config {
    __u8 enabled;
    __u8 default_class;
    __u8 pad[2];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} qos_dscp_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct qos_port_key);
    __type(value, __u8);
    __uint(max_entries, 4096);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} qos_port_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u16);
    __type(value, __u8);
    __uint(max_entries, 4096);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} qos_vlan_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct qos_subnet_key);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 8192);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} qos_subnet_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct qos_config);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} qos_config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 8);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} qos_stats_map SEC(".maps");

static __always_inline void update_stat(__u32 traffic_class)
{
    __u64 *counter = bpf_map_lookup_elem(&qos_stats_map, &traffic_class);
    if (counter)
        __sync_fetch_and_add(counter, 1);
}

SEC("xdp")
int qos_classify(struct xdp_md *xdp_ctx)
{
    struct rs_ctx *ctx = RS_GET_CTX();
    if (!ctx)
        return XDP_DROP;

    void *data_end = (void *)(long)xdp_ctx->data_end;
    void *data = (void *)(long)xdp_ctx->data;
    __u32 pkt_len = data_end - data;
    RS_OBS_STAGE_HIT(xdp_ctx, ctx, pkt_len);

    __u32 cfg_key = 0;
    struct qos_config *cfg = bpf_map_lookup_elem(&qos_config_map, &cfg_key);
    if (!cfg || !cfg->enabled) {
        rs_debug("QoS classify: disabled, skipping");
        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_DROP;
    }

    if (ctx->layers.eth_proto != 0x0800) {
        rs_debug("QoS classify: non-IPv4 packet, skipping");
        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_DROP;
    }

    __u8 traffic_class = cfg->default_class;
    int matched = 0;

    struct iphdr *iph = data + (ctx->layers.l3_offset & RS_L3_OFFSET_MASK);
    if ((void *)(iph + 1) > data_end) {
        rs_debug("QoS classify: IP header bounds check failed");
        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_DROP;
    }

    __u8 dscp = (__u8)((iph->tos >> 2) & 0x3F);
    __u32 dscp_key = dscp;
    __u8 *dscp_class = bpf_map_lookup_elem(&qos_dscp_map, &dscp_key);
    if (dscp_class) {
        traffic_class = *dscp_class;
        matched = 1;
        rs_debug("QoS classify: DSCP %u -> class %u", dscp, traffic_class);
    }

    if (!matched) {
        struct qos_port_key port_key = {
            .proto = ctx->layers.ip_proto,
            .port = ctx->layers.dport,
        };
        __u8 *port_class = bpf_map_lookup_elem(&qos_port_map, &port_key);
        if (port_class) {
            traffic_class = *port_class;
            matched = 1;
            rs_debug("QoS classify: proto %u port %u -> class %u",
                     port_key.proto, bpf_ntohs(port_key.port), traffic_class);
        }
    }

    if (!matched) {
        __u16 vlan_key = ctx->ingress_vlan;
        __u8 *vlan_class = bpf_map_lookup_elem(&qos_vlan_map, &vlan_key);
        if (vlan_class) {
            traffic_class = *vlan_class;
            matched = 1;
            rs_debug("QoS classify: VLAN %u -> class %u", vlan_key, traffic_class);
        }
    }

    if (!matched) {
        struct qos_subnet_key subnet_key = {
            .prefixlen = 32,
            .addr = ctx->layers.saddr,
        };
        __u8 *subnet_class = bpf_map_lookup_elem(&qos_subnet_map, &subnet_key);
        if (subnet_class) {
            traffic_class = *subnet_class;
            matched = 1;
            rs_debug("QoS classify: source subnet match -> class %u", traffic_class);
        }

        if (!matched) {
            subnet_key.addr = ctx->layers.daddr;
            subnet_class = bpf_map_lookup_elem(&qos_subnet_map, &subnet_key);
            if (subnet_class) {
                traffic_class = *subnet_class;
                matched = 1;
                rs_debug("QoS classify: destination subnet match -> class %u", traffic_class);
            }
        }
    }

    if (traffic_class > 7)
        traffic_class = cfg->default_class & 0x7;

    ctx->traffic_class = traffic_class;
    update_stat((__u32)traffic_class);

    if (!matched)
        rs_debug("QoS classify: default class %u", traffic_class);

    RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
    return XDP_DROP;
}
