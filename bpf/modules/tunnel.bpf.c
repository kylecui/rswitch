// SPDX-License-Identifier: GPL-2.0

#ifndef __BPF__
#define __BPF__
#endif

#include "../include/rswitch_common.h"
#include "../core/module_abi.h"

char _license[] SEC("license") = "GPL";

RS_DECLARE_MODULE("tunnel", RS_HOOK_XDP_INGRESS, 15,
                  RS_FLAG_NEED_L2L3_PARSE | RS_FLAG_NEED_FLOW_INFO |
                      RS_FLAG_MODIFIES_PACKET | RS_FLAG_MAY_DROP |
                      RS_FLAG_CREATES_EVENTS,
                  "Tunnel Encapsulation/Decapsulation");

/* Encapsulation is intentionally done in user space or TC. */

struct tunnel_config {
    __u32 enabled;
    __u32 pad;
};

struct vxlan_entry {
    __u16 vlan_id;
    __u16 pad;
    __u32 local_vtep_ip;
    __u32 remote_vtep_ip;
};

struct gre_entry {
    __u32 local_ip;
    __u32 remote_ip;
    __u32 key;
    __u16 vlan_id;
    __u16 pad;
};

struct tunnel_stats {
    __u64 vxlan_decap;
    __u64 vxlan_decap_err;
    __u64 gre_decap;
    __u64 gre_decap_err;
    __u64 unknown_tunnel;
};

struct vxlan_hdr {
    __u8 flags;
    __u8 reserved1[3];
    __u8 vni[3];
    __u8 reserved2;
} __attribute__((packed));

#define VXLAN_UDP_PORT 4789
#define VXLAN_DECAP_OUTER_LEN 50 /* 14 ETH + 20 IPv4 + 8 UDP + 8 VXLAN */
#define RS_ETH_HLEN 14
#define GRE_FLAG_CSUM 0x8000
#define GRE_FLAG_ROUTING 0x4000
#define GRE_FLAG_KEY 0x2000
#define GRE_FLAG_SEQ 0x1000
#define GRE_VERSION_MASK 0x0007
#define INNER_MTU_MAX 1500

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct tunnel_config);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tunnel_config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct vxlan_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} vxlan_vni_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, struct gre_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} gre_tunnel_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct tunnel_stats);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tunnel_stats_map SEC(".maps");

static __always_inline struct tunnel_stats *tunnel_get_stats(void)
{
    __u32 key = 0;
    return bpf_map_lookup_elem(&tunnel_stats_map, &key);
}

static __always_inline int tunnel_reparse_inner(struct xdp_md *xdp, struct rs_ctx *ctx)
{
    void *data = (void *)(long)xdp->data;
    void *data_end = (void *)(long)xdp->data_end;
    struct hdr_cursor nh = { .pos = data };
    struct ethhdr *eth = NULL;
    struct collect_vlans vlans = {0};
    int eth_proto;

    __builtin_memset(&ctx->layers, 0, sizeof(ctx->layers));

    eth_proto = parse_ethhdr_vlan(&nh, data_end, &eth, &vlans);
    if (eth_proto < 0 || !eth)
        return -1;

    ctx->layers.eth_proto = bpf_ntohs(eth_proto);
    ctx->layers.l2_offset = 0;
    ctx->layers.vlan_depth = 0;

#pragma unroll
    for (int i = 0; i < VLAN_MAX_DEPTH; i++) {
        if (vlans.id[i] > 0) {
            ctx->layers.vlan_ids[i] = vlans.id[i];
            ctx->layers.vlan_depth++;
        }
    }

    ctx->layers.l3_offset = (__u16)((char *)nh.pos - (char *)data);

    if (eth_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *iph = NULL;
        int ip_proto = parse_iphdr(&nh, data_end, &iph);

        if (ip_proto < 0 || !iph) {
            ctx->parsed = 1;
            return 0;
        }

        ctx->layers.saddr = iph->saddr;
        ctx->layers.daddr = iph->daddr;
        ctx->layers.ip_proto = iph->protocol;
        ctx->layers.l4_offset = (__u16)((char *)nh.pos - (char *)data);

        if (ip_proto == IPPROTO_TCP) {
            struct tcphdr *tcph = NULL;
            if (parse_tcphdr(&nh, data_end, &tcph) >= 0 && tcph) {
                ctx->layers.sport = tcph->source;
                ctx->layers.dport = tcph->dest;
            }
        } else if (ip_proto == IPPROTO_UDP) {
            struct udphdr *udph = NULL;
            if (parse_udphdr(&nh, data_end, &udph) >= 0 && udph) {
                ctx->layers.sport = udph->source;
                ctx->layers.dport = udph->dest;
            }
        }

        ctx->layers.payload_offset = (__u16)((char *)nh.pos - (char *)data);
        if ((void *)((char *)data + ctx->layers.payload_offset) <= data_end)
            ctx->layers.payload_len = (__u32)((char *)data_end - ((char *)data + ctx->layers.payload_offset));
    }

    ctx->parsed = 1;
    return 0;
}

static __always_inline int tunnel_try_vxlan(struct xdp_md *xdp, struct rs_ctx *ctx,
                                             struct tunnel_stats *stats)
{
    void *data = (void *)(long)xdp->data;
    void *data_end = (void *)(long)xdp->data_end;
    __u16 l3_off = ctx->layers.l3_offset & RS_L3_OFFSET_MASK;
    __u16 l4_off = ctx->layers.l4_offset & RS_L4_OFFSET_MASK;
    struct iphdr *iph = data + l3_off;
    struct udphdr *udph = data + l4_off;
    struct vxlan_hdr *vxh;
    __u32 vni;
    struct vxlan_entry *vxent;

    if ((void *)(iph + 1) > data_end || (void *)(udph + 1) > data_end) {
        if (stats)
            stats->vxlan_decap_err++;
        return 0;
    }

    if (iph->ihl != 5) {
        if (stats)
            stats->vxlan_decap_err++;
        return 0;
    }

    vxh = (void *)(udph + 1);
    if ((void *)(vxh + 1) > data_end) {
        if (stats)
            stats->vxlan_decap_err++;
        return 0;
    }

    vni = ((__u32)vxh->vni[0] << 16) | ((__u32)vxh->vni[1] << 8) | (__u32)vxh->vni[2];
    vxent = bpf_map_lookup_elem(&vxlan_vni_map, &vni);
    if (!vxent) {
        if (stats)
            stats->unknown_tunnel++;
        return 0;
    }

    if (bpf_xdp_adjust_head(xdp, VXLAN_DECAP_OUTER_LEN) < 0) {
        if (stats)
            stats->vxlan_decap_err++;
        return 0;
    }

    data = (void *)(long)xdp->data;
    data_end = (void *)(long)xdp->data_end;
    if ((void *)((char *)data + 1) > data_end) {
        if (stats)
            stats->vxlan_decap_err++;
        return 0;
    }

    if (tunnel_reparse_inner(xdp, ctx) < 0) {
        if (stats)
            stats->vxlan_decap_err++;
        return 0;
    }

    if ((__u32)((char *)data_end - (char *)data) > (INNER_MTU_MAX + RS_ETH_HLEN)) {
        if (stats)
            stats->vxlan_decap++;
        return 1;
    }

    ctx->ingress_vlan = vxent->vlan_id;
    ctx->modified = 1;
    if (stats)
        stats->vxlan_decap++;
    return 1;
}

static __always_inline int tunnel_try_gre(struct xdp_md *xdp, struct rs_ctx *ctx,
                                           struct tunnel_stats *stats)
{
    void *data = (void *)(long)xdp->data;
    void *data_end = (void *)(long)xdp->data_end;
    __u16 l3_off = ctx->layers.l3_offset & RS_L3_OFFSET_MASK;
    struct iphdr *iph = data + l3_off;
    __u16 ihl_bytes;
    struct gre_base_hdr *greh;
    __u16 gre_flags;
    __u32 tunnel_id = 0;
    __u32 gre_hdr_len = sizeof(*greh);
    struct gre_entry *grent;

    if ((void *)(iph + 1) > data_end) {
        if (stats)
            stats->gre_decap_err++;
        return 0;
    }

    ihl_bytes = (__u16)(iph->ihl * 4);
    if (ihl_bytes < sizeof(*iph) || (void *)((char *)iph + ihl_bytes) > data_end) {
        if (stats)
            stats->gre_decap_err++;
        return 0;
    }

    greh = (void *)((char *)iph + ihl_bytes);
    if ((void *)(greh + 1) > data_end) {
        if (stats)
            stats->gre_decap_err++;
        return 0;
    }

    gre_flags = bpf_ntohs(greh->flags);
    if (gre_flags & (GRE_FLAG_CSUM | GRE_FLAG_ROUTING | GRE_FLAG_SEQ)) {
        if (stats)
            stats->gre_decap_err++;
        return 0;
    }

    if (gre_flags & GRE_VERSION_MASK) {
        if (stats)
            stats->gre_decap_err++;
        return 0;
    }

    if (gre_flags & GRE_FLAG_KEY) {
        __be32 *key_ptr = (void *)(greh + 1);
        if ((void *)(key_ptr + 1) > data_end) {
            if (stats)
                stats->gre_decap_err++;
            return 0;
        }
        tunnel_id = bpf_ntohl(*key_ptr);
        gre_hdr_len += sizeof(__be32);
    }

    grent = bpf_map_lookup_elem(&gre_tunnel_map, &tunnel_id);
    if (!grent) {
        if (stats)
            stats->unknown_tunnel++;
        return 0;
    }

    if (bpf_xdp_adjust_head(xdp, RS_ETH_HLEN + ihl_bytes + gre_hdr_len) < 0) {
        if (stats)
            stats->gre_decap_err++;
        return 0;
    }

    data = (void *)(long)xdp->data;
    data_end = (void *)(long)xdp->data_end;
    if ((void *)((char *)data + 1) > data_end) {
        if (stats)
            stats->gre_decap_err++;
        return 0;
    }

    if (tunnel_reparse_inner(xdp, ctx) < 0) {
        if (stats)
            stats->gre_decap_err++;
        return 0;
    }

    if ((__u32)((char *)data_end - (char *)data) > (INNER_MTU_MAX + RS_ETH_HLEN)) {
        if (stats)
            stats->gre_decap++;
        return 1;
    }

    ctx->ingress_vlan = grent->vlan_id;
    ctx->modified = 1;
    if (stats)
        stats->gre_decap++;
    return 1;
}

SEC("xdp")
int tunnel_xdp(struct xdp_md *xdp)
{
    struct rs_ctx *ctx = RS_GET_CTX();
    struct tunnel_stats *stats;
    __u32 key = 0;
    struct tunnel_config *cfg;

    if (!ctx)
        return XDP_PASS;

    if (!ctx->parsed) {
        RS_TAIL_CALL_NEXT(xdp, ctx);
        return XDP_PASS;
    }

    if (ctx->layers.eth_proto != ETH_P_IP) {
        RS_TAIL_CALL_NEXT(xdp, ctx);
        return XDP_PASS;
    }

    cfg = bpf_map_lookup_elem(&tunnel_config_map, &key);
    if (!cfg || !cfg->enabled) {
        RS_TAIL_CALL_NEXT(xdp, ctx);
        return XDP_PASS;
    }

    stats = tunnel_get_stats();

    if (ctx->layers.ip_proto == IPPROTO_UDP &&
        bpf_ntohs(ctx->layers.dport) == VXLAN_UDP_PORT) {
        (void)tunnel_try_vxlan(xdp, ctx, stats);
        RS_TAIL_CALL_NEXT(xdp, ctx);
        return XDP_PASS;
    }

    if (ctx->layers.ip_proto == IPPROTO_GRE) {
        (void)tunnel_try_gre(xdp, ctx, stats);
        RS_TAIL_CALL_NEXT(xdp, ctx);
        return XDP_PASS;
    }

    RS_TAIL_CALL_NEXT(xdp, ctx);
    return XDP_PASS;
}
