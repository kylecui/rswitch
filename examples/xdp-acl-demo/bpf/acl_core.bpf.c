
// bpf/acl_core.bpf.c
#include "include/common.h"
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>

char LICENSE[] SEC("license") = "GPL";

static __always_inline int apply_action(struct xdp_md *ctx, const struct acl_action *a)
{
    switch (a->type) {
        case ACL_DROP:
            incr_stat(STAT_DROP);
            return XDP_DROP;
        case ACL_REDIRECT: {
            // If ifindex == 0 and xsks_map has entry for this queue, redirect to AF_XDP
            __u32 q = ctx->rx_queue_index;
            if (a->ifindex == 0) {
                // Try redirect to XSK map slot for this queue
                int rc = bpf_redirect_map(&xsks_map, q, 0);
                if (rc == XDP_REDIRECT) {
                    incr_stat(STAT_REDIRECT);
                    return rc;
                }
                // Fallthrough to PASS if no xsk is attached
                incr_stat(STAT_PASS);
                return XDP_PASS;
            } else {
                int rc = bpf_redirect(a->ifindex, 0);
                if (rc == XDP_REDIRECT) {
                    incr_stat(STAT_REDIRECT);
                    return rc;
                }
                // fallback
                incr_stat(STAT_PASS);
                return XDP_PASS;
            }
        }
        case ACL_MIRROR:
            // Demo: write a small record to ringbuf and PASS
            incr_stat(STAT_PASS);
            return XDP_PASS;
        case ACL_PASS:
        default:
            incr_stat(STAT_PASS);
            return XDP_PASS;
    }
}

static __always_inline int parse_eth(void **data, void *data_end, __u16 *eth_proto, __u16 *vlan_id)
{
    struct ethhdr *eth = *data;
    if ((void*)(eth + 1) > data_end) return -1;

    *eth_proto = bpf_ntohs(eth->h_proto);
    *vlan_id = 0;

    // Single/Double VLAN (QinQ) minimal support
#pragma clang loop unroll(full)
    for (int i = 0; i < 2; i++) {
        if (*eth_proto == ETH_P_8021Q || *eth_proto == ETH_P_8021AD) {
            struct {
                __be16 tci;
                __be16 proto;
            } *vlan = (void*)eth + sizeof(*eth) + i * sizeof(*vlan);
            if ((void*)(vlan + 1) > data_end) return -1;
            *vlan_id = bpf_ntohs(vlan->tci) & 0x0fff;
            *eth_proto = bpf_ntohs(vlan->proto);
            *data = (void*)vlan + sizeof(*vlan);
        }
    }

    // Advance data pointer to payload after eth/vlan
    *data = (void*)eth + sizeof(*eth);
    return 0;
}

SEC("xdp")
int xdp_acl_core(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    __u16 eth_proto = 0, vlan_id = 0;
    if (parse_eth(&data, data_end, &eth_proto, &vlan_id) < 0)
        return XDP_PASS;

    if (eth_proto != ETH_P_IP) {
        // Non-IPv4: for demo we just PASS (IPv6 can be added later)
        incr_stat(STAT_PASS);
        return XDP_PASS;
    }

    struct iphdr *iph = data;
    if ((void*)(iph + 1) > data_end) return XDP_PASS;
    if (iph->ihl < 5) return XDP_PASS;

    __u8 proto = iph->protocol;
    __u32 ihl_bytes = iph->ihl * 4;
    void *l4 = (void*)iph + ihl_bytes;
    if (l4 > data_end) return XDP_PASS;

    __u16 sport = 0, dport = 0;
    if (proto == IPPROTO_TCP) {
        struct tcphdr *th = l4;
        if ((void*)(th + 1) > data_end) return XDP_PASS;
        sport = bpf_ntohs(th->source);
        dport = bpf_ntohs(th->dest);
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *uh = l4;
        if ((void*)(uh + 1) > data_end) return XDP_PASS;
        sport = bpf_ntohs(uh->source);
        dport = bpf_ntohs(uh->dest);
    } else {
        sport = 0; dport = 0;
    }

    // 1) exact 5-tuple match
    struct key_5t_v4 k = {0};
    k.proto = proto; k.ip_v = 4;
    k.l4_sport = sport; k.l4_dport = dport;
    k.src_v4 = iph->saddr; k.dst_v4 = iph->daddr;

    struct acl_action *act = bpf_map_lookup_elem(&map_acl_5t_v4, &k);
    if (act) {
        incr_stat(STAT_HIT_5T);
        return apply_action(ctx, act);
    }

    // 2) LPM src/dst
    struct lpm_v4_key lpmk = {.prefixlen = 32, .ip = iph->saddr};
    act = bpf_map_lookup_elem(&map_acl_lpm_v4_src, &lpmk);
    if (act) {
        incr_stat(STAT_HIT_LPM);
        return apply_action(ctx, act);
    }

    lpmk.ip = iph->daddr;
    act = bpf_map_lookup_elem(&map_acl_lpm_v4_dst, &lpmk);
    if (act) {
        incr_stat(STAT_HIT_LPM);
        return apply_action(ctx, act);
    }

    // Default: PASS
    incr_stat(STAT_PASS);
    return XDP_PASS;
}
