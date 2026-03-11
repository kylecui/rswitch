// SPDX-License-Identifier: GPL-2.0

#ifndef __BPF__
#define __BPF__
#endif

#include "../include/rswitch_common.h"
#include "../core/module_abi.h"

char _license[] SEC("license") = "GPL";

RS_DECLARE_MODULE("nat", RS_HOOK_XDP_INGRESS, 55,
                  RS_FLAG_NEED_L2L3_PARSE | RS_FLAG_NEED_FLOW_INFO |
                      RS_FLAG_MODIFIES_PACKET | RS_FLAG_MAY_DROP,
                  "NAT - SNAT/DNAT address translation");

RS_DEPENDS_ON("conntrack");

enum nat_mode {
    NAT_MODE_NONE = 0,
    NAT_MODE_SNAT = 1,
    NAT_MODE_DNAT = 2,
    NAT_MODE_MASQ = 3,
};

struct nat_key {
    __be32 addr;
    __be16 port;
    __u8 proto;
    __u8 mode;
} __attribute__((packed));

struct nat_entry {
    __be32 translated_addr;
    __be16 translated_port;
    __be16 pad;
    __u64 last_used_ns;
    __u64 pkts;
    __u64 bytes;
} __attribute__((aligned(8)));

struct dnat_rule {
    __be32 external_addr;
    __be16 external_port;
    __u8 proto;
    __u8 enabled;
    __be32 internal_addr;
    __be16 internal_port;
    __be16 pad;
} __attribute__((aligned(8)));

struct snat_config {
    __u8 enabled;
    __u8 mode;
    __u8 pad[2];
    __be32 snat_addr;
    __be16 port_range_start;
    __be16 port_range_end;
} __attribute__((aligned(8)));

struct nat_config {
    __u8 enabled;
    __u8 pad[3];
    __u32 tcp_timeout;
    __u32 udp_timeout;
} __attribute__((aligned(8)));

struct dnat_rule_key {
    __be32 addr;
    __be16 port;
    __u8 proto;
    __u8 pad;
} __attribute__((packed));

enum nat_stat_type {
    NAT_STAT_SNAT_PKTS = 0,
    NAT_STAT_DNAT_PKTS = 1,
    NAT_STAT_SNAT_NEW = 2,
    NAT_STAT_DNAT_NEW = 3,
    NAT_STAT_SNAT_MISS = 4,
    NAT_STAT_DNAT_MISS = 5,
    NAT_STAT_ERRORS = 6,
    NAT_STAT_TOTAL = 7,
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct nat_key);
    __type(value, struct nat_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} nat_table SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct dnat_rule_key);
    __type(value, struct dnat_rule);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} dnat_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, struct snat_config);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} snat_config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct nat_config);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} nat_config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} nat_stats_map SEC(".maps");

static __always_inline void nat_stat_inc(__u32 stat)
{
    __u64 *counter = bpf_map_lookup_elem(&nat_stats_map, &stat);
    if (counter)
        __sync_fetch_and_add(counter, 1);
}

static __always_inline __u16 csum_fold16(__u32 sum)
{
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    return (__u16)sum;
}

static __always_inline void update_ip_csum(struct iphdr *iph, __be32 old_addr, __be32 new_addr)
{
    __u32 old32 = bpf_ntohl(old_addr);
    __u32 new32 = bpf_ntohl(new_addr);
    __u16 old_hi = (__u16)(old32 >> 16);
    __u16 old_lo = (__u16)(old32 & 0xffff);
    __u16 new_hi = (__u16)(new32 >> 16);
    __u16 new_lo = (__u16)(new32 & 0xffff);
    __u32 sum = (~bpf_ntohs(iph->check)) & 0xffff;

    sum += (~old_hi) & 0xffff;
    sum += (~old_lo) & 0xffff;
    sum += new_hi;
    sum += new_lo;

    iph->check = bpf_htons((__u16)(~csum_fold16(sum)));
}

static __always_inline void update_l4_csum_addr(__sum16 *check, __be32 old_addr, __be32 new_addr)
{
    __u32 old32 = bpf_ntohl(old_addr);
    __u32 new32 = bpf_ntohl(new_addr);
    __u16 old_hi = (__u16)(old32 >> 16);
    __u16 old_lo = (__u16)(old32 & 0xffff);
    __u16 new_hi = (__u16)(new32 >> 16);
    __u16 new_lo = (__u16)(new32 & 0xffff);
    __u32 sum = (~bpf_ntohs(*check)) & 0xffff;

    sum += (~old_hi) & 0xffff;
    sum += (~old_lo) & 0xffff;
    sum += new_hi;
    sum += new_lo;

    *check = bpf_htons((__u16)(~csum_fold16(sum)));
}

static __always_inline void update_l4_csum_port(__sum16 *check, __be16 old_port, __be16 new_port)
{
    __u16 old16 = bpf_ntohs(old_port);
    __u16 new16 = bpf_ntohs(new_port);
    __u32 sum = (~bpf_ntohs(*check)) & 0xffff;

    sum += (~old16) & 0xffff;
    sum += new16;

    *check = bpf_htons((__u16)(~csum_fold16(sum)));
}

static __always_inline __be16 nat_alloc_port(struct rs_ctx *ctx,
                                             const struct snat_config *cfg,
                                             __be16 fallback_port)
{
    __u16 start = bpf_ntohs(cfg->port_range_start);
    __u16 end = bpf_ntohs(cfg->port_range_end);
    __u32 hash;
    __u32 span;

    if (start == 0 || end == 0 || end < start)
        return fallback_port;

    span = (__u32)end - (__u32)start + 1;
    hash = (__u32)ctx->layers.saddr ^ (__u32)ctx->layers.daddr ^
           (((__u32)ctx->layers.sport << 16) | (__u32)ctx->layers.dport) ^
           (__u32)ctx->layers.ip_proto ^ ctx->egress_ifindex;

    return bpf_htons((__u16)(start + (hash % span)));
}

SEC("xdp")
int nat(struct xdp_md *xdp_ctx)
{
    void *data = (void *)(long)xdp_ctx->data;
    void *data_end = (void *)(long)xdp_ctx->data_end;
    struct rs_ctx *ctx = RS_GET_CTX();
    struct iphdr *iph;
    void *l4;
    bool modified = false;
    __u32 cfg_key = 0;
    __u64 now_ns = bpf_ktime_get_ns();
    __u64 pkt_len = (__u64)((char *)data_end - (char *)data);

    if (!ctx)
        return XDP_PASS;

    struct nat_config *cfg = bpf_map_lookup_elem(&nat_config_map, &cfg_key);
    if (!cfg || !cfg->enabled) {
        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_PASS;
    }

    nat_stat_inc(NAT_STAT_TOTAL);

    if (ctx->layers.eth_proto != ETH_P_IP) {
        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_PASS;
    }

    iph = data + (ctx->layers.l3_offset & RS_L3_OFFSET_MASK);
    if ((void *)(iph + 1) > data_end) {
        nat_stat_inc(NAT_STAT_ERRORS);
        return XDP_DROP;
    }

    if (iph->ihl < 5 || (void *)iph + ((__u64)iph->ihl * 4) > data_end) {
        nat_stat_inc(NAT_STAT_ERRORS);
        return XDP_DROP;
    }

    l4 = data + (ctx->layers.l4_offset & RS_L4_OFFSET_MASK);

    if (ctx->layers.ip_proto == IPPROTO_TCP) {
        struct tcphdr *tcph = l4;
        if ((void *)(tcph + 1) > data_end) {
            nat_stat_inc(NAT_STAT_ERRORS);
            return XDP_DROP;
        }
    } else if (ctx->layers.ip_proto == IPPROTO_UDP) {
        struct udphdr *udph = l4;
        if ((void *)(udph + 1) > data_end) {
            nat_stat_inc(NAT_STAT_ERRORS);
            return XDP_DROP;
        }
    }

    if (ctx->layers.ip_proto == IPPROTO_TCP || ctx->layers.ip_proto == IPPROTO_UDP) {
        struct dnat_rule_key dkey = {
            .addr = ctx->layers.daddr,
            .port = ctx->layers.dport,
            .proto = ctx->layers.ip_proto,
            .pad = 0,
        };
        struct dnat_rule *rule = bpf_map_lookup_elem(&dnat_rules, &dkey);

        if (rule && rule->enabled) {
            __be32 old_daddr = iph->daddr;
            __be16 old_dport = ctx->layers.dport;
            __be32 new_daddr = rule->internal_addr;
            __be16 new_dport = rule->internal_port;

            iph->daddr = new_daddr;
            update_ip_csum(iph, old_daddr, new_daddr);

            if (ctx->layers.ip_proto == IPPROTO_TCP) {
                struct tcphdr *tcph = l4;

                update_l4_csum_addr(&tcph->check, old_daddr, new_daddr);
                if (old_dport != new_dport) {
                    update_l4_csum_port(&tcph->check, old_dport, new_dport);
                    tcph->dest = new_dport;
                }
            } else {
                struct udphdr *udph = l4;

                if (udph->check) {
                    update_l4_csum_addr(&udph->check, old_daddr, new_daddr);
                    if (old_dport != new_dport)
                        update_l4_csum_port(&udph->check, old_dport, new_dport);
                }
                if (old_dport != new_dport)
                    udph->dest = new_dport;
            }

            if ((void *)(iph + 1) > data_end) {
                nat_stat_inc(NAT_STAT_ERRORS);
                return XDP_DROP;
            }

            ctx->layers.daddr = new_daddr;
            ctx->layers.dport = new_dport;
            modified = true;
            nat_stat_inc(NAT_STAT_DNAT_PKTS);
            nat_stat_inc(NAT_STAT_DNAT_NEW);
        } else {
            nat_stat_inc(NAT_STAT_DNAT_MISS);
        }
    }

    {
        __u32 snat_key = ctx->egress_ifindex;
        struct snat_config *scfg = bpf_map_lookup_elem(&snat_config_map, &snat_key);

        if (scfg && scfg->enabled &&
            (scfg->mode == NAT_MODE_SNAT || scfg->mode == NAT_MODE_MASQ) &&
            (ctx->layers.ip_proto == IPPROTO_TCP || ctx->layers.ip_proto == IPPROTO_UDP)) {
            __be32 translated_addr = scfg->snat_addr;
            struct nat_key nkey = {
                .addr = ctx->layers.saddr,
                .port = ctx->layers.sport,
                .proto = ctx->layers.ip_proto,
                .mode = scfg->mode,
            };
            struct nat_entry *existing;
            struct nat_entry entry = {};
            __be32 old_saddr = iph->saddr;
            __be16 old_sport = ctx->layers.sport;
            __be32 new_saddr;
            __be16 new_sport;

            if (!translated_addr)
                translated_addr = old_saddr;

            existing = bpf_map_lookup_elem(&nat_table, &nkey);
            if (existing) {
                new_saddr = existing->translated_addr;
                new_sport = existing->translated_port;

                existing->last_used_ns = now_ns;
                existing->pkts++;
                existing->bytes += pkt_len;
            } else {
                new_saddr = translated_addr;
                new_sport = nat_alloc_port(ctx, scfg, old_sport);

                entry.translated_addr = new_saddr;
                entry.translated_port = new_sport;
                entry.pad = 0;
                entry.last_used_ns = now_ns;
                entry.pkts = 1;
                entry.bytes = pkt_len;

                if (bpf_map_update_elem(&nat_table, &nkey, &entry, BPF_ANY) < 0)
                    nat_stat_inc(NAT_STAT_ERRORS);
                else
                    nat_stat_inc(NAT_STAT_SNAT_NEW);
            }

            if (new_saddr != old_saddr || new_sport != old_sport) {
                iph->saddr = new_saddr;
                update_ip_csum(iph, old_saddr, new_saddr);

                if (ctx->layers.ip_proto == IPPROTO_TCP) {
                    struct tcphdr *tcph = l4;

                    update_l4_csum_addr(&tcph->check, old_saddr, new_saddr);
                    if (old_sport != new_sport) {
                        update_l4_csum_port(&tcph->check, old_sport, new_sport);
                        tcph->source = new_sport;
                    }
                } else {
                    struct udphdr *udph = l4;

                    if (udph->check) {
                        update_l4_csum_addr(&udph->check, old_saddr, new_saddr);
                        if (old_sport != new_sport)
                            update_l4_csum_port(&udph->check, old_sport, new_sport);
                    }
                    if (old_sport != new_sport)
                        udph->source = new_sport;
                }

                if ((void *)(iph + 1) > data_end) {
                    nat_stat_inc(NAT_STAT_ERRORS);
                    return XDP_DROP;
                }

                ctx->layers.saddr = new_saddr;
                ctx->layers.sport = new_sport;
                modified = true;
            }

            nat_stat_inc(NAT_STAT_SNAT_PKTS);
        } else {
            nat_stat_inc(NAT_STAT_SNAT_MISS);
        }
    }

    if (modified)
        ctx->modified = 1;

    RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
    return XDP_PASS;
}
