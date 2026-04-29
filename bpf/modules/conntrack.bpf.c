// SPDX-License-Identifier: GPL-2.0

#include "../include/rswitch_common.h"

enum {
    RS_THIS_STAGE_ID  = 32,
    RS_THIS_MODULE_ID = RS_MOD_USER_BASE + 9,
};

char _license[] SEC("license") = "GPL";

RS_DECLARE_MODULE("conntrack", RS_HOOK_XDP_INGRESS, 32,
                  RS_FLAG_NEED_L2L3_PARSE | RS_FLAG_NEED_FLOW_INFO | RS_FLAG_MAY_DROP,
                  "Stateful connection tracking");

#define CT_MAX_ENTRIES 65536
#define CT_STAT_MAX 8

#define CT_DEFAULT_TCP_EST_TIMEOUT 3600
#define CT_DEFAULT_TCP_SYN_TIMEOUT 120
#define CT_DEFAULT_UDP_TIMEOUT 30
#define CT_DEFAULT_ICMP_TIMEOUT 30
#define CT_DEFAULT_CLOSE_TIMEOUT 30

#define CT_TCP_FLAG_SYN 0x01
#define CT_TCP_FLAG_ACK 0x02
#define CT_TCP_FLAG_FIN 0x04
#define CT_TCP_FLAG_RST 0x08

enum ct_state {
    CT_STATE_NONE = 0,
    CT_STATE_NEW = 1,
    CT_STATE_ESTABLISHED = 2,
    CT_STATE_RELATED = 3,
    CT_STATE_INVALID = 4,
};

struct ct_key {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8 proto;
    __u8 pad[3];
} __attribute__((packed));

struct ct_entry {
    __u8 state;
    __u8 flags;
    __u8 direction;
    __u8 pad;
    __u64 created_ns;
    __u64 last_seen_ns;
    __u64 pkts_orig;
    __u64 pkts_reply;
    __u64 bytes_orig;
    __u64 bytes_reply;
    __u32 timeout_sec;
} __attribute__((aligned(8)));

struct ct_config {
    __u8 enabled;
    __u8 default_action;
    __u8 pad[2];
    __u32 tcp_est_timeout;
    __u32 tcp_syn_timeout;
    __u32 udp_timeout;
    __u32 icmp_timeout;
} __attribute__((aligned(8)));

enum ct_stat_type {
    CT_STAT_NEW = 0,
    CT_STAT_ESTABLISHED = 1,
    CT_STAT_RELATED = 2,
    CT_STAT_INVALID = 3,
    CT_STAT_TIMEOUT = 4,
    CT_STAT_DROPS = 5,
    CT_STAT_TOTAL = 6,
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, CT_MAX_ENTRIES);
    __type(key, struct ct_key);
    __type(value, struct ct_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ct_table SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct ct_config);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ct_config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, CT_STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ct_stats_map SEC(".maps");

static __always_inline void ct_stat_inc(__u32 stat)
{
    __u64 *counter = bpf_map_lookup_elem(&ct_stats_map, &stat);
    if (counter)
        __sync_fetch_and_add(counter, 1);
}

static __always_inline __u32 get_default_timeout(__u8 proto, const struct ct_config *cfg)
{
    if (proto == IPPROTO_TCP)
        return cfg->tcp_syn_timeout ? cfg->tcp_syn_timeout : CT_DEFAULT_TCP_SYN_TIMEOUT;
    if (proto == IPPROTO_UDP)
        return cfg->udp_timeout ? cfg->udp_timeout : CT_DEFAULT_UDP_TIMEOUT;
    if (proto == IPPROTO_ICMP)
        return cfg->icmp_timeout ? cfg->icmp_timeout : CT_DEFAULT_ICMP_TIMEOUT;

    return CT_DEFAULT_UDP_TIMEOUT;
}

static __always_inline __u8 make_ct_key(struct rs_ctx *ctx, struct ct_key *key)
{
    __u32 saddr_h = bpf_ntohl(ctx->layers.saddr);
    __u32 daddr_h = bpf_ntohl(ctx->layers.daddr);
    __u16 sport_h = bpf_ntohs(ctx->layers.sport);
    __u16 dport_h = bpf_ntohs(ctx->layers.dport);
    __u8 direction = 0;

    if (saddr_h < daddr_h || (saddr_h == daddr_h && sport_h <= dport_h)) {
        key->src_ip = ctx->layers.saddr;
        key->dst_ip = ctx->layers.daddr;
        key->src_port = ctx->layers.sport;
        key->dst_port = ctx->layers.dport;
        direction = 0;
    } else {
        key->src_ip = ctx->layers.daddr;
        key->dst_ip = ctx->layers.saddr;
        key->src_port = ctx->layers.dport;
        key->dst_port = ctx->layers.sport;
        direction = 1;
    }

    key->proto = ctx->layers.ip_proto;
    key->pad[0] = 0;
    key->pad[1] = 0;
    key->pad[2] = 0;
    return direction;
}

static __always_inline __u8 get_tcp_flags(void *data, void *data_end, struct rs_ctx *ctx)
{
    struct tcphdr *tcph = data + (ctx->layers.l4_offset & RS_L4_OFFSET_MASK);
    __u8 flags = 0;

    if ((void *)(tcph + 1) > data_end)
        return 0;

    if (tcph->syn)
        flags |= CT_TCP_FLAG_SYN;
    if (tcph->ack)
        flags |= CT_TCP_FLAG_ACK;
    if (tcph->fin)
        flags |= CT_TCP_FLAG_FIN;
    if (tcph->rst)
        flags |= CT_TCP_FLAG_RST;

    return flags;
}

static __always_inline void reset_ct_entry(struct ct_entry *entry, __u64 now_ns,
                                           __u8 direction, __u32 timeout_sec)
{
    __builtin_memset(entry, 0, sizeof(*entry));
    entry->state = CT_STATE_NEW;
    entry->direction = direction;
    entry->created_ns = now_ns;
    entry->last_seen_ns = now_ns;
    entry->timeout_sec = timeout_sec;
}

SEC("xdp")
int conntrack(struct xdp_md *xdp_ctx)
{
    void *data = (void *)(long)xdp_ctx->data;
    void *data_end = (void *)(long)xdp_ctx->data_end;
    struct rs_ctx *ctx = RS_GET_CTX();
    __u64 now_ns = bpf_ktime_get_ns();
    __u64 pkt_len = (__u64)((char *)data_end - (char *)data);
    struct ct_key key = {};
    struct ct_entry entry = {};
    struct ct_entry *found;
    __u8 direction;
    __u32 cfg_key = 0;
    __u32 timeout_sec;
    __u64 timeout_ns;

    if (!ctx)
        return XDP_PASS;

    RS_OBS_STAGE_HIT(xdp_ctx, ctx, (__u32)pkt_len);

    struct ct_config *cfg = bpf_map_lookup_elem(&ct_config_map, &cfg_key);
    if (!cfg || !cfg->enabled) {
        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_PASS;
    }

    if (ctx->layers.eth_proto != ETH_P_IP) {
        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_PASS;
    }

    direction = make_ct_key(ctx, &key);
    found = bpf_map_lookup_elem(&ct_table, &key);

    ct_stat_inc(CT_STAT_TOTAL);

    if (!found) {
        timeout_sec = get_default_timeout(ctx->layers.ip_proto, cfg);
        reset_ct_entry(&entry, now_ns, direction, timeout_sec);

        if (direction == 0) {
            entry.pkts_orig = 1;
            entry.bytes_orig = pkt_len;
        } else {
            entry.pkts_reply = 1;
            entry.bytes_reply = pkt_len;
        }

        if (ctx->layers.ip_proto == IPPROTO_TCP)
            entry.flags = get_tcp_flags(data, data_end, ctx);

        if (bpf_map_update_elem(&ct_table, &key, &entry, BPF_ANY) == 0)
            ct_stat_inc(CT_STAT_NEW);

        if (cfg->default_action) {
            ct_stat_inc(CT_STAT_DROPS);
            return XDP_DROP;
        }

        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_PASS;
    }

    timeout_sec = found->timeout_sec;
    if (!timeout_sec)
        timeout_sec = get_default_timeout(ctx->layers.ip_proto, cfg);

    timeout_ns = (__u64)timeout_sec * 1000000000ULL;
    if (now_ns > found->last_seen_ns && (now_ns - found->last_seen_ns) > timeout_ns) {
        ct_stat_inc(CT_STAT_TIMEOUT);

        reset_ct_entry(&entry, now_ns, direction, timeout_sec);
        if (direction == 0) {
            entry.pkts_orig = 1;
            entry.bytes_orig = pkt_len;
        } else {
            entry.pkts_reply = 1;
            entry.bytes_reply = pkt_len;
        }

        if (ctx->layers.ip_proto == IPPROTO_TCP)
            entry.flags = get_tcp_flags(data, data_end, ctx);

        bpf_map_update_elem(&ct_table, &key, &entry, BPF_ANY);
        ct_stat_inc(CT_STAT_NEW);

        if (cfg->default_action) {
            ct_stat_inc(CT_STAT_DROPS);
            return XDP_DROP;
        }

        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_PASS;
    }

    entry = *found;
    entry.last_seen_ns = now_ns;
    entry.direction = direction;

    if (direction == 0) {
        entry.pkts_orig++;
        entry.bytes_orig += pkt_len;
    } else {
        entry.pkts_reply++;
        entry.bytes_reply += pkt_len;
    }

    if (ctx->layers.ip_proto == IPPROTO_TCP) {
        __u8 tcp_flags = get_tcp_flags(data, data_end, ctx);
        entry.flags |= tcp_flags;

        if (tcp_flags & CT_TCP_FLAG_RST) {
            ct_stat_inc(CT_STAT_INVALID);
            bpf_map_delete_elem(&ct_table, &key);
            if (cfg->default_action) {
                ct_stat_inc(CT_STAT_DROPS);
                return XDP_DROP;
            }

            RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
            return XDP_PASS;
        }

        if (tcp_flags & CT_TCP_FLAG_FIN)
            entry.timeout_sec = CT_DEFAULT_CLOSE_TIMEOUT;

        if ((tcp_flags & CT_TCP_FLAG_SYN) && !(tcp_flags & CT_TCP_FLAG_ACK))
            entry.state = CT_STATE_NEW;

        if ((tcp_flags & CT_TCP_FLAG_SYN) && (tcp_flags & CT_TCP_FLAG_ACK) && direction == 1) {
            entry.state = CT_STATE_ESTABLISHED;
            entry.timeout_sec = cfg->tcp_est_timeout ? cfg->tcp_est_timeout : CT_DEFAULT_TCP_EST_TIMEOUT;
        }
    } else if (entry.state == CT_STATE_NONE) {
        entry.state = CT_STATE_ESTABLISHED;
    }

    if (entry.state == CT_STATE_NEW)
        ct_stat_inc(CT_STAT_NEW);
    else if (entry.state == CT_STATE_ESTABLISHED)
        ct_stat_inc(CT_STAT_ESTABLISHED);
    else if (entry.state == CT_STATE_RELATED)
        ct_stat_inc(CT_STAT_RELATED);
    else if (entry.state == CT_STATE_INVALID)
        ct_stat_inc(CT_STAT_INVALID);

    bpf_map_update_elem(&ct_table, &key, &entry, BPF_ANY);

    RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
    return XDP_PASS;
}
