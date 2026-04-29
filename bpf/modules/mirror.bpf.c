// SPDX-License-Identifier: GPL-2.0
/*
 * rSwitch Mirror (SPAN) Module - Enhanced Version
 *
 * Advanced port mirroring with comprehensive filtering and pcap capture.
 * Supports mirroring to SPAN port or ring buffer for userspace pcap capture.
 */

#include "../include/rswitch_common.h"

enum {
    RS_THIS_STAGE_ID  = 70,
    RS_THIS_MODULE_ID = RS_MOD_MIRROR,
};


char _license[] SEC("license") = "GPL";

RS_DECLARE_MODULE(
    "mirror",
    RS_HOOK_XDP_INGRESS,
    45,
    RS_FLAG_NEED_L2L3_PARSE | RS_FLAG_CREATES_EVENTS | RS_FLAG_MAY_REDIRECT,
    "Port mirroring (SPAN) with advanced filtering"
);

#define MIRROR_MAX_RULES        64
#define MIRROR_MAX_SESSIONS     4
#define MIRROR_PCAP_MAX_SIZE    1514

enum mirror_filter_type {
    MIRROR_FILTER_NONE = 0,
    MIRROR_FILTER_SRC_MAC,
    MIRROR_FILTER_DST_MAC,
    MIRROR_FILTER_SRC_IP,
    MIRROR_FILTER_DST_IP,
    MIRROR_FILTER_PROTOCOL,
    MIRROR_FILTER_SRC_PORT,
    MIRROR_FILTER_DST_PORT,
    MIRROR_FILTER_VLAN,
    MIRROR_FILTER_IFINDEX,
    MIRROR_FILTER_NETFLOW,
};

enum mirror_direction {
    MIRROR_DIR_BOTH = 0,
    MIRROR_DIR_INGRESS = 1,
    MIRROR_DIR_EGRESS = 2,
};

enum mirror_type {
    MIRROR_TYPE_SPAN = 0,
    MIRROR_TYPE_RSPAN = 1,
    MIRROR_TYPE_ERSPAN = 2,
};

struct mirror_filter_rule {
    __u32 id;
    __u8 enabled;
    __u8 filter_type;
    __u8 direction;
    __u8 negate;

    union {
        __u8 mac[6];
        __be32 ip;
        __be16 l4_port;
        __u16 vlan;
        __u32 ifindex;
        __u8 protocol;
        struct {
            __be32 src_ip;
            __be32 dst_ip;
            __be16 src_port;
            __be16 dst_port;
            __u8 protocol;
            __u8 _pad[3];
        } netflow;
    } match;

    __u32 _pad;
    __u64 match_count;
};

struct mirror_config {
    __u32 enabled;
    __u32 span_port;

    __u8 ingress_enabled;
    __u8 egress_enabled;
    __u8 pcap_enabled;
    __u8 filter_mode;

    __u16 vlan_filter;
    __u16 protocol_filter;

    __u8 mirror_type;
    __u8 rspan_pad[3];
    __u16 rspan_vlan_id;
    __u16 truncate_size;

    __u64 ingress_mirrored_packets;
    __u64 ingress_mirrored_bytes;
    __u64 egress_mirrored_packets;
    __u64 egress_mirrored_bytes;
    __u64 mirror_drops;
    __u64 pcap_packets;
};

struct mirror_session_stats {
    __u64 pkts;
    __u64 bytes;
    __u64 drops;
};

struct port_mirror_config {
    __u8 mirror_ingress;
    __u8 mirror_egress;
    __u16 _reserved;
};

struct mirror_pcap_event {
    __u64 timestamp;
    __u32 ifindex;
    __u32 pkt_len;
    __u32 cap_len;
    __u8 direction;
    __u8 _pad[3];
    __u8 data[MIRROR_PCAP_MAX_SIZE];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MIRROR_MAX_SESSIONS);
    __type(key, __u32);
    __type(value, struct mirror_config);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} mirror_config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MIRROR_MAX_SESSIONS);
    __type(key, __u32);
    __type(value, struct mirror_session_stats);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} mirror_session_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, struct port_mirror_config);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} port_mirror_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MIRROR_MAX_RULES);
    __type(key, __u32);
    __type(value, struct mirror_filter_rule);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} mirror_filter_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rs_stats);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} mirror_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} mirror_pcap_rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u32);
} tx_port SEC(".maps");

static __always_inline int mac_equal(const __u8 *a, const __u8 *b)
{
    return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] &&
           a[3] == b[3] && a[4] == b[4] && a[5] == b[5];
}

static __always_inline int check_filter_rule(struct xdp_md *ctx,
                                             struct mirror_filter_rule *rule,
                                             int is_ingress,
                                             __u32 ifindex)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    if (!rule->enabled)
        return -1;

    if (rule->direction == MIRROR_DIR_INGRESS && !is_ingress)
        return -1;
    if (rule->direction == MIRROR_DIR_EGRESS && is_ingress)
        return -1;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    int matched = 0;

    switch (rule->filter_type) {
    case MIRROR_FILTER_SRC_MAC:
        matched = mac_equal(eth->h_source, rule->match.mac);
        break;

    case MIRROR_FILTER_DST_MAC:
        matched = mac_equal(eth->h_dest, rule->match.mac);
        break;

    case MIRROR_FILTER_IFINDEX:
        matched = (ifindex == rule->match.ifindex);
        break;

    case MIRROR_FILTER_VLAN: {
        __u16 eth_proto = bpf_ntohs(eth->h_proto);
        if (eth_proto == ETH_P_8021Q) {
            struct vlan_hdr *vhdr = (void *)(eth + 1);
            if ((void *)(vhdr + 1) <= data_end) {
                __u16 vlan_id = bpf_ntohs(vhdr->h_vlan_TCI) & 0x0FFF;
                matched = (vlan_id == rule->match.vlan);
            }
        }
        break;
    }

    case MIRROR_FILTER_PROTOCOL:
    case MIRROR_FILTER_SRC_IP:
    case MIRROR_FILTER_DST_IP:
    case MIRROR_FILTER_SRC_PORT:
    case MIRROR_FILTER_DST_PORT:
    case MIRROR_FILTER_NETFLOW: {
        __u16 eth_proto = bpf_ntohs(eth->h_proto);
        void *l3_hdr = (void *)(eth + 1);

        if (eth_proto == ETH_P_8021Q) {
            struct vlan_hdr *vhdr = l3_hdr;
            if ((void *)(vhdr + 1) > data_end)
                return -1;
            eth_proto = bpf_ntohs(vhdr->h_vlan_encapsulated_proto);
            l3_hdr = (void *)(vhdr + 1);
        }

        if (eth_proto != ETH_P_IP)
            return -1;

        struct iphdr *iph = l3_hdr;
        if ((void *)(iph + 1) > data_end)
            return -1;

        if (rule->filter_type == MIRROR_FILTER_PROTOCOL) {
            matched = (iph->protocol == rule->match.protocol);
        } else if (rule->filter_type == MIRROR_FILTER_SRC_IP) {
            matched = (iph->saddr == rule->match.ip);
        } else if (rule->filter_type == MIRROR_FILTER_DST_IP) {
            matched = (iph->daddr == rule->match.ip);
        } else {
            if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
                return -1;

            __u32 ihl = iph->ihl * 4;
            if (ihl < 20 || ihl > 60)
                return -1;

            void *l4_hdr = l3_hdr + ihl;
            struct udphdr *udph = l4_hdr;
            if ((void *)(udph + 1) > data_end)
                return -1;

            if (rule->filter_type == MIRROR_FILTER_SRC_PORT) {
                matched = (udph->source == rule->match.l4_port);
            } else if (rule->filter_type == MIRROR_FILTER_DST_PORT) {
                matched = (udph->dest == rule->match.l4_port);
            } else {
                matched = (iph->saddr == rule->match.netflow.src_ip ||
                          rule->match.netflow.src_ip == 0) &&
                         (iph->daddr == rule->match.netflow.dst_ip ||
                          rule->match.netflow.dst_ip == 0) &&
                         (udph->source == rule->match.netflow.src_port ||
                          rule->match.netflow.src_port == 0) &&
                         (udph->dest == rule->match.netflow.dst_port ||
                          rule->match.netflow.dst_port == 0) &&
                         (iph->protocol == rule->match.netflow.protocol ||
                          rule->match.netflow.protocol == 0);
            }
        }
        break;
    }

    default:
        return -1;
    }

    if (rule->negate)
        matched = !matched;

    return matched ? 1 : 0;
}

static __always_inline int check_all_filters(struct xdp_md *ctx,
                                             struct mirror_config *config,
                                             int is_ingress,
                                             __u32 ifindex,
                                             __u16 vlan_id)
{
    if (config->vlan_filter != 0 && config->vlan_filter != vlan_id)
        return 0;

    if (config->protocol_filter != 0) {
        void *data_end = (void *)(long)ctx->data_end;
        void *data = (void *)(long)ctx->data;
        struct ethhdr *eth = data;
        if ((void *)(eth + 1) > data_end)
            return 0;
        __u16 eth_proto = bpf_ntohs(eth->h_proto);
        if (config->protocol_filter != eth_proto)
            return 0;
    }

    int has_rules = 0;
    int any_match = 0;

    #pragma unroll
    for (__u32 i = 0; i < 16; i++) {
        __u32 key = i;
        struct mirror_filter_rule *rule = bpf_map_lookup_elem(&mirror_filter_rules, &key);
        if (!rule || !rule->enabled)
            continue;

        has_rules = 1;
        int result = check_filter_rule(ctx, rule, is_ingress, ifindex);
        if (result == 1) {
            __sync_fetch_and_add(&rule->match_count, 1);
            any_match = 1;
        }
    }

    return has_rules ? any_match : 1;
}

static __always_inline void send_to_pcap_ringbuf(struct xdp_md *ctx,
                                                  struct mirror_config *config,
                                                  int is_ingress,
                                                  __u32 ifindex)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    __u32 pkt_len = data_end - data;
    __u32 cap_len = pkt_len;

    if (cap_len > MIRROR_PCAP_MAX_SIZE)
        cap_len = MIRROR_PCAP_MAX_SIZE;

    if (config->truncate_size > 0 && config->truncate_size < cap_len)
        cap_len = config->truncate_size;

    struct mirror_pcap_event *event;
    event = bpf_ringbuf_reserve(&mirror_pcap_rb, sizeof(*event), 0);
    if (!event)
        return;

    event->timestamp = bpf_ktime_get_ns();
    event->ifindex = ifindex;
    event->pkt_len = pkt_len;
    event->cap_len = cap_len;
    event->direction = is_ingress ? MIRROR_DIR_INGRESS : MIRROR_DIR_EGRESS;

    if (cap_len > 0 && cap_len <= MIRROR_PCAP_MAX_SIZE) {
        if (bpf_probe_read_kernel(event->data, cap_len, data) < 0) {
            bpf_ringbuf_discard(event, 0);
            return;
        }
    }

    bpf_ringbuf_submit(event, 0);
    __sync_fetch_and_add(&config->pcap_packets, 1);
}

static __always_inline void update_session_stats(__u32 session_id,
                                                 __u32 packet_len,
                                                 int dropped)
{
    struct mirror_session_stats *stats;

    stats = bpf_map_lookup_elem(&mirror_session_stats, &session_id);
    if (!stats)
        return;

    __sync_fetch_and_add(&stats->pkts, 1);
    __sync_fetch_and_add(&stats->bytes, packet_len);
    if (dropped)
        __sync_fetch_and_add(&stats->drops, 1);
}

static __always_inline void update_mirror_stats(struct mirror_config *config,
                                                 int is_ingress,
                                                 __u32 packet_len)
{
    if (is_ingress) {
        __sync_fetch_and_add(&config->ingress_mirrored_packets, 1);
        __sync_fetch_and_add(&config->ingress_mirrored_bytes, packet_len);
    } else {
        __sync_fetch_and_add(&config->egress_mirrored_packets, 1);
        __sync_fetch_and_add(&config->egress_mirrored_bytes, packet_len);
    }

    __u32 key = 0;
    struct rs_stats *stats = bpf_map_lookup_elem(&mirror_stats, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->rx_packets, 1);
        __sync_fetch_and_add(&stats->rx_bytes, packet_len);
    }
}

static __always_inline int do_mirror(struct xdp_md *ctx,
                                      struct mirror_config *config,
                                      int is_ingress,
                                      __u32 orig_ifindex,
                                      __u32 session_id)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    __u32 packet_len = data_end - data;

    if (config->pcap_enabled || config->mirror_type != MIRROR_TYPE_SPAN)
        send_to_pcap_ringbuf(ctx, config, is_ingress, orig_ifindex);

    update_mirror_stats(config, is_ingress, packet_len);
    update_session_stats(session_id, packet_len, 0);

    if (config->mirror_type == MIRROR_TYPE_ERSPAN) {
        /* ERSPAN: BPF sends packet data to user-space via ringbuf for GRE encap */
        return 0;
    }

    if (config->mirror_type == MIRROR_TYPE_RSPAN) {
        /* RSPAN VLAN rewrite deferred to user-space from ringbuf payload */
        return 0;
    }

    if (config->span_port == 0)
        return 0;

    long ret = bpf_redirect_map(&tx_port, config->span_port, 0);
    if (ret != XDP_REDIRECT) {
        __sync_fetch_and_add(&config->mirror_drops, 1);
        update_session_stats(session_id, packet_len, 1);
        return -1;
    }

    return 0;
}

SEC("xdp")
int mirror_ingress(struct xdp_md *xdp_ctx)
{
    struct rs_ctx *rs_ctx = RS_GET_CTX();
    if (!rs_ctx) {
        rs_debug("Mirror: Failed to get rs_ctx");
        return XDP_DROP;
    }

    void *data_end = (void *)(long)xdp_ctx->data_end;
    void *data = (void *)(long)xdp_ctx->data;
    __u32 pkt_len = data_end - data;
    RS_OBS_STAGE_HIT(xdp_ctx, rs_ctx, pkt_len);

    __u32 ifindex = rs_ctx->ifindex;
    struct port_mirror_config *port_config;

    port_config = bpf_map_lookup_elem(&port_mirror_map, &ifindex);
    if (!port_config || !port_config->mirror_ingress) {
        RS_TAIL_CALL_NEXT(xdp_ctx, rs_ctx);
        return XDP_DROP;
    }

    __u16 vlan_id = 0;

    #pragma unroll
    for (__u32 session_id = 0; session_id < MIRROR_MAX_SESSIONS; session_id++) {
        __u32 cfg_key = session_id;
        struct mirror_config *config;

        config = bpf_map_lookup_elem(&mirror_config_map, &cfg_key);
        if (!config || !config->enabled || !config->ingress_enabled)
            continue;

        if (config->span_port == 0 && !config->pcap_enabled &&
            config->mirror_type == MIRROR_TYPE_SPAN)
            continue;

        if (config->mirror_type == MIRROR_TYPE_SPAN && ifindex == config->span_port)
            continue;

        if (!check_all_filters(xdp_ctx, config, 1, ifindex, vlan_id))
            continue;

        do_mirror(xdp_ctx, config, 1, ifindex, session_id);

        {
            struct rs_obs_event evt = {0};
            rs_obs_build_event(xdp_ctx, rs_ctx, &evt, RS_EVENT_OBS_SAMPLE,
                               RS_OBS_F_SAMPLED, 0, pkt_len);
            RS_EMIT_SAMPLED_EVENT(rs_ctx, &evt, sizeof(evt));
        }
    }

    RS_TAIL_CALL_NEXT(xdp_ctx, rs_ctx);
    return XDP_DROP;
}

SEC("xdp/devmap")
int mirror_egress(struct xdp_md *ctx)
{
    __u16 vlan_id = 0;
    __u32 ifindex = ctx->egress_ifindex;

    #pragma unroll
    for (__u32 session_id = 0; session_id < MIRROR_MAX_SESSIONS; session_id++) {
        __u32 cfg_key = session_id;
        struct mirror_config *config;

        config = bpf_map_lookup_elem(&mirror_config_map, &cfg_key);
        if (!config || !config->enabled || !config->egress_enabled)
            continue;

        if (config->span_port == 0 && !config->pcap_enabled &&
            config->mirror_type == MIRROR_TYPE_SPAN)
            continue;

        if (!check_all_filters(ctx, config, 0, ifindex, vlan_id))
            continue;

        do_mirror(ctx, config, 0, ifindex, session_id);
    }

    return XDP_PASS;
}
