// SPDX-License-Identifier: GPL-2.0

#ifndef __BPF__
#define __BPF__
#endif

#include "../include/rswitch_common.h"
#include "../core/module_abi.h"

char _license[] SEC("license") = "GPL";

RS_DECLARE_MODULE("dhcp_snoop", RS_HOOK_XDP_INGRESS, 19,
                  RS_FLAG_NEED_L2L3_PARSE | RS_FLAG_NEED_FLOW_INFO |
                      RS_FLAG_MAY_DROP | RS_FLAG_CREATES_EVENTS,
                  "DHCP Snooping");


#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68
#define DHCP_OPT_PAD 0
#define DHCP_OPT_END 255
#define DHCP_OPT_MSG_TYPE 53
#define DHCP_MSG_DISCOVER 1
#define DHCP_MSG_OFFER 2
#define DHCP_MSG_REQUEST 3
#define DHCP_MSG_ACK 5
#define DHCP_FIXED_LEN 236
#define DHCP_COOKIE_LEN 4
#define DHCP_MIN_LEN (DHCP_FIXED_LEN + DHCP_COOKIE_LEN)

struct dhcp_snoop_config {
    __u32 enabled;
    __u32 drop_rogue_server;
    __u32 trusted_port_count;   /* 0 = no enforcement (allow all) */
    __u32 pad;
};

struct dhcp_snoop_stats {
    __u64 dhcp_discover;
    __u64 dhcp_offer;
    __u64 dhcp_request;
    __u64 dhcp_ack;
    __u64 rogue_server_drops;
    __u64 bindings_created;
};

struct sg_key {
    __be32 ip_addr;
} __attribute__((packed));

struct sg_entry {
    __u8 mac[6];
    __u16 pad;
    __u32 ifindex;
    __u8 type;
    __u8 pad2[3];
    __u64 last_seen_ns;
    __u64 violations;
} __attribute__((aligned(8)));

struct dhcp_snoop_event {
    __u32 event_type;
    __u32 ifindex;
    __u8 msg_type;
    __u8 action;
    __u16 pad;
    __be32 yiaddr;
    __u8 chaddr[6];
    __u8 pad2[2];
};

enum dhcp_snoop_action {
    DHCP_SNOOP_ACTION_OBSERVED = 0,
    DHCP_SNOOP_ACTION_ROGUE_DROP = 1,
    DHCP_SNOOP_ACTION_BINDING_CREATE = 2,
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct sg_key);
    __type(value, struct sg_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} sg_binding_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} dhcp_trusted_ports_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct dhcp_snoop_config);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} dhcp_snoop_config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct dhcp_snoop_stats);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} dhcp_snoop_stats_map SEC(".maps");

static __always_inline struct dhcp_snoop_stats *get_stats(void)
{
    __u32 zero = 0;
    return bpf_map_lookup_elem(&dhcp_snoop_stats_map, &zero);
}

static __always_inline void emit_snoop_event(__u32 ifindex, __u8 msg_type, __u8 action,
                                              __be32 yiaddr, const __u8 *chaddr)
{
    struct dhcp_snoop_event evt = {
        .event_type = RS_EVENT_ACL_BASE + 0x20,
        .ifindex = ifindex,
        .msg_type = msg_type,
        .action = action,
        .yiaddr = yiaddr,
    };

    if (chaddr)
        __builtin_memcpy(evt.chaddr, chaddr, sizeof(evt.chaddr));

    RS_EMIT_EVENT(&evt, sizeof(evt));
}

/*
 * Extract DHCP message type.
 *
 * RFC 2131: option 53 is mandatory and virtually always appears as the
 * first option right after the 4-byte magic cookie (offset 240).
 * We check that position first for the fast path, then scan a small
 * number of additional options as a fallback.  The two-phase approach
 * keeps the verifier happy while covering real-world DHCP traffic.
 */
static __always_inline __u8 parse_dhcp_message_type(__u8 *dhcp, void *data_end)
{
    /* Fast path: option 53 at standard position (offset 240) */
    __u8 *fast = dhcp + DHCP_MIN_LEN;
    if ((void *)(fast + 3) <= data_end &&
        fast[0] == DHCP_OPT_MSG_TYPE && fast[1] >= 1)
        return fast[2];

    /* Slow path: scan up to 8 options from offset 240 */
    __u32 off = DHCP_MIN_LEN;

#pragma unroll
    for (int i = 0; i < 8; i++) {
        __u8 *opt = dhcp + off;
        if ((void *)(opt + 1) > data_end)
            return 0;

        __u8 code = *opt;
        if (code == DHCP_OPT_END)
            return 0;
        if (code == DHCP_OPT_PAD) {
            off++;
            continue;
        }

        /* Check 3 bytes: code + len + at least 1 value byte.
         * This single check covers the reads of *(opt+1) and *(opt+2)
         * so the verifier has bounds for the value read below. */
        if ((void *)(opt + 3) > data_end)
            return 0;

        __u8 len = *(opt + 1);
        if (len == 0)
            return 0;

        if (code == DHCP_OPT_MSG_TYPE)
            return *(opt + 2);

        /* For non-target options, validate full TLV before advancing */
        if ((void *)(opt + 2 + len) > data_end)
            return 0;

        off += (__u32)len + 2;
    }

    return 0;
}

SEC("xdp")
int dhcp_snoop(struct xdp_md *xdp_ctx)
{
    void *data = (void *)(long)xdp_ctx->data;
    void *data_end = (void *)(long)xdp_ctx->data_end;
    struct rs_ctx *ctx = RS_GET_CTX();
    __u32 zero = 0;

    if (!ctx)
        return XDP_DROP;

    struct dhcp_snoop_config *cfg = bpf_map_lookup_elem(&dhcp_snoop_config_map, &zero);
    if (!cfg || !cfg->enabled) {
        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_DROP;
    }

    if (!ctx->parsed || ctx->layers.eth_proto != ETH_P_IP || ctx->layers.ip_proto != IPPROTO_UDP) {
        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_DROP;
    }

    __u16 sport = bpf_ntohs(ctx->layers.sport);
    __u16 dport = bpf_ntohs(ctx->layers.dport);
    if (!(sport == DHCP_CLIENT_PORT || dport == DHCP_SERVER_PORT || sport == DHCP_SERVER_PORT)) {
        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_DROP;
    }

    __u8 *dhcp = data + (ctx->layers.payload_offset & RS_PAYLOAD_MASK);
    if ((void *)(dhcp + DHCP_MIN_LEN) > data_end) {
        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_DROP;
    }

    __u8 msg_type = parse_dhcp_message_type(dhcp, data_end);
    struct dhcp_snoop_stats *stats = get_stats();

    if (stats) {
        if (msg_type == DHCP_MSG_DISCOVER)
            stats->dhcp_discover++;
        else if (msg_type == DHCP_MSG_OFFER)
            stats->dhcp_offer++;
        else if (msg_type == DHCP_MSG_REQUEST)
            stats->dhcp_request++;
        else if (msg_type == DHCP_MSG_ACK)
            stats->dhcp_ack++;
    }

    if (sport == DHCP_SERVER_PORT) {
        __u32 *trusted = bpf_map_lookup_elem(&dhcp_trusted_ports_map, &ctx->ifindex);
        int trusted_port = trusted && *trusted;
        int has_trusted_ports = cfg->trusted_port_count > 0;

        if (!trusted_port && has_trusted_ports && cfg->drop_rogue_server) {
            if (stats)
                stats->rogue_server_drops++;
            emit_snoop_event(ctx->ifindex, msg_type, DHCP_SNOOP_ACTION_ROGUE_DROP, 0, NULL);
            ctx->drop_reason = RS_DROP_ACL_BLOCK;
            return XDP_DROP;
        }

        if ((trusted_port || !has_trusted_ports) && msg_type == DHCP_MSG_ACK) {
            struct sg_key key = {};
            struct sg_entry entry = {};

            __builtin_memcpy(&key.ip_addr, dhcp + 16, sizeof(key.ip_addr));
            __builtin_memcpy(entry.mac, dhcp + 28, sizeof(entry.mac));
            entry.ifindex = 0;
            entry.type = 1;
            entry.last_seen_ns = bpf_ktime_get_ns();
            entry.violations = 0;

            if (bpf_map_update_elem(&sg_binding_map, &key, &entry, BPF_ANY) == 0) {
                if (stats)
                    stats->bindings_created++;
                emit_snoop_event(ctx->ifindex, msg_type,
                                 DHCP_SNOOP_ACTION_BINDING_CREATE,
                                 key.ip_addr, entry.mac);
            }
        }
    }

    RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
    return XDP_DROP;
}
