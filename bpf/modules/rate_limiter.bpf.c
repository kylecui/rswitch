// SPDX-License-Identifier: GPL-2.0

#include "../include/rswitch_common.h"
#include "../core/module_abi.h"

char _license[] SEC("license") = "GPL";

RS_DECLARE_MODULE("rate_limiter", RS_HOOK_XDP_INGRESS, 28,
                  RS_FLAG_NEED_L2L3_PARSE | RS_FLAG_MAY_DROP | RS_FLAG_NEED_FLOW_INFO,
                  "Token-bucket rate limiter");

enum rl_key_type {
    RL_KEY_SRC_IP = 0,
    RL_KEY_DST_IP = 1,
    RL_KEY_VLAN = 2,
    RL_KEY_TRAFFIC_CLASS = 3,
    RL_KEY_GLOBAL = 4,
};

enum rl_exceed_action {
    RL_EXCEED_DROP = 0,
    RL_EXCEED_REMARK_DSCP = 1,
    RL_EXCEED_PASS = 2,
};

enum rl_result {
    RL_CONFORM = 0,
    RL_EXCEED = 1,
};

struct rl_key {
    __u8 type;
    __u8 pad[3];
    union {
        __be32 ip;
        __u16 vlan_id;
        __u8 traffic_class;
    };
} __attribute__((packed));

struct rl_bucket {
    __u64 tokens;
    __u64 last_refill_ns;
    __u64 rate_bps;
    __u64 burst_bytes;
    __u8  exceed_action;
    __u8  pad[7];
} __attribute__((aligned(8)));

struct rl_stats {
    __u64 conforming_pkts;
    __u64 conforming_bytes;
    __u64 exceeding_pkts;
    __u64 exceeding_bytes;
} __attribute__((aligned(8)));

struct rl_config {
    __u8 enabled;
    __u8 pad[3];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct rl_key);
    __type(value, struct rl_bucket);
    __uint(max_entries, 8192);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rl_bucket_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, struct rl_key);
    __type(value, struct rl_stats);
    __uint(max_entries, 8192);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rl_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct rl_config);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rl_config_map SEC(".maps");

static __always_inline void update_rl_stats(const struct rl_key *key, __u32 pkt_len, int result)
{
    struct rl_stats *stats = bpf_map_lookup_elem(&rl_stats_map, key);
    if (!stats) {
        struct rl_stats zero = {};
        bpf_map_update_elem(&rl_stats_map, key, &zero, BPF_NOEXIST);
        stats = bpf_map_lookup_elem(&rl_stats_map, key);
        if (!stats)
            return;
    }

    if (result == RL_CONFORM) {
        __sync_fetch_and_add(&stats->conforming_pkts, 1);
        __sync_fetch_and_add(&stats->conforming_bytes, pkt_len);
    } else {
        __sync_fetch_and_add(&stats->exceeding_pkts, 1);
        __sync_fetch_and_add(&stats->exceeding_bytes, pkt_len);
    }
}

static __always_inline int consume_tokens(const struct rl_key *key,
                                          struct rl_bucket *bucket,
                                          __u32 pkt_len)
{
    __u64 now_ns = bpf_ktime_get_ns();
    struct rl_bucket updated = *bucket;
    __u64 tokens = updated.tokens;

    if (updated.last_refill_ns == 0) {
        updated.last_refill_ns = now_ns;
    } else if (now_ns > updated.last_refill_ns && updated.rate_bps > 0) {
        __u64 elapsed_ns = now_ns - updated.last_refill_ns;
        __u64 refill = (elapsed_ns * updated.rate_bps) / 1000000000ULL;

        if (refill > 0) {
            __u64 sum = tokens + refill;
            if (sum < tokens || sum > updated.burst_bytes)
                tokens = updated.burst_bytes;
            else
                tokens = sum;
        }

        updated.last_refill_ns = now_ns;
    }

    if (tokens > updated.burst_bytes)
        tokens = updated.burst_bytes;

    updated.tokens = tokens;

    if (updated.tokens >= pkt_len) {
        updated.tokens -= pkt_len;
        bpf_map_update_elem(&rl_bucket_map, key, &updated, BPF_ANY);
        return RL_CONFORM;
    }

    bpf_map_update_elem(&rl_bucket_map, key, &updated, BPF_ANY);
    return RL_EXCEED;
}

static __always_inline struct rl_bucket *lookup_bucket_with_fallback(struct rs_ctx *ctx,
                                                                      struct rl_key *out_key)
{
    struct rl_bucket *bucket;

    *out_key = (struct rl_key){};
    out_key->type = RL_KEY_SRC_IP;
    out_key->ip = ctx->layers.saddr;
    bucket = bpf_map_lookup_elem(&rl_bucket_map, out_key);
    if (bucket)
        return bucket;

    *out_key = (struct rl_key){};
    out_key->type = RL_KEY_TRAFFIC_CLASS;
    out_key->traffic_class = ctx->traffic_class;
    bucket = bpf_map_lookup_elem(&rl_bucket_map, out_key);
    if (bucket)
        return bucket;

    *out_key = (struct rl_key){};
    out_key->type = RL_KEY_GLOBAL;
    bucket = bpf_map_lookup_elem(&rl_bucket_map, out_key);
    return bucket;
}

SEC("xdp")
int rate_limit(struct xdp_md *xdp_ctx)
{
    struct rs_ctx *ctx = RS_GET_CTX();
    if (!ctx)
        return XDP_DROP;

    __u32 cfg_key = 0;
    struct rl_config *cfg = bpf_map_lookup_elem(&rl_config_map, &cfg_key);
    if (!cfg || !cfg->enabled) {
        rs_debug("RL: disabled");
        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_DROP;
    }

    if (ctx->layers.eth_proto != ETH_P_IP) {
        rs_debug("RL: non-IPv4, skipping");
        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_DROP;
    }

    void *data = (void *)(long)xdp_ctx->data;
    void *data_end = (void *)(long)xdp_ctx->data_end;
    __u32 pkt_len = (__u32)(data_end - data);

    struct rl_key key = {};
    struct rl_bucket *bucket = lookup_bucket_with_fallback(ctx, &key);
    if (!bucket) {
        rs_debug("RL: no bucket configured");
        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_DROP;
    }

    int result = consume_tokens(&key, bucket, pkt_len);
    if (result == RL_CONFORM) {
        update_rl_stats(&key, pkt_len, RL_CONFORM);
        rs_debug("RL: conform type=%u len=%u", key.type, pkt_len);
        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_DROP;
    }

    update_rl_stats(&key, pkt_len, RL_EXCEED);

    if (bucket->exceed_action == RL_EXCEED_DROP) {
        rs_debug("RL: exceed drop type=%u len=%u", key.type, pkt_len);
        ctx->drop_reason = RS_DROP_RATE_LIMIT;
        return XDP_DROP;
    }

    if (bucket->exceed_action == RL_EXCEED_REMARK_DSCP) {
        rs_debug("RL: exceed remark type=%u len=%u", key.type, pkt_len);
        ctx->dscp = 0;
        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_DROP;
    }

    rs_debug("RL: exceed pass type=%u len=%u", key.type, pkt_len);
    RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
    return XDP_DROP;
}
