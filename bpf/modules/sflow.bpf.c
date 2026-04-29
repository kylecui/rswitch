// SPDX-License-Identifier: GPL-2.0

#include "../include/rswitch_common.h"

enum {
    RS_THIS_STAGE_ID  = 85,
    RS_THIS_MODULE_ID = RS_MOD_SFLOW,
};


char _license[] SEC("license") = "GPL";

RS_DECLARE_MODULE("sflow", RS_HOOK_XDP_INGRESS, 85,
                  RS_FLAG_NEED_L2L3_PARSE | RS_FLAG_NEED_FLOW_INFO |
                      RS_FLAG_CREATES_EVENTS,
                  "sFlow/NetFlow Packet Sampling");

#define SFLOW_SAMPLE_EVENT_TYPE (RS_EVENT_QOS_BASE + 0x10)
#define SFLOW_DEFAULT_SAMPLE_RATE 1000
#define SFLOW_DEFAULT_HEADER_BYTES 128
#define SFLOW_MAX_HEADER_BYTES 256

struct sflow_config {
    __u32 enabled;
    __u32 sample_rate;
    __u32 max_header_bytes;
    __u32 pad;
};

struct sflow_port_config {
    __u32 enabled;
    __u32 sample_rate;
    __u32 pad[2];
};

struct sflow_counters {
    __u64 packets_seen;
    __u64 packets_sampled;
    __u64 bytes_sampled;
    __u64 sample_drops;
};

struct sflow_sample_event {
    __u32 event_type;
    __u32 ifindex;
    __u64 timestamp_ns;
    __u32 packet_len;
    __u32 captured_len;
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8 protocol;
    __u8 dscp;
    __u16 vlan;
    __u8 header[SFLOW_MAX_HEADER_BYTES];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct sflow_config);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} sflow_config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, struct sflow_port_config);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} sflow_port_config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct sflow_counters);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} sflow_counter_map SEC(".maps");

static __always_inline void sflow_counter_inc_seen(void)
{
    __u32 key = 0;
    struct sflow_counters *c = bpf_map_lookup_elem(&sflow_counter_map, &key);
    if (c)
        __sync_fetch_and_add(&c->packets_seen, 1);
}

static __always_inline void sflow_counter_add_sampled(__u32 bytes)
{
    __u32 key = 0;
    struct sflow_counters *c = bpf_map_lookup_elem(&sflow_counter_map, &key);
    if (!c)
        return;

    __sync_fetch_and_add(&c->packets_sampled, 1);
    __sync_fetch_and_add(&c->bytes_sampled, bytes);
}

static __always_inline void sflow_counter_inc_drop(void)
{
    __u32 key = 0;
    struct sflow_counters *c = bpf_map_lookup_elem(&sflow_counter_map, &key);
    if (c)
        __sync_fetch_and_add(&c->sample_drops, 1);
}

SEC("xdp")
int sflow_sample(struct xdp_md *xdp_ctx)
{
    struct rs_ctx *ctx = RS_GET_CTX();
    __u32 key0 = 0;
    void *data = (void *)(long)xdp_ctx->data;
    void *data_end = (void *)(long)xdp_ctx->data_end;
    __u32 pkt_len = (__u32)(data_end - data);
    __u32 sample_rate;
    __u32 capture_len;
    struct sflow_config *cfg;

    if (!ctx)
        return XDP_DROP;

    RS_OBS_STAGE_HIT(xdp_ctx, ctx, pkt_len);

    if (!ctx->parsed) {
        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_PASS;
    }

    sflow_counter_inc_seen();

    cfg = bpf_map_lookup_elem(&sflow_config_map, &key0);
    if (!cfg || !cfg->enabled) {
        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_PASS;
    }

    sample_rate = cfg->sample_rate;
    if (sample_rate == 0)
        sample_rate = SFLOW_DEFAULT_SAMPLE_RATE;

    {
        struct sflow_port_config *port_cfg = bpf_map_lookup_elem(&sflow_port_config_map, &ctx->ifindex);
        if (port_cfg && port_cfg->enabled && port_cfg->sample_rate > 0)
            sample_rate = port_cfg->sample_rate;
    }

    if (sample_rate == 0 || (bpf_get_prandom_u32() % sample_rate) != 0) {
        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_PASS;
    }

    capture_len = cfg->max_header_bytes;
    if (capture_len == 0)
        capture_len = SFLOW_DEFAULT_HEADER_BYTES;
    if (capture_len > SFLOW_MAX_HEADER_BYTES)
        capture_len = SFLOW_MAX_HEADER_BYTES;
    if (capture_len > pkt_len)
        capture_len = pkt_len;

    {
        struct sflow_sample_event evt = {
            .event_type = SFLOW_SAMPLE_EVENT_TYPE,
            .ifindex = ctx->ifindex,
            .timestamp_ns = bpf_ktime_get_ns(),
            .packet_len = pkt_len,
            .captured_len = capture_len,
            .src_ip = ctx->layers.saddr,
            .dst_ip = ctx->layers.daddr,
            .src_port = ctx->layers.sport,
            .dst_port = ctx->layers.dport,
            .protocol = ctx->layers.ip_proto,
            .dscp = ctx->dscp,
            .vlan = ctx->ingress_vlan,
        };

        if (capture_len > 0)
            bpf_probe_read_kernel(evt.header, capture_len, data);

        if (RS_EMIT_EVENT(&evt, sizeof(evt)) < 0)
            sflow_counter_inc_drop();
        else
            sflow_counter_add_sampled(pkt_len);
    }

    RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
    return XDP_PASS;
}
