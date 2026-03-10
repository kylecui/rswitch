// src/xdp_voq_kern.c
// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "rswitch_common.h"

char _license[] SEC("license") = "GPL";
#define MAX_DEVMAP_PORTS 256

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB
} voq_ringbuf SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct qos_cfg);
} qos_map SEC(".maps");

struct qdepth_key { __u16 port; __u8 prio; __u8 pad; };
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct qdepth_key);
    __type(value, __u32);
} qdepth_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(max_entries, MAX_DEVMAP_PORTS);
    __type(key, __u32);
    __type(value, __u32);
} tx_devmap SEC(".maps");

static __always_inline int parse_ipv4(void *data, void *data_end, __u8 *dscp) {
    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end) return -1;
    if (eth->h_proto != __bpf_htons(ETH_P_IP)) return -1;
    struct iphdr *iph = (void*)(eth + 1);
    if ((void*)(iph + 1) > data_end) return -1;
    *dscp = iph->tos >> 2;
    return 0;
}

SEC("xdp")
int xdp_voq(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    __u8 dscp = 0;
    if (parse_ipv4(data, data_end, &dscp) < 0) {
        return XDP_PASS;
    }

    __u32 zero = 0;
    struct qos_cfg *cfg = bpf_map_lookup_elem(&qos_map, &zero);
    __u32 prio = 0, eg_port = 0;
    if (cfg) {
        prio = cfg->dscp2prio[dscp & 63] & 3;
        eg_port = cfg->port_default;
    }

    struct qdepth_key qk = { .port = (__u16)eg_port, .prio = (__u8)prio };
    __u32 one = 1;
    __u32 *depth = bpf_map_lookup_elem(&qdepth_map, &qk);
    __u32 new_depth = depth ? (*depth + 1) : 1;
    bpf_map_update_elem(&qdepth_map, &qk, &new_depth, BPF_ANY);

    bool congested = new_depth > 2048;

    struct voq_meta *m = bpf_ringbuf_reserve(&voq_ringbuf, sizeof(*m), 0);
    if (m) {
        m->ts_ns = bpf_ktime_get_ns();
        m->eg_port = eg_port;
        m->prio = prio;
        m->len = (__u32)((long)data_end - (long)data);
        m->ecn = congested ? 1 : 0;
        bpf_ringbuf_submit(m, 0);
    }

    if (congested && prio == 0) {
        return XDP_DROP;
    }
    return bpf_redirect_map(&tx_devmap, eg_port, 0);
}
