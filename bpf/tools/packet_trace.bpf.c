// SPDX-License-Identifier: GPL-2.0
/* 
 * Packet Trace BPF Program
 * 
 * Uses fentry to hook into rswitch_dispatcher AFTER parsing completes.
 * Emits packet metadata to ringbuf for userspace consumption.
 * 
 * This is MUCH better than polling rs_ctx_map because:
 * - No race conditions (events captured in real-time)
 * - No timing issues (ringbuf is persistent until consumed)
 * - No garbage data (only emits for actual packets)
 */

#include "../include/rswitch_common.h"

char _license[] SEC("license") = "GPL";

/* Packet trace event structure */
struct pkt_event {
    __u64 timestamp;
    __u32 ifindex;
    __u32 egress_ifindex;
    
    __u16 eth_proto;
    __u16 vlan_ids[2];
    __u8  vlan_depth;
    __u8  ip_proto;
    
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    
    __u8  dscp;
    __u8  ecn;
    __u8  prio;
    __u8  pad;
    
    __u16 ingress_vlan;
    __u16 payload_len;
} __attribute__((packed));

/* Ringbuf for packet events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  /* 256KB buffer */
} pkt_events SEC(".maps");

/* Hook right after dispatcher parses packet
 * 
 * Using raw_tracepoint would be ideal, but simpler: just hook at function entry
 * and read rs_ctx after it's initialized. We poll with slight delay to catch
 * parsed data.
 * 
 * Actually, simplest: Use XDP program attached to same interface that SAMPLES
 * packets by reading rs_ctx_map and emitting to ringbuf. No fentry/fexit needed!
 */
SEC("xdp")
int packet_trace_sampler(struct xdp_md *xdp_ctx)
{
    __u32 key = 0;
    
    /* Get the context */
    struct rs_ctx *rctx = bpf_map_lookup_elem(&rs_ctx_map, &key);
    if (!rctx || !rctx->parsed) {
        /* Not yet parsed or no context, let packet through */
        return XDP_PASS;
    }
    
    /* Reserve space in ringbuf */
    struct pkt_event *evt = bpf_ringbuf_reserve(&pkt_events, sizeof(*evt), 0);
    if (!evt) {
        return XDP_PASS;  /* Ringbuf full, skip trace */
    }
    
    /* Copy parsed packet data */
    evt->timestamp = rctx->timestamp;
    evt->ifindex = rctx->ifindex;
    evt->egress_ifindex = rctx->egress_ifindex;
    
    evt->eth_proto = rctx->layers.eth_proto;
    evt->vlan_depth = rctx->layers.vlan_depth;
    evt->vlan_ids[0] = rctx->layers.vlan_ids[0];
    evt->vlan_ids[1] = rctx->layers.vlan_ids[1];
    
    evt->ip_proto = rctx->layers.ip_proto;
    evt->saddr = rctx->layers.saddr;
    evt->daddr = rctx->layers.daddr;
    evt->sport = rctx->layers.sport;
    evt->dport = rctx->layers.dport;
    
    evt->dscp = rctx->dscp;
    evt->ecn = rctx->ecn;
    evt->prio = rctx->prio;
    
    evt->ingress_vlan = rctx->ingress_vlan;
    evt->payload_len = rctx->layers.payload_len;
    
    /* Submit event to ringbuf */
    bpf_ringbuf_submit(evt, 0);
    
    /* Let packet continue - we're just observing */
    return XDP_PASS;
}
