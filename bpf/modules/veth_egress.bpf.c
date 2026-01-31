// SPDX-License-Identifier: GPL-2.0
#include "../include/rswitch_common.h"
#include "../core/veth_egress_common.h"

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP_HASH);
	__uint(max_entries, RS_MAX_INTERFACES);
	__type(key, __u32);
	__type(value, struct bpf_devmap_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} voq_egress_devmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct veth_egress_config);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} veth_egress_config_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct rs_stats);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} veth_egress_stats SEC(".maps");

static __always_inline void update_stats(__u32 bytes, int is_error)
{
	__u32 key = 0;
	struct rs_stats *stats = bpf_map_lookup_elem(&veth_egress_stats, &key);
	if (stats) {
		if (is_error) {
			__sync_fetch_and_add(&stats->rx_errors, 1);
		} else {
			__sync_fetch_and_add(&stats->tx_packets, 1);
			__sync_fetch_and_add(&stats->tx_bytes, bytes);
		}
	}
}

SEC("xdp")
int veth_egress_redirect(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct voq_tx_meta *meta;
	__u32 key = 0;
	
	struct veth_egress_config *config = bpf_map_lookup_elem(&veth_egress_config_map, &key);
	if (!config || !config->enabled) {
		return XDP_DROP;
	}
	
	meta = data;
	if ((void *)(meta + 1) > data_end) {
		update_stats(0, 1);
		return XDP_DROP;
	}
	
	__u32 egress_ifindex = meta->egress_ifindex;
	__u32 ingress_ifindex = meta->ingress_ifindex;
	__u8 prio = meta->prio;
	__u8 flags = meta->flags;
	__u16 vlan_id = meta->vlan_id;
	__u32 pkt_len = (data_end - data) - VOQ_TX_META_SIZE;
	
	if (egress_ifindex == 0) {
		if (config->flags & VETH_EGRESS_FLAG_STRICT) {
			update_stats(0, 1);
			return XDP_DROP;
		}
		egress_ifindex = config->default_egress_if;
		if (egress_ifindex == 0) {
			update_stats(0, 1);
			return XDP_DROP;
		}
	}
	
	if (bpf_xdp_adjust_head(ctx, (int)VOQ_TX_META_SIZE) < 0) {
		update_stats(0, 1);
		return XDP_DROP;
	}
	
	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		update_stats(0, 1);
		return XDP_DROP;
	}
	
	struct rs_ctx *rctx = bpf_map_lookup_elem(&rs_ctx_map, &key);
	if (rctx) {
		rctx->egress_ifindex = egress_ifindex;
		rctx->ifindex = ingress_ifindex;
		rctx->prio = prio;
		rctx->egress_vlan = vlan_id;
		rctx->action = XDP_REDIRECT;
		rctx->call_depth = 0;
		rctx->error = RS_ERROR_NONE;
		
		if (flags & VOQ_TX_FLAG_SKIP_VLAN)
			rctx->modified |= 0x10;
		if (flags & VOQ_TX_FLAG_SKIP_QOS)
			rctx->modified |= 0x20;
	}
	
	update_stats(pkt_len, 0);
	
	return bpf_redirect_map(&voq_egress_devmap, egress_ifindex, 0);
}

SEC("xdp")
int veth_egress_passthrough(struct xdp_md *ctx)
{
	return XDP_PASS;
}
