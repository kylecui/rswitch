/* SPDX-License-Identifier: GPL-2.0 */
/*
 * AF_XDP Redirect Module - Production Implementation
 * 
 * Stage: 85 (after l2learn, before lastcall)
 * Purpose: Hybrid data plane with VOQ-based priority traffic interception.
 * 
 * Task 12 Status: Complete SHADOW and ACTIVE mode implementation
 * 
 * Operating Modes:
 *   - BYPASS: All traffic through XDP fast-path (default, zero overhead)
 *   - SHADOW: Metadata to ringbuf for observation (VOQd learns traffic patterns)
 *   - ACTIVE: High-priority traffic redirected to user-space VOQd via cpumap
 */

#include "../include/rswitch_common.h"
#include "../core/afxdp_common.h"

char _license[] SEC("license") = "GPL";

/* Module declaration */
RS_DECLARE_MODULE(
	"afxdp_redirect",
	RS_HOOK_XDP_INGRESS,
	85,  /* Stage: after l2learn (80), before lastcall (90) */
	RS_FLAG_CREATES_EVENTS | RS_FLAG_MAY_REDIRECT,
	"AF_XDP redirect for high-priority traffic (foundational)"
);

/* VOQ metadata ringbuf */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 64 << 20);  /* 64 MB - increased for high traffic */
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} voq_ringbuf SEC(".maps");

/* QoS configuration */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct qos_config);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} qos_config_map SEC(".maps");

/* VOQd state - Controls takeover */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct voqd_state);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} voqd_state_map SEC(".maps");

/* Queue depth tracking */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct qdepth_key);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} qdepth_map SEC(".maps");

/* CPUMAP for AF_XDP redirect */
struct {
	__uint(type, BPF_MAP_TYPE_CPUMAP);
	__uint(max_entries, 128);
	__type(key, __u32);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} afxdp_cpumap SEC(".maps");

/* XSKMAP for AF_XDP socket binding
 * Required by libxdp's xsk_socket__create() to bind AF_XDP sockets.
 * Key: queue_id, Value: AF_XDP socket fd (managed by VOQd)
 */
struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, 128);  /* Support up to 128 queues */
	__type(key, __u32);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} xsks_map SEC(".maps");

/* AF_XDP TX devmap - Queue 0 only (high-priority path)
 * 
 * Separate from rs_xdp_devmap to ensure TX queue isolation.
 * All AF_XDP traffic uses queue 0 to avoid contention with XDP fast-path.
 */
struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP_HASH);
	__uint(max_entries, RS_MAX_INTERFACES);
	__type(key, __u32);         /* ifindex */
	__type(value, struct bpf_devmap_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} afxdp_devmap SEC(".maps");

/* Helper: Extract priority from packet using DSCP and port-based classification */
static __always_inline __u32 extract_priority(struct xdp_md *ctx, struct qos_config *qos)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	struct iphdr *iph;
	__u8 dscp;
	__u8 proto;
	__u16 dport = 0;
	
	if ((void *)(eth + 1) > data_end)
		return QOS_PRIO_NORMAL;
	
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return QOS_PRIO_NORMAL;
	
	iph = (void *)(eth + 1);
	if ((void *)(iph + 1) > data_end)
		return QOS_PRIO_NORMAL;
	
	proto = iph->protocol;
	
	/* ICMP: HIGH priority */
	if (proto == IPPROTO_ICMP)
		return QOS_PRIO_HIGH;
	
	/* Parse L4 header for TCP/UDP */
	if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
		__u8 ihl = iph->ihl;
		void *l4 = (void *)iph + (ihl * 4);
		struct {
			__be16 sport;
			__be16 dport;
		} *l4hdr = l4;
		
		if ((void *)(l4hdr + 1) > data_end)
			goto dscp_fallback;
		
		dport = bpf_ntohs(l4hdr->dport);
		
		/* Port-based classification */
		switch (dport) {
		case 22:    /* SSH */
		case 53:    /* DNS */
		case 161:   /* SNMP */
		case 162:   /* SNMP trap */
			return QOS_PRIO_CRITICAL;
		case 80:    /* HTTP */
		case 443:   /* HTTPS */
			return QOS_PRIO_HIGH;
		case 20:    /* FTP data */
		case 21:    /* FTP control */
			return QOS_PRIO_LOW;
		}
	}
	
dscp_fallback:
	dscp = (iph->tos >> 2) & 0x3F;
	if (dscp >= 64)
		return QOS_PRIO_NORMAL;
	
	return qos->dscp2prio[dscp];
}

/* Helper: Simple flow hash */
static __always_inline __u32 compute_flow_hash(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	struct iphdr *iph;
	__u32 hash = 0;
	
	if ((void *)(eth + 1) > data_end)
		return 0;
	
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return 0;
	
	iph = (void *)(eth + 1);
	if ((void *)(iph + 1) > data_end)
		return 0;
	
	/* Simple hash: src ^ dst ^ protocol */
	hash = iph->saddr ^ iph->daddr ^ iph->protocol;
	
	return hash;
}

SEC("xdp")
int afxdp_redirect_ingress(struct xdp_md *ctx)
{
	__u32 key = 0;
	struct rs_ctx *rs_ctx;
	struct voqd_state *state;
	struct qos_config *qos;
	__u32 prio;
	__u64 now_ns;
	
	/* Retrieve shared context */
	rs_ctx = RS_GET_CTX();
	if (!rs_ctx)
		return XDP_PASS;
	
	/* Check for errors from previous modules */
	if (rs_ctx->action == XDP_DROP)
		return XDP_DROP;
	
	/* Note: We DO NOT check egress_ifindex here, because:
	 * - SHADOW mode needs to observe all traffic (including flooding)
	 * - ACTIVE mode can handle flooding by redirecting to AF_XDP
	 * - Only skip if we really can't process (errors, etc.)
	 */
	
	/* Lookup VOQd state */
	state = bpf_map_lookup_elem(&voqd_state_map, &key);
	if (!state) {
		rs_debug("[AF_XDP] No VOQd state found");
		goto next_module;
	}
	
	/* Get current time for timeout checking */
	now_ns = bpf_ktime_get_ns();
	
	rs_debug("[AF_XDP] mode=%d, running=%d, prio_mask=0x%x", 
	           state->mode, state->running, state->prio_mask);
	
	/*
	 * Automatic Failover: ACTIVE/SHADOW -> BYPASS on heartbeat timeout
	 */
	if ((state->mode == VOQD_MODE_ACTIVE || state->mode == VOQD_MODE_SHADOW) &&
	    (state->flags & VOQD_FLAG_AUTO_FAILOVER)) {
		
		/* Check heartbeat timeout */
		if (state->last_heartbeat_ns > 0 &&
		    (now_ns - state->last_heartbeat_ns) > VOQD_HEARTBEAT_TIMEOUT_NS) {
			
			/* VOQd appears dead - failover to BYPASS */
			state->running = 0;
			state->mode = VOQD_MODE_BYPASS;
			state->failover_count++;
			
			/* Note: This direct state mutation is safe because:
			 * 1. Only this XDP program modifies failover_count
			 * 2. VOQd will detect mode change and can restart
			 * 3. BYPASS mode is always safe (no user-space dependency)
			 */
			
			/* Continue with fast-path after failover */
			goto next_module;
		}
	}
	
	/* BYPASS mode: Skip all processing */
	if (state->mode == VOQD_MODE_BYPASS) {
		rs_debug("[AF_XDP] BYPASS mode, skipping");
		goto next_module;
	}
	
	/* Check if VOQd is actually running */
	if (!state->running) {
		rs_debug("[AF_XDP] VOQd not running");
		goto next_module;
	}
	
	/* Lookup QoS config */
	qos = bpf_map_lookup_elem(&qos_config_map, &key);
	if (!qos)
		goto next_module;
	
	/* Extract priority from packet or use pre-classified priority
	 * Priority can come from three sources (in order of preference):
	 * 1. rs_ctx->prio set by ingress classifier/ACL
	 * 2. rs_ctx->prio set by egress QoS module (via DSCP marking feedback)
	 * 3. extract_priority() reading DSCP field directly
	 */
	if (rs_ctx->prio != QOS_PRIO_UNSET && rs_ctx->prio < QOS_MAX_PRIORITIES) {
		/* Priority already classified by upstream module */
		prio = rs_ctx->prio;
		rs_debug("[AF_XDP] Using pre-classified prio=%u", prio);
	} else {
		/* Extract priority from DSCP field */
		prio = extract_priority(ctx, qos);
		rs_debug("[AF_XDP] Extracted prio=%u from DSCP", prio);
	}
	
	/* Check if this priority should be intercepted */
	if (!(state->prio_mask & (1 << prio))) {
		rs_debug("[AF_XDP] Priority %u not in mask 0x%x, skipping", prio, state->prio_mask);
		goto next_module;
	}

	rs_debug("[AF_XDP] Processing priority %u in mode %d", prio, state->mode);
	
	/*
	 * SHADOW Mode: Submit metadata to ringbuf (observation only)
	 */
	if (state->mode == VOQD_MODE_SHADOW) {
		struct voq_meta *meta;
		
		meta = bpf_ringbuf_reserve(&voq_ringbuf, sizeof(*meta), 0);
		if (meta) {
			/* Convert ifindex to port_idx for VOQd compatibility */
			__u32 *port_idx = bpf_map_lookup_elem(&rs_ifindex_to_port_map, &rs_ctx->egress_ifindex);
			meta->ts_ns = now_ns;
			meta->eg_port = port_idx ? *port_idx : rs_ctx->egress_ifindex;  /* Fallback to ifindex if mapping fails */
			meta->prio = prio;
			meta->len = ctx->data_end - ctx->data;
			meta->flow_hash = compute_flow_hash(ctx);
			meta->ecn_hint = 0;  /* TODO: Check congestion */
			meta->drop_hint = 0;
			
			bpf_ringbuf_submit(meta, 0);
		} else {
			/* Ringbuf full - track overload */
			state->overload_drops++;
			
			/* Degrade to BYPASS on sustained overload */
			if ((state->flags & VOQD_FLAG_DEGRADE_ON_OVERLOAD) &&
			    state->overload_drops > VOQD_OVERLOAD_THRESHOLD) {
				state->mode = VOQD_MODE_BYPASS;
				state->failover_count++;
			}
		}
		
		/* In SHADOW mode, continue with fast-path */
		goto next_module;
	}
	
	/*
	 * ACTIVE Mode: Redirect to user-space VOQd via AF_XDP (xsks_map)
	 */
	if (state->mode == VOQD_MODE_ACTIVE) {
		struct voq_meta *meta;
		__u32 queue_id = ctx->rx_queue_index;
		if (queue_id >= 128)
			queue_id = 0;
		
		/* Submit metadata to ringbuf (best-effort, not required for redirect) */
		meta = bpf_ringbuf_reserve(&voq_ringbuf, sizeof(*meta), 0);
		if (meta) {
			__u32 *port_idx = bpf_map_lookup_elem(&rs_ifindex_to_port_map, &rs_ctx->egress_ifindex);
			meta->ts_ns = now_ns;
			meta->eg_port = port_idx ? *port_idx : rs_ctx->egress_ifindex;
			meta->prio = prio;
			meta->len = ctx->data_end - ctx->data;
			meta->flow_hash = compute_flow_hash(ctx);
			meta->ecn_hint = 0;
			meta->drop_hint = 0;
			
			bpf_ringbuf_submit(meta, 0);
		} else {
			state->overload_drops++;
			
			if ((state->flags & VOQD_FLAG_DEGRADE_ON_OVERLOAD) &&
			    state->overload_drops > VOQD_OVERLOAD_THRESHOLD) {
				state->mode = VOQD_MODE_BYPASS;
				state->failover_count++;
				goto next_module;
			}
		}
		
		/* Redirect packet to AF_XDP socket (independent of ringbuf) */
		__u32 *socket_fd = bpf_map_lookup_elem(&xsks_map, &queue_id);
		if (socket_fd && *socket_fd > 0) {
			rs_debug("[AF_XDP] Redirecting to AF_XDP socket fd=%u", *socket_fd);
			return bpf_redirect_map(&xsks_map, queue_id, 0);
		}
		
		rs_debug("[AF_XDP] No AF_XDP socket, continuing with fast-path");
		goto next_module;
	}
	
next_module:
	/* Call next module in chain */
	RS_TAIL_CALL_NEXT(ctx, rs_ctx);
	
	/* Tail-call failed - should not happen if pipeline is properly configured */
	return XDP_PASS;
}
