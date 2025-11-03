// SPDX-License-Identifier: GPL-2.0
/* rSwitch Unified API
 * 
 * Shared data structures and map definitions for kernel/user communication.
 * This header is included by both BPF programs and user-space code.
 */

#ifndef __RSWITCH_UAPI_H
#define __RSWITCH_UAPI_H

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* Constants */
#define RS_ONLYKEY          0       /* Single-entry per-CPU map key */
#define RS_MAX_PROGS        256     /* Maximum tail-call programs */
#define RS_MAX_INTERFACES   64      /* Maximum network interfaces */
#define RS_MAX_VLANS        4096    /* Maximum VLAN IDs */
#define RS_MAX_ALLOWED_VLANS 128    /* Maximum allowed VLANs per port (trunk/hybrid) */
#define RS_VLAN_MAX_DEPTH   2       /* Q-in-Q support (802.1ad) */

/* Parsed packet layer offsets and metadata
 * 
 * Populated by parsing modules and consumed by downstream modules.
 * Avoids re-parsing the same packet multiple times.
 */
struct rs_layers {
    __u16 eth_proto;            /* Ethernet protocol (ETH_P_IP, ETH_P_IPV6, etc.) */
    __u16 vlan_ids[RS_VLAN_MAX_DEPTH]; /* VLAN IDs (outer to inner) */
    
    __u8  vlan_depth;           /* Number of VLAN tags (0-2) */
    __u8  ip_proto;             /* IP protocol (IPPROTO_TCP, IPPROTO_UDP, etc.) */
    __u8  pad[2];
    
    /* IPv4 addresses (network byte order) */
    __be32 saddr;
    __be32 daddr;
    
    /* L4 ports (network byte order) */
    __be16 sport;
    __be16 dport;
    
    /* Packet offsets for direct access */
    __u16 l2_offset;            /* Ethernet header offset */
    __u16 l3_offset;            /* IP header offset */
    __u16 l4_offset;            /* TCP/UDP header offset */
    __u16 payload_offset;       /* Payload offset */
    __u32 payload_len;          /* Payload length */
};

/* Per-packet processing context
 * 
 * Shared across all modules in the tail-call chain via per-CPU map.
 * Each module reads this context, performs its logic, and optionally
 * updates fields before calling the next module.
 */
struct rs_ctx {
    /* Input metadata */
    __u32 ifindex;              /* Ingress interface index */
    __u32 timestamp;            /* Packet arrival timestamp (for aging/telemetry) */
    
    /* Parsing state */
    __u8  parsed;               /* 0=not parsed, 1=L2/L3 parsed */
    __u8  modified;             /* 0=unchanged, 1=packet modified */
    __u8  pad[2];
    struct rs_layers layers;    /* Parsed layer information */
    
    /* VLAN processing results */
    __u16 ingress_vlan;         /* VLAN ID determined at ingress */
    __u16 egress_vlan;          /* VLAN ID for egress (may differ from ingress) */
    
    /* QoS and priority */
    __u8  prio;                 /* Priority (0-7, where 7=highest) */
    __u8  dscp;                 /* DSCP value (for QoS mapping) */
    __u8  ecn;                  /* ECN bits */
    __u8  traffic_class;        /* User-defined traffic class */
    
    /* Forwarding decision */
    __u32 egress_ifindex;       /* Target egress interface */
    __u8  action;               /* XDP_PASS, XDP_DROP, XDP_REDIRECT, etc. */
    __u8  mirror;               /* 0=no mirror, 1=mirror required */
    __u16 mirror_port;          /* Mirror destination port */
    
    /* Error handling */
    __u32 error;                /* Error code (0=no error) */
    __u32 drop_reason;          /* Reason for drop (if action=XDP_DROP) */
    
    /* Tail-call chain state */
    __u32 next_prog_id;         /* Next program to tail-call */
    __u32 call_depth;           /* Current tail-call depth (for debugging) */
    
    /* Reserved for future use */
    __u32 reserved[4];
};

/* Error codes */
#define RS_ERROR_NONE           0
#define RS_ERROR_PARSE_FAILED   1
#define RS_ERROR_INVALID_VLAN   2
#define RS_ERROR_ACL_DENY       3
#define RS_ERROR_NO_ROUTE       4
#define RS_ERROR_QUEUE_FULL     5
#define RS_ERROR_INTERNAL       99

/* Drop reasons (for telemetry) */
#define RS_DROP_NONE            0
#define RS_DROP_PARSE_ERROR     1
#define RS_DROP_VLAN_FILTER     2
#define RS_DROP_ACL_BLOCK       3
#define RS_DROP_NO_FWD_ENTRY    4
#define RS_DROP_TTL_EXCEEDED    5
#define RS_DROP_RATE_LIMIT      6
#define RS_DROP_CONGESTION      7

/* Per-CPU context map
 * 
 * Single-entry map to pass rs_ctx between tail-called programs.
 * Using per-CPU avoids contention and enables zero-copy context transfer.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rs_ctx);
} rs_ctx_map SEC(".maps");

/* Tail-call program array
 * 
 * Indexed by stage number. Loader populates this based on loaded modules.
 * Modules execute: bpf_tail_call(ctx, &rs_progs, next_stage_id)
 */
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, RS_MAX_PROGS);
    __type(key, __u32);
    __type(value, __u32);
} rs_progs SEC(".maps");

/* Ringbuf for events
 * 
 * Used by modules to send events to user-space:
 * - MAC learning notifications
 * - Policy violations
 * - Errors and anomalies
 * - Telemetry samples
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); /* 256KB ring */
} rs_events SEC(".maps");

/* Event types for ringbuf */
enum rs_event_type {
    RS_EVENT_MAC_LEARN      = 1,
    RS_EVENT_ACL_DENY       = 2,
    RS_EVENT_ROUTE_MISS     = 3,
    RS_EVENT_CONGESTION     = 4,
    RS_EVENT_ERROR          = 5,
    RS_EVENT_STATS          = 6,
};

/* Generic event header (prepended to all events) */
struct rs_event {
    __u32 type;                 /* enum rs_event_type */
    __u32 ifindex;              /* Source interface */
    __u64 timestamp;            /* Event timestamp */
    __u32 data_len;             /* Length of event-specific data */
    __u8  data[0];              /* Event-specific data follows */
} __attribute__((packed));

/* MAC learning event */
struct rs_event_mac_learn {
    __u8  mac[6];
    __u16 vlan;
    __u32 port;
} __attribute__((packed));

/* Helper macros for module development */

/* Get per-CPU context (call at start of each module) */
#define RS_GET_CTX() ({ \
    __u32 __key = RS_ONLYKEY; \
    bpf_map_lookup_elem(&rs_ctx_map, &__key); \
})

/* Tail-call to next stage
 * Usage: RS_TAIL_CALL_NEXT(xdp_ctx, rs_ctx_ptr)
 * Calls the next program based on rs_ctx->next_prog_id
 */
#define RS_TAIL_CALL_NEXT(xdp_ctx_ptr, rs_ctx_ptr) ({ \
    if ((rs_ctx_ptr)->next_prog_id != 0 && (rs_ctx_ptr)->call_depth < 32) { \
        (rs_ctx_ptr)->call_depth++; \
        bpf_tail_call((xdp_ctx_ptr), &rs_progs, (rs_ctx_ptr)->next_prog_id); \
    } \
})

/* Emit event to user-space */
#define RS_EMIT_EVENT(event_type, event_data, data_size) ({ \
    struct rs_event *__evt = bpf_ringbuf_reserve(&rs_events, \
        sizeof(struct rs_event) + (data_size), 0); \
    if (__evt) { \
        __evt->type = (event_type); \
        __evt->ifindex = ctx->ingress_ifindex; \
        __evt->timestamp = bpf_ktime_get_ns(); \
        __evt->data_len = (data_size); \
        __builtin_memcpy(__evt->data, (event_data), (data_size)); \
        bpf_ringbuf_submit(__evt, 0); \
    } \
})

#endif /* __RSWITCH_UAPI_H */
