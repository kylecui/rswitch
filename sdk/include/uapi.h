// SPDX-License-Identifier: GPL-2.0
/* rSwitch Unified API
 * 
 * Shared data structures and map definitions for kernel/user communication.
 * This header is included by both BPF programs and user-space code.
 */

#ifndef __RSWITCH_UAPI_H
#define __RSWITCH_UAPI_H

#warning "uapi.h is deprecated. Use #include <rswitch_module.h> instead. See sdk/docs/SDK_Migration_Guide.md"

/* BPF programs use vmlinux.h (CO-RE), user-space uses kernel headers */
#ifdef __BPF__
    /* BPF side: types already defined in vmlinux.h (included via rswitch_bpf.h) */
    #include <bpf/bpf_helpers.h>
#else
    /* User-space side: use kernel UAPI headers */
    #include <linux/types.h>
    #include <linux/bpf.h>
#endif

/* Constants */
#define RS_ONLYKEY          0       /* Single-entry per-CPU map key */
#define RS_MAX_PROGS        256     /* Maximum tail-call programs */
#define RS_MAX_INTERFACES   64      /* Maximum network interfaces */
#define RS_MAX_VLANS        4096    /* Maximum VLAN IDs */
#define RS_MAX_ALLOWED_VLANS 128    /* Maximum allowed VLANs per port (trunk/hybrid) */
#define RS_VLAN_MAX_DEPTH   2       /* Q-in-Q support (802.1ad) */
#define RS_DEFAULT_VLAN     1       /* IEEE 802.1Q default VLAN */

/* Verifier-friendly offset masks for packet access
 * 
 * BPF verifier cannot prove safety of dynamic offsets loaded from maps without
 * explicit range constraints. These masks limit offset ranges to realistic values,
 * allowing the verifier to prove pointer arithmetic is safe.
 * 
 * Offset calculations:
 * - L2 (Ethernet): Always at offset 0
 * - L3 (IP): Ethernet(14) + VLAN tags(0-8) = max 22 bytes → mask 0x3F (63)
 * - L4 (TCP/UDP): L2(22) + IPv4 max options(60) = max 82 bytes → mask 0x7F (127)  
 * - Payload: L2(22) + L3(60) + TCP max options(60) = max 142 bytes → mask 0xFF (255)
 * 
 * Usage pattern:
 *   struct iphdr *iph = data + (ctx->layers.l3_offset & RS_L3_OFFSET_MASK);
 *   if ((void *)(iph + 1) > data_end) return XDP_DROP;
 */
#define RS_L2_OFFSET_MASK  0x00   /* L2 always at offset 0 (no mask needed) */
#define RS_L3_OFFSET_MASK  0x3F   /* Max 63 bytes for L2 headers (Eth + QinQ) */
#define RS_L4_OFFSET_MASK  0x7F   /* Max 127 bytes for L2+L3 headers */
#define RS_PAYLOAD_MASK    0xFF   /* Max 255 bytes for L2+L3+L4 headers */

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
    
    /* Reserved for future use (64 bytes — ABI v2) */
    __u32 reserved[16];
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
    __uint(pinning, LIBBPF_PIN_BY_NAME); // must match the main definition
} rs_ctx_map SEC(".maps");

/* Tail-call program array
 * 
 * Indexed by stage number. Loader populates this based on loaded modules.
 * Modules execute: bpf_tail_call(ctx, &rs_progs, next_stage_id)
 * 
 * CRITICAL: Must be pinned - shared between dispatcher and all modules!
 */
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, RS_MAX_PROGS);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_progs SEC(".maps");

/* Program chain configuration - stores next prog_id for each module
 * 
 * Key: current prog_id (prog_array index)
 * Value: next prog_id to tail-call
 * 
 * This enables reconfigurable egress pipelines without hardcoded slots.
 * Loader populates this when building the pipeline:
 *   prog_chain[4] = 5  (module at slot 4 calls slot 5 next)
 *   prog_chain[5] = 6  (module at slot 5 calls slot 6 next)
 * 
 * Egress modules use this to determine their next hop, avoiding race conditions:
 *   Thread 1 (port 5): Read prog_chain[4] → 5, call prog 5 ✓
 *   Thread 2 (port 6): Read prog_chain[4] → 5, call prog 5 ✓ (no race!)
 * 
 * Compare to dynamic increment (broken):
 *   Thread 1: Read next_prog_id=4 → Set 5 → Call 5
 *   Thread 2: Read next_prog_id=5 → Set 6 → Call 6 (skip 5!) ✗
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, RS_MAX_PROGS);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_prog_chain SEC(".maps");

/* Unified Event Bus
 * 
 * Shared ringbuf for all module events (MAC learning, ACL hits, errors, etc.)
 * Using a single large ringbuf instead of multiple small ones:
 * - Better memory efficiency (1MB shared vs N×256KB per module)
 * - Simplified user-space consumption (single reader)
 * - Event ordering preserved across modules
 * 
 * CRITICAL: Must be pinned - shared infrastructure!
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);  /* 1MB ring */
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_event_bus SEC(".maps");

/* Event Type Enumeration
 * 
 * Each module defines its own event types in a reserved range:
 * - 0x0000-0x00FF: Reserved (core events)
 * - 0x0100-0x01FF: L2Learn events  
 * - 0x0200-0x02FF: ACL events
 * - 0x0300-0x03FF: Route events
 * - 0x0400-0x04FF: Mirror events
 * - 0x0500-0x05FF: QoS events
 * - 0x1000-0x7FFF: User module events (external modules)
 * - 0xFF00-0xFFFF: Reserved (error events)
 */
#define RS_EVENT_RESERVED       0x0000
#define RS_EVENT_PKT_TRACE      0x0001  /* Packet trace event (debug) */
#define RS_EVENT_L2_BASE        0x0100
#define RS_EVENT_ACL_BASE       0x0200
#define RS_EVENT_ROUTE_BASE     0x0300
#define RS_EVENT_MIRROR_BASE    0x0400
#define RS_EVENT_QOS_BASE       0x0500
#define RS_EVENT_USER_BASE      0x1000
#define RS_EVENT_USER_MAX       0x7FFF
#define RS_EVENT_ERROR_BASE     0xFF00

/* L2Learn Events (0x0100-0x01FF) */
#define RS_EVENT_MAC_LEARNED    (RS_EVENT_L2_BASE + 1)  /* 0x0101 */
#define RS_EVENT_MAC_MOVED      (RS_EVENT_L2_BASE + 2)  /* 0x0102 */
#define RS_EVENT_MAC_AGED       (RS_EVENT_L2_BASE + 3)  /* 0x0103 */

/* ACL Events (0x0200-0x02FF) */
#define RS_EVENT_ACL_HIT        (RS_EVENT_ACL_BASE + 1) /* 0x0201 */
#define RS_EVENT_ACL_DENY       (RS_EVENT_ACL_BASE + 2) /* 0x0202 */

/* Error Events (0xFF00-0xFFFF) */
#define RS_EVENT_PARSE_ERROR    (RS_EVENT_ERROR_BASE + 1)
#define RS_EVENT_MAP_FULL       (RS_EVENT_ERROR_BASE + 2)

/* Helper macros for module development */

/* Get per-CPU context (call at start of each module) */
#define RS_GET_CTX() ({ \
    __u32 __key = RS_ONLYKEY; \
    bpf_map_lookup_elem(&rs_ctx_map, &__key); \
})

/* Tail-call to next stage
 * Usage: RS_TAIL_CALL_NEXT(xdp_ctx, rs_ctx_ptr)
 * 
 * Automatically increments next_prog_id and calls the next module.
 * This assumes loader inserts modules sequentially: rs_progs[0], rs_progs[1], ...
 * 
 * CRITICAL: Modules should NOT manually set next_prog_id!
 * The dispatcher initializes it to 0, then this macro auto-increments.
 * 
 * NOTE: Ingress modules only! Egress modules use RS_TAIL_CALL_EGRESS.
 */
#define RS_TAIL_CALL_NEXT(xdp_ctx_ptr, rs_ctx_ptr) ({ \
    if ((rs_ctx_ptr)->call_depth < 32) { \
        (rs_ctx_ptr)->call_depth++; \
        (rs_ctx_ptr)->next_prog_id++; \
        bpf_tail_call((xdp_ctx_ptr), &rs_progs, (rs_ctx_ptr)->next_prog_id); \
    } \
})

/* Tail-call for egress pipeline (reads next prog_id from prog_chain map)
 * Usage: RS_TAIL_CALL_EGRESS(xdp_ctx, rs_ctx_ptr)
 * 
 * CRITICAL: Unlike ingress, egress modules must use rs_ctx->next_prog_id to track
 * their current slot (255, 254, 253...) because they run concurrently during flooding.
 * 
 * Flow:
 * 1. egress.bpf.c (devmap hook): Sets rs_ctx->next_prog_id = prog_chain[0] (e.g., 255)
 * 2. First egress module (qos): Uses next_prog_id=255 to lookup prog_chain[255]→254
 * 3. Second egress module (egress_final): Uses next_prog_id=254, finds prog_chain[254]=0 (end)
 * 
 * Example with 2 egress modules (qos at slot 255, egress_final at slot 254):
 *   Loader configures: prog_chain[0]=255, prog_chain[255]=254, prog_chain[254]=0
 * 
 * Execution:
 *   egress.bpf.c: Sets next_prog_id=255, tail-calls rs_progs[255] (qos)
 *   qos: Reads prog_chain[255]=254, sets next_prog_id=254, tail-calls rs_progs[254]
 *   egress_final: Reads prog_chain[254]=0 (end), returns XDP_PASS
 * 
 * During flooding (concurrent):
 *   All cores use their own rs_ctx (per-CPU), no race condition.
 */
#define RS_TAIL_CALL_EGRESS(xdp_ctx_ptr, rs_ctx_ptr) ({ \
    if ((rs_ctx_ptr)->call_depth < 32) { \
        (rs_ctx_ptr)->call_depth++; \
        __u32 __current_slot = (rs_ctx_ptr)->next_prog_id; \
        __u32 *__next_slot = bpf_map_lookup_elem(&rs_prog_chain, &__current_slot); \
        if (__next_slot && *__next_slot != 0) { \
            (rs_ctx_ptr)->next_prog_id = *__next_slot; \
            bpf_tail_call((xdp_ctx_ptr), &rs_progs, *__next_slot); \
        } \
    } \
})

/* Emit event to unified event bus
 * Usage: 
 *   struct my_event evt = {...};
 *   RS_EMIT_EVENT(&evt, sizeof(evt));
 * 
 * Returns: 0 on success, -1 on failure (ringbuf full)
 */
#define RS_EMIT_EVENT(event_ptr, event_size) ({ \
    void *__evt = bpf_ringbuf_reserve(&rs_event_bus, (event_size), 0); \
    int __ret = -1; \
    if (__evt) { \
        __builtin_memcpy(__evt, (event_ptr), (event_size)); \
        bpf_ringbuf_submit(__evt, 0); \
        __ret = 0; \
    } \
    __ret; \
})

#endif /* __RSWITCH_UAPI_H */
