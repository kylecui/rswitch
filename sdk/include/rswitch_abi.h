/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * rSwitch Module ABI — Stable Type and Constant Definitions
 *
 * This header provides all ABI definitions needed by rSwitch modules:
 *   - struct rs_ctx, struct rs_layers (per-packet context)
 *   - RS_DECLARE_MODULE / RS_DEPENDS_ON (module metadata)
 *   - RS_ABI_VERSION, RS_FLAG_*, RS_HOOK_*, RS_STAGE_* (constants)
 *   - RS_EVENT_*, RS_ERROR_*, RS_DROP_* (event and error codes)
 *   - RS_*_OFFSET_MASK (verifier-safe packet offset masks)
 *
 * This header does NOT include BPF map definitions. For shared maps,
 * include <rswitch_maps.h> separately (opt-in).
 *
 * Typical usage:
 *   #include <rswitch_module.h>    // single entry point (includes this)
 *
 * Direct usage (advanced):
 *   #include <rswitch_abi.h>       // types and constants only
 */

#ifndef __RSWITCH_ABI_H
#define __RSWITCH_ABI_H

/* ── Platform type includes ────────────────────────────────────── */

#ifdef __BPF__
    /* BPF side: types come from vmlinux.h (included before this header) */
    #include <bpf/bpf_helpers.h>
#else
    /* User-space side: use kernel UAPI headers */
    #include <linux/types.h>
    #include <linux/bpf.h>
#endif

/* ── API stability annotations ─────────────────────────────────── */

#ifndef RS_API_STABLE
#define RS_API_STABLE           /* Guaranteed stable across minor versions */
#endif

#ifndef RS_API_EXPERIMENTAL
#define RS_API_EXPERIMENTAL     /* May change between minor versions */
#endif

#ifndef RS_API_INTERNAL
#define RS_API_INTERNAL         /* May change at any time, not for modules */
#endif

#ifndef RS_DEPRECATED
#define RS_DEPRECATED(msg) __attribute__((deprecated(msg)))
#endif

/* ── ABI version ───────────────────────────────────────────────── */

#define RS_ABI_VERSION_MAJOR 2
#define RS_ABI_VERSION_MINOR 0
#define RS_ABI_VERSION ((RS_ABI_VERSION_MAJOR << 16) | RS_ABI_VERSION_MINOR)

#define RS_ABI_VERSION_1 ((1u << 16) | 0)  /* Historical: ABI v1.0 */
#define RS_ABI_VERSION_2 RS_ABI_VERSION     /* Current: ABI v2.0 */

#define RS_ABI_MAJOR(v) ((v) >> 16)
#define RS_ABI_MINOR(v) ((v) & 0xFFFF)

/* ── Hook points ───────────────────────────────────────────────── */

enum rs_hook_point {
    RS_HOOK_XDP_INGRESS = 0,    /* Main XDP ingress hook */
    RS_HOOK_XDP_EGRESS  = 1,    /* XDP devmap egress hook */
    RS_HOOK_MAX,
};

/* ── Module capability flags ───────────────────────────────────── */

#define RS_FLAG_NEED_L2L3_PARSE    (1u << 0)  /* RS_API_STABLE: Requires parsed L2/L3 headers */
#define RS_FLAG_NEED_VLAN_INFO     (1u << 1)  /* RS_API_STABLE: Requires VLAN information */
#define RS_FLAG_NEED_FLOW_INFO     (1u << 2)  /* RS_API_STABLE: Requires 5-tuple flow info */
#define RS_FLAG_MODIFIES_PACKET    (1u << 3)  /* RS_API_STABLE: May modify packet data */
#define RS_FLAG_MAY_DROP           (1u << 4)  /* RS_API_STABLE: May drop packets */
#define RS_FLAG_CREATES_EVENTS     (1u << 5)  /* RS_API_STABLE: Generates ringbuf events */
#define RS_FLAG_MAY_REDIRECT       (1u << 6)  /* RS_API_STABLE: May redirect packets */

/* ── Module descriptor ─────────────────────────────────────────── */

RS_API_STABLE struct rs_module_desc {
    __u32 abi_version;      /* Must be RS_ABI_VERSION */
    __u32 hook;             /* enum rs_hook_point */
    __u32 stage;            /* Pipeline stage (lower = earlier) */
    __u32 flags;            /* Capability flags (RS_FLAG_*) */
    char  name[32];         /* Module name (for logging/debug) */
    char  description[64];  /* Human-readable description */
    __u32 reserved[4];      /* Reserved for future use */
} __attribute__((aligned(8)));

#define RS_MAX_DEPS 4
#define RS_DEP_NAME_LEN 32

RS_API_EXPERIMENTAL struct rs_module_deps {
    __u32 dep_count;
    char deps[RS_MAX_DEPS][RS_DEP_NAME_LEN];
} __attribute__((aligned(8)));

/* ── RS_DECLARE_MODULE ─────────────────────────────────────────── */

#define RS_DECLARE_MODULE(_name, _hook, _stage, _flags, _desc) /* RS_API_STABLE */ \
    const volatile struct rs_module_desc __rs_module \
    __attribute__((section(".rodata.mod"), used)) = { \
        .abi_version = RS_ABI_VERSION, \
        .hook = _hook, \
        .stage = _stage, \
        .flags = _flags, \
        .name = _name, \
        .description = _desc, \
    }

/* ── RS_DEPENDS_ON ─────────────────────────────────────────────── */

#define RS_DEPENDS_ON_1(_dep1) \
    const volatile struct rs_module_deps __rs_module_deps \
    __attribute__((section(".rodata.moddep"), used)) = { \
        .dep_count = 1, \
        .deps = { _dep1 }, \
    }

#define RS_DEPENDS_ON_2(_dep1, _dep2) \
    const volatile struct rs_module_deps __rs_module_deps \
    __attribute__((section(".rodata.moddep"), used)) = { \
        .dep_count = 2, \
        .deps = { _dep1, _dep2 }, \
    }

#define RS_DEPENDS_ON_3(_dep1, _dep2, _dep3) \
    const volatile struct rs_module_deps __rs_module_deps \
    __attribute__((section(".rodata.moddep"), used)) = { \
        .dep_count = 3, \
        .deps = { _dep1, _dep2, _dep3 }, \
    }

#define RS_DEPENDS_ON_4(_dep1, _dep2, _dep3, _dep4) \
    const volatile struct rs_module_deps __rs_module_deps \
    __attribute__((section(".rodata.moddep"), used)) = { \
        .dep_count = 4, \
        .deps = { _dep1, _dep2, _dep3, _dep4 }, \
    }

#define RS_GET_DEP_MACRO(_1, _2, _3, _4, NAME, ...) NAME
#define RS_DEPENDS_ON(...) \
    RS_GET_DEP_MACRO(__VA_ARGS__, RS_DEPENDS_ON_4, RS_DEPENDS_ON_3, RS_DEPENDS_ON_2, RS_DEPENDS_ON_1)(__VA_ARGS__)

/* ── Stage numbers ─────────────────────────────────────────────── */

/* Core module stages (ingress 10-99, egress 100-199) */
#define RS_STAGE_PREPROCESS     10
#define RS_STAGE_VLAN           20
#define RS_STAGE_ACL            30
#define RS_STAGE_ROUTE          40
#define RS_STAGE_QOS            50
#define RS_STAGE_MIRROR         70
#define RS_STAGE_LEARN          80
#define RS_STAGE_LASTCALL       90

/* User module stage ranges (external modules MUST use these) */
#define RS_STAGE_USER_INGRESS_MIN  200
#define RS_STAGE_USER_INGRESS_MAX  299
#define RS_STAGE_USER_EGRESS_MIN   400
#define RS_STAGE_USER_EGRESS_MAX   499

/* ── Platform constants ────────────────────────────────────────── */

#define RS_ONLYKEY          0       /* Single-entry per-CPU map key */
#define RS_MAX_PROGS        256     /* Maximum tail-call programs */
#define RS_MAX_INTERFACES   64      /* Maximum network interfaces */
#define RS_MAX_VLANS        4096    /* Maximum VLAN IDs */
#define RS_MAX_ALLOWED_VLANS 128    /* Maximum allowed VLANs per port */
#define RS_VLAN_MAX_DEPTH   2       /* Q-in-Q support (802.1ad) */
#define RS_DEFAULT_VLAN     1       /* IEEE 802.1Q default VLAN */

/* ── Verifier-safe offset masks ────────────────────────────────── */

#define RS_L2_OFFSET_MASK  0x00   /* L2 always at offset 0 */
#define RS_L3_OFFSET_MASK  0x3F   /* Max 63 bytes for L2 headers */
#define RS_L4_OFFSET_MASK  0x7F   /* Max 127 bytes for L2+L3 headers */
#define RS_PAYLOAD_MASK    0xFF   /* Max 255 bytes for L2+L3+L4 headers */

/* ── Parsed packet layer offsets ───────────────────────────────── */

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

/* ── Per-packet processing context ─────────────────────────────── */

struct rs_ctx {
    /* Input metadata */
    __u32 ifindex;              /* Ingress interface index */
    __u32 timestamp;            /* Packet arrival timestamp */

    /* Parsing state */
    __u8  parsed;               /* 0=not parsed, 1=L2/L3 parsed */
    __u8  modified;             /* 0=unchanged, 1=packet modified */
    __u8  pad[2];
    struct rs_layers layers;    /* Parsed layer information */

    /* VLAN processing results */
    __u16 ingress_vlan;         /* VLAN ID determined at ingress */
    __u16 egress_vlan;          /* VLAN ID for egress */

    /* QoS and priority */
    __u8  prio;                 /* Priority (0-7) */
    __u8  dscp;                 /* DSCP value */
    __u8  ecn;                  /* ECN bits */
    __u8  traffic_class;        /* User-defined traffic class */

    /* Forwarding decision */
    __u32 egress_ifindex;       /* Target egress interface */
    __u8  action;               /* XDP_PASS, XDP_DROP, XDP_REDIRECT, etc. */
    __u8  mirror;               /* 0=no mirror, 1=mirror required */
    __u16 mirror_port;          /* Mirror destination port */

    /* Error handling */
    __u32 error;                /* Error code (0=no error) */
    __u32 drop_reason;          /* Reason for drop */

    /* Tail-call chain state */
    __u32 next_prog_id;         /* Next program to tail-call */
    __u32 call_depth;           /* Current tail-call depth */

    /* Reserved for future use (64 bytes — ABI v2) */
    __u32 reserved[16];
};

/* ── Error codes ───────────────────────────────────────────────── */

#define RS_ERROR_NONE           0
#define RS_ERROR_PARSE_FAILED   1
#define RS_ERROR_INVALID_VLAN   2
#define RS_ERROR_ACL_DENY       3
#define RS_ERROR_NO_ROUTE       4
#define RS_ERROR_QUEUE_FULL     5
#define RS_ERROR_INTERNAL       99

/* ── Drop reasons ──────────────────────────────────────────────── */

#define RS_DROP_NONE            0
#define RS_DROP_PARSE_ERROR     1
#define RS_DROP_VLAN_FILTER     2
#define RS_DROP_ACL_BLOCK       3
#define RS_DROP_NO_FWD_ENTRY    4
#define RS_DROP_TTL_EXCEEDED    5
#define RS_DROP_RATE_LIMIT      6
#define RS_DROP_CONGESTION      7

/* ── Event types ───────────────────────────────────────────────── */

/*
 * Event type namespace allocation:
 *   0x0000-0x00FF: Core reserved events
 *   0x0100-0x01FF: L2Learn events
 *   0x0200-0x02FF: ACL events
 *   0x0300-0x03FF: Route events
 *   0x0400-0x04FF: Mirror events
 *   0x0500-0x05FF: QoS events
 *   0x1000-0x7FFF: User module events (external modules)
 *   0xFF00-0xFFFF: Error events (core)
 */
#define RS_EVENT_RESERVED       0x0000
#define RS_EVENT_PKT_TRACE      0x0001
#define RS_EVENT_L2_BASE        0x0100
#define RS_EVENT_ACL_BASE       0x0200
#define RS_EVENT_ROUTE_BASE     0x0300
#define RS_EVENT_MIRROR_BASE    0x0400
#define RS_EVENT_QOS_BASE       0x0500
#define RS_EVENT_USER_BASE      0x1000
#define RS_EVENT_USER_MAX       0x7FFF
#define RS_EVENT_ERROR_BASE     0xFF00

/* L2Learn Events (0x0100-0x01FF) */
#define RS_EVENT_MAC_LEARNED    (RS_EVENT_L2_BASE + 1)
#define RS_EVENT_MAC_MOVED      (RS_EVENT_L2_BASE + 2)
#define RS_EVENT_MAC_AGED       (RS_EVENT_L2_BASE + 3)

/* ACL Events (0x0200-0x02FF) */
#define RS_EVENT_ACL_HIT        (RS_EVENT_ACL_BASE + 1)
#define RS_EVENT_ACL_DENY       (RS_EVENT_ACL_BASE + 2)

/* Error Events (0xFF00-0xFFFF) */
#define RS_EVENT_PARSE_ERROR    (RS_EVENT_ERROR_BASE + 1)
#define RS_EVENT_MAP_FULL       (RS_EVENT_ERROR_BASE + 2)

#endif /* __RSWITCH_ABI_H */
