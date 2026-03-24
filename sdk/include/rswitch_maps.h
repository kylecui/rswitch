/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * rSwitch Shared BPF Map Definitions — Opt-in Map Access
 *
 * Provides all shared BPF map definitions and helper functions for modules
 * that need direct access to rSwitch infrastructure maps (port config,
 * statistics, MAC table, VLAN membership, module config, etc.)
 *
 * Including this header instantiates map references in your BPF object.
 * Only include it if your module actually uses these maps.
 *
 * For modules that only need pipeline control (RS_GET_CTX, RS_TAIL_CALL_*,
 * RS_EMIT_EVENT), rswitch_module.h is sufficient — those macros work via
 * extern map declarations resolved at load time.
 *
 * Typical usage:
 *   #include <rswitch_module.h>    // always
 *   #include <rswitch_maps.h>      // only if you use maps below
 *
 * Backward-compatible usage (core modules):
 *   #include "rswitch_common.h"    // pulls in everything including maps
 */

#ifndef __RSWITCH_MAPS_H
#define __RSWITCH_MAPS_H

/* ── Dependencies ──────────────────────────────────────────────── */

#ifdef __BPF__
    #include <bpf/bpf_helpers.h>
#else
    #include <linux/types.h>
    #include <linux/bpf.h>
#endif

#include "rswitch_abi.h"

/* ── Module config constants ───────────────────────────────────── */

#define RS_MODULE_CONFIG_KEY_LEN        32
#define RS_MODULE_CONFIG_VAL_LEN        64
#define RS_MAX_MODULE_CONFIG_ENTRIES     256

/* ── Struct definitions (map value types) ──────────────────────── */

/* VLAN mode enumeration */
enum rs_vlan_mode {
    RS_VLAN_MODE_OFF = 0,       /* No VLAN processing */
    RS_VLAN_MODE_ACCESS = 1,    /* Access port (untagged only) */
    RS_VLAN_MODE_TRUNK = 2,     /* Trunk port (tagged + native) */
    RS_VLAN_MODE_HYBRID = 3,    /* Hybrid port (complex rules) */
    RS_VLAN_MODE_QINQ = 4,     /* Q-in-Q (802.1ad) */
};

struct rs_qinq_config {
    __u16 s_vlan;
    __u16 c_vlan_start;
    __u16 c_vlan_end;
    __u16 pad;
};

/*
 * Per-interface configuration loaded by user-space.
 * Modules read this to determine port behavior (VLAN mode, policies, etc.)
 */
struct rs_port_config {
    __u32 ifindex;              /* Interface index (key) */
    __u8  enabled;              /* 0=disabled, 1=enabled */
    __u8  mgmt_type;            /* 0=dumb, 1=managed */
    __u8  vlan_mode;            /* 0=off, 1=access, 2=trunk, 3=hybrid */
    __u8  learning;             /* 0=disabled, 1=enabled (MAC learning) */

    /* VLAN configuration */
    __u16 pvid;                 /* Port VLAN ID (for access/hybrid) */
    __u16 native_vlan;          /* Native VLAN (for trunk untagged) */
    __u16 access_vlan;          /* ACCESS mode VLAN ID (alias for pvid) */
    __u16 allowed_vlan_count;   /* Number of allowed VLANs (trunk mode) */
    __u16 allowed_vlans[128];   /* Allowed VLANs (trunk mode) */
    __u16 tagged_vlan_count;    /* Tagged VLANs count (hybrid mode) */
    __u16 tagged_vlans[64];     /* Tagged VLANs (hybrid mode) */
    __u16 untagged_vlan_count;  /* Untagged VLANs count (hybrid mode) */
    __u16 untagged_vlans[64];   /* Untagged VLANs (hybrid mode) */

    /* QoS */
    __u8  default_prio;         /* Default priority (0-7) */
    __u8  trust_dscp;           /* 0=ignore, 1=trust incoming DSCP */
    __u16 rate_limit_kbps;      /* Ingress rate limit */

    /* Security */
    __u8  port_security;        /* 0=off, 1=on (MAC limiting) */
    __u8  max_macs;             /* Max learned MACs */
    __u16 reserved;

    __u32 reserved2[4];
};

/* Module config map key */
struct rs_module_config_key {
    char module_name[RS_MODULE_CONFIG_KEY_LEN];
    char param_name[RS_MODULE_CONFIG_KEY_LEN];
};

/* Module config map value */
struct rs_module_config_value {
    __u32 type;
    union {
        __s64 int_val;
        __u32 bool_val;
        char str_val[56];
    };
};

/* MAC address as map key */
struct rs_mac_key {
    __u8 mac[6];
    __u16 vlan;                 /* VLAN context for MAC */
} __attribute__((packed));

/* MAC forwarding table entry */
struct rs_mac_entry {
    __u32 ifindex;              /* Egress interface */
    __u8  static_entry;         /* 0=dynamic (learned), 1=static (configured) */
    __u8  reserved[3];
    __u64 last_seen;            /* Timestamp for aging */
    __u32 hit_count;            /* Hit counter for statistics */
} __attribute__((packed));

/*
 * VLAN membership and peer information.
 * For each VLAN, stores which ports are members (tagged/untagged).
 * Used by VLAN module to determine flooding domain.
 */
struct rs_vlan_members {
    __u16 vlan_id;              /* VLAN ID (key) */
    __u16 member_count;         /* Number of member ports */

    /* Bitmask of member ports (ifindex % 64 = bit position) */
    __u64 tagged_members[4];    /* Up to 256 ports as tagged */
    __u64 untagged_members[4];  /* Up to 256 ports as untagged */

    __u32 reserved[4];
};

/* Per-interface packet and byte counters */
struct rs_stats {
    __u64 rx_packets;
    __u64 rx_bytes;
    __u64 tx_packets;
    __u64 tx_bytes;
    __u64 rx_drops;
    __u64 tx_drops;
    __u64 rx_errors;
    __u64 tx_errors;
} __attribute__((aligned(8)));

/* Per-module packet counters */
struct rs_module_stats {
    __u64 packets_processed;
    __u64 packets_forwarded;
    __u64 packets_dropped;
    __u64 packets_error;
    __u64 bytes_processed;
    __u64 last_seen_ns;
    __u32 module_id;
    char  name[32];
} __attribute__((aligned(8)));

/* ── BPF map definitions ───────────────────────────────────────── */

/* Per-packet processing context (shared via tail-call chain) */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rs_ctx);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_ctx_map SEC(".maps");

/* Tail-call program array (indexed by stage number) */
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, RS_MAX_PROGS);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_progs SEC(".maps");

/* Program chain (current_slot -> next_slot for egress pipeline) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, RS_MAX_PROGS);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_prog_chain SEC(".maps");

/* Unified event bus (ringbuf for all module events) */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);   /* 1MB ring */
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_event_bus SEC(".maps");

/* Port configuration map */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, RS_MAX_INTERFACES);
    __type(key, __u32);                     /* ifindex */
    __type(value, struct rs_port_config);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_port_config_map SEC(".maps");

/* Q-in-Q configuration map */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, RS_MAX_INTERFACES);
    __type(key, __u32);                     /* ifindex */
    __type(value, struct rs_qinq_config);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} qinq_config_map SEC(".maps");

/* Interface index to port index mapping (ifindex -> 0-based port_idx) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, RS_MAX_INTERFACES);
    __type(key, __u32);                     /* ifindex */
    __type(value, __u32);                   /* port_idx (0-based) */
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_ifindex_to_port_map SEC(".maps");

/* Module configuration map */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct rs_module_config_key);
    __type(value, struct rs_module_config_value);
    __uint(max_entries, RS_MAX_MODULE_CONFIG_ENTRIES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_module_config_map SEC(".maps");

/*
 * MAC table — extern declaration only.
 *
 * The rs_mac_table instance is defined in l2learn.bpf.c (single owner).
 * Other modules reference the pinned instance via this extern.
 * If your module IS the owner, define RS_MAC_TABLE_OWNER before including
 * this header and provide your own map definition.
 */
#if defined(__BPF__) && !defined(RS_MAC_TABLE_OWNER)
extern struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct rs_mac_key);
    __type(value, struct rs_mac_entry);
} rs_mac_table SEC(".maps");
#endif

/* VLAN membership map */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, RS_MAX_VLANS);
    __type(key, __u16);                     /* vlan_id */
    __type(value, struct rs_vlan_members);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_vlan_map SEC(".maps");

/* Per-interface statistics */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, RS_MAX_INTERFACES);
    __type(key, __u32);                     /* ifindex */
    __type(value, struct rs_stats);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_stats_map SEC(".maps");

/* Per-module statistics */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct rs_module_stats);
    __uint(max_entries, 64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_module_stats_map SEC(".maps");

/* ── Map helper functions ──────────────────────────────────────── */

/* Update per-interface RX statistics atomically */
static __always_inline void rs_stats_update_rx(struct rs_ctx *ctx, __u32 bytes) {
    __u32 key = ctx->ifindex;
    struct rs_stats *stats = bpf_map_lookup_elem(&rs_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->rx_packets, 1);
        __sync_fetch_and_add(&stats->rx_bytes, bytes);
    }
}

/* Update per-interface drop counter atomically */
static __always_inline void rs_stats_update_drop(struct rs_ctx *ctx) {
    __u32 key = ctx->ifindex;
    struct rs_stats *stats = bpf_map_lookup_elem(&rs_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->rx_drops, 1);
    }
}

/* Lookup port configuration by ifindex */
static __always_inline struct rs_port_config *rs_get_port_config(__u32 ifindex) {
    return bpf_map_lookup_elem(&rs_port_config_map, &ifindex);
}

/* MAC table helpers — require rs_mac_table (extern or owner-defined) */
#ifndef RS_MAC_TABLE_OWNER

/* Lookup MAC forwarding entry */
static __always_inline struct rs_mac_entry *rs_mac_lookup(__u8 *mac, __u16 vlan) {
    struct rs_mac_key key = {};
    __builtin_memcpy(key.mac, mac, 6);
    key.vlan = vlan;
    return bpf_map_lookup_elem(&rs_mac_table, &key);
}

/* Update MAC table entry (for learning) */
static __always_inline int rs_mac_update(__u8 *mac, __u16 vlan, __u32 ifindex, __u64 timestamp) {
    struct rs_mac_key key = {};
    struct rs_mac_entry entry = {
        .ifindex = ifindex,
        .static_entry = 0,
        .last_seen = timestamp,
        .hit_count = 1,
    };
    __builtin_memcpy(key.mac, mac, 6);
    key.vlan = vlan;
    return bpf_map_update_elem(&rs_mac_table, &key, &entry, BPF_ANY);
}

#endif /* !RS_MAC_TABLE_OWNER */

/* Check if port is member of VLAN (tagged or untagged) */
static __always_inline int rs_is_vlan_member(__u16 vlan, __u32 ifindex, int *is_tagged) {
    struct rs_vlan_members *members = bpf_map_lookup_elem(&rs_vlan_map, &vlan);
    if (!members)
        return 0;

    __u32 idx = ifindex / 64;
    __u32 bit = ifindex % 64;

    if (idx >= 4)
        return 0;

    if (members->tagged_members[idx] & (1ULL << bit)) {
        *is_tagged = 1;
        return 1;
    }

    if (members->untagged_members[idx] & (1ULL << bit)) {
        *is_tagged = 0;
        return 1;
    }

    return 0;
}

/* Lookup module runtime configuration by name and parameter */
static __always_inline struct rs_module_config_value *
rs_get_module_config(const char *module_name, const char *param_name)
{
    struct rs_module_config_key key = {};

#pragma unroll
    for (int i = 0; i < RS_MODULE_CONFIG_KEY_LEN; i++) {
        char c = module_name[i];
        key.module_name[i] = c;
        if (c == '\0')
            break;
    }

#pragma unroll
    for (int i = 0; i < RS_MODULE_CONFIG_KEY_LEN; i++) {
        char c = param_name[i];
        key.param_name[i] = c;
        if (c == '\0')
            break;
    }

    return bpf_map_lookup_elem(&rs_module_config_map, &key);
}

/* Update per-module statistics (processed/forwarded/dropped) */
RS_API_EXPERIMENTAL static __always_inline void
rs_module_stats_update(__u32 module_idx, __u64 bytes, int forwarded)
{
    struct rs_module_stats *stats;

    stats = bpf_map_lookup_elem(&rs_module_stats_map, &module_idx);
    if (!stats)
        return;

    __sync_fetch_and_add(&stats->packets_processed, 1);
    __sync_fetch_and_add(&stats->bytes_processed, bytes);
    if (forwarded)
        __sync_fetch_and_add(&stats->packets_forwarded, 1);
    else
        __sync_fetch_and_add(&stats->packets_dropped, 1);
    stats->last_seen_ns = bpf_ktime_get_ns();
}

/* Increment per-module error counter */
RS_API_EXPERIMENTAL static __always_inline void
rs_module_stats_error(__u32 module_idx)
{
    struct rs_module_stats *stats;

    stats = bpf_map_lookup_elem(&rs_module_stats_map, &module_idx);
    if (!stats)
        return;

    __sync_fetch_and_add(&stats->packets_error, 1);
}

#endif /* __RSWITCH_MAPS_H */
