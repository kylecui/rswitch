// SPDX-License-Identifier: GPL-2.0
/* rSwitch Common Map Definitions
 * 
 * Shared BPF map definitions used across multiple modules.
 * These maps provide shared state for configuration, forwarding tables,
 * and inter-module communication.
 */

#ifndef __RSWITCH_MAP_DEFS_H
#define __RSWITCH_MAP_DEFS_H

#ifdef __BPF__
    /* BPF side: types from vmlinux.h, bpf_helpers from rswitch_bpf.h */
    #include <bpf/bpf_helpers.h>
#else
    #include <linux/types.h>
    #include <linux/bpf.h>
#endif

#include "uapi.h"

/* VLAN mode enumeration */
enum rs_vlan_mode {
    RS_VLAN_MODE_OFF = 0,       /* No VLAN processing */
    RS_VLAN_MODE_ACCESS = 1,    /* Access port (untagged only) */
    RS_VLAN_MODE_TRUNK = 2,     /* Trunk port (tagged + native) */
    RS_VLAN_MODE_HYBRID = 3     /* Hybrid port (complex rules) */
};

/* Port configuration
 * 
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

/* Port configuration map */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, RS_MAX_INTERFACES);
    __type(key, __u32);                     /* ifindex */
    __type(value, struct rs_port_config);
    __uint(pinning, LIBBPF_PIN_BY_NAME);    /* Pin to /sys/fs/bpf/ */
} rs_port_config_map SEC(".maps");

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

/* MAC forwarding table */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536); /* 64K MAC entries */
    __type(key, struct rs_mac_key);
    __type(value, struct rs_mac_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_mac_table SEC(".maps");

/* VLAN membership and peer information
 * 
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

/* VLAN membership map */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, RS_MAX_VLANS);
    __type(key, __u16);                     /* vlan_id */
    __type(value, struct rs_vlan_members);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_vlan_map SEC(".maps");

/* Devmap for packet redirection with egress program attachment
 * 
 * Standard DEVMAP (not HASH) for efficient redirect operations.
 * Supports egress program attachment via struct bpf_devmap_val.
 * 
 * NOTE: Following PoC design - NO PINNING to avoid conflicts
 * Each module creates its own instance if needed.
 */
struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(max_entries, RS_MAX_INTERFACES);
    __type(key, __u32);         /* ifindex */
    __type(value, struct bpf_devmap_val);
    /* NO pinning - following PoC pattern */
} rs_devmap SEC(".maps");

/* XDP queue redirect map (fast-path only) - DEPRECATED
 * 
 * Use rs_devmap instead. Kept for compatibility.
 * NO PINNING to avoid conflicts (following PoC pattern).
 */
struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP_HASH);
    __uint(max_entries, RS_MAX_INTERFACES);
    __type(key, __u32);         /* ifindex */
    __type(value, struct bpf_devmap_val);
    /* NO pinning */
} rs_xdp_devmap SEC(".maps");

/* Statistics counters
 * 
 * Per-interface packet and byte counters.
 * Updated by modules and exported to user-space for telemetry.
 */
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

/* Per-interface statistics */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, RS_MAX_INTERFACES);
    __type(key, __u32);         /* ifindex */
    __type(value, struct rs_stats);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_stats_map SEC(".maps");

/* Helper functions for map operations */

/* Update statistics atomically */
static __always_inline void rs_stats_update_rx(struct rs_ctx *ctx, __u32 bytes) {
    __u32 key = ctx->ifindex;
    struct rs_stats *stats = bpf_map_lookup_elem(&rs_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->rx_packets, 1);
        __sync_fetch_and_add(&stats->rx_bytes, bytes);
    }
}

static __always_inline void rs_stats_update_drop(struct rs_ctx *ctx) {
    __u32 key = ctx->ifindex;
    struct rs_stats *stats = bpf_map_lookup_elem(&rs_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->rx_drops, 1);
    }
}

/* Lookup port configuration */
static __always_inline struct rs_port_config *rs_get_port_config(__u32 ifindex) {
    return bpf_map_lookup_elem(&rs_port_config_map, &ifindex);
}

/* Lookup MAC forwarding entry */
static __always_inline struct rs_mac_entry *rs_mac_lookup(__u8 *mac, __u16 vlan) {
    struct rs_mac_key key = {};
    __builtin_memcpy(key.mac, mac, 6);
    key.vlan = vlan;
    return bpf_map_lookup_elem(&rs_mac_table, &key);
}

/* Update MAC table (for learning) */
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

#endif /* __RSWITCH_MAP_DEFS_H */
