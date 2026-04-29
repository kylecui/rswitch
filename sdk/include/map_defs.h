// SPDX-License-Identifier: GPL-2.0
/* rSwitch Common Map Definitions
 * 
 * Shared BPF map definitions used across multiple modules.
 * These maps provide shared state for configuration, forwarding tables,
 * and inter-module communication.
 */

#ifndef __RSWITCH_MAP_DEFS_H
#define __RSWITCH_MAP_DEFS_H

#warning "map_defs.h is deprecated. Use #include <rswitch_maps.h> instead. See sdk/docs/SDK_Migration_Guide.md"

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

/* Interface index to port index mapping
 * 
 * Maps real ifindex (e.g., 4) to consecutive port_idx (0, 1, 2, ...)
 * Used by VOQd and AF_XDP modules that need 0-based port indexing.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, RS_MAX_INTERFACES);
    __type(key, __u32);                     /* ifindex */
    __type(value, __u32);                   /* port_idx (0-based) */
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_ifindex_to_port_map SEC(".maps");

#define RS_MODULE_CONFIG_KEY_LEN 32
#define RS_MODULE_CONFIG_VAL_LEN 64
#define RS_MAX_MODULE_CONFIG_ENTRIES 256

struct rs_module_config_key {
    char module_name[RS_MODULE_CONFIG_KEY_LEN];
    char param_name[RS_MODULE_CONFIG_KEY_LEN];
};

struct rs_module_config_value {
    __u32 type;
    union {
        __s64 int_val;
        __u32 bool_val;
        char str_val[56];
    };
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct rs_module_config_key);
    __type(value, struct rs_module_config_value);
    __uint(max_entries, RS_MAX_MODULE_CONFIG_ENTRIES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_module_config_map SEC(".maps");



/* MAC address as map key
 * 
 * NOTE: Kept in map_defs.h for struct definition visibility.
 * Actual map instance moved to l2learn.bpf.c (single owner pattern).
 */
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

/* NOTE: rs_mac_table map instance removed!
 * 
 * Following Single Owner Pattern:
 * - MAC table is defined ONLY in l2learn.bpf.c (its primary owner)
 * - Still pinned (LIBBPF_PIN_BY_NAME) for user-space access
 * - Loader accesses it via l2learn module object
 * - Struct definitions kept here for visibility to other modules
 * 
 * Rationale:
 * - l2learn is the only module that writes to MAC table
 * - Other modules only read (can use external declaration)
 * - Reduces coupling - other modules don't auto-create MAC table instance
 */

/* External declaration for rs_mac_table (defined in l2learn.bpf.c)
 * 
 * This allows helper functions below to reference the map without
 * creating a new instance. The linker will resolve this to the
 * actual pinned map instance created by l2learn.
 * 
 * If RS_MAC_TABLE_OWNER is defined (in l2learn.bpf.c), skip this
 * extern declaration to avoid conflicts.
 */
#if defined(__BPF__) && !defined(RS_MAC_TABLE_OWNER)
extern struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct rs_mac_key);
    __type(value, struct rs_mac_entry);
} rs_mac_table SEC(".maps");
#endif

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

/* NOTE: rs_xdp_devmap removed from here!
 * Following PoC pattern: devmap is defined ONLY in lastcall.bpf.c
 * Loader accesses it via lastcall module's object.
 * No pinning needed - single owner, no cross-module sharing.
 */

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

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct rs_module_stats);
    __uint(max_entries, 64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_module_stats_map SEC(".maps");

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

/* MAC table helper functions
 * 
 * NOTE: These helpers require rs_mac_table to be available:
 * - In l2learn.bpf.c: rs_mac_table is defined locally
 * - In other modules: must use extern declaration before calling these helpers
 * 
 * Example usage in other modules:
 *   extern struct { ... } rs_mac_table SEC(".maps");
 *   struct rs_mac_entry *entry = rs_mac_lookup(mac, vlan);
 */

#ifndef RS_MAC_TABLE_OWNER
/* Only provide helpers if not the owner (owner defines rs_mac_table directly) */

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

#endif /* __RSWITCH_MAP_DEFS_H */
