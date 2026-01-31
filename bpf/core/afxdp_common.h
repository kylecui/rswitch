/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __AFXDP_COMMON_H
#define __AFXDP_COMMON_H

#ifdef __BPF__
    /* BPF side: types from vmlinux.h */
#else
    #include <linux/types.h>
#endif

/*
 * AF_XDP Common Definitions
 * 
 * Shared between XDP kernel programs and user-space AF_XDP sockets.
 * Defines the VOQ metadata structure, QoS configuration, and state machine.
 */

/* QoS Priority Levels */
#define QOS_MAX_PRIORITIES  4

/* Sentinel value for unclassified priority */
#define QOS_PRIO_UNSET      0xFF

/* Legacy alias for compatibility */
#define MAX_PRIORITIES QOS_MAX_PRIORITIES

/* Priority values (0=lowest, 3=highest) */
#define QOS_PRIO_LOW      0
#define QOS_PRIO_NORMAL   1
#define QOS_PRIO_HIGH     2
#define QOS_PRIO_CRITICAL 3

/* VOQ Metadata - Sent via ringbuf from XDP to user-space VOQd */
struct voq_meta {
	__u64 ts_ns;           /* Timestamp (bpf_ktime_get_ns) */
	__u32 eg_port;         /* Egress port index */
	__u32 prio;            /* Priority (0-3, 0=lowest, 3=highest) */
	__u32 len;             /* Packet length */
	__u32 flow_hash;       /* Flow hash for scheduling fairness */
	__u8  ecn_hint;        /* ECN marking hint (0=no congestion, 1=congested) */
	__u8  drop_hint;       /* Drop recommendation */
	__u8  _pad[2];
} __attribute__((packed));

/* QoS Configuration - Loaded from user-space, controls DSCP->priority mapping */
struct qos_config {
	__u32 dscp2prio[64];   /* DSCP (0-63) -> Priority (0-3) mapping */
	__u32 default_port;    /* Default egress port if routing fails */
	__u32 ecn_threshold;   /* Queue depth threshold for ECN marking */
	__u32 drop_threshold;  /* Queue depth threshold for dropping low-priority */
} __attribute__((aligned(8)));

/* VOQd State - Controls AF_XDP takeover behavior */
struct voqd_state {
	__u32 running;         /* 1=VOQd alive (heartbeat), 0=dead */
	__u32 prio_mask;       /* Bitmask: which priorities to intercept (bit 0=prio 0, ...) */
	__u32 mode;            /* Operating mode: 0=BYPASS, 1=SHADOW, 2=ACTIVE */
	__u64 last_heartbeat_ns; /* Last heartbeat timestamp (for timeout detection) */
	__u32 failover_count;  /* Number of automatic failovers to BYPASS */
	__u32 overload_drops;  /* Packets dropped due to VOQd overload */
	__u32 flags;           /* Control flags (auto_failover, etc.) */
	__u32 _reserved;
} __attribute__((aligned(8)));

/* Operating Modes */
enum voqd_mode {
	VOQD_MODE_BYPASS = 0,  /* XDP fast-path only, no user-space involvement */
	VOQD_MODE_SHADOW = 1,  /* VOQd observing (ringbuf), but not intercepting packets */
	VOQD_MODE_ACTIVE = 2,  /* VOQd actively intercepting high-priority flows */
};

/* State Flags */
#define VOQD_FLAG_AUTO_FAILOVER  (1 << 0)  /* Enable automatic ACTIVE->BYPASS on timeout */
#define VOQD_FLAG_DEGRADE_ON_OVERLOAD (1 << 1) /* Degrade to fast-path on overload */
#define VOQD_FLAG_STRICT_PRIORITY (1 << 2) /* Enforce strict priority (no best-effort) */

/* Timeouts (nanoseconds) */
#define VOQD_HEARTBEAT_TIMEOUT_NS (5ULL * 1000000000ULL)  /* 5 seconds */
#define VOQD_OVERLOAD_THRESHOLD 1000  /* Ringbuf reserve failures before degradation */

/* Queue Depth Key - Per-port, per-priority congestion tracking */
struct qdepth_key {
	__u16 port;
	__u8  prio;
	__u8  _pad;
} __attribute__((packed));

/* Port Policy - Per-port QoS and security policy */
struct port_policy {
	__u32 rate_limit_bps;      /* Token bucket rate (bits per second) */
	__u32 burst_bytes;          /* Token bucket burst size */
	__u32 drop_on_congest;      /* Drop low-priority on congestion */
	__u32 ecn_on_congest;       /* ECN mark on congestion */
	__u32 mirror_prio_mask;     /* Which priorities to mirror (bitmask) */
	__u32 _reserved[3];
} __attribute__((aligned(8)));

#endif /* __AFXDP_COMMON_H__ */
