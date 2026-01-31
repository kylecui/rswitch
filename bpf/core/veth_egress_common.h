/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Veth Egress Common Definitions
 * 
 * Shared between XDP programs and user-space (VOQd).
 * Defines the VOQ TX metadata header format for the veth egress path.
 * 
 * Architecture:
 *   VOQd AF_XDP TX → veth_voq_in → veth_voq_out (XDP) → devmap → Physical NIC
 * 
 * The metadata header is prepended by VOQd and stripped by the veth XDP program.
 */

#ifndef __VETH_EGRESS_COMMON_H
#define __VETH_EGRESS_COMMON_H

#ifdef __BPF__
    /* BPF side: types from vmlinux.h */
#else
    #include <linux/types.h>
    #include <stdint.h>
#endif

/*
 * VOQ TX Metadata Header
 * 
 * Prepended by VOQd before AF_XDP TX to veth_voq_in.
 * Stripped by veth_egress XDP program before forwarding to physical NIC.
 * 
 * This header carries context information from the ingress path through
 * user-space, enabling the egress XDP modules to access the original
 * packet metadata (priority, flags, etc.).
 * 
 * Size: 16 bytes (aligned for efficient access)
 */
struct voq_tx_meta {
    __u32 egress_ifindex;       /* Target physical NIC ifindex */
    __u32 ingress_ifindex;      /* Original ingress interface (for context) */
    __u8  prio;                 /* QoS priority (0-7) */
    __u8  flags;                /* Processing flags (see VOQ_TX_FLAG_*) */
    __u16 vlan_id;              /* Egress VLAN ID (0 = no VLAN context) */
    __u32 reserved;             /* Reserved for future use (alignment) */
} __attribute__((packed, aligned(4)));

#define VOQ_TX_META_SIZE sizeof(struct voq_tx_meta)

/* VOQ TX Flags */
#define VOQ_TX_FLAG_SKIP_VLAN      (1 << 0)  /* Skip VLAN processing */
#define VOQ_TX_FLAG_SKIP_QOS       (1 << 1)  /* Skip QoS processing */
#define VOQ_TX_FLAG_MIRROR         (1 << 2)  /* This is a mirrored packet */
#define VOQ_TX_FLAG_FROM_VOQ       (1 << 3)  /* Packet came from VOQ (always set) */

/* Magic value for validation (optional, can be added to reserved field) */
#define VOQ_TX_META_MAGIC          0x564F5158  /* "VOQX" */

/*
 * Veth Egress Configuration
 * 
 * Configuration for the veth egress path, loaded from user-space.
 */
struct veth_egress_config {
    __u32 enabled;              /* 1 = veth egress path enabled */
    __u32 veth_out_ifindex;     /* veth_voq_out interface index */
    __u32 default_egress_if;    /* Default egress if metadata is invalid */
    __u32 flags;                /* Configuration flags */
} __attribute__((aligned(8)));

/* Configuration flags */
#define VETH_EGRESS_FLAG_STRICT    (1 << 0)  /* Drop on invalid metadata */
#define VETH_EGRESS_FLAG_DEBUG     (1 << 1)  /* Enable debug logging */

/*
 * Required headroom for veth egress path
 * 
 * VOQd must ensure packets have at least this much headroom before the
 * Ethernet header to prepend the voq_tx_meta header.
 * 
 * XDP_PACKET_HEADROOM (256) is required for native XDP zero-copy.
 * We add VOQ_TX_META_SIZE on top of that.
 */
#define VOQ_TX_REQUIRED_HEADROOM   (256 + VOQ_TX_META_SIZE)

#endif /* __VETH_EGRESS_COMMON_H */
