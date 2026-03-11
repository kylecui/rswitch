// SPDX-License-Identifier: GPL-2.0

#ifndef __RSWITCH_LACPD_H
#define __RSWITCH_LACPD_H

#include <linux/types.h>

#define LACPD_MAX_MEMBERS 8
#define LACPD_EVENT_TYPE  (0x0100 + 0x20)
#define LACPD_MODE_ACTIVE 1
#define LACPD_MODE_PASSIVE 0
#define LACP_STATE_DETACHED 0
#define LACP_STATE_ATTACHED 1
#define LACP_STATE_COLLECTING 2
#define LACP_STATE_DISTRIBUTING 3

struct lacp_port_info {
    __u32 agg_id;
    __u32 partner_key;
    __u32 actor_key;
    __u8 state;
    __u8 selected;
    __u8 pad[2];
    __u64 last_lacpdu_ts;
} __attribute__((packed));

struct lacp_agg_members {
    __u32 member_count;
    __u32 members[LACPD_MAX_MEMBERS];
    __u32 tx_hash_mode;
} __attribute__((packed));

struct lacp_event {
    __u32 event_type;
    __u32 ifindex;
    __u64 timestamp_ns;
    __u32 pkt_len;
    __u16 partner_key;
    __u16 partner_port_priority;
    __u8 actor_state;
    __u8 partner_system_id[6];
    __u8 parsed;
    __u8 state;
    __u8 selected;
    __u8 pad[1];
} __attribute__((packed));

#endif
