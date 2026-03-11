// SPDX-License-Identifier: GPL-2.0

#ifndef RSWITCH_STPD_H
#define RSWITCH_STPD_H

#include <linux/types.h>

#define STP_EVENT_BPDU (RS_EVENT_L2_BASE + 0x10)

enum stp_port_fwd_state {
    STP_STATE_DISCARDING = 0,
    STP_STATE_LEARNING = 1,
    STP_STATE_FORWARDING = 2,
};

struct stp_port_state {
    __u32 state;
    __u32 role;
    __u32 bridge_priority;
    __u32 path_cost;
    __u64 last_bpdu_ts;
};

struct stp_bpdu_event {
    __u32 event_type;
    __u32 ifindex;
    __u64 timestamp_ns;
    __u32 frame_len;
    __u32 bpdu_len;
    __u8 data[128];
} __attribute__((packed));

#endif
