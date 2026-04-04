/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * rSwitch Observability Structures
 *
 * Shared between BPF programs and user-space for L0/L1/L2 observability.
 * Include this via rswitch_module.h (automatic) or directly for user-space tools.
 */

#ifndef __RSWITCH_OBS_H
#define __RSWITCH_OBS_H

#include "rswitch_abi.h"

/* -- Relaxed per-CPU update macros --------------------------------- */

#ifdef __BPF__
#define RS_READ_ONCE(x)       (*(volatile typeof(x) *)&(x))
#define RS_WRITE_ONCE(x, v)   (*(volatile typeof(x) *)&(x) = (v))
#define RS_NO_TEAR_ADD(x, val) RS_WRITE_ONCE((x), RS_READ_ONCE(x) + (val))
#define RS_NO_TEAR_INC(x)     RS_NO_TEAR_ADD((x), 1)
#endif

/* -- L1 event gate bits -------------------------------------------- */

enum rs_obs_event_gate_bit {
    RS_OBS_GATE_DROP_ANY           = 0,
    RS_OBS_GATE_PASS_SAMPLE        = 1,
    RS_OBS_GATE_REDIRECT_SAMPLE    = 2,
    RS_OBS_GATE_PARSE_EXCEPTION    = 3,
    RS_OBS_GATE_VLAN_EXCEPTION     = 4,
    RS_OBS_GATE_ACL_HIT            = 5,
    RS_OBS_GATE_ACL_DROP           = 6,
    RS_OBS_GATE_ROUTE_EXCEPTION    = 7,
    RS_OBS_GATE_QOS_EXCEPTION      = 8,
    RS_OBS_GATE_MIRROR_EXCEPTION   = 9,
    RS_OBS_GATE_INTERNAL_EXCEPTION = 10,
    RS_OBS_GATE_USER_EVENT         = 11,
    RS_OBS_GATE_DIAG_CHECKPOINT    = 12,
};

/* -- Observability config (L0 map value) --------------------------- */

struct rs_obs_cfg {
    __u32 level;          /* enum rs_obs_level */
    __u32 sample_ppm;     /* 0..1000000 */
    __u64 event_mask;     /* bitset of enum rs_obs_event_gate_bit */
    __u32 burst_limit;    /* max L1 emits per packet path */
    __u32 reserved;
};

/* -- L0 stats keys/values ------------------------------------------ */

enum rs_obs_hist_metric {
    RS_OBS_HIST_PKT_LEN = 1,
};

#define RS_OBS_HIST_BUCKETS 16

struct rs_obs_stats_key {
    __u32 ifindex;
    __u16 rxq;
    __u16 pipeline_id;
    __u16 profile_id;
    __u16 stage_id;
    __u16 module_id;
    __u8  proto;
    __u8  action;
};

struct rs_obs_stats_val {
    __u64 packets;
    __u64 bytes;
};

struct rs_drop_stats_key {
    __u32 ifindex;
    __u16 rxq;
    __u16 pipeline_id;
    __u16 profile_id;
    __u16 stage_id;
    __u16 module_id;
    __u16 reason;
    __u16 reserved;
};

struct rs_drop_stats_val {
    __u64 packets;
};

struct rs_hist_key {
    __u32 ifindex;
    __u16 pipeline_id;
    __u16 profile_id;
    __u16 stage_id;
    __u16 module_id;
    __u8  metric;
    __u8  bucket;
};

struct rs_hist_val {
    __u64 count;
};

struct rs_stage_hit_key {
    __u16 pipeline_id;
    __u16 profile_id;
    __u16 stage_id;
    __u16 module_id;
};

struct rs_stage_hit_val {
    __u64 hits;
};

/* -- L1 event envelope --------------------------------------------- */

enum rs_obs_event_flag {
    RS_OBS_F_SAMPLED      = 1U << 0,
    RS_OBS_F_EXCEPTION    = 1U << 1,
    RS_OBS_F_DROP         = 1U << 2,
    RS_OBS_F_REDIRECT_ERR = 1U << 3,
    RS_OBS_F_PROFILE_MARK = 1U << 4,
};

struct rs_obs_event {
    __u16 event_type;     /* enum rs_obs_event_type */
    __u16 event_len;
    __u32 ifindex;
    __u32 rxq;
    __u64 ts_ns;
    __u16 pipeline_id;
    __u16 profile_id;
    __u16 stage_id;
    __u16 module_id;
    __u16 pkt_len;
    __u16 reason;
    __u8  ip_proto;
    __u8  action;
    __u16 flags;
    __u32 flow_hash;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
};

/* -- L2 diagnostic structures -------------------------------------- */

enum rs_diag_tag {
    RS_DIAG_TAG_ENTRY      = 1,
    RS_DIAG_TAG_EXIT       = 2,
    RS_DIAG_TAG_DROP       = 3,
    RS_DIAG_TAG_REDIRECT   = 4,
    RS_DIAG_TAG_CHECKPOINT = 5,
    RS_DIAG_TAG_EXCEPTION  = 6,
};

enum rs_diag_target_kind {
    RS_DIAG_TARGET_DISPATCHER = 1,
    RS_DIAG_TARGET_EGRESS     = 2,
    RS_DIAG_TARGET_MODULE     = 3,
};

struct rs_diag_event {
    __u64 ts_ns;
    __u32 pid;
    __u32 cpu;
    __u32 prog_id;
    __u32 attach_btf_id;
    __u32 ifindex;
    __u32 egress_ifindex;
    __u16 pipeline_id;
    __u16 profile_id;
    __u16 stage_id;
    __u16 module_id;
    __u16 tag;
    __u16 reason;
    __u8  action;
    __u8  reserved8[3];
};

struct rs_diag_target_key {
    __u32 prog_id;
};

struct rs_diag_target {
    __u32 prog_id;
    __u32 attach_btf_id;
    __u16 stage_id;
    __u16 module_id;
    __u16 hook;           /* enum rs_hook_point */
    __u16 kind;           /* enum rs_diag_target_kind */
    char  prog_name[32];
    char  module_name[32];
};

struct rs_diag_checkpoint {
    __u16 tag;
    __u16 stage_id;
    __u16 module_id;
    __u16 reserved;
};

#endif /* __RSWITCH_OBS_H */
