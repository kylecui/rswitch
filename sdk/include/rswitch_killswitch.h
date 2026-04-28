/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * rSwitch Killswitch — Shared Constants & Structures
 *
 * Used by both BPF module (killswitch.bpf.c) and userspace watchdog.
 */

#ifndef __RSWITCH_KILLSWITCH_H
#define __RSWITCH_KILLSWITCH_H

#ifdef __BPF__
    #include <bpf/bpf_helpers.h>
#else
    #include <linux/types.h>
#endif

/* ── Killswitch UDP port (configurable via map, this is default) ── */
#define RS_KILLSWITCH_PORT_DEFAULT  19999

/* ── Magic key length (fixed, matches key file format) ─────────── */
#define RS_KILLSWITCH_KEY_LEN       32

/* ── Actions ───────────────────────────────────────────────────── */
#define RS_KILLSWITCH_ACTION_NONE   0
#define RS_KILLSWITCH_ACTION_STOP   1
#define RS_KILLSWITCH_ACTION_REBOOT 2

/* ── BPF map pin path ──────────────────────────────────────────── */
#define RS_KILLSWITCH_MAP_PIN       "/sys/fs/bpf/rs_killswitch_map"
#define RS_KILLSWITCH_CFG_MAP_PIN   "/sys/fs/bpf/rs_killswitch_cfg"

/* ── Key file default path ─────────────────────────────────────── */
#define RS_KILLSWITCH_KEY_PATH      "/etc/rswitch/killswitch.key"

/* ── Shared structures ─────────────────────────────────────────── */

/*
 * Killswitch trigger state — written by BPF, read by userspace watchdog.
 * Single-entry array map (key=0).
 */
struct rs_killswitch_state {
    __u32 action;           /* RS_KILLSWITCH_ACTION_* */
    __u32 trigger_ifindex;  /* Interface that received the trigger */
    __u64 trigger_ts;       /* bpf_ktime_get_ns() when triggered */
    __u32 trigger_count;    /* Monotonic counter (never reset) */
    __u32 pad;
};

/*
 * Killswitch configuration — written by userspace at startup,
 * read by BPF on every packet.
 * Single-entry array map (key=0).
 */
struct rs_killswitch_cfg {
    __u16 udp_port;                         /* Network byte order */
    __u8  stop_key[RS_KILLSWITCH_KEY_LEN];  /* 32-byte secret for STOP */
    __u8  reboot_key[RS_KILLSWITCH_KEY_LEN];/* 32-byte secret for REBOOT */
    __u8  enabled;                          /* 0=disabled, 1=enabled */
    __u8  pad[5];
};

#endif /* __RSWITCH_KILLSWITCH_H */
