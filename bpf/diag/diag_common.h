/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __RSWITCH_DIAG_COMMON_H
#define __RSWITCH_DIAG_COMMON_H

#include "../../sdk/include/rswitch_obs.h"

#ifdef __BPF__
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#else
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#endif

/* Diagnostic ringbuf — loaded only by rsdiag, 256KB */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_diag_ringbuf SEC(".maps");

/* Diagnostic targets — populated by loader, read by rsdiag */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, struct rs_diag_target_key);
    __type(value, struct rs_diag_target);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_diag_targets SEC(".maps");

#endif /* __RSWITCH_DIAG_COMMON_H */
