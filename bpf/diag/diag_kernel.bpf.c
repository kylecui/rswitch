// SPDX-License-Identifier: GPL-2.0
/* rSwitch Diagnostic: Kernel XDP tracepoints
 *
 * Loaded exclusively by rsdiag. Catches kernel-level XDP exceptions
 * and redirect errors via tp_btf tracepoints.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "diag_common.h"

const volatile bool diag_xdp_exception_enabled    = false;
const volatile bool diag_xdp_redirect_err_enabled = false;

char _license[] SEC("license") = "GPL";

static __always_inline void emit_diag_exception(__u32 ifindex, __u32 prog_id,
                                                 __u8 action, __u16 reason)
{
    struct rs_diag_event *evt;
    evt = bpf_ringbuf_reserve(&rs_diag_ringbuf, sizeof(*evt), 0);
    if (!evt)
        return;

    evt->ts_ns          = bpf_ktime_get_ns();
    evt->pid            = bpf_get_current_pid_tgid() >> 32;
    evt->cpu            = bpf_get_smp_processor_id();
    evt->prog_id        = prog_id;
    evt->attach_btf_id  = 0;
    evt->ifindex        = ifindex;
    evt->egress_ifindex = 0;
    evt->pipeline_id    = 0;
    evt->profile_id     = 0;
    evt->stage_id       = 0;  /* kernel-level, no stage */
    evt->module_id      = 0;
    evt->tag            = 6;  /* RS_DIAG_TAG_EXCEPTION */
    evt->reason         = reason;
    evt->action         = action;
    __builtin_memset(evt->reserved8, 0, sizeof(evt->reserved8));

    bpf_ringbuf_submit(evt, 0);
}

/*
 * tp_btf/xdp_exception — fired when XDP program returns XDP_ABORTED
 * or an invalid action code.
 *
 * Kernel tracepoint signature:
 *   trace_xdp_exception(struct net_device *dev, struct bpf_prog *xdp, u32 act)
 */
SEC("tp_btf/xdp_exception")
int BPF_PROG(diag_xdp_exception, struct net_device *dev,
             struct bpf_prog *xdp, u32 act)
{
    if (!diag_xdp_exception_enabled)
        return 0;

    __u32 ifindex = BPF_CORE_READ(dev, ifindex);
    __u32 prog_id = BPF_CORE_READ(xdp, aux, id);

    /* Map to internal drop reason: RS_DROP_XDP_ABORTED = 200 category */
    __u16 reason = 200;  /* RS_DROP_INTERNAL */

    emit_diag_exception(ifindex, prog_id, (__u8)act, reason);
    return 0;
}

/*
 * tp_btf/xdp_redirect_err — fired when bpf_redirect_map() or
 * bpf_redirect() fails (e.g., target ifindex down, map full).
 *
 * Kernel tracepoint signature:
 *   trace_xdp_redirect_err(struct net_device *dev, struct bpf_prog *xdp,
 *                           struct bpf_map *map, u32 index, int err)
 *
 * Note: this tracepoint was renamed/reworked across kernel versions.
 * We use BPF_CORE_READ for safety.
 */
SEC("tp_btf/xdp_redirect_err")
int BPF_PROG(diag_xdp_redirect_err, struct net_device *dev,
             struct bpf_prog *xdp, struct bpf_map *map,
             u32 index, int err)
{
    if (!diag_xdp_redirect_err_enabled)
        return 0;

    __u32 ifindex = BPF_CORE_READ(dev, ifindex);
    __u32 prog_id = BPF_CORE_READ(xdp, aux, id);

    /* Reason encodes the redirect error as a negative errno → positive u16 */
    __u16 reason = (err < 0) ? (__u16)(-err) : (__u16)err;

    emit_diag_exception(ifindex, prog_id, 4 /* XDP_REDIRECT */, reason);
    return 0;
}
