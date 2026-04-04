// SPDX-License-Identifier: GPL-2.0
/* rSwitch Diagnostic: Egress fentry/fexit
 *
 * Loaded exclusively by rsdiag. NOT part of the main pipeline.
 * rsdiag retargets to rswitch_egress / rswitch_egress_mirror / egress_final.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "diag_common.h"

const volatile bool diag_egress_entry_enabled = false;
const volatile bool diag_egress_exit_enabled  = false;
const volatile bool diag_egress_final_entry_enabled = false;
const volatile bool diag_egress_final_exit_enabled  = false;

char _license[] SEC("license") = "GPL";

static __always_inline void emit_diag_event(__u16 tag, __u16 stage_id,
                                             __u16 module_id, __u8 action,
                                             __u16 reason, __u32 ifindex,
                                             __u32 egress_ifindex)
{
    struct rs_diag_event *evt;
    evt = bpf_ringbuf_reserve(&rs_diag_ringbuf, sizeof(*evt), 0);
    if (!evt)
        return;

    evt->ts_ns          = bpf_ktime_get_ns();
    evt->pid            = bpf_get_current_pid_tgid() >> 32;
    evt->cpu            = bpf_get_smp_processor_id();
    evt->prog_id        = 0;
    evt->attach_btf_id  = 0;
    evt->ifindex        = ifindex;
    evt->egress_ifindex = egress_ifindex;
    evt->pipeline_id    = 0;
    evt->profile_id     = 0;
    evt->stage_id       = stage_id;
    evt->module_id      = module_id;
    evt->tag            = tag;
    evt->reason         = reason;
    evt->action         = action;
    __builtin_memset(evt->reserved8, 0, sizeof(evt->reserved8));

    bpf_ringbuf_submit(evt, 0);
}

/* Egress hook (devmap) — rsdiag retargets to rswitch_egress */
SEC("fentry/rswitch_egress")
int BPF_PROG(diag_egress_entry, struct xdp_md *ctx)
{
    if (!diag_egress_entry_enabled)
        return 0;

    emit_diag_event(1 /* RS_DIAG_TAG_ENTRY */, 100 /* egress stage */,
                    2 /* RS_MOD_EGRESS */, 0, 0,
                    ctx->ingress_ifindex, ctx->egress_ifindex);
    return 0;
}

SEC("fexit/rswitch_egress")
int BPF_PROG(diag_egress_exit, struct xdp_md *ctx, int ret)
{
    if (!diag_egress_exit_enabled)
        return 0;

    __u16 reason = (ret == 1 /* XDP_DROP */) ? 1 : 0;
    emit_diag_event(2 /* RS_DIAG_TAG_EXIT */, 100,
                    2 /* RS_MOD_EGRESS */, (__u8)ret, reason,
                    ctx->ingress_ifindex, ctx->egress_ifindex);
    return 0;
}

/* Egress final — rsdiag retargets to the egress_final module's XDP function */
SEC("fentry/rswitch_egress")
int BPF_PROG(diag_egress_final_entry, struct xdp_md *ctx)
{
    if (!diag_egress_final_entry_enabled)
        return 0;

    emit_diag_event(1 /* RS_DIAG_TAG_ENTRY */, 190 /* egress_final stage */,
                    0x000E /* RS_MOD_EGRESS_FINAL */, 0, 0,
                    ctx->ingress_ifindex, ctx->egress_ifindex);
    return 0;
}

SEC("fexit/rswitch_egress")
int BPF_PROG(diag_egress_final_exit, struct xdp_md *ctx, int ret)
{
    if (!diag_egress_final_exit_enabled)
        return 0;

    emit_diag_event(2 /* RS_DIAG_TAG_EXIT */, 190,
                    0x000E /* RS_MOD_EGRESS_FINAL */, (__u8)ret, 0,
                    ctx->ingress_ifindex, ctx->egress_ifindex);
    return 0;
}
