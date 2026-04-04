// SPDX-License-Identifier: GPL-2.0
/* rSwitch Diagnostic: Dispatcher fentry/fexit
 *
 * Loaded exclusively by rsdiag. NOT part of the main pipeline.
 * rsdiag uses bpf_program__set_attach_target() to retarget
 * each program to the actual dispatcher/module functions at runtime.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "diag_common.h"

/* rodata flags — rsdiag sets these before load */
const volatile bool diag_dispatcher_entry_enabled = false;
const volatile bool diag_dispatcher_exit_enabled  = false;
const volatile bool diag_module_entry_enabled     = false;
const volatile bool diag_module_exit_enabled      = false;

char _license[] SEC("license") = "GPL";

static __always_inline void emit_diag_event(__u16 tag, __u16 stage_id,
                                             __u16 module_id, __u8 action,
                                             __u16 reason, __u32 ifindex)
{
    struct rs_diag_event *evt;
    evt = bpf_ringbuf_reserve(&rs_diag_ringbuf, sizeof(*evt), 0);
    if (!evt)
        return;

    evt->ts_ns          = bpf_ktime_get_ns();
    evt->pid            = bpf_get_current_pid_tgid() >> 32;
    evt->cpu            = bpf_get_smp_processor_id();
    evt->prog_id        = 0;  /* filled by rsdiag from attach info */
    evt->attach_btf_id  = 0;
    evt->ifindex        = ifindex;
    evt->egress_ifindex = 0;
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

/*
 * fentry/fexit for dispatcher.
 *
 * The SEC name uses a PLACEHOLDER. rsdiag will call:
 *   bpf_program__set_attach_target(prog, target_fd, "rswitch_dispatcher")
 * before loading, which overrides the placeholder.
 *
 * BPF_PROG receives the target function's arguments.
 * rswitch_dispatcher(struct xdp_md *ctx) → args: struct xdp_md *ctx
 */
SEC("fentry/rswitch_dispatcher")
int BPF_PROG(diag_dispatcher_entry, struct xdp_md *ctx)
{
    if (!diag_dispatcher_entry_enabled)
        return 0;

    emit_diag_event(1 /* RS_DIAG_TAG_ENTRY */, 1 /* RS_STAGE_PREPROCESS */,
                    1 /* RS_MOD_DISPATCHER */, 0, 0,
                    ctx->ingress_ifindex);
    return 0;
}

SEC("fexit/rswitch_dispatcher")
int BPF_PROG(diag_dispatcher_exit, struct xdp_md *ctx, int ret)
{
    if (!diag_dispatcher_exit_enabled)
        return 0;

    emit_diag_event(2 /* RS_DIAG_TAG_EXIT */, 1 /* RS_STAGE_PREPROCESS */,
                    1 /* RS_MOD_DISPATCHER */, (__u8)ret, 0,
                    ctx->ingress_ifindex);
    return 0;
}

/*
 * Generic module fentry/fexit — rsdiag retargets these to specific
 * module XDP functions discovered from rs_diag_targets.
 *
 * These are placeholder programs. rsdiag clones them per-target if needed,
 * or uses bpf_program__set_attach_target() to point at the chosen module.
 *
 * Stage/module IDs are passed via rodata or hardcoded by rsdiag before load.
 */
const volatile __u16 diag_module_stage_id  = 0;
const volatile __u16 diag_module_module_id = 0;

SEC("fentry/rswitch_dispatcher")
int BPF_PROG(diag_module_entry, struct xdp_md *ctx)
{
    if (!diag_module_entry_enabled)
        return 0;

    emit_diag_event(1 /* RS_DIAG_TAG_ENTRY */, diag_module_stage_id,
                    diag_module_module_id, 0, 0,
                    ctx->ingress_ifindex);
    return 0;
}

SEC("fexit/rswitch_dispatcher")
int BPF_PROG(diag_module_exit, struct xdp_md *ctx, int ret)
{
    if (!diag_module_exit_enabled)
        return 0;

    emit_diag_event(2 /* RS_DIAG_TAG_EXIT */, diag_module_stage_id,
                    diag_module_module_id, (__u8)ret, 0,
                    ctx->ingress_ifindex);
    return 0;
}
