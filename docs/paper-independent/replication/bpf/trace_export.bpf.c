// SPDX-License-Identifier: GPL-2.0
/* S1 复现 tracing v0.1 —— 重建 cache epoch 历史（现稿 §4.4）
 *
 * 使用 bpftool 生成的 vmlinux.h（真实内核 BTF 布局），确保
 * dst->xdp_prog 与 bq->xdp_prog 的 CO-RE 读取与内核 6.8 一致。
 *
 * fentry/dev_map_enqueue : dst->xdp_prog（ingress 选中的 egress program）
 * fentry/bq_xmit_all     : bq->xdp_prog（bulk queue 实际保留的 program）
 * 两者对照判定「选中≠执行」与 epoch 边界（最终 FLUSH 清 bq）。
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct trace_evt {
    __u64 ts;
    __u32 kind;        /* 1=enqueue 2=xmit_all 3=xdp_do_flush 4=__dev_flush */
    __u32 prog_id;
    __u32 cpu;
    __u32 ifindex;
    __u32 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} rb SEC(".maps");

/* 目标输出设备 ifindex（loader 写入）；0 = 不过滤。
 * fentry 是系统级 hook：不过滤会把同机其他 devmap 流量（如 rSwitch 平台栈）
* 全部记进来，污染 epoch 重建。 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} trace_cfg SEC(".maps");

static __always_inline __u32 target_ifindex(void)
{
    __u32 key = 0;
    __u32 *v = bpf_map_lookup_elem(&trace_cfg, &key);
    return v ? *v : 0;
}

SEC("fentry/dev_map_enqueue")
int BPF_PROG(tr_enqueue, struct bpf_dtab_netdev *dst, struct xdp_buff *xdp,
             struct net_device *dev_rx)
{
    struct trace_evt *e;
    struct bpf_prog *p;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;
    if (target_ifindex() && BPF_CORE_READ(dst, dev, ifindex) != target_ifindex()) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }
    p = BPF_CORE_READ(dst, xdp_prog);
    e->ts = bpf_ktime_get_ns();
    e->kind = 1;
    e->prog_id = p ? BPF_CORE_READ(p, aux, id) : 0;
    e->cpu = bpf_get_smp_processor_id();
    e->ifindex = BPF_CORE_READ(dst, dev, ifindex);
    e->pad = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("fentry/bq_xmit_all")
int BPF_PROG(tr_xmit_all, struct xdp_dev_bulk_queue *bq, u32 flags)
{
    struct trace_evt *e;
    struct bpf_prog *p;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;
    if (target_ifindex() && BPF_CORE_READ(bq, dev, ifindex) != target_ifindex()) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }
    p = BPF_CORE_READ(bq, xdp_prog);
    e->ts = bpf_ktime_get_ns();
    e->kind = 2;
    e->prog_id = p ? BPF_CORE_READ(p, aux, id) : 0;
    e->cpu = bpf_get_smp_processor_id();
    e->ifindex = BPF_CORE_READ(bq, dev, ifindex);
    e->pad = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* 旁证：flush 链定位。预期链路 veth_poll 尾部 → xdp_do_flush(内联) → __dev_flush → bq_xmit_all。
 * kind3=__dev_flush：若 3 有而 2 无，bq 不在该 CPU 的 flush_list（enqueue/flush 跨 CPU）；
 * 若 3 全程为 0，veth_poll 没有触发 flush（模式/驱动路径问题）。 */
SEC("fentry/__dev_flush")
int BPF_PROG(tr_dev_flush)
{
    struct trace_evt *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;
    e->ts = bpf_ktime_get_ns();
    e->kind = 4;
    e->prog_id = 0;
    e->cpu = bpf_get_smp_processor_id();
    e->ifindex = 0;
    e->pad = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}
