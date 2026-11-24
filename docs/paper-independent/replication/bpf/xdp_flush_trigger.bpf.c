// SPDX-License-Identifier: GPL-2.0
/* S1 复现 flush 触发器 v0.1
 * 挂在 ens33（native XDP）。任何入向帧被 redirect 到 target 接口（建议 lo），
 * 驱动 NAPI poll 尾部的 xdp_do_flush() 会全局清所有 CPU 的 devmap flush_list，
 * 从而把滞留在 s1_out bulk queue 里的实验帧 flush 出来执行 egress。
 * 注意：redirect 目标为 lo 时，入向帧改道进入本机协议栈（ping 等正常工作）。
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct bpf_devmap_val);
} fw_ports SEC(".maps");

SEC("xdp")
int xdp_flush_trigger(struct xdp_md *ctx)
{
    __u32 key = 0;
    return bpf_redirect_map(&fw_ports, key, 0);
}

char LICENSE[] SEC("license") = "GPL";
