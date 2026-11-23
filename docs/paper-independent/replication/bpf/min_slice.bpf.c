// SPDX-License-Identifier: GPL-2.0
/* S1 go/no-go 复现切片 v0.2 —— 规格: docs/paper-independent/replication/SOURCES.md
 *
 * 机制（现稿 §3）: ingress root 读取 active-generation 标量 g，写入帧内 capsule，
 * bpf_redirect_map 到 devmap[g&1]。devmap bulk queue（16 帧）自 Linux 5.14
 * (commit cb261b594b41) 起在 epoch 内保留先选的 egress program 直至最终 FLUSH；
 * 混代 epoch 中后选代际的帧执行先保留的 egress program —— 混代。
 *
 * v0.2 变更: capsule（36B）与 wire（72B）内嵌 UDP payload（零 adjust_head，
 * 规避 AF_PACKET 注入帧 headroom 不足）；全主机字节序（同机收发，随 manifest 声明）。
 * 布局: UDP payload = capsule(36) + wire(72) + data(64)，共 172B。
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define CAPSULE_LEN  36
#define WIRE_LEN     72
#define DATA_LEN     64
#define PL_LEN       (CAPSULE_LEN + WIRE_LEN + DATA_LEN)
#define WIRE_MAGIC   0x53315731u   /* "S1W1"，主机字节序 */

/* cfg_map 键 */
#define CFG_ARM           0
#define CFG_WRONG_CAPSULE 1
#define CFG_MUX_ID        2
#define CFG_WRONG_MUX_ID  3

/* 盐表（现稿 §4.3，诊断判别器） */
#define SALT_A_I 0xa11a0a01u
#define SALT_A_E 0xa33a0a03u
#define SALT_B_I 0xb22b0b02u
#define SALT_B_E 0xb44b0b04u

/* 统计键 */
#define ST_RX        0
#define ST_REDIRECT  1
#define ST_EGRESS_A  2
#define ST_EGRESS_B  3
#define ST_MUX       4
#define ST_BADPARSE  5

/* 36B capsule（用户态预填 nonce/seq/tid/d，BPF 填 generation/ingress_bank） */
struct capsule {
    __u32 nonce;
    __u32 seq;
    __u32 transition_id;
    __u32 d_lo;
    __u32 d_hi;
    __u8  generation;
    __u8  ingress_bank;
    __u16 pad0;
    __u32 reserved[3];
};

/* 72B wire record（egress program 写，receiver 读） */
struct wire_record {
    __u32 magic;
    __u32 nonce;
    __u32 seq;
    __u32 transition_id;
    __u32 d_lo;
    __u32 d_hi;
    __u32 requested_gen;
    __u32 ingress_gen;
    __u32 ingress_bank;
    __u32 egress_gen;
    __u32 mux_id;
    __u32 salt_i;
    __u32 salt_e;
    __u32 semantic;
    __u32 path_sig;
    __u32 action;
    __u32 reserved[2];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u32);
} cfg_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} gen_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, struct bpf_devmap_val);   /* 8B：ifindex + prog union；int 会截断 prog */
} devmap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

static __always_inline void stat_inc(__u32 key)
{
    __u64 *v = bpf_map_lookup_elem(&stats, &key);
    if (v)
        (*v)++;
}

static __always_inline __u32 cfg_get(__u32 key)
{
    __u32 *v = bpf_map_lookup_elem(&cfg_map, &key);
    return v ? *v : 0;
}

/* 解析到 UDP payload，要求恰好 PL_LEN 字节 */
static __always_inline int parse_to_payload(struct xdp_md *ctx, __u8 **pl_out)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct udphdr *udp;
    __u8 *pl;

    if ((void *)(eth + 1) > data_end)
        return -1;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return -1;
    ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return -1;
    if (ip->protocol != IPPROTO_UDP)
        return -1;
    udp = (void *)ip + ip->ihl * 4;
    if ((void *)(udp + 1) > data_end)
        return -1;
    pl = (__u8 *)(udp + 1);
    if (pl + PL_LEN > data_end)
        return -1;
    *pl_out = pl;
    return 0;
}

/* ingress root：snapshot 代际 → 填 capsule → redirect_map */
SEC("xdp")
int xdp_ingress_root(struct xdp_md *ctx)
{
    __u8 *pl = NULL;
    struct capsule *c;
    __u32 g = 0, key = 0;
    __u32 *gp;

    stat_inc(ST_RX);
    if (parse_to_payload(ctx, &pl) < 0) {
        stat_inc(ST_BADPARSE);
        return XDP_PASS;
    }

    gp = bpf_map_lookup_elem(&gen_map, &key);
    if (!gp)
        return XDP_PASS;
    g = *gp & 1u;

    c = (struct capsule *)pl;
    c->generation = (__u8)g;          /* 实际赋值处（成功 lookup），非用户态请求处 */
    c->ingress_bank = c->generation;
    if (cfg_get(CFG_WRONG_CAPSULE))
        c->generation ^= 1;           /* 赋值后翻转，暴露 capsule 绑定 */

    stat_inc(ST_REDIRECT);
    return bpf_redirect_map(&devmap, g & 1, 0);
}

/* egress：读 capsule，写 payload 内 wire 区，XDP_PASS 出 s1_out */
static __always_inline int bank_process(struct xdp_md *ctx, __u32 self_bank,
                                        __u32 mux_id)
{
    __u8 *pl = NULL;
    struct capsule *c;
    struct wire_record *w;
    __u32 ig, E, I, sig;

    if (parse_to_payload(ctx, &pl) < 0)
        return XDP_ABORTED;

    c = (struct capsule *)pl;
    w = (struct wire_record *)(pl + CAPSULE_LEN);

    ig = c->generation;               /* 观测代际（wrong_capsule 下为翻转值） */
    E = self_bank ? SALT_B_E : SALT_A_E;
    I = ig ? SALT_B_I : SALT_A_I;
    sig = self_bank ? 0xAAAA0001u : 0xBBBB0002u;
    if (mux_id)
        sig ^= 0x004d5558u;           /* 'MUX' 参与 path 签名 */

    w->magic = WIRE_MAGIC;
    w->nonce = c->nonce;
    w->seq = c->seq;
    w->transition_id = c->transition_id;
    w->d_lo = c->d_lo;
    w->d_hi = c->d_hi;
    w->requested_gen = c->reserved[1];   /* 用户态预填 requested_gen */
    w->ingress_gen = ig;
    w->ingress_bank = c->ingress_bank;
    w->egress_gen = self_bank;
    w->mux_id = mux_id;
    w->salt_i = I;
    w->salt_e = E;
    w->semantic = c->d_lo ^ c->d_hi ^ I ^ E;
    w->path_sig = sig;
    w->action = 0;

    stat_inc(self_bank ? ST_EGRESS_B : ST_EGRESS_A);
    return XDP_PASS;
}

SEC("xdp/devmap")   /* devmap 条目上的 egress program 必须是 BPF_XDP_DEVMAP（v6.8 __dev_map_alloc_node 强制） */
int xdp_egress_bank_a(struct xdp_md *ctx)
{
    return bank_process(ctx, 0, 0);
}

SEC("xdp/devmap")
int xdp_egress_bank_b(struct xdp_md *ctx)
{
    return bank_process(ctx, 1, 0);
}

/* 稳定公共出口：两个 devmap 条目共用的同一对象；
 * 代际选择移入逐帧 capsule（现稿 §3.3） */
SEC("xdp/devmap")
int xdp_egress_common_mux(struct xdp_md *ctx)
{
    __u8 *pl = NULL;
    struct capsule *c;
    __u32 g, mid;

    if (parse_to_payload(ctx, &pl) < 0)
        return XDP_ABORTED;
    c = (struct capsule *)pl;
    g = c->generation & 1u;
    mid = cfg_get(CFG_MUX_ID);
    if (cfg_get(CFG_WRONG_MUX_ID))
        mid = cfg_get(CFG_WRONG_MUX_ID);
    stat_inc(ST_MUX);
    return bank_process(ctx, g, mid);
}

char LICENSE[] SEC("license") = "GPL";
