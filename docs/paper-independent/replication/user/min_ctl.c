// SPDX-License-Identifier: GPL-2.0
/* S1 复现控制器 v0.1 —— 单进程常驻：setup → trace attach → 发送 → dump → teardown
 * 用法:
 *   min_ctl run --tx s1_tx --in s1_in --out s1_out --arm direct \
 *               --frames 2048 --epochs 32 [--wrong-bank] [--wrong-mux] [--wrong-capsule]
 * arm: direct | mux
 * 注意: skeleton 前缀为 min_slice_bpf / trace_export_bpf（bpftool 将 '.' 归一为 '_'）
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_link.h>
#include <net/ethernet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>


#define CAPSULE_LEN 36
#define WIRE_LEN    72
#define DATA_LEN    64
#define UDP_PL_LEN  (CAPSULE_LEN + WIRE_LEN + DATA_LEN)
#define FRAME_LEN   (14 + 20 + 8 + UDP_PL_LEN)
#define BULK_FRAMES_PER_EPOCH 64
#define MAX_CPU    128

/* 与 bpf/min_slice.bpf.c 逐字段一致，主机字节序（同机收发） */
struct capsule_u {
    __u32 nonce;
    __u32 seq;
    __u32 transition_id;
    __u32 d_lo;
    __u32 d_hi;
    __u8  generation;
    __u8  ingress_bank;
    __u16 pad0;
    __u32 reserved[3];   /* reserved[1] = requested_gen */
};

/* 与 bpf/trace_export.bpf.c 的 struct trace_evt 字段一致（skeleton 头不含自定义类型） */
struct trace_evt {
    __u64 ts;
    __u32 kind;
    __u32 prog_id;
    __u32 cpu;
    __u32 ifindex;
    __u32 pad;
};

struct cfg {
    const char *tx_if, *in_if, *out_if;
    int arm;
    int wrong_bank, wrong_mux, wrong_capsule;
    long frames, epochs;
    int hold;
    int tx_idx, in_idx, out_idx;
};

static int write_cfg(struct bpf_object *obj, const char *name, __u32 key, __u32 val)
{
    int fd = bpf_object__find_map_fd_by_name(obj, name);
    return fd < 0 ? fd : bpf_map_update_elem(fd, &key, &val, BPF_ANY);
}

static void fill_frame(unsigned char *f, long seq, __u32 g)
{
    struct ethhdr *eth = (struct ethhdr *)f;
    struct iphdr *ip = (struct iphdr *)(f + 14);
    struct udphdr *udp = (struct udphdr *)(f + 14 + 20);
    struct capsule_u *c = (struct capsule_u *)(f + 14 + 20 + 8);
    __u8 *wire = f + 14 + 20 + 8 + CAPSULE_LEN;

    memset(f, 0, FRAME_LEN);
    memset(eth->h_dest, 0x02, 6);
    eth->h_proto = htons(ETH_P_IP);
    ip->version = 4;
    ip->ihl = 5;
    ip->tot_len = htons(20 + 8 + UDP_PL_LEN);
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->saddr = inet_addr("10.99.0.2");
    ip->daddr = inet_addr("10.99.0.1");
    udp->source = htons(40000);
    udp->dest = htons(40001);
    udp->len = htons(8 + UDP_PL_LEN);
    /* capsule 初值：generation/ingress_bank 由 ingress root 的 BPF 填写 */
    c->nonce = 0x51d00000u | (__u32)seq;
    c->seq = (__u32)seq;
    c->transition_id = (__u32)(seq / BULK_FRAMES_PER_EPOCH);
    c->d_lo = 0xdead0000u ^ (__u32)seq;
    c->d_hi = 0x13370000u ^ (__u32)(seq << 3);
    c->reserved[1] = g;              /* requested_gen */
    /* wire 区保持全 0，由 egress program 写入；data 区不填 */
    (void)wire;
}

static int send_frames(const struct cfg *c, struct bpf_object *obj)
{
    int sock, gen_fd = bpf_object__find_map_fd_by_name(obj, "gen_map");
    unsigned char frame[FRAME_LEN];
    struct sockaddr_ll sa = {0};
    __u32 key = 0, g;
    long sent = 0;

    sock = socket(AF_PACKET, SOCK_RAW, 0);
    if (sock < 0) { perror("socket"); return -1; }
    sa.sll_family = AF_PACKET;
    sa.sll_ifindex = c->tx_idx;
    sa.sll_halen = 6;
    if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) { perror("bind"); close(sock); return -1; }

    for (long e = 0; e < c->epochs && sent < c->frames; e++) {
        for (int f = 0; f < BULK_FRAMES_PER_EPOCH && sent < c->frames; f++) {
            g = (f < BULK_FRAMES_PER_EPOCH / 2) ? 0u : 1u;
            if (bpf_map_update_elem(gen_fd, &key, &g, BPF_ANY) < 0) { perror("publish"); goto out; }
            fill_frame(frame, sent, g);
            if (write(sock, frame, FRAME_LEN) < 0) {
                if (errno != ENOBUFS) perror("write");
            } else {
                sent++;
            }
            usleep(1000);   /* 节流 1ms/帧：突发会溢出 veth 的 XDP rq 被静默丢弃（实测 RX=7/128） */
        }
    }
out:
    fprintf(stderr, "[sender] sent=%ld / %ld\n", sent, c->frames);
    close(sock);
    return (sent == c->frames) ? 0 : -1;
}

static int dump_stats(struct bpf_object *obj)
{
    int st_fd = bpf_object__find_map_fd_by_name(obj, "stats");
    int ncpus = libbpf_num_possible_cpus();
    __u64 *vals;
    __u32 keys[6] = {0, 1, 2, 3, 4, 5};
    const char *kn[6] = {"RX", "REDIRECT", "EGRESS_A", "EGRESS_B", "MUX", "BADPARSE"};
    if (ncpus <= 0) ncpus = MAX_CPU;
    vals = calloc(ncpus, sizeof(__u64));
    for (int i = 0; i < 6; i++) {
        __u64 sum = 0;
        int r;
        memset(vals, 0, sizeof(__u64) * ncpus);
        r = bpf_map_lookup_elem(st_fd, &keys[i], vals);
        if (r == 0) {
            for (int cpu = 0; cpu < ncpus; cpu++) sum += vals[cpu];
            fprintf(stderr, "[stats] %s=%llu (cpus=%d)\n", kn[i], (unsigned long long)sum, ncpus);
        } else {
            fprintf(stderr, "[stats] %s lookup失败 r=%d errno=%d\n", kn[i], r, errno);
        }
    }
    free(vals);
    return 0;
}

static FILE *g_trace_out;

static int on_evt(void *ctx, void *data, size_t sz)
{
    struct trace_evt *e = data;
    (void)ctx; (void)sz;
    fprintf(g_trace_out, "{\"ts\":%llu,\"kind\":%u,\"prog_id\":%u,\"cpu\":%u,\"ifindex\":%u}\n",
            (unsigned long long)e->ts, e->kind, e->prog_id, e->cpu, e->ifindex);
    return 0;
}

static int drain_trace(struct ring_buffer *rb, const char *path)
{
    g_trace_out = fopen(path, "w");
    if (!g_trace_out) { perror("trace out"); return -1; }
    ring_buffer__poll(rb, 0);   /* timeout 0：一次性清空已就绪样本 */
    fclose(g_trace_out);
    return 0;
}

static int do_run(const struct cfg *c)
{
    struct bpf_object *obj = NULL, *tobj = NULL;
    struct bpf_program *prog;
    struct bpf_devmap_val dv = {0};
    struct ring_buffer *rb = NULL;
    int a_fd, b_fd, m_fd, err = -1;
    __u32 k0 = 0, k1 = 1;
    int fds[3];
    const char *names[3] = {"BANK_A", "BANK_B", "MUX"};

    fprintf(stderr, "[phase] start\n");
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    obj = bpf_object__open_file("min_slice.bpf.o", NULL);
    fprintf(stderr, "[phase] open_file done, obj=%p\n", (void *)obj);
    if (!obj) { fprintf(stderr, "open min_slice: %s\n", strerror(errno)); return -1; }
    write_cfg(obj, "cfg_map", 0, (__u32)c->arm);
    write_cfg(obj, "cfg_map", 1, (__u32)c->wrong_capsule);
    write_cfg(obj, "cfg_map", 2, 0x00c0ffeeu);
    write_cfg(obj, "cfg_map", 3, c->wrong_mux ? 0xdeadbeefu : 0x00c0ffeeu);
    fprintf(stderr, "[phase] cfg written\n");
    if (bpf_object__load(obj)) { fprintf(stderr, "load min_slice: %s\n", strerror(errno)); goto out; }
    fprintf(stderr, "[phase] load done\n");

    a_fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "xdp_egress_bank_a"));
    b_fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "xdp_egress_bank_b"));
    m_fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "xdp_egress_common_mux"));

    dv.ifindex = c->out_idx;
    if (c->arm == 1)              dv.bpf_prog.fd = m_fd;
    else if (c->wrong_bank)       dv.bpf_prog.fd = b_fd;
    else                          dv.bpf_prog.fd = a_fd;
    if (bpf_map_update_elem(bpf_object__find_map_fd_by_name(obj, "devmap"), &k0, &dv, BPF_ANY) < 0) {
        fprintf(stderr, "devmap[0]: %s\n", strerror(errno)); goto out;
    }
    dv.ifindex = c->out_idx;
    if (c->arm == 1)              dv.bpf_prog.fd = m_fd;
    else if (c->wrong_bank)       dv.bpf_prog.fd = a_fd;
    else                          dv.bpf_prog.fd = b_fd;
    if (bpf_map_update_elem(bpf_object__find_map_fd_by_name(obj, "devmap"), &k1, &dv, BPF_ANY) < 0) {
        fprintf(stderr, "devmap[1]: %s\n", strerror(errno)); goto out;
    }

    prog = bpf_object__find_program_by_name(obj, "xdp_ingress_root");
    /* native 优先：devmap bq 的 flush 语义由驱动 poll 尾部 xdp_do_flush 保证；
     * generic 模式的 devmap flush 时机不确定（bq_xmit_all 可能不触发）。
     * 实际模式随 manifest 记录。 */
    err = bpf_xdp_attach(c->in_idx, bpf_program__fd(prog), 0, NULL);
    if (err == 0) {
        fprintf(stderr, "[attach] native XDP\n");
    } else {
        err = bpf_xdp_attach(c->in_idx, bpf_program__fd(prog), XDP_FLAGS_SKB_MODE, NULL);
        fprintf(stderr, "[attach] generic(SKB) XDP（native 失败回退）\n");
    }
    if (err) { fprintf(stderr, "xdp attach: %s\n", strerror(errno)); goto out; }

    tobj = bpf_object__open_file("trace_export.bpf.o", NULL);
    if (!tobj) { fprintf(stderr, "open trace_export: %s\n", strerror(errno)); goto out_detach; }
    if (bpf_object__load(tobj)) { fprintf(stderr, "load trace_export: %s\n", strerror(errno)); goto out_detach; }
    bpf_object__for_each_program(prog, tobj) {
        struct bpf_link *lnk = bpf_program__attach_trace(prog);
        if (!lnk) {
            fprintf(stderr, "attach trace prog %s: errno=%d %s\n",
                    bpf_program__name(prog), errno, strerror(errno));
            goto out_detach;
        }
    }
    rb = ring_buffer__new(bpf_object__find_map_fd_by_name(tobj, "rb"), on_evt, NULL, NULL);
    if (!rb) { fprintf(stderr, "ring_buffer__new 失败\n"); goto out_detach; }

    for (__u32 i = 0; i < 2; i++) {
        struct bpf_devmap_val dv_rb = {0};
        if (!bpf_map_lookup_elem(bpf_object__find_map_fd_by_name(obj, "devmap"), &i, &dv_rb))
            fprintf(stderr, "[readback] devmap[%u] ifindex=%d prog_id=%u\n",
                    i, dv_rb.ifindex, dv_rb.bpf_prog.id);
    }
    fds[0] = a_fd; fds[1] = b_fd; fds[2] = m_fd;
    for (int i = 0; i < 3; i++) {
        struct bpf_prog_info info = {};
        __u32 len = sizeof(info);
        if (!bpf_obj_get_info_by_fd(fds[i], &info, &len))
            fprintf(stderr, "[readback] %s prog_id=%u\n", names[i], info.id);
    }

    fprintf(stderr, "[ctl] 5s 后开始发送（编排脚本保证 receiver 先就绪）\n");
    sleep(5);

    dump_stats(obj);
    if (send_frames(c, obj) < 0)
        fprintf(stderr, "[ctl] 发送未完全成功，按契约记为异常 run\n");
    sleep(2);
    drain_trace(rb, "trace_events.jsonl");
    err = 0;
    if (c->hold > 0) {
        int sfd = bpf_object__find_map_fd_by_name(obj, "stats");
        int dfd = bpf_object__find_map_fd_by_name(obj, "devmap");
        int tfd = bpf_object__find_map_fd_by_name(tobj, "trace_cfg");
        if (sfd > 0) bpf_obj_pin(sfd, "/sys/fs/bpf/s1_stats");
        if (dfd > 0) bpf_obj_pin(dfd, "/sys/fs/bpf/s1_devmap");
        if (tfd > 0) bpf_obj_pin(tfd, "/sys/fs/bpf/s1_trace_cfg");
        fprintf(stderr, "[ctl] hold %ds，maps pinned 于 /sys/fs/bpf/s1_*\n", c->hold);
        sleep(c->hold);
    }

out_detach:
    bpf_xdp_detach(c->in_idx, XDP_FLAGS_MASK, NULL);
out:
    if (rb) ring_buffer__free(rb);
    bpf_object__close(tobj);
    bpf_object__close(obj);
    fprintf(stderr, "[ctl] teardown 完成（exit=%d）\n", err);
    return err;
}

int main(int argc, char **argv)
{
    struct cfg c = {0};
    c.frames = 2048; c.epochs = 32; c.arm = 0;

    if (argc < 3 || strcmp(argv[1], "run")) {
        fprintf(stderr, "usage: min_ctl run --tx IF --in IF --out IF --arm direct|mux "
                        "[--wrong-bank] [--wrong-mux] [--wrong-capsule] [--frames N] [--epochs N]\n");
        return 2;
    }
    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--tx")) c.tx_if = argv[++i];
        else if (!strcmp(argv[i], "--in")) c.in_if = argv[++i];
        else if (!strcmp(argv[i], "--out")) c.out_if = argv[++i];
        else if (!strcmp(argv[i], "--arm")) { c.arm = !strcmp(argv[++i], "mux"); }
        else if (!strcmp(argv[i], "--wrong-bank")) c.wrong_bank = 1;
        else if (!strcmp(argv[i], "--wrong-mux")) c.wrong_mux = 1;
        else if (!strcmp(argv[i], "--wrong-capsule")) c.wrong_capsule = 1;
        else if (!strcmp(argv[i], "--frames")) c.frames = atol(argv[++i]);
        else if (!strcmp(argv[i], "--epochs")) c.epochs = atol(argv[++i]);
        else if (!strcmp(argv[i], "--hold")) c.hold = atoi(argv[++i]);
        else { fprintf(stderr, "unknown arg %s\n", argv[i]); return 2; }
    }
    if (!c.tx_if || !c.in_if || !c.out_if) { fprintf(stderr, "missing interface\n"); return 2; }
    c.tx_idx = if_nametoindex(c.tx_if);
    c.in_idx = if_nametoindex(c.in_if);
    c.out_idx = if_nametoindex(c.out_if);
    if (!c.tx_idx || !c.in_idx || !c.out_idx) { fprintf(stderr, "if_nametoindex 失败\n"); return 2; }
    return do_run(&c) ? 1 : 0;
}
