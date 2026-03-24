#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <linux/bpf.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "../../user/common/rs_log.h"

#include "rs_test.h"
#include "test_packets.h"

#ifndef ETH_P_ARP
#define ETH_P_ARP 0x0806
#endif

struct test_xdp_md {
    __u32 data;
    __u32 data_meta;
    __u32 data_end;
    __u32 ingress_ifindex;
    __u32 rx_queue_index;
    __u32 egress_ifindex;
};


struct arp_entry {
    __u8 mac[6];
    __u16 pad;
    __u32 ifindex;
    __u64 timestamp;
};

struct iface_config {
    __u8 mac[6];
    __u16 pad;
    __u8 is_router;
    __u8 pad2[3];
};

struct arp_learn_stats {
    __u64 arp_requests_seen;
    __u64 arp_replies_seen;
    __u64 entries_learned;
    __u64 entries_updated;
};

static const char *g_obj_path;

static int get_ncpus(void)
{
    long n = sysconf(_SC_NPROCESSORS_CONF);
    if (n < 1)
        return 1;
    return (int)n;
}

static int run_arp_learn(struct bpf_program *prog, const void *pkt, __u32 pkt_len, __u32 *retval)
{
    int saved_errno = errno;
    unsigned char out_buf[256] = {0};
    LIBBPF_OPTS(bpf_test_run_opts, topts,
        .data_in = pkt,
        .data_size_in = pkt_len,
        .data_out = out_buf,
        .data_size_out = sizeof(out_buf),
        .repeat = 1,
    );
    int err = bpf_prog_test_run_opts(bpf_program__fd(prog), &topts);
    (void)saved_errno;
    if (retval)
        *retval = topts.retval;
    return err;
}

static int update_percpu_rs_ctx(int map_fd, const struct rs_ctx *ctx)
{
    int ncpus = get_ncpus();
    size_t sz = (size_t)ncpus * sizeof(struct rs_ctx);
    struct rs_ctx *values = calloc(1, sz);
    __u32 key = 0;
    int i;
    int ret;

    if (!values)
        return -ENOMEM;

    for (i = 0; i < ncpus; i++)
        values[i] = *ctx;

    ret = bpf_map_update_elem(map_fd, &key, values, BPF_ANY);
    free(values);
    return ret;
}

static struct bpf_object *open_arp_learn_obj(struct bpf_program **prog_out)
{
    struct bpf_object *obj = bpf_object__open_file(g_obj_path, NULL);
    RS_ASSERT(obj != NULL);
    if (!obj)
        return NULL;

    if (bpf_object__load(obj) != 0) {
        RS_ASSERT_OK(-1);
        bpf_object__close(obj);
        return NULL;
    }

    *prog_out = bpf_object__find_program_by_name(obj, "arp_learn_ingress");
    RS_ASSERT(*prog_out != NULL);
    if (!*prog_out) {
        bpf_object__close(obj);
        return NULL;
    }

    RS_ASSERT_NEQ(bpf_program__fd(*prog_out), -1);
    if (bpf_program__fd(*prog_out) < 0) {
        bpf_object__close(obj);
        return NULL;
    }

    return obj;
}

static void prep_ctx(struct rs_ctx *ctx)
{
    (void)sizeof(enum rs_log_level);
    memset(ctx, 0, sizeof(*ctx));
    ctx->ifindex = 5;
    ctx->parsed = 1;
    ctx->layers.eth_proto = ETH_P_ARP;
    ctx->layers.l2_offset = 0;
    ctx->layers.l3_offset = 14;
}

static void read_arp_stats_sum(int map_fd, struct arp_learn_stats *out)
{
    int ncpus = get_ncpus();
    struct arp_learn_stats *vals;
    __u32 key = 0;
    int i;

    memset(out, 0, sizeof(*out));
    vals = calloc((size_t)ncpus, sizeof(*vals));
    RS_ASSERT(vals != NULL);
    if (!vals)
        return;

    RS_ASSERT_OK(bpf_map_lookup_elem(map_fd, &key, vals));
    if (bpf_map_lookup_elem(map_fd, &key, vals) == 0) {
        for (i = 0; i < ncpus; i++) {
            out->arp_requests_seen += vals[i].arp_requests_seen;
            out->arp_replies_seen += vals[i].arp_replies_seen;
            out->entries_learned += vals[i].entries_learned;
            out->entries_updated += vals[i].entries_updated;
        }
    }

    free(vals);
}

RS_TEST(test_arp_learn_non_arp_passthrough)
{
    struct bpf_object *obj;
    struct bpf_program *prog = NULL;
    struct bpf_map *ctx_map;
    struct rs_ctx ctx;
    struct test_pkt_ipv4_tcp pkt;
    __u32 retval = 0;

    obj = open_arp_learn_obj(&prog);
    if (!obj)
        return;

    ctx_map = bpf_object__find_map_by_name(obj, "rs_ctx_map");
    RS_ASSERT(ctx_map != NULL);
    if (!ctx_map) {
        bpf_object__close(obj);
        return;
    }

    prep_ctx(&ctx);
    ctx.layers.eth_proto = 0x0800;
    RS_ASSERT_OK(update_percpu_rs_ctx(bpf_map__fd(ctx_map), &ctx));

    build_ipv4_tcp_pkt(&pkt, 0x0a000001U, 0x0a000002U, 12345, 80, 0);
    RS_ASSERT_OK(run_arp_learn(prog, &pkt, sizeof(pkt), &retval));
    RS_ASSERT_EQ(retval, XDP_PASS);

    bpf_object__close(obj);
}

RS_TEST(test_arp_learn_request_learns_sender)
{
    struct bpf_object *obj;
    struct bpf_program *prog = NULL;
    struct bpf_map *ctx_map;
    struct bpf_map *arp_tbl_map;
    struct bpf_map *stats_map;
    struct rs_ctx ctx;
    struct test_pkt_arp pkt;
    struct arp_entry entry;
    struct arp_learn_stats stats;
    const __u8 sender_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01};
    __be32 key = htonl(0x0a010101U);
    __u32 retval = 0;

    obj = open_arp_learn_obj(&prog);
    if (!obj)
        return;

    ctx_map = bpf_object__find_map_by_name(obj, "rs_ctx_map");
    arp_tbl_map = bpf_object__find_map_by_name(obj, "arp_tbl");
    stats_map = bpf_object__find_map_by_name(obj, "arp_learn_stats_map");
    RS_ASSERT(ctx_map != NULL);
    RS_ASSERT(arp_tbl_map != NULL);
    RS_ASSERT(stats_map != NULL);
    if (!ctx_map || !arp_tbl_map || !stats_map) {
        bpf_object__close(obj);
        return;
    }

    prep_ctx(&ctx);
    ctx.layers.eth_proto = 0x0806;
    ctx.layers.l3_offset = 14;
    RS_ASSERT_OK(update_percpu_rs_ctx(bpf_map__fd(ctx_map), &ctx));

    build_arp_pkt(&pkt, 0x0a010101U, 0x0a010102U);
    memcpy(pkt.eth.src, sender_mac, sizeof(sender_mac));
    memcpy(pkt.arp.sha, sender_mac, sizeof(sender_mac));

    RS_ASSERT_OK(run_arp_learn(prog, &pkt, sizeof(pkt), &retval));
    RS_ASSERT_EQ(retval, XDP_PASS);

    memset(&entry, 0, sizeof(entry));
    RS_ASSERT_OK(bpf_map_lookup_elem(bpf_map__fd(arp_tbl_map), &key, &entry));
    RS_ASSERT_EQ(memcmp(entry.mac, sender_mac, sizeof(sender_mac)), 0);

    read_arp_stats_sum(bpf_map__fd(stats_map), &stats);
    RS_ASSERT(stats.arp_requests_seen >= 1);

    bpf_object__close(obj);
}

RS_TEST(test_arp_learn_reply_learns_sender)
{
    struct bpf_object *obj;
    struct bpf_program *prog = NULL;
    struct bpf_map *ctx_map;
    struct bpf_map *arp_tbl_map;
    struct bpf_map *stats_map;
    struct rs_ctx ctx;
    struct test_pkt_arp pkt;
    struct arp_entry entry;
    struct arp_learn_stats stats;
    const __u8 sender_mac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x02};
    __be32 key = htonl(0x0a020201U);
    __u32 retval = 0;

    obj = open_arp_learn_obj(&prog);
    if (!obj)
        return;

    ctx_map = bpf_object__find_map_by_name(obj, "rs_ctx_map");
    arp_tbl_map = bpf_object__find_map_by_name(obj, "arp_tbl");
    stats_map = bpf_object__find_map_by_name(obj, "arp_learn_stats_map");
    RS_ASSERT(ctx_map != NULL);
    RS_ASSERT(arp_tbl_map != NULL);
    RS_ASSERT(stats_map != NULL);
    if (!ctx_map || !arp_tbl_map || !stats_map) {
        bpf_object__close(obj);
        return;
    }

    prep_ctx(&ctx);
    ctx.layers.eth_proto = 0x0806;
    ctx.layers.l3_offset = 14;
    RS_ASSERT_OK(update_percpu_rs_ctx(bpf_map__fd(ctx_map), &ctx));

    build_arp_pkt(&pkt, 0x0a020201U, 0x0a020202U);
    memcpy(pkt.eth.src, sender_mac, sizeof(sender_mac));
    memcpy(pkt.arp.sha, sender_mac, sizeof(sender_mac));
    pkt.arp.oper = htons(2);

    RS_ASSERT_OK(run_arp_learn(prog, &pkt, sizeof(pkt), &retval));
    RS_ASSERT_EQ(retval, XDP_PASS);

    memset(&entry, 0, sizeof(entry));
    RS_ASSERT_OK(bpf_map_lookup_elem(bpf_map__fd(arp_tbl_map), &key, &entry));
    RS_ASSERT_EQ(memcmp(entry.mac, sender_mac, sizeof(sender_mac)), 0);

    read_arp_stats_sum(bpf_map__fd(stats_map), &stats);
    RS_ASSERT(stats.arp_replies_seen >= 1);

    bpf_object__close(obj);
}

RS_TEST_SUITE_BEGIN()
    ;
    if (argc < 2) {
        printf("Usage: %s <path_to_arp_learn.bpf.o>\n", argv[0]);
        return 1;
    }
    g_obj_path = argv[1];
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    RS_RUN_TEST(test_arp_learn_non_arp_passthrough);
    RS_RUN_TEST(test_arp_learn_request_learns_sender);
    RS_RUN_TEST(test_arp_learn_reply_learns_sender);
RS_TEST_SUITE_END()
