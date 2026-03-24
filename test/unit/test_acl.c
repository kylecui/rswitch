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

struct test_xdp_md {
    __u32 data;
    __u32 data_meta;
    __u32 data_end;
    __u32 ingress_ifindex;
    __u32 rx_queue_index;
    __u32 egress_ifindex;
};


struct acl_config {
    __u8 default_action;
    __u8 enabled;
    __u8 log_drops;
    __u8 pad;
};

struct acl_5tuple_key {
    __u8 proto;
    __u8 pad[3];
    __u32 src_ip;
    __u32 dst_ip;
    __u16 sport;
    __u16 dport;
} __attribute__((packed));

struct acl_result {
    __u8 action;
    __u8 log_event;
    __u16 redirect_ifindex;
    __u32 stats_id;
} __attribute__((packed));

enum acl_action {
    ACL_ACTION_PASS = 0,
    ACL_ACTION_DROP = 1,
    ACL_ACTION_REDIRECT = 2,
};

enum {
    ACL_STAT_L1_5TUPLE_HIT = 0,
    ACL_STAT_L7_DEFAULT_PASS = 6,
    ACL_STAT_L7_DEFAULT_DROP = 7,
    ACL_STAT_TOTAL_DROPS = 8,
};

static const char *g_obj_path;

static int get_ncpus(void)
{
    long n = sysconf(_SC_NPROCESSORS_CONF);
    if (n < 1)
        return 1;
    return (int)n;
}

static int run_acl(struct bpf_program *prog, const void *pkt, __u32 pkt_len, __u32 *retval)
{
    unsigned char out_buf[256] = {0};
    LIBBPF_OPTS(bpf_test_run_opts, topts,
        .data_in = pkt,
        .data_size_in = pkt_len,
        .data_out = out_buf,
        .data_size_out = sizeof(out_buf),
        .repeat = 1,
    );
    int err = bpf_prog_test_run_opts(bpf_program__fd(prog), &topts);
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

static __u64 lookup_percpu_u64_sum(int map_fd, __u32 key)
{
    int ncpus = get_ncpus();
    __u64 *vals = calloc((size_t)ncpus, sizeof(__u64));
    __u64 sum = 0;
    int i;

    RS_ASSERT(vals != NULL);
    if (!vals)
        return 0;

    RS_ASSERT_OK(bpf_map_lookup_elem(map_fd, &key, vals));
    if (bpf_map_lookup_elem(map_fd, &key, vals) == 0) {
        for (i = 0; i < ncpus; i++)
            sum += vals[i];
    }

    free(vals);
    return sum;
}

static struct bpf_object *open_acl_obj(struct bpf_program **prog_out)
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

    *prog_out = bpf_object__find_program_by_name(obj, "acl_filter");
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

static void prep_ctx(struct rs_ctx *ctx,
                     __u32 saddr_host,
                     __u32 daddr_host,
                     __u16 sport_host,
                     __u16 dport_host)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->ifindex = 5;
    ctx->parsed = 1;
    ctx->layers.eth_proto = 0x0800;
    ctx->layers.ip_proto = 6;
    ctx->layers.saddr = htonl(saddr_host);
    ctx->layers.daddr = htonl(daddr_host);
    ctx->layers.sport = htons(sport_host);
    ctx->layers.dport = htons(dport_host);
}

RS_TEST(test_acl_disabled_bypass_path_tailcall_drop)
{
    struct bpf_object *obj;
    struct bpf_program *prog = NULL;
    struct bpf_map *cfg_map;
    struct acl_config cfg = {.enabled = 0, .default_action = ACL_ACTION_PASS, .log_drops = 0};
    struct test_pkt_ipv4_tcp pkt;
    __u32 key = 0;
    __u32 retval = 0;

    obj = open_acl_obj(&prog);
    if (!obj)
        return;

    cfg_map = bpf_object__find_map_by_name(obj, "acl_config_map");
    RS_ASSERT(cfg_map != NULL);
    if (!cfg_map) {
        bpf_object__close(obj);
        return;
    }

    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(cfg_map), &key, &cfg, BPF_ANY));
    build_ipv4_tcp_pkt(&pkt, 0x0a000001U, 0x0a000002U, 1111, 80, 0);
    RS_ASSERT_OK(run_acl(prog, &pkt, sizeof(pkt), &retval));
    RS_ASSERT_EQ(retval, XDP_DROP);

    bpf_object__close(obj);
}

RS_TEST(test_acl_default_pass_no_rules)
{
    struct bpf_object *obj;
    struct bpf_program *prog = NULL;
    struct bpf_map *cfg_map;
    struct bpf_map *ctx_map;
    struct bpf_map *stats_map;
    struct acl_config cfg = {.enabled = 1, .default_action = ACL_ACTION_PASS, .log_drops = 0};
    struct rs_ctx ctx;
    struct test_pkt_ipv4_tcp pkt;
    __u32 key = 0;
    __u32 retval = 0;

    obj = open_acl_obj(&prog);
    if (!obj)
        return;

    cfg_map = bpf_object__find_map_by_name(obj, "acl_config_map");
    ctx_map = bpf_object__find_map_by_name(obj, "rs_ctx_map");
    stats_map = bpf_object__find_map_by_name(obj, "acl_stats_map");
    RS_ASSERT(cfg_map != NULL);
    RS_ASSERT(ctx_map != NULL);
    RS_ASSERT(stats_map != NULL);
    if (!cfg_map || !ctx_map || !stats_map) {
        bpf_object__close(obj);
        return;
    }

    prep_ctx(&ctx, 0x0a010101U, 0x0a010102U, 1234, 443);
    RS_ASSERT_OK(update_percpu_rs_ctx(bpf_map__fd(ctx_map), &ctx));
    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(cfg_map), &key, &cfg, BPF_ANY));

    build_ipv4_tcp_pkt(&pkt, 0x0a010101U, 0x0a010102U, 1234, 443, 0);
    RS_ASSERT_OK(run_acl(prog, &pkt, sizeof(pkt), &retval));
    RS_ASSERT_EQ(retval, XDP_DROP);
    RS_ASSERT_EQ((long long)lookup_percpu_u64_sum(bpf_map__fd(stats_map), ACL_STAT_L7_DEFAULT_PASS), 1);

    bpf_object__close(obj);
}

RS_TEST(test_acl_5tuple_drop_rule_hit)
{
    struct bpf_object *obj;
    struct bpf_program *prog = NULL;
    struct bpf_map *cfg_map;
    struct bpf_map *ctx_map;
    struct bpf_map *tuple_map;
    struct bpf_map *stats_map;
    struct acl_config cfg = {.enabled = 1, .default_action = ACL_ACTION_PASS, .log_drops = 0};
    struct acl_5tuple_key key_5t;
    struct acl_result result;
    struct rs_ctx ctx;
    struct test_pkt_ipv4_tcp pkt;
    __u32 key = 0;
    __u32 retval = 0;

    obj = open_acl_obj(&prog);
    if (!obj)
        return;

    cfg_map = bpf_object__find_map_by_name(obj, "acl_config_map");
    ctx_map = bpf_object__find_map_by_name(obj, "rs_ctx_map");
    tuple_map = bpf_object__find_map_by_name(obj, "acl_5tuple_map");
    stats_map = bpf_object__find_map_by_name(obj, "acl_stats_map");
    RS_ASSERT(cfg_map != NULL);
    RS_ASSERT(ctx_map != NULL);
    RS_ASSERT(tuple_map != NULL);
    RS_ASSERT(stats_map != NULL);
    if (!cfg_map || !ctx_map || !tuple_map || !stats_map) {
        bpf_object__close(obj);
        return;
    }

    prep_ctx(&ctx, 0x0a020201U, 0x0a020202U, 5555, 8080);
    RS_ASSERT_OK(update_percpu_rs_ctx(bpf_map__fd(ctx_map), &ctx));
    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(cfg_map), &key, &cfg, BPF_ANY));

    memset(&key_5t, 0, sizeof(key_5t));
    key_5t.proto = 6;
    key_5t.src_ip = htonl(0x0a020201U);
    key_5t.dst_ip = htonl(0x0a020202U);
    key_5t.sport = htons(5555);
    key_5t.dport = htons(8080);

    memset(&result, 0, sizeof(result));
    result.action = ACL_ACTION_DROP;
    result.stats_id = ACL_STAT_L1_5TUPLE_HIT;
    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(tuple_map), &key_5t, &result, BPF_ANY));

    build_ipv4_tcp_pkt(&pkt, 0x0a020201U, 0x0a020202U, 5555, 8080, 0);
    RS_ASSERT_OK(run_acl(prog, &pkt, sizeof(pkt), &retval));
    RS_ASSERT_EQ(retval, XDP_DROP);
    RS_ASSERT_EQ((long long)lookup_percpu_u64_sum(bpf_map__fd(stats_map), ACL_STAT_L1_5TUPLE_HIT), 1);
    RS_ASSERT_EQ((long long)lookup_percpu_u64_sum(bpf_map__fd(stats_map), ACL_STAT_TOTAL_DROPS), 1);

    bpf_object__close(obj);
}

RS_TEST(test_acl_default_drop)
{
    struct bpf_object *obj;
    struct bpf_program *prog = NULL;
    struct bpf_map *cfg_map;
    struct bpf_map *ctx_map;
    struct bpf_map *stats_map;
    struct acl_config cfg = {.enabled = 1, .default_action = ACL_ACTION_DROP, .log_drops = 0};
    struct rs_ctx ctx;
    struct test_pkt_ipv4_tcp pkt;
    __u32 key = 0;
    __u32 retval = 0;

    obj = open_acl_obj(&prog);
    if (!obj)
        return;

    cfg_map = bpf_object__find_map_by_name(obj, "acl_config_map");
    ctx_map = bpf_object__find_map_by_name(obj, "rs_ctx_map");
    stats_map = bpf_object__find_map_by_name(obj, "acl_stats_map");
    RS_ASSERT(cfg_map != NULL);
    RS_ASSERT(ctx_map != NULL);
    RS_ASSERT(stats_map != NULL);
    if (!cfg_map || !ctx_map || !stats_map) {
        bpf_object__close(obj);
        return;
    }

    prep_ctx(&ctx, 0x0a030301U, 0x0a030302U, 2222, 53);
    RS_ASSERT_OK(update_percpu_rs_ctx(bpf_map__fd(ctx_map), &ctx));
    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(cfg_map), &key, &cfg, BPF_ANY));

    build_ipv4_tcp_pkt(&pkt, 0x0a030301U, 0x0a030302U, 2222, 53, 0);
    RS_ASSERT_OK(run_acl(prog, &pkt, sizeof(pkt), &retval));
    RS_ASSERT_EQ(retval, XDP_DROP);
    RS_ASSERT_EQ((long long)lookup_percpu_u64_sum(bpf_map__fd(stats_map), ACL_STAT_L7_DEFAULT_DROP), 1);

    bpf_object__close(obj);
}

RS_TEST_SUITE_BEGIN()
    ;
    if (argc < 2) {
        printf("Usage: %s <path_to_acl.bpf.o>\n", argv[0]);
        return 1;
    }

    g_obj_path = argv[1];
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    RS_RUN_TEST(test_acl_disabled_bypass_path_tailcall_drop);
    RS_RUN_TEST(test_acl_default_pass_no_rules);
    RS_RUN_TEST(test_acl_5tuple_drop_rule_hit);
    RS_RUN_TEST(test_acl_default_drop);

RS_TEST_SUITE_END()
