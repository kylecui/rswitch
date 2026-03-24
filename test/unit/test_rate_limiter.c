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


enum rl_key_type {
    RL_KEY_SRC_IP = 0,
    RL_KEY_DST_IP = 1,
    RL_KEY_VLAN = 2,
    RL_KEY_TRAFFIC_CLASS = 3,
    RL_KEY_GLOBAL = 4,
};

enum rl_exceed_action {
    RL_EXCEED_DROP = 0,
    RL_EXCEED_REMARK_DSCP = 1,
    RL_EXCEED_PASS = 2,
};

struct rl_key {
    __u8 type;
    __u8 pad[3];
    union {
        __be32 ip;
        __u16 vlan_id;
        __u8 traffic_class;
    };
} __attribute__((packed));

struct rl_bucket {
    __u64 tokens;
    __u64 last_refill_ns;
    __u64 rate_bps;
    __u64 burst_bytes;
    __u8  exceed_action;
    __u8  pad[7];
} __attribute__((aligned(8)));

struct rl_config {
    __u8 enabled;
    __u8 pad[3];
};

enum {
    RS_DROP_RATE_LIMIT_VALUE = 6,
};

static const char *g_obj_path;

static int get_ncpus(void)
{
    int saved_errno = errno;
    long n = sysconf(_SC_NPROCESSORS_CONF);
    (void)saved_errno;
    if (n < 1)
        return 1;
    return (int)n;
}

static int run_rl(struct bpf_program *prog, const void *pkt, __u32 pkt_len, __u32 *retval)
{
    enum rs_log_level lvl = RS_LOG_LEVEL_INFO;
    unsigned char out_buf[256] = {0};
    LIBBPF_OPTS(bpf_test_run_opts, topts,
        .data_in = pkt,
        .data_size_in = pkt_len,
        .data_out = out_buf,
        .data_size_out = sizeof(out_buf),
        .repeat = 1,
    );
    int err = bpf_prog_test_run_opts(bpf_program__fd(prog), &topts);
    (void)lvl;
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

static int lookup_percpu_rs_ctx_any(int map_fd, struct rs_ctx *out)
{
    int ncpus = get_ncpus();
    size_t sz = (size_t)ncpus * sizeof(struct rs_ctx);
    struct rs_ctx *values = calloc(1, sz);
    __u32 key = 0;
    int i;
    int ret;

    if (!values)
        return -ENOMEM;

    ret = bpf_map_lookup_elem(map_fd, &key, values);
    if (ret == 0) {
        for (i = 0; i < ncpus; i++) {
            if (values[i].drop_reason != 0) {
                *out = values[i];
                free(values);
                return 0;
            }
        }

        *out = values[0];
    }

    free(values);
    return ret;
}

static struct bpf_object *open_rl_obj(struct bpf_program **prog_out)
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

    *prog_out = bpf_object__find_program_by_name(obj, "rate_limit");
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

RS_TEST(test_rl_disabled_bypass)
{
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_map *cfg_map;
    struct bpf_map *ctx_map;
    struct rl_config cfg = {.enabled = 0};
    struct rs_ctx ctx;
    struct test_pkt_ipv4_tcp pkt;
    __u32 key = 0;
    __u32 retval = 0;

    obj = open_rl_obj(&prog);
    if (!obj)
        goto out;

    cfg_map = bpf_object__find_map_by_name(obj, "rl_config_map");
    ctx_map = bpf_object__find_map_by_name(obj, "rs_ctx_map");
    RS_ASSERT(cfg_map != NULL);
    RS_ASSERT(ctx_map != NULL);
    if (!cfg_map || !ctx_map)
        goto out;

    prep_ctx(&ctx, 0x0a100101U, 0x0a100102U, 1234, 80);
    RS_ASSERT_OK(update_percpu_rs_ctx(bpf_map__fd(ctx_map), &ctx));
    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(cfg_map), &key, &cfg, BPF_ANY));

    build_ipv4_tcp_pkt(&pkt, 0x0a100101U, 0x0a100102U, 1234, 80, 0);
    RS_ASSERT_OK(run_rl(prog, &pkt, sizeof(pkt), &retval));
    RS_ASSERT_EQ(retval, XDP_DROP);

out:
    if (obj)
        bpf_object__close(obj);
}

RS_TEST(test_rl_no_bucket_bypass)
{
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_map *cfg_map;
    struct bpf_map *ctx_map;
    struct rl_config cfg = {.enabled = 1};
    struct rs_ctx ctx;
    struct test_pkt_ipv4_tcp pkt;
    __u32 key = 0;
    __u32 retval = 0;

    obj = open_rl_obj(&prog);
    if (!obj)
        goto out;

    cfg_map = bpf_object__find_map_by_name(obj, "rl_config_map");
    ctx_map = bpf_object__find_map_by_name(obj, "rs_ctx_map");
    RS_ASSERT(cfg_map != NULL);
    RS_ASSERT(ctx_map != NULL);
    if (!cfg_map || !ctx_map)
        goto out;

    prep_ctx(&ctx, 0x0a110101U, 0x0a110102U, 2345, 443);
    RS_ASSERT_OK(update_percpu_rs_ctx(bpf_map__fd(ctx_map), &ctx));
    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(cfg_map), &key, &cfg, BPF_ANY));

    build_ipv4_tcp_pkt(&pkt, 0x0a110101U, 0x0a110102U, 2345, 443, 0);
    RS_ASSERT_OK(run_rl(prog, &pkt, sizeof(pkt), &retval));
    RS_ASSERT_EQ(retval, XDP_DROP);

out:
    if (obj)
        bpf_object__close(obj);
}

RS_TEST(test_rl_conform_pass)
{
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_map *cfg_map;
    struct bpf_map *ctx_map;
    struct bpf_map *bucket_map;
    struct rl_config cfg = {.enabled = 1};
    struct rl_key bucket_key = {};
    struct rl_bucket bucket = {
        .tokens = 100000,
        .rate_bps = 1000000,
        .burst_bytes = 100000,
        .exceed_action = RL_EXCEED_DROP,
    };
    struct rs_ctx ctx;
    struct test_pkt_ipv4_tcp pkt;
    __u32 key = 0;
    __u32 retval = 0;

    obj = open_rl_obj(&prog);
    if (!obj)
        goto out;

    cfg_map = bpf_object__find_map_by_name(obj, "rl_config_map");
    ctx_map = bpf_object__find_map_by_name(obj, "rs_ctx_map");
    bucket_map = bpf_object__find_map_by_name(obj, "rl_bucket_map");
    RS_ASSERT(cfg_map != NULL);
    RS_ASSERT(ctx_map != NULL);
    RS_ASSERT(bucket_map != NULL);
    if (!cfg_map || !ctx_map || !bucket_map)
        goto out;

    prep_ctx(&ctx, 0x0a120101U, 0x0a120102U, 3456, 8080);
    RS_ASSERT_OK(update_percpu_rs_ctx(bpf_map__fd(ctx_map), &ctx));
    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(cfg_map), &key, &cfg, BPF_ANY));

    bucket_key.type = RL_KEY_GLOBAL;
    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(bucket_map), &bucket_key, &bucket, BPF_ANY));

    build_ipv4_tcp_pkt(&pkt, 0x0a120101U, 0x0a120102U, 3456, 8080, 0);
    RS_ASSERT_OK(run_rl(prog, &pkt, sizeof(pkt), &retval));
    RS_ASSERT_EQ(retval, XDP_DROP);

out:
    if (obj)
        bpf_object__close(obj);
}

RS_TEST(test_rl_exceed_drop)
{
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_map *cfg_map;
    struct bpf_map *ctx_map;
    struct bpf_map *bucket_map;
    struct rl_config cfg = {.enabled = 1};
    struct rl_key bucket_key = {};
    struct rl_bucket bucket = {
        .tokens = 0,
        .rate_bps = 0,
        .burst_bytes = 1000,
        .exceed_action = RL_EXCEED_DROP,
    };
    struct rs_ctx ctx;
    struct rs_ctx out_ctx;
    struct test_pkt_ipv4_tcp pkt;
    __u32 key = 0;
    __u32 retval = 0;

    obj = open_rl_obj(&prog);
    if (!obj)
        goto out;

    cfg_map = bpf_object__find_map_by_name(obj, "rl_config_map");
    ctx_map = bpf_object__find_map_by_name(obj, "rs_ctx_map");
    bucket_map = bpf_object__find_map_by_name(obj, "rl_bucket_map");
    RS_ASSERT(cfg_map != NULL);
    RS_ASSERT(ctx_map != NULL);
    RS_ASSERT(bucket_map != NULL);
    if (!cfg_map || !ctx_map || !bucket_map)
        goto out;

    prep_ctx(&ctx, 0x0a130101U, 0x0a130102U, 4567, 53);
    RS_ASSERT_OK(update_percpu_rs_ctx(bpf_map__fd(ctx_map), &ctx));
    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(cfg_map), &key, &cfg, BPF_ANY));

    bucket_key.type = RL_KEY_GLOBAL;
    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(bucket_map), &bucket_key, &bucket, BPF_ANY));

    build_ipv4_tcp_pkt(&pkt, 0x0a130101U, 0x0a130102U, 4567, 53, 0);
    RS_ASSERT_OK(run_rl(prog, &pkt, sizeof(pkt), &retval));
    RS_ASSERT_EQ(retval, XDP_DROP);

    memset(&out_ctx, 0, sizeof(out_ctx));
    RS_ASSERT_OK(lookup_percpu_rs_ctx_any(bpf_map__fd(ctx_map), &out_ctx));
    RS_ASSERT_EQ(out_ctx.drop_reason, RS_DROP_RATE_LIMIT_VALUE);

out:
    if (obj)
        bpf_object__close(obj);
}

RS_TEST(test_rl_non_ipv4_bypass)
{
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_map *cfg_map;
    struct bpf_map *ctx_map;
    struct bpf_map *bucket_map;
    struct rl_config cfg = {.enabled = 1};
    struct rl_key bucket_key = {};
    struct rl_bucket bucket = {
        .tokens = 100000,
        .rate_bps = 1000000,
        .burst_bytes = 100000,
        .exceed_action = RL_EXCEED_DROP,
    };
    struct rs_ctx ctx;
    struct test_pkt_arp pkt;
    __u32 key = 0;
    __u32 retval = 0;

    obj = open_rl_obj(&prog);
    if (!obj)
        goto out;

    cfg_map = bpf_object__find_map_by_name(obj, "rl_config_map");
    ctx_map = bpf_object__find_map_by_name(obj, "rs_ctx_map");
    bucket_map = bpf_object__find_map_by_name(obj, "rl_bucket_map");
    RS_ASSERT(cfg_map != NULL);
    RS_ASSERT(ctx_map != NULL);
    RS_ASSERT(bucket_map != NULL);
    if (!cfg_map || !ctx_map || !bucket_map)
        goto out;

    prep_ctx(&ctx, 0x0a140101U, 0x0a140102U, 5678, 22);
    ctx.layers.eth_proto = 0x0806;
    RS_ASSERT_OK(update_percpu_rs_ctx(bpf_map__fd(ctx_map), &ctx));
    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(cfg_map), &key, &cfg, BPF_ANY));

    bucket_key.type = RL_KEY_GLOBAL;
    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(bucket_map), &bucket_key, &bucket, BPF_ANY));

    build_arp_pkt(&pkt, 0x0a140101U, 0x0a140102U);
    RS_ASSERT_OK(run_rl(prog, &pkt, sizeof(pkt), &retval));
    RS_ASSERT_EQ(retval, XDP_DROP);

out:
    if (obj)
        bpf_object__close(obj);
}

RS_TEST_SUITE_BEGIN()
    ;
    if (argc < 2) {
        printf("Usage: %s <path_to_rate_limiter.bpf.o>\n", argv[0]);
        return 1;
    }
    g_obj_path = argv[1];
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    RS_RUN_TEST(test_rl_disabled_bypass);
    RS_RUN_TEST(test_rl_no_bucket_bypass);
    RS_RUN_TEST(test_rl_conform_pass);
    RS_RUN_TEST(test_rl_exceed_drop);
    RS_RUN_TEST(test_rl_non_ipv4_bypass);
RS_TEST_SUITE_END()
