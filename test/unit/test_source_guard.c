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


struct sg_key {
    __be32 ip_addr;
} __attribute__((packed));

struct sg_entry {
    __u8 mac[6];
    __u16 pad;
    __u32 ifindex;
    __u8 type;
    __u8 pad2[3];
    __u64 last_seen_ns;
    __u64 violations;
} __attribute__((aligned(8)));

struct sg_config {
    __u8 enabled;
    __u8 strict_mode;
    __u8 check_mac;
    __u8 check_port;
} __attribute__((aligned(8)));

enum sg_stat_type {
    SG_STAT_TOTAL = 0,
    SG_STAT_PASSED = 1,
    SG_STAT_MAC_VIOLATIONS = 2,
    SG_STAT_PORT_VIOLATIONS = 3,
    SG_STAT_MAX = 4,
};

static const char *g_obj_path;

static int get_ncpus(void)
{
    long n = sysconf(_SC_NPROCESSORS_CONF);
    if (n < 1)
        return 1;
    return (int)n;
}

static int run_source_guard(struct bpf_program *prog, const void *pkt, __u32 pkt_len, __u32 *retval)
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

static struct bpf_object *open_sg_obj(struct bpf_program **prog_out)
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

    *prog_out = bpf_object__find_program_by_name(obj, "source_guard");
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
    ctx->layers.eth_proto = 0x0800;
    ctx->layers.l2_offset = 0;
}

RS_TEST(test_sg_disabled_bypass)
{
    struct bpf_object *obj;
    struct bpf_program *prog = NULL;
    struct bpf_map *cfg_map;
    struct bpf_map *ctx_map;
    struct sg_config cfg = {.enabled = 0, .strict_mode = 0, .check_mac = 0, .check_port = 0};
    struct rs_ctx ctx;
    struct test_pkt_ipv4_tcp pkt;
    __u32 key = 0;
    __u32 retval = 0;

    obj = open_sg_obj(&prog);
    if (!obj)
        return;

    cfg_map = bpf_object__find_map_by_name(obj, "sg_config_map");
    ctx_map = bpf_object__find_map_by_name(obj, "rs_ctx_map");
    RS_ASSERT(cfg_map != NULL);
    RS_ASSERT(ctx_map != NULL);
    if (!cfg_map || !ctx_map) {
        bpf_object__close(obj);
        return;
    }

    prep_ctx(&ctx);
    RS_ASSERT_OK(update_percpu_rs_ctx(bpf_map__fd(ctx_map), &ctx));
    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(cfg_map), &key, &cfg, BPF_ANY));

    build_ipv4_tcp_pkt(&pkt, 0x0a000001U, 0x0a000002U, 1111, 80, 0);
    RS_ASSERT_OK(run_source_guard(prog, &pkt, sizeof(pkt), &retval));
    RS_ASSERT_EQ(retval, XDP_DROP);

    bpf_object__close(obj);
}

RS_TEST(test_sg_port_not_enabled_bypass)
{
    struct bpf_object *obj;
    struct bpf_program *prog = NULL;
    struct bpf_map *cfg_map;
    struct bpf_map *ctx_map;
    struct sg_config cfg = {.enabled = 1, .strict_mode = 1, .check_mac = 1, .check_port = 1};
    struct rs_ctx ctx;
    struct test_pkt_ipv4_tcp pkt;
    __u32 key = 0;
    __u32 retval = 0;

    obj = open_sg_obj(&prog);
    if (!obj)
        return;

    cfg_map = bpf_object__find_map_by_name(obj, "sg_config_map");
    ctx_map = bpf_object__find_map_by_name(obj, "rs_ctx_map");
    RS_ASSERT(cfg_map != NULL);
    RS_ASSERT(ctx_map != NULL);
    if (!cfg_map || !ctx_map) {
        bpf_object__close(obj);
        return;
    }

    prep_ctx(&ctx);
    RS_ASSERT_OK(update_percpu_rs_ctx(bpf_map__fd(ctx_map), &ctx));
    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(cfg_map), &key, &cfg, BPF_ANY));

    build_ipv4_tcp_pkt(&pkt, 0x0a010101U, 0x0a010102U, 1234, 443, 0);
    RS_ASSERT_OK(run_source_guard(prog, &pkt, sizeof(pkt), &retval));
    RS_ASSERT_EQ(retval, XDP_DROP);

    bpf_object__close(obj);
}

RS_TEST(test_sg_binding_match_passes)
{
    struct bpf_object *obj;
    struct bpf_program *prog = NULL;
    struct bpf_map *cfg_map;
    struct bpf_map *ctx_map;
    struct bpf_map *binding_map;
    struct bpf_map *stats_map;
    struct bpf_map *port_enable_map;
    struct sg_config cfg = {.enabled = 1, .strict_mode = 1, .check_mac = 1, .check_port = 1};
    struct sg_key sgk;
    struct sg_entry sge;
    struct rs_ctx ctx;
    struct test_pkt_ipv4_tcp pkt;
    static const __u8 src_mac[6] = {0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee};
    __u32 cfg_key = 0;
    __u32 ifindex = 5;
    __u8 enabled = 1;
    __u32 src_ip = 0x0a020201U;
    __u32 retval = 0;

    obj = open_sg_obj(&prog);
    if (!obj)
        return;

    cfg_map = bpf_object__find_map_by_name(obj, "sg_config_map");
    ctx_map = bpf_object__find_map_by_name(obj, "rs_ctx_map");
    binding_map = bpf_object__find_map_by_name(obj, "sg_binding_map");
    stats_map = bpf_object__find_map_by_name(obj, "sg_stats_map");
    port_enable_map = bpf_object__find_map_by_name(obj, "sg_port_enable_map");
    RS_ASSERT(cfg_map != NULL);
    RS_ASSERT(ctx_map != NULL);
    RS_ASSERT(binding_map != NULL);
    RS_ASSERT(stats_map != NULL);
    RS_ASSERT(port_enable_map != NULL);
    if (!cfg_map || !ctx_map || !binding_map || !stats_map || !port_enable_map) {
        bpf_object__close(obj);
        return;
    }

    prep_ctx(&ctx);
    ctx.layers.saddr = htonl(src_ip);
    RS_ASSERT_OK(update_percpu_rs_ctx(bpf_map__fd(ctx_map), &ctx));
    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(cfg_map), &cfg_key, &cfg, BPF_ANY));
    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(port_enable_map), &ifindex, &enabled, BPF_ANY));

    build_ipv4_tcp_pkt(&pkt, src_ip, 0x0a020202U, 5555, 8080, 0);
    memcpy(pkt.eth.src, src_mac, sizeof(src_mac));

    memset(&sgk, 0, sizeof(sgk));
    sgk.ip_addr = htonl(src_ip);
    memset(&sge, 0, sizeof(sge));
    memcpy(sge.mac, src_mac, sizeof(sge.mac));
    sge.ifindex = 5;
    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(binding_map), &sgk, &sge, BPF_ANY));

    RS_ASSERT_OK(run_source_guard(prog, &pkt, sizeof(pkt), &retval));
    RS_ASSERT_EQ(retval, XDP_DROP);
    RS_ASSERT_EQ((long long)lookup_percpu_u64_sum(bpf_map__fd(stats_map), SG_STAT_PASSED), 1);
    RS_ASSERT_EQ((long long)lookup_percpu_u64_sum(bpf_map__fd(stats_map), SG_STAT_TOTAL), 1);

    bpf_object__close(obj);
}

RS_TEST(test_sg_mac_violation_strict_drops)
{
    struct bpf_object *obj;
    struct bpf_program *prog = NULL;
    struct bpf_map *cfg_map;
    struct bpf_map *ctx_map;
    struct bpf_map *binding_map;
    struct bpf_map *stats_map;
    struct bpf_map *port_enable_map;
    struct sg_config cfg = {.enabled = 1, .strict_mode = 1, .check_mac = 1, .check_port = 0};
    struct sg_key sgk;
    struct sg_entry sge;
    struct rs_ctx ctx;
    struct test_pkt_ipv4_tcp pkt;
    static const __u8 pkt_src_mac[6] = {0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    static const __u8 bind_mac[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    __u32 cfg_key = 0;
    __u32 ifindex = 5;
    __u8 enabled = 1;
    __u32 src_ip = 0x0a030301U;
    __u32 retval = 0;

    obj = open_sg_obj(&prog);
    if (!obj)
        return;

    cfg_map = bpf_object__find_map_by_name(obj, "sg_config_map");
    ctx_map = bpf_object__find_map_by_name(obj, "rs_ctx_map");
    binding_map = bpf_object__find_map_by_name(obj, "sg_binding_map");
    stats_map = bpf_object__find_map_by_name(obj, "sg_stats_map");
    port_enable_map = bpf_object__find_map_by_name(obj, "sg_port_enable_map");
    RS_ASSERT(cfg_map != NULL);
    RS_ASSERT(ctx_map != NULL);
    RS_ASSERT(binding_map != NULL);
    RS_ASSERT(stats_map != NULL);
    RS_ASSERT(port_enable_map != NULL);
    if (!cfg_map || !ctx_map || !binding_map || !stats_map || !port_enable_map) {
        bpf_object__close(obj);
        return;
    }

    prep_ctx(&ctx);
    ctx.layers.saddr = htonl(src_ip);
    RS_ASSERT_OK(update_percpu_rs_ctx(bpf_map__fd(ctx_map), &ctx));
    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(cfg_map), &cfg_key, &cfg, BPF_ANY));
    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(port_enable_map), &ifindex, &enabled, BPF_ANY));

    memset(&sgk, 0, sizeof(sgk));
    sgk.ip_addr = htonl(src_ip);
    memset(&sge, 0, sizeof(sge));
    memcpy(sge.mac, bind_mac, sizeof(sge.mac));
    sge.ifindex = 5;
    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(binding_map), &sgk, &sge, BPF_ANY));

    build_ipv4_tcp_pkt(&pkt, src_ip, 0x0a030302U, 2222, 53, 0);
    memcpy(pkt.eth.src, pkt_src_mac, sizeof(pkt_src_mac));

    RS_ASSERT_OK(run_source_guard(prog, &pkt, sizeof(pkt), &retval));
    RS_ASSERT_EQ(retval, XDP_DROP);
    RS_ASSERT(lookup_percpu_u64_sum(bpf_map__fd(stats_map), SG_STAT_MAC_VIOLATIONS) >= 1);

    bpf_object__close(obj);
}

RS_TEST(test_sg_strict_no_binding_drops)
{
    struct bpf_object *obj;
    struct bpf_program *prog = NULL;
    struct bpf_map *cfg_map;
    struct bpf_map *ctx_map;
    struct bpf_map *stats_map;
    struct bpf_map *port_enable_map;
    struct sg_config cfg = {.enabled = 1, .strict_mode = 1, .check_mac = 1, .check_port = 1};
    struct rs_ctx ctx;
    struct test_pkt_ipv4_tcp pkt;
    __u32 cfg_key = 0;
    __u32 ifindex = 5;
    __u8 enabled = 1;
    __u32 src_ip = 0x0a040401U;
    __u32 retval = 0;

    obj = open_sg_obj(&prog);
    if (!obj)
        return;

    cfg_map = bpf_object__find_map_by_name(obj, "sg_config_map");
    ctx_map = bpf_object__find_map_by_name(obj, "rs_ctx_map");
    stats_map = bpf_object__find_map_by_name(obj, "sg_stats_map");
    port_enable_map = bpf_object__find_map_by_name(obj, "sg_port_enable_map");
    RS_ASSERT(cfg_map != NULL);
    RS_ASSERT(ctx_map != NULL);
    RS_ASSERT(stats_map != NULL);
    RS_ASSERT(port_enable_map != NULL);
    if (!cfg_map || !ctx_map || !stats_map || !port_enable_map) {
        bpf_object__close(obj);
        return;
    }

    prep_ctx(&ctx);
    ctx.layers.saddr = htonl(src_ip);
    RS_ASSERT_OK(update_percpu_rs_ctx(bpf_map__fd(ctx_map), &ctx));
    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(cfg_map), &cfg_key, &cfg, BPF_ANY));
    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(port_enable_map), &ifindex, &enabled, BPF_ANY));

    build_ipv4_tcp_pkt(&pkt, src_ip, 0x0a040402U, 3456, 8443, 0);
    RS_ASSERT_OK(run_source_guard(prog, &pkt, sizeof(pkt), &retval));
    RS_ASSERT_EQ(retval, XDP_DROP);
    RS_ASSERT(lookup_percpu_u64_sum(bpf_map__fd(stats_map), SG_STAT_MAC_VIOLATIONS) >= 1);

    bpf_object__close(obj);
}

RS_TEST_SUITE_BEGIN()
    ;
    if (argc < 2) {
        printf("Usage: %s <path_to_source_guard.bpf.o>\n", argv[0]);
        return 1;
    }

    g_obj_path = argv[1];
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    RS_RUN_TEST(test_sg_disabled_bypass);
    RS_RUN_TEST(test_sg_port_not_enabled_bypass);
    RS_RUN_TEST(test_sg_binding_match_passes);
    RS_RUN_TEST(test_sg_mac_violation_strict_drops);
    RS_RUN_TEST(test_sg_strict_no_binding_drops);

RS_TEST_SUITE_END()
