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


#define MIRROR_MAX_RULES     64
#define MIRROR_MAX_SESSIONS  4

enum mirror_filter_type {
    MIRROR_FILTER_NONE = 0,
    MIRROR_FILTER_SRC_MAC,
    MIRROR_FILTER_DST_MAC,
    MIRROR_FILTER_SRC_IP,
    MIRROR_FILTER_DST_IP,
    MIRROR_FILTER_PROTOCOL,
    MIRROR_FILTER_SRC_PORT,
    MIRROR_FILTER_DST_PORT,
    MIRROR_FILTER_VLAN,
    MIRROR_FILTER_IFINDEX,
    MIRROR_FILTER_NETFLOW,
};

enum mirror_direction {
    MIRROR_DIR_BOTH = 0,
    MIRROR_DIR_INGRESS = 1,
    MIRROR_DIR_EGRESS = 2,
};

enum mirror_type {
    MIRROR_TYPE_SPAN = 0,
    MIRROR_TYPE_RSPAN = 1,
    MIRROR_TYPE_ERSPAN = 2,
};

struct mirror_config {
    __u32 enabled;
    __u32 span_port;
    __u8 ingress_enabled;
    __u8 egress_enabled;
    __u8 pcap_enabled;
    __u8 filter_mode;
    __u16 vlan_filter;
    __u16 protocol_filter;
    __u8 mirror_type;
    __u8 rspan_pad[3];
    __u16 rspan_vlan_id;
    __u16 truncate_size;
    __u64 ingress_mirrored_packets;
    __u64 ingress_mirrored_bytes;
    __u64 egress_mirrored_packets;
    __u64 egress_mirrored_bytes;
    __u64 mirror_drops;
    __u64 pcap_packets;
};

struct port_mirror_config {
    __u8 mirror_ingress;
    __u8 mirror_egress;
    __u16 _reserved;
};

struct mirror_session_stats {
    __u64 pkts;
    __u64 bytes;
    __u64 drops;
};

struct rs_stats {
    __u64 rx_packets;
    __u64 rx_bytes;
    __u64 tx_packets;
    __u64 tx_bytes;
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

static int run_mirror(struct bpf_program *prog, const void *pkt, __u32 pkt_len, __u32 *retval)
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

static struct bpf_object *open_mirror_obj(struct bpf_program **prog_out)
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

    *prog_out = bpf_object__find_program_by_name(obj, "mirror_ingress");
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

static __u64 sum_session_pkts(int map_fd, __u32 key)
{
    int ncpus = get_ncpus();
    struct mirror_session_stats *vals;
    __u64 sum = 0;
    int i;

    vals = calloc((size_t)ncpus, sizeof(*vals));
    RS_ASSERT(vals != NULL);
    if (!vals)
        return 0;

    RS_ASSERT_OK(bpf_map_lookup_elem(map_fd, &key, vals));
    if (bpf_map_lookup_elem(map_fd, &key, vals) == 0) {
        for (i = 0; i < ncpus; i++)
            sum += vals[i].pkts;
    }

    free(vals);
    return sum;
}

RS_TEST(test_mirror_no_port_config_passthrough)
{
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_map *ctx_map;
    struct rs_ctx ctx;
    struct test_pkt_ipv4_tcp pkt;
    __u32 retval = 0;

    obj = open_mirror_obj(&prog);
    if (!obj)
        goto out;

    ctx_map = bpf_object__find_map_by_name(obj, "rs_ctx_map");
    RS_ASSERT(ctx_map != NULL);
    if (!ctx_map)
        goto out;

    prep_ctx(&ctx);
    RS_ASSERT_OK(update_percpu_rs_ctx(bpf_map__fd(ctx_map), &ctx));

    build_ipv4_tcp_pkt(&pkt, 0x0a000001U, 0x0a000002U, 12345, 80, 0);
    RS_ASSERT_OK(run_mirror(prog, &pkt, sizeof(pkt), &retval));
    RS_ASSERT_EQ(retval, XDP_DROP);

out:
    if (obj)
        bpf_object__close(obj);
}

RS_TEST(test_mirror_ingress_pcap_session)
{
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_map *ctx_map;
    struct bpf_map *port_map;
    struct bpf_map *cfg_map;
    struct bpf_map *sess_stats_map;
    struct rs_ctx ctx;
    struct port_mirror_config port_cfg;
    struct mirror_config cfg;
    struct test_pkt_ipv4_tcp pkt;
    __u32 ifindex = 5;
    __u32 session_key = 0;
    __u32 retval = 0;
    __u64 pkts = 0;

    obj = open_mirror_obj(&prog);
    if (!obj)
        goto out;

    ctx_map = bpf_object__find_map_by_name(obj, "rs_ctx_map");
    port_map = bpf_object__find_map_by_name(obj, "port_mirror_map");
    cfg_map = bpf_object__find_map_by_name(obj, "mirror_config_map");
    sess_stats_map = bpf_object__find_map_by_name(obj, "mirror_session_stats");
    RS_ASSERT(ctx_map != NULL);
    RS_ASSERT(port_map != NULL);
    RS_ASSERT(cfg_map != NULL);
    RS_ASSERT(sess_stats_map != NULL);
    if (!ctx_map || !port_map || !cfg_map || !sess_stats_map)
        goto out;

    prep_ctx(&ctx);
    RS_ASSERT_OK(update_percpu_rs_ctx(bpf_map__fd(ctx_map), &ctx));

    memset(&port_cfg, 0, sizeof(port_cfg));
    port_cfg.mirror_ingress = 1;
    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(port_map), &ifindex, &port_cfg, BPF_ANY));

    memset(&cfg, 0, sizeof(cfg));
    cfg.enabled = 1;
    cfg.ingress_enabled = 1;
    cfg.pcap_enabled = 1;
    cfg.span_port = 0;
    cfg.mirror_type = MIRROR_TYPE_SPAN;
    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(cfg_map), &session_key, &cfg, BPF_ANY));

    build_ipv4_tcp_pkt(&pkt, 0x0a000101U, 0x0a000102U, 23456, 443, 0);
    RS_ASSERT_OK(run_mirror(prog, &pkt, sizeof(pkt), &retval));
    RS_ASSERT_EQ(retval, XDP_DROP);

    pkts = sum_session_pkts(bpf_map__fd(sess_stats_map), session_key);
    RS_ASSERT_TRUE(pkts >= 1);

out:
    if (obj)
        bpf_object__close(obj);
}

RS_TEST(test_mirror_filter_mismatch_skips)
{
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_map *ctx_map;
    struct bpf_map *port_map;
    struct bpf_map *cfg_map;
    struct bpf_map *sess_stats_map;
    struct rs_ctx ctx;
    struct port_mirror_config port_cfg;
    struct mirror_config cfg;
    struct test_pkt_ipv4_tcp pkt;
    __u32 ifindex = 5;
    __u32 session_key = 0;
    __u32 retval = 0;
    __u64 pkts = 0;
    __u64 baseline = 0;

    obj = open_mirror_obj(&prog);
    if (!obj)
        goto out;

    ctx_map = bpf_object__find_map_by_name(obj, "rs_ctx_map");
    port_map = bpf_object__find_map_by_name(obj, "port_mirror_map");
    cfg_map = bpf_object__find_map_by_name(obj, "mirror_config_map");
    sess_stats_map = bpf_object__find_map_by_name(obj, "mirror_session_stats");
    RS_ASSERT(ctx_map != NULL);
    RS_ASSERT(port_map != NULL);
    RS_ASSERT(cfg_map != NULL);
    RS_ASSERT(sess_stats_map != NULL);
    if (!ctx_map || !port_map || !cfg_map || !sess_stats_map)
        goto out;

    baseline = sum_session_pkts(bpf_map__fd(sess_stats_map), session_key);

    prep_ctx(&ctx);
    RS_ASSERT_OK(update_percpu_rs_ctx(bpf_map__fd(ctx_map), &ctx));

    memset(&port_cfg, 0, sizeof(port_cfg));
    port_cfg.mirror_ingress = 1;
    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(port_map), &ifindex, &port_cfg, BPF_ANY));

    memset(&cfg, 0, sizeof(cfg));
    cfg.enabled = 1;
    cfg.ingress_enabled = 1;
    cfg.pcap_enabled = 1;
    cfg.span_port = 0;
    cfg.mirror_type = MIRROR_TYPE_SPAN;
    cfg.vlan_filter = 100;
    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(cfg_map), &session_key, &cfg, BPF_ANY));

    build_ipv4_tcp_pkt(&pkt, 0x0a000201U, 0x0a000202U, 34567, 8080, 0);
    RS_ASSERT_OK(run_mirror(prog, &pkt, sizeof(pkt), &retval));
    RS_ASSERT_EQ(retval, XDP_DROP);

    pkts = sum_session_pkts(bpf_map__fd(sess_stats_map), session_key);
    RS_ASSERT_EQ(pkts - baseline, 0);

out:
    if (obj)
        bpf_object__close(obj);
}

RS_TEST_SUITE_BEGIN()
    ;
    if (argc < 2) {
        printf("Usage: %s <path_to_mirror.bpf.o>\n", argv[0]);
        return 1;
    }
    g_obj_path = argv[1];
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    RS_RUN_TEST(test_mirror_no_port_config_passthrough);
    RS_RUN_TEST(test_mirror_ingress_pcap_session);
    RS_RUN_TEST(test_mirror_filter_mismatch_skips);
RS_TEST_SUITE_END()
