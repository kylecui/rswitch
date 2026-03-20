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

struct rs_layers {
    __u16 eth_proto;
    __u16 vlan_ids[2];
    __u8 vlan_depth;
    __u8 ip_proto;
    __u8 pad[2];
    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;
    __u16 l2_offset;
    __u16 l3_offset;
    __u16 l4_offset;
    __u16 payload_offset;
    __u32 payload_len;
};

struct rs_ctx {
    __u32 ifindex;
    __u32 timestamp;
    __u8 parsed;
    __u8 modified;
    __u8 pad[2];
    struct rs_layers layers;
    __u16 ingress_vlan;
    __u16 egress_vlan;
    __u8 prio;
    __u8 dscp;
    __u8 ecn;
    __u8 traffic_class;
    __u32 egress_ifindex;
    __u8 action;
    __u8 mirror;
    __u16 mirror_port;
    __u32 error;
    __u32 drop_reason;
    __u32 next_prog_id;
    __u32 call_depth;
    __u32 reserved[4];
};

enum stp_port_fwd_state {
    STP_STATE_DISCARDING = 0,
    STP_STATE_LEARNING = 1,
    STP_STATE_FORWARDING = 2,
};

struct stp_port_state {
    __u32 state;
    __u32 role;
    __u32 bridge_priority;
    __u32 path_cost;
    __u64 last_bpdu_ts;
};

enum stp_stats_key {
    STP_STAT_BPDU_EVENTS = 0,
    STP_STAT_BPDU_EVENT_FAIL = 1,
    STP_STAT_DROPPED_DISCARDING = 2,
    STP_STAT_PASSED_LEARNING = 3,
    STP_STAT_FORWARDED = 4,
    STP_STAT_MAX = 5,
};

static const char *g_obj_path;

static int get_ncpus(void)
{
    long n = sysconf(_SC_NPROCESSORS_CONF);
    if (n < 1)
        return 1;
    return (int)n;
}

static int run_stp(struct bpf_program *prog, const void *pkt, __u32 pkt_len, __u32 *retval)
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

static struct bpf_object *open_stp_obj(struct bpf_program **prog_out)
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

    *prog_out = bpf_object__find_program_by_name(obj, "stp_ingress");
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

RS_TEST(test_stp_bpdu_detection)
{
    struct bpf_object *obj;
    struct bpf_program *prog = NULL;
    struct bpf_map *ctx_map;
    struct rs_ctx ctx;
    struct test_pkt_ipv4_tcp pkt;
    static const __u8 bpdu_mac[6] = {0x01, 0x80, 0xC2, 0x00, 0x00, 0x00};
    __u32 retval = 0;

    obj = open_stp_obj(&prog);
    if (!obj)
        return;

    ctx_map = bpf_object__find_map_by_name(obj, "rs_ctx_map");
    RS_ASSERT(ctx_map != NULL);
    if (!ctx_map) {
        bpf_object__close(obj);
        return;
    }

    prep_ctx(&ctx);
    RS_ASSERT_OK(update_percpu_rs_ctx(bpf_map__fd(ctx_map), &ctx));

    build_ipv4_tcp_pkt(&pkt, 0x0a000001U, 0x0a000002U, 1111, 80, 0);
    memcpy(pkt.eth.dst, bpdu_mac, sizeof(bpdu_mac));

    RS_ASSERT_OK(run_stp(prog, &pkt, sizeof(pkt), &retval));
    RS_ASSERT_EQ(retval, XDP_PASS);

    bpf_object__close(obj);
}

RS_TEST(test_stp_discarding_port_drops)
{
    struct bpf_object *obj;
    struct bpf_program *prog = NULL;
    struct bpf_map *ctx_map;
    struct bpf_map *state_map;
    struct bpf_map *stats_map;
    struct rs_ctx ctx;
    struct stp_port_state port_state;
    struct test_pkt_ipv4_tcp pkt;
    __u32 ifindex = 5;
    __u32 retval = 0;

    obj = open_stp_obj(&prog);
    if (!obj)
        return;

    ctx_map = bpf_object__find_map_by_name(obj, "rs_ctx_map");
    state_map = bpf_object__find_map_by_name(obj, "stp_port_state_map");
    stats_map = bpf_object__find_map_by_name(obj, "stp_stats_map");
    RS_ASSERT(ctx_map != NULL);
    RS_ASSERT(state_map != NULL);
    RS_ASSERT(stats_map != NULL);
    if (!ctx_map || !state_map || !stats_map) {
        bpf_object__close(obj);
        return;
    }

    prep_ctx(&ctx);
    RS_ASSERT_OK(update_percpu_rs_ctx(bpf_map__fd(ctx_map), &ctx));

    memset(&port_state, 0, sizeof(port_state));
    port_state.state = STP_STATE_DISCARDING;
    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(state_map), &ifindex, &port_state, BPF_ANY));

    build_ipv4_tcp_pkt(&pkt, 0x0a010101U, 0x0a010102U, 1234, 443, 0);
    RS_ASSERT_OK(run_stp(prog, &pkt, sizeof(pkt), &retval));
    RS_ASSERT_EQ(retval, XDP_DROP);
    RS_ASSERT_EQ((long long)lookup_percpu_u64_sum(bpf_map__fd(stats_map), STP_STAT_DROPPED_DISCARDING), 1);

    bpf_object__close(obj);
}

RS_TEST(test_stp_learning_port_passes)
{
    struct bpf_object *obj;
    struct bpf_program *prog = NULL;
    struct bpf_map *ctx_map;
    struct bpf_map *state_map;
    struct bpf_map *stats_map;
    struct rs_ctx ctx;
    struct stp_port_state port_state;
    struct test_pkt_ipv4_tcp pkt;
    __u32 ifindex = 5;
    __u32 retval = 0;

    obj = open_stp_obj(&prog);
    if (!obj)
        return;

    ctx_map = bpf_object__find_map_by_name(obj, "rs_ctx_map");
    state_map = bpf_object__find_map_by_name(obj, "stp_port_state_map");
    stats_map = bpf_object__find_map_by_name(obj, "stp_stats_map");
    RS_ASSERT(ctx_map != NULL);
    RS_ASSERT(state_map != NULL);
    RS_ASSERT(stats_map != NULL);
    if (!ctx_map || !state_map || !stats_map) {
        bpf_object__close(obj);
        return;
    }

    prep_ctx(&ctx);
    RS_ASSERT_OK(update_percpu_rs_ctx(bpf_map__fd(ctx_map), &ctx));

    memset(&port_state, 0, sizeof(port_state));
    port_state.state = STP_STATE_LEARNING;
    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(state_map), &ifindex, &port_state, BPF_ANY));

    build_ipv4_tcp_pkt(&pkt, 0x0a020201U, 0x0a020202U, 5555, 8080, 0);
    RS_ASSERT_OK(run_stp(prog, &pkt, sizeof(pkt), &retval));
    RS_ASSERT_EQ(retval, XDP_PASS);
    RS_ASSERT_EQ((long long)lookup_percpu_u64_sum(bpf_map__fd(stats_map), STP_STAT_PASSED_LEARNING), 1);

    bpf_object__close(obj);
}

RS_TEST(test_stp_forwarding_port_tailcall_drop)
{
    struct bpf_object *obj;
    struct bpf_program *prog = NULL;
    struct bpf_map *ctx_map;
    struct bpf_map *state_map;
    struct bpf_map *stats_map;
    struct rs_ctx ctx;
    struct stp_port_state port_state;
    struct test_pkt_ipv4_tcp pkt;
    __u32 ifindex = 5;
    __u32 retval = 0;

    obj = open_stp_obj(&prog);
    if (!obj)
        return;

    ctx_map = bpf_object__find_map_by_name(obj, "rs_ctx_map");
    state_map = bpf_object__find_map_by_name(obj, "stp_port_state_map");
    stats_map = bpf_object__find_map_by_name(obj, "stp_stats_map");
    RS_ASSERT(ctx_map != NULL);
    RS_ASSERT(state_map != NULL);
    RS_ASSERT(stats_map != NULL);
    if (!ctx_map || !state_map || !stats_map) {
        bpf_object__close(obj);
        return;
    }

    prep_ctx(&ctx);
    RS_ASSERT_OK(update_percpu_rs_ctx(bpf_map__fd(ctx_map), &ctx));

    memset(&port_state, 0, sizeof(port_state));
    port_state.state = STP_STATE_FORWARDING;
    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(state_map), &ifindex, &port_state, BPF_ANY));

    build_ipv4_tcp_pkt(&pkt, 0x0a030301U, 0x0a030302U, 2222, 53, 0);
    RS_ASSERT_OK(run_stp(prog, &pkt, sizeof(pkt), &retval));
    RS_ASSERT_EQ(retval, XDP_DROP);
    RS_ASSERT_EQ((long long)lookup_percpu_u64_sum(bpf_map__fd(stats_map), STP_STAT_FORWARDED), 1);

    bpf_object__close(obj);
}

RS_TEST(test_stp_no_port_state_forwarding)
{
    struct bpf_object *obj;
    struct bpf_program *prog = NULL;
    struct bpf_map *ctx_map;
    struct bpf_map *stats_map;
    struct rs_ctx ctx;
    struct test_pkt_ipv4_tcp pkt;
    __u32 retval = 0;
    __u64 baseline;

    obj = open_stp_obj(&prog);
    if (!obj)
        return;

    ctx_map = bpf_object__find_map_by_name(obj, "rs_ctx_map");
    stats_map = bpf_object__find_map_by_name(obj, "stp_stats_map");
    RS_ASSERT(ctx_map != NULL);
    RS_ASSERT(stats_map != NULL);
    if (!ctx_map || !stats_map) {
        bpf_object__close(obj);
        return;
    }

    baseline = lookup_percpu_u64_sum(bpf_map__fd(stats_map), STP_STAT_FORWARDED);

    prep_ctx(&ctx);
    RS_ASSERT_OK(update_percpu_rs_ctx(bpf_map__fd(ctx_map), &ctx));

    build_ipv4_tcp_pkt(&pkt, 0x0a040401U, 0x0a040402U, 3456, 8443, 0);
    RS_ASSERT_OK(run_stp(prog, &pkt, sizeof(pkt), &retval));
    RS_ASSERT_EQ(retval, XDP_DROP);
    RS_ASSERT_EQ((long long)(lookup_percpu_u64_sum(bpf_map__fd(stats_map), STP_STAT_FORWARDED) - baseline), 1);

    bpf_object__close(obj);
}

RS_TEST_SUITE_BEGIN()
    ;
    if (argc < 2) {
        printf("Usage: %s <path_to_stp.bpf.o>\n", argv[0]);
        return 1;
    }

    g_obj_path = argv[1];
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    RS_RUN_TEST(test_stp_bpdu_detection);
    RS_RUN_TEST(test_stp_discarding_port_drops);
    RS_RUN_TEST(test_stp_learning_port_passes);
    RS_RUN_TEST(test_stp_forwarding_port_tailcall_drop);
    RS_RUN_TEST(test_stp_no_port_state_forwarding);

RS_TEST_SUITE_END()
