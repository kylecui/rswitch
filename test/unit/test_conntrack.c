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

#define CT_TCP_FLAG_SYN 0x01
#define CT_TCP_FLAG_ACK 0x02
#define CT_TCP_FLAG_FIN 0x04
#define CT_TCP_FLAG_RST 0x08

enum ct_state {
    CT_STATE_NONE = 0,
    CT_STATE_NEW = 1,
    CT_STATE_ESTABLISHED = 2,
    CT_STATE_RELATED = 3,
    CT_STATE_INVALID = 4,
};

struct ct_key {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8 proto;
    __u8 pad[3];
} __attribute__((packed));

struct ct_entry {
    __u8 state;
    __u8 flags;
    __u8 direction;
    __u8 pad;
    __u64 created_ns;
    __u64 last_seen_ns;
    __u64 pkts_orig;
    __u64 pkts_reply;
    __u64 bytes_orig;
    __u64 bytes_reply;
    __u32 timeout_sec;
} __attribute__((aligned(8)));

struct ct_config {
    __u8 enabled;
    __u8 default_action;
    __u8 pad[2];
    __u32 tcp_est_timeout;
    __u32 tcp_syn_timeout;
    __u32 udp_timeout;
    __u32 icmp_timeout;
} __attribute__((aligned(8)));

enum ct_stat_type {
    CT_STAT_NEW = 0,
    CT_STAT_ESTABLISHED = 1,
    CT_STAT_RELATED = 2,
    CT_STAT_INVALID = 3,
    CT_STAT_TIMEOUT = 4,
    CT_STAT_DROPS = 5,
    CT_STAT_TOTAL = 6,
};

static const char *g_obj_path;

static int get_ncpus(void)
{
    long n = sysconf(_SC_NPROCESSORS_CONF);
    if (n < 1)
        return 1;
    return (int)n;
}

static int run_conntrack(struct bpf_program *prog, const void *pkt, __u32 pkt_len, __u32 *retval)
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

static struct bpf_object *open_ct_obj(struct bpf_program **prog_out)
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

    *prog_out = bpf_object__find_program_by_name(obj, "conntrack");
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
    ctx->layers.ip_proto = 6;
    ctx->layers.l2_offset = 0;
    ctx->layers.l3_offset = 14;
    ctx->layers.l4_offset = 34;
}

static void make_normalized_ct_key(struct ct_key *key,
                                   __u32 saddr_host,
                                   __u32 daddr_host,
                                   __u16 sport_host,
                                   __u16 dport_host,
                                   __u8 proto)
{
    memset(key, 0, sizeof(*key));
    if (saddr_host < daddr_host || (saddr_host == daddr_host && sport_host <= dport_host)) {
        key->src_ip = htonl(saddr_host);
        key->dst_ip = htonl(daddr_host);
        key->src_port = htons(sport_host);
        key->dst_port = htons(dport_host);
    } else {
        key->src_ip = htonl(daddr_host);
        key->dst_ip = htonl(saddr_host);
        key->src_port = htons(dport_host);
        key->dst_port = htons(sport_host);
    }
    key->proto = proto;
}

RS_TEST(test_ct_disabled_bypass)
{
    struct bpf_object *obj;
    struct bpf_program *prog = NULL;
    struct bpf_map *cfg_map;
    struct bpf_map *ctx_map;
    struct ct_config cfg = {.enabled = 0, .default_action = 0};
    struct rs_ctx ctx;
    struct test_pkt_ipv4_tcp pkt;
    __u32 key = 0;
    __u32 retval = 0;

    obj = open_ct_obj(&prog);
    if (!obj)
        return;

    cfg_map = bpf_object__find_map_by_name(obj, "ct_config_map");
    ctx_map = bpf_object__find_map_by_name(obj, "rs_ctx_map");
    RS_ASSERT(cfg_map != NULL);
    RS_ASSERT(ctx_map != NULL);
    if (!cfg_map || !ctx_map) {
        bpf_object__close(obj);
        return;
    }

    prep_ctx(&ctx);
    ctx.layers.saddr = htonl(0x0a000001U);
    ctx.layers.daddr = htonl(0x0a000002U);
    ctx.layers.sport = htons(1111);
    ctx.layers.dport = htons(80);

    RS_ASSERT_OK(update_percpu_rs_ctx(bpf_map__fd(ctx_map), &ctx));
    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(cfg_map), &key, &cfg, BPF_ANY));

    build_ipv4_tcp_pkt(&pkt, 0x0a000001U, 0x0a000002U, 1111, 80, 0);
    RS_ASSERT_OK(run_conntrack(prog, &pkt, sizeof(pkt), &retval));
    RS_ASSERT_EQ(retval, XDP_PASS);

    bpf_object__close(obj);
}

RS_TEST(test_ct_new_connection_created)
{
    struct bpf_object *obj;
    struct bpf_program *prog = NULL;
    struct bpf_map *cfg_map;
    struct bpf_map *ctx_map;
    struct bpf_map *stats_map;
    struct bpf_map *table_map;
    struct ct_config cfg = {.enabled = 1, .default_action = 0, .tcp_syn_timeout = 120};
    struct rs_ctx ctx;
    struct test_pkt_ipv4_tcp pkt;
    struct ct_key lookup_key;
    struct ct_entry entry;
    __u64 total;
    __u64 new_count;
    __u32 key = 0;
    __u32 retval = 0;

    obj = open_ct_obj(&prog);
    if (!obj)
        return;

    cfg_map = bpf_object__find_map_by_name(obj, "ct_config_map");
    ctx_map = bpf_object__find_map_by_name(obj, "rs_ctx_map");
    stats_map = bpf_object__find_map_by_name(obj, "ct_stats_map");
    table_map = bpf_object__find_map_by_name(obj, "ct_table");
    RS_ASSERT(cfg_map != NULL);
    RS_ASSERT(ctx_map != NULL);
    RS_ASSERT(stats_map != NULL);
    RS_ASSERT(table_map != NULL);
    if (!cfg_map || !ctx_map || !stats_map || !table_map) {
        bpf_object__close(obj);
        return;
    }

    prep_ctx(&ctx);
    ctx.layers.saddr = htonl(0x0a010101U);
    ctx.layers.daddr = htonl(0x0a010102U);
    ctx.layers.sport = htons(1234);
    ctx.layers.dport = htons(80);
    RS_ASSERT_OK(update_percpu_rs_ctx(bpf_map__fd(ctx_map), &ctx));

    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(cfg_map), &key, &cfg, BPF_ANY));

    build_ipv4_tcp_pkt(&pkt, 0x0a010101U, 0x0a010102U, 1234, 80, 0);
    RS_ASSERT_OK(run_conntrack(prog, &pkt, sizeof(pkt), &retval));
    RS_ASSERT_EQ(retval, XDP_PASS);

    total = lookup_percpu_u64_sum(bpf_map__fd(stats_map), CT_STAT_TOTAL);
    new_count = lookup_percpu_u64_sum(bpf_map__fd(stats_map), CT_STAT_NEW);
    RS_ASSERT(total >= 1);
    RS_ASSERT(new_count >= 1);

    make_normalized_ct_key(&lookup_key, 0x0a010101U, 0x0a010102U, 1234, 80, 6);
    RS_ASSERT_OK(bpf_map_lookup_elem(bpf_map__fd(table_map), &lookup_key, &entry));
    RS_ASSERT_EQ(entry.state, CT_STATE_NEW);

    bpf_object__close(obj);
}

RS_TEST(test_ct_established_on_synack)
{
    struct bpf_object *obj;
    struct bpf_program *prog = NULL;
    struct bpf_map *cfg_map;
    struct bpf_map *ctx_map;
    struct bpf_map *stats_map;
    struct bpf_map *table_map;
    struct ct_config cfg = {.enabled = 1, .default_action = 0, .tcp_est_timeout = 3600, .tcp_syn_timeout = 120};
    struct rs_ctx ctx;
    struct test_pkt_ipv4_tcp syn_pkt;
    struct test_pkt_ipv4_tcp synack_pkt;
    struct ct_key lookup_key;
    struct ct_entry entry;
    __u64 established;
    __u32 key = 0;
    __u32 retval = 0;

    obj = open_ct_obj(&prog);
    if (!obj)
        return;

    cfg_map = bpf_object__find_map_by_name(obj, "ct_config_map");
    ctx_map = bpf_object__find_map_by_name(obj, "rs_ctx_map");
    stats_map = bpf_object__find_map_by_name(obj, "ct_stats_map");
    table_map = bpf_object__find_map_by_name(obj, "ct_table");
    RS_ASSERT(cfg_map != NULL);
    RS_ASSERT(ctx_map != NULL);
    RS_ASSERT(stats_map != NULL);
    RS_ASSERT(table_map != NULL);
    if (!cfg_map || !ctx_map || !stats_map || !table_map) {
        bpf_object__close(obj);
        return;
    }

    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(cfg_map), &key, &cfg, BPF_ANY));

    prep_ctx(&ctx);
    ctx.layers.saddr = htonl(0x0a000001U);
    ctx.layers.daddr = htonl(0x0a000002U);
    ctx.layers.sport = htons(1000);
    ctx.layers.dport = htons(80);
    RS_ASSERT_OK(update_percpu_rs_ctx(bpf_map__fd(ctx_map), &ctx));

    build_ipv4_tcp_pkt(&syn_pkt, 0x0a000001U, 0x0a000002U, 1000, 80, 0);
    RS_ASSERT_OK(run_conntrack(prog, &syn_pkt, sizeof(syn_pkt), &retval));
    RS_ASSERT_EQ(retval, XDP_PASS);

    prep_ctx(&ctx);
    ctx.layers.saddr = htonl(0x0a000002U);
    ctx.layers.daddr = htonl(0x0a000001U);
    ctx.layers.sport = htons(80);
    ctx.layers.dport = htons(1000);
    RS_ASSERT_OK(update_percpu_rs_ctx(bpf_map__fd(ctx_map), &ctx));

    build_ipv4_tcp_pkt(&synack_pkt, 0x0a000002U, 0x0a000001U, 80, 1000, 0);
    synack_pkt.tcp.doff_flags = htons((5U << 12) | 0x012);
    RS_ASSERT_OK(run_conntrack(prog, &synack_pkt, sizeof(synack_pkt), &retval));
    RS_ASSERT_EQ(retval, XDP_PASS);

    established = lookup_percpu_u64_sum(bpf_map__fd(stats_map), CT_STAT_ESTABLISHED);
    RS_ASSERT(established >= 1);

    make_normalized_ct_key(&lookup_key, 0x0a000001U, 0x0a000002U, 1000, 80, 6);
    RS_ASSERT_OK(bpf_map_lookup_elem(bpf_map__fd(table_map), &lookup_key, &entry));
    RS_ASSERT_EQ(entry.state, CT_STATE_ESTABLISHED);

    bpf_object__close(obj);
}

RS_TEST(test_ct_rst_deletes_entry)
{
    struct bpf_object *obj;
    struct bpf_program *prog = NULL;
    struct bpf_map *cfg_map;
    struct bpf_map *ctx_map;
    struct bpf_map *stats_map;
    struct bpf_map *table_map;
    struct ct_config cfg = {.enabled = 1, .default_action = 0, .tcp_syn_timeout = 120};
    struct rs_ctx ctx;
    struct test_pkt_ipv4_tcp syn_pkt;
    struct test_pkt_ipv4_tcp rst_pkt;
    struct ct_key lookup_key;
    struct ct_entry entry;
    __u64 invalid;
    __u32 key = 0;
    __u32 retval = 0;
    int ret;

    obj = open_ct_obj(&prog);
    if (!obj)
        return;

    cfg_map = bpf_object__find_map_by_name(obj, "ct_config_map");
    ctx_map = bpf_object__find_map_by_name(obj, "rs_ctx_map");
    stats_map = bpf_object__find_map_by_name(obj, "ct_stats_map");
    table_map = bpf_object__find_map_by_name(obj, "ct_table");
    RS_ASSERT(cfg_map != NULL);
    RS_ASSERT(ctx_map != NULL);
    RS_ASSERT(stats_map != NULL);
    RS_ASSERT(table_map != NULL);
    if (!cfg_map || !ctx_map || !stats_map || !table_map) {
        bpf_object__close(obj);
        return;
    }

    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(cfg_map), &key, &cfg, BPF_ANY));

    prep_ctx(&ctx);
    ctx.layers.saddr = htonl(0x0a020201U);
    ctx.layers.daddr = htonl(0x0a020202U);
    ctx.layers.sport = htons(2000);
    ctx.layers.dport = htons(443);
    RS_ASSERT_OK(update_percpu_rs_ctx(bpf_map__fd(ctx_map), &ctx));

    build_ipv4_tcp_pkt(&syn_pkt, 0x0a020201U, 0x0a020202U, 2000, 443, 0);
    RS_ASSERT_OK(run_conntrack(prog, &syn_pkt, sizeof(syn_pkt), &retval));
    RS_ASSERT_EQ(retval, XDP_PASS);

    build_ipv4_tcp_pkt(&rst_pkt, 0x0a020201U, 0x0a020202U, 2000, 443, 0);
    rst_pkt.tcp.doff_flags = htons((5U << 12) | 0x004);
    RS_ASSERT_OK(run_conntrack(prog, &rst_pkt, sizeof(rst_pkt), &retval));
    RS_ASSERT_EQ(retval, XDP_PASS);

    invalid = lookup_percpu_u64_sum(bpf_map__fd(stats_map), CT_STAT_INVALID);
    RS_ASSERT(invalid >= 1);

    make_normalized_ct_key(&lookup_key, 0x0a020201U, 0x0a020202U, 2000, 443, 6);
    ret = bpf_map_lookup_elem(bpf_map__fd(table_map), &lookup_key, &entry);
    RS_ASSERT_NE(ret, 0);
    RS_ASSERT(errno == ENOENT);

    bpf_object__close(obj);
}

RS_TEST_SUITE_BEGIN()
    ;
    if (argc < 2) {
        printf("Usage: %s <path_to_conntrack.bpf.o>\n", argv[0]);
        return 1;
    }
    g_obj_path = argv[1];
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    RS_RUN_TEST(test_ct_disabled_bypass);
    RS_RUN_TEST(test_ct_new_connection_created);
    RS_RUN_TEST(test_ct_established_on_synack);
    RS_RUN_TEST(test_ct_rst_deletes_entry);
RS_TEST_SUITE_END()
