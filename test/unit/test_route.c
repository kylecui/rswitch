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

struct lpm_key {
    __u32 prefixlen;
    __be32 addr;
};

struct route_entry {
    __be32 nexthop;
    __u32 ifindex;
    __u32 metric;
    __u8 type;      /* 0=direct, 1=static */
    __u8 pad[3];
    __u32 ecmp_group_id;
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

struct route_config {
    __u8 enabled;
    __u8 pad[3];
};

enum route_stat_type {
    ROUTE_STAT_LOOKUP = 0,
    ROUTE_STAT_HIT = 1,
    ROUTE_STAT_MISS = 2,
    ROUTE_STAT_ARP_HIT = 3,
    ROUTE_STAT_ARP_MISS = 4,
    ROUTE_STAT_TTL_EXCEEDED = 5,
    ROUTE_STAT_DIRECT = 6,
    ROUTE_STAT_STATIC = 7,
    ROUTE_STAT_REDIRECT = 8,
    ROUTE_STAT_MAX = 9,
};

static const char *g_obj_path;

static int get_ncpus(void)
{
    long n = sysconf(_SC_NPROCESSORS_CONF);
    if (n < 1)
        return 1;
    return (int)n;
}

static int run_route(struct bpf_program *prog, const void *pkt, __u32 pkt_len, __u32 *retval)
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

static struct bpf_object *open_route_obj(struct bpf_program **prog_out)
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

    *prog_out = bpf_object__find_program_by_name(obj, "route_ipv4");
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

RS_TEST(test_route_disabled_bypass)
{
    struct bpf_object *obj;
    struct bpf_program *prog = NULL;
    struct bpf_map *cfg_map;
    struct bpf_map *ctx_map;
    struct route_config cfg = {.enabled = 0};
    struct rs_ctx ctx;
    struct test_pkt_ipv4_tcp pkt;
    __u32 key = 0;
    __u32 retval = 0;

    obj = open_route_obj(&prog);
    if (!obj)
        return;

    cfg_map = bpf_object__find_map_by_name(obj, "route_cfg");
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
    RS_ASSERT_OK(run_route(prog, &pkt, sizeof(pkt), &retval));
    RS_ASSERT_EQ(retval, XDP_PASS);

    bpf_object__close(obj);
}

RS_TEST(test_route_ttl_exceeded_drops)
{
    struct bpf_object *obj;
    struct bpf_program *prog = NULL;
    struct bpf_map *cfg_map;
    struct bpf_map *iface_map;
    struct bpf_map *ctx_map;
    struct bpf_map *stats_map;
    struct route_config cfg = {.enabled = 1};
    struct iface_config iface = {.is_router = 1};
    struct rs_ctx ctx;
    struct test_pkt_ipv4_tcp pkt;
    static const __u8 router_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    __u32 cfg_key = 0;
    __u32 ifkey = 5;
    __u32 retval = 0;

    obj = open_route_obj(&prog);
    if (!obj)
        return;

    cfg_map = bpf_object__find_map_by_name(obj, "route_cfg");
    iface_map = bpf_object__find_map_by_name(obj, "iface_cfg");
    ctx_map = bpf_object__find_map_by_name(obj, "rs_ctx_map");
    stats_map = bpf_object__find_map_by_name(obj, "route_stats");
    RS_ASSERT(cfg_map != NULL);
    RS_ASSERT(iface_map != NULL);
    RS_ASSERT(ctx_map != NULL);
    RS_ASSERT(stats_map != NULL);
    if (!cfg_map || !iface_map || !ctx_map || !stats_map) {
        bpf_object__close(obj);
        return;
    }

    prep_ctx(&ctx);
    ctx.layers.saddr = htonl(0x0a010101U);
    ctx.layers.daddr = htonl(0x0a010102U);
    ctx.layers.sport = htons(1234);
    ctx.layers.dport = htons(443);
    RS_ASSERT_OK(update_percpu_rs_ctx(bpf_map__fd(ctx_map), &ctx));
    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(cfg_map), &cfg_key, &cfg, BPF_ANY));

    memcpy(iface.mac, router_mac, sizeof(router_mac));
    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(iface_map), &ifkey, &iface, BPF_ANY));

    build_ipv4_tcp_pkt(&pkt, 0x0a010101U, 0x0a010102U, 1234, 443, 0);
    memcpy(pkt.eth.dst, router_mac, sizeof(router_mac));
    pkt.ip.ttl = 1;

    RS_ASSERT_OK(run_route(prog, &pkt, sizeof(pkt), &retval));
    RS_ASSERT_EQ(retval, XDP_DROP);
    RS_ASSERT(lookup_percpu_u64_sum(bpf_map__fd(stats_map), ROUTE_STAT_TTL_EXCEEDED) >= 1);

    bpf_object__close(obj);
}

RS_TEST(test_route_miss_drops)
{
    struct bpf_object *obj;
    struct bpf_program *prog = NULL;
    struct bpf_map *cfg_map;
    struct bpf_map *iface_map;
    struct bpf_map *ctx_map;
    struct bpf_map *stats_map;
    struct route_config cfg = {.enabled = 1};
    struct iface_config iface = {.is_router = 1};
    struct rs_ctx ctx;
    struct test_pkt_ipv4_tcp pkt;
    static const __u8 router_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    __u32 cfg_key = 0;
    __u32 ifkey = 5;
    __u32 retval = 0;

    obj = open_route_obj(&prog);
    if (!obj)
        return;

    cfg_map = bpf_object__find_map_by_name(obj, "route_cfg");
    iface_map = bpf_object__find_map_by_name(obj, "iface_cfg");
    ctx_map = bpf_object__find_map_by_name(obj, "rs_ctx_map");
    stats_map = bpf_object__find_map_by_name(obj, "route_stats");
    RS_ASSERT(cfg_map != NULL);
    RS_ASSERT(iface_map != NULL);
    RS_ASSERT(ctx_map != NULL);
    RS_ASSERT(stats_map != NULL);
    if (!cfg_map || !iface_map || !ctx_map || !stats_map) {
        bpf_object__close(obj);
        return;
    }

    prep_ctx(&ctx);
    ctx.layers.saddr = htonl(0x0a020201U);
    ctx.layers.daddr = htonl(0x0a090909U);
    ctx.layers.sport = htons(5555);
    ctx.layers.dport = htons(8080);
    RS_ASSERT_OK(update_percpu_rs_ctx(bpf_map__fd(ctx_map), &ctx));
    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(cfg_map), &cfg_key, &cfg, BPF_ANY));

    memcpy(iface.mac, router_mac, sizeof(router_mac));
    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(iface_map), &ifkey, &iface, BPF_ANY));

    build_ipv4_tcp_pkt(&pkt, 0x0a020201U, 0x0a090909U, 5555, 8080, 0);
    memcpy(pkt.eth.dst, router_mac, sizeof(router_mac));
    pkt.ip.ttl = 64;

    RS_ASSERT_OK(run_route(prog, &pkt, sizeof(pkt), &retval));
    RS_ASSERT_EQ(retval, XDP_DROP);
    RS_ASSERT(lookup_percpu_u64_sum(bpf_map__fd(stats_map), ROUTE_STAT_MISS) >= 1);

    bpf_object__close(obj);
}

RS_TEST(test_route_hit_with_arp)
{
    struct bpf_object *obj;
    struct bpf_program *prog = NULL;
    struct bpf_map *cfg_map;
    struct bpf_map *iface_map;
    struct bpf_map *route_map;
    struct bpf_map *arp_map;
    struct bpf_map *ctx_map;
    struct bpf_map *stats_map;
    struct route_config cfg = {.enabled = 1};
    struct iface_config router_iface = {.is_router = 1};
    struct iface_config egress_iface = {.is_router = 0};
    struct lpm_key rkey;
    struct route_entry route;
    struct arp_entry arp;
    struct rs_ctx ctx;
    struct test_pkt_ipv4_tcp pkt;
    static const __u8 router_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    static const __u8 egress_mac[6] = {0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB};
    static const __u8 nh_mac[6] = {0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC};
    __u32 cfg_key = 0;
    __u32 router_ifkey = 5;
    __u32 egress_ifkey = 10;
    __be32 arp_key = htonl(0x0a020001U);
    __u32 retval = 0;

    obj = open_route_obj(&prog);
    if (!obj)
        return;

    cfg_map = bpf_object__find_map_by_name(obj, "route_cfg");
    iface_map = bpf_object__find_map_by_name(obj, "iface_cfg");
    route_map = bpf_object__find_map_by_name(obj, "route_tbl");
    arp_map = bpf_object__find_map_by_name(obj, "arp_tbl");
    ctx_map = bpf_object__find_map_by_name(obj, "rs_ctx_map");
    stats_map = bpf_object__find_map_by_name(obj, "route_stats");
    RS_ASSERT(cfg_map != NULL);
    RS_ASSERT(iface_map != NULL);
    RS_ASSERT(route_map != NULL);
    RS_ASSERT(arp_map != NULL);
    RS_ASSERT(ctx_map != NULL);
    RS_ASSERT(stats_map != NULL);
    if (!cfg_map || !iface_map || !route_map || !arp_map || !ctx_map || !stats_map) {
        bpf_object__close(obj);
        return;
    }

    prep_ctx(&ctx);
    ctx.layers.saddr = htonl(0x0a010001U);
    ctx.layers.daddr = htonl(0x0a020005U);
    ctx.layers.sport = htons(2222);
    ctx.layers.dport = htons(80);
    RS_ASSERT_OK(update_percpu_rs_ctx(bpf_map__fd(ctx_map), &ctx));
    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(cfg_map), &cfg_key, &cfg, BPF_ANY));

    memcpy(router_iface.mac, router_mac, sizeof(router_mac));
    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(iface_map), &router_ifkey, &router_iface, BPF_ANY));

    memcpy(egress_iface.mac, egress_mac, sizeof(egress_mac));
    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(iface_map), &egress_ifkey, &egress_iface, BPF_ANY));

    memset(&rkey, 0, sizeof(rkey));
    rkey.prefixlen = 24;
    rkey.addr = htonl(0x0a020000U);
    memset(&route, 0, sizeof(route));
    route.nexthop = htonl(0x0a020001U);
    route.ifindex = 10;
    route.type = 1;
    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(route_map), &rkey, &route, BPF_ANY));

    memset(&arp, 0, sizeof(arp));
    memcpy(arp.mac, nh_mac, sizeof(nh_mac));
    arp.ifindex = 10;
    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(arp_map), &arp_key, &arp, BPF_ANY));

    build_ipv4_tcp_pkt(&pkt, 0x0a010001U, 0x0a020005U, 2222, 80, 0);
    memcpy(pkt.eth.dst, router_mac, sizeof(router_mac));
    pkt.ip.ttl = 64;

    RS_ASSERT_OK(run_route(prog, &pkt, sizeof(pkt), &retval));
    RS_ASSERT_EQ(retval, XDP_PASS);
    RS_ASSERT(lookup_percpu_u64_sum(bpf_map__fd(stats_map), ROUTE_STAT_HIT) >= 1);
    RS_ASSERT(lookup_percpu_u64_sum(bpf_map__fd(stats_map), ROUTE_STAT_ARP_HIT) >= 1);

    bpf_object__close(obj);
}

RS_TEST_SUITE_BEGIN()
    ;
    if (argc < 2) {
        printf("Usage: %s <path_to_route.bpf.o>\n", argv[0]);
        return 1;
    }
    g_obj_path = argv[1];
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    RS_RUN_TEST(test_route_disabled_bypass);
    RS_RUN_TEST(test_route_ttl_exceeded_drops);
    RS_RUN_TEST(test_route_miss_drops);
    RS_RUN_TEST(test_route_hit_with_arp);
RS_TEST_SUITE_END()
