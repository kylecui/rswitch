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


struct rs_mac_key {
    __u8 mac[6];
    __u16 vlan;
} __attribute__((packed));

struct rs_mac_entry {
    __u32 ifindex;
    __u8 static_entry;
    __u8 reserved[3];
    __u64 last_seen;
    __u32 hit_count;
} __attribute__((packed));

struct rs_port_config {
    __u32 ifindex;
    __u8 enabled;
    __u8 mgmt_type;
    __u8 vlan_mode;
    __u8 learning;
    __u16 pvid;
    __u16 native_vlan;
    __u16 access_vlan;
    __u16 allowed_vlan_count;
    __u16 allowed_vlans[128];
    __u16 tagged_vlan_count;
    __u16 tagged_vlans[64];
    __u16 untagged_vlan_count;
    __u16 untagged_vlans[64];
    __u8 default_prio;
    __u8 trust_dscp;
    __u16 rate_limit_kbps;
    __u8 port_security;
    __u8 max_macs;
    __u16 reserved;
    __u32 reserved2[4];
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

static int run_l2learn(struct bpf_program *prog, const void *pkt, __u32 pkt_len, __u32 *retval)
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

static struct bpf_object *open_l2learn_obj(struct bpf_program **prog_out)
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

    *prog_out = bpf_object__find_program_by_name(obj, "l2learn_ingress");
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
    memset(ctx, 0, sizeof(*ctx));
    ctx->ifindex = 5;
    ctx->parsed = 1;
    ctx->layers.eth_proto = 0x0800;
    ctx->layers.l2_offset = 0;
}

RS_TEST(test_l2learn_learning_disabled_passthrough)
{
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_map *ctx_map;
    struct bpf_map *port_map;
    struct bpf_map *mac_map;
    struct rs_ctx ctx;
    struct rs_port_config port;
    struct test_pkt_ipv4_tcp pkt;
    struct rs_mac_key mac_key;
    struct rs_mac_entry mac_val;
    const __u8 src_mac[6] = {0x02, 0x10, 0x20, 0x30, 0x40, 0x50};
    __u32 ifindex = 5;
    __u32 retval = 0;
    int ret;

    obj = open_l2learn_obj(&prog);
    if (!obj)
        goto out;

    ctx_map = bpf_object__find_map_by_name(obj, "rs_ctx_map");
    port_map = bpf_object__find_map_by_name(obj, "rs_port_config_map");
    mac_map = bpf_object__find_map_by_name(obj, "rs_mac_table");
    RS_ASSERT(ctx_map != NULL);
    RS_ASSERT(port_map != NULL);
    RS_ASSERT(mac_map != NULL);
    if (!ctx_map || !port_map || !mac_map)
        goto out;

    prep_ctx(&ctx);
    RS_ASSERT_OK(update_percpu_rs_ctx(bpf_map__fd(ctx_map), &ctx));

    memset(&port, 0, sizeof(port));
    port.ifindex = ifindex;
    port.enabled = 1;
    port.learning = 0;
    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(port_map), &ifindex, &port, BPF_ANY));

    build_ipv4_tcp_pkt(&pkt, 0x0a000001U, 0x0a000002U, 12345, 80, 0);
    memcpy(pkt.eth.src, src_mac, sizeof(src_mac));

    RS_ASSERT_OK(run_l2learn(prog, &pkt, sizeof(pkt), &retval));
    RS_ASSERT_EQ(retval, XDP_DROP);

    memset(&mac_key, 0, sizeof(mac_key));
    memcpy(mac_key.mac, src_mac, sizeof(src_mac));
    mac_key.vlan = 0;
    errno = 0;
    ret = bpf_map_lookup_elem(bpf_map__fd(mac_map), &mac_key, &mac_val);
    RS_ASSERT_NE(ret, 0);

out:
    if (obj)
        bpf_object__close(obj);
}

RS_TEST(test_l2learn_learns_new_mac)
{
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_map *ctx_map;
    struct bpf_map *port_map;
    struct bpf_map *mac_map;
    struct rs_ctx ctx;
    struct rs_port_config port;
    struct test_pkt_ipv4_tcp pkt;
    struct rs_mac_key mac_key;
    struct rs_mac_entry mac_val;
    const __u8 src_mac[6] = {0xAA, 0xBB, 0xCC, 0x11, 0x22, 0x33};
    const __u8 dst_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    __u32 ifindex = 5;
    __u32 retval = 0;

    obj = open_l2learn_obj(&prog);
    if (!obj)
        goto out;

    ctx_map = bpf_object__find_map_by_name(obj, "rs_ctx_map");
    port_map = bpf_object__find_map_by_name(obj, "rs_port_config_map");
    mac_map = bpf_object__find_map_by_name(obj, "rs_mac_table");
    RS_ASSERT(ctx_map != NULL);
    RS_ASSERT(port_map != NULL);
    RS_ASSERT(mac_map != NULL);
    if (!ctx_map || !port_map || !mac_map)
        goto out;

    prep_ctx(&ctx);
    ctx.ingress_vlan = 100;
    RS_ASSERT_OK(update_percpu_rs_ctx(bpf_map__fd(ctx_map), &ctx));

    memset(&port, 0, sizeof(port));
    port.ifindex = ifindex;
    port.enabled = 1;
    port.learning = 1;
    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(port_map), &ifindex, &port, BPF_ANY));

    build_ipv4_tcp_pkt(&pkt, 0x0a000101U, 0x0a000102U, 23456, 443, 0);
    memcpy(pkt.eth.src, src_mac, sizeof(src_mac));
    memcpy(pkt.eth.dst, dst_mac, sizeof(dst_mac));

    RS_ASSERT_OK(run_l2learn(prog, &pkt, sizeof(pkt), &retval));
    RS_ASSERT_EQ(retval, XDP_DROP);

    memset(&mac_key, 0, sizeof(mac_key));
    memcpy(mac_key.mac, src_mac, sizeof(src_mac));
    mac_key.vlan = 100;
    RS_ASSERT_OK(bpf_map_lookup_elem(bpf_map__fd(mac_map), &mac_key, &mac_val));
    RS_ASSERT_EQ(mac_val.ifindex, 5);

out:
    if (obj)
        bpf_object__close(obj);
}

RS_TEST(test_l2learn_known_dest_sets_egress)
{
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_map *ctx_map;
    struct bpf_map *port_map;
    struct bpf_map *mac_map;
    struct rs_ctx ctx;
    struct rs_port_config port;
    struct test_pkt_ipv4_tcp pkt;
    struct rs_mac_key src_key;
    struct rs_mac_entry src_val;
    struct rs_mac_key dst_key;
    struct rs_mac_entry dst_val;
    const __u8 src_mac[6] = {0x02, 0x44, 0x55, 0x66, 0x77, 0x88};
    const __u8 dst_mac[6] = {0x00, 0x21, 0x43, 0x65, 0x87, 0xA9};
    __u32 ifindex = 5;
    __u32 retval = 0;

    obj = open_l2learn_obj(&prog);
    if (!obj)
        goto out;

    ctx_map = bpf_object__find_map_by_name(obj, "rs_ctx_map");
    port_map = bpf_object__find_map_by_name(obj, "rs_port_config_map");
    mac_map = bpf_object__find_map_by_name(obj, "rs_mac_table");
    RS_ASSERT(ctx_map != NULL);
    RS_ASSERT(port_map != NULL);
    RS_ASSERT(mac_map != NULL);
    if (!ctx_map || !port_map || !mac_map)
        goto out;

    prep_ctx(&ctx);
    ctx.ingress_vlan = 0;
    RS_ASSERT_OK(update_percpu_rs_ctx(bpf_map__fd(ctx_map), &ctx));

    memset(&port, 0, sizeof(port));
    port.ifindex = ifindex;
    port.enabled = 1;
    port.learning = 1;
    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(port_map), &ifindex, &port, BPF_ANY));

    memset(&dst_key, 0, sizeof(dst_key));
    memcpy(dst_key.mac, dst_mac, sizeof(dst_mac));
    dst_key.vlan = 0;
    memset(&dst_val, 0, sizeof(dst_val));
    dst_val.ifindex = 10;
    dst_val.static_entry = 0;
    dst_val.last_seen = 1;
    dst_val.hit_count = 1;
    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(mac_map), &dst_key, &dst_val, BPF_ANY));

    build_ipv4_tcp_pkt(&pkt, 0x0a000201U, 0x0a000202U, 34567, 8080, 0);
    memcpy(pkt.eth.src, src_mac, sizeof(src_mac));
    memcpy(pkt.eth.dst, dst_mac, sizeof(dst_mac));

    RS_ASSERT_OK(run_l2learn(prog, &pkt, sizeof(pkt), &retval));
    RS_ASSERT_EQ(retval, XDP_DROP);

    memset(&src_key, 0, sizeof(src_key));
    memcpy(src_key.mac, src_mac, sizeof(src_mac));
    src_key.vlan = 0;
    RS_ASSERT_OK(bpf_map_lookup_elem(bpf_map__fd(mac_map), &src_key, &src_val));
    RS_ASSERT_EQ(src_val.ifindex, 5);

    memset(&dst_val, 0, sizeof(dst_val));
    RS_ASSERT_OK(bpf_map_lookup_elem(bpf_map__fd(mac_map), &dst_key, &dst_val));
    RS_ASSERT_EQ(dst_val.ifindex, 10);
    RS_ASSERT_TRUE(dst_val.hit_count >= 2);

out:
    if (obj)
        bpf_object__close(obj);
}

RS_TEST(test_l2learn_broadcast_dst_floods)
{
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_map *ctx_map;
    struct bpf_map *port_map;
    struct bpf_map *mac_map;
    struct rs_ctx ctx;
    struct rs_port_config port;
    struct test_pkt_ipv4_tcp pkt;
    struct rs_mac_key src_key;
    struct rs_mac_entry src_val;
    const __u8 src_mac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01};
    const __u8 dst_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    __u32 ifindex = 5;
    __u32 retval = 0;

    obj = open_l2learn_obj(&prog);
    if (!obj)
        goto out;

    ctx_map = bpf_object__find_map_by_name(obj, "rs_ctx_map");
    port_map = bpf_object__find_map_by_name(obj, "rs_port_config_map");
    mac_map = bpf_object__find_map_by_name(obj, "rs_mac_table");
    RS_ASSERT(ctx_map != NULL);
    RS_ASSERT(port_map != NULL);
    RS_ASSERT(mac_map != NULL);
    if (!ctx_map || !port_map || !mac_map)
        goto out;

    prep_ctx(&ctx);
    RS_ASSERT_OK(update_percpu_rs_ctx(bpf_map__fd(ctx_map), &ctx));

    memset(&port, 0, sizeof(port));
    port.ifindex = ifindex;
    port.enabled = 1;
    port.learning = 1;
    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(port_map), &ifindex, &port, BPF_ANY));

    build_ipv4_tcp_pkt(&pkt, 0x0a000301U, 0x0a000302U, 45678, 53, 0);
    memcpy(pkt.eth.src, src_mac, sizeof(src_mac));
    memcpy(pkt.eth.dst, dst_mac, sizeof(dst_mac));

    RS_ASSERT_OK(run_l2learn(prog, &pkt, sizeof(pkt), &retval));
    RS_ASSERT_EQ(retval, XDP_DROP);

    memset(&src_key, 0, sizeof(src_key));
    memcpy(src_key.mac, src_mac, sizeof(src_mac));
    src_key.vlan = 0;
    RS_ASSERT_OK(bpf_map_lookup_elem(bpf_map__fd(mac_map), &src_key, &src_val));
    RS_ASSERT_EQ(src_val.ifindex, 5);

out:
    if (obj)
        bpf_object__close(obj);
}

RS_TEST_SUITE_BEGIN()
    ;
    if (argc < 2) {
        printf("Usage: %s <path_to_l2learn.bpf.o>\n", argv[0]);
        return 1;
    }
    g_obj_path = argv[1];
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    RS_RUN_TEST(test_l2learn_learning_disabled_passthrough);
    RS_RUN_TEST(test_l2learn_learns_new_mac);
    RS_RUN_TEST(test_l2learn_known_dest_sets_egress);
    RS_RUN_TEST(test_l2learn_broadcast_dst_floods);
RS_TEST_SUITE_END()
