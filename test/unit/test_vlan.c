#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/bpf.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "../../user/common/rs_log.h"

#include "rs_test.h"
#include "test_packets.h"

enum rs_vlan_mode {
    RS_VLAN_MODE_OFF = 0,
    RS_VLAN_MODE_ACCESS = 1,
    RS_VLAN_MODE_TRUNK = 2,
    RS_VLAN_MODE_HYBRID = 3,
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

struct rs_vlan_members {
    __u16 vlan_id;
    __u16 member_count;
    __u64 tagged_members[4];
    __u64 untagged_members[4];
    __u32 reserved[4];
};

static const char *g_obj_path;

static int get_ncpus(void)
{
    long n = sysconf(_SC_NPROCESSORS_CONF);
    if (n < 1)
        return 1;
    return (int)n;
}

static int run_vlan(struct bpf_program *prog, const void *pkt, __u32 pkt_len, __u32 *retval)
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

static int update_percpu_ctx(int map_fd, const struct rs_ctx *ctx)
{
    int ncpus = get_ncpus();
    struct rs_ctx *vals = calloc((size_t)ncpus, sizeof(struct rs_ctx));
    __u32 key = 0;
    int i;
    int ret;

    if (!vals)
        return -ENOMEM;

    for (i = 0; i < ncpus; i++)
        vals[i] = *ctx;

    ret = bpf_map_update_elem(map_fd, &key, vals, BPF_ANY);
    free(vals);
    return ret;
}

static int lookup_percpu_ctx_any(int map_fd, struct rs_ctx *out)
{
    int ncpus = get_ncpus();
    struct rs_ctx *vals = calloc((size_t)ncpus, sizeof(struct rs_ctx));
    __u32 key = 0;
    int i;
    int ret;

    if (!vals)
        return -ENOMEM;

    ret = bpf_map_lookup_elem(map_fd, &key, vals);
    if (ret == 0) {
        /* Prefer CPU that BPF actually modified (ingress_vlan set).
         * Since update_percpu_ctx sets parsed=1 on ALL CPUs, using
         * parsed alone would always match CPU 0 even if BPF ran on
         * another CPU.  Prioritize the one with real BPF output. */
        for (i = 0; i < ncpus; i++) {
            if (vals[i].ingress_vlan != 0) {
                *out = vals[i];
                free(vals);
                return 0;
            }
        }
        /* Fallback: return any CPU with parsed flag (BPF ran but
         * might not have set ingress_vlan, e.g. drop before assign). */
        for (i = 0; i < ncpus; i++) {
            if (vals[i].parsed) {
                *out = vals[i];
                free(vals);
                return 0;
            }
        }
        *out = vals[0];
    }

    free(vals);
    return ret;
}

static void prep_ctx(struct rs_ctx *ctx,
                     __u32 ifindex,
                     int tagged,
                     __u16 vlan,
                     __u8 ip_proto,
                     __u16 sport,
                     __u16 dport)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->ifindex = ifindex;
    ctx->parsed = 1;
    ctx->layers.eth_proto = 0x0800;
    ctx->layers.ip_proto = ip_proto;
    ctx->layers.sport = htons(sport);
    ctx->layers.dport = htons(dport);
    if (tagged) {
        ctx->layers.vlan_depth = 1;
        ctx->layers.vlan_ids[0] = vlan;
    }
}

static void prep_vlan_members(struct rs_vlan_members *members, __u16 vlan_id, __u32 ifindex)
{
    __u32 word_idx = ((ifindex - 1U) / 64U) & 3U;
    __u32 bit_idx = (ifindex - 1U) % 64U;

    memset(members, 0, sizeof(*members));
    members->vlan_id = vlan_id;
    members->member_count = 1;
    members->tagged_members[word_idx] |= 1ULL << bit_idx;
    members->untagged_members[word_idx] |= 1ULL << bit_idx;
}

static struct bpf_object *open_vlan_obj(struct bpf_program **prog_out)
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

    *prog_out = bpf_object__find_program_by_name(obj, "vlan_ingress");
    RS_ASSERT(*prog_out != NULL);
    if (!*prog_out) {
        bpf_object__close(obj);
        return NULL;
    }

    return obj;
}

RS_TEST(test_access_untagged_sets_ingress_vlan)
{
    struct bpf_object *obj;
    struct bpf_program *prog = NULL;
    struct bpf_map *ctx_map;
    struct bpf_map *port_map;
    struct bpf_map *vlan_map;
    struct rs_ctx ctx;
    struct rs_ctx out_ctx;
    struct rs_port_config port;
    struct rs_vlan_members members;
    struct test_pkt_ipv4_tcp pkt;
    __u32 ifindex = 5;
    __u16 vlan_id = 100;
    __u32 retval = 0;

    obj = open_vlan_obj(&prog);
    if (!obj)
        return;

    ctx_map = bpf_object__find_map_by_name(obj, "rs_ctx_map");
    port_map = bpf_object__find_map_by_name(obj, "rs_port_config_map");
    vlan_map = bpf_object__find_map_by_name(obj, "rs_vlan_map");
    RS_ASSERT(ctx_map != NULL);
    RS_ASSERT(port_map != NULL);
    RS_ASSERT(vlan_map != NULL);
    if (!ctx_map || !port_map || !vlan_map) {
        bpf_object__close(obj);
        return;
    }

    prep_ctx(&ctx, ifindex, 0, 0, 6, 12345, 80);
    RS_ASSERT_OK(update_percpu_ctx(bpf_map__fd(ctx_map), &ctx));

    memset(&port, 0, sizeof(port));
    port.ifindex = ifindex;
    port.enabled = 1;
    port.mgmt_type = 1;
    port.vlan_mode = RS_VLAN_MODE_ACCESS;
    port.access_vlan = vlan_id;
    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(port_map), &ifindex, &port, BPF_ANY));

    prep_vlan_members(&members, vlan_id, ifindex);
    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(vlan_map), &vlan_id, &members, BPF_ANY));

    build_ipv4_tcp_pkt(&pkt, 0x0a000001U, 0x0a000002U, 12345, 80, 0);
    RS_ASSERT_OK(run_vlan(prog, &pkt, sizeof(pkt), &retval));
    RS_ASSERT_EQ(retval, XDP_DROP);

    RS_ASSERT_OK(lookup_percpu_ctx_any(bpf_map__fd(ctx_map), &out_ctx));
    RS_ASSERT_EQ(out_ctx.ingress_vlan, vlan_id);

    bpf_object__close(obj);
}

RS_TEST(test_access_tagged_drop)
{
    struct bpf_object *obj;
    struct bpf_program *prog = NULL;
    struct bpf_map *ctx_map;
    struct bpf_map *port_map;
    struct bpf_map *vlan_map;
    struct rs_ctx ctx;
    struct rs_port_config port;
    struct rs_vlan_members members;
    struct test_pkt_vlan_ipv4_tcp pkt;
    __u32 ifindex = 5;
    __u16 vlan_id = 100;
    __u32 retval = 0;

    obj = open_vlan_obj(&prog);
    if (!obj)
        return;

    ctx_map = bpf_object__find_map_by_name(obj, "rs_ctx_map");
    port_map = bpf_object__find_map_by_name(obj, "rs_port_config_map");
    vlan_map = bpf_object__find_map_by_name(obj, "rs_vlan_map");
    RS_ASSERT(ctx_map != NULL);
    RS_ASSERT(port_map != NULL);
    RS_ASSERT(vlan_map != NULL);
    if (!ctx_map || !port_map || !vlan_map) {
        bpf_object__close(obj);
        return;
    }

    prep_ctx(&ctx, ifindex, 1, vlan_id, 6, 3456, 443);
    RS_ASSERT_OK(update_percpu_ctx(bpf_map__fd(ctx_map), &ctx));

    memset(&port, 0, sizeof(port));
    port.ifindex = ifindex;
    port.enabled = 1;
    port.mgmt_type = 1;
    port.vlan_mode = RS_VLAN_MODE_ACCESS;
    port.access_vlan = vlan_id;
    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(port_map), &ifindex, &port, BPF_ANY));

    prep_vlan_members(&members, vlan_id, ifindex);
    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(vlan_map), &vlan_id, &members, BPF_ANY));

    build_vlan_ipv4_tcp_pkt(&pkt, vlan_id, 0x0a000001U, 0x0a000002U, 3456, 443);
    RS_ASSERT_OK(run_vlan(prog, &pkt, sizeof(pkt), &retval));
    RS_ASSERT_EQ(retval, XDP_DROP);

    bpf_object__close(obj);
}

RS_TEST(test_trunk_tagged_allowed)
{
    struct bpf_object *obj;
    struct bpf_program *prog = NULL;
    struct bpf_map *ctx_map;
    struct bpf_map *port_map;
    struct bpf_map *vlan_map;
    struct rs_ctx ctx;
    struct rs_ctx out_ctx;
    struct rs_port_config port;
    struct rs_vlan_members members;
    struct test_pkt_vlan_ipv4_tcp pkt;
    __u32 ifindex = 5;
    __u16 vlan_id = 100;
    __u32 retval = 0;

    obj = open_vlan_obj(&prog);
    if (!obj)
        return;

    ctx_map = bpf_object__find_map_by_name(obj, "rs_ctx_map");
    port_map = bpf_object__find_map_by_name(obj, "rs_port_config_map");
    vlan_map = bpf_object__find_map_by_name(obj, "rs_vlan_map");
    RS_ASSERT(ctx_map != NULL);
    RS_ASSERT(port_map != NULL);
    RS_ASSERT(vlan_map != NULL);
    if (!ctx_map || !port_map || !vlan_map) {
        bpf_object__close(obj);
        return;
    }

    prep_ctx(&ctx, ifindex, 1, vlan_id, 6, 2200, 8443);
    RS_ASSERT_OK(update_percpu_ctx(bpf_map__fd(ctx_map), &ctx));

    memset(&port, 0, sizeof(port));
    port.ifindex = ifindex;
    port.enabled = 1;
    port.mgmt_type = 1;
    port.vlan_mode = RS_VLAN_MODE_TRUNK;
    port.native_vlan = 100;
    port.allowed_vlan_count = 2;
    port.allowed_vlans[0] = 100;
    port.allowed_vlans[1] = 200;
    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(port_map), &ifindex, &port, BPF_ANY));

    prep_vlan_members(&members, vlan_id, ifindex);
    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(vlan_map), &vlan_id, &members, BPF_ANY));

    build_vlan_ipv4_tcp_pkt(&pkt, vlan_id, 0x0a000001U, 0x0a000002U, 2200, 8443);
    RS_ASSERT_OK(run_vlan(prog, &pkt, sizeof(pkt), &retval));
    RS_ASSERT_EQ(retval, XDP_DROP);

    RS_ASSERT_OK(lookup_percpu_ctx_any(bpf_map__fd(ctx_map), &out_ctx));
    RS_ASSERT_EQ(out_ctx.ingress_vlan, vlan_id);

    bpf_object__close(obj);
}

RS_TEST(test_trunk_tagged_disallowed_drop)
{
    struct bpf_object *obj;
    struct bpf_program *prog = NULL;
    struct bpf_map *ctx_map;
    struct bpf_map *port_map;
    struct bpf_map *vlan_map;
    struct rs_ctx ctx;
    struct rs_port_config port;
    struct rs_vlan_members members;
    struct test_pkt_vlan_ipv4_tcp pkt;
    __u32 ifindex = 5;
    __u16 vlan_id = 300;
    __u32 retval = 0;

    obj = open_vlan_obj(&prog);
    if (!obj)
        return;

    ctx_map = bpf_object__find_map_by_name(obj, "rs_ctx_map");
    port_map = bpf_object__find_map_by_name(obj, "rs_port_config_map");
    vlan_map = bpf_object__find_map_by_name(obj, "rs_vlan_map");
    RS_ASSERT(ctx_map != NULL);
    RS_ASSERT(port_map != NULL);
    RS_ASSERT(vlan_map != NULL);
    if (!ctx_map || !port_map || !vlan_map) {
        bpf_object__close(obj);
        return;
    }

    prep_ctx(&ctx, ifindex, 1, vlan_id, 6, 8888, 8080);
    RS_ASSERT_OK(update_percpu_ctx(bpf_map__fd(ctx_map), &ctx));

    memset(&port, 0, sizeof(port));
    port.ifindex = ifindex;
    port.enabled = 1;
    port.mgmt_type = 1;
    port.vlan_mode = RS_VLAN_MODE_TRUNK;
    port.native_vlan = 100;
    port.allowed_vlan_count = 2;
    port.allowed_vlans[0] = 100;
    port.allowed_vlans[1] = 200;
    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(port_map), &ifindex, &port, BPF_ANY));

    prep_vlan_members(&members, vlan_id, ifindex);
    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(vlan_map), &vlan_id, &members, BPF_ANY));

    build_vlan_ipv4_tcp_pkt(&pkt, vlan_id, 0x0a000001U, 0x0a000002U, 8888, 8080);
    RS_ASSERT_OK(run_vlan(prog, &pkt, sizeof(pkt), &retval));
    RS_ASSERT_EQ(retval, XDP_DROP);

    bpf_object__close(obj);
}

RS_TEST(test_vlan_mode_off_tailcall_fail_drop)
{
    struct bpf_object *obj;
    struct bpf_program *prog = NULL;
    struct bpf_map *ctx_map;
    struct bpf_map *port_map;
    struct bpf_map *vlan_map;
    struct rs_ctx ctx;
    struct rs_port_config port;
    struct rs_vlan_members members;
    struct test_pkt_ipv4_tcp pkt;
    __u32 ifindex = 5;
    __u16 vlan_id = 1;
    __u32 retval = 0;

    obj = open_vlan_obj(&prog);
    if (!obj)
        return;

    ctx_map = bpf_object__find_map_by_name(obj, "rs_ctx_map");
    port_map = bpf_object__find_map_by_name(obj, "rs_port_config_map");
    vlan_map = bpf_object__find_map_by_name(obj, "rs_vlan_map");
    RS_ASSERT(ctx_map != NULL);
    RS_ASSERT(port_map != NULL);
    RS_ASSERT(vlan_map != NULL);
    if (!ctx_map || !port_map || !vlan_map) {
        bpf_object__close(obj);
        return;
    }

    prep_ctx(&ctx, ifindex, 0, 0, 6, 4000, 4001);
    RS_ASSERT_OK(update_percpu_ctx(bpf_map__fd(ctx_map), &ctx));

    memset(&port, 0, sizeof(port));
    port.ifindex = ifindex;
    port.enabled = 1;
    port.mgmt_type = 1;
    port.vlan_mode = RS_VLAN_MODE_OFF;
    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(port_map), &ifindex, &port, BPF_ANY));

    prep_vlan_members(&members, vlan_id, ifindex);
    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(vlan_map), &vlan_id, &members, BPF_ANY));

    build_ipv4_tcp_pkt(&pkt, 0x0a000001U, 0x0a000002U, 4000, 4001, 0);
    RS_ASSERT_OK(run_vlan(prog, &pkt, sizeof(pkt), &retval));
    RS_ASSERT_EQ(retval, XDP_DROP);

    bpf_object__close(obj);
}

RS_TEST_SUITE_BEGIN()
    ;
    if (argc < 2) {
        printf("Usage: %s <path_to_vlan.bpf.o>\n", argv[0]);
        return 1;
    }

    g_obj_path = argv[1];
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    RS_RUN_TEST(test_access_untagged_sets_ingress_vlan);
    RS_RUN_TEST(test_access_tagged_drop);
    RS_RUN_TEST(test_trunk_tagged_allowed);
    RS_RUN_TEST(test_trunk_tagged_disallowed_drop);
    RS_RUN_TEST(test_vlan_mode_off_tailcall_fail_drop);

RS_TEST_SUITE_END()
