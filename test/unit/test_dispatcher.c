#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

enum rs_vlan_mode {
    RS_VLAN_MODE_OFF = 0,
    RS_VLAN_MODE_ACCESS = 1,
    RS_VLAN_MODE_TRUNK = 2,
    RS_VLAN_MODE_HYBRID = 3,
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

static const char *g_obj_path;

static int run_dispatcher(struct bpf_program *prog,
                          const void *pkt,
                          __u32 pkt_len,
                          __u32 ingress_ifindex,
                          __u32 *retval)
{
    unsigned char out_buf[256] = {0};
    struct test_xdp_md xdp_ctx = {
        .data = 0,
        .data_meta = 0,
        .data_end = pkt_len,
        .ingress_ifindex = ingress_ifindex,
        .rx_queue_index = 0,
        .egress_ifindex = 0,
    };
    LIBBPF_OPTS(bpf_test_run_opts, topts,
        .data_in = pkt,
        .data_size_in = pkt_len,
        .data_out = out_buf,
        .data_size_out = sizeof(out_buf),
        .ctx_in = &xdp_ctx,
        .ctx_size_in = sizeof(xdp_ctx),
        .repeat = 1,
    );
    int prog_fd = bpf_program__fd(prog);
    int err;

    err = bpf_prog_test_run_opts(prog_fd, &topts);
    if (retval)
        *retval = topts.retval;
    return err;
}

static struct bpf_object *open_dispatcher_obj(struct bpf_program **prog_out)
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

    *prog_out = bpf_object__find_program_by_name(obj, "rswitch_dispatcher");
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

RS_TEST(test_unmanaged_port_returns_pass)
{
    struct bpf_program *prog = NULL;
    struct bpf_object *obj = open_dispatcher_obj(&prog);
    struct test_pkt_ipv4_tcp pkt;
    __u32 retval = 0;

    if (!obj)
        return;

    build_ipv4_tcp_pkt(&pkt, 0x0a000001U, 0x0a000002U, 12345, 80, 0);
    RS_ASSERT_OK(run_dispatcher(prog, &pkt, sizeof(pkt), 99, &retval));
    RS_ASSERT_EQ(retval, XDP_PASS);

    bpf_object__close(obj);
}

RS_TEST(test_managed_ipv4_tcp_tailcall_fail_drop)
{
    struct bpf_program *prog = NULL;
    struct bpf_object *obj = open_dispatcher_obj(&prog);
    struct test_pkt_ipv4_tcp pkt;
    struct bpf_map *port_map;
    struct rs_port_config cfg;
    __u32 key = 7;
    __u32 retval = 0;

    if (!obj)
        return;

    port_map = bpf_object__find_map_by_name(obj, "rs_port_config_map");
    RS_ASSERT(port_map != NULL);
    if (!port_map) {
        bpf_object__close(obj);
        return;
    }

    memset(&cfg, 0, sizeof(cfg));
    cfg.ifindex = key;
    cfg.enabled = 1;
    cfg.mgmt_type = 1;
    cfg.vlan_mode = RS_VLAN_MODE_OFF;
    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(port_map), &key, &cfg, BPF_ANY));

    build_ipv4_tcp_pkt(&pkt, 0xc0a80101U, 0xc0a80102U, 1000, 443, 0);
    RS_ASSERT_OK(run_dispatcher(prog, &pkt, sizeof(pkt), key, &retval));
    RS_ASSERT_EQ(retval, XDP_DROP);

    bpf_object__close(obj);
}

RS_TEST(test_managed_arp_tailcall_fail_drop)
{
    struct bpf_program *prog = NULL;
    struct bpf_object *obj = open_dispatcher_obj(&prog);
    struct test_pkt_arp pkt;
    struct bpf_map *port_map;
    struct rs_port_config cfg;
    __u32 key = 8;
    __u32 retval = 0;

    if (!obj)
        return;

    port_map = bpf_object__find_map_by_name(obj, "rs_port_config_map");
    RS_ASSERT(port_map != NULL);
    if (!port_map) {
        bpf_object__close(obj);
        return;
    }

    memset(&cfg, 0, sizeof(cfg));
    cfg.ifindex = key;
    cfg.enabled = 1;
    cfg.mgmt_type = 1;
    cfg.vlan_mode = RS_VLAN_MODE_OFF;
    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(port_map), &key, &cfg, BPF_ANY));

    build_arp_pkt(&pkt, 0xc0a80101U, 0xc0a80164U);
    RS_ASSERT_OK(run_dispatcher(prog, &pkt, sizeof(pkt), key, &retval));
    RS_ASSERT_EQ(retval, XDP_DROP);

    bpf_object__close(obj);
}

RS_TEST(test_too_short_packet_drop)
{
    struct bpf_program *prog = NULL;
    struct bpf_object *obj = open_dispatcher_obj(&prog);
    unsigned char short_pkt[10] = {0};
    struct bpf_map *port_map;
    struct rs_port_config cfg;
    __u32 key = 9;
    __u32 retval = 0;

    if (!obj)
        return;

    port_map = bpf_object__find_map_by_name(obj, "rs_port_config_map");
    RS_ASSERT(port_map != NULL);
    if (!port_map) {
        bpf_object__close(obj);
        return;
    }

    memset(&cfg, 0, sizeof(cfg));
    cfg.ifindex = key;
    cfg.enabled = 1;
    cfg.mgmt_type = 1;
    cfg.vlan_mode = RS_VLAN_MODE_OFF;
    RS_ASSERT_OK(bpf_map_update_elem(bpf_map__fd(port_map), &key, &cfg, BPF_ANY));

    RS_ASSERT_OK(run_dispatcher(prog, short_pkt, sizeof(short_pkt), key, &retval));
    RS_ASSERT_EQ(retval, XDP_DROP);

    bpf_object__close(obj);
}

RS_TEST_SUITE_BEGIN()
    ;
    if (argc < 2) {
        printf("Usage: %s <path_to_dispatcher.bpf.o>\n", argv[0]);
        return 1;
    }

    g_obj_path = argv[1];
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    RS_RUN_TEST(test_unmanaged_port_returns_pass);
    RS_RUN_TEST(test_managed_ipv4_tcp_tailcall_fail_drop);
    RS_RUN_TEST(test_managed_arp_tailcall_fail_drop);
    RS_RUN_TEST(test_too_short_packet_drop);

RS_TEST_SUITE_END()
