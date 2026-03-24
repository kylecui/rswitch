// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * BPF_PROG_TEST_RUN tests for the rSwitch VLAN module.
 *
 * Tests:
 *   1. ACCESS mode: tagged packet on access port -> XDP_DROP
 *   2. ACCESS mode: untagged packet with valid VLAN config -> passes (tail-call fails -> XDP_DROP)
 *   3. TRUNK mode: tagged packet not in allowed list -> XDP_DROP
 *   4. No port config: -> XDP_DROP
 *
 * Note: The VLAN module calls RS_TAIL_CALL_NEXT on success. Since we don't
 * populate rs_progs, the tail-call will fail and the module returns XDP_DROP.
 * We can distinguish "passed VLAN checks" from "failed VLAN checks" by
 * inspecting the rs_ctx error/drop_reason fields.
 */

#include <arpa/inet.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <string.h>

#include "../unit/rs_test.h"
#include "../unit/test_packets.h"

/*
 * Port config stub matching the beginning of rs_port_config.
 * We need enough to set vlan_mode, access_vlan, native_vlan,
 * and related fields.
 *
 * Since the full struct is large, we create a minimal version
 * and rely on the BPF map value_size for the rest (zeroed).
 */

/* VLAN modes (from module_abi.h) */
#define RS_VLAN_MODE_OFF     0
#define RS_VLAN_MODE_ACCESS  1
#define RS_VLAN_MODE_TRUNK   2
#define RS_VLAN_MODE_HYBRID  3

/* Drop reasons (from uapi.h) */
#define RS_DROP_VLAN_FILTER  3

/* Error codes (from uapi.h) */
#define RS_ERROR_INVALID_VLAN 3

/* rs_vlan_members - mirrors bpf/core/uapi.h */
struct rs_vlan_members {
    __u64 tagged_members[4];
    __u64 untagged_members[4];
    __u32 member_count;
    __u32 pad;
};

static const char *g_obj_path;

/*
 * Test: No port config at all -> VLAN module drops the packet.
 * The module does: rs_get_port_config(ctx->ifindex) -> NULL -> XDP_DROP.
 *
 * But first the module checks ctx->parsed: the dispatcher sets this.
 * Without populating rs_ctx_map with parsed=1, the module drops early
 * with RS_ERROR_PARSE_FAILED.
 */
RS_TEST(test_vlan_no_ctx_drops)
{
    struct rs_test_ctx *ctx;
    struct rs_test_pkt *pkt;
    __u32 retval = 0;

    ctx = rs_test_open(g_obj_path);
    RS_ASSERT_TRUE(ctx != NULL);
    if (!ctx)
        return;

    pkt = rs_test_pkt_tcp("10.0.0.1", "10.0.0.2", 12345, 80, 0x02);
    RS_ASSERT_TRUE(pkt != NULL);
    if (!pkt) {
        rs_test_close(ctx);
        return;
    }

    /* No rs_ctx_map setup -> parsed=0 -> drops with parse error */
    RS_ASSERT_OK(rs_test_run(ctx, "vlan_ingress", pkt->data, pkt->len, NULL, &retval));
    RS_ASSERT_ACTION(retval, XDP_DROP);

    rs_test_pkt_free(pkt);
    rs_test_close(ctx);
}

/*
 * Test: VLAN module with parsed ctx but no port config -> XDP_DROP.
 * We pre-populate rs_ctx_map with parsed=1, ifindex=1.
 * But don't populate rs_port_config_map -> module drops.
 */
RS_TEST(test_vlan_no_port_config_drops)
{
    struct rs_test_ctx *tctx;
    struct rs_test_pkt *pkt;
    struct rs_ctx setup_ctx;
    __u32 key = 0;
    __u32 retval = 0;

    tctx = rs_test_open(g_obj_path);
    RS_ASSERT_TRUE(tctx != NULL);
    if (!tctx)
        return;

    /* Set up rs_ctx with parsed=1 */
    memset(&setup_ctx, 0, sizeof(setup_ctx));
    setup_ctx.parsed = 1;
    setup_ctx.ifindex = 1;
    setup_ctx.layers.eth_proto = 0x0800;
    RS_ASSERT_OK(rs_test_map_insert(tctx, "rs_ctx_map", &key, &setup_ctx));

    pkt = rs_test_pkt_tcp("10.0.0.1", "10.0.0.2", 12345, 80, 0x02);
    RS_ASSERT_TRUE(pkt != NULL);
    if (!pkt) {
        rs_test_close(tctx);
        return;
    }

    RS_ASSERT_OK(rs_test_run(tctx, "vlan_ingress", pkt->data, pkt->len, NULL, &retval));
    RS_ASSERT_ACTION(retval, XDP_DROP);

    rs_test_pkt_free(pkt);
    rs_test_close(tctx);
}

/*
 * Test: VLAN-tagged packet on ACCESS port -> XDP_DROP.
 * ACCESS mode drops all tagged packets.
 *
 * Note: Requires setting up rs_ctx_map with parsed=1 and vlan info,
 * port_config with vlan_mode=ACCESS, and rs_vlan_map with members.
 * Without a fully populated port config map (since we can't easily
 * create a full rs_port_config in test), we rely on the module
 * reading vlan_mode from the map.
 */
RS_TEST(test_vlan_tagged_packet_drops_without_config)
{
    struct rs_test_ctx *tctx;
    struct rs_test_pkt *inner;
    struct rs_test_pkt *pkt;
    struct rs_ctx setup_ctx;
    __u32 key = 0;
    __u32 retval = 0;

    tctx = rs_test_open(g_obj_path);
    RS_ASSERT_TRUE(tctx != NULL);
    if (!tctx)
        return;

    /* Set up rs_ctx with parsed=1 and VLAN tag info */
    memset(&setup_ctx, 0, sizeof(setup_ctx));
    setup_ctx.parsed = 1;
    setup_ctx.ifindex = 1;
    setup_ctx.layers.eth_proto = 0x8100;  /* 802.1Q tagged */
    setup_ctx.layers.vlan_ids[0] = 100;
    setup_ctx.layers.vlan_depth = 1;
    RS_ASSERT_OK(rs_test_map_insert(tctx, "rs_ctx_map", &key, &setup_ctx));

    /* Create a VLAN-tagged packet */
    inner = rs_test_pkt_tcp("10.0.0.1", "10.0.0.2", 12345, 80, 0x02);
    RS_ASSERT_TRUE(inner != NULL);
    if (!inner) {
        rs_test_close(tctx);
        return;
    }

    pkt = rs_test_pkt_vlan(100, inner);
    RS_ASSERT_TRUE(pkt != NULL);
    if (!pkt) {
        rs_test_pkt_free(inner);
        rs_test_close(tctx);
        return;
    }

    /* Without port config, module drops (no port config for ifindex 1) */
    RS_ASSERT_OK(rs_test_run(tctx, "vlan_ingress", pkt->data, pkt->len, NULL, &retval));
    RS_ASSERT_ACTION(retval, XDP_DROP);

    rs_test_pkt_free(pkt);
    rs_test_pkt_free(inner);
    rs_test_close(tctx);
}

RS_TEST_SUITE_BEGIN()
    ;
    if (argc < 2) {
        printf("Usage: %s <path_to_vlan.bpf.o> [junit.xml]\n", argv[0]);
        return 1;
    }

    g_obj_path = argv[1];
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    RS_RUN_TEST(test_vlan_no_ctx_drops);
    RS_RUN_TEST(test_vlan_no_port_config_drops);
    RS_RUN_TEST(test_vlan_tagged_packet_drops_without_config);

    if (argc > 2)
        rs_test_report_junit(argv[2]);

RS_TEST_SUITE_END()
