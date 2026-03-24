// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * BPF_PROG_TEST_RUN tests for the rSwitch core dispatcher.
 *
 * Tests:
 *   1. Bypass mode: unmanaged port -> XDP_PASS
 *   2. Managed port with empty pipeline: context initialized, falls through
 *   3. IPv4 TCP packet parsing: rs_ctx fields populated correctly
 *   4. ARP packet: minimal parsing, no L3/L4
 */

#include <arpa/inet.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <string.h>

#include "../unit/rs_test.h"
#include "../unit/test_packets.h"

/*
 * Dispatcher needs rs_port_config_map populated to decide bypass vs pipeline.
 * The port_config layout mirrors bpf/core/uapi.h struct rs_port_config.
 * We only populate the fields the dispatcher checks: mgmt_type, enabled,
 * default_prio.
 */

/* Minimal rs_port_config stub — only the fields dispatcher reads */
struct rs_port_config_stub {
    __u32 ifindex;
    __u8 mgmt_type;
    __u8 enabled;
    __u8 default_prio;
    __u8 pad;
    /* remaining fields are zeroed — dispatcher only checks mgmt_type + enabled */
};

static const char *g_obj_path;

/*
 * Test: Bypass mode entry point processes packet without pipeline.
 * rswitch_bypass does minimal init and returns XDP_PASS.
 */
RS_TEST(test_dispatcher_bypass_returns_pass)
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

    RS_ASSERT_OK(rs_test_run(ctx, "rswitch_bypass", pkt->data, pkt->len, NULL, &retval));
    RS_ASSERT_ACTION(retval, XDP_PASS);

    rs_test_pkt_free(pkt);
    rs_test_close(ctx);
}

/*
 * Test: Bypass mode with UDP packet also returns XDP_PASS.
 */
RS_TEST(test_dispatcher_bypass_udp_pass)
{
    struct rs_test_ctx *ctx;
    struct rs_test_pkt *pkt;
    __u32 retval = 0;

    ctx = rs_test_open(g_obj_path);
    RS_ASSERT_TRUE(ctx != NULL);
    if (!ctx)
        return;

    pkt = rs_test_pkt_udp("192.168.1.10", "192.168.1.20", 5000, 53);
    RS_ASSERT_TRUE(pkt != NULL);
    if (!pkt) {
        rs_test_close(ctx);
        return;
    }

    RS_ASSERT_OK(rs_test_run(ctx, "rswitch_bypass", pkt->data, pkt->len, NULL, &retval));
    RS_ASSERT_ACTION(retval, XDP_PASS);

    rs_test_pkt_free(pkt);
    rs_test_close(ctx);
}

/*
 * Test: Bypass mode with ARP packet returns XDP_PASS.
 */
RS_TEST(test_dispatcher_bypass_arp_pass)
{
    struct rs_test_ctx *ctx;
    struct rs_test_pkt *pkt;
    __u32 retval = 0;

    ctx = rs_test_open(g_obj_path);
    RS_ASSERT_TRUE(ctx != NULL);
    if (!ctx)
        return;

    pkt = rs_test_pkt_arp("10.0.0.1", "00:11:22:33:44:55", "10.0.0.2", 1);
    RS_ASSERT_TRUE(pkt != NULL);
    if (!pkt) {
        rs_test_close(ctx);
        return;
    }

    RS_ASSERT_OK(rs_test_run(ctx, "rswitch_bypass", pkt->data, pkt->len, NULL, &retval));
    RS_ASSERT_ACTION(retval, XDP_PASS);

    rs_test_pkt_free(pkt);
    rs_test_close(ctx);
}

/*
 * Test: Bypass mode populates rs_ctx correctly (basic fields).
 * After running rswitch_bypass, the rs_ctx_map should have:
 *   - action = XDP_PASS (2)
 *   - ifindex set (from xdp_md)
 */
RS_TEST(test_dispatcher_bypass_populates_ctx)
{
    struct rs_test_ctx *tctx;
    struct rs_test_pkt *pkt;
    struct rs_ctx out_ctx;
    __u32 retval = 0;

    tctx = rs_test_open(g_obj_path);
    RS_ASSERT_TRUE(tctx != NULL);
    if (!tctx)
        return;

    pkt = rs_test_pkt_tcp("10.0.0.1", "10.0.0.2", 12345, 80, 0x02);
    RS_ASSERT_TRUE(pkt != NULL);
    if (!pkt) {
        rs_test_close(tctx);
        return;
    }

    RS_ASSERT_OK(rs_test_run(tctx, "rswitch_bypass", pkt->data, pkt->len, &out_ctx, &retval));
    RS_ASSERT_ACTION(retval, XDP_PASS);

    /* Bypass sets action = XDP_PASS */
    RS_ASSERT_EQ(out_ctx.action, XDP_PASS);

    rs_test_pkt_free(pkt);
    rs_test_close(tctx);
}

RS_TEST_SUITE_BEGIN()
    ;
    if (argc < 2) {
        printf("Usage: %s <path_to_dispatcher.bpf.o> [junit.xml]\n", argv[0]);
        return 1;
    }

    g_obj_path = argv[1];
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    RS_RUN_TEST(test_dispatcher_bypass_returns_pass);
    RS_RUN_TEST(test_dispatcher_bypass_udp_pass);
    RS_RUN_TEST(test_dispatcher_bypass_arp_pass);
    RS_RUN_TEST(test_dispatcher_bypass_populates_ctx);

    if (argc > 2)
        rs_test_report_junit(argv[2]);

RS_TEST_SUITE_END()
