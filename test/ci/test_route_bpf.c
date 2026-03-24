// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * BPF_PROG_TEST_RUN tests for the rSwitch route module.
 *
 * Tests:
 *   1. Routing disabled: packet passes through (tail-call fails -> XDP_PASS)
 *   2. Non-IPv4 packet: passes through
 *   3. TTL=1 packet: dropped (TTL exceeded)
 *   4. No route match: dropped (no forwarding entry)
 *
 * The route module uses multiple maps: route_tbl (LPM), arp_tbl,
 * iface_cfg, route_cfg, route_stats. We set up the minimum needed
 * for each test scenario.
 */

#include <arpa/inet.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <string.h>

#include "../unit/rs_test.h"
#include "../unit/test_packets.h"

/* Route config - mirrors route.bpf.c struct route_config */
struct route_config {
    __u8 enabled;
    __u8 pad[3];
};

/* Interface config - mirrors route.bpf.c struct iface_config */
struct iface_config {
    __u8 mac[6];
    __u16 pad;
    __u8 is_router;
    __u8 pad2[3];
};

/* LPM key for route table */
struct lpm_key {
    __u32 prefixlen;
    __be32 addr;
};

/* Route entry */
struct route_entry {
    __be32 nexthop;
    __u32 ifindex;
    __u32 metric;
    __u8 type;
    __u8 pad[3];
    __u32 ecmp_group_id;
};

/* ARP entry */
struct arp_entry {
    __u8 mac[6];
    __u16 pad;
    __u32 ifindex;
    __u64 timestamp;
};

static const char *g_obj_path;

/*
 * Helper: Set up rs_ctx_map with parsed IPv4 context.
 */
static int setup_ipv4_ctx(struct rs_test_ctx *ctx, __u32 ifindex,
                          const char *sip, const char *dip)
{
    struct rs_ctx setup;
    struct in_addr saddr, daddr;
    __u32 key = 0;

    if (inet_pton(AF_INET, sip, &saddr) != 1)
        return -1;
    if (inet_pton(AF_INET, dip, &daddr) != 1)
        return -1;

    memset(&setup, 0, sizeof(setup));
    setup.parsed = 1;
    setup.ifindex = ifindex;
    setup.action = 2;  /* XDP_PASS default */
    setup.layers.eth_proto = 0x0800;  /* ETH_P_IP */
    setup.layers.ip_proto = 6;  /* TCP */
    setup.layers.saddr = saddr.s_addr;
    setup.layers.daddr = daddr.s_addr;
    setup.layers.l3_offset = sizeof(struct test_eth_hdr);
    setup.layers.l4_offset = sizeof(struct test_eth_hdr) + sizeof(struct test_ipv4_hdr);

    return rs_test_map_insert(ctx, "rs_ctx_map", &key, &setup);
}

/*
 * Helper: Enable routing.
 */
static int enable_routing(struct rs_test_ctx *ctx)
{
    struct route_config cfg;
    __u32 key = 0;

    memset(&cfg, 0, sizeof(cfg));
    cfg.enabled = 1;

    return rs_test_map_insert(ctx, "route_cfg", &key, &cfg);
}

/*
 * Helper: Configure interface as router with given MAC.
 */
static int setup_iface(struct rs_test_ctx *ctx, __u32 ifindex,
                       const __u8 mac[6], __u8 is_router)
{
    struct iface_config cfg;

    memset(&cfg, 0, sizeof(cfg));
    memcpy(cfg.mac, mac, 6);
    cfg.is_router = is_router;

    return rs_test_map_insert(ctx, "iface_cfg", &ifindex, &cfg);
}

/*
 * Test: Routing disabled -> passes through (returns XDP_PASS on tail-call failure).
 * route_cfg.enabled = 0 -> RS_TAIL_CALL_NEXT -> tail-call fails -> XDP_PASS.
 */
RS_TEST(test_route_disabled_passes)
{
    struct rs_test_ctx *ctx;
    struct rs_test_pkt *pkt;
    __u32 retval = 0;

    ctx = rs_test_open(g_obj_path);
    RS_ASSERT_TRUE(ctx != NULL);
    if (!ctx)
        return;

    /* Don't enable routing - leave route_cfg at defaults (enabled=0) */
    RS_ASSERT_OK(setup_ipv4_ctx(ctx, 1, "10.0.0.1", "10.0.0.2"));

    pkt = rs_test_pkt_tcp("10.0.0.1", "10.0.0.2", 12345, 80, 0x02);
    RS_ASSERT_TRUE(pkt != NULL);
    if (!pkt) {
        rs_test_close(ctx);
        return;
    }

    RS_ASSERT_OK(rs_test_run(ctx, "route_ipv4", pkt->data, pkt->len, NULL, &retval));
    /* Routing disabled -> RS_TAIL_CALL_NEXT -> fails -> XDP_PASS */
    RS_ASSERT_ACTION(retval, XDP_PASS);

    rs_test_pkt_free(pkt);
    rs_test_close(ctx);
}

/*
 * Test: Non-router destination MAC -> packet passes through (not for router).
 * Even with routing enabled, if dest MAC doesn't match any router iface,
 * packet is forwarded at L2.
 */
RS_TEST(test_route_not_for_router_passes)
{
    struct rs_test_ctx *ctx;
    struct rs_test_pkt *pkt;
    __u32 retval = 0;

    ctx = rs_test_open(g_obj_path);
    RS_ASSERT_TRUE(ctx != NULL);
    if (!ctx)
        return;

    RS_ASSERT_OK(enable_routing(ctx));
    RS_ASSERT_OK(setup_ipv4_ctx(ctx, 1, "10.0.0.1", "10.0.0.2"));

    /* Don't set up any router interface -> is_for_router returns 0 */

    pkt = rs_test_pkt_tcp("10.0.0.1", "10.0.0.2", 12345, 80, 0x02);
    RS_ASSERT_TRUE(pkt != NULL);
    if (!pkt) {
        rs_test_close(ctx);
        return;
    }

    RS_ASSERT_OK(rs_test_run(ctx, "route_ipv4", pkt->data, pkt->len, NULL, &retval));
    /* Not for router -> RS_TAIL_CALL_NEXT -> fails -> XDP_PASS */
    RS_ASSERT_ACTION(retval, XDP_PASS);

    rs_test_pkt_free(pkt);
    rs_test_close(ctx);
}

/*
 * Test: TTL=1 packet -> XDP_DROP (TTL exceeded).
 * We need routing enabled, dest MAC matching a router iface, and TTL=1.
 *
 * Note: Building a TTL=1 packet requires constructing raw bytes because
 * rs_test_pkt_tcp uses TTL=64. We modify the packet after construction.
 */
RS_TEST(test_route_ttl_exceeded_drops)
{
    struct rs_test_ctx *ctx;
    struct rs_test_pkt *pkt;
    struct test_pkt_ipv4_tcp *raw;
    __u8 router_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    __u32 retval = 0;

    ctx = rs_test_open(g_obj_path);
    RS_ASSERT_TRUE(ctx != NULL);
    if (!ctx)
        return;

    RS_ASSERT_OK(enable_routing(ctx));
    RS_ASSERT_OK(setup_ipv4_ctx(ctx, 1, "10.0.0.1", "10.0.0.2"));

    /* Set up router interface 0 with broadcast MAC so default test packets match.
     * The test packet helper uses dst MAC ff:ff:ff:ff:ff:ff by default. */
    RS_ASSERT_OK(setup_iface(ctx, 0, router_mac, 1));

    pkt = rs_test_pkt_tcp("10.0.0.1", "10.0.0.2", 12345, 80, 0x02);
    RS_ASSERT_TRUE(pkt != NULL);
    if (!pkt) {
        rs_test_close(ctx);
        return;
    }

    /* Modify TTL to 1 */
    raw = (struct test_pkt_ipv4_tcp *)pkt->data;
    raw->ip.ttl = 1;

    RS_ASSERT_OK(rs_test_run(ctx, "route_ipv4", pkt->data, pkt->len, NULL, &retval));
    RS_ASSERT_ACTION(retval, XDP_DROP);

    rs_test_pkt_free(pkt);
    rs_test_close(ctx);
}

/*
 * Test: No route found -> XDP_DROP.
 * Routing enabled, dest MAC matches router, TTL > 1, but no route in LPM trie.
 */
RS_TEST(test_route_no_route_drops)
{
    struct rs_test_ctx *ctx;
    struct rs_test_pkt *pkt;
    __u8 router_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    __u32 retval = 0;

    ctx = rs_test_open(g_obj_path);
    RS_ASSERT_TRUE(ctx != NULL);
    if (!ctx)
        return;

    RS_ASSERT_OK(enable_routing(ctx));
    RS_ASSERT_OK(setup_ipv4_ctx(ctx, 1, "10.0.0.1", "10.0.0.2"));
    RS_ASSERT_OK(setup_iface(ctx, 0, router_mac, 1));

    /* Don't insert any route -> route_tbl lookup will miss */

    pkt = rs_test_pkt_tcp("10.0.0.1", "10.0.0.2", 12345, 80, 0x02);
    RS_ASSERT_TRUE(pkt != NULL);
    if (!pkt) {
        rs_test_close(ctx);
        return;
    }

    RS_ASSERT_OK(rs_test_run(ctx, "route_ipv4", pkt->data, pkt->len, NULL, &retval));
    RS_ASSERT_ACTION(retval, XDP_DROP);

    rs_test_pkt_free(pkt);
    rs_test_close(ctx);
}

RS_TEST_SUITE_BEGIN()
    ;
    if (argc < 2) {
        printf("Usage: %s <path_to_route.bpf.o> [junit.xml]\n", argv[0]);
        return 1;
    }

    g_obj_path = argv[1];
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    RS_RUN_TEST(test_route_disabled_passes);
    RS_RUN_TEST(test_route_not_for_router_passes);
    RS_RUN_TEST(test_route_ttl_exceeded_drops);
    RS_RUN_TEST(test_route_no_route_drops);

    if (argc > 2)
        rs_test_report_junit(argv[2]);

RS_TEST_SUITE_END()
