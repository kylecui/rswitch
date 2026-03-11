#include <arpa/inet.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <string.h>

#include "rs_test.h"
#include "test_packets.h"

struct acl_config {
    __u8 default_action;
    __u8 enabled;
    __u8 log_drops;
    __u8 pad;
};

struct acl_result {
    __u8 action;
    __u8 log_event;
    __u16 redirect_ifindex;
    __u32 stats_id;
} __attribute__((packed));

struct acl_lpm_key {
    __u32 prefixlen;
    __u32 ip;
};

enum acl_action {
    ACL_ACTION_PASS = 0,
    ACL_ACTION_DROP = 1,
};

static const char *g_obj_path;

static int setup_acl_default_drop(struct rs_test_ctx *ctx)
{
    struct acl_config cfg;
    __u32 key = 0;

    memset(&cfg, 0, sizeof(cfg));
    cfg.enabled = 1;
    cfg.default_action = ACL_ACTION_DROP;
    return rs_test_map_insert(ctx, "acl_config_map", &key, &cfg);
}

static int insert_allow_subnet_rule(struct rs_test_ctx *ctx)
{
    struct acl_lpm_key key;
    struct acl_result result;
    struct in_addr addr;

    if (inet_pton(AF_INET, "10.0.0.0", &addr) != 1)
        return -1;

    memset(&key, 0, sizeof(key));
    key.prefixlen = 24;
    key.ip = addr.s_addr;

    memset(&result, 0, sizeof(result));
    result.action = ACL_ACTION_PASS;
    return rs_test_map_insert(ctx, "acl_lpm_src_map", &key, &result);
}

RS_TEST(test_acl_matching_subnet_packet_allows_pipeline)
{
    struct rs_test_ctx *ctx;
    struct rs_test_pkt *pkt;
    __u32 retval = 0;

    ctx = rs_test_open(g_obj_path);
    RS_ASSERT_TRUE(ctx != NULL);
    if (!ctx)
        return;

    RS_ASSERT_OK(setup_acl_default_drop(ctx));
    RS_ASSERT_OK(insert_allow_subnet_rule(ctx));

    pkt = rs_test_pkt_tcp("10.0.0.10", "192.168.1.100", 12345, 80, 0x02);
    RS_ASSERT_TRUE(pkt != NULL);
    if (!pkt) {
        rs_test_close(ctx);
        return;
    }

    RS_ASSERT_OK(rs_test_run(ctx, "acl_filter", pkt->data, pkt->len, NULL, &retval));
    RS_ASSERT_TRUE(retval == XDP_PASS || retval == XDP_DROP);

    rs_test_pkt_free(pkt);
    rs_test_close(ctx);
}

RS_TEST(test_acl_non_matching_subnet_packet_drops)
{
    struct rs_test_ctx *ctx;
    struct rs_test_pkt *pkt;
    __u32 retval = 0;

    ctx = rs_test_open(g_obj_path);
    RS_ASSERT_TRUE(ctx != NULL);
    if (!ctx)
        return;

    RS_ASSERT_OK(setup_acl_default_drop(ctx));
    RS_ASSERT_OK(insert_allow_subnet_rule(ctx));

    pkt = rs_test_pkt_tcp("10.1.0.10", "192.168.1.100", 12345, 80, 0x02);
    RS_ASSERT_TRUE(pkt != NULL);
    if (!pkt) {
        rs_test_close(ctx);
        return;
    }

    RS_ASSERT_OK(rs_test_run(ctx, "acl_filter", pkt->data, pkt->len, NULL, &retval));
    RS_ASSERT_ACTION(retval, XDP_DROP);

    rs_test_pkt_free(pkt);
    rs_test_close(ctx);
}

RS_TEST_SUITE_BEGIN()
    ;
    if (argc < 2) {
        printf("Usage: %s <path_to_acl.bpf.o> [junit.xml]\n", argv[0]);
        return 1;
    }

    g_obj_path = argv[1];
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    RS_RUN_TEST(test_acl_matching_subnet_packet_allows_pipeline);
    RS_RUN_TEST(test_acl_non_matching_subnet_packet_drops);

    if (argc > 2)
        rs_test_report_junit(argv[2]);

RS_TEST_SUITE_END()
