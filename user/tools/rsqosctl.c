// SPDX-License-Identifier: GPL-2.0

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if __has_include("rs_log.h")
#include "rs_log.h"
#else
#include "../common/rs_log.h"
#endif

#define PIN_BASE_DIR "/sys/fs/bpf"

struct qos_port_key {
    __u8 proto;
    __u8 pad;
    __be16 port;
} __attribute__((packed));

struct qos_subnet_key {
    __u32 prefixlen;
    __be32 addr;
};

struct qos_cls_config {
    __u8 enabled;
    __u8 default_class;
    __u8 pad[2];
};

static int open_pinned_map(const char *map_name)
{
    char path[256];

    snprintf(path, sizeof(path), "%s/%s", PIN_BASE_DIR, map_name);
    return bpf_obj_get(path);
}

static int parse_u32(const char *s, __u32 *out)
{
    char *end = NULL;
    unsigned long v;

    errno = 0;
    v = strtoul(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0' || v > UINT32_MAX)
        return -1;

    *out = (__u32)v;
    return 0;
}

static int parse_u16(const char *s, __u16 *out)
{
    __u32 v;

    if (parse_u32(s, &v) < 0 || v > UINT16_MAX)
        return -1;

    *out = (__u16)v;
    return 0;
}

static int parse_u8(const char *s, __u8 max, __u8 *out)
{
    __u32 v;

    if (parse_u32(s, &v) < 0 || v > max)
        return -1;

    *out = (__u8)v;
    return 0;
}

static int parse_protocol(const char *proto_str, __u8 *proto)
{
    if (strcasecmp(proto_str, "tcp") == 0) {
        *proto = IPPROTO_TCP;
        return 0;
    }
    if (strcasecmp(proto_str, "udp") == 0) {
        *proto = IPPROTO_UDP;
        return 0;
    }
    if (strcasecmp(proto_str, "icmp") == 0) {
        *proto = IPPROTO_ICMP;
        return 0;
    }

    return parse_u8(proto_str, 255, proto);
}

static int parse_subnet(const char *input, struct qos_subnet_key *key)
{
    const char *slash = strchr(input, '/');
    char ip_str[INET_ADDRSTRLEN];
    size_t ip_len;
    __u32 prefixlen;
    struct in_addr ip;

    if (!slash)
        return -1;

    ip_len = (size_t)(slash - input);
    if (ip_len == 0 || ip_len >= sizeof(ip_str))
        return -1;

    memcpy(ip_str, input, ip_len);
    ip_str[ip_len] = '\0';

    if (parse_u32(slash + 1, &prefixlen) < 0 || prefixlen > 32)
        return -1;

    if (inet_pton(AF_INET, ip_str, &ip) != 1)
        return -1;

    key->prefixlen = prefixlen;
    key->addr = ip.s_addr;
    return 0;
}

static int cmd_add_dscp_rule(int argc, char **argv)
{
    int fd;
    __u8 dscp;
    __u8 traffic_class;
    __u32 key;

    if (argc != 4) {
        RS_LOG_ERROR("Usage: rsqosctl add-dscp-rule <dscp> <traffic_class>");
        return 1;
    }

    if (parse_u8(argv[2], 63, &dscp) < 0 || parse_u8(argv[3], 7, &traffic_class) < 0) {
        RS_LOG_ERROR("Invalid arguments: dscp must be 0-63, traffic_class must be 0-7");
        return 1;
    }

    fd = open_pinned_map("qos_dscp_map");
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open qos_dscp_map: %s", strerror(errno));
        return 1;
    }

    key = dscp;
    if (bpf_map_update_elem(fd, &key, &traffic_class, BPF_ANY) < 0) {
        RS_LOG_ERROR("Failed to update qos_dscp_map: %s", strerror(errno));
        close(fd);
        return 1;
    }

    RS_LOG_INFO("Added DSCP rule: dscp=%u -> class=%u", dscp, traffic_class);
    close(fd);
    return 0;
}

static int cmd_add_port_rule(int argc, char **argv)
{
    int fd;
    struct qos_port_key key = {0};
    __u16 port;
    __u8 traffic_class;

    if (argc != 5) {
        RS_LOG_ERROR("Usage: rsqosctl add-port-rule <proto> <port> <traffic_class>");
        return 1;
    }

    if (parse_protocol(argv[2], &key.proto) < 0 || parse_u16(argv[3], &port) < 0 || parse_u8(argv[4], 7, &traffic_class) < 0) {
        RS_LOG_ERROR("Invalid arguments: proto must be tcp/udp/icmp/0-255, port 0-65535, traffic_class 0-7");
        return 1;
    }
    key.port = htons(port);

    fd = open_pinned_map("qos_port_map");
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open qos_port_map: %s", strerror(errno));
        return 1;
    }

    if (bpf_map_update_elem(fd, &key, &traffic_class, BPF_ANY) < 0) {
        RS_LOG_ERROR("Failed to update qos_port_map: %s", strerror(errno));
        close(fd);
        return 1;
    }

    RS_LOG_INFO("Added port rule: proto=%u port=%u -> class=%u", key.proto, port, traffic_class);
    close(fd);
    return 0;
}

static int cmd_add_vlan_rule(int argc, char **argv)
{
    int fd;
    __u16 vlan_id;
    __u8 traffic_class;

    if (argc != 4) {
        RS_LOG_ERROR("Usage: rsqosctl add-vlan-rule <vlan_id> <traffic_class>");
        return 1;
    }

    if (parse_u16(argv[2], &vlan_id) < 0 || parse_u8(argv[3], 7, &traffic_class) < 0) {
        RS_LOG_ERROR("Invalid arguments: vlan_id must be 0-65535, traffic_class must be 0-7");
        return 1;
    }

    fd = open_pinned_map("qos_vlan_map");
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open qos_vlan_map: %s", strerror(errno));
        return 1;
    }

    if (bpf_map_update_elem(fd, &vlan_id, &traffic_class, BPF_ANY) < 0) {
        RS_LOG_ERROR("Failed to update qos_vlan_map: %s", strerror(errno));
        close(fd);
        return 1;
    }

    RS_LOG_INFO("Added VLAN rule: vlan_id=%u -> class=%u", vlan_id, traffic_class);
    close(fd);
    return 0;
}

static int cmd_add_subnet_rule(int argc, char **argv)
{
    int fd;
    struct qos_subnet_key key = {0};
    __u8 traffic_class;

    if (argc != 4) {
        RS_LOG_ERROR("Usage: rsqosctl add-subnet-rule <prefix/len> <traffic_class>");
        return 1;
    }

    if (parse_subnet(argv[2], &key) < 0 || parse_u8(argv[3], 7, &traffic_class) < 0) {
        RS_LOG_ERROR("Invalid arguments: prefix must be IPv4 CIDR and traffic_class must be 0-7");
        return 1;
    }

    fd = open_pinned_map("qos_subnet_map");
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open qos_subnet_map: %s", strerror(errno));
        return 1;
    }

    if (bpf_map_update_elem(fd, &key, &traffic_class, BPF_ANY) < 0) {
        RS_LOG_ERROR("Failed to update qos_subnet_map: %s", strerror(errno));
        close(fd);
        return 1;
    }

    RS_LOG_INFO("Added subnet rule: %s -> class=%u", argv[2], traffic_class);
    close(fd);
    return 0;
}

static int show_dscp_rules(void)
{
    int fd;
    __u32 key;
    __u8 val;

    fd = open_pinned_map("qos_dscp_map");
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open qos_dscp_map: %s", strerror(errno));
        return 1;
    }

    RS_LOG_INFO("DSCP rules:");
    for (key = 0; key < 64; key++) {
        if (bpf_map_lookup_elem(fd, &key, &val) == 0)
            RS_LOG_INFO("  dscp=%u -> class=%u", key, val);
    }

    close(fd);
    return 0;
}

static int show_port_rules(void)
{
    int fd;
    int ret;
    struct qos_port_key cur;
    struct qos_port_key next;
    __u8 val;
    bool have_any = false;

    fd = open_pinned_map("qos_port_map");
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open qos_port_map: %s", strerror(errno));
        return 1;
    }

    RS_LOG_INFO("Port rules:");
    ret = bpf_map_get_next_key(fd, NULL, &next);
    while (ret == 0) {
        if (bpf_map_lookup_elem(fd, &next, &val) == 0) {
            RS_LOG_INFO("  proto=%u port=%u -> class=%u", next.proto, ntohs(next.port), val);
            have_any = true;
        }
        cur = next;
        ret = bpf_map_get_next_key(fd, &cur, &next);
    }
    if (!have_any)
        RS_LOG_INFO("  (none)");

    close(fd);
    return 0;
}

static int show_vlan_rules(void)
{
    int fd;
    int ret;
    __u16 cur;
    __u16 next;
    __u8 val;
    bool have_any = false;

    fd = open_pinned_map("qos_vlan_map");
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open qos_vlan_map: %s", strerror(errno));
        return 1;
    }

    RS_LOG_INFO("VLAN rules:");
    ret = bpf_map_get_next_key(fd, NULL, &next);
    while (ret == 0) {
        if (bpf_map_lookup_elem(fd, &next, &val) == 0) {
            RS_LOG_INFO("  vlan_id=%u -> class=%u", next, val);
            have_any = true;
        }
        cur = next;
        ret = bpf_map_get_next_key(fd, &cur, &next);
    }
    if (!have_any)
        RS_LOG_INFO("  (none)");

    close(fd);
    return 0;
}

static int show_subnet_rules(void)
{
    int fd;
    int ret;
    struct qos_subnet_key cur;
    struct qos_subnet_key next;
    __u8 val;
    char ipbuf[INET_ADDRSTRLEN];
    bool have_any = false;

    fd = open_pinned_map("qos_subnet_map");
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open qos_subnet_map: %s", strerror(errno));
        return 1;
    }

    RS_LOG_INFO("Subnet rules:");
    ret = bpf_map_get_next_key(fd, NULL, &next);
    while (ret == 0) {
        struct in_addr addr = { .s_addr = next.addr };

        if (bpf_map_lookup_elem(fd, &next, &val) == 0) {
            if (!inet_ntop(AF_INET, &addr, ipbuf, sizeof(ipbuf)))
                snprintf(ipbuf, sizeof(ipbuf), "<invalid>");
            RS_LOG_INFO("  %s/%u -> class=%u", ipbuf, next.prefixlen, val);
            have_any = true;
        }
        cur = next;
        ret = bpf_map_get_next_key(fd, &cur, &next);
    }
    if (!have_any)
        RS_LOG_INFO("  (none)");

    close(fd);
    return 0;
}

static int cmd_show_classes(void)
{
    int rc;

    rc = show_dscp_rules();
    if (rc)
        return rc;
    rc = show_port_rules();
    if (rc)
        return rc;
    rc = show_vlan_rules();
    if (rc)
        return rc;
    return show_subnet_rules();
}

static int cmd_show_class_stats(void)
{
    int fd;
    int ncpus;
    void *values;
    __u32 key;

    fd = open_pinned_map("qos_stats_map");
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open qos_stats_map: %s", strerror(errno));
        return 1;
    }

    ncpus = libbpf_num_possible_cpus();
    if (ncpus <= 0) {
        RS_LOG_ERROR("Failed to get CPU count");
        close(fd);
        return 1;
    }

    values = calloc((size_t)ncpus, sizeof(__u64));
    if (!values) {
        RS_LOG_ERROR("Failed to allocate stats buffer");
        close(fd);
        return 1;
    }

    RS_LOG_INFO("QoS class packet counters:");
    for (key = 0; key < 8; key++) {
        int i;
        __u64 sum = 0;

        memset(values, 0, (size_t)ncpus * sizeof(__u64));
        if (bpf_map_lookup_elem(fd, &key, values) == 0) {
            __u64 *percpu = values;
            for (i = 0; i < ncpus; i++)
                sum += percpu[i];
            RS_LOG_INFO("  class=%u packets=%llu", key, (unsigned long long)sum);
        }
    }

    free(values);
    close(fd);
    return 0;
}

static int cmd_set_enabled(bool enabled)
{
    int fd;
    __u32 key = 0;
    struct qos_cls_config cfg = {0};

    fd = open_pinned_map("qos_config_map");
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open qos_config_map: %s", strerror(errno));
        return 1;
    }

    if (bpf_map_lookup_elem(fd, &key, &cfg) < 0) {
        cfg.enabled = 0;
        cfg.default_class = 0;
    }

    cfg.enabled = enabled ? 1 : 0;
    if (bpf_map_update_elem(fd, &key, &cfg, BPF_ANY) < 0) {
        RS_LOG_ERROR("Failed to update qos_config_map: %s", strerror(errno));
        close(fd);
        return 1;
    }

    RS_LOG_INFO("QoS classification %s", enabled ? "enabled" : "disabled");
    close(fd);
    return 0;
}

static void usage(const char *prog)
{
    RS_LOG_INFO("Usage: %s <command> [args]", prog);
    RS_LOG_INFO("Commands:");
    RS_LOG_INFO("  add-dscp-rule <dscp> <traffic_class>");
    RS_LOG_INFO("  add-port-rule <proto> <port> <traffic_class>");
    RS_LOG_INFO("  add-vlan-rule <vlan_id> <traffic_class>");
    RS_LOG_INFO("  add-subnet-rule <prefix/len> <traffic_class>");
    RS_LOG_INFO("  show-classes");
    RS_LOG_INFO("  show-class-stats");
    RS_LOG_INFO("  enable");
    RS_LOG_INFO("  disable");
}

int main(int argc, char **argv)
{
    rs_log_init("rsqosctl", RS_LOG_LEVEL_INFO);

    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "add-dscp-rule") == 0)
        return cmd_add_dscp_rule(argc, argv);
    if (strcmp(argv[1], "add-port-rule") == 0)
        return cmd_add_port_rule(argc, argv);
    if (strcmp(argv[1], "add-vlan-rule") == 0)
        return cmd_add_vlan_rule(argc, argv);
    if (strcmp(argv[1], "add-subnet-rule") == 0)
        return cmd_add_subnet_rule(argc, argv);
    if (strcmp(argv[1], "show-classes") == 0)
        return cmd_show_classes();
    if (strcmp(argv[1], "show-class-stats") == 0)
        return cmd_show_class_stats();
    if (strcmp(argv[1], "enable") == 0)
        return cmd_set_enabled(true);
    if (strcmp(argv[1], "disable") == 0)
        return cmd_set_enabled(false);

    RS_LOG_ERROR("Unknown command: %s", argv[1]);
    usage(argv[0]);
    return 1;
}
