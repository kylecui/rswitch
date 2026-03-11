// SPDX-License-Identifier: GPL-2.0

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <getopt.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#if __has_include("rs_log.h")
#include "rs_log.h"
#else
#include "../common/rs_log.h"
#endif

#define PIN_BASE_DIR "/sys/fs/bpf"

#define FLOW_ACTION_FORWARD 0
#define FLOW_ACTION_DROP 1
#define FLOW_ACTION_SET_VLAN 2
#define FLOW_ACTION_SET_DSCP 3
#define FLOW_ACTION_MIRROR 4
#define FLOW_ACTION_CONTROLLER 5

#define FLOW_STAT_MATCHES 0
#define FLOW_STAT_MISSES 1
#define FLOW_STAT_DROPS 2
#define FLOW_STAT_FORWARDS 3
#define FLOW_STAT_MAX 4

struct flow_key {
    __u32 ingress_ifindex;
    __u16 vlan_id;
    __u8 ip_proto;
    __u8 pad;
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
} __attribute__((packed));

struct flow_entry {
    __u16 priority;
    __u8 action;
    __u8 enabled;
    __u32 egress_ifindex;
    __u16 set_vlan_id;
    __u8 set_dscp;
    __u8 mirror;
    __u32 idle_timeout_sec;
    __u32 hard_timeout_sec;
    __u64 created_ns;
    __u64 last_match_ns;
    __u64 match_pkts;
    __u64 match_bytes;
} __attribute__((aligned(8)));

struct flow_config {
    __u8 enabled;
    __u8 default_action;
    __u8 pad[2];
} __attribute__((aligned(8)));

static int open_map(const char *name)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", PIN_BASE_DIR, name);
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

static int parse_ip_any(const char *s, __be32 *out)
{
    if (!s || strcmp(s, "any") == 0 || strcmp(s, "0") == 0 || strcmp(s, "0.0.0.0") == 0) {
        *out = 0;
        return 0;
    }
    return inet_pton(AF_INET, s, out) == 1 ? 0 : -1;
}

static int parse_port_any(const char *s, __be16 *out)
{
    __u16 port;

    if (!s || strcmp(s, "any") == 0 || strcmp(s, "0") == 0) {
        *out = 0;
        return 0;
    }
    if (parse_u16(s, &port) < 0)
        return -1;
    *out = htons(port);
    return 0;
}

static int parse_vlan_any(const char *s, __u16 *out)
{
    if (!s || strcmp(s, "any") == 0 || strcmp(s, "0") == 0) {
        *out = 0;
        return 0;
    }
    return parse_u16(s, out);
}

static int parse_proto(const char *s, __u8 *out)
{
    __u32 v;

    if (!s || strcmp(s, "any") == 0 || strcmp(s, "0") == 0) {
        *out = 0;
        return 0;
    }
    if (strcasecmp(s, "tcp") == 0) {
        *out = IPPROTO_TCP;
        return 0;
    }
    if (strcasecmp(s, "udp") == 0) {
        *out = IPPROTO_UDP;
        return 0;
    }
    if (strcasecmp(s, "icmp") == 0) {
        *out = IPPROTO_ICMP;
        return 0;
    }
    if (parse_u32(s, &v) < 0 || v > 255)
        return -1;
    *out = (__u8)v;
    return 0;
}

static int parse_ifindex_any(const char *s, __u32 *out)
{
    __u32 idx;
    unsigned int ifidx;

    if (!s || strcmp(s, "any") == 0 || strcmp(s, "0") == 0) {
        *out = 0;
        return 0;
    }
    if (parse_u32(s, &idx) == 0) {
        *out = idx;
        return 0;
    }
    ifidx = if_nametoindex(s);
    if (ifidx == 0)
        return -1;
    *out = ifidx;
    return 0;
}

static int parse_action(const char *s, __u8 *out)
{
    if (strcasecmp(s, "forward") == 0) {
        *out = FLOW_ACTION_FORWARD;
        return 0;
    }
    if (strcasecmp(s, "drop") == 0) {
        *out = FLOW_ACTION_DROP;
        return 0;
    }
    if (strcasecmp(s, "set-vlan") == 0) {
        *out = FLOW_ACTION_SET_VLAN;
        return 0;
    }
    if (strcasecmp(s, "set-dscp") == 0) {
        *out = FLOW_ACTION_SET_DSCP;
        return 0;
    }
    if (strcasecmp(s, "mirror") == 0) {
        *out = FLOW_ACTION_MIRROR;
        return 0;
    }
    if (strcasecmp(s, "controller") == 0) {
        *out = FLOW_ACTION_CONTROLLER;
        return 0;
    }
    return -1;
}

static __u64 monotonic_ns(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0)
        return 0;
    return (__u64)ts.tv_sec * 1000000000ULL + (__u64)ts.tv_nsec;
}

static const char *action_name(__u8 action)
{
    switch (action) {
    case FLOW_ACTION_FORWARD:
        return "forward";
    case FLOW_ACTION_DROP:
        return "drop";
    case FLOW_ACTION_SET_VLAN:
        return "set-vlan";
    case FLOW_ACTION_SET_DSCP:
        return "set-dscp";
    case FLOW_ACTION_MIRROR:
        return "mirror";
    case FLOW_ACTION_CONTROLLER:
        return "controller";
    default:
        return "unknown";
    }
}

static void format_ip(__be32 ip, char *buf, size_t len)
{
    if (ip == 0) {
        snprintf(buf, len, "*");
        return;
    }
    if (!inet_ntop(AF_INET, &ip, buf, len))
        snprintf(buf, len, "<invalid>");
}

static int cmd_add(int argc, char **argv)
{
    struct flow_key key = {0};
    struct flow_entry entry = {0};
    __be32 src_ip_v = 0, dst_ip_v = 0;
    __be16 src_port_v = 0, dst_port_v = 0;
    __u8 proto_v = 0;
    __u16 vlan_v = 0;
    __u32 ingress_v = 0;
    char *src_ip = NULL, *dst_ip = NULL, *src_port = NULL, *dst_port = NULL;
    char *proto = NULL, *vlan = NULL, *ingress = NULL, *action = NULL;
    char *egress = NULL, *set_vlan = NULL, *set_dscp = NULL;
    char *priority = NULL, *idle_timeout = NULL, *hard_timeout = NULL;
    int fd;

    struct option opts[] = {
        {"src-ip", required_argument, 0, 's'},
        {"dst-ip", required_argument, 0, 'd'},
        {"src-port", required_argument, 0, 'S'},
        {"dst-port", required_argument, 0, 'D'},
        {"proto", required_argument, 0, 'p'},
        {"vlan", required_argument, 0, 'v'},
        {"ingress", required_argument, 0, 'i'},
        {"action", required_argument, 0, 'a'},
        {"priority", required_argument, 0, 'P'},
        {"egress", required_argument, 0, 'e'},
        {"set-vlan", required_argument, 0, 'V'},
        {"set-dscp", required_argument, 0, 'T'},
        {"idle-timeout", required_argument, 0, 'I'},
        {"hard-timeout", required_argument, 0, 'H'},
        {0, 0, 0, 0}
    };

    optind = 1;
    for (;;) {
        int c = getopt_long(argc, argv, "", opts, NULL);
        if (c == -1)
            break;
        switch (c) {
        case 's': src_ip = optarg; break;
        case 'd': dst_ip = optarg; break;
        case 'S': src_port = optarg; break;
        case 'D': dst_port = optarg; break;
        case 'p': proto = optarg; break;
        case 'v': vlan = optarg; break;
        case 'i': ingress = optarg; break;
        case 'a': action = optarg; break;
        case 'P': priority = optarg; break;
        case 'e': egress = optarg; break;
        case 'V': set_vlan = optarg; break;
        case 'T': set_dscp = optarg; break;
        case 'I': idle_timeout = optarg; break;
        case 'H': hard_timeout = optarg; break;
        default:
            RS_LOG_ERROR("Invalid arguments for add");
            return 1;
        }
    }

    if (!action || !priority) {
        RS_LOG_ERROR("add requires --action and --priority");
        return 1;
    }
    if (parse_ip_any(src_ip, &src_ip_v) < 0 || parse_ip_any(dst_ip, &dst_ip_v) < 0 ||
        parse_port_any(src_port, &src_port_v) < 0 || parse_port_any(dst_port, &dst_port_v) < 0 ||
        parse_proto(proto, &proto_v) < 0 || parse_vlan_any(vlan, &vlan_v) < 0 ||
        parse_ifindex_any(ingress, &ingress_v) < 0) {
        RS_LOG_ERROR("Invalid flow match parameters");
        return 1;
    }
    key.src_ip = src_ip_v;
    key.dst_ip = dst_ip_v;
    key.src_port = src_port_v;
    key.dst_port = dst_port_v;
    key.ip_proto = proto_v;
    key.vlan_id = vlan_v;
    key.ingress_ifindex = ingress_v;
    if (parse_action(action, &entry.action) < 0) {
        RS_LOG_ERROR("Invalid action: %s", action);
        return 1;
    }

    {
        __u16 p;
        if (parse_u16(priority, &p) < 0) {
            RS_LOG_ERROR("Invalid --priority");
            return 1;
        }
        entry.priority = p;
    }

    if (egress && parse_ifindex_any(egress, &entry.egress_ifindex) < 0) {
        RS_LOG_ERROR("Invalid --egress value: %s", egress);
        return 1;
    }
    if (set_vlan && parse_u16(set_vlan, &entry.set_vlan_id) < 0) {
        RS_LOG_ERROR("Invalid --set-vlan value: %s", set_vlan);
        return 1;
    }
    if (set_dscp) {
        __u32 d;
        if (parse_u32(set_dscp, &d) < 0 || d > 63) {
            RS_LOG_ERROR("Invalid --set-dscp value: %s", set_dscp);
            return 1;
        }
        entry.set_dscp = (__u8)d;
    }
    if (idle_timeout && parse_u32(idle_timeout, &entry.idle_timeout_sec) < 0) {
        RS_LOG_ERROR("Invalid --idle-timeout value: %s", idle_timeout);
        return 1;
    }
    if (hard_timeout && parse_u32(hard_timeout, &entry.hard_timeout_sec) < 0) {
        RS_LOG_ERROR("Invalid --hard-timeout value: %s", hard_timeout);
        return 1;
    }

    entry.enabled = 1;
    entry.mirror = entry.action == FLOW_ACTION_MIRROR ? 1 : 0;
    entry.created_ns = monotonic_ns();
    entry.last_match_ns = entry.created_ns;

    if (entry.action == FLOW_ACTION_FORWARD && entry.egress_ifindex == 0) {
        RS_LOG_ERROR("forward action requires --egress <ifname|ifindex>");
        return 1;
    }
    if (entry.action == FLOW_ACTION_SET_VLAN && !set_vlan) {
        RS_LOG_ERROR("set-vlan action requires --set-vlan <id>");
        return 1;
    }
    if (entry.action == FLOW_ACTION_SET_DSCP && !set_dscp) {
        RS_LOG_ERROR("set-dscp action requires --set-dscp <val>");
        return 1;
    }
    if (entry.action == FLOW_ACTION_MIRROR && entry.egress_ifindex == 0) {
        RS_LOG_ERROR("mirror action requires --egress <ifname|ifindex>");
        return 1;
    }

    fd = open_map("flow_table_map");
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open flow_table_map: %s", strerror(errno));
        return 1;
    }

    if (bpf_map_update_elem(fd, &key, &entry, BPF_ANY) < 0) {
        RS_LOG_ERROR("Failed to add flow: %s", strerror(errno));
        close(fd);
        return 1;
    }

    RS_LOG_INFO("Flow added: action=%s priority=%u", action_name(entry.action), entry.priority);
    close(fd);
    return 0;
}

static int cmd_del(int argc, char **argv)
{
    struct flow_key key = {0};
    __be32 src_ip_v = 0, dst_ip_v = 0;
    __be16 src_port_v = 0, dst_port_v = 0;
    __u8 proto_v = 0;
    __u16 vlan_v = 0;
    __u32 ingress_v = 0;
    char *src_ip = NULL, *dst_ip = NULL, *src_port = NULL, *dst_port = NULL;
    char *proto = NULL, *vlan = NULL, *ingress = NULL;
    int fd;

    struct option opts[] = {
        {"src-ip", required_argument, 0, 's'},
        {"dst-ip", required_argument, 0, 'd'},
        {"src-port", required_argument, 0, 'S'},
        {"dst-port", required_argument, 0, 'D'},
        {"proto", required_argument, 0, 'p'},
        {"vlan", required_argument, 0, 'v'},
        {"ingress", required_argument, 0, 'i'},
        {0, 0, 0, 0}
    };

    optind = 1;
    for (;;) {
        int c = getopt_long(argc, argv, "", opts, NULL);
        if (c == -1)
            break;
        switch (c) {
        case 's': src_ip = optarg; break;
        case 'd': dst_ip = optarg; break;
        case 'S': src_port = optarg; break;
        case 'D': dst_port = optarg; break;
        case 'p': proto = optarg; break;
        case 'v': vlan = optarg; break;
        case 'i': ingress = optarg; break;
        default:
            RS_LOG_ERROR("Invalid arguments for del");
            return 1;
        }
    }

    if (parse_ip_any(src_ip, &src_ip_v) < 0 || parse_ip_any(dst_ip, &dst_ip_v) < 0 ||
        parse_port_any(src_port, &src_port_v) < 0 || parse_port_any(dst_port, &dst_port_v) < 0 ||
        parse_proto(proto, &proto_v) < 0 || parse_vlan_any(vlan, &vlan_v) < 0 ||
        parse_ifindex_any(ingress, &ingress_v) < 0) {
        RS_LOG_ERROR("Invalid flow key parameters");
        return 1;
    }
    key.src_ip = src_ip_v;
    key.dst_ip = dst_ip_v;
    key.src_port = src_port_v;
    key.dst_port = dst_port_v;
    key.ip_proto = proto_v;
    key.vlan_id = vlan_v;
    key.ingress_ifindex = ingress_v;

    fd = open_map("flow_table_map");
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open flow_table_map: %s", strerror(errno));
        return 1;
    }

    if (bpf_map_delete_elem(fd, &key) < 0) {
        RS_LOG_ERROR("Failed to delete flow: %s", strerror(errno));
        close(fd);
        return 1;
    }

    RS_LOG_INFO("Flow deleted");
    close(fd);
    return 0;
}

static int cmd_show(void)
{
    int fd = open_map("flow_table_map");
    struct flow_key key;
    struct flow_key next;
    struct flow_entry entry;
    int ret;
    bool first = true;
    int count = 0;

    if (fd < 0) {
        RS_LOG_ERROR("Failed to open flow_table_map: %s", strerror(errno));
        return 1;
    }

    printf("Flow table:\n");
    printf("--------------------------------------------------------------------------------\n");
    printf("%-21s %-21s %-8s %-6s %-8s %-10s %-6s %-10s\n",
           "src", "dst", "proto", "vlan", "ingress", "action", "prio", "pkts");
    printf("--------------------------------------------------------------------------------\n");

    ret = bpf_map_get_next_key(fd, NULL, &next);
    while (ret == 0) {
        char src[INET_ADDRSTRLEN];
        char dst[INET_ADDRSTRLEN];
        char src_ep[64];
        char dst_ep[64];
        const char *proto_name;

        if (bpf_map_lookup_elem(fd, &next, &entry) == 0) {
            format_ip(next.src_ip, src, sizeof(src));
            format_ip(next.dst_ip, dst, sizeof(dst));

            if (next.src_port == 0)
                snprintf(src_ep, sizeof(src_ep), "%s:*", src);
            else
                snprintf(src_ep, sizeof(src_ep), "%s:%u", src, ntohs(next.src_port));

            if (next.dst_port == 0)
                snprintf(dst_ep, sizeof(dst_ep), "%s:*", dst);
            else
                snprintf(dst_ep, sizeof(dst_ep), "%s:%u", dst, ntohs(next.dst_port));

            if (next.ip_proto == IPPROTO_TCP)
                proto_name = "tcp";
            else if (next.ip_proto == IPPROTO_UDP)
                proto_name = "udp";
            else if (next.ip_proto == IPPROTO_ICMP)
                proto_name = "icmp";
            else if (next.ip_proto == 0)
                proto_name = "*";
            else
                proto_name = "num";

            printf("%-21s %-21s %-8s %-6u %-8u %-10s %-6u %-10llu\n",
                   src_ep, dst_ep, proto_name, next.vlan_id, next.ingress_ifindex,
                   action_name(entry.action), entry.priority,
                   (unsigned long long)entry.match_pkts);
            count++;
        }

        key = next;
        first = false;
        ret = bpf_map_get_next_key(fd, first ? NULL : &key, &next);
    }

    if (count == 0)
        printf("(empty)\n");
    printf("--------------------------------------------------------------------------------\n");
    printf("Total flows: %d\n", count);

    close(fd);
    return 0;
}

static int cmd_flush(void)
{
    int fd = open_map("flow_table_map");
    struct flow_key key;
    struct flow_key next;
    int ret;
    bool first = true;
    int count = 0;

    if (fd < 0) {
        RS_LOG_ERROR("Failed to open flow_table_map: %s", strerror(errno));
        return 1;
    }

    ret = bpf_map_get_next_key(fd, NULL, &next);
    while (ret == 0) {
        if (bpf_map_delete_elem(fd, &next) == 0)
            count++;

        key = next;
        first = false;
        ret = bpf_map_get_next_key(fd, first ? NULL : &key, &next);
    }

    RS_LOG_INFO("Flushed %d flow entries", count);
    close(fd);
    return 0;
}

static int cmd_stats(void)
{
    static const char *names[] = {
        [FLOW_STAT_MATCHES] = "matches",
        [FLOW_STAT_MISSES] = "misses",
        [FLOW_STAT_DROPS] = "drops",
        [FLOW_STAT_FORWARDS] = "forwards",
    };
    int fd = open_map("flow_stats_map");
    int ncpus;
    __u64 *percpu;

    if (fd < 0) {
        RS_LOG_ERROR("Failed to open flow_stats_map: %s", strerror(errno));
        return 1;
    }

    ncpus = libbpf_num_possible_cpus();
    if (ncpus <= 0) {
        RS_LOG_ERROR("Failed to get CPU count");
        close(fd);
        return 1;
    }

    percpu = calloc((size_t)ncpus, sizeof(__u64));
    if (!percpu) {
        RS_LOG_ERROR("Failed to allocate percpu buffer");
        close(fd);
        return 1;
    }

    printf("Flow stats:\n");
    for (__u32 i = 0; i < FLOW_STAT_MAX; i++) {
        __u64 total = 0;
        memset(percpu, 0, (size_t)ncpus * sizeof(__u64));
        if (bpf_map_lookup_elem(fd, &i, percpu) == 0) {
            for (int c = 0; c < ncpus; c++)
                total += percpu[c];
        }
        printf("  %-10s: %llu\n", names[i], (unsigned long long)total);
    }

    free(percpu);
    close(fd);
    return 0;
}

static int cmd_set_enable(bool enabled)
{
    int fd = open_map("flow_config_map");
    struct flow_config cfg = {0};
    __u32 key = 0;

    if (fd < 0) {
        RS_LOG_ERROR("Failed to open flow_config_map: %s", strerror(errno));
        return 1;
    }

    if (bpf_map_lookup_elem(fd, &key, &cfg) < 0) {
        cfg.enabled = 1;
        cfg.default_action = 0;
    }

    cfg.enabled = enabled ? 1 : 0;
    if (bpf_map_update_elem(fd, &key, &cfg, BPF_ANY) < 0) {
        RS_LOG_ERROR("Failed to update flow_config_map: %s", strerror(errno));
        close(fd);
        return 1;
    }

    RS_LOG_INFO("Flow table %s", enabled ? "enabled" : "disabled");
    close(fd);
    return 0;
}

static void usage(const char *prog)
{
    RS_LOG_INFO("Usage: %s <command> [options]", prog);
    RS_LOG_INFO("Commands:");
    RS_LOG_INFO("  add --src-ip <ip|any> --dst-ip <ip|any> --src-port <port|any> --dst-port <port|any>");
    RS_LOG_INFO("      --proto <tcp|udp|icmp|any> --vlan <id|any> --ingress <ifname|ifindex|any>");
    RS_LOG_INFO("      --action <forward|drop|set-vlan|set-dscp|mirror> --priority <n>");
    RS_LOG_INFO("      [--egress <ifname|ifindex>] [--set-vlan <id>] [--set-dscp <0-63>]");
    RS_LOG_INFO("      [--idle-timeout <sec>] [--hard-timeout <sec>]");
    RS_LOG_INFO("  del --src-ip ... --dst-ip ... --src-port ... --dst-port ... --proto ... --vlan ... --ingress ...");
    RS_LOG_INFO("  show");
    RS_LOG_INFO("  flush");
    RS_LOG_INFO("  stats");
    RS_LOG_INFO("  enable");
    RS_LOG_INFO("  disable");
}

int main(int argc, char **argv)
{
    rs_log_init("rsflowctl", RS_LOG_LEVEL_INFO);

    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "add") == 0)
        return cmd_add(argc - 1, argv + 1);
    if (strcmp(argv[1], "del") == 0)
        return cmd_del(argc - 1, argv + 1);
    if (strcmp(argv[1], "show") == 0)
        return cmd_show();
    if (strcmp(argv[1], "flush") == 0)
        return cmd_flush();
    if (strcmp(argv[1], "stats") == 0)
        return cmd_stats();
    if (strcmp(argv[1], "enable") == 0)
        return cmd_set_enable(true);
    if (strcmp(argv[1], "disable") == 0)
        return cmd_set_enable(false);

    RS_LOG_ERROR("Unknown command: %s", argv[1]);
    usage(argv[0]);
    return 1;
}
