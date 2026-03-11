// SPDX-License-Identifier: GPL-2.0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#if __has_include("rs_log.h")
#include "rs_log.h"
#else
#include "../common/rs_log.h"
#endif

#define PIN_BASE_DIR "/sys/fs/bpf"

enum nat_mode {
    NAT_MODE_NONE = 0,
    NAT_MODE_SNAT = 1,
    NAT_MODE_DNAT = 2,
    NAT_MODE_MASQ = 3,
};

struct nat_key {
    __be32 addr;
    __be16 port;
    __u8 proto;
    __u8 mode;
} __attribute__((packed));

struct nat_entry {
    __be32 translated_addr;
    __be16 translated_port;
    __be16 pad;
    __u64 last_used_ns;
    __u64 pkts;
    __u64 bytes;
} __attribute__((aligned(8)));

struct dnat_rule {
    __be32 external_addr;
    __be16 external_port;
    __u8 proto;
    __u8 enabled;
    __be32 internal_addr;
    __be16 internal_port;
    __be16 pad;
} __attribute__((aligned(8)));

struct dnat_rule_key {
    __be32 addr;
    __be16 port;
    __u8 proto;
    __u8 pad;
} __attribute__((packed));

struct snat_config {
    __u8 enabled;
    __u8 mode;
    __u8 pad[2];
    __be32 snat_addr;
    __be16 port_range_start;
    __be16 port_range_end;
} __attribute__((aligned(8)));

struct nat_config {
    __u8 enabled;
    __u8 pad[3];
    __u32 tcp_timeout;
    __u32 udp_timeout;
} __attribute__((aligned(8)));

static const char *nat_stat_names[8] = {
    "SNAT packets",
    "DNAT packets",
    "SNAT new",
    "DNAT new",
    "SNAT miss",
    "DNAT miss",
    "Errors",
    "Total",
};

static int open_pinned_map(const char *name)
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
    if (errno || end == s || *end != '\0' || v > 0xffffffffUL)
        return -1;

    *out = (__u32)v;
    return 0;
}

static int parse_u16(const char *s, __u16 *out)
{
    __u32 v;
    if (parse_u32(s, &v) < 0 || v > 65535)
        return -1;
    *out = (__u16)v;
    return 0;
}

static int parse_ipv4(const char *s, __be32 *addr)
{
    struct in_addr a;

    if (inet_pton(AF_INET, s, &a) != 1)
        return -1;
    *addr = a.s_addr;
    return 0;
}

static int parse_proto(const char *s, __u8 *proto)
{
    __u32 v;

    if (strcasecmp(s, "tcp") == 0) {
        *proto = IPPROTO_TCP;
        return 0;
    }
    if (strcasecmp(s, "udp") == 0) {
        *proto = IPPROTO_UDP;
        return 0;
    }
    if (parse_u32(s, &v) < 0 || v > 255)
        return -1;

    *proto = (__u8)v;
    return 0;
}

static int cmd_add_snat_common(int argc, char **argv, __u8 mode)
{
    int fd;
    __u32 ifindex;
    __u16 pstart;
    __u16 pend;
    struct snat_config cfg = {0};

    if (argc != 6) {
        RS_LOG_ERROR("Usage: %s <ifindex> <snat_ip> <port_start> <port_end>",
                     mode == NAT_MODE_SNAT ? "rsnatctl add-snat" : "rsnatctl add-masquerade");
        return 1;
    }

    if (parse_u32(argv[2], &ifindex) < 0 ||
        parse_ipv4(argv[3], &cfg.snat_addr) < 0 ||
        parse_u16(argv[4], &pstart) < 0 ||
        parse_u16(argv[5], &pend) < 0 ||
        pstart == 0 || pend == 0 || pend < pstart) {
        RS_LOG_ERROR("Invalid arguments");
        return 1;
    }

    cfg.enabled = 1;
    cfg.mode = mode;
    cfg.port_range_start = htons(pstart);
    cfg.port_range_end = htons(pend);

    fd = open_pinned_map("snat_config_map");
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open snat_config_map: %s", strerror(errno));
        return 1;
    }

    if (bpf_map_update_elem(fd, &ifindex, &cfg, BPF_ANY) < 0) {
        RS_LOG_ERROR("Failed to update snat_config_map: %s", strerror(errno));
        close(fd);
        return 1;
    }

    RS_LOG_INFO("Configured %s for ifindex=%u ip=%s ports=%u-%u",
                mode == NAT_MODE_SNAT ? "SNAT" : "MASQUERADE",
                ifindex, argv[3], pstart, pend);
    close(fd);
    return 0;
}

static int cmd_add_dnat(int argc, char **argv)
{
    int fd;
    __u16 ext_port;
    __u16 int_port;
    __u8 proto;
    __be32 ext_addr;
    struct dnat_rule_key key = {0};
    struct dnat_rule val = {0};

    if (argc != 7) {
        RS_LOG_ERROR("Usage: rsnatctl add-dnat <external_ip> <external_port> <proto> <internal_ip> <internal_port>");
        return 1;
    }

    if (parse_ipv4(argv[2], &ext_addr) < 0 ||
        parse_u16(argv[3], &ext_port) < 0 ||
        parse_proto(argv[4], &proto) < 0 ||
        parse_ipv4(argv[5], &val.internal_addr) < 0 ||
        parse_u16(argv[6], &int_port) < 0) {
        RS_LOG_ERROR("Invalid DNAT arguments");
        return 1;
    }

    key.addr = ext_addr;
    key.port = htons(ext_port);
    key.proto = proto;

    val.external_addr = key.addr;
    val.external_port = key.port;
    val.proto = key.proto;
    val.enabled = 1;
    val.internal_port = htons(int_port);

    fd = open_pinned_map("dnat_rules");
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open dnat_rules: %s", strerror(errno));
        return 1;
    }

    if (bpf_map_update_elem(fd, &key, &val, BPF_ANY) < 0) {
        RS_LOG_ERROR("Failed to update dnat_rules: %s", strerror(errno));
        close(fd);
        return 1;
    }

    RS_LOG_INFO("Added DNAT %s:%u/%u -> %s:%u",
                argv[2], ext_port, proto, argv[5], int_port);
    close(fd);
    return 0;
}

static int cmd_del_dnat(int argc, char **argv)
{
    int fd;
    __u16 ext_port;
    __u8 proto;
    __be32 ext_addr;
    struct dnat_rule_key key = {0};

    if (argc != 5) {
        RS_LOG_ERROR("Usage: rsnatctl del-dnat <external_ip> <external_port> <proto>");
        return 1;
    }

    if (parse_ipv4(argv[2], &ext_addr) < 0 ||
        parse_u16(argv[3], &ext_port) < 0 ||
        parse_proto(argv[4], &proto) < 0) {
        RS_LOG_ERROR("Invalid DNAT key");
        return 1;
    }

    key.addr = ext_addr;
    key.port = htons(ext_port);
    key.proto = proto;

    fd = open_pinned_map("dnat_rules");
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open dnat_rules: %s", strerror(errno));
        return 1;
    }

    if (bpf_map_delete_elem(fd, &key) < 0) {
        RS_LOG_ERROR("Failed to delete DNAT rule: %s", strerror(errno));
        close(fd);
        return 1;
    }

    RS_LOG_INFO("Deleted DNAT rule %s:%u/%u", argv[2], ext_port, proto);
    close(fd);
    return 0;
}

static int show_config(void)
{
    int fd;
    __u32 key = 0;
    struct nat_config cfg = {0};

    fd = open_pinned_map("nat_config_map");
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open nat_config_map: %s", strerror(errno));
        return 1;
    }

    if (bpf_map_lookup_elem(fd, &key, &cfg) < 0) {
        RS_LOG_ERROR("Failed to read nat_config_map: %s", strerror(errno));
        close(fd);
        return 1;
    }

    RS_LOG_INFO("NAT status: %s", cfg.enabled ? "enabled" : "disabled");
    RS_LOG_INFO("Timeouts: tcp=%u udp=%u", cfg.tcp_timeout, cfg.udp_timeout);
    close(fd);
    return 0;
}

static int show_snat_config(void)
{
    int fd;
    int ret;
    __u32 cur = 0;
    __u32 next = 0;
    bool first = true;
    bool any = false;

    fd = open_pinned_map("snat_config_map");
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open snat_config_map: %s", strerror(errno));
        return 1;
    }

    RS_LOG_INFO("SNAT configs:");
    for (;;) {
        ret = bpf_map_get_next_key(fd, first ? NULL : &cur, &next);
        if (ret < 0)
            break;
        first = false;

        struct snat_config cfg = {0};
        struct in_addr addr;
        char ipbuf[INET_ADDRSTRLEN];

        if (bpf_map_lookup_elem(fd, &next, &cfg) == 0) {
            addr.s_addr = cfg.snat_addr;
            if (!inet_ntop(AF_INET, &addr, ipbuf, sizeof(ipbuf)))
                snprintf(ipbuf, sizeof(ipbuf), "<invalid>");
            RS_LOG_INFO("  ifindex=%u enabled=%u mode=%u ip=%s ports=%u-%u",
                        next, cfg.enabled, cfg.mode, ipbuf,
                        ntohs(cfg.port_range_start), ntohs(cfg.port_range_end));
            any = true;
        }

        cur = next;
    }

    if (!any)
        RS_LOG_INFO("  (none)");

    close(fd);
    return 0;
}

static int show_dnat_rules(void)
{
    int fd;
    int ret;
    struct dnat_rule_key cur = {0};
    struct dnat_rule_key next = {0};
    bool first = true;
    bool any = false;

    fd = open_pinned_map("dnat_rules");
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open dnat_rules: %s", strerror(errno));
        return 1;
    }

    RS_LOG_INFO("DNAT rules:");
    for (;;) {
        ret = bpf_map_get_next_key(fd, first ? NULL : &cur, &next);
        if (ret < 0)
            break;
        first = false;

        struct dnat_rule val = {0};
        char ext_ip[INET_ADDRSTRLEN];
        char int_ip[INET_ADDRSTRLEN];
        struct in_addr ext_addr = { .s_addr = next.addr };

        if (bpf_map_lookup_elem(fd, &next, &val) == 0) {
            struct in_addr int_addr = { .s_addr = val.internal_addr };

            if (!inet_ntop(AF_INET, &ext_addr, ext_ip, sizeof(ext_ip)))
                snprintf(ext_ip, sizeof(ext_ip), "<invalid>");
            if (!inet_ntop(AF_INET, &int_addr, int_ip, sizeof(int_ip)))
                snprintf(int_ip, sizeof(int_ip), "<invalid>");

            RS_LOG_INFO("  %s:%u/%u -> %s:%u enabled=%u",
                        ext_ip, ntohs(next.port), next.proto,
                        int_ip, ntohs(val.internal_port), val.enabled);
            any = true;
        }

        cur = next;
    }

    if (!any)
        RS_LOG_INFO("  (none)");

    close(fd);
    return 0;
}

static int cmd_show(void)
{
    int rc;

    rc = show_config();
    if (rc)
        return rc;
    rc = show_snat_config();
    if (rc)
        return rc;
    return show_dnat_rules();
}

static int cmd_show_translations(void)
{
    int fd;
    int ret;
    struct nat_key cur = {0};
    struct nat_key next = {0};
    bool first = true;
    bool any = false;

    fd = open_pinned_map("nat_table");
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open nat_table: %s", strerror(errno));
        return 1;
    }

    RS_LOG_INFO("Active NAT translations:");
    for (;;) {
        ret = bpf_map_get_next_key(fd, first ? NULL : &cur, &next);
        if (ret < 0)
            break;
        first = false;

        struct nat_entry val = {0};
        if (bpf_map_lookup_elem(fd, &next, &val) == 0) {
            char src_ip[INET_ADDRSTRLEN];
            char nat_ip[INET_ADDRSTRLEN];
            struct in_addr saddr = { .s_addr = next.addr };
            struct in_addr taddr = { .s_addr = val.translated_addr };

            if (!inet_ntop(AF_INET, &saddr, src_ip, sizeof(src_ip)))
                snprintf(src_ip, sizeof(src_ip), "<invalid>");
            if (!inet_ntop(AF_INET, &taddr, nat_ip, sizeof(nat_ip)))
                snprintf(nat_ip, sizeof(nat_ip), "<invalid>");

            RS_LOG_INFO("  mode=%u proto=%u %s:%u -> %s:%u pkts=%llu bytes=%llu",
                        next.mode, next.proto,
                        src_ip, ntohs(next.port),
                        nat_ip, ntohs(val.translated_port),
                        (unsigned long long)val.pkts,
                        (unsigned long long)val.bytes);
            any = true;
        }

        cur = next;
    }

    if (!any)
        RS_LOG_INFO("  (none)");

    close(fd);
    return 0;
}

static int cmd_stats(void)
{
    int fd;
    int ncpus;
    __u64 *values;

    fd = open_pinned_map("nat_stats_map");
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open nat_stats_map: %s", strerror(errno));
        return 1;
    }

    ncpus = libbpf_num_possible_cpus();
    if (ncpus <= 0) {
        RS_LOG_ERROR("Failed to detect CPU count");
        close(fd);
        return 1;
    }

    values = calloc((size_t)ncpus, sizeof(__u64));
    if (!values) {
        RS_LOG_ERROR("Failed to allocate stats buffer");
        close(fd);
        return 1;
    }

    RS_LOG_INFO("NAT statistics:");
    for (__u32 i = 0; i < 8; i++) {
        __u64 total = 0;

        memset(values, 0, (size_t)ncpus * sizeof(__u64));
        if (bpf_map_lookup_elem(fd, &i, values) == 0) {
            for (int cpu = 0; cpu < ncpus; cpu++)
                total += values[cpu];
        }
        RS_LOG_INFO("  %-12s %llu", nat_stat_names[i], (unsigned long long)total);
    }

    free(values);
    close(fd);
    return 0;
}

static int cmd_flush(void)
{
    int fd;
    int ret;
    int count = 0;
    struct nat_key cur = {0};
    struct nat_key next = {0};
    bool first = true;

    fd = open_pinned_map("nat_table");
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open nat_table: %s", strerror(errno));
        return 1;
    }

    for (;;) {
        ret = bpf_map_get_next_key(fd, first ? NULL : &cur, &next);
        if (ret < 0)
            break;
        first = false;

        if (bpf_map_delete_elem(fd, &next) == 0)
            count++;
        cur = next;
    }

    RS_LOG_INFO("Flushed %d NAT translations", count);
    close(fd);
    return 0;
}

static int cmd_set_enabled(bool enabled)
{
    int fd;
    __u32 key = 0;
    struct nat_config cfg = {0};

    fd = open_pinned_map("nat_config_map");
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open nat_config_map: %s", strerror(errno));
        return 1;
    }

    if (bpf_map_lookup_elem(fd, &key, &cfg) < 0) {
        cfg.enabled = 0;
        cfg.tcp_timeout = 300;
        cfg.udp_timeout = 60;
    }

    cfg.enabled = enabled ? 1 : 0;
    if (bpf_map_update_elem(fd, &key, &cfg, BPF_ANY) < 0) {
        RS_LOG_ERROR("Failed to update nat_config_map: %s", strerror(errno));
        close(fd);
        return 1;
    }

    RS_LOG_INFO("NAT %s", enabled ? "enabled" : "disabled");
    close(fd);
    return 0;
}

static void usage(const char *prog)
{
    RS_LOG_INFO("Usage: %s <command> [args]", prog);
    RS_LOG_INFO("Commands:");
    RS_LOG_INFO("  add-snat <ifindex> <snat_ip> <port_start> <port_end>");
    RS_LOG_INFO("  add-masquerade <ifindex> <egress_ip> <port_start> <port_end>");
    RS_LOG_INFO("  add-dnat <external_ip> <external_port> <proto> <internal_ip> <internal_port>");
    RS_LOG_INFO("  del-dnat <external_ip> <external_port> <proto>");
    RS_LOG_INFO("  show");
    RS_LOG_INFO("  show-translations");
    RS_LOG_INFO("  stats");
    RS_LOG_INFO("  flush");
    RS_LOG_INFO("  enable");
    RS_LOG_INFO("  disable");
}

int main(int argc, char **argv)
{
    rs_log_init("rsnatctl", RS_LOG_LEVEL_INFO);

    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "add-snat") == 0)
        return cmd_add_snat_common(argc, argv, NAT_MODE_SNAT);
    if (strcmp(argv[1], "add-masquerade") == 0)
        return cmd_add_snat_common(argc, argv, NAT_MODE_MASQ);
    if (strcmp(argv[1], "add-dnat") == 0)
        return cmd_add_dnat(argc, argv);
    if (strcmp(argv[1], "del-dnat") == 0)
        return cmd_del_dnat(argc, argv);
    if (strcmp(argv[1], "show") == 0)
        return cmd_show();
    if (strcmp(argv[1], "show-translations") == 0)
        return cmd_show_translations();
    if (strcmp(argv[1], "stats") == 0)
        return cmd_stats();
    if (strcmp(argv[1], "flush") == 0)
        return cmd_flush();
    if (strcmp(argv[1], "enable") == 0)
        return cmd_set_enabled(true);
    if (strcmp(argv[1], "disable") == 0)
        return cmd_set_enabled(false);

    RS_LOG_ERROR("Unknown command: %s", argv[1]);
    usage(argv[0]);
    return 1;
}
