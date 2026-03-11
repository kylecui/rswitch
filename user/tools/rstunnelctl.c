// SPDX-License-Identifier: GPL-2.0

#ifndef __uint
#define __uint(name, val) int name
#endif
#ifndef __type
#define __type(name, val) val name
#endif
#ifndef SEC
#define SEC(name)
#endif

#define RS_MAC_TABLE_OWNER 1
#define bpf_map_lookup_elem(...) ((void *)0)
#define bpf_map_update_elem(...) (0)

#include "../../bpf/core/uapi.h"
#include "../../bpf/core/map_defs.h"

#undef bpf_map_lookup_elem
#undef bpf_map_update_elem
#include "../common/rs_log.h"

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <getopt.h>
#include <linux/types.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PIN_BASE_DIR "/sys/fs/bpf"

struct tunnel_config {
    __u32 enabled;
    __u32 pad;
};

struct vxlan_entry {
    __u16 vlan_id;
    __u16 pad;
    __u32 local_vtep_ip;
    __u32 remote_vtep_ip;
};

struct gre_entry {
    __u32 local_ip;
    __u32 remote_ip;
    __u32 key;
    __u16 vlan_id;
    __u16 pad;
};

struct tunnel_stats {
    __u64 vxlan_decap;
    __u64 vxlan_decap_err;
    __u64 gre_decap;
    __u64 gre_decap_err;
    __u64 unknown_tunnel;
};

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
    if (errno || end == s || *end != '\0' || v > UINT32_MAX)
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

static int parse_ipv4(const char *s, __u32 *addr)
{
    struct in_addr a;

    if (inet_pton(AF_INET, s, &a) != 1)
        return -1;

    *addr = a.s_addr;
    return 0;
}

static void format_ipv4(__u32 addr, char *buf, size_t len)
{
    struct in_addr a = { .s_addr = addr };

    if (!inet_ntop(AF_INET, &a, buf, len))
        snprintf(buf, len, "<invalid>");
}

static int cmd_add_vxlan(int argc, char **argv)
{
    int fd;
    __u32 vni = 0;
    struct vxlan_entry val = {0};
    bool have_vni = false;
    bool have_vlan = false;
    bool have_local = false;
    bool have_remote = false;

    struct option opts[] = {
        {"vni", required_argument, 0, 'n'},
        {"vlan", required_argument, 0, 'v'},
        {"local-vtep", required_argument, 0, 'l'},
        {"remote-vtep", required_argument, 0, 'r'},
        {0, 0, 0, 0},
    };

    optind = 1;
    for (;;) {
        int c = getopt_long(argc, argv, "", opts, NULL);
        if (c == -1)
            break;
        switch (c) {
        case 'n':
            have_vni = parse_u32(optarg, &vni) == 0;
            break;
        case 'v':
            have_vlan = parse_u16(optarg, &val.vlan_id) == 0;
            break;
        case 'l':
            have_local = parse_ipv4(optarg, &val.local_vtep_ip) == 0;
            break;
        case 'r':
            have_remote = parse_ipv4(optarg, &val.remote_vtep_ip) == 0;
            break;
        default:
            RS_LOG_ERROR("Invalid add-vxlan arguments");
            return 1;
        }
    }

    if (!have_vni || !have_vlan || !have_local || !have_remote) {
        RS_LOG_ERROR("Usage: rstunnelctl add-vxlan --vni <N> --vlan <N> --local-vtep <IP> --remote-vtep <IP>");
        return 1;
    }

    fd = open_map("vxlan_vni_map");
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open vxlan_vni_map: %s", strerror(errno));
        return 1;
    }

    if (bpf_map_update_elem(fd, &vni, &val, BPF_ANY) < 0) {
        RS_LOG_ERROR("Failed to add VXLAN VNI %u: %s", vni, strerror(errno));
        close(fd);
        return 1;
    }

    RS_LOG_INFO("Added VXLAN VNI=%u VLAN=%u", vni, val.vlan_id);
    close(fd);
    return 0;
}

static int cmd_del_vxlan(int argc, char **argv)
{
    int fd;
    __u32 vni;

    if (argc != 3 || strcmp(argv[1], "--vni") != 0 || parse_u32(argv[2], &vni) < 0) {
        RS_LOG_ERROR("Usage: rstunnelctl del-vxlan --vni <N>");
        return 1;
    }

    fd = open_map("vxlan_vni_map");
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open vxlan_vni_map: %s", strerror(errno));
        return 1;
    }

    if (bpf_map_delete_elem(fd, &vni) < 0) {
        RS_LOG_ERROR("Failed to delete VXLAN VNI %u: %s", vni, strerror(errno));
        close(fd);
        return 1;
    }

    RS_LOG_INFO("Deleted VXLAN VNI=%u", vni);
    close(fd);
    return 0;
}

static int cmd_show_vxlan(void)
{
    int fd;
    __u32 key;
    __u32 next;
    bool first = true;
    int count = 0;

    fd = open_map("vxlan_vni_map");
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open vxlan_vni_map: %s", strerror(errno));
        return 1;
    }

    RS_LOG_INFO("VXLAN mappings:");
    for (;;) {
        int ret = bpf_map_get_next_key(fd, first ? NULL : &key, &next);
        if (ret < 0)
            break;
        first = false;

        struct vxlan_entry val = {0};
        if (bpf_map_lookup_elem(fd, &next, &val) == 0) {
            char lip[INET_ADDRSTRLEN];
            char rip[INET_ADDRSTRLEN];
            format_ipv4(val.local_vtep_ip, lip, sizeof(lip));
            format_ipv4(val.remote_vtep_ip, rip, sizeof(rip));
            RS_LOG_INFO("  VNI=%u VLAN=%u local=%s remote=%s", next, val.vlan_id, lip, rip);
            count++;
        }
        key = next;
    }

    if (!count)
        RS_LOG_INFO("  (none)");

    close(fd);
    return 0;
}

static int cmd_add_gre(int argc, char **argv)
{
    int fd;
    __u32 tunnel_id = 0;
    struct gre_entry val = {0};
    bool have_id = false;
    bool have_local = false;
    bool have_remote = false;
    bool have_key = false;

    struct option opts[] = {
        {"id", required_argument, 0, 'i'},
        {"local", required_argument, 0, 'l'},
        {"remote", required_argument, 0, 'r'},
        {"key", required_argument, 0, 'k'},
        {"vlan", required_argument, 0, 'v'},
        {0, 0, 0, 0},
    };

    optind = 1;
    for (;;) {
        int c = getopt_long(argc, argv, "", opts, NULL);
        if (c == -1)
            break;
        switch (c) {
        case 'i':
            have_id = parse_u32(optarg, &tunnel_id) == 0;
            break;
        case 'l':
            have_local = parse_ipv4(optarg, &val.local_ip) == 0;
            break;
        case 'r':
            have_remote = parse_ipv4(optarg, &val.remote_ip) == 0;
            break;
        case 'k':
            have_key = parse_u32(optarg, &val.key) == 0;
            break;
        case 'v':
            if (parse_u16(optarg, &val.vlan_id) < 0) {
                RS_LOG_ERROR("Invalid --vlan value: %s", optarg);
                return 1;
            }
            break;
        default:
            RS_LOG_ERROR("Invalid add-gre arguments");
            return 1;
        }
    }

    if (!have_id || !have_local || !have_remote || !have_key) {
        RS_LOG_ERROR("Usage: rstunnelctl add-gre --id <N> --local <IP> --remote <IP> --key <N> [--vlan <N>]");
        return 1;
    }

    fd = open_map("gre_tunnel_map");
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open gre_tunnel_map: %s", strerror(errno));
        return 1;
    }

    if (bpf_map_update_elem(fd, &tunnel_id, &val, BPF_ANY) < 0) {
        RS_LOG_ERROR("Failed to add GRE tunnel id=%u: %s", tunnel_id, strerror(errno));
        close(fd);
        return 1;
    }

    RS_LOG_INFO("Added GRE tunnel id=%u key=%u vlan=%u", tunnel_id, val.key, val.vlan_id);
    close(fd);
    return 0;
}

static int cmd_del_gre(int argc, char **argv)
{
    int fd;
    __u32 tunnel_id;

    if (argc != 3 || strcmp(argv[1], "--id") != 0 || parse_u32(argv[2], &tunnel_id) < 0) {
        RS_LOG_ERROR("Usage: rstunnelctl del-gre --id <N>");
        return 1;
    }

    fd = open_map("gre_tunnel_map");
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open gre_tunnel_map: %s", strerror(errno));
        return 1;
    }

    if (bpf_map_delete_elem(fd, &tunnel_id) < 0) {
        RS_LOG_ERROR("Failed to delete GRE tunnel id=%u: %s", tunnel_id, strerror(errno));
        close(fd);
        return 1;
    }

    RS_LOG_INFO("Deleted GRE tunnel id=%u", tunnel_id);
    close(fd);
    return 0;
}

static int cmd_show_gre(void)
{
    int fd;
    __u32 key;
    __u32 next;
    bool first = true;
    int count = 0;

    fd = open_map("gre_tunnel_map");
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open gre_tunnel_map: %s", strerror(errno));
        return 1;
    }

    RS_LOG_INFO("GRE tunnels:");
    for (;;) {
        int ret = bpf_map_get_next_key(fd, first ? NULL : &key, &next);
        if (ret < 0)
            break;
        first = false;

        struct gre_entry val = {0};
        if (bpf_map_lookup_elem(fd, &next, &val) == 0) {
            char lip[INET_ADDRSTRLEN];
            char rip[INET_ADDRSTRLEN];
            format_ipv4(val.local_ip, lip, sizeof(lip));
            format_ipv4(val.remote_ip, rip, sizeof(rip));
            RS_LOG_INFO("  id=%u key=%u vlan=%u local=%s remote=%s", next, val.key, val.vlan_id, lip, rip);
            count++;
        }
        key = next;
    }

    if (!count)
        RS_LOG_INFO("  (none)");

    close(fd);
    return 0;
}

static int cmd_stats(void)
{
    int fd;
    int ncpus;
    __u32 key = 0;
    struct tunnel_stats total = {0};
    struct tunnel_stats *percpu;

    fd = open_map("tunnel_stats_map");
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open tunnel_stats_map: %s", strerror(errno));
        return 1;
    }

    ncpus = libbpf_num_possible_cpus();
    if (ncpus <= 0) {
        RS_LOG_ERROR("Failed to get CPU count");
        close(fd);
        return 1;
    }

    percpu = calloc((size_t)ncpus, sizeof(*percpu));
    if (!percpu) {
        RS_LOG_ERROR("Failed to allocate stats buffer");
        close(fd);
        return 1;
    }

    if (bpf_map_lookup_elem(fd, &key, percpu) < 0) {
        RS_LOG_ERROR("Failed to read tunnel_stats_map: %s", strerror(errno));
        free(percpu);
        close(fd);
        return 1;
    }

    for (int i = 0; i < ncpus; i++) {
        total.vxlan_decap += percpu[i].vxlan_decap;
        total.vxlan_decap_err += percpu[i].vxlan_decap_err;
        total.gre_decap += percpu[i].gre_decap;
        total.gre_decap_err += percpu[i].gre_decap_err;
        total.unknown_tunnel += percpu[i].unknown_tunnel;
    }

    RS_LOG_INFO("Tunnel stats:");
    RS_LOG_INFO("  vxlan_decap=%llu", (unsigned long long)total.vxlan_decap);
    RS_LOG_INFO("  vxlan_decap_err=%llu", (unsigned long long)total.vxlan_decap_err);
    RS_LOG_INFO("  gre_decap=%llu", (unsigned long long)total.gre_decap);
    RS_LOG_INFO("  gre_decap_err=%llu", (unsigned long long)total.gre_decap_err);
    RS_LOG_INFO("  unknown_tunnel=%llu", (unsigned long long)total.unknown_tunnel);

    free(percpu);
    close(fd);
    return 0;
}

static int cmd_set_enabled(bool enabled)
{
    int fd;
    __u32 key = 0;
    struct tunnel_config cfg = {0};

    fd = open_map("tunnel_config_map");
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open tunnel_config_map: %s", strerror(errno));
        return 1;
    }

    if (bpf_map_lookup_elem(fd, &key, &cfg) < 0)
        memset(&cfg, 0, sizeof(cfg));

    cfg.enabled = enabled ? 1 : 0;
    if (bpf_map_update_elem(fd, &key, &cfg, BPF_ANY) < 0) {
        RS_LOG_ERROR("Failed to update tunnel_config_map: %s", strerror(errno));
        close(fd);
        return 1;
    }

    RS_LOG_INFO("Tunnel processing %s", enabled ? "enabled" : "disabled");
    close(fd);
    return 0;
}

static void usage(const char *prog)
{
    RS_LOG_INFO("Usage: %s <command> [options]", prog);
    RS_LOG_INFO("Commands:");
    RS_LOG_INFO("  add-vxlan --vni <N> --vlan <N> --local-vtep <IP> --remote-vtep <IP>");
    RS_LOG_INFO("  del-vxlan --vni <N>");
    RS_LOG_INFO("  show-vxlan");
    RS_LOG_INFO("  add-gre --id <N> --local <IP> --remote <IP> --key <N> [--vlan <N>]");
    RS_LOG_INFO("  del-gre --id <N>");
    RS_LOG_INFO("  show-gre");
    RS_LOG_INFO("  stats");
    RS_LOG_INFO("  enable");
    RS_LOG_INFO("  disable");
}

int main(int argc, char **argv)
{
    rs_log_init("rstunnelctl", RS_LOG_LEVEL_INFO);

    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "add-vxlan") == 0)
        return cmd_add_vxlan(argc - 1, argv + 1);
    if (strcmp(argv[1], "del-vxlan") == 0)
        return cmd_del_vxlan(argc - 1, argv + 1);
    if (strcmp(argv[1], "show-vxlan") == 0)
        return cmd_show_vxlan();
    if (strcmp(argv[1], "add-gre") == 0)
        return cmd_add_gre(argc - 1, argv + 1);
    if (strcmp(argv[1], "del-gre") == 0)
        return cmd_del_gre(argc - 1, argv + 1);
    if (strcmp(argv[1], "show-gre") == 0)
        return cmd_show_gre();
    if (strcmp(argv[1], "stats") == 0)
        return cmd_stats();
    if (strcmp(argv[1], "enable") == 0)
        return cmd_set_enabled(true);
    if (strcmp(argv[1], "disable") == 0)
        return cmd_set_enabled(false);

    RS_LOG_ERROR("Unknown command: %s", argv[1]);
    usage(argv[0]);
    return 1;
}
