// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * rsroutectl - rSwitch Route Control Tool
 * 
 * Manages IPv4 routing tables and ARP entries:
 * - route-add/del/show: Manage routing table entries
 * - arp-add/del/show: Manage ARP table entries
 * - iface-set: Configure interface MAC and router status
 * - enable/disable: Toggle routing functionality
 * - stats: Display routing statistics
 * 
 * Usage examples:
 *   rsroutectl route-add --dest 192.168.1.0/24 --nexthop 0.0.0.0 --ifindex 1
 *   rsroutectl route-add --dest 0.0.0.0/0 --nexthop 192.168.1.254 --ifindex 1
 *   rsroutectl arp-add --ip 192.168.1.254 --mac 00:11:22:33:44:55 --ifindex 1
 *   rsroutectl iface-set --ifindex 1 --mac 00:aa:bb:cc:dd:ee --router
 *   rsroutectl enable
 *   rsroutectl stats
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#if __has_include("rs_log.h")
#include "rs_log.h"
#else
#include "../common/rs_log.h"
#endif

#define PIN_BASE_DIR "/sys/fs/bpf"
#define MAX_ECMP_PATHS 4

// Match route.bpf.c structures
struct lpm_key {
    __u32 prefixlen;
    __u32 addr;  // Note: __be32 in kernel, but we handle endianness in userspace
};

struct route_entry {
    __u32 nexthop;  // __be32 in kernel
    __u32 ifindex;
    __u32 metric;
    __u8 type;
    __u8 pad[3];
    __u32 ecmp_group_id;
};

struct ecmp_group {
    __u8 count;
    __u8 pad[3];
    struct {
        __u32 nexthop;
        __u32 ifindex;
        __u8 weight;
        __u8 pad[3];
    } paths[MAX_ECMP_PATHS];
};

struct arp_entry {
    __u8 mac[6];
    __u16 pad;
    __u32 ifindex;
    __u64 timestamp;
};

struct iface_config {
    __u8 mac[6];
    __u16 pad;
    __u8 is_router;
    __u8 pad2[3];
};

struct route_config {
    __u8 enabled;
    __u8 icmp_redirect;
    __u8 send_arp_req;
    __u8 pad;
};

struct arp_cfg {
    __u32 max_age_sec;
    __u8 enabled;
    __u8 pad[3];
};

enum route_stat_type {
    ROUTE_STAT_LOOKUP = 0,
    ROUTE_STAT_HIT = 1,
    ROUTE_STAT_MISS = 2,
    ROUTE_STAT_ARP_HIT = 3,
    ROUTE_STAT_ARP_MISS = 4,
    ROUTE_STAT_TTL_EXCEEDED = 5,
    ROUTE_STAT_DIRECT = 6,
    ROUTE_STAT_STATIC = 7,
    ROUTE_STAT_REDIRECT = 8,
    ROUTE_STAT_MAX = 9,
};

static const char *stat_names[ROUTE_STAT_MAX] = {
    [ROUTE_STAT_LOOKUP] = "Route lookups",
    [ROUTE_STAT_HIT] = "Route hits",
    [ROUTE_STAT_MISS] = "Route misses",
    [ROUTE_STAT_ARP_HIT] = "ARP hits",
    [ROUTE_STAT_ARP_MISS] = "ARP misses",
    [ROUTE_STAT_TTL_EXCEEDED] = "TTL exceeded",
    [ROUTE_STAT_DIRECT] = "Direct routes",
    [ROUTE_STAT_STATIC] = "Static routes",
    [ROUTE_STAT_REDIRECT] = "Redirect candidates",
};

// Parse IP/prefix (CIDR notation)
static int parse_cidr(const char *cidr, __u32 *ip, __u32 *prefixlen)
{
    char buf[64];
    char *slash;
    struct in_addr addr;
    
    strncpy(buf, cidr, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    
    slash = strchr(buf, '/');
    if (slash) {
        *slash = '\0';
        *prefixlen = atoi(slash + 1);
        if (*prefixlen > 32) {
            RS_LOG_ERROR("Invalid prefix length: %u (must be 0-32)", *prefixlen);
            return -1;
        }
    } else {
        *prefixlen = 32;  // Host route
    }
    
    if (inet_pton(AF_INET, buf, &addr) != 1) {
        RS_LOG_ERROR("Invalid IP address: %s", buf);
        return -1;
    }
    
    *ip = addr.s_addr;  // Already in network byte order
    return 0;
}

// Parse MAC address
static int parse_mac(const char *mac_str, __u8 *mac)
{
    unsigned int m[6];
    
    if (sscanf(mac_str, "%x:%x:%x:%x:%x:%x",
               &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) != 6) {
        RS_LOG_ERROR("Invalid MAC address: %s (format: XX:XX:XX:XX:XX:XX)", mac_str);
        return -1;
    }
    
    for (int i = 0; i < 6; i++)
        mac[i] = (__u8)m[i];
    
    return 0;
}

static int open_pinned_map(const char *name)
{
    char map_path[256];
    snprintf(map_path, sizeof(map_path), "%s/%s", PIN_BASE_DIR, name);
    return bpf_obj_get(map_path);
}

static int ifindex_from_arg(const char *dev)
{
    if (!dev || !*dev)
        return 0;
    if (strspn(dev, "0123456789") == strlen(dev))
        return atoi(dev);
    return (int)if_nametoindex(dev);
}

static __u64 monotonic_ns(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return ((__u64)ts.tv_sec * 1000000000ULL) + (__u64)ts.tv_nsec;
}

// Add route
static int cmd_route_add(int argc, char **argv)
{
    char *dest_str = NULL, *nexthop_str = NULL;
    int ifindex = 0, metric = 0;
    struct lpm_key key = {0};
    struct route_entry entry = {0};
    int fd, ret;
    
    struct option long_opts[] = {
        {"dest", required_argument, 0, 'd'},
        {"nexthop", required_argument, 0, 'n'},
        {"ifindex", required_argument, 0, 'i'},
        {"metric", required_argument, 0, 'm'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "d:n:i:m:", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'd':
            dest_str = optarg;
            break;
        case 'n':
            nexthop_str = optarg;
            break;
        case 'i':
            ifindex = atoi(optarg);
            break;
        case 'm':
            metric = atoi(optarg);
            break;
        default:
            RS_LOG_ERROR("Usage: rsroutectl route-add --dest <CIDR> --nexthop <IP> --ifindex <N> [--metric <M>]");
            return -1;
        }
    }
    
    if (!dest_str || !nexthop_str || ifindex == 0) {
        RS_LOG_ERROR("Missing required arguments (need --dest, --nexthop, --ifindex)");
        return -1;
    }
    
    // Parse destination
    if (parse_cidr(dest_str, &key.addr, &key.prefixlen) < 0)
        return -1;
    
    // Parse nexthop (0.0.0.0 means direct route)
    struct in_addr nh_addr;
    if (inet_pton(AF_INET, nexthop_str, &nh_addr) != 1) {
        RS_LOG_ERROR("Invalid nexthop IP: %s", nexthop_str);
        return -1;
    }
    
    entry.nexthop = nh_addr.s_addr;
    entry.ifindex = ifindex;
    entry.metric = metric;
    entry.type = (entry.nexthop == 0) ? 0 : 1;  // 0=direct, 1=static
    entry.ecmp_group_id = 0;
    
    // Open map
    fd = open_pinned_map("route_tbl");
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open route table: %s", strerror(errno));
        return -1;
    }
    
    // Add route
    ret = bpf_map_update_elem(fd, &key, &entry, BPF_ANY);
    if (ret < 0) {
        RS_LOG_ERROR("Failed to add route: %s", strerror(errno));
        close(fd);
        return -1;
    }
    
    char dest_fmt[INET_ADDRSTRLEN], nh_fmt[INET_ADDRSTRLEN];
    struct in_addr tmp_addr;
    tmp_addr.s_addr = key.addr;
    inet_ntop(AF_INET, &tmp_addr, dest_fmt, sizeof(dest_fmt));
    tmp_addr.s_addr = entry.nexthop;
    inet_ntop(AF_INET, &tmp_addr, nh_fmt, sizeof(nh_fmt));
    
    printf("Added route: %s/%u via %s dev %u metric %u (%s)\n",
           dest_fmt, key.prefixlen, 
           entry.nexthop ? nh_fmt : "direct",
           entry.ifindex, entry.metric,
           entry.type == 0 ? "direct" : "static");
    
    close(fd);
    return 0;
}

// Delete route
static int cmd_route_del(int argc, char **argv)
{
    char *dest_str = NULL;
    struct lpm_key key = {0};
    int fd, ret;
    
    if (argc < 3 || strcmp(argv[1], "--dest") != 0) {
        RS_LOG_ERROR("Usage: rsroutectl route-del --dest <CIDR>");
        return -1;
    }
    
    dest_str = argv[2];
    
    if (parse_cidr(dest_str, &key.addr, &key.prefixlen) < 0)
        return -1;
    
    fd = open_pinned_map("route_tbl");
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open route table: %s", strerror(errno));
        return -1;
    }
    
    ret = bpf_map_delete_elem(fd, &key);
    if (ret < 0) {
        RS_LOG_ERROR("Failed to delete route: %s", strerror(errno));
        close(fd);
        return -1;
    }
    
    char dest_fmt[INET_ADDRSTRLEN];
    struct in_addr tmp_addr;
    tmp_addr.s_addr = key.addr;
    inet_ntop(AF_INET, &tmp_addr, dest_fmt, sizeof(dest_fmt));
    
    printf("Deleted route: %s/%u\n", dest_fmt, key.prefixlen);
    
    close(fd);
    return 0;
}

// Show routes (note: LPM trie cannot be iterated)
static int cmd_route_show(void)
{
    int route_fd = open_pinned_map("route_tbl");
    int arp_fd = open_pinned_map("arp_tbl");
    int ecmp_fd = open_pinned_map("ecmp_groups");
    __u64 now = monotonic_ns();
    int count = 0;

    if (route_fd < 0) {
        RS_LOG_ERROR("Failed to open route table: %s", strerror(errno));
        return -1;
    }

    printf("\nRouting Table:\n");
    printf("%-18s %-8s %-16s %-6s %-7s %-6s %-10s\n",
           "Destination", "Type", "Next-hop", "Dev", "Metric", "ECMP", "ARP");
    printf("--------------------------------------------------------------------------------\n");

    struct lpm_key cur = {0}, next;
    struct route_entry entry;
    int has_prev = 0;

    while (bpf_map_get_next_key(route_fd, has_prev ? &cur : NULL, &next) == 0) {
        if (bpf_map_lookup_elem(route_fd, &next, &entry) == 0) {
            struct in_addr daddr = { .s_addr = next.addr };
            char dst[INET_ADDRSTRLEN];
            char prefix[32];
            char nh[INET_ADDRSTRLEN] = "direct";
            char arp_state[16] = "n/a";
            inet_ntop(AF_INET, &daddr, dst, sizeof(dst));
            snprintf(prefix, sizeof(prefix), "%s/%u", dst, next.prefixlen);

            if (entry.nexthop != 0) {
                struct in_addr nh_addr = { .s_addr = entry.nexthop };
                inet_ntop(AF_INET, &nh_addr, nh, sizeof(nh));
            }

            if (entry.ecmp_group_id > 0 && ecmp_fd >= 0) {
                struct ecmp_group group;
                if (bpf_map_lookup_elem(ecmp_fd, &entry.ecmp_group_id, &group) == 0) {
                    snprintf(arp_state, sizeof(arp_state), "paths:%u", group.count);
                } else {
                    snprintf(arp_state, sizeof(arp_state), "ecmp-miss");
                }
            } else if (arp_fd >= 0) {
                __u32 nh_key = entry.nexthop;
                if (nh_key == 0)
                    nh_key = next.addr;
                struct arp_entry a;
                if (bpf_map_lookup_elem(arp_fd, &nh_key, &a) == 0) {
                    if (a.timestamp > 0 && now > a.timestamp) {
                        __u64 age = (now - a.timestamp) / 1000000000ULL;
                        snprintf(arp_state, sizeof(arp_state), "%llus", (unsigned long long)age);
                    } else {
                        snprintf(arp_state, sizeof(arp_state), "hit");
                    }
                } else {
                    snprintf(arp_state, sizeof(arp_state), "miss");
                }
            }

            printf("%-18s %-8s %-16s %-6u %-7u %-6u %-10s\n",
                   prefix,
                   entry.type == 0 ? "direct" : "static",
                   nh,
                   entry.ifindex,
                   entry.metric,
                   entry.ecmp_group_id,
                   arp_state);
            count++;
        }
        cur = next;
        has_prev = 1;
    }

    if (count == 0)
        printf("(empty)\n");
    printf("Total: %d routes\n\n", count);

    close(route_fd);
    if (arp_fd >= 0)
        close(arp_fd);
    if (ecmp_fd >= 0)
        close(ecmp_fd);
    return 0;
}

static int cmd_add_simple(int argc, char **argv)
{
    if (argc < 6) {
        RS_LOG_ERROR("Usage: rsroutectl add <prefix/len> via <nexthop> dev <interface> [metric <N>]");
        return -1;
    }

    const char *prefix = argv[1];
    if (strcmp(argv[2], "via") != 0 || strcmp(argv[4], "dev") != 0) {
        RS_LOG_ERROR("Usage: rsroutectl add <prefix/len> via <nexthop> dev <interface> [metric <N>]");
        return -1;
    }
    const char *nexthop = argv[3];
    int ifindex = ifindex_from_arg(argv[5]);
    int metric = 0;

    for (int i = 6; i + 1 < argc; i++) {
        if (strcmp(argv[i], "metric") == 0) {
            metric = atoi(argv[i + 1]);
            i++;
        }
    }

    if (ifindex <= 0) {
        RS_LOG_ERROR("Invalid interface: %s", argv[5]);
        return -1;
    }

    struct lpm_key key = {0};
    struct route_entry entry = {0};
    if (parse_cidr(prefix, &key.addr, &key.prefixlen) < 0)
        return -1;

    struct in_addr nh_addr;
    if (inet_pton(AF_INET, nexthop, &nh_addr) != 1) {
        RS_LOG_ERROR("Invalid nexthop: %s", nexthop);
        return -1;
    }

    entry.nexthop = nh_addr.s_addr;
    entry.ifindex = ifindex;
    entry.metric = metric;
    entry.type = entry.nexthop == 0 ? 0 : 1;
    entry.ecmp_group_id = 0;

    int route_fd = open_pinned_map("route_tbl");
    if (route_fd < 0) {
        RS_LOG_ERROR("Failed to open route table: %s", strerror(errno));
        return -1;
    }

    int ret = bpf_map_update_elem(route_fd, &key, &entry, BPF_ANY);
    close(route_fd);
    if (ret < 0) {
        RS_LOG_ERROR("Failed to add route: %s", strerror(errno));
        return -1;
    }

    printf("Added route: %s via %s dev %u metric %u\n", prefix, nexthop, ifindex, metric);
    return 0;
}

static int allocate_ecmp_group_id(int ecmp_fd, __u32 *group_id)
{
    if (!group_id)
        return -1;
    __u32 base = (__u32)time(NULL) ^ (__u32)getpid();
    struct ecmp_group probe;

    for (int i = 1; i < 1024; i++) {
        __u32 id = (base + i) & 0x7fffffff;
        if (id == 0)
            continue;
        if (bpf_map_lookup_elem(ecmp_fd, &id, &probe) != 0) {
            *group_id = id;
            return 0;
        }
    }
    return -1;
}

static int cmd_add_ecmp(int argc, char **argv)
{
    if (argc < 8) {
        RS_LOG_ERROR("Usage: rsroutectl add-ecmp <prefix/len> via <nexthop1> dev <if1> via <nexthop2> dev <if2> [via ...]");
        return -1;
    }

    struct lpm_key key = {0};
    struct route_entry entry = {0};
    struct ecmp_group group = {0};
    int path_idx = 0;

    if (parse_cidr(argv[1], &key.addr, &key.prefixlen) < 0)
        return -1;

    int i = 2;
    while (i + 3 < argc && path_idx < MAX_ECMP_PATHS) {
        if (strcmp(argv[i], "via") != 0 || strcmp(argv[i + 2], "dev") != 0) {
            RS_LOG_ERROR("Invalid ECMP syntax near: %s", argv[i]);
            return -1;
        }

        struct in_addr nh;
        if (inet_pton(AF_INET, argv[i + 1], &nh) != 1) {
            RS_LOG_ERROR("Invalid nexthop: %s", argv[i + 1]);
            return -1;
        }

        int ifindex = ifindex_from_arg(argv[i + 3]);
        if (ifindex <= 0) {
            RS_LOG_ERROR("Invalid interface: %s", argv[i + 3]);
            return -1;
        }

        group.paths[path_idx].nexthop = nh.s_addr;
        group.paths[path_idx].ifindex = ifindex;
        group.paths[path_idx].weight = 1;
        path_idx++;
        i += 4;
    }

    if (i != argc) {
        RS_LOG_ERROR("ECMP supports up to %d paths with full via/dev pairs", MAX_ECMP_PATHS);
        return -1;
    }

    if (path_idx < 2) {
        RS_LOG_ERROR("ECMP requires at least 2 valid paths");
        return -1;
    }

    group.count = (__u8)path_idx;
    entry.nexthop = 0;
    entry.ifindex = group.paths[0].ifindex;
    entry.metric = 0;
    entry.type = 1;

    int ecmp_fd = open_pinned_map("ecmp_groups");
    int route_fd = open_pinned_map("route_tbl");
    if (ecmp_fd < 0 || route_fd < 0) {
        RS_LOG_ERROR("Failed to open maps (ecmp=%d route=%d): %s", ecmp_fd, route_fd, strerror(errno));
        if (ecmp_fd >= 0)
            close(ecmp_fd);
        if (route_fd >= 0)
            close(route_fd);
        return -1;
    }

    if (allocate_ecmp_group_id(ecmp_fd, &entry.ecmp_group_id) < 0) {
        RS_LOG_ERROR("Failed to allocate ECMP group id");
        close(ecmp_fd);
        close(route_fd);
        return -1;
    }

    if (bpf_map_update_elem(ecmp_fd, &entry.ecmp_group_id, &group, BPF_ANY) != 0) {
        RS_LOG_ERROR("Failed to create ECMP group: %s", strerror(errno));
        close(ecmp_fd);
        close(route_fd);
        return -1;
    }

    if (bpf_map_update_elem(route_fd, &key, &entry, BPF_ANY) != 0) {
        RS_LOG_ERROR("Failed to add ECMP route: %s", strerror(errno));
        close(ecmp_fd);
        close(route_fd);
        return -1;
    }

    printf("Added ECMP route: %s group %u paths %u\n", argv[1], entry.ecmp_group_id, group.count);
    close(ecmp_fd);
    close(route_fd);
    return 0;
}

// Add ARP entry
static int cmd_arp_add(int argc, char **argv)
{
    char *ip_str = NULL, *mac_str = NULL;
    int ifindex = 0;
    __u32 ip_key;
    struct arp_entry entry = {0};
    int fd, ret;
    
    struct option long_opts[] = {
        {"ip", required_argument, 0, 'i'},
        {"mac", required_argument, 0, 'm'},
        {"ifindex", required_argument, 0, 'I'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "i:m:I:", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'i':
            ip_str = optarg;
            break;
        case 'm':
            mac_str = optarg;
            break;
        case 'I':
            ifindex = atoi(optarg);
            break;
        default:
            RS_LOG_ERROR("Usage: rsroutectl arp-add --ip <IP> --mac <MAC> --ifindex <N>");
            return -1;
        }
    }
    
    if (!ip_str || !mac_str || ifindex == 0) {
        RS_LOG_ERROR("Missing required arguments (need --ip, --mac, --ifindex)");
        return -1;
    }
    
    // Parse IP
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) != 1) {
        RS_LOG_ERROR("Invalid IP address: %s", ip_str);
        return -1;
    }
    ip_key = addr.s_addr;
    
    // Parse MAC
    if (parse_mac(mac_str, entry.mac) < 0)
        return -1;
    
    entry.ifindex = ifindex;
    entry.timestamp = 0;  // Userspace doesn't set timestamp
    
    // Open map
    char map_path[256];
    snprintf(map_path, sizeof(map_path), "%s/arp_tbl", PIN_BASE_DIR);
    fd = bpf_obj_get(map_path);
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open ARP table: %s", strerror(errno));
        return -1;
    }
    
    ret = bpf_map_update_elem(fd, &ip_key, &entry, BPF_ANY);
    if (ret < 0) {
        RS_LOG_ERROR("Failed to add ARP entry: %s", strerror(errno));
        close(fd);
        return -1;
    }
    
    printf("Added ARP entry: %s → %02x:%02x:%02x:%02x:%02x:%02x dev %u\n",
           ip_str,
           entry.mac[0], entry.mac[1], entry.mac[2],
           entry.mac[3], entry.mac[4], entry.mac[5],
           entry.ifindex);
    
    close(fd);
    return 0;
}

// Delete ARP entry
static int cmd_arp_del(int argc, char **argv)
{
    char *ip_str = NULL;
    __u32 ip_key;
    int fd, ret;
    
    if (argc < 3 || strcmp(argv[1], "--ip") != 0) {
        RS_LOG_ERROR("Usage: rsroutectl arp-del --ip <IP>");
        return -1;
    }
    
    ip_str = argv[2];
    
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) != 1) {
        RS_LOG_ERROR("Invalid IP address: %s", ip_str);
        return -1;
    }
    ip_key = addr.s_addr;
    
    char map_path[256];
    snprintf(map_path, sizeof(map_path), "%s/arp_tbl", PIN_BASE_DIR);
    fd = bpf_obj_get(map_path);
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open ARP table: %s", strerror(errno));
        return -1;
    }
    
    ret = bpf_map_delete_elem(fd, &ip_key);
    if (ret < 0) {
        RS_LOG_ERROR("Failed to delete ARP entry: %s", strerror(errno));
        close(fd);
        return -1;
    }
    
    printf("Deleted ARP entry: %s\n", ip_str);
    
    close(fd);
    return 0;
}

// Show ARP table
static int cmd_arp_show(void)
{
    int fd = open_pinned_map("arp_tbl");
    __u64 now = monotonic_ns();
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open ARP table: %s", strerror(errno));
        return -1;
    }
    
    printf("\nARP Table:\n");
    printf("%-16s %-20s %-10s %-10s\n", "IP Address", "MAC Address", "Interface", "Age(s)");
    printf("-----------------------------------------------------------------------\n");
    
    __u32 key = 0, next_key;
    struct arp_entry entry;
    int count = 0;
    int has_prev = 0;
    
    while (bpf_map_get_next_key(fd, has_prev ? &key : NULL, &next_key) == 0) {
        if (bpf_map_lookup_elem(fd, &next_key, &entry) == 0) {
            struct in_addr addr;
            addr.s_addr = next_key;
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
            
            unsigned long long age_sec = 0;
            if (entry.timestamp > 0 && now > entry.timestamp)
                age_sec = (unsigned long long)((now - entry.timestamp) / 1000000000ULL);

            printf("%-16s %02x:%02x:%02x:%02x:%02x:%02x   %-10u %-10llu\n",
                   ip_str,
                   entry.mac[0], entry.mac[1], entry.mac[2],
                   entry.mac[3], entry.mac[4], entry.mac[5],
                   entry.ifindex,
                   age_sec);
            count++;
        }
        key = next_key;
        has_prev = 1;
    }
    
    if (count == 0)
        printf("(empty)\n");
    else
        printf("-----------------------------------------------------------------------\n");
    
    printf("Total: %d entries\n\n", count);
    
    close(fd);
    return 0;
}

static int cmd_flush_arp(void)
{
    int fd = open_pinned_map("arp_tbl");
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open ARP table: %s", strerror(errno));
        return -1;
    }

    __u32 next;
    int deleted = 0;

    while (bpf_map_get_next_key(fd, NULL, &next) == 0) {
        if (bpf_map_delete_elem(fd, &next) == 0)
            deleted++;
    }

    close(fd);
    printf("Flushed ARP table: %d entries removed\n", deleted);
    return 0;
}

static int cmd_set_arp_timeout(int argc, char **argv)
{
    if (argc < 2) {
        RS_LOG_ERROR("Usage: rsroutectl set-arp-timeout <seconds>");
        return -1;
    }

    __u32 sec = (__u32)strtoul(argv[1], NULL, 10);
    struct arp_cfg cfg = {
        .max_age_sec = sec,
        .enabled = sec > 0 ? 1 : 0,
    };
    __u32 key = 0;
    int fd = open_pinned_map("arp_config");
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open arp_config: %s", strerror(errno));
        return -1;
    }

    int ret = bpf_map_update_elem(fd, &key, &cfg, BPF_ANY);
    close(fd);
    if (ret != 0) {
        RS_LOG_ERROR("Failed to set ARP timeout: %s", strerror(errno));
        return -1;
    }

    printf("ARP timeout %s (%u seconds)\n", cfg.enabled ? "enabled" : "disabled", sec);
    return 0;
}

static int cmd_auto_populate(void)
{
    struct ifaddrs *ifas = NULL, *ifa;
    int route_fd = open_pinned_map("route_tbl");
    int added = 0;

    if (route_fd < 0) {
        RS_LOG_ERROR("Failed to open route table: %s", strerror(errno));
        return -1;
    }

    if (getifaddrs(&ifas) != 0) {
        RS_LOG_ERROR("getifaddrs failed: %s", strerror(errno));
        close(route_fd);
        return -1;
    }

    for (ifa = ifas; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || !ifa->ifa_netmask)
            continue;
        if (ifa->ifa_addr->sa_family != AF_INET)
            continue;
        if (!(ifa->ifa_flags & IFF_UP) || (ifa->ifa_flags & IFF_LOOPBACK))
            continue;

        struct sockaddr_in *a = (struct sockaddr_in *)ifa->ifa_addr;
        struct sockaddr_in *m = (struct sockaddr_in *)ifa->ifa_netmask;
        __u32 addr = a->sin_addr.s_addr;
        __u32 mask = m->sin_addr.s_addr;
        __u32 net = addr & mask;
        __u32 prefix = (__u32)__builtin_popcount(ntohl(mask));

        struct lpm_key key = {
            .prefixlen = prefix,
            .addr = net,
        };
        struct route_entry entry = {
            .nexthop = 0,
            .ifindex = if_nametoindex(ifa->ifa_name),
            .metric = 0,
            .type = 0,
            .ecmp_group_id = 0,
        };

        if (entry.ifindex == 0)
            continue;
        if (bpf_map_update_elem(route_fd, &key, &entry, BPF_ANY) == 0)
            added++;
    }

    freeifaddrs(ifas);
    close(route_fd);
    printf("Auto-populated %d connected routes\n", added);
    return 0;
}

// Configure interface
static int cmd_iface_set(int argc, char **argv)
{
    int ifindex = 0;
    char *mac_str = NULL;
    int is_router = 0;
    struct iface_config cfg = {0};
    int fd, ret;
    
    struct option long_opts[] = {
        {"ifindex", required_argument, 0, 'i'},
        {"mac", required_argument, 0, 'm'},
        {"router", no_argument, 0, 'r'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "i:m:r", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'i':
            ifindex = atoi(optarg);
            break;
        case 'm':
            mac_str = optarg;
            break;
        case 'r':
            is_router = 1;
            break;
        default:
            RS_LOG_ERROR("Usage: rsroutectl iface-set --ifindex <N> --mac <MAC> [--router]");
            return -1;
        }
    }
    
    if (ifindex == 0 || !mac_str) {
        RS_LOG_ERROR("Missing required arguments (need --ifindex, --mac)");
        return -1;
    }
    
    if (parse_mac(mac_str, cfg.mac) < 0)
        return -1;
    
    cfg.is_router = is_router;
    
    char map_path[256];
    snprintf(map_path, sizeof(map_path), "%s/iface_cfg", PIN_BASE_DIR);
    fd = bpf_obj_get(map_path);
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open interface config: %s", strerror(errno));
        return -1;
    }
    
    __u32 key = ifindex;
    ret = bpf_map_update_elem(fd, &key, &cfg, BPF_ANY);
    if (ret < 0) {
        RS_LOG_ERROR("Failed to set interface config: %s", strerror(errno));
        close(fd);
        return -1;
    }
    
    printf("Set interface %u: MAC=%02x:%02x:%02x:%02x:%02x:%02x %s\n",
           ifindex,
           cfg.mac[0], cfg.mac[1], cfg.mac[2],
           cfg.mac[3], cfg.mac[4], cfg.mac[5],
           cfg.is_router ? "(router)" : "");
    
    close(fd);
    return 0;
}

// Enable/disable routing
static int cmd_set_enabled(int enable)
{
    struct route_config cfg = {0};
    __u32 key = 0;
    int fd, ret;
    
    char map_path[256];
    snprintf(map_path, sizeof(map_path), "%s/route_cfg", PIN_BASE_DIR);
    fd = bpf_obj_get(map_path);
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open route config: %s", strerror(errno));
        return -1;
    }
    
    // Read existing config
    ret = bpf_map_lookup_elem(fd, &key, &cfg);
    if (ret < 0) {
        memset(&cfg, 0, sizeof(cfg));
    }
    
    cfg.enabled = enable ? 1 : 0;
    
    ret = bpf_map_update_elem(fd, &key, &cfg, BPF_ANY);
    if (ret < 0) {
        RS_LOG_ERROR("Failed to update routing state: %s", strerror(errno));
        close(fd);
        return -1;
    }
    
    printf("Routing %s\n", enable ? "enabled" : "disabled");
    
    close(fd);
    return 0;
}

// Show statistics
static int cmd_stats(void)
{
    char map_path[256];
    snprintf(map_path, sizeof(map_path), "%s/route_stats", PIN_BASE_DIR);
    
    int fd = bpf_obj_get(map_path);
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open stats map: %s", strerror(errno));
        return -1;
    }
    
    printf("\nRouting Statistics:\n");
    printf("══════════════════════════════════════\n");
    
    for (int i = 0; i < ROUTE_STAT_MAX; i++) {
        __u32 key = i;
        __u64 val = 0;
        
        if (bpf_map_lookup_elem(fd, &key, &val) == 0) {
            printf("  %-20s: %llu\n", stat_names[i], (unsigned long long)val);
        }
    }
    
    printf("══════════════════════════════════════\n\n");
    
    close(fd);
    return 0;
}

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s <command> [options]\n\n", prog);
    fprintf(stderr, "Commands:\n");
    fprintf(stderr, "  add             Add route: <prefix/len> via <nexthop> dev <if> [metric <N>]\n");
    fprintf(stderr, "  add-ecmp        Add ECMP route with 2-4 via/dev path pairs\n");
    fprintf(stderr, "  show            Show routing table with ECMP/ARP status\n");
    fprintf(stderr, "  show-arp        Show ARP table with age\n");
    fprintf(stderr, "  flush-arp       Delete all ARP entries\n");
    fprintf(stderr, "  set-arp-timeout Set ARP stale timeout in seconds\n");
    fprintf(stderr, "  auto-populate   Add connected routes from system interfaces\n");
    fprintf(stderr, "  route-add       Add route to routing table\n");
    fprintf(stderr, "  route-del       Delete route from routing table\n");
    fprintf(stderr, "  route-show      Show routing table\n");
    fprintf(stderr, "  arp-add         Add ARP entry\n");
    fprintf(stderr, "  arp-del         Delete ARP entry\n");
    fprintf(stderr, "  arp-show        Show ARP table\n");
    fprintf(stderr, "  iface-set       Configure interface MAC and router status\n");
    fprintf(stderr, "  enable          Enable routing\n");
    fprintf(stderr, "  disable         Disable routing\n");
    fprintf(stderr, "  stats           Show routing statistics\n\n");
    fprintf(stderr, "Examples:\n");
    fprintf(stderr, "  %s add 192.168.1.0/24 via 0.0.0.0 dev eth0 metric 10\n\n", prog);
    fprintf(stderr, "  %s add-ecmp 10.0.0.0/8 via 192.168.1.2 dev eth0 via 192.168.1.3 dev eth1\n\n", prog);
    fprintf(stderr, "  %s show\n\n", prog);
    fprintf(stderr, "  %s show-arp\n\n", prog);
    fprintf(stderr, "  # Add direct route (connected network)\n");
    fprintf(stderr, "  %s route-add --dest 192.168.1.0/24 --nexthop 0.0.0.0 --ifindex 1\n\n", prog);
    fprintf(stderr, "  # Add static route via gateway\n");
    fprintf(stderr, "  %s route-add --dest 10.0.0.0/8 --nexthop 192.168.1.254 --ifindex 1 --metric 10\n\n", prog);
    fprintf(stderr, "  # Add default route\n");
    fprintf(stderr, "  %s route-add --dest 0.0.0.0/0 --nexthop 192.168.1.254 --ifindex 1 --metric 100\n\n", prog);
    fprintf(stderr, "  # Add ARP entry for gateway\n");
    fprintf(stderr, "  %s arp-add --ip 192.168.1.254 --mac 00:11:22:33:44:55 --ifindex 1\n\n", prog);
    fprintf(stderr, "  # Configure router interface\n");
    fprintf(stderr, "  %s iface-set --ifindex 1 --mac 00:aa:bb:cc:dd:ee --router\n\n", prog);
    fprintf(stderr, "  # Enable routing\n");
    fprintf(stderr, "  %s enable\n", prog);
}

int main(int argc, char **argv)
{
    rs_log_init("rsroutectl", RS_LOG_LEVEL_INFO);

    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }
    
    const char *cmd = argv[1];
    
    if (strcmp(cmd, "add") == 0) {
        return cmd_add_simple(argc - 1, argv + 1);
    } else if (strcmp(cmd, "add-ecmp") == 0) {
        return cmd_add_ecmp(argc - 1, argv + 1);
    } else if (strcmp(cmd, "show") == 0 || strcmp(cmd, "route-show") == 0) {
        return cmd_route_show();
    } else if (strcmp(cmd, "show-arp") == 0 || strcmp(cmd, "arp-show") == 0) {
        return cmd_arp_show();
    } else if (strcmp(cmd, "flush-arp") == 0) {
        return cmd_flush_arp();
    } else if (strcmp(cmd, "set-arp-timeout") == 0) {
        return cmd_set_arp_timeout(argc - 1, argv + 1);
    } else if (strcmp(cmd, "auto-populate") == 0) {
        return cmd_auto_populate();
    } else if (strcmp(cmd, "route-add") == 0) {
        return cmd_route_add(argc - 1, argv + 1);
    } else if (strcmp(cmd, "route-del") == 0) {
        return cmd_route_del(argc - 1, argv + 1);
    } else if (strcmp(cmd, "arp-add") == 0) {
        return cmd_arp_add(argc - 1, argv + 1);
    } else if (strcmp(cmd, "arp-del") == 0) {
        return cmd_arp_del(argc - 1, argv + 1);
    } else if (strcmp(cmd, "iface-set") == 0) {
        return cmd_iface_set(argc - 1, argv + 1);
    } else if (strcmp(cmd, "enable") == 0) {
        return cmd_set_enabled(1);
    } else if (strcmp(cmd, "disable") == 0) {
        return cmd_set_enabled(0);
    } else if (strcmp(cmd, "stats") == 0) {
        return cmd_stats();
    } else {
        RS_LOG_ERROR("Unknown command: %s", cmd);
        usage(argv[0]);
        return 1;
    }
}
