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
#include <sys/stat.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define PIN_BASE_DIR "/sys/fs/bpf"

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

enum route_stat_type {
    ROUTE_STAT_LOOKUP = 0,
    ROUTE_STAT_HIT = 1,
    ROUTE_STAT_MISS = 2,
    ROUTE_STAT_ARP_HIT = 3,
    ROUTE_STAT_ARP_MISS = 4,
    ROUTE_STAT_TTL_EXCEEDED = 5,
    ROUTE_STAT_DIRECT = 6,
    ROUTE_STAT_STATIC = 7,
    ROUTE_STAT_MAX = 8,
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
            fprintf(stderr, "Invalid prefix length: %u (must be 0-32)\n", *prefixlen);
            return -1;
        }
    } else {
        *prefixlen = 32;  // Host route
    }
    
    if (inet_pton(AF_INET, buf, &addr) != 1) {
        fprintf(stderr, "Invalid IP address: %s\n", buf);
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
        fprintf(stderr, "Invalid MAC address: %s (format: XX:XX:XX:XX:XX:XX)\n", mac_str);
        return -1;
    }
    
    for (int i = 0; i < 6; i++)
        mac[i] = (__u8)m[i];
    
    return 0;
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
            fprintf(stderr, "Usage: rsroutectl route-add --dest <CIDR> --nexthop <IP> --ifindex <N> [--metric <M>]\n");
            return -1;
        }
    }
    
    if (!dest_str || !nexthop_str || ifindex == 0) {
        fprintf(stderr, "Missing required arguments (need --dest, --nexthop, --ifindex)\n");
        return -1;
    }
    
    // Parse destination
    if (parse_cidr(dest_str, &key.addr, &key.prefixlen) < 0)
        return -1;
    
    // Parse nexthop (0.0.0.0 means direct route)
    struct in_addr nh_addr;
    if (inet_pton(AF_INET, nexthop_str, &nh_addr) != 1) {
        fprintf(stderr, "Invalid nexthop IP: %s\n", nexthop_str);
        return -1;
    }
    
    entry.nexthop = nh_addr.s_addr;
    entry.ifindex = ifindex;
    entry.metric = metric;
    entry.type = (entry.nexthop == 0) ? 0 : 1;  // 0=direct, 1=static
    
    // Open map
    char map_path[256];
    snprintf(map_path, sizeof(map_path), "%s/route_tbl", PIN_BASE_DIR);
    fd = bpf_obj_get(map_path);
    if (fd < 0) {
        fprintf(stderr, "Failed to open route table: %s\n", strerror(errno));
        return -1;
    }
    
    // Add route
    ret = bpf_map_update_elem(fd, &key, &entry, BPF_ANY);
    if (ret < 0) {
        fprintf(stderr, "Failed to add route: %s\n", strerror(errno));
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
        fprintf(stderr, "Usage: rsroutectl route-del --dest <CIDR>\n");
        return -1;
    }
    
    dest_str = argv[2];
    
    if (parse_cidr(dest_str, &key.addr, &key.prefixlen) < 0)
        return -1;
    
    char map_path[256];
    snprintf(map_path, sizeof(map_path), "%s/route_tbl", PIN_BASE_DIR);
    fd = bpf_obj_get(map_path);
    if (fd < 0) {
        fprintf(stderr, "Failed to open route table: %s\n", strerror(errno));
        return -1;
    }
    
    ret = bpf_map_delete_elem(fd, &key);
    if (ret < 0) {
        fprintf(stderr, "Failed to delete route: %s\n", strerror(errno));
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
    printf("\nRouting Table:\n");
    printf("══════════════════════════════════════\n");
    printf("Note: LPM tries cannot be iterated.\n");
    printf("Use 'route-add' commands are shown in config.\n\n");
    
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
            fprintf(stderr, "Usage: rsroutectl arp-add --ip <IP> --mac <MAC> --ifindex <N>\n");
            return -1;
        }
    }
    
    if (!ip_str || !mac_str || ifindex == 0) {
        fprintf(stderr, "Missing required arguments (need --ip, --mac, --ifindex)\n");
        return -1;
    }
    
    // Parse IP
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) != 1) {
        fprintf(stderr, "Invalid IP address: %s\n", ip_str);
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
        fprintf(stderr, "Failed to open ARP table: %s\n", strerror(errno));
        return -1;
    }
    
    ret = bpf_map_update_elem(fd, &ip_key, &entry, BPF_ANY);
    if (ret < 0) {
        fprintf(stderr, "Failed to add ARP entry: %s\n", strerror(errno));
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
        fprintf(stderr, "Usage: rsroutectl arp-del --ip <IP>\n");
        return -1;
    }
    
    ip_str = argv[2];
    
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) != 1) {
        fprintf(stderr, "Invalid IP address: %s\n", ip_str);
        return -1;
    }
    ip_key = addr.s_addr;
    
    char map_path[256];
    snprintf(map_path, sizeof(map_path), "%s/arp_tbl", PIN_BASE_DIR);
    fd = bpf_obj_get(map_path);
    if (fd < 0) {
        fprintf(stderr, "Failed to open ARP table: %s\n", strerror(errno));
        return -1;
    }
    
    ret = bpf_map_delete_elem(fd, &ip_key);
    if (ret < 0) {
        fprintf(stderr, "Failed to delete ARP entry: %s\n", strerror(errno));
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
    char map_path[256];
    snprintf(map_path, sizeof(map_path), "%s/arp_tbl", PIN_BASE_DIR);
    
    int fd = bpf_obj_get(map_path);
    if (fd < 0) {
        fprintf(stderr, "Failed to open ARP table: %s\n", strerror(errno));
        return -1;
    }
    
    printf("\nARP Table:\n");
    printf("══════════════════════════════════════════════════════════\n");
    printf("%-16s %-20s %-10s\n", "IP Address", "MAC Address", "Interface");
    printf("──────────────────────────────────────────────────────────\n");
    
    __u32 key = 0, next_key;
    struct arp_entry entry;
    int count = 0;
    
    while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(fd, &next_key, &entry) == 0) {
            struct in_addr addr;
            addr.s_addr = next_key;
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
            
            printf("%-16s %02x:%02x:%02x:%02x:%02x:%02x   %-10u\n",
                   ip_str,
                   entry.mac[0], entry.mac[1], entry.mac[2],
                   entry.mac[3], entry.mac[4], entry.mac[5],
                   entry.ifindex);
            count++;
        }
        key = next_key;
    }
    
    if (count == 0)
        printf("(empty)\n");
    else
        printf("──────────────────────────────────────────────────────────\n");
    
    printf("Total: %d entries\n\n", count);
    
    close(fd);
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
            fprintf(stderr, "Usage: rsroutectl iface-set --ifindex <N> --mac <MAC> [--router]\n");
            return -1;
        }
    }
    
    if (ifindex == 0 || !mac_str) {
        fprintf(stderr, "Missing required arguments (need --ifindex, --mac)\n");
        return -1;
    }
    
    if (parse_mac(mac_str, cfg.mac) < 0)
        return -1;
    
    cfg.is_router = is_router;
    
    char map_path[256];
    snprintf(map_path, sizeof(map_path), "%s/iface_cfg", PIN_BASE_DIR);
    fd = bpf_obj_get(map_path);
    if (fd < 0) {
        fprintf(stderr, "Failed to open interface config: %s\n", strerror(errno));
        return -1;
    }
    
    __u32 key = ifindex;
    ret = bpf_map_update_elem(fd, &key, &cfg, BPF_ANY);
    if (ret < 0) {
        fprintf(stderr, "Failed to set interface config: %s\n", strerror(errno));
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
        fprintf(stderr, "Failed to open route config: %s\n", strerror(errno));
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
        fprintf(stderr, "Failed to update routing state: %s\n", strerror(errno));
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
        fprintf(stderr, "Failed to open stats map: %s\n", strerror(errno));
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
    fprintf(stderr, "  route-add       Add route to routing table\n");
    fprintf(stderr, "  route-del       Delete route from routing table\n");
    fprintf(stderr, "  route-show      Show routing table (LPM tries cannot be iterated)\n");
    fprintf(stderr, "  arp-add         Add ARP entry\n");
    fprintf(stderr, "  arp-del         Delete ARP entry\n");
    fprintf(stderr, "  arp-show        Show ARP table\n");
    fprintf(stderr, "  iface-set       Configure interface MAC and router status\n");
    fprintf(stderr, "  enable          Enable routing\n");
    fprintf(stderr, "  disable         Disable routing\n");
    fprintf(stderr, "  stats           Show routing statistics\n\n");
    fprintf(stderr, "Examples:\n");
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
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }
    
    const char *cmd = argv[1];
    
    if (strcmp(cmd, "route-add") == 0) {
        return cmd_route_add(argc - 1, argv + 1);
    } else if (strcmp(cmd, "route-del") == 0) {
        return cmd_route_del(argc - 1, argv + 1);
    } else if (strcmp(cmd, "route-show") == 0) {
        return cmd_route_show();
    } else if (strcmp(cmd, "arp-add") == 0) {
        return cmd_arp_add(argc - 1, argv + 1);
    } else if (strcmp(cmd, "arp-del") == 0) {
        return cmd_arp_del(argc - 1, argv + 1);
    } else if (strcmp(cmd, "arp-show") == 0) {
        return cmd_arp_show();
    } else if (strcmp(cmd, "iface-set") == 0) {
        return cmd_iface_set(argc - 1, argv + 1);
    } else if (strcmp(cmd, "enable") == 0) {
        return cmd_set_enabled(1);
    } else if (strcmp(cmd, "disable") == 0) {
        return cmd_set_enabled(0);
    } else if (strcmp(cmd, "stats") == 0) {
        return cmd_stats();
    } else {
        fprintf(stderr, "Unknown command: %s\n\n", cmd);
        usage(argv[0]);
        return 1;
    }
}
