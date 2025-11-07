// SPDX-License-Identifier: GPL-2.0
/*
 * rsaclctl - rSwitch ACL Control Tool
 * 
 * Manages ACL rules with 7-level partial match architecture:
 * - Level 1: 5-tuple exact match (proto+src_ip+dst_ip+sport+dport)
 * - Level 2: Proto + Dst IP + Dst Port (any source → specific destination)
 * - Level 3: Proto + Src IP + Dst Port (specific source → any destination)
 * - Level 4: Proto + Dst Port (global port filtering)
 * - Level 5: Src IP prefix (LPM trie)
 * - Level 6: Dst IP prefix (LPM trie)
 * - Level 7: Default policy
 * 
 * Usage:
 *   rsaclctl add-5t --proto tcp --src 10.1.2.3 --sport 443 --dst 192.168.1.100 --dport 22 --action drop
 *   rsaclctl add-proto-dst --proto tcp --dst 203.0.113.5 --dport 443 --action drop
 *   rsaclctl add-proto-src --proto tcp --src 10.1.2.3 --dport 22 --action drop
 *   rsaclctl add-proto-port --proto udp --dport 443 --action drop
 *   rsaclctl add-lpm-src --prefix 192.168.0.0/16 --action pass
 *   rsaclctl add-lpm-dst --prefix 10.0.0.0/8 --action drop
 *   rsaclctl set-default --action pass
 *   rsaclctl enable / disable
 *   rsaclctl list / stats / clear
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

// Match BPF structures from acl.bpf.c
enum acl_action {
    ACL_ACTION_PASS = 0,
    ACL_ACTION_DROP = 1,
    ACL_ACTION_REDIRECT = 2,
};

struct acl_result {
    __u8 action;
    __u8 log_event;
    __u16 redirect_ifindex;
    __u32 stats_id;
} __attribute__((packed));

struct acl_5tuple_key {
    __u8  proto;
    __u8  pad[3];
    __u32 src_ip;
    __u32 dst_ip;
    __u16 sport;
    __u16 dport;
} __attribute__((packed));

// Level 2: Proto + Dst IP + Dst Port
struct acl_proto_dstip_port_key {
    __u8  proto;
    __u8  pad[3];
    __u32 dst_ip;
    __u16 dst_port;
    __u16 pad2;
} __attribute__((packed));

// Level 3: Proto + Src IP + Dst Port
struct acl_proto_srcip_port_key {
    __u8  proto;
    __u8  pad[3];
    __u32 src_ip;
    __u16 dst_port;
    __u16 pad2;
} __attribute__((packed));

// Level 4: Proto + Dst Port
struct acl_proto_port_key {
    __u8  proto;
    __u8  pad;
    __u16 dst_port;
} __attribute__((packed));

struct acl_lpm_key {
    __u32 prefixlen;
    __u32 ip;
};

struct acl_config {
    __u8 default_action;
    __u8 enabled;
    __u8 log_drops;
    __u8 pad;
};

enum acl_stat_type {
    ACL_STAT_L1_5TUPLE_HIT = 0,
    ACL_STAT_L2_PROTO_DSTIP_PORT_HIT = 1,
    ACL_STAT_L3_PROTO_SRCIP_PORT_HIT = 2,
    ACL_STAT_L4_PROTO_PORT_HIT = 3,
    ACL_STAT_L5_LPM_SRC_HIT = 4,
    ACL_STAT_L6_LPM_DST_HIT = 5,
    ACL_STAT_L7_DEFAULT_PASS = 6,
    ACL_STAT_L7_DEFAULT_DROP = 7,
    ACL_STAT_TOTAL_DROPS = 8,
    ACL_STAT_MAX = 9,
};

#define PIN_BASE_DIR "/sys/fs/bpf"

static const char *stat_names[] = {
    [ACL_STAT_L1_5TUPLE_HIT] = "L1: 5-tuple hits",
    [ACL_STAT_L2_PROTO_DSTIP_PORT_HIT] = "L2: Proto+DstIP+Port hits",
    [ACL_STAT_L3_PROTO_SRCIP_PORT_HIT] = "L3: Proto+SrcIP+Port hits",
    [ACL_STAT_L4_PROTO_PORT_HIT] = "L4: Proto+Port hits",
    [ACL_STAT_L5_LPM_SRC_HIT] = "L5: LPM src hits",
    [ACL_STAT_L6_LPM_DST_HIT] = "L6: LPM dst hits",
    [ACL_STAT_L7_DEFAULT_PASS] = "L7: Default PASS",
    [ACL_STAT_L7_DEFAULT_DROP] = "L7: Default DROP",
    [ACL_STAT_TOTAL_DROPS] = "Total drops",
};

static const char *action_names[] = {
    [ACL_ACTION_PASS] = "PASS",
    [ACL_ACTION_DROP] = "DROP",
    [ACL_ACTION_REDIRECT] = "REDIRECT",
};

// Parse protocol name to number
static int parse_protocol(const char *proto_str)
{
    if (strcasecmp(proto_str, "tcp") == 0)
        return 6;
    if (strcasecmp(proto_str, "udp") == 0)
        return 17;
    if (strcasecmp(proto_str, "icmp") == 0)
        return 1;
    if (strcasecmp(proto_str, "any") == 0)
        return 0;
    
    // Try as number
    return atoi(proto_str);
}

// Parse action name to enum
static int parse_action(const char *action_str)
{
    if (strcasecmp(action_str, "pass") == 0 || strcasecmp(action_str, "accept") == 0)
        return ACL_ACTION_PASS;
    if (strcasecmp(action_str, "drop") == 0 || strcasecmp(action_str, "deny") == 0)
        return ACL_ACTION_DROP;
    if (strcasecmp(action_str, "redirect") == 0)
        return ACL_ACTION_REDIRECT;
    
    fprintf(stderr, "Invalid action: %s (must be pass/drop/redirect)\n", action_str);
    return -1;
}

// Parse IP/prefix (192.168.1.0/24 or 10.1.2.3)
static int parse_ip_prefix(const char *cidr, __u32 *ip, __u32 *prefixlen)
{
    char buf[64];
    char *slash;
    
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
        *prefixlen = 32;  // Host address
    }
    
    if (inet_pton(AF_INET, buf, ip) != 1) {
        fprintf(stderr, "Invalid IP address: %s\n", buf);
        return -1;
    }
    
    return 0;
}

// Add 5-tuple exact match rule
static int cmd_add_5tuple(int argc, char **argv)
{
    struct acl_5tuple_key key = {0};
    struct acl_result result = {0};
    char *proto_str = NULL, *src_str = NULL, *dst_str = NULL, *action_str = NULL;
    int sport = 0, dport = 0;
    int fd, ret;
    
    struct option long_opts[] = {
        {"proto", required_argument, 0, 'p'},
        {"src", required_argument, 0, 's'},
        {"sport", required_argument, 0, 'S'},
        {"dst", required_argument, 0, 'd'},
        {"dport", required_argument, 0, 'D'},
        {"action", required_argument, 0, 'a'},
        {"redirect-ifindex", required_argument, 0, 'r'},
        {"log", no_argument, 0, 'l'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "p:s:S:d:D:a:r:l", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'p':
            proto_str = optarg;
            break;
        case 's':
            src_str = optarg;
            break;
        case 'S':
            sport = atoi(optarg);
            break;
        case 'd':
            dst_str = optarg;
            break;
        case 'D':
            dport = atoi(optarg);
            break;
        case 'a':
            action_str = optarg;
            break;
        case 'r':
            result.redirect_ifindex = atoi(optarg);
            break;
        case 'l':
            result.log_event = 1;
            break;
        default:
            fprintf(stderr, "Usage: rsaclctl add-5t --proto <proto> --src <ip> --sport <port> --dst <ip> --dport <port> --action <action> [--redirect-ifindex <idx>] [--log]\n");
            fprintf(stderr, "Note: This is EXACT 5-tuple match. All fields including ports must match exactly.\n");
            fprintf(stderr, "      Omitted ports default to 0. Use add-proto-{dst,src,port} for partial matching.\n");
            return -1;
        }
    }
    
    if (!proto_str || !src_str || !dst_str || !action_str) {
        fprintf(stderr, "Missing required arguments (need --proto, --src, --dst, --action)\n");
        fprintf(stderr, "Note: 5-tuple requires EXACT match on all fields including ports.\n");
        fprintf(stderr, "      If --sport or --dport is omitted, it defaults to 0 (matches port 0 only).\n");
        fprintf(stderr, "      For wildcard matching, use:\n");
        fprintf(stderr, "        - add-proto-dst: match any source -> specific destination\n");
        fprintf(stderr, "        - add-proto-src: match specific source -> any destination\n");
        fprintf(stderr, "        - add-proto-port: match any source/destination on specific port\n");
        return -1;
    }
    
    // Parse fields
    key.proto = parse_protocol(proto_str);
    if (inet_pton(AF_INET, src_str, &key.src_ip) != 1) {
        fprintf(stderr, "Invalid source IP: %s\n", src_str);
        return -1;
    }
    if (inet_pton(AF_INET, dst_str, &key.dst_ip) != 1) {
        fprintf(stderr, "Invalid destination IP: %s\n", dst_str);
        return -1;
    }
    key.sport = htons(sport);
    key.dport = htons(dport);
    
    result.action = parse_action(action_str);
    if (result.action < 0)
        return -1;
    
    // Open map
    char map_path[256];
    snprintf(map_path, sizeof(map_path), "%s/acl_5tuple_map", PIN_BASE_DIR);
    fd = bpf_obj_get(map_path);
    if (fd < 0) {
        fprintf(stderr, "Failed to open 5-tuple map: %s\n", strerror(errno));
        return -1;
    }
    
    // Add rule
    ret = bpf_map_update_elem(fd, &key, &result, BPF_ANY);
    if (ret < 0) {
        fprintf(stderr, "Failed to add 5-tuple rule: %s\n", strerror(errno));
        close(fd);
        return -1;
    }
    
    char src_fmt[INET_ADDRSTRLEN], dst_fmt[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &key.src_ip, src_fmt, sizeof(src_fmt));
    inet_ntop(AF_INET, &key.dst_ip, dst_fmt, sizeof(dst_fmt));
    
    printf("Added 5-tuple rule: proto=%u %s:%u -> %s:%u action=%s%s\n",
           key.proto, src_fmt, ntohs(key.sport), dst_fmt, ntohs(key.dport),
           action_names[result.action],
           result.log_event ? " (log)" : "");
    
    close(fd);
    return 0;
}

// Add Level 2: Proto + Dst IP + Dst Port rule
static int cmd_add_proto_dst(int argc, char **argv)
{
    struct acl_proto_dstip_port_key key = {0};
    struct acl_result result = {0};
    char *proto_str = NULL, *dst_str = NULL, *action_str = NULL;
    int dport = 0;
    int fd, ret;
    
    struct option long_opts[] = {
        {"proto", required_argument, 0, 'p'},
        {"dst", required_argument, 0, 'd'},
        {"dport", required_argument, 0, 'D'},
        {"action", required_argument, 0, 'a'},
        {"log", no_argument, 0, 'l'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "p:d:D:a:l", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'p':
            proto_str = optarg;
            break;
        case 'd':
            dst_str = optarg;
            break;
        case 'D':
            dport = atoi(optarg);
            break;
        case 'a':
            action_str = optarg;
            break;
        case 'l':
            result.log_event = 1;
            break;
        default:
            fprintf(stderr, "Usage: rsaclctl add-proto-dst --proto <proto> --dst <ip> --dport <port> --action <action> [--log]\n");
            return -1;
        }
    }
    
    if (!proto_str || !dst_str || !action_str) {
        fprintf(stderr, "Missing required arguments (need --proto, --dst, --dport, --action)\n");
        return -1;
    }
    
    // Parse fields
    key.proto = parse_protocol(proto_str);
    if (inet_pton(AF_INET, dst_str, &key.dst_ip) != 1) {
        fprintf(stderr, "Invalid destination IP: %s\n", dst_str);
        return -1;
    }
    key.dst_port = htons(dport);
    
    result.action = parse_action(action_str);
    if (result.action < 0)
        return -1;
    
    // Open map
    char map_path[256];
    snprintf(map_path, sizeof(map_path), "%s/acl_pdp_map", PIN_BASE_DIR);
    fd = bpf_obj_get(map_path);
    if (fd < 0) {
        fprintf(stderr, "Failed to open proto+dst map: %s\n", strerror(errno));
        return -1;
    }
    
    // Add rule
    ret = bpf_map_update_elem(fd, &key, &result, BPF_ANY);
    if (ret < 0) {
        fprintf(stderr, "Failed to add proto+dst rule: %s\n", strerror(errno));
        close(fd);
        return -1;
    }
    
    char dst_fmt[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &key.dst_ip, dst_fmt, sizeof(dst_fmt));
    
    printf("Added Level 2 rule: proto=%u * -> %s:%u action=%s%s\n",
           key.proto, dst_fmt, ntohs(key.dst_port),
           action_names[result.action],
           result.log_event ? " (log)" : "");
    
    close(fd);
    return 0;
}

// Add Level 3: Proto + Src IP + Dst Port rule
static int cmd_add_proto_src(int argc, char **argv)
{
    struct acl_proto_srcip_port_key key = {0};
    struct acl_result result = {0};
    char *proto_str = NULL, *src_str = NULL, *action_str = NULL;
    int dport = 0;
    int fd, ret;
    
    struct option long_opts[] = {
        {"proto", required_argument, 0, 'p'},
        {"src", required_argument, 0, 's'},
        {"dport", required_argument, 0, 'D'},
        {"action", required_argument, 0, 'a'},
        {"log", no_argument, 0, 'l'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "p:s:D:a:l", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'p':
            proto_str = optarg;
            break;
        case 's':
            src_str = optarg;
            break;
        case 'D':
            dport = atoi(optarg);
            break;
        case 'a':
            action_str = optarg;
            break;
        case 'l':
            result.log_event = 1;
            break;
        default:
            fprintf(stderr, "Usage: rsaclctl add-proto-src --proto <proto> --src <ip> --dport <port> --action <action> [--log]\n");
            return -1;
        }
    }
    
    if (!proto_str || !src_str || !action_str) {
        fprintf(stderr, "Missing required arguments (need --proto, --src, --dport, --action)\n");
        return -1;
    }
    
    // Parse fields
    key.proto = parse_protocol(proto_str);
    if (inet_pton(AF_INET, src_str, &key.src_ip) != 1) {
        fprintf(stderr, "Invalid source IP: %s\n", src_str);
        return -1;
    }
    key.dst_port = htons(dport);
    
    result.action = parse_action(action_str);
    if (result.action < 0)
        return -1;
    
    // Open map
    char map_path[256];
    snprintf(map_path, sizeof(map_path), "%s/acl_psp_map", PIN_BASE_DIR);
    fd = bpf_obj_get(map_path);
    if (fd < 0) {
        fprintf(stderr, "Failed to open proto+src map: %s\n", strerror(errno));
        return -1;
    }
    
    // Add rule
    ret = bpf_map_update_elem(fd, &key, &result, BPF_ANY);
    if (ret < 0) {
        fprintf(stderr, "Failed to add proto+src rule: %s\n", strerror(errno));
        close(fd);
        return -1;
    }
    
    char src_fmt[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &key.src_ip, src_fmt, sizeof(src_fmt));
    
    printf("Added Level 3 rule: proto=%u %s:* -> *:%u action=%s%s\n",
           key.proto, src_fmt, ntohs(key.dst_port),
           action_names[result.action],
           result.log_event ? " (log)" : "");
    
    close(fd);
    return 0;
}

// Add Level 4: Proto + Dst Port rule (global port filtering)
static int cmd_add_proto_port(int argc, char **argv)
{
    struct acl_proto_port_key key = {0};
    struct acl_result result = {0};
    char *proto_str = NULL, *action_str = NULL;
    int dport = 0;
    int fd, ret;
    
    struct option long_opts[] = {
        {"proto", required_argument, 0, 'p'},
        {"dport", required_argument, 0, 'D'},
        {"action", required_argument, 0, 'a'},
        {"log", no_argument, 0, 'l'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "p:D:a:l", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'p':
            proto_str = optarg;
            break;
        case 'D':
            dport = atoi(optarg);
            break;
        case 'a':
            action_str = optarg;
            break;
        case 'l':
            result.log_event = 1;
            break;
        default:
            fprintf(stderr, "Usage: rsaclctl add-proto-port --proto <proto> --dport <port> --action <action> [--log]\n");
            return -1;
        }
    }
    
    if (!proto_str || !action_str) {
        fprintf(stderr, "Missing required arguments (need --proto, --dport, --action)\n");
        return -1;
    }
    
    // Parse fields
    key.proto = parse_protocol(proto_str);
    key.dst_port = htons(dport);
    
    result.action = parse_action(action_str);
    if (result.action < 0)
        return -1;
    
    // Open map
    char map_path[256];
    snprintf(map_path, sizeof(map_path), "%s/acl_pp_map", PIN_BASE_DIR);
    fd = bpf_obj_get(map_path);
    if (fd < 0) {
        fprintf(stderr, "Failed to open proto+port map: %s\n", strerror(errno));
        return -1;
    }
    
    // Add rule
    ret = bpf_map_update_elem(fd, &key, &result, BPF_ANY);
    if (ret < 0) {
        fprintf(stderr, "Failed to add proto+port rule: %s\n", strerror(errno));
        close(fd);
        return -1;
    }
    
    printf("Added Level 4 rule: proto=%u * -> *:%u action=%s%s\n",
           key.proto, ntohs(key.dst_port),
           action_names[result.action],
           result.log_event ? " (log)" : "");
    
    close(fd);
    return 0;
}

// Add LPM prefix rule
static int cmd_add_lpm(const char *map_name, int argc, char **argv)
{
    struct acl_lpm_key key = {0};
    struct acl_result result = {0};
    char *prefix_str = NULL, *action_str = NULL;
    int fd, ret;
    
    struct option long_opts[] = {
        {"prefix", required_argument, 0, 'p'},
        {"action", required_argument, 0, 'a'},
        {"log", no_argument, 0, 'l'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "p:a:l", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'p':
            prefix_str = optarg;
            break;
        case 'a':
            action_str = optarg;
            break;
        case 'l':
            result.log_event = 1;
            break;
        default:
            fprintf(stderr, "Usage: rsaclctl %s --prefix <ip/prefix> --action <action> [--log]\n", map_name);
            return -1;
        }
    }
    
    if (!prefix_str || !action_str) {
        fprintf(stderr, "Missing required arguments (need --prefix, --action)\n");
        return -1;
    }
    
    if (parse_ip_prefix(prefix_str, &key.ip, &key.prefixlen) < 0)
        return -1;
    
    result.action = parse_action(action_str);
    if (result.action < 0)
        return -1;
    
    char map_path[256];
    snprintf(map_path, sizeof(map_path), "%s/%s", PIN_BASE_DIR, map_name);
    fd = bpf_obj_get(map_path);
    if (fd < 0) {
        fprintf(stderr, "Failed to open %s: %s\n", map_name, strerror(errno));
        return -1;
    }
    
    ret = bpf_map_update_elem(fd, &key, &result, BPF_ANY);
    if (ret < 0) {
        fprintf(stderr, "Failed to add LPM rule: %s\n", strerror(errno));
        close(fd);
        return -1;
    }
    
    char ip_fmt[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &key.ip, ip_fmt, sizeof(ip_fmt));
    
    printf("Added %s rule: %s/%u action=%s%s\n",
           map_name, ip_fmt, key.prefixlen,
           action_names[result.action],
           result.log_event ? " (log)" : "");
    
    close(fd);
    return 0;
}

// Set default action
static int cmd_set_default(int argc, char **argv)
{
    char *action_str = NULL;
    struct acl_config cfg;
    __u32 key = 0;
    int fd, ret;
    
    if (argc < 3 || strcmp(argv[1], "--action") != 0) {
        fprintf(stderr, "Usage: rsaclctl set-default --action <pass|drop>\n");
        return -1;
    }
    
    action_str = argv[2];
    int action = parse_action(action_str);
    if (action < 0)
        return -1;
    
    char map_path[256];
    snprintf(map_path, sizeof(map_path), "%s/acl_config_map", PIN_BASE_DIR);
    fd = bpf_obj_get(map_path);
    if (fd < 0) {
        fprintf(stderr, "Failed to open config map: %s\n", strerror(errno));
        return -1;
    }
    
    // Read current config
    ret = bpf_map_lookup_elem(fd, &key, &cfg);
    if (ret < 0) {
        // Initialize if not exists
        memset(&cfg, 0, sizeof(cfg));
        cfg.enabled = 1;
    }
    
    cfg.default_action = action;
    
    ret = bpf_map_update_elem(fd, &key, &cfg, BPF_ANY);
    if (ret < 0) {
        fprintf(stderr, "Failed to set default action: %s\n", strerror(errno));
        close(fd);
        return -1;
    }
    
    printf("Default action set to: %s\n", action_names[action]);
    
    close(fd);
    return 0;
}

// Enable/disable ACL
static int cmd_set_enabled(int enable)
{
    struct acl_config cfg;
    __u32 key = 0;
    int fd, ret;
    
    char map_path[256];
    snprintf(map_path, sizeof(map_path), "%s/acl_config_map", PIN_BASE_DIR);
    fd = bpf_obj_get(map_path);
    if (fd < 0) {
        fprintf(stderr, "Failed to open config map: %s\n", strerror(errno));
        return -1;
    }
    
    ret = bpf_map_lookup_elem(fd, &key, &cfg);
    if (ret < 0) {
        memset(&cfg, 0, sizeof(cfg));
        cfg.default_action = ACL_ACTION_PASS;
    }
    
    cfg.enabled = enable ? 1 : 0;
    
    ret = bpf_map_update_elem(fd, &key, &cfg, BPF_ANY);
    if (ret < 0) {
        fprintf(stderr, "Failed to update ACL state: %s\n", strerror(errno));
        close(fd);
        return -1;
    }
    
    printf("ACL %s\n", enable ? "enabled" : "disabled");
    
    close(fd);
    return 0;
}

// Show statistics
static int cmd_stats(void)
{
    __u64 stats[ACL_STAT_MAX] = {0};
    int fd, i;
    
    char map_path[256];
    snprintf(map_path, sizeof(map_path), "%s/acl_stats_map", PIN_BASE_DIR);
    fd = bpf_obj_get(map_path);
    if (fd < 0) {
        fprintf(stderr, "Failed to open stats map: %s\n", strerror(errno));
        return -1;
    }
    
    printf("\nACL Statistics:\n");
    printf("───────────────────────────────────────\n");
    
    for (i = 0; i < ACL_STAT_MAX; i++) {
        __u32 key = i;
        __u64 val = 0;
        
        if (bpf_map_lookup_elem(fd, &key, &val) == 0) {
            stats[i] = val;
            printf("  %-20s: %llu\n", stat_names[i], (unsigned long long)val);
        }
    }
    
    printf("───────────────────────────────────────\n\n");
    
    close(fd);
    return 0;
}

// List all rules
static int cmd_list(void)
{
    printf("\nACL Rules:\n");
    printf("═══════════════════════════════════════\n\n");
    
    // Show config
    char map_path[256];
    snprintf(map_path, sizeof(map_path), "%s/acl_config_map", PIN_BASE_DIR);
    int cfg_fd = bpf_obj_get(map_path);
    if (cfg_fd >= 0) {
        __u32 key = 0;
        struct acl_config cfg;
        if (bpf_map_lookup_elem(cfg_fd, &key, &cfg) == 0) {
            printf("Status: %s\n", cfg.enabled ? "ENABLED" : "DISABLED");
            printf("Default Action: %s\n", action_names[cfg.default_action]);
            printf("Log Drops: %s\n\n", cfg.log_drops ? "YES" : "NO");
        }
        close(cfg_fd);
    }
    
    printf("5-Tuple Rules:\n");
    printf("───────────────────────────────────────\n");
    
    snprintf(map_path, sizeof(map_path), "%s/acl_5tuple_map", PIN_BASE_DIR);
    int tuple_fd = bpf_obj_get(map_path);
    if (tuple_fd >= 0) {
        struct acl_5tuple_key key = {0}, next_key;
        struct acl_result result;
        int count = 0;
        
        while (bpf_map_get_next_key(tuple_fd, &key, &next_key) == 0) {
            if (bpf_map_lookup_elem(tuple_fd, &next_key, &result) == 0) {
                char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &next_key.src_ip, src, sizeof(src));
                inet_ntop(AF_INET, &next_key.dst_ip, dst, sizeof(dst));
                
                printf("  proto=%u %s:%u -> %s:%u  action=%s\n",
                       next_key.proto, src, ntohs(next_key.sport),
                       dst, ntohs(next_key.dport),
                       action_names[result.action]);
                count++;
            }
            key = next_key;
        }
        
        if (count == 0)
            printf("  (none)\n");
        else
            printf("  Total: %d rules\n", count);
        
        close(tuple_fd);
    }
    
    printf("\nLevel 2: Proto+DstIP+Port Rules:\n");
    printf("───────────────────────────────────────\n");
    
    snprintf(map_path, sizeof(map_path), "%s/acl_pdp_map", PIN_BASE_DIR);
    int proto_dst_fd = bpf_obj_get(map_path);
    if (proto_dst_fd >= 0) {
        struct acl_proto_dstip_port_key key = {0}, next_key;
        struct acl_result result;
        int count = 0;
        
        while (bpf_map_get_next_key(proto_dst_fd, &key, &next_key) == 0) {
            if (bpf_map_lookup_elem(proto_dst_fd, &next_key, &result) == 0) {
                char dst[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &next_key.dst_ip, dst, sizeof(dst));
                
                printf("  proto=%u * -> %s:%u  action=%s\n",
                       next_key.proto, dst, ntohs(next_key.dst_port),
                       action_names[result.action]);
                count++;
            }
            key = next_key;
        }
        
        if (count == 0)
            printf("  (none)\n");
        else
            printf("  Total: %d rules\n", count);
        
        close(proto_dst_fd);
    }
    
    printf("\nLevel 3: Proto+SrcIP+Port Rules:\n");
    printf("───────────────────────────────────────\n");
    
    snprintf(map_path, sizeof(map_path), "%s/acl_psp_map", PIN_BASE_DIR);
    int proto_src_fd = bpf_obj_get(map_path);
    if (proto_src_fd >= 0) {
        struct acl_proto_srcip_port_key key = {0}, next_key;
        struct acl_result result;
        int count = 0;
        
        while (bpf_map_get_next_key(proto_src_fd, &key, &next_key) == 0) {
            if (bpf_map_lookup_elem(proto_src_fd, &next_key, &result) == 0) {
                char src[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &next_key.src_ip, src, sizeof(src));
                
                printf("  proto=%u %s:* -> *:%u  action=%s\n",
                       next_key.proto, src, ntohs(next_key.dst_port),
                       action_names[result.action]);
                count++;
            }
            key = next_key;
        }
        
        if (count == 0)
            printf("  (none)\n");
        else
            printf("  Total: %d rules\n", count);
        
        close(proto_src_fd);
    }
    
    printf("\nLevel 4: Proto+Port Rules:\n");
    printf("───────────────────────────────────────\n");
    
    snprintf(map_path, sizeof(map_path), "%s/acl_pp_map", PIN_BASE_DIR);
    int proto_port_fd = bpf_obj_get(map_path);
    if (proto_port_fd >= 0) {
        struct acl_proto_port_key key = {0}, next_key;
        struct acl_result result;
        int count = 0;
        
        while (bpf_map_get_next_key(proto_port_fd, &key, &next_key) == 0) {
            if (bpf_map_lookup_elem(proto_port_fd, &next_key, &result) == 0) {
                printf("  proto=%u * -> *:%u  action=%s\n",
                       next_key.proto, ntohs(next_key.dst_port),
                       action_names[result.action]);
                count++;
            }
            key = next_key;
        }
        
        if (count == 0)
            printf("  (none)\n");
        else
            printf("  Total: %d rules\n", count);
        
        close(proto_port_fd);
    }
    
    printf("\nLPM Source Prefix Rules:\n");
    printf("───────────────────────────────────────\n");
    
    snprintf(map_path, sizeof(map_path), "%s/acl_lpm_src_map", PIN_BASE_DIR);
    int lpm_src_fd = bpf_obj_get(map_path);
    if (lpm_src_fd >= 0) {
        printf("  (LPM trie - cannot iterate)\n");
        close(lpm_src_fd);
    }
    
    printf("\nLPM Destination Prefix Rules:\n");
    printf("───────────────────────────────────────\n");
    
    snprintf(map_path, sizeof(map_path), "%s/acl_lpm_dst_map", PIN_BASE_DIR);
    int lpm_dst_fd = bpf_obj_get(map_path);
    if (lpm_dst_fd >= 0) {
        printf("  (LPM trie - cannot iterate)\n");
        close(lpm_dst_fd);
    }
    
    printf("\n");
    return 0;
}

// Clear all rules
static int cmd_clear(void)
{
    char map_path[256];
    
    // Clear 5-tuple map
    snprintf(map_path, sizeof(map_path), "%s/acl_5tuple_map", PIN_BASE_DIR);
    int fd = bpf_obj_get(map_path);
    if (fd >= 0) {
        struct acl_5tuple_key key = {0}, next_key;
        int count = 0;
        
        while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
            bpf_map_delete_elem(fd, &next_key);
            key = next_key;
            count++;
        }
        
        printf("Cleared %d 5-tuple rules\n", count);
        close(fd);
    }
    
    // Clear Level 2 map
    snprintf(map_path, sizeof(map_path), "%s/acl_pdp_map", PIN_BASE_DIR);
    fd = bpf_obj_get(map_path);
    if (fd >= 0) {
        struct acl_proto_dstip_port_key key = {0}, next_key;
        int count = 0;
        
        while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
            bpf_map_delete_elem(fd, &next_key);
            key = next_key;
            count++;
        }
        
        printf("Cleared %d proto+dst rules\n", count);
        close(fd);
    }
    
    // Clear Level 3 map
    snprintf(map_path, sizeof(map_path), "%s/acl_psp_map", PIN_BASE_DIR);
    fd = bpf_obj_get(map_path);
    if (fd >= 0) {
        struct acl_proto_srcip_port_key key = {0}, next_key;
        int count = 0;
        
        while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
            bpf_map_delete_elem(fd, &next_key);
            key = next_key;
            count++;
        }
        
        printf("Cleared %d proto+src rules\n", count);
        close(fd);
    }
    
    // Clear Level 4 map
    snprintf(map_path, sizeof(map_path), "%s/acl_pp_map", PIN_BASE_DIR);
    fd = bpf_obj_get(map_path);
    if (fd >= 0) {
        struct acl_proto_port_key key = {0}, next_key;
        int count = 0;
        
        while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
            bpf_map_delete_elem(fd, &next_key);
            key = next_key;
            count++;
        }
        
        printf("Cleared %d proto+port rules\n", count);
        close(fd);
    }
    
    printf("Note: LPM tries cannot be cleared individually (reload module to clear)\n");
    
    return 0;
}

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s <command> [options]\n\n", prog);
    fprintf(stderr, "Commands:\n");
    fprintf(stderr, "  add-5t          Add 5-tuple exact match rule (Level 1)\n");
    fprintf(stderr, "  add-proto-dst   Add proto+dst_ip+port rule (Level 2)\n");
    fprintf(stderr, "  add-proto-src   Add proto+src_ip+port rule (Level 3)\n");
    fprintf(stderr, "  add-proto-port  Add proto+port rule (Level 4)\n");
    fprintf(stderr, "  add-lpm-src     Add source IP prefix rule (Level 5)\n");
    fprintf(stderr, "  add-lpm-dst     Add destination IP prefix rule (Level 6)\n");
    fprintf(stderr, "  set-default     Set default action (Level 7)\n");
    fprintf(stderr, "  enable          Enable ACL\n");
    fprintf(stderr, "  disable         Disable ACL\n");
    fprintf(stderr, "  list            List all rules\n");
    fprintf(stderr, "  stats           Show statistics\n");
    fprintf(stderr, "  clear           Clear all rules\n\n");
    fprintf(stderr, "Examples:\n");
    fprintf(stderr, "  # Block HTTPS to malicious site (any source -> specific destination)\n");
    fprintf(stderr, "  %s add-proto-dst --proto tcp --dst 203.0.113.5 --dport 443 --action drop\n\n", prog);
    fprintf(stderr, "  # Block SSH from attacker (specific source -> any destination)\n");
    fprintf(stderr, "  %s add-proto-src --proto tcp --src 10.1.2.3 --dport 22 --action drop\n\n", prog);
    fprintf(stderr, "  # Block QUIC globally (any -> any on UDP 443)\n");
    fprintf(stderr, "  %s add-proto-port --proto udp --dport 443 --action drop\n\n", prog);
    fprintf(stderr, "  # Exact 5-tuple match\n");
    fprintf(stderr, "  %s add-5t --proto tcp --src 10.1.2.3 --dst 192.168.1.100 --dport 22 --action drop\n\n", prog);
    fprintf(stderr, "  # Prefix-based filtering\n");
    fprintf(stderr, "  %s add-lpm-src --prefix 192.168.0.0/16 --action pass\n\n", prog);
    fprintf(stderr, "  # Set default policy\n");
    fprintf(stderr, "  %s set-default --action drop\n\n", prog);
    fprintf(stderr, "  # Enable ACL enforcement\n");
    fprintf(stderr, "  %s enable\n", prog);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }
    
    const char *cmd = argv[1];
    
    if (strcmp(cmd, "add-5t") == 0) {
        return cmd_add_5tuple(argc - 1, argv + 1);
    } else if (strcmp(cmd, "add-proto-dst") == 0) {
        return cmd_add_proto_dst(argc - 1, argv + 1);
    } else if (strcmp(cmd, "add-proto-src") == 0) {
        return cmd_add_proto_src(argc - 1, argv + 1);
    } else if (strcmp(cmd, "add-proto-port") == 0) {
        return cmd_add_proto_port(argc - 1, argv + 1);
    } else if (strcmp(cmd, "add-lpm-src") == 0) {
        return cmd_add_lpm("acl_lpm_src_map", argc - 1, argv + 1);
    } else if (strcmp(cmd, "add-lpm-dst") == 0) {
        return cmd_add_lpm("acl_lpm_dst_map", argc - 1, argv + 1);
    } else if (strcmp(cmd, "set-default") == 0) {
        return cmd_set_default(argc - 1, argv + 1);
    } else if (strcmp(cmd, "enable") == 0) {
        return cmd_set_enabled(1);
    } else if (strcmp(cmd, "disable") == 0) {
        return cmd_set_enabled(0);
    } else if (strcmp(cmd, "list") == 0) {
        return cmd_list();
    } else if (strcmp(cmd, "stats") == 0) {
        return cmd_stats();
    } else if (strcmp(cmd, "clear") == 0) {
        return cmd_clear();
    } else {
        fprintf(stderr, "Unknown command: %s\n\n", cmd);
        usage(argv[0]);
        return 1;
    }
}
