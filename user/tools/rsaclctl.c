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
#include <net/if.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#if __has_include("rs_log.h")
#include "rs_log.h"
#else
#include "../common/rs_log.h"
#endif

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

enum ct_state {
    CT_STATE_NONE = 0,
    CT_STATE_NEW = 1,
    CT_STATE_ESTABLISHED = 2,
    CT_STATE_RELATED = 3,
    CT_STATE_INVALID = 4,
};

struct ct_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 proto;
    __u8 pad[3];
} __attribute__((packed));

struct ct_entry {
    __u8 state;
    __u8 flags;
    __u8 direction;
    __u8 pad;
    __u64 created_ns;
    __u64 last_seen_ns;
    __u64 pkts_orig;
    __u64 pkts_reply;
    __u64 bytes_orig;
    __u64 bytes_reply;
    __u32 timeout_sec;
} __attribute__((aligned(8)));

struct ct_config {
    __u8 enabled;
    __u8 default_action;
    __u8 pad[2];
    __u32 tcp_est_timeout;
    __u32 tcp_syn_timeout;
    __u32 udp_timeout;
    __u32 icmp_timeout;
} __attribute__((aligned(8)));

enum ct_stat_type {
    CT_STAT_NEW = 0,
    CT_STAT_ESTABLISHED = 1,
    CT_STAT_RELATED = 2,
    CT_STAT_INVALID = 3,
    CT_STAT_TIMEOUT = 4,
    CT_STAT_DROPS = 5,
    CT_STAT_TOTAL = 6,
    CT_STAT_MAX = 8,
};

struct sg_key {
    __u32 ip_addr;
} __attribute__((packed));

struct sg_entry {
    __u8 mac[6];
    __u16 pad;
    __u32 ifindex;
    __u8 type;
    __u8 pad2[3];
    __u64 last_seen_ns;
    __u64 violations;
} __attribute__((aligned(8)));

struct sg_config {
    __u8 enabled;
    __u8 strict_mode;
    __u8 check_mac;
    __u8 check_port;
} __attribute__((aligned(8)));

enum sg_stat_type {
    SG_STAT_TOTAL = 0,
    SG_STAT_PASSED = 1,
    SG_STAT_MAC_VIOLATIONS = 2,
    SG_STAT_PORT_VIOLATIONS = 3,
    SG_STAT_MAX = 4,
};

struct dhcp_snoop_config {
    __u32 enabled;
    __u32 drop_rogue_server;
    __u32 pad[2];
};

struct dhcp_snoop_stats {
    __u64 dhcp_discover;
    __u64 dhcp_offer;
    __u64 dhcp_request;
    __u64 dhcp_ack;
    __u64 rogue_server_drops;
    __u64 bindings_created;
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

static const char *ct_state_names[] = {
    [CT_STATE_NONE] = "NONE",
    [CT_STATE_NEW] = "NEW",
    [CT_STATE_ESTABLISHED] = "ESTABLISHED",
    [CT_STATE_RELATED] = "RELATED",
    [CT_STATE_INVALID] = "INVALID",
};

static const char *ct_stat_names[] = {
    [CT_STAT_NEW] = "New flows",
    [CT_STAT_ESTABLISHED] = "Established flows",
    [CT_STAT_RELATED] = "Related flows",
    [CT_STAT_INVALID] = "Invalid flows",
    [CT_STAT_TIMEOUT] = "Timeouts",
    [CT_STAT_DROPS] = "Drops",
    [CT_STAT_TOTAL] = "Total packets",
};

static const char *sg_stat_names[] = {
    [SG_STAT_TOTAL] = "Total packets",
    [SG_STAT_PASSED] = "Passed",
    [SG_STAT_MAC_VIOLATIONS] = "MAC violations",
    [SG_STAT_PORT_VIOLATIONS] = "Port violations",
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
    
    RS_LOG_ERROR("Invalid action: %s (must be pass/drop/redirect)", action_str);
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
            RS_LOG_ERROR("Invalid prefix length: %u (must be 0-32)", *prefixlen);
            return -1;
        }
    } else {
        *prefixlen = 32;  // Host address
    }
    
    if (inet_pton(AF_INET, buf, ip) != 1) {
        RS_LOG_ERROR("Invalid IP address: %s", buf);
        return -1;
    }
    
    return 0;
}

static int parse_mac(const char *mac_str, __u8 *mac)
{
    unsigned int m[6];

    if (sscanf(mac_str, "%x:%x:%x:%x:%x:%x",
               &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) != 6) {
        RS_LOG_ERROR("Invalid MAC address: %s (format: XX:XX:XX:XX:XX:XX)", mac_str);
        return -1;
    }

    for (int i = 0; i < 6; i++) {
        if (m[i] > 0xff) {
            RS_LOG_ERROR("Invalid MAC address octet in: %s", mac_str);
            return -1;
        }
        mac[i] = (__u8)m[i];
    }

    return 0;
}

static int parse_sg_type(const char *type_str)
{
    if (!type_str || strcmp(type_str, "static") == 0)
        return 0;
    if (strcmp(type_str, "dhcp-learned") == 0)
        return 1;
    if (strcmp(type_str, "arp-learned") == 0)
        return 2;

    RS_LOG_ERROR("Invalid binding type: %s (must be static|dhcp-learned|arp-learned)", type_str);
    return -1;
}

static const char *sg_type_name(__u8 type)
{
    if (type == 0)
        return "static";
    if (type == 1)
        return "dhcp-learned";
    if (type == 2)
        return "arp-learned";
    return "unknown";
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

static void format_mac(const __u8 *mac, char *buf, size_t len)
{
    snprintf(buf, len, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static int lookup_percpu_counter(int fd, __u32 key, __u64 *total)
{
    int ncpu = libbpf_num_possible_cpus();
    __u64 sum = 0;

    if (ncpu <= 0)
        return -1;

    __u64 values[ncpu];
    if (bpf_map_lookup_elem(fd, &key, values) < 0)
        return -1;

    for (int i = 0; i < ncpu; i++)
        sum += values[i];

    *total = sum;
    return 0;
}

static int lookup_percpu_dhcp_stats(int fd, __u32 key, struct dhcp_snoop_stats *total)
{
    int ncpu = libbpf_num_possible_cpus();
    struct dhcp_snoop_stats sum = {0};

    if (ncpu <= 0)
        return -1;

    struct dhcp_snoop_stats values[ncpu];
    if (bpf_map_lookup_elem(fd, &key, values) < 0)
        return -1;

    for (int i = 0; i < ncpu; i++) {
        sum.dhcp_discover += values[i].dhcp_discover;
        sum.dhcp_offer += values[i].dhcp_offer;
        sum.dhcp_request += values[i].dhcp_request;
        sum.dhcp_ack += values[i].dhcp_ack;
        sum.rogue_server_drops += values[i].rogue_server_drops;
        sum.bindings_created += values[i].bindings_created;
    }

    *total = sum;
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
            RS_LOG_ERROR("Usage: rsaclctl add-5t --proto <proto> --src <ip> --sport <port> --dst <ip> --dport <port> --action <action> [--redirect-ifindex <idx>] [--log]");
            RS_LOG_ERROR("Note: This is EXACT 5-tuple match. All fields including ports must match exactly.");
            RS_LOG_ERROR("      Omitted ports default to 0. Use add-proto-{dst,src,port} for partial matching.");
            return -1;
        }
    }
    
    if (!proto_str || !src_str || !dst_str || !action_str) {
        RS_LOG_ERROR("Missing required arguments (need --proto, --src, --dst, --action)");
        RS_LOG_ERROR("Note: 5-tuple requires EXACT match on all fields including ports.");
        RS_LOG_ERROR("      If --sport or --dport is omitted, it defaults to 0 (matches port 0 only).");
        RS_LOG_ERROR("      For wildcard matching, use:");
        RS_LOG_ERROR("        - add-proto-dst: match any source -> specific destination");
        RS_LOG_ERROR("        - add-proto-src: match specific source -> any destination");
        RS_LOG_ERROR("        - add-proto-port: match any source/destination on specific port");
        return -1;
    }
    
    // Parse fields
    key.proto = parse_protocol(proto_str);
    if (inet_pton(AF_INET, src_str, &key.src_ip) != 1) {
        RS_LOG_ERROR("Invalid source IP: %s", src_str);
        return -1;
    }
    if (inet_pton(AF_INET, dst_str, &key.dst_ip) != 1) {
        RS_LOG_ERROR("Invalid destination IP: %s", dst_str);
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
        RS_LOG_ERROR("Failed to open 5-tuple map: %s", strerror(errno));
        return -1;
    }
    
    // Add rule
    ret = bpf_map_update_elem(fd, &key, &result, BPF_ANY);
    if (ret < 0) {
        RS_LOG_ERROR("Failed to add 5-tuple rule: %s", strerror(errno));
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
            RS_LOG_ERROR("Usage: rsaclctl add-proto-dst --proto <proto> --dst <ip> --dport <port> --action <action> [--log]");
            return -1;
        }
    }
    
    if (!proto_str || !dst_str || !action_str) {
        RS_LOG_ERROR("Missing required arguments (need --proto, --dst, --dport, --action)");
        return -1;
    }
    
    // Parse fields
    key.proto = parse_protocol(proto_str);
    if (inet_pton(AF_INET, dst_str, &key.dst_ip) != 1) {
        RS_LOG_ERROR("Invalid destination IP: %s", dst_str);
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
        RS_LOG_ERROR("Failed to open proto+dst map: %s", strerror(errno));
        return -1;
    }
    
    // Add rule
    ret = bpf_map_update_elem(fd, &key, &result, BPF_ANY);
    if (ret < 0) {
        RS_LOG_ERROR("Failed to add proto+dst rule: %s", strerror(errno));
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
            RS_LOG_ERROR("Usage: rsaclctl add-proto-src --proto <proto> --src <ip> --dport <port> --action <action> [--log]");
            return -1;
        }
    }
    
    if (!proto_str || !src_str || !action_str) {
        RS_LOG_ERROR("Missing required arguments (need --proto, --src, --dport, --action)");
        return -1;
    }
    
    // Parse fields
    key.proto = parse_protocol(proto_str);
    if (inet_pton(AF_INET, src_str, &key.src_ip) != 1) {
        RS_LOG_ERROR("Invalid source IP: %s", src_str);
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
        RS_LOG_ERROR("Failed to open proto+src map: %s", strerror(errno));
        return -1;
    }
    
    // Add rule
    ret = bpf_map_update_elem(fd, &key, &result, BPF_ANY);
    if (ret < 0) {
        RS_LOG_ERROR("Failed to add proto+src rule: %s", strerror(errno));
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
            RS_LOG_ERROR("Usage: rsaclctl add-proto-port --proto <proto> --dport <port> --action <action> [--log]");
            return -1;
        }
    }
    
    if (!proto_str || !action_str) {
        RS_LOG_ERROR("Missing required arguments (need --proto, --dport, --action)");
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
        RS_LOG_ERROR("Failed to open proto+port map: %s", strerror(errno));
        return -1;
    }
    
    // Add rule
    ret = bpf_map_update_elem(fd, &key, &result, BPF_ANY);
    if (ret < 0) {
        RS_LOG_ERROR("Failed to add proto+port rule: %s", strerror(errno));
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
            RS_LOG_ERROR("Usage: rsaclctl %s --prefix <ip/prefix> --action <action> [--log]", map_name);
            return -1;
        }
    }
    
    if (!prefix_str || !action_str) {
        RS_LOG_ERROR("Missing required arguments (need --prefix, --action)");
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
        RS_LOG_ERROR("Failed to open %s: %s", map_name, strerror(errno));
        return -1;
    }
    
    ret = bpf_map_update_elem(fd, &key, &result, BPF_ANY);
    if (ret < 0) {
        RS_LOG_ERROR("Failed to add LPM rule: %s", strerror(errno));
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
        RS_LOG_ERROR("Usage: rsaclctl set-default --action <pass|drop>");
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
        RS_LOG_ERROR("Failed to open config map: %s", strerror(errno));
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
        RS_LOG_ERROR("Failed to set default action: %s", strerror(errno));
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
        RS_LOG_ERROR("Failed to open config map: %s", strerror(errno));
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
        RS_LOG_ERROR("Failed to update ACL state: %s", strerror(errno));
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
        RS_LOG_ERROR("Failed to open stats map: %s", strerror(errno));
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

static int cmd_show_connections(void)
{
    char map_path[256];
    snprintf(map_path, sizeof(map_path), "%s/ct_table", PIN_BASE_DIR);

    int fd = bpf_obj_get(map_path);
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open ct_table: %s", strerror(errno));
        return -1;
    }

    printf("\nConntrack Table:\n");
    printf("══════════════════════════════════════════════════════════════════════════\n");
    printf("%-21s %-21s %-5s %-12s %-10s %-10s %-8s\n",
           "Source", "Destination", "Proto", "State", "Pkts(O/R)", "Bytes(O/R)", "Timeout");
    printf("──────────────────────────────────────────────────────────────────────────\n");

    struct ct_key key = {0}, next_key = {0};
    struct ct_entry entry = {0};
    int count = 0;
    int first = 1;

    while (bpf_map_get_next_key(fd, first ? NULL : &key, &next_key) == 0) {
        first = 0;
        if (bpf_map_lookup_elem(fd, &next_key, &entry) == 0) {
            struct in_addr saddr = {.s_addr = next_key.src_ip};
            struct in_addr daddr = {.s_addr = next_key.dst_ip};
            char s_ip[INET_ADDRSTRLEN], d_ip[INET_ADDRSTRLEN];
            char src[64], dst[64];
            const char *state = "UNKNOWN";

            inet_ntop(AF_INET, &saddr, s_ip, sizeof(s_ip));
            inet_ntop(AF_INET, &daddr, d_ip, sizeof(d_ip));
            snprintf(src, sizeof(src), "%s:%u", s_ip, ntohs(next_key.src_port));
            snprintf(dst, sizeof(dst), "%s:%u", d_ip, ntohs(next_key.dst_port));

            if (entry.state < sizeof(ct_state_names) / sizeof(ct_state_names[0]) && ct_state_names[entry.state])
                state = ct_state_names[entry.state];

            printf("%-21s %-21s %-5u %-12s %5llu/%-4llu %5llu/%-4llu %-8u\n",
                   src, dst, next_key.proto, state,
                   (unsigned long long)entry.pkts_orig,
                   (unsigned long long)entry.pkts_reply,
                   (unsigned long long)entry.bytes_orig,
                   (unsigned long long)entry.bytes_reply,
                   entry.timeout_sec);
            count++;
        }
        key = next_key;
    }

    if (count == 0)
        printf("(empty)\n");

    printf("──────────────────────────────────────────────────────────────────────────\n");
    printf("Total: %d connections\n\n", count);

    close(fd);
    return 0;
}

static int cmd_flush_connections(void)
{
    char map_path[256];
    snprintf(map_path, sizeof(map_path), "%s/ct_table", PIN_BASE_DIR);

    int fd = bpf_obj_get(map_path);
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open ct_table: %s", strerror(errno));
        return -1;
    }

    struct ct_key key = {0}, next_key = {0};
    int first = 1;
    int count = 0;

    while (bpf_map_get_next_key(fd, first ? NULL : &key, &next_key) == 0) {
        first = 0;
        if (bpf_map_delete_elem(fd, &next_key) == 0)
            count++;
        key = next_key;
    }

    printf("Flushed %d conntrack entries\n", count);
    close(fd);
    return 0;
}

static int cmd_conntrack_stats(void)
{
    char map_path[256];
    snprintf(map_path, sizeof(map_path), "%s/ct_stats_map", PIN_BASE_DIR);

    int fd = bpf_obj_get(map_path);
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open ct_stats_map: %s", strerror(errno));
        return -1;
    }

    printf("\nConntrack Statistics:\n");
    printf("───────────────────────────────────────\n");

    for (int i = 0; i < CT_STAT_MAX; i++) {
        __u32 key = i;
        __u64 val = 0;

        if (bpf_map_lookup_elem(fd, &key, &val) == 0 && i < (int)(sizeof(ct_stat_names) / sizeof(ct_stat_names[0])) && ct_stat_names[i])
            printf("  %-20s: %llu\n", ct_stat_names[i], (unsigned long long)val);
    }

    printf("───────────────────────────────────────\n\n");
    close(fd);
    return 0;
}

static int cmd_conntrack_enable_disable(int enable)
{
    char map_path[256];
    struct ct_config cfg = {0};
    __u32 key = 0;

    snprintf(map_path, sizeof(map_path), "%s/ct_config_map", PIN_BASE_DIR);
    int fd = bpf_obj_get(map_path);
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open ct_config_map: %s", strerror(errno));
        return -1;
    }

    if (bpf_map_lookup_elem(fd, &key, &cfg) < 0) {
        memset(&cfg, 0, sizeof(cfg));
        cfg.tcp_est_timeout = 3600;
        cfg.tcp_syn_timeout = 120;
        cfg.udp_timeout = 30;
        cfg.icmp_timeout = 30;
    }

    cfg.enabled = enable ? 1 : 0;
    if (bpf_map_update_elem(fd, &key, &cfg, BPF_ANY) < 0) {
        RS_LOG_ERROR("Failed to update conntrack state: %s", strerror(errno));
        close(fd);
        return -1;
    }

    printf("Conntrack %s\n", enable ? "enabled" : "disabled");
    close(fd);
    return 0;
}

static int cmd_set_timeout(int argc, char **argv)
{
    if (argc != 3) {
        RS_LOG_ERROR("Usage: rsaclctl set-timeout <tcp-est|tcp-syn|udp|icmp> <seconds>");
        return -1;
    }

    const char *timeout_type = argv[1];
    int seconds = atoi(argv[2]);
    if (seconds < 0) {
        RS_LOG_ERROR("Timeout must be >= 0 seconds");
        return -1;
    }

    char map_path[256];
    struct ct_config cfg = {0};
    __u32 key = 0;

    snprintf(map_path, sizeof(map_path), "%s/ct_config_map", PIN_BASE_DIR);
    int fd = bpf_obj_get(map_path);
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open ct_config_map: %s", strerror(errno));
        return -1;
    }

    if (bpf_map_lookup_elem(fd, &key, &cfg) < 0) {
        memset(&cfg, 0, sizeof(cfg));
        cfg.enabled = 1;
        cfg.tcp_est_timeout = 3600;
        cfg.tcp_syn_timeout = 120;
        cfg.udp_timeout = 30;
        cfg.icmp_timeout = 30;
    }

    if (strcmp(timeout_type, "tcp-est") == 0)
        cfg.tcp_est_timeout = (__u32)seconds;
    else if (strcmp(timeout_type, "tcp-syn") == 0)
        cfg.tcp_syn_timeout = (__u32)seconds;
    else if (strcmp(timeout_type, "udp") == 0)
        cfg.udp_timeout = (__u32)seconds;
    else if (strcmp(timeout_type, "icmp") == 0)
        cfg.icmp_timeout = (__u32)seconds;
    else {
        RS_LOG_ERROR("Unknown timeout type '%s' (expected tcp-est|tcp-syn|udp|icmp)", timeout_type);
        close(fd);
        return -1;
    }

    if (bpf_map_update_elem(fd, &key, &cfg, BPF_ANY) < 0) {
        RS_LOG_ERROR("Failed to update conntrack timeout: %s", strerror(errno));
        close(fd);
        return -1;
    }

    printf("Set conntrack timeout %s=%d seconds\n", timeout_type, seconds);
    close(fd);
    return 0;
}

static int cmd_add_binding(int argc, char **argv)
{
    struct sg_key key = {0};
    struct sg_entry entry = {0};
    char *ip_str = NULL;
    char *mac_str = NULL;
    char *port_str = NULL;
    char *type_str = "static";
    int fd;

    struct option long_opts[] = {
        {"ip", required_argument, 0, 'i'},
        {"mac", required_argument, 0, 'm'},
        {"port", required_argument, 0, 'p'},
        {"type", required_argument, 0, 't'},
        {0, 0, 0, 0}
    };

    optind = 1;
    int opt;
    while ((opt = getopt_long(argc, argv, "i:m:p:t:", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'i':
            ip_str = optarg;
            break;
        case 'm':
            mac_str = optarg;
            break;
        case 'p':
            port_str = optarg;
            break;
        case 't':
            type_str = optarg;
            break;
        default:
            RS_LOG_ERROR("Usage: rsaclctl add-binding --ip <addr> --mac <aa:bb:cc:dd:ee:ff> [--port <ifname>] [--type static]");
            return -1;
        }
    }

    if (!ip_str || !mac_str) {
        RS_LOG_ERROR("Missing required arguments (need --ip and --mac)");
        return -1;
    }

    if (inet_pton(AF_INET, ip_str, &key.ip_addr) != 1) {
        RS_LOG_ERROR("Invalid IPv4 address: %s", ip_str);
        return -1;
    }

    if (parse_mac(mac_str, entry.mac) < 0)
        return -1;

    int binding_type = parse_sg_type(type_str);
    if (binding_type < 0)
        return -1;
    entry.type = (__u8)binding_type;

    if (port_str) {
        int ifindex = ifindex_from_arg(port_str);
        if (ifindex <= 0) {
            RS_LOG_ERROR("Invalid port/interface: %s", port_str);
            return -1;
        }
        entry.ifindex = (__u32)ifindex;
    }

    fd = open_pinned_map("sg_binding_map");
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open sg_binding_map: %s", strerror(errno));
        return -1;
    }

    if (bpf_map_update_elem(fd, &key, &entry, BPF_ANY) < 0) {
        RS_LOG_ERROR("Failed to add source binding: %s", strerror(errno));
        close(fd);
        return -1;
    }

    RS_LOG_INFO("Added source binding ip=%s mac=%s ifindex=%u type=%s",
                ip_str, mac_str, entry.ifindex, sg_type_name(entry.type));
    close(fd);
    return 0;
}

static int cmd_del_binding(int argc, char **argv)
{
    struct sg_key key = {0};
    char *ip_str = NULL;
    int fd;

    struct option long_opts[] = {
        {"ip", required_argument, 0, 'i'},
        {0, 0, 0, 0}
    };

    optind = 1;
    int opt;
    while ((opt = getopt_long(argc, argv, "i:", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'i':
            ip_str = optarg;
            break;
        default:
            RS_LOG_ERROR("Usage: rsaclctl del-binding --ip <addr>");
            return -1;
        }
    }

    if (!ip_str) {
        RS_LOG_ERROR("Missing required argument --ip");
        return -1;
    }

    if (inet_pton(AF_INET, ip_str, &key.ip_addr) != 1) {
        RS_LOG_ERROR("Invalid IPv4 address: %s", ip_str);
        return -1;
    }

    fd = open_pinned_map("sg_binding_map");
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open sg_binding_map: %s", strerror(errno));
        return -1;
    }

    if (bpf_map_delete_elem(fd, &key) < 0) {
        RS_LOG_ERROR("Failed to delete source binding: %s", strerror(errno));
        close(fd);
        return -1;
    }

    RS_LOG_INFO("Deleted source binding ip=%s", ip_str);
    close(fd);
    return 0;
}

static int cmd_show_bindings(void)
{
    int fd = open_pinned_map("sg_binding_map");
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open sg_binding_map: %s", strerror(errno));
        return -1;
    }

    struct sg_key key = {0}, next_key = {0};
    struct sg_entry entry = {0};
    int first = 1;
    int count = 0;

    RS_LOG_INFO("Source guard bindings:");
    while (bpf_map_get_next_key(fd, first ? NULL : &key, &next_key) == 0) {
        first = 0;
        if (bpf_map_lookup_elem(fd, &next_key, &entry) == 0) {
            char ip[INET_ADDRSTRLEN] = {0};
            char mac[32] = {0};

            inet_ntop(AF_INET, &next_key.ip_addr, ip, sizeof(ip));
            format_mac(entry.mac, mac, sizeof(mac));

            RS_LOG_INFO("  ip=%s mac=%s ifindex=%u type=%s last_seen_ns=%llu violations=%llu",
                        ip, mac, entry.ifindex, sg_type_name(entry.type),
                        (unsigned long long)entry.last_seen_ns,
                        (unsigned long long)entry.violations);
            count++;
        }
        key = next_key;
    }

    RS_LOG_INFO("Total source bindings: %d", count);
    close(fd);
    return 0;
}

static int cmd_source_guard_set_enabled(int enable, int argc, char **argv)
{
    char *port_str = NULL;
    struct option long_opts[] = {
        {"port", required_argument, 0, 'p'},
        {0, 0, 0, 0}
    };

    optind = 1;
    int opt;
    while ((opt = getopt_long(argc, argv, "p:", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'p':
            port_str = optarg;
            break;
        default:
            RS_LOG_ERROR("Usage: rsaclctl %s [--port <ifname>]",
                         enable ? "source-guard-enable" : "source-guard-disable");
            return -1;
        }
    }

    if (port_str) {
        int ifindex = ifindex_from_arg(port_str);
        if (ifindex <= 0) {
            RS_LOG_ERROR("Invalid port/interface: %s", port_str);
            return -1;
        }

        int fd = open_pinned_map("sg_port_enable_map");
        if (fd < 0) {
            RS_LOG_ERROR("Failed to open sg_port_enable_map: %s", strerror(errno));
            return -1;
        }

        __u32 key = (__u32)ifindex;
        __u8 value = enable ? 1 : 0;
        if (bpf_map_update_elem(fd, &key, &value, BPF_ANY) < 0) {
            RS_LOG_ERROR("Failed to update sg_port_enable_map: %s", strerror(errno));
            close(fd);
            return -1;
        }

        RS_LOG_INFO("Source guard %s for ifindex=%u", enable ? "enabled" : "disabled", key);
        close(fd);
        return 0;
    }

    int fd = open_pinned_map("sg_config_map");
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open sg_config_map: %s", strerror(errno));
        return -1;
    }

    __u32 key = 0;
    struct sg_config cfg = {
        .enabled = 1,
        .strict_mode = 1,
        .check_mac = 1,
        .check_port = 1,
    };

    if (bpf_map_lookup_elem(fd, &key, &cfg) < 0) {
        cfg.enabled = 1;
        cfg.strict_mode = 1;
        cfg.check_mac = 1;
        cfg.check_port = 1;
    }

    cfg.enabled = enable ? 1 : 0;

    if (bpf_map_update_elem(fd, &key, &cfg, BPF_ANY) < 0) {
        RS_LOG_ERROR("Failed to update sg_config_map: %s", strerror(errno));
        close(fd);
        return -1;
    }

    RS_LOG_INFO("Source guard globally %s", enable ? "enabled" : "disabled");
    close(fd);
    return 0;
}

static int cmd_source_guard_mode(int argc, char **argv)
{
    if (argc != 2) {
        RS_LOG_ERROR("Usage: rsaclctl source-guard-mode <strict|permissive>");
        return -1;
    }

    int strict;
    if (strcmp(argv[1], "strict") == 0)
        strict = 1;
    else if (strcmp(argv[1], "permissive") == 0)
        strict = 0;
    else {
        RS_LOG_ERROR("Invalid mode: %s (must be strict or permissive)", argv[1]);
        return -1;
    }

    int fd = open_pinned_map("sg_config_map");
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open sg_config_map: %s", strerror(errno));
        return -1;
    }

    __u32 key = 0;
    struct sg_config cfg = {
        .enabled = 1,
        .strict_mode = 1,
        .check_mac = 1,
        .check_port = 1,
    };

    if (bpf_map_lookup_elem(fd, &key, &cfg) < 0) {
        cfg.enabled = 1;
        cfg.check_mac = 1;
        cfg.check_port = 1;
    }

    cfg.strict_mode = strict ? 1 : 0;

    if (bpf_map_update_elem(fd, &key, &cfg, BPF_ANY) < 0) {
        RS_LOG_ERROR("Failed to update sg_config_map: %s", strerror(errno));
        close(fd);
        return -1;
    }

    RS_LOG_INFO("Source guard mode set to %s", strict ? "strict" : "permissive");
    close(fd);
    return 0;
}

static int cmd_source_guard_stats(void)
{
    int fd = open_pinned_map("sg_stats_map");
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open sg_stats_map: %s", strerror(errno));
        return -1;
    }

    RS_LOG_INFO("Source guard statistics:");
    for (int i = 0; i < SG_STAT_MAX; i++) {
        __u64 val = 0;
        if (lookup_percpu_counter(fd, (__u32)i, &val) == 0)
            RS_LOG_INFO("  %s: %llu", sg_stat_names[i], (unsigned long long)val);
    }

    close(fd);
    return 0;
}

static int cmd_dhcp_snoop_enable_disable(int enable)
{
    int fd = open_pinned_map("dhcp_snoop_config_map");
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open dhcp_snoop_config_map: %s", strerror(errno));
        return -1;
    }

    __u32 key = 0;
    struct dhcp_snoop_config cfg = {
        .enabled = 1,
        .drop_rogue_server = 1,
    };

    if (bpf_map_lookup_elem(fd, &key, &cfg) < 0) {
        cfg.enabled = 1;
        cfg.drop_rogue_server = 1;
    }

    cfg.enabled = enable ? 1 : 0;
    if (bpf_map_update_elem(fd, &key, &cfg, BPF_ANY) < 0) {
        RS_LOG_ERROR("Failed to update dhcp_snoop_config_map: %s", strerror(errno));
        close(fd);
        return -1;
    }

    RS_LOG_INFO("DHCP snooping %s", enable ? "enabled" : "disabled");
    close(fd);
    return 0;
}

static int cmd_set_unset_trusted_port(int set, int argc, char **argv)
{
    if (argc != 2) {
        RS_LOG_ERROR("Usage: rsaclctl %s <ifname>", set ? "set-trusted-port" : "unset-trusted-port");
        return -1;
    }

    int ifindex = ifindex_from_arg(argv[1]);
    if (ifindex <= 0) {
        RS_LOG_ERROR("Invalid port/interface: %s", argv[1]);
        return -1;
    }

    int fd = open_pinned_map("dhcp_trusted_ports_map");
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open dhcp_trusted_ports_map: %s", strerror(errno));
        return -1;
    }

    __u32 key = (__u32)ifindex;
    if (set) {
        __u32 trusted = 1;
        if (bpf_map_update_elem(fd, &key, &trusted, BPF_ANY) < 0) {
            RS_LOG_ERROR("Failed to set trusted port: %s", strerror(errno));
            close(fd);
            return -1;
        }
        RS_LOG_INFO("Set trusted DHCP port ifindex=%u", key);
    } else {
        if (bpf_map_delete_elem(fd, &key) < 0 && errno != ENOENT) {
            RS_LOG_ERROR("Failed to unset trusted port: %s", strerror(errno));
            close(fd);
            return -1;
        }
        RS_LOG_INFO("Unset trusted DHCP port ifindex=%u", key);
    }

    close(fd);
    return 0;
}

static int cmd_show_trusted_ports(void)
{
    int fd = open_pinned_map("dhcp_trusted_ports_map");
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open dhcp_trusted_ports_map: %s", strerror(errno));
        return -1;
    }

    __u32 key = 0, next_key = 0;
    __u32 trusted = 0;
    int first = 1;
    int count = 0;
    char ifname[IF_NAMESIZE];

    RS_LOG_INFO("DHCP trusted ports:");
    while (bpf_map_get_next_key(fd, first ? NULL : &key, &next_key) == 0) {
        first = 0;
        if (bpf_map_lookup_elem(fd, &next_key, &trusted) == 0 && trusted) {
            if (if_indextoname((unsigned int)next_key, ifname))
                RS_LOG_INFO("  ifindex=%u ifname=%s trusted=%u", next_key, ifname, trusted);
            else
                RS_LOG_INFO("  ifindex=%u ifname=<unknown> trusted=%u", next_key, trusted);
            count++;
        }
        key = next_key;
    }

    RS_LOG_INFO("Total trusted ports: %d", count);
    close(fd);
    return 0;
}

static int cmd_dhcp_snoop_stats(void)
{
    int fd = open_pinned_map("dhcp_snoop_stats_map");
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open dhcp_snoop_stats_map: %s", strerror(errno));
        return -1;
    }

    __u32 key = 0;
    struct dhcp_snoop_stats stats = {0};
    if (lookup_percpu_dhcp_stats(fd, key, &stats) < 0) {
        RS_LOG_ERROR("Failed to read dhcp_snoop_stats_map: %s", strerror(errno));
        close(fd);
        return -1;
    }

    RS_LOG_INFO("DHCP snooping statistics:");
    RS_LOG_INFO("  Discover: %llu", (unsigned long long)stats.dhcp_discover);
    RS_LOG_INFO("  Offer: %llu", (unsigned long long)stats.dhcp_offer);
    RS_LOG_INFO("  Request: %llu", (unsigned long long)stats.dhcp_request);
    RS_LOG_INFO("  Ack: %llu", (unsigned long long)stats.dhcp_ack);
    RS_LOG_INFO("  Rogue server drops: %llu", (unsigned long long)stats.rogue_server_drops);
    RS_LOG_INFO("  Bindings created: %llu", (unsigned long long)stats.bindings_created);

    close(fd);
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
    fprintf(stderr, "  show-connections    Show active conntrack entries\n");
    fprintf(stderr, "  flush-connections   Flush all conntrack entries\n");
    fprintf(stderr, "  conntrack-stats     Show conntrack statistics\n");
    fprintf(stderr, "  conntrack-enable    Enable conntrack processing\n");
    fprintf(stderr, "  conntrack-disable   Disable conntrack processing\n");
    fprintf(stderr, "  set-timeout         Set conntrack timeout\n\n");
    fprintf(stderr, "  add-binding             Add source guard IP/MAC binding\n");
    fprintf(stderr, "  del-binding             Delete source guard binding by IP\n");
    fprintf(stderr, "  show-bindings           Show source guard bindings\n");
    fprintf(stderr, "  source-guard-enable     Enable source guard globally or per-port\n");
    fprintf(stderr, "  source-guard-disable    Disable source guard globally or per-port\n");
    fprintf(stderr, "  source-guard-stats      Show source guard statistics\n");
    fprintf(stderr, "  source-guard-mode       Set source guard mode (strict/permissive)\n\n");
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
    fprintf(stderr, "  %s enable\n\n", prog);
    fprintf(stderr, "  # Show current conntrack table\n");
    fprintf(stderr, "  %s show-connections\n\n", prog);
    fprintf(stderr, "  # Set conntrack TCP established timeout to 10 minutes\n");
    fprintf(stderr, "  %s set-timeout tcp-est 600\n", prog);
    fprintf(stderr, "  # Add source guard static binding\n");
    fprintf(stderr, "  %s add-binding --ip 10.1.2.3 --mac aa:bb:cc:dd:ee:ff --port eth0 --type static\n", prog);
}

int main(int argc, char **argv)
{
    rs_log_init("rsaclctl", RS_LOG_LEVEL_INFO);

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
    } else if (strcmp(cmd, "show-connections") == 0) {
        return cmd_show_connections();
    } else if (strcmp(cmd, "flush-connections") == 0) {
        return cmd_flush_connections();
    } else if (strcmp(cmd, "conntrack-stats") == 0) {
        return cmd_conntrack_stats();
    } else if (strcmp(cmd, "conntrack-enable") == 0) {
        return cmd_conntrack_enable_disable(1);
    } else if (strcmp(cmd, "conntrack-disable") == 0) {
        return cmd_conntrack_enable_disable(0);
    } else if (strcmp(cmd, "set-timeout") == 0) {
        return cmd_set_timeout(argc - 1, argv + 1);
    } else if (strcmp(cmd, "add-binding") == 0) {
        return cmd_add_binding(argc - 1, argv + 1);
    } else if (strcmp(cmd, "del-binding") == 0) {
        return cmd_del_binding(argc - 1, argv + 1);
    } else if (strcmp(cmd, "show-bindings") == 0) {
        return cmd_show_bindings();
    } else if (strcmp(cmd, "source-guard-enable") == 0) {
        return cmd_source_guard_set_enabled(1, argc - 1, argv + 1);
    } else if (strcmp(cmd, "source-guard-disable") == 0) {
        return cmd_source_guard_set_enabled(0, argc - 1, argv + 1);
    } else if (strcmp(cmd, "source-guard-stats") == 0) {
        return cmd_source_guard_stats();
    } else if (strcmp(cmd, "source-guard-mode") == 0) {
        return cmd_source_guard_mode(argc - 1, argv + 1);
    } else if (strcmp(cmd, "dhcp-snoop-enable") == 0) {
        return cmd_dhcp_snoop_enable_disable(1);
    } else if (strcmp(cmd, "dhcp-snoop-disable") == 0) {
        return cmd_dhcp_snoop_enable_disable(0);
    } else if (strcmp(cmd, "set-trusted-port") == 0) {
        return cmd_set_unset_trusted_port(1, argc - 1, argv + 1);
    } else if (strcmp(cmd, "unset-trusted-port") == 0) {
        return cmd_set_unset_trusted_port(0, argc - 1, argv + 1);
    } else if (strcmp(cmd, "show-trusted-ports") == 0) {
        return cmd_show_trusted_ports();
    } else if (strcmp(cmd, "dhcp-snoop-stats") == 0) {
        return cmd_dhcp_snoop_stats();
    } else {
        RS_LOG_ERROR("Unknown command: %s", cmd);
        usage(argv[0]);
        return 1;
    }
}
