// SPDX-License-Identifier: GPL-2.0
/*
 * rswitchctl ACL Commands
 * 
 * ACL management: add/delete/show rules, statistics
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#if __has_include("rs_log.h")
#include "rs_log.h"
#else
#include "../common/rs_log.h"
#endif

#define DEFAULT_ACL_RULES_MAP      "/sys/fs/bpf/acl_rules"
#define DEFAULT_ACL_RULE_ORDER_MAP "/sys/fs/bpf/acl_rule_order"
#define DEFAULT_ACL_CONFIG_MAP     "/sys/fs/bpf/acl_config_map"
#define DEFAULT_ACL_STATS_MAP      "/sys/fs/bpf/acl_stats"

/* ACL rule structure (must match BPF side) */
struct acl_rule {
    uint32_t src_ip;
    uint32_t src_ip_mask;
    uint32_t dst_ip;
    uint32_t dst_ip_mask;
    
    uint16_t src_port_min;
    uint16_t src_port_max;
    uint16_t dst_port_min;
    uint16_t dst_port_max;
    
    uint8_t  protocol;    // IPPROTO_TCP, IPPROTO_UDP, 0=any
    uint8_t  action;      // 0=PASS, 1=DROP, 2=RATE_LIMIT
    uint16_t vlan_id;     // 0=any
    
    uint32_t ingress_port; // 0=any
    uint32_t priority;    // Lower value = higher priority
    
    uint32_t rate_limit_bps;
    uint32_t burst_size;
    
    uint64_t match_count;
    uint64_t match_bytes;
    uint64_t last_match_ts;
};

struct acl_config {
    uint32_t enabled;
    uint32_t default_action;  // 0=PASS, 1=DROP
    uint32_t rule_count;
    uint32_t reserved;
};

struct acl_stats {
    uint64_t total_matches;
    uint64_t total_drops;
    uint64_t total_rate_limited;
};

/* Parse IP/mask (e.g., "192.168.1.0/24") */
static int parse_ip_cidr(const char *str, uint32_t *ip, uint32_t *mask)
{
    char buf[64];
    strncpy(buf, str, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    
    char *slash = strchr(buf, '/');
    if (slash) {
        *slash = '\0';
        int prefix_len = atoi(slash + 1);
        if (prefix_len < 0 || prefix_len > 32) {
            RS_LOG_ERROR("Invalid prefix length: %d", prefix_len);
            return -1;
        }
        *mask = prefix_len == 0 ? 0 : htonl(~0u << (32 - prefix_len));
    } else {
        *mask = 0xFFFFFFFF;  // /32
    }
    
    struct in_addr addr;
    if (inet_pton(AF_INET, buf, &addr) != 1) {
        RS_LOG_ERROR("Invalid IP address: %s", buf);
        return -1;
    }
    
    *ip = addr.s_addr;
    return 0;
}

/* Add ACL rule */
int cmd_acl_add_rule(int argc, char **argv)
{
    struct acl_rule rule = {0};
    uint32_t rule_id = 0;
    int has_rule_id = 0;
    
    // Default values
    rule.src_port_max = 65535;
    rule.dst_port_max = 65535;
    rule.action = 0;  // PASS
    rule.priority = 1000;
    
    // Parse arguments
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--id") == 0 && i + 1 < argc) {
            rule_id = atoi(argv[++i]);
            has_rule_id = 1;
        }
        else if (strcmp(argv[i], "--src") == 0 && i + 1 < argc) {
            if (parse_ip_cidr(argv[++i], &rule.src_ip, &rule.src_ip_mask) < 0)
                return -1;
        }
        else if (strcmp(argv[i], "--dst") == 0 && i + 1 < argc) {
            if (parse_ip_cidr(argv[++i], &rule.dst_ip, &rule.dst_ip_mask) < 0)
                return -1;
        }
        else if (strcmp(argv[i], "--src-port") == 0 && i + 1 < argc) {
            rule.src_port_min = rule.src_port_max = atoi(argv[++i]);
        }
        else if (strcmp(argv[i], "--dst-port") == 0 && i + 1 < argc) {
            rule.dst_port_min = rule.dst_port_max = atoi(argv[++i]);
        }
        else if (strcmp(argv[i], "--protocol") == 0 && i + 1 < argc) {
            i++;
            if (strcmp(argv[i], "tcp") == 0)
                rule.protocol = 6;  // IPPROTO_TCP
            else if (strcmp(argv[i], "udp") == 0)
                rule.protocol = 17; // IPPROTO_UDP
            else if (strcmp(argv[i], "icmp") == 0)
                rule.protocol = 1;  // IPPROTO_ICMP
            else
                rule.protocol = atoi(argv[i]);
        }
        else if (strcmp(argv[i], "--action") == 0 && i + 1 < argc) {
            i++;
            if (strcmp(argv[i], "pass") == 0)
                rule.action = 0;
            else if (strcmp(argv[i], "drop") == 0)
                rule.action = 1;
            else if (strcmp(argv[i], "rate-limit") == 0)
                rule.action = 2;
            else {
                RS_LOG_ERROR("Invalid action: %s (use pass/drop/rate-limit)", argv[i]);
                return -1;
            }
        }
        else if (strcmp(argv[i], "--priority") == 0 && i + 1 < argc) {
            rule.priority = atoi(argv[++i]);
        }
        else if (strcmp(argv[i], "--rate-limit") == 0 && i + 1 < argc) {
            rule.rate_limit_bps = atoi(argv[++i]);
        }
        else if (strcmp(argv[i], "--vlan") == 0 && i + 1 < argc) {
            rule.vlan_id = atoi(argv[++i]);
        }
    }
    
    if (!has_rule_id) {
        RS_LOG_ERROR("--id required");
        return -1;
    }
    
    // Open map
    int fd = bpf_obj_get(DEFAULT_ACL_RULES_MAP);
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open ACL rules map: %s", strerror(errno));
        return -1;
    }
    
    // Add rule
    if (bpf_map_update_elem(fd, &rule_id, &rule, BPF_ANY) < 0) {
        RS_LOG_ERROR("Failed to add rule: %s", strerror(errno));
        close(fd);
        return -1;
    }
    
    printf("ACL rule %u added successfully\n", rule_id);
    close(fd);
    return 0;
}

/* Delete ACL rule */
int cmd_acl_del_rule(uint32_t rule_id)
{
    int fd = bpf_obj_get(DEFAULT_ACL_RULES_MAP);
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open ACL rules map: %s", strerror(errno));
        return -1;
    }
    
    if (bpf_map_delete_elem(fd, &rule_id) < 0) {
        RS_LOG_ERROR("Failed to delete rule %u: %s", rule_id, strerror(errno));
        close(fd);
        return -1;
    }
    
    printf("ACL rule %u deleted\n", rule_id);
    close(fd);
    return 0;
}

/* Show ACL rules */
int cmd_acl_show_rules(void)
{
    int fd = bpf_obj_get(DEFAULT_ACL_RULES_MAP);
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open ACL rules map: %s", strerror(errno));
        return -1;
    }
    
    printf("ACL Rules:\n");
    printf("%-5s %-8s %-18s %-18s %-12s %-12s %-10s %-10s %s\n",
           "ID", "Priority", "Src IP", "Dst IP", "Src Port", "Dst Port", "Protocol", "Action", "Matches");
    printf("---------------------------------------------------------------------------------------------------\n");
    
    uint32_t rule_id = 0, next_id;
    struct acl_rule rule;
    
    while (bpf_map_get_next_key(fd, &rule_id, &next_id) == 0) {
        if (bpf_map_lookup_elem(fd, &next_id, &rule) == 0) {
            // Format IP addresses
            struct in_addr src_addr = {.s_addr = rule.src_ip};
            struct in_addr dst_addr = {.s_addr = rule.dst_ip};
            char src_str[32], dst_str[32];
            
            if (rule.src_ip == 0) {
                strcpy(src_str, "any");
            } else {
                snprintf(src_str, sizeof(src_str), "%s", inet_ntoa(src_addr));
            }
            
            if (rule.dst_ip == 0) {
                strcpy(dst_str, "any");
            } else {
                snprintf(dst_str, sizeof(dst_str), "%s", inet_ntoa(dst_addr));
            }
            
            // Format ports
            char src_port_str[16], dst_port_str[16];
            if (rule.src_port_min == 0 && rule.src_port_max == 65535)
                strcpy(src_port_str, "any");
            else if (rule.src_port_min == rule.src_port_max)
                snprintf(src_port_str, sizeof(src_port_str), "%u", rule.src_port_min);
            else
                snprintf(src_port_str, sizeof(src_port_str), "%u-%u", rule.src_port_min, rule.src_port_max);
            
            if (rule.dst_port_min == 0 && rule.dst_port_max == 65535)
                strcpy(dst_port_str, "any");
            else if (rule.dst_port_min == rule.dst_port_max)
                snprintf(dst_port_str, sizeof(dst_port_str), "%u", rule.dst_port_min);
            else
                snprintf(dst_port_str, sizeof(dst_port_str), "%u-%u", rule.dst_port_min, rule.dst_port_max);
            
            // Format protocol
            const char *proto_str = "any";
            if (rule.protocol == 6) proto_str = "tcp";
            else if (rule.protocol == 17) proto_str = "udp";
            else if (rule.protocol == 1) proto_str = "icmp";
            
            // Format action
            const char *action_str = "pass";
            if (rule.action == 1) action_str = "drop";
            else if (rule.action == 2) action_str = "rate-limit";
            
            printf("%-5u %-8u %-18s %-18s %-12s %-12s %-10s %-10s %lu\n",
                   next_id, rule.priority, src_str, dst_str,
                   src_port_str, dst_port_str, proto_str, action_str,
                   rule.match_count);
        }
        rule_id = next_id;
    }
    
    close(fd);
    return 0;
}

/* Show ACL statistics */
int cmd_acl_show_stats(void)
{
    int fd = bpf_obj_get(DEFAULT_ACL_STATS_MAP);
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open ACL stats map: %s", strerror(errno));
        return -1;
    }
    
    struct acl_stats stats;
    uint32_t key = 0;
    
    if (bpf_map_lookup_elem(fd, &key, &stats) < 0) {
        RS_LOG_ERROR("Failed to read stats: %s", strerror(errno));
        close(fd);
        return -1;
    }
    
    printf("ACL Statistics:\n");
    printf("  Total Matches: %lu\n", stats.total_matches);
    printf("  Total Drops: %lu\n", stats.total_drops);
    printf("  Total Rate Limited: %lu\n", stats.total_rate_limited);
    
    close(fd);
    return 0;
}

/* Enable/disable ACL */
int cmd_acl_enable(int enable)
{
    int fd = bpf_obj_get(DEFAULT_ACL_CONFIG_MAP);
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open ACL config map: %s", strerror(errno));
        return -1;
    }
    
    struct acl_config config;
    uint32_t key = 0;
    
    if (bpf_map_lookup_elem(fd, &key, &config) < 0) {
        memset(&config, 0, sizeof(config));
    }
    
    config.enabled = enable ? 1 : 0;
    
    if (bpf_map_update_elem(fd, &key, &config, BPF_ANY) < 0) {
        RS_LOG_ERROR("Failed to update config: %s", strerror(errno));
        close(fd);
        return -1;
    }
    
    printf("ACL %s\n", enable ? "enabled" : "disabled");
    close(fd);
    return 0;
}
