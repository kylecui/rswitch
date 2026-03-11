// SPDX-License-Identifier: GPL-2.0
/*
 * rswitchctl Mirror Commands - Enhanced Version
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#if __has_include("rs_log.h")
#include "rs_log.h"
#else
#include "../common/rs_log.h"
#endif

#define DEFAULT_MIRROR_CONFIG_MAP   "/sys/fs/bpf/mirror_config_map"
#define DEFAULT_PORT_MIRROR_MAP     "/sys/fs/bpf/port_mirror_map"
#define DEFAULT_MIRROR_STATS_MAP    "/sys/fs/bpf/mirror_stats"
#define DEFAULT_MIRROR_FILTER_MAP   "/sys/fs/bpf/mirror_filter_rules"

#define MIRROR_MAX_RULES 64

enum mirror_filter_type {
    MIRROR_FILTER_NONE = 0,
    MIRROR_FILTER_SRC_MAC,
    MIRROR_FILTER_DST_MAC,
    MIRROR_FILTER_SRC_IP,
    MIRROR_FILTER_DST_IP,
    MIRROR_FILTER_PROTOCOL,
    MIRROR_FILTER_SRC_PORT,
    MIRROR_FILTER_DST_PORT,
    MIRROR_FILTER_VLAN,
    MIRROR_FILTER_IFINDEX,
    MIRROR_FILTER_NETFLOW,
};

enum mirror_direction {
    MIRROR_DIR_BOTH = 0,
    MIRROR_DIR_INGRESS = 1,
    MIRROR_DIR_EGRESS = 2,
};

struct mirror_filter_rule {
    uint32_t id;
    uint8_t enabled;
    uint8_t filter_type;
    uint8_t direction;
    uint8_t negate;

    union {
        uint8_t mac[6];
        uint32_t ip;
        uint16_t l4_port;
        uint16_t vlan;
        uint32_t ifindex;
        uint8_t protocol;
        struct {
            uint32_t src_ip;
            uint32_t dst_ip;
            uint16_t src_port;
            uint16_t dst_port;
            uint8_t protocol;
            uint8_t _pad[3];
        } netflow;
    } match;

    uint32_t _pad;
    uint64_t match_count;
};

struct mirror_config {
    uint32_t enabled;
    uint32_t span_port;

    uint8_t  ingress_enabled;
    uint8_t  egress_enabled;
    uint8_t  pcap_enabled;
    uint8_t  filter_mode;

    uint16_t vlan_filter;
    uint16_t protocol_filter;

    uint64_t ingress_mirrored_packets;
    uint64_t ingress_mirrored_bytes;
    uint64_t egress_mirrored_packets;
    uint64_t egress_mirrored_bytes;
    uint64_t mirror_drops;
    uint64_t pcap_packets;
};

struct port_mirror_config {
    uint8_t  mirror_ingress;
    uint8_t  mirror_egress;
    uint16_t reserved;
};

static const char *filter_type_str(uint8_t type)
{
    switch (type) {
    case MIRROR_FILTER_SRC_MAC:   return "src-mac";
    case MIRROR_FILTER_DST_MAC:   return "dst-mac";
    case MIRROR_FILTER_SRC_IP:    return "src-ip";
    case MIRROR_FILTER_DST_IP:    return "dst-ip";
    case MIRROR_FILTER_PROTOCOL:  return "protocol";
    case MIRROR_FILTER_SRC_PORT:  return "src-port";
    case MIRROR_FILTER_DST_PORT:  return "dst-port";
    case MIRROR_FILTER_VLAN:      return "vlan";
    case MIRROR_FILTER_IFINDEX:   return "ifindex";
    case MIRROR_FILTER_NETFLOW:   return "netflow";
    default:                      return "unknown";
    }
}

static const char *direction_str(uint8_t dir)
{
    switch (dir) {
    case MIRROR_DIR_BOTH:    return "both";
    case MIRROR_DIR_INGRESS: return "ingress";
    case MIRROR_DIR_EGRESS:  return "egress";
    default:                 return "unknown";
    }
}

int cmd_mirror_enable(int enable, uint32_t span_port)
{
    int fd = bpf_obj_get(DEFAULT_MIRROR_CONFIG_MAP);
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open mirror config map: %s", strerror(errno));
        return -1;
    }

    struct mirror_config config;
    uint32_t key = 0;

    if (bpf_map_lookup_elem(fd, &key, &config) < 0)
        memset(&config, 0, sizeof(config));

    config.enabled = enable ? 1 : 0;
    if (span_port > 0)
        config.span_port = span_port;
    config.ingress_enabled = enable ? 1 : 0;
    config.egress_enabled = enable ? 1 : 0;

    if (bpf_map_update_elem(fd, &key, &config, BPF_ANY) < 0) {
        RS_LOG_ERROR("Failed to update config: %s", strerror(errno));
        close(fd);
        return -1;
    }

    printf("Mirroring %s", enable ? "enabled" : "disabled");
    if (enable && config.span_port)
        printf(" (SPAN port: %u)", config.span_port);
    if (enable && config.pcap_enabled)
        printf(" (PCAP: enabled)");
    printf("\n");

    close(fd);
    return 0;
}

int cmd_mirror_set_span_port(uint32_t span_port)
{
    int fd = bpf_obj_get(DEFAULT_MIRROR_CONFIG_MAP);
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open mirror config map: %s", strerror(errno));
        return -1;
    }

    struct mirror_config config;
    uint32_t key = 0;

    if (bpf_map_lookup_elem(fd, &key, &config) < 0)
        memset(&config, 0, sizeof(config));

    config.span_port = span_port;

    if (bpf_map_update_elem(fd, &key, &config, BPF_ANY) < 0) {
        RS_LOG_ERROR("Failed to update config: %s", strerror(errno));
        close(fd);
        return -1;
    }

    printf("SPAN port set to %u\n", span_port);
    close(fd);
    return 0;
}

int cmd_mirror_set_pcap(int enable)
{
    int fd = bpf_obj_get(DEFAULT_MIRROR_CONFIG_MAP);
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open mirror config map: %s", strerror(errno));
        return -1;
    }

    struct mirror_config config;
    uint32_t key = 0;

    if (bpf_map_lookup_elem(fd, &key, &config) < 0)
        memset(&config, 0, sizeof(config));

    config.pcap_enabled = enable ? 1 : 0;

    if (bpf_map_update_elem(fd, &key, &config, BPF_ANY) < 0) {
        RS_LOG_ERROR("Failed to update config: %s", strerror(errno));
        close(fd);
        return -1;
    }

    printf("PCAP capture %s\n", enable ? "enabled" : "disabled");
    close(fd);
    return 0;
}

int cmd_mirror_set_port(uint32_t ifindex, int ingress, int egress)
{
    int fd = bpf_obj_get(DEFAULT_PORT_MIRROR_MAP);
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open port mirror map: %s", strerror(errno));
        return -1;
    }

    struct port_mirror_config port_config;

    if (bpf_map_lookup_elem(fd, &ifindex, &port_config) < 0)
        memset(&port_config, 0, sizeof(port_config));

    if (ingress >= 0)
        port_config.mirror_ingress = ingress ? 1 : 0;
    if (egress >= 0)
        port_config.mirror_egress = egress ? 1 : 0;

    if (bpf_map_update_elem(fd, &ifindex, &port_config, BPF_ANY) < 0) {
        RS_LOG_ERROR("Failed to update port config: %s", strerror(errno));
        close(fd);
        return -1;
    }

    printf("Port %u mirroring: ingress=%s, egress=%s\n",
           ifindex,
           port_config.mirror_ingress ? "enabled" : "disabled",
           port_config.mirror_egress ? "enabled" : "disabled");

    close(fd);
    return 0;
}

int cmd_mirror_add_filter(uint32_t id, uint8_t type, uint8_t direction,
                          const char *value, int negate)
{
    int fd = bpf_obj_get(DEFAULT_MIRROR_FILTER_MAP);
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open filter map: %s", strerror(errno));
        return -1;
    }

    if (id >= MIRROR_MAX_RULES) {
        RS_LOG_ERROR("Rule ID must be < %d", MIRROR_MAX_RULES);
        close(fd);
        return -1;
    }

    struct mirror_filter_rule rule;
    memset(&rule, 0, sizeof(rule));

    rule.id = id;
    rule.enabled = 1;
    rule.filter_type = type;
    rule.direction = direction;
    rule.negate = negate ? 1 : 0;

    switch (type) {
    case MIRROR_FILTER_SRC_IP:
    case MIRROR_FILTER_DST_IP:
        if (inet_pton(AF_INET, value, &rule.match.ip) != 1) {
            RS_LOG_ERROR("Invalid IP address: %s", value);
            close(fd);
            return -1;
        }
        break;
    case MIRROR_FILTER_SRC_PORT:
    case MIRROR_FILTER_DST_PORT:
        rule.match.l4_port = htons((uint16_t)atoi(value));
        break;
    case MIRROR_FILTER_VLAN:
        rule.match.vlan = (uint16_t)atoi(value);
        break;
    case MIRROR_FILTER_IFINDEX:
        rule.match.ifindex = (uint32_t)atoi(value);
        break;
    case MIRROR_FILTER_PROTOCOL:
        rule.match.protocol = (uint8_t)atoi(value);
        break;
    case MIRROR_FILTER_SRC_MAC:
    case MIRROR_FILTER_DST_MAC:
        if (sscanf(value, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                   &rule.match.mac[0], &rule.match.mac[1], &rule.match.mac[2],
                   &rule.match.mac[3], &rule.match.mac[4], &rule.match.mac[5]) != 6) {
            RS_LOG_ERROR("Invalid MAC address: %s", value);
            close(fd);
            return -1;
        }
        break;
    default:
        RS_LOG_ERROR("Unsupported filter type: %d", type);
        close(fd);
        return -1;
    }

    if (bpf_map_update_elem(fd, &id, &rule, BPF_ANY) < 0) {
        RS_LOG_ERROR("Failed to add filter: %s", strerror(errno));
        close(fd);
        return -1;
    }

    printf("Added filter rule %u: type=%s, direction=%s, value=%s%s\n",
           id, filter_type_str(type), direction_str(direction), value,
           negate ? " (negated)" : "");

    close(fd);
    return 0;
}

int cmd_mirror_del_filter(uint32_t id)
{
    int fd = bpf_obj_get(DEFAULT_MIRROR_FILTER_MAP);
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open filter map: %s", strerror(errno));
        return -1;
    }

    struct mirror_filter_rule rule;
    memset(&rule, 0, sizeof(rule));
    rule.id = id;
    rule.enabled = 0;

    if (bpf_map_update_elem(fd, &id, &rule, BPF_ANY) < 0) {
        RS_LOG_ERROR("Failed to delete filter: %s", strerror(errno));
        close(fd);
        return -1;
    }

    printf("Deleted filter rule %u\n", id);
    close(fd);
    return 0;
}

int cmd_mirror_show_filters(void)
{
    int fd = bpf_obj_get(DEFAULT_MIRROR_FILTER_MAP);
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open filter map: %s", strerror(errno));
        return -1;
    }

    printf("Mirror Filter Rules:\n");
    printf("%-4s %-10s %-10s %-8s %-20s %-10s\n",
           "ID", "Type", "Direction", "Negate", "Value", "Matches");
    printf("--------------------------------------------------------------\n");

    int found = 0;
    for (uint32_t i = 0; i < MIRROR_MAX_RULES; i++) {
        struct mirror_filter_rule rule;
        if (bpf_map_lookup_elem(fd, &i, &rule) < 0)
            continue;
        if (!rule.enabled)
            continue;

        found = 1;
        char value[64] = "";

        switch (rule.filter_type) {
        case MIRROR_FILTER_SRC_IP:
        case MIRROR_FILTER_DST_IP:
            inet_ntop(AF_INET, &rule.match.ip, value, sizeof(value));
            break;
        case MIRROR_FILTER_SRC_PORT:
        case MIRROR_FILTER_DST_PORT:
            snprintf(value, sizeof(value), "%u", ntohs(rule.match.l4_port));
            break;
        case MIRROR_FILTER_VLAN:
            snprintf(value, sizeof(value), "%u", rule.match.vlan);
            break;
        case MIRROR_FILTER_IFINDEX:
            snprintf(value, sizeof(value), "%u", rule.match.ifindex);
            break;
        case MIRROR_FILTER_PROTOCOL:
            snprintf(value, sizeof(value), "%u", rule.match.protocol);
            break;
        case MIRROR_FILTER_SRC_MAC:
        case MIRROR_FILTER_DST_MAC:
            snprintf(value, sizeof(value), "%02x:%02x:%02x:%02x:%02x:%02x",
                     rule.match.mac[0], rule.match.mac[1], rule.match.mac[2],
                     rule.match.mac[3], rule.match.mac[4], rule.match.mac[5]);
            break;
        }

        printf("%-4u %-10s %-10s %-8s %-20s %-10lu\n",
               rule.id, filter_type_str(rule.filter_type),
               direction_str(rule.direction),
               rule.negate ? "yes" : "no",
               value, rule.match_count);
    }

    if (!found)
        printf("  (no filter rules configured)\n");

    close(fd);
    return 0;
}

int cmd_mirror_show_config(void)
{
    int fd = bpf_obj_get(DEFAULT_MIRROR_CONFIG_MAP);
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open mirror config map: %s", strerror(errno));
        return -1;
    }

    struct mirror_config config;
    uint32_t key = 0;

    if (bpf_map_lookup_elem(fd, &key, &config) < 0) {
        RS_LOG_ERROR("Failed to read config: %s", strerror(errno));
        close(fd);
        return -1;
    }

    printf("Mirror Configuration:\n");
    printf("  Status: %s\n", config.enabled ? "enabled" : "disabled");
    printf("  SPAN Port: %u\n", config.span_port);
    printf("  Ingress Mirroring: %s\n", config.ingress_enabled ? "enabled" : "disabled");
    printf("  Egress Mirroring: %s\n", config.egress_enabled ? "enabled" : "disabled");
    printf("  PCAP Capture: %s\n", config.pcap_enabled ? "enabled" : "disabled");

    if (config.vlan_filter > 0)
        printf("  VLAN Filter: %u\n", config.vlan_filter);
    if (config.protocol_filter > 0)
        printf("  Protocol Filter: 0x%04x\n", config.protocol_filter);

    close(fd);

    fd = bpf_obj_get(DEFAULT_PORT_MIRROR_MAP);
    if (fd >= 0) {
        printf("\nPer-Port Mirroring:\n");
        printf("%-10s %-15s %-15s\n", "Port", "Ingress", "Egress");
        printf("----------------------------------------\n");

        uint32_t port_id = 0, next_port;
        struct port_mirror_config port_config;

        while (bpf_map_get_next_key(fd, &port_id, &next_port) == 0) {
            if (bpf_map_lookup_elem(fd, &next_port, &port_config) == 0) {
                if (port_config.mirror_ingress || port_config.mirror_egress) {
                    printf("%-10u %-15s %-15s\n",
                           next_port,
                           port_config.mirror_ingress ? "enabled" : "disabled",
                           port_config.mirror_egress ? "enabled" : "disabled");
                }
            }
            port_id = next_port;
        }
        close(fd);
    }

    cmd_mirror_show_filters();

    return 0;
}

int cmd_mirror_show_stats(void)
{
    int fd = bpf_obj_get(DEFAULT_MIRROR_CONFIG_MAP);
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open mirror config map: %s", strerror(errno));
        return -1;
    }

    struct mirror_config config;
    uint32_t key = 0;

    if (bpf_map_lookup_elem(fd, &key, &config) < 0) {
        RS_LOG_ERROR("Failed to read config: %s", strerror(errno));
        close(fd);
        return -1;
    }

    printf("Mirror Statistics:\n");
    printf("  Ingress:\n");
    printf("    Packets: %lu\n", config.ingress_mirrored_packets);
    printf("    Bytes: %lu\n", config.ingress_mirrored_bytes);
    printf("  Egress:\n");
    printf("    Packets: %lu\n", config.egress_mirrored_packets);
    printf("    Bytes: %lu\n", config.egress_mirrored_bytes);
    printf("  PCAP Packets: %lu\n", config.pcap_packets);
    printf("  Drops: %lu\n", config.mirror_drops);

    close(fd);
    return 0;
}
