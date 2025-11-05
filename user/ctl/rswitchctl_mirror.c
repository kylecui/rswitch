// SPDX-License-Identifier: GPL-2.0
/*
 * rswitchctl Mirror Commands
 * 
 * Port mirroring (SPAN) management
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define DEFAULT_MIRROR_CONFIG_MAP "/sys/fs/bpf/mirror_config_map"
#define DEFAULT_PORT_MIRROR_MAP   "/sys/fs/bpf/port_mirror_map"
#define DEFAULT_MIRROR_STATS_MAP  "/sys/fs/bpf/mirror_stats"

/* Mirror structures (must match BPF side) */
struct mirror_config {
    uint32_t enabled;
    uint32_t span_port;
    
    uint8_t  ingress_enabled;
    uint8_t  egress_enabled;
    uint16_t reserved;
    
    uint16_t filter_vlan;
    uint16_t filter_proto;
    
    uint64_t ingress_packets;
    uint64_t ingress_bytes;
    uint64_t egress_packets;
    uint64_t egress_bytes;
    uint64_t mirror_drops;
};

struct port_mirror_config {
    uint8_t  mirror_ingress;
    uint8_t  mirror_egress;
    uint16_t reserved;
};

/* Enable/disable mirroring */
int cmd_mirror_enable(int enable, uint32_t span_port)
{
    int fd = bpf_obj_get(DEFAULT_MIRROR_CONFIG_MAP);
    if (fd < 0) {
        fprintf(stderr, "Failed to open mirror config map: %s\n", strerror(errno));
        return -1;
    }
    
    struct mirror_config config;
    uint32_t key = 0;
    
    if (bpf_map_lookup_elem(fd, &key, &config) < 0) {
        memset(&config, 0, sizeof(config));
    }
    
    config.enabled = enable ? 1 : 0;
    if (span_port > 0)
        config.span_port = span_port;
    config.ingress_enabled = enable ? 1 : 0;
    config.egress_enabled = enable ? 1 : 0;
    
    if (bpf_map_update_elem(fd, &key, &config, BPF_ANY) < 0) {
        fprintf(stderr, "Failed to update config: %s\n", strerror(errno));
        close(fd);
        return -1;
    }
    
    if (enable) {
        printf("Mirroring enabled (SPAN port: %u)\n", config.span_port);
    } else {
        printf("Mirroring disabled\n");
    }
    
    close(fd);
    return 0;
}

/* Set SPAN port */
int cmd_mirror_set_span_port(uint32_t span_port)
{
    int fd = bpf_obj_get(DEFAULT_MIRROR_CONFIG_MAP);
    if (fd < 0) {
        fprintf(stderr, "Failed to open mirror config map: %s\n", strerror(errno));
        return -1;
    }
    
    struct mirror_config config;
    uint32_t key = 0;
    
    if (bpf_map_lookup_elem(fd, &key, &config) < 0) {
        memset(&config, 0, sizeof(config));
    }
    
    config.span_port = span_port;
    
    if (bpf_map_update_elem(fd, &key, &config, BPF_ANY) < 0) {
        fprintf(stderr, "Failed to update config: %s\n", strerror(errno));
        close(fd);
        return -1;
    }
    
    printf("SPAN port set to %u\n", span_port);
    close(fd);
    return 0;
}

/* Configure port mirroring */
int cmd_mirror_set_port(uint32_t ifindex, int ingress, int egress)
{
    int fd = bpf_obj_get(DEFAULT_PORT_MIRROR_MAP);
    if (fd < 0) {
        fprintf(stderr, "Failed to open port mirror map: %s\n", strerror(errno));
        return -1;
    }
    
    struct port_mirror_config port_config;
    
    if (bpf_map_lookup_elem(fd, &ifindex, &port_config) < 0) {
        memset(&port_config, 0, sizeof(port_config));
    }
    
    if (ingress >= 0)
        port_config.mirror_ingress = ingress ? 1 : 0;
    if (egress >= 0)
        port_config.mirror_egress = egress ? 1 : 0;
    
    if (bpf_map_update_elem(fd, &ifindex, &port_config, BPF_ANY) < 0) {
        fprintf(stderr, "Failed to update port config: %s\n", strerror(errno));
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

/* Show mirror configuration */
int cmd_mirror_show_config(void)
{
    int fd = bpf_obj_get(DEFAULT_MIRROR_CONFIG_MAP);
    if (fd < 0) {
        fprintf(stderr, "Failed to open mirror config map: %s\n", strerror(errno));
        return -1;
    }
    
    struct mirror_config config;
    uint32_t key = 0;
    
    if (bpf_map_lookup_elem(fd, &key, &config) < 0) {
        fprintf(stderr, "Failed to read config: %s\n", strerror(errno));
        close(fd);
        return -1;
    }
    
    printf("Mirror Configuration:\n");
    printf("  Status: %s\n", config.enabled ? "enabled" : "disabled");
    printf("  SPAN Port: %u\n", config.span_port);
    printf("  Ingress Mirroring: %s\n", config.ingress_enabled ? "enabled" : "disabled");
    printf("  Egress Mirroring: %s\n", config.egress_enabled ? "enabled" : "disabled");
    
    if (config.filter_vlan > 0)
        printf("  VLAN Filter: %u\n", config.filter_vlan);
    if (config.filter_proto > 0)
        printf("  Protocol Filter: 0x%04x\n", config.filter_proto);
    
    close(fd);
    
    // Show per-port config
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
    
    return 0;
}

/* Show mirror statistics */
int cmd_mirror_show_stats(void)
{
    int fd = bpf_obj_get(DEFAULT_MIRROR_STATS_MAP);
    if (fd < 0) {
        fprintf(stderr, "Failed to open mirror stats map: %s\n", strerror(errno));
        return -1;
    }
    
    struct mirror_config stats;  // Reuse config struct (has stats fields)
    uint32_t key = 0;
    
    if (bpf_map_lookup_elem(fd, &key, &stats) < 0) {
        fprintf(stderr, "Failed to read stats: %s\n", strerror(errno));
        close(fd);
        return -1;
    }
    
    printf("Mirror Statistics:\n");
    printf("  Ingress:\n");
    printf("    Packets: %lu\n", stats.ingress_packets);
    printf("    Bytes: %lu\n", stats.ingress_bytes);
    printf("  Egress:\n");
    printf("    Packets: %lu\n", stats.egress_packets);
    printf("    Bytes: %lu\n", stats.egress_bytes);
    printf("  Drops: %lu\n", stats.mirror_drops);
    
    close(fd);
    return 0;
}
