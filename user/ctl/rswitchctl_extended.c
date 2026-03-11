// SPDX-License-Identifier: GPL-2.0
/*
 * rswitchctl_extended - Enhanced Control API
 * 
 * Additional commands for pipeline inspection, module management,
 * policy updates, and telemetry query.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#if __has_include("rs_log.h")
#include "rs_log.h"
#else
#include "../common/rs_log.h"
#endif

#define BPF_PIN_PATH "/sys/fs/bpf"

struct rs_stats {
    __u64 rx_packets;
    __u64 rx_bytes;
    __u64 tx_packets;
    __u64 tx_bytes;
    __u64 rx_drops;
    __u64 tx_drops;
};

struct rs_module_stats {
    __u64 packets_processed;
    __u64 packets_forwarded;
    __u64 packets_dropped;
    __u64 packets_error;
    __u64 bytes_processed;
    __u64 last_seen_ns;
    __u32 module_id;
    char name[32];
};

/* List all loaded BPF programs */
int cmd_list_modules(void)
{
    char path[256];
    struct bpf_prog_info info = {};
    __u32 info_len = sizeof(info);
    int fd;
    
    printf("Loaded rSwitch Modules:\n");
    printf("%-4s %-20s %-10s %-10s\n", "ID", "Name", "Type", "Tag");
    printf("------------------------------------------------------------\n");
    
    /* Iterate through pinned programs */
    DIR *dir = opendir(BPF_PIN_PATH);
    if (!dir) {
        RS_LOG_ERROR("Failed to open %s: %s", BPF_PIN_PATH, strerror(errno));
        return -1;
    }
    
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.')
            continue;
        
        /* Try to open as BPF object */
        snprintf(path, sizeof(path), "%s/%s", BPF_PIN_PATH, entry->d_name);
        fd = bpf_obj_get(path);
        if (fd < 0)
            continue;
        
        /* Get program info */
        if (bpf_obj_get_info_by_fd(fd, &info, &info_len) == 0) {
            if (info.type == BPF_PROG_TYPE_XDP) {
                printf("%-4u %-20s %-10s %02x%02x%02x%02x\n",
                       info.id,
                       info.name[0] ? info.name : entry->d_name,
                       "XDP",
                       info.tag[0], info.tag[1], info.tag[2], info.tag[3]);
            }
        }
        
        close(fd);
    }
    
    closedir(dir);
    return 0;
}

/* Show pipeline configuration */
int cmd_show_pipeline(void)
{
    char path[256];
    int fd;
    
    printf("rSwitch Pipeline Configuration:\n\n");
    
    /* Open rs_progs (tail-call map) */
    snprintf(path, sizeof(path), "%s/rs_progs", BPF_PIN_PATH);
    fd = bpf_obj_get(path);
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open rs_progs map: %s", strerror(errno));
        return -1;
    }
    
    printf("Tail-Call Chain:\n");
    printf("%-8s %-20s %-10s\n", "Stage", "Module", "Prog ID");
    printf("------------------------------------------------------------\n");
    
    /* Iterate through tail-call map */
    __u32 key, next_key;
    struct bpf_prog_info info = {};
    __u32 info_len = sizeof(info);
    
    key = 0;
    while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
        __u32 prog_id;
        if (bpf_map_lookup_elem(fd, &next_key, &prog_id) == 0) {
            int prog_fd = bpf_prog_get_fd_by_id(prog_id);
            if (prog_fd > 0) {
                memset(&info, 0, sizeof(info));
                if (bpf_obj_get_info_by_fd(prog_fd, &info, &info_len) == 0) {
                    printf("%-8u %-20s %-10u\n", next_key, info.name, prog_id);
                }
                close(prog_fd);
            }
        }
        key = next_key;
    }
    
    close(fd);
    return 0;
}

/* Show port configurations */
int cmd_show_ports(void)
{
    char path[256];
    int fd;
    
    printf("Port Configuration:\n\n");
    
    /* Open rs_port_config_map */
    snprintf(path, sizeof(path), "%s/rs_port_config_map", BPF_PIN_PATH);
    fd = bpf_obj_get(path);
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open rs_port_config_map: %s", strerror(errno));
        return -1;
    }
    
    printf("%-8s %-10s %-8s %-12s %-8s\n", "Ifindex", "Enabled", "Mode", "VLAN", "Learning");
    printf("------------------------------------------------------------\n");
    
    /* Iterate through port config */
    __u32 key, next_key;
    struct rs_port_config {
        __u32 ifindex;
        __u8  enabled;
        __u8  mgmt_type;
        __u8  vlan_mode;
        __u8  learning;
        __u16 pvid;
        /* ... other fields ... */
    } config;
    
    key = 0;
    while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(fd, &next_key, &config) == 0) {
            const char *vlan_mode_str[] = {"OFF", "ACCESS", "TRUNK", "HYBRID"};
            printf("%-8u %-10s %-8s %-12s %-8s\n",
                   config.ifindex,
                   config.enabled ? "yes" : "no",
                   config.vlan_mode < 4 ? vlan_mode_str[config.vlan_mode] : "UNKNOWN",
                   config.vlan_mode != 0 ? "enabled" : "disabled",
                   config.learning ? "on" : "off");
        }
        key = next_key;
    }
    
    close(fd);
    return 0;
}

/* Show MAC table */
int cmd_show_macs(int limit)
{
    char path[256];
    int fd;
    
    printf("MAC Address Table:\n\n");
    
    /* Open rs_mac_table */
    snprintf(path, sizeof(path), "%s/rs_mac_table", BPF_PIN_PATH);
    fd = bpf_obj_get(path);
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open rs_mac_table: %s", strerror(errno));
        return -1;
    }
    
    printf("%-18s %-6s %-10s %-8s\n", "MAC Address", "VLAN", "Interface", "Type");
    printf("------------------------------------------------------------\n");
    
    /* Iterate through MAC table */
    struct rs_mac_key {
        __u8 mac[6];
        __u16 vlan;
    } key, next_key;
    
    struct rs_mac_entry {
        __u32 ifindex;
        __u8  static_entry;
        __u8  reserved[3];
        __u64 last_seen;
        __u32 hit_count;
    } entry;
    
    int count = 0;
    memset(&key, 0, sizeof(key));
    
    while (bpf_map_get_next_key(fd, &key, &next_key) == 0 && count < limit) {
        if (bpf_map_lookup_elem(fd, &next_key, &entry) == 0) {
            printf("%02x:%02x:%02x:%02x:%02x:%02x %-6u %-10u %-8s\n",
                   next_key.mac[0], next_key.mac[1], next_key.mac[2],
                   next_key.mac[3], next_key.mac[4], next_key.mac[5],
                   next_key.vlan,
                   entry.ifindex,
                   entry.static_entry ? "static" : "dynamic");
            count++;
        }
        key = next_key;
    }
    
    printf("\nTotal entries shown: %d\n", count);
    close(fd);
    return 0;
}

/* Show statistics */
int cmd_show_stats(const char *module_filter, const char *format)
{
    char path[256];
    int stats_fd;
    int module_fd;
    int ncpus;
    int json = format && strcmp(format, "json") == 0;
    int first_iface = 1;
    int first_module = 1;

    ncpus = libbpf_num_possible_cpus();
    if (ncpus <= 0) {
        RS_LOG_ERROR("Failed to get possible CPU count");
        return -1;
    }

    snprintf(path, sizeof(path), "%s/rs_stats_map", BPF_PIN_PATH);
    stats_fd = bpf_obj_get(path);
    if (stats_fd < 0) {
        RS_LOG_ERROR("Failed to open rs_stats_map: %s", strerror(errno));
        return -1;
    }

    snprintf(path, sizeof(path), "%s/rs_module_stats_map", BPF_PIN_PATH);
    module_fd = bpf_obj_get(path);

    if (json) {
        printf("{\n  \"interfaces\": [\n");
    } else {
        printf("Interface Statistics:\n\n");
        printf("%-8s %-12s %-12s %-12s %-12s\n",
               "Ifindex", "RX Packets", "RX Bytes", "TX Packets", "TX Bytes");
        printf("--------------------------------------------------------------------\n");
    }

    {
        __u32 key;
        __u32 next_key;
        int ret = bpf_map_get_next_key(stats_fd, NULL, &next_key);

        while (ret == 0) {
            struct rs_stats total = {0};
            struct rs_stats *values = calloc((size_t)ncpus, sizeof(*values));

            if (!values)
                break;

            if (bpf_map_lookup_elem(stats_fd, &next_key, values) == 0) {
                for (int c = 0; c < ncpus; c++) {
                    total.rx_packets += values[c].rx_packets;
                    total.rx_bytes += values[c].rx_bytes;
                    total.tx_packets += values[c].tx_packets;
                    total.tx_bytes += values[c].tx_bytes;
                    total.rx_drops += values[c].rx_drops;
                    total.tx_drops += values[c].tx_drops;
                }

                if (json) {
                    printf("%s    {\"ifindex\": %u, \"rx_packets\": %llu, \"rx_bytes\": %llu, \"tx_packets\": %llu, \"tx_bytes\": %llu}",
                           first_iface ? "" : ",\n",
                           next_key,
                           (unsigned long long)total.rx_packets,
                           (unsigned long long)total.rx_bytes,
                           (unsigned long long)total.tx_packets,
                           (unsigned long long)total.tx_bytes);
                    first_iface = 0;
                } else {
                    printf("%-8u %-12llu %-12llu %-12llu %-12llu\n",
                           next_key,
                           (unsigned long long)total.rx_packets,
                           (unsigned long long)total.rx_bytes,
                           (unsigned long long)total.tx_packets,
                           (unsigned long long)total.tx_bytes);
                }
            }

            free(values);
            key = next_key;
            ret = bpf_map_get_next_key(stats_fd, &key, &next_key);
        }
    }

    if (json) {
        printf("\n  ],\n  \"modules\": [\n");
    } else {
        printf("\nPer-Module Statistics:\n\n");
        printf("%-20s %15s %15s %15s %10s\n",
               "Module", "Processed", "Forwarded", "Dropped", "Errors");
        printf("%-20s %15s %15s %15s %10s\n",
               "------", "---------", "---------", "-------", "------");
    }

    if (module_fd >= 0) {
        for (__u32 i = 0; i < 64; i++) {
            struct rs_module_stats total = {0};
            const char *name = "(unknown)";
            struct rs_module_stats *values = calloc((size_t)ncpus, sizeof(*values));

            if (!values)
                break;

            if (bpf_map_lookup_elem(module_fd, &i, values) < 0) {
                free(values);
                continue;
            }

            for (int c = 0; c < ncpus; c++) {
                total.packets_processed += values[c].packets_processed;
                total.packets_forwarded += values[c].packets_forwarded;
                total.packets_dropped += values[c].packets_dropped;
                total.packets_error += values[c].packets_error;
                total.bytes_processed += values[c].bytes_processed;
            }

            if (total.packets_processed == 0) {
                free(values);
                continue;
            }

            for (int c = 0; c < ncpus; c++) {
                if (values[c].name[0] != '\0') {
                    name = values[c].name;
                    break;
                }
            }

            if (module_filter && strcmp(module_filter, name) != 0) {
                free(values);
                continue;
            }

            if (json) {
                printf("%s    {\"module\": \"%s\", \"processed\": %llu, \"forwarded\": %llu, \"dropped\": %llu, \"errors\": %llu}",
                       first_module ? "" : ",\n",
                       name,
                       (unsigned long long)total.packets_processed,
                       (unsigned long long)total.packets_forwarded,
                       (unsigned long long)total.packets_dropped,
                       (unsigned long long)total.packets_error);
                first_module = 0;
            } else {
                printf("%-20s %15llu %15llu %15llu %10llu\n",
                       name,
                       (unsigned long long)total.packets_processed,
                       (unsigned long long)total.packets_forwarded,
                       (unsigned long long)total.packets_dropped,
                       (unsigned long long)total.packets_error);
            }

            free(values);
        }
    } else if (!json) {
        RS_LOG_WARN("Module stats map not available");
    }

    if (json)
        printf("\n  ]\n}\n");

    close(stats_fd);
    if (module_fd >= 0)
        close(module_fd);
    return 0;
}

/* Flush MAC table */
int cmd_flush_macs(void)
{
    char path[256];
    int fd;
    
    /* Open rs_mac_table */
    snprintf(path, sizeof(path), "%s/rs_mac_table", BPF_PIN_PATH);
    fd = bpf_obj_get(path);
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open rs_mac_table: %s", strerror(errno));
        return -1;
    }
    
    /* Iterate and delete all dynamic entries */
    struct rs_mac_key {
        __u8 mac[6];
        __u16 vlan;
    } key, next_key, keys_to_delete[1024];
    
    struct rs_mac_entry {
        __u32 ifindex;
        __u8  static_entry;
        __u8  reserved[3];
        __u64 last_seen;
        __u32 hit_count;
    } entry;
    
    int count = 0;
    memset(&key, 0, sizeof(key));
    
    /* First, collect keys to delete */
    while (bpf_map_get_next_key(fd, &key, &next_key) == 0 && count < 1024) {
        if (bpf_map_lookup_elem(fd, &next_key, &entry) == 0) {
            if (!entry.static_entry) {
                keys_to_delete[count++] = next_key;
            }
        }
        key = next_key;
    }
    
    /* Delete collected keys */
    for (int i = 0; i < count; i++) {
        bpf_map_delete_elem(fd, &keys_to_delete[i]);
    }
    
    printf("Flushed %d dynamic MAC entries\n", count);
    close(fd);
    return 0;
}

/* Get telemetry snapshot */
int cmd_get_telemetry(void)
{
    printf("Telemetry Snapshot:\n\n");
    
    /* Collect metrics from various maps */
    printf("VOQd State:\n");
    /* Call existing show_state functionality */
    
    printf("\nStatistics:\n");
    cmd_show_stats(NULL, "text");
    
    printf("\nMAC Table Summary:\n");
    cmd_show_macs(10);
    
    return 0;
}

/* Usage */
static void usage_extended(const char *prog)
{
    fprintf(stderr,
        "Extended Commands:\n"
        "  list-modules           List all loaded BPF modules\n"
        "  show-pipeline          Show tail-call pipeline configuration\n"
        "  show-ports             Show port configuration\n"
        "  show-macs [limit]      Show MAC address table (default: 100)\n"
        "  show-stats             Show interface statistics\n"
        "  flush-macs             Flush dynamic MAC entries\n"
        "  get-telemetry          Get comprehensive telemetry snapshot\n"
        "\n"
        "Examples:\n"
        "  %s list-modules\n"
        "  %s show-pipeline\n"
        "  %s show-macs 50\n"
        "  %s flush-macs\n",
        prog, prog, prog, prog);
}

/* Main entry for extended commands */
int main_extended(int argc, char **argv)
{
    if (argc < 2) {
        usage_extended(argv[0]);
        return 1;
    }
    
    const char *cmd = argv[1];
    
    if (strcmp(cmd, "list-modules") == 0) {
        return cmd_list_modules();
    } else if (strcmp(cmd, "show-pipeline") == 0) {
        return cmd_show_pipeline();
    } else if (strcmp(cmd, "show-ports") == 0) {
        return cmd_show_ports();
    } else if (strcmp(cmd, "show-macs") == 0) {
        int limit = 100;
        if (argc > 2)
            limit = atoi(argv[2]);
        return cmd_show_macs(limit);
    } else if (strcmp(cmd, "show-stats") == 0) {
        return cmd_show_stats(NULL, "text");
    } else if (strcmp(cmd, "flush-macs") == 0) {
        return cmd_flush_macs();
    } else if (strcmp(cmd, "get-telemetry") == 0) {
        return cmd_get_telemetry();
    } else {
        RS_LOG_ERROR("Unknown command: %s", cmd);
        usage_extended(argv[0]);
        return 1;
    }
}
