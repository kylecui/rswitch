// SPDX-License-Identifier: GPL-2.0
/* 
 * rsportctl - rSwitch Port Configuration Tool
 * 
 * Configure individual port settings including VLAN mode, learning, etc.
 * 
 * Usage:
 *   rsportctl <ifname> show
 *   rsportctl <ifname> set vlan-mode <off|access|trunk|hybrid>
 *   rsportctl <ifname> set access-vlan <vlan_id>
 *   rsportctl <ifname> set native-vlan <vlan_id>
 *   rsportctl <ifname> set learning <on|off>
 *   rsportctl <ifname> set allowed-vlans <vlan1,vlan2,...>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#if __has_include("rs_log.h")
#include "rs_log.h"
#else
#include "../common/rs_log.h"
#endif
#include <bpf/bpf.h>

#define PIN_PATH "/sys/fs/bpf"

/* From map_defs.h */
enum rs_vlan_mode {
    RS_VLAN_MODE_OFF = 0,
    RS_VLAN_MODE_ACCESS = 1,
    RS_VLAN_MODE_TRUNK = 2,
    RS_VLAN_MODE_HYBRID = 3
};

struct rs_port_config {
    __u32 ifindex;
    __u8  enabled;
    __u8  mgmt_type;
    __u8  vlan_mode;
    __u8  learning;
    
    __u16 pvid;
    __u16 native_vlan;
    __u16 access_vlan;
    __u16 allowed_vlan_count;
    __u16 allowed_vlans[128];
    __u16 tagged_vlan_count;
    __u16 tagged_vlans[64];
    __u16 untagged_vlan_count;
    __u16 untagged_vlans[64];
    
    __u8  default_prio;
    __u8  trust_dscp;
    __u16 rate_limit_kbps;
    
    __u8  port_security;
    __u8  max_macs;
    __u16 reserved;
    
    __u32 reserved2[4];
};

static const char *vlan_mode_str(int mode)
{
    switch (mode) {
    case RS_VLAN_MODE_OFF:    return "OFF";
    case RS_VLAN_MODE_ACCESS: return "ACCESS";
    case RS_VLAN_MODE_TRUNK:  return "TRUNK";
    case RS_VLAN_MODE_HYBRID: return "HYBRID";
    default: return "UNKNOWN";
    }
}

static int parse_vlan_mode(const char *str)
{
    if (strcasecmp(str, "off") == 0)    return RS_VLAN_MODE_OFF;
    if (strcasecmp(str, "access") == 0) return RS_VLAN_MODE_ACCESS;
    if (strcasecmp(str, "trunk") == 0)  return RS_VLAN_MODE_TRUNK;
    if (strcasecmp(str, "hybrid") == 0) return RS_VLAN_MODE_HYBRID;
    return -1;
}

static int parse_vlan_list(const char *str, __u16 *vlans, __u16 *count, __u16 max_count)
{
    char *buf = strdup(str);
    char *token = strtok(buf, ",");
    *count = 0;
    
    while (token && *count < max_count) {
        int vlan = atoi(token);
        if (vlan < 1 || vlan > 4094) {
            RS_LOG_ERROR("Invalid VLAN ID: %d (must be 1-4094)", vlan);
            free(buf);
            return -1;
        }
        vlans[(*count)++] = (__u16)vlan;
        token = strtok(NULL, ",");
    }
    
    free(buf);
    return 0;
}

static void show_port(struct rs_port_config *cfg)
{
    printf("Port Configuration:\n");
    printf("  Interface: %d\n", cfg->ifindex);
    printf("  Enabled: %s\n", cfg->enabled ? "yes" : "no");
    printf("  Management: %s\n", cfg->mgmt_type ? "managed" : "dumb");
    printf("  VLAN mode: %s\n", vlan_mode_str(cfg->vlan_mode));
    printf("  MAC learning: %s\n", cfg->learning ? "enabled" : "disabled");
    
    printf("\nVLAN Configuration:\n");
    if (cfg->vlan_mode == RS_VLAN_MODE_ACCESS) {
        printf("  Access VLAN: %d\n", cfg->access_vlan);
    } else if (cfg->vlan_mode == RS_VLAN_MODE_TRUNK) {
        printf("  Native VLAN: %d\n", cfg->native_vlan);
        printf("  Allowed VLANs (%d): ", cfg->allowed_vlan_count);
        for (int i = 0; i < cfg->allowed_vlan_count; i++) {
            printf("%d%s", cfg->allowed_vlans[i], 
                   i < cfg->allowed_vlan_count - 1 ? "," : "");
        }
        printf("\n");
    } else if (cfg->vlan_mode == RS_VLAN_MODE_HYBRID) {
        printf("  PVID: %d\n", cfg->pvid);
        printf("  Tagged VLANs (%d): ", cfg->tagged_vlan_count);
        for (int i = 0; i < cfg->tagged_vlan_count; i++) {
            printf("%d%s", cfg->tagged_vlans[i],
                   i < cfg->tagged_vlan_count - 1 ? "," : "");
        }
        printf("\n  Untagged VLANs (%d): ", cfg->untagged_vlan_count);
        for (int i = 0; i < cfg->untagged_vlan_count; i++) {
            printf("%d%s", cfg->untagged_vlans[i],
                   i < cfg->untagged_vlan_count - 1 ? "," : "");
        }
        printf("\n");
    }
    
    printf("\nQoS:\n");
    printf("  Default priority: %d\n", cfg->default_prio);
    printf("  Trust DSCP: %s\n", cfg->trust_dscp ? "yes" : "no");
    printf("  Rate limit: %d kbps\n", cfg->rate_limit_kbps);
    
    printf("\nSecurity:\n");
    printf("  Port security: %s\n", cfg->port_security ? "enabled" : "disabled");
    if (cfg->port_security)
        printf("  Max MACs: %d\n", cfg->max_macs);
}

static void usage(const char *prog)
{
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  %s <ifname> show\n", prog);
    fprintf(stderr, "  %s <ifname> set vlan-mode <off|access|trunk|hybrid>\n", prog);
    fprintf(stderr, "  %s <ifname> set access-vlan <vlan_id>\n", prog);
    fprintf(stderr, "  %s <ifname> set native-vlan <vlan_id>\n", prog);
    fprintf(stderr, "  %s <ifname> set pvid <vlan_id>\n", prog);
    fprintf(stderr, "  %s <ifname> set learning <on|off>\n", prog);
    fprintf(stderr, "  %s <ifname> set allowed-vlans <vlan1,vlan2,...>\n", prog);
    fprintf(stderr, "\nExamples:\n");
    fprintf(stderr, "  %s ens34 show\n", prog);
    fprintf(stderr, "  %s ens34 set vlan-mode access\n", prog);
    fprintf(stderr, "  %s ens34 set access-vlan 10\n", prog);
    fprintf(stderr, "  %s ens35 set vlan-mode trunk\n", prog);
    fprintf(stderr, "  %s ens35 set native-vlan 1\n", prog);
    fprintf(stderr, "  %s ens35 set allowed-vlans 10,20,30\n", prog);
}

int main(int argc, char **argv)
{
    rs_log_init("rsportctl", RS_LOG_LEVEL_INFO);

    char map_path[256];
    int map_fd;
    __u32 ifindex;
    struct rs_port_config cfg;
    int ret;
    
    if (argc < 3) {
        usage(argv[0]);
        return 1;
    }
    
    const char *ifname = argv[1];
    const char *cmd = argv[2];
    
    /* Get interface index */
    ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        RS_LOG_ERROR("Interface %s not found", ifname);
        return 1;
    }
    
    /* Open port config map */
    snprintf(map_path, sizeof(map_path), "%s/rs_port_config_map", PIN_PATH);
    map_fd = bpf_obj_get(map_path);
    if (map_fd < 0) {
        RS_LOG_ERROR("Failed to open %s: %s", map_path, strerror(errno));
        RS_LOG_ERROR("Is rSwitch loader running?");
        return 1;
    }
    
    /* Get current config */
    ret = bpf_map_lookup_elem(map_fd, &ifindex, &cfg);
    if (ret < 0) {
        RS_LOG_ERROR("Port %s not configured in rSwitch", ifname);
        close(map_fd);
        return 1;
    }
    
    /* Execute command */
    if (strcmp(cmd, "show") == 0) {
        show_port(&cfg);
    } else if (strcmp(cmd, "set") == 0 && argc >= 5) {
        const char *key = argv[3];
        const char *value = argv[4];
        int modified = 0;
        
        if (strcmp(key, "vlan-mode") == 0) {
            int mode = parse_vlan_mode(value);
            if (mode < 0) {
                RS_LOG_ERROR("Invalid VLAN mode: %s", value);
                close(map_fd);
                return 1;
            }
            cfg.vlan_mode = mode;
            modified = 1;
            printf("Set VLAN mode to %s\n", vlan_mode_str(mode));
        } else if (strcmp(key, "access-vlan") == 0) {
            int vlan = atoi(value);
            if (vlan < 1 || vlan > 4094) {
                RS_LOG_ERROR("Invalid VLAN ID: %d", vlan);
                close(map_fd);
                return 1;
            }
            cfg.access_vlan = vlan;
            cfg.pvid = vlan;  /* Also set PVID */
            modified = 1;
            printf("Set access VLAN to %d\n", vlan);
        } else if (strcmp(key, "native-vlan") == 0) {
            int vlan = atoi(value);
            if (vlan < 1 || vlan > 4094) {
                RS_LOG_ERROR("Invalid VLAN ID: %d", vlan);
                close(map_fd);
                return 1;
            }
            cfg.native_vlan = vlan;
            modified = 1;
            printf("Set native VLAN to %d\n", vlan);
        } else if (strcmp(key, "pvid") == 0) {
            int vlan = atoi(value);
            if (vlan < 1 || vlan > 4094) {
                RS_LOG_ERROR("Invalid VLAN ID: %d", vlan);
                close(map_fd);
                return 1;
            }
            cfg.pvid = vlan;
            modified = 1;
            printf("Set PVID to %d\n", vlan);
        } else if (strcmp(key, "learning") == 0) {
            if (strcasecmp(value, "on") == 0 || strcmp(value, "1") == 0) {
                cfg.learning = 1;
                printf("Enabled MAC learning\n");
            } else {
                cfg.learning = 0;
                printf("Disabled MAC learning\n");
            }
            modified = 1;
        } else if (strcmp(key, "allowed-vlans") == 0) {
            if (parse_vlan_list(value, cfg.allowed_vlans, &cfg.allowed_vlan_count, 128) < 0) {
                close(map_fd);
                return 1;
            }
            modified = 1;
            printf("Set %d allowed VLANs\n", cfg.allowed_vlan_count);
        } else {
            RS_LOG_ERROR("Unknown setting: %s", key);
            close(map_fd);
            usage(argv[0]);
            return 1;
        }
        
        if (modified) {
            ret = bpf_map_update_elem(map_fd, &ifindex, &cfg, BPF_EXIST);
            if (ret < 0) {
                RS_LOG_ERROR("Failed to update port config: %s", strerror(errno));
                close(map_fd);
                return 1;
            }
            printf("Configuration updated successfully\n");
        }
    } else {
        usage(argv[0]);
        close(map_fd);
        return 1;
    }
    
    close(map_fd);
    return 0;
}
