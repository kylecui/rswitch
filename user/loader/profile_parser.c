// SPDX-License-Identifier: GPL-2.0
/* 
 * rSwitch Profile Parser
 * 
 * Simple YAML parser for rSwitch profile files.
 * Supports minimal YAML subset needed for profile configuration:
 * - Key-value pairs (name: value)
 * - Lists (- item)
 * - Comments (# comment)
 * - Nested structures (limited to 2 levels)
 * 
 * Does NOT support:
 * - Complex YAML features (anchors, aliases, multi-line strings)
 * - Deep nesting (>2 levels)
 * - Arbitrary YAML documents
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include "profile_parser.h"

#define MAX_LINE_LEN 1024
#define MAX_MODULES 32
#define MAX_PORTS 64
#define MAX_VLANS 128

/* Trim whitespace from both ends of string */
static char *trim(char *str)
{
    char *end;
    
    /* Trim leading space */
    while (isspace((unsigned char)*str)) str++;
    
    if (*str == 0) return str;
    
    /* Trim trailing space */
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    
    *(end + 1) = '\0';
    return str;
}

/* Remove comments from line */
static void remove_comment(char *line)
{
    char *hash = strchr(line, '#');
    if (hash) *hash = '\0';
}

/* Parse a simple key: value line */
static int parse_key_value(char *line, char *key, char *value, size_t maxlen)
{
    char *colon = strchr(line, ':');
    if (!colon) return -1;
    
    *colon = '\0';
    strncpy(key, trim(line), maxlen - 1);
    key[maxlen - 1] = '\0';
    
    strncpy(value, trim(colon + 1), maxlen - 1);
    value[maxlen - 1] = '\0';
    
    return 0;
}

/* Parse boolean value */
static int parse_bool(const char *value)
{
    if (strcmp(value, "true") == 0 || strcmp(value, "yes") == 0 || strcmp(value, "1") == 0)
        return 1;
    return 0;
}

/* Initialize profile with defaults */
void profile_init(struct rs_profile *profile)
{
    memset(profile, 0, sizeof(*profile));
    
    /* Default settings */
    profile->settings.mac_learning = 0;
    profile->settings.mac_aging_time = 300;
    profile->settings.vlan_enforcement = 0;
    profile->settings.default_vlan = 1;
    profile->settings.unknown_unicast_flood = 1;
    profile->settings.broadcast_flood = 1;
    profile->settings.multicast_flood = 1;
    profile->settings.stats_enabled = 1;
    profile->settings.ringbuf_enabled = 0;
    profile->settings.debug = 0;
    
    profile->ports = NULL;
    profile->port_count = 0;
    profile->vlans = NULL;
    profile->vlan_count = 0;
}

/* Free profile resources */
void profile_free(struct rs_profile *profile)
{
    if (!profile) return;
    
    for (int i = 0; i < profile->ingress_count; i++) {
        free(profile->ingress_modules[i]);
    }
    
    for (int i = 0; i < profile->egress_count; i++) {
        free(profile->egress_modules[i]);
    }
    
    if (profile->ports) {
        free(profile->ports);
    }
    
    if (profile->vlans) {
        free(profile->vlans);
    }
    
    memset(profile, 0, sizeof(*profile));
}

/* Parse ingress/egress module list */
static int parse_module_list(FILE *fp, char ***modules, int *count, const char *section)
{
    char line[MAX_LINE_LEN];
    int module_count = 0;
    char **module_list = NULL;
    
    /* Allocate initial array */
    module_list = calloc(MAX_MODULES, sizeof(char *));
    if (!module_list) {
        return -ENOMEM;
    }
    
    while (fgets(line, sizeof(line), fp)) {
        remove_comment(line);
        char *trimmed = trim(line);
        
        if (strlen(trimmed) == 0) continue;
        
        /* Check if we're entering another section */
        if (strchr(trimmed, ':') && trimmed[0] != '-') {
            /* Put the line back by seeking backwards */
            fseek(fp, -(long)strlen(line) - 1, SEEK_CUR);
            break;
        }
        
        /* Parse list item */
        if (trimmed[0] == '-') {
            char *module_name = trim(trimmed + 1);
            if (strlen(module_name) > 0 && module_count < MAX_MODULES) {
                module_list[module_count] = strdup(module_name);
                if (!module_list[module_count]) {
                    goto error;
                }
                module_count++;
            }
        }
    }
    
    *modules = module_list;
    *count = module_count;
    return 0;
    
error:
    for (int i = 0; i < module_count; i++) {
        free(module_list[i]);
    }
    free(module_list);
    return -ENOMEM;
}

/* Parse settings section */
static int parse_settings(FILE *fp, struct rs_profile_settings *settings)
{
    char line[MAX_LINE_LEN];
    char key[256], value[256];
    
    fprintf(stderr, "DEBUG: Entering parse_settings()\n");
    
    while (fgets(line, sizeof(line), fp)) {
        char line_copy[MAX_LINE_LEN];
        strncpy(line_copy, line, sizeof(line_copy) - 1);
        
        remove_comment(line);
        char *trimmed = trim(line);
        
        if (strlen(trimmed) == 0) continue;
        
        /* Check if we're entering another section (not indented) */
        /* Need to check the original line BEFORE trim() removed leading spaces */
        if (line_copy[0] != ' ' && line_copy[0] != '\t' && strchr(trimmed, ':')) {
            fprintf(stderr, "DEBUG: Exiting parse_settings() - found non-indented key: %s\n", trimmed);
            fseek(fp, -(long)strlen(line_copy) - 1, SEEK_CUR);
            break;
        }
        
        if (parse_key_value(trimmed, key, value, sizeof(key)) == 0) {
            fprintf(stderr, "DEBUG: parse_settings() - key='%s', value='%s'\n", key, value);
            if (strcmp(key, "mac_learning") == 0) {
                settings->mac_learning = parse_bool(value);
                fprintf(stderr, "DEBUG: Set mac_learning=%d\n", settings->mac_learning);
            } else if (strcmp(key, "mac_aging_time") == 0) {
                settings->mac_aging_time = atoi(value);
            } else if (strcmp(key, "vlan_enforcement") == 0) {
                settings->vlan_enforcement = parse_bool(value);
                fprintf(stderr, "DEBUG: Set vlan_enforcement=%d\n", settings->vlan_enforcement);
            } else if (strcmp(key, "default_vlan") == 0) {
                settings->default_vlan = atoi(value);
            } else if (strcmp(key, "unknown_unicast_flood") == 0) {
                settings->unknown_unicast_flood = parse_bool(value);
            } else if (strcmp(key, "broadcast_flood") == 0) {
                settings->broadcast_flood = parse_bool(value);
            } else if (strcmp(key, "multicast_flood") == 0) {
                settings->multicast_flood = parse_bool(value);
            } else if (strcmp(key, "stats_enabled") == 0) {
                settings->stats_enabled = parse_bool(value);
            } else if (strcmp(key, "ringbuf_enabled") == 0) {
                settings->ringbuf_enabled = parse_bool(value);
            } else if (strcmp(key, "debug") == 0) {
                settings->debug = parse_bool(value);
            }
            /* Silently ignore unknown settings for forward compatibility */
        }
    }
    
    return 0;
}

/* Parse comma-separated VLAN list (e.g., "1,10,20,30") */
static int parse_vlan_list(const char *value, uint16_t *vlans, int max_vlans)
{
    char *str = strdup(value);
    char *token;
    char *saveptr;
    int count = 0;
    
    if (!str) return 0;
    
    token = strtok_r(str, ",", &saveptr);
    while (token && count < max_vlans) {
        vlans[count++] = (uint16_t)atoi(trim(token));
        token = strtok_r(NULL, ",", &saveptr);
    }
    
    free(str);
    return count;
}

/* Parse a single port configuration */
static int parse_port_item(FILE *fp, struct rs_profile_port *port)
{
    char line[MAX_LINE_LEN];
    char key[256], value[256];
    
    memset(port, 0, sizeof(*port));
    port->enabled = 1;
    port->management = 1;  // Default: managed
    port->mac_learning = 1;
    
    while (fgets(line, sizeof(line), fp)) {
        char line_copy[MAX_LINE_LEN];
        strncpy(line_copy, line, sizeof(line_copy) - 1);
        
        remove_comment(line);
        char *trimmed = trim(line);
        
        if (strlen(trimmed) == 0) continue;
        
        /* Check if we're exiting this port (another port item or section) */
        if (trimmed[0] == '-' || (line_copy[0] != ' ' && line_copy[0] != '\t' && strchr(trimmed, ':'))) {
            fseek(fp, -(long)strlen(line_copy) - 1, SEEK_CUR);
            break;
        }
        
        if (parse_key_value(trimmed, key, value, sizeof(key)) == 0) {
            if (strcmp(key, "interface") == 0) {
                strncpy(port->interface, value, sizeof(port->interface) - 1);
            } else if (strcmp(key, "enabled") == 0) {
                port->enabled = parse_bool(value);
            } else if (strcmp(key, "management") == 0) {
                if (strcmp(value, "managed") == 0) port->management = 1;
                else if (strcmp(value, "unmanaged") == 0) port->management = 0;
            } else if (strcmp(key, "vlan_mode") == 0) {
                if (strcmp(value, "off") == 0) port->vlan_mode = 0;
                else if (strcmp(value, "access") == 0) port->vlan_mode = 1;
                else if (strcmp(value, "trunk") == 0) port->vlan_mode = 2;
                else if (strcmp(value, "hybrid") == 0) port->vlan_mode = 3;
            } else if (strcmp(key, "access_vlan") == 0) {
                port->access_vlan = atoi(value);
            } else if (strcmp(key, "native_vlan") == 0) {
                port->native_vlan = atoi(value);
            } else if (strcmp(key, "pvid") == 0) {
                port->pvid = atoi(value);
            } else if (strcmp(key, "allowed_vlans") == 0) {
                /* Handle both array [1,10,20] and list format */
                char *val = value;
                if (val[0] == '[') val++;  /* Skip leading [ */
                char *end = strchr(val, ']');
                if (end) *end = '\0';  /* Remove trailing ] */
                port->allowed_vlan_count = parse_vlan_list(val, port->allowed_vlans, 128);
            } else if (strcmp(key, "mac_learning") == 0) {
                port->mac_learning = parse_bool(value);
            } else if (strcmp(key, "default_priority") == 0) {
                port->default_priority = atoi(value);
            }
        }
    }
    
    return 0;
}

/* Parse ports section */
static int parse_ports(FILE *fp, struct rs_profile *profile)
{
    char line[MAX_LINE_LEN];
    struct rs_profile_port *ports = NULL;
    int port_count = 0;
    
    ports = calloc(MAX_PORTS, sizeof(struct rs_profile_port));
    if (!ports) return -ENOMEM;
    
    while (fgets(line, sizeof(line), fp)) {
        char line_copy[MAX_LINE_LEN];
        strncpy(line_copy, line, sizeof(line_copy) - 1);
        
        remove_comment(line);
        char *trimmed = trim(line);
        
        if (strlen(trimmed) == 0) continue;
        
        /* Check if we're entering another section */
        if (line_copy[0] != ' ' && line_copy[0] != '\t' && strchr(trimmed, ':')) {
            fseek(fp, -(long)strlen(line_copy) - 1, SEEK_CUR);
            break;
        }
        
        /* Parse port list item */
        if (trimmed[0] == '-' && port_count < MAX_PORTS) {
            if (parse_port_item(fp, &ports[port_count]) == 0) {
                if (strlen(ports[port_count].interface) > 0) {
                    port_count++;
                }
            }
        }
    }
    
    profile->ports = ports;
    profile->port_count = port_count;
    return 0;
}

/* Parse interface list (e.g., [ens34, ens35] or [ens34]) */
static int parse_interface_list(const char *value, char ifaces[][32], int max_ifaces)
{
    char *str = strdup(value);
    char *token;
    char *saveptr;
    int count = 0;
    
    if (!str) return 0;
    
    /* Remove brackets */
    char *val = str;
    if (val[0] == '[') val++;
    char *end = strchr(val, ']');
    if (end) *end = '\0';
    
    token = strtok_r(val, ",", &saveptr);
    while (token && count < max_ifaces) {
        strncpy(ifaces[count], trim(token), 31);
        ifaces[count][31] = '\0';
        count++;
        token = strtok_r(NULL, ",", &saveptr);
    }
    
    free(str);
    return count;
}

/* Parse a single VLAN configuration */
static int parse_vlan_item(FILE *fp, struct rs_profile_vlan *vlan)
{
    char line[MAX_LINE_LEN];
    char key[256], value[256];
    
    memset(vlan, 0, sizeof(*vlan));
    
    while (fgets(line, sizeof(line), fp)) {
        char line_copy[MAX_LINE_LEN];
        strncpy(line_copy, line, sizeof(line_copy) - 1);
        
        remove_comment(line);
        char *trimmed = trim(line);
        
        if (strlen(trimmed) == 0) continue;
        
        /* Check if we're exiting this VLAN (another VLAN item or section) */
        if (trimmed[0] == '-' || (line_copy[0] != ' ' && line_copy[0] != '\t' && strchr(trimmed, ':'))) {
            fseek(fp, -(long)strlen(line_copy) - 1, SEEK_CUR);
            break;
        }
        
        if (parse_key_value(trimmed, key, value, sizeof(key)) == 0) {
            if (strcmp(key, "vlan_id") == 0) {
                vlan->vlan_id = (uint16_t)atoi(value);
            } else if (strcmp(key, "name") == 0) {
                /* Remove quotes if present */
                char *val = value;
                if (val[0] == '"') val++;
                char *end = strchr(val, '"');
                if (end) *end = '\0';
                strncpy(vlan->name, val, sizeof(vlan->name) - 1);
            } else if (strcmp(key, "tagged_ports") == 0) {
                vlan->tagged_count = parse_interface_list(value, vlan->tagged_ports, 16);
            } else if (strcmp(key, "untagged_ports") == 0) {
                vlan->untagged_count = parse_interface_list(value, vlan->untagged_ports, 16);
            }
        }
    }
    
    return 0;
}

/* Parse vlans section */
static int parse_vlans(FILE *fp, struct rs_profile *profile)
{
    char line[MAX_LINE_LEN];
    struct rs_profile_vlan *vlans = NULL;
    int vlan_count = 0;
    
    vlans = calloc(MAX_VLANS, sizeof(struct rs_profile_vlan));
    if (!vlans) return -ENOMEM;
    
    while (fgets(line, sizeof(line), fp)) {
        char line_copy[MAX_LINE_LEN];
        strncpy(line_copy, line, sizeof(line_copy) - 1);
        
        remove_comment(line);
        char *trimmed = trim(line);
        
        if (strlen(trimmed) == 0) continue;
        
        /* Check if we're entering another section */
        if (line_copy[0] != ' ' && line_copy[0] != '\t' && strchr(trimmed, ':')) {
            fseek(fp, -(long)strlen(line_copy) - 1, SEEK_CUR);
            break;
        }
        
        /* Parse VLAN list item */
        if (trimmed[0] == '-' && vlan_count < MAX_VLANS) {
            if (parse_vlan_item(fp, &vlans[vlan_count]) == 0) {
                if (vlans[vlan_count].vlan_id > 0) {
                    vlan_count++;
                }
            }
        }
    }
    
    profile->vlans = vlans;
    profile->vlan_count = vlan_count;
    return 0;
}

/* Load and parse profile from file */
int profile_load(const char *filename, struct rs_profile *profile)
{
    FILE *fp = NULL;
    char line[MAX_LINE_LEN];
    char key[256], value[256];
    int ret = 0;
    
    if (!filename || !profile) {
        return -EINVAL;
    }
    
    profile_init(profile);
    
    fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "Failed to open profile: %s\n", filename);
        return -errno;
    }
    
    while (fgets(line, sizeof(line), fp)) {
        remove_comment(line);
        char *trimmed = trim(line);
        
        if (strlen(trimmed) == 0) continue;
        
        if (parse_key_value(trimmed, key, value, sizeof(key)) != 0) {
            continue;
        }
        
        /* Top-level keys */
        if (strcmp(key, "name") == 0) {
            strncpy(profile->name, value, sizeof(profile->name) - 1);
        } else if (strcmp(key, "description") == 0) {
            strncpy(profile->description, value, sizeof(profile->description) - 1);
        } else if (strcmp(key, "version") == 0) {
            strncpy(profile->version, value, sizeof(profile->version) - 1);
        } else if (strcmp(key, "ingress") == 0) {
            ret = parse_module_list(fp, &profile->ingress_modules, 
                                   &profile->ingress_count, "ingress");
            if (ret < 0) goto error;
        } else if (strcmp(key, "egress") == 0) {
            ret = parse_module_list(fp, &profile->egress_modules,
                                   &profile->egress_count, "egress");
            if (ret < 0) goto error;
        } else if (strcmp(key, "settings") == 0) {
            ret = parse_settings(fp, &profile->settings);
            if (ret < 0) goto error;
        } else if (strcmp(key, "ports") == 0) {
            ret = parse_ports(fp, profile);
            if (ret < 0) goto error;
        } else if (strcmp(key, "vlans") == 0) {
            ret = parse_vlans(fp, profile);
            if (ret < 0) goto error;
        }
    }
    
    fclose(fp);
    return 0;
    
error:
    if (fp) fclose(fp);
    profile_free(profile);
    return ret;
}

/* Print profile information */
void profile_print(const struct rs_profile *profile)
{
    if (!profile) return;
    
    printf("Profile: %s (%s)\n", profile->name, profile->version);
    printf("Description: %s\n", profile->description);
    
    printf("\nIngress pipeline (%d modules):\n", profile->ingress_count);
    for (int i = 0; i < profile->ingress_count; i++) {
        printf("  - %s\n", profile->ingress_modules[i]);
    }
    
    printf("\nEgress pipeline (%d modules):\n", profile->egress_count);
    for (int i = 0; i < profile->egress_count; i++) {
        printf("  - %s\n", profile->egress_modules[i]);
    }
    
    printf("\nSettings:\n");
    printf("  MAC learning: %s\n", profile->settings.mac_learning ? "enabled" : "disabled");
    printf("  MAC aging time: %d seconds\n", profile->settings.mac_aging_time);
    printf("  VLAN enforcement: %s\n", profile->settings.vlan_enforcement ? "enabled" : "disabled");
    printf("  Default VLAN: %d\n", profile->settings.default_vlan);
    printf("  Unknown unicast flood: %s\n", profile->settings.unknown_unicast_flood ? "yes" : "no");
    printf("  Broadcast flood: %s\n", profile->settings.broadcast_flood ? "yes" : "no");
    printf("  Multicast flood: %s\n", profile->settings.multicast_flood ? "yes" : "no");
    printf("  Statistics: %s\n", profile->settings.stats_enabled ? "enabled" : "disabled");
    printf("  Ringbuf events: %s\n", profile->settings.ringbuf_enabled ? "enabled" : "disabled");
    printf("  Debug: %s\n", profile->settings.debug ? "enabled" : "disabled");
    
    if (profile->port_count > 0) {
        printf("\nPort Configurations (%d ports):\n", profile->port_count);
        for (int i = 0; i < profile->port_count; i++) {
            struct rs_profile_port *p = &profile->ports[i];
            const char *mode_str[] = {"off", "access", "trunk", "hybrid"};
            printf("  %s: mode=%s", p->interface, 
                   p->vlan_mode < 4 ? mode_str[p->vlan_mode] : "unknown");
            if (p->vlan_mode == 1) printf(", access_vlan=%d", p->access_vlan);
            if (p->vlan_mode == 2) printf(", native=%d, allowed=%d VLANs", 
                                          p->native_vlan, p->allowed_vlan_count);
            printf("\n");
        }
    }
    
    if (profile->vlan_count > 0) {
        printf("\nVLAN Configurations (%d VLANs):\n", profile->vlan_count);
        for (int i = 0; i < profile->vlan_count; i++) {
            struct rs_profile_vlan *v = &profile->vlans[i];
            printf("  VLAN %d (%s): tagged=%d, untagged=%d\n",
                   v->vlan_id, v->name, v->tagged_count, v->untagged_count);
        }
    }
}
