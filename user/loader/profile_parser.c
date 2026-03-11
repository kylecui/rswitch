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
#include <limits.h>

#include "profile_parser.h"
#include "rs_log.h"

#define MAX_LINE_LEN 1024
#define MAX_MODULES 32
#define MAX_PORTS 64
#define MAX_VLANS 128
#define MAX_INHERIT_DEPTH 3

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

static int count_indent(const char *line)
{
    int indent = 0;

    while (*line == ' ' || *line == '\t') {
        indent++;
        line++;
    }

    return indent;
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
    
    /* Default VOQd settings (disabled by default) */
    profile->voqd.enabled = 0;
    profile->voqd.mode = 0;  // BYPASS
    profile->voqd.num_ports = 0;
    profile->voqd.prio_mask = 0x0C;  // HIGH + CRITICAL by default
    profile->voqd.enable_afxdp = 0;
    profile->voqd.zero_copy = 0;
    profile->voqd.rx_ring_size = 2048;
    profile->voqd.tx_ring_size = 2048;
    profile->voqd.frame_size = 2048;
    profile->voqd.batch_size = 256;
    profile->voqd.poll_timeout_ms = 100;
    profile->voqd.busy_poll = 0;
    profile->voqd.cpu_affinity = -1;  // No affinity
    profile->voqd.enable_scheduler = 1;
    profile->voqd.use_veth_egress = 1;  // Default enabled when VOQd is on
    strcpy(profile->voqd.veth_in_ifname, "veth_voq_in");
    
    profile->ports = NULL;
    profile->port_count = 0;
    profile->vlans = NULL;
    profile->vlan_count = 0;
}

/* Free profile resources */
void profile_free(struct rs_profile *profile)
{
    if (!profile) return;

    free(profile->ingress_modules);
    free(profile->egress_modules);
    
    if (profile->ports) {
        free(profile->ports);
    }
    
    if (profile->vlans) {
        free(profile->vlans);
    }
    
    memset(profile, 0, sizeof(*profile));
}

static void profile_defaults(struct rs_profile *defaults)
{
    profile_init(defaults);
}

static void profile_merge(struct rs_profile *child, const struct rs_profile *parent)
{
    struct rs_profile defaults;

    if (!child || !parent)
        return;

    if (child->name[0] == '\0')
        strncpy(child->name, parent->name, sizeof(child->name) - 1);

    if (child->description[0] == '\0')
        strncpy(child->description, parent->description, sizeof(child->description) - 1);

    if (child->version[0] == '\0')
        strncpy(child->version, parent->version, sizeof(child->version) - 1);

    if (child->ingress_count == 0 && parent->ingress_count > 0) {
        child->ingress_modules = malloc(parent->ingress_count * sizeof(struct rs_profile_module_entry));
        if (child->ingress_modules) {
            memcpy(child->ingress_modules,
                   parent->ingress_modules,
                   parent->ingress_count * sizeof(struct rs_profile_module_entry));
            child->ingress_count = parent->ingress_count;
        } else {
            RS_LOG_ERROR("Failed to allocate inherited ingress modules");
        }
    }

    if (child->egress_count == 0 && parent->egress_count > 0) {
        child->egress_modules = malloc(parent->egress_count * sizeof(struct rs_profile_module_entry));
        if (child->egress_modules) {
            memcpy(child->egress_modules,
                   parent->egress_modules,
                   parent->egress_count * sizeof(struct rs_profile_module_entry));
            child->egress_count = parent->egress_count;
        } else {
            RS_LOG_ERROR("Failed to allocate inherited egress modules");
        }
    }

    profile_defaults(&defaults);

    if (child->settings.mac_learning == defaults.settings.mac_learning)
        child->settings.mac_learning = parent->settings.mac_learning;
    if (child->settings.mac_aging_time == defaults.settings.mac_aging_time)
        child->settings.mac_aging_time = parent->settings.mac_aging_time;
    if (child->settings.vlan_enforcement == defaults.settings.vlan_enforcement)
        child->settings.vlan_enforcement = parent->settings.vlan_enforcement;
    if (child->settings.default_vlan == defaults.settings.default_vlan)
        child->settings.default_vlan = parent->settings.default_vlan;
    if (child->settings.unknown_unicast_flood == defaults.settings.unknown_unicast_flood)
        child->settings.unknown_unicast_flood = parent->settings.unknown_unicast_flood;
    if (child->settings.broadcast_flood == defaults.settings.broadcast_flood)
        child->settings.broadcast_flood = parent->settings.broadcast_flood;
    if (child->settings.multicast_flood == defaults.settings.multicast_flood)
        child->settings.multicast_flood = parent->settings.multicast_flood;
    if (child->settings.stats_enabled == defaults.settings.stats_enabled)
        child->settings.stats_enabled = parent->settings.stats_enabled;
    if (child->settings.ringbuf_enabled == defaults.settings.ringbuf_enabled)
        child->settings.ringbuf_enabled = parent->settings.ringbuf_enabled;
    if (child->settings.debug == defaults.settings.debug)
        child->settings.debug = parent->settings.debug;

    if (child->voqd.enabled == defaults.voqd.enabled)
        child->voqd.enabled = parent->voqd.enabled;
    if (child->voqd.mode == defaults.voqd.mode)
        child->voqd.mode = parent->voqd.mode;
    if (child->voqd.num_ports == defaults.voqd.num_ports)
        child->voqd.num_ports = parent->voqd.num_ports;
    if (child->voqd.prio_mask == defaults.voqd.prio_mask)
        child->voqd.prio_mask = parent->voqd.prio_mask;
    if (child->voqd.enable_afxdp == defaults.voqd.enable_afxdp)
        child->voqd.enable_afxdp = parent->voqd.enable_afxdp;
    if (child->voqd.zero_copy == defaults.voqd.zero_copy)
        child->voqd.zero_copy = parent->voqd.zero_copy;
    if (child->voqd.rx_ring_size == defaults.voqd.rx_ring_size)
        child->voqd.rx_ring_size = parent->voqd.rx_ring_size;
    if (child->voqd.tx_ring_size == defaults.voqd.tx_ring_size)
        child->voqd.tx_ring_size = parent->voqd.tx_ring_size;
    if (child->voqd.frame_size == defaults.voqd.frame_size)
        child->voqd.frame_size = parent->voqd.frame_size;
    if (child->voqd.batch_size == defaults.voqd.batch_size)
        child->voqd.batch_size = parent->voqd.batch_size;
    if (child->voqd.poll_timeout_ms == defaults.voqd.poll_timeout_ms)
        child->voqd.poll_timeout_ms = parent->voqd.poll_timeout_ms;
    if (child->voqd.busy_poll == defaults.voqd.busy_poll)
        child->voqd.busy_poll = parent->voqd.busy_poll;
    if (child->voqd.cpu_affinity == defaults.voqd.cpu_affinity)
        child->voqd.cpu_affinity = parent->voqd.cpu_affinity;
    if (child->voqd.enable_scheduler == defaults.voqd.enable_scheduler)
        child->voqd.enable_scheduler = parent->voqd.enable_scheduler;
    if (child->voqd.use_veth_egress == defaults.voqd.use_veth_egress)
        child->voqd.use_veth_egress = parent->voqd.use_veth_egress;
    if (strcmp(child->voqd.veth_in_ifname, defaults.voqd.veth_in_ifname) == 0)
        strncpy(child->voqd.veth_in_ifname, parent->voqd.veth_in_ifname,
                sizeof(child->voqd.veth_in_ifname) - 1);

    if (child->port_count == 0 && parent->port_count > 0) {
        child->ports = malloc(parent->port_count * sizeof(struct rs_profile_port));
        if (child->ports) {
            memcpy(child->ports,
                   parent->ports,
                   parent->port_count * sizeof(struct rs_profile_port));
            child->port_count = parent->port_count;
        } else {
            RS_LOG_ERROR("Failed to allocate inherited port list");
        }
    }

    if (child->vlan_count == 0 && parent->vlan_count > 0) {
        child->vlans = malloc(parent->vlan_count * sizeof(struct rs_profile_vlan));
        if (child->vlans) {
            memcpy(child->vlans,
                   parent->vlans,
                   parent->vlan_count * sizeof(struct rs_profile_vlan));
            child->vlan_count = parent->vlan_count;
        } else {
            RS_LOG_ERROR("Failed to allocate inherited VLAN list");
        }
    }
}

static int resolve_parent_path(const char *child_filename,
                               const char *extends_name,
                               char *parent_path,
                               size_t parent_path_len)
{
    const char *slash;

    if (!child_filename || !extends_name || !parent_path)
        return -EINVAL;

    if (extends_name[0] == '/') {
        int n = snprintf(parent_path, parent_path_len, "%s", extends_name);
        return (n < 0 || (size_t)n >= parent_path_len) ? -ENAMETOOLONG : 0;
    }

    slash = strrchr(child_filename, '/');
    if (!slash) {
        int n = snprintf(parent_path, parent_path_len, "%s", extends_name);
        return (n < 0 || (size_t)n >= parent_path_len) ? -ENAMETOOLONG : 0;
    }

    {
        size_t dir_len = (size_t)(slash - child_filename);
        int n;

        if (dir_len + 1 >= parent_path_len)
            return -ENAMETOOLONG;

        memcpy(parent_path, child_filename, dir_len);
        parent_path[dir_len] = '\0';

        n = snprintf(parent_path + dir_len,
                     parent_path_len - dir_len,
                     "/%s",
                     extends_name);
        return (n < 0 || (size_t)n >= (parent_path_len - dir_len)) ? -ENAMETOOLONG : 0;
    }
}

static int profile_load_recursive(const char *filename, struct rs_profile *profile, int depth)
{
    int ret;

    if (depth > MAX_INHERIT_DEPTH) {
        RS_LOG_ERROR("Profile inheritance depth exceeded (%d): %s", MAX_INHERIT_DEPTH, filename);
        return -ELOOP;
    }

    ret = profile_load(filename, profile);
    if (ret < 0)
        return ret;

    if (profile->extends[0] == '\0')
        return 0;

    {
        char parent_path[PATH_MAX];
        struct rs_profile parent;

        ret = resolve_parent_path(filename, profile->extends, parent_path, sizeof(parent_path));
        if (ret < 0) {
            RS_LOG_ERROR("Failed to resolve parent path '%s' from '%s'", profile->extends, filename);
            return ret;
        }

        profile_init(&parent);
        ret = profile_load_recursive(parent_path, &parent, depth + 1);
        if (ret < 0) {
            profile_free(&parent);
            return ret;
        }

        profile_merge(profile, &parent);
        profile_free(&parent);
    }

    return 0;
}

int profile_load_with_inheritance(const char *filename, struct rs_profile *profile)
{
    return profile_load_recursive(filename, profile, 0);
}

/* Parse ingress/egress module list */
static int parse_module_list(FILE *fp, struct rs_profile_module_entry **modules,
                             int *count, const char *section)
{
    char line[MAX_LINE_LEN];
    int module_count = 0;
    struct rs_profile_module_entry *module_list = NULL;

    (void)section;

    /* Allocate initial array */
    module_list = calloc(MAX_MODULES, sizeof(struct rs_profile_module_entry));
    if (!module_list) {
        return -ENOMEM;
    }

    while (fgets(line, sizeof(line), fp)) {
        size_t original_len = strlen(line);
        char line_copy[MAX_LINE_LEN];
        char key[256], value[256];

        strncpy(line_copy, line, sizeof(line_copy) - 1);
        line_copy[sizeof(line_copy) - 1] = '\0';

        remove_comment(line);
        char *trimmed = trim(line);

        if (strlen(trimmed) == 0) continue;

        /* Check if we're entering another section */
        if (line_copy[0] != ' ' && line_copy[0] != '\t' && strchr(trimmed, ':')) {
            fseek(fp, -(long)original_len, SEEK_CUR);
            break;
        }

        /* Parse list item */
        if (trimmed[0] == '-' && module_count < MAX_MODULES) {
            char *list_item = trim(trimmed + 1);
            struct rs_profile_module_entry entry;

            memset(&entry, 0, sizeof(entry));
            entry.stage_override = -1;

            if (strlen(list_item) == 0) {
                continue;
            }

            if (parse_key_value(list_item, key, value, sizeof(key)) == 0) {
                if (strcmp(key, "name") != 0) {
                    continue;
                }

                strncpy(entry.name, value, sizeof(entry.name) - 1);

                while (fgets(line, sizeof(line), fp)) {
                    size_t child_len = strlen(line);
                    char child_copy[MAX_LINE_LEN];
                    char child_key[256], child_value[256];
                    char *first_non_ws;
                    int child_indent;

                    strncpy(child_copy, line, sizeof(child_copy) - 1);
                    child_copy[sizeof(child_copy) - 1] = '\0';

                    remove_comment(line);
                    char *child_trimmed = trim(line);

                    if (strlen(child_trimmed) == 0)
                        continue;

                    first_non_ws = child_copy;
                    while (*first_non_ws == ' ' || *first_non_ws == '\t')
                        first_non_ws++;

                    child_indent = count_indent(child_copy);

                    if (child_copy[0] != ' ' && child_copy[0] != '\t') {
                        fseek(fp, -(long)child_len, SEEK_CUR);
                        break;
                    }

                    if (*first_non_ws == '-') {
                        fseek(fp, -(long)child_len, SEEK_CUR);
                        break;
                    }

                    if (parse_key_value(child_trimmed, child_key, child_value,
                                        sizeof(child_key)) != 0) {
                        continue;
                    }

                    if (strcmp(child_key, "stage") == 0) {
                        entry.stage_override = atoi(child_value);
                    } else if (strcmp(child_key, "optional") == 0) {
                        entry.optional = parse_bool(child_value);
                    } else if (strcmp(child_key, "condition") == 0) {
                        strncpy(entry.condition, child_value, sizeof(entry.condition) - 1);
                    } else if (strcmp(child_key, "name") == 0) {
                        strncpy(entry.name, child_value, sizeof(entry.name) - 1);
                    } else if (strcmp(child_key, "config") == 0) {
                        while (fgets(line, sizeof(line), fp)) {
                            size_t cfg_len = strlen(line);
                            char cfg_copy[MAX_LINE_LEN];
                            char cfg_key[256], cfg_value[256];
                            char *cfg_first_non_ws;
                            int cfg_indent;

                            strncpy(cfg_copy, line, sizeof(cfg_copy) - 1);
                            cfg_copy[sizeof(cfg_copy) - 1] = '\0';

                            remove_comment(line);
                            char *cfg_trimmed = trim(line);

                            if (strlen(cfg_trimmed) == 0)
                                continue;

                            cfg_first_non_ws = cfg_copy;
                            while (*cfg_first_non_ws == ' ' || *cfg_first_non_ws == '\t')
                                cfg_first_non_ws++;

                            if (cfg_copy[0] != ' ' && cfg_copy[0] != '\t') {
                                fseek(fp, -(long)cfg_len, SEEK_CUR);
                                break;
                            }

                            if (*cfg_first_non_ws == '-') {
                                fseek(fp, -(long)cfg_len, SEEK_CUR);
                                break;
                            }

                            cfg_indent = count_indent(cfg_copy);
                            if (cfg_indent <= child_indent) {
                                fseek(fp, -(long)cfg_len, SEEK_CUR);
                                break;
                            }

                            if (parse_key_value(cfg_trimmed, cfg_key, cfg_value,
                                                sizeof(cfg_key)) != 0) {
                                continue;
                            }

                            if (entry.config_count >= RS_MAX_MODULE_CONFIG_PARAMS) {
                                continue;
                            }

                            strncpy(entry.config[entry.config_count].key,
                                    cfg_key,
                                    sizeof(entry.config[entry.config_count].key) - 1);
                            strncpy(entry.config[entry.config_count].value,
                                    cfg_value,
                                    sizeof(entry.config[entry.config_count].value) - 1);
                            entry.config_count++;
                        }
                    }
                }
            } else {
                strncpy(entry.name, list_item, sizeof(entry.name) - 1);
            }

            if (entry.name[0] != '\0') {
                module_list[module_count] = entry;
                module_count++;
            }
        }
    }

    *modules = module_list;
    *count = module_count;
    return 0;
}

/* Parse settings section */
static int parse_settings(FILE *fp, struct rs_profile_settings *settings)
{
    char line[MAX_LINE_LEN];
    char key[256], value[256];
    
    while (fgets(line, sizeof(line), fp)) {
        char line_copy[MAX_LINE_LEN];
        strncpy(line_copy, line, sizeof(line_copy) - 1);
        
        remove_comment(line);
        char *trimmed = trim(line);
        
        if (strlen(trimmed) == 0) continue;
        
        /* Check if we're entering another section (not indented) */
        /* Need to check the original line BEFORE trim() removed leading spaces */
        if (line_copy[0] != ' ' && line_copy[0] != '\t' && strchr(trimmed, ':')) {
            fseek(fp, -(long)strlen(line_copy), SEEK_CUR);
            break;
        }
        
        if (parse_key_value(trimmed, key, value, sizeof(key)) == 0) {
            if (strcmp(key, "mac_learning") == 0) {
                settings->mac_learning = parse_bool(value);
            } else if (strcmp(key, "mac_aging_time") == 0) {
                settings->mac_aging_time = atoi(value);
            } else if (strcmp(key, "vlan_enforcement") == 0) {
                settings->vlan_enforcement = parse_bool(value);
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
    
    /* Remove brackets if present: "[1, 10, 20]" -> "1, 10, 20" */
    char *start = str;
    char *end = str + strlen(str) - 1;
    while (*start == '[' || *start == ' ') start++;
    while (end > start && (*end == ']' || *end == ' ' || *end == '\n')) *end-- = '\0';
    
    token = strtok_r(start, ",", &saveptr);
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
    
    /* Save interface if already set, then initialize */
    char saved_interface[32];
    strncpy(saved_interface, port->interface, sizeof(saved_interface) - 1);
    saved_interface[31] = '\0';
    
    memset(port, 0, sizeof(*port));
    
    /* Restore interface */
    if (strlen(saved_interface) > 0) {
        strncpy(port->interface, saved_interface, sizeof(port->interface) - 1);
    }
    
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
            fseek(fp, -(long)strlen(line_copy), SEEK_CUR);
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
            fseek(fp, -(long)strlen(line_copy), SEEK_CUR);
            break;
        }
        
        /* Parse port list item */
        if (trimmed[0] == '-' && port_count < MAX_PORTS) {
            
            /* Initialize port structure with defaults */
            memset(&ports[port_count], 0, sizeof(struct rs_profile_port));
            ports[port_count].enabled = 1;
            ports[port_count].management = 1;
            ports[port_count].mac_learning = 1;
            
            /* Check if this line has content after '-' (e.g., "- interface: ens34") */
            char *content_after_dash = trim(trimmed + 1);
            char first_key[256], first_value[256];
            
            /* If there's a key-value on the same line as '-', parse it */
            if (strlen(content_after_dash) > 0 && parse_key_value(content_after_dash, first_key, first_value, sizeof(first_key)) == 0) {
                /* Pre-populate the interface field */
                if (strcmp(first_key, "interface") == 0) {
                    strncpy(ports[port_count].interface, first_value, sizeof(ports[port_count].interface) - 1);
                }
            }
            
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
    
    /* Save pre-populated vlan_id (if set by parse_vlans inline parsing) */
    uint16_t saved_vlan_id = vlan->vlan_id;
    
    memset(vlan, 0, sizeof(*vlan));
    
    /* Restore saved vlan_id */
    if (saved_vlan_id > 0) {
        vlan->vlan_id = saved_vlan_id;
    }
    
    while (fgets(line, sizeof(line), fp)) {
        char line_copy[MAX_LINE_LEN];
        strncpy(line_copy, line, sizeof(line_copy) - 1);
        
        remove_comment(line);
        char *trimmed = trim(line);
        
        if (strlen(trimmed) == 0) continue;
        
        /* Check if we're exiting this VLAN (another VLAN item or section) */
        if (trimmed[0] == '-' || (line_copy[0] != ' ' && line_copy[0] != '\t' && strchr(trimmed, ':'))) {
            fseek(fp, -(long)strlen(line_copy), SEEK_CUR);
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

/* Parse voqd_config section */
static int parse_voqd_config(FILE *fp, struct rs_profile_voqd *voqd)
{
    char line[MAX_LINE_LEN];
    char key[256], value[256];
    
    while (fgets(line, sizeof(line), fp)) {
        char line_copy[MAX_LINE_LEN];
        strncpy(line_copy, line, sizeof(line_copy) - 1);
        line_copy[sizeof(line_copy) - 1] = '\0';
        
        remove_comment(line);
        char *trimmed = trim(line);
        
        if (strlen(trimmed) == 0) continue;
        
        /* Check if we're entering another section (non-indented line with ':') */
        if (line_copy[0] != ' ' && line_copy[0] != '\t' && strchr(trimmed, ':')) {
            /* Rewind to start of this line */
            fseek(fp, -(long)strlen(line_copy), SEEK_CUR);
            break;
        }
        
        if (parse_key_value(trimmed, key, value, sizeof(key)) != 0) {
            continue;
        }
        
        /* Parse VOQd configuration fields */
        if (strcmp(key, "enable") == 0 || strcmp(key, "enabled") == 0 || 
            strcmp(key, "enable_afxdp") == 0) {
            voqd->enabled = parse_bool(value);
            voqd->enable_afxdp = voqd->enabled;  // enable_afxdp implies enabled
        } else if (strcmp(key, "mode") == 0) {
            if (strcmp(value, "bypass") == 0) voqd->mode = 0;
            else if (strcmp(value, "shadow") == 0) voqd->mode = 1;
            else if (strcmp(value, "active") == 0) voqd->mode = 2;
            else voqd->mode = atoi(value);
        } else if (strcmp(key, "num_ports") == 0) {
            voqd->num_ports = atoi(value);
        } else if (strcmp(key, "prio_mask") == 0) {
            voqd->prio_mask = (uint32_t)strtoul(value, NULL, 0);
        } else if (strcmp(key, "zero_copy") == 0) {
            voqd->zero_copy = parse_bool(value);
        } else if (strcmp(key, "rx_ring_size") == 0) {
            voqd->rx_ring_size = atoi(value);
        } else if (strcmp(key, "tx_ring_size") == 0) {
            voqd->tx_ring_size = atoi(value);
        } else if (strcmp(key, "frame_size") == 0) {
            voqd->frame_size = atoi(value);
        } else if (strcmp(key, "batch_size") == 0) {
            voqd->batch_size = atoi(value);
        } else if (strcmp(key, "poll_timeout_ms") == 0) {
            voqd->poll_timeout_ms = atoi(value);
        } else if (strcmp(key, "busy_poll") == 0) {
            voqd->busy_poll = parse_bool(value);
        } else if (strcmp(key, "cpu_affinity") == 0) {
            voqd->cpu_affinity = atoi(value);
        } else if (strcmp(key, "enable_scheduler") == 0) {
            voqd->enable_scheduler = parse_bool(value);
        } else if (strcmp(key, "use_veth_egress") == 0) {
            voqd->use_veth_egress = parse_bool(value);
        } else if (strcmp(key, "veth_in_ifname") == 0) {
            strncpy(voqd->veth_in_ifname, value, sizeof(voqd->veth_in_ifname) - 1);
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
            fseek(fp, -(long)strlen(line_copy), SEEK_CUR);
            break;
        }
        
        /* Parse VLAN list item */
        if (trimmed[0] == '-' && vlan_count < MAX_VLANS) {
            /* Check if this line has content after '-' (e.g., "- vlan_id: 1") */
            char *content_after_dash = trim(trimmed + 1);
            char first_key[256], first_value[256];
            
            /* If there's a key-value on the same line as '-', parse it */
            if (strlen(content_after_dash) > 0 && parse_key_value(content_after_dash, first_key, first_value, sizeof(first_key)) == 0) {
                /* Pre-populate the vlan_id field */
                if (strcmp(first_key, "vlan_id") == 0) {
                    vlans[vlan_count].vlan_id = (uint16_t)atoi(first_value);
                }
            }
            
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
        RS_LOG_ERROR("Failed to open profile: %s", filename);
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
        } else if (strcmp(key, "extends") == 0) {
            char *extend_value = value;
            size_t value_len = strlen(extend_value);

            if (value_len >= 2 && extend_value[0] == '"' && extend_value[value_len - 1] == '"') {
                extend_value[value_len - 1] = '\0';
                extend_value++;
            }
            strncpy(profile->extends, extend_value, sizeof(profile->extends) - 1);
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
        } else if (strcmp(key, "voqd_config") == 0) {
            ret = parse_voqd_config(fp, &profile->voqd);
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
        const struct rs_profile_module_entry *entry = &profile->ingress_modules[i];
        printf("  - %s", entry->name);
        if (entry->stage_override >= 0) {
            printf(" (stage_override=%d)", entry->stage_override);
        }
        if (entry->optional) {
            if (entry->condition[0] != '\0') {
                printf(" [optional if %s]", entry->condition);
            } else {
                printf(" [optional]");
            }
        }
        printf("\n");
    }
    
    printf("\nEgress pipeline (%d modules):\n", profile->egress_count);
    for (int i = 0; i < profile->egress_count; i++) {
        const struct rs_profile_module_entry *entry = &profile->egress_modules[i];
        printf("  - %s", entry->name);
        if (entry->stage_override >= 0) {
            printf(" (stage_override=%d)", entry->stage_override);
        }
        if (entry->optional) {
            if (entry->condition[0] != '\0') {
                printf(" [optional if %s]", entry->condition);
            } else {
                printf(" [optional]");
            }
        }
        printf("\n");
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
