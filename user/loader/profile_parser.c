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
        remove_comment(line);
        char *trimmed = trim(line);
        
        if (strlen(trimmed) == 0) continue;
        
        /* Check if we're entering another section (not indented) */
        if (trimmed[0] != ' ' && trimmed[0] != '\t' && strchr(trimmed, ':')) {
            fprintf(stderr, "DEBUG: Exiting parse_settings() - found non-indented key: %s\n", trimmed);
            fseek(fp, -(long)strlen(line) - 1, SEEK_CUR);
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
}
