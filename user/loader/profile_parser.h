// SPDX-License-Identifier: GPL-2.0
/* 
 * rSwitch Profile Parser - Header
 */

#ifndef __PROFILE_PARSER_H__
#define __PROFILE_PARSER_H__

#include <stdint.h>

/* Profile settings structure */
struct rs_profile_settings {
    /* MAC learning */
    int mac_learning;
    int mac_aging_time;
    
    /* VLAN */
    int vlan_enforcement;
    int default_vlan;
    
    /* Flooding behavior */
    int unknown_unicast_flood;
    int broadcast_flood;
    int multicast_flood;
    
    /* Statistics and events */
    int stats_enabled;
    int ringbuf_enabled;
    
    /* Debug */
    int debug;
};

/* Profile structure */
struct rs_profile {
    char name[64];
    char description[256];
    char version[16];
    
    /* Ingress pipeline modules */
    char **ingress_modules;
    int ingress_count;
    
    /* Egress pipeline modules */
    char **egress_modules;
    int egress_count;
    
    /* Settings */
    struct rs_profile_settings settings;
};

/* Initialize profile with defaults */
void profile_init(struct rs_profile *profile);

/* Free profile resources */
void profile_free(struct rs_profile *profile);

/* Load and parse profile from file */
int profile_load(const char *filename, struct rs_profile *profile);

/* Print profile information */
void profile_print(const struct rs_profile *profile);

#endif /* __PROFILE_PARSER_H__ */
