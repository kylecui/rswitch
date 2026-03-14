// SPDX-License-Identifier: GPL-2.0
/* 
 * rSwitch Profile Parser - Header
 */

#ifndef __PROFILE_PARSER_H__
#define __PROFILE_PARSER_H__

#include <stdint.h>

#define RS_MAX_MODULE_CONFIG_PARAMS 16

struct rs_module_config_param {
    char key[32];
    char value[64];
};

/* Port configuration structure */
struct rs_profile_port {
    char interface[32];
    int enabled;
    int management;  // 0=unmanaged, 1=managed
    int vlan_mode;   // 0=off, 1=access, 2=trunk, 3=hybrid
    int access_vlan;
    int native_vlan;
    int pvid;
    uint16_t allowed_vlans[128];
    int allowed_vlan_count;
    uint16_t tagged_vlans[64];
    int tagged_vlan_count;
    uint16_t untagged_vlans[64];
    int untagged_vlan_count;
    int mac_learning;
    int default_priority;
};

/* VLAN configuration structure */
struct rs_profile_vlan {
    uint16_t vlan_id;
    char name[32];
    char tagged_ports[16][32];    // Interface names
    int tagged_count;
    char untagged_ports[16][32];  // Interface names
    int untagged_count;
};

/* VOQd configuration structure */
struct rs_profile_voqd {
    int enabled;           // Enable VOQd (AF_XDP user-space scheduler)
    int mode;              // 0=BYPASS, 1=SHADOW, 2=ACTIVE
    int num_ports;         // Number of ports for VOQd
    uint32_t prio_mask;    // Priority bitmask for interception
    int enable_afxdp;      // Enable AF_XDP sockets
    int zero_copy;         // Use zero-copy mode (if supported)
    int rx_ring_size;      // AF_XDP RX ring size
    int tx_ring_size;      // AF_XDP TX ring size
    int frame_size;        // Frame size (typically 2048)
    int batch_size;        // Batch processing size
    int poll_timeout_ms;   // Poll timeout in milliseconds
    int busy_poll;         // Enable busy polling
    int cpu_affinity;      // CPU core for VOQd threads
    int enable_scheduler;  // Enable DRR/WFQ scheduler
    int use_veth_egress;   // Enable veth egress path for XDP egress processing
    char veth_in_ifname[32]; // Veth inside interface name
};

/* Management plane configuration */
struct rs_profile_mgmt {
    int enabled;
    int port;                    /* HTTP listen port, default 8080 */
    char web_root[256];          /* static web root path */
    int use_namespace;           /* 1 = use mgmt namespace isolation */
    char namespace_name[64];     /* namespace name, default "rswitch-mgmt" */
    int iface_mode;              /* 0 = dhcp, 1 = static */
    char static_ip[46];          /* static IP in CIDR, e.g. "10.0.0.100/24" */
    char gateway[46];            /* default gateway, e.g. "10.0.0.1" */
    int mgmt_vlan;               /* management VLAN (0 = untagged) */
    int auth_enabled;            /* require HTTP Basic auth */
    char auth_user[64];          /* username */
    char auth_password[128];     /* password (plaintext in config, hashed at runtime) */
    int session_timeout;         /* session timeout in seconds, default 3600 */
    int rate_limit_max_fails;    /* max auth failures before lockout, default 5 */
    int rate_limit_lockout_sec;  /* lockout duration in seconds, default 300 */
};

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

struct rs_profile_module_entry {
    char name[64];
    int stage_override;    /* -1 = use compiled-in default */
    int optional;          /* 0 = required (default), 1 = optional */
    char condition[64];    /* Condition for optional modules (e.g., "debug_mode") */
    struct rs_module_config_param config[RS_MAX_MODULE_CONFIG_PARAMS];
    int config_count;
};

#define RS_MAX_DHCP_TRUSTED_PORTS 16

struct rs_profile_dhcp_snooping {
    int enabled;
    int drop_rogue_server;
    char trusted_ports[RS_MAX_DHCP_TRUSTED_PORTS][32];
    int trusted_port_count;
};

/* Profile structure */
struct rs_profile {
    char name[64];
    char description[256];
    char version[16];
    char extends[256];
    
    /* Ingress pipeline modules */
    struct rs_profile_module_entry *ingress_modules;
    int ingress_count;
    
    /* Egress pipeline modules */
    struct rs_profile_module_entry *egress_modules;
    int egress_count;
    
    /* Settings */
    struct rs_profile_settings settings;
    
    /* VOQd configuration */
    struct rs_profile_voqd voqd;

    /* Management plane configuration */
    struct rs_profile_mgmt mgmt;

    /* DHCP snooping configuration */
    struct rs_profile_dhcp_snooping dhcp_snooping;
    
    /* Port configurations */
    struct rs_profile_port *ports;
    int port_count;
    
    /* VLAN configurations */
    struct rs_profile_vlan *vlans;
    int vlan_count;
};

/* Initialize profile with defaults */
void profile_init(struct rs_profile *profile);

/* Free profile resources */
void profile_free(struct rs_profile *profile);

/* Load and parse profile from file */
int profile_load(const char *filename, struct rs_profile *profile);
int profile_load_with_inheritance(const char *filename, struct rs_profile *profile);

/* Print profile information */
void profile_print(const struct rs_profile *profile);

#endif /* __PROFILE_PARSER_H__ */
