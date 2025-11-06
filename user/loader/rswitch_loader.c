// SPDX-License-Identifier: GPL-2.0
/* rSwitch Auto-Discovering Loader
 * 
 * This loader replaces kSwitchLoader.c with a modular, plugin-based architecture.
 * 
 * Key Features:
 *   - Auto-discovers modules by reading .rodata.mod ELF sections
 *   - Sorts modules by stage number for deterministic pipeline order
 *   - Builds tail-call prog_array dynamically based on discovered modules
 *   - Supports profile-based loading (future: YAML profiles)
 *   - Validates module ABI compatibility
 * 
 * Architecture:
 *   1. Scan BPF object files in core/ and modules/ directories
 *   2. Extract rs_module_desc from .rodata.mod sections
 *   3. Sort modules by stage number (10, 20, 30, ..., 90)
 *   4. Load BPF objects and attach dispatcher to interfaces
 *   5. Populate prog_array map with sorted tail-call chain
 *   6. Configure port settings via maps
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <getopt.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <dirent.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "profile_parser.h"

/* Copy necessary structure definitions (user-space safe versions) */
#define RS_ABI_VERSION 1
#define RS_HOOK_XDP_INGRESS 0
#define RS_HOOK_XDP_EGRESS 1

/* VLAN mode enumeration (must match bpf/core/map_defs.h) */
#define RS_VLAN_MODE_OFF    0
#define RS_VLAN_MODE_ACCESS 1
#define RS_VLAN_MODE_TRUNK  2
#define RS_VLAN_MODE_HYBRID 3

/* MUST match bpf/core/module_abi.h exactly! */
struct rs_module_desc {
    __u32 abi_version;      /* Must be RS_ABI_VERSION */
    __u32 hook;             /* enum rs_hook_point */
    __u32 stage;            /* Pipeline stage (lower = earlier) */
    __u32 flags;            /* Capability flags (RS_FLAG_*) */
    char  name[32];         /* Module name (for logging/debug) */
    char  description[64];  /* Human-readable description */
    __u32 reserved[4];      /* Reserved for future use */
} __attribute__((aligned(8)));

struct rs_port_config {
    __u32 ifindex;
    __u8  enabled;
    __u8  mgmt_type;
    __u8  vlan_mode;
    __u8  learning;
    __u16 pvid;
    __u16 native_vlan;
    __u16 access_vlan;
    __u16 allowed_vlans[128];
    __u16 vlan_count;
    __u8  default_prio;
    __u8  trust_dscp;
    __u16 rate_limit_kbps;
    __u8  port_security;
    __u8  max_macs;
    __u16 reserved;
    __u32 reserved2[4];
};

/* VLAN membership structure - MUST match bpf/core/map_defs.h */
struct rs_vlan_members {
    __u16 vlan_id;
    __u16 member_count;
    __u64 tagged_members[4];      /* Bitmask: ifindex -> bit position */
    __u64 untagged_members[4];    /* Bitmask: ifindex -> bit position */
    __u32 reserved[4];
};

#define MAX_MODULES 64
#define MAX_INTERFACES 64
#define BPF_PIN_PATH "/sys/fs/bpf"
#define BUILD_DIR "./build/bpf"

/* Configuration defaults */
#define DEFAULT_XDP_FLAGS XDP_FLAGS_UPDATE_IF_NOEXIST
#define DEFAULT_MODE "dumb"

/* Module metadata extracted from BPF objects */
struct loaded_module {
    char name[64];
    char path[256];
    struct rs_module_desc desc;
    struct bpf_object *obj;
    struct bpf_program *prog;
    int prog_fd;
    int stage;
};

/* Global loader state */
struct loader_ctx {
    /* Modules */
    struct loaded_module modules[MAX_MODULES];
    int num_modules;
    
    /* Core programs */
    struct bpf_object *dispatcher_obj;
    struct bpf_program *dispatcher_prog;
    int dispatcher_fd;
    
    struct bpf_object *egress_obj;
    struct bpf_program *egress_prog;
    int egress_fd;
    
    /* Shared maps */
    int rs_ctx_map_fd;
    int rs_progs_fd;
    int rs_port_config_map_fd;
    int rs_devmap_fd;
    int rs_stats_map_fd;
    int rs_event_bus_fd;     /* Unified event bus (replaces per-module ringbufs) */
    int rs_mac_table_fd;     /* MAC table from l2learn module */
    
    /* Configuration */
    __u32 interfaces[MAX_INTERFACES];
    int num_interfaces;
    __u32 xdp_flags;
    char mode[32];
    char profile_path[256];
    struct rs_profile profile;
    int use_profile;
    int verbose;
};

static volatile int keep_running = 1;

/* Signal handler for graceful shutdown */
static void sig_handler(int sig)
{
    keep_running = 0;
}

/* Set RLIMIT_MEMLOCK to unlimited for BPF operations */
static int bump_memlock_rlimit(void)
{
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit: %s\n", 
                strerror(errno));
        return -1;
    }
    return 0;
}

/* Create BPF filesystem pin directory */
static int create_pin_dir(const char *path)
{
    struct stat st;
    
    if (stat(path, &st) == 0) {
        if (!S_ISDIR(st.st_mode)) {
            fprintf(stderr, "%s exists but is not a directory\n", path);
            return -1;
        }
        return 0;
    }
    
    if (mkdir(path, 0755) && errno != EEXIST) {
        fprintf(stderr, "Failed to create directory %s: %s\n", 
                path, strerror(errno));
        return -1;
    }
    
    return 0;
}

/* Read .rodata.mod section from BPF object to extract module metadata
 * 
 * This is the core auto-discovery mechanism. Each module embeds its
 * rs_module_desc in a .rodata.mod ELF section via RS_DECLARE_MODULE macro.
 */
static int read_module_metadata(const char *path, struct rs_module_desc *desc)
{
    struct bpf_object *obj;
    struct bpf_map *map;
    const void *data;
    size_t size;
    int err;
    
    /* Open BPF object without loading */
    obj = bpf_object__open(path);
    err = libbpf_get_error(obj);
    if (err) {
        fprintf(stderr, "Failed to open %s: %s\n", path, strerror(-err));
        return -1;
    }
    
    /* Find .rodata.mod map (automatically created by libbpf for .rodata sections) */
    bpf_object__for_each_map(map, obj) {
        const char *map_name = bpf_map__name(map);
        if (strstr(map_name, ".rodata.mod")) {
            data = bpf_map__initial_value(map, &size);
            
            /* BTF might show size=0 for .rodata.mod, but data should be valid */
            if (!data) {
                fprintf(stderr, "No data in .rodata.mod section of %s\n", path);
                bpf_object__close(obj);
                return -1;
            }
            
            /* If size is 0 or less than expected, assume it's sizeof(rs_module_desc) */
            if (size == 0 || size < sizeof(*desc)) {
                size = sizeof(*desc);
            }
            
            memcpy(desc, data, sizeof(*desc));
            bpf_object__close(obj);
            
            /* Validate ABI version */
            if (desc->abi_version != RS_ABI_VERSION) {
                fprintf(stderr, "Module %s ABI mismatch: expected %u, got %u\n",
                        path, RS_ABI_VERSION, desc->abi_version);
                return -1;
            }
            
            return 0;
        }
    }
    
    bpf_object__close(obj);
    fprintf(stderr, "No .rodata.mod section found in %s\n", path);
    return -1;
}

/* Check if module is in profile's ingress list */
static int is_module_in_profile(const char *module_name, struct rs_profile *profile)
{
    if (!profile || profile->ingress_count == 0) {
        /* No profile - load all modules (backward compatibility) */
        return 1;
    }
    
    for (int i = 0; i < profile->ingress_count; i++) {
        if (strcmp(module_name, profile->ingress_modules[i]) == 0) {
            return 1;
        }
    }
    
    return 0;
}

/* Discover and load all modules from build directory */
static int discover_modules(struct loader_ctx *ctx)
{
    DIR *dir;
    struct dirent *entry;
    char path[512];
    int count = 0;
    
    /* Scan build/bpf directory for .bpf.o files */
    dir = opendir(BUILD_DIR);
    if (!dir) {
        fprintf(stderr, "Failed to open %s: %s\n", BUILD_DIR, strerror(errno));
        return -1;
    }
    
    while ((entry = readdir(dir)) != NULL && count < MAX_MODULES) {
        /* Skip non-BPF objects */
        if (!strstr(entry->d_name, ".bpf.o"))
            continue;
        
        /* Skip core programs (handled separately) */
        if (strstr(entry->d_name, "dispatcher") || 
            strstr(entry->d_name, "egress"))
            continue;
        
        snprintf(path, sizeof(path), "%s/%s", BUILD_DIR, entry->d_name);
        
        /* Try to read module metadata */
        struct rs_module_desc desc;
        if (read_module_metadata(path, &desc) == 0) {
            /* Check if module is in profile (if profile is used) */
            if (ctx->use_profile && !is_module_in_profile(desc.name, &ctx->profile)) {
                if (ctx->verbose) {
                    printf("Skipping module: %s (not in profile)\n", desc.name);
                }
                continue;
            }
            
            strncpy(ctx->modules[count].name, desc.name, sizeof(ctx->modules[count].name) - 1);
            strncpy(ctx->modules[count].path, path, sizeof(ctx->modules[count].path) - 1);
            memcpy(&ctx->modules[count].desc, &desc, sizeof(desc));
            ctx->modules[count].stage = desc.stage;
            
            if (ctx->verbose) {
                printf("Discovered module: %s (stage=%u, hook=%u, flags=0x%x)\n",
                       desc.name, desc.stage, desc.hook, desc.flags);
            }
            
            count++;
        }
    }
    
    closedir(dir);
    ctx->num_modules = count;
    
    printf("Discovered %d modules\n", count);
    return count;
}

/* Compare function for qsort - sort modules by stage number */
static int compare_modules(const void *a, const void *b)
{
    const struct loaded_module *ma = (const struct loaded_module *)a;
    const struct loaded_module *mb = (const struct loaded_module *)b;
    return ma->stage - mb->stage;
}

/* Load core dispatcher and egress programs */
static int load_core_programs(struct loader_ctx *ctx)
{
    char path[256];
    int err;
    
    /* Load dispatcher */
    snprintf(path, sizeof(path), "%s/dispatcher.bpf.o", BUILD_DIR);
    ctx->dispatcher_obj = bpf_object__open(path);
    err = libbpf_get_error(ctx->dispatcher_obj);
    if (err) {
        fprintf(stderr, "Failed to open dispatcher: %s\n", strerror(-err));
        return -1;
    }
    
    err = bpf_object__load(ctx->dispatcher_obj);
    if (err) {
        fprintf(stderr, "Failed to load dispatcher: %s\n", strerror(-err));
        return -1;
    }
    
    ctx->dispatcher_prog = bpf_object__find_program_by_name(ctx->dispatcher_obj, 
                                                             "rswitch_dispatcher");
    if (!ctx->dispatcher_prog) {
        fprintf(stderr, "Failed to find rswitch_dispatcher program\n");
        return -1;
    }
    
    ctx->dispatcher_fd = bpf_program__fd(ctx->dispatcher_prog);
    if (ctx->dispatcher_fd < 0) {
        fprintf(stderr, "Failed to get dispatcher FD\n");
        return -1;
    }
    
    /* NOTE: rs_ctx_map and rs_progs are auto-pinned by libbpf
     * via LIBBPF_PIN_BY_NAME to /sys/fs/bpf/<map_name>
     * No manual pinning needed!
     */
    
    /* Load egress */
    snprintf(path, sizeof(path), "%s/egress.bpf.o", BUILD_DIR);
    ctx->egress_obj = bpf_object__open(path);
    err = libbpf_get_error(ctx->egress_obj);
    if (err) {
        fprintf(stderr, "Failed to open egress: %s\n", strerror(-err));
        return -1;
    }
    
    err = bpf_object__load(ctx->egress_obj);
    if (err) {
        fprintf(stderr, "Failed to load egress: %s\n", strerror(-err));
        return -1;
    }
    
    ctx->egress_prog = bpf_object__find_program_by_name(ctx->egress_obj, 
                                                         "rswitch_egress");
    if (!ctx->egress_prog) {
        fprintf(stderr, "Failed to find rswitch_egress program\n");
        return -1;
    }
    
    ctx->egress_fd = bpf_program__fd(ctx->egress_prog);
    if (ctx->egress_fd < 0) {
        fprintf(stderr, "Failed to get egress FD\n");
        return -1;
    }
    
    printf("Loaded core programs: dispatcher_fd=%d, egress_fd=%d\n",
           ctx->dispatcher_fd, ctx->egress_fd);
    
    return 0;
}

/* Get file descriptors for pinned maps */
static int get_pinned_maps(struct loader_ctx *ctx)
{
    char path[256];
    
    /* LIBBPF_PIN_BY_NAME pins to /sys/fs/bpf/<map_name> (NOT /sys/fs/bpf/rswitch/)
     * This is automatic pinning by libbpf, not manual.
     */
    ctx->rs_ctx_map_fd = bpf_obj_get("/sys/fs/bpf/rs_ctx_map");
    ctx->rs_progs_fd = bpf_obj_get("/sys/fs/bpf/rs_progs");
    
    /* Port config map - may or may not be pinned */
    snprintf(path, sizeof(path), "%s/rs_port_config_map", BPF_PIN_PATH);
    ctx->rs_port_config_map_fd = bpf_obj_get(path);
    
    snprintf(path, sizeof(path), "%s/rs_devmap", BPF_PIN_PATH);
    ctx->rs_devmap_fd = bpf_obj_get(path);
    
    snprintf(path, sizeof(path), "%s/rs_stats_map", BPF_PIN_PATH);
    ctx->rs_stats_map_fd = bpf_obj_get(path);
    
    /* Unified event bus is pinned by core infrastructure */
    ctx->rs_event_bus_fd = -1;  /* Will be obtained from pinned path */
    ctx->rs_mac_table_fd = -1;  /* Will be obtained from l2learn module */
    
    if (ctx->rs_progs_fd < 0) {
        fprintf(stderr, "Warning: Failed to get rs_progs from /sys/fs/bpf/rs_progs\n");
        /* Try to get from dispatcher object */
        struct bpf_map *map = bpf_object__find_map_by_name(ctx->dispatcher_obj, "rs_progs");
        if (map) {
            ctx->rs_progs_fd = bpf_map__fd(map);
            printf("Got rs_progs from dispatcher object: fd=%d\n", ctx->rs_progs_fd);
        }
    }
    
    if (ctx->rs_port_config_map_fd < 0) {
        struct bpf_map *map = bpf_object__find_map_by_name(ctx->dispatcher_obj, "rs_port_config_map");
        if (map) {
            ctx->rs_port_config_map_fd = bpf_map__fd(map);
        }
    }
    
    if (ctx->rs_devmap_fd < 0) {
        struct bpf_map *map = bpf_object__find_map_by_name(ctx->dispatcher_obj, "rs_devmap");
        if (map) {
            ctx->rs_devmap_fd = bpf_map__fd(map);
        }
    }
    
    printf("Map FDs: rs_progs=%d, port_config=%d, devmap=%d\n",
           ctx->rs_progs_fd, ctx->rs_port_config_map_fd, ctx->rs_devmap_fd);
    
    return 0;
}

/* Load module BPF objects and get program FDs */
static int load_modules(struct loader_ctx *ctx)
{
    int i, err;
    
    for (i = 0; i < ctx->num_modules; i++) {
        struct loaded_module *mod = &ctx->modules[i];
        
        /* Open BPF object */
        mod->obj = bpf_object__open(mod->path);
        err = libbpf_get_error(mod->obj);
        if (err) {
            fprintf(stderr, "Failed to open module %s: %s\n", 
                    mod->name, strerror(-err));
            continue;
        }
        
        /* Load BPF object */
        err = bpf_object__load(mod->obj);
        if (err) {
            fprintf(stderr, "Failed to load module %s: %s\n", 
                    mod->name, strerror(-err));
            bpf_object__close(mod->obj);
            mod->obj = NULL;
            continue;
        }
        
        /* Find XDP program (modules should have SEC("xdp") programs) */
        bpf_object__for_each_program(mod->prog, mod->obj) {
            const char *sec_name = bpf_program__section_name(mod->prog);
            if (strncmp(sec_name, "xdp", 3) == 0) {
                mod->prog_fd = bpf_program__fd(mod->prog);
                break;
            }
        }
        
        if (mod->prog_fd < 0) {
            fprintf(stderr, "Failed to find XDP program in module %s\n", mod->name);
            bpf_object__close(mod->obj);
            mod->obj = NULL;
            continue;
        }
        
        if (ctx->verbose) {
            printf("Loaded module %s: stage=%u, fd=%d\n", 
                   mod->name, mod->stage, mod->prog_fd);
        }
    }
    
    return 0;
}

/* Build tail-call prog_array by inserting modules in stage order */
static int build_prog_array(struct loader_ctx *ctx)
{
    int i, err;
    __u32 idx = 0;
    
    if (ctx->rs_progs_fd < 0) {
        fprintf(stderr, "rs_progs map FD not available\n");
        return -1;
    }
    
    /* Sort modules by stage number */
    qsort(ctx->modules, ctx->num_modules, sizeof(struct loaded_module), compare_modules);
    
    printf("\nBuilding tail-call pipeline:\n");
    
    /* Insert modules into prog_array in stage order */
    for (i = 0; i < ctx->num_modules; i++) {
        struct loaded_module *mod = &ctx->modules[i];
        
        if (!mod->obj || mod->prog_fd < 0)
            continue;
        
        /* Insert at sequential index (0, 1, 2, ...) */
        err = bpf_map_update_elem(ctx->rs_progs_fd, &idx, &mod->prog_fd, BPF_ANY);
        if (err) {
            fprintf(stderr, "Failed to insert %s into prog_array[%u]: %s\n",
                    mod->name, idx, strerror(errno));
            return -1;
        }
        
        printf("  [%u] stage=%2u: %s (fd=%d)\n", idx, mod->stage, mod->name, mod->prog_fd);
        idx++;
    }
    
    printf("Pipeline built with %u modules\n", idx);
    return 0;
}

/* Configure port settings via rs_port_config_map */
static int configure_ports(struct loader_ctx *ctx)
{
    int i, err;
    
    if (ctx->rs_port_config_map_fd < 0) {
        fprintf(stderr, "Warning: port_config_map not available, skipping config\n");
        return 0;
    }
    
    printf("Configuring ports:\n");
    
    /* If profile has explicit port configurations, use them */
    if (ctx->use_profile && ctx->profile.port_count > 0) {
        printf("  Using profile port configurations (%d ports)\n", ctx->profile.port_count);
        
        for (i = 0; i < ctx->profile.port_count; i++) {
            struct rs_profile_port *pport = &ctx->profile.ports[i];
            __u32 ifindex = if_nametoindex(pport->interface);
            
            if (ifindex == 0) {
                fprintf(stderr, "  Warning: interface %s not found, skipping\n", pport->interface);
                continue;
            }
            
            struct rs_port_config cfg = {
                .ifindex = ifindex,
                .enabled = pport->enabled,
                .mgmt_type = pport->management,
                .vlan_mode = pport->vlan_mode,
                .learning = pport->mac_learning,
                .pvid = pport->pvid ? pport->pvid : pport->access_vlan,
                .native_vlan = pport->native_vlan,
                .access_vlan = pport->access_vlan,
                .default_prio = pport->default_priority,
                .trust_dscp = 0,
                .vlan_count = pport->allowed_vlan_count,
            };
            
            /* Copy allowed VLANs */
            if (ctx->verbose) {
                fprintf(stderr, "DEBUG: configure_ports() port=%s, allowed_vlan_count=%d\n",
                        pport->interface, pport->allowed_vlan_count);
                fprintf(stderr, "DEBUG: allowed_vlans=[");
                for (int j = 0; j < pport->allowed_vlan_count && j < 10; j++) {
                    fprintf(stderr, "%d%s", pport->allowed_vlans[j], 
                            j < pport->allowed_vlan_count-1 ? ", " : "");
                }
                fprintf(stderr, "]\n");
            }
            
            for (int j = 0; j < pport->allowed_vlan_count && j < 128; j++) {
                cfg.allowed_vlans[j] = pport->allowed_vlans[j];
            }
            
            err = bpf_map_update_elem(ctx->rs_port_config_map_fd, &ifindex, &cfg, BPF_ANY);
            if (err) {
                fprintf(stderr, "  Failed to configure port %s: %s\n", 
                        pport->interface, strerror(errno));
                continue;
            }
            
            const char *mode_str[] = {"OFF", "ACCESS", "TRUNK", "HYBRID"};
            printf("  Port %u (%s): mode=%s", ifindex, pport->interface, 
                   mode_str[pport->vlan_mode < 4 ? pport->vlan_mode : 0]);
            if (pport->vlan_mode == RS_VLAN_MODE_ACCESS) {
                printf(", access_vlan=%d", pport->access_vlan);
            } else if (pport->vlan_mode == RS_VLAN_MODE_TRUNK) {
                printf(", native=%d, allowed=%d VLANs", pport->native_vlan, pport->allowed_vlan_count);
            }
            printf(", learning=%s\n", pport->mac_learning ? "on" : "off");
        }
        
        return 0;
    }
    
    /* Otherwise use default configuration based on global settings */
    __u8 vlan_mode = RS_VLAN_MODE_OFF;
    __u16 default_vlan = 1;
    
    if (ctx->use_profile && ctx->profile.settings.vlan_enforcement) {
        vlan_mode = RS_VLAN_MODE_ACCESS;
        default_vlan = ctx->profile.settings.default_vlan;
        printf("  Using default config: ACCESS mode (VLAN %d)\n", default_vlan);
    } else {
        printf("  Using default config: OFF mode\n");
    }
    
    for (i = 0; i < ctx->num_interfaces; i++) {
        __u32 ifindex = ctx->interfaces[i];
        struct rs_port_config cfg = {
            .ifindex = ifindex,
            .enabled = 1,
            .mgmt_type = 1,
            .vlan_mode = vlan_mode,
            .learning = ctx->use_profile ? ctx->profile.settings.mac_learning : 1,
            .pvid = default_vlan,
            .native_vlan = default_vlan,
            .access_vlan = default_vlan,
            .default_prio = 0,
            .trust_dscp = 0,
        };
        
        err = bpf_map_update_elem(ctx->rs_port_config_map_fd, &ifindex, &cfg, BPF_ANY);
        if (err) {
            fprintf(stderr, "  Failed to configure port %u: %s\n", 
                    ifindex, strerror(errno));
            continue;
        }
        
        char ifname[IF_NAMESIZE];
        if_indextoname(ifindex, ifname);
        
        const char *mode_str[] = {"OFF", "ACCESS", "TRUNK", "HYBRID"};
        printf("  Port %u (%s): mode=%s, vlan=%d, learning=%s\n", 
               ifindex, ifname, mode_str[vlan_mode], default_vlan,
               cfg.learning ? "on" : "off");
    }
    
    return 0;
}

/* Initialize VLAN map with default VLAN 1 containing all ports
 * 
 * CRITICAL: Without this, VLAN module will drop all packets!
 * PoC initializes vlan_peer_array in loader - we must do the same.
 */
static int initialize_vlan_map(struct loader_ctx *ctx)
{
    int i, j, err;
    char path[256];
    int vlan_map_fd = -1;
    
    /* Find rs_vlan_map */
    snprintf(path, sizeof(path), "%s/rs_vlan_map", BPF_PIN_PATH);
    vlan_map_fd = bpf_obj_get(path);
    if (vlan_map_fd < 0) {
        /* Try finding in loaded modules */
        for (i = 0; i < ctx->num_modules; i++) {
            if (ctx->modules[i].obj) {
                struct bpf_map *map = bpf_object__find_map_by_name(ctx->modules[i].obj, "rs_vlan_map");
                if (map) {
                    vlan_map_fd = bpf_map__fd(map);
                    break;
                }
            }
        }
    }
    
    if (vlan_map_fd < 0) {
        printf("Warning: rs_vlan_map not found, VLAN validation may fail\n");
        return 0;
    }
    
    printf("\nInitializing VLAN map:\n");
    
    /* If profile has explicit VLAN configurations, use them */
    if (ctx->use_profile && ctx->profile.vlan_count > 0) {
        printf("  Using profile VLAN configurations (%d VLANs)\n", ctx->profile.vlan_count);
        
        for (i = 0; i < ctx->profile.vlan_count; i++) {
            struct rs_profile_vlan *pvlan = &ctx->profile.vlans[i];
            struct rs_vlan_members vlan = {
                .vlan_id = pvlan->vlan_id,
                .member_count = pvlan->tagged_count + pvlan->untagged_count,
            };
            
            /* Clear bitmasks */
            for (j = 0; j < 4; j++) {
                vlan.tagged_members[j] = 0;
                vlan.untagged_members[j] = 0;
            }
            
            /* Add tagged ports */
            for (j = 0; j < pvlan->tagged_count; j++) {
                __u32 ifindex = if_nametoindex(pvlan->tagged_ports[j]);
                if (ifindex == 0) {
                    fprintf(stderr, "  Warning: tagged port %s not found\n", pvlan->tagged_ports[j]);
                    continue;
                }
                
                __u32 word_idx = ((ifindex - 1) / 64) & 3;
                __u64 bit_mask = 1ULL << ((ifindex - 1) % 64);
                vlan.tagged_members[word_idx] |= bit_mask;
            }
            
            /* Add untagged ports */
            for (j = 0; j < pvlan->untagged_count; j++) {
                __u32 ifindex = if_nametoindex(pvlan->untagged_ports[j]);
                if (ifindex == 0) {
                    fprintf(stderr, "  Warning: untagged port %s not found\n", pvlan->untagged_ports[j]);
                    continue;
                }
                
                __u32 word_idx = ((ifindex - 1) / 64) & 3;
                __u64 bit_mask = 1ULL << ((ifindex - 1) % 64);
                vlan.untagged_members[word_idx] |= bit_mask;
            }
            
            __u16 vlan_id = pvlan->vlan_id;
            err = bpf_map_update_elem(vlan_map_fd, &vlan_id, &vlan, BPF_ANY);
            if (err) {
                fprintf(stderr, "  Failed to create VLAN %d: %s\n", vlan_id, strerror(errno));
                continue;
            }
            
            printf("  VLAN %d (%s): %d tagged, %d untagged\n", 
                   pvlan->vlan_id, pvlan->name, pvlan->tagged_count, pvlan->untagged_count);
        }
        
        close(vlan_map_fd);
        return 0;
    }
    
    /* Otherwise create default VLAN 1 with all ports as untagged members */
    struct rs_vlan_members vlan1 = {
        .vlan_id = 1,
        .member_count = ctx->num_interfaces,
    };
    
    /* Clear bitmasks */
    for (i = 0; i < 4; i++) {
        vlan1.tagged_members[i] = 0;
        vlan1.untagged_members[i] = 0;
    }
    
    /* Add all ports to VLAN 1 as untagged members */
    for (i = 0; i < ctx->num_interfaces; i++) {
        __u32 ifindex = ctx->interfaces[i];
        
        /* Set bit in untagged_members bitmask
         * Each __u64 holds 64 ports, so:
         * - ifindex 1-64 go in untagged_members[0]
         * - ifindex 65-128 go in untagged_members[1], etc.
         */
        int word_idx = (ifindex - 1) / 64;  /* Which __u64 */
        int bit_idx = (ifindex - 1) % 64;   /* Which bit */
        
        if (word_idx < 4) {
            vlan1.untagged_members[word_idx] |= (1ULL << bit_idx);
        }
    }
    
    /* Insert VLAN 1 into map */
    __u16 vlan_key = 1;
    err = bpf_map_update_elem(vlan_map_fd, &vlan_key, &vlan1, BPF_ANY);
    if (err) {
        fprintf(stderr, "Failed to create default VLAN 1: %s\n", strerror(errno));
        return -1;
    }
    
    printf("  VLAN 1: %u ports (default untagged)\n", ctx->num_interfaces);
    return 0;
}

/* Populate devmaps with queue isolation
 * 
 * Following PoC pattern: find rs_xdp_devmap from lastcall module object
 * (not pinned, not in dispatcher - matches PoC's egress_map approach)
 */
static int populate_devmaps(struct loader_ctx *ctx)
{
    int i, err;
    int xdp_devmap_fd = -1, afxdp_devmap_fd = -1;
    int egress_prog_fd = ctx->egress_fd;  /* Egress already loaded in load_core_programs() */
    char path[256];
    
    if (egress_prog_fd < 0) {
        fprintf(stderr, "Warning: Egress program not loaded - VLAN isolation will NOT work!\n");
    }
    
    /* Find rs_xdp_devmap from lastcall module (owner)
     * Following PoC: loader finds egress_map from lastcall object
     */
    for (i = 0; i < ctx->num_modules; i++) {
        if (strcmp(ctx->modules[i].name, "lastcall") == 0 && ctx->modules[i].obj) {
            struct bpf_map *map = bpf_object__find_map_by_name(ctx->modules[i].obj, "rs_xdp_devmap");
            if (map) {
                xdp_devmap_fd = bpf_map__fd(map);
                if (ctx->verbose) {
                    printf("Found rs_xdp_devmap in lastcall module: fd=%d\n", xdp_devmap_fd);
                }
                break;
            }
        }
    }
    
    /* Open AF_XDP devmap */
    snprintf(path, sizeof(path), "%s/afxdp_devmap", BPF_PIN_PATH);
    afxdp_devmap_fd = bpf_obj_get(path);
    if (afxdp_devmap_fd < 0) {
        /* Try finding in loaded modules */
        for (i = 0; i < ctx->num_modules; i++) {
            if (ctx->modules[i].obj) {
                struct bpf_map *map = bpf_object__find_map_by_name(ctx->modules[i].obj, "afxdp_devmap");
                if (map) {
                    afxdp_devmap_fd = bpf_map__fd(map);
                    break;
                }
            }
        }
    }
    
    if (xdp_devmap_fd < 0 && afxdp_devmap_fd < 0) {
        fprintf(stderr, "Warning: No devmaps found, skipping devmap population\n");
        return 0;
    }
    
    printf("\nPopulating devmaps with queue isolation:\n");
    
    for (i = 0; i < ctx->num_interfaces; i++) {
        __u32 ifindex = ctx->interfaces[i];
        char ifname[IF_NAMESIZE];
        if_indextoname(ifindex, ifname);
        
        /* XDP devmap: queue 1 (round-robin across 1-3 in production) */
        if (xdp_devmap_fd >= 0) {
            struct bpf_devmap_val xdp_val = {
                .ifindex = ifindex,
                .bpf_prog.fd = egress_prog_fd,  /* Attach egress hook for VLAN isolation */
            };
            /* Note: Queue selection via xdp_txq_id not supported in all kernels.
             * For queue isolation, use ethtool -X to configure RSS or run
             * setup_nic_queues.sh to set IRQ affinity */
            
            err = bpf_map_update_elem(xdp_devmap_fd, &ifindex, &xdp_val, BPF_ANY);
            if (err) {
                fprintf(stderr, "Warning: Failed to add %s to XDP devmap: %s\n",
                        ifname, strerror(errno));
            } else {
                if (egress_prog_fd >= 0) {
                    printf("  XDP devmap: %s (ifindex=%u) with egress hook\n", ifname, ifindex);
                } else {
                    printf("  XDP devmap: %s (ifindex=%u) without egress hook\n", ifname, ifindex);
                }
            }
        }
        
        /* AF_XDP devmap: queue 0 (dedicated for high-priority) */
        if (afxdp_devmap_fd >= 0) {
            struct bpf_devmap_val afxdp_val = {
                .ifindex = ifindex,
                .bpf_prog.fd = -1,
            };
            /* Note: Queue 0 isolation achieved via NIC IRQ affinity.
             * Run setup_nic_queues.sh to configure. */
            
            err = bpf_map_update_elem(afxdp_devmap_fd, &ifindex, &afxdp_val, BPF_ANY);
            if (err) {
                fprintf(stderr, "Warning: Failed to add %s to AF_XDP devmap: %s\n",
                        ifname, strerror(errno));
            } else {
                printf("  AF_XDP devmap: %s (ifindex=%u)\n", ifname, ifindex);
            }
        }
    }
    
    printf("Queue isolation framework enabled (use setup_nic_queues.sh for IRQ affinity)\n");
    return 0;
}

/* Attach dispatcher to interfaces */
static int attach_xdp(struct loader_ctx *ctx)
{
    int i, err;
    
    printf("\nAttaching XDP programs:\n");
    
    for (i = 0; i < ctx->num_interfaces; i++) {
        __u32 ifindex = ctx->interfaces[i];
        char ifname[IF_NAMESIZE];
        
        if_indextoname(ifindex, ifname);
        
        err = bpf_xdp_attach(ifindex, ctx->dispatcher_fd, ctx->xdp_flags, NULL);
        if (err) {
            fprintf(stderr, "Failed to attach XDP to %s (ifindex=%u): %s\n",
                    ifname, ifindex, strerror(-err));
            return -1;
        }
        
        printf("  Attached to %s (ifindex=%u)\n", ifname, ifindex);
    }
    
    return 0;
}

/* Detach XDP programs from interfaces */
static void detach_xdp(struct loader_ctx *ctx)
{
    int i;
    
    printf("\nDetaching XDP programs:\n");
    
    for (i = 0; i < ctx->num_interfaces; i++) {
        __u32 ifindex = ctx->interfaces[i];
        char ifname[IF_NAMESIZE];
        
        if_indextoname(ifindex, ifname);
        if (bpf_xdp_detach(ifindex, ctx->xdp_flags, NULL) < 0) {
            fprintf(stderr, "  Warning: Failed to detach from %s (ifindex=%u): %s\n",
                    ifname, ifindex, strerror(errno));
        } else {
            printf("  Detached from %s (ifindex=%u)\n", ifname, ifindex);
        }
    }
}

/* Close all map file descriptors */
static void close_map_fds(struct loader_ctx *ctx)
{
    printf("\nClosing map file descriptors:\n");
    
    if (ctx->rs_ctx_map_fd >= 0) {
        close(ctx->rs_ctx_map_fd);
        printf("  Closed rs_ctx_map_fd\n");
    }
    if (ctx->rs_progs_fd >= 0) {
        close(ctx->rs_progs_fd);
        printf("  Closed rs_progs_fd\n");
    }
    if (ctx->rs_port_config_map_fd >= 0) {
        close(ctx->rs_port_config_map_fd);
        printf("  Closed rs_port_config_map_fd\n");
    }
    if (ctx->rs_devmap_fd >= 0) {
        close(ctx->rs_devmap_fd);
        printf("  Closed rs_devmap_fd\n");
    }
    if (ctx->rs_stats_map_fd >= 0) {
        close(ctx->rs_stats_map_fd);
        printf("  Closed rs_stats_map_fd\n");
    }
    if (ctx->rs_event_bus_fd >= 0) {
        close(ctx->rs_event_bus_fd);
        printf("  Closed rs_event_bus_fd\n");
    }
    
    if (ctx->rs_mac_table_fd >= 0) {
        close(ctx->rs_mac_table_fd);
        printf("  Closed rs_mac_table_fd\n");
    }
}

/* Unpin all maps from BPF filesystem */
static void unpin_maps(void)
{
    const char *pinned_maps[] = {
        "/sys/fs/bpf/rs_ctx_map",
        "/sys/fs/bpf/rs_progs",
        "/sys/fs/bpf/rs_port_config_map",
        "/sys/fs/bpf/rs_vlan_map",
        "/sys/fs/bpf/rs_event_bus",
        "/sys/fs/bpf/rs_mac_table",
        "/sys/fs/bpf/rs_stats_map",
        NULL
    };
    
    printf("\nUnpinning maps from BPF filesystem:\n");
    
    for (int i = 0; pinned_maps[i] != NULL; i++) {
        struct stat st;
        if (stat(pinned_maps[i], &st) == 0) {
            if (unlink(pinned_maps[i]) < 0) {
                fprintf(stderr, "  Warning: Failed to unpin %s: %s\n",
                        pinned_maps[i], strerror(errno));
            } else {
                printf("  Unpinned %s\n", pinned_maps[i]);
            }
        }
    }
}

/* Cleanup resources */
static void cleanup(struct loader_ctx *ctx)
{
    int i;
    
    printf("\n========== Cleanup Started ==========\n");
    
    /* Step 1: Detach XDP programs from all interfaces */
    detach_xdp(ctx);
    
    /* Step 2: Close map file descriptors */
    close_map_fds(ctx);
    
    /* Step 3: Close module BPF objects */
    printf("\nClosing module BPF objects:\n");
    for (i = 0; i < ctx->num_modules; i++) {
        if (ctx->modules[i].obj) {
            bpf_object__close(ctx->modules[i].obj);
            printf("  Closed %s\n", ctx->modules[i].name);
        }
    }
    
    /* Step 4: Close core BPF objects */
    printf("\nClosing core BPF objects:\n");
    if (ctx->dispatcher_obj) {
        bpf_object__close(ctx->dispatcher_obj);
        printf("  Closed dispatcher\n");
    }
    if (ctx->egress_obj) {
        bpf_object__close(ctx->egress_obj);
        printf("  Closed egress\n");
    }
    
    /* Step 5: Unpin maps from BPF filesystem */
    unpin_maps();
    
    /* Step 6: Free profile */
    if (ctx->use_profile) {
        profile_free(&ctx->profile);
        printf("\nFreed profile memory\n");
    }
    
    printf("\n========== Cleanup Complete ==========\n");
}

/* Parse interface list from string (comma-separated) */
static int parse_interfaces(struct loader_ctx *ctx, const char *iface_str)
{
    char *str = strdup(iface_str);
    char *token;
    int count = 0;
    
    token = strtok(str, ",");
    while (token && count < MAX_INTERFACES) {
        /* Try as interface name first */
        __u32 ifindex = if_nametoindex(token);
        if (ifindex == 0) {
            /* Try as numeric ifindex */
            ifindex = atoi(token);
            if (ifindex == 0) {
                fprintf(stderr, "Invalid interface: %s\n", token);
                free(str);
                return -1;
            }
        }
        
        ctx->interfaces[count++] = ifindex;
        token = strtok(NULL, ",");
    }
    
    free(str);
    ctx->num_interfaces = count;
    return count;
}

static void usage(const char *prog)
{
    fprintf(stderr, 
        "Usage: %s [OPTIONS]\n"
        "Options:\n"
        "  -i, --ifaces <list>    Comma-separated interface list (names or indices)\n"
        "  -m, --mode <mode>      Operating mode: dumb, l2, l3, firewall (default: dumb)\n"
        "  -p, --profile <path>   Load YAML profile (overrides --mode)\n"
        "  -v, --verbose          Verbose output\n"
        "  -h, --help             Show this help\n"
        "\n"
        "Examples:\n"
        "  %s -i eth0,eth1,eth2 -m l2 -v\n"
        "  %s -i 3,4,5 -m dumb\n"
        "  %s -i eth0,eth1 -p /path/to/custom.yaml\n"
        "\n"
        "Modes:\n"
        "  dumb      - Simple flooding switch (no learning)\n"
        "  l2        - L2 learning switch with VLAN support\n"
        "  l3        - L3 router with ACL (future)\n"
        "  firewall  - Security firewall with deep inspection (future)\n"
        "\n"
        "Profiles are YAML files in etc/profiles/ that define pipeline composition.\n"
        "Use --profile to load custom configuration or --mode for built-in presets.\n",
        prog, prog, prog, prog);
}

int main(int argc, char **argv)
{
    struct loader_ctx ctx = {0};
    int opt, err;
    char *iface_list = NULL;
    
    /* Initialize map FDs to -1 */
    ctx.rs_ctx_map_fd = -1;
    ctx.rs_progs_fd = -1;
    ctx.rs_port_config_map_fd = -1;
    ctx.rs_devmap_fd = -1;
    ctx.rs_stats_map_fd = -1;
    
    /* Default XDP flags */
    ctx.xdp_flags = DEFAULT_XDP_FLAGS;
    
    static struct option long_options[] = {
        {"ifaces", required_argument, 0, 'i'},
        {"mode", required_argument, 0, 'm'},
        {"profile", required_argument, 0, 'p'},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    /* Parse arguments */
    while ((opt = getopt_long(argc, argv, "i:m:p:vh", long_options, NULL)) != -1) {
        switch (opt) {
        case 'i':
            iface_list = optarg;
            break;
        case 'm':
            strncpy(ctx.mode, optarg, sizeof(ctx.mode) - 1);
            break;
        case 'p':
            strncpy(ctx.profile_path, optarg, sizeof(ctx.profile_path) - 1);
            ctx.use_profile = 1;
            break;
        case 'v':
            ctx.verbose = 1;
            break;
        case 'h':
        default:
            usage(argv[0]);
            return opt == 'h' ? 0 : 1;
        }
    }
    
    /* Load profile if specified, otherwise use mode-based profile */
    if (ctx.use_profile) {
        /* Load custom profile */
        if (profile_load(ctx.profile_path, &ctx.profile) < 0) {
            fprintf(stderr, "Failed to load profile: %s\n", ctx.profile_path);
            return 1;
        }
        if (ctx.verbose) {
            printf("Loaded profile from: %s\n\n", ctx.profile_path);
            profile_print(&ctx.profile);
            printf("\n");
        }
    } else {
        /* Use built-in mode - construct profile path */
        if (strlen(ctx.mode) == 0)
            strcpy(ctx.mode, DEFAULT_MODE);
        
        snprintf(ctx.profile_path, sizeof(ctx.profile_path), 
                 "./etc/profiles/%s.yaml", ctx.mode);
        
        if (profile_load(ctx.profile_path, &ctx.profile) == 0) {
            ctx.use_profile = 1;
            if (ctx.verbose) {
                printf("Loaded built-in profile: %s\n\n", ctx.mode);
                profile_print(&ctx.profile);
                printf("\n");
            }
        } else {
            /* Profile not found - use legacy mode (load all modules) */
            if (ctx.verbose) {
                printf("Profile not found: %s (loading all modules)\n", ctx.profile_path);
            }
            ctx.use_profile = 0;
        }
    }
    
    ctx.xdp_flags = DEFAULT_XDP_FLAGS;
    
    /* Parse interfaces */
    if (!iface_list) {
        fprintf(stderr, "Error: -i/--ifaces required\n");
        usage(argv[0]);
        return 1;
    }
    
    if (parse_interfaces(&ctx, iface_list) <= 0) {
        fprintf(stderr, "No valid interfaces specified\n");
        return 1;
    }
    
    printf("rSwitch Auto-Discovering Loader\n");
    printf("================================\n");
    if (ctx.use_profile) {
        printf("Profile: %s (%s)\n", ctx.profile.name, ctx.profile.version);
        printf("Description: %s\n", ctx.profile.description);
    } else {
        printf("Mode: %s (legacy - all modules)\n", ctx.mode);
    }
    printf("Interfaces: %d\n", ctx.num_interfaces);
    printf("\n");
    
    /* Setup */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    if (bump_memlock_rlimit()) {
        return 1;
    }
    
    if (create_pin_dir(BPF_PIN_PATH)) {
        return 1;
    }
    
    /* Discovery phase */
    if (discover_modules(&ctx) < 0) {
        fprintf(stderr, "Module discovery failed\n");
        return 1;
    }
    
    /* Load core programs */
    if (load_core_programs(&ctx) < 0) {
        cleanup(&ctx);
        return 1;
    }
    
    /* Get map FDs */
    get_pinned_maps(&ctx);
    
    /* Load modules */
    if (load_modules(&ctx) < 0) {
        cleanup(&ctx);
        return 1;
    }
    
    /* Get rs_event_bus from pinned path (shared infrastructure) */
    ctx.rs_event_bus_fd = bpf_obj_get("/sys/fs/bpf/rs_event_bus");
    if (ctx.rs_event_bus_fd >= 0) {
        printf("Got unified event bus: fd=%d\n", ctx.rs_event_bus_fd);
    } else {
        fprintf(stderr, "Warning: Failed to open rs_event_bus (not critical)\n");
    }
    
    /* Get rs_mac_table from l2learn module (pinned by l2learn) */
    for (int i = 0; i < ctx.num_modules; i++) {
        if (strcmp(ctx.modules[i].name, "l2learn") == 0) {
            /* Try to get from pinned path first (preferred) */
            ctx.rs_mac_table_fd = bpf_obj_get("/sys/fs/bpf/rs_mac_table");
            if (ctx.rs_mac_table_fd >= 0) {
                printf("Got rs_mac_table from pinned path: fd=%d\n", ctx.rs_mac_table_fd);
            } else {
                /* Fallback: get from module object */
                struct bpf_map *map = bpf_object__find_map_by_name(ctx.modules[i].obj, "rs_mac_table");
                if (map) {
                    ctx.rs_mac_table_fd = bpf_map__fd(map);
                    printf("Got rs_mac_table from l2learn module: fd=%d\n", ctx.rs_mac_table_fd);
                }
            }
            break;
        }
    }
    
    /* Build tail-call pipeline */
    if (build_prog_array(&ctx) < 0) {
        cleanup(&ctx);
        return 1;
    }
    
    /* Configure ports */
    configure_ports(&ctx);
    
    /* Initialize VLAN map with default configuration */
    initialize_vlan_map(&ctx);
    
    /* Populate devmaps with queue isolation */
    populate_devmaps(&ctx);
    
    /* Attach XDP */
    if (attach_xdp(&ctx) < 0) {
        cleanup(&ctx);
        return 1;
    }
    
    printf("\nrSwitch running. Press Ctrl+C to exit.\n");
    
    /* Main loop */
    while (keep_running) {
        sleep(1);
    }
    
    /* Cleanup */
    cleanup(&ctx);
    
    return 0;
}
