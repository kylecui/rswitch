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
#include <sys/wait.h>
#include <sys/types.h>
#include <dirent.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "profile_parser.h"
#include "rs_log.h"
#include "../lifecycle/lifecycle.h"

extern int profile_load_with_inheritance(const char *path, struct rs_profile *profile) __attribute__((weak));

/* Copy necessary structure definitions (user-space safe versions) */
#define RS_ABI_VERSION_MAJOR 1
#define RS_ABI_VERSION_MINOR 0
#define RS_ABI_VERSION ((RS_ABI_VERSION_MAJOR << 16) | RS_ABI_VERSION_MINOR)
#define RS_ABI_VERSION_1 1
#define RS_ABI_MAJOR(v) ((v) >> 16)
#define RS_ABI_MINOR(v) ((v) & 0xFFFF)
#define RS_HOOK_XDP_INGRESS 0
#define RS_HOOK_XDP_EGRESS 1
#define RS_MAX_DEPS 4
#define RS_DEP_NAME_LEN 32

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

struct rs_module_deps {
    __u32 dep_count;
    char deps[RS_MAX_DEPS][RS_DEP_NAME_LEN];
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
    __u16 allowed_vlan_count;   /* MUST match BPF side: count before array */
    __u16 allowed_vlans[128];
    __u16 tagged_vlan_count;    /* For hybrid mode */
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

/* VLAN membership structure - MUST match bpf/core/map_defs.h */
struct rs_vlan_members {
    __u16 vlan_id;
    __u16 member_count;
    __u64 tagged_members[4];      /* Bitmask: ifindex -> bit position */
    __u64 untagged_members[4];    /* Bitmask: ifindex -> bit position */
    __u32 reserved[4];
};

#define RS_MODULE_CONFIG_KEY_LEN 32
#define RS_MODULE_CONFIG_VAL_LEN 64

struct rs_module_config_key {
    char module_name[RS_MODULE_CONFIG_KEY_LEN];
    char param_name[RS_MODULE_CONFIG_KEY_LEN];
};

struct rs_module_config_value {
    __u32 type;
    union {
        __s64 int_val;
        __u32 bool_val;
        char str_val[56];
    };
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
    struct rs_module_deps deps;
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
    int rs_prog_chain_fd;
    int rs_port_config_map_fd;
    int rs_ifindex_to_port_map_fd;
    int rs_devmap_fd;
    int rs_stats_map_fd;
    int rs_event_bus_fd;
    int rs_mac_table_fd;
    int rs_vlan_map_fd;
    int rs_module_config_map_fd;
    
    /* Configuration */
    __u32 interfaces[MAX_INTERFACES];
    int num_interfaces;
    __u32 xdp_flags;
    char mode[32];
    char profile_path[256];
    struct rs_profile profile;
    int use_profile;
    int verbose;
    
    /* VOQd process management */
    pid_t voqd_pid;         /* VOQd process ID (0 = not running) */
    int voqd_enabled;       /* VOQd should be started */
    
    /* Veth egress path */
    struct bpf_object *veth_egress_obj;
    struct bpf_program *veth_egress_prog;
    int veth_egress_fd;
    int voq_egress_devmap_fd;
    __u32 veth_out_ifindex;
    int veth_egress_enabled;
    
    __u32 mgmt_ifindex;
};

static volatile int keep_running = 1;
static volatile int shutdown_in_progress = 0;
static volatile sig_atomic_t shutdown_requested = 0;

static int profile_load_compat(const char *path, struct rs_profile *profile)
{
    if (profile_load_with_inheritance)
        return profile_load_with_inheritance(path, profile);
    return profile_load(path, profile);
}

static void handle_signal(int sig)
{
    (void)sig;
    shutdown_requested = 1;
}

/* Set RLIMIT_MEMLOCK to unlimited for BPF operations */
static int bump_memlock_rlimit(void)
{
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
        RS_LOG_ERROR("Failed to increase RLIMIT_MEMLOCK limit: %s",
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
            RS_LOG_ERROR("%s exists but is not a directory", path);
            return -1;
        }
        return 0;
    }
    
    if (mkdir(path, 0755) && errno != EEXIST) {
        RS_LOG_ERROR("Failed to create directory %s: %s",
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
        RS_LOG_ERROR("Failed to open %s: %s", path, strerror(-err));
        return -1;
    }
    
    /* Find .rodata.mod map (automatically created by libbpf for .rodata sections) */
    bpf_object__for_each_map(map, obj) {
        const char *map_name = bpf_map__name(map);
        if (strstr(map_name, ".rodata.mod")) {
            data = bpf_map__initial_value(map, &size);
            
            /* BTF might show size=0 for .rodata.mod, but data should be valid */
            if (!data) {
                RS_LOG_ERROR("No data in .rodata.mod section of %s", path);
                bpf_object__close(obj);
                return -1;
            }
            
            /* If size is 0 or less than expected, assume it's sizeof(rs_module_desc) */
            if (size == 0 || size < sizeof(*desc)) {
                size = sizeof(*desc);
            }
            
            memcpy(desc, data, sizeof(*desc));
            bpf_object__close(obj);
            
            {
                __u32 mod_major = RS_ABI_MAJOR(desc->abi_version);
                __u32 mod_minor = RS_ABI_MINOR(desc->abi_version);
                __u32 plat_major = RS_ABI_VERSION_MAJOR;
                __u32 plat_minor = RS_ABI_VERSION_MINOR;

                if (mod_major == 0 && desc->abi_version == RS_ABI_VERSION_1) {
                    mod_major = 1;
                    mod_minor = 0;
                }

                if (mod_major != plat_major) {
                    RS_LOG_ERROR("Module %s ABI major mismatch: platform %u.%u, module %u.%u (raw=%u)",
                                 path, plat_major, plat_minor, mod_major, mod_minor,
                                 desc->abi_version);
                    return -1;
                }

                if (mod_minor > plat_minor) {
                    RS_LOG_WARN("Module %s requires newer ABI minor: platform %u.%u, module %u.%u",
                                path, plat_major, plat_minor, mod_major, mod_minor);
                    return -1;
                }
            }
            
            return 0;
        }
    }
    
    bpf_object__close(obj);
    RS_LOG_WARN("No .rodata.mod section found in %s (not a module?)", path);
    return -1;
}

static int read_module_deps(const char *path, struct rs_module_deps *deps)
{
    struct bpf_object *obj;
    struct bpf_map *map;
    const void *data;
    size_t size;
    int err;

    memset(deps, 0, sizeof(*deps));

    obj = bpf_object__open(path);
    err = libbpf_get_error(obj);
    if (err) {
        RS_LOG_ERROR("Failed to open %s for dependency read: %s", path, strerror(-err));
        return -1;
    }

    bpf_object__for_each_map(map, obj) {
        const char *map_name = bpf_map__name(map);
        if (!strstr(map_name, ".rodata.moddep"))
            continue;

        data = bpf_map__initial_value(map, &size);
        if (!data) {
            RS_LOG_ERROR("No data in .rodata.moddep section of %s", path);
            bpf_object__close(obj);
            return -1;
        }

        if (size == 0 || size < sizeof(*deps))
            size = sizeof(*deps);

        memcpy(deps, data, sizeof(*deps));
        if (deps->dep_count > RS_MAX_DEPS)
            deps->dep_count = RS_MAX_DEPS;

        for (int i = 0; i < (int)deps->dep_count; i++)
            deps->deps[i][RS_DEP_NAME_LEN - 1] = '\0';

        bpf_object__close(obj);
        return 0;
    }

    bpf_object__close(obj);
    return 0;
}

/* Check if module is in profile's ingress or egress list */
static const struct rs_profile_module_entry *find_module_profile_entry(
    const struct rs_profile *profile, const char *module_name)
{
    if (!profile || (profile->ingress_count == 0 && profile->egress_count == 0)) {
        return NULL;
    }

    /* Check ingress modules */
    for (int i = 0; i < profile->ingress_count; i++) {
        if (strcmp(module_name, profile->ingress_modules[i].name) == 0) {
            return &profile->ingress_modules[i];
        }
    }

    /* Check egress modules */
    for (int i = 0; i < profile->egress_count; i++) {
        if (strcmp(module_name, profile->egress_modules[i].name) == 0) {
            return &profile->egress_modules[i];
        }
    }

    return NULL;
}

/* Check if module is in profile's ingress or egress list */
static int is_module_in_profile(const char *module_name, struct rs_profile *profile)
{
    if (!profile || (profile->ingress_count == 0 && profile->egress_count == 0)) {
        /* No profile - load all modules (backward compatibility) */
        return 1;
    }

    if (find_module_profile_entry(profile, module_name)) {
        return 1;
    }

    return 0;
}

static int evaluate_module_condition(const char *condition,
                                     const struct rs_profile_settings *settings)
{
    if (!condition || condition[0] == '\0') {
        return 1;
    }

    if (!settings) {
        return 1;
    }

    if (strcmp(condition, "debug_mode") == 0 || strcmp(condition, "debug") == 0) {
        return settings->debug;
    }
    if (strcmp(condition, "stats_enabled") == 0) {
        return settings->stats_enabled;
    }
    if (strcmp(condition, "ringbuf_enabled") == 0) {
        return settings->ringbuf_enabled;
    }
    if (strcmp(condition, "mac_learning") == 0) {
        return settings->mac_learning;
    }
    if (strcmp(condition, "vlan_enforcement") == 0) {
        return settings->vlan_enforcement;
    }

    RS_LOG_WARN("Unknown condition '%s' - loading module anyway", condition);
    return 1;
}

static int validate_stage_for_hook(const char *module_name, __u32 hook, int stage)
{
    if (hook == RS_HOOK_XDP_INGRESS) {
        if (stage < 10 || stage > 99) {
            RS_LOG_ERROR("Invalid ingress stage %d for module %s (valid range: 10-99)",
                         stage, module_name);
            return -1;
        }
    } else if (hook == RS_HOOK_XDP_EGRESS) {
        if (stage < 100 || stage > 199) {
            RS_LOG_ERROR("Invalid egress stage %d for module %s (valid range: 100-199)",
                         stage, module_name);
            return -1;
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
        RS_LOG_ERROR("Failed to open %s: %s", BUILD_DIR, strerror(errno));
        return -1;
    }
    
    while ((entry = readdir(dir)) != NULL && count < MAX_MODULES) {
        /* Skip non-BPF objects */
        if (!strstr(entry->d_name, ".bpf.o"))
            continue;
        
        /* Skip core programs (handled separately)
         * Note: egress_final is a MODULE, not core, so don't skip it
         * Only skip dispatcher.bpf.o and egress.bpf.o (core entry points)
         */
        if (strcmp(entry->d_name, "dispatcher.bpf.o") == 0 || 
            strcmp(entry->d_name, "egress.bpf.o") == 0)
            continue;
        
        snprintf(path, sizeof(path), "%s/%s", BUILD_DIR, entry->d_name);
        
        /* Try to read module metadata */
        struct rs_module_desc desc;
        if (read_module_metadata(path, &desc) == 0) {
            struct rs_module_deps deps = {};
            const struct rs_profile_module_entry *profile_entry = NULL;
            int effective_stage = desc.stage;

            if (read_module_deps(path, &deps) < 0) {
                RS_LOG_ERROR("Failed to read dependency metadata from %s", path);
                closedir(dir);
                return -1;
            }

            /* Check if module is in profile (if profile is used)
             * Exception: egress_final is infrastructure, always load it
             */
            if (ctx->use_profile && 
                strcmp(desc.name, "egress_final") != 0 &&
                !is_module_in_profile(desc.name, &ctx->profile)) {
                if (ctx->verbose) {
                    printf("Skipping module: %s (not in profile)\n", desc.name);
                }
                continue;
            }

            if (ctx->use_profile) {
                profile_entry = find_module_profile_entry(&ctx->profile, desc.name);

                if (profile_entry && profile_entry->optional) {
                    const char *condition = profile_entry->condition[0] != '\0' ?
                        profile_entry->condition : "(none)";
                    int condition_met = evaluate_module_condition(profile_entry->condition,
                                                                  &ctx->profile.settings);
                    if (!condition_met) {
                        RS_LOG_INFO("Skipping optional module %s (condition '%s' not met)",
                                    desc.name, condition);
                        continue;
                    }

                    RS_LOG_INFO("Loading optional module %s (condition '%s' met)",
                                desc.name, condition);
                }

                if (profile_entry && profile_entry->stage_override >= 0) {
                    effective_stage = profile_entry->stage_override;
                }
            }

            if (validate_stage_for_hook(desc.name, desc.hook, effective_stage) < 0) {
                closedir(dir);
                return -1;
            }

            for (int i = 0; i < count; i++) {
                if (ctx->modules[i].desc.hook == desc.hook &&
                    ctx->modules[i].stage == effective_stage) {
                    RS_LOG_ERROR("Stage conflict: modules %s and %s both use stage %d",
                                 ctx->modules[i].name, desc.name, effective_stage);
                    closedir(dir);
                    return -1;
                }
            }
            
            strncpy(ctx->modules[count].name, desc.name, sizeof(ctx->modules[count].name) - 1);
            strncpy(ctx->modules[count].path, path, sizeof(ctx->modules[count].path) - 1);
            memcpy(&ctx->modules[count].desc, &desc, sizeof(desc));
            memcpy(&ctx->modules[count].deps, &deps, sizeof(deps));
            ctx->modules[count].stage = effective_stage;
            
            if (ctx->verbose) {
                const int optional_module = profile_entry && profile_entry->optional;
                const char *condition = optional_module && profile_entry->condition[0] != '\0' ?
                    profile_entry->condition : "(none)";
                if (effective_stage != (int)desc.stage) {
                    if (optional_module) {
                        printf("Discovered module: %s (stage=%d override from %u, hook=%u, flags=0x%x) [optional, condition: %s]\n",
                               desc.name, effective_stage, desc.stage, desc.hook, desc.flags,
                               condition);
                    } else {
                        printf("Discovered module: %s (stage=%d override from %u, hook=%u, flags=0x%x)\n",
                               desc.name, effective_stage, desc.stage, desc.hook, desc.flags);
                    }
                } else {
                    if (optional_module) {
                        printf("Discovered module: %s (stage=%d, hook=%u, flags=0x%x) [optional, condition: %s]\n",
                               desc.name, effective_stage, desc.hook, desc.flags, condition);
                    } else {
                        printf("Discovered module: %s (stage=%d, hook=%u, flags=0x%x)\n",
                               desc.name, effective_stage, desc.hook, desc.flags);
                    }
                }

                if (ctx->modules[count].deps.dep_count > 0) {
                    printf("  Dependencies:");
                    for (int d = 0; d < (int)ctx->modules[count].deps.dep_count; d++) {
                        printf(" %s", ctx->modules[count].deps.deps[d]);
                    }
                    printf("\n");
                }
            }
            
            count++;
        }
    }
    
    closedir(dir);
    ctx->num_modules = count;
    
    printf("Discovered %d modules\n", count);
    return count;
}

static int validate_dependencies(struct loader_ctx *ctx)
{
    int edges[MAX_MODULES][MAX_MODULES] = {{0}};
    int indegree[MAX_MODULES] = {0};
    int queue[MAX_MODULES] = {0};
    int topo_order[MAX_MODULES] = {0};
    int num_edges = 0;
    int q_head = 0;
    int q_tail = 0;
    int topo_count = 0;

    for (int i = 0; i < ctx->num_modules; i++) {
        struct loaded_module *mod = &ctx->modules[i];

        if (mod->deps.dep_count > RS_MAX_DEPS) {
            RS_LOG_ERROR("Module %s declares too many dependencies (%u > %u)",
                         mod->name, mod->deps.dep_count, RS_MAX_DEPS);
            return -1;
        }

        for (int d = 0; d < (int)mod->deps.dep_count; d++) {
            const char *dep_name = mod->deps.deps[d];
            int dep_idx = -1;

            if (dep_name[0] == '\0') {
                RS_LOG_ERROR("Module %s has empty dependency at index %d", mod->name, d);
                return -1;
            }

            for (int j = 0; j < ctx->num_modules; j++) {
                if (strcmp(ctx->modules[j].name, dep_name) == 0) {
                    dep_idx = j;
                    break;
                }
            }

            if (dep_idx < 0) {
                RS_LOG_ERROR("Module %s requires %s, which is not loaded", mod->name, dep_name);
                return -1;
            }

            if (dep_idx == i) {
                RS_LOG_ERROR("Module %s cannot depend on itself", mod->name);
                return -1;
            }

            if (!edges[dep_idx][i]) {
                edges[dep_idx][i] = 1;
                indegree[i]++;
                num_edges++;
            }

            if (ctx->modules[dep_idx].stage >= mod->stage) {
                RS_LOG_WARN("Module %s depends on %s, but %s stage=%d and %s stage=%d",
                            mod->name, dep_name,
                            dep_name, ctx->modules[dep_idx].stage,
                            mod->name, mod->stage);
            }
        }
    }

    for (int i = 0; i < ctx->num_modules; i++) {
        if (indegree[i] == 0)
            queue[q_tail++] = i;
    }

    while (q_head < q_tail) {
        int u = queue[q_head++];
        topo_order[topo_count++] = u;

        for (int v = 0; v < ctx->num_modules; v++) {
            if (!edges[u][v])
                continue;
            indegree[v]--;
            if (indegree[v] == 0)
                queue[q_tail++] = v;
        }
    }

    if (topo_count != ctx->num_modules) {
        RS_LOG_ERROR("Dependency cycle detected across discovered modules");
        return -1;
    }

    if (ctx->verbose && num_edges > 0) {
        printf("Dependency order:");
        for (int i = 0; i < topo_count; i++)
            printf(" %s", ctx->modules[topo_order[i]].name);
        printf("\n");
    }

    for (int i = 0; i < ctx->num_modules; i++) {
        int has_incoming = 0;
        int has_outgoing = 0;

        if (strcmp(ctx->modules[i].name, "lastcall") == 0 ||
            strcmp(ctx->modules[i].name, "egress_final") == 0) {
            continue;
        }

        for (int j = 0; j < ctx->num_modules; j++) {
            if (edges[j][i])
                has_incoming = 1;
            if (edges[i][j])
                has_outgoing = 1;
        }

        if (!has_incoming && !has_outgoing) {
            RS_LOG_WARN("Module %s is not connected in dependency graph", ctx->modules[i].name);
        }
    }

    return 0;
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
    
    /* Open with pin_root_path so maps with LIBBPF_PIN_BY_NAME are auto-pinned
     * to /sys/fs/bpf/<map_name>. This is critical for mgmtd (separate process)
     * to access shared BPF maps via bpf_obj_get().
     */
    LIBBPF_OPTS(bpf_object_open_opts, opts,
        .pin_root_path = BPF_PIN_PATH,
    );
    
    /* Load dispatcher */
    snprintf(path, sizeof(path), "%s/dispatcher.bpf.o", BUILD_DIR);
    ctx->dispatcher_obj = bpf_object__open_file(path, &opts);
    err = libbpf_get_error(ctx->dispatcher_obj);
    if (err) {
        RS_LOG_ERROR("Failed to open dispatcher: %s", strerror(-err));
        return -1;
    }
    
    err = bpf_object__load(ctx->dispatcher_obj);
    if (err) {
        RS_LOG_ERROR("Failed to load dispatcher: %s", strerror(-err));
        return -1;
    }
    
    ctx->dispatcher_prog = bpf_object__find_program_by_name(ctx->dispatcher_obj, 
                                                             "rswitch_dispatcher");
    if (!ctx->dispatcher_prog) {
        RS_LOG_ERROR("Failed to find rswitch_dispatcher program");
        return -1;
    }
    
    ctx->dispatcher_fd = bpf_program__fd(ctx->dispatcher_prog);
    if (ctx->dispatcher_fd < 0) {
        RS_LOG_ERROR("Failed to get dispatcher FD");
        return -1;
    }
    
    /* Load egress (same opts — reuses already-pinned maps) */
    snprintf(path, sizeof(path), "%s/egress.bpf.o", BUILD_DIR);
    ctx->egress_obj = bpf_object__open_file(path, &opts);
    err = libbpf_get_error(ctx->egress_obj);
    if (err) {
        RS_LOG_ERROR("Failed to open egress: %s", strerror(-err));
        return -1;
    }
    
    err = bpf_object__load(ctx->egress_obj);
    if (err) {
        RS_LOG_ERROR("Failed to load egress: %s", strerror(-err));
        return -1;
    }
    
    ctx->egress_prog = bpf_object__find_program_by_name(ctx->egress_obj, 
                                                         "rswitch_egress");
    if (!ctx->egress_prog) {
        RS_LOG_ERROR("Failed to find rswitch_egress program");
        return -1;
    }
    
    ctx->egress_fd = bpf_program__fd(ctx->egress_prog);
    if (ctx->egress_fd < 0) {
        RS_LOG_ERROR("Failed to get egress FD");
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
    ctx->rs_prog_chain_fd = bpf_obj_get("/sys/fs/bpf/rs_prog_chain");
    
    /* Port config map - may or may not be pinned */
    snprintf(path, sizeof(path), "%s/rs_port_config_map", BPF_PIN_PATH);
    ctx->rs_port_config_map_fd = bpf_obj_get(path);

#ifdef LASTCALL_MANUAL_BROADCAST
    snprintf(path, sizeof(path), "%s/rs_devmap", BPF_PIN_PATH);
#else    
    snprintf(path, sizeof(path), "%s/rs_xdp_devmap", BPF_PIN_PATH);    
#endif
    ctx->rs_devmap_fd = bpf_obj_get(path);
    
    /* Ifindex to port index mapping */
    snprintf(path, sizeof(path), "%s/rs_ifindex_to_port_map", BPF_PIN_PATH);
    ctx->rs_ifindex_to_port_map_fd = bpf_obj_get(path);
    if (ctx->rs_ifindex_to_port_map_fd < 0) {
        /* Try to get from dispatcher object */
        struct bpf_map *map = bpf_object__find_map_by_name(ctx->dispatcher_obj, "rs_ifindex_to_port_map");
        if (map) {
            ctx->rs_ifindex_to_port_map_fd = bpf_map__fd(map);
        }
    }
    
    snprintf(path, sizeof(path), "%s/rs_stats_map", BPF_PIN_PATH);
    ctx->rs_stats_map_fd = bpf_obj_get(path);
    
    snprintf(path, sizeof(path), "%s/rs_event_bus", BPF_PIN_PATH);
    ctx->rs_event_bus_fd = bpf_obj_get(path);
    
    snprintf(path, sizeof(path), "%s/rs_vlan_map", BPF_PIN_PATH);
    ctx->rs_vlan_map_fd = bpf_obj_get(path);

    snprintf(path, sizeof(path), "%s/rs_module_config_map", BPF_PIN_PATH);
    ctx->rs_module_config_map_fd = bpf_obj_get(path);
    
    if (ctx->rs_progs_fd < 0) {
        RS_LOG_WARN("Failed to get rs_progs from /sys/fs/bpf/rs_progs");
        /* Try to get from dispatcher object */
        struct bpf_map *map = bpf_object__find_map_by_name(ctx->dispatcher_obj, "rs_progs");
        if (map) {
            ctx->rs_progs_fd = bpf_map__fd(map);
            printf("Got rs_progs from dispatcher object: fd=%d\n", ctx->rs_progs_fd);
        }
    }
    
    if (ctx->rs_prog_chain_fd < 0) {
        struct bpf_map *map = bpf_object__find_map_by_name(ctx->dispatcher_obj, "rs_prog_chain");
        if (map) {
            ctx->rs_prog_chain_fd = bpf_map__fd(map);
            printf("Got rs_prog_chain from dispatcher object: fd=%d\n", ctx->rs_prog_chain_fd);
        }
    }
    
    if (ctx->rs_port_config_map_fd < 0) {
        struct bpf_map *map = bpf_object__find_map_by_name(ctx->dispatcher_obj, "rs_port_config_map");
        if (map) {
            ctx->rs_port_config_map_fd = bpf_map__fd(map);
        }
    }
    
    if (ctx->rs_event_bus_fd < 0) {
        struct bpf_map *map = bpf_object__find_map_by_name(ctx->dispatcher_obj, "rs_event_bus");
        if (map) {
            ctx->rs_event_bus_fd = bpf_map__fd(map);
        }
    }
    
    if (ctx->rs_vlan_map_fd < 0) {
        struct bpf_map *map = bpf_object__find_map_by_name(ctx->dispatcher_obj, "rs_vlan_map");
        if (map) {
            ctx->rs_vlan_map_fd = bpf_map__fd(map);
        }
    }

    if (ctx->rs_module_config_map_fd < 0) {
        struct bpf_map *map = bpf_object__find_map_by_name(ctx->dispatcher_obj, "rs_module_config_map");
        if (map) {
            ctx->rs_module_config_map_fd = bpf_map__fd(map);
        }
    }
    
    if (ctx->rs_stats_map_fd < 0) {
        struct bpf_map *map = bpf_object__find_map_by_name(ctx->dispatcher_obj, "rs_stats_map");
        if (map) {
            ctx->rs_stats_map_fd = bpf_map__fd(map);
        }
    }
    
    printf("Map FDs: rs_progs=%d, port_config=%d, ctx=%d, chain=%d, event_bus=%d, vlan=%d, module_cfg=%d, stats=%d, devmap=%d\n",
           ctx->rs_progs_fd, ctx->rs_port_config_map_fd, ctx->rs_ctx_map_fd, 
           ctx->rs_prog_chain_fd, ctx->rs_event_bus_fd, ctx->rs_vlan_map_fd,
           ctx->rs_module_config_map_fd,
           ctx->rs_stats_map_fd, ctx->rs_devmap_fd);
    
    return 0;
}

/* Helper: Reuse shared maps in a BPF object before loading
 * 
 * CRITICAL: This must be called after bpf_object__open_file() but BEFORE bpf_object__load()!
 * 
 * Maps with LIBBPF_PIN_BY_NAME in BPF source are pinned by the dispatcher when it loads.
 * However, subsequent module loads create NEW map instances instead of reusing pinned ones.
 * 
 * The fix: For each shared map, we:
 * 1. Call bpf_map__set_autocreate(map, false) to prevent creating a new instance
 * 2. Call bpf_map__reuse_fd(map, fd) with the FD from the already-pinned map
 * 
 * This ensures all modules share the SAME map instances as the dispatcher.
 */
static int reuse_shared_maps(struct bpf_object *obj, struct loader_ctx *ctx)
{
    struct bpf_map *map;
    int err;
    const char *names_to_reuse[] = {
        "rs_ctx_map", "rs_progs", "rs_prog_chain", "rs_port_config_map",
        "rs_ifindex_to_port_map", "rs_stats_map", "rs_event_bus", 
        "rs_vlan_map", "rs_module_config_map", "rs_devmap", "rs_xdp_devmap"
    };
    int fds_to_reuse[] = {
        ctx->rs_ctx_map_fd, ctx->rs_progs_fd, ctx->rs_prog_chain_fd, 
        ctx->rs_port_config_map_fd, ctx->rs_ifindex_to_port_map_fd, 
        ctx->rs_stats_map_fd, ctx->rs_event_bus_fd, ctx->rs_vlan_map_fd,
        ctx->rs_module_config_map_fd, ctx->rs_devmap_fd, ctx->rs_devmap_fd
    };
    int num_maps = sizeof(names_to_reuse) / sizeof(names_to_reuse[0]);
    
    for (int i = 0; i < num_maps; i++) {
        if (fds_to_reuse[i] <= 0)
            continue;
            
        map = bpf_object__find_map_by_name(obj, names_to_reuse[i]);
        if (!map)
            continue;
        
        err = bpf_map__reuse_fd(map, fds_to_reuse[i]);
        if (err) {
            RS_LOG_WARN("reuse_fd failed for %s (fd=%d): %s",
                        names_to_reuse[i], fds_to_reuse[i], strerror(-err));
            continue;
        }
        
        RS_LOG_DEBUG("Reusing %s with fd=%d (map_fd after=%d)",
                     names_to_reuse[i], fds_to_reuse[i], bpf_map__fd(map));
    }
    
    return 0;
}

/* Load module BPF objects and get program FDs */
static int load_modules(struct loader_ctx *ctx)
{
    int i, err;
    
    for (i = 0; i < ctx->num_modules; i++) {
        struct loaded_module *mod = &ctx->modules[i];
        
        /* Open BPF object with pin_root_path so LIBBPF_PIN_BY_NAME maps are reused */
        LIBBPF_OPTS(bpf_object_open_opts, opts,
            .pin_root_path = "/sys/fs/bpf",
        );
        mod->obj = bpf_object__open_file(mod->path, &opts);
        err = libbpf_get_error(mod->obj);
        if (err) {
            RS_LOG_ERROR("Failed to open module %s: %s",
                         mod->name, strerror(-err));
            continue;
        }
        
        /* CRITICAL: Reuse shared maps BEFORE loading!
         * Without this, each module creates its own copies of rs_ctx_map, rs_progs, etc.
         * which breaks the tail-call pipeline since modules aren't in the dispatcher's prog_array.
         */
        RS_LOG_DEBUG("[%s] Calling reuse_shared_maps", mod->name);
        err = reuse_shared_maps(mod->obj, ctx);
        if (err) {
            RS_LOG_WARN("Failed to reuse shared maps for %s", mod->name);
            /* Continue anyway - module may work with its own maps */
        }
        
        /* Load BPF object */
        err = bpf_object__load(mod->obj);
        if (err) {
            RS_LOG_ERROR("Failed to load module %s: %s",
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
            RS_LOG_ERROR("Failed to find XDP program in module %s", mod->name);
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
        RS_LOG_ERROR("rs_progs map FD not available");
        return -1;
    }
    
    /* Sort modules by stage number */
    qsort(ctx->modules, ctx->num_modules, sizeof(struct loaded_module), compare_modules);
    
    printf("\nBuilding tail-call pipeline:\n");
    
    /* Build separate pipelines for ingress and egress 
     * 
     * CRITICAL: Ingress and egress MUST use different prog_array slots!
     * Following PoC pattern (attached loader lines 583-585):
     * - Ingress: slots 0, 1, 2, ... (low slots, forward)
     * - Egress: slots 255, 254, 253, ... (high slots, backward to avoid collision)
     * 
     * prog_chain map usage:
     * - Ingress modules: chain[slot] points to next ingress slot
     * - Egress modules: chain[slot] points to next egress slot
     * - Devmap entry: chain[0] = first egress slot (e.g., 255)
     * 
     * Why this works:
     * - rs_progs[0..N] = ingress programs
     * - rs_progs[255..255-M] = egress programs
     * - NO overlap between ingress and egress slots
     */
    int ingress_idx = 0;
    int egress_slot = 255;  /* Start from high end, go downward */
    int ingress_count = 0, egress_count = 0;
    int first_egress_prog_idx = -1;
    
    /* Pass 1: Insert ingress modules */
    for (i = 0; i < ctx->num_modules; i++) {
        struct loaded_module *mod = &ctx->modules[i];
        
        if (!mod->obj || mod->prog_fd < 0)
            continue;
        
        if (mod->desc.hook != RS_HOOK_XDP_INGRESS)
            continue;  /* Skip egress modules in this pass */
        
        /* Insert into prog_array at ingress_idx */
        err = bpf_map_update_elem(ctx->rs_progs_fd, &ingress_idx, &mod->prog_fd, BPF_ANY);
        if (err) {
            RS_LOG_ERROR("Failed to insert %s into prog_array[%u]: %s",
                         mod->name, ingress_idx, strerror(errno));
            return -1;
        }
        
        /* Build chain: find next ingress module */
        int next_ingress_idx = -1;
        for (int j = i + 1; j < ctx->num_modules; j++) {
            if (ctx->modules[j].desc.hook == RS_HOOK_XDP_INGRESS && 
                ctx->modules[j].prog_fd >= 0) {
                next_ingress_idx = ingress_idx + 1;
                break;
            }
        }
        
        if (next_ingress_idx >= 0) {
            /* Not last ingress module */
            err = bpf_map_update_elem(ctx->rs_prog_chain_fd, &ingress_idx, &next_ingress_idx, BPF_ANY);
            if (err) {
                RS_LOG_ERROR("Failed to set prog_chain[%u]=%u: %s",
                             ingress_idx, next_ingress_idx, strerror(errno));
                return -1;
            }
            printf("  [%3u] stage=%3u hook=ingress: %s (fd=%d) → next=%u\n", 
                   ingress_idx, mod->stage, mod->name, mod->prog_fd, next_ingress_idx);
        } else {
            /* Last ingress module */
            printf("  [%3u] stage=%3u hook=ingress: %s (fd=%d) [LAST]\n", 
                   ingress_idx, mod->stage, mod->name, mod->prog_fd);
        }
        
        ingress_idx++;
        ingress_count++;
    }
    
    /* Pass 2: Insert egress modules (from high slots downward) */
    for (i = 0; i < ctx->num_modules; i++) {
        struct loaded_module *mod = &ctx->modules[i];
        
        if (!mod->obj || mod->prog_fd < 0)
            continue;
        
        if (mod->desc.hook != RS_HOOK_XDP_EGRESS)
            continue;  /* Skip ingress modules in this pass */
        
        /* Insert into prog_array at egress_slot (255, 254, 253, ...) */
        err = bpf_map_update_elem(ctx->rs_progs_fd, &egress_slot, &mod->prog_fd, BPF_ANY);
        if (err) {
            RS_LOG_ERROR("Failed to insert %s into prog_array[%u]: %s",
                         mod->name, egress_slot, strerror(errno));
            return -1;
        }
        
        /* Remember first egress module's slot for devmap hook entry point */
        if (first_egress_prog_idx < 0) {
            first_egress_prog_idx = egress_slot;  /* 255 for first egress module */
        }
        
        /* Build chain: find next egress module and calculate its slot
         * Next module will be at (current_slot - 1) because we're counting down
         */
        int next_egress_slot = -1;
        int next_egress_count = 0;
        
        for (int j = i + 1; j < ctx->num_modules; j++) {
            if (ctx->modules[j].desc.hook == RS_HOOK_XDP_EGRESS && 
                ctx->modules[j].prog_fd >= 0) {
                next_egress_count++;
                if (next_egress_count == 1) {
                    /* Found immediate next egress module - it will be at slot-1 */
                    next_egress_slot = egress_slot - 1;
                    break;
                }
            }
        }
        
        if (next_egress_slot >= 0) {
            /* Not last egress module - link to next */
            err = bpf_map_update_elem(ctx->rs_prog_chain_fd, &egress_slot, &next_egress_slot, BPF_ANY);
            if (err) {
                RS_LOG_ERROR("Failed to set prog_chain[%u]=%u: %s",
                             egress_slot, next_egress_slot, strerror(errno));
                return -1;
            }
            printf("  [%3u] stage=%3u hook=egress : %s (fd=%d) → next=%u\n", 
                   egress_slot, mod->stage, mod->name, mod->prog_fd, next_egress_slot);
        } else {
            /* Last egress module */
            printf("  [%3u] stage=%3u hook=egress : %s (fd=%d) [LAST]\n", 
                   egress_slot, mod->stage, mod->name, mod->prog_fd);
        }
        
        egress_slot--;  /* Move to next lower slot for next module */
        egress_count++;
    }
    
    /* Set devmap egress entry point (prog_chain[0] = first egress module)
     * 
     * CRITICAL: Devmap egress hook (egress.bpf.c) reads prog_chain[RS_ONLYKEY=0]
     * to get the first egress module FD for tail-calling.
     */
    if (first_egress_prog_idx >= 0) {
        int key = 0;  /* RS_ONLYKEY - devmap egress uses key 0 */
        err = bpf_map_update_elem(ctx->rs_prog_chain_fd, &key, &first_egress_prog_idx, BPF_ANY);
        if (err) {
            RS_LOG_ERROR("Failed to set egress entry point prog_chain[0]=%u: %s",
                         first_egress_prog_idx, strerror(errno));
            return -1;
        }
        printf("\nEgress entry point: prog_chain[0] = %u (devmap→first egress module)\n",
               first_egress_prog_idx);
    }
    
    printf("\nPipeline built: %u ingress + %u egress modules\n", 
           ingress_count, egress_count);
    return 0;
}

/* Configure port settings via rs_port_config_map */
static int configure_ports(struct loader_ctx *ctx)
{
    int i, err;
    
    if (ctx->rs_port_config_map_fd < 0) {
        RS_LOG_WARN("port_config_map not available, skipping config");
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
                RS_LOG_WARN("Interface %s not found, skipping", pport->interface);
                continue;
            }
            
            /* Create ifindex -> port_idx mapping (consecutive 0-based indices) */
            __u32 port_idx = i;  /* Use array index as port_idx */
            err = bpf_map_update_elem(ctx->rs_ifindex_to_port_map_fd, &ifindex, &port_idx, BPF_ANY);
            if (err) {
                RS_LOG_WARN("Failed to create ifindex->port_idx mapping for %s: %s",
                            pport->interface, strerror(errno));
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
                .allowed_vlan_count = pport->allowed_vlan_count,
            };
            
            /* Copy allowed VLANs */
            if (ctx->verbose) {
                RS_LOG_DEBUG("configure_ports() port=%s, allowed_vlan_count=%d",
                             pport->interface, pport->allowed_vlan_count);
                char vlan_buf[256] = "";
                int pos = 0;
                for (int j = 0; j < pport->allowed_vlan_count && j < 10; j++) {
                    pos += snprintf(vlan_buf + pos, sizeof(vlan_buf) - pos, "%d%s",
                                    pport->allowed_vlans[j],
                                    j < pport->allowed_vlan_count - 1 ? ", " : "");
                }
                RS_LOG_DEBUG("allowed_vlans=[%s]", vlan_buf);
            }
            
            for (int j = 0; j < pport->allowed_vlan_count && j < 128; j++) {
                cfg.allowed_vlans[j] = pport->allowed_vlans[j];
            }
            
            err = bpf_map_update_elem(ctx->rs_port_config_map_fd, &ifindex, &cfg, BPF_ANY);
            if (err) {
                RS_LOG_ERROR("Failed to configure port %s: %s",
                             pport->interface, strerror(errno));
                continue;
            }
            
            const char *mode_str[] = {"OFF", "ACCESS", "TRUNK", "HYBRID"};
            printf("  Port %u (%s) -> port_idx %u: mode=%s", ifindex, pport->interface, port_idx, 
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
        
        /* Create ifindex -> port_idx mapping (consecutive 0-based indices) */
        __u32 port_idx = i;  /* Use array index as port_idx */
        err = bpf_map_update_elem(ctx->rs_ifindex_to_port_map_fd, &ifindex, &port_idx, BPF_ANY);
        if (err) {
            RS_LOG_WARN("Failed to create ifindex->port_idx mapping for ifindex %u: %s",
                        ifindex, strerror(errno));
        }
        
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
            RS_LOG_ERROR("Failed to configure port %u: %s",
                         ifindex, strerror(errno));
            continue;
        }
        
        char ifname[IF_NAMESIZE];
        if_indextoname(ifindex, ifname);
        
        const char *mode_str[] = {"OFF", "ACCESS", "TRUNK", "HYBRID"};
        printf("  Port %u (%s) -> port_idx %u: mode=%s, vlan=%d, learning=%s\n", 
               ifindex, ifname, port_idx, mode_str[vlan_mode], default_vlan,
               cfg.learning ? "on" : "off");
    }
    
    return 0;
}

static int parse_int64_value(const char *str, __s64 *out)
{
    char *end = NULL;
    long long parsed;

    if (!str || !out || str[0] == '\0')
        return 0;

    errno = 0;
    parsed = strtoll(str, &end, 10);
    if (errno != 0 || end == str || *end != '\0')
        return 0;

    *out = (__s64)parsed;
    return 1;
}

static int write_module_configs(struct loader_ctx *ctx)
{
    int map_fd;

    map_fd = bpf_obj_get("/sys/fs/bpf/rs_module_config_map");
    if (map_fd < 0) {
        RS_LOG_WARN("Module config map unavailable, skipping module config write");
        return 0;
    }

    for (int i = 0; i < ctx->num_modules; i++) {
        const struct rs_profile_module_entry *entry;

        entry = find_module_profile_entry(&ctx->profile, ctx->modules[i].name);
        if (!entry || entry->config_count <= 0)
            continue;

        for (int j = 0; j < entry->config_count; j++) {
            struct rs_module_config_key key = {};
            struct rs_module_config_value val = {};
            const char *cfg_value = entry->config[j].value;
            __s64 int_value = 0;
            int err;

            strncpy(key.module_name, ctx->modules[i].name, sizeof(key.module_name) - 1);
            strncpy(key.param_name, entry->config[j].key, sizeof(key.param_name) - 1);

            if (strcmp(cfg_value, "true") == 0 || strcmp(cfg_value, "false") == 0) {
                val.type = 1;
                val.bool_val = (strcmp(cfg_value, "true") == 0) ? 1 : 0;
            } else if (parse_int64_value(cfg_value, &int_value)) {
                val.type = 0;
                val.int_val = int_value;
            } else {
                val.type = 2;
                strncpy(val.str_val, cfg_value, sizeof(val.str_val) - 1);
            }

            err = bpf_map_update_elem(map_fd, &key, &val, BPF_ANY);
            if (err) {
                RS_LOG_WARN("Failed to write module config %s.%s: %s",
                            key.module_name,
                            key.param_name,
                            strerror(errno));
            }
        }
    }

    close(map_fd);
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
                    RS_LOG_WARN("Tagged port %s not found", pvlan->tagged_ports[j]);
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
                    RS_LOG_WARN("Untagged port %s not found", pvlan->untagged_ports[j]);
                    continue;
                }
                
                __u32 word_idx = ((ifindex - 1) / 64) & 3;
                __u64 bit_mask = 1ULL << ((ifindex - 1) % 64);
                vlan.untagged_members[word_idx] |= bit_mask;
            }
            
            __u16 vlan_id = pvlan->vlan_id;
            err = bpf_map_update_elem(vlan_map_fd, &vlan_id, &vlan, BPF_ANY);
            if (err) {
                RS_LOG_ERROR("Failed to create VLAN %d: %s", vlan_id, strerror(errno));
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
        RS_LOG_ERROR("Failed to create default VLAN 1: %s", strerror(errno));
        return -1;
    }
    
    printf("  VLAN 1: %u ports (default untagged)\n", ctx->num_interfaces);
    return 0;
}

/* Initialize QoS configuration maps
 * 
 * CRITICAL: QoS module checks QOS_FLAG_ENABLED in qos_config_ext_map.
 * Without this initialization, QoS will be disabled and all packets pass through.
 */
static int initialize_qos_config(struct loader_ctx *ctx)
{
    int err;
    char path[256];
    int qos_config_ext_fd = -1;
    int qos_config_fd = -1;
    
    /* Try to open qos_config_ext_map (pinned by egress_qos module) */
    snprintf(path, sizeof(path), "%s/qos_config_ext_map", BPF_PIN_PATH);
    qos_config_ext_fd = bpf_obj_get(path);
    
    if (qos_config_ext_fd < 0) {
        /* QoS module not loaded, skip initialization */
        if (ctx->verbose) {
            printf("QoS config: egress_qos module not loaded, skipping\n");
        }
        return 0;
    }
    
    /* Try to open qos_config_map (shared with afxdp_redirect) */
    snprintf(path, sizeof(path), "%s/qos_config_map", BPF_PIN_PATH);
    qos_config_fd = bpf_obj_get(path);
    
    printf("Initializing QoS configuration:\n");
    
    /* Initialize qos_config_ext (local to egress_qos) */
    struct qos_config_ext {
        __u32 flags;
        __u8  default_priority;
        __u8  pad[3];
        __u8  dscp_map[4];  /* QOS_MAX_PRIORITIES = 4 */
    } __attribute__((aligned(8)));
    
    struct qos_config_ext cfg_ext = {
        .flags = (1 << 0),  /* QOS_FLAG_ENABLED */
        .default_priority = 1,  /* NORMAL priority for unclassified */
        .dscp_map = {10, 18, 34, 46},  /* LOW=AF11, NORMAL=AF21, HIGH=AF41, CRITICAL=EF */
    };
    
    /* Check if profile overrides QoS settings */
    if (ctx->use_profile) {
        /* Enable rate limiting if configured */
        if (ctx->profile.settings.stats_enabled) {
            cfg_ext.flags |= (1 << 1);  /* QOS_FLAG_RATE_LIMIT_ENABLED */
        }
        /* Enable ECN marking (recommended for production) */
        cfg_ext.flags |= (1 << 2);  /* QOS_FLAG_ECN_ENABLED */
        /* Enable DSCP rewriting (standard behavior) */
        cfg_ext.flags |= (1 << 3);  /* QOS_FLAG_DSCP_REWRITE */
    }
    
    __u32 key = 0;
    err = bpf_map_update_elem(qos_config_ext_fd, &key, &cfg_ext, BPF_ANY);
    if (err) {
        RS_LOG_ERROR("Failed to initialize qos_config_ext_map: %s", strerror(errno));
        close(qos_config_ext_fd);
        if (qos_config_fd >= 0) close(qos_config_fd);
        return -1;
    }
    
    printf("  ✓ QoS enabled (flags=0x%x)\n", cfg_ext.flags);
    printf("  ✓ Default priority: NORMAL\n");
    printf("  ✓ DSCP marking: LOW=%u, NORMAL=%u, HIGH=%u, CRITICAL=%u\n",
           cfg_ext.dscp_map[0], cfg_ext.dscp_map[1], cfg_ext.dscp_map[2], cfg_ext.dscp_map[3]);
    
    /* Initialize qos_config (shared with afxdp_redirect) */
    if (qos_config_fd >= 0) {
        struct qos_config {
            __u32 dscp2prio[64];
            __u32 default_port;
            __u32 ecn_threshold;
            __u32 drop_threshold;
        } __attribute__((aligned(8)));
        
        struct qos_config cfg = {
            .default_port = 0,
            .ecn_threshold = 100,   /* ECN marking at 100 packets queue depth */
            .drop_threshold = 200,  /* Drop low-priority at 200 packets */
        };
        
        /* Initialize DSCP->priority mapping (default: DSCP value >> 3 maps to priority) */
        for (int i = 0; i < 64; i++) {
            /* Standard DiffServ mapping:
             * EF (46) -> CRITICAL (3)
             * AF4x (32-38) -> HIGH (2)
             * AF2x (16-22) -> NORMAL (1)
             * AF1x (8-14) -> LOW (0)
             * Default (0) -> NORMAL (1)
             */
            if (i == 46) {  /* EF */
                cfg.dscp2prio[i] = 3;  /* CRITICAL */
            } else if (i >= 32 && i <= 38) {  /* AF4x */
                cfg.dscp2prio[i] = 2;  /* HIGH */
            } else if (i >= 16 && i <= 22) {  /* AF2x */
                cfg.dscp2prio[i] = 1;  /* NORMAL */
            } else if (i >= 8 && i <= 14) {  /* AF1x */
                cfg.dscp2prio[i] = 0;  /* LOW */
            } else {
                cfg.dscp2prio[i] = 1;  /* NORMAL (default) */
            }
        }
        
        err = bpf_map_update_elem(qos_config_fd, &key, &cfg, BPF_ANY);
        if (err) {
            RS_LOG_WARN("Failed to initialize qos_config_map: %s", strerror(errno));
        } else {
            printf("  ✓ DSCP->priority mapping initialized\n");
            printf("  ✓ ECN threshold: %u packets\n", cfg.ecn_threshold);
            printf("  ✓ Drop threshold: %u packets\n", cfg.drop_threshold);
        }
        
        close(qos_config_fd);
    }
    
    close(qos_config_ext_fd);
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
        RS_LOG_WARN("Egress program not loaded - VLAN isolation will NOT work!");
    }
    
    /* Find rs_xdp_devmap from lastcall module (owner)
     * Following PoC: loader finds egress_map from lastcall object
     */
    for (i = 0; i < ctx->num_modules; i++) {
        if (strcmp(ctx->modules[i].name, "lastcall") == 0 && ctx->modules[i].obj) {
            struct bpf_map *map = bpf_object__find_map_by_name(ctx->modules[i].obj, "rs_xdp_devmap");
            if (map) {
                xdp_devmap_fd = bpf_map__fd(map);
                printf("Found rs_xdp_devmap in lastcall module: fd=%d\n", xdp_devmap_fd);
                /* Update context for consistency */
                ctx->rs_devmap_fd = xdp_devmap_fd;
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
        RS_LOG_WARN("No devmaps found, skipping devmap population");
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
                RS_LOG_WARN("Failed to add %s to XDP devmap: %s",
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
                RS_LOG_WARN("Failed to add %s to AF_XDP devmap: %s",
                            ifname, strerror(errno));
            } else {
                printf("  AF_XDP devmap: %s (ifindex=%u)\n", ifname, ifindex);
            }
        }
    }
    
    printf("Queue isolation framework enabled (use setup_nic_queues.sh for IRQ affinity)\n");
    return 0;
}

static int setup_veth_egress(struct loader_ctx *ctx)
{
    char path[256];
    int err;
    
    if (!ctx->veth_egress_enabled)
        return 0;
    
    ctx->veth_out_ifindex = if_nametoindex("veth_voq_out");
    if (ctx->veth_out_ifindex == 0) {
        RS_LOG_WARN("veth_voq_out not found. Run setup_veth_egress.sh first.");
        ctx->veth_egress_enabled = 0;
        return 0;
    }
    
    snprintf(path, sizeof(path), "%s/veth_egress.bpf.o", BUILD_DIR);
    ctx->veth_egress_obj = bpf_object__open(path);
    err = libbpf_get_error(ctx->veth_egress_obj);
    if (err) {
        RS_LOG_WARN("Failed to open veth_egress.bpf.o: %s", strerror(-err));
        ctx->veth_egress_enabled = 0;
        return 0;
    }
    
    err = bpf_object__load(ctx->veth_egress_obj);
    if (err) {
        RS_LOG_WARN("Failed to load veth_egress.bpf.o: %s", strerror(-err));
        bpf_object__close(ctx->veth_egress_obj);
        ctx->veth_egress_obj = NULL;
        ctx->veth_egress_enabled = 0;
        return 0;
    }
    
    ctx->veth_egress_prog = bpf_object__find_program_by_name(ctx->veth_egress_obj,
                                                             "veth_egress_redirect");
    if (!ctx->veth_egress_prog) {
        RS_LOG_WARN("veth_egress_redirect program not found");
        bpf_object__close(ctx->veth_egress_obj);
        ctx->veth_egress_obj = NULL;
        ctx->veth_egress_enabled = 0;
        return 0;
    }
    
    ctx->veth_egress_fd = bpf_program__fd(ctx->veth_egress_prog);
    
    struct bpf_map *devmap = bpf_object__find_map_by_name(ctx->veth_egress_obj, "voq_egress_devmap");
    if (devmap) {
        ctx->voq_egress_devmap_fd = bpf_map__fd(devmap);
    }
    
    struct bpf_map *config_map = bpf_object__find_map_by_name(ctx->veth_egress_obj, "veth_egress_config_map");
    if (config_map) {
        int config_fd = bpf_map__fd(config_map);
        struct {
            __u32 enabled;
            __u32 veth_out_ifindex;
            __u32 default_egress_if;
            __u32 flags;
        } config = {
            .enabled = 1,
            .veth_out_ifindex = ctx->veth_out_ifindex,
            .default_egress_if = ctx->num_interfaces > 0 ? ctx->interfaces[0] : 0,
            .flags = 0,
        };
        __u32 key = 0;
        bpf_map_update_elem(config_fd, &key, &config, BPF_ANY);
    }
    
    if (ctx->voq_egress_devmap_fd >= 0 && ctx->egress_fd >= 0) {
        for (int i = 0; i < ctx->num_interfaces; i++) {
            __u32 ifindex = ctx->interfaces[i];
            struct bpf_devmap_val val = {
                .ifindex = ifindex,
                .bpf_prog.fd = ctx->egress_fd,
            };
            err = bpf_map_update_elem(ctx->voq_egress_devmap_fd, &ifindex, &val, BPF_ANY);
            if (err) {
                char ifname[IF_NAMESIZE];
                if_indextoname(ifindex, ifname);
                RS_LOG_WARN("Failed to add %s to voq_egress_devmap: %s",
                            ifname, strerror(errno));
            }
        }
    }
    
    LIBBPF_OPTS(bpf_xdp_attach_opts, opts);
    err = bpf_xdp_attach(ctx->veth_out_ifindex, ctx->veth_egress_fd,
                         XDP_FLAGS_DRV_MODE, &opts);
    if (err) {
        err = bpf_xdp_attach(ctx->veth_out_ifindex, ctx->veth_egress_fd,
                             XDP_FLAGS_SKB_MODE, &opts);
        if (err) {
            RS_LOG_WARN("Failed to attach XDP to veth_voq_out: %s",
                        strerror(-err));
            ctx->veth_egress_enabled = 0;
            return 0;
        }
        printf("Veth egress: attached to veth_voq_out (generic mode)\n");
    } else {
        printf("Veth egress: attached to veth_voq_out (native mode)\n");
    }
    
    printf("Veth egress path enabled: VOQd TX -> veth -> XDP -> physical NIC\n");
    return 0;
}

static int prepare_interface(const char *ifname);

static int setup_mgmt_veth(struct loader_ctx *ctx)
{
    char cmd[512];
    __u32 mgmt_ifindex;
    int err;
    const char *veth_host = "mgmt-br";
    const char *veth_ns = "mgmt0";
    const char *ns_name;
    __u16 mgmt_vlan;

    RS_LOG_INFO("setup_mgmt_veth: use_profile=%d mgmt.enabled=%d mgmt.use_namespace=%d",
                ctx->use_profile, ctx->profile.mgmt.enabled,
                ctx->profile.mgmt.use_namespace);

    if (!ctx->use_profile || !ctx->profile.mgmt.enabled ||
        !ctx->profile.mgmt.use_namespace)
        return 0;

    ns_name = ctx->profile.mgmt.namespace_name[0]
              ? ctx->profile.mgmt.namespace_name
              : "rswitch-mgmt";
    mgmt_vlan = ctx->profile.mgmt.mgmt_vlan;
    if (mgmt_vlan == 0)
        mgmt_vlan = 1;

    RS_LOG_INFO("Setting up management veth in XDP pipeline (ns=%s vlan=%u)",
                ns_name, mgmt_vlan);

    snprintf(cmd, sizeof(cmd), "ip netns list 2>/dev/null | grep -qw '%s'", ns_name);
    if (system(cmd) != 0) {
        snprintf(cmd, sizeof(cmd), "ip netns add %s", ns_name);
        if (system(cmd) != 0) {
            RS_LOG_ERROR("Failed to create namespace %s", ns_name);
            return -1;
        }
    }

    snprintf(cmd, sizeof(cmd), "ip link del %s 2>/dev/null", veth_host);
    system(cmd);

    snprintf(cmd, sizeof(cmd), "ip link add %s type veth peer name %s",
             veth_host, veth_ns);
    if (system(cmd) != 0) {
        RS_LOG_ERROR("Failed to create veth pair %s <-> %s", veth_host, veth_ns);
        return -1;
    }

    snprintf(cmd, sizeof(cmd), "ip link set %s netns %s", veth_ns, ns_name);
    if (system(cmd) != 0) {
        RS_LOG_ERROR("Failed to move %s into namespace %s", veth_ns, ns_name);
        return -1;
    }

    snprintf(cmd, sizeof(cmd), "ip link set %s up", veth_host);
    system(cmd);
    snprintf(cmd, sizeof(cmd), "ip netns exec %s ip link set %s up", ns_name, veth_ns);
    system(cmd);
    snprintf(cmd, sizeof(cmd), "ip netns exec %s ip link set lo up", ns_name);
    system(cmd);

    mgmt_ifindex = if_nametoindex(veth_host);
    if (mgmt_ifindex == 0) {
        RS_LOG_ERROR("mgmt-br ifindex lookup failed after creation");
        return -1;
    }

    printf("  Created veth pair: %s (ifindex=%u) <-> %s (ns:%s)\n",
           veth_host, mgmt_ifindex, veth_ns, ns_name);

    prepare_interface(veth_host);

    RS_LOG_INFO("mgmt-br map fds: port_config=%d, ifindex_to_port=%d, devmap=%d, egress=%d",
                ctx->rs_port_config_map_fd, ctx->rs_ifindex_to_port_map_fd,
                ctx->rs_devmap_fd, ctx->egress_fd);

    if (ctx->rs_port_config_map_fd >= 0) {
        __u32 port_idx = ctx->num_interfaces;
        RS_LOG_INFO("mgmt-br: setting ifindex_to_port: ifindex=%u -> port_idx=%u (fd=%d)",
                    mgmt_ifindex, port_idx, ctx->rs_ifindex_to_port_map_fd);
        err = bpf_map_update_elem(ctx->rs_ifindex_to_port_map_fd,
                                  &mgmt_ifindex, &port_idx, BPF_ANY);
        if (err)
            RS_LOG_WARN("Failed to create ifindex->port_idx for mgmt-br: %s", strerror(errno));

        struct rs_port_config cfg = {
            .ifindex = mgmt_ifindex,
            .enabled = 1,
            .mgmt_type = 1,
            .vlan_mode = RS_VLAN_MODE_ACCESS,
            .learning = 1,
            .pvid = mgmt_vlan,
            .native_vlan = mgmt_vlan,
            .access_vlan = mgmt_vlan,
            .default_prio = 0,
            .trust_dscp = 0,
        };

        err = bpf_map_update_elem(ctx->rs_port_config_map_fd,
                                  &mgmt_ifindex, &cfg, BPF_ANY);
        if (err)
            RS_LOG_WARN("Failed to configure mgmt-br port: %s", strerror(errno));
        else
            RS_LOG_INFO("mgmt-br port_config: ifindex=%u, ACCESS vlan=%u, learning=on",
                        mgmt_ifindex, mgmt_vlan);
    } else {
        RS_LOG_WARN("mgmt-br: rs_port_config_map_fd=%d, skipping port config",
                    ctx->rs_port_config_map_fd);
    }

    if (ctx->rs_devmap_fd >= 0) {
        struct bpf_devmap_val xdp_val = {
            .ifindex = mgmt_ifindex,
            .bpf_prog.fd = ctx->egress_fd,
        };
        RS_LOG_INFO("mgmt-br: adding to devmap: key=ifindex=%u, val.ifindex=%u, val.prog.fd=%d",
                    mgmt_ifindex, mgmt_ifindex, ctx->egress_fd);
        err = bpf_map_update_elem(ctx->rs_devmap_fd, &mgmt_ifindex,
                                  &xdp_val, BPF_ANY);
        if (err)
            RS_LOG_WARN("Failed to add mgmt-br to XDP devmap: %s (errno=%d)",
                        strerror(errno), errno);
        else
            RS_LOG_INFO("mgmt-br added to XDP devmap (ifindex=%u) with egress hook",
                        mgmt_ifindex);
    } else {
        RS_LOG_WARN("mgmt-br: rs_devmap_fd=%d, skipping devmap registration",
                    ctx->rs_devmap_fd);
    }

    {
        char path[256];
        snprintf(path, sizeof(path), "%s/rs_vlan_map", BPF_PIN_PATH);
        int vlan_map_fd = bpf_obj_get(path);
        if (vlan_map_fd < 0) {
            for (int i = 0; i < ctx->num_modules; i++) {
                if (ctx->modules[i].obj) {
                    struct bpf_map *map = bpf_object__find_map_by_name(
                        ctx->modules[i].obj, "rs_vlan_map");
                    if (map) {
                        vlan_map_fd = bpf_map__fd(map);
                        break;
                    }
                }
            }
        }
        if (vlan_map_fd >= 0) {
            struct rs_vlan_members vlan = {0};
            __u16 vkey = mgmt_vlan;
            err = bpf_map_lookup_elem(vlan_map_fd, &vkey, &vlan);
            if (err) {
                memset(&vlan, 0, sizeof(vlan));
                vlan.vlan_id = mgmt_vlan;
            }

            int word_idx = (mgmt_ifindex - 1) / 64;
            int bit_idx = (mgmt_ifindex - 1) % 64;
            if (word_idx < 4) {
                vlan.untagged_members[word_idx] |= (1ULL << bit_idx);
                vlan.member_count++;
            }

            err = bpf_map_update_elem(vlan_map_fd, &vkey, &vlan, BPF_ANY);
            if (err)
                RS_LOG_WARN("Failed to add mgmt-br to VLAN %u: %s",
                            mgmt_vlan, strerror(errno));
            else
                RS_LOG_INFO("VLAN %u: added mgmt-br (ifindex=%u) as untagged member "
                            "(word=%d bit=%d)", mgmt_vlan, mgmt_ifindex,
                            (mgmt_ifindex - 1) / 64, (mgmt_ifindex - 1) % 64);

            if (vlan_map_fd != ctx->rs_vlan_map_fd)
                close(vlan_map_fd);
        }
    }

    /*
     * IMPORTANT: Attach mgmt-br in SKB/generic mode to match physical ports.
     * veth supports native XDP, but if physical ports use xdpgeneric (e.g.
     * VMware NICs), BPF_F_BROADCAST redirect from native→generic silently
     * fails. All ports in the devmap must use the same XDP mode.
     */
    err = bpf_xdp_attach(mgmt_ifindex, ctx->dispatcher_fd,
                          XDP_FLAGS_SKB_MODE, NULL);
    if (err) {
        RS_LOG_WARN("Failed to attach XDP dispatcher to mgmt-br: %s",
                    strerror(-err));
    } else {
        printf("  XDP dispatcher attached to mgmt-br (generic/SKB mode)\n");
    }

    ctx->mgmt_ifindex = mgmt_ifindex;

    printf("  Management veth ready for XDP pipeline participation\n");
    return 0;
}

/* Attach dispatcher to interfaces */
/* Prepare interface for XDP (promiscuous mode + disable VLAN offload) */
static int prepare_interface(const char *ifname)
{
    char cmd[256];
    int ret;
    
    /* Enable promiscuous mode for switch operation */
    snprintf(cmd, sizeof(cmd), "ip link set dev %s promisc on 2>/dev/null", ifname);
    ret = system(cmd);
    if (ret != 0) {
        RS_LOG_WARN("Failed to enable promiscuous mode on %s", ifname);
    }
    
    /* Disable hardware VLAN offload so XDP can see VLAN tags */
    snprintf(cmd, sizeof(cmd), "ethtool -K %s rx-vlan-offload off 2>/dev/null", ifname);
    ret = system(cmd);
    if (ret != 0) {
        RS_LOG_WARN("Failed to disable VLAN offload on %s", ifname);
    }
    
    return 0;
}

static int attach_xdp(struct loader_ctx *ctx)
{
    int i, err;
    
    printf("\nAttaching XDP programs:\n");
    
    for (i = 0; i < ctx->num_interfaces; i++) {
        __u32 ifindex = ctx->interfaces[i];
        char ifname[IF_NAMESIZE];
        
        if_indextoname(ifindex, ifname);
        
        /* Prepare interface (promisc + disable VLAN offload) */
        prepare_interface(ifname);
        
        err = bpf_xdp_attach(ifindex, ctx->dispatcher_fd, ctx->xdp_flags, NULL);
        if (err) {
            RS_LOG_ERROR("Failed to attach XDP to %s (ifindex=%u): %s",
                         ifname, ifindex, strerror(-err));
            return -1;
        }
        
        printf("  Attached to %s (ifindex=%u)\n", ifname, ifindex);
    }
    
    return 0;
}

/* Start VOQd user-space scheduler */
static int start_voqd(struct loader_ctx *ctx)
{
    char cmd[1024];
    char iface_list[512] = "";
    int i;
    
    printf("\nStarting VOQd (user-space scheduler)...\n");
    
    /* Check if rswitch-voqd binary exists */
    if (access("./build/rswitch-voqd", X_OK) != 0) {
        RS_LOG_ERROR("VOQd binary not found: ./build/rswitch-voqd");
        RS_LOG_ERROR("Build VOQd first or disable voqd_config in profile");
        return -1;
    }
    
    /* Build interface list */
    for (i = 0; i < ctx->num_interfaces; i++) {
        char ifname[IF_NAMESIZE];
        if_indextoname(ctx->interfaces[i], ifname);
        
        if (i > 0) strcat(iface_list, ",");
        strcat(iface_list, ifname);
    }
    
    /* Build VOQd command from profile configuration */
    struct rs_profile_voqd *voqd = &ctx->profile.voqd;
    
    RS_LOG_DEBUG("start_voqd() voqd->mode=%d, voqd->enabled=%d, voqd->prio_mask=0x%x",
                 voqd->mode, voqd->enabled, voqd->prio_mask);
    
    snprintf(cmd, sizeof(cmd),
             "./build/rswitch-voqd -i %s -p %d -m %s -P 0x%x %s%s%s",
             iface_list,
             voqd->num_ports > 0 ? voqd->num_ports : ctx->num_interfaces,
             voqd->mode == 2 ? "active" : (voqd->mode == 1 ? "shadow" : "bypass"),
             voqd->prio_mask,
             voqd->enable_scheduler ? "-s " : "",     /* Enable scheduler thread */
             voqd->enable_scheduler ? "-S 10 " : "",  /* Stats interval 10s */
             voqd->zero_copy ? "-z" : "");            /* Zero-copy mode */
    
    printf("  Command: %s (forked)\n", cmd);
    printf("  Mode: %s\n", voqd->mode == 2 ? "ACTIVE" : (voqd->mode == 1 ? "SHADOW" : "BYPASS"));
    printf("  Priority Mask: 0x%02x\n", voqd->prio_mask);
    printf("  Ports: %d\n", voqd->num_ports > 0 ? voqd->num_ports : ctx->num_interfaces);
    
    /* Fork and exec VOQd */
    pid_t pid = fork();
    if (pid < 0) {
        RS_LOG_ERROR("Failed to fork VOQd process: %s", strerror(errno));
        return -1;
    }
    
    if (pid == 0) {
        /* Child process - exec VOQd */
        /* Redirect stdout/stderr to log file */
        FILE *log = fopen("/tmp/rswitch-voqd.log", "w");
        if (log) {
            dup2(fileno(log), STDOUT_FILENO);
            dup2(fileno(log), STDERR_FILENO);
            fclose(log);
        }
        
        /* Execute VOQd via shell (for background &) */
        execl("/bin/sh", "sh", "-c", cmd, NULL);
        
        /* If exec fails */
        fprintf(stderr, "Failed to exec VOQd: %s\n", strerror(errno));
        exit(1);
    }
    
    /* Parent process - store PID */
    ctx->voqd_pid = pid;
    ctx->voqd_enabled = 1;
    
    /* Give VOQd time to initialize */
    sleep(2);
    
    /* Check if VOQd is still running */
    int status;
    if (waitpid(pid, &status, WNOHANG) != 0) {
        RS_LOG_ERROR("VOQd process exited prematurely");
        RS_LOG_ERROR("Check /tmp/rswitch-voqd.log for errors");
        ctx->voqd_pid = 0;
        ctx->voqd_enabled = 0;
        return -1;
    }
    
    printf("  ✓ VOQd started (PID: %d)\n", pid);
    printf("  ✓ Log: /tmp/rswitch-voqd.log\n");
    
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
        char cmd[256];
        
        if_indextoname(ifindex, ifname);
        
        /* Detach XDP program */
        if (bpf_xdp_detach(ifindex, ctx->xdp_flags, NULL) < 0) {
            RS_LOG_WARN("Failed to detach from %s (ifindex=%u): %s",
                        ifname, ifindex, strerror(errno));
            
            /* Try force detach as fallback */
            snprintf(cmd, sizeof(cmd), "ip link set %s xdp off 2>/dev/null", ifname);
            if (system(cmd) == 0) {
                printf("  Force detached from %s using ip command\n", ifname);
            }
        } else {
            printf("  ✓ Detached from %s (ifindex=%u)\n", ifname, ifindex);
        }
        
        /* Bring interface back up */
        snprintf(cmd, sizeof(cmd), "ip link set %s up 2>/dev/null", ifname);
        system(cmd);
        printf("  ✓ Restored %s to UP state\n", ifname);
    }
    
    if (ctx->mgmt_ifindex) {
        char cmd[256];
        if (bpf_xdp_detach(ctx->mgmt_ifindex, XDP_FLAGS_SKB_MODE, NULL) < 0) {
            snprintf(cmd, sizeof(cmd), "ip link set mgmt-br xdp off 2>/dev/null");
            system(cmd);
        }
        printf("  ✓ Detached from mgmt-br (ifindex=%u)\n", ctx->mgmt_ifindex);
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
    if (ctx->rs_ifindex_to_port_map_fd >= 0) {
        close(ctx->rs_ifindex_to_port_map_fd);
        printf("  Closed rs_ifindex_to_port_map_fd\n");
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
    if (ctx->rs_module_config_map_fd >= 0) {
        close(ctx->rs_module_config_map_fd);
        printf("  Closed rs_module_config_map_fd\n");
    }
    
    if (ctx->rs_mac_table_fd >= 0) {
        close(ctx->rs_mac_table_fd);
        printf("  Closed rs_mac_table_fd\n");
    }
}

/* Unpin all maps from BPF filesystem */
static void unpin_maps(void)
{
    DIR *dir;
    struct dirent *entry;
    char path[512];
    int unpinned = 0, failed = 0;
    
    printf("\nUnpinning maps from BPF filesystem (/sys/fs/bpf/):\n");
    
    dir = opendir("/sys/fs/bpf");
    if (!dir) {
        RS_LOG_WARN("Failed to open /sys/fs/bpf: %s", strerror(errno));
        return;
    }
    
    while ((entry = readdir(dir)) != NULL) {
        /* Skip . and .. */
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        
        /* Only unpin rSwitch-related maps (rs_*, acl_*, afxdp_*, qos_*, voq_*, voqd_*, 
         * arp_*, route_*, mirror_*, iface_*, egress_*, ingress_*, xsks_map, qdepth_map) */
        if (strncmp(entry->d_name, "rs_", 3) != 0 && 
            strncmp(entry->d_name, "acl_", 4) != 0 &&
            strncmp(entry->d_name, "afxdp_", 6) != 0 &&
            strncmp(entry->d_name, "qos_", 4) != 0 &&
            strncmp(entry->d_name, "voq_", 4) != 0 &&
            strncmp(entry->d_name, "voqd_", 5) != 0 &&
            strncmp(entry->d_name, "arp_", 4) != 0 &&
            strncmp(entry->d_name, "route_", 6) != 0 &&
            strncmp(entry->d_name, "mirror_", 7) != 0 &&
            strncmp(entry->d_name, "iface_", 6) != 0 &&
            strncmp(entry->d_name, "egress_", 7) != 0 &&
            strncmp(entry->d_name, "ingress_", 8) != 0 &&
            strcmp(entry->d_name, "xsks_map") != 0 &&
            strcmp(entry->d_name, "qdepth_map") != 0)
            continue;
        
        snprintf(path, sizeof(path), "/sys/fs/bpf/%s", entry->d_name);
        
        /* Check if it's a file (pinned map/prog) */
        struct stat st;
        if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
            if (unlink(path) < 0) {
                RS_LOG_WARN("Failed to unpin %s: %s",
                            entry->d_name, strerror(errno));
                failed++;
            } else {
                printf("  Unpinned %s\n", entry->d_name);
                unpinned++;
            }
        }
    }
    
    closedir(dir);
    
    printf("  Total: %d unpinned, %d failed\n", unpinned, failed);
}

/* Cleanup resources */
static void cleanup(struct loader_ctx *ctx)
{
    int i;
    
    printf("\n========== Cleanup Started ==========\n");
    
    /* Step 0: Stop VOQd if running */
    if (ctx->voqd_enabled && ctx->voqd_pid > 0) {
        printf("\nStopping VOQd (PID: %d)...\n", ctx->voqd_pid);
        
        /* Send SIGTERM for graceful shutdown */
        if (kill(ctx->voqd_pid, SIGTERM) == 0) {
            /* Wait up to 2 seconds for graceful shutdown (reduced from 5s) */
            int timeout = 20;  /* 20 * 100ms = 2 seconds */
            while (timeout > 0) {
                int status;
                if (waitpid(ctx->voqd_pid, &status, WNOHANG) != 0) {
                    printf("  ✓ VOQd stopped gracefully\n");
                    break;
                }
                usleep(100000);  /* 100ms */
                timeout--;
            }
            
            /* Force kill if still running */
            if (timeout == 0) {
                printf("  VOQd did not stop gracefully, forcing...\n");
                kill(ctx->voqd_pid, SIGKILL);
                waitpid(ctx->voqd_pid, NULL, 0);
                printf("  ✓ VOQd killed\n");
            }
        } else {
            RS_LOG_WARN("Failed to stop VOQd: %s", strerror(errno));
        }
        
        ctx->voqd_pid = 0;
        ctx->voqd_enabled = 0;
    }
    
    if (ctx->use_profile && ctx->profile.mgmt.enabled &&
        ctx->profile.mgmt.use_namespace) {
        const char *ns = ctx->profile.mgmt.namespace_name[0]
                         ? ctx->profile.mgmt.namespace_name
                         : "rswitch-mgmt";
        char cmd[256];

        printf("\nTearing down management veth...\n");
        snprintf(cmd, sizeof(cmd),
                 "ip netns exec %s dhcpcd -k mgmt0 2>/dev/null || true", ns);
        system(cmd);
        system("ip link del mgmt-br 2>/dev/null || true");
        snprintf(cmd, sizeof(cmd), "ip netns del %s 2>/dev/null || true", ns);
        system(cmd);
        printf("  Management veth + namespace removed\n");
    }
    
    /* Step 1: Flush TX queues to prevent netdev watchdog timeout
     * CRITICAL: Do this BEFORE detaching XDP to allow pending packets to drain */
    printf("\nFlushing TX queues...\n");
    for (i = 0; i < ctx->num_interfaces; i++) {
        char ifname[IF_NAMESIZE];
        if_indextoname(ctx->interfaces[i], ifname);
        
        /* Bring interface down briefly to flush queues */
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "ip link set %s down 2>/dev/null", ifname);
        system(cmd);
        printf("  Flushed %s\n", ifname);
    }
    
    /* Small delay to allow kernel to process queue flush */
    usleep(100000);  /* 100ms */
    
    /* Step 2: Detach XDP programs from all interfaces
     * IMPORTANT: Do this while maps are still valid, so XDP programs can clean up */
    detach_xdp(ctx);
    
    /* Step 3: Brief delay to ensure XDP fully detached before closing maps */
    usleep(50000);  /* 50ms */
    
    /* Step 4: Close map file descriptors */
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
    if (ctx->veth_egress_obj) {
        if (ctx->veth_out_ifindex > 0) {
            LIBBPF_OPTS(bpf_xdp_attach_opts, opts);
            bpf_xdp_detach(ctx->veth_out_ifindex, 0, &opts);
            printf("  Detached XDP from veth_voq_out\n");
        }
        bpf_object__close(ctx->veth_egress_obj);
        printf("  Closed veth_egress\n");
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
                RS_LOG_ERROR("Invalid interface: %s", token);
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
    struct rs_lifecycle_config lifecycle_cfg = {
        .state_dir = "/var/lib/rswitch/",
        .drain_timeout_sec = 30,
        .save_mac_table = 1,
        .save_routes = 1,
        .save_acl_counters = 1,
    };
    int opt, err;
    char *iface_list = NULL;

    rs_log_init("rswitch-loader", RS_LOG_LEVEL_INFO);
    
    /* Initialize map FDs to -1 */
    ctx.rs_ctx_map_fd = -1;
    ctx.rs_progs_fd = -1;
    ctx.rs_prog_chain_fd = -1;
    ctx.rs_port_config_map_fd = -1;
    ctx.rs_ifindex_to_port_map_fd = -1;
    ctx.rs_devmap_fd = -1;
    ctx.rs_stats_map_fd = -1;
    ctx.rs_module_config_map_fd = -1;
    ctx.veth_egress_fd = -1;
    ctx.voq_egress_devmap_fd = -1;
    ctx.veth_out_ifindex = 0;
    ctx.veth_egress_enabled = 0;
    ctx.mgmt_ifindex = 0;
    
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

    if (ctx.verbose) {
        rs_log_set_level(RS_LOG_LEVEL_DEBUG);
    }
    
    /* Load profile if specified, otherwise use mode-based profile */
    if (ctx.use_profile) {
        /* Load custom profile */
        if (profile_load_compat(ctx.profile_path, &ctx.profile) < 0) {
            RS_LOG_ERROR("Failed to load profile: %s", ctx.profile_path);
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
        
        if (profile_load_compat(ctx.profile_path, &ctx.profile) == 0) {
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
        RS_LOG_ERROR("-i/--ifaces required");
        usage(argv[0]);
        return 1;
    }
    
    if (parse_interfaces(&ctx, iface_list) <= 0) {
        RS_LOG_ERROR("No valid interfaces specified");
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
    
    /* Setup signal handlers for graceful shutdown */
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    signal(SIGHUP, handle_signal);

    if (rs_lifecycle_init(&lifecycle_cfg) != 0)
        RS_LOG_WARN("Lifecycle init failed, continuing without persistence");
    
    if (bump_memlock_rlimit()) {
        return 1;
    }
    
    if (create_pin_dir(BPF_PIN_PATH)) {
        return 1;
    }
    
    /* Discovery phase */
    if (discover_modules(&ctx) < 0) {
        RS_LOG_ERROR("Module discovery failed");
        return 1;
    }

    if (validate_dependencies(&ctx) < 0) {
        RS_LOG_ERROR("Dependency validation failed");
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
        RS_LOG_WARN("Failed to open rs_event_bus (not critical)");
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

    rs_lifecycle_restore_state();
    
    /* Build tail-call pipeline */
    if (build_prog_array(&ctx) < 0) {
        cleanup(&ctx);
        return 1;
    }

    write_module_configs(&ctx);
    
    /* Configure ports */
    configure_ports(&ctx);
    
    /* Initialize VLAN map with default configuration */
    initialize_vlan_map(&ctx);
    
    /* Initialize QoS configuration */
    initialize_qos_config(&ctx);
    
    /* Populate devmaps with queue isolation */
    populate_devmaps(&ctx);
    
    /* Setup veth egress path if VOQd is enabled */
    if (ctx.use_profile && ctx.profile.voqd.enabled) {
        ctx.veth_egress_enabled = 1;
        setup_veth_egress(&ctx);
    }
    
    /* Attach XDP */
    if (attach_xdp(&ctx) < 0) {
        cleanup(&ctx);
        return 1;
    }
    
    /* Setup management veth in XDP pipeline (if profile enables it) */
    if (setup_mgmt_veth(&ctx) < 0) {
        RS_LOG_WARN("Management veth setup failed, continuing without management plane");
    }
    
    /* Start VOQd if configured in profile */
    if (ctx.use_profile && ctx.profile.voqd.enabled) {
        if (start_voqd(&ctx) < 0) {
            RS_LOG_WARN("Failed to start VOQd, continuing with fast-path only");
        }
    }
    
    printf("\nrSwitch running. Press Ctrl+C to exit.\n");
    printf("Attached to %d interface%s\n", ctx.num_interfaces, ctx.num_interfaces > 1 ? "s" : "");
    if (ctx.voqd_enabled) {
        printf("VOQd enabled (PID: %d)\n", ctx.voqd_pid);
    }
    printf("\n");
    
    /* Main loop - use shorter sleep for faster shutdown response */
    int loop_count = 0;
    while (keep_running) {
        usleep(100000);  /* 100ms - much faster response than sleep(1) */

        if (shutdown_requested && !shutdown_in_progress) {
            shutdown_in_progress = 1;
            keep_running = 0;
            RS_LOG_INFO("Initiating graceful shutdown...");
            rs_lifecycle_shutdown(&lifecycle_cfg);
            continue;
        }
        
        /* Periodic health check every 10 seconds */
        if (++loop_count >= 100) {  /* 100 * 100ms = 10 seconds */
            loop_count = 0;
            
            /* Check if VOQd is still alive */
            if (ctx.voqd_enabled && ctx.voqd_pid > 0) {
                int status;
                pid_t result = waitpid(ctx.voqd_pid, &status, WNOHANG);
                if (result != 0) {
                    RS_LOG_WARN("VOQd process died unexpectedly");
                    ctx.voqd_pid = 0;
                    ctx.voqd_enabled = 0;
                }
            }
        }
    }
    
    /* Cleanup */
    cleanup(&ctx);
    rs_lifecycle_cleanup();
    
    return 0;
}
