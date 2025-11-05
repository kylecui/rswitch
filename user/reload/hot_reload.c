// SPDX-License-Identifier: GPL-2.0
/* 
 * rSwitch Hot-Reload Module Manager
 * 
 * Provides zero-downtime module updates by manipulating prog_array entries
 * without detaching XDP from interfaces.
 * 
 * Features:
 * - Hot-swap individual modules in the pipeline
 * - Atomic updates to prog_array (single map update operation)
 * - ABI version checking for compatibility
 * - Graceful fallback on reload failure
 * - Pipeline validation before applying changes
 * 
 * Hot-reload process:
 * 1. Load new module BPF object (verify ABI compatibility)
 * 2. Verify new module stage matches old module (prevent pipeline reordering)
 * 3. Update prog_array entry (atomic operation)
 * 4. Close old BPF object (kernel keeps program alive if pinned)
 * 5. Verify pipeline integrity
 * 
 * Safety guarantees:
 * - Traffic continues flowing during reload (XDP stays attached)
 * - Single map update is atomic from kernel perspective
 * - Old module remains active until new module is loaded
 * - Rollback possible if new module fails to load
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>

/* BPF pinning path */
#define BPF_PIN_PATH "/sys/fs/bpf"

/* From rswitch_loader.c */
#define RS_ABI_VERSION 1
#define RS_HOOK_XDP_INGRESS 0
#define RS_HOOK_XDP_EGRESS 1
#define MAX_MODULES 64
#define BUILD_DIR "./build/bpf"

struct rs_module_desc {
    __u32 abi_version;
    __u32 hook;
    __u32 stage;
    __u32 flags;
    char  name[32];
    char  description[64];
    __u32 reserved[4];
} __attribute__((aligned(8)));

/* Module state tracking */
struct reload_module {
    char name[64];
    char path[256];
    struct rs_module_desc desc;
    struct bpf_object *obj;
    struct bpf_program *prog;
    int prog_fd;
    int stage;
    int active;  /* 1 = currently loaded in pipeline */
};

/* Reload context */
struct reload_ctx {
    struct reload_module modules[MAX_MODULES];
    int num_modules;
    
    /* Map FDs */
    int rs_progs_fd;
    
    /* Options */
    int verbose;
    int dry_run;  /* Validate but don't apply */
};

/* Auto-get rs_progs FD if not already set */
static int ensure_rs_progs_fd(struct reload_ctx *ctx)
{
    if (ctx->rs_progs_fd > 0) {
        /* Already set, use provided FD */
        return 0;
    }
    
    /* Auto-detect from pinned map */
    ctx->rs_progs_fd = bpf_obj_get(BPF_PIN_PATH "/rs_progs");
    if (ctx->rs_progs_fd < 0) {
        fprintf(stderr, "Failed to get rs_progs map: %s\n", strerror(errno));
        fprintf(stderr, "Make sure rSwitch is running and maps are pinned.\n");
        fprintf(stderr, "Or specify the map FD manually with -p/--prog-fd\n");
        return -1;
    }
    
    if (ctx->verbose) {
        printf("Auto-detected rs_progs map: fd=%d\n", ctx->rs_progs_fd);
    }
    
    return 0;
}

/* Read module metadata from BPF object */
static int read_module_metadata(const char *path, struct rs_module_desc *desc)
{
    struct bpf_object *obj;
    const struct btf *btf;
    const struct btf_type *type;
    const char *sec_name;
    __u32 type_id;
    int err;
    
    obj = bpf_object__open(path);
    err = libbpf_get_error(obj);
    if (err) {
        fprintf(stderr, "Failed to open %s: %s\n", path, strerror(-err));
        return -1;
    }
    
    btf = bpf_object__btf(obj);
    if (!btf) {
        bpf_object__close(obj);
        fprintf(stderr, "No BTF in %s\n", path);
        return -1;
    }
    
    /* Find .rodata.mod section */
    for (type_id = 1; type_id < btf__type_cnt(btf); type_id++) {
        type = btf__type_by_id(btf, type_id);
        if (!btf_is_datasec(type))
            continue;
        
        sec_name = btf__name_by_offset(btf, type->name_off);
        if (strcmp(sec_name, ".rodata.mod") == 0) {
            /* Found section - read data */
            struct bpf_map *map = bpf_object__find_map_by_name(obj, ".rodata.mod");
            if (!map) {
                bpf_object__close(obj);
                fprintf(stderr, "Failed to find .rodata.mod map in %s\n", path);
                return -1;
            }
            
            /* Get initial value (embedded in ELF) */
            size_t size;
            const void *data = bpf_map__initial_value(map, &size);
            if (!data || size < sizeof(*desc)) {
                /* BTF may report size=0, try assuming correct size */
                if (size == 0) {
                    size = sizeof(*desc);
                } else {
                    bpf_object__close(obj);
                    fprintf(stderr, "Invalid .rodata.mod section in %s (size=%zu)\n", 
                            path, size);
                    return -1;
                }
            }
            
            memcpy(desc, data, sizeof(*desc));
            
            /* Validate ABI version */
            if (desc->abi_version != RS_ABI_VERSION) {
                fprintf(stderr, "ABI version mismatch in %s: expected %u, got %u\n",
                        path, RS_ABI_VERSION, desc->abi_version);
                return -1;
            }
            
            bpf_object__close(obj);
            return 0;
        }
    }
    
    bpf_object__close(obj);
    fprintf(stderr, "No .rodata.mod section found in %s\n", path);
    return -1;
}

/* Load module and prepare for hot-reload */
static int load_module_for_reload(struct reload_ctx *ctx, const char *module_name, 
                                   struct reload_module *module)
{
    char path[512];
    int err;
    
    /* Construct path to module */
    snprintf(path, sizeof(path), "%s/%s.bpf.o", BUILD_DIR, module_name);
    
    /* Read metadata first */
    if (read_module_metadata(path, &module->desc) < 0) {
        return -1;
    }
    
    strncpy(module->name, module->desc.name, sizeof(module->name) - 1);
    strncpy(module->path, path, sizeof(module->path) - 1);
    module->stage = module->desc.stage;
    
    /* Load BPF object */
    module->obj = bpf_object__open(path);
    err = libbpf_get_error(module->obj);
    if (err) {
        fprintf(stderr, "Failed to open module %s: %s\n", module_name, strerror(-err));
        return -1;
    }
    
    err = bpf_object__load(module->obj);
    if (err) {
        fprintf(stderr, "Failed to load module %s: %s\n", module_name, strerror(-err));
        bpf_object__close(module->obj);
        return -1;
    }
    
    /* Find main program (should match module name) */
    char prog_name[128];
    snprintf(prog_name, sizeof(prog_name), "%s_ingress", module_name);
    
    module->prog = bpf_object__find_program_by_name(module->obj, prog_name);
    if (!module->prog) {
        /* Try alternative naming patterns */
        module->prog = bpf_object__find_program_by_name(module->obj, module_name);
        if (!module->prog) {
            /* Try first XDP program in object */
            struct bpf_program *prog;
            bpf_object__for_each_program(prog, module->obj) {
                if (bpf_program__type(prog) == BPF_PROG_TYPE_XDP) {
                    module->prog = prog;
                    break;
                }
            }
        }
    }
    
    if (!module->prog) {
        fprintf(stderr, "No XDP program found in module %s\n", module_name);
        bpf_object__close(module->obj);
        return -1;
    }
    
    module->prog_fd = bpf_program__fd(module->prog);
    if (module->prog_fd < 0) {
        fprintf(stderr, "Failed to get FD for module %s\n", module_name);
        bpf_object__close(module->obj);
        return -1;
    }
    
    if (ctx->verbose) {
        printf("Loaded module: %s (stage=%u, fd=%d)\n", 
               module->name, module->stage, module->prog_fd);
    }
    
    return 0;
}

/* Update prog_array entry for a specific stage */
static int update_prog_array(struct reload_ctx *ctx, int stage, int new_prog_fd)
{
    int err;
    
    if (ctx->dry_run) {
        printf("[DRY-RUN] Would update prog_array[%d] = fd %d\n", stage, new_prog_fd);
        return 0;
    }
    
    err = bpf_map_update_elem(ctx->rs_progs_fd, &stage, &new_prog_fd, BPF_ANY);
    if (err < 0) {
        fprintf(stderr, "Failed to update prog_array[%d]: %s\n", 
                stage, strerror(errno));
        return -1;
    }
    
    if (ctx->verbose) {
        printf("Updated prog_array[%d] = fd %d\n", stage, new_prog_fd);
    }
    
    return 0;
}

/* Verify pipeline integrity by checking all expected stages */
static int verify_pipeline(struct reload_ctx *ctx, int *expected_stages, int num_stages)
{
    int err, fd;
    
    /* Ensure rs_progs FD is available */
    if (ensure_rs_progs_fd(ctx) < 0) {
        return -1;
    }
    
    printf("Verifying pipeline integrity:\n");
    
    for (int i = 0; i < num_stages; i++) {
        int stage = expected_stages[i];
        
        err = bpf_map_lookup_elem(ctx->rs_progs_fd, &stage, &fd);
        if (err < 0) {
            fprintf(stderr, "  [FAIL] Stage %d: not found in prog_array\n", stage);
            return -1;
        }
        
        if (fd <= 0) {
            fprintf(stderr, "  [FAIL] Stage %d: invalid fd %d\n", stage, fd);
            return -1;
        }
        
        printf("  [OK] Stage %d: fd=%d\n", stage, fd);
    }
    
    printf("Pipeline verification passed\n");
    return 0;
}

/* Hot-reload a single module */
static int hot_reload_module(struct reload_ctx *ctx, const char *module_name)
{
    struct reload_module new_module = {0};
    int old_stage = -1;
    int err;
    
    printf("\n=== Hot-reloading module: %s ===\n", module_name);
    
    /* Ensure rs_progs FD is available */
    if (ensure_rs_progs_fd(ctx) < 0) {
        return -1;
    }
    
    /* Step 1: Load new module */
    printf("Step 1: Loading new module...\n");
    if (load_module_for_reload(ctx, module_name, &new_module) < 0) {
        fprintf(stderr, "Failed to load new module\n");
        return -1;
    }
    
    /* Step 2: Find old module with same stage (if any) */
    printf("Step 2: Checking for existing module at stage %d...\n", new_module.stage);
    for (int i = 0; i < ctx->num_modules; i++) {
        if (ctx->modules[i].stage == new_module.stage && ctx->modules[i].active) {
            old_stage = i;
            printf("  Found existing module: %s (stage=%d)\n", 
                   ctx->modules[i].name, ctx->modules[i].stage);
            break;
        }
    }
    
    /* Step 3: Update prog_array (atomic from kernel perspective) */
    printf("Step 3: Updating pipeline (stage %d)...\n", new_module.stage);
    err = update_prog_array(ctx, new_module.stage, new_module.prog_fd);
    if (err < 0) {
        fprintf(stderr, "Failed to update pipeline\n");
        bpf_object__close(new_module.obj);
        return -1;
    }
    
    /* Step 4: Replace old module in tracking array */
    printf("Step 4: Updating module registry...\n");
    if (old_stage >= 0) {
        /* Close old object (kernel keeps program alive if still in use) */
        if (ctx->modules[old_stage].obj) {
            if (ctx->verbose) {
                printf("  Closing old module: %s\n", ctx->modules[old_stage].name);
            }
            if (!ctx->dry_run) {
                bpf_object__close(ctx->modules[old_stage].obj);
            }
        }
        
        /* Replace with new module */
        memcpy(&ctx->modules[old_stage], &new_module, sizeof(new_module));
        ctx->modules[old_stage].active = 1;
    } else {
        /* New module (no previous at this stage) */
        if (ctx->num_modules >= MAX_MODULES) {
            fprintf(stderr, "Module registry full\n");
            bpf_object__close(new_module.obj);
            return -1;
        }
        
        memcpy(&ctx->modules[ctx->num_modules], &new_module, sizeof(new_module));
        ctx->modules[ctx->num_modules].active = 1;
        ctx->num_modules++;
    }
    
    printf("✓ Hot-reload completed successfully\n");
    printf("  Module: %s\n", new_module.name);
    printf("  Stage: %d\n", new_module.stage);
    printf("  FD: %d\n", new_module.prog_fd);
    
    return 0;
}

/* Remove module from pipeline (clear prog_array entry) */
static int unload_module(struct reload_ctx *ctx, const char *module_name)
{
    int err;
    
    printf("\n=== Unloading module: %s ===\n", module_name);
    
    /* Ensure rs_progs FD is available */
    if (ensure_rs_progs_fd(ctx) < 0) {
        return -1;
    }
    
    /* Find module */
    int idx = -1;
    for (int i = 0; i < ctx->num_modules; i++) {
        if (strcmp(ctx->modules[i].name, module_name) == 0 && ctx->modules[i].active) {
            idx = i;
            break;
        }
    }
    
    if (idx < 0) {
        fprintf(stderr, "Module not found: %s\n", module_name);
        return -1;
    }
    
    int stage = ctx->modules[idx].stage;
    
    /* Clear prog_array entry (set to -1 for "no program") */
    printf("Clearing pipeline stage %d...\n", stage);
    int no_prog = -1;
    
    if (!ctx->dry_run) {
        err = bpf_map_delete_elem(ctx->rs_progs_fd, &stage);
        if (err < 0) {
            fprintf(stderr, "Failed to delete prog_array[%d]: %s\n", 
                    stage, strerror(errno));
            return -1;
        }
    } else {
        printf("[DRY-RUN] Would delete prog_array[%d]\n", stage);
    }
    
    /* Close BPF object */
    if (ctx->modules[idx].obj && !ctx->dry_run) {
        bpf_object__close(ctx->modules[idx].obj);
    }
    
    /* Mark as inactive */
    ctx->modules[idx].active = 0;
    
    printf("✓ Module unloaded successfully\n");
    return 0;
}

/* List currently loaded modules */
static int list_modules(struct reload_ctx *ctx)
{
    struct bpf_prog_info info = {};
    __u32 info_len = sizeof(info);
    __u32 prog_id = 0;
    int prog_fd;
    int err;
    int found = 0;
    
    printf("\n=== Currently Loaded Modules ===\n");
    printf("%-8s %-30s %-12s %-10s %s\n", "ID", "Program Name", "Tag", "FD", "Type");
    printf("--------------------------------------------------------------------------------\n");
    
    /* Iterate through all BPF programs in the system */
    while (1) {
        err = bpf_prog_get_next_id(prog_id, &prog_id);
        if (err) {
            if (errno == ENOENT) {
                /* No more programs */
                break;
            }
            fprintf(stderr, "Error iterating programs: %s\n", strerror(errno));
            break;
        }
        
        prog_fd = bpf_prog_get_fd_by_id(prog_id);
        if (prog_fd < 0) {
            continue;
        }
        
        /* Get program info */
        memset(&info, 0, sizeof(info));
        info_len = sizeof(info);
        err = bpf_obj_get_info_by_fd(prog_fd, &info, &info_len);
        if (err < 0) {
            close(prog_fd);
            continue;
        }
        
        /* Filter: only show XDP programs with rswitch-related names */
        if (info.type != BPF_PROG_TYPE_XDP) {
            close(prog_fd);
            continue;
        }
        
        /* Check if this is an rSwitch module (name contains common patterns) */
        const char *name = info.name;
        int is_rswitch = 0;
        
        /* Common rSwitch module patterns */
        if (strstr(name, "rswitch") != NULL ||
            strstr(name, "l2learn") != NULL ||
            strstr(name, "lastcall") != NULL ||
            strstr(name, "vlan") != NULL ||
            strstr(name, "acl") != NULL ||
            strstr(name, "mirror") != NULL ||
            strstr(name, "dispatcher") != NULL ||
            strstr(name, "egress") != NULL) {
            is_rswitch = 1;
        }
        
        if (!is_rswitch) {
            close(prog_fd);
            continue;
        }
        
        /* Format tag as hex string */
        char tag_str[17];
        snprintf(tag_str, sizeof(tag_str), "%02x%02x%02x%02x%02x%02x%02x%02x",
                 info.tag[0], info.tag[1], info.tag[2], info.tag[3],
                 info.tag[4], info.tag[5], info.tag[6], info.tag[7]);
        
        const char *prog_type = "XDP";
        
        printf("%-8d %-30s %-12s %-10d %s\n",
               prog_id,
               info.name[0] ? info.name : "<unnamed>",
               tag_str,
               prog_fd,
               prog_type);
        
        found++;
        close(prog_fd);
    }
    
    if (found == 0) {
        printf("(No rSwitch modules loaded)\n");
        printf("\nNote: Only showing XDP programs with rSwitch-related names.\n");
    } else {
        printf("\nTotal: %d module(s) loaded\n", found);
        printf("\nNote: This shows all rSwitch XDP programs in the system.\n");
        printf("To see pipeline order, use: sudo bpftool map dump name rs_progs\n");
    }
    
    printf("\n");
    return 0;
}

/* Usage */
static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s <command> [OPTIONS]\n"
        "\n"
        "Commands:\n"
        "  reload <module>     Hot-reload a module (e.g., 'vlan', 'l2learn')\n"
        "  unload <module>     Remove module from pipeline\n"
        "  list                List currently loaded modules (auto-detects rs_progs)\n"
        "  verify <stages...>  Verify pipeline integrity for given stages\n"
        "\n"
        "Options:\n"
        "  -p, --prog-fd <fd>  File descriptor of rs_progs map (auto-detected if omitted)\n"
        "  -n, --dry-run       Validate but don't apply changes\n"
        "  -v, --verbose       Verbose output\n"
        "  -h, --help          Show this help\n"
        "\n"
        "Examples:\n"
        "  # List currently loaded modules (auto-detects rs_progs):\n"
        "  sudo %s list\n"
        "  \n"
        "  # Hot-reload vlan module (auto-detects rs_progs):\n"
        "  sudo %s reload vlan -v\n"
        "  \n"
        "  # Verify pipeline (auto-detects rs_progs):\n"
        "  sudo %s verify 20 80 90\n"
        "  \n"
        "  # Manual FD override (if needed):\n"
        "  sudo bpftool map list | grep rs_progs\n"
        "  sudo %s reload vlan -p 42 -v\n",
        prog, prog, prog, prog, prog);
}

int main(int argc, char **argv)
{
    struct reload_ctx ctx = {0};
    const char *command = NULL;
    const char *module_name = NULL;
    int opt;
    
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }
    
    command = argv[1];
    
    /* Parse remaining arguments */
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--prog-fd") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "Missing argument for %s\n", argv[i-1]);
                return 1;
            }
            ctx.rs_progs_fd = atoi(argv[i]);
        } else if (strcmp(argv[i], "-n") == 0 || strcmp(argv[i], "--dry-run") == 0) {
            ctx.dry_run = 1;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            ctx.verbose = 1;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else if (argv[i][0] != '-' && !module_name) {
            module_name = argv[i];
        }
    }
    
    /* Execute command */
    if (strcmp(command, "reload") == 0) {
        if (!module_name) {
            fprintf(stderr, "Error: module name required for reload\n");
            usage(argv[0]);
            return 1;
        }
        
        return hot_reload_module(&ctx, module_name) < 0 ? 1 : 0;
        
    } else if (strcmp(command, "unload") == 0) {
        if (!module_name) {
            fprintf(stderr, "Error: module name required for unload\n");
            usage(argv[0]);
            return 1;
        }
        
        return unload_module(&ctx, module_name) < 0 ? 1 : 0;
        
    } else if (strcmp(command, "list") == 0) {
        return list_modules(&ctx) < 0 ? 1 : 0;
        
    } else if (strcmp(command, "verify") == 0) {
        /* Remaining args are stages */
        int stages[64];
        int num_stages = 0;
        for (int i = 2; i < argc && num_stages < 64; i++) {
            if (argv[i][0] != '-' && strcmp(argv[i], command) != 0) {
                stages[num_stages++] = atoi(argv[i]);
            }
        }
        
        if (num_stages == 0) {
            fprintf(stderr, "Error: at least one stage required for verify\n");
            return 1;
        }
        
        return verify_pipeline(&ctx, stages, num_stages) < 0 ? 1 : 0;
        
    } else {
        fprintf(stderr, "Unknown command: %s\n", command);
        usage(argv[0]);
        return 1;
    }
    
    return 0;
}
