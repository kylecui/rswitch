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
#include <getopt.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>

#if __has_include("rs_log.h")
#include "rs_log.h"
#else
#include "../common/rs_log.h"
#endif

/* BPF pinning path */
#define BPF_PIN_PATH "/sys/fs/bpf"

/* From rswitch_loader.c */
#define RS_ABI_VERSION_MAJOR 2
#define RS_ABI_VERSION_MINOR 0
#define RS_ABI_VERSION ((RS_ABI_VERSION_MAJOR << 16) | RS_ABI_VERSION_MINOR)
#define RS_ABI_MAJOR(v) ((v) >> 16)
#define RS_ABI_MINOR(v) ((v) & 0xFFFF)
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
    int rs_prog_chain_fd;
    
    /* Options */
    int verbose;
    int dry_run;  /* Validate but don't apply */
};

struct verified_module {
    struct rs_module_desc desc;
    struct bpf_object *obj;
    struct bpf_program *prog;
    int prog_fd;
};

/* Forward declarations */
static int is_loadable_module(int prog_fd, struct rs_module_desc *desc);
static int read_module_metadata(const char *path, struct rs_module_desc *desc);
static int verify_module_before_swap(struct reload_ctx *ctx, const char *module_path,
                                     const char *expected_module_name, __u32 expected_hook,
                                     int dry_run, struct verified_module *out);
static int reload_module(struct reload_ctx *ctx, const char *module_name, int dry_run);

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
        RS_LOG_ERROR("Failed to get rs_progs map: %s", strerror(errno));
        RS_LOG_ERROR("Make sure rSwitch is running and maps are pinned.");
        RS_LOG_ERROR("Or specify the map FD manually with -p/--prog-fd");
        return -1;
    }
    
    if (ctx->verbose) {
        printf("Auto-detected rs_progs map: fd=%d\n", ctx->rs_progs_fd);
    }

    if (ctx->rs_prog_chain_fd <= 0) {
        ctx->rs_prog_chain_fd = bpf_obj_get(BPF_PIN_PATH "/rs_prog_chain");
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
        RS_LOG_ERROR("Failed to open %s: %s", path, strerror(-err));
        return -1;
    }
    
    btf = bpf_object__btf(obj);
    if (!btf) {
        bpf_object__close(obj);
        RS_LOG_ERROR("No BTF in %s", path);
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
                RS_LOG_ERROR("Failed to find .rodata.mod map in %s", path);
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
                    RS_LOG_ERROR("Invalid .rodata.mod section in %s (size=%zu)",
                                 path, size);
                    return -1;
                }
            }
            
            memcpy(desc, data, sizeof(*desc));
            
            {
                __u32 mod_major = RS_ABI_MAJOR(desc->abi_version);
                __u32 mod_minor = RS_ABI_MINOR(desc->abi_version);

                if (mod_major == 0 && desc->abi_version == 1) {
                    mod_major = 1;
                    mod_minor = 0;
                }

                if (mod_major != RS_ABI_VERSION_MAJOR) {
                    RS_LOG_ERROR("ABI major mismatch in %s: platform=%u.%u module=%u.%u (raw=%u)",
                                 path,
                                 RS_ABI_VERSION_MAJOR,
                                 RS_ABI_VERSION_MINOR,
                                 mod_major,
                                 mod_minor,
                                 desc->abi_version);
                    bpf_object__close(obj);
                    return -1;
                }

                if (mod_minor > RS_ABI_VERSION_MINOR) {
                    RS_LOG_ERROR("ABI minor too new in %s: platform=%u.%u module=%u.%u",
                                 path,
                                 RS_ABI_VERSION_MAJOR,
                                 RS_ABI_VERSION_MINOR,
                                 mod_major,
                                 mod_minor);
                    bpf_object__close(obj);
                    return -1;
                }
            }
            
            bpf_object__close(obj);
            return 0;
        }
    }
    
    bpf_object__close(obj);
    RS_LOG_ERROR("No .rodata.mod section found in %s", path);
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
        RS_LOG_ERROR("Failed to open module %s: %s", module_name, strerror(-err));
        return -1;
    }
    
    err = bpf_object__load(module->obj);
    if (err) {
        RS_LOG_ERROR("Failed to load module %s: %s", module_name, strerror(-err));
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
        RS_LOG_ERROR("No XDP program found in module %s", module_name);
        bpf_object__close(module->obj);
        return -1;
    }
    
    module->prog_fd = bpf_program__fd(module->prog);
    if (module->prog_fd < 0) {
        RS_LOG_ERROR("Failed to get FD for module %s", module_name);
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
        RS_LOG_ERROR("Failed to update prog_array[%d]: %s", stage, strerror(errno));
        return -1;
    }
    
    if (ctx->verbose) {
        printf("Updated prog_array[%d] = fd %d\n", stage, new_prog_fd);
    }
    
    return 0;
}

/* Find module by stage number */
static int find_module_by_stage(int stage, int *out_prog_id, char *out_name, size_t name_len)
{
    struct bpf_prog_info info = {};
    __u32 info_len = sizeof(info);
    __u32 prog_id = 0;
    int prog_fd;
    int err;
    struct rs_module_desc desc;
    
    /* Iterate through all BPF programs */
    while (1) {
        err = bpf_prog_get_next_id(prog_id, &prog_id);
        if (err) {
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
        
        /* Only check XDP programs with module metadata */
        if (info.type != BPF_PROG_TYPE_XDP || !is_loadable_module(prog_fd, &desc)) {
            close(prog_fd);
            continue;
        }
        
        /* Check if module's stage matches */
        char path[256];
        snprintf(path, sizeof(path), "%s/%s.bpf.o", BUILD_DIR, info.name);
        
        /* Try to read metadata from loaded program's BTF */
        struct rs_module_desc mod_desc;
        if (read_module_metadata(path, &mod_desc) == 0) {
            if (mod_desc.stage == stage) {
                *out_prog_id = prog_id;
                if (out_name) {
                    snprintf(out_name, name_len, "%s", info.name);
                }
                close(prog_fd);
                return 0;
            }
        }
        
        close(prog_fd);
    }
    
    return -1;  /* Not found */
}

/* Verify pipeline integrity by checking all expected stages */
static int verify_pipeline(struct reload_ctx *ctx, int *expected_stages, int num_stages)
{
    int prog_id;
    char module_name[64];
    
    printf("Verifying pipeline integrity:\n");
    
    for (int i = 0; i < num_stages; i++) {
        int stage = expected_stages[i];
        
        if (find_module_by_stage(stage, &prog_id, module_name, sizeof(module_name)) < 0) {
            RS_LOG_ERROR("  [FAIL] Stage %d: no module loaded", stage);
            return -1;
        }
        
        printf("  [OK] Stage %d: %s (prog_id=%d)\n", stage, module_name, prog_id);
    }
    
    printf("Pipeline verification passed\n");
    return 0;
}

static void emit_reload_event(const char *module_name, int success, const char *reason)
{
    int fd = bpf_obj_get("/sys/fs/bpf/rs_event_bus");
    if (fd >= 0) {
        close(fd);
    }

    if (success) {
        RS_LOG_INFO("RELOAD %s SUCCESS", module_name);
    } else if (reason && reason[0] != '\0') {
        RS_LOG_ERROR("RELOAD %s FAILED: %s", module_name, reason);
    } else {
        RS_LOG_ERROR("RELOAD %s FAILED", module_name);
    }
}

static int module_name_matches(const char *expected, const char *prog_name)
{
    size_t n;

    if (!expected || !prog_name) {
        return 0;
    }

    if (strcmp(expected, prog_name) == 0) {
        return 1;
    }

    n = strlen(expected);
    if (strncmp(expected, prog_name, n) == 0 && (prog_name[n] == '_' || prog_name[n] == '\0')) {
        return 1;
    }

    return 0;
}

static __u32 hook_from_slot(__u32 slot)
{
    return slot >= 128 ? RS_HOOK_XDP_EGRESS : RS_HOOK_XDP_INGRESS;
}

static int find_module_slot(struct reload_ctx *ctx, const char *module_name,
                            int *out_slot, int *out_prog_fd)
{
    __u32 slot;

    if (ensure_rs_progs_fd(ctx) < 0) {
        return -1;
    }

    for (slot = 0; slot <= 255; slot++) {
        __u32 prog_id = 0;
        int prog_fd;
        struct bpf_prog_info info = {};
        __u32 info_len = sizeof(info);

        if (bpf_map_lookup_elem(ctx->rs_progs_fd, &slot, &prog_id) < 0 || prog_id == 0) {
            continue;
        }

        prog_fd = bpf_prog_get_fd_by_id(prog_id);
        if (prog_fd < 0) {
            continue;
        }

        if (bpf_obj_get_info_by_fd(prog_fd, &info, &info_len) < 0) {
            close(prog_fd);
            continue;
        }

        if (info.type == BPF_PROG_TYPE_XDP && module_name_matches(module_name, (const char *)info.name)) {
            *out_slot = (int)slot;
            *out_prog_fd = prog_fd;
            return 0;
        }

        close(prog_fd);
    }

    return -1;
}

static struct bpf_program *find_xdp_program(struct bpf_object *obj, const char *module_name)
{
    struct bpf_program *prog;
    char prog_name[128];

    snprintf(prog_name, sizeof(prog_name), "%s_ingress", module_name);
    prog = bpf_object__find_program_by_name(obj, prog_name);
    if (prog) {
        return prog;
    }

    snprintf(prog_name, sizeof(prog_name), "%s_egress", module_name);
    prog = bpf_object__find_program_by_name(obj, prog_name);
    if (prog) {
        return prog;
    }

    prog = bpf_object__find_program_by_name(obj, module_name);
    if (prog) {
        return prog;
    }

    bpf_object__for_each_program(prog, obj) {
        if (bpf_program__type(prog) == BPF_PROG_TYPE_XDP) {
            return prog;
        }
    }

    return NULL;
}

static int verify_module_before_swap(struct reload_ctx *ctx, const char *module_path,
                                     const char *expected_module_name, __u32 expected_hook,
                                     int dry_run, struct verified_module *out)
{
    LIBBPF_OPTS(bpf_object_open_opts, opts,
        .pin_root_path = "/sys/fs/bpf",
    );
    int err;

    memset(out, 0, sizeof(*out));
    out->prog_fd = -1;

    err = read_module_metadata(module_path, &out->desc);
    if (err < 0) {
        return -1;
    }

    if (strcmp(out->desc.name, expected_module_name) != 0) {
        RS_LOG_ERROR("Module name mismatch: expected %s, got %s",
                     expected_module_name, out->desc.name);
        return -1;
    }

    if (out->desc.hook != expected_hook) {
        RS_LOG_ERROR("Hook mismatch for %s: expected %u, got %u",
                     expected_module_name, expected_hook, out->desc.hook);
        return -1;
    }

    out->obj = bpf_object__open_file(module_path, &opts);
    err = libbpf_get_error(out->obj);
    if (err) {
        out->obj = NULL;
        RS_LOG_ERROR("Failed to open %s: %s", module_path, strerror(-err));
        return -1;
    }

    err = bpf_object__load(out->obj);
    if (err) {
        RS_LOG_ERROR("Verifier rejected %s: %s", module_path, strerror(-err));
        bpf_object__close(out->obj);
        out->obj = NULL;
        return -1;
    }

    out->prog = find_xdp_program(out->obj, expected_module_name);
    if (!out->prog) {
        RS_LOG_ERROR("No XDP program found in %s", module_path);
        bpf_object__close(out->obj);
        out->obj = NULL;
        return -1;
    }

    out->prog_fd = bpf_program__fd(out->prog);
    if (out->prog_fd < 0) {
        RS_LOG_ERROR("Failed to get program FD for %s", expected_module_name);
        bpf_object__close(out->obj);
        out->obj = NULL;
        return -1;
    }

    if (dry_run) {
        RS_LOG_INFO("Dry-run verification passed for %s", expected_module_name);
    }

    return 0;
}

static int atomic_module_swap(struct reload_ctx *ctx, const char *module_name, int slot,
                              struct bpf_object *new_obj, struct bpf_program *new_prog,
                              int new_fd, int old_fd)
{
    __u32 key = (__u32)slot;
    __u32 new_prog_id = 0;
    __u32 got_prog_id = 0;
    struct bpf_prog_info info = {};
    __u32 info_len = sizeof(info);
    int err;

    err = bpf_obj_get_info_by_fd(new_fd, &info, &info_len);
    if (err < 0) {
        RS_LOG_ERROR("Failed to read new program info for %s: %s", module_name, strerror(errno));
        bpf_object__close(new_obj);
        return -1;
    }
    new_prog_id = info.id;

    err = bpf_map_update_elem(ctx->rs_progs_fd, &key, &new_fd, BPF_ANY);
    if (err) {
        RS_LOG_ERROR("Failed to update rs_progs[%d] for module %s: %s",
                     slot, module_name, strerror(errno));
        bpf_object__close(new_obj);
        return -1;
    }

    if (bpf_map_lookup_elem(ctx->rs_progs_fd, &key, &got_prog_id) == 0 && got_prog_id != new_prog_id) {
        RS_LOG_ERROR("Swap verification failed for %s at slot %d (expected prog_id=%u, got=%u)",
                     module_name, slot, new_prog_id, got_prog_id);
        if (old_fd >= 0) {
            bpf_map_update_elem(ctx->rs_progs_fd, &key, &old_fd, BPF_ANY);
        }
        bpf_object__close(new_obj);
        return -1;
    }

    for (int i = 0; i < MAX_MODULES; i++) {
        if (ctx->modules[i].active && strcmp(ctx->modules[i].name, module_name) == 0) {
            if (ctx->modules[i].obj) {
                bpf_object__close(ctx->modules[i].obj);
            }
            ctx->modules[i].obj = new_obj;
            ctx->modules[i].prog = new_prog;
            ctx->modules[i].prog_fd = new_fd;
            ctx->modules[i].stage = slot;
            return 0;
        }
    }

    for (int i = 0; i < MAX_MODULES; i++) {
        if (!ctx->modules[i].active) {
            snprintf(ctx->modules[i].name, sizeof(ctx->modules[i].name), "%s", module_name);
            ctx->modules[i].obj = new_obj;
            ctx->modules[i].prog = new_prog;
            ctx->modules[i].prog_fd = new_fd;
            ctx->modules[i].stage = slot;
            ctx->modules[i].active = 1;
            ctx->num_modules++;
            return 0;
        }
    }

    RS_LOG_WARN("Module tracking table full; swap succeeded but not tracked: %s", module_name);
    return 0;
}

static int reload_module(struct reload_ctx *ctx, const char *module_name, int dry_run)
{
    char module_path[512];
    struct verified_module verified;
    int slot = -1;
    int old_prog_fd = -1;
    __u32 expected_hook;

    if (find_module_slot(ctx, module_name, &slot, &old_prog_fd) < 0) {
        RS_LOG_ERROR("Module %s is not currently loaded in rs_progs", module_name);
        emit_reload_event(module_name, 0, "module not loaded");
        return -1;
    }

    expected_hook = hook_from_slot((__u32)slot);
    snprintf(module_path, sizeof(module_path), "%s/%s.bpf.o", BUILD_DIR, module_name);

    if (verify_module_before_swap(ctx, module_path, module_name, expected_hook,
                                  dry_run, &verified) < 0) {
        if (old_prog_fd >= 0) {
            close(old_prog_fd);
        }
        emit_reload_event(module_name, 0, "pre-verification failed");
        return -1;
    }

    if (dry_run) {
        if (verified.obj) {
            bpf_object__close(verified.obj);
        }
        if (old_prog_fd >= 0) {
            close(old_prog_fd);
        }
        emit_reload_event(module_name, 1, NULL);
        printf("Dry-run succeeded: module %s verified for slot %d\n", module_name, slot);
        return 0;
    }

    if (atomic_module_swap(ctx, module_name, slot, verified.obj, verified.prog,
                           verified.prog_fd, old_prog_fd) < 0) {
        if (old_prog_fd >= 0) {
            close(old_prog_fd);
        }
        emit_reload_event(module_name, 0, "atomic swap failed");
        return -1;
    }

    if (old_prog_fd >= 0) {
        close(old_prog_fd);
    }

    emit_reload_event(module_name, 1, NULL);
    printf("Reloaded module %s at slot %d\n", module_name, slot);
    return 0;
}

/* Hot-reload a single module */
static int hot_reload_module(struct reload_ctx *ctx, const char *module_name)
{
    return reload_module(ctx, module_name, ctx->dry_run);
}

/* Remove module from pipeline (clear prog_array entry) */
static int unload_module(struct reload_ctx *ctx, const char *module_name)
{
    int prog_id;
    char found_name[64];
    int err;
    struct bpf_prog_info info = {};
    __u32 info_len = sizeof(info);
    int prog_fd;
    int stage = -1;
    
    printf("\n=== Unloading module: %s ===\n", module_name);
    
    /* Ensure rs_progs FD is available */
    if (ensure_rs_progs_fd(ctx) < 0) {
        return -1;
    }
    
    /* Find the module by name */
    __u32 search_id = 0;
    int found = 0;
    
    while (1) {
        err = bpf_prog_get_next_id(search_id, &search_id);
        if (err) {
            break;
        }
        
        prog_fd = bpf_prog_get_fd_by_id(search_id);
        if (prog_fd < 0) {
            continue;
        }
        
        memset(&info, 0, sizeof(info));
        info_len = sizeof(info);
        err = bpf_obj_get_info_by_fd(prog_fd, &info, &info_len);
        if (err < 0) {
            close(prog_fd);
            continue;
        }
        
        /* Check if name matches (partial match for flexibility) */
        if (info.type == BPF_PROG_TYPE_XDP && strstr(info.name, module_name) != NULL) {
            /* Found the module, now get its stage from metadata */
            char path[256];
            snprintf(path, sizeof(path), "%s/%s.bpf.o", BUILD_DIR, info.name);
            
            struct rs_module_desc desc;
            if (read_module_metadata(path, &desc) == 0) {
                stage = desc.stage;
                prog_id = search_id;
                snprintf(found_name, sizeof(found_name), "%s", info.name);
                found = 1;
                close(prog_fd);
                break;
            }
        }
        
        close(prog_fd);
    }
    
    if (!found) {
        RS_LOG_ERROR("Module not found: %s", module_name);
        RS_LOG_ERROR("Use 'list' command to see loaded modules.");
        return -1;
    }
    
    printf("Found module: %s at stage %d (prog_id=%d)\n", found_name, stage, prog_id);
    
    /* Clear prog_array entry (delete key) */
    printf("Clearing pipeline stage %d...\n", stage);
    
    if (!ctx->dry_run) {
        err = bpf_map_delete_elem(ctx->rs_progs_fd, &stage);
        if (err < 0) {
            RS_LOG_ERROR("Failed to delete prog_array[%d]: %s", stage, strerror(errno));
            return -1;
        }
    } else {
        printf("[DRY-RUN] Would delete prog_array[%d]\n", stage);
    }
    
    printf("✓ Module unloaded successfully\n");
    printf("  Note: The BPF program may still exist in the kernel.\n");
    printf("        Use 'bpftool prog' to verify and manually delete if needed.\n");
    return 0;
}

/* Check if a program is a loadable module (has RS_DECLARE_MODULE metadata) */
static int is_loadable_module(int prog_fd, struct rs_module_desc *desc)
{
    struct bpf_prog_info info = {};
    __u32 info_len = sizeof(info);
    __u32 btf_id;
    struct btf *btf = NULL;
    const struct btf_type *type;
    const char *sec_name;
    __u32 type_id;
    int ret = 0;
    
    /* Get program info to find BTF ID */
    if (bpf_obj_get_info_by_fd(prog_fd, &info, &info_len) < 0) {
        return 0;
    }
    
    btf_id = info.btf_id;
    if (btf_id == 0) {
        return 0;  /* No BTF, not a module */
    }
    
    /* Load BTF from kernel */
    btf = btf__load_from_kernel_by_id(btf_id);
    if (!btf) {
        return 0;
    }
    
    /* Search for .rodata.mod section in BTF */
    for (type_id = 1; type_id < btf__type_cnt(btf); type_id++) {
        type = btf__type_by_id(btf, type_id);
        if (!btf_is_datasec(type))
            continue;
        
        sec_name = btf__name_by_offset(btf, type->name_off);
        if (strcmp(sec_name, ".rodata.mod") == 0) {
            /* Found module metadata section */
            /* Note: We can't easily read the data from BTF alone,
             * but presence of .rodata.mod section is enough to
             * identify this as a loadable module */
            ret = 1;
            break;
        }
    }
    
    btf__free(btf);
    return ret;
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
    struct rs_module_desc desc;
    
    printf("\n=== Currently Loaded Modules (Pipeline) ===\n");
    printf("%-8s %-30s %-16s %-8s %s\n", "ID", "Module Name", "Tag", "Type", "Status");
    printf("--------------------------------------------------------------------------------\n");
    
    /* Iterate through all BPF programs in the system */
    while (1) {
        err = bpf_prog_get_next_id(prog_id, &prog_id);
        if (err) {
            if (errno == ENOENT) {
                /* No more programs */
                break;
            }
            RS_LOG_ERROR("Error iterating programs: %s", strerror(errno));
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
        
        /* Filter: only XDP programs */
        if (info.type != BPF_PROG_TYPE_XDP) {
            close(prog_fd);
            continue;
        }
        
        /* Check if this is a loadable module (has .rodata.mod metadata) */
        if (!is_loadable_module(prog_fd, &desc)) {
            close(prog_fd);
            continue;
        }
        
        /* Format tag as hex string */
        char tag_str[17];
        snprintf(tag_str, sizeof(tag_str), "%02x%02x%02x%02x%02x%02x%02x%02x",
                 info.tag[0], info.tag[1], info.tag[2], info.tag[3],
                 info.tag[4], info.tag[5], info.tag[6], info.tag[7]);
        
        printf("%-8d %-30s %-16s %-8s %s\n",
               prog_id,
               info.name[0] ? info.name : "<unnamed>",
               tag_str,
               "XDP",
               "loaded");
        
        found++;
        close(prog_fd);
    }
    
    if (found == 0) {
        printf("(No modules loaded in pipeline)\n");
        printf("\nHint: Load modules using rswitch_loader with a profile.\n");
    } else {
        printf("\nTotal: %d module(s) in pipeline\n", found);
    }
    
    printf("\nNote: This shows only loadable modules (with RS_DECLARE_MODULE).\n");
    printf("      Core programs (dispatcher, egress) are not listed.\n");
    printf("\n");
    return 0;
}

/* Usage */
static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s <command> [OPTIONS]\n"
        "   or: %s -r <module> [OPTIONS]\n"
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
        prog, prog, prog, prog, prog, prog);
}

int main(int argc, char **argv)
{
    struct reload_ctx ctx = {0};
    const char *command = NULL;
    const char *module_name = NULL;
    int stages[64] = {0};
    int num_stages = 0;

    rs_log_init("rswitch-reload", RS_LOG_LEVEL_INFO);
    
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "-r") == 0 || strcmp(argv[1], "--reload") == 0) {
        static struct option long_options[] = {
            {"reload", required_argument, NULL, 'r'},
            {"prog-fd", required_argument, NULL, 'p'},
            {"dry-run", no_argument, NULL, 'n'},
            {"verbose", no_argument, NULL, 'v'},
            {"help", no_argument, NULL, 'h'},
            {0, 0, 0, 0},
        };
        int opt;

        command = "reload";
        optind = 1;

        while ((opt = getopt_long(argc, argv, "r:p:nvh", long_options, NULL)) != -1) {
            switch (opt) {
            case 'r':
                module_name = optarg;
                break;
            case 'p':
                ctx.rs_progs_fd = atoi(optarg);
                break;
            case 'n':
                ctx.dry_run = 1;
                break;
            case 'v':
                ctx.verbose = 1;
                break;
            case 'h':
                usage(argv[0]);
                return 0;
            default:
                usage(argv[0]);
                return 1;
            }
        }
    } else {
        command = argv[1];
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--prog-fd") == 0) {
                if (++i >= argc) {
                    RS_LOG_ERROR("Missing argument for %s", argv[i - 1]);
                    return 1;
                }
                ctx.rs_progs_fd = atoi(argv[i]);
                continue;
            }

            if (strcmp(argv[i], "-n") == 0 || strcmp(argv[i], "--dry-run") == 0) {
                ctx.dry_run = 1;
                continue;
            }

            if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
                ctx.verbose = 1;
                continue;
            }

            if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
                usage(argv[0]);
                return 0;
            }

            if (argv[i][0] != '-') {
                if ((strcmp(command, "reload") == 0 || strcmp(command, "unload") == 0) && !module_name) {
                    module_name = argv[i];
                } else if (strcmp(command, "verify") == 0 && num_stages < 64) {
                    stages[num_stages++] = atoi(argv[i]);
                }
            }
        }
    }

    if (ctx.verbose)
        rs_log_set_level(RS_LOG_LEVEL_DEBUG);
    
    /* Execute command */
    if (strcmp(command, "reload") == 0) {
        if (!module_name) {
            RS_LOG_ERROR("module name required for reload");
            usage(argv[0]);
            return 1;
        }
        
        return hot_reload_module(&ctx, module_name) < 0 ? 1 : 0;
        
    } else if (strcmp(command, "unload") == 0) {
        if (!module_name) {
            RS_LOG_ERROR("module name required for unload");
            usage(argv[0]);
            return 1;
        }
        
        return unload_module(&ctx, module_name) < 0 ? 1 : 0;
        
    } else if (strcmp(command, "list") == 0) {
        return list_modules(&ctx) < 0 ? 1 : 0;
        
    } else if (strcmp(command, "verify") == 0) {
        if (num_stages == 0) {
            RS_LOG_ERROR("at least one stage required for verify");
            return 1;
        }
        
        return verify_pipeline(&ctx, stages, num_stages) < 0 ? 1 : 0;
        
    } else {
        RS_LOG_ERROR("Unknown command: %s", command);
        usage(argv[0]);
        return 1;
    }
    
    return 0;
}
