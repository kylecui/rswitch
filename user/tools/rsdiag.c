// SPDX-License-Identifier: GPL-2.0

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#if __has_include("rs_log.h")
#include "rs_log.h"
#else
#include "../common/rs_log.h"
#endif

#include "../../sdk/include/rswitch_obs.h"

#define PIN_PATH "/sys/fs/bpf"

#define DIAG_DISPATCHER_OBJ "./build/bpf/diag_dispatcher.bpf.o"
#define DIAG_EGRESS_OBJ     "./build/bpf/diag_egress.bpf.o"
#define DIAG_KERNEL_OBJ     "./build/bpf/diag_kernel.bpf.o"

static volatile sig_atomic_t stop = 0;

struct rsdiag_ctx {
    int obs_cfg_fd;
    int obs_stats_fd;
    int drop_stats_fd;
    int hist_fd;
    int stage_hit_fd;
    int diag_targets_fd;
    struct bpf_object *diag_dispatcher_obj;
    struct bpf_object *diag_egress_obj;
    struct bpf_object *diag_kernel_obj;
    struct bpf_link **links;
    int nr_links;
    struct ring_buffer *diag_rb;
};

struct stage_hit_row {
    struct rs_stage_hit_key key;
    __u64 hits;
};

struct drop_reason_row {
    __u16 reason;
    __u16 stage;
    __u16 module;
    __u64 packets;
};

struct diff_row {
    __u16 stage;
    __u16 module;
    __u64 old_hits;
    __u64 new_hits;
};

struct diag_dispatcher_rodata {
    bool diag_dispatcher_entry_enabled;
    bool diag_dispatcher_exit_enabled;
    bool diag_module_entry_enabled;
    bool diag_module_exit_enabled;
    __u16 diag_module_stage_id;
    __u16 diag_module_module_id;
};

struct diag_egress_rodata {
    bool diag_egress_entry_enabled;
    bool diag_egress_exit_enabled;
    bool diag_egress_final_entry_enabled;
    bool diag_egress_final_exit_enabled;
};

struct diag_kernel_rodata {
    bool diag_xdp_exception_enabled;
    bool diag_xdp_redirect_err_enabled;
};

static void sig_handler(int sig)
{
    (void)sig;
    stop = 1;
}

static void format_u64_commas(__u64 value, char *buf, size_t len)
{
    char rev[64];
    size_t i = 0, j = 0;

    if (!buf || !len)
        return;

    if (value == 0) {
        snprintf(buf, len, "0");
        return;
    }

    while (value > 0 && i < sizeof(rev) - 1) {
        if (i > 0 && (i % 3) == 0)
            rev[i++] = ',';
        rev[i++] = '0' + (value % 10);
        value /= 10;
    }

    if (i == 0) {
        snprintf(buf, len, "0");
        return;
    }

    while (i > 0 && j < len - 1)
        buf[j++] = rev[--i];
    buf[j] = '\0';
}

static const char *module_id_to_name(__u16 mod_id)
{
    static char user_buf[32];

    switch (mod_id) {
    case RS_MOD_DISPATCHER:   return "dispatcher";
    case RS_MOD_VLAN:         return "vlan";
    case RS_MOD_QOS_CLASSIFY: return "qos_classify";
    case RS_MOD_ACL:          return "acl";
    case RS_MOD_ROUTE:        return "route";
    case RS_MOD_FLOW_TABLE:   return "flow_table";
    case RS_MOD_MIRROR:       return "mirror";
    case RS_MOD_L2LEARN:      return "l2learn";
    case RS_MOD_SFLOW:        return "sflow";
    case RS_MOD_LASTCALL:     return "lastcall";
    case RS_MOD_EGRESS:       return "egress";
    case RS_MOD_EGRESS_QOS:   return "egress_qos";
    case RS_MOD_EGRESS_VLAN:  return "egress_vlan";
    case RS_MOD_EGRESS_FINAL: return "egress_final";
    case RS_MOD_VETH_EGRESS:  return "veth_egress";
    default:
        if (mod_id >= RS_MOD_USER_BASE) {
            snprintf(user_buf, sizeof(user_buf), "user_%u", mod_id);
            return user_buf;
        }
        return "unknown";
    }
}

static int module_name_to_id(const char *name, __u16 *mod_id)
{
    char *end = NULL;
    unsigned long v;

    if (!name || !mod_id)
        return -1;

    if (strcmp(name, "dispatcher") == 0) { *mod_id = RS_MOD_DISPATCHER; return 0; }
    if (strcmp(name, "vlan") == 0) { *mod_id = RS_MOD_VLAN; return 0; }
    if (strcmp(name, "qos_classify") == 0) { *mod_id = RS_MOD_QOS_CLASSIFY; return 0; }
    if (strcmp(name, "acl") == 0) { *mod_id = RS_MOD_ACL; return 0; }
    if (strcmp(name, "route") == 0) { *mod_id = RS_MOD_ROUTE; return 0; }
    if (strcmp(name, "flow_table") == 0) { *mod_id = RS_MOD_FLOW_TABLE; return 0; }
    if (strcmp(name, "mirror") == 0) { *mod_id = RS_MOD_MIRROR; return 0; }
    if (strcmp(name, "l2learn") == 0) { *mod_id = RS_MOD_L2LEARN; return 0; }
    if (strcmp(name, "sflow") == 0) { *mod_id = RS_MOD_SFLOW; return 0; }
    if (strcmp(name, "lastcall") == 0) { *mod_id = RS_MOD_LASTCALL; return 0; }
    if (strcmp(name, "egress") == 0) { *mod_id = RS_MOD_EGRESS; return 0; }
    if (strcmp(name, "egress_qos") == 0) { *mod_id = RS_MOD_EGRESS_QOS; return 0; }
    if (strcmp(name, "egress_vlan") == 0) { *mod_id = RS_MOD_EGRESS_VLAN; return 0; }
    if (strcmp(name, "egress_final") == 0) { *mod_id = RS_MOD_EGRESS_FINAL; return 0; }
    if (strcmp(name, "veth_egress") == 0) { *mod_id = RS_MOD_VETH_EGRESS; return 0; }

    if (strncmp(name, "user_", 5) == 0) {
        v = strtoul(name + 5, &end, 10);
        if (*name && end && *end == '\0' && v >= RS_MOD_USER_BASE && v <= 0xFFFFu) {
            *mod_id = (__u16)v;
            return 0;
        }
    }

    errno = 0;
    v = strtoul(name, &end, 10);
    if (errno == 0 && end && *end == '\0' && v <= 0xFFFFu) {
        *mod_id = (__u16)v;
        return 0;
    }

    return -1;
}

static const char *drop_reason_to_name(__u16 reason)
{
    static char reason_buf[32];

    switch (reason) {
    case RS_DROP_PARSE_ETH:      return "PARSE_ETH";
    case RS_DROP_PARSE_VLAN_TAG: return "PARSE_VLAN_TAG";
    case RS_DROP_PARSE_IP:       return "PARSE_IP";
    case RS_DROP_ACL_DENY:       return "ACL_DENY";
    case RS_DROP_NO_ROUTE:       return "NO_ROUTE";
    case RS_DROP_TTL_EXCEEDED:   return "TTL_EXCEEDED";
    case RS_DROP_QUEUE_FULL:     return "QUEUE_FULL";
    case RS_DROP_RATE_EXCEEDED:  return "RATE_EXCEEDED";
    case RS_DROP_TAILCALL_FAIL:  return "TAILCALL_FAIL";
    case RS_DROP_INTERNAL:       return "INTERNAL";
    case RS_DROP_REDIRECT_FAIL:  return "REDIRECT_FAIL";
    default:
        snprintf(reason_buf, sizeof(reason_buf), "reason_%u", reason);
        return reason_buf;
    }
}

static const char *diag_tag_to_name(__u16 tag)
{
    switch (tag) {
    case RS_DIAG_TAG_ENTRY:      return "ENTRY";
    case RS_DIAG_TAG_EXIT:       return "EXIT";
    case RS_DIAG_TAG_DROP:       return "DROP";
    case RS_DIAG_TAG_REDIRECT:   return "REDIRECT";
    case RS_DIAG_TAG_CHECKPOINT: return "CHECKPOINT";
    case RS_DIAG_TAG_EXCEPTION:  return "EXCEPTION";
    default:                     return "UNKNOWN";
    }
}

static const char *obs_level_to_name(__u32 level)
{
    switch (level) {
    case RS_OBS_LEVEL_L0: return "L0";
    case RS_OBS_LEVEL_L1: return "L1";
    case RS_OBS_LEVEL_L2: return "L2";
    default:              return "UNKNOWN";
    }
}

static void init_ctx(struct rsdiag_ctx *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->obs_cfg_fd = -1;
    ctx->obs_stats_fd = -1;
    ctx->drop_stats_fd = -1;
    ctx->hist_fd = -1;
    ctx->stage_hit_fd = -1;
    ctx->diag_targets_fd = -1;
}

static int open_map_fd(const char *name)
{
    char path[256];

    snprintf(path, sizeof(path), "%s/%s", PIN_PATH, name);
    return bpf_obj_get(path);
}

static int open_pinned_maps(struct rsdiag_ctx *ctx)
{
    ctx->obs_cfg_fd = open_map_fd("rs_obs_cfg_map");
    if (ctx->obs_cfg_fd < 0) {
        RS_LOG_ERROR("Failed to open rs_obs_cfg_map: %s", strerror(errno));
        return -1;
    }

    ctx->obs_stats_fd = open_map_fd("rs_obs_stats_map");
    if (ctx->obs_stats_fd < 0) {
        RS_LOG_ERROR("Failed to open rs_obs_stats_map: %s", strerror(errno));
        return -1;
    }

    ctx->drop_stats_fd = open_map_fd("rs_drop_stats_map");
    if (ctx->drop_stats_fd < 0) {
        RS_LOG_ERROR("Failed to open rs_drop_stats_map: %s", strerror(errno));
        return -1;
    }

    ctx->hist_fd = open_map_fd("rs_hist_map");
    if (ctx->hist_fd < 0) {
        RS_LOG_ERROR("Failed to open rs_hist_map: %s", strerror(errno));
        return -1;
    }

    ctx->stage_hit_fd = open_map_fd("rs_stage_hit_map");
    if (ctx->stage_hit_fd < 0) {
        RS_LOG_ERROR("Failed to open rs_stage_hit_map: %s", strerror(errno));
        return -1;
    }

    ctx->diag_targets_fd = open_map_fd("rs_diag_targets");
    if (ctx->diag_targets_fd < 0) {
        RS_LOG_ERROR("Failed to open rs_diag_targets: %s", strerror(errno));
        return -1;
    }

    return 0;
}

static void close_ctx(struct rsdiag_ctx *ctx)
{
    int i;

    if (!ctx)
        return;

    if (ctx->obs_cfg_fd >= 0)
        close(ctx->obs_cfg_fd);
    if (ctx->obs_stats_fd >= 0)
        close(ctx->obs_stats_fd);
    if (ctx->drop_stats_fd >= 0)
        close(ctx->drop_stats_fd);
    if (ctx->hist_fd >= 0)
        close(ctx->hist_fd);
    if (ctx->stage_hit_fd >= 0)
        close(ctx->stage_hit_fd);
    if (ctx->diag_targets_fd >= 0)
        close(ctx->diag_targets_fd);

    if (ctx->links) {
        for (i = 0; i < ctx->nr_links; i++) {
            if (ctx->links[i])
                bpf_link__destroy(ctx->links[i]);
        }
        free(ctx->links);
        ctx->links = NULL;
        ctx->nr_links = 0;
    }

    ring_buffer__free(ctx->diag_rb);
    ctx->diag_rb = NULL;

    bpf_object__close(ctx->diag_dispatcher_obj);
    bpf_object__close(ctx->diag_egress_obj);
    bpf_object__close(ctx->diag_kernel_obj);
    ctx->diag_dispatcher_obj = NULL;
    ctx->diag_egress_obj = NULL;
    ctx->diag_kernel_obj = NULL;
}

static int add_link(struct rsdiag_ctx *ctx, struct bpf_link *link)
{
    struct bpf_link **new_links;

    new_links = realloc(ctx->links, sizeof(*ctx->links) * (ctx->nr_links + 1));
    if (!new_links) {
        RS_LOG_ERROR("Failed to grow link array");
        return -1;
    }

    ctx->links = new_links;
    ctx->links[ctx->nr_links++] = link;
    return 0;
}

static int find_target_by_kind_module(int map_fd, __u16 kind, __u16 module_id,
                                      const char *module_name,
                                      struct rs_diag_target *out)
{
    struct rs_diag_target_key key, next_key;
    struct rs_diag_target val;
    int ret;

    memset(&key, 0, sizeof(key));
    ret = bpf_map_get_next_key(map_fd, NULL, &next_key);
    while (ret == 0) {
        key = next_key;
        if (bpf_map_lookup_elem(map_fd, &key, &val) == 0) {
            if (val.kind == kind) {
                if (kind == RS_DIAG_TARGET_MODULE) {
                    if (module_name && strncmp(val.module_name, module_name,
                                               sizeof(val.module_name)) == 0) {
                        *out = val;
                        return 0;
                    }
                } else {
                    if (module_id == 0 || val.module_id == module_id) {
                        *out = val;
                        return 0;
                    }
                }
            }
        }
        ret = bpf_map_get_next_key(map_fd, &key, &next_key);
    }

    return -1;
}

static int set_prog_autoload(struct bpf_object *obj, const char *prog_name, bool enabled)
{
    struct bpf_program *prog;

    prog = bpf_object__find_program_by_name(obj, prog_name);
    if (!prog) {
        RS_LOG_ERROR("Program '%s' not found", prog_name);
        return -1;
    }
    bpf_program__set_autoload(prog, enabled);
    return 0;
}

static int set_attach_target_for_prog(struct bpf_object *obj, const char *prog_name,
                                      const struct rs_diag_target *target)
{
    struct bpf_program *prog;
    int target_fd;
    int ret;

    prog = bpf_object__find_program_by_name(obj, prog_name);
    if (!prog) {
        RS_LOG_ERROR("Program '%s' not found", prog_name);
        return -1;
    }

    target_fd = bpf_prog_get_fd_by_id(target->prog_id);
    if (target_fd < 0) {
        RS_LOG_ERROR("Failed to get prog fd by id %u: %s", target->prog_id, strerror(errno));
        return -1;
    }

    ret = bpf_program__set_attach_target(prog, target_fd, target->prog_name);
    close(target_fd);
    if (ret) {
        RS_LOG_ERROR("set_attach_target failed for '%s' -> '%s': %d",
                     prog_name, target->prog_name, ret);
        return -1;
    }

    return 0;
}

static int setup_dispatcher_rodata(struct bpf_object *obj,
                                   bool dispatcher,
                                   bool module,
                                   __u16 module_stage,
                                   __u16 module_id)
{
    struct bpf_map *rodata;
    struct diag_dispatcher_rodata *cfg;
    size_t sz = 0;

    rodata = bpf_object__find_map_by_name(obj, ".rodata");
    if (!rodata) {
        RS_LOG_ERROR("Failed to find .rodata in dispatcher object");
        return -1;
    }

    cfg = bpf_map__initial_value(rodata, &sz);
    if (!cfg || sz < sizeof(*cfg)) {
        RS_LOG_ERROR("Invalid dispatcher .rodata size (%zu)", sz);
        return -1;
    }

    memset(cfg, 0, sizeof(*cfg));
    cfg->diag_dispatcher_entry_enabled = dispatcher;
    cfg->diag_dispatcher_exit_enabled = dispatcher;
    cfg->diag_module_entry_enabled = module;
    cfg->diag_module_exit_enabled = module;
    cfg->diag_module_stage_id = module_stage;
    cfg->diag_module_module_id = module_id;
    return 0;
}

static int setup_egress_rodata(struct bpf_object *obj, bool egress, bool egress_final)
{
    struct bpf_map *rodata;
    struct diag_egress_rodata *cfg;
    size_t sz = 0;

    rodata = bpf_object__find_map_by_name(obj, ".rodata");
    if (!rodata) {
        RS_LOG_ERROR("Failed to find .rodata in egress object");
        return -1;
    }

    cfg = bpf_map__initial_value(rodata, &sz);
    if (!cfg || sz < sizeof(*cfg)) {
        RS_LOG_ERROR("Invalid egress .rodata size (%zu)", sz);
        return -1;
    }

    memset(cfg, 0, sizeof(*cfg));
    cfg->diag_egress_entry_enabled = egress;
    cfg->diag_egress_exit_enabled = egress;
    cfg->diag_egress_final_entry_enabled = egress_final;
    cfg->diag_egress_final_exit_enabled = egress_final;
    return 0;
}

static int setup_kernel_rodata(struct bpf_object *obj, bool xdp_exception, bool xdp_redirect_err)
{
    struct bpf_map *rodata;
    struct diag_kernel_rodata *cfg;
    size_t sz = 0;

    rodata = bpf_object__find_map_by_name(obj, ".rodata");
    if (!rodata) {
        RS_LOG_ERROR("Failed to find .rodata in kernel object");
        return -1;
    }

    cfg = bpf_map__initial_value(rodata, &sz);
    if (!cfg || sz < sizeof(*cfg)) {
        RS_LOG_ERROR("Invalid kernel .rodata size (%zu)", sz);
        return -1;
    }

    memset(cfg, 0, sizeof(*cfg));
    cfg->diag_xdp_exception_enabled = xdp_exception;
    cfg->diag_xdp_redirect_err_enabled = xdp_redirect_err;
    return 0;
}

static int attach_autoloaded_programs(struct rsdiag_ctx *ctx, struct bpf_object *obj)
{
    struct bpf_program *prog;

    bpf_object__for_each_program(prog, obj) {
        struct bpf_link *link;
        int fd;

        fd = bpf_program__fd(prog);
        if (fd < 0)
            continue;

        link = bpf_program__attach(prog);
        if (libbpf_get_error(link)) {
            RS_LOG_ERROR("Failed to attach program '%s'", bpf_program__name(prog));
            return -1;
        }

        if (add_link(ctx, link) < 0) {
            bpf_link__destroy(link);
            return -1;
        }
    }

    return 0;
}

static int handle_diag_event(void *ctx_unused, void *data, size_t data_sz)
{
    struct rs_diag_event *evt = data;

    (void)ctx_unused;
    if (data_sz < sizeof(*evt))
        return 0;

    printf("[%llu] cpu=%u pid=%u ifindex=%u tag=%s stage=%u mod=%s action=%u reason=%u\n",
           (unsigned long long)evt->ts_ns,
           evt->cpu,
           evt->pid,
           evt->ifindex,
           diag_tag_to_name(evt->tag),
           evt->stage_id,
           module_id_to_name(evt->module_id),
           evt->action,
           evt->reason);
    return 0;
}

static void usage(const char *prog)
{
    fprintf(stderr, "rsdiag - rSwitch Diagnostic Tool\n\n");
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  %s start [--dispatcher] [--egress] [--egress-final] [--kernel] [--module <name>] [--all]\n", prog);
    fprintf(stderr, "  %s stop\n", prog);
    fprintf(stderr, "  %s status\n", prog);
    fprintf(stderr, "  %s dump --view <matrix|reason|diff> [options]\n", prog);
    fprintf(stderr, "  %s dump --diag-live\n", prog);
    fprintf(stderr, "\n");
    fprintf(stderr, "dump options:\n");
    fprintf(stderr, "  --view matrix [--pipeline P] [--profile R]\n");
    fprintf(stderr, "  --view reason [--stage S] [--module M] [--top N]\n");
    fprintf(stderr, "  --view diff --old-profile X --new-profile Y [--pipeline P]\n");
    fprintf(stderr, "  --diag-live    Stream live diagnostic events from ringbuf\n");
}

static int cmd_stop(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    printf("rsdiag is a foreground tool. Use Ctrl+C to stop.\n");
    return 0;
}

static int kind_to_short_name(__u16 kind, char *buf, size_t len)
{
    if (!buf || !len)
        return -1;

    switch (kind) {
    case RS_DIAG_TARGET_DISPATCHER:
        snprintf(buf, len, "DISP");
        break;
    case RS_DIAG_TARGET_EGRESS:
        snprintf(buf, len, "EGR");
        break;
    case RS_DIAG_TARGET_MODULE:
        snprintf(buf, len, "MOD");
        break;
    default:
        snprintf(buf, len, "%u", kind);
        break;
    }
    return 0;
}

static int cmd_status(int argc, char **argv)
{
    struct rsdiag_ctx ctx;
    struct rs_obs_cfg cfg;
    struct rs_diag_target_key key, next_key;
    struct rs_diag_target target;
    __u32 cfg_key = 0;
    int ret;
    int count = 0;

    (void)argc;
    (void)argv;

    init_ctx(&ctx);
    if (open_pinned_maps(&ctx) < 0)
        goto err;

    ret = bpf_map_lookup_elem(ctx.obs_cfg_fd, &cfg_key, &cfg);
    if (ret < 0) {
        RS_LOG_ERROR("Failed to read rs_obs_cfg_map: %s", strerror(errno));
        goto err;
    }

    printf("Observability Config:\n");
    printf("  Level: %s\n", obs_level_to_name(cfg.level));
    printf("  Sample PPM: %u\n", cfg.sample_ppm);
    printf("  Event Mask: 0x%llx\n", (unsigned long long)cfg.event_mask);
    printf("  Burst Limit: %u\n\n", cfg.burst_limit);

    printf("Diagnostic Targets:\n");
    printf("+----------+---------+----------+-------+------------------+------------------+\n");
    printf("| prog_id  | stage   | module   | kind  | prog_name        | module_name      |\n");
    printf("+----------+---------+----------+-------+------------------+------------------+\n");

    ret = bpf_map_get_next_key(ctx.diag_targets_fd, NULL, &next_key);
    while (ret == 0) {
        char kind_buf[8];

        key = next_key;
        if (bpf_map_lookup_elem(ctx.diag_targets_fd, &key, &target) == 0) {
            kind_to_short_name(target.kind, kind_buf, sizeof(kind_buf));
            printf("| %-8u | %-7u | %-8u | %-5s | %-16.16s | %-16.16s |\n",
                   target.prog_id,
                   target.stage_id,
                   target.module_id,
                   kind_buf,
                   target.prog_name,
                   target.module_name);
            count++;
        }

        ret = bpf_map_get_next_key(ctx.diag_targets_fd, &key, &next_key);
    }

    printf("+----------+---------+----------+-------+------------------+------------------+\n");
    printf("Total targets: %d\n", count);

    close_ctx(&ctx);
    return 0;

err:
    close_ctx(&ctx);
    return 1;
}

static int cmp_stage_hit_rows(const void *a, const void *b)
{
    const struct stage_hit_row *ra = a;
    const struct stage_hit_row *rb = b;

    if (ra->key.stage_id != rb->key.stage_id)
        return (int)ra->key.stage_id - (int)rb->key.stage_id;
    return (int)ra->key.module_id - (int)rb->key.module_id;
}

static int cmp_drop_rows(const void *a, const void *b)
{
    const struct drop_reason_row *ra = a;
    const struct drop_reason_row *rb = b;

    if (ra->packets < rb->packets)
        return 1;
    if (ra->packets > rb->packets)
        return -1;
    return 0;
}

static int cmp_diff_rows(const void *a, const void *b)
{
    const struct diff_row *ra = a;
    const struct diff_row *rb = b;

    if (ra->stage != rb->stage)
        return (int)ra->stage - (int)rb->stage;
    return (int)ra->module - (int)rb->module;
}

static int sum_stage_hit_percpu(int map_fd, const struct rs_stage_hit_key *key, __u64 *hits)
{
    struct rs_stage_hit_val *vals;
    int ncpus;
    int i;

    ncpus = libbpf_num_possible_cpus();
    if (ncpus <= 0)
        return -1;

    vals = calloc(ncpus, sizeof(*vals));
    if (!vals)
        return -1;

    if (bpf_map_lookup_elem(map_fd, key, vals) < 0) {
        free(vals);
        return -1;
    }

    *hits = 0;
    for (i = 0; i < ncpus; i++)
        *hits += vals[i].hits;

    free(vals);
    return 0;
}

static int sum_drop_percpu(int map_fd, const struct rs_drop_stats_key *key, __u64 *packets)
{
    struct rs_drop_stats_val *vals;
    int ncpus;
    int i;

    ncpus = libbpf_num_possible_cpus();
    if (ncpus <= 0)
        return -1;

    vals = calloc(ncpus, sizeof(*vals));
    if (!vals)
        return -1;

    if (bpf_map_lookup_elem(map_fd, key, vals) < 0) {
        free(vals);
        return -1;
    }

    *packets = 0;
    for (i = 0; i < ncpus; i++)
        *packets += vals[i].packets;

    free(vals);
    return 0;
}

static int dump_view_matrix(struct rsdiag_ctx *ctx, int pipeline, int profile)
{
    struct rs_stage_hit_key key, next_key;
    struct stage_hit_row *rows = NULL;
    size_t nr_rows = 0;
    size_t cap = 0;
    int ret;
    size_t i;
    __u64 max_hits = 0;

    ret = bpf_map_get_next_key(ctx->stage_hit_fd, NULL, &next_key);
    while (ret == 0) {
        struct stage_hit_row row;

        key = next_key;
        if ((pipeline >= 0 && key.pipeline_id != (__u16)pipeline) ||
            (profile >= 0 && key.profile_id != (__u16)profile)) {
            ret = bpf_map_get_next_key(ctx->stage_hit_fd, &key, &next_key);
            continue;
        }

        if (sum_stage_hit_percpu(ctx->stage_hit_fd, &key, &row.hits) == 0) {
            row.key = key;
            if (nr_rows == cap) {
                size_t new_cap = cap ? cap * 2 : 64;
                struct stage_hit_row *tmp = realloc(rows, new_cap * sizeof(*rows));
                if (!tmp) {
                    RS_LOG_ERROR("Out of memory");
                    free(rows);
                    return -1;
                }
                rows = tmp;
                cap = new_cap;
            }
            rows[nr_rows++] = row;
            if (row.hits > max_hits)
                max_hits = row.hits;
        }

        ret = bpf_map_get_next_key(ctx->stage_hit_fd, &key, &next_key);
    }

    qsort(rows, nr_rows, sizeof(*rows), cmp_stage_hit_rows);

    if (pipeline >= 0 && profile >= 0)
        printf("Stage Hit Matrix (pipeline=%d, profile=%d):\n", pipeline, profile);
    else if (pipeline >= 0)
        printf("Stage Hit Matrix (pipeline=%d, profile=all):\n", pipeline);
    else if (profile >= 0)
        printf("Stage Hit Matrix (pipeline=all, profile=%d):\n", profile);
    else
        printf("Stage Hit Matrix (pipeline=all, profile=all):\n");
    printf("+-------+----------------+-------------+----------+\n");
    printf("| stage | module         | hits        | hit_pct  |\n");
    printf("+-------+----------------+-------------+----------+\n");

    for (i = 0; i < nr_rows; i++) {
        char hits_buf[32];
        double pct = 0.0;

        format_u64_commas(rows[i].hits, hits_buf, sizeof(hits_buf));
        if (max_hits)
            pct = (double)rows[i].hits * 100.0 / (double)max_hits;

        printf("| %-5u | %-14s | %11s | %7.2f%% |\n",
               rows[i].key.stage_id,
               module_id_to_name(rows[i].key.module_id),
               hits_buf,
               pct);
    }

    printf("+-------+----------------+-------------+----------+\n");

    free(rows);
    return 0;
}

static int dump_view_reason(struct rsdiag_ctx *ctx, int stage, int module, int topn)
{
    struct rs_drop_stats_key key, next_key;
    struct drop_reason_row *rows = NULL;
    size_t nr_rows = 0;
    size_t cap = 0;
    int ret;
    size_t i;

    ret = bpf_map_get_next_key(ctx->drop_stats_fd, NULL, &next_key);
    while (ret == 0) {
        struct drop_reason_row row;

        key = next_key;
        if ((stage >= 0 && key.stage_id != (__u16)stage) ||
            (module >= 0 && key.module_id != (__u16)module)) {
            ret = bpf_map_get_next_key(ctx->drop_stats_fd, &key, &next_key);
            continue;
        }

        if (sum_drop_percpu(ctx->drop_stats_fd, &key, &row.packets) == 0) {
            size_t j;
            bool merged = false;

            row.reason = key.reason;
            row.stage = key.stage_id;
            row.module = key.module_id;

            for (j = 0; j < nr_rows; j++) {
                if (rows[j].reason == row.reason &&
                    rows[j].stage == row.stage &&
                    rows[j].module == row.module) {
                    rows[j].packets += row.packets;
                    merged = true;
                    break;
                }
            }

            if (merged) {
                ret = bpf_map_get_next_key(ctx->drop_stats_fd, &key, &next_key);
                continue;
            }

            if (nr_rows == cap) {
                size_t new_cap = cap ? cap * 2 : 64;
                struct drop_reason_row *tmp = realloc(rows, new_cap * sizeof(*rows));
                if (!tmp) {
                    RS_LOG_ERROR("Out of memory");
                    free(rows);
                    return -1;
                }
                rows = tmp;
                cap = new_cap;
            }
            rows[nr_rows++] = row;
        }

        ret = bpf_map_get_next_key(ctx->drop_stats_fd, &key, &next_key);
    }

    qsort(rows, nr_rows, sizeof(*rows), cmp_drop_rows);

    if (topn <= 0)
        topn = 10;
    if ((size_t)topn > nr_rows)
        topn = (int)nr_rows;

    printf("Top Drop Reasons:\n");
    printf("+------+-------------------+-------+---------+-----------+\n");
    printf("| rank | reason            | stage | module  | packets   |\n");
    printf("+------+-------------------+-------+---------+-----------+\n");

    for (i = 0; i < (size_t)topn; i++) {
        char pkt_buf[32];

        format_u64_commas(rows[i].packets, pkt_buf, sizeof(pkt_buf));
        printf("| %-4zu | %-17s | %-5u | %-7s | %9s |\n",
               i + 1,
               drop_reason_to_name(rows[i].reason),
               rows[i].stage,
               module_id_to_name(rows[i].module),
               pkt_buf);
    }

    printf("+------+-------------------+-------+---------+-----------+\n");

    free(rows);
    return 0;
}

static int diff_row_upsert(struct diff_row **rows, size_t *nr_rows, size_t *cap,
                           __u16 stage, __u16 module, bool is_old, __u64 hits)
{
    size_t i;

    for (i = 0; i < *nr_rows; i++) {
        if ((*rows)[i].stage == stage && (*rows)[i].module == module) {
            if (is_old)
                (*rows)[i].old_hits += hits;
            else
                (*rows)[i].new_hits += hits;
            return 0;
        }
    }

    if (*nr_rows == *cap) {
        size_t new_cap = *cap ? *cap * 2 : 64;
        struct diff_row *tmp = realloc(*rows, new_cap * sizeof(**rows));
        if (!tmp)
            return -1;
        *rows = tmp;
        *cap = new_cap;
    }

    (*rows)[*nr_rows].stage = stage;
    (*rows)[*nr_rows].module = module;
    (*rows)[*nr_rows].old_hits = is_old ? hits : 0;
    (*rows)[*nr_rows].new_hits = is_old ? 0 : hits;
    (*nr_rows)++;
    return 0;
}

static int dump_view_diff(struct rsdiag_ctx *ctx, int old_profile, int new_profile, int pipeline)
{
    struct rs_stage_hit_key key, next_key;
    struct diff_row *rows = NULL;
    size_t nr_rows = 0;
    size_t cap = 0;
    int ret;
    size_t i;

    ret = bpf_map_get_next_key(ctx->stage_hit_fd, NULL, &next_key);
    while (ret == 0) {
        __u64 hits = 0;
        bool is_old;

        key = next_key;

        if (pipeline >= 0 && key.pipeline_id != (__u16)pipeline) {
            ret = bpf_map_get_next_key(ctx->stage_hit_fd, &key, &next_key);
            continue;
        }

        if (key.profile_id != (__u16)old_profile && key.profile_id != (__u16)new_profile) {
            ret = bpf_map_get_next_key(ctx->stage_hit_fd, &key, &next_key);
            continue;
        }

        if (sum_stage_hit_percpu(ctx->stage_hit_fd, &key, &hits) < 0) {
            ret = bpf_map_get_next_key(ctx->stage_hit_fd, &key, &next_key);
            continue;
        }

        is_old = (key.profile_id == (__u16)old_profile);
        if (diff_row_upsert(&rows, &nr_rows, &cap, key.stage_id, key.module_id, is_old, hits) < 0) {
            free(rows);
            return -1;
        }

        ret = bpf_map_get_next_key(ctx->stage_hit_fd, &key, &next_key);
    }

    qsort(rows, nr_rows, sizeof(*rows), cmp_diff_rows);

    printf("Profile Diff (old=%d, new=%d, pipeline=%s):\n",
           old_profile, new_profile, pipeline >= 0 ? "set" : "all");
    printf("+-------+----------+----------+----------+---------+\n");
    printf("| stage | module   | old_hits | new_hits | delta   |\n");
    printf("+-------+----------+----------+----------+---------+\n");

    for (i = 0; i < nr_rows; i++) {
        char old_buf[32], new_buf[32];
        char delta_buf[32];

        format_u64_commas(rows[i].old_hits, old_buf, sizeof(old_buf));
        format_u64_commas(rows[i].new_hits, new_buf, sizeof(new_buf));

        if (rows[i].old_hits == 0) {
            if (rows[i].new_hits == 0)
                snprintf(delta_buf, sizeof(delta_buf), "0.0%%");
            else
                snprintf(delta_buf, sizeof(delta_buf), "+inf");
        } else {
            double delta = ((double)rows[i].new_hits - (double)rows[i].old_hits) *
                           100.0 / (double)rows[i].old_hits;
            snprintf(delta_buf, sizeof(delta_buf), "%+.1f%%", delta);
        }

        printf("| %-5u | %-8s | %8s | %8s | %7s |\n",
               rows[i].stage,
               module_id_to_name(rows[i].module),
               old_buf,
               new_buf,
               delta_buf);
    }

    printf("+-------+----------+----------+----------+---------+\n");
    free(rows);
    return 0;
}

static int stream_diag_ringbuf(void)
{
    struct ring_buffer *rb = NULL;
    int rb_fd;
    int ret = 0;

    rb_fd = open_map_fd("rs_diag_ringbuf");
    if (rb_fd < 0) {
        RS_LOG_ERROR("Failed to open rs_diag_ringbuf: %s", strerror(errno));
        return -1;
    }

    rb = ring_buffer__new(rb_fd, handle_diag_event, NULL, NULL);
    close(rb_fd);
    if (!rb) {
        RS_LOG_ERROR("Failed to create ring buffer");
        return -1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("Streaming diagnostic events... Press Ctrl+C to stop.\n");
    while (!stop) {
        ret = ring_buffer__poll(rb, 100);
        if (ret == -EINTR)
            break;
        if (ret < 0) {
            RS_LOG_ERROR("ring_buffer__poll failed: %d", ret);
            ring_buffer__free(rb);
            return -1;
        }
    }

    ring_buffer__free(rb);
    return 0;
}

static int cmd_dump(int argc, char **argv)
{
    static const struct option long_opts[] = {
        { "view", required_argument, NULL, 'v' },
        { "pipeline", required_argument, NULL, 'p' },
        { "profile", required_argument, NULL, 'r' },
        { "stage", required_argument, NULL, 's' },
        { "module", required_argument, NULL, 'm' },
        { "top", required_argument, NULL, 'n' },
        { "old-profile", required_argument, NULL, 'o' },
        { "new-profile", required_argument, NULL, 'w' },
        { "diag-live", no_argument, NULL, 'l' },
        { "help", no_argument, NULL, 'h' },
        { 0, 0, 0, 0 },
    };
    struct rsdiag_ctx ctx;
    const char *view = NULL;
    int pipeline = -1;
    int profile = -1;
    int stage = -1;
    int module = -1;
    int topn = 10;
    int old_profile = -1;
    int new_profile = -1;
    int diag_live = 0;
    int opt;

    optind = 1;
    while ((opt = getopt_long(argc, argv, "", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'v':
            view = optarg;
            break;
        case 'p':
            pipeline = atoi(optarg);
            break;
        case 'r':
            profile = atoi(optarg);
            break;
        case 's':
            stage = atoi(optarg);
            break;
        case 'm': {
            __u16 mid;
            if (module_name_to_id(optarg, &mid) < 0) {
                RS_LOG_ERROR("Unknown module: %s", optarg);
                return 1;
            }
            module = mid;
            break;
        }
        case 'n':
            topn = atoi(optarg);
            break;
        case 'o':
            old_profile = atoi(optarg);
            break;
        case 'w':
            new_profile = atoi(optarg);
            break;
        case 'l':
            diag_live = 1;
            break;
        case 'h':
        default:
            usage("rsdiag");
            return 1;
        }
    }

    if (diag_live)
        return stream_diag_ringbuf() < 0 ? 1 : 0;

    if (!view) {
        RS_LOG_ERROR("dump requires --view or --diag-live");
        return 1;
    }

    init_ctx(&ctx);
    if (open_pinned_maps(&ctx) < 0)
        goto err;

    if (strcmp(view, "matrix") == 0) {
        if (dump_view_matrix(&ctx, pipeline, profile) < 0)
            goto err;
    } else if (strcmp(view, "reason") == 0) {
        if (dump_view_reason(&ctx, stage, module, topn) < 0)
            goto err;
    } else if (strcmp(view, "diff") == 0) {
        if (old_profile < 0 || new_profile < 0) {
            RS_LOG_ERROR("dump --view diff requires --old-profile and --new-profile");
            goto err;
        }
        if (dump_view_diff(&ctx, old_profile, new_profile, pipeline) < 0)
            goto err;
    } else {
        RS_LOG_ERROR("Unknown dump view: %s", view);
        goto err;
    }

    close_ctx(&ctx);
    return 0;

err:
    close_ctx(&ctx);
    return 1;
}

static int cmd_start(int argc, char **argv)
{
    static const struct option long_opts[] = {
        { "dispatcher", no_argument, NULL, 'd' },
        { "egress", no_argument, NULL, 'e' },
        { "egress-final", no_argument, NULL, 'f' },
        { "kernel", no_argument, NULL, 'k' },
        { "module", required_argument, NULL, 'm' },
        { "all", no_argument, NULL, 'a' },
        { "help", no_argument, NULL, 'h' },
        { 0, 0, 0, 0 },
    };
    struct rsdiag_ctx ctx;
    struct rs_diag_target target_dispatcher, target_egress, target_egress_final, target_module;
    bool do_dispatcher = false;
    bool do_egress = false;
    bool do_egress_final = false;
    bool do_kernel = false;
    bool do_module = false;
    bool do_all = false;
    char module_name[32] = {};
    int ringbuf_fd = -1;
    int ret = -1;
    int opt;

    memset(&target_dispatcher, 0, sizeof(target_dispatcher));
    memset(&target_egress, 0, sizeof(target_egress));
    memset(&target_egress_final, 0, sizeof(target_egress_final));
    memset(&target_module, 0, sizeof(target_module));

    optind = 1;
    while ((opt = getopt_long(argc, argv, "", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'd':
            do_dispatcher = true;
            break;
        case 'e':
            do_egress = true;
            break;
        case 'f':
            do_egress_final = true;
            break;
        case 'k':
            do_kernel = true;
            break;
        case 'm':
            do_module = true;
            snprintf(module_name, sizeof(module_name), "%s", optarg);
            break;
        case 'a':
            do_all = true;
            break;
        case 'h':
        default:
            usage("rsdiag");
            return 1;
        }
    }

    if (do_all) {
        do_dispatcher = true;
        do_egress = true;
        do_egress_final = true;
        do_kernel = true;
    }

    if (!do_dispatcher && !do_egress && !do_egress_final && !do_kernel && !do_module) {
        RS_LOG_ERROR("start requires at least one selector (--dispatcher/--egress/--egress-final/--kernel/--module/--all)");
        return 1;
    }

    init_ctx(&ctx);
    if (open_pinned_maps(&ctx) < 0)
        goto out;

    if (ctx.diag_targets_fd < 0) {
        RS_LOG_ERROR("rs_diag_targets map unavailable");
        goto out;
    }

    if (do_dispatcher) {
        if (find_target_by_kind_module(ctx.diag_targets_fd, RS_DIAG_TARGET_DISPATCHER,
                                       RS_MOD_DISPATCHER, NULL,
                                       &target_dispatcher) < 0) {
            RS_LOG_ERROR("Dispatcher target not found in rs_diag_targets");
            goto out;
        }
    }

    if (do_egress) {
        if (find_target_by_kind_module(ctx.diag_targets_fd, RS_DIAG_TARGET_EGRESS,
                                       RS_MOD_EGRESS, NULL,
                                       &target_egress) < 0) {
            RS_LOG_ERROR("Egress target not found in rs_diag_targets");
            goto out;
        }
    }

    if (do_egress_final) {
        if (find_target_by_kind_module(ctx.diag_targets_fd, RS_DIAG_TARGET_EGRESS,
                                       RS_MOD_EGRESS_FINAL, NULL,
                                       &target_egress_final) < 0) {
            RS_LOG_ERROR("Egress-final target not found in rs_diag_targets");
            goto out;
        }
    }

    if (do_module) {
        if (find_target_by_kind_module(ctx.diag_targets_fd, RS_DIAG_TARGET_MODULE,
                                       0, module_name,
                                       &target_module) < 0) {
            RS_LOG_ERROR("Module target '%s' not found in rs_diag_targets", module_name);
            goto out;
        }
    }

    if (do_dispatcher || do_module) {
        struct bpf_program *prog;

        ctx.diag_dispatcher_obj = bpf_object__open_file(DIAG_DISPATCHER_OBJ, NULL);
        if (libbpf_get_error(ctx.diag_dispatcher_obj)) {
            RS_LOG_ERROR("Failed to open %s", DIAG_DISPATCHER_OBJ);
            ctx.diag_dispatcher_obj = NULL;
            goto out;
        }

        bpf_object__for_each_program(prog, ctx.diag_dispatcher_obj)
            bpf_program__set_autoload(prog, false);

        if (do_dispatcher) {
            if (set_prog_autoload(ctx.diag_dispatcher_obj, "diag_dispatcher_entry", true) < 0 ||
                set_prog_autoload(ctx.diag_dispatcher_obj, "diag_dispatcher_exit", true) < 0)
                goto out;

            if (set_attach_target_for_prog(ctx.diag_dispatcher_obj, "diag_dispatcher_entry",
                                           &target_dispatcher) < 0 ||
                set_attach_target_for_prog(ctx.diag_dispatcher_obj, "diag_dispatcher_exit",
                                           &target_dispatcher) < 0)
                goto out;
        }

        if (do_module) {
            if (set_prog_autoload(ctx.diag_dispatcher_obj, "diag_module_entry", true) < 0 ||
                set_prog_autoload(ctx.diag_dispatcher_obj, "diag_module_exit", true) < 0)
                goto out;

            if (set_attach_target_for_prog(ctx.diag_dispatcher_obj, "diag_module_entry",
                                           &target_module) < 0 ||
                set_attach_target_for_prog(ctx.diag_dispatcher_obj, "diag_module_exit",
                                           &target_module) < 0)
                goto out;
        }

        if (setup_dispatcher_rodata(ctx.diag_dispatcher_obj,
                                    do_dispatcher,
                                    do_module,
                                    target_module.stage_id,
                                    target_module.module_id) < 0)
            goto out;

        if (bpf_object__load(ctx.diag_dispatcher_obj)) {
            RS_LOG_ERROR("Failed to load dispatcher diag object");
            goto out;
        }

        if (attach_autoloaded_programs(&ctx, ctx.diag_dispatcher_obj) < 0)
            goto out;
    }

    if (do_egress || do_egress_final) {
        struct bpf_program *prog;

        ctx.diag_egress_obj = bpf_object__open_file(DIAG_EGRESS_OBJ, NULL);
        if (libbpf_get_error(ctx.diag_egress_obj)) {
            RS_LOG_ERROR("Failed to open %s", DIAG_EGRESS_OBJ);
            ctx.diag_egress_obj = NULL;
            goto out;
        }

        bpf_object__for_each_program(prog, ctx.diag_egress_obj)
            bpf_program__set_autoload(prog, false);

        if (do_egress) {
            if (set_prog_autoload(ctx.diag_egress_obj, "diag_egress_entry", true) < 0 ||
                set_prog_autoload(ctx.diag_egress_obj, "diag_egress_exit", true) < 0)
                goto out;

            if (set_attach_target_for_prog(ctx.diag_egress_obj, "diag_egress_entry", &target_egress) < 0 ||
                set_attach_target_for_prog(ctx.diag_egress_obj, "diag_egress_exit", &target_egress) < 0)
                goto out;
        }

        if (do_egress_final) {
            if (set_prog_autoload(ctx.diag_egress_obj, "diag_egress_final_entry", true) < 0 ||
                set_prog_autoload(ctx.diag_egress_obj, "diag_egress_final_exit", true) < 0)
                goto out;

            if (set_attach_target_for_prog(ctx.diag_egress_obj, "diag_egress_final_entry", &target_egress_final) < 0 ||
                set_attach_target_for_prog(ctx.diag_egress_obj, "diag_egress_final_exit", &target_egress_final) < 0)
                goto out;
        }

        if (setup_egress_rodata(ctx.diag_egress_obj, do_egress, do_egress_final) < 0)
            goto out;

        if (bpf_object__load(ctx.diag_egress_obj)) {
            RS_LOG_ERROR("Failed to load egress diag object");
            goto out;
        }

        if (attach_autoloaded_programs(&ctx, ctx.diag_egress_obj) < 0)
            goto out;
    }

    if (do_kernel) {
        struct bpf_program *prog;

        ctx.diag_kernel_obj = bpf_object__open_file(DIAG_KERNEL_OBJ, NULL);
        if (libbpf_get_error(ctx.diag_kernel_obj)) {
            RS_LOG_ERROR("Failed to open %s", DIAG_KERNEL_OBJ);
            ctx.diag_kernel_obj = NULL;
            goto out;
        }

        bpf_object__for_each_program(prog, ctx.diag_kernel_obj)
            bpf_program__set_autoload(prog, false);

        if (set_prog_autoload(ctx.diag_kernel_obj, "diag_xdp_exception", true) < 0 ||
            set_prog_autoload(ctx.diag_kernel_obj, "diag_xdp_redirect_err", true) < 0)
            goto out;

        if (setup_kernel_rodata(ctx.diag_kernel_obj, true, true) < 0)
            goto out;

        if (bpf_object__load(ctx.diag_kernel_obj)) {
            RS_LOG_ERROR("Failed to load kernel diag object");
            goto out;
        }

        if (attach_autoloaded_programs(&ctx, ctx.diag_kernel_obj) < 0)
            goto out;
    }

    ringbuf_fd = open_map_fd("rs_diag_ringbuf");
    if (ringbuf_fd < 0) {
        RS_LOG_ERROR("Failed to open rs_diag_ringbuf: %s", strerror(errno));
        goto out;
    }

    ctx.diag_rb = ring_buffer__new(ringbuf_fd, handle_diag_event, NULL, NULL);
    close(ringbuf_fd);
    ringbuf_fd = -1;

    if (!ctx.diag_rb) {
        RS_LOG_ERROR("Failed to create diag ring buffer");
        goto out;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("rsdiag started. Press Ctrl+C to stop.\n");
    while (!stop) {
        ret = ring_buffer__poll(ctx.diag_rb, 100);
        if (ret == -EINTR)
            break;
        if (ret < 0) {
            RS_LOG_ERROR("ring_buffer__poll failed: %d", ret);
            goto out;
        }
    }

    ret = 0;

out:
    if (ringbuf_fd >= 0)
        close(ringbuf_fd);
    close_ctx(&ctx);
    return ret == 0 ? 0 : 1;
}

int main(int argc, char **argv)
{
    rs_log_init("rsdiag", RS_LOG_LEVEL_INFO);

    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "start") == 0)
        return cmd_start(argc - 1, argv + 1);
    else if (strcmp(argv[1], "stop") == 0)
        return cmd_stop(argc - 1, argv + 1);
    else if (strcmp(argv[1], "status") == 0)
        return cmd_status(argc - 1, argv + 1);
    else if (strcmp(argv[1], "dump") == 0)
        return cmd_dump(argc - 1, argv + 1);

    fprintf(stderr, "Unknown command: %s\n", argv[1]);
    usage(argv[0]);
    return 1;
}
