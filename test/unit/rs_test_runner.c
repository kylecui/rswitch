#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/bpf.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "rs_test.h"

struct rs_layers {
    __u16 eth_proto;
    __u16 vlan_ids[2];
    __u8 vlan_depth;
    __u8 ip_proto;
    __u8 pad[2];
    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;
    __u16 l2_offset;
    __u16 l3_offset;
    __u16 l4_offset;
    __u16 payload_offset;
    __u32 payload_len;
};

struct rs_ctx {
    __u32 ifindex;
    __u32 timestamp;
    __u8 parsed;
    __u8 modified;
    __u8 pad[2];
    struct rs_layers layers;
    __u16 ingress_vlan;
    __u16 egress_vlan;
    __u8 prio;
    __u8 dscp;
    __u8 ecn;
    __u8 traffic_class;
    __u32 egress_ifindex;
    __u8 action;
    __u8 mirror;
    __u16 mirror_port;
    __u32 error;
    __u32 drop_reason;
    __u32 next_prog_id;
    __u32 call_depth;
    __u32 reserved[4];
};

struct test_xdp_md {
    __u32 data;
    __u32 data_meta;
    __u32 data_end;
    __u32 ingress_ifindex;
    __u32 rx_queue_index;
    __u32 egress_ifindex;
};

struct rs_test_ctx {
    struct bpf_object *obj;
};

static int rs_test_ncpus(void)
{
    long n = sysconf(_SC_NPROCESSORS_CONF);

    if (n < 1)
        return 1;
    return (int)n;
}

static int rs_test_map_fd(struct rs_test_ctx *ctx, const char *map_name)
{
    struct bpf_map *map;

    if (!ctx || !ctx->obj || !map_name)
        return -EINVAL;

    map = bpf_object__find_map_by_name(ctx->obj, map_name);
    if (!map)
        return -ENOENT;
    return bpf_map__fd(map);
}

struct rs_test_ctx *rs_test_open(const char *obj_path)
{
    struct rs_test_ctx *ctx;

    if (!obj_path)
        return NULL;

    ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return NULL;

    ctx->obj = bpf_object__open_file(obj_path, NULL);
    if (!ctx->obj) {
        free(ctx);
        return NULL;
    }

    if (bpf_object__load(ctx->obj) != 0) {
        bpf_object__close(ctx->obj);
        free(ctx);
        return NULL;
    }

    return ctx;
}

int rs_test_map_insert(struct rs_test_ctx *ctx, const char *map_name, const void *key, const void *value)
{
    struct bpf_map_info info;
    __u32 info_len = sizeof(info);
    int map_fd;

    if (!ctx || !map_name || !key || !value)
        return -EINVAL;

    map_fd = rs_test_map_fd(ctx, map_name);
    if (map_fd < 0)
        return map_fd;

    memset(&info, 0, sizeof(info));
    if (bpf_obj_get_info_by_fd(map_fd, &info, &info_len) != 0)
        return -errno;

    if (info.type == BPF_MAP_TYPE_PERCPU_ARRAY || info.type == BPF_MAP_TYPE_PERCPU_HASH ||
        info.type == BPF_MAP_TYPE_LRU_PERCPU_HASH || info.type == BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE) {
        int ncpus = rs_test_ncpus();
        size_t value_size = info.value_size;
        size_t total = (size_t)ncpus * value_size;
        unsigned char *percpu_vals = calloc(1, total);
        int i;
        int ret;

        if (!percpu_vals)
            return -ENOMEM;

        for (i = 0; i < ncpus; i++)
            memcpy(percpu_vals + ((size_t)i * value_size), value, value_size);

        ret = bpf_map_update_elem(map_fd, key, percpu_vals, BPF_ANY);
        free(percpu_vals);
        return ret == 0 ? 0 : -errno;
    }

    if (bpf_map_update_elem(map_fd, key, value, BPF_ANY) != 0)
        return -errno;

    return 0;
}

static int rs_test_read_ctx_map(struct rs_test_ctx *ctx, struct rs_ctx *out_ctx)
{
    struct bpf_map_info info;
    __u32 info_len = sizeof(info);
    __u32 key = 0;
    int map_fd;

    if (!out_ctx)
        return 0;

    memset(out_ctx, 0, sizeof(*out_ctx));

    map_fd = rs_test_map_fd(ctx, "rs_ctx_map");
    if (map_fd < 0)
        return map_fd;

    memset(&info, 0, sizeof(info));
    if (bpf_obj_get_info_by_fd(map_fd, &info, &info_len) != 0)
        return -errno;

    if (info.type == BPF_MAP_TYPE_PERCPU_ARRAY) {
        int ncpus = rs_test_ncpus();
        size_t value_size = info.value_size;
        size_t total = (size_t)ncpus * value_size;
        struct rs_ctx *vals = calloc(1, total);
        int i;

        if (!vals)
            return -ENOMEM;

        if (bpf_map_lookup_elem(map_fd, &key, vals) != 0) {
            free(vals);
            return -errno;
        }

        *out_ctx = vals[0];
        for (i = 0; i < ncpus; i++) {
            if (vals[i].parsed || vals[i].ingress_vlan || vals[i].egress_ifindex || vals[i].drop_reason) {
                *out_ctx = vals[i];
                break;
            }
        }

        free(vals);
        return 0;
    }

    if (bpf_map_lookup_elem(map_fd, &key, out_ctx) != 0)
        return -errno;
    return 0;
}

int rs_test_run(struct rs_test_ctx *ctx,
                const char *prog_name,
                void *pkt,
                __u32 pkt_size,
                struct rs_ctx *out_ctx,
                __u32 *retval)
{
    unsigned char out_buf[512];
    struct bpf_program *prog;
    struct test_xdp_md xdp_ctx;
    int err;

    if (!ctx || !ctx->obj || !prog_name || !pkt || pkt_size == 0)
        return -EINVAL;

    prog = bpf_object__find_program_by_name(ctx->obj, prog_name);
    if (!prog)
        return -ENOENT;
    if (bpf_program__fd(prog) < 0)
        return -EINVAL;

    memset(out_buf, 0, sizeof(out_buf));
    memset(&xdp_ctx, 0, sizeof(xdp_ctx));
    xdp_ctx.data_end = pkt_size;
    xdp_ctx.ingress_ifindex = 5;

    LIBBPF_OPTS(bpf_test_run_opts, topts,
        .data_in = pkt,
        .data_size_in = pkt_size,
        .data_out = out_buf,
        .data_size_out = sizeof(out_buf),
        .ctx_in = &xdp_ctx,
        .ctx_size_in = sizeof(xdp_ctx),
        .repeat = 1,
    );

    err = bpf_prog_test_run_opts(bpf_program__fd(prog), &topts);
    if (retval)
        *retval = topts.retval;
    if (err)
        return err;

    if (out_ctx)
        return rs_test_read_ctx_map(ctx, out_ctx);
    return 0;
}

void rs_test_close(struct rs_test_ctx *ctx)
{
    if (!ctx)
        return;
    if (ctx->obj)
        bpf_object__close(ctx->obj);
    free(ctx);
}
