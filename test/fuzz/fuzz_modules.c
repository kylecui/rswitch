#include <errno.h>
#include <linux/bpf.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "../unit/test_packets.h"
#include "rs_fuzz.h"

struct test_xdp_md {
    __u32 data;
    __u32 data_meta;
    __u32 data_end;
    __u32 ingress_ifindex;
    __u32 rx_queue_index;
    __u32 egress_ifindex;
};

struct rs_fuzz_ctx {
    struct bpf_object *obj;
    struct bpf_program *prog;
};

struct fuzz_stats {
    uint64_t iterations_done;
    uint64_t crashes;
    uint64_t invalid_retval;
    uint64_t map_health_errors;
    __u32 seen_retvals[64];
    size_t seen_count;
};

static uint32_t xorshift32(uint32_t *state)
{
    uint32_t x = *state;

    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    return x;
}

static bool is_expected_xdp_retval(__u32 retval)
{
    return retval == XDP_ABORTED || retval == XDP_DROP || retval == XDP_PASS ||
           retval == XDP_TX || retval == XDP_REDIRECT;
}

static void remember_retval(struct fuzz_stats *stats, __u32 retval)
{
    size_t i;

    for (i = 0; i < stats->seen_count; i++) {
        if (stats->seen_retvals[i] == retval)
            return;
    }

    if (stats->seen_count < (sizeof(stats->seen_retvals) / sizeof(stats->seen_retvals[0]))) {
        stats->seen_retvals[stats->seen_count] = retval;
        stats->seen_count++;
    }
}

static int map_health_check(struct rs_fuzz_ctx *ctx)
{
    struct bpf_map *map;

    if (!ctx || !ctx->obj)
        return -EINVAL;

    bpf_object__for_each_map(map, ctx->obj) {
        struct bpf_map_info info;
        __u32 len = sizeof(info);
        int map_fd = bpf_map__fd(map);

        memset(&info, 0, sizeof(info));
        if (map_fd < 0)
            return -EINVAL;
        if (bpf_obj_get_info_by_fd(map_fd, &info, &len) != 0)
            return -errno;
    }

    return 0;
}

struct rs_fuzz_ctx *rs_fuzz_init(const char *obj_path, const char *prog_name)
{
    struct rs_fuzz_ctx *ctx;

    if (!obj_path || !prog_name)
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

    ctx->prog = bpf_object__find_program_by_name(ctx->obj, prog_name);
    if (!ctx->prog || bpf_program__fd(ctx->prog) < 0) {
        bpf_object__close(ctx->obj);
        free(ctx);
        return NULL;
    }

    return ctx;
}

int rs_fuzz_run(struct rs_fuzz_ctx *ctx, const void *data, size_t size, __u32 *retval)
{
    struct test_xdp_md xdp_ctx;
    unsigned char out_buf[512];
    int err;

    if (!ctx || !ctx->prog || !data || size == 0 || size > UINT32_MAX)
        return -EINVAL;

    memset(&xdp_ctx, 0, sizeof(xdp_ctx));
    xdp_ctx.data_end = (__u32)size;
    xdp_ctx.ingress_ifindex = 5;
    memset(out_buf, 0, sizeof(out_buf));

    LIBBPF_OPTS(bpf_test_run_opts, topts,
        .data_in = data,
        .data_size_in = (__u32)size,
        .data_out = out_buf,
        .data_size_out = sizeof(out_buf),
        .ctx_in = &xdp_ctx,
        .ctx_size_in = sizeof(xdp_ctx),
        .repeat = 1,
    );

    err = bpf_prog_test_run_opts(bpf_program__fd(ctx->prog), &topts);
    if (retval)
        *retval = topts.retval;
    if (err)
        return -errno;
    return 0;
}

void rs_fuzz_close(struct rs_fuzz_ctx *ctx)
{
    if (!ctx)
        return;
    if (ctx->obj)
        bpf_object__close(ctx->obj);
    free(ctx);
}

static size_t build_seed_packet(uint32_t strategy, uint8_t *buf, size_t cap)
{
    struct rs_test_pkt *seed = NULL;

    if (strategy == 0)
        seed = rs_test_pkt_tcp("10.0.0.1", "10.0.0.2", 1111, 80, 0x02);
    else if (strategy == 1)
        seed = rs_test_pkt_udp("10.0.0.1", "10.0.0.2", 1111, 53);
    else if (strategy == 2)
        seed = rs_test_pkt_icmp("10.0.0.1", "10.0.0.2", 8, 0);
    else
        seed = rs_test_pkt_arp("10.0.0.1", "02:00:00:00:00:01", "10.0.0.2", 1);

    if (!seed)
        return 0;

    if (seed->len > cap) {
        rs_test_pkt_free(seed);
        return 0;
    }

    memcpy(buf, seed->data, seed->len);
    cap = seed->len;
    rs_test_pkt_free(seed);
    return cap;
}

static size_t make_input(uint32_t *rng, uint64_t iter, uint8_t *buf, size_t cap)
{
    uint32_t mode = xorshift32(rng) % 4;
    size_t len;
    size_t i;

    if (mode == 0) {
        len = (size_t)(xorshift32(rng) % 512U) + 1U;
        if (len > cap)
            len = cap;
        for (i = 0; i < len; i++)
            buf[i] = (uint8_t)(xorshift32(rng) & 0xffU);
        return len;
    }

    len = build_seed_packet((uint32_t)(iter % 4U), buf, cap);
    if (len == 0)
        return 0;

    if (mode == 1) {
        size_t flips = (size_t)(xorshift32(rng) % 8U) + 1U;
        for (i = 0; i < flips; i++) {
            size_t off = (size_t)(xorshift32(rng) % (uint32_t)len);
            buf[off] ^= (uint8_t)(1U << (xorshift32(rng) % 8U));
        }
        return len;
    }

    if (mode == 2) {
        if (len < 2)
            return len;
        return (size_t)(xorshift32(rng) % (uint32_t)(len - 1U)) + 1U;
    }

    if (len > 34) {
        buf[14] = 0x4f;
        buf[16] = 0xff;
        buf[17] = 0xff;
    }
    return len;
}

int main(int argc, char **argv)
{
    const char *obj_path = "./build/bpf/acl.bpf.o";
    const char *prog_name = "acl_filter";
    uint64_t iterations = 10000;
    uint32_t seed = (uint32_t)time(NULL);
    struct rs_fuzz_ctx *ctx;
    struct fuzz_stats stats;
    uint8_t input[2048];
    uint64_t i;

    if (argc > 1)
        obj_path = argv[1];
    if (argc > 2)
        prog_name = argv[2];
    if (argc > 3)
        iterations = strtoull(argv[3], NULL, 10);
    if (argc > 4)
        seed = (uint32_t)strtoul(argv[4], NULL, 10);

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    ctx = rs_fuzz_init(obj_path, prog_name);
    if (!ctx) {
        fprintf(stderr, "fuzz init failed for %s:%s\n", obj_path, prog_name);
        return 1;
    }

    memset(&stats, 0, sizeof(stats));

    for (i = 0; i < iterations; i++) {
        __u32 retval = 0;
        size_t len = make_input(&seed, i, input, sizeof(input));
        int run_rc;

        if (len == 0)
            continue;

        run_rc = rs_fuzz_run(ctx, input, len, &retval);
        stats.iterations_done++;

        if (run_rc != 0) {
            stats.crashes++;
            continue;
        }

        remember_retval(&stats, retval);
        if (!is_expected_xdp_retval(retval))
            stats.invalid_retval++;

        if ((i % 256U) == 0U && map_health_check(ctx) != 0)
            stats.map_health_errors++;
    }

    printf("fuzz report\n");
    printf("  object: %s\n", obj_path);
    printf("  program: %s\n", prog_name);
    printf("  seed: %u\n", seed);
    printf("  iterations completed: %llu\n", (unsigned long long)stats.iterations_done);
    printf("  unique return values: %zu\n", stats.seen_count);
    printf("  anomalies: crashes=%llu invalid_retvals=%llu map_health=%llu\n",
           (unsigned long long)stats.crashes,
           (unsigned long long)stats.invalid_retval,
           (unsigned long long)stats.map_health_errors);

    rs_fuzz_close(ctx);
    return (stats.crashes || stats.invalid_retval || stats.map_health_errors) ? 1 : 0;
}
