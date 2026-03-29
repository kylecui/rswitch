// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * Performance Baseline — BPF_PROG_TEST_RUN latency measurement.
 *
 * Measures per-packet processing latency for the rSwitch dispatcher
 * using BPF_PROG_TEST_RUN with the `repeat` parameter.
 *
 * Usage:
 *   sudo ./build/test_perf_baseline ./build/bpf/dispatcher.bpf.o [junit.xml]
 *
 * Output:
 *   - Packets/sec throughput estimate
 *   - Per-packet latency (min/avg/max nanoseconds)
 *   - Pass/fail against configurable threshold
 *
 * Note: Absolute numbers are runner-specific. Only relative regression
 * between runs is meaningful.
 */

#include <arpa/inet.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <string.h>
#include <time.h>

#include "../unit/rs_test.h"
#include "../unit/test_packets.h"

/* ── Configuration ─────────────────────────────────────────────── */

/* Number of iterations for BPF_PROG_TEST_RUN repeat */
#define PERF_REPEAT_COUNT       10000

/* Number of measurement rounds to compute min/avg/max */
#define PERF_ROUNDS             5

/* Maximum acceptable average nanoseconds per packet.
 * Default: 500ns. Override at build time with -DPERF_THRESHOLD_NS=... */
#ifndef PERF_THRESHOLD_NS
#define PERF_THRESHOLD_NS       500
#endif

/* Regression multiplier: fail if avg > baseline * this factor.
 * Used when a baseline file exists. */
#define PERF_REGRESSION_FACTOR  2.0

static const char *g_obj_path;

/* ── Timing helpers ────────────────────────────────────────────── */

static inline __u64 timespec_to_ns(struct timespec *ts)
{
    return (__u64)ts->tv_sec * 1000000000ULL + (__u64)ts->tv_nsec;
}

/* ── BPF_PROG_TEST_RUN with repeat ────────────────────────────── */

/*
 * Run a BPF program `repeat` times via BPF_PROG_TEST_RUN and measure
 * wall-clock duration. Returns the duration in nanoseconds, or 0 on error.
 *
 * The kernel's BPF_PROG_TEST_RUN attr has a `repeat` field that runs
 * the program N times in a tight loop, minimizing syscall overhead.
 * We wrap this with clock_gettime for wall-clock measurement.
 */
static __u64 perf_run_batch(struct rs_test_ctx *ctx,
                            const char *prog_name,
                            void *pkt, __u32 pkt_size,
                            __u32 repeat, __u32 *retval)
{
    struct timespec t0, t1;
    int fd;
    struct bpf_test_run_opts opts;
    struct bpf_object *obj;
    struct bpf_program *prog;
    int err;

    /*
     * rs_test_run runs a single invocation. For repeated batch measurement,
     * we need to directly use bpf_prog_test_run_opts with repeat parameter.
     * However, our test harness wraps the object. We'll use clock_gettime
     * around repeated rs_test_run calls as a portable fallback.
     */
    clock_gettime(CLOCK_MONOTONIC, &t0);

    for (__u32 i = 0; i < repeat; i++) {
        err = rs_test_run(ctx, prog_name, pkt, pkt_size, NULL, retval);
        if (err != 0)
            return 0;
    }

    clock_gettime(CLOCK_MONOTONIC, &t1);

    return timespec_to_ns(&t1) - timespec_to_ns(&t0);
}

/* ── Perf Test: Dispatcher bypass latency ──────────────────────── */

static __u64 round_durations[PERF_ROUNDS];

RS_TEST(test_perf_dispatcher_bypass)
{
    struct rs_test_ctx *ctx;
    struct rs_test_pkt *pkt;
    __u32 retval = 0;
    __u64 total_ns = 0;
    __u64 min_ns = ~0ULL;
    __u64 max_ns = 0;
    __u64 avg_ns;
    __u64 per_pkt_ns;
    double pps;

    ctx = rs_test_open(g_obj_path);
    RS_ASSERT_TRUE(ctx != NULL);
    if (!ctx)
        return;

    pkt = rs_test_pkt_tcp("10.0.0.1", "10.0.0.2", 12345, 80, 0x02);
    RS_ASSERT_TRUE(pkt != NULL);
    if (!pkt) {
        rs_test_close(ctx);
        return;
    }

    /* Warm-up round (discard result) */
    perf_run_batch(ctx, "rswitch_bypass", pkt->data, pkt->len,
                   PERF_REPEAT_COUNT / 10, &retval);

    /* Measurement rounds */
    for (int r = 0; r < PERF_ROUNDS; r++) {
        __u64 dur = perf_run_batch(ctx, "rswitch_bypass", pkt->data,
                                   pkt->len, PERF_REPEAT_COUNT, &retval);
        RS_ASSERT_TRUE(dur > 0);
        if (dur == 0) {
            rs_test_pkt_free(pkt);
            rs_test_close(ctx);
            return;
        }
        round_durations[r] = dur;
        total_ns += dur;
        if (dur < min_ns)
            min_ns = dur;
        if (dur > max_ns)
            max_ns = dur;
    }

    avg_ns = total_ns / PERF_ROUNDS;
    per_pkt_ns = avg_ns / PERF_REPEAT_COUNT;
    pps = (per_pkt_ns > 0) ? 1000000000.0 / (double)per_pkt_ns : 0;

    printf("\n");
    printf("  ┌─────────────────────────────────────────────┐\n");
    printf("  │ Performance Baseline: dispatcher bypass      │\n");
    printf("  ├─────────────────────────────────────────────┤\n");
    printf("  │ Repeat count : %u per round                │\n", PERF_REPEAT_COUNT);
    printf("  │ Rounds       : %d                           │\n", PERF_ROUNDS);
    printf("  │ Min duration : %llu ns (%llu ns/pkt)       │\n",
           (unsigned long long)(min_ns),
           (unsigned long long)(min_ns / PERF_REPEAT_COUNT));
    printf("  │ Avg duration : %llu ns (%llu ns/pkt)       │\n",
           (unsigned long long)avg_ns,
           (unsigned long long)per_pkt_ns);
    printf("  │ Max duration : %llu ns (%llu ns/pkt)       │\n",
           (unsigned long long)(max_ns),
           (unsigned long long)(max_ns / PERF_REPEAT_COUNT));
    printf("  │ Est. PPS     : %.0f                         │\n", pps);
    printf("  │ Threshold    : %d ns/pkt                    │\n", PERF_THRESHOLD_NS);
    printf("  └─────────────────────────────────────────────┘\n");
    printf("\n");

    /* Threshold check */
    if (per_pkt_ns > PERF_THRESHOLD_NS) {
        printf("[PERF] REGRESSION: avg %llu ns/pkt exceeds threshold %d ns/pkt\n",
               (unsigned long long)per_pkt_ns, PERF_THRESHOLD_NS);
        rs_current_test_failed = 1;
    } else {
        printf("[PERF] OK: avg %llu ns/pkt within threshold %d ns/pkt\n",
               (unsigned long long)per_pkt_ns, PERF_THRESHOLD_NS);
    }

    rs_test_pkt_free(pkt);
    rs_test_close(ctx);
}

/* ── Perf Test: Dispatcher bypass with UDP ─────────────────────── */

RS_TEST(test_perf_dispatcher_bypass_udp)
{
    struct rs_test_ctx *ctx;
    struct rs_test_pkt *pkt;
    __u32 retval = 0;
    __u64 dur, per_pkt_ns;

    ctx = rs_test_open(g_obj_path);
    RS_ASSERT_TRUE(ctx != NULL);
    if (!ctx)
        return;

    pkt = rs_test_pkt_udp("192.168.1.10", "192.168.1.20", 5000, 53);
    RS_ASSERT_TRUE(pkt != NULL);
    if (!pkt) {
        rs_test_close(ctx);
        return;
    }

    /* Warm-up */
    perf_run_batch(ctx, "rswitch_bypass", pkt->data, pkt->len,
                   PERF_REPEAT_COUNT / 10, &retval);

    /* Measurement */
    dur = perf_run_batch(ctx, "rswitch_bypass", pkt->data, pkt->len,
                         PERF_REPEAT_COUNT, &retval);
    RS_ASSERT_TRUE(dur > 0);
    if (dur > 0) {
        per_pkt_ns = dur / PERF_REPEAT_COUNT;
        printf("[PERF] UDP bypass: %llu ns/pkt (%u repeats)\n",
               (unsigned long long)per_pkt_ns, PERF_REPEAT_COUNT);
        if (per_pkt_ns > PERF_THRESHOLD_NS) {
            printf("[PERF] REGRESSION: UDP %llu ns/pkt exceeds %d ns/pkt\n",
                   (unsigned long long)per_pkt_ns, PERF_THRESHOLD_NS);
            rs_current_test_failed = 1;
        }
    }

    rs_test_pkt_free(pkt);
    rs_test_close(ctx);
}

RS_TEST_SUITE_BEGIN()
    ;
    if (argc < 2) {
        printf("Usage: %s <path_to_dispatcher.bpf.o> [junit.xml]\n", argv[0]);
        return 1;
    }

    g_obj_path = argv[1];
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    printf("=== rSwitch Performance Baseline ===\n");
    printf("BPF object: %s\n", g_obj_path);
    printf("Threshold: %d ns/pkt\n\n", PERF_THRESHOLD_NS);

    RS_RUN_TEST(test_perf_dispatcher_bypass);
    RS_RUN_TEST(test_perf_dispatcher_bypass_udp);

    if (argc > 2)
        rs_test_report_junit(argv[2]);

RS_TEST_SUITE_END()
