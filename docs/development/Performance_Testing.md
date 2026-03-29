# Performance Testing

> **Audience**: CI maintainers and module developers who want to detect performance regressions.

---

## 1. Overview

rSwitch includes a performance baseline test that measures per-packet processing latency using `BPF_PROG_TEST_RUN`. This runs in CI to detect regressions between commits.

**Key principle**: Absolute numbers are runner-specific (GitHub Actions VMs have variable performance). Only **relative regression** between runs on the same runner type is meaningful.

---

## 2. What Gets Measured

The baseline test (`test/ci/test_perf_baseline.c`) measures:

| Metric | Description |
|--------|-------------|
| **Per-packet latency** (ns/pkt) | Wall-clock time per `BPF_PROG_TEST_RUN` invocation |
| **Min/Avg/Max** | Across multiple measurement rounds |
| **Estimated PPS** | Packets per second (1B ns / avg_ns) |

### Test Programs

| Test | BPF Program | Description |
|------|-------------|-------------|
| `test_perf_dispatcher_bypass` | `rswitch_bypass` | TCP packet through bypass path (baseline) |
| `test_perf_dispatcher_bypass_udp` | `rswitch_bypass` | UDP packet through bypass path |

---

## 3. Threshold Policy

### Default Threshold

The default threshold is **500 ns/pkt**. This is intentionally generous to avoid false positives on shared CI runners.

```c
#define PERF_THRESHOLD_NS 500    // Override: -DPERF_THRESHOLD_NS=300
```

### Regression Detection

The test **fails** if:

- Average per-packet latency exceeds `PERF_THRESHOLD_NS`
- This indicates a significant regression from the expected baseline

### Adjusting Thresholds

For self-hosted runners with dedicated hardware, tighten the threshold:

```bash
# In Makefile or CI:
CFLAGS += -DPERF_THRESHOLD_NS=200
```

For particularly noisy CI environments, relax it:

```bash
CFLAGS += -DPERF_THRESHOLD_NS=1000
```

---

## 4. Running Locally

```bash
# Build
make all
make test-ci

# Run (requires root for BPF)
sudo ./build/test_perf_baseline ./build/bpf/dispatcher.bpf.o

# With JUnit output
sudo ./build/test_perf_baseline ./build/bpf/dispatcher.bpf.o perf_results.junit.xml
```

### Example Output

```
=== rSwitch Performance Baseline ===
BPF object: ./build/bpf/dispatcher.bpf.o
Threshold: 500 ns/pkt

[RUN ] test_perf_dispatcher_bypass

  ┌─────────────────────────────────────────────┐
  │ Performance Baseline: dispatcher bypass      │
  ├─────────────────────────────────────────────┤
  │ Repeat count : 10000 per round              │
  │ Rounds       : 5                            │
  │ Min duration : 1800000 ns (180 ns/pkt)      │
  │ Avg duration : 2100000 ns (210 ns/pkt)      │
  │ Max duration : 2500000 ns (250 ns/pkt)      │
  │ Est. PPS     : 4761905                       │
  │ Threshold    : 500 ns/pkt                    │
  └─────────────────────────────────────────────┘

[PERF] OK: avg 210 ns/pkt within threshold 500 ns/pkt
[PASS] test_perf_dispatcher_bypass
```

---

## 5. CI Integration

The performance baseline runs as a separate CI job (`perf-baseline`) after the build succeeds:

```yaml
perf-baseline:
  needs: build
  runs-on: ubuntu-24.04
  steps:
    - Build BPF objects
    - Run test_perf_baseline
    - Upload results as CI artifact
```

Results are stored as CI artifacts for historical comparison. The job **fails** if any test exceeds the threshold.

---

## 6. Limitations

| Limitation | Detail |
|-----------|--------|
| **No runtime multi-kernel testing** | `BPF_PROG_TEST_RUN` executes on the host kernel only. Cross-kernel testing requires virtme-ng or self-hosted runners. |
| **Shared runner variability** | GitHub Actions runners are shared VMs. Latency can vary ±50% between runs. Set generous thresholds. |
| **BPF_PROG_TEST_RUN overhead** | Each call has syscall overhead. Measured latency includes this overhead, not just BPF execution time. |
| **No full pipeline measurement** | Currently measures dispatcher bypass only. Full pipeline (dispatcher → VLAN → ACL → route) measurement is planned. |

---

## 7. Adding New Performance Tests

To measure a new module:

1. Add a new `RS_TEST()` function in `test/ci/test_perf_baseline.c`
2. Use `perf_run_batch()` for consistent measurement
3. Compare against `PERF_THRESHOLD_NS`
4. Register with `RS_RUN_TEST()` in the test suite

Example:

```c
RS_TEST(test_perf_my_module)
{
    struct rs_test_ctx *ctx = rs_test_open(g_obj_path);
    struct rs_test_pkt *pkt = rs_test_pkt_tcp("10.0.0.1", "10.0.0.2", 80, 80, 0x02);
    __u32 retval = 0;

    __u64 dur = perf_run_batch(ctx, "my_module_entry", pkt->data, pkt->len,
                               PERF_REPEAT_COUNT, &retval);
    __u64 per_pkt = dur / PERF_REPEAT_COUNT;

    printf("[PERF] my_module: %llu ns/pkt\n", (unsigned long long)per_pkt);
    if (per_pkt > PERF_THRESHOLD_NS)
        rs_current_test_failed = 1;

    rs_test_pkt_free(pkt);
    rs_test_close(ctx);
}
```

---

*See also: [Contributing](Contributing.md) · [CO-RE Guide](CO-RE_Guide.md) · [CI Workflow](../../.github/workflows/ci.yml)*
