# 性能测试 (Performance Testing)

> **受众**：希望检测性能回归 (performance regressions) 的CI维护者和模块开发人员。

---

## 1. 概述

rSwitch包含一个性能基线测试，使用 `BPF_PROG_TEST_RUN` 测量每个数据包的处理延迟。该测试在CI中运行，以检测提交之间的回归。

**关键原则**：绝对数值取决于运行环境（GitHub Actions虚拟机的性能会有波动）。只有在相同类型的运行环境上进行的运行之间的**相对回归**才有意义。

---

## 2. 测量内容

基线测试 (`test/ci/test_perf_baseline.c`) 测量以下内容：

| 指标 | 描述 |
|--------|-------------|
| **每个数据包的延迟** (ns/pkt) | 每次 `BPF_PROG_TEST_RUN` 调用的实际运行时间 (Wall-clock time) |
| **最小/平均/最大** | 跨多个测量轮次 |
| **估计的PPS** | 每秒数据包数 (10^9 ns / 平均纳秒数) |

### 测试程序

| 测试 | BPF程序 | 描述 |
|------|-------------|-------------|
| `test_perf_dispatcher_bypass` | `rswitch_bypass` | 通过旁路路径的TCP数据包（基线） |
| `test_perf_dispatcher_bypass_udp` | `rswitch_bypass` | 通过旁路路径的UDP数据包 |

---

## 3. 阈值策略

### 默认阈值

默认阈值为 **500 ns/pkt**。这是有意设置得比较宽松，以避免在共享CI运行环境上出现误报。

```c
#define PERF_THRESHOLD_NS 500    // 覆盖方式：-DPERF_THRESHOLD_NS=300
```

### 回归检测

如果满足以下条件，测试将**失败**：

- 平均每个数据包的延迟超过 `PERF_THRESHOLD_NS`
- 这表明与预期基线相比存在显著回归

### 调整阈值

对于具有专用硬件的自托管运行环境，请收紧阈值：

```bash
# 在 Makefile 或 CI 中：
CFLAGS += -DPERF_THRESHOLD_NS=200
```

对于噪声特别大的CI环境，请放宽阈值：

```bash
CFLAGS += -DPERF_THRESHOLD_NS=1000
```

---

## 4. 本地运行

```bash
# 构建
make all
make test-ci

# 运行（BPF 需要 root 权限）
sudo ./build/test_perf_baseline ./build/bpf/dispatcher.bpf.o

# 带有 JUnit 输出
sudo ./build/test_perf_baseline ./build/bpf/dispatcher.bpf.o perf_results.junit.xml
```

### 示例输出

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

## 5. CI集成

性能基线在构建成功后作为一个单独的CI作业 (`perf-baseline`) 运行：

```yaml
perf-baseline:
  needs: build
  runs-on: ubuntu-24.04
  steps:
    - 构建 BPF 对象
    - 运行 test_perf_baseline
    - 将结果上传为 CI 产物 (artifact)
```

结果存储为CI产物，以便进行历史对比。如果任何测试超过阈值，作业将失败。

---

## 6. 局限性

| 局限性 | 详情 |
|-----------|--------|
| **无运行时多内核测试** | `BPF_PROG_TEST_RUN` 仅在宿主内核上执行。跨内核测试需要virtme-ng或自托管运行环境。 |
| **共享运行环境的波动性** | GitHub Actions运行环境是共享虚拟机。运行之间的延迟波动可能达到 ±50%。请设置宽松的阈值。 |
| **BPF_PROG_TEST_RUN开销** | 每次调用都有系统调用开销。测得的延迟包含此开销，而不仅仅是BPF执行时间。 |
| **无完整流水线测量** | 目前仅测量dispatcher旁路。计划进行完整流水线（dispatcher → VLAN → ACL → route）测量。 |

---

## 7. 添加新的性能测试

要测量新模块：

1. 在 `test/ci/test_perf_baseline.c` 中添加一个新的 `RS_TEST()` 函数
2. 使用 `perf_run_batch()` 进行一致性测量
3. 与 `PERF_THRESHOLD_NS` 进行比较
4. 在测试套件中使用 `RS_RUN_TEST()` 进行注册

示例：

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

*另请参阅：[贡献指南](Contributing.md) · [CO-RE指南](CO-RE_Guide.md) · [CI工作流](../../.github/workflows/ci.yml)*
