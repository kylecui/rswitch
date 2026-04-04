# Observability in rSwitch

## Three-Layer Model

rSwitch provides a three-layer observability architecture. Each layer trades more overhead for deeper visibility.

| Layer | Name | Overhead | Lifecycle | Data Path |
|-------|------|----------|-----------|-----------|
| **L0** | Always-on counters | Near-zero (per-CPU `+=`) | Permanent — compiled into every module | Per-CPU maps, aggregated by user-space |
| **L1** | Sampled events | Low (gated by probability + burst limit) | Permanent — compiled in, gated by config | `rs_event_bus` ringbuf (shared with other events) |
| **L2** | Diagnostic fentry/fexit | Moderate (function tracing) | On-demand — loaded/unloaded by `rsdiag` | `rs_diag_ringbuf` (separate, 256KB) |

**Principle**: L0 runs unconditionally with zero locks. L1 uses three-layer gating (whitelist → probability → rate limit). L2 attaches fentry/fexit probes only when a developer explicitly runs `rsdiag start`.

---

## L0 — Always-On Counters

### Maps

| Map | Type | Key | Value | Purpose |
|-----|------|-----|-------|---------|
| `rs_obs_stats_map` | `PERCPU_ARRAY` | `__u32` | `rs_obs_stats_val` | Per-module packet/byte/drop/error counters |
| `rs_drop_stats_map` | `PERCPU_HASH` | `rs_obs_stats_key` | `rs_obs_stats_val` | Drop distribution by reason × module |
| `rs_hist_map` | `PERCPU_HASH` | `rs_obs_stats_key` | `rs_obs_stats_val` | Latency/size histograms |
| `rs_stage_hit_map` | `PERCPU_HASH` | `rs_obs_stats_key` | `rs_obs_stats_val` | Stage hit matrix (which modules processed which packets) |

### Key Structures

```c
struct rs_obs_stats_key {
    __u16 pipeline_id;
    __u16 profile_id;
    __u16 stage_id;
    __u16 module_id;
};

struct rs_obs_stats_val {
    __u64 pkts;
    __u64 bytes;
    __u64 drops;
    __u64 errors;
};
```

### BPF Helper Macros

Every module must define its identity before using obs helpers:

```c
#define RS_THIS_STAGE_ID    20    /* from pipeline slot assignment */
#define RS_THIS_MODULE_ID   20    /* from enum rs_obs_module_id */
```

| Macro | When to Call | Description |
|-------|-------------|-------------|
| `RS_OBS_STAGE_HIT(ctx, rctx, pkt_len)` | Once at module entry | Records that this module touched this packet |
| `RS_RECORD_DROP(ctx, rctx, reason)` | On every drop path | Sets `rs_ctx` action to DROP, records drop reason in obs maps |
| `RS_OBS_FINAL_ACTION(ctx, rctx, pkt_len)` | **Terminal endpoints only** | Records final XDP action + byte count |

> **Critical**: `RS_OBS_FINAL_ACTION` is ONLY for terminal pipeline endpoints: `dispatcher` (parse fail), `lastcall`, `egress`, `egress_final`. Regular pass-through modules must NOT call it.

---

## L1 — Sampled Events

### Configuration

L1 is controlled by a single config entry in `rs_obs_cfg_map` (key = 0):

```c
struct rs_obs_cfg {
    __u32 level;          /* enum rs_obs_level: OFF=0, COUNTERS=1, SAMPLED=2, FULL=3 */
    __u32 sample_ppm;     /* 0..1000000 (parts per million) */
    __u64 event_mask;     /* bitset of enabled event types */
    __u32 burst_limit;    /* max L1 emits per packet path */
    __u32 reserved;
};
```

### Three-Layer Gating

Every L1 event must pass all three gates:

1. **Whitelist**: `event_mask` bit for this event type must be set
2. **Probability**: `bpf_get_prng_u32() % 1000000 < sample_ppm`
3. **Rate limit**: Per-packet burst counter (`RS_CTX_OBS_BURST_USED`) must be below `burst_limit`

### BPF Usage

```c
RS_EMIT_SAMPLED_EVENT(rctx, &my_event, sizeof(my_event));
```

The macro handles all three gating checks internally.

### Event Types

L1 events share the `rs_event_bus` ringbuf with existing rSwitch events. Obs events use `struct rs_obs_event` with `event_type` in range `0x0002–0x0005`:

| event_type | Constant | Description |
|------------|----------|-------------|
| `0x0002` | `RS_OBS_EVT_SAMPLE` | Generic sampled packet metadata |
| `0x0003` | `RS_OBS_EVT_DROP` | Drop event with reason |
| `0x0004` | `RS_OBS_EVT_REDIRECT_ERR` | Redirect failure |
| `0x0005` | `RS_OBS_EVT_PROFILE_MARK` | Profile transition marker |

---

## L2 — Diagnostic fentry/fexit

L2 probes are **not** part of the main pipeline. They are loaded on-demand by the `rsdiag` CLI tool.

### BPF Programs

| File | Probes | Targets |
|------|--------|---------|
| `bpf/diag/diag_dispatcher.bpf.c` | fentry/fexit | Dispatcher + generic module entry/exit |
| `bpf/diag/diag_egress.bpf.c` | fentry/fexit | Egress + egress_final |
| `bpf/diag/diag_kernel.bpf.c` | tp_btf | `xdp_exception`, `xdp_redirect_err` |

### Maps

| Map | Type | Size | Purpose |
|-----|------|------|---------|
| `rs_diag_ringbuf` | `RINGBUF` | 256KB | L2 diagnostic events (separate from `rs_event_bus`) |
| `rs_diag_targets` | `HASH` | 128 entries | Attach target discovery — populated by loader, read by rsdiag |

### How It Works

1. The **loader** populates `rs_diag_targets` with prog_id, BTF ID, stage/module info for every loaded BPF program
2. `rsdiag start` reads `rs_diag_targets`, opens the diag BPF objects, uses `bpf_program__set_attach_target()` to retarget each fentry/fexit to the actual function
3. On `Ctrl+C`, rsdiag detaches and unloads all diag programs

---

## rsdiag CLI Reference

```
rsdiag start [--filter stage=X] [--filter module=Y]
    Attach diagnostic fentry/fexit probes. Streams L2 events to stdout.
    Press Ctrl+C to detach and exit.

rsdiag status
    Show current obs config (level, sample_ppm, burst_limit) and
    list all diag targets registered by the loader.

rsdiag dump --view matrix
    Print the stage hit matrix: rows = modules, columns = pipelines/profiles.

rsdiag dump --view reason [--top N]
    Print top-N drop reasons across all modules (default N=10).

rsdiag dump --view diff --profile A --compare B
    Compare stage hit counts between two profiles.

rsdiag dump --diag-live
    Stream L2 events from rs_diag_ringbuf in real time.
```

---

## Observability Map Reference

All maps pin to `/sys/fs/bpf/<map_name>` via `LIBBPF_PIN_BY_NAME`.

| Map Name | BPF Type | Key | Value | Layer |
|----------|----------|-----|-------|-------|
| `rs_obs_cfg_map` | `PERCPU_ARRAY` | `__u32` (0) | `rs_obs_cfg` | L1 config |
| `rs_obs_stats_map` | `PERCPU_ARRAY` | `__u32` | `rs_obs_stats_val` | L0 |
| `rs_drop_stats_map` | `PERCPU_HASH` | `rs_obs_stats_key` | `rs_obs_stats_val` | L0 |
| `rs_hist_map` | `PERCPU_HASH` | `rs_obs_stats_key` | `rs_obs_stats_val` | L0 |
| `rs_stage_hit_map` | `PERCPU_HASH` | `rs_obs_stats_key` | `rs_obs_stats_val` | L0 |
| `rs_diag_ringbuf` | `RINGBUF` | — | `rs_diag_event` | L2 |
| `rs_diag_targets` | `HASH` | `rs_diag_target_key` | `rs_diag_target` | L2 |

---

## Prometheus Metrics

Exposed by `rswitch-prometheus` on the `/metrics` endpoint:

| Metric | Labels | Description |
|--------|--------|-------------|
| `rswitch_obs_pkts_total` | pipeline, profile, stage, module | L0 packet counter |
| `rswitch_obs_bytes_total` | pipeline, profile, stage, module | L0 byte counter |
| `rswitch_obs_drops_total` | pipeline, profile, stage, module | L0 drop counter |
| `rswitch_obs_stage_hits_total` | pipeline, profile, stage, module | Stage hit counter |
| `rswitch_obs_drop_reasons_total` | pipeline, profile, stage, module, reason | Per-reason drop counter |

---

## Reserved rs_ctx Slots

These `rs_ctx` array slots are reserved for the observability system:

| Macro | Purpose |
|-------|---------|
| `RS_CTX_PIPELINE_ID` | Current pipeline ID (set by dispatcher) |
| `RS_CTX_PROFILE_ID` | Active profile ID (set by dispatcher) |
| `RS_CTX_OBS_BURST_USED` | L1 burst counter — incremented per emit, reset per packet |
| `RS_CTX_OBS_FLOW_HASH` | Flow hash for deterministic sampling |

---

## Drop Reason Categories

`enum rs_drop_reason` is organized into ranges:

| Range | Category | Examples |
|-------|----------|----------|
| 1–31 | Parse errors | `RS_DROP_PARSE_L2`, `RS_DROP_PARSE_L3`, `RS_DROP_PARSE_L4` |
| 32–63 | Policy / ACL | `RS_DROP_POLICY_DENY`, `RS_DROP_ACL_DENY` |
| 64–95 | Limit / resource | `RS_DROP_RATE_LIMIT`, `RS_DROP_QUEUE_FULL` |
| 96–127 | State machine | `RS_DROP_STP_BLOCKED`, `RS_DROP_CONNTRACK_INVALID` |
| 128–159 | Forwarding | `RS_DROP_NO_ROUTE`, `RS_DROP_TTL_EXPIRED`, `RS_DROP_FIB_LOOKUP_FAIL` |
| 160–191 | Egress | `RS_DROP_EGRESS_FILTER`, `RS_DROP_CHECKSUM_ERROR` |
| 192–223 | Tunnel | `RS_DROP_TUNNEL_DECAP_FAIL`, `RS_DROP_TUNNEL_ENCAP_FAIL` |
| 224–254 | User-defined | Reserved for SDK module developers |
| 255 | Unknown | `RS_DROP_UNKNOWN` |

---

## Dual Include Path

The obs system is defined in two parallel include trees that **must stay in sync**:

| Path | Used By | Files |
|------|---------|-------|
| SDK: `sdk/include/` | External modules via `rswitch_module.h` | `rswitch_obs.h`, `rswitch_maps.h`, `rswitch_helpers.h` |
| Core: `bpf/include/` + `bpf/core/` | Internal core programs | `rswitch_bpf.h`, `map_defs.h` |

When adding a new obs map or helper, you **must** update both paths.

---

## Anti-Patterns

These are hard rules. Violating them will cause correctness or performance bugs.

### 1. Never use `__sync_fetch_and_add` in L0 helpers

All L0 maps are `PERCPU`. Simple `+=` is correct and lock-free. Atomics on per-CPU maps add unnecessary overhead and confuse the BPF verifier.

### 2. Never call `RS_OBS_FINAL_ACTION` from pass-through modules

Only terminal pipeline endpoints call it: `dispatcher` (on parse failure), `lastcall`, `egress`, `egress_final`. If a regular module calls it, final action counters will be double-counted.

### 3. Never emit L1 events without checking burst_limit

Always use `RS_EMIT_SAMPLED_EVENT`, which enforces all three gating layers internally. Direct `bpf_ringbuf_output` to `rs_event_bus` bypasses sampling and can flood the ringbuf.

### 4. Never load diag BPF programs from the main loader

Diag programs are loaded exclusively by `rsdiag`. The loader only populates `rs_diag_targets` for discovery. Loading diag programs at boot wastes resources and attaches probes permanently.

### 5. Never share `rs_diag_ringbuf` with `rs_event_bus`

They are separate ringbufs for separate consumers. `rs_event_bus` is consumed by `rswitch-events`. `rs_diag_ringbuf` is consumed by `rsdiag`. Mixing them breaks both consumers.

### 6. Never assume obs maps exist without checking

Obs maps are pinned by the loader. If the loader hasn't run (or failed), `bpf_obj_get()` will return `-ENOENT`. Always check return values.

### 7. Never add obs maps without updating both include paths

SDK modules use `rswitch_maps.h` + `rswitch_helpers.h`. Core modules use `map_defs.h` + `rswitch_bpf.h`. A map defined in only one path will cause link errors or silent map duplication.

---

## Adding Observability to a New Module

Minimal example for a new pipeline module with L0 instrumentation:

```c
#include "rswitch_module.h"   /* or rswitch_common.h for core modules */

#define RS_THIS_STAGE_ID    42
#define RS_THIS_MODULE_ID   4200   /* pick from user range or register in rs_obs_module_id */

SEC("xdp")
int my_module(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u32 pkt_len = data_end - data;

    struct rs_ctx *rctx = bpf_map_lookup_elem(&rs_ctx_map, &(int){0});
    if (!rctx)
        return XDP_DROP;

    /* L0: record that this module touched the packet */
    RS_OBS_STAGE_HIT(ctx, rctx, pkt_len);

    /* ... module processing ... */

    if (should_drop) {
        RS_RECORD_DROP(ctx, rctx, RS_DROP_POLICY_DENY);
        return XDP_DROP;
    }

    /* Pass to next stage — do NOT call RS_OBS_FINAL_ACTION here */
    return XDP_PASS;
}
```

For L1 sampled events, additionally:

```c
struct rs_obs_event evt = {
    .event_type = RS_OBS_EVT_SAMPLE,
    .module_id  = RS_THIS_MODULE_ID,
    /* ... fill fields ... */
};
RS_EMIT_SAMPLED_EVENT(rctx, &evt, sizeof(evt));
```
