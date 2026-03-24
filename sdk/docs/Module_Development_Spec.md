# rSwitch Module Development Specification

**Version**: 2.0  
**Status**: Normative  
**Audience**: Module developers (internal & third-party)

---

## 1. Overview

rSwitch is a reconfigurable network switching and traffic weaving platform built on eBPF/XDP. Developers extend its functionality by writing **BPF modules** that plug into a **tail-call pipeline**. This specification defines the mandatory structure, conventions, and APIs that every module must follow.

**Compliance is enforced**: Modules that do not follow this spec will not be accepted into the official module set and may fail at load time.

---

## 2. Module File Layout

Every module is a single C file named `<module_name>.bpf.c` placed in `rswitch/bpf/modules/`.

### 2.1 Mandatory File Structure (in order)

```c
// ── Section 1: License Header ──────────────────────────────
// SPDX-License-Identifier: GPL-2.0

// ── Section 2: Includes ────────────────────────────────────
#include "../include/rswitch_common.h"
#include "../core/module_abi.h"
// Optional: #include "../core/afxdp_common.h" (if using AF_XDP/VOQ types)
// Optional: #include "../core/veth_egress_common.h" (if using veth egress types)

// ── Section 3: License Declaration ─────────────────────────
char _license[] SEC("license") = "GPL";

// ── Section 4: Module Metadata ─────────────────────────────
RS_DECLARE_MODULE("module_name", RS_HOOK_xxx, stage, flags, "description");
// Optional: RS_DEPENDS_ON("other_module");

// ── Section 5: Data Structures ─────────────────────────────
// struct definitions, enums, constants

// ── Section 6: BPF Maps ────────────────────────────────────
// map definitions

// ── Section 7: Helper Functions ────────────────────────────
// static __always_inline helpers

// ── Section 8: Program Entry Point(s) ──────────────────────
SEC("xdp")        // Ingress modules
// or SEC("xdp/devmap")  // Egress modules
int func_name(struct xdp_md *xdp_ctx)
{
    // ... module logic ...
}
```

### 2.2 Rules

| Rule | Requirement |
|------|-------------|
| **R-LAYOUT-01** | `_license[]` declaration MUST appear after includes, before `RS_DECLARE_MODULE`. Never at the end of the file. |
| **R-LAYOUT-02** | `RS_DECLARE_MODULE()` MUST appear after license, before any code. Never at the end of the file. |
| **R-LAYOUT-03** | Only ONE `_license[]` declaration per file. No duplicates. |
| **R-LAYOUT-04** | Do NOT use `#ifndef __BPF__` / `#define __BPF__` guards in module files. The build system defines `__BPF__` via compiler flags (`-D__BPF__` in `Makefile.module`). |

---

## 3. Includes

### 3.1 Mandatory Includes

Every module MUST include exactly these two headers, in this order:

```c
#include "../include/rswitch_common.h"
#include "../core/module_abi.h"
```

- **`rswitch_common.h`** — Provides CO-RE types, protocol constants, parsing helpers, core shared maps (`rs_ctx_map`, `rs_progs`, `rs_prog_chain`, `rs_event_bus`), and all framework macros (`RS_GET_CTX()`, `RS_TAIL_CALL_NEXT()`, etc.).
- **`module_abi.h`** — Provides `RS_DECLARE_MODULE()`, `RS_DEPENDS_ON()`, hook point constants, stage conventions, and capability flags.

### 3.2 Optional Includes

| Header | When to use |
|--------|-------------|
| `../core/afxdp_common.h` | Module interacts with AF_XDP/VOQ subsystem (e.g., `afxdp_redirect`, `egress_qos`) |
| `../core/veth_egress_common.h` | Module is part of the veth egress path (e.g., `veth_egress`) |

### 3.3 Forbidden Includes

| Forbidden | Use instead |
|-----------|-------------|
| `<linux/bpf.h>`, `<bpf/bpf_helpers.h>`, `<linux/if_ether.h>`, etc. | `rswitch_common.h` (provides all via CO-RE) |
| `"uapi.h"`, `"map_defs.h"` (direct) | `rswitch_common.h` (includes them) |
| `"module_abi.h"` (without path) | `"../core/module_abi.h"` (use relative path) |

---

## 4. Module Metadata

### 4.1 RS_DECLARE_MODULE

Every module MUST declare its metadata:

```c
RS_DECLARE_MODULE("name", hook_point, stage, flags, "description");
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `name` | string | Unique module identifier, lowercase, no spaces |
| `hook_point` | enum | `RS_HOOK_XDP_INGRESS` or `RS_HOOK_XDP_EGRESS` |
| `stage` | u32 | Pipeline position (see Stage Map below) |
| `flags` | u32 | Bitwise OR of `RS_FLAG_*` capabilities |
| `description` | string | Human-readable one-liner |

### 4.2 Stage Map

Modules execute in order of their stage number. The following ranges are reserved:

| Range | Domain | Modules |
|-------|--------|---------|
| 10–12 | Pre-processing | dispatcher, lacp, lldp, stp |
| 15–19 | Early filtering | tunnel, source_guard, dhcp_snoop |
| 20–29 | VLAN + QoS | vlan (20), qos_classify (25), rate_limiter (28) |
| 30–39 | Access control | acl (30), conntrack (35) |
| 40–49 | Mirroring | mirror (40) |
| 50–59 | Routing + NAT | route (50), nat (55) |
| 60–69 | Flow acceleration | flow_table (60) |
| 80–89 | Learning + sampling | l2learn (80), arp_learn (82), afxdp_redirect (84), sflow (85) |
| 90–99 | Ingress final | lastcall (90) |
| 170–179 | Egress QoS | egress_qos (170) |
| 180–189 | Egress VLAN | egress_vlan (180) |
| 190–199 | Egress final | egress_final (190) |

**Third-party modules**: Use stages 200–299 (user ingress) or 400–499 (user egress). See `RS_STAGE_USER_INGRESS_MIN`/`MAX` and `RS_STAGE_USER_EGRESS_MIN`/`MAX` in `module_abi.h`.

### 4.3 Capability Flags

| Flag | Meaning |
|------|---------|
| `RS_FLAG_NEED_L2L3_PARSE` | Module requires L2/L3 headers to be pre-parsed |
| `RS_FLAG_NEED_FLOW_INFO` | Module requires L4 flow information (sport/dport) |
| `RS_FLAG_MODIFIES_PACKET` | Module may modify packet data |
| `RS_FLAG_MAY_DROP` | Module may drop packets |
| `RS_FLAG_CREATES_EVENTS` | Module emits events via `rs_event_bus` |
| `RS_FLAG_MAY_REDIRECT` | Module may redirect packets (`bpf_redirect_map`) |

### 4.4 Dependencies

If a module requires another module to run first:

```c
RS_DEPENDS_ON("conntrack");  // Must run after conntrack
```

---

## 5. Context Access

### 5.1 Getting the Context

Every module MUST use the `RS_GET_CTX()` macro to obtain the per-CPU pipeline context:

```c
struct rs_ctx *ctx = RS_GET_CTX();
if (!ctx)
    return XDP_DROP;  // Ingress default
    // or return XDP_PASS;  // Egress default (let kernel handle)
```

**FORBIDDEN**: Do not use `bpf_map_lookup_elem(&rs_ctx_map, &key)` directly. Always use `RS_GET_CTX()`.

### 5.2 Context Fields

| Field | Type | Description |
|-------|------|-------------|
| `ifindex` | u32 | Ingress interface index |
| `parsed` | u8 | 1 if dispatcher parsed headers |
| `modified` | u8 | Set to 1 if packet was modified |
| `layers` | struct | Parsed protocol layers (see below) |
| `ingress_vlan` | u16 | Effective ingress VLAN |
| `egress_vlan` | u16 | Egress VLAN to apply |
| `prio` | u8 | QoS priority (0–7, 0xFF=unset) |
| `dscp` | u8 | DSCP value |
| `ecn` | u8 | ECN bits |
| `traffic_class` | u8 | Classified traffic class |
| `egress_ifindex` | u32 | Target egress interface |
| `action` | u8 | Forwarding decision (XDP_PASS/DROP/REDIRECT) |
| `mirror` | u8 | Mirror flag |
| `mirror_port` | u16 | Mirror destination port |
| `error` | u32 | Error code (`RS_ERROR_*`) |
| `drop_reason` | u32 | Drop reason (`RS_DROP_*`) |
| `call_depth` | u32 | Pipeline call depth counter |

### 5.3 Layer Offsets

When accessing packet headers via `ctx->layers.l3_offset`, always apply the offset mask:

```c
struct iphdr *iph = data + (ctx->layers.l3_offset & RS_L3_OFFSET_MASK);
if ((void *)(iph + 1) > data_end)
    return XDP_DROP;
```

Available masks: `RS_L2_OFFSET_MASK`, `RS_L3_OFFSET_MASK`, `RS_L4_OFFSET_MASK`.

---

## 6. Pipeline Chaining

### 6.1 Ingress Modules

After processing, ingress modules MUST chain to the next module:

```c
RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
return XDP_DROP;  // Fallthrough if tail-call fails
```

### 6.2 Egress Dispatch Mechanism

When an ingress module sets `ctx->action = XDP_REDIRECT` and `ctx->egress_ifindex`, the terminal ingress module (`lastcall`) calls `bpf_redirect_map()` to forward the packet to the target interface via a devmap. The devmap has an egress program attached via `BPF_F_DEVMAP_PROG`, which triggers the egress tail-call chain.

The egress pipeline is independent from ingress: it has its own `rs_progs` prog_array entries and its own `rs_prog_chain` linkage. Egress modules are sorted by stage (170, 180, 190 for core; 400–499 for user modules) and chained via `RS_TAIL_CALL_EGRESS`.

**Flow**: Ingress pipeline → `lastcall` → `bpf_redirect_map(devmap)` → devmap egress prog → egress tail-call chain → `egress_final` → transmit.

### 6.3 Egress Modules

Egress modules MUST use the egress-specific chain:

```c
RS_TAIL_CALL_EGRESS(xdp_ctx, ctx);
return XDP_DROP;  // Fallthrough
```

### 6.4 Terminal Modules

Terminal modules (`lastcall`, `egress_final`) do NOT chain. They perform the final action (e.g., `bpf_redirect_map`) and return.

### 6.5 SEC Names

| Module Type | SEC Annotation |
|-------------|----------------|
| Ingress | `SEC("xdp")` |
| Egress (devmap callback) | `SEC("xdp/devmap")` |
| Standalone (veth path) | `SEC("xdp")` |

---

## 7. BPF Maps

### 7.1 Naming Convention

| Map Type | Naming Rule | Example |
|----------|-------------|---------|
| **Framework shared maps** | `rs_` prefix | `rs_ctx_map`, `rs_progs`, `rs_event_bus`, `rs_vlan_map`, `rs_mac_table` |
| **Module-private maps** | Module-specific prefix | `acl_5tuple_map`, `rl_bucket_map`, `stp_port_state_map` |
| **Cross-module shared maps** | Defined in `core/map_defs.h` with `rs_` prefix, accessed via `extern` | `rs_mac_table` (owned by l2learn, read by others) |

### 7.2 Map Pinning

All maps that need to be accessible from user-space MUST include pinning:

```c
__uint(pinning, LIBBPF_PIN_BY_NAME);
```

This is required for:
- Configuration maps (loaded by user-space)
- Statistics maps (read by user-space)
- Any map shared between modules

### 7.3 Map Ownership

When multiple modules access the same data:

1. **One module owns the map** — defines it with full struct.
2. **Other modules declare `extern`** — or access it via shared definitions in `core/map_defs.h`.

Example (MAC table):
```c
// l2learn.bpf.c (owner):
#define RS_MAC_TABLE_OWNER
#include "../include/rswitch_common.h"

// acl.bpf.c (consumer):
#include "../include/rswitch_common.h"  // Gets extern access to rs_mac_table
```

### 7.4 Map Alignment

All value structs SHOULD use proper alignment:

```c
struct my_entry {
    __u64 timestamp;
    __u32 counter;
    __u8  flags;
    __u8  pad[3];         // Explicit padding
} __attribute__((aligned(8)));
```

---

## 8. Event Emission

### 8.1 Using RS_EMIT_EVENT

Modules that emit events MUST use the `RS_EMIT_EVENT()` macro:

```c
struct my_event evt = {
    .event_type = MY_EVENT_TYPE,
    .ifindex = ctx->ifindex,
    // ...
};
RS_EMIT_EVENT(&evt, sizeof(evt));
```

**FORBIDDEN**: Do not use `bpf_ringbuf_reserve()` / `bpf_ringbuf_submit()` directly on `rs_event_bus`. Always use `RS_EMIT_EVENT()`.

### 8.2 Event Type Ranges

| Range | Domain |
|-------|--------|
| `RS_EVENT_L2_BASE + 0x00–0x0F` | L2 learning events |
| `RS_EVENT_L2_BASE + 0x10–0x1F` | STP events |
| `RS_EVENT_ACL_BASE + 0x00–0x0F` | ACL match events |
| `RS_EVENT_ACL_BASE + 0x10–0x1F` | Source guard events |
| `RS_EVENT_ROUTE_BASE + 0x00–0x0F` | Route events |
| `RS_EVENT_QOS_BASE + 0x00–0x0F` | QoS events |
| `RS_EVENT_QOS_BASE + 0x10–0x1F` | sFlow events |
| `RS_EVENT_USER_BASE`–`RS_EVENT_USER_MAX` (`0x1000`–`0x7FFF`) | User module events (third-party) |

### 8.3 Event Struct Convention

Every event struct MUST start with:

```c
struct my_event {
    __u32 event_type;   // MUST be first field
    __u32 ifindex;      // SHOULD be second field
    // ... module-specific fields ...
};
```

---

## 9. Statistics

### 9.1 Stats Pattern

Modules SHOULD expose per-CPU statistics:

```c
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, MY_STAT_MAX);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} mymod_stats_map SEC(".maps");

static __always_inline void update_stat(__u32 key)
{
    __u64 *val = bpf_map_lookup_elem(&mymod_stats_map, &key);
    if (val)
        __sync_fetch_and_add(val, 1);
}
```

### 9.2 Stats Key Convention

Use an enum for stats keys:

```c
enum mymod_stat_type {
    MYMOD_STAT_PROCESSED = 0,
    MYMOD_STAT_DROPPED = 1,
    MYMOD_STAT_ERROR = 2,
    MYMOD_STAT_MAX = 3,   // MUST be last — used as max_entries
};
```

---

## 10. Configuration

### 10.1 Config Map Pattern

Modules that are configurable SHOULD expose a config map:

```c
struct mymod_config {
    __u8 enabled;       // MUST be first field
    __u8 pad[3];
    // ... module-specific config ...
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct mymod_config);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} mymod_config_map SEC(".maps");
```

### 10.2 Enable Check

Configurable modules MUST check the `enabled` field early:

```c
__u32 cfg_key = 0;
struct mymod_config *cfg = bpf_map_lookup_elem(&mymod_config_map, &cfg_key);
if (!cfg || !cfg->enabled) {
    RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
    return XDP_DROP;
}
```

---

## 11. Debug Logging

Use the framework debug macro:

```c
rs_debug("MyMod: processing packet on ifindex=%u", ctx->ifindex);
```

Debug output is compiled out in release builds. Do NOT use `bpf_printk()` directly.

---

## 12. Coding Style

### 12.1 Functions

- All helper functions MUST be `static __always_inline`.
- Entry point function names SHOULD match the module name (e.g., `rate_limit` for `rate_limiter` module).

### 12.2 Error Handling

- Set `ctx->error` and `ctx->drop_reason` before dropping.
- Use framework error codes: `RS_ERROR_*`, `RS_DROP_*`.

### 12.3 Verifier Friendliness

- Always mask offsets before pointer arithmetic: `data + (offset & RS_L3_OFFSET_MASK)`.
- Always bounds-check after pointer arithmetic: `if ((void *)(ptr + 1) > data_end)`.
- Use `#pragma clang loop unroll(full)` or `bpf_loop()` for bounded iteration.
- Avoid unbounded loops — the BPF verifier will reject them.

---

## 13. Testing

### 13.1 Test Infrastructure

rSwitch provides two testing levels:

| Level | Location | Framework | Mechanism |
|-------|----------|-----------|-----------|
| **Unit tests** | `rswitch/test/unit/` | `rs_test.h` + `rs_test_runner.c` | `BPF_PROG_TEST_RUN` — loads the compiled `.bpf.o`, injects packets, reads `rs_ctx_map` output |
| **SDK mock tests** | `rswitch/sdk/test/` | `test_harness.h` + `mock_maps.h` | User-space mock — tests pure logic without kernel |

### 13.2 Writing Unit Tests

Create a file `rswitch/test/unit/test_<module>.c`:

```c
#include "rs_test.h"
#include "test_packets.h"

// Test packet definitions
static unsigned char test_ipv4_pkt[] = { /* ... */ };

RS_TEST(test_mymod_basic_pass)
{
    struct rs_test_ctx *tc = rs_test_open("path/to/mymod.bpf.o");
    RS_ASSERT(tc != NULL);

    // Set up config
    struct mymod_config cfg = { .enabled = 1 };
    RS_ASSERT_OK(rs_test_map_insert(tc, "mymod_config_map", &(uint32_t){0}, &cfg));

    // Set up context
    struct rs_ctx input_ctx = {
        .ifindex = 5,
        .parsed = 1,
        .layers.eth_proto = 0x0800,
    };
    RS_ASSERT_OK(rs_test_map_insert(tc, "rs_ctx_map", &(uint32_t){0}, &input_ctx));

    // Run
    struct rs_ctx out_ctx = {};
    __u32 retval = 0;
    RS_ASSERT_OK(rs_test_run(tc, "mymod_entry", test_ipv4_pkt, sizeof(test_ipv4_pkt), &out_ctx, &retval));

    // Verify
    RS_ASSERT_EQ(retval, XDP_DROP);  // Expected: tail-call fallthrough
    RS_ASSERT_EQ(out_ctx.error, 0);

    rs_test_close(tc);
}

RS_TEST_SUITE_BEGIN();
    RS_RUN_TEST(test_mymod_basic_pass);
RS_TEST_SUITE_END();
```

### 13.3 Test Conventions

| Convention | Rule |
|------------|------|
| File naming | `test_<module_name>.c` |
| Test naming | `test_<module>_<scenario>` |
| Setup | Configure maps (config, rules) via `rs_test_map_insert()` |
| Execution | Call `rs_test_run()` with packet data |
| Assertions | Check `retval` (XDP action) + `out_ctx` fields |
| Cleanup | Always call `rs_test_close()` |

### 13.4 Running Tests

```bash
cd rswitch/test/unit
./run_tests.sh
```

Or individually:

```bash
gcc -o test_mymod test_mymod.c rs_test_runner.c -lbpf -lelf -lz
sudo ./test_mymod
```

---

## 14. Build

### 14.1 Using the SDK Makefile

```bash
make -f rswitch/sdk/Makefile.module MODULE=my_module
```

### 14.2 Verification

After building, verify module metadata:

```bash
make -f rswitch/sdk/Makefile.module MODULE=my_module verify
```

---

## 15. Checklist

Before submitting a module, verify:

- [ ] File follows Section 2 layout (SPDX → includes → license → RS_DECLARE_MODULE → structs → maps → helpers → entry)
- [ ] Includes exactly `rswitch_common.h` + `module_abi.h`
- [ ] No `#ifndef __BPF__` guard
- [ ] Single `_license[]` declaration after includes
- [ ] `RS_DECLARE_MODULE()` with correct hook, stage, flags, description
- [ ] Uses `RS_GET_CTX()` (not manual map lookup)
- [ ] Calls `RS_TAIL_CALL_NEXT()` or `RS_TAIL_CALL_EGRESS()` (unless terminal)
- [ ] Uses `RS_EMIT_EVENT()` for events (not raw ringbuf)
- [ ] All maps have `LIBBPF_PIN_BY_NAME`
- [ ] Config map has `enabled` as first field
- [ ] All pointer arithmetic uses offset masks
- [ ] All bounds checks before access
- [ ] Uses `rs_debug()` (not `bpf_printk`)
- [ ] Module compiles with `Makefile.module`
- [ ] Unit test exists in `rswitch/test/unit/`

---

## Appendix A: Complete Module Template (Ingress)

```c
// SPDX-License-Identifier: GPL-2.0

#include "../include/rswitch_common.h"
#include "../core/module_abi.h"

char _license[] SEC("license") = "GPL";

RS_DECLARE_MODULE("my_module", RS_HOOK_XDP_INGRESS, 200,
                  RS_FLAG_NEED_L2L3_PARSE,
                  "My custom module description");

/* ── Data Structures ── */

struct mymod_config {
    __u8 enabled;
    __u8 pad[3];
};

enum mymod_stat {
    MYMOD_STAT_PROCESSED = 0,
    MYMOD_STAT_MAX = 1,
};

/* ── Maps ── */

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct mymod_config);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} mymod_config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, MYMOD_STAT_MAX);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} mymod_stats_map SEC(".maps");

/* ── Helpers ── */

static __always_inline void mymod_stat_inc(__u32 key)
{
    __u64 *val = bpf_map_lookup_elem(&mymod_stats_map, &key);
    if (val)
        __sync_fetch_and_add(val, 1);
}

/* ── Entry Point ── */

SEC("xdp")
int my_module_main(struct xdp_md *xdp_ctx)
{
    struct rs_ctx *ctx = RS_GET_CTX();
    if (!ctx)
        return XDP_DROP;

    /* Config check */
    __u32 cfg_key = 0;
    struct mymod_config *cfg = bpf_map_lookup_elem(&mymod_config_map, &cfg_key);
    if (!cfg || !cfg->enabled) {
        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_DROP;
    }

    /* Module logic */
    mymod_stat_inc(MYMOD_STAT_PROCESSED);

    /* Chain to next module */
    RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
    return XDP_DROP;
}
```

## Appendix B: Complete Module Template (Egress)

```c
// SPDX-License-Identifier: GPL-2.0

#include "../include/rswitch_common.h"
#include "../core/module_abi.h"

char _license[] SEC("license") = "GPL";

RS_DECLARE_MODULE("my_egress", RS_HOOK_XDP_EGRESS, 400,
                  RS_FLAG_MODIFIES_PACKET,
                  "My custom egress module");

SEC("xdp/devmap")
int my_egress_main(struct xdp_md *xdp_ctx)
{
    struct rs_ctx *ctx = RS_GET_CTX();
    if (!ctx)
        return XDP_PASS;

    /* Module logic */

    /* Chain to next egress module */
    RS_TAIL_CALL_EGRESS(xdp_ctx, ctx);
    return XDP_PASS;
}
```

---

*This specification supersedes the conventions described in `SDK_Quick_Start.md`. When in conflict, this document takes precedence.*
