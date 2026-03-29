# ABI v1 → v2 Migration Guide

> **Audience**: Module developers upgrading from rSwitch ABI v1.0 to ABI v2.0.
>
> This guide covers every breaking change, the exact code modifications needed, and common pitfalls.

---

## 1. Summary of Breaking Changes

ABI v2.0 is a **major** version bump. Modules compiled against ABI v1.0 headers will be **rejected** by the v2.0 loader (major mismatch). All modules must be recompiled.

| Change | ABI v1.0 | ABI v2.0 | Impact |
|--------|----------|----------|--------|
| **`rs_ctx.reserved` size** | `__u32 reserved[4]` (16 bytes) | `__u32 reserved[16]` (64 bytes) | Struct layout change — binary incompatible |
| **User ingress stage range** | Not defined (ad-hoc) | 200-299 (`RS_STAGE_USER_INGRESS_MIN/MAX`) | Modules using hardcoded stages outside this range will violate policy |
| **User egress stage range** | Not defined (ad-hoc) | 400-499 (`RS_STAGE_USER_EGRESS_MIN/MAX`) | Same as above |
| **User event type range** | Flat namespace (collision risk) | `0x1000-0x7FFF` (`RS_EVENT_USER_BASE/MAX`) | Event types outside this range may collide with core events |
| **`RS_FLAG_MAY_REDIRECT`** | Not available | Bit 6 | Modules that redirect packets should set this flag |
| **`RS_DEPENDS_ON()` macro** | Not available | Declares module dependencies | Optional — existing modules work without it |
| **Unified SDK header** | `#include "module_abi.h"` (legacy) | `#include <rswitch_module.h>` | Old headers still work but emit deprecation warnings |

---

## 2. Step-by-Step Migration Checklist

### Step 1: Update Include Path

**Before (v1)**:
```c
#include "module_abi.h"
#include "rswitch_bpf.h"
#include "map_defs.h"
```

**After (v2)**:
```c
#include <rswitch_module.h>    /* Single entry point — includes ABI, helpers, maps */
```

`rswitch_module.h` includes `rswitch_abi.h`, `rswitch_helpers.h`, and `rswitch_maps.h`. You no longer need individual includes.

> **Note**: The old headers (`module_abi.h`, `rswitch_bpf.h`, `map_defs.h`, `uapi.h`) still compile but emit `#warning` deprecation notices. Remove them to silence warnings.

### Step 2: Install SDK v2.0 Headers

```bash
# Update SDK on the build machine
cd rswitch && sudo make install-sdk

# Verify version
pkg-config --modversion rswitch
# Expected: 2.0.0
```

If building out-of-tree with `Makefile.module`:
```bash
# Makefile.module automatically pulls headers from the installed SDK
make -f /usr/local/share/rswitch/Makefile.module
```

### Step 3: Verify `RS_DECLARE_MODULE` ABI Version

The `RS_DECLARE_MODULE` macro automatically embeds `RS_ABI_VERSION` (which is now `2.0`). No code change needed — recompiling against v2.0 headers is sufficient.

```c
// This remains unchanged — the macro picks up the correct version
RS_DECLARE_MODULE("my_module",
    RS_HOOK_XDP_INGRESS,
    RS_STAGE_USER_INGRESS_MIN + 10,  // Stage 210
    RS_FLAG_NEED_L2L3_PARSE | RS_FLAG_MODIFIES_PACKET,
    "My custom packet processor"
);
```

After rebuilding, verify the embedded version:
```bash
# Check the .rodata.mod section
llvm-readelf -x .rodata.mod build/my_module.bpf.o | head -4
# First 4 bytes should show 0x00020000 (version 2.0, big-endian)
```

### Step 4: Update Stage Numbers

If your module uses hardcoded stage numbers, update them to the v2 user ranges:

| Hook | v2 Range | Macro |
|------|----------|-------|
| Ingress | 200-299 | `RS_STAGE_USER_INGRESS_MIN` (200) to `RS_STAGE_USER_INGRESS_MAX` (299) |
| Egress | 400-499 | `RS_STAGE_USER_EGRESS_MIN` (400) to `RS_STAGE_USER_EGRESS_MAX` (499) |

**Before (v1)** — hardcoded arbitrary stage:
```c
RS_DECLARE_MODULE("my_module", RS_HOOK_XDP_INGRESS, 50, ...);
// Stage 50 is in the core range — will work but violates v2 policy
```

**After (v2)** — use user range:
```c
RS_DECLARE_MODULE("my_module", RS_HOOK_XDP_INGRESS,
    RS_STAGE_USER_INGRESS_MIN + 10,  // Stage 210
    ...);
```

> **Warning**: Core stages 10-99 (ingress) and 100-199 (egress) are reserved for rSwitch platform modules. User modules that claim core stages will load but may conflict with future platform modules.

### Step 5: Migrate Event Types to User Namespace

If your module emits custom events via `RS_EMIT_EVENT`, update event type constants:

**Before (v1)** — flat namespace with collision risk:
```c
#define MY_EVENT_FOO  42   // Could collide with core events
RS_EMIT_EVENT(MY_EVENT_FOO, &data, sizeof(data));
```

**After (v2)** — use user event range:
```c
#define MY_EVENT_FOO  (RS_EVENT_USER_BASE + 1)   // 0x1001
#define MY_EVENT_BAR  (RS_EVENT_USER_BASE + 2)   // 0x1002
RS_EMIT_EVENT(MY_EVENT_FOO, &data, sizeof(data));
```

The user event range is `0x1000-0x7FFF` (28,672 values). Coordinate with other module authors if sharing a platform.

### Step 6: Add New Capability Flags (If Applicable)

If your module redirects packets (via `bpf_redirect`, `bpf_redirect_map`, etc.), add the new flag:

```c
RS_DECLARE_MODULE("my_redirector",
    RS_HOOK_XDP_INGRESS,
    RS_STAGE_USER_INGRESS_MIN + 20,
    RS_FLAG_NEED_L2L3_PARSE | RS_FLAG_MAY_REDIRECT,  // ← new in v2
    "Redirects packets to target port"
);
```

This flag is informational — the loader does not enforce it. But setting it correctly enables future tooling and pipeline optimization.

### Step 7: Declare Dependencies (Optional)

ABI v2.0 introduces `RS_DEPENDS_ON()` for declaring module dependencies:

```c
RS_DECLARE_MODULE("my_module", ...);
RS_DEPENDS_ON("dispatcher", "vlan");  // Requires dispatcher and vlan modules
```

This is **experimental** (`RS_API_EXPERIMENTAL`) and optional. It has no runtime effect in v2.0 but enables future dependency-aware loading.

### Step 8: Rebuild and Test

```bash
# Clean build
make clean && make

# Run BPF test harness (if available)
sudo ./test/run_tests.sh

# Or test with BPF_PROG_TEST_RUN
sudo ./test/bpf_test_runner my_module.bpf.o
```

---

## 3. Common Pitfalls

### Pitfall 1: Mixing v1 and v2 Headers

**Symptom**: Compilation succeeds but the loader rejects the module with "ABI major mismatch."

**Cause**: Build system includes stale v1 headers from a different path. The module embeds ABI v1.0 despite using v2 sources.

**Fix**: Ensure `-I` flags point to the v2 SDK:
```bash
# Verify which rswitch_abi.h is being used
clang -E -dM my_module.bpf.c | grep RS_ABI_VERSION_MAJOR
# Must show: #define RS_ABI_VERSION_MAJOR 2
```

### Pitfall 2: `rs_ctx` Size Assumption

**Symptom**: Module reads garbage from `rs_ctx` fields after the reserved area.

**Cause**: Code assumes `sizeof(struct rs_ctx)` matches the v1 layout (which had 48 fewer bytes in `reserved`).

**Fix**: Never hardcode `rs_ctx` size. Always use `sizeof(struct rs_ctx)` and access fields by name.

### Pitfall 3: Stage Conflict with Core Modules

**Symptom**: Pipeline ordering is wrong — your module runs before/after the expected position.

**Cause**: User module uses a core stage number (e.g., 30 = ACL stage).

**Fix**: Use `RS_STAGE_USER_INGRESS_MIN + offset` for ingress, `RS_STAGE_USER_EGRESS_MIN + offset` for egress.

### Pitfall 4: Event Type Collision

**Symptom**: User-space event consumer receives unexpected event data.

**Cause**: Module uses event type in the core range (0x0000-0x0FFF) or error range (0xFF00-0xFFFF).

**Fix**: Use `RS_EVENT_USER_BASE + N` for all custom events. Stay within `0x1000-0x7FFF`.

### Pitfall 5: Hot-Reload ABI Check

**Symptom**: `hot_reload reload my_module` rejects the new binary with "ABI mismatch."

**Cause**: The running platform is v2.0 but the module was compiled against v1 headers (or vice versa).

**Fix**: Ensure the module is compiled against the same major version as the running platform. Hot-reload enforces `mod_major == plat_major && mod_minor <= plat_minor`.

---

## 4. Quick Reference: v1 vs v2 Side-by-Side

```c
/* ═══════════════════════════════════════════════════════ */
/* ABI v1.0 (old)                                         */
/* ═══════════════════════════════════════════════════════ */

#include "module_abi.h"
#include "rswitch_bpf.h"

RS_DECLARE_MODULE("my_module",
    RS_HOOK_XDP_INGRESS,
    50,                              // ad-hoc stage
    RS_FLAG_NEED_L2L3_PARSE,
    "My module"
);

#define MY_EVENT 42                   // flat namespace
RS_EMIT_EVENT(MY_EVENT, &data, sizeof(data));


/* ═══════════════════════════════════════════════════════ */
/* ABI v2.0 (new)                                         */
/* ═══════════════════════════════════════════════════════ */

#include <rswitch_module.h>          // unified entry point

RS_DECLARE_MODULE("my_module",
    RS_HOOK_XDP_INGRESS,
    RS_STAGE_USER_INGRESS_MIN + 10,  // stage 210 (user range)
    RS_FLAG_NEED_L2L3_PARSE,
    "My module"
);

#define MY_EVENT (RS_EVENT_USER_BASE + 1)   // user namespace
RS_EMIT_EVENT(MY_EVENT, &data, sizeof(data));

RS_DEPENDS_ON("dispatcher");         // optional: declare dependencies
```

---

## 5. Verification Checklist

After migration, verify each point:

- [ ] `pkg-config --modversion rswitch` returns `2.0.0`
- [ ] `clang -E -dM ... | grep RS_ABI_VERSION_MAJOR` returns `2`
- [ ] No `#warning` deprecation messages during compilation (all old headers removed)
- [ ] Module loads successfully: `sudo ./scripts/rswitch-init.sh start`
- [ ] Hot-reload works: `sudo ./user/reload/hot_reload reload my_module --dry-run`
- [ ] Stage number is in user range (200-299 for ingress, 400-499 for egress)
- [ ] Event types are in user range (`0x1000-0x7FFF`)

---

*See also: [ABI Stability Policy](ABI_POLICY.md) · [SDK Quick Start](../../sdk/docs/SDK_Quick_Start.md) · [SDK Migration Guide](../../sdk/docs/SDK_Migration_Guide.md)*
