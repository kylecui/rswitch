# SDK Header Migration Guide

> **Audience**: Downstream projects that vendored rSwitch headers before SDK v2.0.
>
> **Goal**: Migrate from legacy headers (`uapi.h`, `map_defs.h`, `rswitch_bpf.h`, `module_abi.h`) to the consolidated SDK headers (`rswitch_module.h`, `rswitch_maps.h`).

---

## 1. Header Mapping Table

| Legacy Header | Replacement | What Moved |
|---------------|-------------|------------|
| `uapi.h` | `rswitch_abi.h` (types/constants) + `rswitch_helpers.h` (macros) | `struct rs_ctx`, `struct rs_layers`, `RS_GET_CTX`, `RS_TAIL_CALL_*`, `RS_EMIT_EVENT`, error/drop codes |
| `map_defs.h` | `rswitch_maps.h` | `struct rs_port_config`, `struct rs_mac_key`, `struct rs_mac_entry`, `struct rs_stats`, all map definitions and helper functions |
| `rswitch_bpf.h` | `rswitch_module.h` | CO-RE macros, protocol constants, packet parsing helpers, compiler hints |
| `module_abi.h` | `rswitch_abi.h` | `RS_DECLARE_MODULE`, `struct rs_module_info`, ABI version constants |

### Recommended Include Pattern

After migration, all BPF source files should use at most two includes:

```c
#include <rswitch_module.h>   /* Required: ABI types + helpers + pipeline macros */
#include <rswitch_maps.h>     /* Optional: only if you access shared maps */
```

`rswitch_module.h` pulls in `rswitch_abi.h` and `rswitch_helpers.h` automatically — you never need to include those directly.

---

## 2. Step-by-Step Migration

### Step 1: Replace Header Includes

Find all legacy `#include` directives and replace them:

```diff
- #include "uapi.h"
- #include "rswitch_bpf.h"
- #include "module_abi.h"
+ #include <rswitch_module.h>
```

If your file also uses shared maps (port config, statistics, MAC table, VLAN maps):

```diff
- #include "map_defs.h"
+ #include <rswitch_maps.h>
```

### Step 2: Update Include Paths

Legacy headers used quoted includes with relative paths. The SDK headers use angle brackets resolved via the `-I` flag:

```diff
  # In your Makefile / build system
- CFLAGS += -I./include/rswitch
+ CFLAGS += -I$(SDK_DIR)/include
```

Or use the provided `Makefile.module` which sets paths automatically:

```bash
make -f /path/to/sdk/Makefile.module MODULE=my_module
```

### Step 3: Remove Vendored Copies

Once migration is verified, delete vendored copies of legacy headers:

```bash
rm include/rswitch/uapi.h
rm include/rswitch/map_defs.h
rm include/rswitch/rswitch_bpf.h
rm include/rswitch/module_abi.h
```

### Step 4: Verify Build

```bash
# Using Makefile.module (recommended)
make -f /path/to/sdk/Makefile.module MODULE=my_module clean all

# Or with manual clang invocation
clang -g -O2 -target bpf \
    -D__TARGET_ARCH_x86 -D__BPF__ \
    -I/path/to/sdk/include \
    -Wall -Werror \
    -c my_module.bpf.c -o my_module.bpf.o
```

---

## 3. Before/After Examples

### Example A: Simple Ingress Module

**Before** (legacy headers):

```c
#include "rswitch_bpf.h"
#include "uapi.h"

SEC("xdp")
int my_filter(struct xdp_md *ctx)
{
    struct rs_ctx *rs = RS_GET_CTX();
    if (!rs) return XDP_PASS;

    if (rs->layers.ip_proto == IPPROTO_UDP)
        return XDP_DROP;

    RS_TAIL_CALL_NEXT(ctx, rs);
    return XDP_PASS;
}
```

**After** (SDK headers):

```c
#include <rswitch_module.h>

SEC("xdp")
int my_filter(struct xdp_md *ctx)
{
    struct rs_ctx *rs = RS_GET_CTX();
    if (!rs) return XDP_PASS;

    if (rs->layers.ip_proto == IPPROTO_UDP)
        return XDP_DROP;

    RS_TAIL_CALL_NEXT(ctx, rs);
    return XDP_PASS;
}
```

No code changes needed — only the `#include` line changes.

### Example B: Module with Map Access

**Before** (legacy headers):

```c
#include "rswitch_bpf.h"
#include "uapi.h"
#include "map_defs.h"

SEC("xdp")
int my_stats(struct xdp_md *ctx)
{
    struct rs_ctx *rs = RS_GET_CTX();
    if (!rs) return XDP_PASS;

    rs_stats_update_rx(rs, ctx->data_end - ctx->data);
    RS_TAIL_CALL_NEXT(ctx, rs);
    return XDP_PASS;
}
```

**After** (SDK headers):

```c
#include <rswitch_module.h>
#include <rswitch_maps.h>

SEC("xdp")
int my_stats(struct xdp_md *ctx)
{
    struct rs_ctx *rs = RS_GET_CTX();
    if (!rs) return XDP_PASS;

    rs_stats_update_rx(rs, ctx->data_end - ctx->data);
    RS_TAIL_CALL_NEXT(ctx, rs);
    return XDP_PASS;
}
```

### Example C: Module Metadata Declaration

**Before** (legacy `module_abi.h`):

```c
#include "module_abi.h"

RS_DECLARE_MODULE(my_module, 2, 0, RS_HOOK_INGRESS, RS_STAGE_L3);
```

**After** (`rswitch_module.h` includes `rswitch_abi.h` which provides `RS_DECLARE_MODULE`):

```c
#include <rswitch_module.h>

RS_DECLARE_MODULE(my_module, 2, 0, RS_HOOK_INGRESS, RS_STAGE_L3);
```

---

## 4. Common Migration Errors

### Error: `'vmlinux.h' file not found`

**Cause**: `rswitch_helpers.h` (included via `rswitch_module.h`) requires `vmlinux.h`.

**Fix**: Generate it from your running kernel:

```bash
# Using the provided helper script
sdk/scripts/generate_vmlinux.sh include/vmlinux.h

# Or manually
bpftool btf dump file /sys/kernel/btf/vmlinux format c > include/vmlinux.h
```

### Error: `redefinition of 'struct rs_ctx'`

**Cause**: Both a legacy header and a new SDK header are included, causing duplicate definitions.

**Fix**: Remove all legacy `#include` directives. Do not mix old and new headers.

### Error: `use of undeclared identifier 'rs_port_config_map'`

**Cause**: Map definitions are now opt-in. `rswitch_module.h` does NOT include maps.

**Fix**: Add `#include <rswitch_maps.h>` to files that access shared maps.

### Error: `unknown type name 'struct rs_port_config'`

**Cause**: Same as above — struct definitions for map values live in `rswitch_maps.h`.

**Fix**: Add `#include <rswitch_maps.h>`.

### Warning: `"uapi.h is deprecated..."` (or similar)

**Cause**: Legacy headers now emit `#warning` to remind you to migrate.

**Fix**: Replace the `#include` as described in Step 1. The warning disappears once you switch to the new headers.

---

## 5. Verification Checklist

After migration, verify:

- [ ] `grep -rn 'uapi\.h\|map_defs\.h\|rswitch_bpf\.h\|module_abi\.h' src/` → no matches (all legacy includes removed)
- [ ] Build succeeds with `-Wall -Werror` (no deprecation warnings)
- [ ] `bpftool prog show` lists your module after loading (BPF programs intact)
- [ ] `bpftool map show` confirms pinned maps are accessible (map references resolved)
- [ ] Functional test passes (packets processed correctly through your module)

---

## 6. SDK Header Architecture

```
rswitch_module.h          ← Single entry point (recommended)
  └── rswitch_helpers.h   ← BPF helpers, macros, packet parsing
        ├── vmlinux.h     ← Kernel types (CO-RE)
        ├── bpf_helpers.h ← libbpf
        └── rswitch_abi.h ← ABI types, constants, struct definitions
              ├── bpf_helpers.h  (BPF side)
              └── linux/types.h  (user-space side)

rswitch_maps.h            ← Shared map definitions (opt-in)
  ├── bpf_helpers.h
  └── rswitch_abi.h

rswitch_common.h          ← Legacy catch-all (includes everything)
  ├── rswitch_module.h
  └── rswitch_maps.h
```

Legacy headers (`uapi.h`, `map_defs.h`, `rswitch_bpf.h`, `module_abi.h`) are retained for backward compatibility but emit deprecation warnings at compile time.

---

*See also: [SDK Quick Start](SDK_Quick_Start.md) · [ABI Policy](../../docs/development/ABI_POLICY.md) · [Module Developer Guide](../../docs/development/Module_Developer_Guide.md)*
