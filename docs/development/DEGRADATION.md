# Graceful Degradation Protocol

> How rSwitch modules should behave when the pipeline is partially available
> or running outside the full rSwitch environment.

## Overview

A well-written rSwitch module must handle **degraded conditions** without
crashing or silently dropping traffic. This document defines the standard
patterns for detecting and responding to partial pipeline availability.

## When Degradation Occurs

| Condition | Cause | Module Behavior |
|-----------|-------|-----------------|
| `rs_ctx_map` lookup returns `NULL` | Pipeline not initialized, module loaded standalone | Pass packet through (XDP_PASS) |
| `rs_prog_chain` lookup returns `NULL` | No next stage configured | Return XDP_PASS (end of pipeline) |
| Tail call fails (falls through) | Target program not loaded | Return XDP_PASS or XDP_DROP per module policy |
| Required config map empty | Module not yet configured | Pass packet through |

## Detection: `RS_IS_PIPELINE_ACTIVE`

The SDK provides a helper macro to check if the rSwitch pipeline is active:

```c
#include "rswitch_helpers.h"

SEC("xdp")
int my_module(struct xdp_md *xdp_ctx)
{
    /* Check if pipeline is active before relying on rs_ctx */
    if (!RS_IS_PIPELINE_ACTIVE())
        return XDP_PASS;  /* Graceful fallback: pass traffic */

    struct rs_ctx *ctx = RS_GET_CTX();
    if (!ctx)
        return XDP_PASS;

    /* Normal module logic here... */
}
```

`RS_IS_PIPELINE_ACTIVE()` performs a zero-key lookup on `rs_ctx_map`. If the
map is not pinned or the pipeline has not been initialized, the lookup returns
`NULL` and the macro evaluates to `false`.

## Recommended Patterns

### Pattern 1: Pass-Through on Degradation (DEFAULT)

Most modules should pass traffic when degraded. This prevents a partially-loaded
pipeline from black-holing packets.

```c
struct rs_ctx *ctx = RS_GET_CTX();
if (!ctx)
    return XDP_PASS;  /* Pipeline not ready — let kernel handle it */
```

### Pattern 2: Drop on Degradation (Security Modules Only)

Security-critical modules (ACL, source guard) may choose to drop traffic when
the pipeline is not fully operational. **This must be explicitly documented.**

```c
struct rs_ctx *ctx = RS_GET_CTX();
if (!ctx)
    return XDP_DROP;  /* SECURITY: deny traffic if pipeline is degraded */
```

### Pattern 3: Tail Call Fallthrough

When a tail call to the next stage fails (target not loaded), the BPF program
continues execution after the `bpf_tail_call()`. Always handle this case:

```c
/* Continue to next stage */
RS_TAIL_CALL_NEXT(xdp_ctx, ctx);

/* Tail call failed — this is the last stage or target is missing */
return XDP_PASS;  /* or XDP_DROP for security modules */
```

### Pattern 4: Config Map Fallback

If your module relies on a configuration map, handle the case where it's empty:

```c
struct my_config *cfg = bpf_map_lookup_elem(&my_config_map, &key);
if (!cfg) {
    /* Config not loaded yet — pass through */
    RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
    return XDP_PASS;
}
```

## Testing Degradation

Use `BPF_PROG_TEST_RUN` to test degradation behavior. The test harness in
`test/unit/rs_test_runner.c` initializes `rs_ctx_map` but you can test with
an empty map to verify fallback behavior.

See the CI test suite in `test/ci/` for examples of testing modules under
partially configured conditions (e.g., `test_vlan_bpf.c` tests VLAN module
without port configuration).

## Guidelines

1. **Default to XDP_PASS** — when in doubt, pass the packet. A silently
   dropped packet is harder to debug than one that reaches the kernel stack.

2. **Document your fallback** — if your module drops on degradation, put a
   comment in the code and note it in the module's header/README.

3. **Never crash** — a NULL pointer dereference in BPF causes `XDP_ABORTED`
   and logs a kernel warning. Always check return values.

4. **Log degradation** — use `bpf_printk()` (under `#ifdef DEBUG`) to log
   when your module enters degraded mode. This helps operators diagnose
   partial-load scenarios.

## See Also

- [Module Development Spec](../../sdk/docs/Module_Development_Spec.md)
- [ABI Policy](ABI_POLICY.md) — versioning and compatibility guarantees
- [SDK Quick Start](../../sdk/docs/SDK_Quick_Start.md) — getting started guide
