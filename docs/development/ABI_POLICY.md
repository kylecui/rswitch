# ABI Stability Policy

**Applies to**: rSwitch ABI v2.0+
**Last updated**: 2026-03-24

This document defines the stability contract for rSwitch's module ABI. It governs how changes are classified, communicated, and enforced.

---

## 1. Version Semantics

rSwitch uses a two-component ABI version: **`MAJOR.MINOR`** (encoded as `(MAJOR << 16) | MINOR`).

| Version Component | When Bumped | Effect on Existing Modules |
|-------------------|-------------|---------------------------|
| **MAJOR** | Breaking changes: struct layout, removed fields, semantic changes | Loader **rejects** modules built against older major versions |
| **MINOR** | Additive changes: new flags, new error codes, new reserved-field usage | Loader **accepts** modules built against same major + older minor |

### Loader Enforcement

The loader (`rswitch_loader`), registry, and hot-reload daemon all enforce ABI compatibility:

```
Module ABI    Platform ABI    Result
─────────────────────────────────────
1.x           2.x             REJECTED  (major mismatch)
2.0           2.1             ACCEPTED  (older minor OK)
2.1           2.0             REJECTED  (newer minor than platform)
2.1           2.1             ACCEPTED  (exact match)
3.0           2.x             REJECTED  (major mismatch)
```

**Rule**: A module loads only when `mod_major == plat_major && mod_minor <= plat_minor`.

---

## 2. Stability Tiers

Every public API element is annotated with one of three stability tiers:

### RS_API_STABLE

**Guarantee**: No breaking changes within the same major version. If a stable API must change, the major version is bumped.

**Includes**:
- `struct rs_ctx` layout and field semantics
- `struct rs_layers` layout and field semantics
- `struct rs_module_desc` layout
- `RS_DECLARE_MODULE()` macro signature
- `RS_DEPENDS_ON()` macro signature
- `RS_GET_CTX()`, `RS_TAIL_CALL_NEXT()`, `RS_TAIL_CALL_EGRESS()`, `RS_EMIT_EVENT()`
- All `RS_FLAG_*` constants (existing bits never change meaning)
- All `RS_HOOK_*` constants
- `RS_STAGE_USER_INGRESS_MIN/MAX`, `RS_STAGE_USER_EGRESS_MIN/MAX`
- `RS_EVENT_USER_BASE`, `RS_EVENT_USER_MAX`
- All `RS_ERROR_*` and `RS_DROP_*` constants

### RS_API_EXPERIMENTAL

**Guarantee**: May change between minor versions. Will be promoted to STABLE or removed within 2 minor releases.

**Current experimental APIs**:
- `struct rs_module_deps` (dependency declaration format)
- Module configuration map interface (`rs_get_module_config`)

**Migration**: When an experimental API changes, the changelog will include migration instructions.

### RS_API_INTERNAL

**Guarantee**: None. May change at any commit. Do not use in external modules.

**Includes**:
- Internal map layouts (ring buffer metadata, prog chain internals)
- Dispatcher stage assignment logic
- Loader ELF parsing internals

---

## 3. Struct Layout Rules

### rs_ctx (Per-Packet Context)

The `rs_ctx` struct is the primary ABI surface between modules. The following rules apply:

1. **No field reordering**: Fields maintain their offset within a major version
2. **No field removal**: Fields may be deprecated but not removed within a major version
3. **No type changes**: A field's type and size never change within a major version
4. **Reserved area**: `reserved[16]` (64 bytes) at the end of `rs_ctx` is available for future minor-version additions. New fields are allocated from `reserved[]` — the total struct size does not change within a major version
5. **Padding**: Explicit `pad[]` fields exist for alignment; they must not be repurposed without a major bump

### rs_module_desc (Module Metadata)

1. **Format is frozen** within a major version (field offsets, sizes, section name `.rodata.mod`)
2. `reserved[4]` at end is available for future minor-version extensions
3. `name` max length (32) and `description` max length (64) are stable

### Adding New Fields (Minor Bump)

When a new field is needed:
1. Allocate from the `reserved[]` area (no struct size change)
2. Bump `RS_ABI_VERSION_MINOR`
3. Old modules (same major, older minor) continue to work — they simply don't read/write the new field
4. New modules that need the field set `RS_ABI_VERSION_MINOR` to the version that introduced it

---

## 4. Flag and Constant Stability

### RS_FLAG_* Capability Flags

| Rule | Detail |
|------|--------|
| Existing bits never change meaning | `RS_FLAG_MAY_DROP` is always bit 4 |
| New flags use the next available bit | Currently bits 0-6 are assigned |
| Adding a new flag is a **minor** bump | Existing modules that don't set the flag are unaffected |
| The loader never rejects modules for missing optional flags | Flags are informational / declarative |

### RS_EVENT_* Event Types

| Range | Owner | Stability |
|-------|-------|-----------|
| `0x0000-0x0FFF` | Core rSwitch | STABLE within major version |
| `0x1000-0x7FFF` | User modules | STABLE range boundary; internal allocation is user's responsibility |
| `0x8000-0xFEFF` | Reserved | Do not use |
| `0xFF00-0xFFFF` | Core errors | STABLE within major version |

### RS_STAGE_* Stage Ranges

| Range | Owner | Stability |
|-------|-------|-----------|
| 10-99 | Core ingress | STABLE |
| 100-199 | Core egress | STABLE |
| 200-299 | User ingress | STABLE |
| 400-499 | User egress | STABLE |
| 300-399 | Reserved | Do not use |

---

## 5. Deprecation Process

When a STABLE API needs to change:

1. **Announce**: Add `RS_DEPRECATED("Use X instead, removed in ABI vN+1")` annotation
2. **Grace period**: Deprecated API remains functional for at least 1 major version
3. **Document**: Changelog and migration guide published alongside the deprecation
4. **Remove**: Deprecated API removed in the next major version

Example timeline:
```
ABI 2.0  — RS_FLAG_FOO introduced (STABLE)
ABI 2.3  — RS_FLAG_FOO deprecated, RS_FLAG_BAR replaces it
ABI 3.0  — RS_FLAG_FOO removed, RS_FLAG_BAR is now the only option
```

---

## 6. ABI Version History

| Version | Date | Changes |
|---------|------|---------|
| **2.0** | 2026-03 | `rs_ctx.reserved` expanded 16→64 bytes; `RS_FLAG_MAY_REDIRECT` added; user stage ranges (200-299, 400-499); user event range (0x1000-0x7FFF); major bump from 1.0 |
| **1.0** | 2025-12 | Initial ABI: `rs_ctx` with 16-byte reserved area, 6 capability flags, core stage ranges only |

---

## 7. For Module Developers

### Checking ABI Compatibility

```c
#include "rswitch_module.h"

// RS_DECLARE_MODULE automatically embeds RS_ABI_VERSION in .rodata.mod
// The loader checks this at load time — no manual version check needed.
```

### Building Against a Specific ABI

The ABI version is set at compile time by the SDK headers. To target a specific ABI:

```bash
# Check installed SDK version
pkg-config --modversion rswitch
# Output: 2.0.0

# The module's ABI version matches the SDK headers it was compiled against
```

### When Your Module Stops Loading

If the loader rejects your module with "ABI major mismatch":
1. Recompile against the current SDK headers (`sudo make install-sdk` to update)
2. Review the [ABI Version History](#6-abi-version-history) for breaking changes
3. Update your code if any APIs were removed or changed

---

## 8. References

- [SDK Quick Start](../../sdk/docs/SDK_Quick_Start.md) — Getting started with module development
- [Module Developer Guide](Module_Developer_Guide.md) — Complete module authoring patterns
- [API Reference](API_Reference.md) — Full API documentation
- Header: [`rswitch_abi.h`](../../sdk/include/rswitch_abi.h) — Canonical ABI definitions
