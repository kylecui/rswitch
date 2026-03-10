# API Backlog — SDK, Tooling & Developer Experience

> **Scope**: Module API stability, developer SDK, documentation tooling, and testing framework.
>
> **Priority Legend**: 🔴 Critical (blocks third-party development) · 🟡 High (needed soon) · 🟢 Medium (improves quality) · ⚪ Low (nice to have)

---

## 1. API Stability & Versioning

### 1.1 🔴 ABI Versioning System

**Goal**: Guarantee binary compatibility between modules and the core platform across releases, so third-party modules don't break on platform upgrades.

**Current State**: `module_abi.h` defines `RS_ABI_VERSION 1`. The loader checks ABI version at load time but there is no formal compatibility policy, no deprecation mechanism, and no semantic versioning contract.

**Requirements**:
- Semantic ABI version: `MAJOR.MINOR` (major = breaking, minor = additive)
- Loader enforces: module ABI major must match platform major; module minor ≤ platform minor
- Deprecation annotations: `RS_DEPRECATED("Use rs_new_api() instead", removal_version=3)`
- Compile-time warnings when modules use deprecated APIs
- ABI changelog generated from header diff between releases
- `rswitchctl show-abi` — display current ABI version and supported range

**Key Structures to Version**:
| Structure | Current Fields | Stability |
|-----------|---------------|-----------|
| `struct rs_ctx` | 20+ fields (ifindex, action, layers, etc.) | Must be append-only after v1 stable |
| `struct rs_layers` | offsets, protocols, VLAN info | Must be append-only |
| `RS_DECLARE_MODULE()` | 5 params: name, hook, stage, flags, desc | Extend via RS_DECLARE_MODULE_V2() |
| Capability flags | `RS_FLAG_*` (6 defined) | New flags = minor bump |
| Error/drop codes | `RS_ERROR_*`, `RS_DROP_*` | New codes = minor bump |

**Affected Files**: `bpf/core/module_abi.h`, `bpf/include/rswitch_bpf.h`, loader verification logic

---

### 1.2 🟡 API Stability Tiers

**Goal**: Clearly communicate which APIs are stable, experimental, or internal.

**Requirements**:
- **Stable**: `RS_DECLARE_MODULE()`, `RS_GET_CTX()`, `RS_TAIL_CALL_NEXT()`, `RS_TAIL_CALL_EGRESS()`, `RS_EMIT_EVENT()`, all `RS_FLAG_*`, all `RS_ERROR_*` / `RS_DROP_*` codes, `rs_get_port_config()`, `rs_mac_lookup()`, `rs_mac_update()`, `rs_is_vlan_member()`, `rs_stats_update_rx()`, `rs_stats_update_drop()`
- **Experimental**: Per-module config API (1.3 in platform backlog), advanced egress manipulation
- **Internal**: Dispatcher internals, loader data structures, tail-call map layout
- Header annotations: `RS_API_STABLE`, `RS_API_EXPERIMENTAL`, `RS_API_INTERNAL`
- Documentation auto-generated from annotations

---

## 2. Module SDK

### 2.1 🔴 Module Development Kit

**Goal**: Provide everything a developer needs to create, build, test, and package an rSwitch module without cloning the full repository.

**Current State**: Module development requires the full rswitch source tree. No standalone SDK exists.

**SDK Contents**:
```
rswitch-sdk/
├── include/
│   ├── rswitch_bpf.h         # Module API headers
│   ├── module_abi.h           # ABI definitions
│   └── vmlinux.h              # Kernel types (CO-RE)
├── templates/
│   ├── simple_module.bpf.c    # Minimal module template
│   ├── stateful_module.bpf.c  # Module with private map state
│   └── egress_module.bpf.c    # Egress pipeline module template
├── Makefile.module             # Standalone build rules
├── test/
│   ├── test_harness.h         # Unit test framework
│   └── mock_maps.h            # Map mocking for offline tests
└── docs/
    └── SDK_Quick_Start.md
```

**Requirements**:
- `make install-sdk` target to generate and install SDK from main tree
- SDK version matches platform ABI version
- SDK includes pre-built `vmlinux.h` for common kernel versions
- Standalone compilation: `make -f Makefile.module MODULE=my_module`
- Minimal dependencies: clang, llvm, libbpf headers only

---

### 2.2 🟡 Module Scaffolding CLI

**Goal**: Generate boilerplate for new modules via CLI command.

**Requirements**:
- `rswitchctl new-module <name> --stage <N> --hook <ingress|egress> [--flags FLAG1,FLAG2]`
- Generate: `.bpf.c` source, Makefile entry, profile snippet, test stub
- Validate stage number not conflicting with existing modules
- Interactive mode: prompt for capabilities if flags not specified
- Output includes inline documentation explaining each section

**Example**:
```bash
$ rswitchctl new-module rate_limiter --stage 35 --hook ingress --flags NEED_L2L3_PARSE,MAY_DROP
Created:
  bpf/modules/rate_limiter.bpf.c     (module source)
  test/test_rate_limiter.c            (test stub)
  etc/profiles/rate_limiter.yaml      (example profile)
```

---

### 2.3 🟢 Module Packaging Format

**Goal**: Distribute compiled modules as standalone packages that can be installed without recompiling.

**Requirements**:
- Package format: `.rsmod` archive containing:
  - Compiled BPF object (`.o`)
  - Module metadata (name, version, ABI version, stage, flags, description)
  - Optional: profile snippet, documentation, license
- `rswitchctl install-module <package.rsmod>`
- `rswitchctl list-modules` — show installed modules (built-in + installed)
- Signature verification (GPG or similar) for module authenticity
- Dependency declaration: required platform ABI version, optional peer modules

---

## 3. Developer Tooling

### 3.1 🟡 Documentation Generator

**Goal**: Auto-generate API reference documentation from source code annotations.

**Current State**: API reference (`docs/development/API_Reference.md`) is manually maintained. Drift risk is high as API evolves.

**Requirements**:
- Parse `RS_DECLARE_MODULE()` calls → module registry table
- Parse `RS_FLAG_*`, `RS_ERROR_*`, `RS_DROP_*` defines → enum tables
- Parse helper function signatures → function reference
- Parse struct definitions (`rs_ctx`, `rs_layers`) → data structure docs
- Output: Markdown files compatible with current docs structure
- CI integration: warn if generated docs differ from committed docs

**Implementation**: Custom Python/C parser or Doxygen with BPF-aware filters

---

### 3.2 🟡 Developer CLI Enhancements

**Goal**: Streamline the develop-test-reload cycle.

**New Commands**:
| Command | Description |
|---------|-------------|
| `rswitchctl dev watch <module>` | Auto-rebuild and hot-reload on source change |
| `rswitchctl dev trace <module>` | Live event stream filtered to specific module |
| `rswitchctl dev inspect <module>` | Show loaded program info, map state, counters |
| `rswitchctl dev benchmark <profile>` | Run built-in performance test |
| `rswitchctl dev verify <module.o>` | Offline BPF verifier check |

**Requirements**:
- File watcher integration (inotify) for `dev watch`
- Ring buffer consumer for `dev trace` (read from `rs_event_bus`)
- BPF program info via `bpf_prog_get_info_by_fd()` for `dev inspect`

---

### 3.3 🟢 Interactive Module Debugger

**Goal**: Step-through debugging experience for BPF module development.

**Requirements**:
- Packet replay: feed saved pcap packets through a specific module
- Breakpoint simulation: dump `rs_ctx` state at configurable pipeline stages
- Map state snapshots: before/after comparison for any BPF map
- Integration with `bpftool` for program inspection
- Output: structured JSON trace of packet processing decisions

---

## 4. Testing Framework

### 4.1 🔴 Module Unit Testing

**Goal**: Developers can write and run unit tests for individual modules without loading into the kernel.

**Current State**: No unit test framework. Testing requires full deployment and live traffic.

**Requirements**:
- User-space BPF test runner using `BPF_PROG_RUN` (bpf_prog_test_run)
- Test harness API:
  ```c
  RS_TEST("acl blocks denied traffic") {
      struct rs_test_pkt pkt = rs_test_pkt_ipv4(
          .src = "192.168.1.100",
          .dst = "10.0.0.1",
          .proto = IPPROTO_TCP,
          .dport = 80
      );
      rs_test_map_insert(acl_map, &rule);
      int result = rs_test_run(acl_module, &pkt);
      RS_ASSERT_EQ(result, XDP_DROP);
      RS_ASSERT_EQ(pkt.rs_ctx.drop_reason, RS_DROP_ACL_BLOCK);
  }
  ```
- Map pre-population for test setup
- Context assertion helpers (check `rs_ctx` fields after processing)
- `make test-module MODULE=acl` target
- JUnit XML output for CI integration

---

### 4.2 🟡 Integration Test Framework

**Goal**: End-to-end testing of complete profiles with traffic generation.

**Requirements**:
- veth pair test topology setup/teardown scripts
- Traffic generators: crafted packets via `scapy` or raw sockets
- Validation: packet capture on egress, counter verification
- Profile test matrix: each of 18 profiles gets basic smoke test
- `make test-integration PROFILE=l3-acl-lab`

---

### 4.3 🟢 Fuzz Testing for BPF Modules

**Goal**: Find edge cases and verifier issues through automated input fuzzing.

**Requirements**:
- Fuzz packet headers (malformed Ethernet, IP, VLAN combinations)
- Fuzz `rs_ctx` initial state (unexpected field values)
- Fuzz map contents (corrupt/missing entries)
- Integration with `BPF_PROG_RUN` for safe kernel-side execution
- Crash/hang detection with timeout
- Corpus of known-good and known-bad packets

---

## Prioritized Roadmap

| Phase | Items | Rationale |
|-------|-------|-----------|
| **Phase 1** (Enable third-party dev) | 1.1 ABI Versioning, 2.1 Module SDK, 4.1 Unit Testing | Minimum viable developer experience |
| **Phase 2** (Accelerate development) | 2.2 Scaffolding CLI, 3.1 Doc Generator, 3.2 Dev CLI | Reduce friction in module development cycle |
| **Phase 3** (Quality & trust) | 1.2 Stability Tiers, 4.2 Integration Tests, 2.3 Packaging | Enable safe module distribution |
| **Phase 4** (Advanced tooling) | 3.3 Debugger, 4.3 Fuzz Testing | Deep debugging and edge-case coverage |

---

*Last updated: 2026-03-10*
*Related: [Module Developer Guide](../development/Module_Developer_Guide.md) · [API Reference](../development/API_Reference.md) · [Platform Backlog](platform-backlog.md)*
