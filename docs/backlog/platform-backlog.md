# Platform Backlog — Core Infrastructure

> **Scope**: Core platform capabilities, configuration system, loader, and infrastructure improvements.
>
> **Priority Legend**: 🔴 Critical (blocks product development) · 🟡 High (needed soon) · 🟢 Medium (improves quality) · ⚪ Low (nice to have)

---

## 1. Profile System Enhancements

### 1.1 🔴 Advanced YAML Stage Overrides

**Goal**: Allow profiles to override default stage numbers for modules, enabling fine-grained pipeline customization without recompiling BPF programs.

**Current State**: Modules declare their stage via `RS_DECLARE_MODULE()` at compile time (e.g., vlan=20, acl=30, route=50). Profiles list module names in `ingress:` / `egress:` arrays but cannot override stage ordering.

**Requirements**:
- Support `stage:` field per module entry in profile YAML
- Validate stage ranges: ingress 10–99, egress 100–199
- Detect and reject stage conflicts at load time
- Preserve backward compatibility with simple module-name arrays

**Example**:
```yaml
ingress:
  - name: vlan
    stage: 15          # Override default stage 20
  - name: acl
    stage: 25          # Override default stage 30
  - name: custom_module
    stage: 45          # New module at custom position
```

**Affected Components**: `user/loader/profile_parser.c`, `user/loader/module_loader.c`

---

### 1.2 🟡 Optional Modules with Conditions

**Goal**: Support conditionally loaded modules that activate based on runtime flags or profile settings.

**Current State**: All modules listed in a profile's `ingress:` / `egress:` arrays are loaded unconditionally.

**Requirements**:
- Add `optional: true` and `condition:` fields to module entries
- Support conditions: `debug_mode`, `stats_enabled`, custom boolean settings
- Gracefully skip optional modules whose conditions are unmet
- Log which optional modules were loaded/skipped

**Example**:
```yaml
ingress:
  - name: mirror
    optional: true
    condition: debug_mode
  - name: acl
```

---

### 1.3 🟡 Module-Specific Configuration Parameters

**Goal**: Pass per-module configuration from YAML profiles into BPF map entries, allowing runtime module tuning.

**Current State**: Modules share global `settings:` values. No mechanism exists for per-module config injection.

**Requirements**:
- Define a `config:` section per module in YAML
- Loader writes config entries to a dedicated `rs_module_config_map` BPF map
- Modules read their config at runtime via a helper `rs_get_module_config()`
- Support integer, boolean, and string config values

**Example**:
```yaml
ingress:
  - name: acl
    config:
      max_rules: 1000
      default_action: drop
      log_denied: true
```

**Affected Components**: New BPF map definition, loader config writer, module config reader helper

---

### 1.4 🟢 Profile Inheritance and Templates

**Goal**: Reduce profile duplication by supporting inheritance — a profile can extend a base profile and override specific sections.

**Current State**: Each profile is fully self-contained. Common configurations (port layouts, settings) are duplicated across many of the 18 existing profiles.

**Requirements**:
- Add `extends:` field referencing a base profile filename
- Deep-merge: child sections override parent sections at the key level
- Support multi-level inheritance (max depth 3)
- Clear error messages for circular references
- `rswitchctl show-profile --resolved` to dump the merged result

**Example**:
```yaml
extends: l3.yaml
name: "L3 with QoS"

# Only override what differs
egress:
  - egress_qos
  - egress_vlan
  - egress_final

voqd_config:
  enabled: true
  mode: active
```

---

## 2. Loader Improvements

### 2.1 🔴 Robust Hot-Reload

**Goal**: Production-grade hot-reload with atomic module replacement and rollback on failure.

**Current State**: `scripts/hot-reload.sh` provides basic reload. No atomicity guarantees, no rollback.

**Requirements**:
- Atomic swap of BPF program in tail-call map (single map update)
- Pre-verify new module before swapping (load + verify, then swap)
- Automatic rollback if new module fails verification
- Zero-packet-loss during swap (tail-call map guarantees this)
- CLI command: `rswitchctl reload <module_name> [--dry-run]`
- Event emission for reload success/failure

**Affected Components**: `user/loader/module_loader.c`, `user/tools/rswitchctl.c`

---

### 2.2 🟡 Module Dependency Resolution

**Goal**: Automatically validate and resolve inter-module dependencies at load time.

**Current State**: Module ordering is implicit — profiles must list modules in correct order manually.

**Requirements**:
- Modules declare dependencies via ELF metadata (e.g., `RS_DEPENDS_ON("vlan")`)
- Loader performs topological sort to validate ordering
- Error on missing dependencies with clear messages
- Warning on unnecessary modules (loaded but never reached in pipeline)

---

### 2.3 🟢 Profile Validation CLI

**Goal**: Validate profiles offline without loading any BPF programs.

**Requirements**:
- `rswitchctl validate-profile <profile.yaml>` — parse, check stage conflicts, verify module existence, validate port configs
- Machine-readable output (JSON) for CI integration
- Warning for deprecated settings
- Suggest fixes for common errors

---

## 3. Performance & Observability

### 3.1 🔴 Performance Benchmarking Framework

**Goal**: Quantitative performance measurement on real hardware for informed optimization.

**Current State**: No automated benchmarking. Performance claims are based on XDP inherent speed, not measured rSwitch throughput.

**Requirements**:
- Benchmark harness using `pktgen` or T-Rex traffic generator
- Metrics: packets/sec, latency (p50/p99), CPU utilization per core
- Test matrix: profiles × NIC types × packet sizes (64B, 512B, 1518B)
- Automated regression detection: alert if throughput drops > 5%
- Results stored as JSON for historical comparison
- Initial target: 10 Mpps on Intel X710 with L2 profile

**Deliverables**: `test/benchmark/` directory with scripts and result templates

---

### 3.2 🟡 Enhanced Statistics and Telemetry

**Goal**: Per-module, per-port, per-VLAN statistics with export capabilities.

**Current State**: `rs_stats_map` provides basic RX/TX/drop counters per interface. No per-module or per-VLAN breakdown.

**Requirements**:
- Per-module counters: packets processed, forwarded, dropped, errors
- Per-VLAN counters: ingress/egress packet and byte counts
- Histogram support: packet size distribution, processing latency
- Export formats: Prometheus metrics endpoint, JSON dump
- `rswitchctl show-stats --module acl --format json`

---

### 3.3 🟢 Structured Logging

**Goal**: Replace `printf`-based logging with structured, leveled logging.

**Requirements**:
- Log levels: ERROR, WARN, INFO, DEBUG, TRACE
- Structured fields: timestamp, module, component, message, key-value pairs
- Output targets: stdout, file, syslog
- Runtime log level changes via `rswitchctl set-log-level <level>`
- BPF-side: map-based debug flag already exists (`settings.debug`) — extend to per-module

---

## 4. Build & CI

### 4.1 🟡 CI Pipeline

**Goal**: Automated build, test, and validation on every commit.

**Requirements**:
- GitHub Actions workflow for:
  - Build matrix: clang 14/15/16, kernel headers 5.8/5.15/6.1
  - BPF verifier check (load all modules, verify all profiles)
  - Unit tests for loader and CLI tools
  - Profile validation for all 18 profiles
- Badge on README for build status

---

### 4.2 🟢 Cross-Kernel Testing

**Goal**: Validate CO-RE portability claims across kernel versions.

**Requirements**:
- QEMU/VM-based test runner with multiple kernel images
- Test kernels: 5.8, 5.15 (LTS), 6.1 (LTS), 6.6 (LTS), latest
- Automated: load all profiles, verify maps created, basic packet forwarding
- Report: per-kernel pass/fail matrix

---

## Prioritized Roadmap

| Phase | Items | Rationale |
|-------|-------|-----------|
| **Phase 1** (Pre-product) | 1.1 Stage Overrides, 2.1 Hot-Reload, 3.1 Benchmarking | Unblock product-specific pipeline customization and ensure performance baseline |
| **Phase 2** (Product development) | 1.2 Optional Modules, 1.3 Module Config, 2.2 Dependencies | Enable product to configure modules per deployment |
| **Phase 3** (Production readiness) | 3.2 Telemetry, 4.1 CI, 3.3 Logging | Operational visibility and quality gates |
| **Phase 4** (Platform maturity) | 1.4 Profile Inheritance, 2.3 Validation CLI, 4.2 Cross-Kernel | Reduce profile sprawl, improve developer experience |

---

*Last updated: 2026-03-10*
*Related: [Architecture](../development/Architecture.md) · [Configuration](../deployment/Configuration.md) · [API Backlog](api-backlog.md)*
