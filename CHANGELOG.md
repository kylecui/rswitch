# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- CHANGELOG.md following Keep a Changelog format
- Reserved byte allocation registry in ABI policy documentation
- Downstream service ordering guide in Systemd Integration docs
- Shared map discovery table in MAP_PINNING.md
- SDK Migration Guide (`sdk/docs/SDK_Migration_Guide.md`) with header mapping table and step-by-step migration
- `sdk/scripts/generate_vmlinux.sh` helper script for vmlinux.h generation
- Deprecation warnings (`#warning`) on all legacy headers: `uapi.h`, `map_defs.h`, `rswitch_bpf.h`, `module_abi.h`
- Hot-Reload architecture documentation (`docs/development/Hot_Reload.md`)
- Per-module config workaround guide in SDK Quick Start (BPF map, EnvironmentFile, config file patterns)
- ABI v1→v2 migration guide (`docs/development/ABI_Migration_v1_to_v2.md`) with step-by-step checklist and common pitfalls
- Multi-kernel compile matrix in CI (`kernel-compat` job) — validates CO-RE BTF compatibility against 6.2, 6.5, and 6.8 kernel headers
- Performance baseline CI job (`perf-baseline`) — measures per-packet latency via `BPF_PROG_TEST_RUN` with regression detection
- `test/ci/test_perf_baseline.c` — BPF performance test using repeat-mode packet injection
- Performance testing documentation (`docs/development/Performance_Testing.md`)
- Chinese (zh-CN) translations: VOQd Setup, NIC Configuration, API Reference, MAP Pinning, Graceful Degradation, Performance Testing

### Changed
- MAP_PINNING.md: clarified convention — core maps use flat `/sys/fs/bpf/` with `rs_` prefix, user modules use `/sys/fs/bpf/<project>/` subdirectories
- `module_abi.h` (sdk + bpf/core): reduced from 202-line duplicate to 18-line thin wrapper re-exporting `rswitch_abi.h`
- SDK Quick Start: added `generate_vmlinux.sh` usage and link to Migration Guide
- README.md: hot-reload status updated from "Planned" to "✅ Implemented"
- README.md: per-module config marked as "Planned (v2.1)" with version target

### Fixed
- MAP_PINNING.md contradiction with `rswitch_helpers.h` regarding subdirectory pin paths

---

## [2.0.1] - 2026-03-28

### Fixed
- **mgmtd**: mDNS multicast join now retries indefinitely with exponential backoff instead of silently failing after one attempt

---

## [2.0.0] - 2026-03-24

### Added
- **ABI v2.0**: Expanded `rs_ctx.reserved` from 16 bytes (`[4]`) to 64 bytes (`[16]`) for future minor-version fields
- **ABI v2.0**: User ingress stage range 200-299, user egress stage range 400-499
- **ABI v2.0**: User event type range `0x1000-0x7FFF` for downstream modules
- **ABI v2.0**: `RS_FLAG_MAY_REDIRECT` capability flag (bit 6)
- **ABI v2.0**: Module dependency declaration macros (`RS_DEPENDS_ON`)
- **SDK**: Standalone module development kit with `rswitch_module.h` unified entry point
- **SDK**: Installable package via `make install-sdk` with pkg-config integration
- **SDK**: `SDK_Quick_Start.md` tutorial (820 lines) and `Module_Development_Spec.md`
- **SDK**: `Makefile.module` for out-of-tree module builds
- **CI**: BPF test harnesses (`test_harness.h`), GitHub Actions pipeline, clang-format
- **Docs**: ABI Stability Policy with versioning contract, stability tiers, deprecation rules
- **Docs**: Graceful Degradation protocol for partial pipeline availability
- **Docs**: Contributing guide with PR process and coding standards
- **Docs**: Bilingual documentation — 13 Chinese (zh-CN) translations
- **Docs**: Platform Architecture comprehensive design document
- **Docs**: Concept documents (Reconfigurable Architecture, Network Device Gallery, Framework Guide)
- **Legal**: LGPL-2.1-or-later LICENSE file
- **Legal**: SPDX-License-Identifier headers on all source files

### Changed
- **ABI**: Major version bumped from 1.0 to 2.0 (breaking: struct layout change)
- **Headers**: Refactored into consolidated SDK headers (`rswitch_abi.h`, `rswitch_helpers.h`, `rswitch_maps.h`, `rswitch_module.h`)
- **README**: Updated with accurate feature status table and known limitations
- **Archive**: Historical documents marked with ARCHIVED notice headers

### Fixed
- **BPF test**: Include `action`/`ifindex` in per-CPU context scan for `BPF_PROG_TEST_RUN`
- **AF_XDP**: Use `rx_queue_index` instead of hardcoded `queue_id=0` for XSKMAP lookup
- **AF_XDP**: Standardize XSKMAP pin path to `/sys/fs/bpf/rswitch/xsks_map`
- **AF_XDP**: Add `sendto()` TX wakeup when kernel `needs_wakeup` flag is set
- **AF_XDP**: Decouple AF_XDP redirect from ringbuf availability in ACTIVE mode
- **AF_XDP**: Replace linear frame allocator with stack-based pool to prevent TX frame exhaustion

### Removed
- Stale `.bak` files; added `*.bak` to `.gitignore`

---

## [1.0.0] - 2026-01-15

### Added
- **Management Portal**: Full web management UI with namespace isolation, DHCP-based IP acquisition, REST API, real-time WebSocket monitoring
- **Management Portal**: Session-cookie authentication with rate limiting
- **Management Portal**: Profile management page, VLAN port dropdowns, real port names
- **Management Portal**: SQLite event persistence with REST query API and live event streaming
- **Management Portal**: Network configuration page for management interface
- **QoS**: Traffic classification and priority extraction for IP packets
- **QoS**: AF_XDP socket management integrated with VOQd data plane
- **QoS**: Software queue simulation for NICs without hardware queues
- **QoS**: CLI tools (`rsqosctl`, `rsvoqctl`) for QoS monitoring and control
- **DHCP**: DHCP snooping with trusted port enforcement
- **ACL**: Real user-defined priority for ACL rules
- **Systemd**: Service units for rswitch, failsafe, mgmtd, and watchdog
- **Systemd**: Fail-safe L2 bridge script for fallback connectivity
- **Installer**: One-line install/uninstall scripts with port auto-detection and CLI interface selection
- **Profiles**: Reorganized profiles; removed hardcoded interface references
- **Testing**: Unit tests for ARP learn, L2 learn, route, mirror, STP, rate limiter, source guard, conntrack
- **Docs**: Management portal deployment guide, bilingual concept docs, QoS testing guide

### Changed
- **Loader**: Resolve BPF object paths from `RSWITCH_HOME` environment variable
- **Loader**: Separate egress `prog_array` to fix kernel 6.8.0 `owner_prog_type` enforcement
- **BPF**: Widen `RS_MAX_INTERFACES` to 256
- **BPF**: Align ingress and egress modules with module development specification
- **Egress**: Descending slot allocation in `prog_array` for egress pipeline
- **Service**: Updated service units and Makefile for production install path

### Fixed
- **AF_XDP**: Multiple fixes for XSKMAP lookup, TX wakeup, frame allocation, redirect decoupling
- **Egress VLAN**: BPF verifier rejection and `l3_offset`/`l4_offset` updates on tag push/pop
- **Installer**: Create log directory before logging helpers are called
- **mgmtd**: Profile switch now updates dashboard and modules correctly
- **mgmtd**: Validate `web_root` path and fallback to default if invalid
- **mgmtd**: Sync port VLAN config to BPF data plane on VLAN changes
- **Portal**: WebSocket auth pre-check to prevent reconnect loop on expired sessions
- **Init**: Flush switch port IPs before bringing interface UP

---

## [0.9] - 2025-11-17

### Added
- Initial XDP pipeline with ingress/egress dual-pipeline architecture
- BPF modules: dispatcher, VLAN, ACL, route, L2 learn, last-call, mirror, egress modules
- VOQd user-space QoS scheduler (BYPASS/SHADOW/ACTIVE modes)
- AF_XDP integration for high-throughput forwarding
- YAML profile-based configuration system
- Startup, diagnostic, and health-check scripts

### Fixed
- IP checksum validation and incremental updates for DSCP/ECN changes
- BPF verifier compatibility improvements across multiple modules
- Map pinning for `qos_stats_map`
- VOQd startup race condition detection

---

[unreleased]: https://github.com/kylecui/rswitch/compare/v2.0.1...HEAD
[2.0.1]: https://github.com/kylecui/rswitch/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/kylecui/rswitch/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/kylecui/rswitch/compare/v0.9...v1.0.0
[0.9]: https://github.com/kylecui/rswitch/releases/tag/v0.9
