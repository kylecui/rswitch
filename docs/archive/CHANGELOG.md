# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased] - 2025-11-17
### Added
- `rswitch_start.sh`, `rswitch_diag.sh`, `voqd_check.sh` startup/diagnostic/health scripts to handle DOCKER/VM/boot race conditions and to verify VOQd/loader status.
- `egress_final` module: IP checksum verification and auto-fix logic; per-module final stats map for checksum validation.
- New docs: Development Log Summary, Module Status Report, Troubleshooting & Fixes Summary, Outstanding Tasks and Recommendations.

- **Docs**: Added "Recent Implementation Fixes" summary sections across key docs (`Migration_Guide.md`, `Troubleshooting_and_Fixes_Summary.md`, `Module_Status_Report.md`, `Development_Log_Summary.md`) to collate engineering fixes and verification steps for maintainers and deployers.

### Changed
- `rswitch_loader`: Faster signal handling (100ms loop), improved cleanup sequence (flush TX → detach XDP → close maps), startup delay for maps, and robust map unpin logic under review.
- `egress_qos.bpf.c`: Added `pinning` for `qos_stats_map`, corrected DSCP/ECN rewrite checksum handling via RFC1624 incremental update, DSCP remarking behavior.
- `egress_final.bpf.c`: BPF verifier-friendly checksum calculation (unrolled/conditionally verified), verified and fixed boundary checks across IP options, added per-CPU final stats map.
- `egress_vlan.bpf.c`: Update `rs_ctx->layers.l3_offset` and `l4_offset` on VLAN tag push/pop to maintain correct offsets for downstream IP parsing.
- AF_XDP/xsk manager: Protect against type confusion by avoiding reading nonexistent libxdp fields; previously-undefined memory accesses in `xsk_manager_get_stats` fixed; now returning accurate counts or using libxdp APIs correctly.
- CLI and scripts: Fixed `rsqosctl` argument usage (`stats` instead of `--stats`) and added robust startup sequences and wait timeouts to avoid `No such file` errors for BPF maps.
- BPF Verifier: Improved offset masking and explicit bounds checking in multiple modules (e.g., `egress_final`) to help verifier proofing (applied `& 0x3F` for L3 offsets, and safer access patterns).

### Fixed
- QoS initialization: `qos_config_ext_map` properly initialized in loader, enabling QoS by default when configured.
- DHCP priority: Documented DHCP denormalization (UDP 67/68 default HIGH) and added runtime CLI steps to normalise when needed.
- IP checksum issues: Corrected incremental checksum calculation for DSCP rewrite and ECN marking; added final checksum verification and auto-correction to prevent invalid outgoing packets.
- VOQd/Early exit false positive: Fixed startup race detection that previously reported VOQd process prematurely as exited.
- AF_XDP stats corruption: Fixed unexpected large packet count values due to incorrect struct access; now safe and consistent stats collection.
- BPF verifier errors: Eliminated common verifier fails by constraining offsets and unrolling loops and ensuring packet bounds before any access.
- Map pinning: Fixed missing pinning for `qos_stats_map` and added additional map verification steps in loader/startup scripts.

### Security / Stability
- Replaced several unsafe internal struct casts with libxdp-safe APIs, reducing potential for memory corruption and incorrect reads of kernel/UMEM structures.
- Added various guard checks for IP header length and options, plus packet data length checks to avoid OOB access.

### Documentation
- Expanded and consolidated docs: `README.md` updated with quick start, and added numerous docs for debugging, BPF verifier tips, VOQd integration, QoS classification, shutdown fixes, and startup sequencing.

### Removed
- None (no breaking removals in this release summary).

## Known Issues / Follow-ups
- AF_XDP + `zero_copy` and performance validation still need thorough testing on real NICs (e.g., Intel X710, Mellanox CX-5); some performance-related behaviors were tuned for generic environments and may need reprofiling.
- Map cleanup: there are some maps that persist after loader quits in certain configurations—`unpin_maps()` rules and map naming conventions need to be audited thoroughly. See `docs/Troubleshooting_and_Fixes_Summary.md` for details.
- Verifier edge cases: while we improved verifier-friendly code, more rigor needed for complex options parsing and non-standard header forms (e.g., heavy IP options, jumbo frames).

## How to update this Changelog
- Add new entries under `Unreleased` with a short description.
- When cutting a release, move entries into a new dated section and increment version.

---
*Generated: 2025-11-17*