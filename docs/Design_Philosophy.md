# Design Philosophy

This document summarizes the core design principles of the rSwitch production
implementation (source code under `rswitch/` and `rswitch/bpf/modules/`).

Key Principles
- Modularity: The pipeline is stage-based; modules are independent BPF programs
  attached to specific stages (see `bpf/modules/`).
- Profiles: Runtime behavior is controlled by YAML profiles in `rswitch/etc/profiles/`.
- CO-RE: BPF modules use CO-RE patterns for portability (`vmlinux.h`, libbpf).
- Safety: BPF verifier considerations (bounds checks, offset masks `&0x3F`) are
  implemented across modules.
- Performance: AF_XDP + VOQd for zero-copy paths and queue-based scheduling.
- Observability: Per-module pinned maps and `qos_stats_map` allow operator visibility.
- Graceful Management: Loader orchestrates module pin/unpin, tail-call chains, and
  ensures proper attach/detach order to avoid kernel watchdog issues.

Architecture Overview
- Data path: `dispatcher` → `egress` → tail-call modules → `egress_final`.
- User space: `rswitch_loader` loads modules mapped by YAML profiles and manages
  AF_XDP sockets (`rswitch/user/voqd/`) and tools.

Verification and Validation
- Unit tests for the AF_XDP socket lifecycle and per-module behavior in `rswitch/test/`.
- Use `rswitch/scripts/rswitch_start.sh` and `rswitch/scripts/voqd_check.sh` to
  validate startup and runtime behavior.

Where the code is definitive
- For any behavior, configuration or operational question, consult the C source
  under `rswitch/` (loader, user, voqd) and `rswitch/bpf/modules/` for module
  specifics. YAML and shell scripts in `rswitch/` are used for examples and
  conveniences but can be inconsistent; when in doubt, prefer C source.
