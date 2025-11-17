# rSwitch - Reconfigurable Switch (Production)

Overview
--------
rSwitch is a production-grade, modular XDP switch. The authoritative
implementation is under `rswitch/`:
- `rswitch/user/` — loader, VOQd, and tools
- `rswitch/bpf/modules/` — per-module BPF programs (CO-RE)
- `rswitch/etc/profiles/` — YAML profiles composing runtime pipelines

Quick links
- `rswitch/docs/Quick_Start.md`
- `rswitch/docs/How_To_Use.md`
- `rswitch/docs/Design_Philosophy.md`
- `rswitch/docs/Module_Developer_Guide.md`

Prerequisites (Debian/Ubuntu example)
```bash
sudo apt update
sudo apt install -y build-essential cmake clang llvm pkg-config make libxdp-dev libbpf-dev linux-headers-$(uname -r)
```

Build & run (quick example)
```bash
make vmlinux && make
PROFILE=etc/profiles/l2.yaml
IFACES=ens34,ens35,ens36
sudo ./build/rswitch_loader --profile "$PROFILE" --ifaces $IFACES
```

Verify
```bash
sudo bpftool prog list | grep rswitch
sudo bpftool map show | grep rswitch
ps aux | grep rswitch-voqd
```

Developer notes
- Author BPF modules in `rswitch/bpf/modules/` following the module ABI.
- Rebuild with `make` and use `scripts/hot-reload.sh` to iterate.
- Be verifier friendly: use `data_end` checks, offset masks (e.g., `& 0x3F`), and avoid unbounded loops.

Diagnostics & cleanup
- `rswitch/scripts/rswitch_start.sh` — boot helper waiting for maps/VOQd.
- `rswitch/scripts/voqd_check.sh` — VOQd health & CPU affinity checks.
- `rswitch/scripts/unpin_maps.sh` — remove pinned maps after shutdown (if present).

Notes
- When docs or PoC scripts conflict with the `rswitch/` C sources, the C sources are authoritative.

License
SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
