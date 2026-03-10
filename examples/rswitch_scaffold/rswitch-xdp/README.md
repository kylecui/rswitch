# rswitch-xdp

Minimal, production-grade **libbpf + CO-RE** scaffolding for a reconfigurable switch dataplane.
It provides:
- XDP program: per-port, per-priority **logical VOQ** metadata export (ringbuf) + **devmap** fast-path.
- Userland loader: libbpf-based loader to attach, configure maps (devmap, qos_map), and pin them under `/sys/fs/bpf/rswitch`.
- Helper scripts to generate `vmlinux.h` (via `bpftool`), load/unload, and set devmap ports.

> Tested kernels: 5.10+ (BTF + CO-RE). Requires `clang`, `llvm`, `libbpf-dev`, and `bpftool` on the build host.

## Tree

```
rswitch-xdp/
  ├─ src/
  │   ├─ xdp_voq_kern.c      # XDP program
  │   └─ xdp_voq_user.c      # libbpf loader
  ├─ include/
  │   ├─ rswitch_common.h
  │   └─ vmlinux.h           # generated (see scripts/generate_vmlinux.sh)
  ├─ etc/
  │   └─ qos.json            # DSCP->prio map and default egress port
  ├─ scripts/
  │   ├─ generate_vmlinux.sh
  │   ├─ load.sh
  │   └─ unload.sh
  ├─ Makefile
  └─ README.md
```

## Quick start

1) Generate `include/vmlinux.h` once (requires `bpftool` and kernel BTF available):

```bash
sudo ./scripts/generate_vmlinux.sh
```

2) Build:

```bash
make
```

3) Load on interface (replace `eth0` and adjust devmap port index if needed):

```bash
sudo ./scripts/load.sh eth0 1
```

4) Unload:

```bash
sudo ./scripts/unload.sh eth0
```

## Notes

- The loader will create and pin maps under `/sys/fs/bpf/rswitch`. You can inspect with `bpftool`.
- `etc/qos.json` controls DSCP->prio mapping and default egress port; edit and re-run `load.sh`.
- `devmap` is configured with a single port index from the CLI in `load.sh` for demo. Extend as needed.
