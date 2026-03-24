> **⚠️ ARCHIVED** — This document is historical reference only. It may not reflect current implementation. See [current documentation](../README.md) for up-to-date information.

# Quick Start (Release-ready)

This quick-start guide uses the production `rswitch/` code in this repository.
All commands assume you are in the repository root and have the required build
tools and libraries installed (libbpf, libxdp). The loader and modules are
found in `rswitch/` and `rswitch/bpf/modules/`.

Prerequisites
- sudo/root access
- libbpf & libxdp installed (system or external/libbpf)
- Kernel headers

Build
```
make vmlinux
make
```

Select a profile and interfaces
```
# Example profile path
PROFILE=etc/profiles/l2.yaml
INTERFACES=ens34,ens35,ens36
```

Run
```
sudo ./build/rswitch_loader --profile "$PROFILE" --ifaces $INTERFACES
```
If you see `No such file` when reading maps, wait 3-5s or use `rswitch/scripts/rswitch_start.sh` to wait for maps and VOQd.

Verification
```
sudo bpftool prog list | grep rswitch
sudo bpftool map show | grep rswitch
ps -ef | grep rswitch-voqd
```

Basic troubleshooting
- Check pinned maps: `ls /sys/fs/bpf | grep rswitch`
- Check logs: `tail -f /var/log/rswitch.log` (if loader started with logging)
- Use `rswitch/scripts/voqd_check.sh` to validate VOQd

Cleanup
```
sudo ./build/rswitch_loader --detach --profile "$PROFILE" # simplified
# if maps are persisted, remove with unpin scripts or rm -rf /sys/fs/bpf/rswitch_*
```

Notes
- Profiles are mapped to YAML files inside `rswitch/etc/profiles/`.
- Use `--debug` and `--xdp-mode` flags when needed (see `rswitch/user/loader/rswitch_loader.c` for options).
