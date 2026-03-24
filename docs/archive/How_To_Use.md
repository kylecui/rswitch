> **⚠️ ARCHIVED** — This document is historical reference only. It may not reflect current implementation. See [current documentation](../README.md) for up-to-date information.

# How To Use rSwitch (Production)

This document demonstrates typical usage patterns and commands derived from the
actual `rswitch` code and user tools under `rswitch/`.

1) Build
```
make vmlinux    # CO-RE
make
```

2) Choose a profile
```
ls etc/profiles/    # list available profiles
PROFILE=etc/profiles/l3-qos-voqd-test.yaml
```

3) Configure NIC queues (optional)
```
# scripts/setup_nic_queues.sh exists to set IRQ affinity and isolation
sudo rswitch/scripts/setup_nic_queues.sh ens34 2
```

4) Start
```
sudo ./build/rswitch_loader --profile "$PROFILE" --ifaces ens34,ens35
```

5) Validate
```
sudo bpftool prog list | grep rswitch
sudo bpftool map show | grep rswitch
ps -ef | grep rswitch-voqd
sudo ./build/rsqosctl stats
```

6) Modify and hot-reload a module (development)
```
# Edit bpf/modules/my_module.bpf.c
make
sudo scripts/hot-reload.sh reload my_module
```

7) Shutdown and cleanup
```
sudo pkill rswitch_loader || true
# Remove pinned maps when loader terminates
sudo ./scripts/unpin_maps.sh || true
```

Notes on flags
- `--debug`: increases loader log verbosity
- `--xdp-mode`: `native` or `generic` switch; `rswitch_loader` documents available flags

Verification scripts
- `rswitch/scripts/rswitch_diag.sh` - quick diagnostics
- `rswitch/scripts/voqd_check.sh` - VOQd readiness
