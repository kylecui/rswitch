
# XDP ACL Minimal Demo (IPv4, 5-tuple + LPM)

This is a minimal, production-friendly starting point for an XDP-based ACL datapath.

## Features
- Exact 5-tuple (IPv4) hash match (highest priority)
- LPM (IPv4) match for src/dst prefixes (medium priority)
- Actions: PASS, DROP, REDIRECT (to ifindex or AF_XDP via XSKMAP)
- Per-CPU stats
- VLAN header parsing (single/double) minimal
- Simple loader (no skeleton), and a `bpftool` helper script

## Build
Requirements: `clang`, `llvm-strip`, `libbpf-dev`, `bpftool`.

```bash
make
```

Artifacts:
- `build/bpf/acl_core.bpf.o`
- `build/user/xdp-acl-loader`

## Run
Attach to interface and insert demo rules:
```bash
sudo build/user/xdp-acl-loader eth0 build/bpf/acl_core.bpf.o demo
```

Or use the script:
```bash
sudo ./scripts/aclctl.sh load eth0
sudo ./scripts/aclctl.sh add-5t TCP 10.1.2.3 443 0.0.0.0 0 DROP
sudo ./scripts/aclctl.sh add-lpm-src 192.168.1.0/24 PASS
sudo ./scripts/aclctl.sh stats
```

### AF_XDP redirect
If an ACL uses `REDIRECT` with `ifindex=0`, the program will try `bpf_redirect_map(xsks_map, rx_queue_index, 0)`.
Attach an XSK socket per-queue from user space to enable this path.

## Notes
- MIRROR/RATE_LIMIT are placeholders in this minimal demo; MIRROR can be integrated with a separate module or via perf/ringbuf sampling.
- IPv6 + extension headers template and port-range compilation tips are provided in the main ChatGPT message.
