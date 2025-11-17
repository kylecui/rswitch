# Module Developer Guide

This guide shows how to author a BPF module, compile, test and include it into
a runtime profile. It is aligned to the `rswitch/bpf/modules` and loader
(`rswitch/user/loader/rswitch_loader.c`) implementation.

Authoring a module
1. Create `rswitch/bpf/modules/my_module.bpf.c` and use the module ABI headers:
```
#include "core/module_abi.h"
#include "core/uapi.h"

RS_DECLARE_MODULE("mymodule", RS_HOOK_XDP_EGRESS, 35, RS_FLAG_NEED_L2L3_PARSE);

SEC("xdp")
int mymodule_egress(struct xdp_md *ctx) {
  // safe header parsing and bounds checks
  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
```

2) Module rules
- Use a fixed stage (0-255) that fits pipeline ordering (see `README` sections)
- Use `RS_FLAG_*` flags for parse requirements and compiled behavior
- Avoid verifier-unfriendly runtime loops or unchecked array accesses; prefer
  fixed expansion or guarded reads (example: `offset & 0x3F` bounds masking).

Compilation
```
make
```
`make` builds the `bpf/modules` and is used by the loader to load compiled BPF objects.

Profile integration
1. Edit a profile file in `rswitch/etc/profiles/custom.yaml` and add your module name to
the respective stage list (ingress/egress).
2. Start loader with that profile:
```
sudo ./build/rswitch_loader --profile etc/profiles/custom.yaml --ifaces ens34,ens35
```

Testing & Debugging
- Use `RS_DEBUG_LEVEL` in module source to add debug prints (via `bpf_printk`).
- Use `bpftool prog dump` and `bpftool map` to inspect loaded maps and programs.
- Use the `--debug` loader flag to increase log output and `voqd` health checks.

Verifier considerations
- Always check `data_end` and packet bounds before accessing data.
- Avoid reading memory beyond `ctx->data_end`, and use consistent offset masking.
- Keep arrays small and loops bounded; when needed, unroll loops for verifier.

Useful paths
- Module source: `rswitch/bpf/modules/`
- Loader: `rswitch/user/loader/rswitch_loader.c`
- YAML profiles: `rswitch/etc/profiles/`
- Tests: `rswitch/test/`
