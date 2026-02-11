# BPF Map Sharing Fix - Troubleshooting Documentation

**Date**: February 11, 2026  
**Issue**: XDP tail-call pipeline breaks after ACL module  
**Status**: ✅ RESOLVED

---

## Problem Statement

When running rSwitch with the `all-modules-test.yaml` profile, packets were processed through `dispatcher → vlan → arp_learn → acl` but then **stopped**. The subsequent modules (mirror, route, l2learn, afxdp_redirect, lastcall) never executed.

### Expected Pipeline Flow
```
dispatcher → vlan → arp_learn → acl → mirror → route → l2learn → afxdp_redirect → lastcall
```

### Observed Behavior
```
dispatcher → vlan → arp_learn → acl → [STOP]
```

---

## Root Cause Analysis

### Investigation Method

1. **trace_pipe analysis**: Confirmed packets stopped after ACL
   ```bash
   sudo cat /sys/kernel/debug/tracing/trace_pipe
   ```

2. **bpftool map inspection**: Revealed different map IDs between modules
   ```bash
   sudo bpftool prog show | grep -E 'mirror|dispatcher' -A3
   sudo bpftool map show pinned /sys/fs/bpf/rs_ctx_map
   sudo bpftool map show pinned /sys/fs/bpf/rs_progs
   ```

### Root Cause

**XDP modules were NOT sharing the same BPF maps as the dispatcher.**

When libbpf loads each module's `.bpf.o` file, it creates NEW instances of maps defined in the object file, even if those maps have `LIBBPF_PIN_BY_NAME`. The dispatcher's `rs_ctx_map` (ID 1055) and `rs_progs` (ID 1056) were different from mirror's maps (IDs 1082-1088).

This meant:
- The dispatcher's `rs_progs` prog_array contained the module FDs
- But mirror's BPF code referenced a DIFFERENT `rs_progs` that was empty
- Tail-calls from ACL to mirror failed silently (returned XDP_DROP)

---

## Solution

### Fix 1: Implement `reuse_shared_maps()` in Loader

Added a function to reuse pinned map FDs before loading each module.

**File**: `rswitch/user/loader/rswitch_loader.c`

```c
static int reuse_shared_maps(struct bpf_object *obj, struct loader_ctx *ctx)
{
    struct bpf_map *map;
    int err;
    const char *names_to_reuse[] = {
        "rs_ctx_map", "rs_progs", "rs_prog_chain", "rs_port_config_map",
        "rs_ifindex_to_port_map", "rs_stats_map", "rs_event_bus", 
        "rs_vlan_map", "rs_devmap", "rs_xdp_devmap"
    };
    int fds_to_reuse[] = {
        ctx->rs_ctx_map_fd, ctx->rs_progs_fd, ctx->rs_prog_chain_fd, 
        ctx->rs_port_config_map_fd, ctx->rs_ifindex_to_port_map_fd, 
        ctx->rs_stats_map_fd, ctx->rs_event_bus_fd, ctx->rs_vlan_map_fd, 
        ctx->rs_devmap_fd, ctx->rs_devmap_fd
    };
    int num_maps = sizeof(names_to_reuse) / sizeof(names_to_reuse[0]);
    
    for (int i = 0; i < num_maps; i++) {
        if (fds_to_reuse[i] <= 0)  // NOTE: <= 0, not < 0
            continue;
            
        map = bpf_object__find_map_by_name(obj, names_to_reuse[i]);
        if (!map)
            continue;
        
        err = bpf_map__reuse_fd(map, fds_to_reuse[i]);
        if (err) {
            fprintf(stderr, "  reuse_fd failed for %s (fd=%d): %s\n",
                    names_to_reuse[i], fds_to_reuse[i], strerror(-err));
            continue;
        }
        
        fprintf(stderr, "  Reusing %s with fd=%d (map_fd after=%d)\n", 
                names_to_reuse[i], fds_to_reuse[i], bpf_map__fd(map));
    }
    
    return 0;
}
```

**Call site** (in `load_modules()`):
```c
mod->obj = bpf_object__open_file(mod->path, &opts);
// ... error handling ...

// CRITICAL: Reuse shared maps BEFORE loading!
err = reuse_shared_maps(mod->obj, ctx);

// Load BPF object
err = bpf_object__load(mod->obj);
```

### Fix 2: Correct FD Validation

Changed from `< 0` to `<= 0` because FD 0 (stdin) is not a valid BPF map FD.

```c
// WRONG
if (fds_to_reuse[i] < 0)

// CORRECT
if (fds_to_reuse[i] <= 0)
```

### Fix 3: Remove `rs_mac_table` from Reuse List

`rs_mac_table` is created by the `l2learn` module, not the dispatcher. Its FD is not populated when `reuse_shared_maps()` runs for other modules.

### Fix 4: Do NOT Use `bpf_map__set_autocreate(false)`

Initial attempts included calling `bpf_map__set_autocreate(map, false)` before `bpf_map__reuse_fd()`. This caused:
```
BPF map 'rs_ctx_map' is referenced but wasn't created
```

**Solution**: Only call `bpf_map__reuse_fd()` - it handles everything internally.

### Fix 5: Sync `mirror.bpf.c` to Use Pipeline Macros

The mirror module was returning `XDP_PASS` directly instead of using `RS_TAIL_CALL_NEXT()`.

**Before** (broken):
```c
SEC("xdp")
int mirror_ingress(struct xdp_md *ctx)
{
    // ... processing ...
    return XDP_PASS;  // Pipeline breaks here!
}
```

**After** (fixed):
```c
SEC("xdp")
int mirror_ingress(struct xdp_md *xdp_ctx)
{
    struct rs_ctx *rs_ctx = RS_GET_CTX();
    if (!rs_ctx) {
        rs_debug("Mirror: Failed to get rs_ctx");
        return XDP_DROP;
    }

    // ... processing ...

    RS_TAIL_CALL_NEXT(xdp_ctx, rs_ctx);
    return XDP_DROP;  // Only reached if tail-call fails
}
```

---

## Verification

### 1. Check Map IDs Match

```bash
# Get pinned map IDs
sudo bpftool map show pinned /sys/fs/bpf/rs_ctx_map
# Output: 1666: percpu_array  name rs_ctx_map ...

sudo bpftool map show pinned /sys/fs/bpf/rs_progs
# Output: 1667: prog_array  name rs_progs ...

# Verify mirror uses same IDs
sudo bpftool prog show | grep mirror_ingress -A2
# Output should include map_ids with 1666 and 1667
```

### 2. Check trace_pipe for Full Pipeline

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

Expected output shows ALL modules executing:
```
Starting pipeline on port 6, target port 0, first_prog_id=0
VLAN check passed: port 6, VLAN 1, tagged=0, mode=1, target=0
ARP Learn: Reply 10.174.29.155 is-at 00:0c:29:71:c3:da
ACL: disabled, passing through. target=0
Route: Entry on ifindex=6, proto=0x800, target=0
Route: Disabled, passing through
L2learn: learn source mac, key existing, egress port: 6
L2Learn: learned src=00:0c:29:71:c3:da
[AF_XDP] mode=2, running=1, prio_mask=0xc
LastCall: egress_ifindex=3 (0=flood)
Lastcall: Redirected to port 3, ret=4
Egress on port 3: pkt_len=74
Egress final: packet processing complete
```

---

## Key Learnings

### 1. libbpf Map Reuse Behavior

- `LIBBPF_PIN_BY_NAME` pins maps but doesn't automatically reuse them across object files
- Each `.bpf.o` file creates its own map instances by default
- Must explicitly call `bpf_map__reuse_fd()` to share maps between objects
- Do NOT combine with `bpf_map__set_autocreate(false)` - it breaks map references

### 2. BPF Tail-Call Requirements

For tail-calls to work across modules:
1. All modules must reference the SAME `rs_progs` prog_array map
2. The dispatcher must populate `rs_progs` with module program FDs
3. Each module must use `RS_TAIL_CALL_NEXT()` to continue the pipeline

### 3. Debugging BPF Map Issues

```bash
# List all maps with their IDs
sudo bpftool map show

# Check which maps a program uses
sudo bpftool prog show id <prog_id>

# Verify map contents
sudo bpftool map dump pinned /sys/fs/bpf/rs_progs
```

### 4. Common Pitfalls

| Issue | Symptom | Fix |
|-------|---------|-----|
| Map not shared | Different map_ids in `bpftool prog show` | Call `bpf_map__reuse_fd()` before load |
| Invalid FD 0 | `reuse_fd` with fd=0 | Check `<= 0` not `< 0` |
| set_autocreate + reuse_fd | "map wasn't created" error | Remove `set_autocreate(false)` call |
| Module missing RS_GET_CTX | Pipeline breaks at that module | Add `RS_GET_CTX()` and `RS_TAIL_CALL_NEXT()` |

---

## Files Modified

1. **`rswitch/user/loader/rswitch_loader.c`**
   - Added `reuse_shared_maps()` function
   - Modified `load_modules()` to call it before `bpf_object__load()`
   - Fixed FD validation from `< 0` to `<= 0`
   - Removed `rs_mac_table` from reuse list

2. **`rswitch/bpf/modules/mirror.bpf.c`**
   - Changed function signature to use `xdp_ctx` parameter name
   - Added `RS_GET_CTX()` to get shared context
   - Replaced all `return XDP_PASS` with `RS_TAIL_CALL_NEXT()`

---

## Test Environment

- **Host**: `10.174.254.128`
- **User**: `kylecui`
- **Project Path**: `~/dev/rswitch/`
- **Profile**: `etc/profiles/all-modules-test.yaml`
- **Interfaces**: `ens34`, `ens35`, `ens36`, `ens37`
- **libbpf Version**: 1.3.0 (pkg-config) / 1.6 (headers)

---

## Commands Reference

### Build and Run
```bash
cd ~/dev/rswitch
make build/rswitch_loader
sudo ./build/rswitch_loader -i ens34,ens35,ens36,ens37 -p etc/profiles/all-modules-test.yaml -v
```

### Clean Up
```bash
sudo pkill -9 rswitch_loader
for iface in ens34 ens35 ens36 ens37; do
    sudo ip link set $iface xdpgeneric off
done
sudo rm -f /sys/fs/bpf/*
```

### Debug
```bash
# Watch packet flow
sudo cat /sys/kernel/debug/tracing/trace_pipe

# Check loaded programs
sudo bpftool prog show | grep -E 'name|map_ids'

# Check pinned maps
ls -la /sys/fs/bpf/
sudo bpftool map show pinned /sys/fs/bpf/rs_ctx_map
```
