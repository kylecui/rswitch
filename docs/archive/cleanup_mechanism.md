> **⚠️ ARCHIVED** — This document is historical reference only. It may not reflect current implementation. See [current documentation](../README.md) for up-to-date information.

# rSwitch Loader Cleanup Mechanism

## Overview

The rSwitch loader now implements comprehensive cleanup functionality to ensure all resources are properly released when the loader exits (either normally or via signal).

## Cleanup Steps

When the loader exits, the following cleanup sequence is executed:

### 1. **Detach XDP Programs** (`detach_xdp()`)
- Detaches XDP programs from all configured interfaces
- Uses the same `xdp_flags` that were used during attachment for consistency
- Reports any failures but continues cleanup
- **Effect**: Interfaces return to normal operation without XDP processing

### 2. **Close Map File Descriptors** (`close_map_fds()`)
- Closes all map file descriptors:
  - `rs_ctx_map_fd`
  - `rs_progs_fd` (tail-call prog_array)
  - `rs_port_config_map_fd`
  - `rs_devmap_fd`
  - `rs_stats_map_fd`
- **Effect**: Releases user-space references to BPF maps

### 3. **Close Module BPF Objects** (`cleanup()`)
- Calls `bpf_object__close()` for each loaded module
- **Effect**: Releases kernel references to module programs and their local maps

### 4. **Close Core BPF Objects** (`cleanup()`)
- Closes dispatcher and egress BPF objects
- **Effect**: Releases kernel references to core programs

### 5. **Unpin Maps from BPF Filesystem** (`unpin_maps()`)
- Unlinks pinned maps from `/sys/fs/bpf/`:
  - `rs_ctx_map`
  - `rs_progs`
  - `rs_port_config_map`
  - `rs_vlan_map`
  - `rs_mac_table`
  - `rs_stats_map`
- **Effect**: Removes persistent map references; maps will be garbage collected when all FDs are closed

### 6. **Free User-Space Memory** (`cleanup()`)
- Frees profile data structures
- **Effect**: Releases user-space memory

## Signal Handling

The loader registers signal handlers for graceful shutdown:

```c
signal(SIGINT, sig_handler);   // Ctrl+C
signal(SIGTERM, sig_handler);  // kill command
```

When a signal is received:
1. `keep_running` flag is set to 0
2. Main loop exits
3. `cleanup()` is called automatically

## Testing Cleanup

### Manual Test

```bash
# Start loader
sudo ./build/rswitch_loader -i eth0,eth1,eth2 -m dumb

# In another terminal, check resources
sudo ls -la /sys/fs/bpf/
sudo bpftool prog show type xdp
sudo ip link show eth0 | grep xdp

# Stop loader with Ctrl+C
# Then check again - all resources should be cleaned up
sudo ls -la /sys/fs/bpf/
sudo bpftool prog show type xdp
```

### Automated Test

```bash
sudo ./test_cleanup.sh
```

This script:
1. Checks state before loader run
2. Runs loader for 5 seconds
3. Verifies complete cleanup after exit

## Comparison with PoC

### PoC kSwitchLoader Cleanup
- ✓ Closes BPF objects (`bpf_object__close()`)
- ✗ Does NOT detach XDP programs
- ✗ Does NOT unpin maps
- ✗ Does NOT close map FDs explicitly

**Result**: After PoC loader exits, XDP programs remain attached and maps remain pinned.

### New rSwitch Loader Cleanup
- ✓ Detaches all XDP programs from interfaces
- ✓ Closes all map file descriptors
- ✓ Unpins all maps from BPF filesystem
- ✓ Closes all BPF objects
- ✓ Frees user-space memory

**Result**: After new loader exits, system is completely cleaned - no residual BPF resources.

## Why This Matters

### 1. **Development Iteration**
Without proper cleanup, each test run leaves:
- XDP programs attached (prevents reattachment with `XDP_FLAGS_UPDATE_IF_NOEXIST`)
- Maps pinned (prevents clean restart)
- File descriptors open (resource leak)

Proper cleanup enables:
```bash
# Run test multiple times without manual cleanup
sudo ./build/rswitch_loader -i eth0,eth1 -m dumb
# Ctrl+C
sudo ./build/rswitch_loader -i eth0,eth1 -m dumb  # Works immediately!
```

### 2. **Production Deployment**
- Clean shutdown during service restart
- No resource leaks during orchestration (Kubernetes, systemd)
- Predictable state after crashes (kernel cleans up remaining resources)

### 3. **Debugging**
Clear distinction between:
- Intended state (loader running)
- Clean state (loader not running)

Makes it easier to identify stuck resources.

## Implementation Details

### XDP Flags Consistency

The loader stores `xdp_flags` in `loader_ctx` during initialization:

```c
ctx.xdp_flags = DEFAULT_XDP_FLAGS;  // XDP_FLAGS_UPDATE_IF_NOEXIST
```

Same flags are used in both `attach_xdp()` and `detach_xdp()` to ensure symmetry.

### Map Unpinning

Maps are unpinned by unlinking their paths from the BPF filesystem:

```c
const char *pinned_maps[] = {
    "/sys/fs/bpf/rs_ctx_map",
    "/sys/fs/bpf/rs_progs",
    // ... etc
};

for (int i = 0; pinned_maps[i] != NULL; i++) {
    if (stat(pinned_maps[i], &st) == 0) {
        unlink(pinned_maps[i]);
    }
}
```

**Important**: Maps are NOT immediately destroyed - kernel keeps them alive while:
- Any file descriptor references them
- Any BPF program uses them

Once all references are released, kernel garbage collects the maps.

### Error Handling

Cleanup is **best-effort**:
- Errors are logged but do not stop cleanup sequence
- Each step is independent
- Goal: clean up as much as possible even if some steps fail

Example:
```c
if (bpf_xdp_detach(...) < 0) {
    fprintf(stderr, "Warning: Failed to detach...\n");
    // Continue to next cleanup step
}
```

## Future Enhancements

### Persistent Mode (Future)

For some use cases, we may want maps to persist after loader exit:

```bash
sudo ./build/rswitch_loader -i eth0,eth1 -m dumb --persist-maps
```

This would:
- Still detach XDP programs (safety)
- Still close objects
- **Skip** map unpinning
- Allow next loader instance to reuse existing maps

Use case: Hot upgrade without losing MAC learning table.

### State Preservation

Future VOQd mode may want to preserve certain state across restarts:
- Statistics counters
- Telemetry baselines
- Policy hit counts

Selective unpinning could preserve specific maps while cleaning others.

## Summary

The new loader provides **complete, production-ready cleanup** that:

✅ **Enables rapid development iteration** (no manual cleanup between runs)  
✅ **Prevents resource leaks** (all maps, programs, FDs released)  
✅ **Ensures clean state** (interfaces return to normal after exit)  
✅ **Handles signals gracefully** (Ctrl+C, kill)  
✅ **Logs all actions** (clear visibility into cleanup process)

This is a **significant improvement** over the PoC loader and follows best practices for BPF application lifecycle management.
