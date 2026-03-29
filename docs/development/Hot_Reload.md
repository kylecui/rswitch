# Hot-Reload Architecture

> **Status**: Implemented in rSwitch v2.0 (`user/reload/hot_reload.c`, 1100+ lines).
>
> Hot-reload enables zero-downtime module updates by swapping prog_array entries without detaching XDP from network interfaces.

---

## 1. How It Works

rSwitch modules execute in a tail-call chain via a shared `rs_progs` prog_array map. Each pipeline slot corresponds to one module. Hot-reload replaces a single slot atomically:

```
                  prog_array (rs_progs)
                  ┌────────────────────┐
  slot 0 (parser) │  prog_fd = 42      │
                  ├────────────────────┤
  slot 1 (vlan)   │  prog_fd = 55      │  ◄── bpf_map_update_elem(slot, &new_fd)
                  ├────────────────────┤       (atomic from kernel's perspective)
  slot 2 (acl)    │  prog_fd = 63      │
                  ├────────────────────┤
  slot 3 (fwd)    │  prog_fd = 71      │
                  └────────────────────┘

  XDP stays attached to NIC → traffic never stops
```

### Reload Sequence

1. **Load** new module BPF object from disk
2. **Verify** ABI compatibility (major version must match, minor ≤ platform)
3. **Verify** module name and hook type match the slot being replaced
4. **Load** the BPF program into the kernel (verifier runs)
5. **Swap** the prog_array entry (`bpf_map_update_elem`) — this is the atomic step
6. **Verify** the swap succeeded by reading back the entry
7. **Close** old BPF object (kernel keeps the old program alive until last reference drops)

The critical insight: `bpf_map_update_elem` on a prog_array is atomic from the kernel's perspective. Any packet currently executing the old program will complete; subsequent tail-calls land on the new program.

---

## 2. What IS Atomic

- **Single prog_array entry update**: The kernel atomically swaps the file descriptor pointer. No packet sees a partially-updated state.
- **Traffic continuity**: XDP attachment is untouched. Packets continue flowing through the NIC during the entire reload.
- **Per-slot isolation**: Replacing module at slot N does not affect modules at other slots.

---

## 3. Current Limitations

| Limitation | Detail |
|-----------|--------|
| **No hot-add of new modules** | The module must already be loaded in the pipeline. You cannot add a new slot dynamically — that requires a full pipeline reload via `rswitch_loader`. |
| **ABI version must match** | Major version must equal the platform's ABI major. Minor version must be ≤ platform minor. Mismatched modules are rejected before swap. |
| **Same hook type required** | An ingress module cannot be hot-swapped into an egress slot (and vice versa). Hook type is verified before swap. |
| **Stage/slot must match** | The new module's declared stage must match the slot being replaced. This prevents accidental pipeline reordering. |
| **Pipeline validation is pre-swap only** | If the BPF verifier rejects the new module, the swap is aborted and the old module remains active. However, there is no post-swap semantic validation. |
| **No automatic rollback of successful swaps** | Once the swap succeeds, the old module is gone. Rolling back requires re-loading the old module binary. |
| **No multi-module atomic swap** | Each slot is swapped independently. If you need to replace modules A and B atomically, there is a brief window where A is updated but B is not. |

---

## 4. Usage

### CLI — `hot_reload` Binary

```bash
# Reload (swap) a single module
sudo ./user/reload/hot_reload reload <module_name>

# Dry-run — validate without applying
sudo ./user/reload/hot_reload reload <module_name> --dry-run

# List currently loaded modules
sudo ./user/reload/hot_reload list

# Verify pipeline integrity at specific stages
sudo ./user/reload/hot_reload verify <stage1> [stage2 ...]

# Verbose output
sudo ./user/reload/hot_reload reload <module_name> --verbose
```

### Wrapper Script

```bash
# Convenience wrapper
sudo ./scripts/hot-reload.sh reload my_module
```

### Options

| Flag | Description |
|------|-------------|
| `-n`, `--dry-run` | Validate the new module without applying the swap |
| `-v`, `--verbose` | Print detailed progress during reload |
| `-p`, `--prog-fd <fd>` | Specify rs_progs map FD manually (auto-detected by default) |
| `-h`, `--help` | Show usage information |

---

## 5. Failure Modes and Recovery

### Module Fails to Load (Verifier Rejection)

**What happens**: BPF verifier rejects the new module. Swap is never attempted.

**Recovery**: Fix the module source, rebuild, and retry. The old module continues operating normally.

### ABI Mismatch

**What happens**: The new module declares ABI v1 but the platform runs ABI v2 (or vice versa). Swap is rejected before loading.

**Recovery**: Rebuild the module against the correct SDK version.

### Module Name Mismatch

**What happens**: The module binary's `RS_DECLARE_MODULE(name, ...)` does not match the name passed to `reload`. Swap is rejected.

**Recovery**: Pass the correct module name (matching the `RS_DECLARE_MODULE` declaration).

### Swap Verification Failure

**What happens**: After `bpf_map_update_elem`, the readback check finds a different prog_id than expected. This is extremely rare and indicates a concurrent modification.

**Recovery**: The tool attempts to restore the old program. If restoration fails, a full pipeline reload via `rswitch_loader` is required.

### Module Crashes at Runtime

**What happens**: The new module passes the verifier but has a logic error (e.g., always returns XDP_DROP).

**Recovery**: Re-run `hot_reload reload <module_name>` with the previous known-good binary. There is no automatic rollback.

---

## 6. Architecture Details

### File Layout

```
user/reload/
├── hot_reload.c              # Main hot-reload implementation (1100+ lines)
└── Makefile                   # Build rules (linked against libbpf)
```

### Key Data Structures

```c
struct reload_ctx {
    struct reload_module modules[MAX_MODULES];  // Tracked modules
    int num_modules;
    int rs_progs_fd;          // File descriptor for rs_progs prog_array
    int rs_prog_chain_fd;     // File descriptor for rs_prog_chain (egress)
    int verbose;
    int dry_run;
};
```

### Map Dependencies

| Map | Used For |
|-----|----------|
| `rs_progs` | Prog_array — the actual swap target. Pinned at `/sys/fs/bpf/rs_progs`. |
| `rs_prog_chain` | Egress pipeline chaining. Updated when reloading egress modules. |

---

*See also: [Module Developer Guide](Module_Developer_Guide.md) · [ABI Policy](ABI_POLICY.md) · [Platform Architecture](Platform_Architecture.md)*
