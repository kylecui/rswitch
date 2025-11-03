# rSwitch Hot-Reload System

Zero-downtime module updates for rSwitch pipeline without detaching XDP.

## Overview

The hot-reload system allows you to dynamically update, add, or remove modules from the rSwitch pipeline while traffic continues to flow. This is achieved by manipulating the `rs_progs` BPF prog_array map without detaching XDP from network interfaces.

### Key Features

- **Zero Downtime**: XDP remains attached during module updates
- **Atomic Updates**: Single map update operation from kernel perspective
- **ABI Validation**: Checks module compatibility before applying changes
- **Dry-Run Mode**: Validate changes without applying them
- **Pipeline Verification**: Check integrity of loaded pipeline
- **Graceful Fallback**: Old module stays active until new one loads successfully

## Architecture

### Hot-Reload Process

1. **Load New Module**: Load BPF object and verify ABI compatibility
2. **Stage Matching**: Verify new module stage matches old module (prevents reordering)
3. **Atomic Update**: Update `rs_progs[stage]` entry (single map operation)
4. **Cleanup**: Close old BPF object (kernel keeps program if still referenced)
5. **Verification**: Validate pipeline integrity

### Safety Guarantees

- Traffic flows uninterrupted (XDP stays attached to interfaces)
- Map updates are atomic from kernel perspective
- Old module remains active until successfully replaced
- Rollback possible if new module fails to load
- ABI version checking prevents incompatible modules

## Usage

### Method 1: Helper Script (Recommended)

The `hot-reload.sh` script automatically finds the `rs_progs` map and handles errors.

```bash
# Reload a module
sudo ./scripts/hot-reload.sh reload vlan

# Reload with verbose output
sudo ./scripts/hot-reload.sh reload l2learn -v

# Dry-run (validate without applying)
sudo ./scripts/hot-reload.sh reload vlan -n

# Verify pipeline integrity
sudo ./scripts/hot-reload.sh verify 20 80 90

# List loaded modules
sudo ./scripts/hot-reload.sh list
```

### Method 2: Direct Tool Usage

For more control, use the `hot_reload` tool directly.

```bash
# Find rs_progs map FD
RS_PROGS_FD=$(sudo bpftool map list | grep rs_progs | awk '{print $1}' | cut -d: -f1)

# Reload module
sudo ./build/hot_reload reload vlan -p $RS_PROGS_FD -v

# Unload module (remove from pipeline)
sudo ./build/hot_reload unload vlan -p $RS_PROGS_FD

# Verify specific stages
sudo ./build/hot_reload verify 20 80 90 -p $RS_PROGS_FD
```

## Common Use Cases

### 1. Update Module Logic

Modify module code and hot-reload without traffic interruption:

```bash
# Edit module
vim bpf/modules/vlan.bpf.c

# Rebuild only the module
make build/bpf/vlan.bpf.o

# Hot-reload
sudo ./scripts/hot-reload.sh reload vlan -v
```

### 2. Add Module to Pipeline

Load a new module into an empty stage:

```bash
# Build new module
make build/bpf/acl.bpf.o

# Load into pipeline (stage 40)
sudo ./scripts/hot-reload.sh reload acl -v
```

### 3. Remove Module from Pipeline

Temporarily disable a module without restarting:

```bash
sudo ./scripts/hot-reload.sh unload l2learn
```

### 4. Validate Before Production

Test changes in dry-run mode:

```bash
# Test reload without applying
sudo ./scripts/hot-reload.sh reload vlan -n

# Review output for errors
# If successful, apply for real:
sudo ./scripts/hot-reload.sh reload vlan
```

### 5. Pipeline Health Check

Verify all expected modules are loaded:

```bash
# For L2 profile (stages 20, 80, 90)
sudo ./scripts/hot-reload.sh verify 20 80 90

# For custom pipeline
sudo ./scripts/hot-reload.sh verify 20 40 70 80 90
```

## Module Development Workflow

### Iterative Development

```bash
# 1. Edit module
vim bpf/modules/mymodule.bpf.c

# 2. Rebuild
make build/bpf/mymodule.bpf.o

# 3. Test in dry-run
sudo ./scripts/hot-reload.sh reload mymodule -n

# 4. Apply if successful
sudo ./scripts/hot-reload.sh reload mymodule -v

# 5. Verify
sudo ./scripts/hot-reload.sh verify <stage>
```

### Debugging

Enable verbose output to see detailed reload process:

```bash
sudo ./scripts/hot-reload.sh reload vlan -v
```

Output shows:
- Module loading status
- Stage matching
- prog_array updates
- Old module cleanup
- Verification results

## Limitations

### Cannot Change

- **Module Stage**: New module must use same stage as old module
- **Pipeline Order**: Stage numbers define order (use profiles for reordering)
- **Dispatcher/Egress**: Core programs cannot be hot-reloaded (require restart)

### Risks

- **Brief Window**: Small time window during map update where old program may still execute
- **Module Dependencies**: Ensure new module is compatible with current pipeline state
- **Map Sharing**: Modules sharing maps must maintain compatible data structures

## Troubleshooting

### rs_progs Map Not Found

```bash
# Check if rswitch_loader is running
ps aux | grep rswitch_loader

# Check pinned maps
ls -la /sys/fs/bpf/rswitch/

# Manually find map
sudo bpftool map list | grep rs_progs
```

### Module Load Failed

```bash
# Check BPF verifier errors
sudo dmesg | tail -50

# Verify ABI version
llvm-objdump -s build/bpf/mymodule.bpf.o | grep -A 10 ".rodata.mod"

# Check module dependencies
sudo bpftool prog show
```

### Pipeline Verification Failed

```bash
# List all prog_array entries
sudo bpftool map dump id <rs_progs_id>

# Check for missing stages
sudo ./scripts/hot-reload.sh verify <expected_stages>
```

## Examples

### Example 1: Update VLAN Module

```bash
# Current pipeline: vlan@20 → l2learn@80 → lastcall@90

# Edit VLAN logic
vim bpf/modules/vlan.bpf.c

# Rebuild
make build/bpf/vlan.bpf.o

# Hot-reload (traffic continues flowing)
sudo ./scripts/hot-reload.sh reload vlan -v

# Verify
sudo ./scripts/hot-reload.sh verify 20 80 90
```

### Example 2: Add ACL Module

```bash
# Current pipeline: vlan@20 → l2learn@80 → lastcall@90
# Target: vlan@20 → acl@40 → l2learn@80 → lastcall@90

# Create and build ACL module at stage 40
vim bpf/modules/acl.bpf.c  # RS_DECLARE_MODULE("acl", RS_HOOK_XDP_INGRESS, 40, ...)
make build/bpf/acl.bpf.o

# Load into pipeline
sudo ./scripts/hot-reload.sh reload acl -v

# Verify new pipeline
sudo ./scripts/hot-reload.sh verify 20 40 80 90
```

### Example 3: Emergency Disable

```bash
# Disable problematic module immediately
sudo ./scripts/hot-reload.sh unload l2learn

# Traffic continues but without MAC learning
# Investigate and fix module
vim bpf/modules/l2learn.bpf.c
make build/bpf/l2learn.bpf.o

# Re-enable
sudo ./scripts/hot-reload.sh reload l2learn -v
```

## Integration with Profiles

Hot-reload complements profile-based loading:

- **Profiles**: Define initial pipeline composition
- **Hot-reload**: Runtime updates without restart

```bash
# Start with L2 profile
sudo ./build/rswitch_loader -i eth0,eth1 -m l2

# Later: hot-reload individual modules
sudo ./scripts/hot-reload.sh reload vlan
```

## Performance Impact

- **Reload Time**: ~10-50ms (load new module, update map)
- **Traffic Impact**: Minimal (single map update, no packet drops expected)
- **CPU Spike**: Brief increase during BPF object load/verification
- **Memory**: Old module memory released after object close

## See Also

- `docs/Milestone1_plan.md`: Module ABI design
- `docs/rSwitch_Definition.md`: Core architecture
- `user/reload/hot_reload.c`: Implementation details
- `scripts/hot-reload.sh`: Helper script source
