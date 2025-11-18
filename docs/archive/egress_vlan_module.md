# Egress VLAN Module (egress_vlan.bpf.c)

## Purpose

The `egress_vlan` module is an **optional pluggable component** in the egress pipeline that handles VLAN tag manipulation on packet egress. It provides modular, policy-driven VLAN tagging separate from the base devmap hook.

## Architecture Position

```
Packet Flow:
  Ingress Pipeline → Forwarding Decision → Devmap
    → egress.bpf.c (devmap hook: VLAN isolation check)
      → Tail-call Pipeline:
        → egress_qos (170) [Priority + Rate Limiting]
        → egress_vlan (180) [VLAN Tag Manipulation]  ← THIS MODULE
        → egress_final (190) [Statistics + Cleanup]
      → XDP_PASS → NIC TX
```

**Key distinction:**
- `egress.bpf.c` (devmap hook): Mandatory, runs on EVERY packet, does VLAN **isolation checks**
- `egress_vlan.bpf.c` (module): Optional, only loaded if specified in profile, does VLAN **tag manipulation**

## When to Use

### Scenario 1: Basic Switching (No egress_vlan)
```yaml
# etc/profiles/l2-basic.yaml
egress:
  - egress_final  # Only cleanup, no VLAN processing
```

**Behavior:**
- `egress.bpf.c` devmap hook handles VLAN isolation
- Built-in `process_vlan_egress()` function does tag add/remove
- Sufficient for most use cases

### Scenario 2: Advanced VLAN Control (With egress_vlan)
```yaml
# etc/profiles/l2-advanced.yaml
egress:
  - egress_qos    # QoS classification and rate limiting
  - egress_vlan   # Modular VLAN tagging with custom logic
  - egress_final  # Final cleanup
```

**Use when you need:**
- **Separate QoS and VLAN processing**: QoS sets priority (PCP), then egress_vlan applies it to VLAN tag
- **Custom VLAN policies**: Extend `egress_vlan` module for special tagging rules
- **Telemetry**: Track VLAN operations separately from other egress processing
- **Dynamic reconfiguration**: Hot-reload VLAN logic without affecting QoS

## Functionality

### VLAN Mode Support

#### ACCESS Mode (port->vlan_mode = RS_VLAN_MODE_ACCESS)
- **Rule**: Always send untagged
- **Action**: Remove VLAN tags if present

```c
// Example:
// Packet: VLAN 10 tagged → egress_vlan → untagged
// Packet: untagged → egress_vlan → untagged (no change)
```

#### TRUNK Mode (port->vlan_mode = RS_VLAN_MODE_TRUNK)
- **Native VLAN Rule**: Send untagged
- **Non-native VLAN Rule**: Send tagged
- **Allowed VLANs**: Check `allowed_vlans[]` list

```c
// Example (native_vlan=1, allowed_vlans=[10,20,30]):
// Packet: VLAN 1 tagged → egress_vlan → untagged (native)
// Packet: VLAN 10 untagged → egress_vlan → tagged VID=10 (non-native)
// Packet: VLAN 10 tagged → egress_vlan → keep tag (non-native)
// Packet: VLAN 99 tagged → egress_vlan → drop (not in allowed list)
```

#### HYBRID Mode (port->vlan_mode = RS_VLAN_MODE_HYBRID)
- **Tagged VLANs List**: `tagged_vlans[]` - send with tag
- **Untagged VLANs List**: `untagged_vlans[]` - send without tag
- **Fallback**: If VLAN not in either list, send as-is

```c
// Example (tagged=[10,20], untagged=[30,40]):
// Packet: VLAN 10 → egress_vlan → tagged VID=10
// Packet: VLAN 30 → egress_vlan → untagged
// Packet: VLAN 99 → egress_vlan → as-is (no policy)
```

## Priority (PCP) Handling

The module integrates with QoS by using `rs_ctx->prio`:

```c
// Egress pipeline execution order:
// 1. egress_qos sets rs_ctx->prio based on DSCP/5-tuple
// 2. egress_vlan reads rs_ctx->prio and embeds it in VLAN TCI
// 3. Result: VLAN tag has both VID and PCP
```

**TCI Format**: `[PCP:3 bits][DEI:1 bit][VID:12 bits]`
- PCP (Priority Code Point): 0-7, from QoS classification
- DEI (Drop Eligible Indicator): Currently always 0
- VID (VLAN ID): 1-4094

## Implementation Details

### Helper Functions

#### `should_send_tagged(port, vlan_id)`
Determines if a VLAN should be sent tagged on the egress port:
- ACCESS: Always returns 0 (untagged)
- TRUNK: Returns 1 if VLAN in `allowed_vlans[]` and not `native_vlan`
- HYBRID: Returns 1 if VLAN in `tagged_vlans[]`

#### `egress_add_vlan_tag(ctx, vlan_id, pcp)`
Uses `parsing_helpers.h:vlan_tag_push()` to insert VLAN header:
1. Builds TCI: `(pcp << 13) | vlan_id`
2. Calls `vlan_tag_push(ctx, eth, tci)`
3. Updates packet data pointers after head adjustment

#### `egress_remove_vlan_tag(ctx)`
Uses `parsing_helpers.h:vlan_tag_pop()` to remove VLAN header:
1. Validates packet is 802.1Q tagged
2. Calls `vlan_tag_pop(ctx, eth)`
3. Returns 0 on success, -1 on failure

### Context Updates

After modifying packet, the module updates `rs_ctx->layers`:

```c
// Tag added:
rs_ctx->layers.vlan_depth = 1;
rs_ctx->layers.vlan_ids[0] = egress_vlan;

// Tag removed:
rs_ctx->layers.vlan_depth = 0;
rs_ctx->layers.vlan_ids[0] = 0;
```

This ensures subsequent modules (e.g., telemetry) see accurate packet state.

## Configuration Example

### Step 1: Update Profile

```yaml
# etc/profiles/l2-vlan-qos.yaml
name: "L2 Switch with QoS and VLAN Control"
ingress:
  - vlan       # Ingress VLAN processing
  - acl        # Access control
  - l2learn    # MAC learning
  - lastcall   # Forwarding decision

egress:
  - egress_qos   # Priority classification, rate limiting
  - egress_vlan  # VLAN tag manipulation (uses priority from QoS)
  - egress_final # Statistics, cleanup
```

### Step 2: Configure Port VLAN Mode

```bash
# Configure port 3 as TRUNK with native VLAN 1, allowed VLANs 10,20,30
sudo ./build/rsportctl --port 3 --vlan-mode trunk --native-vlan 1 --allowed-vlans 10,20,30

# Configure port 4 as ACCESS in VLAN 10
sudo ./build/rsportctl --port 4 --vlan-mode access --pvid 10

# Configure port 5 as HYBRID
sudo ./build/rsportctl --port 5 --vlan-mode hybrid \
  --pvid 1 --tagged-vlans 10,20 --untagged-vlans 30,40
```

### Step 3: Run Loader with Profile

```bash
sudo ./build/rswitch_loader --profile etc/profiles/l2-vlan-qos.yaml \
  --ifaces ens34,ens35,ens36,ens37
```

### Step 4: Verify Module Loaded

```bash
# Check egress pipeline
sudo bpftool prog show | grep egress
# Expected output:
# ... prog 123: xdp  name egress_qos_xdp  tag ...
# ... prog 124: xdp  name egress_vlan_xdp  tag ...
# ... prog 125: xdp  name egress_final_xdp  tag ...

# Check tail-call chain
sudo bpftool map dump name rs_prog_chain
# Expected output showing chain: 255 → 254 → 253 → 0
# (egress_qos → egress_vlan → egress_final → end)
```

## Debugging

### Trace Execution

```bash
# Enable BPF tracing
sudo cat /sys/kernel/debug/tracing/trace_pipe | grep egress_vlan
```

**Expected output:**
```
<...>-1234 [003] d.s. 123.456789: bpf_trace_printk: egress_vlan: port=3, vlan=10, tagged=0, should_tag=1, mode=2
<...>-1234 [003] d.s. 123.456790: bpf_trace_printk: Added VLAN tag: VID=10, PCP=3
```

### Common Issues

#### Issue: Module not executing
**Symptom**: No "egress_vlan:" messages in trace
**Causes**:
1. Module not in profile YAML: Check `egress:` section includes `- egress_vlan`
2. Module discovery failed: Run `./build/rswitch_loader --list-modules` to verify
3. Tail-call chain broken: Check `rs_prog_chain` map with bpftool

#### Issue: VLAN tags not applied/removed
**Symptom**: Packet VLAN state incorrect
**Debug**:
```bash
# Check port configuration
sudo ./build/rsportctl --show

# Check VLAN membership
sudo bpftool map dump name rs_vlan_map

# Verify packet state in trace
sudo cat /sys/kernel/debug/tracing/trace_pipe | grep -E "egress_vlan|vlan="
```

#### Issue: Priority (PCP) not set correctly
**Symptom**: VLAN tag has wrong priority bits
**Cause**: QoS module not loaded before egress_vlan
**Fix**: Ensure profile has correct order:
```yaml
egress:
  - egress_qos   # MUST come before egress_vlan
  - egress_vlan  # Reads prio from QoS
  - egress_final
```

## Comparison: egress.bpf.c vs egress_vlan.bpf.c

| Feature | egress.bpf.c (devmap hook) | egress_vlan.bpf.c (module) |
|---------|---------------------------|----------------------------|
| **Execution** | Always runs on every packet | Only if loaded in profile |
| **SEC annotation** | `SEC("xdp/devmap")` | `SEC("xdp/devmap")` (tail-call) |
| **Purpose** | VLAN isolation + pipeline start | VLAN tag manipulation |
| **VLAN Isolation** | ✅ Check membership, drop if not member | ❌ N/A |
| **Tag Add/Remove** | ✅ Via `process_vlan_egress()` | ✅ Via module helpers |
| **Configurable** | No, always attached to devmap | Yes, optional in profile |
| **Tail-call chain** | Starts pipeline | Part of pipeline |
| **QoS Integration** | ❌ No PCP handling | ✅ Uses `rs_ctx->prio` |
| **Hot-reload** | ❌ Requires devmap reattach | ✅ Can reload module |

## Performance Considerations

### Without egress_vlan (Built-in Processing)
```
Latency: ~200ns per packet (devmap hook only)
Overhead: None (inline processing)
```

### With egress_vlan (Modular Processing)
```
Latency: ~200ns (devmap) + ~150ns (tail-call) + ~100ns (VLAN processing) = ~450ns
Overhead: +1 tail-call (33-call limit impact: minimal)
```

**Recommendation**: Use built-in processing (no egress_vlan) unless you need:
- Separation between QoS and VLAN processing
- Custom VLAN logic extensions
- Independent hot-reload of VLAN logic

## Future Enhancements

### Planned Features
1. **QinQ (802.1ad) Support**: Double VLAN tagging
2. **VLAN Translation**: Rewrite VLAN IDs on egress
3. **Per-VLAN Statistics**: Count packets per VLAN per port
4. **Dynamic VLAN Assignment**: Based on packet content (e.g., RADIUS attributes)

### Extension Example

```c
// rswitch/bpf/modules/egress_vlan_qinq.bpf.c
RS_DECLARE_MODULE(
    "egress_vlan_qinq",
    RS_HOOK_XDP_EGRESS,
    181,  // After egress_vlan
    RS_FLAG_MODIFIES_PACKET,
    "Add outer VLAN tag for QinQ tunneling"
);

SEC("xdp/devmap")
int egress_vlan_qinq_xdp(struct xdp_md *ctx) {
    struct rs_ctx *rs_ctx = RS_GET_CTX();
    
    // Check if port is QinQ uplink
    if (rs_ctx->egress_port_type == PORT_TYPE_QINQ_UPLINK) {
        // Add outer S-tag (802.1ad)
        __u16 outer_vlan = get_service_vlan(rs_ctx->ingress_ifindex);
        egress_add_svlan_tag(ctx, outer_vlan, rs_ctx->prio);
    }
    
    RS_TAIL_CALL_EGRESS(ctx, rs_ctx);
    return XDP_PASS;
}
```

## Summary

**egress_vlan.bpf.c** provides:
- ✅ Modular VLAN tag manipulation in egress pipeline
- ✅ Integration with QoS module for priority (PCP) handling
- ✅ Support for ACCESS/TRUNK/HYBRID port modes
- ✅ Hot-reload capability for dynamic reconfiguration
- ✅ Extensible architecture for custom VLAN policies

**When to use**: Advanced scenarios requiring separate QoS/VLAN processing, custom VLAN logic, or independent hot-reload.

**When NOT to use**: Basic switching - built-in `egress.bpf.c` VLAN processing is sufficient and faster.
