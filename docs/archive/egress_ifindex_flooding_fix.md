> **⚠️ ARCHIVED** — This document is historical reference only. It may not reflect current implementation. See [current documentation](../README.md) for up-to-date information.

# Egress ifindex Fix for Flooding (BPF_F_BROADCAST)

## Problem

During packet flooding (BPF_F_BROADCAST), the egress_vlan module was reading `rs_ctx->egress_ifindex` which is 0 for broadcast traffic, causing it to skip processing with the message:

```
egress_vlan: No egress port set
```

This resulted in:
- VLAN isolation checks NOT performed during flooding
- VLAN tags NOT added/removed on flooded packets
- Security issue: packets leaked between VLANs

## Root Cause

**Key insight**: When `bpf_redirect_map()` uses `BPF_F_BROADCAST` flag:
1. Kernel calls the devmap egress program **once per destination port**
2. Each invocation has **different `ctx->egress_ifindex`** (set by devmap)
3. But **same `rs_ctx`** (per-CPU, shared across all invocations)

**The bug**: `egress_vlan` was reading `rs_ctx->egress_ifindex` which is:
- Set by lastcall for **unicast** forwarding (single destination)
- Set to **0** for **flooding** (BPF_F_BROADCAST to all ports)

**Expected behavior**: Read `ctx->egress_ifindex` instead, which devmap sets correctly for each port.

## Solution

Changed `egress_vlan.bpf.c` to read egress port from XDP context:

```c
// BEFORE (incorrect):
__u32 egress_ifindex = rs_ctx->egress_ifindex;  // 0 during flooding

// AFTER (correct):
__u32 egress_ifindex = ctx->egress_ifindex;     // actual port (4, 5, 6, etc.)
```

## Technical Details

### Unicast Forwarding Flow

```
lastcall: Sets rs_ctx->egress_ifindex = 3
   ↓
bpf_redirect_map(&devmap, 3, 0)  // Single port
   ↓
devmap: Calls egress hook with ctx->egress_ifindex = 3
   ↓
egress_vlan: Reads ctx->egress_ifindex = 3 ✅
```

### Broadcast/Flooding Flow

```
lastcall: Sets rs_ctx->egress_ifindex = 0 (flood marker)
   ↓
bpf_redirect_map(&devmap, 0, BPF_F_BROADCAST)  // All ports
   ↓
devmap: Calls egress hook MULTIPLE times:
   - Call 1: ctx->egress_ifindex = 4
   - Call 2: ctx->egress_ifindex = 5
   - Call 3: ctx->egress_ifindex = 6
   ↓
egress_vlan: Reads ctx->egress_ifindex = 4/5/6 ✅ (per call)
            (NOT rs_ctx->egress_ifindex = 0)
```

### Why rs_ctx is Same for All Broadcast Calls

**Per-CPU map**: `rs_ctx_map` uses `BPF_MAP_TYPE_PERCPU_ARRAY`
- Each CPU core has its own instance
- Same core processes all broadcast destinations (sequential)
- All invocations see the same `rs_ctx` content

**This is safe because**:
- Broadcast is sequential on same CPU (not parallel)
- `ctx->egress_ifindex` changes per call (set by devmap)
- Only read-only access to `rs_ctx` (VLAN ID, priority, etc.)

## Verification

### Before Fix - Trace Output

```
[rSwitch] Flooding: VLAN 1 from port 3 to all ports
[rSwitch] Egress on port 4: pkt_len=60
[rSwitch] egress_vlan: No egress port set        ❌ BUG
[rSwitch] Egress final: packet processing complete

[rSwitch] Egress on port 5: pkt_len=60
[rSwitch] egress_vlan: No egress port set        ❌ BUG
[rSwitch] Egress final: packet processing complete
```

**Result**: No VLAN isolation, no tag manipulation during flooding.

### After Fix - Expected Trace Output

```
[rSwitch] Flooding: VLAN 1 from port 3 to all ports
[rSwitch] Egress on port 4: pkt_len=60
[rSwitch] egress_vlan: Isolation check - port 4, VLAN 1     ✅ FIXED
[rSwitch] egress_vlan: Port 4 is member of VLAN 1, allowing
[rSwitch] egress_vlan: port=4, vlan=1, tagged=0, should_tag=0, mode=1
[rSwitch] Egress final: packet processing complete

[rSwitch] Egress on port 5: pkt_len=60
[rSwitch] egress_vlan: Isolation check - port 5, VLAN 1     ✅ FIXED
[rSwitch] egress_vlan: Port 5 not in VLAN 1, dropping (isolation)  ← Correct behavior
```

**Result**: VLAN isolation enforced, packets only sent to member ports.

## Testing

### Test 1: Unicast (Should Still Work)

```bash
# Port 3 (TRUNK, VLAN 10) → Port 4 (ACCESS, VLAN 10)
# Expected: Packet delivered, VLAN tag removed for ACCESS port
```

### Test 2: Flooding within Same VLAN (Should Work Now)

```bash
# Port 3 (VLAN 10) broadcasts ARP request
# Expected: Only ports in VLAN 10 receive the packet
# Ports in other VLANs: Dropped by egress_vlan isolation check
```

### Test 3: Flooding Across VLANs (Should Drop)

```bash
# Port 3 (VLAN 10) broadcasts
# Port 5 (VLAN 20) should NOT receive
# Expected: egress_vlan drops packet at port 5 (not member of VLAN 10)
```

## Impact on Other Modules

### egress_qos.bpf.c
✅ **Already correct** - uses `ctx->egress_ifindex` (line 437)

### egress_final.bpf.c
✅ **No issue** - doesn't need egress port information

### Future Egress Modules
⚠️ **Important**: Always read egress port from `ctx->egress_ifindex`, NOT `rs_ctx->egress_ifindex`

**Rule of thumb**:
```c
// In devmap egress programs (SEC("xdp/devmap")):
__u32 egress_port = ctx->egress_ifindex;        // ✅ Correct

// In ingress programs:
__u32 egress_port = rs_ctx->egress_ifindex;     // ✅ Correct (set by lastcall)
```

## Related Issues

This fix also resolves:
- VLAN leakage during ARP flooding
- Broadcast storms not properly isolated by VLAN
- MAC learning seeing packets on wrong VLANs

## Code Changes

**File**: `rswitch/bpf/modules/egress_vlan.bpf.c`

```diff
- __u32 egress_ifindex = rs_ctx->egress_ifindex;
+ __u32 egress_ifindex = ctx->egress_ifindex;
```

**Added comment explaining the difference between unicast and flooding behavior.**
