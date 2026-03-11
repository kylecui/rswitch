# rSwitch SDK Quick Start

The rSwitch SDK lets you build and test standalone BPF modules without cloning the full development tree.

---

## 1. SDK Contents

```
sdk/
├── include/                  # Stable platform headers
│   ├── rswitch_bpf.h         # BPF helper functions and CO-RE macros
│   ├── rswitch_common.h      # Single include for all BPF modules
│   ├── module_abi.h          # Module ABI: RS_DECLARE_MODULE, RS_DEPENDS_ON, flags
│   ├── uapi.h                # Core types: rs_ctx, rs_layers, macros, shared maps
│   └── map_defs.h            # Shared map definitions and helper functions
├── templates/                # Starter module implementations
│   ├── simple_module.bpf.c   # Minimal ingress module
│   ├── stateful_module.bpf.c # Ingress module with private BPF map state
│   └── egress_module.bpf.c   # Egress pipeline module
├── Makefile.module           # Standalone build rules
├── test/                     # Testing support
│   ├── test_harness.h        # Unit test framework (RS_TEST, RS_ASSERT_*)
│   └── mock_maps.h           # Map mocks for user-space testing
└── docs/
    └── SDK_Quick_Start.md    # This file
```

---

## 2. Prerequisites

- **clang** (≥ 12) and **llvm** (for BPF target)
- **libbpf** headers and library
- **Linux kernel** with BTF support (`/sys/kernel/btf/vmlinux`)

If `include/vmlinux.h` is not present, generate it:

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > include/vmlinux.h
```

---

## 3. Create a Module

### 3.1 From Template

```bash
cp templates/simple_module.bpf.c my_filter.bpf.c
```

Edit the file:
1. Update `RS_DECLARE_MODULE()` with your module's name, stage, flags, and description
2. Rename the XDP function
3. Add your packet processing logic
4. Optionally add dependencies with `RS_DEPENDS_ON()`

### 3.2 Using rswitchctl Scaffolding

If you have the full rSwitch installation, use the scaffolding CLI:

```bash
rswitchctl new-module my_filter --stage 35 --hook ingress --flags NEED_L2L3_PARSE,MAY_DROP
```

This generates a ready-to-build module source file.

### 3.3 Module Structure

Every rSwitch BPF module follows this structure:

```c
// SPDX-License-Identifier: GPL-2.0
#include "../include/rswitch_common.h"
#include "../include/module_abi.h"

char _license[] SEC("license") = "GPL";

// 1. Module declaration (embedded in .rodata.mod ELF section)
RS_DECLARE_MODULE(
    "my_filter",                                    // Name (max 32 chars)
    RS_HOOK_XDP_INGRESS,                            // Hook point
    35,                                             // Stage number (ordering)
    RS_FLAG_NEED_L2L3_PARSE | RS_FLAG_MAY_DROP,     // Capability flags
    "Filters packets by custom criteria"            // Description
);

// 2. Optional: dependency declarations
RS_DEPENDS_ON("vlan");  // Requires VLAN processing before this module

// 3. XDP program entry point
SEC("xdp")
int my_filter_func(struct xdp_md *xdp_ctx)
{
    // Get per-CPU shared context
    struct rs_ctx *ctx = RS_GET_CTX();
    if (!ctx) return XDP_DROP;

    // Access parsed headers
    void *data = (void *)(long)xdp_ctx->data;
    void *data_end = (void *)(long)xdp_ctx->data_end;

    // Use verifier-safe offset masks
    struct iphdr *iph = data + (ctx->layers.l3_offset & RS_L3_OFFSET_MASK);
    if ((void *)(iph + 1) > data_end)
        return XDP_DROP;

    // Your filtering logic...

    // Continue to next module in pipeline
    RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
    return XDP_DROP;  // Fallthrough = drop
}
```

---

## 4. Build

```bash
make -f Makefile.module MODULE=my_filter
```

Output: `my_filter.bpf.o`

Verify module metadata:

```bash
make -f Makefile.module MODULE=my_filter verify
```

---

## 5. Key API Reference

### 5.1 Module Declaration

| Macro / Constant | Description |
|-------------------|-------------|
| `RS_DECLARE_MODULE(name, hook, stage, flags, desc)` | Declares module metadata in `.rodata.mod` section |
| `RS_HOOK_XDP_INGRESS` | Ingress pipeline hook |
| `RS_HOOK_XDP_EGRESS` | Egress pipeline hook |
| `RS_ABI_VERSION` | Current ABI version (v1.0 = `0x00010000`) |

### 5.2 Capability Flags

| Flag | Meaning |
|------|---------|
| `RS_FLAG_NEED_L2L3_PARSE` | Module requires parsed L2/L3 headers in `ctx->layers` |
| `RS_FLAG_NEED_VLAN_INFO` | Module requires VLAN information |
| `RS_FLAG_NEED_FLOW_INFO` | Module requires 5-tuple flow info (L4 ports, protocol) |
| `RS_FLAG_MODIFIES_PACKET` | Module may modify packet data |
| `RS_FLAG_MAY_DROP` | Module may drop packets |
| `RS_FLAG_CREATES_EVENTS` | Module generates events to `rs_event_bus` |

### 5.3 Context and Pipeline Macros

| Macro | Description |
|-------|-------------|
| `RS_GET_CTX()` | Returns per-packet `struct rs_ctx *` from per-CPU map |
| `RS_TAIL_CALL_NEXT(xdp_ctx, ctx)` | Continue ingress pipeline (auto-increments slot) |
| `RS_TAIL_CALL_EGRESS(xdp_ctx, ctx)` | Continue egress pipeline (reads next slot from `rs_prog_chain`) |
| `RS_EMIT_EVENT(event_ptr, size)` | Emit structured event to unified event bus |

### 5.4 Dependency Declaration

| Macro | Description |
|-------|-------------|
| `RS_DEPENDS_ON("mod1")` | Declare one dependency |
| `RS_DEPENDS_ON("mod1", "mod2")` | Declare two dependencies |
| `RS_DEPENDS_ON("mod1", "mod2", "mod3")` | Declare three dependencies |
| `RS_DEPENDS_ON("mod1", "mod2", "mod3", "mod4")` | Declare four dependencies (maximum) |

Dependencies are declared in `.rodata.moddep` section and resolved by the loader using topological sort.

### 5.5 API Stability Tiers

| Annotation | Guarantee |
|-----------|-----------|
| `RS_API_STABLE` | No breaking changes across minor versions |
| `RS_API_EXPERIMENTAL` | May change between minor versions |
| `RS_API_INTERNAL` | May change at any time; do not use in external modules |

All macros in sections 5.1–5.4 are **RS_API_STABLE**.

### 5.6 Per-CPU Context (`struct rs_ctx`)

The shared context is populated by upstream modules and consumed by downstream modules:

| Field | Type | Set By | Description |
|-------|------|--------|-------------|
| `ifindex` | `__u32` | dispatcher | Ingress interface index |
| `timestamp` | `__u32` | dispatcher | Packet arrival timestamp |
| `parsed` | `__u8` | dispatcher | 1 if L2/L3 headers are parsed |
| `modified` | `__u8` | any | 1 if packet data was modified |
| `layers` | `struct rs_layers` | dispatcher/vlan | Parsed header offsets and values |
| `ingress_vlan` | `__u16` | vlan | Classified ingress VLAN |
| `egress_vlan` | `__u16` | vlan/route | VLAN for egress |
| `prio` | `__u8` | qos_classify | Priority (0-7) |
| `dscp` | `__u8` | qos_classify | DSCP value |
| `traffic_class` | `__u8` | qos_classify | Traffic class |
| `egress_ifindex` | `__u32` | route/l2learn | Target output port |
| `action` | `__u8` | any | XDP_PASS / XDP_DROP / XDP_REDIRECT |
| `mirror` | `__u8` | mirror | 1 if mirror is required |
| `mirror_port` | `__u16` | mirror | Mirror destination port |
| `error` | `__u32` | any | `RS_ERROR_*` code |
| `drop_reason` | `__u32` | any | `RS_DROP_*` reason |
| `next_prog_id` | `__u32` | pipeline | Next module slot (managed by macros) |
| `call_depth` | `__u32` | pipeline | Recursion guard (max 32) |

### 5.7 Parsed Layers (`struct rs_layers`)

| Field | Type | Description |
|-------|------|-------------|
| `eth_proto` | `__u16` | Ethernet protocol (ETH_P_IP, ETH_P_IPV6, etc.) |
| `vlan_ids[2]` | `__u16[]` | VLAN IDs (outer, inner — supports Q-in-Q) |
| `vlan_depth` | `__u8` | Number of VLAN tags (0-2) |
| `ip_proto` | `__u8` | IP protocol (IPPROTO_TCP, IPPROTO_UDP, etc.) |
| `saddr` | `__be32` | Source IPv4 address |
| `daddr` | `__be32` | Destination IPv4 address |
| `sport` | `__be16` | Source L4 port |
| `dport` | `__be16` | Destination L4 port |
| `l2_offset` | `__u16` | Ethernet header offset |
| `l3_offset` | `__u16` | IP header offset |
| `l4_offset` | `__u16` | TCP/UDP header offset |
| `payload_offset` | `__u16` | Payload offset |
| `payload_len` | `__u32` | Payload length |

### 5.8 Verifier-Safe Offset Masks

Always mask offsets before pointer arithmetic to pass the BPF verifier:

| Mask | Value | Use For |
|------|-------|---------|
| `RS_L3_OFFSET_MASK` | `0x3F` (63) | L3 header access |
| `RS_L4_OFFSET_MASK` | `0x7F` (127) | L4 header access |
| `RS_PAYLOAD_MASK` | `0xFF` (255) | Payload access |

```c
// CORRECT: mask offset before pointer arithmetic
struct iphdr *iph = data + (ctx->layers.l3_offset & RS_L3_OFFSET_MASK);
if ((void *)(iph + 1) > data_end) return XDP_DROP;

// WRONG: raw offset — BPF verifier will reject
struct iphdr *iph = data + ctx->layers.l3_offset;  // REJECTED
```

### 5.9 Module Configuration

Modules can receive per-module configuration parameters from YAML profiles:

```c
#include "../include/rswitch_bpf.h"

// Read a config parameter set by the profile
struct rs_module_config_value *val = rs_get_module_config("my_filter", "threshold");
if (val && val->type == 0 /* int */) {
    __s64 threshold = val->int_val;
    // Use threshold...
}
```

Profile YAML:
```yaml
modules:
  - name: my_filter
    stage: 35
    config:
      threshold: 1000
```

### 5.10 Per-Module Statistics

Track your module's processing statistics:

```c
#include "../include/rswitch_bpf.h"

// Call at end of your module's processing
rs_module_stats_inc(ctx, RS_MODULE_STATS_PROCESSED);  // or FORWARDED, DROPPED, ERROR
```

Statistics are accessible via CLI:
```bash
rswitchctl show-stats --module my_filter
rswitchctl show-stats --module my_filter --json
```

### 5.11 Event Bus

Emit structured events to user-space:

```c
struct {
    __u16 type;
    __u16 len;
    __u32 src_ip;
    __u32 reason;
} my_event;

my_event.type = 0x0600;  // Choose from your module's event range
my_event.len = sizeof(my_event);
my_event.src_ip = ctx->layers.saddr;
my_event.reason = 42;

RS_EMIT_EVENT(&my_event, sizeof(my_event));
```

Event type ranges (namespaced per function):
```
0x0000-0x00FF  Core (reserved)
0x0100-0x01FF  L2 events
0x0200-0x02FF  ACL events
0x0300-0x03FF  Route events
0x0400-0x04FF  Mirror events
0x0500-0x05FF  QoS events
0x0600-0xFEFF  Available for custom modules
0xFF00-0xFFFF  Error events (reserved)
```

### 5.12 Shared Maps

Your module can access platform-wide shared maps:

| Map | Access | Purpose |
|-----|--------|---------|
| `rs_port_config_map` | Read | Per-port configuration |
| `rs_stats_map` | Read/Write | Per-interface statistics |
| `rs_module_stats_map` | Read/Write | Per-module statistics |
| `rs_vlan_map` | Read | VLAN membership bitmasks |
| `rs_mac_table` | Read | MAC forwarding table (extern) |
| `rs_module_config_map` | Read | Module config parameters |
| `rs_event_bus` | Write | Event emission |

Helper functions for common operations:
```c
// Port configuration lookup
struct rs_port_config *port = rs_get_port_config(ctx->ifindex);

// Statistics update
rs_stats_update_rx(ctx, packet_bytes);
rs_stats_update_drop(ctx);

// MAC table lookup
struct rs_mac_entry *entry = rs_mac_lookup(eth->h_dest, ctx->ingress_vlan);

// VLAN membership check
int is_tagged;
int member = rs_is_vlan_member(vlan_id, ifindex, &is_tagged);
```

---

## 6. Stage Number Conventions

Modules execute in ascending stage order (ingress) or descending slot order (egress). Choose your stage number based on where your module fits in the processing pipeline.

### Ingress Pipeline (Stages 10–99)

| Range | Phase | Built-in Modules |
|-------|-------|------------------|
| 10-12 | Pre-processing | `dispatcher`(10), `lacp`(11), `lldp`(11), `stp`(12) |
| 15-19 | Early filtering | `tunnel`(15), `source_guard`(18), `dhcp_snoop`(19) |
| 20-29 | VLAN + QoS | `vlan`(20), `qos_classify`(25), `rate_limiter`(28) |
| 30-39 | Access control | `acl`(30), `conntrack`(32) |
| 40-49 | Mirroring | `mirror`(45) |
| 50-59 | Routing + NAT | `route`(50), `nat`(55) |
| 60-69 | Flow acceleration | `flow_table`(60) |
| 70-79 | Reserved | — |
| 80-89 | Learning + sampling | `l2learn`(80), `arp_learn`(80), `afxdp_redirect`(85), `sflow`(85) |
| 90-99 | Final | `lastcall`(90) — **always last** |

### Egress Pipeline (Stages 100–199)

| Range | Phase | Built-in Modules |
|-------|-------|------------------|
| 100-169 | Custom egress processing | — (your modules here) |
| 170-179 | QoS enforcement | `egress_qos`(170) |
| 180-189 | VLAN tagging | `egress_vlan`(180) |
| 190-199 | Final | `egress_final`(190) — **always last** |

### Choosing a Stage Number

1. Identify which existing modules your module should run **before** and **after**
2. Pick a stage number between them
3. If your module has dependencies, declare them with `RS_DEPENDS_ON()`
4. Stage numbers can be overridden in YAML profiles (the loader uses the profile value if specified)

---

## 7. Testing

### 7.1 Unit Tests with test_harness.h

```c
#include "../test/test_harness.h"

RS_TEST(test_my_filter_drops_invalid) {
    // Setup test context
    struct rs_ctx ctx = { .layers.saddr = 0x0A000001 };

    // Test your filtering logic
    int result = my_filter_logic(&ctx);

    RS_ASSERT_EQ(result, XDP_DROP);
    RS_ASSERT_EQ(ctx.drop_reason, RS_DROP_ACL_BLOCK);
}

RS_TEST(test_my_filter_passes_valid) {
    struct rs_ctx ctx = { .layers.saddr = 0xC0A80001 };
    int result = my_filter_logic(&ctx);
    RS_ASSERT_EQ(result, XDP_PASS);
}

int main() {
    RS_RUN_ALL_TESTS();
    return 0;
}
```

Available assertions:
- `RS_ASSERT_EQ(a, b)` — Assert equal
- `RS_ASSERT_NE(a, b)` — Assert not equal
- `RS_ASSERT_TRUE(cond)` — Assert condition true
- `RS_ASSERT_FALSE(cond)` — Assert condition false

### 7.2 Map Mocks with mock_maps.h

Test map-related logic in user-space without kernel map loading:

```c
#include "../test/mock_maps.h"

RS_TEST(test_flow_tracking) {
    // mock_maps.h provides simulated map operations
    struct flow_key key = { .src_ip = 0x0A000001 };
    struct flow_value val = { .packets = 0 };

    // Test your map update logic
    mock_map_update(&key, &val);
    struct flow_value *result = mock_map_lookup(&key);
    RS_ASSERT_TRUE(result != NULL);
}
```

---

## 8. Install and Deploy

### 8.1 Install Compiled Module

```bash
sudo make -f Makefile.module MODULE=my_filter install
```

Installs to `/usr/local/lib/rswitch/modules/my_filter.bpf.o`.

### 8.2 Package as .rsmod

```bash
rswitchctl pack-module ./my_filter.bpf.o
# Creates my_filter.rsmod
```

Install from package:
```bash
rswitchctl install-module my_filter.rsmod
```

List installed modules:
```bash
rswitchctl list-modules
```

### 8.3 Add to Profile

Include your module in a YAML profile:

```yaml
# Simple form (use module's built-in stage number)
modules:
  - my_filter

# Extended form (with overrides and config)
modules:
  - name: my_filter
    stage: 35                          # Override stage number
    optional: true                     # Don't fail if module not found
    condition: "interface:eth2"        # Only load if eth2 exists
    config:
      threshold: 1000
      mode: "strict"
```

### 8.4 Hot-Reload

Replace a running module without pipeline disruption:

```bash
rswitchctl reload my_filter              # Atomic swap
rswitchctl reload my_filter --dry-run    # Validate only
```

---

## 9. Available Built-in Modules

rSwitch ships with 27 BPF modules covering the full network stack:

| Category | Modules |
|----------|---------|
| **Core** (4) | `dispatcher`, `egress`, `egress_final`, `lastcall` |
| **L2 Switching** (6) | `vlan`, `egress_vlan`, `l2learn`, `stp`, `lacp`, `lldp` |
| **L3 Routing** (4) | `route` (ECMP/ARP), `conntrack`, `nat` (SNAT/DNAT), `flow_table` |
| **Security** (3) | `acl`, `source_guard`, `dhcp_snoop` |
| **QoS** (3) | `qos_classify`, `rate_limiter`, `egress_qos` |
| **Monitoring** (2) | `mirror` (SPAN/RSPAN/ERSPAN), `sflow` |
| **Tunneling** (1) | `tunnel` (VXLAN/GRE) |
| **Utility** (4) | `arp_learn`, `afxdp_redirect`, `core_example`, `veth_egress` |

For detailed descriptions, see [Platform Architecture — Module Classification](../../docs/development/Platform_Architecture.md#9-module-classification).

---

## 10. CLI Tools Reference

### Platform Management

| Command | Description |
|---------|-------------|
| `rswitchctl show-pipeline` | Display active pipeline modules and stages |
| `rswitchctl show-stats [--module <name>] [--json]` | Interface or per-module statistics |
| `rswitchctl show-abi` | Display ABI version and module compatibility |
| `rswitchctl show-profile <file> [--resolved]` | Display profile (with inheritance resolution) |
| `rswitchctl validate-profile <file> [--json]` | Validate profile without loading |
| `rswitchctl reload <module> [--dry-run]` | Hot-reload a module |
| `rswitchctl health [--json]` | System health check |

### Module Management

| Command | Description |
|---------|-------------|
| `rswitchctl new-module <name> --stage N --hook <ingress\|egress>` | Generate module from template |
| `rswitchctl pack-module <file.bpf.o>` | Package module as .rsmod |
| `rswitchctl install-module <file.rsmod>` | Install module from package |
| `rswitchctl list-modules` | List installed modules |

### Developer Tools

| Command | Description |
|---------|-------------|
| `rswitchctl dev inspect <module.bpf.o>` | Inspect module metadata (ABI, deps, maps, sections) |
| `rswitchctl dev maps` | List all pinned BPF maps with sizes |
| `rswitchctl dev dump-map <map_name>` | Dump map contents |
| `rswitchctl dev trace [--module <name>]` | Live packet trace through pipeline |
| `rswitchctl dev perf` | Per-module performance profiling |

### Configuration Management

| Command | Description |
|---------|-------------|
| `rswitchctl apply <profile> [--confirm N]` | Apply profile with auto-rollback timer |
| `rswitchctl confirm` | Confirm applied changes (cancel rollback timer) |
| `rswitchctl rollback` | Rollback to previous configuration |
| `rswitchctl snapshot-create [description]` | Create named configuration snapshot |
| `rswitchctl snapshot-list` | List available snapshots |

---

## 11. Further Reading

- [Platform Architecture](../../docs/development/Platform_Architecture.md) — Full platform design, module classification, and stage map
- [Module Developer Guide](../../docs/development/Module_Developer_Guide.md) — In-depth module development patterns
- [API Reference](../../docs/development/API_Reference.md) — Complete API documentation
- [CO-RE Guide](../../docs/development/CO-RE_Guide.md) — Cross-kernel portability patterns
- [Contributing](../../docs/development/Contributing.md) — How to contribute to rSwitch
