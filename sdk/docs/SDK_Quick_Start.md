# rSwitch SDK Quick Start

The rSwitch SDK lets you build and test standalone BPF modules without cloning the full development tree.

---

## 1. SDK Contents

```
sdk/
├── include/                      # Stable platform headers
│   ├── rswitch_module.h          # Single entry point (recommended)
│   ├── rswitch_abi.h             # ABI types, constants, struct definitions
│   ├── rswitch_helpers.h         # BPF helpers, packet parsing, pipeline macros
│   ├── rswitch_maps.h            # Shared map definitions (opt-in)
│   ├── rswitch_common.h          # Backward compat — includes everything
│   ├── rswitch_bpf.h             # Legacy helpers (prefer rswitch_helpers.h)
│   ├── module_abi.h              # Legacy ABI (prefer rswitch_abi.h)
│   ├── uapi.h                    # Legacy types (prefer rswitch_abi.h)
│   └── map_defs.h                # Legacy maps (prefer rswitch_maps.h)
├── templates/                    # Starter module implementations
│   ├── simple_module.bpf.c       # Minimal ingress module
│   ├── stateful_module.bpf.c     # Ingress module with private BPF map state
│   └── egress_module.bpf.c       # Egress pipeline module
├── Makefile.module               # Standalone build rules
├── rswitch.pc.in                 # pkg-config template
├── test/                         # Testing support
│   ├── test_harness.h            # Unit test framework (RS_TEST, RS_ASSERT_*)
│   └── mock_maps.h               # Map mocks for user-space testing
└── docs/
    └── SDK_Quick_Start.md        # This file
```

### Include Strategy

| Header | When to Use |
|--------|-------------|
| `rswitch_module.h` | **Default**: ABI types + helpers + pipeline macros. No shared maps. |
| `rswitch_maps.h` | **Opt-in**: Add when you need `rs_port_config_map`, `rs_stats_map`, `rs_mac_table`, etc. |
| `rswitch_common.h` | **Legacy**: Includes everything (module.h + maps.h). Use for backward compatibility only. |

---

## 2. Prerequisites

- **clang** (≥ 12) and **llvm** (for BPF target)
- **libbpf** headers and library
- **Linux kernel** with BTF support (`/sys/kernel/btf/vmlinux`)

If `include/vmlinux.h` is not present, generate it:

```bash
# Using the provided helper script (recommended)
sdk/scripts/generate_vmlinux.sh include/vmlinux.h

# Or manually
bpftool btf dump file /sys/kernel/btf/vmlinux format c > include/vmlinux.h
```

> **Migrating from legacy headers?** See the [SDK Migration Guide](SDK_Migration_Guide.md) for the complete header mapping and step-by-step migration instructions.

### Install SDK System-Wide (Optional)

If you want to build modules outside the rSwitch source tree:

```bash
# From the rswitch/ directory:
sudo make install-sdk

# Verify:
pkg-config --cflags rswitch
# Output: -I/usr/local/include/rswitch
```

This installs headers to `/usr/local/include/rswitch/`, pkg-config to `/usr/local/lib/pkgconfig/rswitch.pc`, and templates to `/usr/local/share/rswitch/templates/`.

---

## 3. Build Your First Module

This walkthrough builds a packet counter module from scratch using the installed SDK. The module counts packets per source IP and emits an event when a new source is seen.

### 3.1 Set Up

```bash
mkdir ~/my_rswitch_module && cd ~/my_rswitch_module

# Copy the simple template as a starting point
cp /usr/local/share/rswitch/templates/simple_module.bpf.c pkt_counter.bpf.c

# Copy the build rules
cp /usr/local/share/rswitch/Makefile.module Makefile.module
```

### 3.2 Write the Module

Replace the contents of `pkt_counter.bpf.c` with:

```c
// SPDX-License-Identifier: GPL-2.0
/*
 * pkt_counter — Counts packets per source IP, emits event on new source.
 *
 * Demonstrates:
 *   - User stage range (210)
 *   - Private BPF map
 *   - User event emission (RS_EVENT_USER_BASE)
 *   - Pipeline continuation (RS_TAIL_CALL_NEXT)
 */

#include "rswitch_module.h"

char _license[] SEC("license") = "GPL";

RS_DECLARE_MODULE(
    "pkt_counter",
    RS_HOOK_XDP_INGRESS,
    210,                                        /* User ingress stage (200-299) */
    RS_FLAG_NEED_L2L3_PARSE | RS_FLAG_CREATES_EVENTS,
    "Counts packets per source IP"
);

/* User event: new source IP seen */
#define PKT_COUNTER_EVENT_NEW_SRC  (RS_EVENT_USER_BASE + 0x01)  /* 0x1001 */

/* Private per-source-IP counter map */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);             /* Source IPv4 address */
    __type(value, __u64);           /* Packet count */
    __uint(max_entries, 16384);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_pkt_counter_map SEC(".maps");

/* Event structure for new-source notifications */
struct pkt_counter_event {
    __u16 type;
    __u16 len;
    __u32 src_ip;
    __u64 timestamp;
};

SEC("xdp")
int pkt_counter_func(struct xdp_md *xdp_ctx)
{
    struct rs_ctx *ctx = RS_GET_CTX();
    if (!ctx)
        return XDP_DROP;

    /* Only count IPv4 packets */
    if (!ctx->parsed || ctx->layers.eth_proto != __bpf_htons(0x0800))
        goto next;

    __u32 src_ip = ctx->layers.saddr;
    __u64 *count = bpf_map_lookup_elem(&rs_pkt_counter_map, &src_ip);

    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        /* New source IP — initialize counter and emit event */
        __u64 one = 1;
        bpf_map_update_elem(&rs_pkt_counter_map, &src_ip, &one, BPF_ANY);

        struct pkt_counter_event evt = {
            .type = PKT_COUNTER_EVENT_NEW_SRC,
            .len = sizeof(evt),
            .src_ip = src_ip,
            .timestamp = bpf_ktime_get_ns(),
        };
        RS_EMIT_EVENT(&evt, sizeof(evt));
    }

next:
    RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
    return XDP_DROP;
}
```

### 3.3 Build

```bash
make -f Makefile.module MODULE=pkt_counter
```

Expected output:
```
Built: pkt_counter.bpf.o
```

### 3.4 Verify Module Metadata

```bash
make -f Makefile.module MODULE=pkt_counter verify
```

This reads the `.rodata.mod` ELF section to confirm the module name, ABI version, stage, and flags are embedded correctly.

### 3.5 Inspect the Object (Optional)

```bash
# Check ELF sections
llvm-objdump -h pkt_counter.bpf.o

# You should see:
#   .rodata.mod  — module metadata (name, stage, flags)
#   .maps        — BPF map definitions (rs_pkt_counter_map)
#   xdp          — XDP program section
```

### 3.6 Install and Load

```bash
# Install the compiled module
sudo make -f Makefile.module MODULE=pkt_counter install
# Installs to: /usr/local/lib/rswitch/modules/pkt_counter.bpf.o

# Add to your rSwitch profile (YAML):
# modules:
#   - name: pkt_counter
#     stage: 210

# Or hot-reload into a running pipeline:
rswitchctl reload pkt_counter
```

### 3.7 Monitor

```bash
# Check module statistics
rswitchctl show-stats --module pkt_counter

# Dump the counter map
rswitchctl dev dump-map rs_pkt_counter_map

# Watch events
rswitchctl dev trace --module pkt_counter
```

---

## 4. Create a Module

### 4.1 From Template

```bash
cp templates/simple_module.bpf.c my_filter.bpf.c
```

Edit the file:
1. Update `RS_DECLARE_MODULE()` with your module's name, stage, flags, and description
2. Rename the XDP function
3. Add your packet processing logic
4. Optionally add dependencies with `RS_DEPENDS_ON()`

### 4.2 Using rswitchctl Scaffolding

If you have the full rSwitch installation, use the scaffolding CLI:

```bash
rswitchctl new-module my_filter --stage 210 --hook ingress --flags NEED_L2L3_PARSE,MAY_DROP
```

This generates a ready-to-build module source file.

### 4.3 Module Structure

Every rSwitch BPF module follows this structure:

```c
// SPDX-License-Identifier: GPL-2.0
#include "rswitch_module.h"

char _license[] SEC("license") = "GPL";

// 1. Module declaration (embedded in .rodata.mod ELF section)
RS_DECLARE_MODULE(
    "my_filter",                                    // Name (max 32 chars)
    RS_HOOK_XDP_INGRESS,                            // Hook point
    210,                                            // Stage number (user range: 200-299)
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

## 5. Build

```bash
make -f Makefile.module MODULE=my_filter
```

Output: `my_filter.bpf.o`

Verify module metadata:

```bash
make -f Makefile.module MODULE=my_filter verify
```

---

## 6. Key API Reference

### 6.1 Module Declaration

| Macro / Constant | Description |
|-------------------|-------------|
| `RS_DECLARE_MODULE(name, hook, stage, flags, desc)` | Declares module metadata in `.rodata.mod` section |
| `RS_HOOK_XDP_INGRESS` | Ingress pipeline hook |
| `RS_HOOK_XDP_EGRESS` | Egress pipeline hook |
| `RS_ABI_VERSION` | Current ABI version (v2.0 = `0x00020000`) |

### 6.2 Capability Flags

| Flag | Meaning |
|------|---------|
| `RS_FLAG_NEED_L2L3_PARSE` | Module requires parsed L2/L3 headers in `ctx->layers` |
| `RS_FLAG_NEED_VLAN_INFO` | Module requires VLAN information |
| `RS_FLAG_NEED_FLOW_INFO` | Module requires 5-tuple flow info (L4 ports, protocol) |
| `RS_FLAG_MODIFIES_PACKET` | Module may modify packet data |
| `RS_FLAG_MAY_DROP` | Module may drop packets |
| `RS_FLAG_CREATES_EVENTS` | Module generates events to `rs_event_bus` |
| `RS_FLAG_MAY_REDIRECT` | Module may redirect packets via `bpf_redirect_map` |

### 6.3 Context and Pipeline Macros

| Macro | Description |
|-------|-------------|
| `RS_GET_CTX()` | Returns per-packet `struct rs_ctx *` from per-CPU map |
| `RS_TAIL_CALL_NEXT(xdp_ctx, ctx)` | Continue ingress pipeline (auto-increments slot) |
| `RS_TAIL_CALL_EGRESS(xdp_ctx, ctx)` | Continue egress pipeline (reads next slot from `rs_prog_chain`) |
| `RS_EMIT_EVENT(event_ptr, size)` | Emit structured event to unified event bus |

### 6.4 Dependency Declaration

| Macro | Description |
|-------|-------------|
| `RS_DEPENDS_ON("mod1")` | Declare one dependency |
| `RS_DEPENDS_ON("mod1", "mod2")` | Declare two dependencies |
| `RS_DEPENDS_ON("mod1", "mod2", "mod3")` | Declare three dependencies |
| `RS_DEPENDS_ON("mod1", "mod2", "mod3", "mod4")` | Declare four dependencies (maximum) |

Dependencies are declared in `.rodata.moddep` section and resolved by the loader using topological sort.

### 6.5 API Stability Tiers

| Annotation | Guarantee |
|-----------|-----------|
| `RS_API_STABLE` | No breaking changes across minor versions |
| `RS_API_EXPERIMENTAL` | May change between minor versions |
| `RS_API_INTERNAL` | May change at any time; do not use in external modules |

All macros in sections 6.1–6.4 are **RS_API_STABLE**. See the [ABI Stability Policy](../../docs/development/ABI_POLICY.md) for version semantics and deprecation rules.

### 6.6 Per-CPU Context (`struct rs_ctx`)

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
| `action` | `__u8` | any | XDP_PASS / XDP_DROP / XDP_REDIRECT, etc. |
| `mirror` | `__u8` | mirror | 1 if mirror is required |
| `mirror_port` | `__u16` | mirror | Mirror destination port |
| `error` | `__u32` | any | `RS_ERROR_*` code |
| `drop_reason` | `__u32` | any | `RS_DROP_*` reason |
| `next_prog_id` | `__u32` | pipeline | Next module slot (managed by macros) |
| `call_depth` | `__u32` | pipeline | Recursion guard (max 32) |
| `reserved[16]` | `__u32[16]` | — | Reserved for future use (64 bytes, ABI v2) |

### 6.7 Parsed Layers (`struct rs_layers`)

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

### 6.8 Verifier-Safe Offset Masks

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

### 6.9 Module Configuration

> **Status**: Per-module `config:` in YAML profiles is planned for v2.1. The `rs_module_config_map` infrastructure exists in the BPF layer, but the loader does not yet parse `config:` sections from profile YAML. Until then, use the workarounds below.

#### Workaround 1: Direct BPF Map Updates (Recommended)

The `rs_module_config_map` is already pinned. You can populate it from user-space before or after loading:

```c
#include "rswitch_module.h"
#include "rswitch_maps.h"       /* Needed for rs_get_module_config */

// Read a config parameter set via user-space tool
struct rs_module_config_value *val = rs_get_module_config("my_filter", "threshold");
```

Populate from user-space with `bpftool`:

```bash
# Write a config value to the pinned map
bpftool map update pinned /sys/fs/bpf/rs_module_config_map \
    key <module_name_bytes> <param_name_bytes> \
    value <type_and_value_bytes>
```

Or use a companion user-space program to read a config file and populate the map at startup.

#### Workaround 2: Environment Variables via Systemd

For static configuration that doesn't change at runtime:

```ini
# /etc/rswitch/module-env.conf
MY_MODULE_THRESHOLD=1000
MY_MODULE_LOG_LEVEL=2
```

```ini
# In your module's systemd service
[Service]
EnvironmentFile=/etc/rswitch/module-env.conf
```

#### Workaround 3: Module-Specific Config Files

Create a user-space companion that reads a module-specific config and populates BPF maps:

```bash
# /etc/rswitch/modules/my_filter.conf
threshold = 1000
max_flows = 65536
```

This is the pattern used by production deployments (e.g., jz_sniff_rn) and is proven in the field.

#### Future: YAML Profile Config (v2.1)

When implemented, per-module config will work as follows:
if (val && val->type == 0 /* int */) {
    __s64 threshold = val->int_val;
    // Use threshold...
}
```

Profile YAML:
```yaml
modules:
  - name: my_filter
    stage: 210
    config:
      threshold: 1000
```

### 6.10 Per-Module Statistics

Track your module's processing statistics:

```c
#include "rswitch_module.h"
#include "rswitch_maps.h"       /* Needed for rs_module_stats_inc */

// Call at end of your module's processing
rs_module_stats_inc(ctx, RS_MODULE_STATS_PROCESSED);  // or FORWARDED, DROPPED, ERROR
```

Statistics are accessible via CLI:
```bash
rswitchctl show-stats --module my_filter
rswitchctl show-stats --module my_filter --json
```

### 6.11 Event Bus

Emit structured events to user-space:

```c
struct {
    __u16 type;
    __u16 len;
    __u32 src_ip;
    __u32 reason;
} my_event;

my_event.type = RS_EVENT_USER_BASE + 0x01;  /* User event range: 0x1000-0x7FFF */
my_event.len = sizeof(my_event);
my_event.src_ip = ctx->layers.saddr;
my_event.reason = 42;

RS_EMIT_EVENT(&my_event, sizeof(my_event));
```

Event type ranges (namespaced per function):
```
0x0000-0x0FFF  Core reserved (rSwitch internal)
0x1000-0x7FFF  User modules (RS_EVENT_USER_BASE to RS_EVENT_USER_MAX)
0x8000-0xFEFF  Reserved for future use
0xFF00-0xFFFF  Error events (core)
```

User modules MUST use event types in the `RS_EVENT_USER_BASE` (0x1000) to `RS_EVENT_USER_MAX` (0x7FFF) range. Define your events relative to `RS_EVENT_USER_BASE`:

```c
#define MY_EVENT_FOO  (RS_EVENT_USER_BASE + 0x01)  /* 0x1001 */
#define MY_EVENT_BAR  (RS_EVENT_USER_BASE + 0x02)  /* 0x1002 */
```

### 6.12 Shared Maps

Your module can access platform-wide shared maps by including `rswitch_maps.h`:

```c
#include "rswitch_module.h"
#include "rswitch_maps.h"
```

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

If your module does **not** need shared maps (e.g., it only inspects `ctx` fields and does its own processing), omit `rswitch_maps.h` to keep your BPF object lean.

---

## 7. Stage Number Conventions

Modules execute in ascending stage order (ingress) or descending slot order (egress). Choose your stage number based on where your module fits in the processing pipeline.

### Core Ingress Pipeline (Stages 10–99)

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

### Core Egress Pipeline (Stages 100–199)

| Range | Phase | Built-in Modules |
|-------|-------|------------------|
| 100-169 | Custom egress processing | — |
| 170-179 | QoS enforcement | `egress_qos`(170) |
| 180-189 | VLAN tagging | `egress_vlan`(180) |
| 190-199 | Final | `egress_final`(190) — **always last** |

### User Ingress Stages (200–299) ← Your Modules

| Range | Suggested Use |
|-------|---------------|
| 200-219 | User pre-processing (early filtering, classification) |
| 220-259 | User general processing (main module logic) |
| 260-289 | User post-processing (enrichment, annotation) |
| 290-299 | User final stages (logging, telemetry) |

### User Egress Stages (400–499) ← Your Modules

| Range | Suggested Use |
|-------|---------------|
| 400-419 | User pre-egress (egress filtering) |
| 420-469 | User general egress (rewriting, tagging) |
| 470-499 | User final egress (counters, mirroring) |

### Choosing a Stage Number

1. **External modules MUST use user ranges**: ingress 200-299, egress 400-499
2. Identify which existing modules your module should run **before** and **after**
3. Pick a stage number in the appropriate user sub-range
4. If your module has dependencies, declare them with `RS_DEPENDS_ON()`
5. Stage numbers can be overridden in YAML profiles (the loader uses the profile value if specified)

> **Why separate ranges?** Core stages (10-99, 100-199) are reserved for built-in rSwitch modules. Using user ranges (200-299, 400-499) guarantees your modules won't collide with current or future core modules.

---

## 8. Testing

### 8.1 Unit Tests with test_harness.h

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

### 8.2 Map Mocks with mock_maps.h

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

## 9. Install and Deploy

### 9.1 Install Compiled Module

```bash
sudo make -f Makefile.module MODULE=my_filter install
```

Installs to `/usr/local/lib/rswitch/modules/my_filter.bpf.o`.

### 9.2 Package as .rsmod

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

### 9.3 Add to Profile

Include your module in a YAML profile:

```yaml
# Simple form (use module's built-in stage number)
modules:
  - my_filter

# Extended form (with overrides and config)
modules:
  - name: my_filter
    stage: 210                         # Override stage number
    optional: true                     # Don't fail if module not found
    condition: "interface:eth2"        # Only load if eth2 exists
    config:
      threshold: 1000
      mode: "strict"
```

### 9.4 Hot-Reload

Replace a running module without pipeline disruption:

```bash
rswitchctl reload my_filter              # Atomic swap
rswitchctl reload my_filter --dry-run    # Validate only
```

---

## 10. Map Pinning Convention

All core rSwitch maps are pinned to the flat `/sys/fs/bpf/` directory via `LIBBPF_PIN_BY_NAME`. User modules should pin their private maps the same way — prefix map names with `rs_` or your module prefix to avoid collisions.

```c
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 16384);
    __uint(pinning, LIBBPF_PIN_BY_NAME);  /* Pins to /sys/fs/bpf/rs_my_map */
} rs_my_map SEC(".maps");
```

For details, see [Map Pinning Convention](../../docs/development/MAP_PINNING.md).

---

## 11. Available Built-in Modules

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

## 12. CLI Tools Reference

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

## 13. Loading Modules Without rs_loader

The default SDK workflow assumes modules are loaded by `rs_loader`, which resolves `extern` map references automatically at load time. If your project uses **standard libbpf APIs** (`bpf_object__open()` / `bpf_object__load()`) with its own loader, the `extern` pipeline map declarations in `rswitch_helpers.h` will cause load failures because libbpf cannot resolve them without explicit BTF-based map reuse setup.

### The `__RSWITCH_MAPS_H` Escape Hatch

`rswitch_helpers.h` guards its extern map declarations with `#ifndef __RSWITCH_MAPS_H`. Define this macro **before** including any rSwitch headers to suppress the externs, then provide your own concrete (non-extern) map definitions with `LIBBPF_PIN_BY_NAME` pinning.

### Step-by-Step

1. **Create a local map header** (e.g., `my_maps.h`):

```c
/* Suppress extern map declarations from rswitch_helpers.h */
#ifndef __RSWITCH_MAPS_H
#define __RSWITCH_MAPS_H
#endif

#include <rswitch_module.h>

/* Concrete (non-extern) pipeline map definitions.
 * These attach to the same pinned maps created by rSwitch core
 * via LIBBPF_PIN_BY_NAME. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rs_ctx);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_ctx_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, RS_MAX_PROGS);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_progs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, RS_MAX_PROGS);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_prog_chain SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_event_bus SEC(".maps");
```

2. **Include your map header first** in each BPF module:

```c
#include "my_maps.h"    /* Must come before rswitch_module.h */

SEC("xdp")
int my_module(struct xdp_md *ctx)
{
    struct rs_ctx *rs = RS_GET_CTX();
    if (!rs) return XDP_PASS;
    /* ... module logic ... */
    RS_TAIL_CALL_NEXT(ctx, rs);
    return XDP_PASS;
}
```

3. **Set the pin path** in your loader so libbpf finds the rSwitch core maps:

```c
struct bpf_object *obj = bpf_object__open(path);
/* Point to the rSwitch pinned map directory */
bpf_object__set_pin_maps_dir(obj, "/sys/fs/bpf");
bpf_object__load(obj);
```

### Important Notes

- Map type, key/value types, and `max_entries` **must exactly match** the core definitions in `rswitch_helpers.h` (lines 251-281). Mismatches will cause silent data corruption or load failures.
- All pipeline macros (`RS_GET_CTX`, `RS_TAIL_CALL_NEXT`, `RS_EMIT_EVENT`, etc.) continue to work normally — they reference maps by name, not by extern linkage.
- This pattern is used in production by [jz_sniff_rn](https://github.com/kylecui/jz_sniff_rn) (8 BPF modules loaded via custom `bpf_loader.c`).

---

## 14. Further Reading

- [ABI Stability Policy](../../docs/development/ABI_POLICY.md) — Version semantics, stability tiers, deprecation rules
- [Map Pinning Convention](../../docs/development/MAP_PINNING.md) — Map pin path standards
- [Platform Architecture](../../docs/development/Platform_Architecture.md) — Full platform design, module classification, and stage map
- [Module Developer Guide](../../docs/development/Module_Developer_Guide.md) — In-depth module development patterns
- [API Reference](../../docs/development/API_Reference.md) — Complete API documentation
- [CO-RE Guide](../../docs/development/CO-RE_Guide.md) — Cross-kernel portability patterns
- [Contributing](../../docs/development/Contributing.md) — How to contribute to rSwitch
