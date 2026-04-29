# CO-RE Portability Guide

**CO-RE (Compile Once - Run Everywhere)** enables rSwitch BPF modules compiled on one kernel version to run on any other kernel version (5.8+) without recompilation. This guide covers how CO-RE works, how to write CO-RE compliant modules, and how to deploy across kernel versions.

---

## Overview

### Traditional BPF vs CO-RE

| Aspect | Traditional | CO-RE |
|--------|------------|-------|
| **Headers** | Multiple `<linux/*.h>` files | Single `vmlinux.h` + helpers |
| **Portability** | Must recompile per kernel | Compile once, run everywhere |
| **Field access** | Direct struct access (breaks on layout changes) | BTF-aware relocation at load time |
| **Dependencies** | Kernel headers on build AND target | Kernel headers on build only; target needs BTF |
| **Binary size** | Larger (redundant type definitions) | 20-30% smaller |
| **Runtime overhead** | None | None (relocation happens at load time) |

### How It Works

1. **BTF (BPF Type Format)**: The kernel exports type information via `/sys/kernel/btf/vmlinux`
2. **vmlinux.h**: Generated from BTF, contains all kernel type definitions in one header
3. **libbpf relocation**: At load time, libbpf reads the target kernel's BTF and adjusts struct field offsets
4. **Feature detection**: `bpf_core_field_exists()` enables runtime adaptation to kernel capabilities

---

## System Requirements

### Kernel

- **Minimum**: Linux 5.8+
- **Required config**:
  ```
  CONFIG_DEBUG_INFO_BTF=y          # BTF support (required)
  CONFIG_DEBUG_INFO_BTF_MODULES=y  # Module BTF (optional)
  ```

### Verify BTF Support

```bash
# Check if BTF is available
ls /sys/kernel/btf/vmlinux

# Inspect BTF contents
bpftool btf dump file /sys/kernel/btf/vmlinux format c | head -20
```

### Build Tools

| Tool | Minimum Version | Purpose |
|------|-----------------|---------|
| bpftool | 5.8+ | Generate vmlinux.h |
| libbpf | 0.6+ | CO-RE relocation at load time |
| clang/LLVM | 10+ | BTF generation in compiled objects |

---

## Generating vmlinux.h

Before the first build (or after a kernel upgrade):

```bash
cd rswitch/
make vmlinux
```

This generates `bpf/include/vmlinux.h` from the running kernel's BTF. Notes:

- vmlinux.h is ~150,000 lines; it is in `.gitignore`
- Each development environment generates its own
- Only regenerate after kernel version changes

---

## Writing CO-RE Modules

### Header Includes

```c
// CO-RE way (correct)
#include "../include/rswitch_bpf.h"   // Includes vmlinux.h + all helpers

// Traditional way (do NOT use for new modules)
// #include <linux/if_ether.h>
// #include <linux/ip.h>
// #include <linux/tcp.h>
```

### Packet Access Helpers

`rswitch_bpf.h` provides CO-RE safe helpers for packet parsing:

```c
// Safe Ethernet header access
struct ethhdr *eth = get_ethhdr(ctx);
if (!eth) return XDP_DROP;

// Safe IPv4 header access
struct iphdr *iph = get_iphdr(ctx, l3_offset);
if (!iph) return XDP_DROP;

// Safe IPv6 header access
struct ipv6hdr *ip6h = get_ipv6hdr(ctx, l3_offset);

// Generic header access macro
struct tcphdr *tcp = GET_HEADER(ctx, l4_offset, struct tcphdr);
```

### CO-RE Field Access

For kernel structures that may change layout across versions:

```c
// CO-RE safe read (recommended for kernel structs)
__u64 tstamp;
bpf_core_read(&tstamp, sizeof(tstamp), &skb->tstamp);

// Macro shorthand
READ_KERN(dst, src);

// Direct access is safe for fixed-layout XDP structures
void *data = (void *)(long)ctx->data;       // OK — xdp_md is stable
void *data_end = (void *)(long)ctx->data_end;  // OK
```

### Runtime Feature Detection

Adapt to kernel capabilities at runtime:

```c
SEC("xdp")
int adaptive_module(struct xdp_md *ctx)
{
    // Check if a field exists in the running kernel
    if (bpf_core_field_exists(struct xdp_md, rx_queue_index)) {
        // Use rx_queue_index feature (kernel 5.18+)
        __u32 queue;
        bpf_core_read(&queue, sizeof(queue), &ctx->rx_queue_index);
        rs_debug("RX queue: %u", queue);
    } else {
        // Fallback for older kernels
        rs_debug("rx_queue_index not available");
    }

    return XDP_PASS;
}
```

### Field Existence and Size

```c
// Check if a struct field exists
if (FIELD_EXISTS(struct my_struct, my_field)) {
    // Field available — use it
}

// Get field size
size_t sz = FIELD_SIZE(struct iphdr, ihl);
```

### Bounds Checking

```c
// Verify pointer is within packet bounds
if (!CHECK_BOUNDS(ctx, ptr, size)) {
    return XDP_DROP;
}
```

---

## Offset Masking for Verifier Compliance

The BPF verifier requires provably bounded memory access. Use offset masks:

```c
// WRONG — verifier cannot prove offset is bounded
struct iphdr *iph = data + ctx->layers.l3_offset;

// CORRECT — mask constrains offset to a known range
struct iphdr *iph = data + (ctx->layers.l3_offset & RS_L3_OFFSET_MASK);
if ((void *)(iph + 1) > data_end)
    return XDP_DROP;
```

| Mask | Value | Maximum | Use |
|------|-------|---------|-----|
| `RS_L3_OFFSET_MASK` | `0x3F` | 63 bytes | L2 header offset |
| `RS_L4_OFFSET_MASK` | `0x7F` | 127 bytes | L3 header offset |
| `RS_PAYLOAD_MASK` | `0xFF` | 255 bytes | Full header stack |

---

## Cross-Kernel Deployment

Compiled `.bpf.o` files can be deployed to any machine with a compatible kernel:

```bash
# Build on development machine (kernel 5.15)
cd rswitch/
make vmlinux    # Generate vmlinux.h from local kernel
make            # Compile BPF objects

# Deploy to production server (kernel 6.1)
scp build/bpf/*.bpf.o server:/opt/rswitch/bpf/
ssh server "cd /opt/rswitch && sudo ./rswitch_loader --profile profiles/l2-simple-managed.yaml --ifaces eth0"
# libbpf automatically adapts struct layouts for kernel 6.1
```

**Requirements on the target machine:**
- Kernel 5.8+ with BTF enabled (`/sys/kernel/btf/vmlinux` must exist)
- libbpf installed
- NO kernel headers or vmlinux.h needed

---

## Migrating Existing Modules to CO-RE

### Step 1: Replace Headers

```diff
- #include <linux/if_ether.h>
- #include <linux/ip.h>
- #include <linux/tcp.h>
+ #include "../include/rswitch_bpf.h"
```

### Step 2: Update Field Access (if needed)

For `xdp_md` fields (stable layout), direct access is fine:
```c
void *data = (void *)(long)ctx->data;  // No change needed
```

For kernel internal structures that may change:
```diff
  struct sk_buff *skb = ...;
- __u64 tstamp = skb->tstamp;           // May break on kernel changes
+ __u64 tstamp;
+ bpf_core_read(&tstamp, sizeof(tstamp), &skb->tstamp);  // CO-RE safe
```

### Step 3: Add Feature Detection (optional)

```c
if (bpf_core_field_exists(struct xdp_md, rx_queue_index)) {
    // Use new feature
} else {
    // Fallback
}
```

### Step 4: Rebuild and Test

```bash
make vmlinux     # Regenerate vmlinux.h (if not already done)
make clean && make
sudo ./build/rswitch_loader --profile etc/profiles/l2-simple-managed.yaml --ifaces eth0 --verbose
```

---

## Current CO-RE Status

All rSwitch modules are CO-RE compatible and portable across kernel 5.8+:

| Component | CO-RE Status |
|-----------|-------------|
| `dispatcher.bpf.c` | Fully CO-RE |
| `egress.bpf.c` | Fully CO-RE |
| `vlan.bpf.c` | Fully CO-RE |
| `acl.bpf.c` | Fully CO-RE |
| `l2learn.bpf.c` | Fully CO-RE |
| `lastcall.bpf.c` | Fully CO-RE |
| `afxdp_redirect.bpf.c` | Fully CO-RE |
| `core_example.bpf.c` | Fully CO-RE (reference implementation) |
| `route.bpf.c` | Fully CO-RE |
| `mirror.bpf.c` | Fully CO-RE |
| `egress_vlan.bpf.c` | Fully CO-RE |
| `egress_qos.bpf.c` | Fully CO-RE |
| `egress_final.bpf.c` | Fully CO-RE |

---

## Performance Impact

| Phase | Impact | Notes |
|-------|--------|-------|
| Compile time | +10-20% | Processing vmlinux.h (~150K lines) |
| Load time | +5-10% | libbpf BTF relocation |
| **Runtime** | **0%** | Relocated code is identical to direct access |
| Binary size | -20-30% | Fewer redundant type definitions |

Use `ccache` to mitigate compile-time overhead:

```bash
sudo apt install ccache
export CC="ccache clang"
make
```

---

## Troubleshooting

### vmlinux.h generation fails

```bash
# Error: bpftool not found
sudo apt install linux-tools-$(uname -r)
# Or specify path explicitly:
make BPFTOOL=/usr/local/sbin/bpftool vmlinux
```

### BTF not available on target

```bash
# Error: /sys/kernel/btf/vmlinux not found
# Solution: Upgrade kernel to 5.8+ with CONFIG_DEBUG_INFO_BTF=y
# Or rebuild kernel with BTF enabled
```

### Relocation failure at load time

```bash
# Error: libbpf: failed to relocate field offset
# Cause: Field doesn't exist in target kernel
# Solution: Use bpf_core_field_exists() with fallback logic
```

### Compile time too slow

```bash
# vmlinux.h is ~150K lines — use ccache
sudo apt install ccache
export CC="ccache clang"
make clean && make
```

---

## Best Practices

1. **Always use `rswitch_bpf.h`** for new modules — never include individual `<linux/*.h>` headers
2. **Generate vmlinux.h once per environment** — add to `.gitignore`
3. **Use `bpf_core_field_exists()`** for kernel 5.18+ features that may not exist on older kernels
4. **Test on multiple kernels** — verify loading on at least 5.15, 6.1, and 6.6
5. **Document minimum kernel version** for any feature-gated code paths
6. **Use the `core_example.bpf.c` module** as a reference for CO-RE patterns

---

## References

- [BPF CO-RE Reference (Nakryiko)](https://nakryiko.com/posts/bpf-portability-and-co-re/)
- [libbpf CO-RE API](https://github.com/libbpf/libbpf)
- [BTF Specification](https://www.kernel.org/doc/html/latest/bpf/btf.html)
- [CO-RE Portability Patterns](../paperwork/CO-RE_Portability_Patterns.md) — rSwitch-specific deep dive

---

## See Also

- [Architecture.md](./Architecture.md) — System architecture overview
- [Module_Developer_Guide.md](./Module_Developer_Guide.md) — Module development tutorial
- [API_Reference.md](./API_Reference.md) — Complete API reference
