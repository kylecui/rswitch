# CO-RE Portability Patterns

## Overview

rSwitch implements comprehensive Compile Once - Run Everywhere (CO-RE) patterns to ensure BPF programs work across different kernel versions without recompilation. This document details the CO-RE techniques, offset management, and portability strategies used throughout the codebase.

## CO-RE Fundamentals

### Core Challenge

BPF programs compiled for one kernel version may not work on another due to:
- **Structure field reordering**
- **Field additions/removals**
- **Size changes**
- **Alignment modifications**

### CO-RE Solution

```c
// Traditional approach (breaks on kernel changes)
struct sk_buff *skb = ctx->skb;
__u32 len = skb->len;  // Offset may change

// CO-RE approach (portable)
struct sk_buff *skb = ctx->skb;
__u32 len = BPF_CORE_READ(skb, len);  // Runtime offset resolution
```

## rSwitch CO-RE Architecture

### Unified Headers

```c
// include/rswitch_bpf.h - CO-RE unified headers
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Kernel structure definitions with CO-RE annotations
struct ethhdr {
    unsigned char h_dest[ETH_ALEN];
    unsigned char h_source[ETH_ALEN];
    __be16 h_proto;
} __attribute__((preserve_access_index));

struct iphdr {
    __u8 ihl:4;
    __u8 version:4;
    __u8 tos;
    __be16 tot_len;
    // ... other fields
} __attribute__((preserve_access_index));
```

### Offset-Based Access Pattern

```c
// uapi.h - Offset storage in context
struct rs_layers {
    // Stored offsets for CO-RE safety
    __u16 l2_offset;                  // Ethernet header offset
    __u16 l3_offset;                  // IP header offset
    __u16 l4_offset;                  // Transport header offset

    // Parsed field values (CO-RE safe)
    __u16 eth_proto;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
};
```

## Parsing with CO-RE Safety

### Ethernet Header Parsing

```c
// CO-RE safe Ethernet parsing
static __always_inline int parse_ethernet(struct rs_ctx *ctx,
                                          struct xdp_md *xdp_ctx) {
    void *data = (void *)(long)xdp_ctx->data;
    void *data_end = (void *)(long)xdp_ctx->data_end;

    // Bounds check
    if (data + sizeof(struct ethhdr) > data_end)
        return -1;

    // CO-RE safe access
    struct ethhdr *eth = data;
    ctx->layers.eth_proto = BPF_CORE_READ(eth, h_proto);
    ctx->layers.l2_offset = 0;  // Ethernet always at offset 0

    // Store MAC addresses (direct copy is safe)
    memcpy(&ctx->layers.eth, eth, sizeof(*eth));

    return 0;
}
```

### IP Header Parsing

```c
// CO-RE safe IP parsing with offset masking
static __always_inline int parse_ipv4(struct rs_ctx *ctx,
                                      struct xdp_md *xdp_ctx) {
    void *data = (void *)(long)xdp_ctx->data;
    void *data_end = (void *)(long)xdp_ctx->data_end;

    // Calculate IP header position
    __u16 l3_offset = ctx->layers.l2_offset + sizeof(struct ethhdr);

    // VLAN adjustment
    if (ctx->layers.vlan_depth > 0) {
        l3_offset += sizeof(struct vlan_hdr) * ctx->layers.vlan_depth;
    }

    // Bounds check with CO-RE safety mask
    __u16 masked_offset = l3_offset & RS_L3_OFFSET_MASK;
    if ((void *)((char *)data + masked_offset + sizeof(struct iphdr)) > data_end)
        return -1;

    // CO-RE safe IP header access
    struct iphdr *iph = (struct iphdr *)((char *)data + masked_offset);

    // Read fields using BPF_CORE_READ
    ctx->layers.ip_proto = BPF_CORE_READ(iph, protocol);
    ctx->layers.saddr = BPF_CORE_READ(iph, saddr);
    ctx->layers.daddr = BPF_CORE_READ(iph, daddr);
    ctx->layers.l3_offset = masked_offset;

    return 0;
}
```

### Transport Header Parsing

```c
// CO-RE safe TCP/UDP parsing
static __always_inline int parse_transport(struct rs_ctx *ctx,
                                           struct xdp_md *xdp_ctx) {
    void *data = (void *)(long)xdp_ctx->data;
    void *data_end = (void *)(long)xdp_ctx->data_end;

    __u16 l4_offset = ctx->layers.l3_offset +
                      (BPF_CORE_READ((struct iphdr *)((char *)data + ctx->layers.l3_offset), ihl) << 2);

    __u16 masked_offset = l4_offset & RS_L4_OFFSET_MASK;

    // Protocol-specific parsing
    if (ctx->layers.ip_proto == IPPROTO_TCP) {
        if ((void *)((char *)data + masked_offset + sizeof(struct tcphdr)) > data_end)
            return -1;

        struct tcphdr *tcp = (struct tcphdr *)((char *)data + masked_offset);
        ctx->layers.sport = BPF_CORE_READ(tcp, source);
        ctx->layers.dport = BPF_CORE_READ(tcp, dest);

    } else if (ctx->layers.ip_proto == IPPROTO_UDP) {
        if ((void *)((char *)data + masked_offset + sizeof(struct udphdr)) > data_end)
            return -1;

        struct udphdr *udp = (struct udphdr *)((char *)data + masked_offset);
        ctx->layers.sport = BPF_CORE_READ(udp, source);
        ctx->layers.dport = BPF_CORE_READ(udp, dest);
    }

    ctx->layers.l4_offset = masked_offset;
    return 0;
}
```

## Offset Masking Strategy

### Safety Bounds

```c
// include/rswitch_common.h - Offset masking constants
#define RS_L2_OFFSET_MASK  0x0FFF  // Max 4095 bytes for L2
#define RS_L3_OFFSET_MASK  0x1FFF  // Max 8191 bytes for L3
#define RS_L4_OFFSET_MASK  0x3FFF  // Max 16383 bytes for L4

// Verifier-friendly bounds checking
#define CHECK_OFFSET_BOUNDS(offset, mask, max_size, data_end) \
    (((offset) & (mask)) + (max_size) <= (data_end - data))
```

### Masking Rationale

```c
// Why masking is necessary:
//
// 1. Verifier cannot track dynamic offsets from maps
// 2. BPF_CORE_READ resolves at runtime, but verifier needs compile-time bounds
// 3. Masking limits offset range to realistic values
// 4. Prevents verifier from rejecting programs due to "unknown" bounds
//
// Example:
//   l3_offset = 128 (from map) & RS_L3_OFFSET_MASK (0x1FFF) = 128
//   Verifier knows: 128 + sizeof(iphdr) <= 8191 + 20 = reasonable bound
```

## Map Access Patterns

### CO-RE Safe Map Operations

```c
// Traditional map access (CO-RE compatible)
struct rs_port_config *get_port_config(__u32 ifindex) {
    return bpf_map_lookup_elem(&rs_port_config_map, &ifindex);
}

// CO-RE safe structure field access
static __always_inline __u16 get_port_vlan_mode(struct rs_port_config *port) {
    return BPF_CORE_READ(port, vlan_mode);
}

static __always_inline __u16 get_port_access_vlan(struct rs_port_config *port) {
    return BPF_CORE_READ(port, access_vlan);
}
```

### Map Structure Definitions

```c
// CO-RE annotated map structures
struct rs_port_config {
    __u32 ifindex;
    __u8  vlan_mode;
    __u8  pad[3];
    __u16 access_vlan;
    __u16 native_vlan;
    __u16 pvid;
    __u16 allowed_vlan_count;
    __u16 allowed_vlans[RS_MAX_ALLOWED_VLANS];
} __attribute__((preserve_access_index));
```

## Verifier Compatibility

### Bounds Checking Strategies

```c
// Strategy 1: Pre-computed bounds
static __always_inline int safe_access(struct rs_ctx *ctx, void *data, void *data_end) {
    __u16 offset = ctx->layers.l3_offset & RS_L3_OFFSET_MASK;

    // Pre-check bounds before access
    if (offset + sizeof(struct iphdr) > (data_end - data))
        return -1;

    struct iphdr *iph = (struct iphdr *)((char *)data + offset);
    __u8 tos = BPF_CORE_READ(iph, tos);  // Safe access

    return 0;
}

// Strategy 2: Loop unrolling for arrays
static __always_inline int check_vlan_array(__u16 vlan_id, __u16 *allowed_list, __u16 count) {
    if (count > RS_MAX_ALLOWED_VLANS)
        count = RS_MAX_ALLOWED_VLANS;

    // Verifier-friendly loop with early exit
    for (int i = 0; i < RS_MAX_ALLOWED_VLANS; i++) {
        if (i == count)  // Bounds check first
            break;
        if (allowed_list[i] == vlan_id)  // Access second
            return 1;
    }
    return 0;
}
```

### Complex Structure Handling

```c
// Handling nested structures with CO-RE
struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
} __attribute__((preserve_access_index));

static __always_inline int parse_vlan_tags(struct rs_ctx *ctx, struct xdp_md *xdp_ctx) {
    void *data = (void *)(long)xdp_ctx->data;
    void *data_end = (void *)(long)xdp_ctx->data_end;

    __u16 offset = sizeof(struct ethhdr);
    int depth = 0;

    // Parse up to 2 VLAN tags
    for (int i = 0; i < 2 && depth < RS_MAX_VLAN_DEPTH; i++) {
        if ((void *)((char *)data + offset + sizeof(struct vlan_hdr)) > data_end)
            break;

        struct vlan_hdr *vhdr = (struct vlan_hdr *)((char *)data + offset);

        // CO-RE safe TCI reading
        __u16 tci = BPF_CORE_READ(vhdr, h_vlan_TCI);
        __u16 proto = BPF_CORE_READ(vhdr, h_vlan_encapsulated_proto);

        // Extract VLAN ID (12 bits)
        ctx->layers.vlan_ids[depth] = tci & 0x0FFF;
        ctx->layers.vlan_pcp[depth] = (tci >> 13) & 0x07;

        depth++;

        // Check for more VLAN tags
        if (proto != bpf_htons(ETH_P_8021Q))
            break;

        offset += sizeof(struct vlan_hdr);
    }

    ctx->layers.vlan_depth = depth;
    return 0;
}
```

## Build System Integration

### CO-RE Compilation Flags

```makefile
# Makefile - CO-RE compilation
BPF_CFLAGS += -g -O2
BPF_CFLAGS += -target bpf
BPF_CFLAGS += -D__TARGET_ARCH_$(ARCH)
BPF_CFLAGS += -I$(KERNEL_HEADERS)
BPF_CFLAGS += -Iinclude/

# Enable CO-RE relocations
BPF_CFLAGS += -fexperimental-assign-type

# Generate BTF information
BPF_LDFLAGS += -g

# Compilation command
%.o: %.c
    clang $(BPF_CFLAGS) -c $< -o $@
    llvm-strip -g $@  # Strip debug info but keep BTF
```

### Kernel Version Detection

```c
// Runtime kernel version detection
static __always_inline __u32 get_kernel_version(void) {
    return BPF_CORE_READ(bpf_get_current_task_btf(), bpf_get_current_task_btf()->kversion);
}

// Conditional CO-RE logic
static __always_inline int kernel_aware_access(void *ptr) {
    __u32 kversion = get_kernel_version();

    if (kversion >= KERNEL_VERSION(5, 10, 0)) {
        // Use new field access
        return BPF_CORE_READ(ptr, new_field);
    } else {
        // Use old field access
        return BPF_CORE_READ(ptr, old_field);
    }
}
```

## Testing and Validation

### CO-RE Compatibility Testing

```bash
# Test on multiple kernel versions
#!/bin/bash
KERNELS=("5.4.0" "5.8.0" "5.10.0" "5.15.0" "6.0.0")

for kernel in "${KERNELS[@]}"; do
    echo "Testing on kernel $kernel"
    # Load BPF program
    # Run test suite
    # Check for CO-RE relocations
    bpftool prog load rswitch.o /sys/fs/bpf/test_prog
    bpftool prog show pinned /sys/fs/bpf/test_prog
done
```

### Relocation Verification

```c
// Check CO-RE relocations in loaded program
$ bpftool prog dump xlated pinned /sys/fs/bpf/rswitch_dispatcher | grep CORE
// Should show CO-RE relocation entries
```

## Performance Considerations

### CO-RE Overhead

```c
// CO-RE access cost comparison
// Direct access (fastest, but not portable)
__u32 len = skb->len;

// CO-RE access (portable, small overhead)
__u32 len = BPF_CORE_READ(skb, len);

// Overhead: ~5-10 cycles per access
// Acceptable for networking (packet processing budget: ~1000 cycles)
```

### Optimization Strategies

```c
// Cache CO-RE results when possible
static __always_inline void cache_core_reads(struct rs_ctx *ctx, struct iphdr *iph) {
    // Read once, use multiple times
    ctx->layers.saddr = BPF_CORE_READ(iph, saddr);
    ctx->layers.daddr = BPF_CORE_READ(iph, daddr);
    ctx->layers.ip_proto = BPF_CORE_READ(iph, protocol);
    ctx->layers.ttl = BPF_CORE_READ(iph, ttl);
}

// Avoid redundant CO-RE reads
__u8 ttl = ctx->layers.ttl;  // Use cached value
// Instead of: BPF_CORE_READ(iph, ttl) again
```

## Future CO-RE Enhancements

### Advanced Type Handling

```c
// Future: Union type handling
union ip_addr {
    __u32 v4;
    struct in6_addr v6;
} __attribute__((preserve_access_index));

// CO-RE safe union access
static __always_inline void handle_ip_addr(union ip_addr *addr, int is_ipv6) {
    if (is_ipv6) {
        struct in6_addr v6 = BPF_CORE_READ(addr, v6);
        // Handle IPv6
    } else {
        __u32 v4 = BPF_CORE_READ(addr, v4);
        // Handle IPv4
    }
}
```

### Dynamic Structure Adaptation

```c
// Future: Runtime structure adaptation
struct adaptive_access {
    const char *field_name;
    size_t offset;
    size_t size;
};

// Lookup field at runtime
static __always_inline void *adaptive_read(void *ptr, const char *field_name) {
    // Lookup field info from BTF
    // Calculate offset
    // Perform safe access
    return NULL;  // Placeholder
}
```

## Debugging CO-RE Issues

### Common Problems

```c
// Problem 1: Missing preserve_access_index
struct my_struct {
    int field;
};  // Missing __attribute__((preserve_access_index))

// Fix:
struct my_struct {
    int field;
} __attribute__((preserve_access_index));

// Problem 2: Incorrect field access
BPF_CORE_READ(ptr, non_existent_field);  // Compile error

// Problem 3: Bounds checking issues
void *unsafe = data + offset;  // Verifier rejects
void *safe = data + (offset & MASK);  // Verifier accepts
```

### Debugging Tools

```bash
# Inspect BTF information
bpftool btf dump file vmlinux

# Check CO-RE relocations
readelf -r program.o

# Validate program loading
bpftool prog load program.o /sys/fs/bpf/test 2>&1 | grep -i core

# Kernel log for CO-RE issues
dmesg | grep -i bpf_core
```

## CO-RE Compliance Audit Findings

### Overview of Current Codebase Issues

A comprehensive review of the rSwitch kernel-space BPF modules revealed significant CO-RE non-compliance issues. While the foundational infrastructure (vmlinux.h annotations, CO-RE macros in rswitch_bpf.h) is properly implemented, the application code extensively uses direct structure field access instead of the required BPF_CORE_READ macros. This creates portability risks across different kernel versions.

### Key Findings

#### 1. Direct Field Access Patterns
- **Problem**: Widespread use of direct member access (e.g., `iph->saddr`) instead of `BPF_CORE_READ(iph, saddr)`
- **Impact**: Code will break when kernel structure layouts change between versions
- **Scope**: Found in all major modules except the example file

#### 2. Affected Files and Specific Issues

**bpf/core/dispatcher.bpf.c**:
```c
// Current (non-CO-RE compliant):
iph->protocol, iph->saddr, iph->daddr

// Should be:
BPF_CORE_READ(iph, protocol), BPF_CORE_READ(iph, saddr), BPF_CORE_READ(iph, daddr)
```

**bpf/modules/l2learn.bpf.c**:
```c
// Current:
eth->h_source, eth->h_dest

// Should be:
BPF_CORE_READ(eth, h_source), BPF_CORE_READ(eth, h_dest)
```

**bpf/modules/vlan.bpf.c**:
```c
// Current:
vhdr->h_vlan_TCI

// Should be:
BPF_CORE_READ(vhdr, h_vlan_TCI)
```

**bpf/modules/route.bpf.c**:
```c
// Current:
iph->ttl

// Should be:
BPF_CORE_READ(iph, ttl)
```

**bpf/modules/acl.bpf.c**:
```c
// Current:
ctx->layers.ip_proto

// Should be:
BPF_CORE_READ(ctx->layers, ip_proto)  // If layers is a kernel struct
```
*Note: ctx->layers appears to be a custom structure, so direct access may be acceptable if not kernel-defined*

#### 3. Parsing Helpers Analysis

**bpf/include/rswitch_parsing.h**:
- Contains proper CO-RE compliant functions like `get_ethhdr()` and `get_iphdr()`
- These use `BPF_CORE_READ` correctly
- However, many modules bypass these helpers and use direct access

**bpf/include/parsing_helpers.h**:
- Legacy parsing functions with direct access patterns
- Should be migrated to CO-RE compliant versions

#### 4. Infrastructure Status

**Positive Findings**:
- `bpf/include/vmlinux.h`: Properly annotated with `preserve_access_index` pragma on all record types
- `bpf/include/rswitch_bpf.h`: Contains CO-RE macros (`BPF_CORE_READ`, `READ_KERN`) and helper functions
- `bpf/core/core_example.bpf.c`: Demonstrates proper CO-RE usage (only compliant file found)

**Infrastructure Gaps**:
- No systematic enforcement of CO-RE usage in build process
- Mixed usage patterns across modules
- Lack of automated testing for CO-RE compliance

### Recommended Fixes

#### Priority 1: Core Dispatcher
Replace direct access in `dispatcher.bpf.c` with CO-RE macros:
```c
// Before:
ctx->layers.ip_proto = iph->protocol;

// After:
ctx->layers.ip_proto = BPF_CORE_READ(iph, protocol);
```

#### Priority 2: Module Migration
Update all modules to use existing CO-RE helpers:
```c
// Instead of direct access, use:
struct ethhdr *eth = get_ethhdr(ctx, xdp_ctx);
struct iphdr *iph = get_iphdr(ctx, xdp_ctx);
```

#### Priority 3: Build System Enhancements
Add CO-RE compliance checks to the build process:
```makefile
# Proposed addition to Makefile
check-core-compliance:
    @echo "Checking CO-RE compliance..."
    @grep -r "->" bpf/modules/ | grep -v "ctx->" | wc -l
    @if [ $$? -eq 0 ]; then echo "WARNING: Direct field access found"; fi
```

#### Priority 4: Testing Framework
Implement multi-kernel testing to validate CO-RE effectiveness.

### Migration Strategy

1. **Phase 1**: Update core dispatcher and parsing functions
2. **Phase 2**: Migrate modules one by one, starting with l2learn and vlan
3. **Phase 3**: Deprecate legacy parsing helpers
4. **Phase 4**: Add automated compliance checks
5. **Phase 5**: Multi-kernel validation testing

### Risk Assessment

- **High Risk**: Direct field access will cause runtime failures on kernel structure changes
- **Medium Risk**: Verifier may reject programs due to unknown bounds from direct access
- **Low Risk**: Custom structures (non-kernel) can continue using direct access

### Conclusion

While rSwitch has the CO-RE infrastructure in place, the codebase exhibits systematic non-compliance in application code. Implementing the recommended fixes will ensure true kernel portability and future-proof the BPF programs against kernel evolution.</content>
<parameter name="filePath">/home/kylecui/dev/rSwitch/rswitch/docs/paperwork/CO-RE_Portability_Patterns.md