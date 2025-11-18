# BPF Verifier Offset Masking Pattern

## Problem

When accessing packet data using dynamic offsets loaded from BPF maps, the verifier cannot prove pointer safety:

```c
// ❌ FAILS: Verifier cannot prove l3_offset is within bounds
struct iphdr *iph = data + ctx->layers.l3_offset;
if ((void *)(iph + 1) > data_end)
    return XDP_DROP;
// Error: invalid access to packet, R9(id=4,off=8,r=0)
```

**Root Cause**: `l3_offset` is `__u16` (0-65535). Verifier sees the range as too large and cannot prove that `data + l3_offset` stays within packet bounds, even with subsequent bounds checking.

## Solution: Offset Masking

Apply a bitmask to limit the offset range to realistic values:

```c
// ✅ WORKS: Mask limits offset range, verifier can prove safety
struct iphdr *iph = data + (ctx->layers.l3_offset & RS_L3_OFFSET_MASK);
if ((void *)(iph + 1) > data_end)
    return XDP_DROP;
```

## Offset Masks

Defined in `bpf/core/uapi.h`:

```c
#define RS_L2_OFFSET_MASK  0x00   /* L2 always at offset 0 */
#define RS_L3_OFFSET_MASK  0x3F   /* Max 63 bytes: Eth(14) + QinQ(8) */
#define RS_L4_OFFSET_MASK  0x7F   /* Max 127 bytes: L2(22) + IPv4_max(60) */
#define RS_PAYLOAD_MASK    0xFF   /* Max 255 bytes: L2+L3+L4 headers */
```

### Rationale

**L3 Offset (0x3F = 63 bytes)**:
- Ethernet: 14 bytes
- Single VLAN: +4 bytes = 18 bytes
- QinQ (802.1ad): +4 bytes = 22 bytes
- Mask 0x3F covers up to 63 bytes (plenty of margin)

**L4 Offset (0x7F = 127 bytes)**:
- L2 max: 22 bytes
- IPv4 with max options: 60 bytes
- Total: 82 bytes
- Mask 0x7F covers up to 127 bytes

**Payload Offset (0xFF = 255 bytes)**:
- L2 max: 22 bytes
- L3 max: 60 bytes (IPv4 with options)
- TCP max: 60 bytes (with options)
- Total: 142 bytes
- Mask 0xFF covers up to 255 bytes

## Usage Pattern

### Accessing IP Header

```c
// Check if L3 has been parsed
if (!ctx->layers.l3_offset) {
    return XDP_PASS;  // Not an IP packet
}

// Reload data pointers (in case invalidated)
data = (void *)(long)xdp_ctx->data;
data_end = (void *)(long)xdp_ctx->data_end;

// Create pointer with masked offset
struct iphdr *iph = data + (ctx->layers.l3_offset & RS_L3_OFFSET_MASK);

// Bounds check
if ((void *)(iph + 1) > data_end) {
    return XDP_DROP;
}

// Now safe to access iph->ttl, iph->saddr, etc.
```

### Accessing TCP/UDP Header

```c
if (!ctx->layers.l4_offset) {
    return XDP_PASS;
}

data = (void *)(long)xdp_ctx->data;
data_end = (void *)(long)xdp_ctx->data_end;

struct tcphdr *tcp = data + (ctx->layers.l4_offset & RS_L4_OFFSET_MASK);
if ((void *)(tcp + 1) > data_end) {
    return XDP_DROP;
}

// Access tcp->source, tcp->dest, etc.
```

### Accessing Payload

```c
if (!ctx->layers.payload_offset) {
    return XDP_PASS;
}

data = (void *)(long)xdp_ctx->data;
data_end = (void *)(long)xdp_ctx->data_end;

void *payload = data + (ctx->layers.payload_offset & RS_PAYLOAD_MASK);
if (payload + MIN_PAYLOAD_SIZE > data_end) {
    return XDP_DROP;
}

// Access payload data
```

## Why This Works

1. **Range Limitation**: Masking reduces the offset range from 0-65535 to 0-63 (for L3), which the verifier can reason about.

2. **Verifier Logic**: After the mask, verifier knows:
   - `l3_offset & 0x3F` is in range [0, 63]
   - `data + [0, 63]` stays within reasonable bounds
   - If `(data + 63 + 20) < data_end`, then access is safe

3. **Pointer Tracking**: The verifier can establish a relationship between the masked offset and the final pointer, allowing it to track validity across the bounds check.

## Common Pitfalls

### ❌ Don't: Check before masking

```c
// Verifier still sees l3_offset as 0-65535
if (data + ctx->layers.l3_offset + sizeof(struct iphdr) > data_end)
    return XDP_DROP;
struct iphdr *iph = data + ctx->layers.l3_offset;  // FAILS
```

### ❌ Don't: Mask after pointer creation

```c
struct iphdr *iph = data + ctx->layers.l3_offset;  // Verifier rejects here
iph = (struct iphdr *)((unsigned long)iph & 0x3F);  // Too late
```

### ✅ Do: Mask when creating pointer

```c
struct iphdr *iph = data + (ctx->layers.l3_offset & RS_L3_OFFSET_MASK);
if ((void *)(iph + 1) > data_end)
    return XDP_DROP;
```

## References

- **Linux Kernel BPF Verifier**: `kernel/bpf/verifier.c`
- **Cilium BPF Guide**: https://docs.cilium.io/en/stable/bpf/
- **BPF Pointer Arithmetic**: https://www.kernel.org/doc/html/latest/bpf/verifier.html

## Discovery

This pattern was discovered during Route module development when the verifier consistently rejected pointer arithmetic with map-derived offsets, even with correct bounds checking. The solution emerged from understanding that the verifier requires compile-time provable range constraints on offsets.

**Credit**: Discovered through systematic debugging of verifier rejection messages and analysis of successful patterns in other BPF programs.
