# eBPF Programming Best Practices for rSwitch

**Last Updated**: November 4, 2025  
**Author**: Lessons learned from PoC debugging and Week 2 deployment

---

## 🥇 The Golden Rule

> ### **"永远在访问内存之前进行边界检查"**
> ### **"ALWAYS check bounds BEFORE accessing memory"**

This is the **single most important rule** in eBPF programming. Violating it leads to verification failures that can be extremely difficult to debug.

---

## Why This Rule Matters

### The eBPF Verifier's Job
The verifier performs **static analysis** to prove your program is safe:
- No out-of-bounds memory access
- No infinite loops
- No null pointer dereferences
- All code paths terminate

**Key Insight**: Runtime checks don't help. The verifier needs **compile-time proof** of safety.

### What Happens When You Violate It

```c
// ❌ WRONG - Access first, check later
if (arr[i] == target) {     // Verifier error: potential out-of-bounds
    if (i < count)
        return 1;
}

// Error: "invalid access to map value, value_size=556 off=556 size=2"
```

Even if your runtime logic ensures `i < count`, the verifier analyzes all possible paths **statically** and sees a potential violation.

---

## Universal Patterns

### 1. Packet Header Validation

```c
// ✅ CORRECT Pattern
void *data = (void *)(long)ctx->data;
void *data_end = (void *)(long)ctx->data_end;

// Check BEFORE access
struct ethhdr *eth = data;
if ((void *)(eth + 1) > data_end)  // Bounds check FIRST
    return XDP_DROP;

// Now safe to access eth->h_proto, eth->h_dest, etc.
__u16 eth_proto = eth->h_proto;
```

**Why `(eth + 1)`?**
- Pointer arithmetic: `eth + 1` points to the byte *after* the struct
- Verifier sees: "accessing from `data` to `data + sizeof(struct ethhdr)`"
- This proves all fields within `struct ethhdr` are accessible

### 2. Array Access in Loops

```c
// ❌ WRONG - No bounds check before access
for (int i = 0; i < 128; i++) {
    if (arr[i] == target)  // Verifier: "What if arr has < 128 elements?"
        return 1;
}

// ✅ CORRECT - Check bounds BEFORE access
for (int i = 0; i < 128; i++) {
    if (i >= count)        // Bounds check FIRST
        break;
    if (arr[i] == target)  // Access SECOND
        return 1;
}

// ✅ EVEN BETTER - PoC proven pattern
for (int i = 0; i < 128; i++) {
    if (i == count)        // Early exit (verifier understands this better)
        break;
    if (arr[i] == target)  // Safe access
        return 1;
}
```

### 3. Map Value Dereference

```c
// ❌ WRONG - No null check
struct port_config *cfg = bpf_map_lookup_elem(&map, &key);
cfg->enabled = 1;  // Verifier error: cfg might be NULL!

// ✅ CORRECT - Check BEFORE access
struct port_config *cfg = bpf_map_lookup_elem(&map, &key);
if (!cfg)          // Null check FIRST
    return -1;
cfg->enabled = 1;  // Safe access SECOND
```

### 4. Nested Struct Access

```c
// ✅ CORRECT - Validate each level
struct outer *o = get_outer();
if (!o)                          // Check outer FIRST
    return -1;

if (o->inner_offset + sizeof(struct inner) > STRUCT_SIZE)  // Bounds check
    return -1;

struct inner *i = (void *)o + o->inner_offset;
// Now safe to access i->field
```

---

## rSwitch-Specific Applications

### Issue #6: VLAN Array Bounds (Week 2)

**Problem**: Loop accessing 128 elements, but array only has 64

```c
// ❌ WRONG - Verifier assumes worst case
for (int i = 0; i < RS_MAX_ALLOWED_VLANS; i++) {  // 128 iterations
    if (i >= count) break;
    if (untagged_vlans[i] == vlan) return 1;  // untagged_vlans[64]!
}
// Verifier: "404 + 128×2 = 660 > 556 (struct size)" ❌
```

**Solution**: Clamp count + early exit pattern

```c
// ✅ CORRECT - Prove bounds to verifier
__u16 count = port->untagged_vlan_count;
if (count > 64)      // Clamp to actual array size
    count = 64;

for (int i = 0; i < RS_MAX_ALLOWED_VLANS; i++) {
    if (i == count)  // Early exit BEFORE access
        break;
    if (untagged_vlans[i] == vlan)  // Safe: max 64 iterations
        return 1;
}
// Verifier: "404 + 64×2 = 532 < 556" ✅
```

### Dispatcher Lazy Parsing

```c
// ✅ CORRECT - Minimal validation
void *data = (void *)(long)ctx->data;
void *data_end = (void *)(long)ctx->data_end;

struct ethhdr *eth = data;
if ((void *)(eth + 1) > data_end)  // Check FIRST
    return XDP_DROP;

// Now safe to access eth->h_proto
__u16 proto = eth->h_proto;

// DON'T parse IP headers here - let modules do it (lazy parsing)
```

### L3 Header Parsing (In Modules)

```c
// ✅ CORRECT - Layered validation
struct iphdr *iph = data + sizeof(struct ethhdr);
if ((void *)(iph + 1) > data_end)  // Check IP header bounds
    return XDP_DROP;

// Now safe to access iph->protocol, iph->saddr, etc.
__u8 proto = iph->protocol;

// For L4 headers
struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);
if ((void *)(tcph + 1) > data_end)  // Check TCP header bounds
    return XDP_DROP;

// Now safe to access tcph->dest, tcph->source, etc.
```

---

## Common Pitfalls & Solutions

### Pitfall #1: Pointer Arithmetic Without Validation

```c
// ❌ WRONG
struct ethhdr *eth = data;
struct iphdr *iph = (void *)eth + sizeof(*eth);  // Unchecked!
__u32 saddr = iph->saddr;  // Verifier error!

// ✅ CORRECT
struct ethhdr *eth = data;
if ((void *)(eth + 1) > data_end)
    return XDP_DROP;

struct iphdr *iph = (void *)(eth + 1);
if ((void *)(iph + 1) > data_end)  // Check BEFORE access
    return XDP_DROP;
__u32 saddr = iph->saddr;  // Safe
```

### Pitfall #2: Variable-Length Headers (IPv6, TCP Options)

```c
// ❌ WRONG - Assuming fixed size
struct ipv6hdr *ip6h = data + sizeof(struct ethhdr);
struct tcphdr *tcph = (void *)ip6h + 40;  // IPv6 might have extension headers!

// ✅ CORRECT - Calculate actual header length
struct iphdr *iph = data + sizeof(struct ethhdr);
if ((void *)(iph + 1) > data_end)
    return XDP_DROP;

__u8 ihl = iph->ihl;
if (ihl < 5)  // Invalid IP header length
    return XDP_DROP;

void *l4 = (void *)iph + (ihl * 4);
if (l4 + sizeof(struct tcphdr) > data_end)
    return XDP_DROP;
```

### Pitfall #3: Loop Unrolling Failures

```c
// ❌ WRONG - Verifier can't unroll dynamic loops
for (int i = 0; i < dynamic_count; i++) {  // dynamic_count from config
    // ...
}

// ✅ CORRECT - Use fixed upper bound
#define MAX_ITERATIONS 128
for (int i = 0; i < MAX_ITERATIONS; i++) {
    if (i == actual_count)  // Early exit
        break;
    // ...
}
```

### Pitfall #4: Complex Control Flow

```c
// ❌ HARD FOR VERIFIER - Many nested conditions
if (condition1) {
    if (condition2) {
        if (condition3) {
            // Deep nesting confuses verifier
        }
    }
}

// ✅ BETTER - Early returns
if (!condition1)
    return XDP_DROP;
if (!condition2)
    return XDP_DROP;
if (!condition3)
    return XDP_DROP;
// Simpler control flow, easier for verifier
```

---

## Verifier-Friendly Coding Patterns

### 1. Use `#pragma unroll` for Small Fixed Loops

```c
#pragma unroll
for (int i = 0; i < 8; i++) {  // Small fixed count
    // Verifier can unroll this completely
}
```

### 2. Explicit Bounds for All Accesses

```c
// ✅ Make bounds explicit
if (offset + size > MAX_SIZE)
    return -1;

void *ptr = base + offset;
// Verifier knows: offset + size ≤ MAX_SIZE
```

### 3. Use `__builtin_memcpy` for Safe Copies

```c
// ✅ Verifier-friendly memory copy
__builtin_memcpy(dst, src, sizeof(*dst));
// Better than manual field-by-field copying
```

### 4. Const Propagation Helps

```c
// ✅ Verifier can optimize constant bounds
const int MAX = 64;
for (int i = 0; i < MAX; i++) {
    // Verifier: "loop bound is constant 64"
}
```

---

## Debugging Verification Failures

### Step 1: Enable Verbose Verifier Logs

```bash
# Load with verbose logging
sudo bpftool prog load obj.o /sys/fs/bpf/prog 2>&1 | tee verifier.log

# Or in code
libbpf_set_print(libbpf_print_fn);
```

### Step 2: Read the Error Message Carefully

```
184: (69) r5 = *(u16 *)(r2 +0)
invalid access to map value, value_size=556 off=556 size=2
R2 min value is outside of the allowed memory range
```

- **Line 184**: Instruction number
- **`*(u16 *)(r2 +0)`**: Reading 2 bytes from register r2
- **offset=556, size=2**: Trying to read at struct_end + 2 bytes
- **value_size=556**: Map value is 556 bytes total

### Step 3: Find the Corresponding Source Line

```bash
# Add debug info during compilation
clang -g -O2 -target bpf -c code.bpf.c -o code.bpf.o

# Match instruction to source
llvm-objdump -S code.bpf.o | grep -A 5 "instruction_184"
```

### Step 4: Check All Paths to That Line

The verifier analyzes **all possible execution paths**. Even if one path is safe, another might not be:

```c
if (condition) {
    i = 10;
} else {
    i = 200;  // Could be out of bounds!
}
arr[i] = val;  // Verifier: "i could be 200!"
```

---

## Testing Strategies

### 1. Start Simple

```c
// Test with minimal code first
SEC("xdp")
int test_prog(struct xdp_md *ctx) {
    return XDP_PASS;  // Does it load?
}

// Add complexity incrementally
// - Add Ethernet validation
// - Add IP parsing
// - Add business logic
```

### 2. Use `bpf_printk` for Debugging

```c
if ((void *)(eth + 1) > data_end) {
    bpf_printk("Packet too short: %lu bytes", data_end - data);
    return XDP_DROP;
}
```

### 3. Validate in User Space First

```c
// Test logic in user-space unit tests
bool is_vlan_allowed_userspace(uint16_t vlan, uint16_t *list, uint16_t count) {
    for (int i = 0; i < 128; i++) {
        if (i == count) break;
        if (list[i] == vlan) return true;
    }
    return false;
}
```

---

## Reference: rSwitch Proven Patterns

All patterns below have passed verifier in production:

### Pattern 1: PoC `is_in_list` (from `src/inc/defs.h`)

```c
static __always_inline int is_in_list(__u16 target, __u16 *arr, __u16 len)
{
    int i;
    for (i = 0; i < MAX_TRUNK_VLANS; i++) {  // Fixed bound
        if (i == len)     // Early exit BEFORE access
            break;
        if (arr[i] == target)  // Access AFTER check
            return 1;
    }
    return 0;
}
```

### Pattern 2: Dispatcher Lazy Parsing

```c
// Minimal validation in dispatcher
struct ethhdr *eth = data;
if ((void *)(eth + 1) > data_end)
    return XDP_DROP;

// Modules do full parsing when needed
if (!ctx->parsed) {
    if (rs_parse_packet_layers(xdp_ctx, &ctx->layers) < 0)
        return XDP_DROP;
    ctx->parsed = 1;
}
```

### Pattern 3: Map Lookup Safety

```c
struct rs_port_config *port = bpf_map_lookup_elem(&map, &ifindex);
if (!port)  // NULL check FIRST
    return XDP_DROP;

// Now safe to access port->fields
if (port->enabled) {
    // ...
}
```

---

## Summary Checklist

Before submitting eBPF code, verify:

- [ ] **All packet accesses**: `if (ptr + size > data_end) return XDP_DROP;`
- [ ] **All map lookups**: `if (!ptr) return XDP_DROP;`
- [ ] **All array accesses**: `if (i >= count) break;` BEFORE `arr[i]`
- [ ] **All pointer arithmetic**: Validate bounds after calculation
- [ ] **Loop bounds**: Use fixed constants, early exits
- [ ] **Struct field access**: Ensure offset + size < struct_size
- [ ] **Variable-length headers**: Calculate actual length, don't assume

**Remember**: The verifier is your friend. If it rejects your code, there's likely a real bug lurking.

---

## Additional Resources

- **Linux Kernel BPF Documentation**: `Documentation/bpf/`
- **eBPF Verifier Source**: `kernel/bpf/verifier.c`
- **libbpf Examples**: `tools/testing/selftests/bpf/`
- **rSwitch PoC**: `src/` directory (battle-tested patterns)

---

**Golden Rule Again** (because it's that important):

> ## **永远在访问内存之前进行边界检查**
> ## **ALWAYS CHECK BOUNDS BEFORE ACCESSING MEMORY**

This single principle will save you days of debugging time.

---

*Document created from: Week 2 deployment lessons learned*  
*Date: November 4, 2025*  
*Status: Living document - update as we learn more*
