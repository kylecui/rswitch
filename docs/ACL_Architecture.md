# ACL Module - Multi-Level Index Architecture

## Overview

The rSwitch ACL module implements a **production-grade, scalable packet filtering system** using multi-level indexing to avoid the performance limitations of linear rule iteration.

### Design Principle

> **"No loops, only lookups"** - Replace O(N) linear search with O(1) hash and O(log N) LPM lookups

## Architecture

### Problem with Traditional Approach

The initial ACL implementation used a loop to iterate through rules:

```c
#pragma unroll
for (__u32 i = 0; i < 64; i++) {  // PROBLEM: Limited to 64 rules, O(N) complexity
    if (match_rule(rule[i], packet)) {
        return rule[i].action;
    }
}
```

**Limitations:**
- Maximum 64 rules (verifier constraint on loop bounds)
- O(N) complexity - performance degrades with rule count
- Sequential matching - no parallelism

### New Multi-Level Design

Instead, we use **three-level indexed lookup**:

```
┌────────────────────────────────────────────────┐
│  Packet arrives (L3/L4 parsed by dispatcher)  │
└──────────────────┬─────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────┐
│  Level 1: 5-Tuple Exact Match (HASH)            │
│  Key: {proto, src_ip, dst_ip, sport, dport}     │
│  Complexity: O(1)                                │
│  Priority: HIGHEST                               │
└──────┬───────────────────────────────────────────┘
       │ Miss
       ▼
┌──────────────────────────────────────────────────┐
│  Level 2a: Source IP Prefix Match (LPM TRIE)    │
│  Key: {prefixlen, src_ip}                        │
│  Complexity: O(log N)                            │
│  Priority: MEDIUM                                │
└──────┬───────────────────────────────────────────┘
       │ Miss
       ▼
┌──────────────────────────────────────────────────┐
│  Level 2b: Dest IP Prefix Match (LPM TRIE)      │
│  Key: {prefixlen, dst_ip}                        │
│  Complexity: O(log N)                            │
│  Priority: MEDIUM                                │
└──────┬───────────────────────────────────────────┘
       │ Miss
       ▼
┌──────────────────────────────────────────────────┐
│  Level 3: Default Policy                         │
│  Action: PASS or DROP (configurable)             │
│  Priority: LOWEST                                │
└──────────────────────────────────────────────────┘
```

## BPF Map Definitions

### Level 1: 5-Tuple Exact Match

```c
struct acl_5tuple_key {
    __u8  proto;           // IPPROTO_TCP, IPPROTO_UDP, etc.
    __u8  pad[3];
    __u32 src_ip;          // Network byte order
    __u32 dst_ip;
    __u16 sport;           // Network byte order
    __u16 dport;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct acl_5tuple_key);
    __type(value, struct acl_result);
    __uint(max_entries, 65536);  // Scales to thousands of rules
} acl_5tuple_map;
```

**Use case:** Block specific connections
- SSH from attacker IP to server: `tcp 10.1.2.3:* → 192.168.1.100:22`
- HTTPS to malicious site: `tcp *:* → 203.0.113.5:443`

### Level 2: LPM Prefix Match

```c
struct acl_lpm_key {
    __u32 prefixlen;       // In bits (e.g., 24 for /24)
    __u32 ip;              // Network byte order
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct acl_lpm_key);
    __type(value, struct acl_result);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 16384);
} acl_lpm_src_map;  // Separate map for dest with acl_lpm_dst_map
```

**Use case:** Block entire subnets
- Block attacker network: `10.0.0.0/8 → * (any dest)`
- Allow management subnet: `* → 192.168.100.0/24`

**Why separate src/dst maps?**
- Longest prefix match operates on single IP
- Need independent lookups for src and dst prefixes
- Enables rules like "block 10.0.0.0/8 → any" separately from "allow any → 192.168.0.0/16"

### Action Result

```c
struct acl_result {
    __u8 action;           // ACL_ACTION_PASS, DROP, REDIRECT
    __u8 log_event;        // Emit event to ringbuf
    __u16 redirect_ifindex; // Target for REDIRECT action (0 = AF_XDP)
    __u32 stats_id;        // Statistics counter ID (future use)
};
```

## Processing Flow

### Main ACL Function

```c
SEC("xdp")
int acl_filter(struct xdp_md *xdp_ctx)
{
    struct rs_ctx *ctx = RS_GET_CTX();
    
    /* Build 5-tuple key from parsed context */
    struct acl_5tuple_key key = {
        .proto = ctx->layers.ip_proto,
        .src_ip = ctx->layers.saddr,
        .dst_ip = ctx->layers.daddr,
        .sport = ctx->layers.sport,
        .dport = ctx->layers.dport,
    };
    
    /* Level 1: 5-tuple lookup */
    result = bpf_map_lookup_elem(&acl_5tuple_map, &key);
    if (result) {
        return apply_action(result);  // O(1) - FAST PATH
    }
    
    /* Level 2a: Source prefix lookup */
    struct acl_lpm_key lpm_key = { .prefixlen = 32, .ip = ctx->layers.saddr };
    result = bpf_map_lookup_elem(&acl_lpm_src_map, &lpm_key);
    if (result) {
        return apply_action(result);  // O(log N) - PREFIX MATCH
    }
    
    /* Level 2b: Dest prefix lookup */
    lpm_key.ip = ctx->layers.daddr;
    result = bpf_map_lookup_elem(&acl_lpm_dst_map, &lpm_key);
    if (result) {
        return apply_action(result);
    }
    
    /* Level 3: Default policy */
    return (cfg->default_action == DROP) ? XDP_DROP : XDP_PASS;
}
```

**Key points:**
- No loops, only 3-4 map lookups maximum
- Early exit on first match (priority order)
- Uses pre-parsed packet data from `rs_ctx->layers` (verified in Phase 0)

## Control Plane - rsaclctl

### Add 5-Tuple Rule

```bash
# Block SSH from specific attacker
sudo rsaclctl add-5t \
    --proto tcp \
    --src 10.1.2.3 \
    --dst 192.168.1.100 \
    --dport 22 \
    --action drop \
    --log

# Block any traffic from attacker to web server
sudo rsaclctl add-5t \
    --proto tcp \
    --src 10.10.10.10 \
    --dst 192.168.1.80 \
    --dport 443 \
    --action drop
```

### Add LPM Prefix Rule

```bash
# Block entire attacker network (source)
sudo rsaclctl add-lpm-src \
    --prefix 10.0.0.0/8 \
    --action drop \
    --log

# Allow traffic to management subnet (destination)
sudo rsaclctl add-lpm-dst \
    --prefix 192.168.100.0/24 \
    --action pass
```

### Configuration

```bash
# Set default policy
sudo rsaclctl set-default --action pass

# Enable/disable ACL processing
sudo rsaclctl enable
sudo rsaclctl disable

# List all rules
sudo rsaclctl list

# Show statistics
sudo rsaclctl stats

# Clear all rules
sudo rsaclctl clear
```

## Statistics

Per-CPU counters track ACL performance:

```c
enum acl_stat_type {
    ACL_STAT_5TUPLE_HIT = 0,    // Level 1 matches
    ACL_STAT_LPM_SRC_HIT = 1,   // Level 2a matches
    ACL_STAT_LPM_DST_HIT = 2,   // Level 2b matches
    ACL_STAT_DEFAULT_PASS = 3,  // Default allow
    ACL_STAT_DEFAULT_DROP = 4,  // Default deny
    ACL_STAT_TOTAL_DROPS = 5,   // Total dropped packets
};
```

Example output:

```
ACL Statistics:
───────────────────────────────────────
  5-tuple hits        : 1523
  LPM src hits        : 42
  LPM dst hits        : 8
  Default PASS        : 95432
  Default DROP        : 0
  Total drops         : 1565
───────────────────────────────────────
```

**Analysis:**
- Most traffic matches Level 1 (fast path) or default policy
- LPM lookups used for subnet-level filtering
- Low total drops → mostly legitimate traffic

## Testing

### Run Test Script

```bash
cd rswitch/user/tools
./test_acl.sh
```

This will:
1. Clear existing rules
2. Set default PASS
3. Add example 5-tuple and LPM rules
4. Enable ACL
5. Show rule list
6. Guide you through traffic testing

### Manual Testing

```bash
# Terminal 1: Monitor ACL decisions
sudo cat /sys/kernel/debug/tracing/trace_pipe | grep ACL

# Terminal 2: Send test traffic
ping 192.168.1.1  # Watch for "ACL: default PASS" or "ACL: DROP"

# Terminal 3: Check statistics
sudo rsaclctl stats
```

## Performance Comparison

| Approach | Complexity | Max Rules | Verifier-Friendly | Scalable |
|----------|-----------|-----------|-------------------|----------|
| **Linear Loop** | O(N) | 64 | ❌ (unroll limit) | ❌ |
| **Hash (5-tuple)** | O(1) | 65536 | ✅ | ✅ |
| **LPM Trie** | O(log N) | 16384 | ✅ | ✅ |
| **Multi-Level** | O(1) best, O(log N) worst | 65536+ | ✅ | ✅ |

**Benchmark (estimated):**
- Linear (64 rules): ~640 ns/packet (10 ns × 64 iterations)
- Multi-level: ~30 ns/packet (3 lookups × 10 ns)
- **Speedup: 21x faster**

## Future Extensions

### Port Range Compilation

Instead of runtime range checks, compile port ranges to bucket arrays:

```c
// Control plane compiles "1024-65535" to bucket array
__u8 port_buckets[256];  // port >> 8
port_buckets[4..255] = 1;  // Ports 1024-65535

// Data plane lookup
__u8 bucket = dport >> 8;
if (port_buckets[bucket]) {
    // Port in range, apply action
}
```

### IPv6 Support

Separate maps with 128-bit addresses:

```c
struct acl_5tuple_key_v6 {
    __u8 proto;
    __u8 pad[3];
    __u32 src_ip[4];  // 128-bit address
    __u32 dst_ip[4];
    __u16 sport;
    __u16 dport;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct acl_5tuple_key_v6);
    __type(value, struct acl_result);
} acl_5tuple_v6_map;
```

### VLAN Isolation

Map-of-maps for per-VLAN ACL policies:

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __type(key, __u16);  // VLAN ID
    __type(value, __u32);  // Inner map FD
} acl_vlan_policy;

// Lookup: vlan_map = acl_vlan_policy[vlan_id]
//         result = vlan_map[5tuple_key]
```

### Hot Reload with Shadow Maps

1. Create shadow map with new rules
2. Atomic switch via map-of-maps
3. Zero packet loss during update

```c
// Current active map
acl_5tuple_active → map_fd_A

// Load new rules to shadow
acl_5tuple_shadow → map_fd_B (new rules)

// Atomic swap
acl_5tuple_active → map_fd_B (now active)
```

## Verification

### Debug Logging

ACL module emits debug messages for verification:

```
ACL: 5-tuple hit
ACL: DROP packet proto=6 10.1.2.3:54321 -> 192.168.1.100:22

ACL: LPM src hit
ACL: DROP packet proto=1 10.5.6.7:0 -> 192.168.1.1:0

ACL: default PASS
```

### Integration with Phase 0

ACL relies on L3/L4 parsing from dispatcher:

```c
struct rs_ctx {
    struct {
        __u32 saddr, daddr;     // Parsed by dispatcher
        __u16 sport, dport;     // Extracted from TCP/UDP headers
        __u8 ip_proto;          // IPPROTO_TCP, IPPROTO_UDP, etc.
        __u16 eth_proto;        // 0x0800 for IPv4
    } layers;
};
```

**Verified in Phase 0:**
- ✅ IPv4 addresses: `10.174.29.155 -> 10.174.29.254`
- ✅ Protocol: `proto=1 (ICMP), proto=6 (TCP), proto=17 (UDP)`
- ✅ Ports: `sport=443, dport=63646` (TCP/UDP)
- ✅ DSCP: Extracted from TOS field

## Summary

The multi-level ACL architecture solves the scalability problem through:

1. **Hash-based exact matching** (O(1)) for specific flows
2. **LPM tries** (O(log N)) for prefix-based filtering
3. **No linear iteration** - eliminates 64-rule verifier limit
4. **Composable policies** - mix exact + prefix + default
5. **Production-ready** - tested, documented, tooling complete

**Key Innovation:** Transform ACL from "iterate and match" to "index and lookup".
