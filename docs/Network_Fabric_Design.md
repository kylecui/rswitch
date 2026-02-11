# Network Fabric Design

## Executive Summary

**Network Fabric** is the next evolution of rSwitch's reconfigurable architecture, enabling **fine-grained, SDN-like flow control** across the data plane. While the current reconfigurable architecture allows composing processing pipelines from modules, Network Fabric adds the ability to programmatically define **flow-level policies** — matching specific traffic patterns and applying custom actions at line rate.

**Key Capabilities**:
- OpenFlow-style flow tables with match/action rules
- Per-flow QoS policies (bandwidth, priority, marking)
- Traffic engineering with explicit path selection
- Multi-switch orchestration for campus/datacenter fabrics
- Intent-based networking abstractions

---

## Motivation

### Current State: Module-Level Reconfigurability

Today, rSwitch provides **coarse-grained** control:

```
Profile → Modules → Pipeline
         (vlan, acl, route, ...)
```

Operators select which modules run, but **within each module**, behavior is largely fixed or controlled by simple per-port configuration.

### Desired State: Flow-Level Reconfigurability

Network Fabric adds a **finer grain**:

```
Profile → Modules → Pipeline
              ↓
         Flow Tables → Per-Flow Actions
                       (match, meter, forward, mark, ...)
```

This enables scenarios like:
- "Route HTTP traffic through the firewall, but bypass for internal subnets"
- "Rate-limit video streaming to 100Mbps per user"
- "Mirror all DNS traffic to the security appliance"
- "Prefer path A for latency-sensitive traffic, path B for bulk transfers"

---

## Architecture Overview

### High-Level Design

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              USER SPACE                                          │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ┌────────────────────────────────────────────────────────────────────────────┐ │
│  │                         FABRIC CONTROLLER                                   │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌───────────────┐  │ │
│  │  │   Intent     │  │    Flow      │  │   Topology   │  │    Path       │  │ │
│  │  │   Engine     │──│   Compiler   │──│   Manager    │──│   Calculator  │  │ │
│  │  └──────────────┘  └──────┬───────┘  └──────────────┘  └───────────────┘  │ │
│  └───────────────────────────┼────────────────────────────────────────────────┘ │
│                              │                                                   │
│                              ▼                                                   │
│  ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐          │
│  │  Profile YAML    │───▶│  rswitch_loader  │───▶│   Fabric Agent   │          │
│  │  fabric.yaml     │    │  (orchestrator)  │    │  (flow pusher)   │          │
│  └──────────────────┘    └────────┬─────────┘    └────────┬─────────┘          │
│                                   │                       │                     │
│            ┌──────────────────────┼───────────────────────┼─────────┐           │
│            │      BPF Maps (pinned in /sys/fs/bpf)                  │           │
│            │  rs_flow_table, rs_meters, rs_groups, rs_actions, ...  │           │
│            └──────────────────────┼───────────────────────┼─────────┘           │
│                                   │                       │                     │
├───────────────────────────────────┼───────────────────────┼─────────────────────┤
│                              KERNEL SPACE                                        │
├───────────────────────────────────┼───────────────────────┼─────────────────────┤
│                                   ▼                       ▼                     │
│  ┌─────────────────────────────────────────────────────────────────────────────┐│
│  │                     XDP INGRESS PIPELINE + FLOW ENGINE                      ││
│  │  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐  ││
│  │  │dispatcher│──▶│  parse   │──▶│ flow_lkp │──▶│ actions  │──▶│ lastcall │  ││
│  │  │ (entry)  │   │ stage=10 │   │ stage=25 │   │ stage=26 │   │ stage=90 │  ││
│  │  └──────────┘   └──────────┘   └────┬─────┘   └──────────┘   └──────────┘  ││
│  │                                      │                                       ││
│  │                              ┌───────▼───────┐                              ││
│  │                              │ rs_flow_table │                              ││
│  │                              │  (BPF hash)   │                              ││
│  │                              └───────────────┘                              ││
│  └─────────────────────────────────────────────────────────────────────────────┘│
│                                                                                  │
└──────────────────────────────────────────────────────────────────────────────────┘
```

### Component Responsibilities

| Component | Location | Responsibility |
|-----------|----------|----------------|
| **Intent Engine** | User-space | Translates high-level policies to flow rules |
| **Flow Compiler** | User-space | Optimizes and validates flow rule sets |
| **Topology Manager** | User-space | Maintains fabric topology graph |
| **Path Calculator** | User-space | Computes optimal paths for traffic classes |
| **Fabric Agent** | User-space | Pushes compiled flows to BPF maps |
| **flow_lkp module** | BPF | Performs flow table lookups |
| **actions module** | BPF | Executes match actions (meter, mark, forward) |

---

## Flow Table Design

### OpenFlow-Inspired Model

Network Fabric adopts an **OpenFlow-inspired** model with key simplifications for XDP performance:

```
┌─────────────────────────────────────────────────────────────────┐
│                         FLOW TABLE                               │
├─────────────────────────────────────────────────────────────────┤
│  Priority │    Match Fields      │   Actions   │  Counters     │
├───────────┼──────────────────────┼─────────────┼───────────────┤
│   1000    │  dst_ip=10.0.0.0/8   │  fwd:port2  │  pkts: 1.2M   │
│    900    │  tcp_dport=443       │  meter:1,   │  pkts: 500K   │
│           │                      │  fwd:port3  │               │
│    800    │  src_mac=AA:BB:*     │  drop       │  pkts: 1234   │
│      1    │  * (default)         │  fwd:normal │  pkts: 10M    │
└───────────┴──────────────────────┴─────────────┴───────────────┘
```

### Match Fields (Supported)

| Layer | Field | Size | Notes |
|-------|-------|------|-------|
| L2 | `in_port` | 32-bit | Ingress interface index |
| L2 | `eth_src` | 48-bit | Source MAC (with mask) |
| L2 | `eth_dst` | 48-bit | Destination MAC (with mask) |
| L2 | `eth_type` | 16-bit | Ethertype |
| L2 | `vlan_id` | 12-bit | VLAN ID (0 = no tag) |
| L2 | `vlan_pcp` | 3-bit | VLAN priority |
| L3 | `ip_src` | 32-bit | Source IPv4 (with mask) |
| L3 | `ip_dst` | 32-bit | Destination IPv4 (with mask) |
| L3 | `ip_proto` | 8-bit | IP protocol number |
| L3 | `ip_dscp` | 6-bit | DSCP value |
| L4 | `tcp_src` | 16-bit | TCP source port |
| L4 | `tcp_dst` | 16-bit | TCP destination port |
| L4 | `udp_src` | 16-bit | UDP source port |
| L4 | `udp_dst` | 16-bit | UDP destination port |
| L4 | `tcp_flags` | 8-bit | TCP flags (SYN, ACK, etc.) |

### Actions (Supported)

| Action | Parameters | Description |
|--------|------------|-------------|
| `output` | `port` | Forward to specific port |
| `output_group` | `group_id` | Forward to port group (multicast/ECMP) |
| `drop` | — | Discard packet |
| `controller` | `reason` | Send to user-space (AF_XDP) |
| `set_vlan` | `vlan_id` | Set/modify VLAN tag |
| `pop_vlan` | — | Remove VLAN tag |
| `push_vlan` | `vlan_id` | Add VLAN tag |
| `set_queue` | `queue_id` | Assign to QoS queue |
| `set_dscp` | `dscp` | Mark DSCP value |
| `meter` | `meter_id` | Apply metering (rate limit) |
| `mirror` | `port` | Copy to mirror port |
| `goto_table` | `table_id` | Jump to another flow table |

### Data Structures

```c
/* Flow match key - used for hash table lookup */
struct rs_flow_key {
    __u32 in_port;              /* Ingress interface */
    __u8  eth_src[6];           /* Source MAC */
    __u8  eth_dst[6];           /* Destination MAC */
    __u16 eth_type;             /* Ethertype */
    __u16 vlan_id;              /* VLAN ID */
    __be32 ip_src;              /* Source IP */
    __be32 ip_dst;              /* Destination IP */
    __u8  ip_proto;             /* IP protocol */
    __u8  ip_dscp;              /* DSCP */
    __be16 l4_src;              /* L4 source port */
    __be16 l4_dst;              /* L4 destination port */
    __u8  tcp_flags;            /* TCP flags */
    __u8  pad[3];
} __attribute__((packed));

/* Flow match mask - which fields to match */
struct rs_flow_mask {
    __u32 in_port_mask;
    __u8  eth_src_mask[6];
    __u8  eth_dst_mask[6];
    __u16 eth_type_mask;
    __u16 vlan_id_mask;
    __be32 ip_src_mask;
    __be32 ip_dst_mask;
    __u8  ip_proto_mask;
    __u8  ip_dscp_mask;
    __be16 l4_src_mask;
    __be16 l4_dst_mask;
    __u8  tcp_flags_mask;
    __u8  pad[3];
} __attribute__((packed));

/* Flow entry value - actions and metadata */
struct rs_flow_entry {
    __u16 priority;             /* Higher = more specific */
    __u16 action_count;         /* Number of actions */
    __u32 actions[8];           /* Encoded action list */
    __u32 meter_id;             /* Meter reference (0 = none) */
    __u32 group_id;             /* Group reference (0 = none) */
    __u64 packet_count;         /* Hit counter */
    __u64 byte_count;           /* Byte counter */
    __u64 last_hit;             /* Timestamp of last hit */
    __u32 idle_timeout;         /* Seconds until idle expiry (0 = no timeout) */
    __u32 hard_timeout;         /* Seconds until forced expiry (0 = no timeout) */
    __u64 install_time;         /* When rule was installed */
} __attribute__((packed));

/* Encoded action format (fits in 32 bits) */
#define RS_ACTION_OUTPUT        0x01
#define RS_ACTION_DROP          0x02
#define RS_ACTION_CONTROLLER    0x03
#define RS_ACTION_SET_VLAN      0x04
#define RS_ACTION_POP_VLAN      0x05
#define RS_ACTION_PUSH_VLAN     0x06
#define RS_ACTION_SET_QUEUE     0x07
#define RS_ACTION_SET_DSCP      0x08
#define RS_ACTION_METER         0x09
#define RS_ACTION_MIRROR        0x0A
#define RS_ACTION_GOTO_TABLE    0x0B
#define RS_ACTION_GROUP         0x0C

/* Action encoding: [type:8][reserved:8][param:16] */
#define RS_ENCODE_ACTION(type, param) (((type) << 24) | ((param) & 0xFFFF))
#define RS_ACTION_TYPE(action)  (((action) >> 24) & 0xFF)
#define RS_ACTION_PARAM(action) ((action) & 0xFFFF)
```

### BPF Maps

```c
/* Primary flow table - exact match */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct rs_flow_key);
    __type(value, struct rs_flow_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_flow_table SEC(".maps");

/* Wildcard flow table - uses LPM for IP prefix matching */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 8192);
    __type(key, struct rs_lpm_key);
    __type(value, struct rs_flow_entry);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_flow_table_lpm SEC(".maps");

/* Meter table for rate limiting */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);  /* meter_id */
    __type(value, struct rs_meter);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_meters SEC(".maps");

/* Group table for multicast/ECMP */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);  /* group_id */
    __type(value, struct rs_group);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_groups SEC(".maps");
```

---

## Flow Lookup Module

### Module: `flow_lkp.bpf.c`

```c
// bpf/modules/flow_lkp.bpf.c

#include "rswitch_bpf.h"
#include "flow_defs.h"

RS_DECLARE_MODULE(
    "flow_lkp",
    RS_HOOK_XDP_INGRESS,
    25,  /* After parsing, before ACL */
    RS_FLAG_NEED_L2L3_PARSE,
    "Flow table lookup and action execution"
);

SEC("xdp")
int flow_lkp_main(struct xdp_md *xdp)
{
    struct rs_ctx *ctx = RS_GET_CTX();
    if (!ctx) return XDP_PASS;
    
    /* Build flow key from parsed headers */
    struct rs_flow_key key = {
        .in_port = ctx->ifindex,
        .eth_type = ctx->layers.eth_proto,
        .vlan_id = ctx->ingress_vlan,
        .ip_src = ctx->layers.saddr,
        .ip_dst = ctx->layers.daddr,
        .ip_proto = ctx->layers.ip_proto,
        .l4_src = ctx->layers.sport,
        .l4_dst = ctx->layers.dport,
    };
    /* Copy MAC addresses */
    __builtin_memcpy(key.eth_src, /* source MAC */, 6);
    __builtin_memcpy(key.eth_dst, /* dest MAC */, 6);
    
    /* Exact match lookup first */
    struct rs_flow_entry *flow = bpf_map_lookup_elem(&rs_flow_table, &key);
    
    if (!flow) {
        /* Try LPM lookup for wildcard rules */
        struct rs_lpm_key lpm_key = {
            .prefixlen = 32,
            .ip_dst = ctx->layers.daddr,
        };
        flow = bpf_map_lookup_elem(&rs_flow_table_lpm, &lpm_key);
    }
    
    if (flow) {
        /* Update counters */
        __sync_fetch_and_add(&flow->packet_count, 1);
        __sync_fetch_and_add(&flow->byte_count, /* pkt_len */);
        flow->last_hit = bpf_ktime_get_ns();
        
        /* Store flow pointer in ctx for action module */
        ctx->flow_entry = flow;  /* New field in rs_ctx */
        ctx->next_prog_id++;     /* Skip to action module */
    }
    
    RS_TAIL_CALL_NEXT(xdp, ctx);
    return XDP_PASS;
}
```

### Module: `flow_actions.bpf.c`

```c
// bpf/modules/flow_actions.bpf.c

RS_DECLARE_MODULE(
    "flow_actions",
    RS_HOOK_XDP_INGRESS,
    26,  /* Immediately after flow_lkp */
    RS_FLAG_MODIFIES_PACKET,
    "Execute flow actions"
);

SEC("xdp")
int flow_actions_main(struct xdp_md *xdp)
{
    struct rs_ctx *ctx = RS_GET_CTX();
    if (!ctx || !ctx->flow_entry) 
        goto next;
    
    struct rs_flow_entry *flow = ctx->flow_entry;
    
    /* Execute each action in order */
    #pragma unroll
    for (int i = 0; i < 8 && i < flow->action_count; i++) {
        __u32 action = flow->actions[i];
        __u8 type = RS_ACTION_TYPE(action);
        __u16 param = RS_ACTION_PARAM(action);
        
        switch (type) {
        case RS_ACTION_OUTPUT:
            ctx->egress_ifindex = param;
            ctx->action = XDP_REDIRECT;
            break;
            
        case RS_ACTION_DROP:
            return XDP_DROP;
            
        case RS_ACTION_SET_VLAN:
            ctx->egress_vlan = param;
            break;
            
        case RS_ACTION_SET_QUEUE:
            ctx->prio = param & 0x7;
            break;
            
        case RS_ACTION_SET_DSCP:
            ctx->dscp = param & 0x3F;
            ctx->modified = 1;
            break;
            
        case RS_ACTION_METER:
            if (apply_meter(ctx, param) < 0)
                return XDP_DROP;  /* Rate exceeded */
            break;
            
        case RS_ACTION_MIRROR:
            ctx->mirror = 1;
            ctx->mirror_port = param;
            break;
            
        case RS_ACTION_CONTROLLER:
            /* Redirect to AF_XDP socket */
            ctx->action = XDP_REDIRECT;
            ctx->egress_ifindex = RS_CONTROLLER_PORT;
            break;
        }
    }
    
next:
    RS_TAIL_CALL_NEXT(xdp, ctx);
    return XDP_PASS;
}
```

---

## Metering (Rate Limiting)

### Token Bucket Algorithm

Network Fabric implements **Two-Rate Three-Color Marker (trTCM)** metering for fine-grained rate control:

```
                    ┌─────────────────┐
                    │   Token Bucket  │
                    │                 │
     Tokens fill    │  ┌───────────┐  │    Packet arrives
     at CIR rate    │  │  Tokens   │  │◀───────────────────
         │          │  │   (Tc)    │  │
         ▼          │  └───────────┘  │
    ┌────────┐      │                 │      ┌─────────────┐
    │ Refill │─────▶│  If tokens >= │──────▶│ GREEN (pass)│
    └────────┘      │  packet_size   │       └─────────────┘
                    │                 │
                    │  If tokens <   │       ┌─────────────┐
                    │  packet_size   │──────▶│ RED (drop)  │
                    └─────────────────┘       └─────────────┘
```

### Meter Data Structure

```c
/* Meter configuration and state */
struct rs_meter {
    /* Configuration (set by controller) */
    __u32 meter_id;
    __u64 cir;                  /* Committed Information Rate (bytes/sec) */
    __u64 cbs;                  /* Committed Burst Size (bytes) */
    __u64 pir;                  /* Peak Information Rate (bytes/sec) */
    __u64 pbs;                  /* Peak Burst Size (bytes) */
    
    /* Runtime state (updated by BPF) */
    __u64 tokens_c;             /* Current committed tokens */
    __u64 tokens_p;             /* Current peak tokens */
    __u64 last_update;          /* Last token refill time */
    
    /* Statistics */
    __u64 green_packets;
    __u64 yellow_packets;
    __u64 red_packets;
    __u64 green_bytes;
    __u64 yellow_bytes;
    __u64 red_bytes;
};

/* Token bucket update (called per-packet) */
static __always_inline int apply_meter(struct rs_ctx *ctx, __u32 meter_id)
{
    struct rs_meter *meter = bpf_map_lookup_elem(&rs_meters, &meter_id);
    if (!meter)
        return 0;  /* No meter = pass */
    
    __u64 now = bpf_ktime_get_ns();
    __u64 elapsed = now - meter->last_update;
    __u32 pkt_len = /* packet length */;
    
    /* Refill tokens based on elapsed time */
    __u64 new_tokens_c = meter->tokens_c + (meter->cir * elapsed / 1000000000ULL);
    if (new_tokens_c > meter->cbs)
        new_tokens_c = meter->cbs;
    
    /* Check if packet fits */
    if (new_tokens_c >= pkt_len) {
        meter->tokens_c = new_tokens_c - pkt_len;
        meter->last_update = now;
        meter->green_packets++;
        meter->green_bytes += pkt_len;
        return 0;  /* GREEN - pass */
    }
    
    /* Rate exceeded */
    meter->red_packets++;
    meter->red_bytes += pkt_len;
    return -1;  /* RED - drop */
}
```

---

## Group Tables (Multicast/ECMP)

### Group Types

| Type | Use Case | Behavior |
|------|----------|----------|
| `ALL` | Multicast/broadcast | Send to all ports in group |
| `SELECT` | ECMP load balancing | Hash-based selection |
| `INDIRECT` | Abstraction | Single bucket reference |
| `FAST_FAILOVER` | Redundancy | First live port wins |

### Data Structure

```c
/* Port bucket within a group */
struct rs_bucket {
    __u32 port;                 /* Output port ifindex */
    __u32 weight;               /* For weighted ECMP */
    __u8  watch_port;           /* Port to monitor for liveness */
    __u8  active;               /* 0=down, 1=up */
    __u16 reserved;
};

#define RS_MAX_BUCKETS 16

/* Group entry */
struct rs_group {
    __u32 group_id;
    __u8  type;                 /* GROUP_ALL, GROUP_SELECT, etc. */
    __u8  bucket_count;
    __u16 reserved;
    struct rs_bucket buckets[RS_MAX_BUCKETS];
};

#define RS_GROUP_ALL            0x01
#define RS_GROUP_SELECT         0x02
#define RS_GROUP_INDIRECT       0x03
#define RS_GROUP_FAST_FAILOVER  0x04
```

### ECMP Implementation

```c
static __always_inline __u32 select_ecmp_port(struct rs_ctx *ctx, struct rs_group *group)
{
    /* Compute 5-tuple hash for consistent hashing */
    __u32 hash = jhash_3words(
        ctx->layers.saddr,
        ctx->layers.daddr,
        (ctx->layers.sport << 16) | ctx->layers.dport,
        0  /* seed */
    );
    
    /* Weighted selection */
    __u32 total_weight = 0;
    #pragma unroll
    for (int i = 0; i < RS_MAX_BUCKETS && i < group->bucket_count; i++) {
        if (group->buckets[i].active)
            total_weight += group->buckets[i].weight;
    }
    
    if (total_weight == 0)
        return 0;  /* No active ports */
    
    __u32 target = hash % total_weight;
    __u32 cumulative = 0;
    
    #pragma unroll
    for (int i = 0; i < RS_MAX_BUCKETS && i < group->bucket_count; i++) {
        if (!group->buckets[i].active)
            continue;
        cumulative += group->buckets[i].weight;
        if (target < cumulative)
            return group->buckets[i].port;
    }
    
    return group->buckets[0].port;  /* Fallback */
}
```

---

## Traffic Engineering

### Path Selection Model

Network Fabric supports **explicit path selection** for traffic engineering:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         TRAFFIC ENGINEERING                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   Traffic Class        Path Constraint           Selected Path               │
│   ─────────────        ───────────────           ─────────────               │
│   VoIP (DSCP=46)       Latency < 5ms             A → B → D (direct)         │
│   Video (DSCP=34)      Bandwidth > 1Gbps         A → C → E → D (10G link)   │
│   Bulk (DSCP=0)        Cost-optimized            A → F → G → D (cheapest)   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Path Table Structure

```c
/* Traffic class definition */
struct rs_traffic_class {
    __u8  tc_id;                /* Traffic class ID (0-7) */
    __u8  dscp_match;           /* DSCP value to match */
    __u8  dscp_mask;            /* DSCP mask */
    __u8  prio;                 /* Queue priority */
    __u32 min_bandwidth;        /* Minimum guaranteed bandwidth (Kbps) */
    __u32 max_bandwidth;        /* Maximum allowed bandwidth (Kbps) */
    __u32 path_group;           /* Group ID for path selection */
};

/* Segment routing path (simplified) */
struct rs_sr_path {
    __u32 path_id;
    __u8  hop_count;
    __u8  reserved[3];
    __u32 hops[8];              /* Next-hop ifindex for each segment */
};
```

---

## Multi-Switch Orchestration

### Fabric Topology

For multi-switch deployments, Network Fabric maintains a **centralized topology view**:

```
                        ┌─────────────────────────┐
                        │    Fabric Controller    │
                        │  (Topology + Paths)     │
                        └───────────┬─────────────┘
                                    │ gRPC/REST
               ┌────────────────────┼────────────────────┐
               │                    │                    │
               ▼                    ▼                    ▼
        ┌─────────────┐      ┌─────────────┐      ┌─────────────┐
        │  rSwitch-1  │──────│  rSwitch-2  │──────│  rSwitch-3  │
        │  (Leaf)     │      │  (Spine)    │      │  (Leaf)     │
        └─────────────┘      └─────────────┘      └─────────────┘
               │                                         │
        ┌──────┴──────┐                           ┌──────┴──────┐
        │   Hosts     │                           │   Hosts     │
        └─────────────┘                           └─────────────┘
```

### Topology Discovery Protocol

```yaml
# Fabric topology configuration (fabric.yaml)
fabric:
  name: "datacenter-pod-1"
  controller: "10.0.0.1:6653"
  
switches:
  - id: "rswitch-1"
    role: leaf
    datapath_id: "0x0001"
    ports:
      - name: eth0
        peer: "rswitch-2:eth1"  # Uplink to spine
      - name: eth1
        role: host             # Downlink to hosts
        
  - id: "rswitch-2"
    role: spine
    datapath_id: "0x0002"
    ports:
      - name: eth1
        peer: "rswitch-1:eth0"
      - name: eth2
        peer: "rswitch-3:eth0"
        
  - id: "rswitch-3"
    role: leaf
    datapath_id: "0x0003"
    ports:
      - name: eth0
        peer: "rswitch-2:eth2"
      - name: eth1
        role: host
```

### Flow Synchronization

The Fabric Controller pushes flows to individual switches via a **Fabric Agent** daemon:

```
┌──────────────────────────────────────────────────────────────────────┐
│                    FLOW SYNCHRONIZATION PROTOCOL                      │
├──────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  Controller                          Switch                           │
│      │                                  │                             │
│      │──── FlowMod(ADD, flow_1) ───────▶│                            │
│      │                                  │──── Update rs_flow_table   │
│      │◀─── FlowModAck(OK) ─────────────│                             │
│      │                                  │                             │
│      │──── FlowMod(MODIFY, flow_2) ────▶│                            │
│      │                                  │──── Update rs_flow_table   │
│      │◀─── FlowModAck(OK) ─────────────│                             │
│      │                                  │                             │
│      │──── BarrierRequest ─────────────▶│                            │
│      │                                  │──── Flush pending          │
│      │◀─── BarrierReply ───────────────│                             │
│                                                                       │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Intent-Based Networking

### High-Level Abstractions

Network Fabric provides **intent-based** abstractions that compile down to flow rules:

```yaml
# Intent example: "Isolate finance department traffic"
intents:
  - name: "finance-isolation"
    type: segmentation
    spec:
      segment: "finance"
      endpoints:
        - subnet: "10.1.0.0/16"
        - vlan: 100
      policy:
        internal: allow
        external: deny
        exceptions:
          - dst: "10.255.0.1"  # Allow access to shared printer
            action: allow

# This compiles to flow rules:
# 1. ALLOW: src=10.1.0.0/16, dst=10.1.0.0/16 → forward (internal)
# 2. ALLOW: src=10.1.0.0/16, dst=10.255.0.1 → forward (exception)
# 3. DENY: src=10.1.0.0/16, dst=* → drop (external default)
```

### Intent Types

| Intent | Description | Compiles To |
|--------|-------------|-------------|
| `segmentation` | Network isolation | ACL flows with deny-by-default |
| `qos-policy` | Traffic prioritization | Meter + DSCP marking rules |
| `load-balance` | Distribute across backends | Group with SELECT type |
| `path-preference` | Traffic engineering | Group with explicit next-hops |
| `mirror` | Traffic visibility | Mirror action rules |
| `rate-limit` | Bandwidth control | Meter rules |

### Intent Compiler

```python
# User-space intent compiler (simplified)

class IntentCompiler:
    def compile_segmentation(self, intent):
        flows = []
        segment = intent['spec']['segment']
        endpoints = intent['spec']['endpoints']
        
        # Allow internal traffic
        for ep in endpoints:
            for other_ep in endpoints:
                flows.append(FlowRule(
                    match={'ip_src': ep, 'ip_dst': other_ep},
                    actions=[Action.FORWARD_NORMAL],
                    priority=1000
                ))
        
        # Allow exceptions
        for exc in intent['spec']['policy'].get('exceptions', []):
            flows.append(FlowRule(
                match={'ip_src': endpoints, 'ip_dst': exc['dst']},
                actions=[Action.FORWARD_NORMAL],
                priority=900
            ))
        
        # Deny external (default)
        if intent['spec']['policy']['external'] == 'deny':
            for ep in endpoints:
                flows.append(FlowRule(
                    match={'ip_src': ep},
                    actions=[Action.DROP],
                    priority=100
                ))
        
        return flows
```

---

## Integration with Existing Architecture

### Module Pipeline with Flow Tables

```
┌────────────────────────────────────────────────────────────────────────────┐
│                    ENHANCED INGRESS PIPELINE                                │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐ │
│  │dispatcher│──▶│  parse   │──▶│ flow_lkp │──▶│  actions │──▶│   vlan   │ │
│  │          │   │ stage=10 │   │ stage=25 │   │ stage=26 │   │ stage=30 │ │
│  └──────────┘   └──────────┘   └────┬─────┘   └──────────┘   └──────────┘ │
│                                      │                              │       │
│                              ┌───────▼───────┐                      │       │
│                              │ rs_flow_table │                      │       │
│                              └───────────────┘                      │       │
│                                                                     │       │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐         │       │
│  │   acl    │◀──│  route   │◀──│ l2learn  │◀──│ lastcall │◀────────┘       │
│  │ stage=40 │   │ stage=50 │   │ stage=80 │   │ stage=90 │                 │
│  └──────────┘   └──────────┘   └──────────┘   └──────────┘                 │
│                                                                             │
└────────────────────────────────────────────────────────────────────────────┘

Flow table lookup happens EARLY (stage 25-26):
- If flow matches → apply actions, may skip remaining modules
- If no match → continue normal module pipeline
```

### Profile Configuration

```yaml
# etc/profiles/fabric-enabled.yaml
name: "Network Fabric Enabled"
version: "2.0"

# Enable flow table modules
ingress:
  - parse          # NEW: Dedicated parser
  - flow_lkp       # NEW: Flow table lookup
  - flow_actions   # NEW: Action execution
  - vlan           # Existing
  - acl            # Existing (fallback for non-flow traffic)
  - route
  - l2learn
  - lastcall

egress:
  - egress_qos
  - egress_vlan
  - egress_final

# Flow table configuration
flow_tables:
  - table_id: 0
    name: "ingress_acl"
    max_entries: 65536
    miss_action: continue  # Continue to ACL module if no match

# Meter configuration
meters:
  - meter_id: 1
    name: "video_ratelimit"
    cir: 100000000     # 100 Mbps
    cbs: 1000000       # 1 MB burst

# Group configuration
groups:
  - group_id: 1
    name: "backend_servers"
    type: select       # ECMP
    buckets:
      - port: eth2
        weight: 1
      - port: eth3
        weight: 1
```

### Updated `rs_ctx` Structure

```c
/* Extended rs_ctx for Network Fabric */
struct rs_ctx {
    /* ... existing fields ... */
    
    /* Network Fabric additions */
    struct rs_flow_entry *flow_entry;   /* Matched flow (NULL if no match) */
    __u32 flow_table_id;                /* Current flow table */
    __u8  flow_hit;                     /* 1 if flow matched */
    __u8  skip_modules;                 /* Bitmap of modules to skip */
    __u16 reserved_fabric;
    
    /* ... existing fields ... */
};
```

---

## User-Space Components

### Fabric Agent Daemon

```c
/* user/fabric_agent/main.c */

/* Fabric Agent: Receives flow updates from controller, pushes to BPF maps */

struct fabric_agent {
    int controller_fd;              /* Connection to controller */
    struct bpf_map *flow_table;     /* BPF flow table map FD */
    struct bpf_map *meters;         /* BPF meters map FD */
    struct bpf_map *groups;         /* BPF groups map FD */
};

/* Handle FlowMod message from controller */
int handle_flow_mod(struct fabric_agent *agent, struct flow_mod *mod)
{
    struct rs_flow_key key;
    struct rs_flow_entry entry;
    
    /* Convert controller message to BPF structures */
    convert_match_to_key(&mod->match, &key);
    convert_actions_to_entry(&mod->actions, &entry);
    
    switch (mod->command) {
    case FLOW_ADD:
        return bpf_map_update_elem(agent->flow_table, &key, &entry, BPF_NOEXIST);
    case FLOW_MODIFY:
        return bpf_map_update_elem(agent->flow_table, &key, &entry, BPF_EXIST);
    case FLOW_DELETE:
        return bpf_map_delete_elem(agent->flow_table, &key);
    }
    return -1;
}
```

### CLI Tools

```bash
# Flow table management
$ rsctl flow add --match "ip_dst=10.0.0.0/8" --action "output:eth2" --priority 1000
$ rsctl flow list
$ rsctl flow delete --match "ip_dst=10.0.0.0/8"

# Meter management
$ rsctl meter add --id 1 --rate 100mbps --burst 1mb
$ rsctl meter stats 1

# Group management
$ rsctl group add --id 1 --type select --buckets "eth2:1,eth3:1"
$ rsctl group stats 1

# Intent management
$ rsctl intent apply finance-isolation.yaml
$ rsctl intent show finance-isolation
```

---

## Performance Considerations

### Lookup Optimization

| Technique | Benefit |
|-----------|---------|
| **Exact match first** | O(1) hash lookup for specific flows |
| **LPM fallback** | Efficient prefix matching for wildcard rules |
| **Per-CPU maps** | Avoid lock contention on counters |
| **Batch updates** | Reduce syscall overhead for bulk changes |

### Memory Budget

| Component | Entries | Memory |
|-----------|---------|--------|
| Flow table (exact) | 65,536 | ~8 MB |
| Flow table (LPM) | 8,192 | ~2 MB |
| Meters | 4,096 | ~512 KB |
| Groups | 1,024 | ~256 KB |
| **Total** | | **~11 MB** |

### Latency Impact

```
Without flow tables:  ~50 ns (module pipeline only)
With flow tables:     ~80 ns (+ hash lookup + action execution)
Overhead:             ~30 ns per packet
```

---

## Migration Path

### Phase 1: Foundation (v2.1)
- [ ] Implement `flow_lkp` and `flow_actions` modules
- [ ] Add flow table BPF maps
- [ ] Basic CLI for flow management
- [ ] Exact-match flows only

### Phase 2: Advanced Features (v2.2)
- [ ] LPM/wildcard flow matching
- [ ] Metering (token bucket)
- [ ] Group tables (multicast/ECMP)
- [ ] Flow statistics and aging

### Phase 3: Orchestration (v2.3)
- [ ] Fabric Agent daemon
- [ ] Controller protocol (OpenFlow-lite or custom)
- [ ] Multi-switch topology discovery
- [ ] Centralized path computation

### Phase 4: Intent Layer (v3.0)
- [ ] Intent YAML schema
- [ ] Intent compiler
- [ ] Policy conflict detection
- [ ] Intent reconciliation loop

---

## API Summary

### BPF Maps (New)

| Map | Type | Key | Value |
|-----|------|-----|-------|
| `rs_flow_table` | HASH | `rs_flow_key` | `rs_flow_entry` |
| `rs_flow_table_lpm` | LPM_TRIE | `rs_lpm_key` | `rs_flow_entry` |
| `rs_meters` | HASH | `meter_id` | `rs_meter` |
| `rs_groups` | HASH | `group_id` | `rs_group` |

### User-Space APIs (New)

| Function | Description |
|----------|-------------|
| `rs_flow_add()` | Add flow rule |
| `rs_flow_delete()` | Remove flow rule |
| `rs_flow_modify()` | Update flow rule |
| `rs_flow_list()` | Enumerate all flows |
| `rs_meter_create()` | Create meter |
| `rs_meter_stats()` | Get meter statistics |
| `rs_group_create()` | Create port group |
| `rs_group_update()` | Modify group buckets |

### Event Types (New)

| Event | Code | Description |
|-------|------|-------------|
| `RS_EVENT_FLOW_HIT` | 0x0600 | Flow rule matched |
| `RS_EVENT_FLOW_MISS` | 0x0601 | No flow rule matched |
| `RS_EVENT_FLOW_EXPIRED` | 0x0602 | Flow aged out |
| `RS_EVENT_METER_DROP` | 0x0610 | Packet dropped by meter |

---

## References

- [Reconfigurable_Architecture.md](./Reconfigurable_Architecture.md) — Foundation architecture
- [API_Reference.md](./API_Reference.md) — Current API documentation
- [OpenFlow Specification v1.5](https://opennetworking.org/software-defined-standards/specifications/) — Flow table model reference
- [P4 Language Specification](https://p4.org/specs/) — Match-action pipeline concepts
