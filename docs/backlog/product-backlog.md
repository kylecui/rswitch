# Product Backlog — Network Function Modules

> **Scope**: New BPF modules and enhancements to existing modules that add network product capabilities. These are the building blocks for assembling specific network products on the rSwitch platform.
>
> **Priority Legend**: 🔴 Critical (required for first product) · 🟡 High (needed soon) · 🟢 Medium (improves product) · ⚪ Low (future product)

---

## 1. Layer 2 Enhancements

### 1.1 🟡 QinQ / 802.1ad Double VLAN Tagging

**Goal**: Support service-provider VLAN stacking (S-VLAN + C-VLAN) for multi-tenant and carrier Ethernet deployments.

**Current State**: `vlan.bpf.c` handles single 802.1Q tags. `rs_layers` already tracks `vlan_ids[2]` and `vlan_depth`, but only index 0 is processed. The egress VLAN module only pushes/pops single tags.

**Requirements**:
- Parse double-tagged frames: outer S-VLAN (EtherType 0x88A8) + inner C-VLAN (0x8100)
- New port mode: `qinq` — push S-VLAN on ingress, pop on egress
- S-VLAN ↔ C-VLAN translation table (map-based)
- Profile configuration:
  ```yaml
  ports:
    - interface: "eth0"
      vlan_mode: qinq
      s_vlan: 1000       # Service VLAN
      allowed_c_vlans: "100-200"  # Customer VLAN range
  ```
- Egress VLAN module updates to handle double push/pop
- `rsvlanctl` CLI extension for QinQ management

**Affected Modules**: `vlan.bpf.c`, `egress_vlan.bpf.c`, `user/tools/rsvlanctl.c`

---

### 1.2 🟢 STP/RSTP — Spanning Tree Protocol

**Goal**: Prevent L2 loops in topologies with redundant links.

**Current State**: No loop prevention. Broadcast storms are possible in multi-port L2 profiles.

**Requirements**:
- BPF module intercepts STP BPDUs (dst MAC `01:80:C2:00:00:00`)
- Forward BPDUs to user-space STP daemon via ring buffer
- User-space daemon runs RSTP state machine (port states: Discarding, Learning, Forwarding)
- Daemon writes port states to `rs_port_config_map` — BPF module enforces forwarding decisions
- Convergence time target: < 2 seconds (RSTP)
- Module stage: 12 (early ingress, before VLAN processing)

**Architecture**:
```
Packet → Dispatcher → [STP module] → VLAN → ...
                           ↓ (BPDUs)
                      Ring Buffer
                           ↓
                    User-space RSTP daemon
                           ↓ (port state updates)
                    rs_port_config_map
```

**New Components**: `bpf/modules/stp.bpf.c`, `user/stpd/` (user-space daemon)

---

### 1.3 🟢 LACP — Link Aggregation Control Protocol

**Goal**: Bond multiple physical interfaces into a logical aggregate for redundancy and bandwidth.

**Current State**: No link aggregation. Each interface is independent.

**Requirements**:
- BPF module intercepts LACP PDUs (EtherType 0x8809)
- Forward LACPDUs to user-space LACP daemon via ring buffer
- Daemon negotiates with partner, manages aggregation groups
- Aggregation-aware forwarding: hash-based TX distribution across member links
- Support: active/passive LACP modes, short/long timeout
- Integration with L2 forwarding: MAC table entries reference aggregate group, not individual port
- Module stage: 11 (very early ingress)

**New Components**: `bpf/modules/lacp.bpf.c`, `user/lacpd/`

---

### 1.4 ⚪ LLDP — Link Layer Discovery Protocol

**Goal**: Neighbor discovery for network topology awareness.

**Requirements**:
- Intercept LLDP frames (dst MAC `01:80:C2:00:00:0E`)
- Parse and store neighbor information (chassis ID, port ID, TTL, system name)
- User-space daemon manages neighbor table with aging
- `rswitchctl show-neighbors` CLI command
- Emit LLDP frames on configured intervals
- Module stage: 11 (early ingress, can share with LACP)

---

## 2. Layer 3 Enhancements

### 2.1 🔴 Route Module Enhancements

**Goal**: Production-grade IPv4 routing with dynamic route management.

**Current State**: `route.bpf.c` is implemented with LPM trie lookup, ARP table, TTL decrement, and ICMP TTL-exceeded generation. Basic but functional.

**Requirements**:
- **Connected routes**: Auto-populate from interface addresses
- **Static route CLI**: `rsroutectl add 10.0.0.0/24 via 192.168.1.1 dev eth1`
- **ECMP**: Equal-cost multi-path with hash-based next-hop selection (up to 4 paths)
- **Route metrics**: Prefer lower metric routes
- **ARP resolution queue**: Buffer packets while ARP is resolving (user-space)
- **ARP aging**: Periodic ARP entry refresh and stale removal
- **ICMP redirect**: Generate redirects when forwarding on same interface as source
- **Route table dump**: `rsroutectl show` with prefix, next-hop, interface, metric, age

**Future** (not for first product):
- IPv6 routing (requires new LPM map and NDP)
- Policy-based routing (source-based route selection)
- BGP/OSPF integration via FRRouting or BIRD socket

---

### 2.2 🟡 Stateful ACL with Connection Tracking

**Goal**: Allow return traffic for established connections without explicit rules.

**Current State**: `acl.bpf.c` performs stateless packet matching (5-tuple: src/dst IP, src/dst port, protocol). Every packet is evaluated against the rule table independently.

**Requirements**:
- Connection tracking table: BPF hash map keyed by 5-tuple
- States: NEW, ESTABLISHED, RELATED, INVALID
- TCP state tracking: SYN → SYN-ACK → ESTABLISHED → FIN tracking
- UDP: First packet = NEW, reply = ESTABLISHED, timeout-based aging
- ICMP: Match echo-reply to echo-request
- Rule syntax extension:
  ```
  rsaclctl add --src 192.168.1.0/24 --action allow --state new --track
  rsaclctl add --state established --action allow   # Allow all return traffic
  ```
- Connection table aging: configurable timeouts (TCP est: 3600s, UDP: 30s, ICMP: 30s)
- `rsaclctl show-connections` — dump active connection table
- Performance: minimal per-packet overhead for ESTABLISHED lookups (hash map O(1))

**New Map**: `rs_conntrack_map` (hash map, key=5-tuple, value=state+timestamps)

---

### 2.3 🟢 NAT — Network Address Translation

**Goal**: Source NAT (masquerade) and destination NAT for gateway deployments.

**Requirements**:
- SNAT: Rewrite source IP/port for outbound traffic (masquerade mode)
- DNAT: Rewrite destination IP/port for inbound traffic (port forwarding)
- Integration with connection tracking (2.2) — NAT entries tied to conntrack entries
- NAT table: BPF hash map with original ↔ translated address mappings
- Port range allocation for SNAT (avoid conflicts)
- Profile configuration:
  ```yaml
  nat:
    snat:
      - interface: "eth0"     # WAN interface
        mode: masquerade
    dnat:
      - external_port: 8080
        internal_ip: "192.168.1.100"
        internal_port: 80
  ```
- Module stage: 55 (after route, before L2 learn)

**Depends on**: 2.2 (Connection Tracking)

---

## 3. QoS & Traffic Engineering

### 3.1 🔴 QoS Traffic Classification Module

**Goal**: Classify packets into traffic classes based on configurable rules, separate from the existing egress QoS marking.

**Current State**: `egress_qos.bpf.c` does DSCP/PCP-based priority marking on the egress path. No ingress-side classification module exists to assign traffic classes based on complex match criteria.

**Requirements**:
- Ingress module at stage 25 (between VLAN and ACL)
- Classification criteria:
  - DSCP value mapping (e.g., DSCP 46 → traffic_class 7)
  - Source/destination subnet
  - Protocol/port (e.g., TCP/22 → management class)
  - VLAN priority (PCP bits)
  - Custom class map rules
- Write classification result to `rs_ctx->traffic_class`
- Downstream modules (QoS, VOQd) use `traffic_class` for scheduling decisions
- Profile configuration:
  ```yaml
  qos_classify:
    - match: { dscp: 46 }
      traffic_class: 7    # Expedited Forwarding → highest priority
    - match: { dst_port: 22, protocol: tcp }
      traffic_class: 6    # Management traffic
    - match: { vlan: 100 }
      traffic_class: 4    # Premium VLAN
    - default:
      traffic_class: 0    # Best effort
  ```
- CLI: `rsqosctl show-classes`, `rsqosctl add-class-rule ...`

**New Module**: `bpf/modules/qos_classify.bpf.c`

---

### 3.2 🟡 Rate Limiting / Policing

**Goal**: Per-flow or per-class rate limiting at ingress to prevent bandwidth abuse.

**Requirements**:
- Token bucket algorithm in BPF (per-flow state in hash map)
- Rate limit targets: per-source-IP, per-destination, per-VLAN, per-traffic-class
- Actions on exceed: drop, remark DSCP, redirect to lower priority queue
- Configuration:
  ```yaml
  rate_limits:
    - match: { src_subnet: "10.0.0.0/8" }
      rate: 100mbps
      burst: 10mb
      exceed_action: drop
  ```
- Module stage: 28 (after classification, before ACL)
- Per-policer counters: conforming/exceeding/violating packets and bytes

**New Module**: `bpf/modules/rate_limiter.bpf.c`

---

### 3.3 🟢 Traffic Shaping (User-space)

**Goal**: Smooth bursty traffic via user-space token bucket or leaky bucket shaping.

**Requirements**:
- Integration with VOQd: shape traffic per queue before transmission
- Algorithms: Token Bucket, Weighted Fair Queuing (WFQ)
- Per-port and per-class shaping rates
- Burst tolerance configuration
- Statistics: shaped packets, queue depth, delay introduced

**Affected Components**: `user/voqd/` scheduler enhancements

---

## 4. Security Modules

### 4.1 🟡 Anti-Spoofing / Source Guard

**Goal**: Prevent IP/MAC spoofing attacks by validating source addresses against a binding table.

**Requirements**:
- IP-MAC-Port binding table (BPF hash map)
- Validate: source MAC matches expected for ingress port, source IP matches bound MAC
- Actions: drop spoofed packets, log violation events
- Auto-learn mode: populate bindings from DHCP snooping or ARP inspection
- Manual bindings via CLI: `rsaclctl add-binding --ip 10.0.0.5 --mac aa:bb:cc:dd:ee:ff --port eth1`
- Module stage: 18 (very early, after dispatcher, before VLAN)

**New Module**: `bpf/modules/source_guard.bpf.c`

---

### 4.2 🟢 DHCP Snooping

**Goal**: Build trusted IP-MAC bindings by inspecting DHCP traffic, preventing rogue DHCP servers.

**Requirements**:
- Intercept DHCP packets (UDP 67/68)
- Trust model: only forward DHCP server responses from designated trusted ports
- Extract IP-MAC bindings from DHCP ACK messages
- Feed bindings to source guard module (4.1)
- Trusted port configuration in profile YAML

---

## 5. Advanced Forwarding

### 5.1 🟡 Network Fabric Flow Tables

**Goal**: OpenFlow-style per-flow forwarding rules for SDN and overlay network use cases.

**Current State**: Forwarding is destination-MAC-based (L2) or LPM-based (L3). No per-flow policy routing.

**Requirements**:
- Flow table: BPF hash map with multi-field match (ingress port, VLAN, src/dst MAC, src/dst IP, protocol, src/dst port)
- Actions per flow: forward to port, drop, set VLAN, set DSCP, mirror, redirect to VOQd queue
- Priority-ordered rule evaluation (highest priority match wins)
- Flow table management via gRPC or REST API (user-space controller interface)
- Wildcard support: `*` for any-match fields
- Flow counters: per-flow packet/byte counts, last-match timestamp
- Flow aging: idle timeout and hard timeout per flow entry
- Module stage: 60 (after route, high-flexibility position)

**New Module**: `bpf/modules/flow_table.bpf.c`
**New Component**: `user/flow_controller/` (API endpoint for external SDN controllers)

---

### 5.2 ⚪ Tunnel Encapsulation / Decapsulation

**Goal**: VXLAN and GRE tunnel support for overlay networking.

**Requirements**:
- VXLAN decapsulation: strip outer headers, forward inner frame
- VXLAN encapsulation: wrap frame in UDP/IP/Ethernet with VNI
- GRE decapsulation/encapsulation
- VNI ↔ VLAN mapping table
- Tunnel endpoint management
- MTU handling: path MTU discovery, fragmentation avoidance

**Note**: Complex due to packet size changes. May require `bpf_xdp_adjust_head()` and careful bounds checking. Evaluate feasibility with current BPF verifier constraints.

---

## 6. Monitoring & Mirroring Enhancements

### 6.1 🟡 Enhanced Mirror Module

**Goal**: Extend current mirror module with flexible mirror policies.

**Current State**: `mirror.bpf.c` at stage 40 supports basic SPAN mirroring to a designated port.

**Requirements**:
- ACL-based selective mirroring (mirror only traffic matching specific rules)
- RSPAN: Mirror to remote port via VLAN encapsulation
- ERSPAN: Mirror with GRE encapsulation (Type II/III headers)
- Per-mirror-session counters
- Multiple simultaneous mirror sessions (up to 4)
- Truncated mirroring: copy only first N bytes of each packet (reduce bandwidth)

---

### 6.2 🟢 sFlow / NetFlow Export

**Goal**: Sampled flow export for network visibility tools.

**Requirements**:
- Packet sampling at configurable rate (1:N)
- sFlow v5 datagram generation in user-space
- NetFlow v9 / IPFIX flow record export
- Collector configuration: IP, port, sampling rate
- Per-interface sampling configuration

---

## Prioritized Roadmap

| Phase | Items | Rationale |
|-------|-------|-----------|
| **Phase 1** (First product MVP) | 2.1 Route Enhancements, 3.1 QoS Classification, 2.2 Stateful ACL | Core L3 product with security and QoS |
| **Phase 2** (Product differentiation) | 1.1 QinQ, 3.2 Rate Limiting, 5.1 Flow Tables, 6.1 Enhanced Mirror | Enterprise features and SDN capability |
| **Phase 3** (Enterprise readiness) | 4.1 Source Guard, 2.3 NAT, 1.2 STP/RSTP, 1.3 LACP | Carrier-grade L2 and security |
| **Phase 4** (Advanced networking) | 5.2 Tunnels, 3.3 Shaping, 4.2 DHCP Snooping, 6.2 sFlow, 1.4 LLDP | Overlay networking and deep visibility |

---

*Last updated: 2026-03-10*
*Related: [Architecture](../development/Architecture.md) · [Scenario Profiles](../usage/Scenario_Profiles.md) · [Platform Backlog](platform-backlog.md)*
