# Ecosystem Backlog — Community, Orchestration & Enterprise

> **Scope**: Module marketplace, multi-switch orchestration, intent-based networking, monitoring integrations, and production hardening.
>
> **Priority Legend**: 🔴 Critical (blocks scale-out) · 🟡 High (needed soon) · 🟢 Medium (improves adoption) · ⚪ Low (future vision)

---

## 1. Module Marketplace & Distribution

### 1.1 🟡 Module Registry

**Goal**: A central catalog where developers can publish and users can discover rSwitch modules.

**Current State**: All modules are built-in, shipped with the rSwitch source tree. No mechanism for third-party module distribution.

**Requirements**:
- Registry server (lightweight — Git-based or static file index initially)
- Module metadata format:
  ```json
  {
    "name": "rate_limiter",
    "version": "1.0.0",
    "abi_version": "1.2",
    "author": "example@example.com",
    "description": "Token-bucket rate limiting per source IP",
    "stage": 28,
    "hook": "ingress",
    "flags": ["NEED_L2L3_PARSE", "MAY_DROP"],
    "license": "GPL-2.0",
    "checksum": "sha256:abcdef..."
  }
  ```
- CLI integration:
  - `rswitchctl module search <query>` — search registry
  - `rswitchctl module install <name>[@version]` — download and install
  - `rswitchctl module publish <package.rsmod>` — publish to registry
  - `rswitchctl module info <name>` — show details, compatibility
- Compatibility check: module ABI version vs installed platform ABI version
- Signature verification for module authenticity
- Local cache for installed modules: `~/.rswitch/modules/`

**Depends on**: [API Backlog 2.3 — Module Packaging Format](api-backlog.md)

---

### 1.2 🟢 Module Marketplace Portal

**Goal**: Web-based interface for browsing, reviewing, and downloading modules.

**Requirements**:
- Searchable catalog with categories (L2, L3, Security, QoS, Monitoring)
- Module detail pages with: description, usage examples, compatibility matrix, download count
- User ratings and reviews
- Author profiles and verified publisher badges
- Automated compatibility testing: CI pipeline verifies module against platform releases
- API endpoint for CLI tool backend

**Note**: This is a separate web application, not part of the rSwitch binary. Consider hosting on GitHub Pages or a lightweight service initially.

---

## 2. Multi-Switch Orchestration

### 2.1 🟡 Centralized Controller

**Goal**: Manage multiple rSwitch instances from a single control plane.

**Current State**: Each rSwitch instance is independently configured via local YAML profiles and CLI tools. No coordination between instances.

**Requirements**:
- Controller daemon: `rswitch-controller`
- Agent on each switch: `rswitch-agent` (communicates with controller)
- Communication: gRPC over TLS (mutual authentication)
- Controller capabilities:
  - Push profile updates to multiple switches simultaneously
  - Collect aggregated statistics from all switches
  - Health monitoring with alerting
  - Firmware/module update orchestration
- Agent capabilities:
  - Register with controller on startup
  - Receive and apply profile updates
  - Report statistics and health status periodically
  - Local fallback if controller unreachable

**Architecture**:
```
┌─────────────────────────────┐
│    rSwitch Controller       │
│  ┌───────┐  ┌───────────┐  │
│  │ API   │  │ Config DB │  │
│  │ (gRPC)│  │ (SQLite)  │  │
│  └───┬───┘  └───────────┘  │
└──────┼──────────────────────┘
       │ gRPC/TLS
  ┌────┼────────────┐
  │    │             │
  ▼    ▼             ▼
┌────┐ ┌────┐    ┌────┐
│ SW1│ │ SW2│    │ SW3│
│agent│ │agent│  │agent│
└────┘ └────┘    └────┘
```

**New Components**: `user/controller/`, `user/agent/`

---

### 2.2 🟢 Topology Discovery

**Goal**: Automatically discover the network topology between rSwitch instances.

**Requirements**:
- LLDP-based neighbor detection between rSwitch instances
- Build topology graph: switches, links, ports, speeds
- Detect topology changes and notify controller
- REST/gRPC API to query topology
- Visualization data output (JSON graph format for web UI)

**Depends on**: 2.1 (Controller), [Product Backlog 1.4 — LLDP](product-backlog.md)

---

### 2.3 ⚪ Distributed State Synchronization

**Goal**: Synchronize forwarding state (MAC tables, routes, ACL rules) across multiple rSwitch instances.

**Requirements**:
- MAC table sync: learned MACs on one switch propagated to peers
- Route table sync: consistent routing across the fabric
- ACL rule distribution: push rules from controller to all switches
- Conflict resolution: last-writer-wins with vector clocks
- Incremental sync: only changed entries, not full table dumps

---

## 3. Intent-Based Networking

### 3.1 🟢 Intent Translation Engine

**Goal**: Express network requirements as high-level intents rather than low-level configurations.

**Current State**: All configuration is explicit YAML — users must know module names, stage numbers, VLAN IDs, etc.

**Intent Examples**:
```yaml
intents:
  - type: isolate
    groups:
      - name: "Engineering"
        hosts: ["10.0.1.0/24"]
      - name: "Finance"
        hosts: ["10.0.2.0/24"]
    policy: deny_inter_group

  - type: prioritize
    traffic: { protocol: tcp, port: 5060 }   # VoIP SIP
    level: critical

  - type: protect
    target: "10.0.0.1"                        # Server
    from: external
    allow: [tcp/443, tcp/22]
```

**Requirements**:
- Intent parser: YAML → intermediate representation
- Policy compiler: intermediate representation → rSwitch profile + module configs
  - `isolate` → VLAN assignments + ACL rules
  - `prioritize` → QoS classification rules + VOQd queue assignments
  - `protect` → ACL rules + connection tracking
- Validation: detect conflicting intents before applying
- `rswitchctl intent apply <intents.yaml>`
- `rswitchctl intent explain <intents.yaml>` — show what configs would be generated

---

### 3.2 ⚪ Policy Verification

**Goal**: Formally verify that intended network policies are correctly enforced.

**Requirements**:
- Model the packet processing pipeline as a decision graph
- Input: intent + generated configuration
- Verification queries: "Can host A reach host B on port 80?", "Is VLAN 100 isolated from VLAN 200?"
- Detect policy violations before deployment
- Continuous verification: monitor actual forwarding against intended policy

---

## 4. Monitoring & Alerting Integrations

### 4.1 🔴 Prometheus Metrics Export

**Goal**: Expose rSwitch metrics in Prometheus format for standard monitoring stacks.

**Current State**: Statistics available via `rswitchctl show-stats` and BPF maps. No Prometheus endpoint.

**Requirements**:
- HTTP endpoint on configurable port (default: 9417)
- Metrics exported:
  ```
  rswitch_port_rx_packets_total{interface="eth0"} 1234567
  rswitch_port_tx_packets_total{interface="eth0"} 1234000
  rswitch_port_drop_packets_total{interface="eth0", reason="acl_block"} 567
  rswitch_module_packets_processed_total{module="vlan"} 1234567
  rswitch_voqd_queue_depth{port="0", priority="7"} 42
  rswitch_voqd_mode{mode="active"} 1
  rswitch_mac_table_entries 256
  rswitch_vlan_count 5
  rswitch_uptime_seconds 86400
  ```
- Configurable scrape interval (metrics read from BPF maps on demand)
- Labels: interface, module, VLAN, priority, drop reason
- Histogram: packet processing latency (if measurable via BPF timestamp)

**Implementation**: Lightweight HTTP server in `user/exporter/` or integrate into `rswitchctl`

---

### 4.2 🟡 Grafana Dashboard Templates

**Goal**: Pre-built dashboards for common monitoring scenarios.

**Deliverables**:
- `monitoring/grafana/rswitch-overview.json` — System overview (ports, throughput, drops)
- `monitoring/grafana/rswitch-qos.json` — QoS dashboard (queues, priorities, VOQd)
- `monitoring/grafana/rswitch-security.json` — Security (ACL hits, blocked traffic, conntrack)
- `monitoring/grafana/rswitch-vlan.json` — VLAN statistics per port
- Each dashboard uses Prometheus as data source
- Variables: selectable interfaces, time ranges, module filters

---

### 4.3 🟢 Alerting Rules

**Goal**: Pre-defined alerting rules for common operational issues.

**Deliverables**:
- `monitoring/alerts/rswitch-alerts.yaml` (Prometheus alerting rules)
- Alerts:
  - Port down (no RX packets for > 60 seconds)
  - High drop rate (> 1% of ingress packets dropped)
  - MAC table full (> 90% capacity)
  - VOQd queue congestion (queue depth > 80% of max)
  - CPU utilization spike (rSwitch process > 80% CPU)
  - ARP table aging failures
  - Module load/reload failures

---

### 4.4 🟢 SNMP Agent

**Goal**: SNMP v2c/v3 support for integration with legacy NMS (Network Management Systems).

**Requirements**:
- Standard MIBs: IF-MIB (interface counters), BRIDGE-MIB (MAC table), Q-BRIDGE-MIB (VLANs)
- Custom rSwitch MIB for module and QoS statistics
- SNMP traps for critical events (port down, ACL violations, module failures)
- Integration via AgentX sub-agent (works with existing SNMP daemon like snmpd)

---

## 5. Production Hardening

### 5.1 🔴 Graceful Shutdown & State Persistence

**Goal**: Clean shutdown that preserves state and restores on restart.

**Current State**: `pkill rswitch_loader` kills the process. BPF programs remain pinned until manually cleaned. No state persistence.

**Requirements**:
- Signal handlers: SIGTERM → graceful shutdown sequence
- Shutdown sequence:
  1. Stop accepting new configuration changes
  2. Drain VOQd queues (configurable timeout)
  3. Save persistent state (MAC table, routes, ACL counters) to disk
  4. Unpin BPF programs and maps
  5. Exit cleanly
- Startup restoration: reload saved state from previous run
- State file location: `/var/lib/rswitch/state.db` (SQLite or binary)
- `rswitchctl shutdown [--drain-timeout 30s]`

---

### 5.2 🔴 Health Checks & Watchdog

**Goal**: Detect and recover from runtime failures automatically.

**Requirements**:
- Periodic self-checks:
  - BPF programs still loaded (check pinned path exists)
  - Maps accessible and consistent
  - VOQd process running (if configured)
  - Packet counters incrementing (not stalled)
- Watchdog: restart failed components automatically
  - Module crash → reload from disk
  - VOQd crash → restart with same config
  - Map corruption → re-initialize from profile
- Health endpoint: `rswitchctl health` → JSON status for monitoring
- Systemd watchdog integration: `sd_notify(WATCHDOG=1)` heartbeat

---

### 5.3 🟡 Resource Limits & Protection

**Goal**: Prevent resource exhaustion in production deployments.

**Requirements**:
- MAC table size limit with eviction policy (LRU aging)
- Connection tracking table size limit with aggressive aging on pressure
- BPF map memory budget: configurable max memory per map type
- CPU affinity: pin rSwitch threads to specific cores
- Memory locking: `mlockall()` to prevent page faults on hot path
- File descriptor limits: ensure sufficient for BPF programs + maps + AF_XDP sockets
- OOM protection: `oom_score_adj = -1000` for critical processes

---

### 5.4 🟢 Configuration Rollback

**Goal**: Automatically revert to previous configuration if new config causes failures.

**Requirements**:
- Before applying new profile: snapshot current state
- Apply timeout: if no "commit" within 60 seconds, auto-rollback
- `rswitchctl apply <profile.yaml> --confirm-timeout 60s`
- `rswitchctl confirm` — accept new config permanently
- `rswitchctl rollback` — manual rollback to previous
- Configuration history: last 5 applied profiles stored

---

### 5.5 🟢 Audit Logging

**Goal**: Track all configuration changes and administrative actions for compliance.

**Requirements**:
- Log all CLI commands with timestamp, user, source IP
- Log all profile changes, module reloads, map updates
- Log format: structured JSON, compatible with syslog and SIEM
- Tamper-evident: append-only log with checksums
- Retention policy: configurable (default 90 days)
- `rswitchctl audit-log [--since 2026-01-01] [--action reload]`

---

## Prioritized Roadmap

| Phase | Items | Rationale |
|-------|-------|-----------|
| **Phase 1** (Production-ready) | 4.1 Prometheus, 5.1 Graceful Shutdown, 5.2 Health Checks | Minimum viable production deployment |
| **Phase 2** (Operational maturity) | 4.2 Grafana, 4.3 Alerting, 5.3 Resource Limits, 1.1 Module Registry | Ops visibility and module distribution |
| **Phase 3** (Scale-out) | 2.1 Controller, 5.4 Rollback, 5.5 Audit Logging | Multi-switch management and compliance |
| **Phase 4** (Platform vision) | 3.1 Intent Engine, 1.2 Marketplace, 2.2 Topology, 4.4 SNMP | SDN-ready platform with community ecosystem |
| **Phase 5** (Advanced) | 3.2 Policy Verification, 2.3 Distributed State | Academic / research-grade capabilities |

---

*Last updated: 2026-03-10*
*Related: [Architecture](../development/Architecture.md) · [Platform Backlog](platform-backlog.md) · [API Backlog](api-backlog.md) · [Product Backlog](product-backlog.md)*
