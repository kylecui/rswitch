# Distributed State Synchronization

**Status**: Design Proposal (Not Implemented)  
**Ecosystem**: 2.3  
**Priority**: LOW  
**Dependencies**: Centralized Controller (Eco 2.1), Agent (Eco 2.2)

---

## Overview

Distributed State Synchronization enables multiple rSwitch instances in a fabric to share critical switching state—MAC tables, routing information, ACL rules, and connection tracking data. This creates a cohesive fabric where state learned on one switch is immediately available to all peers, improving failover performance, reducing traffic flooding, and enabling fabric-wide policy enforcement.

**Key Benefits**:
- **Zero-flood MAC learning**: MAC entries learned on one switch propagate to all peers
- **Dynamic route convergence**: Routing changes distributed automatically across fabric
- **Unified policy**: ACL rules managed centrally, enforced consistently
- **Stateful failover**: Connection tracking state preserved across switch failures

---

## Problem Statement

Current rSwitch instances operate independently with isolated state:

### 1. MAC Learning Isolation
- Switch A learns MAC `aa:bb:cc:dd:ee:ff` on port 3
- Switch B receives packet destined to that MAC → floods to all ports
- Result: Unnecessary broadcast traffic, suboptimal forwarding

### 2. Manual Route Propagation
- Operator adds route `10.0.0.0/24 via 192.168.1.1` on Switch A
- Must manually replicate to Switch B, C, D...
- Result: Configuration drift, inconsistent forwarding behavior

### 3. Per-Switch ACL Management
- Security policy requires blocking port 22 from `192.168.0.0/16`
- Rule must be configured individually on each switch
- Result: Management overhead, compliance gaps

### 4. Stateless Failover
- Active TCP connection tracked on Switch A
- Link fails, traffic reroutes to Switch B
- Switch B has no conntrack state → connection reset
- Result: Application disruption, poor user experience

**Solution**: Distributed state sync coordinates state across fabric instances through centralized controller.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   Centralized Controller                     │
│  - State aggregation and distribution coordinator           │
│  - Conflict resolution arbiter                               │
│  - Authoritative source for ACL rules                        │
└──────────┬─────────────┬─────────────┬───────────────────────┘
           │             │             │
    TCP    │      TCP    │      TCP    │
           │             │             │
     ┌─────▼────┐  ┌─────▼────┐  ┌─────▼────┐
     │ Agent A  │  │ Agent B  │  │ Agent C  │
     │ (rSwitch)│  │ (rSwitch)│  │ (rSwitch)│
     └──────────┘  └──────────┘  └──────────┘
```

### Communication Flow

1. **State Change Detection**: Agent monitors BPF maps for changes (MAC learned, route added, flow created)
2. **Local Application**: State immediately applied to local BPF maps
3. **Upstream Report**: Agent sends state update to controller
4. **Controller Processing**: Validates, resolves conflicts, updates global view
5. **Peer Distribution**: Controller forwards update to relevant peer agents
6. **Peer Application**: Receiving agents apply state to local BPF maps

### Consistency Model

**Eventually Consistent**: State updates propagate asynchronously. Brief windows where switches have divergent views are acceptable. Conflicts resolved through deterministic rules (vector clocks, timestamps, controller authority).

**Design Choice Rationale**:
- Strong consistency requires 2PC/Raft → high latency, complex failure handling
- Switching state is inherently convergent (MAC timeouts, route costs)
- Sub-second eventual consistency sufficient for target use cases

---

## State Types & Sync Strategy

| State Type | Sync Method | Trigger | Frequency | Conflict Resolution |
|------------|-------------|---------|-----------|---------------------|
| **MAC Table** | Incremental | MAC learn event | On-change | Last-writer-wins (timestamp) |
| **Routes** | Full table | Route add/delete | On-change + periodic (60s) | Longest prefix match, cost comparison |
| **ACL Rules** | Full table | Controller command | On-change | Controller authoritative |
| **Conntrack** | Selective (active flows) | Flow creation | Periodic (5s) | Merge (union of flows) |

### MAC Table Sync
- **Rationale**: Most frequent state changes, highest value for reducing floods
- **Optimization**: Only sync learned MACs (not static entries)
- **Aging**: Respect local aging timers, let entries expire independently

### Route Sync
- **Rationale**: Critical for correct forwarding, relatively infrequent changes
- **Full Table**: Ensures consistency, simplifies conflict resolution
- **Periodic Sync**: Handles missed updates, drift correction

### ACL Rule Sync
- **Rationale**: Security-critical, must be consistent across fabric
- **Controller Authority**: Single source of truth prevents conflicts
- **Push Model**: Controller pushes rules to agents (no agent-initiated changes)

### Conntrack Sync
- **Rationale**: Enables stateful failover, most complex to implement
- **Selective**: Only sync active flows (ignore short-lived UDP)
- **Merge Strategy**: Union of flows across switches (no conflicts)

---

## Wire Format

Reuses controller/agent TCP protocol established in Eco 2.1/2.2.

### Message Types

#### MSG_STATE_UPDATE (Agent → Controller, Controller → Agent)
```json
{
  "type": "state_update",
  "state_class": "mac",
  "action": "add",
  "data": {
    "mac": "aa:bb:cc:dd:ee:ff",
    "vlan": 100,
    "port": 3,
    "timestamp": 1710165432,
    "agent_id": "switch-a"
  },
  "vector_clock": {
    "switch-a": 42,
    "switch-b": 15
  }
}
```

**Fields**:
- `state_class`: `mac`, `route`, `acl`, `conntrack`
- `action`: `add`, `delete`, `update`
- `data`: State-specific payload
- `vector_clock`: Logical timestamp for conflict detection

#### MSG_STATE_SYNC_REQ (Agent → Controller)
```json
{
  "type": "state_sync_req",
  "state_class": "route",
  "full_sync": true,
  "agent_id": "switch-b"
}
```

Request full table dump (e.g., after reconnect).

#### MSG_STATE_SYNC_RESP (Controller → Agent)
```json
{
  "type": "state_sync_resp",
  "state_class": "route",
  "entries": [
    {"prefix": "10.0.0.0/24", "nexthop": "192.168.1.1", "cost": 10},
    {"prefix": "10.1.0.0/16", "nexthop": "192.168.1.2", "cost": 20}
  ],
  "vector_clock": {
    "switch-a": 100,
    "switch-b": 85,
    "switch-c": 92
  }
}
```

### Encoding
- **Format**: JSON (human-readable, debuggable)
- **Future Optimization**: Binary encoding (protobuf/msgpack) for high-throughput fabrics

---

## Conflict Resolution

### Vector Clocks

Each agent maintains vector `[switch-a: N, switch-b: M, ...]` tracking causal dependencies.

**Update Rule**:
1. Agent increments own counter on local state change
2. Includes vector in state update message
3. Controller merges vectors (element-wise max)
4. Peers update vectors on receipt

**Conflict Detection**:
- If vectors are incomparable (`A[i] > B[i]` and `A[j] < B[j]`), concurrent updates detected
- Apply state-specific resolution strategy

### Resolution Strategies by State Type

#### MAC Table: Last-Writer-Wins
```
Concurrent updates:
  Switch A: MAC aa:bb:cc:dd:ee:ff → port 3 (timestamp 1000)
  Switch B: MAC aa:bb:cc:dd:ee:ff → port 5 (timestamp 1001)

Resolution: Keep port 5 (newer timestamp)
```

**Rationale**: MAC entries are dynamic, host may have moved. Newest information most accurate.

#### Routes: Longest Prefix Match + Cost
```
Concurrent updates:
  Switch A: 10.0.0.0/24 via 192.168.1.1 (cost 10)
  Switch B: 10.0.0.0/24 via 192.168.1.2 (cost 5)

Resolution: Keep 192.168.1.2 (lower cost)
```

**Rationale**: Routing protocol semantics—prefer lower cost path.

#### ACL Rules: Controller Authoritative
```
Conflict: Agent attempts to modify ACL rule

Resolution: Reject agent change, controller version wins
```

**Rationale**: Security policy must have single source of truth. Agents are read-only consumers.

#### Conntrack: Merge (Union)
```
Concurrent updates:
  Switch A: Flow 192.168.1.10:5000 → 10.0.0.5:80 (state ESTABLISHED)
  Switch B: Flow 192.168.1.20:6000 → 10.0.0.6:443 (state ESTABLISHED)

Resolution: Keep both flows (independent connections)
```

**Rationale**: Conntrack entries are independent, no true conflict. Merge provides complete view.

---

## Failure Modes

### Controller Unavailable

**Scenario**: Controller process crashes or network partition isolates controller.

**Behavior**:
1. Agents detect TCP disconnect (keepalive timeout)
2. Enter **autonomous mode**: continue forwarding with local state
3. Queue state updates in memory (bounded buffer, drop oldest on overflow)
4. Periodically attempt reconnection (exponential backoff: 1s, 2s, 4s, ..., max 60s)
5. On reconnect: send MSG_STATE_SYNC_REQ, receive full state, replay queued updates

**Trade-off**: Temporary state divergence acceptable vs. forwarding plane disruption.

### Agent Disconnect

**Scenario**: Agent process terminates or network link fails.

**Behavior**:
1. Controller detects TCP disconnect
2. Mark agent state as **stale** (timestamp of last contact)
3. After timeout (default 60s): remove agent's contributed state
   - MAC entries with `agent_id=disconnected_agent` deleted
   - Routes contributed by agent withdrawn
4. On reconnect: agent sends full state, controller reintegrates

**Rationale**: Stale state (especially MACs) can cause blackholing. Timeout balances quick recovery vs. flapping.

### Network Partition

**Scenario**: Fabric splits into two islands, each with controller connectivity.

**Behavior**:
1. Each island operates independently (controller can't reach across partition)
2. State diverges during partition
3. On partition heal: agents reconnect, controller detects divergent vector clocks
4. Trigger full state reconciliation (MSG_STATE_SYNC_REQ/RESP)
5. Apply conflict resolution strategies per state type

**Challenge**: Requires careful tuning of timeouts to avoid premature state deletion.

---

## Performance Considerations

### Batching
- **Problem**: Bursts of MAC learning events (1000 MACs in 100ms) would flood controller
- **Solution**: Aggregate state updates in 100ms window, send single batched message
- **Trade-off**: 100ms propagation delay vs. reduced message overhead

### Compression
- **Problem**: Full route sync on 100k routes → multi-MB message
- **Solution**: gzip JSON payload (typical 5:1 compression ratio)
- **Trade-off**: CPU cost of compression vs. network bandwidth

### Rate Limiting
- **Problem**: Misbehaving agent spamming state updates
- **Solution**: Token bucket per agent (1000 updates/sec burst, 100 sustained)
- **Trade-off**: Legitimate burst traffic may be dropped

### Expected Overhead

**Baseline Deployment** (3 switches, 1000 MACs, 100 routes):
- **CPU**: <1% per agent (state monitoring, JSON serialization)
- **Memory**: ~10MB per agent (queued updates, vector clocks)
- **Network**: ~50KB/s steady-state (periodic route sync, conntrack updates)

**Large Deployment** (20 switches, 50k MACs, 5k routes):
- **CPU**: <5% per agent, ~20% controller (state aggregation)
- **Memory**: ~100MB per agent, ~1GB controller
- **Network**: ~500KB/s sustained

**Bottleneck**: Controller becomes single point of scalability. See Future Extensions for HA solutions.

---

## Future Extensions

### BPF Map-to-Map Direct Sync

**Concept**: Bypass userspace controller, replicate BPF maps directly between switches using eBPF's `bpf_map_update_elem()` called from XDP program on receiving sync packets.

**Benefits**:
- Microsecond propagation latency (vs. milliseconds through userspace)
- Zero CPU overhead for forwarding plane

**Challenges**:
- Requires kernel support for remote map updates
- Security concerns (any switch can modify peer maps)

### RDMA-Based Fast Sync

**Concept**: Use RDMA write to directly update remote switch memory (BPF maps stored in RDMA-registered region).

**Benefits**:
- Sub-microsecond latency
- Hardware-offloaded replication

**Challenges**:
- Requires RDMA-capable NICs
- Complex memory management (pinning BPF maps)

### Raft Consensus for Controller HA

**Problem**: Single controller is availability bottleneck.

**Solution**: Deploy 3-5 controller instances in Raft cluster. Leader handles state distribution, followers replicate log. On leader failure, new leader elected in <1s.

**Benefits**:
- No single point of failure
- Strong consistency guarantees

**Trade-off**: Increased operational complexity (multi-node deployment).

---

## Implementation Roadmap

### Phase 1: MAC Table Sync (3-4 weeks)
**Goal**: Eliminate MAC flooding in multi-switch fabric.

- Implement MAC learn event detection in agent (poll `mac_table` BPF map)
- Add MSG_STATE_UPDATE handler in controller
- Distribute MAC updates to peer agents
- Test: 2-switch fabric, verify MAC learned on A appears in B's table

**Success Metric**: Zero flooded frames after initial learning period.

### Phase 2: Route Sync (2-3 weeks)
**Goal**: Enable dynamic routing across fabric.

- Implement route add/delete detection in agent
- Add periodic full route sync (60s)
- Handle conflict resolution (LPM + cost)
- Test: Add route on A, verify forwarding on B uses new route

**Success Metric**: Route convergence <5s after change.

### Phase 3: ACL Distribution (2 weeks)
**Goal**: Centralized security policy management.

- Implement controller-side ACL rule management API
- Push ACL rules to agents on change
- Agent applies rules to `acl_table` BPF map
- Test: Add block rule on controller, verify drops on all switches

**Success Metric**: Policy enforcement within 1s of controller update.

### Phase 4: Conntrack Sync (4-5 weeks)
**Goal**: Stateful failover for TCP connections.

- Implement selective conntrack monitoring (active TCP flows only)
- Periodic sync (5s) of flow state
- Handle merge conflicts (union of flows)
- Test: Establish TCP connection, fail over to backup switch, verify no RST

**Success Metric**: 95% of connections survive failover without disruption.

**Total Estimated Effort**: 11-14 weeks (one engineer, full-time)

---

## Open Questions

1. **MAC Aging Synchronization**: Should MAC aging timers reset on sync? Or let each switch age independently?
   - Proposal: Independent aging. Simplifies implementation, eventual consistency model tolerates brief divergence.

2. **Conntrack Security**: Can malicious agent inject fake conntrack state to bypass firewall?
   - Mitigation: Controller validates source IP ranges against agent's known topology position.

3. **State Explosion**: How to handle 1M+ MAC entries?
   - Mitigation: Implement incremental sync with bloom filters (only sync MACs not in peer's filter).

4. **Backward Compatibility**: How to handle mixed-version fabric (some switches support sync, others don't)?
   - Proposal: Controller tracks agent capabilities, only distributes state to capable peers.

---

## References

- **Eco 2.1**: Centralized Controller (`user/controller/`)
- **Eco 2.2**: Agent Architecture (`user/agent/`)
- **Vector Clocks**: Mattern, F. (1988). "Virtual Time and Global States of Distributed Systems"
- **Eventual Consistency**: Vogels, W. (2009). "Eventually Consistent" (ACM Queue)

---

**Document Version**: 1.0  
**Last Updated**: 2026-03-11  
**Author**: rSwitch Development Team
