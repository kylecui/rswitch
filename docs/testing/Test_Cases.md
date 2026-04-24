# rSwitch Test Case Suite

Generated: 2026-04-24 | Based on: codebase analysis + documentation review

---

## 1. Project Understanding Summary

### Project Type

Multi-component network infrastructure platform combining:
- **BPF data plane** — XDP/eBPF kernel-space packet processing (CO-RE)
- **User-space control plane** — 14 daemons, 11 CLI tools, YAML profile system
- **Management plane** — REST API (45+ endpoints), Web Portal (10 pages), Prometheus exporter

### Key Modules

| Layer | Components |
|-------|-----------|
| BPF Modules (25) | dispatcher, vlan, acl, route, l2learn, qos, mirror, egress_vlan, egress_final, egress_qos, lastcall, stp, rate_limiter, source_guard, conntrack, arp_learn, dhcp_snooping, afxdp_redirect, packet_trace, afxdp_tx, sflow_tap, nat, tunnel_encap, tunnel_decap, debug_drop |
| User-Space Libraries | audit, lifecycle, registry, resource_limits, rollback, topology, hot_reload |
| CLI Tools (11) | rswitchctl, rsportctl, rsvlanctl, rsaclctl, rsroutectl, rsqosctl, rsflowctl, rsnatctl, rsvoqctl, rstunnelctl, rsdiag |
| Daemons (14) | rswitch_loader, rswitch-voqd, rswitch-mgmtd, rswitch-stpd, rswitch-lldpd, rswitch-lacpd, rswitch-watchdog, rswitch-telemetry, rswitch-events, rswitch-sflow, rswitch-prometheus, rswitch-controller, rswitch-agent, rswitch-snmpagent |
| REST API | 45+ endpoints across auth, system, ports, modules, vlans, acls, routes, nat, profiles, config, topology, events, dhcp-snooping, websocket |
| Web Portal | 10 HTML pages: index, ports, modules, vlans, acls, routes, logs, dhcp, network, profiles |
| Profiles | 9 YAML profiles in etc/profiles/: all-modules, dumb, firewall, l2, l3, l3-routing, qos-voqd, qos-voqd-minimal, qos-voqd-shadow |

### External Interfaces

- **BPF maps** pinned at `/sys/fs/bpf/rs_*` (12 map types)
- **REST API** on port 8080 (mgmtd, in network namespace)
- **Prometheus metrics** on port 9417 (16 metric families)
- **WebSocket** at `/api/ws` for real-time events
- **Systemd services** (5 unit files)
- **AF_XDP sockets** for VOQd active mode

### High-Risk Areas

1. **BPF verifier compatibility** — CO-RE across kernel 5.8–6.x, offset masking, bounds checking
2. **VOQd mode transitions** — BYPASS ↔ SHADOW ↔ ACTIVE, AF_XDP socket lifecycle
3. **Hot-reload** — atomic prog_array replacement without packet loss
4. **Profile parsing** — malformed YAML, missing fields, type mismatches
5. **Management portal auth** — session hijack, rate limiting bypass, concurrent sessions
6. **Config rollback** — snapshot/restore integrity, partial failure recovery
7. **Network namespace isolation** — mgmtd veth pair, DHCP, cross-namespace leaks
8. **Multi-port VLAN state** — tagged/untagged/hybrid consistency across 256 ports

### Current Test Infrastructure

| Category | Files | Framework |
|----------|-------|-----------|
| Unit tests | 12 C test files | Custom `rs_test.h` + BPF_PROG_RUN |
| Integration | 7 shell scripts | Custom `lib.sh` (veth pairs, netns) |
| Smoke | `smoke_test.sh` | Shell (ELF inspection, BTF, metadata) |
| Functional | `functional_test.sh` | Shell (map access, CLI commands) |
| Fuzz | `fuzz_modules.c` + 4 seeds | LLVM libFuzzer |
| Benchmark | 3 scripts | Custom shell (`iperf3`, `perf stat`) |
| CI | 3 BPF_PROG_RUN tests | C (dispatcher, route, vlan) |

### Key Assumptions

- A1: Tests run as root on a Linux host with kernel 5.8+
- A2: `make` has been run and all build artifacts exist in `build/`
- A3: Integration tests use veth pairs in network namespaces (no physical NICs required)
- A4: REST API tests assume mgmtd running in standalone mode (no namespace)
- A5: Profile tests use files from `etc/profiles/`

---

## 2. Test Strategy

### Layer Suitability

| Layer | Scope | Recommended Coverage | Automation |
|-------|-------|---------------------|------------|
| **Unit (BPF)** | Individual BPF modules via BPF_PROG_RUN | All 17 modules | Fully automated (C + shell runner) |
| **Unit (User)** | Profile parser, config validation, utility functions | Parser, validators | Fully automated (C) |
| **Integration** | Cross-module packet flow, veth-based forwarding | All pipeline combinations | Fully automated (shell + netns) |
| **API Contract** | REST API request/response validation | All 45+ endpoints | Fully automated (curl/Python) |
| **CLI** | All CLI tool commands and flags | All 11 tools | Fully automated (shell) |
| **E2E** | Full stack: loader → BPF → mgmtd → portal | Key workflows | Semi-automated (shell + curl) |
| **Smoke** | Build artifacts, ELF validity, basic loading | Per-build | Fully automated (CI gate) |
| **Fuzz** | Malformed packets, corrupt YAML, API payloads | BPF modules, parser | Continuous (libFuzzer/AFL) |
| **Performance** | Throughput, latency, queue depth | Key profiles | Automated (benchmark suite) |
| **Security** | Auth bypass, injection, namespace escape | Auth, portal, BPF maps | Semi-automated |

### Automation Priority

1. **P0 — Immediate**: BPF unit tests for all modules (extend existing framework), profile parser edge cases
2. **P1 — High**: REST API contract tests (new: Python/curl), CLI tool tests (extend existing)
3. **P2 — Medium**: Integration pipeline tests (extend existing), VOQd mode transitions
4. **P3 — Lower**: Web portal E2E (Playwright), security tests, performance regression

### Manual/Exploratory (Not Automated)

- Physical NIC mode testing (XDP native vs generic vs offload)
- Multi-host L2/L3 forwarding with real traffic
- Grafana dashboard visual validation
- Long-running stability (soak tests)

---

## 3. Traceability Matrix

| Design Point / Module | Entry / Interface | Risk | Test Layer | Scenarios | Priority | Notes |
|---|---|---|---|---|---|---|
| BPF dispatcher | XDP ingress entry | Pipeline routing failure | Unit / Integration | Normal dispatch, unknown stage, empty prog_array | High | All traffic entry point |
| BPF VLAN | XDP stage 20 | VLAN tag corruption, member leak | Unit / Integration | ACCESS/TRUNK/HYBRID modes, native VLAN, QinQ stub, 4094 boundary | High | Existing unit tests |
| BPF ACL | XDP stage 30 | Rule bypass, priority inversion | Unit / Integration | PASS/DROP/LOG actions, IP ranges, port ranges, wildcard, max rules | High | Existing unit tests |
| BPF Route | XDP stage 50 | LPM mismatch, ARP miss | Unit / Integration | Default route, longest prefix, ARP learn, TTL decrement | High | Existing unit tests |
| BPF L2Learn | XDP stage 80 | MAC table overflow, age race | Unit / Integration | Learn, age, table full, multicast skip | High | Existing unit tests |
| BPF Mirror | XDP stage 70 | Infinite loop, SPAN overload | Unit | Enable/disable, per-port, ingress/egress, stats | Medium | Existing unit tests |
| BPF QoS | XDP qos stage | Priority mismap | Unit | DSCP marking, priority assignment, remarking | Medium | |
| BPF egress_vlan | XDP devmap stage 180 | Tag insertion/removal error | Unit / Integration | Push/pop/swap tags | High | |
| BPF egress_final | XDP devmap stage 190 | Packet drop on egress | Unit | Normal forward, stats update | Medium | |
| BPF STP | XDP | BPDU pass-through failure | Unit | BPDU forward, non-BPDU block in STP state | Medium | Existing unit tests |
| BPF rate_limiter | XDP | Over-limit pass-through | Unit | Rate enforcement, burst, token bucket refill | Medium | Existing unit tests |
| BPF source_guard | XDP | IP/MAC spoof pass | Unit | Valid binding, spoofed MAC, spoofed IP | Medium | Existing unit tests |
| BPF conntrack | XDP | State table corruption | Unit | New/established/related, timeout, table full | Medium | Existing unit tests |
| BPF dhcp_snooping | XDP | Rogue DHCP server pass | Unit | Trusted port, untrusted port, DHCP offer/ack/discover | Medium | |
| BPF arp_learn | XDP | ARP poison entry | Unit | Gratuitous ARP, ARP reply learn, table full | Medium | Existing unit tests |
| BPF afxdp_redirect | XDP stage 85 | AF_XDP socket miss | Unit | Redirect to socket, socket unavailable fallback | Medium | |
| BPF lastcall | XDP stage 90 | Packet leak past pipeline | Unit | devmap redirect, unknown dest drop | High | |
| Loader | CLI: rswitch_loader | Profile load failure, BPF attach fail | Integration | Valid profile, invalid profile, missing module, hot-reload, graceful shutdown | High | |
| Profile parser | profile_parser.c | Malformed YAML crash | Unit / Fuzz | Valid fields, missing fields, wrong types, extends, unknown keys | High | High risk |
| VOQd | rswitch-voqd daemon | Mode transition data loss | Integration | BYPASS→SHADOW→ACTIVE, AF_XDP setup, sw-queues, stats, graceful stop | High | |
| mgmtd (Auth) | POST /api/auth/login,logout | Session hijack, brute force | API / Security | Valid login, wrong password, lockout, session timeout, concurrent sessions | High | |
| mgmtd (System) | GET /api/system/* | Info leak, unauthorized reboot | API | info, health, reboot, shutdown, network CRUD | High | |
| mgmtd (Ports) | GET/PUT /api/ports/* | Config corruption | API | List, stats, config update | Medium | |
| mgmtd (Modules) | GET/POST/PUT /api/modules/* | Hot-reload failure via API | API | List, stats, reload, config | Medium | |
| mgmtd (VLANs) | CRUD /api/vlans | VLAN ID collision, invalid range | API | Create, read, update, delete, boundary IDs (1, 4094) | High | |
| mgmtd (ACLs) | CRUD /api/acls | Rule conflict | API | Create, read, update, delete, priority ordering | High | |
| mgmtd (Routes) | CRUD /api/routes | Routing loop | API | Add, list, delete, overlapping prefixes | Medium | |
| mgmtd (NAT) | /api/nat/* | Conntrack leak | API | Rules CRUD, conntrack list | Medium | |
| mgmtd (Profiles) | CRUD /api/profiles/* | Active profile corruption | API | List, get, apply, update, delete, active | High | |
| mgmtd (Config) | /api/config/* | Rollback failure, data loss | API | Save, snapshot, rollback, reset, export, audit | High | |
| mgmtd (Topology) | GET /api/topology | Stale neighbor data | API | Topology read | Low | |
| mgmtd (Events) | GET /api/events | Event flood | API | Event list, filtering | Low | |
| mgmtd (DHCP) | /api/dhcp-snooping/* | Rogue server config bypass | API | Config, trusted-ports, bindings | Medium | |
| mgmtd (WebSocket) | /api/ws | Connection leak | API / E2E | Connect, receive events, disconnect | Medium | |
| Web Portal | 10 HTML pages | XSS, broken rendering | E2E | Page load, CRUD operations, live refresh, auth flow | Medium | |
| CLI: rswitchctl | CLI binary | Crash on invalid args | CLI | show-pipeline, show-stats, acl-*, mirror-*, help, invalid subcommand | High | |
| CLI: rsportctl | CLI binary | Invalid port ID | CLI | show, set, invalid port | Medium | |
| CLI: rsvlanctl | CLI binary | Invalid VLAN ID | CLI | show, add-port, remove-port, boundary | Medium | |
| CLI: rsaclctl | CLI binary | Rule overflow | CLI | add, delete, show, max rules | Medium | |
| CLI: rsroutectl | CLI binary | Invalid prefix | CLI | add, delete, show, default route | Medium | |
| CLI: rsqosctl | CLI binary | Invalid priority | CLI | show, set, priority range | Medium | |
| CLI: rsflowctl | CLI binary | No flows | CLI | show, clear | Low | |
| CLI: rsnatctl | CLI binary | Invalid rule | CLI | add, delete, show | Medium | |
| CLI: rsvoqctl | CLI binary | Invalid mode | CLI | show, set-mode, stats | Medium | |
| CLI: rstunnelctl | CLI binary | Tunnel conflict | CLI | add, delete, show | Low | |
| CLI: rsdiag | CLI binary | Diagnostic hang | CLI | Full diagnostic run, individual checks | Medium | |
| Prometheus | rswitch-prometheus :9417 | Metric cardinality explosion | Integration | /metrics endpoint, all 16 metric families, label correctness | Medium | |
| Systemd | 5 service units | Service dependency failure | Integration | Start, stop, restart, dependency order, failure recovery | Medium | |
| Scripts | 30+ helper scripts | Destructive cleanup | Integration | install/uninstall, load/unload, hot-reload, voqd_check | Medium | |
| Hot-reload | hot-reload.sh + loader | Packet loss during reload | Integration | Single module reload, verify, list, unload | High | |
| Security | Auth, namespace, BPF maps | Privilege escalation | Security | Map permission, namespace escape, CORS, auth bypass | High | |
| BPF packet_trace | XDP ringbuf output | Missed trace events | Unit / Integration | Load BPF object, ringbuf read, dedup logic | Medium | New in 4.14 |
| BPF afxdp_tx | XDP AF_XDP transmit | TX queue exhaustion | Unit | Frame submit, queue full fallback | Medium | New in 4.14 |
| BPF sflow_tap | XDP sFlow sampling | Sampling rate error | Unit | Sampling ratio, copy to userspace | Low | New in 4.14 |
| BPF nat | XDP stage | NAT table miss | Unit | SNAT/DNAT, conntrack, port exhaustion | Medium | New in 4.14 |
| BPF tunnel_encap | XDP | Header corruption | Unit | VXLAN encap, inner/outer headers | Medium | New in 4.14 |
| BPF tunnel_decap | XDP | Header strip failure | Unit | VXLAN decap, inner frame restore | Medium | New in 4.14 |
| BPF debug_drop | XDP | False positive drop | Unit | Conditional drop, debug filter | Low | New in 4.14 |
| User-space: audit | audit.c library | Log corruption, rotation failure | Unit | Write, rotate, read, JSON escape, auto-create dir | High | New in 4.14 |
| User-space: lifecycle | lifecycle.c library | State loss on restart | Unit / Integration | Init, save_state, restore_state, shutdown, missing dir | High | New in 4.14 |
| User-space: registry | registry.c library | Index stale, ABI mismatch | Unit | update_index, search, install, publish, no-match | High | New in 4.14 |
| User-space: resource_limits | resource_limits.c | OOM kill, FD exhaustion | Unit / Integration | oom_protect, set_fd_limit, mac_pressure, mac_evict_lru | High | New in 4.14 |
| User-space: rollback | rollback.c library | Snapshot corruption, partial apply | Unit / Integration | create_snapshot, list, apply, confirm, rollback_to | High | New in 4.14 |
| User-space: topology | topology.c library | Stale neighbour data | Unit | discover, print_json, missing dir | Medium | New in 4.14 |
| User-space: hot_reload | hot_reload.c | ABI bypass, dry-run ignored | Unit / Integration | reload, dry-run, list, unload, ABI mismatch, invalid cmd | High | New in 4.14 |
| User-space: rs_packet_trace | rs_packet_trace.c | Dedup failure, map open error | Integration | Open map, poll per-CPU, dedup by timestamp, SIGTERM | Medium | New in 4.14 |
| User-space: rs_packet_trace_v2 | rs_packet_trace_v2.c | Ringbuf attach failure | Integration | Load BPF, ringbuf, SIGINT/SIGTERM clean exit | Medium | New in 4.14 |
| User-space: rsqosctl_simple | rsqosctl_simple.c | Unknown cmd no error | CLI | enable, disable, stats, unknown command → exit 1 | Medium | New in 4.14 |
| Profile: dumb | etc/profiles/dumb.yaml | MAC learning active when disabled | Integration | Single-module load, flood-all, no MAC table activity | Medium | New in 4.7 |
| Profile: all-modules | etc/profiles/all-modules.yaml | Missing module BPF object | Integration | 12-module load, stage order verification | High | New in 4.7 |
| Profile: qos-voqd-shadow | etc/profiles/qos-voqd-shadow.yaml | AF_XDP sockets created in shadow | Integration | VOQd shadow mode, AF_XDP disabled, pipeline match | High | New in 4.7 |

---

## 4. Detailed Test Cases

### 4.1 BPF Data Plane — Dispatcher

#### TC-BPF-DISP-001 Normal ingress dispatch

- **Objective**: Verify dispatcher routes packets to the correct first pipeline stage
- **Target**: `bpf/modules/dispatcher.bpf.o`
- **Preconditions**: Dispatcher loaded, prog_array populated with vlan at slot 20
- **Inputs**: Valid Ethernet frame (IPv4/TCP) on active port
- **Steps**:
  1. Load dispatcher and vlan modules via BPF_PROG_RUN
  2. Send well-formed IPv4/TCP packet
  3. Check return action
- **Expected Results**: Packet dispatched to stage 20 (vlan), not dropped
- **Priority**: High
- **Risk Covered**: Pipeline routing failure
- **Automation Hint**: C unit test (extend `test_dispatcher.c`), BPF_PROG_RUN

#### TC-BPF-DISP-002 Empty prog_array fallback

- **Objective**: Verify dispatcher handles missing tail-call target gracefully
- **Target**: `bpf/modules/dispatcher.bpf.o`
- **Preconditions**: Dispatcher loaded, prog_array empty (no modules registered)
- **Inputs**: Valid Ethernet frame
- **Steps**:
  1. Load dispatcher only (no other modules)
  2. Send packet
  3. Check return action and stats
- **Expected Results**: Packet dropped (XDP_DROP), drop counter incremented
- **Priority**: High
- **Risk Covered**: Crash on missing tail-call target
- **Automation Hint**: C unit test

#### TC-BPF-DISP-003 Non-IP packet handling

- **Objective**: Verify dispatcher handles non-IP protocols (ARP, LLDP, BPDU)
- **Target**: `bpf/modules/dispatcher.bpf.o`
- **Preconditions**: Full pipeline loaded
- **Inputs**: ARP request, LLDP frame, STP BPDU
- **Steps**:
  1. Send each frame type through dispatcher
  2. Observe routing behavior
- **Expected Results**: ARP → arp_learn stage, LLDP/BPDU → appropriate handler or pass
- **Priority**: Medium
- **Risk Covered**: Protocol misclassification
- **Automation Hint**: C unit test with crafted packets

### 4.2 BPF Data Plane — VLAN

#### TC-BPF-VLAN-001 Access mode — untagged ingress

- **Objective**: Verify untagged traffic on access port gets assigned to pvid
- **Target**: `bpf/modules/vlan.bpf.o`
- **Preconditions**: Port configured as ACCESS with pvid=100
- **Inputs**: Untagged Ethernet frame
- **Steps**:
  1. Configure port via rs_port_config_map: vlan_mode=ACCESS, pvid=100
  2. Send untagged frame
  3. Check rs_ctx.vlan_id after processing
- **Expected Results**: vlan_id set to 100, packet forwarded
- **Priority**: High
- **Risk Covered**: VLAN assignment failure
- **Automation Hint**: C unit test (extend `test_vlan.c`)

#### TC-BPF-VLAN-002 Access mode — tagged ingress (reject)

- **Objective**: Verify tagged traffic on access port is dropped
- **Target**: `bpf/modules/vlan.bpf.o`
- **Preconditions**: Port configured as ACCESS with pvid=100
- **Inputs**: 802.1Q tagged frame with VLAN 200
- **Steps**:
  1. Send VLAN-tagged frame to access port
  2. Check return action
- **Expected Results**: Packet dropped (XDP_DROP), VLAN enforcement counter incremented
- **Priority**: High
- **Risk Covered**: VLAN enforcement bypass
- **Automation Hint**: C unit test

#### TC-BPF-VLAN-003 Trunk mode — allowed VLAN

- **Objective**: Verify tagged traffic with allowed VLAN passes on trunk port
- **Target**: `bpf/modules/vlan.bpf.o`
- **Preconditions**: Port configured as TRUNK, allowed_vlans includes VLAN 100
- **Inputs**: 802.1Q tagged frame with VLAN 100
- **Steps**:
  1. Configure rs_vlan_map with VLAN 100 membership including this port
  2. Send tagged frame
- **Expected Results**: Packet forwarded, vlan_id=100
- **Priority**: High
- **Risk Covered**: Trunk VLAN filtering
- **Automation Hint**: C unit test

#### TC-BPF-VLAN-004 Trunk mode — disallowed VLAN

- **Objective**: Verify tagged traffic with non-member VLAN is dropped
- **Target**: `bpf/modules/vlan.bpf.o`
- **Preconditions**: Port configured as TRUNK, VLAN 999 not in allowed list
- **Inputs**: 802.1Q tagged frame with VLAN 999
- **Steps**:
  1. Send tagged frame for VLAN not in membership
- **Expected Results**: Packet dropped
- **Priority**: High
- **Risk Covered**: VLAN membership leak
- **Automation Hint**: C unit test

#### TC-BPF-VLAN-005 Trunk mode — native VLAN (untagged ingress)

- **Objective**: Verify untagged traffic on trunk port assigned to native_vlan
- **Target**: `bpf/modules/vlan.bpf.o`
- **Preconditions**: Port configured as TRUNK, native_vlan=1
- **Inputs**: Untagged Ethernet frame
- **Expected Results**: vlan_id set to 1 (native VLAN)
- **Priority**: High
- **Risk Covered**: Native VLAN assignment
- **Automation Hint**: C unit test

#### TC-BPF-VLAN-006 Hybrid mode — mixed traffic

- **Objective**: Verify hybrid port accepts both tagged and untagged traffic
- **Target**: `bpf/modules/vlan.bpf.o`
- **Preconditions**: Port configured as HYBRID, pvid=10, allowed_vlans=[10, 20]
- **Inputs**: Untagged frame, tagged frame VLAN 20, tagged frame VLAN 999
- **Expected Results**: Untagged → vlan 10 (pass), tagged 20 (pass), tagged 999 (drop)
- **Priority**: Medium
- **Risk Covered**: Hybrid mode consistency
- **Automation Hint**: C unit test

#### TC-BPF-VLAN-007 VLAN boundary — ID 1 and 4094

- **Objective**: Verify VLAN boundaries are handled correctly
- **Target**: `bpf/modules/vlan.bpf.o`
- **Preconditions**: Membership configured for VLAN 1 and 4094
- **Inputs**: Tagged frames with VLAN 0, 1, 4094, 4095
- **Expected Results**: VLAN 1 and 4094 pass, VLAN 0 and 4095 drop
- **Priority**: Medium
- **Risk Covered**: Boundary condition
- **Automation Hint**: C unit test

### 4.3 BPF Data Plane — ACL

#### TC-BPF-ACL-001 PASS rule match

- **Objective**: Verify ACL PASS rule allows matching traffic
- **Target**: `bpf/modules/acl.bpf.o`
- **Preconditions**: ACL rule: src=10.0.0.0/8, action=PASS, priority=100
- **Inputs**: Packet from 10.1.2.3
- **Expected Results**: Packet forwarded, ACL pass counter incremented
- **Priority**: High
- **Risk Covered**: Rule matching accuracy
- **Automation Hint**: C unit test (extend `test_acl.c`)

#### TC-BPF-ACL-002 DROP rule match

- **Objective**: Verify ACL DROP rule blocks matching traffic
- **Target**: `bpf/modules/acl.bpf.o`
- **Preconditions**: ACL rule: src=192.168.0.0/16, action=DROP
- **Inputs**: Packet from 192.168.1.1
- **Expected Results**: Packet dropped (XDP_DROP), ACL drop counter incremented
- **Priority**: High
- **Risk Covered**: Rule enforcement
- **Automation Hint**: C unit test

#### TC-BPF-ACL-003 Priority ordering

- **Objective**: Verify higher priority rules take precedence
- **Target**: `bpf/modules/acl.bpf.o`
- **Preconditions**: Rule A: src=10.0.0.0/8, action=PASS, priority=100; Rule B: src=10.1.0.0/16, action=DROP, priority=200
- **Inputs**: Packet from 10.1.2.3
- **Expected Results**: Rule B (priority 200) matches first → packet dropped
- **Priority**: High
- **Risk Covered**: Priority inversion
- **Automation Hint**: C unit test

#### TC-BPF-ACL-004 No matching rule — default action

- **Objective**: Verify packets with no matching rule use default action
- **Target**: `bpf/modules/acl.bpf.o`
- **Preconditions**: No rules matching traffic
- **Inputs**: Packet from 172.16.0.1
- **Expected Results**: Default action applied (pass or drop per config)
- **Priority**: High
- **Risk Covered**: Implicit deny/allow policy
- **Automation Hint**: C unit test

#### TC-BPF-ACL-005 Port range match

- **Objective**: Verify ACL matches on L4 port ranges
- **Target**: `bpf/modules/acl.bpf.o`
- **Preconditions**: Rule: dst-port=80, action=DROP
- **Inputs**: TCP packet to port 80, TCP packet to port 443
- **Expected Results**: Port 80 dropped, port 443 passed
- **Priority**: Medium
- **Risk Covered**: L4 matching accuracy
- **Automation Hint**: C unit test

#### TC-BPF-ACL-006 Maximum rule capacity

- **Objective**: Verify behavior at maximum ACL rule count
- **Target**: `bpf/modules/acl.bpf.o`
- **Preconditions**: ACL map at max_entries
- **Inputs**: Attempt to add one more rule
- **Expected Results**: Insertion fails gracefully, existing rules unaffected
- **Priority**: Medium
- **Risk Covered**: Table overflow
- **Automation Hint**: C unit test

### 4.4 BPF Data Plane — Route

#### TC-BPF-ROUTE-001 Exact prefix match

- **Objective**: Verify LPM routing with exact prefix match
- **Target**: `bpf/modules/route.bpf.o`
- **Preconditions**: Route: 10.0.1.0/24 → port 2
- **Inputs**: Packet destined to 10.0.1.100
- **Expected Results**: Packet redirected to port 2, TTL decremented
- **Priority**: High
- **Risk Covered**: Routing accuracy
- **Automation Hint**: C unit test (extend `test_route.c`)

#### TC-BPF-ROUTE-002 Longest prefix match

- **Objective**: Verify LPM selects the most specific route
- **Target**: `bpf/modules/route.bpf.o`
- **Preconditions**: Routes: 10.0.0.0/8 → port 1, 10.0.1.0/24 → port 2
- **Inputs**: Packet to 10.0.1.50
- **Expected Results**: Packet goes to port 2 (more specific /24)
- **Priority**: High
- **Risk Covered**: LPM correctness
- **Automation Hint**: C unit test

#### TC-BPF-ROUTE-003 Default route fallback

- **Objective**: Verify 0.0.0.0/0 default route catches unmatched traffic
- **Target**: `bpf/modules/route.bpf.o`
- **Preconditions**: Only default route: 0.0.0.0/0 → port 0
- **Inputs**: Packet to 172.16.5.5
- **Expected Results**: Packet routed via default route to port 0
- **Priority**: High
- **Risk Covered**: Default route
- **Automation Hint**: C unit test

#### TC-BPF-ROUTE-004 ARP miss — no ARP entry

- **Objective**: Verify route module handles missing ARP entry for next hop
- **Target**: `bpf/modules/route.bpf.o`
- **Preconditions**: Route exists but no ARP entry for next hop
- **Inputs**: Packet to routed destination
- **Expected Results**: Packet dropped or queued (ARP resolution pending), drop counter incremented
- **Priority**: High
- **Risk Covered**: ARP miss handling
- **Automation Hint**: C unit test

#### TC-BPF-ROUTE-005 TTL expiry

- **Objective**: Verify packets with TTL=1 are dropped
- **Target**: `bpf/modules/route.bpf.o`
- **Preconditions**: Valid route exists
- **Inputs**: IPv4 packet with TTL=1
- **Expected Results**: Packet dropped (TTL expired)
- **Priority**: Medium
- **Risk Covered**: TTL handling
- **Automation Hint**: C unit test

### 4.5 BPF Data Plane — L2Learn

#### TC-BPF-L2L-001 Learn new MAC address

- **Objective**: Verify L2Learn records new source MAC with correct port and timestamp
- **Target**: `bpf/modules/l2learn.bpf.o`
- **Preconditions**: MAC learning enabled, rs_mac_table empty
- **Inputs**: Frame with source MAC AA:BB:CC:DD:EE:01 on port 3
- **Expected Results**: MAC entry created in rs_mac_table: MAC→port 3, timestamp set
- **Priority**: High
- **Risk Covered**: MAC learning functionality
- **Automation Hint**: C unit test (extend `test_l2learn.c`)

#### TC-BPF-L2L-002 MAC table full

- **Objective**: Verify behavior when MAC table reaches max_entries
- **Target**: `bpf/modules/l2learn.bpf.o`
- **Preconditions**: rs_mac_table at capacity
- **Inputs**: Frame with new unknown source MAC
- **Expected Results**: Entry not added (bpf_map_update_elem fails), existing entries unaffected, packet still forwarded
- **Priority**: Medium
- **Risk Covered**: Table overflow
- **Automation Hint**: C unit test

#### TC-BPF-L2L-003 Multicast source MAC skip

- **Objective**: Verify L2Learn does not learn multicast/broadcast source MACs
- **Target**: `bpf/modules/l2learn.bpf.o`
- **Preconditions**: MAC learning enabled
- **Inputs**: Frame with multicast source MAC (bit 0 of first octet set)
- **Expected Results**: No entry created, packet forwarded normally
- **Priority**: Medium
- **Risk Covered**: Invalid MAC learning
- **Automation Hint**: C unit test

#### TC-BPF-L2L-004 MAC port migration

- **Objective**: Verify MAC entry updates when a host moves to a different port
- **Target**: `bpf/modules/l2learn.bpf.o`
- **Preconditions**: MAC AA:BB:CC:DD:EE:01 learned on port 3
- **Inputs**: Same MAC seen on port 5
- **Expected Results**: Entry updated to port 5, timestamp refreshed
- **Priority**: Medium
- **Risk Covered**: Station move handling
- **Automation Hint**: C unit test

### 4.6 BPF Data Plane — Other Modules

#### TC-BPF-STP-001 BPDU passthrough

- **Objective**: Verify STP module forwards BPDU frames
- **Target**: `bpf/modules/stp.bpf.o`
- **Preconditions**: STP module loaded
- **Inputs**: Ethernet frame with destination MAC 01:80:C2:00:00:00
- **Expected Results**: Frame forwarded (not dropped)
- **Priority**: Medium
- **Risk Covered**: BPDU blocking
- **Automation Hint**: C unit test

#### TC-BPF-RL-001 Rate limiter enforcement

- **Objective**: Verify traffic exceeding rate limit is dropped
- **Target**: `bpf/modules/rate_limiter.bpf.o`
- **Preconditions**: Rate limit configured at 1000 pps
- **Inputs**: Burst of 2000 packets in 1 second
- **Expected Results**: ~1000 packets pass, ~1000 dropped
- **Priority**: Medium
- **Risk Covered**: Rate limit bypass
- **Automation Hint**: C unit test with timing

#### TC-BPF-SG-001 Source guard — valid binding

- **Objective**: Verify traffic from valid IP/MAC binding passes
- **Target**: `bpf/modules/source_guard.bpf.o`
- **Preconditions**: Binding: MAC=AA:BB:CC:DD:EE:01, IP=10.0.0.1
- **Inputs**: Packet with matching src MAC and src IP
- **Expected Results**: Packet forwarded
- **Priority**: Medium
- **Risk Covered**: False positive blocking
- **Automation Hint**: C unit test

#### TC-BPF-SG-002 Source guard — spoofed IP

- **Objective**: Verify traffic with spoofed IP is dropped
- **Target**: `bpf/modules/source_guard.bpf.o`
- **Preconditions**: Binding: MAC=AA:BB:CC:DD:EE:01, IP=10.0.0.1
- **Inputs**: Packet with correct MAC but src IP=10.0.0.99
- **Expected Results**: Packet dropped
- **Priority**: Medium
- **Risk Covered**: IP spoofing
- **Automation Hint**: C unit test

#### TC-BPF-CT-001 Conntrack — new connection

- **Objective**: Verify new TCP SYN creates conntrack entry
- **Target**: `bpf/modules/conntrack.bpf.o`
- **Preconditions**: Conntrack module loaded, table empty
- **Inputs**: TCP SYN packet
- **Expected Results**: New conntrack entry created with state=NEW
- **Priority**: Medium
- **Risk Covered**: Connection tracking
- **Automation Hint**: C unit test

#### TC-BPF-CT-002 Conntrack — established flow

- **Objective**: Verify packets matching established conntrack entry pass
- **Target**: `bpf/modules/conntrack.bpf.o`
- **Preconditions**: Conntrack entry exists for flow
- **Inputs**: Data packet matching existing connection
- **Expected Results**: Packet forwarded, state=ESTABLISHED
- **Priority**: Medium
- **Risk Covered**: Stateful bypass
- **Automation Hint**: C unit test

#### TC-BPF-MIRROR-001 SPAN port mirroring

- **Objective**: Verify mirrored copy is sent to SPAN port
- **Target**: `bpf/modules/mirror.bpf.o`
- **Preconditions**: Mirror enabled, SPAN port = 5
- **Inputs**: Any ingress packet on mirrored port
- **Expected Results**: Original packet forwarded normally, copy sent to port 5
- **Priority**: Medium
- **Risk Covered**: Mirror functionality
- **Automation Hint**: C unit test

#### TC-BPF-DHCPS-001 DHCP snooping — untrusted port DHCP server

- **Objective**: Verify DHCP server packets from untrusted ports are dropped
- **Target**: `bpf/modules/dhcp_snooping.bpf.o`
- **Preconditions**: DHCP snooping enabled, port 3 untrusted
- **Inputs**: DHCP OFFER packet on port 3
- **Expected Results**: Packet dropped
- **Priority**: Medium
- **Risk Covered**: Rogue DHCP server
- **Automation Hint**: C unit test

#### TC-BPF-EVLAN-001 Egress VLAN tag push

- **Objective**: Verify egress VLAN module inserts 802.1Q tag for trunk ports
- **Target**: `bpf/modules/egress_vlan.bpf.o`
- **Preconditions**: Egress port configured as TRUNK
- **Inputs**: Packet with vlan_id=100 on egress to trunk port
- **Expected Results**: 802.1Q header inserted with VLAN 100
- **Priority**: High
- **Risk Covered**: Tag corruption
- **Automation Hint**: C unit test

#### TC-BPF-EVLAN-002 Egress VLAN tag strip for access port

- **Objective**: Verify egress VLAN module strips tag for access ports
- **Target**: `bpf/modules/egress_vlan.bpf.o`
- **Preconditions**: Egress port configured as ACCESS
- **Inputs**: Internally tagged packet on egress to access port
- **Expected Results**: 802.1Q header removed, untagged frame sent
- **Priority**: High
- **Risk Covered**: Access port leaking tags
- **Automation Hint**: C unit test

#### TC-BPF-NAT-001 DNAT rule match — dest rewrite and checksum update

- **Objective**: Verify that a matching DNAT rule rewrites destination IP/port and updates IP and L4 checksums
- **Target**: `bpf/modules/nat.bpf.o`
- **Preconditions**: `nat_config_map` enabled; `dnat_rules` populated with external `10.0.0.1:80/TCP` → internal `192.168.1.10:8080`
- **Inputs**: IPv4/TCP packet with `daddr=10.0.0.1`, `dport=80`
- **Steps**:
  1. Load nat module; populate `dnat_rules` with the rule above; set `nat_config_map.enabled=1`
  2. Run BPF_PROG_RUN with the crafted packet
  3. Inspect rewritten packet headers and `nat_stats_map`
- **Expected Results**: `iph->daddr` rewritten to `192.168.1.10`; TCP `dest` rewritten to `8080`; IP checksum and TCP checksum valid; `NAT_STAT_DNAT_PKTS` and `NAT_STAT_DNAT_NEW` incremented; pipeline continues
- **Priority**: High
- **Risk Covered**: DNAT rule application, checksum correctness
- **Automation Hint**: C unit test (extend or create `test_nat.c`), BPF_PROG_RUN

#### TC-BPF-NAT-002 DNAT miss — no matching rule, packet passes

- **Objective**: Verify that a packet with no matching DNAT rule is forwarded unmodified
- **Target**: `bpf/modules/nat.bpf.o`
- **Preconditions**: `nat_config_map` enabled; `dnat_rules` empty
- **Inputs**: IPv4/TCP packet with arbitrary `daddr`/`dport`
- **Steps**:
  1. Load nat module with empty `dnat_rules`; set `nat_config_map.enabled=1`
  2. Run BPF_PROG_RUN
  3. Verify packet headers unchanged; check `nat_stats_map`
- **Expected Results**: IP/TCP headers unchanged; `NAT_STAT_DNAT_MISS` incremented; tail-call continues
- **Priority**: High
- **Risk Covered**: DNAT miss path, packet corruption on miss
- **Automation Hint**: C unit test, BPF_PROG_RUN

#### TC-BPF-NAT-003 SNAT/masquerade — source rewrite for outgoing traffic

- **Objective**: Verify SNAT rewrites source IP/port and creates a tracking entry in `nat_table`
- **Target**: `bpf/modules/nat.bpf.o`
- **Preconditions**: `nat_config_map` enabled; `snat_config_map` entry for `egress_ifindex` with `mode=NAT_MODE_MASQ`, `snat_addr=203.0.113.1`, valid port range
- **Inputs**: IPv4/TCP packet; `ctx->egress_ifindex` matching the SNAT config key
- **Steps**:
  1. Configure `snat_config_map`; set `nat_config_map.enabled=1`
  2. Run BPF_PROG_RUN
  3. Inspect `iph->saddr`, TCP source port, `nat_table` entry, and `nat_stats_map`
- **Expected Results**: `iph->saddr` = `203.0.113.1`; TCP `source` port within configured range; new `nat_table` entry created; IP and TCP checksums valid; `NAT_STAT_SNAT_PKTS` and `NAT_STAT_SNAT_NEW` incremented
- **Priority**: High
- **Risk Covered**: SNAT rewrite, port allocation, new entry creation
- **Automation Hint**: C unit test, BPF_PROG_RUN

#### TC-BPF-NAT-004 NAT disabled — module passthrough

- **Objective**: Verify that when `nat_config_map.enabled=0` the module performs no translation and continues the pipeline
- **Target**: `bpf/modules/nat.bpf.o`
- **Preconditions**: `nat_config_map` with `enabled=0`
- **Inputs**: Any valid IPv4/TCP packet
- **Steps**:
  1. Load nat module; set `nat_config_map.enabled=0`
  2. Run BPF_PROG_RUN
  3. Verify headers unchanged and no stats incremented
- **Expected Results**: Packet passes unchanged; tail-call to next stage; no stat counters modified
- **Priority**: Medium
- **Risk Covered**: Unintended NAT when disabled
- **Automation Hint**: C unit test, BPF_PROG_RUN

#### TC-BPF-NAT-005 Malformed packet — truncated IP/L4 headers

- **Objective**: Verify NAT drops packets with truncated IP or L4 headers and increments error counter
- **Target**: `bpf/modules/nat.bpf.o`
- **Preconditions**: `nat_config_map.enabled=1`
- **Inputs**: (a) Ethernet + partial IPv4 header (less than 20 bytes); (b) complete IPv4 but truncated TCP header
- **Steps**:
  1. Enable NAT module
  2. Run BPF_PROG_RUN with each malformed packet
  3. Check return action and `nat_stats_map`
- **Expected Results**: XDP_DROP returned; `NAT_STAT_ERRORS` incremented for each malformed case
- **Priority**: High
- **Risk Covered**: BPF verifier bounds, kernel memory safety
- **Automation Hint**: C unit test, BPF_PROG_RUN with crafted short packets

#### TC-BPF-NAT-006 UDP with checksum zero — checksum stays zero after DNAT

- **Objective**: Verify that when a UDP packet has checksum=0 (checksum disabled), DNAT does not write a non-zero checksum
- **Target**: `bpf/modules/nat.bpf.o`
- **Preconditions**: `nat_config_map.enabled=1`; DNAT rule present; UDP packet with `check=0`
- **Inputs**: IPv4/UDP packet (`udph->check == 0`) matching a DNAT rule
- **Steps**:
  1. Configure DNAT rule and enable NAT
  2. Run BPF_PROG_RUN with UDP packet having zero checksum
  3. Inspect `udph->check` in output
- **Expected Results**: `udph->check` remains `0` after rewrite (module skips UDP checksum update when original is zero per RFC 768); IP checksum updated correctly
- **Priority**: Medium
- **Risk Covered**: RFC 768 compliance, UDP zero-checksum corruption
- **Automation Hint**: C unit test, BPF_PROG_RUN

#### TC-BPF-NAT-007 Existing nat_table entry reuse — counter updates

- **Objective**: Verify that SNAT reuses an existing `nat_table` entry and updates `last_used_ns`, `pkts`, and `bytes` in place rather than creating a duplicate
- **Target**: `bpf/modules/nat.bpf.o`
- **Preconditions**: `nat_config_map.enabled=1`; SNAT configured; a pre-existing `nat_table` entry for the flow
- **Inputs**: Second IPv4/TCP packet for the same 5-tuple that already has a `nat_table` entry
- **Steps**:
  1. Run first packet to create the `nat_table` entry; record `pkts` and `last_used_ns`
  2. Run second identical packet via BPF_PROG_RUN
  3. Re-read `nat_table` entry
- **Expected Results**: `nat_table` entry `pkts` incremented by 1; `bytes` incremented by packet length; `last_used_ns` updated; `NAT_STAT_SNAT_NEW` not incremented again; translated address/port unchanged
- **Priority**: Medium
- **Risk Covered**: Entry reuse vs. duplicate creation, counter accuracy
- **Automation Hint**: C unit test, BPF_PROG_RUN (two sequential runs on same map)

#### TC-BPF-FLOW-001 Exact flow match — FORWARD action

- **Objective**: Verify that an exact 5-tuple + ingress_ifindex match in `flow_table_map` triggers FORWARD, sets `ctx->egress_ifindex`, and updates match counters
- **Target**: `bpf/modules/flow_table.bpf.o`
- **Preconditions**: `flow_config_map.enabled=1`; `flow_table_map` contains an enabled entry with `action=FLOW_ACTION_FORWARD` and `egress_ifindex=5`
- **Inputs**: IPv4/TCP packet whose 5-tuple + ingress ifindex exactly matches the entry
- **Steps**:
  1. Load flow_table module; insert exact-match entry; enable module
  2. Run BPF_PROG_RUN
  3. Verify `ctx->egress_ifindex`, `flow_entry.match_pkts`, and `flow_stats_map`
- **Expected Results**: `ctx->egress_ifindex=5`; `ctx->action=XDP_REDIRECT`; `match_pkts` incremented; `FLOW_STAT_MATCHES` and `FLOW_STAT_FORWARDS` incremented; pipeline continues
- **Priority**: High
- **Risk Covered**: Core flow table forwarding path
- **Automation Hint**: C unit test, BPF_PROG_RUN

#### TC-BPF-FLOW-002 Flow match — DROP action

- **Objective**: Verify that a flow entry with `action=FLOW_ACTION_DROP` returns XDP_DROP and increments drop stats
- **Target**: `bpf/modules/flow_table.bpf.o`
- **Preconditions**: `flow_config_map.enabled=1`; matching entry with `action=FLOW_ACTION_DROP`
- **Inputs**: Matching IPv4/TCP packet
- **Steps**:
  1. Insert drop-action flow entry; enable module
  2. Run BPF_PROG_RUN
  3. Verify return action and `flow_stats_map`
- **Expected Results**: XDP_DROP returned; `FLOW_STAT_DROPS` and `FLOW_STAT_MATCHES` incremented
- **Priority**: High
- **Risk Covered**: Flow-driven packet drop, ACL-style flows
- **Automation Hint**: C unit test, BPF_PROG_RUN

#### TC-BPF-FLOW-003 Flow miss — default action pass

- **Objective**: Verify that a flow miss with `flow_config.default_action=0` continues the pipeline without dropping
- **Target**: `bpf/modules/flow_table.bpf.o`
- **Preconditions**: `flow_config_map.enabled=1`, `default_action=0`; `flow_table_map` empty
- **Inputs**: Any IPv4 packet
- **Steps**:
  1. Enable module with `default_action=0` and empty table
  2. Run BPF_PROG_RUN
  3. Verify `FLOW_STAT_MISSES` and return action
- **Expected Results**: Tail-call to next stage; `FLOW_STAT_MISSES` incremented; packet not dropped
- **Priority**: High
- **Risk Covered**: Default-pass behavior correctness
- **Automation Hint**: C unit test, BPF_PROG_RUN

#### TC-BPF-FLOW-004 Flow miss — default action drop

- **Objective**: Verify that a flow miss with `flow_config.default_action=1` results in XDP_DROP
- **Target**: `bpf/modules/flow_table.bpf.o`
- **Preconditions**: `flow_config_map.enabled=1`, `default_action=1`; no matching entry
- **Inputs**: Any IPv4 packet
- **Steps**:
  1. Enable module with `default_action=1` and empty table
  2. Run BPF_PROG_RUN
- **Expected Results**: XDP_DROP; `FLOW_STAT_MISSES` and `FLOW_STAT_DROPS` incremented
- **Priority**: High
- **Risk Covered**: Default-deny whitelist mode
- **Automation Hint**: C unit test, BPF_PROG_RUN

#### TC-BPF-FLOW-005 Wildcard matching — progressively relaxed key lookup

- **Objective**: Verify the wildcard fallback chain: exact → ifindex=0 → vlan_id=0 → ports=0 → IPs=0
- **Target**: `bpf/modules/flow_table.bpf.o`
- **Preconditions**: `flow_config_map.enabled=1`; only a wildcard entry (ifindex=0, vlan_id=0, src_port=0, dst_port=0, src_ip=0, dst_ip=0) in `flow_table_map`
- **Inputs**: IPv4/TCP packet that does not exactly match any entry but matches the wildcard
- **Steps**:
  1. Insert only the fully-wildcarded entry with `action=FLOW_ACTION_FORWARD`
  2. Send a packet that has no exact match
  3. Verify the wildcard entry is matched
- **Expected Results**: Wildcard entry matched; `FLOW_STAT_MATCHES` incremented; forward action applied
- **Priority**: Medium
- **Risk Covered**: Wildcard precedence, fallback lookup correctness
- **Automation Hint**: C unit test; try each wildcard level independently

#### TC-BPF-FLOW-006 Flow timeout — idle and hard timeout

- **Objective**: Verify that entries exceeding their idle or hard timeout are deleted from `flow_table_map` and the packet is treated as a miss
- **Target**: `bpf/modules/flow_table.bpf.o`
- **Preconditions**: Flow entry with `idle_timeout_sec=1` (or `hard_timeout_sec=1`); `last_match_ns` (or `created_ns`) set to `now - 2s`
- **Inputs**: Matching IPv4 packet sent after the timeout has elapsed
- **Steps**:
  1. Insert entry with short timeout; manually set timestamps to simulate expiry
  2. Run BPF_PROG_RUN
  3. Verify entry removed from `flow_table_map`; verify miss counter
- **Expected Results**: `bpf_map_delete_elem` removes expired entry; `FLOW_STAT_MISSES` incremented (entry treated as absent); packet follows default action
- **Priority**: Medium
- **Risk Covered**: Stale flow entry accumulation, table exhaustion
- **Automation Hint**: C unit test; manipulate timestamps via map update before BPF_PROG_RUN

#### TC-BPF-FLOW-007 SET_VLAN and SET_DSCP actions

- **Objective**: Verify `FLOW_ACTION_SET_VLAN` writes `ctx->egress_vlan` and `FLOW_ACTION_SET_DSCP` writes `ctx->dscp`
- **Target**: `bpf/modules/flow_table.bpf.o`
- **Preconditions**: `flow_config_map.enabled=1`; two entries — one with `action=FLOW_ACTION_SET_VLAN` (set_vlan_id=100), one with `action=FLOW_ACTION_SET_DSCP` (set_dscp=46)
- **Inputs**: Two separate IPv4 packets, one matching each entry
- **Steps**:
  1. Insert both entries
  2. Run BPF_PROG_RUN for each packet
  3. Inspect `ctx->egress_vlan`, `ctx->dscp`, and `ctx->modified`
- **Expected Results**: VLAN packet: `ctx->egress_vlan=100`, `ctx->modified=1`; DSCP packet: `ctx->dscp=46`, `ctx->modified=1`; both continue pipeline
- **Priority**: Medium
- **Risk Covered**: Metadata modification actions
- **Automation Hint**: C unit test, BPF_PROG_RUN

#### TC-BPF-FLOW-008 CONTROLLER action — event emission

- **Objective**: Verify `FLOW_ACTION_CONTROLLER` emits a `flow_controller_event` to the ring buffer and continues the pipeline
- **Target**: `bpf/modules/flow_table.bpf.o`
- **Preconditions**: `flow_config_map.enabled=1`; entry with `action=FLOW_ACTION_CONTROLLER`; ring buffer (`rs_event_bus`) accessible
- **Inputs**: IPv4/TCP packet matching the controller-action entry
- **Steps**:
  1. Insert controller entry
  2. Run BPF_PROG_RUN
  3. Poll ring buffer for events; verify event fields
- **Expected Results**: `flow_controller_event` emitted with correct `ingress_ifindex`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `pkt_len`; `event_type=FLOW_EVENT_CONTROLLER`; pipeline continues (tail-call next)
- **Priority**: Medium
- **Risk Covered**: Controller event path, ring buffer correctness
- **Automation Hint**: C unit test with ring buffer poll

#### TC-BPF-LACP-001 LACPDU frame — event emission

- **Objective**: Verify that a slow-protocol (EtherType 0x8809) frame causes a `lacp_event` to be emitted to the ring buffer and the packet is passed (XDP_PASS)
- **Target**: `bpf/modules/lacp.bpf.o`
- **Preconditions**: LACP module loaded; `lacp_agg_map` may or may not have an entry for the ingress port
- **Inputs**: Ethernet frame with `h_proto=0x8809` (ETH_P_SLOW)
- **Steps**:
  1. Load lacp module
  2. Run BPF_PROG_RUN with LACPDU-formatted slow-protocol frame
  3. Poll ring buffer; verify `lacp_event` fields
- **Expected Results**: `lacp_event` emitted with correct `ifindex`, `event_type=LACP_EVENT_TYPE`; XDP_PASS returned
- **Priority**: Medium
- **Risk Covered**: LACPDU capture, ring buffer delivery
- **Automation Hint**: C unit test, BPF_PROG_RUN

#### TC-BPF-LACP-002 Non-slow-protocol — normal forwarding

- **Objective**: Verify that a regular data frame (not EtherType 0x8809) on a port with no `lacp_agg_map` entry continues through the pipeline
- **Target**: `bpf/modules/lacp.bpf.o`
- **Preconditions**: `lacp_agg_map` has no entry for the ingress ifindex
- **Inputs**: Standard IPv4/TCP Ethernet frame
- **Steps**:
  1. Ensure no `lacp_agg_map` entry for port
  2. Run BPF_PROG_RUN with normal frame
  3. Verify tail-call issued and no event emitted
- **Expected Results**: Tail-call to next stage; no ring buffer event; XDP_PASS
- **Priority**: Medium
- **Risk Covered**: Non-LACP traffic disruption
- **Automation Hint**: C unit test, BPF_PROG_RUN

#### TC-BPF-LACP-003 DETACHED port state — traffic drop

- **Objective**: Verify that data frames arriving on a port in `LACP_STATE_DETACHED` are dropped (XDP_DROP)
- **Target**: `bpf/modules/lacp.bpf.o`
- **Preconditions**: `lacp_agg_map` entry for ingress ifindex with `state=LACP_STATE_DETACHED`
- **Inputs**: Standard IPv4 Ethernet frame (non-slow-protocol)
- **Steps**:
  1. Insert `lacp_agg_map` entry with `state=LACP_STATE_DETACHED`
  2. Run BPF_PROG_RUN
  3. Verify return action
- **Expected Results**: XDP_DROP; no tail-call
- **Priority**: Medium
- **Risk Covered**: Traffic on detached LAG port
- **Automation Hint**: C unit test, BPF_PROG_RUN

#### TC-BPF-LACP-004 DISTRIBUTING port state — pipeline continuation

- **Objective**: Verify that data frames on a port in `LACP_STATE_DISTRIBUTING` proceed through the pipeline
- **Target**: `bpf/modules/lacp.bpf.o`
- **Preconditions**: `lacp_agg_map` entry with `state=LACP_STATE_DISTRIBUTING`
- **Inputs**: Standard IPv4 Ethernet frame
- **Steps**:
  1. Insert entry with `state=LACP_STATE_DISTRIBUTING`
  2. Run BPF_PROG_RUN
  3. Verify tail-call issued
- **Expected Results**: Tail-call to next stage (RS_TAIL_CALL_NEXT); XDP_PASS
- **Priority**: Medium
- **Risk Covered**: Active LAG port forwarding
- **Automation Hint**: C unit test, BPF_PROG_RUN

#### TC-BPF-LLDP-001 LLDP frame capture — ringbuf event and drop

- **Objective**: Verify that an LLDP frame (EtherType 0x88CC, multicast DST 01:80:C2:00:00:0E) is captured to the ring buffer and then dropped (XDP_DROP)
- **Target**: `bpf/modules/lldp.bpf.o`
- **Preconditions**: LLDP module loaded; `rs_event_bus` ring buffer accessible
- **Inputs**: Ethernet frame with `h_proto=0x88CC` and `h_dest=01:80:C2:00:00:0E`
- **Steps**:
  1. Load lldp module
  2. Run BPF_PROG_RUN with valid LLDP frame (e.g., 128 bytes)
  3. Poll ring buffer for `lldp_frame_event`
- **Expected Results**: `lldp_frame_event` submitted with `event_type=RS_EVENT_LLDP_FRAME`; `frame_len` equals actual packet length; `cap_len <= LLDP_MAX_FRAME_SIZE (2048)`; XDP_DROP returned
- **Priority**: Medium
- **Risk Covered**: LLDP forwarding into data plane (must not forward), capture accuracy
- **Automation Hint**: C unit test, BPF_PROG_RUN with ring buffer poll

#### TC-BPF-LLDP-002 Oversized LLDP frame — truncated capture

- **Objective**: Verify that an LLDP frame larger than `LLDP_MAX_FRAME_SIZE` has its captured payload truncated to `LLDP_MAX_FRAME_SIZE` bytes
- **Target**: `bpf/modules/lldp.bpf.o`
- **Preconditions**: LLDP module loaded
- **Inputs**: LLDP frame of length > 2048 bytes (e.g., 2200 bytes)
- **Steps**:
  1. Craft LLDP frame with `frame_len > 2048`
  2. Run BPF_PROG_RUN
  3. Inspect `lldp_frame_event.cap_len` and `frame_len`
- **Expected Results**: `frame_len=2200`; `cap_len=2048`; event submitted; XDP_DROP
- **Priority**: Medium
- **Risk Covered**: Ring buffer overflow on oversized frames
- **Automation Hint**: C unit test

#### TC-BPF-LLDP-003 Non-LLDP traffic — pipeline continuation

- **Objective**: Verify that non-LLDP frames (wrong EtherType or non-multicast DST) proceed through the pipeline via tail-call
- **Target**: `bpf/modules/lldp.bpf.o`
- **Preconditions**: LLDP module loaded
- **Inputs**: (a) IPv4/TCP frame; (b) ARP frame; (c) frame with `h_dest=01:80:C2:00:00:0E` but `h_proto` not equal to `0x88CC`
- **Steps**:
  1. Run BPF_PROG_RUN for each non-LLDP frame
  2. Verify tail-call issued; no ring buffer event
- **Expected Results**: RS_TAIL_CALL_NEXT issued; no `lldp_frame_event` emitted; XDP_DROP (tail-call path)
- **Priority**: Medium
- **Risk Covered**: Non-LLDP traffic incorrectly captured
- **Automation Hint**: C unit test, BPF_PROG_RUN

#### TC-BPF-SFLOW-001 Sampling with rate=1 — every packet sampled

- **Objective**: Verify that setting `sflow_config.sample_rate=1` causes every packet to be sampled (100% sampling)
- **Target**: `bpf/modules/sflow.bpf.o`
- **Preconditions**: `sflow_config_map.enabled=1`, `sample_rate=1`; no per-port override; `ctx->parsed=1`
- **Inputs**: Any valid IPv4 packet
- **Steps**:
  1. Enable sflow with `sample_rate=1`
  2. Run BPF_PROG_RUN 10 times with the same packet
  3. Check `sflow_counter_map.packets_sampled` and ring buffer events
- **Expected Results**: All 10 packets sampled; `packets_sampled=10`; `packets_seen=10`; 10 `sflow_sample_event` entries emitted
- **Priority**: Medium
- **Risk Covered**: Sampling rate accuracy at rate=1
- **Automation Hint**: C unit test, BPF_PROG_RUN loop

#### TC-BPF-SFLOW-002 Per-port sample rate override

- **Objective**: Verify that a `sflow_port_config_map` entry for the ingress port overrides the global `sflow_config.sample_rate`
- **Target**: `bpf/modules/sflow.bpf.o`
- **Preconditions**: Global `sample_rate=1000`; per-port entry for `ctx->ifindex` with `enabled=1`, `sample_rate=1`; `ctx->parsed=1`
- **Inputs**: Valid IPv4 packet on the configured port
- **Steps**:
  1. Set global rate=1000 and per-port rate=1
  2. Run BPF_PROG_RUN multiple times
  3. Verify sampling occurs at rate=1 (every packet), not rate=1000
- **Expected Results**: Per-port rate overrides global; `packets_sampled` equals `packets_seen` (rate=1); ring buffer event emitted for each packet
- **Priority**: Medium
- **Risk Covered**: Per-port override precedence
- **Automation Hint**: C unit test, BPF_PROG_RUN

#### TC-BPF-SFLOW-003 Module disabled — passthrough

- **Objective**: Verify that when `sflow_config_map.enabled=0` no sampling occurs and the pipeline continues
- **Target**: `bpf/modules/sflow.bpf.o`
- **Preconditions**: `sflow_config_map.enabled=0`; `ctx->parsed=1`
- **Inputs**: Any valid IPv4 packet
- **Steps**:
  1. Disable sflow module
  2. Run BPF_PROG_RUN
  3. Verify `packets_sampled=0` and tail-call issued
- **Expected Results**: No `sflow_sample_event` emitted; `packets_seen` incremented; tail-call to next stage
- **Priority**: Medium
- **Risk Covered**: Passthrough behavior, observability impact when disabled
- **Automation Hint**: C unit test, BPF_PROG_RUN

#### TC-BPF-SFLOW-004 Header capture truncation

- **Objective**: Verify that `captured_len` in `sflow_sample_event` is capped at `SFLOW_MAX_HEADER_BYTES` (256) for large packets
- **Target**: `bpf/modules/sflow.bpf.o`
- **Preconditions**: `sflow_config_map.enabled=1`, `sample_rate=1`, `max_header_bytes=256`; `ctx->parsed=1`
- **Inputs**: Large packet (e.g., 1500 bytes)
- **Steps**:
  1. Send large packet with sampling enabled
  2. Capture emitted `sflow_sample_event`
  3. Verify `packet_len` and `captured_len`
- **Expected Results**: `packet_len=1500`; `captured_len=256`; only first 256 bytes in `evt.header`; pipeline continues
- **Priority**: Medium
- **Risk Covered**: Ring buffer overflow, capture accuracy
- **Automation Hint**: C unit test, BPF_PROG_RUN

#### TC-BPF-TUN-001 VXLAN decapsulation — valid VNI mapped to VLAN

- **Objective**: Verify that a VXLAN-encapsulated frame with a known VNI is decapsulated and `ctx->ingress_vlan` is set to the mapped VLAN ID
- **Target**: `bpf/modules/tunnel.bpf.o`
- **Preconditions**: `tunnel_config_map.enabled=1`; `vxlan_vni_map` contains VNI=100 mapped to `vlan_id=10`
- **Inputs**: Outer IPv4/UDP (dport=4789) frame containing VXLAN header with VNI=100, followed by inner Ethernet frame
- **Steps**:
  1. Enable tunnel module; insert VNI-to-VLAN mapping
  2. Run BPF_PROG_RUN
  3. Verify `ctx->ingress_vlan`, `ctx->modified`, packet head adjustment, and `tunnel_stats_map.vxlan_decap`
- **Expected Results**: Outer headers stripped via `bpf_xdp_adjust_head`; inner Ethernet frame exposed; `ctx->ingress_vlan=10`; `ctx->modified=1`; `vxlan_decap` counter incremented; pipeline continues
- **Priority**: High
- **Risk Covered**: VXLAN decap, VLAN assignment
- **Automation Hint**: C unit test, BPF_PROG_RUN

#### TC-BPF-TUN-002 GRE decapsulation — valid tunnel ID

- **Objective**: Verify that a GRE-encapsulated packet with a known tunnel key is decapsulated and `ctx->ingress_vlan` set
- **Target**: `bpf/modules/tunnel.bpf.o`
- **Preconditions**: `tunnel_config_map.enabled=1`; `gre_tunnel_map` contains key=200 mapped to `vlan_id=20`; outer IPv4 with `protocol=GRE` and GRE_FLAG_KEY set
- **Inputs**: IPv4/GRE frame with key=200 and inner Ethernet payload
- **Steps**:
  1. Enable tunnel; insert GRE key-to-VLAN entry
  2. Run BPF_PROG_RUN
  3. Verify `ctx->ingress_vlan`, `tunnel_stats_map.gre_decap`
- **Expected Results**: GRE+outer IP headers stripped; `ctx->ingress_vlan=20`; `ctx->modified=1`; `gre_decap` incremented; pipeline continues
- **Priority**: High
- **Risk Covered**: GRE decap, tunnel key lookup
- **Automation Hint**: C unit test, BPF_PROG_RUN

#### TC-BPF-TUN-003 Unknown VNI/tunnel — passthrough with counter

- **Objective**: Verify that a VXLAN or GRE packet with an unknown VNI/key is not decapsulated; packet continues pipeline; `unknown_tunnel` counter incremented
- **Target**: `bpf/modules/tunnel.bpf.o`
- **Preconditions**: `tunnel_config_map.enabled=1`; `vxlan_vni_map` and `gre_tunnel_map` empty
- **Inputs**: (a) VXLAN frame with VNI=999; (b) GRE frame with key=999
- **Steps**:
  1. Enable tunnel; leave maps empty
  2. Run BPF_PROG_RUN for each packet
  3. Verify packet data unchanged and `tunnel_stats_map.unknown_tunnel`
- **Expected Results**: Packet headers NOT modified; `unknown_tunnel` incremented for each; pipeline continues via tail-call
- **Priority**: High
- **Risk Covered**: Unknown tunnel passthrough, no header corruption
- **Automation Hint**: C unit test, BPF_PROG_RUN

#### TC-BPF-TUN-004 VXLAN with IP options — decap rejected

- **Objective**: Verify that a VXLAN packet with an outer IP header having `ihl` not equal to 5 (IP options present) is rejected and `vxlan_decap_err` incremented
- **Target**: `bpf/modules/tunnel.bpf.o`
- **Preconditions**: `tunnel_config_map.enabled=1`; VNI present in `vxlan_vni_map`
- **Inputs**: Outer IPv4 frame with `ihl=6` (IP options) and VXLAN/UDP on dport=4789
- **Steps**:
  1. Craft VXLAN packet with `ihl=6`
  2. Run BPF_PROG_RUN
  3. Check `tunnel_stats_map.vxlan_decap_err` and packet state
- **Expected Results**: Decap not performed; `vxlan_decap_err` incremented; pipeline continues
- **Priority**: Medium
- **Risk Covered**: IP options handling, decap guard
- **Automation Hint**: C unit test, BPF_PROG_RUN

#### TC-BPF-TUN-005 GRE with unsupported flags — decap rejected

- **Objective**: Verify that a GRE frame with unsupported flags (CSUM, ROUTING, or SEQ set) or non-zero version field is rejected
- **Target**: `bpf/modules/tunnel.bpf.o`
- **Preconditions**: `tunnel_config_map.enabled=1`
- **Inputs**: (a) GRE with `GRE_FLAG_CSUM=1`; (b) GRE with `GRE_FLAG_SEQ=1`; (c) GRE with `version=1`
- **Steps**:
  1. Craft GRE packets with each unsupported flag/version combination
  2. Run BPF_PROG_RUN for each
  3. Verify `tunnel_stats_map.gre_decap_err`
- **Expected Results**: Each packet rejected from decap; `gre_decap_err` incremented; pipeline continues
- **Priority**: Medium
- **Risk Covered**: GRE flag validation, malformed tunnel packets
- **Automation Hint**: C unit test, BPF_PROG_RUN

#### TC-BPF-TUN-006 Tunnel module disabled — passthrough

- **Objective**: Verify that when `tunnel_config_map.enabled=0` the module performs no decapsulation and continues the pipeline
- **Target**: `bpf/modules/tunnel.bpf.o`
- **Preconditions**: `tunnel_config_map.enabled=0`
- **Inputs**: Valid VXLAN-encapsulated packet
- **Steps**:
  1. Disable tunnel module; set `enabled=0`
  2. Run BPF_PROG_RUN with VXLAN packet
  3. Verify packet unchanged and tail-call issued
- **Expected Results**: No header stripping; `ctx->modified` not set; tail-call to next stage; no stats incremented
- **Priority**: Medium
- **Risk Covered**: Unintended decap when disabled
- **Automation Hint**: C unit test, BPF_PROG_RUN

#### TC-BPF-VETH-001 Valid VOQ meta — redirect to physical NIC

- **Objective**: Verify that a packet with a valid `voq_tx_meta` header is correctly stripped and redirected to the physical NIC via `voq_egress_devmap`
- **Target**: `bpf/modules/veth_egress.bpf.o`
- **Preconditions**: `veth_egress_config_map.enabled=1`; `voq_egress_devmap` contains entry for `egress_ifindex=3`; packet prefixed with `voq_tx_meta` with `egress_ifindex=3`
- **Inputs**: Packet with `VOQ_TX_META_SIZE`-byte metadata header followed by valid Ethernet frame
- **Steps**:
  1. Load veth_egress module; configure devmap and config
  2. Run BPF_PROG_RUN
  3. Verify `bpf_redirect_map` called with `egress_ifindex=3`; `veth_egress_stats.tx_packets` incremented
- **Expected Results**: Meta header stripped via `bpf_xdp_adjust_head`; redirect to devmap entry 3; `tx_packets` and `tx_bytes` updated; `rs_ctx` egress fields populated
- **Priority**: Medium
- **Risk Covered**: VOQ egress redirect, meta header stripping
- **Automation Hint**: C unit test, BPF_PROG_RUN

#### TC-BPF-VETH-002 Missing/truncated VOQ meta — drop

- **Objective**: Verify that a packet too small to contain a full `voq_tx_meta` header results in XDP_DROP and error counter increment
- **Target**: `bpf/modules/veth_egress.bpf.o`
- **Preconditions**: `veth_egress_config_map.enabled=1`
- **Inputs**: Packet shorter than `VOQ_TX_META_SIZE` bytes
- **Steps**:
  1. Craft packet smaller than metadata header
  2. Run BPF_PROG_RUN
  3. Verify return action and `veth_egress_stats.rx_errors`
- **Expected Results**: XDP_DROP; `rx_errors` incremented
- **Priority**: Medium
- **Risk Covered**: Malformed VOQ packet handling
- **Automation Hint**: C unit test, BPF_PROG_RUN

#### TC-BPF-VETH-003 Zero egress_ifindex with default fallback

- **Objective**: Verify that when `voq_tx_meta.egress_ifindex=0` and `VETH_EGRESS_FLAG_STRICT` is not set, the module falls back to `config->default_egress_if`
- **Target**: `bpf/modules/veth_egress.bpf.o`
- **Preconditions**: `veth_egress_config_map.enabled=1`; `flags` does not have `VETH_EGRESS_FLAG_STRICT`; `default_egress_if=4`; `voq_egress_devmap` has entry 4
- **Inputs**: Packet with `voq_tx_meta.egress_ifindex=0`
- **Steps**:
  1. Configure default_egress_if=4; clear STRICT flag
  2. Run BPF_PROG_RUN with egress_ifindex=0 in meta
  3. Verify redirect uses ifindex=4
- **Expected Results**: Redirect to devmap entry 4; `tx_packets` incremented; no error
- **Priority**: Medium
- **Risk Covered**: Default egress fallback
- **Automation Hint**: C unit test, BPF_PROG_RUN

#### TC-BPF-VETH-004 Module disabled — drop

- **Objective**: Verify that when `veth_egress_config_map.enabled=0` all packets are dropped immediately
- **Target**: `bpf/modules/veth_egress.bpf.o`
- **Preconditions**: `veth_egress_config_map.enabled=0`
- **Inputs**: Any packet
- **Steps**:
  1. Disable module
  2. Run BPF_PROG_RUN
  3. Verify return action
- **Expected Results**: XDP_DROP; no redirect attempted
- **Priority**: Medium
- **Risk Covered**: Disabled module traffic leak
- **Automation Hint**: C unit test, BPF_PROG_RUN

#### TC-BPF-EQOS-001 Traffic classification via qos_class_map

- **Objective**: Verify that a `qos_class_map` entry for `{proto, dscp, dport}` assigns the correct priority to `ctx->prio`
- **Target**: `bpf/modules/egress_qos.bpf.o`
- **Preconditions**: `qos_config_ext_map.flags=QOS_FLAG_ENABLED`; `qos_class_map` entry `{TCP, dscp=0, dport=80}` mapped to `priority=2`
- **Inputs**: IPv4/TCP packet with `dport=80`, DSCP=0
- **Steps**:
  1. Enable egress_qos; insert classification entry
  2. Run BPF_PROG_RUN
  3. Inspect `ctx->prio` and `qos_stats_map[QOS_STAT_CLASSIFIED_PACKETS]`
- **Expected Results**: `ctx->prio=2`; `QOS_STAT_CLASSIFIED_PACKETS` incremented; `QOS_STAT_PRIORITY_2` incremented; pipeline continues
- **Priority**: Medium
- **Risk Covered**: Classification accuracy
- **Automation Hint**: C unit test, BPF_PROG_RUN

#### TC-BPF-EQOS-002 Rate limiter drop — token bucket exhausted

- **Objective**: Verify that once `qos_rate_limiters` token bucket for a priority is exhausted, subsequent packets are dropped
- **Target**: `bpf/modules/egress_qos.bpf.o`
- **Preconditions**: `QOS_FLAG_ENABLED | QOS_FLAG_RATE_LIMIT_ENABLED` set; `qos_rate_limiters[0]` configured with very low `rate_bps` and `burst_bytes=1`; packet classified to priority=0
- **Inputs**: Multiple packets classified to priority=0
- **Steps**:
  1. Drain token bucket by sending enough packets to exhaust burst
  2. Send one more packet
  3. Verify drop action and `QOS_STAT_RATE_LIMITED_PACKETS`
- **Expected Results**: Packet dropped (XDP_DROP); `QOS_STAT_RATE_LIMITED_PACKETS` incremented; `RS_DROP_RATE_LIMIT` recorded
- **Priority**: Medium
- **Risk Covered**: Rate enforcement, token bucket exhaustion
- **Automation Hint**: C unit test, BPF_PROG_RUN with rate limiter pre-set to exhausted state

#### TC-BPF-EQOS-003 ECN marking under congestion (ECT packet)

- **Objective**: Verify that a high-priority packet with ECT bits set in IP TOS has CE bits set when queue depth exceeds the ECN threshold
- **Target**: `bpf/modules/egress_qos.bpf.o`
- **Preconditions**: `QOS_FLAG_ENABLED | QOS_FLAG_ECN_ENABLED` set; `voqd_state_map.mode` not equal to `VOQD_MODE_ACTIVE`; `qos_qdepth_map` entry for `{port, priority}` with depth above `qos_config.ecn_threshold`; packet classified to `priority>=QOS_PRIO_HIGH` with ECT(0) in TOS
- **Inputs**: IPv4 packet with `tos & 0x03 = 0x02` (ECT(0)) and high priority
- **Steps**:
  1. Set up congestion state above ECN threshold
  2. Run BPF_PROG_RUN
  3. Inspect `iph->tos` ECN bits and `QOS_STAT_ECN_MARKED`
- **Expected Results**: TOS ECN bits = `0x03` (CE); IP checksum updated; `QOS_STAT_ECN_MARKED` incremented; packet NOT dropped; pipeline continues
- **Priority**: Medium
- **Risk Covered**: ECN marking correctness, checksum integrity
- **Automation Hint**: C unit test, BPF_PROG_RUN

#### TC-BPF-EQOS-004 Low-priority drop under congestion

- **Objective**: Verify that a low-priority packet is dropped (not ECN-marked) when queue depth exceeds threshold
- **Target**: `bpf/modules/egress_qos.bpf.o`
- **Preconditions**: `QOS_FLAG_ENABLED | QOS_FLAG_ECN_ENABLED` set; queue depth above threshold; packet classified to `priority < QOS_PRIO_HIGH` (i.e., priority=0 or 1)
- **Inputs**: IPv4 packet with low priority (e.g., best-effort FTP traffic)
- **Steps**:
  1. Configure congestion state; low priority classification
  2. Run BPF_PROG_RUN
  3. Verify drop and `QOS_STAT_CONGESTION_DROPS`
- **Expected Results**: XDP_DROP; `QOS_STAT_CONGESTION_DROPS` incremented; `RS_DROP_CONGESTION` recorded
- **Priority**: Medium
- **Risk Covered**: Selective drop under congestion
- **Automation Hint**: C unit test, BPF_PROG_RUN

#### TC-BPF-EQOS-005 DSCP rewrite — TOS and checksum update

- **Objective**: Verify that `QOS_FLAG_DSCP_REWRITE` rewrites the IP TOS DSCP field per `cfg->dscp_map[priority]` and updates the IP checksum correctly
- **Target**: `bpf/modules/egress_qos.bpf.o`
- **Preconditions**: `QOS_FLAG_ENABLED | QOS_FLAG_DSCP_REWRITE` set; `qos_config_ext_map.dscp_map[2]=46` (EF); packet classified to priority=2
- **Inputs**: IPv4 packet with original DSCP=0
- **Steps**:
  1. Configure DSCP rewrite for priority=2 to DSCP=46
  2. Run BPF_PROG_RUN
  3. Inspect `iph->tos`, IP checksum, and `QOS_STAT_DSCP_REMARKED`
- **Expected Results**: `iph->tos` upper 6 bits = 46; IP checksum valid (RFC 1624); ECN bits preserved; `QOS_STAT_DSCP_REMARKED` incremented
- **Priority**: Medium
- **Risk Covered**: DSCP rewrite, checksum correctness, ECN bit preservation
- **Automation Hint**: C unit test, BPF_PROG_RUN

#### TC-BPF-EQOS-006 VOQd ACTIVE mode — skip kernel congestion check

- **Objective**: Verify that when `voqd_state_map.mode=VOQD_MODE_ACTIVE` the BPF module skips its own congestion detection and ECN marking (delegating to VOQd)
- **Target**: `bpf/modules/egress_qos.bpf.o`
- **Preconditions**: `QOS_FLAG_ENABLED | QOS_FLAG_ECN_ENABLED` set; `voqd_state_map.mode=VOQD_MODE_ACTIVE`; queue depth above threshold
- **Inputs**: ECT-capable IPv4 packet
- **Steps**:
  1. Set VOQd state to ACTIVE; simulate high queue depth
  2. Run BPF_PROG_RUN
  3. Verify no ECN marking occurs and no congestion drop
- **Expected Results**: `iph->tos` ECN bits unchanged; `QOS_STAT_ECN_MARKED` NOT incremented; `QOS_STAT_CONGESTION_DROPS` NOT incremented; pipeline continues
- **Priority**: Medium
- **Risk Covered**: VOQd/BPF congestion control interaction
- **Automation Hint**: C unit test, BPF_PROG_RUN with `voqd_state_map` pre-set

#### TC-BPF-QCLS-001 DSCP-based classification

- **Objective**: Verify that a non-zero DSCP value in the IP TOS field matches `qos_dscp_map` and assigns the correct traffic class to `ctx->traffic_class`
- **Target**: `bpf/modules/qos_classify.bpf.o`
- **Preconditions**: `qos_config_map.enabled=1`; `qos_dscp_map[46]=3` (EF to class 3)
- **Inputs**: IPv4 packet with `tos = 0xB8` (DSCP=46)
- **Steps**:
  1. Enable qos_classify; insert DSCP-to-class mapping
  2. Run BPF_PROG_RUN
  3. Inspect `ctx->traffic_class` and `qos_stats_map[3]`
- **Expected Results**: `ctx->traffic_class=3`; `qos_stats_map[3]` incremented; pipeline continues
- **Priority**: Medium
- **Risk Covered**: DSCP classification accuracy
- **Automation Hint**: C unit test, BPF_PROG_RUN

#### TC-BPF-QCLS-002 Port-based classification

- **Objective**: Verify that when no DSCP match exists, `qos_port_map` lookup by `{proto, dport}` assigns the correct traffic class
- **Target**: `bpf/modules/qos_classify.bpf.o`
- **Preconditions**: `qos_config_map.enabled=1`; `qos_dscp_map` empty for DSCP=0; `qos_port_map[{TCP, 22}]=3`
- **Inputs**: IPv4/TCP packet with `dport=22`, DSCP=0
- **Steps**:
  1. Enable module; insert port entry; leave DSCP map empty for key 0
  2. Run BPF_PROG_RUN
  3. Inspect `ctx->traffic_class`
- **Expected Results**: `ctx->traffic_class=3`; pipeline continues
- **Priority**: Medium
- **Risk Covered**: Port-based QoS classification
- **Automation Hint**: C unit test, BPF_PROG_RUN

#### TC-BPF-QCLS-003 VLAN-based classification

- **Objective**: Verify that when no DSCP or port match exists, `qos_vlan_map` lookup by `ctx->ingress_vlan` assigns traffic class
- **Target**: `bpf/modules/qos_classify.bpf.o`
- **Preconditions**: `qos_config_map.enabled=1`; DSCP=0 and port not matched; `qos_vlan_map[100]=2`; `ctx->ingress_vlan=100`
- **Inputs**: IPv4 packet on VLAN 100 with DSCP=0 and port not in `qos_port_map`
- **Steps**:
  1. Configure VLAN-to-class mapping
  2. Run BPF_PROG_RUN
  3. Inspect `ctx->traffic_class`
- **Expected Results**: `ctx->traffic_class=2`; pipeline continues
- **Priority**: Medium
- **Risk Covered**: VLAN-based QoS classification
- **Automation Hint**: C unit test, BPF_PROG_RUN

#### TC-BPF-QCLS-004 LPM subnet classification

- **Objective**: Verify that when no DSCP, port, or VLAN match exists, `qos_subnet_map` LPM lookup on source or destination IP assigns traffic class
- **Target**: `bpf/modules/qos_classify.bpf.o`
- **Preconditions**: `qos_config_map.enabled=1`; prior classifiers unmatched; `qos_subnet_map` entry for `192.168.1.0/24` mapped to class 1
- **Inputs**: IPv4 packet with `saddr=192.168.1.42`, unmatched DSCP/port/VLAN
- **Steps**:
  1. Insert LPM entry for `192.168.1.0/24` mapped to class 1
  2. Run BPF_PROG_RUN
  3. Inspect `ctx->traffic_class`
- **Expected Results**: `ctx->traffic_class=1`; `qos_stats_map[1]` incremented; pipeline continues
- **Priority**: Medium
- **Risk Covered**: LPM subnet classification, longest-prefix lookup
- **Automation Hint**: C unit test, BPF_PROG_RUN

#### TC-BPF-QCLS-005 Classification precedence order — DSCP > port > VLAN > subnet

- **Objective**: Verify that when multiple classifiers would each match, DSCP takes precedence over port, port over VLAN, VLAN over subnet
- **Target**: `bpf/modules/qos_classify.bpf.o`
- **Preconditions**: `qos_config_map.enabled=1`; all four maps populated with different class values for the same packet: `qos_dscp_map[46]=3`, `qos_port_map[{TCP,80}]=2`, `qos_vlan_map[100]=1`, subnet entry mapped to class 0
- **Inputs**: IPv4/TCP packet with DSCP=46, dport=80, ingress VLAN=100, src in subnet
- **Steps**:
  1. Populate all four maps with conflicting class values
  2. Run BPF_PROG_RUN
  3. Verify `ctx->traffic_class`
- **Expected Results**: `ctx->traffic_class=3` (DSCP wins); port/VLAN/subnet lookups not reached due to early `matched=1` exit after DSCP hit
- **Priority**: Medium
- **Risk Covered**: Classifier precedence, policy correctness
- **Automation Hint**: C unit test; repeat test with DSCP removed to confirm port wins, etc.

#### TC-BPF-QCLS-006 Module disabled — passthrough

- **Objective**: Verify that when `qos_config_map.enabled=0` the module skips all classification and continues the pipeline, leaving `ctx->traffic_class` at its default
- **Target**: `bpf/modules/qos_classify.bpf.o`
- **Preconditions**: `qos_config_map.enabled=0`
- **Inputs**: Any IPv4 packet
- **Steps**:
  1. Disable qos_classify module
  2. Run BPF_PROG_RUN
  3. Verify `ctx->traffic_class` unchanged and tail-call issued
- **Expected Results**: `ctx->traffic_class` = initial value (not overwritten); no stats incremented; pipeline continues
- **Priority**: Medium
- **Risk Covered**: Unintended classification when disabled
- **Automation Hint**: C unit test, BPF_PROG_RUN

### 4.7 Loader & Profile System

#### TC-LOADER-001 Load valid L2 profile

- **Objective**: Verify loader successfully loads l2.yaml profile
- **Target**: `rswitch_loader`
- **Preconditions**: Build complete, BPF filesystem mounted
- **Inputs**: `sudo ./build/rswitch_loader --profile etc/profiles/l2.yaml --ifaces veth0`
- **Steps**:
  1. Create veth pair
  2. Run loader with l2 profile
  3. Check BPF maps pinned
  4. Check modules loaded
- **Expected Results**: Loader starts, BPF programs attached, maps pinned at /sys/fs/bpf/rs_*
- **Priority**: High
- **Risk Covered**: Basic loading
- **Automation Hint**: Shell integration test (extend `test_loader.sh`)

#### TC-LOADER-002 Load all profiles sequentially

- **Objective**: Verify all 10 shipped profiles load without error
- **Target**: `rswitch_loader`
- **Preconditions**: Build complete
- **Inputs**: Each profile in etc/profiles/
- **Steps**:
  1. For each profile: load → verify → unload → cleanup
- **Expected Results**: All 10 profiles load successfully
- **Priority**: High
- **Risk Covered**: Profile compatibility regression
- **Automation Hint**: Shell integration test

#### TC-LOADER-003 Invalid profile — missing required field

- **Objective**: Verify loader rejects profile missing `name` or `ingress`
- **Target**: `rswitch_loader`, `profile_parser.c`
- **Preconditions**: Build complete
- **Inputs**: YAML with `name:` removed
- **Expected Results**: Loader exits with clear error message, no BPF programs loaded
- **Priority**: High
- **Risk Covered**: Malformed config crash
- **Automation Hint**: Shell test with crafted YAML

#### TC-LOADER-004 Invalid profile — unknown module name

- **Objective**: Verify loader handles reference to non-existent module
- **Target**: `rswitch_loader`
- **Preconditions**: Build complete
- **Inputs**: Profile with `ingress: [nonexistent_module]`
- **Expected Results**: Loader logs error for missing module, continues with available modules or exits
- **Priority**: Medium
- **Risk Covered**: Missing module handling
- **Automation Hint**: Shell test

#### TC-LOADER-005 Profile with `extends`

- **Objective**: Verify profile inheritance works
- **Target**: `profile_parser.c`
- **Preconditions**: Base profile and extending profile exist
- **Inputs**: Profile with `extends: l2.yaml`
- **Expected Results**: Extended profile inherits base settings, overrides take precedence
- **Priority**: Medium
- **Risk Covered**: Inheritance correctness
- **Automation Hint**: Shell test or C unit test

#### TC-LOADER-006 Graceful shutdown

- **Objective**: Verify loader cleans up BPF programs and maps on SIGTERM
- **Target**: `rswitch_loader`
- **Preconditions**: Loader running with loaded profile
- **Inputs**: `kill -TERM <loader_pid>`
- **Steps**:
  1. Start loader
  2. Send SIGTERM
  3. Verify cleanup
- **Expected Results**: XDP programs detached, pinned maps cleaned, process exits 0
- **Priority**: High
- **Risk Covered**: Resource leak on shutdown
- **Automation Hint**: Shell integration test

#### TC-LOADER-007 Hot-reload module

- **Objective**: Verify hot-reload replaces module without service interruption
- **Target**: `scripts/hot-reload.sh`, `rswitch_loader`
- **Preconditions**: Loader running with pipeline
- **Inputs**: `sudo ./scripts/hot-reload.sh reload vlan`
- **Steps**:
  1. Start loader with l2 profile
  2. Execute hot-reload for vlan module
  3. Verify prog_array updated atomically
- **Expected Results**: Module replaced, no packet loss during swap, stats preserved
- **Priority**: High
- **Risk Covered**: Hot-reload data loss
- **Automation Hint**: Shell integration test (extend `test_hotreload.sh`)

#### TC-PROF-PARSE-001 Parser — all field types

- **Objective**: Verify profile parser handles bool, int, string, hex, list types correctly
- **Target**: `profile_parser.c`
- **Preconditions**: Valid profile with all field types
- **Inputs**: YAML with `mac_learning: true`, `default_vlan: 100`, `prio_mask: 0x0C`, `allowed_vlans: [1,100,200]`
- **Expected Results**: All fields parsed to correct C types
- **Priority**: High
- **Risk Covered**: Type parsing errors
- **Automation Hint**: C unit test

#### TC-PROF-PARSE-002 Parser — unknown keys ignored

- **Objective**: Verify parser ignores unknown YAML keys without crash
- **Target**: `profile_parser.c`
- **Inputs**: YAML with `unknown_key: 42`
- **Expected Results**: Key ignored, no error, valid fields parsed correctly
- **Priority**: Medium
- **Risk Covered**: Forward compatibility
- **Automation Hint**: C unit test

#### TC-PROF-PARSE-003 Parser — fuzz with malformed YAML

- **Objective**: Verify parser doesn't crash on malformed input
- **Target**: `profile_parser.c`
- **Preconditions**: Fuzz corpus available
- **Inputs**: Random/malformed YAML strings
- **Expected Results**: Parser returns error without crash, buffer overflow, or UB
- **Priority**: High
- **Risk Covered**: Memory safety
- **Automation Hint**: libFuzzer (extend `fuzz_modules.c`)

#### TC-LOADER-008 Profile loader — dumb profile loads successfully

- **Objective**: Verify loader accepts `dumb.yaml` and attaches only the `lastcall` ingress module
- **Target**: `rswitch_loader`, `etc/profiles/dumb.yaml`
- **Preconditions**: Build complete; veth pair available
- **Inputs**: `sudo ./build/rswitch_loader --profile etc/profiles/dumb.yaml --ifaces veth0`
- **Steps**:
  1. Load dumb profile on veth0
  2. Query attached XDP programs via `bpftool net show dev veth0`
  3. Verify only `lastcall` module stage is present in prog_array slot
  4. Confirm no `rs_mac_table` map activity (mac_learning=false)
- **Expected Results**: Loader exits 0; single-module pipeline attached; MAC table remains empty under traffic
- **Priority**: Medium
- **Risk Covered**: Minimal-pipeline correctness; flood-all behaviour when MAC learning disabled
- **Automation Hint**: Shell integration test

#### TC-LOADER-009 Profile loader — all-modules profile loads all 12 modules

- **Objective**: Verify loader registers all 9 ingress + 3 egress modules from `all-modules.yaml`
- **Target**: `rswitch_loader`, `etc/profiles/all-modules.yaml`
- **Preconditions**: Build complete; 2 veth pairs available; all `.bpf.o` files present in `./build/bpf/`
- **Inputs**: `sudo ./build/rswitch_loader --profile etc/profiles/all-modules.yaml --ifaces veth0,veth1`
- **Steps**:
  1. Load all-modules profile
  2. Run `sudo ./build/rswitchctl show-pipeline`
  3. Verify ingress stages for: vlan, dhcp_snoop, arp_learn, acl, mirror, route, l2learn, afxdp_redirect, lastcall
  4. Verify egress stages for: egress_qos, egress_vlan, egress_final
- **Expected Results**: 12 modules reported; no missing stages; loader exits 0
- **Priority**: High
- **Risk Covered**: Full-pipeline load ordering; module ABI compatibility across all modules
- **Automation Hint**: Shell integration test (`rswitchctl show-pipeline` output parsing)

#### TC-LOADER-010 Profile loader — qos-voqd-shadow profile starts VOQd in shadow mode

- **Objective**: Verify `qos-voqd-shadow.yaml` loads correctly with VOQd in shadow mode and `enable_afxdp=false`
- **Target**: `rswitch_loader`, `rswitch-voqd`, `etc/profiles/qos-voqd-shadow.yaml`
- **Preconditions**: Build complete; veth pair available; no existing VOQd process
- **Inputs**: `sudo ./build/rswitch_loader --profile etc/profiles/qos-voqd-shadow.yaml --ifaces veth0,veth1`
- **Steps**:
  1. Load qos-voqd-shadow profile
  2. Confirm VOQd process starts with `mode=shadow`
  3. Verify `enable_afxdp=false` (no AF_XDP sockets created; `ss -a` shows no XDP sockets)
  4. Send traffic; confirm packets processed without AF_XDP redirection
  5. Verify ingress pipeline: vlan → l2learn → afxdp_redirect → lastcall
- **Expected Results**: VOQd runs in shadow mode; AF_XDP sockets absent; pipeline matches profile spec
- **Priority**: High
- **Risk Covered**: VOQd shadow-mode startup; AF_XDP disabled path; profile-to-process configuration propagation
- **Automation Hint**: Shell integration test (process inspection + `ss` + pipeline query)

### 4.8 CLI Tools

#### TC-CLI-RSCTL-001 rswitchctl — show-pipeline

- **Objective**: Verify `rswitchctl show-pipeline` displays loaded modules
- **Target**: `rswitchctl`
- **Preconditions**: Loader running with l2 profile
- **Inputs**: `sudo ./build/rswitchctl show-pipeline`
- **Expected Results**: Output lists module names and stage numbers in order
- **Priority**: High
- **Risk Covered**: Pipeline visibility
- **Automation Hint**: Shell test

#### TC-CLI-RSCTL-002 rswitchctl — show-stats

- **Objective**: Verify `rswitchctl show-stats` displays per-port statistics
- **Target**: `rswitchctl`
- **Preconditions**: Loader running
- **Inputs**: `sudo ./build/rswitchctl show-stats`
- **Expected Results**: Output shows RX/TX/drop counters per interface
- **Priority**: High
- **Risk Covered**: Stats visibility
- **Automation Hint**: Shell test

#### TC-CLI-RSCTL-003 rswitchctl — help output

- **Objective**: Verify rswitchctl shows usage without crash
- **Target**: `rswitchctl`
- **Preconditions**: Build complete
- **Inputs**: `./build/rswitchctl` (no args) or `--help`
- **Expected Results**: Usage text printed, exit code 0 or 1
- **Priority**: Medium
- **Risk Covered**: UX
- **Automation Hint**: Shell test (already in `test_loader.sh`)

#### TC-CLI-RSCTL-004 rswitchctl — invalid subcommand

- **Objective**: Verify graceful handling of invalid subcommand
- **Target**: `rswitchctl`
- **Inputs**: `./build/rswitchctl nonexistent-command`
- **Expected Results**: Error message + usage, non-zero exit code
- **Priority**: Medium
- **Risk Covered**: Crash on bad input
- **Automation Hint**: Shell test

#### TC-CLI-PORT-001 rsportctl — show all ports

- **Objective**: Verify rsportctl lists port state
- **Target**: `rsportctl`
- **Preconditions**: Loader running
- **Inputs**: `sudo ./build/rsportctl show`
- **Expected Results**: Port list with interface names, link state, VLAN mode
- **Priority**: Medium
- **Risk Covered**: Port visibility
- **Automation Hint**: Shell test

#### TC-CLI-VLAN-001 rsvlanctl — show VLANs

- **Objective**: Verify rsvlanctl displays VLAN table
- **Target**: `rsvlanctl`
- **Preconditions**: Loader running, VLANs configured
- **Inputs**: `sudo ./build/rsvlanctl show`
- **Expected Results**: VLAN ID, name, member ports listed
- **Priority**: Medium
- **Risk Covered**: VLAN visibility
- **Automation Hint**: Shell test

#### TC-CLI-VLAN-002 rsvlanctl — add-port and remove-port

- **Objective**: Verify VLAN port membership modification via CLI
- **Target**: `rsvlanctl`
- **Preconditions**: Loader running
- **Inputs**: `rsvlanctl add-port veth0 trunk 100,200` then `rsvlanctl remove-port veth0 100`
- **Expected Results**: Port added/removed from VLAN membership, map updated
- **Priority**: Medium
- **Risk Covered**: VLAN config mutation
- **Automation Hint**: Shell test

#### TC-CLI-ACL-001 rsaclctl — CRUD cycle

- **Objective**: Verify ACL rule add/show/delete via CLI
- **Target**: `rsaclctl`
- **Preconditions**: Loader running with ACL module
- **Inputs**: Add rule, show rules, delete rule
- **Expected Results**: Rule appears after add, disappears after delete
- **Priority**: High
- **Risk Covered**: ACL management
- **Automation Hint**: Shell test

#### TC-CLI-ROUTE-001 rsroutectl — add/show/delete route

- **Objective**: Verify route management via CLI
- **Target**: `rsroutectl`
- **Preconditions**: Loader running with route module
- **Inputs**: `rsroutectl add 10.0.0.0/8 via 192.168.1.1`, `rsroutectl show`, `rsroutectl delete 10.0.0.0/8`
- **Expected Results**: Route added to LPM map, visible in show, removed on delete
- **Priority**: Medium
- **Risk Covered**: Route management
- **Automation Hint**: Shell test

#### TC-CLI-QOS-001 rsqosctl — show QoS state

- **Objective**: Verify QoS state visibility
- **Target**: `rsqosctl`
- **Preconditions**: Loader running with QoS
- **Inputs**: `sudo ./build/rsqosctl show`
- **Expected Results**: QoS configuration and stats displayed
- **Priority**: Medium
- **Risk Covered**: QoS visibility
- **Automation Hint**: Shell test

#### TC-CLI-VOQ-001 rsvoqctl — show VOQd state

- **Objective**: Verify VOQd state visibility via CLI
- **Target**: `rsvoqctl`
- **Preconditions**: VOQd running
- **Inputs**: `sudo ./build/rsvoqctl show`
- **Expected Results**: VOQd mode, port count, queue depth, stats displayed
- **Priority**: Medium
- **Risk Covered**: VOQd visibility
- **Automation Hint**: Shell test

#### TC-CLI-DIAG-001 rsdiag — full diagnostic run

- **Objective**: Verify rsdiag completes without crash
- **Target**: `rsdiag`
- **Preconditions**: Build complete
- **Inputs**: `sudo ./build/rsdiag`
- **Expected Results**: Diagnostic output covering programs, maps, interfaces, no crash
- **Priority**: Medium
- **Risk Covered**: Diagnostic tool stability
- **Automation Hint**: Shell test

#### TC-CLI-NOMAP-001 CLI tools — graceful failure when maps not pinned

- **Objective**: Verify all CLI tools exit gracefully when BPF maps are not available
- **Target**: All 11 CLI tools
- **Preconditions**: No loader running, no maps pinned
- **Inputs**: Run each CLI tool
- **Expected Results**: Clear error message "Failed to open map" or similar, non-zero exit
- **Priority**: Medium
- **Risk Covered**: Crash without loader
- **Automation Hint**: Shell test (already in `functional_test.sh`)

### 4.9 REST API (mgmtd)

#### TC-API-AUTH-001 Login — valid credentials

- **Objective**: Verify successful login returns session cookie
- **Target**: `POST /api/auth/login`
- **Preconditions**: mgmtd running with auth_enabled=true, auth_user=admin, auth_password=rswitch
- **Inputs**: `{"username":"admin","password":"rswitch"}`
- **Expected Results**: 200 OK, Set-Cookie header with session token
- **Priority**: High
- **Risk Covered**: Authentication
- **Automation Hint**: curl/Python (pytest-httpx)

#### TC-API-AUTH-002 Login — wrong password

- **Objective**: Verify login rejection with wrong password
- **Target**: `POST /api/auth/login`
- **Inputs**: `{"username":"admin","password":"wrong"}`
- **Expected Results**: 401 Unauthorized, no cookie set
- **Priority**: High
- **Risk Covered**: Auth bypass
- **Automation Hint**: curl/Python

#### TC-API-AUTH-003 Login — rate limiting lockout

- **Objective**: Verify account lockout after max failed attempts
- **Target**: `POST /api/auth/login`
- **Preconditions**: rate_limit_max_fails=5, rate_limit_lockout_sec=300
- **Inputs**: 5 consecutive wrong passwords, then correct password
- **Steps**:
  1. Send 5 failed login attempts
  2. Send correct credentials
- **Expected Results**: 6th attempt (even with correct password) returns 429 or 403 for lockout period
- **Priority**: High
- **Risk Covered**: Brute force
- **Automation Hint**: Python test with timing

#### TC-API-AUTH-004 Logout — session invalidation

- **Objective**: Verify logout invalidates session
- **Target**: `POST /api/auth/logout`
- **Steps**:
  1. Login successfully
  2. Logout
  3. Attempt authenticated API call with old cookie
- **Expected Results**: Step 3 returns 401
- **Priority**: High
- **Risk Covered**: Session persistence after logout
- **Automation Hint**: curl/Python

#### TC-API-AUTH-005 Unauthenticated access — reject

- **Objective**: Verify API endpoints require authentication
- **Target**: All API endpoints except login
- **Inputs**: `GET /api/system/info` without cookie
- **Expected Results**: 401 Unauthorized
- **Priority**: High
- **Risk Covered**: Auth bypass
- **Automation Hint**: curl/Python

#### TC-API-AUTH-006 Session timeout

- **Objective**: Verify session expires after configured timeout
- **Target**: `POST /api/auth/login`
- **Preconditions**: session_timeout=5 (low value for testing)
- **Steps**:
  1. Login
  2. Wait > 5 seconds
  3. Attempt authenticated request
- **Expected Results**: 401 Unauthorized after timeout
- **Priority**: Medium
- **Risk Covered**: Stale sessions
- **Automation Hint**: Python test with sleep

#### TC-API-SYS-001 System info

- **Objective**: Verify /api/system/info returns correct data
- **Target**: `GET /api/system/info`
- **Preconditions**: Authenticated session
- **Expected Results**: JSON with hostname, version, uptime, port_count, management_ip
- **Priority**: High
- **Risk Covered**: Info accuracy
- **Automation Hint**: curl/Python

#### TC-API-SYS-002 Health check

- **Objective**: Verify /api/system/health returns status
- **Target**: `GET /api/system/health`
- **Expected Results**: 200 OK with health status JSON
- **Priority**: High
- **Risk Covered**: Monitoring integration
- **Automation Hint**: curl/Python

#### TC-API-SYS-003 System reboot — requires auth

- **Objective**: Verify reboot endpoint works and requires auth
- **Target**: `POST /api/system/reboot`
- **Steps**:
  1. Call without auth → 401
  2. Call with auth → 200 (or accepted)
- **Expected Results**: Auth required; with auth, reboot initiated
- **Priority**: Medium
- **Risk Covered**: Unauthorized reboot
- **Automation Hint**: curl (skip actual reboot in CI)

#### TC-API-SYS-004 Network config — GET/PUT

- **Objective**: Verify management network configuration retrieval and update
- **Target**: `GET/PUT /api/system/network`
- **Steps**:
  1. GET current network config
  2. PUT updated config
  3. GET again to verify
- **Expected Results**: Config returned, updated, persisted
- **Priority**: Medium
- **Risk Covered**: Network misconfiguration
- **Automation Hint**: curl/Python

#### TC-API-PORT-001 List ports

- **Objective**: Verify /api/ports returns all port data
- **Target**: `GET /api/ports`
- **Expected Results**: JSON array of ports with interface, ifindex, link_state, stats, vlan_mode
- **Priority**: High
- **Risk Covered**: Port visibility
- **Automation Hint**: curl/Python

#### TC-API-PORT-002 Port stats

- **Objective**: Verify per-port statistics endpoint
- **Target**: `GET /api/ports/:id/stats`
- **Inputs**: Valid port ID
- **Expected Results**: JSON with rx_packets, tx_packets, rx_bytes, tx_bytes, drops, errors
- **Priority**: Medium
- **Risk Covered**: Stats accuracy
- **Automation Hint**: curl/Python

#### TC-API-PORT-003 Port config update

- **Objective**: Verify port configuration change via API
- **Target**: `PUT /api/ports/:id/config`
- **Inputs**: `{"vlan_mode":"trunk","native_vlan":1}`
- **Expected Results**: 200 OK, BPF map updated, subsequent GET reflects change
- **Priority**: Medium
- **Risk Covered**: Config mutation
- **Automation Hint**: curl/Python

#### TC-API-MOD-001 List modules

- **Objective**: Verify /api/modules returns loaded pipeline
- **Target**: `GET /api/modules`
- **Expected Results**: JSON with module names, stages, packet counts
- **Priority**: Medium
- **Risk Covered**: Pipeline visibility
- **Automation Hint**: curl/Python

#### TC-API-MOD-002 Module hot-reload via API

- **Objective**: Verify module reload through REST API
- **Target**: `POST /api/modules/:name/reload`
- **Inputs**: Module name = "vlan"
- **Expected Results**: 200 OK, module reloaded atomically
- **Priority**: Medium
- **Risk Covered**: API-driven hot-reload
- **Automation Hint**: curl/Python

#### TC-API-VLAN-001 VLAN CRUD — full cycle

- **Objective**: Verify VLAN create, read, update, delete via API
- **Target**: `/api/vlans`
- **Steps**:
  1. `POST /api/vlans` — create VLAN 100
  2. `GET /api/vlans` — verify VLAN 100 exists
  3. `PUT /api/vlans/100` — update name
  4. `GET /api/vlans` — verify update
  5. `DELETE /api/vlans/100` — delete
  6. `GET /api/vlans` — verify deleted
- **Expected Results**: Full CRUD cycle succeeds, BPF maps updated
- **Priority**: High
- **Risk Covered**: VLAN management
- **Automation Hint**: Python test

#### TC-API-VLAN-002 VLAN boundary IDs

- **Objective**: Verify boundary VLAN IDs (1, 4094) accepted; invalid (0, 4095, -1) rejected
- **Target**: `POST /api/vlans`
- **Inputs**: vlan_id values: 0, 1, 4094, 4095, -1, 65535
- **Expected Results**: 1 and 4094 succeed; others return 400
- **Priority**: Medium
- **Risk Covered**: Boundary validation
- **Automation Hint**: Python test

#### TC-API-VLAN-003 Duplicate VLAN creation

- **Objective**: Verify creating VLAN with existing ID is handled
- **Target**: `POST /api/vlans`
- **Preconditions**: VLAN 100 already exists
- **Inputs**: `{"vlan_id":100,"name":"Duplicate"}`
- **Expected Results**: 409 Conflict or update semantics
- **Priority**: Medium
- **Risk Covered**: Duplicate handling
- **Automation Hint**: Python test

#### TC-API-ACL-001 ACL CRUD — full cycle

- **Objective**: Verify ACL rule create, read, update, delete via API
- **Target**: `/api/acls`
- **Steps**:
  1. POST create rule
  2. GET verify exists
  3. PUT update rule
  4. DELETE rule
  5. GET verify deleted
- **Expected Results**: Full CRUD succeeds
- **Priority**: High
- **Risk Covered**: ACL management
- **Automation Hint**: Python test

#### TC-API-ROUTE-001 Route CRUD — full cycle

- **Objective**: Verify route add, list, delete via API
- **Target**: `/api/routes`
- **Steps**:
  1. POST add route
  2. GET list routes
  3. DELETE route
- **Expected Results**: Route appears, then disappears
- **Priority**: High
- **Risk Covered**: Route management
- **Automation Hint**: Python test

#### TC-API-NAT-001 NAT rules — list and create

- **Objective**: Verify NAT rule management
- **Target**: `/api/nat/rules`, `/api/nat/conntrack`
- **Steps**:
  1. POST create NAT rule
  2. GET list rules
  3. GET conntrack table
- **Expected Results**: Rule created, listed, conntrack accessible
- **Priority**: Medium
- **Risk Covered**: NAT management
- **Automation Hint**: Python test

#### TC-API-PROF-001 Profile CRUD — full cycle

- **Objective**: Verify profile list, get, update, delete, apply
- **Target**: `/api/profiles/*`
- **Steps**:
  1. GET /api/profiles — list
  2. GET /api/profiles/l2 — get details
  3. GET /api/profiles/active — check active
  4. POST /api/profiles/apply — apply different profile
  5. GET /api/profiles/active — verify changed
- **Expected Results**: All operations succeed
- **Priority**: High
- **Risk Covered**: Profile management
- **Automation Hint**: Python test

#### TC-API-PROF-002 Delete active profile — reject

- **Objective**: Verify active profile cannot be deleted
- **Target**: `DELETE /api/profiles/:name`
- **Preconditions**: Profile "l2" is active
- **Inputs**: `DELETE /api/profiles/l2`
- **Expected Results**: 409 Conflict or similar rejection
- **Priority**: Medium
- **Risk Covered**: Active profile deletion
- **Automation Hint**: Python test

#### TC-API-CFG-001 Config snapshot and rollback

- **Objective**: Verify config save, snapshot, and rollback
- **Target**: `/api/config/*`
- **Steps**:
  1. POST /api/config/save — save current
  2. POST /api/config/snapshot — create named snapshot
  3. GET /api/config/snapshots — verify listed
  4. Make a change (e.g., add VLAN)
  5. POST /api/config/rollback/:id — rollback
  6. Verify change is undone
- **Expected Results**: Full snapshot/rollback cycle works
- **Priority**: High
- **Risk Covered**: Config data loss
- **Automation Hint**: Python test

#### TC-API-CFG-002 Config reset to defaults

- **Objective**: Verify config reset clears customizations
- **Target**: `POST /api/config/reset`
- **Preconditions**: Custom VLANs/ACLs configured
- **Expected Results**: All custom config cleared, defaults restored
- **Priority**: Medium
- **Risk Covered**: Incomplete reset
- **Automation Hint**: Python test

#### TC-API-CFG-003 Config export

- **Objective**: Verify config export produces valid downloadable config
- **Target**: `POST /api/config/export`
- **Expected Results**: Response contains complete config (YAML or JSON)
- **Priority**: Medium
- **Risk Covered**: Export completeness
- **Automation Hint**: Python test

#### TC-API-CFG-004 Config audit log

- **Objective**: Verify audit log records configuration changes
- **Target**: `GET /api/config/audit`
- **Preconditions**: At least one config change made
- **Expected Results**: Audit entries with timestamp, action, user, details
- **Priority**: Medium
- **Risk Covered**: Audit trail
- **Automation Hint**: Python test

#### TC-API-TOPO-001 Topology endpoint

- **Objective**: Verify topology returns neighbor data
- **Target**: `GET /api/topology`
- **Expected Results**: JSON with neighbor information (LLDP/STP data)
- **Priority**: Low
- **Risk Covered**: Topology visibility
- **Automation Hint**: curl/Python

#### TC-API-EVT-001 Events endpoint

- **Objective**: Verify event log retrieval
- **Target**: `GET /api/events`
- **Expected Results**: JSON array of events with timestamp, type, details
- **Priority**: Low
- **Risk Covered**: Event visibility
- **Automation Hint**: curl/Python

#### TC-API-DHCP-001 DHCP snooping config via API

- **Objective**: Verify DHCP snooping configuration and trusted port management
- **Target**: `/api/dhcp-snooping/*`
- **Steps**:
  1. GET /api/dhcp-snooping — current state
  2. POST /api/dhcp-snooping/config — enable
  3. POST /api/dhcp-snooping/trusted-ports — set trusted ports
  4. GET /api/dhcp-snooping — verify
- **Expected Results**: Config persisted, trusted ports updated
- **Priority**: Medium
- **Risk Covered**: DHCP snooping management
- **Automation Hint**: Python test

#### TC-API-WS-001 WebSocket connection

- **Objective**: Verify WebSocket event stream connects and receives events
- **Target**: `/api/ws`
- **Steps**:
  1. Login and get session cookie
  2. Open WebSocket connection to /api/ws
  3. Wait for events (or trigger one)
  4. Verify event format
- **Expected Results**: Connection established, events received as JSON
- **Priority**: Medium
- **Risk Covered**: Real-time event delivery
- **Automation Hint**: Python (websockets library)

#### TC-API-WS-002 WebSocket — unauthenticated reject

- **Objective**: Verify WebSocket rejects unauthenticated connections
- **Target**: `/api/ws`
- **Inputs**: WebSocket connect without session cookie
- **Expected Results**: Connection rejected (401 or close)
- **Priority**: Medium
- **Risk Covered**: Unauthorized event access
- **Automation Hint**: Python

#### TC-API-INV-001 Invalid JSON payload

- **Objective**: Verify API handles malformed JSON gracefully
- **Target**: `POST /api/vlans`
- **Inputs**: `{"vlan_id":` (incomplete JSON), `not json at all`, empty body
- **Expected Results**: 400 Bad Request, descriptive error message
- **Priority**: Medium
- **Risk Covered**: Input validation
- **Automation Hint**: Python test

#### TC-API-INV-002 Unknown endpoint — 404

- **Objective**: Verify unknown API paths return 404
- **Target**: `GET /api/nonexistent`
- **Expected Results**: 404 Not Found
- **Priority**: Low
- **Risk Covered**: Error handling
- **Automation Hint**: curl

#### TC-API-INV-003 Wrong HTTP method — 405

- **Objective**: Verify wrong method returns appropriate error
- **Target**: `DELETE /api/system/info` (should be GET only)
- **Expected Results**: 405 Method Not Allowed or 404
- **Priority**: Low
- **Risk Covered**: Method validation
- **Automation Hint**: curl

### 4.10 Daemons & VOQd

#### TC-VOQD-001 VOQd — BYPASS mode start

- **Objective**: Verify VOQd starts in BYPASS mode
- **Target**: `rswitch-voqd`
- **Inputs**: `sudo ./build/rswitch-voqd -m bypass -p 4`
- **Expected Results**: Process starts, logs mode=BYPASS, no AF_XDP sockets created
- **Priority**: High
- **Risk Covered**: Mode initialization
- **Automation Hint**: Shell test

#### TC-VOQD-002 VOQd — SHADOW mode

- **Objective**: Verify VOQd shadow mode observes without affecting traffic
- **Target**: `rswitch-voqd`
- **Inputs**: `sudo ./build/rswitch-voqd -m shadow -p 4 -i veth0`
- **Expected Results**: Process starts, stats collected, no packet redirect
- **Priority**: High
- **Risk Covered**: Shadow side effects
- **Automation Hint**: Shell test

#### TC-VOQD-003 VOQd — ACTIVE mode with software queues

- **Objective**: Verify VOQd active mode with software queue emulation
- **Target**: `rswitch-voqd`
- **Inputs**: `sudo ./build/rswitch-voqd -m active -q -Q 2048 -i veth0`
- **Expected Results**: AF_XDP sockets created, software queues initialized, packets redirected
- **Priority**: High
- **Risk Covered**: Active mode functionality
- **Automation Hint**: Shell integration test

#### TC-VOQD-004 VOQd — zero-copy flag

- **Objective**: Verify zero-copy AF_XDP mode (NIC-dependent)
- **Target**: `rswitch-voqd`
- **Inputs**: `sudo ./build/rswitch-voqd -m active -z -i veth0`
- **Expected Results**: Zero-copy attempted; falls back gracefully if NIC doesn't support it
- **Priority**: Medium
- **Risk Covered**: Zero-copy compatibility
- **Automation Hint**: Shell test (veth won't support zero-copy — test graceful fallback)

#### TC-VOQD-005 VOQd — statistics interval

- **Objective**: Verify stats printing at configured interval
- **Target**: `rswitch-voqd`
- **Inputs**: `sudo ./build/rswitch-voqd -m shadow -S 2 -i veth0`
- **Steps**:
  1. Start with -S 2 (2 second interval)
  2. Capture stdout for 5 seconds
  3. Count stats output lines
- **Expected Results**: Stats printed approximately every 2 seconds
- **Priority**: Low
- **Risk Covered**: Stats reporting
- **Automation Hint**: Shell test with timeout

#### TC-VOQD-006 VOQd — graceful shutdown

- **Objective**: Verify VOQd cleans up AF_XDP sockets on SIGTERM
- **Target**: `rswitch-voqd`
- **Steps**:
  1. Start VOQd in active mode
  2. Send SIGTERM
  3. Verify sockets closed and maps updated
- **Expected Results**: Clean exit, no resource leaks
- **Priority**: High
- **Risk Covered**: Resource leak
- **Automation Hint**: Shell test

#### TC-VOQD-007 VOQd — invalid CLI arguments

- **Objective**: Verify VOQd rejects invalid arguments gracefully
- **Target**: `rswitch-voqd`
- **Inputs**: `-m invalid_mode`, `-p 0`, `-p 999`, no arguments
- **Expected Results**: Error message, non-zero exit, no crash
- **Priority**: Medium
- **Risk Covered**: Input validation
- **Automation Hint**: Shell test

#### TC-DAEMON-WD-001 Watchdog — monitor loader health

- **Objective**: Verify watchdog detects loader failure and takes action
- **Target**: `rswitch-watchdog`
- **Preconditions**: Watchdog and loader running
- **Steps**:
  1. Start watchdog
  2. Kill loader process
  3. Observe watchdog behavior
- **Expected Results**: Watchdog logs failure, attempts restart (per systemd dependency)
- **Priority**: Medium
- **Risk Covered**: Unmonitored failure
- **Automation Hint**: Shell integration test

#### TC-DAEMON-TEL-001 Telemetry daemon — event emission

- **Objective**: Verify telemetry daemon reads ringbuf events
- **Target**: `rswitch-telemetry`
- **Preconditions**: Loader running with ringbuf_enabled=true
- **Steps**:
  1. Start telemetry daemon
  2. Generate traffic
  3. Check telemetry output
- **Expected Results**: Events logged with timestamps and metadata
- **Priority**: Medium
- **Risk Covered**: Event pipeline
- **Automation Hint**: Shell test

#### TC-DAEMON-EVT-001 Events daemon — event consumer

- **Objective**: Verify events daemon processes events for WebSocket delivery
- **Target**: `rswitch-events`
- **Preconditions**: Loader running
- **Steps**:
  1. Start events daemon
  2. Generate events (via traffic or config change)
  3. Verify events available via /api/events or WebSocket
- **Expected Results**: Events delivered to mgmtd WebSocket clients
- **Priority**: Medium
- **Risk Covered**: Event delivery pipeline
- **Automation Hint**: Shell + curl/Python

#### TC-DAEMON-PROM-001 Prometheus exporter — /metrics

- **Objective**: Verify Prometheus exporter serves metrics endpoint
- **Target**: `rswitch-prometheus`
- **Preconditions**: Loader running
- **Inputs**: `curl http://localhost:9417/metrics`
- **Expected Results**: Response contains all 16 metric families with valid Prometheus format
- **Priority**: Medium
- **Risk Covered**: Monitoring integration
- **Automation Hint**: curl + grep for metric names

#### TC-DAEMON-PROM-002 Prometheus — metric accuracy

- **Objective**: Verify metric values match BPF map counters
- **Target**: `rswitch-prometheus`
- **Steps**:
  1. Read BPF map counters directly (bpftool)
  2. Scrape /metrics
  3. Compare values
- **Expected Results**: Metric values match map counters (within scrape window)
- **Priority**: Medium
- **Risk Covered**: Metric accuracy
- **Automation Hint**: Shell script

### 4.11 Web Portal

#### TC-WEB-001 Portal login page load

- **Objective**: Verify portal login page renders
- **Target**: `http://localhost:8080/`
- **Preconditions**: mgmtd running in standalone mode
- **Steps**:
  1. Open browser/fetch index.html
  2. Verify login form present
- **Expected Results**: HTML rendered, login form visible
- **Priority**: Medium
- **Risk Covered**: Portal accessibility
- **Automation Hint**: Playwright or curl for HTML content

#### TC-WEB-002 Portal — all pages load

- **Objective**: Verify all 10 portal pages load without errors
- **Target**: 10 HTML pages
- **Preconditions**: Authenticated session
- **Steps**: Fetch each page: index, ports, modules, vlans, acls, routes, logs, dhcp, network, profiles
- **Expected Results**: Each returns 200 OK, valid HTML, no JavaScript errors
- **Priority**: Medium
- **Risk Covered**: Broken pages
- **Automation Hint**: Playwright

#### TC-WEB-003 Portal — VLAN creation via UI

- **Objective**: Verify VLAN can be created through the portal
- **Target**: `vlans.html`
- **Steps**:
  1. Navigate to VLANs page
  2. Fill in VLAN ID and name
  3. Submit form
  4. Verify VLAN appears in list
- **Expected Results**: VLAN created, page refreshes, new VLAN visible
- **Priority**: Medium
- **Risk Covered**: UI CRUD
- **Automation Hint**: Playwright

#### TC-WEB-004 Portal — live logs via WebSocket

- **Objective**: Verify logs page receives real-time events
- **Target**: `logs.html`
- **Preconditions**: Events daemon running
- **Steps**:
  1. Navigate to Logs page
  2. Wait for WebSocket connection
  3. Verify events appear
- **Expected Results**: Events stream displayed in real-time
- **Priority**: Low
- **Risk Covered**: Live event display
- **Automation Hint**: Playwright

### 4.12 Security

#### TC-SEC-001 BPF map permissions

- **Objective**: Verify pinned BPF maps are only accessible by root
- **Target**: `/sys/fs/bpf/rs_*`
- **Steps**:
  1. Check file permissions on pinned maps
  2. Attempt access as non-root user
- **Expected Results**: Maps owned by root, non-root access denied
- **Priority**: High
- **Risk Covered**: Privilege escalation
- **Automation Hint**: Shell test

#### TC-SEC-002 CORS enforcement

- **Objective**: Verify CORS headers on mgmtd API
- **Target**: mgmtd
- **Inputs**: Cross-origin request with `Origin: https://evil.com`
- **Expected Results**: CORS blocked or restricted to configured origins
- **Priority**: Medium
- **Risk Covered**: Cross-site attacks
- **Automation Hint**: curl with Origin header

#### TC-SEC-003 Password hashing — SHA-256

- **Objective**: Verify passwords are stored hashed, not plaintext
- **Target**: mgmtd auth
- **Steps**:
  1. Inspect profile YAML (plaintext password)
  2. Verify mgmtd hashes it before comparison (code review + test)
  3. Verify constant_time_compare is used
- **Expected Results**: Password hashed with SHA-256, timing-safe comparison
- **Priority**: High
- **Risk Covered**: Password leak
- **Automation Hint**: Code review + functional test

#### TC-SEC-004 Namespace isolation

- **Objective**: Verify mgmtd network namespace prevents cross-namespace access
- **Target**: mgmtd namespace
- **Preconditions**: mgmtd running in rswitch-mgmt namespace
- **Steps**:
  1. Verify mgmtd is in rswitch-mgmt namespace
  2. Verify port 8080 not reachable from default namespace
- **Expected Results**: Port isolated within namespace
- **Priority**: Medium
- **Risk Covered**: Namespace escape
- **Automation Hint**: Shell test with `ip netns exec`

#### TC-SEC-005 XSS prevention — API responses

- **Objective**: Verify API responses don't reflect unsanitized input
- **Target**: mgmtd API
- **Inputs**: VLAN name containing `<script>alert(1)</script>`
- **Expected Results**: Input either rejected or HTML-escaped in responses
- **Priority**: Medium
- **Risk Covered**: XSS
- **Automation Hint**: Python test

### 4.13 Systemd & Operations

#### TC-SYS-001 Service start/stop cycle

- **Objective**: Verify systemd service lifecycle
- **Target**: rswitch.service
- **Steps**:
  1. `systemctl start rswitch`
  2. Verify loader running
  3. `systemctl stop rswitch`
  4. Verify clean shutdown
- **Expected Results**: Start/stop succeeds, no orphan processes
- **Priority**: High
- **Risk Covered**: Service management
- **Automation Hint**: Shell test

#### TC-SYS-002 Service dependency ordering

- **Objective**: Verify rswitch-mgmtd starts after rswitch
- **Target**: systemd units
- **Steps**:
  1. Start rswitch-mgmtd (should auto-start rswitch or wait)
  2. Verify ordering
- **Expected Results**: Dependencies respected
- **Priority**: Medium
- **Risk Covered**: Race condition on startup
- **Automation Hint**: Shell test

#### TC-SYS-003 Failsafe service

- **Objective**: Verify failsafe service handles loader crash
- **Target**: rswitch-failsafe.service
- **Steps**:
  1. Start services
  2. Kill loader
  3. Verify failsafe activates
- **Expected Results**: Failsafe cleans up BPF state
- **Priority**: Medium
- **Risk Covered**: Crash recovery
- **Automation Hint**: Shell test

#### TC-OPS-001 Install and uninstall scripts

- **Objective**: Verify install.sh and uninstall.sh work correctly
- **Target**: `scripts/install.sh`, `scripts/uninstall.sh`
- **Steps**:
  1. Run install.sh
  2. Verify files in /opt/rswitch/
  3. Run uninstall.sh
  4. Verify cleanup
- **Expected Results**: Clean install and removal
- **Priority**: Medium
- **Risk Covered**: Installation integrity
- **Automation Hint**: Shell test (in clean environment/container)

#### TC-OPS-002 Hot-reload script

- **Objective**: Verify hot-reload.sh commands: reload, verify, list, unload
- **Target**: `scripts/hot-reload.sh`
- **Preconditions**: Loader running
- **Steps**:
  1. `hot-reload.sh list` — show loaded modules
  2. `hot-reload.sh reload vlan` — reload module
  3. `hot-reload.sh verify 20` — verify stage
- **Expected Results**: All commands succeed
- **Priority**: High
- **Risk Covered**: Operational tooling
- **Automation Hint**: Shell test (already in `test_hotreload.sh`)

### 4.14 User-Space Components

#### TC-USR-AUDIT-001 audit — write log entry

- **Objective**: Verify `audit_log()` appends a JSON entry to `/var/log/rswitch/audit.json`
- **Target**: `user/audit/audit.c`
- **Preconditions**: `/var/log/rswitch/` exists (or is created automatically); audit binary built
- **Inputs**: Call `audit_log(SEV_INFO, "test", "load", "root", 1, "unit test")`
- **Steps**:
  1. Invoke audit_log with known fields
  2. Read last line of `/var/log/rswitch/audit.json`
  3. Parse JSON and verify all fields present
- **Expected Results**: JSON line contains `timestamp`, `severity`, `category`, `action`, `user`, `success`, `detail` with correct values
- **Priority**: High
- **Risk Covered**: Audit trail completeness; JSON correctness
- **Automation Hint**: C unit test

#### TC-USR-AUDIT-002 audit — auto-create log directory

- **Objective**: Verify audit creates `/var/log/rswitch/` when it does not exist
- **Target**: `user/audit/audit.c`
- **Preconditions**: `/var/log/rswitch/` removed before test
- **Inputs**: Call `audit_log(SEV_INFO, "test", "create", "root", 1, "dir test")`
- **Steps**:
  1. Remove `/var/log/rswitch/` if present
  2. Call audit_log
  3. Verify directory and file created
- **Expected Results**: Directory created; log entry written; no crash
- **Priority**: Medium
- **Risk Covered**: First-run robustness; missing directory handling
- **Automation Hint**: C unit test (run as root or with CAP_DAC_OVERRIDE)

#### TC-USR-AUDIT-003 audit — rotate creates timestamped archive

- **Objective**: Verify `audit_rotate()` renames `audit.json` to `audit-YYYYMMDD-HHMMSS.json`
- **Target**: `user/audit/audit.c`
- **Preconditions**: Non-empty `audit.json` exists
- **Inputs**: Call `audit_rotate()`
- **Steps**:
  1. Write at least one log entry
  2. Call audit_rotate()
  3. List `/var/log/rswitch/` and match rotated filename against pattern `audit-[0-9]{8}-[0-9]{6}.json`
  4. Verify original `audit.json` no longer exists (or is empty)
- **Expected Results**: Rotated file present with correct name pattern; original removed
- **Priority**: Medium
- **Risk Covered**: Log rotation; disk space management
- **Automation Hint**: C unit test

#### TC-USR-AUDIT-004 audit — read returns entries in reverse-chronological order

- **Objective**: Verify `audit_read()` returns entries newest-first
- **Target**: `user/audit/audit.c`
- **Preconditions**: At least 3 log entries with different timestamps
- **Inputs**: Three sequential `audit_log()` calls; then `audit_read()`
- **Steps**:
  1. Write entries E1, E2, E3 in order
  2. Call audit_read() and collect returned timestamps
  3. Verify timestamps are non-increasing
- **Expected Results**: E3 timestamp ≥ E2 timestamp ≥ E1 timestamp in returned order
- **Priority**: Medium
- **Risk Covered**: Audit read ordering; observer usability
- **Automation Hint**: C unit test

#### TC-USR-AUDIT-005 audit — JSON-escape special characters in detail field

- **Objective**: Verify detail strings containing `"`, `\`, and newlines are properly escaped
- **Target**: `user/audit/audit.c`
- **Preconditions**: None
- **Inputs**: `detail = "has \"quotes\" and \\backslash"`
- **Steps**:
  1. Call audit_log with special-character detail
  2. Read raw log file line
  3. Parse as JSON and verify round-trip correctness
- **Expected Results**: Valid JSON; detail field decodes back to original string
- **Priority**: Medium
- **Risk Covered**: JSON correctness under adversarial input
- **Automation Hint**: C unit test

#### TC-USR-LIFE-001 lifecycle — init creates state directory and PID file

- **Objective**: Verify `lifecycle_init()` creates `/var/lib/rswitch/` and `/var/run/rswitch.pid`
- **Target**: `user/lifecycle/lifecycle.c`
- **Preconditions**: State dir and PID file absent
- **Inputs**: Call `lifecycle_init()`
- **Steps**:
  1. Remove `/var/lib/rswitch/` and `/var/run/rswitch.pid` if present
  2. Call lifecycle_init()
  3. Stat both paths
- **Expected Results**: Directory exists; PID file contains current PID
- **Priority**: High
- **Risk Covered**: Startup correctness; single-instance enforcement
- **Automation Hint**: C unit test

#### TC-USR-LIFE-002 lifecycle — save_state dumps BPF map content to files

- **Objective**: Verify `lifecycle_save_state()` writes map dump files under `/var/lib/rswitch/`
- **Target**: `user/lifecycle/lifecycle.c`
- **Preconditions**: At least one BPF map pinned (rs_mac_table or similar); lifecycle_init() called
- **Inputs**: Call `lifecycle_save_state()`
- **Steps**:
  1. Populate a BPF map with known entries
  2. Call lifecycle_save_state()
  3. Verify files present under state dir; parse metadata file
- **Expected Results**: Map dump file(s) created; metadata file contains valid JSON with timestamp and module list
- **Priority**: High
- **Risk Covered**: State persistence; warm-restart capability
- **Automation Hint**: Integration test (requires BPF environment)

#### TC-USR-LIFE-003 lifecycle — restore_state reloads entries into BPF maps

- **Objective**: Verify `lifecycle_restore_state()` reads saved dumps and repopulates maps
- **Target**: `user/lifecycle/lifecycle.c`
- **Preconditions**: `lifecycle_save_state()` succeeded; maps cleared before restore
- **Inputs**: Call `lifecycle_restore_state()`
- **Steps**:
  1. Save state with known entries
  2. Clear the maps
  3. Call lifecycle_restore_state()
  4. Query maps and compare to original entries
- **Expected Results**: All saved entries present in maps post-restore
- **Priority**: High
- **Risk Covered**: Warm-restart data fidelity
- **Automation Hint**: Integration test

#### TC-USR-LIFE-004 lifecycle — shutdown unpins all BPF objects

- **Objective**: Verify `lifecycle_shutdown()` removes all pinned BPF objects from `/sys/fs/bpf/`
- **Target**: `user/lifecycle/lifecycle.c`
- **Preconditions**: Loader running; maps pinned with `rs_*`, `acl_*`, `route_*`, etc. prefixes
- **Inputs**: Call `lifecycle_shutdown()`
- **Steps**:
  1. Verify pinned objects exist before shutdown
  2. Call lifecycle_shutdown()
  3. List `/sys/fs/bpf/` and confirm all rswitch-owned pins removed
- **Expected Results**: Zero rswitch pins remain; function returns 0
- **Priority**: High
- **Risk Covered**: Clean teardown; no orphaned pinned maps after restart
- **Automation Hint**: Shell + C integration test

#### TC-USR-LIFE-005 lifecycle — missing state dir on restore returns gracefully

- **Objective**: Verify `lifecycle_restore_state()` returns a non-fatal error when state dir is absent
- **Target**: `user/lifecycle/lifecycle.c`
- **Preconditions**: State dir removed before call
- **Inputs**: Call `lifecycle_restore_state()` with no state dir
- **Steps**:
  1. Remove `/var/lib/rswitch/`
  2. Call lifecycle_restore_state()
  3. Verify return code and no crash
- **Expected Results**: Returns non-zero error code; no crash; error logged
- **Priority**: Medium
- **Risk Covered**: First-start without prior state; robustness
- **Automation Hint**: C unit test

#### TC-USR-REG-001 registry — update_index scans build dir and writes JSON

- **Objective**: Verify `registry_update_index()` scans `./build/bpf` for `.bpf.o` files and produces valid JSON index
- **Target**: `user/registry/registry.c`
- **Preconditions**: At least 2 `.bpf.o` files present in `./build/bpf/`
- **Inputs**: Call `registry_update_index()`
- **Steps**:
  1. Ensure known `.bpf.o` files exist in build dir
  2. Call registry_update_index()
  3. Parse resulting index file as JSON
  4. Verify each `.bpf.o` file has an entry
- **Expected Results**: Valid JSON index; all scanned modules present; function returns 0
- **Priority**: High
- **Risk Covered**: Module discovery; registry accuracy
- **Automation Hint**: C unit test

#### TC-USR-REG-002 registry — search finds module by name substring

- **Objective**: Verify `registry_search()` returns matching modules using case-insensitive name match
- **Target**: `user/registry/registry.c`
- **Preconditions**: Index populated with at least one module named `vlan_filter`
- **Inputs**: `registry_search("VLAN")`
- **Steps**:
  1. Update index with known modules
  2. Search for "VLAN" (upper-case)
  3. Verify `vlan_filter` appears in results
- **Expected Results**: At least one match returned; case-insensitive comparison confirmed
- **Priority**: Medium
- **Risk Covered**: User-facing discovery UX; search correctness
- **Automation Hint**: C unit test

#### TC-USR-REG-003 registry — install copies .bpf.o and performs ABI check

- **Objective**: Verify `registry_install()` copies module to target dir and rejects ABI-incompatible modules
- **Target**: `user/registry/registry.c`
- **Preconditions**: Valid `.bpf.o` present; and a deliberately ABI-mismatched `.bpf.o` available
- **Inputs**: (a) valid `.bpf.o`; (b) ABI-mismatched `.bpf.o`
- **Steps**:
  1. Install valid module → verify file copied
  2. Install mismatched module → verify rejection (non-zero return)
- **Expected Results**: Valid module installed; mismatched module rejected with error
- **Priority**: High
- **Risk Covered**: ABI safety; preventing incompatible module deployment
- **Automation Hint**: C unit test

#### TC-USR-REG-004 registry — publish creates .rsmod package in packages dir

- **Objective**: Verify `registry_publish()` packs module into `.rsmod` and places it under `/var/lib/rswitch/registry/packages`
- **Target**: `user/registry/registry.c`
- **Preconditions**: Packages dir exists or is created by publish
- **Inputs**: Valid `.bpf.o` path
- **Steps**:
  1. Call registry_publish() with valid module
  2. List packages dir
  3. Verify `.rsmod` file created
- **Expected Results**: `.rsmod` file present; function returns 0
- **Priority**: Medium
- **Risk Covered**: Module distribution workflow
- **Automation Hint**: C unit test

#### TC-USR-REG-005 registry — search returns empty on no match

- **Objective**: Verify `registry_search()` returns empty result set for non-existent module name
- **Target**: `user/registry/registry.c`
- **Preconditions**: Index populated
- **Inputs**: `registry_search("nonexistent_xyz_module")`
- **Steps**:
  1. Search for clearly non-existent name
  2. Verify result count is 0 and no crash
- **Expected Results**: Zero results; function returns 0 (not error)
- **Priority**: Low
- **Risk Covered**: Negative search path; no false positives
- **Automation Hint**: C unit test

#### TC-USR-RES-001 resource_limits — oom_protect sets oom_score_adj to -1000

- **Objective**: Verify `oom_protect()` writes -1000 to `/proc/self/oom_score_adj`
- **Target**: `user/resource/resource_limits.c`
- **Preconditions**: Process has CAP_SYS_RESOURCE or runs as root
- **Inputs**: Call `oom_protect()`
- **Steps**:
  1. Call oom_protect()
  2. Read `/proc/self/oom_score_adj`
  3. Verify value is -1000
- **Expected Results**: Value reads -1000; function returns 0
- **Priority**: High
- **Risk Covered**: OOM kill prevention for critical switch daemon
- **Automation Hint**: C unit test (run as root)

#### TC-USR-RES-002 resource_limits — set_fd_limit raises RLIMIT_NOFILE

- **Objective**: Verify `set_fd_limit(n)` sets both soft and hard RLIMIT_NOFILE to n
- **Target**: `user/resource/resource_limits.c`
- **Preconditions**: Process has permission to raise fd limit
- **Inputs**: Call `set_fd_limit(65536)`
- **Steps**:
  1. Call set_fd_limit(65536)
  2. Call getrlimit(RLIMIT_NOFILE, &rl)
  3. Verify rl.rlim_cur == 65536 and rl.rlim_max == 65536
- **Expected Results**: Both limits set; function returns 0
- **Priority**: Medium
- **Risk Covered**: FD exhaustion under high port count
- **Automation Hint**: C unit test

#### TC-USR-RES-003 resource_limits — mac_pressure triggers when map usage exceeds 90%

- **Objective**: Verify `mac_pressure()` returns true when BPF map occupancy > 90%
- **Target**: `user/resource/resource_limits.c`
- **Preconditions**: `rs_mac_table` map accessible; capacity known
- **Inputs**: Fill map to 91% capacity
- **Steps**:
  1. Insert entries until 91% full
  2. Call mac_pressure()
  3. Verify return value is non-zero (pressure detected)
- **Expected Results**: mac_pressure() returns true at >90% fill; false at <90%
- **Priority**: High
- **Risk Covered**: MAC table overflow prevention
- **Automation Hint**: C unit + BPF integration test

#### TC-USR-RES-004 resource_limits — mac_evict_lru removes aged non-static entries

- **Objective**: Verify `mac_evict_lru()` deletes oldest non-static entries when called
- **Target**: `user/resource/resource_limits.c`
- **Preconditions**: MAC table contains mix of static and dynamic entries with varying ages
- **Inputs**: Call `mac_evict_lru(count)` with count=5
- **Steps**:
  1. Insert 10 dynamic entries with varying timestamps; insert 2 static entries
  2. Call mac_evict_lru(5)
  3. Verify 5 oldest dynamic entries removed; static entries preserved
- **Expected Results**: 5 LRU dynamic entries deleted; static entries untouched; function returns number evicted
- **Priority**: High
- **Risk Covered**: MAC table eviction policy; static entry preservation
- **Automation Hint**: C unit + BPF integration test

#### TC-USR-ROLL-001 rollback — create_snapshot saves snapshot.json and profile copy

- **Objective**: Verify `rollback_create_snapshot()` creates a snapshot directory with `snapshot.json` and profile copy
- **Target**: `user/rollback/rollback.c`
- **Preconditions**: Snapshot base dir `/var/lib/rswitch/snapshots` accessible; active profile known
- **Inputs**: Call `rollback_create_snapshot("test-snap")`
- **Steps**:
  1. Call rollback_create_snapshot()
  2. List snapshot dir for new subdirectory
  3. Verify `snapshot.json` and profile copy present
- **Expected Results**: Snapshot dir created; JSON and profile files present; function returns 0
- **Priority**: High
- **Risk Covered**: Pre-upgrade checkpoint creation
- **Automation Hint**: C unit test

#### TC-USR-ROLL-002 rollback — list_snapshots returns newest-first order

- **Objective**: Verify `rollback_list_snapshots()` returns snapshots sorted newest-first
- **Target**: `user/rollback/rollback.c`
- **Preconditions**: At least 3 snapshots exist with different timestamps
- **Inputs**: Call `rollback_list_snapshots()`
- **Steps**:
  1. Create snapshots S1, S2, S3 sequentially
  2. Call rollback_list_snapshots()
  3. Verify order: S3, S2, S1
- **Expected Results**: Newest snapshot first; count matches number created
- **Priority**: Medium
- **Risk Covered**: Snapshot list UX; correct ordering for rollback selection
- **Automation Hint**: C unit test

#### TC-USR-ROLL-003 rollback — apply writes pending_apply.json and forks watchdog

- **Objective**: Verify `rollback_apply(snapshot_id)` writes `/var/lib/rswitch/pending_apply.json` and spawns watchdog process
- **Target**: `user/rollback/rollback.c`
- **Preconditions**: Valid snapshot exists
- **Inputs**: Call `rollback_apply(snapshot_id)`
- **Steps**:
  1. Call rollback_apply() with valid snapshot ID
  2. Verify `/var/lib/rswitch/pending_apply.json` created and readable as JSON
  3. Verify watchdog child process spawned (check via `ps`)
- **Expected Results**: Pending file present with correct snapshot reference; watchdog running
- **Priority**: High
- **Risk Covered**: Safe rollback with watchdog safety net
- **Automation Hint**: C integration test

#### TC-USR-ROLL-004 rollback — confirm removes pending_apply.json

- **Objective**: Verify `rollback_confirm()` deletes `/var/lib/rswitch/pending_apply.json`
- **Target**: `user/rollback/rollback.c`
- **Preconditions**: `pending_apply.json` exists
- **Inputs**: Call `rollback_confirm()`
- **Steps**:
  1. Create pending_apply.json manually
  2. Call rollback_confirm()
  3. Verify file no longer exists
- **Expected Results**: File removed; function returns 0
- **Priority**: High
- **Risk Covered**: Confirmed-apply finalisation; watchdog disarm
- **Automation Hint**: C unit test

#### TC-USR-ROLL-005 rollback — rollback_to copies profile from snapshot

- **Objective**: Verify `rollback_to(snapshot_id)` restores the profile YAML from the named snapshot
- **Target**: `user/rollback/rollback.c`
- **Preconditions**: Snapshot with known profile exists; current profile differs
- **Inputs**: Call `rollback_to(snapshot_id)`
- **Steps**:
  1. Create snapshot with profile A
  2. Switch active profile to B
  3. Call rollback_to(snapshot_id)
  4. Verify active profile file matches profile A content
- **Expected Results**: Active profile matches snapshot copy; function returns 0
- **Priority**: High
- **Risk Covered**: Profile rollback correctness
- **Automation Hint**: Shell + C integration test

#### TC-USR-TOPO-001 topology — discover returns LLDP neighbours from JSON files

- **Objective**: Verify `topology_discover()` reads LLDP JSON files from `TOPO_LLDP_DATA_DIR` and populates neighbour list
- **Target**: `user/topology/topology.c`
- **Preconditions**: Test LLDP JSON files placed in data dir
- **Inputs**: 2 LLDP JSON files representing 2 neighbours
- **Steps**:
  1. Place 2 LLDP JSON files in TOPO_LLDP_DATA_DIR
  2. Call topology_discover()
  3. Verify returned count equals 2; verify neighbour fields match file contents
- **Expected Results**: 2 neighbours discovered; chassis ID, port ID, TTL populated
- **Priority**: High
- **Risk Covered**: Topology discovery accuracy
- **Automation Hint**: C unit test (with test fixture LLDP files)

#### TC-USR-TOPO-002 topology — print_json outputs valid JSON

- **Objective**: Verify `topology_print_json()` produces output parseable as valid JSON
- **Target**: `user/topology/topology.c`
- **Preconditions**: topology_discover() succeeded with ≥1 neighbour
- **Inputs**: Call `topology_print_json()` after discovery
- **Steps**:
  1. Discover at least one neighbour
  2. Capture topology_print_json() output
  3. Parse with JSON parser (e.g., `python3 -m json.tool`)
- **Expected Results**: Valid JSON; no parse errors; neighbour data present
- **Priority**: Medium
- **Risk Covered**: Output format correctness; downstream tooling compatibility
- **Automation Hint**: Shell test (`topology_print_json | python3 -m json.tool`)

#### TC-USR-TOPO-003 topology — missing LLDP data dir returns 0 gracefully

- **Objective**: Verify `topology_discover()` returns 0 (not error) when TOPO_LLDP_DATA_DIR does not exist
- **Target**: `user/topology/topology.c`
- **Preconditions**: TOPO_LLDP_DATA_DIR removed or pointing to non-existent path
- **Inputs**: Call `topology_discover()` with absent data dir
- **Steps**:
  1. Remove or rename TOPO_LLDP_DATA_DIR
  2. Call topology_discover()
  3. Verify return value and no crash
- **Expected Results**: Returns 0 (empty topology); no crash; no error log for expected-missing dir
- **Priority**: Medium
- **Risk Covered**: First-start robustness; no LLDP daemon running
- **Automation Hint**: C unit test

#### TC-USR-HREL-001 hot_reload — reload command performs atomic module swap

- **Objective**: Verify `hot_reload reload <module>` updates BPF prog_array slot atomically without detaching XDP
- **Target**: `user/reload/hot_reload.c`
- **Preconditions**: Loader running with module M loaded; replacement `.bpf.o` available
- **Inputs**: `sudo ./build/hot_reload reload vlan`
- **Steps**:
  1. Record current prog_array slot for vlan
  2. Run hot_reload reload vlan
  3. Verify BPF prog_array slot updated (new prog fd via `bpftool prog list`)
  4. Verify XDP program still attached on interface (not detached/reattached)
- **Expected Results**: Slot updated atomically; XDP attachment continuous; no traffic interruption
- **Priority**: High
- **Risk Covered**: Zero-downtime hot-reload
- **Automation Hint**: Integration test + bpftool verification

#### TC-USR-HREL-002 hot_reload — dry-run mode does not modify prog_array

- **Objective**: Verify `-n`/`--dry-run` flag reports what would change without applying
- **Target**: `user/reload/hot_reload.c`
- **Preconditions**: Loader running
- **Inputs**: `sudo ./build/hot_reload --dry-run reload vlan`
- **Steps**:
  1. Record current prog_array state
  2. Run hot_reload with --dry-run
  3. Re-read prog_array state
  4. Verify no change
- **Expected Results**: Dry-run output printed; prog_array unchanged; return 0
- **Priority**: High
- **Risk Covered**: Operator preview before live change
- **Automation Hint**: Integration test

#### TC-USR-HREL-003 hot_reload — list command shows loaded modules

- **Objective**: Verify `hot_reload list` prints currently loaded modules with stage numbers
- **Target**: `user/reload/hot_reload.c`
- **Preconditions**: Loader running with at least 2 modules
- **Inputs**: `sudo ./build/hot_reload list`
- **Steps**:
  1. Run hot_reload list
  2. Verify output contains module names and stage numbers
- **Expected Results**: At least one module listed per loaded stage; output human-readable
- **Priority**: Medium
- **Risk Covered**: Operator visibility
- **Automation Hint**: Shell test

#### TC-USR-HREL-004 hot_reload — unload removes module from prog_array

- **Objective**: Verify `hot_reload unload <module>` clears the module's slot in BPF prog_array
- **Target**: `user/reload/hot_reload.c`
- **Preconditions**: Module loaded in prog_array
- **Inputs**: `sudo ./build/hot_reload unload mirror`
- **Steps**:
  1. Verify mirror slot occupied before unload
  2. Run hot_reload unload mirror
  3. Verify slot is now NULL/empty in prog_array
- **Expected Results**: Slot cleared; function returns 0; subsequent list shows module absent
- **Priority**: High
- **Risk Covered**: Module removal without full reload
- **Automation Hint**: Integration test + bpftool verification

#### TC-USR-HREL-005 hot_reload — ABI mismatch rejected

- **Objective**: Verify `hot_reload reload` rejects a replacement module with incompatible ABI version
- **Target**: `user/reload/hot_reload.c`
- **Preconditions**: ABI-mismatched `.bpf.o` available (different RS_MODULE_ABI_VERSION)
- **Inputs**: `sudo ./build/hot_reload reload vlan` with mismatched object
- **Steps**:
  1. Provide ABI-incompatible vlan.bpf.o
  2. Run hot_reload reload vlan
  3. Verify non-zero exit code and error message
  4. Verify original prog_array slot unchanged
- **Expected Results**: Reload rejected; error message cites ABI mismatch; no change applied
- **Priority**: High
- **Risk Covered**: ABI safety gate for hot-reload
- **Automation Hint**: C unit + integration test

#### TC-USR-HREL-006 hot_reload — invalid subcommand prints usage and returns error

- **Objective**: Verify unknown subcommand causes usage message and non-zero exit
- **Target**: `user/reload/hot_reload.c`
- **Preconditions**: Binary built
- **Inputs**: `./build/hot_reload frobnicate`
- **Steps**:
  1. Run hot_reload with unknown subcommand
  2. Verify stderr contains usage text
  3. Verify exit code non-zero
- **Expected Results**: Usage printed; exit code != 0
- **Priority**: Low
- **Risk Covered**: CLI error handling UX
- **Automation Hint**: Shell test

#### TC-USR-PTRACE-001 rs_packet_trace — opens rs_ctx_map and polls per-CPU values

- **Objective**: Verify `rs_packet_trace` opens the pinned `rs_ctx_map` and reads per-CPU entries
- **Target**: `user/tools/rs_packet_trace.c`
- **Preconditions**: Loader running; `rs_ctx_map` pinned; traffic flowing
- **Inputs**: `sudo ./build/rs_packet_trace` (run for 2 seconds, then kill)
- **Steps**:
  1. Start rs_packet_trace
  2. Generate a few packets through the switch
  3. Observe stdout for packet trace output
  4. Kill process after 2s
- **Expected Results**: Per-CPU context entries printed; no crash on SIGTERM
- **Priority**: High
- **Risk Covered**: Packet tracing visibility; per-CPU map read correctness
- **Automation Hint**: Integration test

#### TC-USR-PTRACE-002 rs_packet_trace — deduplicates by timestamp

- **Objective**: Verify tool suppresses duplicate per-CPU entries with identical timestamps
- **Target**: `user/tools/rs_packet_trace.c`
- **Preconditions**: Controlled test where same context written to multiple CPUs with same timestamp
- **Inputs**: Synthetic per-CPU map with duplicate timestamps
- **Steps**:
  1. Pre-populate rs_ctx_map with identical timestamp across 4 CPUs
  2. Run rs_packet_trace; count output lines
  3. Verify only one line printed (deduplicated)
- **Expected Results**: Single output line for identical timestamps across CPUs
- **Priority**: Medium
- **Risk Covered**: Output noise reduction; dedup logic correctness
- **Automation Hint**: C unit test with mock map

#### TC-USR-PTRACE-003 rs_packet_trace_v2 — loads packet_trace.bpf.o and uses ringbuf

- **Objective**: Verify `rs_packet_trace_v2` loads `./build/bpf/packet_trace.bpf.o` and attaches to `pkt_events` ringbuf map
- **Target**: `user/tools/rs_packet_trace_v2.c`
- **Preconditions**: `./build/bpf/packet_trace.bpf.o` exists; loader running on test interface
- **Inputs**: `sudo ./build/rs_packet_trace_v2`
- **Steps**:
  1. Run rs_packet_trace_v2
  2. Verify no load error in stderr
  3. Generate a few packets
  4. Observe ringbuf events printed on stdout
- **Expected Results**: BPF object loaded; events read from pkt_events ringbuf; no crash
- **Priority**: High
- **Risk Covered**: Ringbuf-based tracing path; BPF object load correctness
- **Automation Hint**: Integration test

#### TC-USR-PTRACE-004 rs_packet_trace_v2 — SIGINT/SIGTERM causes graceful exit

- **Objective**: Verify `rs_packet_trace_v2` exits cleanly on SIGINT or SIGTERM without resource leak
- **Target**: `user/tools/rs_packet_trace_v2.c`
- **Preconditions**: rs_packet_trace_v2 running
- **Inputs**: `kill -SIGINT <pid>` or Ctrl-C
- **Steps**:
  1. Start rs_packet_trace_v2
  2. Send SIGINT after 1 second
  3. Verify process exits with code 0
  4. Verify BPF objects unloaded (no leaked pinned programs)
- **Expected Results**: Clean exit; BPF resources freed; exit code 0
- **Priority**: High
- **Risk Covered**: Resource leak prevention; signal handling correctness
- **Automation Hint**: Shell test

#### TC-CLI-QOSS-001 rsqosctl_simple — enable command succeeds

- **Objective**: Verify `rsqosctl_simple enable` returns 0 and applies QoS enable
- **Target**: `user/tools/rsqosctl_simple.c`
- **Preconditions**: Loader running with QoS-capable profile
- **Inputs**: `sudo ./build/rsqosctl_simple enable`
- **Steps**:
  1. Run rsqosctl_simple enable
  2. Verify exit code 0
  3. Verify QoS state reflected in BPF map or stats output
- **Expected Results**: Exit 0; QoS enabled
- **Priority**: High
- **Risk Covered**: QoS enable path
- **Automation Hint**: Shell integration test

#### TC-CLI-QOSS-002 rsqosctl_simple — unknown command prints usage and returns 1

- **Objective**: Verify unknown command causes usage message and exit code 1
- **Target**: `user/tools/rsqosctl_simple.c`
- **Preconditions**: Binary built
- **Inputs**: `./build/rsqosctl_simple unknowncmd`
- **Steps**:
  1. Run rsqosctl_simple with unknown subcommand
  2. Verify stderr/stdout contains usage or error text
  3. Verify exit code is 1
- **Expected Results**: Error message printed; exit code == 1
- **Priority**: Medium
- **Risk Covered**: CLI error handling; expected exit codes
- **Automation Hint**: Shell test

### 4.18 Integration — Pipeline Tests

#### TC-INT-PIPE-001 L2 switching — MAC learning and forwarding

- **Objective**: Verify end-to-end L2 switching with MAC learning
- **Target**: l2.yaml profile pipeline
- **Preconditions**: veth pairs in namespaces
- **Steps**:
  1. Load l2 profile
  2. Send frame from NS_A → NS_B
  3. Verify frame arrives
  4. Verify MAC learned in rs_mac_table
- **Expected Results**: Frame forwarded, MAC learned
- **Priority**: High
- **Risk Covered**: Core L2 functionality
- **Automation Hint**: Shell integration test (extend existing)

#### TC-INT-PIPE-002 VLAN filtering — tagged traffic

- **Objective**: Verify VLAN filtering allows member traffic and drops non-member
- **Target**: l2-vlan.yaml profile
- **Preconditions**: veth pairs
- **Steps**:
  1. Load l2-vlan profile
  2. Send tagged traffic for allowed VLAN → should forward
  3. Send tagged traffic for disallowed VLAN → should drop
- **Expected Results**: Correct filtering behavior
- **Priority**: High
- **Risk Covered**: VLAN enforcement
- **Automation Hint**: Shell integration test (already in `test_vlan_filtering.sh`)

#### TC-INT-PIPE-003 ACL + Route combined pipeline

- **Objective**: Verify ACL and route modules work together correctly
- **Target**: l3.yaml or firewall.yaml profile
- **Steps**:
  1. Load L3 profile with ACL
  2. Add ACL PASS rule for specific subnet
  3. Add ACL DROP rule for other subnet
  4. Add routes
  5. Send traffic → verify pass/drop/route behavior
- **Expected Results**: ACL filters first, surviving packets routed correctly
- **Priority**: High
- **Risk Covered**: Multi-module interaction
- **Automation Hint**: Shell integration test

#### TC-INT-PIPE-004 Egress VLAN tag manipulation

- **Objective**: Verify ingress-to-egress VLAN tag handling
- **Target**: Full pipeline with egress modules
- **Steps**:
  1. Send untagged frame to access port (ingress VLAN assignment)
  2. Verify frame arrives at trunk port with correct 802.1Q tag
  3. Send tagged frame to trunk port
  4. Verify frame arrives at access port untagged
- **Expected Results**: Tags correctly added/removed on egress
- **Priority**: High
- **Risk Covered**: Tag corruption
- **Automation Hint**: Shell integration test with tcpdump

#### TC-INT-PIPE-005 Full QoS pipeline

- **Objective**: Verify QoS marking → VOQd scheduling → egress path
- **Target**: qos-voqd.yaml profile
- **Preconditions**: VOQd in active or shadow mode
- **Steps**:
  1. Load QoS profile
  2. Send traffic with different DSCP values
  3. Verify priority assignment and queue placement
- **Expected Results**: Traffic classified, queued, and forwarded per priority
- **Priority**: Medium
- **Risk Covered**: QoS pipeline
- **Automation Hint**: Shell integration test

### 4.19 Performance & Benchmark

#### TC-PERF-001 Throughput baseline — L2 profile

- **Objective**: Establish throughput baseline for L2 switching
- **Target**: l2.yaml profile
- **Preconditions**: Veth pairs or physical NICs
- **Steps**: Run `test/benchmark/bench_throughput.sh`
- **Expected Results**: Throughput meets baseline (document in results/)
- **Priority**: Medium
- **Risk Covered**: Performance regression
- **Automation Hint**: Existing benchmark suite

#### TC-PERF-002 Latency baseline — L2 profile

- **Objective**: Establish latency baseline
- **Target**: l2.yaml profile
- **Steps**: Run `test/benchmark/bench_latency.sh`
- **Expected Results**: P50/P99 latency within acceptable range
- **Priority**: Medium
- **Risk Covered**: Latency regression
- **Automation Hint**: Existing benchmark suite

#### TC-PERF-003 Module hot-reload latency

- **Objective**: Measure packet loss during hot-reload
- **Target**: Hot-reload path
- **Steps**:
  1. Generate continuous traffic
  2. Execute hot-reload
  3. Measure any lost packets during swap
- **Expected Results**: Zero or near-zero packet loss
- **Priority**: High
- **Risk Covered**: Hot-reload impact
- **Automation Hint**: Custom shell test with counters

---

## 5. Suggested Directory Layout

Extending the existing `test/` structure:

```text
test/
├── unit/                     # Existing: BPF module unit tests (C)
│   ├── rs_test.h
│   ├── rs_test_runner.c
│   ├── run_tests.sh
│   ├── test_acl.c            # Existing
│   ├── test_vlan.c           # Existing
│   ├── ...                   # Existing (12 modules)
│   ├── test_egress_vlan.c    # NEW: egress VLAN unit tests
│   ├── test_dhcp_snooping.c  # NEW: DHCP snooping unit tests
│   ├── test_qos.c            # NEW: QoS module unit tests
│   ├── test_packet_trace.c   # NEW: BPF packet_trace module unit tests
│   └── test_nat.c            # NEW: BPF NAT module unit tests
│
├── unit_user/                # NEW: user-space unit tests
│   ├── test_profile_parser.c # Profile parser edge cases
│   ├── test_audit.c          # NEW: audit write/rotate/read/JSON-escape
│   ├── test_lifecycle.c      # NEW: lifecycle init/save/restore/shutdown
│   ├── test_registry.c       # NEW: registry update_index/search/install/publish
│   ├── test_resource_limits.c # NEW: oom_protect/set_fd_limit/mac_pressure/mac_evict_lru
│   ├── test_rollback.c       # NEW: rollback create/list/apply/confirm/rollback_to
│   ├── test_topology.c       # NEW: topology discover/print_json/missing dir
│   ├── test_hot_reload.c     # NEW: hot_reload reload/dry-run/list/unload/ABI/invalid cmd
│   └── run_tests.sh
│
├── integration/              # Existing: integration tests (shell)
│   ├── lib.sh                # Existing helper
│   ├── test_loader.sh        # Existing
│   ├── test_vlan_filtering.sh # Existing
│   ├── ...                   # Existing (7 tests)
│   ├── test_egress_vlan.sh   # NEW: egress tag push/pop
│   ├── test_l3_routing.sh    # NEW: full L3 routing flow
│   ├── test_voqd_modes.sh    # NEW: VOQd mode transitions
│   ├── test_mgmtd_api.sh     # NEW: basic API smoke test
│   ├── test_loader_profiles.sh # NEW: dumb / all-modules / qos-voqd-shadow profiles
│   ├── test_hot_reload_bin.sh # NEW: hot_reload binary integration (TC-USR-HREL-001~006)
│   └── test_packet_trace.sh  # NEW: rs_packet_trace / rs_packet_trace_v2 integration
│
├── api/                      # NEW: REST API contract tests
│   ├── conftest.py           # Fixtures: mgmtd startup, auth session
│   ├── test_auth.py          # Auth endpoints
│   ├── test_system.py        # System endpoints
│   ├── test_ports.py         # Port endpoints
│   ├── test_vlans.py         # VLAN CRUD
│   ├── test_acls.py          # ACL CRUD
│   ├── test_routes.py        # Route CRUD
│   ├── test_nat.py           # NAT endpoints
│   ├── test_profiles.py      # Profile management
│   ├── test_config.py        # Config snapshot/rollback
│   ├── test_websocket.py     # WebSocket tests
│   ├── test_security.py      # Auth bypass, CORS, XSS
│   └── requirements.txt      # requests, pytest, websockets
│
├── cli/                      # NEW: CLI tool tests
│   ├── lib_cli.sh            # CLI test helpers
│   ├── test_rswitchctl.sh
│   ├── test_rsportctl.sh
│   ├── test_rsvlanctl.sh
│   ├── test_rsaclctl.sh
│   ├── test_rsroutectl.sh
│   ├── test_rsqosctl.sh
│   ├── test_rsvoqctl.sh
│   ├── test_rsdiag.sh
│   └── test_rsqosctl_simple.sh # NEW: rsqosctl_simple enable/disable/stats/unknown-cmd
│
├── e2e/                      # NEW: end-to-end tests
│   ├── test_portal.spec.ts   # Playwright: portal pages
│   └── playwright.config.ts
│
├── security/                 # NEW: security tests
│   ├── test_bpf_permissions.sh
│   ├── test_namespace_isolation.sh
│   └── test_api_security.py
│
├── smoke_test.sh             # Existing
├── functional_test.sh        # Existing
├── benchmark/                # Existing
├── ci/                       # Existing
└── fuzz/                     # Existing
```

---

## 6. Automation Priority

### P0 — Gate every build (CI required)

| Test | Type | Estimated Effort |
|------|------|-----------------|
| BPF unit tests — all 17 modules | C / BPF_PROG_RUN | 3 new modules to add |
| Profile parser — edge cases + fuzz | C + libFuzzer | 1 new test file |
| Smoke test | Shell | Already exists |
| CLI help/no-crash | Shell | Already partially exists |

### P1 — Gate every PR

| Test | Type | Estimated Effort |
|------|------|-----------------|
| REST API contract tests (all 45+ endpoints) | Python (pytest) | New test suite |
| CLI CRUD tests (VLAN, ACL, route) | Shell | New test scripts |
| Integration — L2, VLAN, L3 pipeline | Shell | Extend existing |
| VOQd mode transitions | Shell | New test |

### P2 — Weekly / release gate

| Test | Type | Estimated Effort |
|------|------|-----------------|
| Portal E2E (all pages load, basic CRUD) | Playwright | New |
| Security tests (auth, namespace, CORS) | Shell + Python | New |
| Config snapshot/rollback cycle | Python | New |
| Performance benchmarks | Shell | Already exists |

### P3 — Manual / exploratory

| Test | Notes |
|------|-------|
| Physical NIC testing (i40e, mlx5, hv_netvsc) | Requires hardware |
| Multi-host L2/L3 forwarding | Requires lab |
| Grafana dashboard validation | Visual |
| Long-running soak test | Hours/days |

---

## 7. Uncertainties / Items Requiring Confirmation

| ID | Item | Impact |
|----|------|--------|
| U1 | `conntrack` module — is it fully implemented or planned? Docs mention `[Planned: connection tracking]` | Affects TC-BPF-CT-* priority |
| U2 | `afxdp_redirect` module — test requires AF_XDP-capable NIC or veth workaround | May need to skip in CI |
| U3 | `rswitch-controller` and `rswitch-agent` daemons — no documentation found; unclear purpose | No test cases generated |
| U4 | `rswitch-snmpagent` — SNMP support scope unclear | No test cases generated |
| U5 | Rate limiter — is it token bucket or leaky bucket? Affects test expectations | Need code review |
| U6 | mgmtd CORS — are allowed origins configurable? Current config unknown | Affects TC-SEC-002 |
| U7 | Profile `extends` — does it support multi-level inheritance? | Affects TC-LOADER-005 depth |
| U8 | VOQd active mode — does it work with veth pairs for testing? AF_XDP on veth has limitations | Affects TC-VOQD-003 in CI |
| U9 | `rswitch-sflow` — sFlow export scope and format unclear | No test cases generated |
| U10 | Some BPF modules (e.g., `qos`) have no existing unit tests — unclear if they have BPF_PROG_RUN testability | Affects test feasibility |
| U11 | `REGISTRY_INDEX_FILE` path — defined in `registry.h` but not confirmed here; integration tests need actual path | Affects TC-USR-REG-001~005 setup |
| U12 | `ROLLBACK_SNAPSHOT_DIR` path — defined in `rollback.h`; confirm it matches `/var/lib/rswitch/snapshots` | Affects TC-USR-ROLL-* preconditions |
| U13 | `TOPO_LLDP_DATA_DIR` path — defined in `topology.h`; confirm path for test fixture placement | Affects TC-USR-TOPO-001~003 |
| U14 | `hot_reload` binary name — source is `hot_reload.c` but installed binary name may differ; confirm build target | Affects TC-USR-HREL-* commands |
| U15 | `rs_packet_trace` map poll loop — no explicit SIGTERM handler visible in v1; confirm graceful exit behaviour | Affects TC-USR-PTRACE-001 |
| U16 | `rsqosctl_simple stats` — source shows `stats` command path but underlying BPF map interaction not confirmed | Affects TC-CLI-QOSS-001 verification |
| U17 | BPF module count 25 — derived from build directory scan; actual count may vary if some modules are disabled by CMake conditionals | Affects section 1 accuracy |

---

## Test Case Count Summary

| Subsystem | Cases | Priority Breakdown |
|-----------|------:|-------------------|
| BPF Data Plane | 83 | 40 High, 43 Medium |
| Loader & Profiles | 13 | 9 High, 4 Medium |
| CLI Tools | 15 | 5 High, 10 Medium |
| REST API | 35 | 16 High, 16 Medium, 3 Low |
| Daemons & VOQd | 12 | 5 High, 6 Medium, 1 Low |
| Web Portal | 4 | 0 High, 3 Medium, 1 Low |
| Security | 5 | 2 High, 3 Medium |
| Systemd & Ops | 5 | 2 High, 3 Medium |
| User-Space Components | 37 | 24 High, 11 Medium, 2 Low |
| Integration Pipeline | 5 | 4 High, 1 Medium |
| Performance | 3 | 1 High, 2 Medium |
| **Total** | **217** | **108 High, 102 Medium, 7 Low** |
