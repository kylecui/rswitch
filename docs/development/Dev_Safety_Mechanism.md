# Dev Safety Mechanism

## Overview

Physical rSwitch devices risk becoming inaccessible when a buggy build takes over all NICs with XDP programs. This mechanism provides two independent safety layers:

1. **Boot Grace Period** — Device boots as normal Ubuntu first, then auto-deploys rswitch after a configurable delay. If deployment fails, the device stays accessible via standard SSH.
2. **Killswitch Module** — An XDP pipeline module (stage 5) that monitors for a magic UDP packet. On match, it signals a userspace watchdog to stop rswitch or reboot the machine.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Boot Sequence                         │
│                                                         │
│  Power On → Normal Ubuntu (SSH works)                   │
│     │                                                    │
│     ├── 60s grace period (configurable)                  │
│     │                                                    │
│     ▼                                                    │
│  rswitch-dev-deploy.service                             │
│     ├── git pull latest dev                              │
│     ├── make clean && make                               │
│     ├── Success? → systemctl start rswitch               │
│     │     └── mgmt namespace provides SSH                │
│     └── Failure? → STOP. Device stays normal Ubuntu.     │
│                    SSH via physical NIC still works.      │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│              Killswitch (Runtime Safety)                  │
│                                                         │
│  Every packet → Dispatcher → [Killswitch stage 5]       │
│     │                                                    │
│     ├── Not magic? → Continue pipeline (zero overhead)   │
│     │                                                    │
│     └── Magic UDP packet detected?                       │
│           ├── Write action to rs_killswitch_map          │
│           └── Continue pipeline (don't drop the packet)  │
│                                                         │
│  rs-killswitch-watchdog (userspace daemon)               │
│     ├── Polls rs_killswitch_map every 500ms              │
│     ├── Action = STOP  → systemctl stop rswitch          │
│     └── Action = REBOOT → systemctl reboot               │
└─────────────────────────────────────────────────────────┘
```

## Layer 1: Boot Grace Period

### Service: `rswitch-dev-deploy.service`

A oneshot systemd service that runs AFTER `network-online.target` with a configurable delay (default 60s). It:

1. Waits for grace period (device is fully accessible as normal Ubuntu)
2. Pulls latest code from git
3. Builds rswitch
4. If build succeeds, starts `rswitch.service`
5. If build fails, logs error and exits — device stays in normal Ubuntu mode

### Configuration

```bash
# /etc/rswitch/dev-deploy.conf
GRACE_PERIOD=60              # Seconds to wait before deploying
RSWITCH_REPO=/home/user/rSwitch/rswitch
RSWITCH_BRANCH=dev
AUTO_START=true              # Start rswitch after successful build
```

### When to Use

This service is for **development/testing devices only**. Production devices should use the standard `rswitch.service` with the existing failsafe mechanism.

## Layer 2: Killswitch Module

### Trigger Protocol

The killswitch listens for **UDP packets on a dedicated port** (default: 19999) with a magic payload:

```
┌──────────────┬──────────────┬──────────────────────┐
│ Ethernet/VLAN│ IP/UDP       │ Payload              │
│ (any)        │ dst_port=    │ [32B secret][1B act]  │
│              │ 19999        │                       │
└──────────────┴──────────────┴──────────────────────┘
```

- **Port**: Configurable, default 19999
- **Secret**: 32-byte key loaded from `/etc/rswitch/killswitch.key`
- **Action byte**: `0x01` = stop rswitch, `0x02` = reboot
- **Source restriction**: Optional source MAC/IP filter for additional security

### Why UDP, Not Raw Payload Scanning

Per Oracle architecture review:
- Raw payload scanning (sliding window over entire packet) is O(pkt_len × pattern_len) per packet — too expensive for XDP hot path
- UDP port check is O(1) — only packets to port 19999 trigger the 32-byte compare
- Standard tooling can send UDP packets (netcat, socat, python) — no custom tools needed
- Verifier-friendly: bounded 32-byte compare with `#pragma unroll`, no `bpf_loop()` (5.8+ compat)

### BPF Module: `killswitch.bpf.c`

- **Stage**: 5 (RS_STAGE_KILLSWITCH) — runs before ALL other modules
- **Hook**: RS_HOOK_XDP_INGRESS
- **Flags**: RS_FLAG_MAY_DROP (in case of future rate-limiting)
- **Map**: `rs_killswitch_map` (ARRAY, 1 entry, pinned)

```c
struct rs_killswitch_state {
    __u32 action;          // 0=none, 1=stop, 2=reboot
    __u32 trigger_ifindex; // Which interface received the trigger
    __u64 trigger_ts;      // When the trigger was received
    __u32 trigger_count;   // Monotonic counter
};
```

**Fast path** (non-matching packets):
1. Check if packet is IPv4 UDP → if not, skip (tail-call next)
2. Check UDP dst port == killswitch port → if not, skip
3. Compare 32 bytes of payload against secret → if no match, skip

Cost for non-matching packets: ~3 comparisons + 1 tail-call = negligible.

**VLAN handling**: Because killswitch runs before the VLAN module (stage 20), it must parse VLAN tags itself to find the IP header. The dispatcher already parses this into `rs_ctx->layers`, so killswitch reads from context.

### Userspace Watchdog: `rs-killswitch-watchdog`

A lightweight daemon that:
1. Opens pinned `rs_killswitch_map`
2. Polls every 500ms
3. If `action != 0`:
   - `action == 1` → `systemctl stop rswitch && /opt/rswitch/scripts/rswitch-failsafe.sh setup`
   - `action == 2` → `systemctl reboot`
4. Resets the map after executing action (for stop; reboot is irreversible)

### Key File Format

```
# /etc/rswitch/killswitch.key
# 32 bytes hex-encoded (64 hex chars), one line
# Generate with: openssl rand -hex 32
a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2
```

### Trigger Tool

```bash
# scripts/rswitch-killswitch-trigger.sh
# Usage: rswitch-killswitch-trigger.sh <target-ip> <action> [key-file]
#   action: stop | reboot
#   key-file: defaults to /etc/rswitch/killswitch.key

# Example: Emergency stop rswitch on 10.174.1.191
./scripts/rswitch-killswitch-trigger.sh 10.174.1.191 stop

# Example: Reboot device
./scripts/rswitch-killswitch-trigger.sh 10.174.1.191 reboot /path/to/key
```

Uses `socat` or python to send the UDP magic packet.

## Security Considerations

1. **High-entropy secret**: 32 bytes = 256 bits. Accidental trigger probability is negligible.
2. **Source filtering** (optional): Can restrict to specific MAC or IP addresses.
3. **No replay protection**: This is a dev/test mechanism, not production security. An attacker who can sniff the wire can replay the packet. For production, use proper out-of-band management (IPMI/iLO/iDRAC).
4. **Same L2 domain**: Trigger packets must reach the physical NIC. They work within the same network segment.

## File Inventory

| File | Type | Purpose |
|------|------|---------|
| `bpf/modules/killswitch.bpf.c` | BPF module | XDP killswitch (stage 5) |
| `sdk/include/rswitch_killswitch.h` | Header | Shared constants & structs |
| `user/killswitch/rs_killswitch_watchdog.c` | Userspace | Map polling + action execution |
| `scripts/rswitch-dev-deploy.sh` | Script | Boot grace period + auto-deploy |
| `scripts/rswitch-killswitch-trigger.sh` | Script | Send trigger UDP packet |
| `etc/systemd/rswitch-dev-deploy.service` | Systemd | Dev deploy service unit |
| `etc/systemd/rswitch-killswitch.service` | Systemd | Killswitch watchdog service |
| `etc/rswitch/killswitch.key.example` | Config | Example key file |

## Future: libxdp Pre-Dispatch Survivability

The current design only works when rswitch is running (killswitch is in the pipeline). If rswitch crashes or its XDP program is replaced, the killswitch is gone too. During this time, the boot grace period and existing failsafe (L2 bridge) provide access.

True "survive rswitch failure" requires migrating rSwitch's XDP attachment from direct `bpf_xdp_attach()` to libxdp multiprog. This is a separate, larger project:
- Move dispatcher to run as a libxdp program in a multiprog chain
- Place killswitch as the first program in the chain (runs before dispatcher)
- Killswitch persists even if dispatcher is replaced

**Effort**: Large. Tracked separately from this implementation.
