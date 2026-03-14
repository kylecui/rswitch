#!/bin/bash
# rswitch-gen-profile.sh — Generate a default profile YAML from detected ports
#
# Usage: rswitch-gen-profile.sh <comma-separated-ports> [output-file]
#
# Generates a production-ready L2+VLAN+DHCP snooping profile with all
# detected ports configured as access ports on VLAN 1.
# First port is set as trunk (uplink heuristic).

set -euo pipefail

die() { echo "ERROR: $*" >&2; exit 1; }

PORTS="${1:-}"
OUTPUT="${2:-/dev/stdout}"
INSTALL_PREFIX="${INSTALL_PREFIX:-/opt/rswitch}"

[ -z "$PORTS" ] && die "Usage: $0 <port1,port2,...> [output-file]"

IFS=',' read -ra PORT_LIST <<< "$PORTS"
PORT_COUNT=${#PORT_LIST[@]}

[ "$PORT_COUNT" -eq 0 ] && die "No ports specified"

gen_port_entry() {
    local iface="$1"
    local is_first="$2"

    if [ "$is_first" = "true" ] && [ "$PORT_COUNT" -gt 1 ]; then
        cat <<EOF
  - interface: ${iface}
    vlan_mode: trunk
    allowed_vlans: [1]
    native_vlan: 1
    mac_learning: true
    default_priority: 1
EOF
    else
        cat <<EOF
  - interface: ${iface}
    vlan_mode: access
    access_vlan: 1
    mac_learning: true
    default_priority: 1
EOF
    fi
}

gen_trusted_ports() {
    for p in "${PORT_LIST[@]}"; do
        echo "    - ${p}"
    done
}

cat > "$OUTPUT" <<EOF
name: default
description: "Auto-generated rSwitch profile (${PORT_COUNT} ports)"
version: "1.0"

ingress:
  - vlan
  - dhcp_snoop
  - l2learn
  - lastcall

egress:
  - egress_vlan
  - egress_final

settings:
  mac_learning: true
  mac_aging_time: 300
  vlan_enforcement: true
  default_vlan: 1
  unknown_unicast_flood: true
  broadcast_flood: true
  multicast_flood: true
  stats_enabled: true
  ringbuf_enabled: true
  debug: false

ports:
$(
    first=true
    for p in "${PORT_LIST[@]}"; do
        gen_port_entry "$p" "$first"
        first=false
        echo ""
    done
)
management:
  enabled: true
  port: 8080
  web_root: ${INSTALL_PREFIX}/web
  use_namespace: true
  namespace_name: rswitch-mgmt
  iface_mode: dhcp
  mgmt_vlan: 1
  auth_enabled: true
  auth_user: admin
  auth_password: rswitch

dhcp_snooping:
  enabled: true
  drop_rogue_server: true
  trusted_ports:
$(gen_trusted_ports)

vlans:
  - vlan_id: 1
    name: "default"
    untagged_ports: [$(IFS=', '; echo "${PORT_LIST[*]}")]
    tagged_ports: []
EOF
