#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PASS=0
FAIL=0
SKIP=0

RSWITCH_DIR="${RSWITCH_DIR:-$(cd "$(dirname "$0")/../.." && pwd)}"
BUILD_DIR="$RSWITCH_DIR/build"
BPF_DIR="$BUILD_DIR/bpf"
PROFILE_DIR="$RSWITCH_DIR/etc/profiles"
BPF_PIN_PATH="/sys/fs/bpf"

pass() {
    echo -e "${GREEN}PASS${NC}: $1"
    PASS=$((PASS + 1))
}

fail() {
    echo -e "${RED}FAIL${NC}: $1"
    FAIL=$((FAIL + 1))
}

skip() {
    echo -e "${YELLOW}SKIP${NC}: $1"
    SKIP=$((SKIP + 1))
}

info() {
    echo -e "${BLUE}INFO${NC}: $1"
}

require_root() {
    if [ "$EUID" -ne 0 ]; then
        echo "This test requires root. Run with sudo."
        exit 1
    fi
}

require_build() {
    if [ ! -f "$BUILD_DIR/rswitch_loader" ]; then
        echo "rSwitch not built. Run 'make all' first."
        exit 1
    fi
}

setup_veth_pair() {
    local ns_a="$1"
    local ns_b="$2"
    local veth_a="$3"
    local veth_b="$4"
    local ip_a="$5"
    local ip_b="$6"

    ip netns add "$ns_a" 2>/dev/null || true
    ip netns add "$ns_b" 2>/dev/null || true
    ip link add "$veth_a" type veth peer name "$veth_b" 2>/dev/null || true
    ip link set "$veth_a" netns "$ns_a"
    ip link set "$veth_b" netns "$ns_b"
    ip -n "$ns_a" link set lo up
    ip -n "$ns_b" link set lo up
    ip -n "$ns_a" link set "$veth_a" up
    ip -n "$ns_b" link set "$veth_b" up
    if [ -n "$ip_a" ]; then
        ip -n "$ns_a" addr flush dev "$veth_a" 2>/dev/null || true
        ip -n "$ns_a" addr add "$ip_a" dev "$veth_a"
    fi
    if [ -n "$ip_b" ]; then
        ip -n "$ns_b" addr flush dev "$veth_b" 2>/dev/null || true
        ip -n "$ns_b" addr add "$ip_b" dev "$veth_b"
    fi
}

teardown_veth_pair() {
    local ns_a="$1"
    local ns_b="$2"
    local veth_a="$3"

    if [ -n "$ns_a" ] && [ -n "$veth_a" ]; then
        ip -n "$ns_a" link set dev "$veth_a" xdp off 2>/dev/null || true
    fi
    ip netns del "$ns_a" 2>/dev/null || true
    ip netns del "$ns_b" 2>/dev/null || true
}

setup_veth() {
    local veth1="$1" veth2="$2"
    ip link add "$veth1" type veth peer name "$veth2" 2>/dev/null || true
    ip link set "$veth1" up
    ip link set "$veth2" up
}

teardown_veth() {
    ip link del "$1" 2>/dev/null || true
}

send_packet() {
    local ns="$1"
    local iface="$2"
    local src_ip="$3"
    local dst_ip="$4"
    local l4_proto="${5:-icmp}"
    local dport="${6:-0}"
    local vlan_id="${7:-0}"

    if command -v python3 >/dev/null 2>&1; then
        ip netns exec "$ns" python3 - "$iface" "$src_ip" "$dst_ip" "$l4_proto" "$dport" "$vlan_id" <<'PY'
import sys
try:
    from scapy.all import Ether, IP, ICMP, TCP, UDP, Dot1Q, sendp
except Exception:
    sys.exit(42)

iface, src_ip, dst_ip, proto, dport, vlan = sys.argv[1:]
vlan = int(vlan)
dport = int(dport)

pkt = Ether(dst="02:00:00:00:00:02", src="02:00:00:00:00:01")
if vlan > 0:
    pkt = pkt / Dot1Q(vlan=vlan)
ip = IP(src=src_ip, dst=dst_ip, ttl=64)

proto = proto.lower()
if proto == "tcp":
    pkt = pkt / ip / TCP(sport=34567, dport=dport if dport > 0 else 80, flags="S")
elif proto == "udp":
    pkt = pkt / ip / UDP(sport=34567, dport=dport if dport > 0 else 53)
else:
    pkt = pkt / ip / ICMP(type=8, code=0)

sendp(pkt, iface=iface, verbose=False, count=1)
PY
        rc=$?
        if [ "$rc" -eq 0 ]; then
            return 0
        fi
    fi

    if [ -n "$dst_ip" ]; then
        ip netns exec "$ns" ping -c 1 -W 1 -I "$iface" "$dst_ip" >/dev/null 2>&1
        return $?
    fi

    return 1
}

capture_packet() {
    local ns="$1"
    local iface="$2"
    local output_pcap="$3"
    local timeout_s="${4:-3}"

    rm -f "$output_pcap"
    ip netns exec "$ns" timeout "$timeout_s" tcpdump -i "$iface" -nn -U -c 1 -w "$output_pcap" >/dev/null 2>&1 || true
    [ -s "$output_pcap" ]
}

assert_forwarded() {
    local pcap="$1"
    local msg="$2"

    if [ -s "$pcap" ]; then
        pass "$msg"
    else
        fail "$msg"
    fi
}

assert_dropped() {
    local pcap="$1"
    local msg="$2"

    if [ ! -s "$pcap" ]; then
        pass "$msg"
    else
        fail "$msg"
    fi
}

assert_counter() {
    local map_name="$1"
    local key_u32="$2"
    local expected_min="$3"
    local label="$4"
    local map_path="${5:-$BPF_PIN_PATH/$map_name}"
    local key_hex
    local out
    local value

    if [ ! -e "$map_path" ]; then
        skip "$label (map missing: $map_name)"
        return 0
    fi

    key_hex=$(printf "%02x %02x %02x %02x" \
        $((key_u32 & 0xff)) \
        $(((key_u32 >> 8) & 0xff)) \
        $(((key_u32 >> 16) & 0xff)) \
        $(((key_u32 >> 24) & 0xff)))

    out="$(bpftool map lookup pinned "$map_path" key hex $key_hex 2>/dev/null)"
    if [ -z "$out" ]; then
        fail "$label (lookup failed)"
        return 1
    fi

    value=$(printf "%s" "$out" | awk '/value:/{for(i=2;i<=NF;i++){if($i ~ /^[0-9]+$/){print $i; exit}}}')
    if [ -z "$value" ]; then
        value=$(printf "%s" "$out" | awk '/value:/{for(i=2;i<=NF;i++){if($i ~ /^0x/){print strtonum($i); exit}}}')
    fi

    if [ -n "$value" ] && [ "$value" -ge "$expected_min" ]; then
        pass "$label (value=$value >= $expected_min)"
    else
        fail "$label (value=${value:-unknown} < $expected_min)"
    fi
}

cleanup_bpf() {
    rm -f "$BPF_PIN_PATH"/rs_* 2>/dev/null || true
    rm -f "$BPF_PIN_PATH"/acl_* 2>/dev/null || true
    rm -f "$BPF_PIN_PATH"/mirror_* 2>/dev/null || true
    rm -rf "$BPF_PIN_PATH"/rs_test 2>/dev/null || true
    rm -rf "$BPF_PIN_PATH"/test_progs 2>/dev/null || true
}

print_summary() {
    local test_name="$1"
    echo ""
    echo "========================================="
    echo "$test_name - Summary"
    echo "========================================="
    echo -e "${GREEN}Passed: $PASS${NC}"
    echo -e "${RED}Failed: $FAIL${NC}"
    echo -e "${YELLOW}Skipped: $SKIP${NC}"
    echo ""

    if [ "$FAIL" -eq 0 ]; then
        echo -e "${GREEN}All tests passed${NC}"
        return 0
    fi

    echo -e "${RED}$FAIL test(s) failed${NC}"
    return 1
}

wait_for_map() {
    local map="$1"
    local timeout="${2:-5}"
    local elapsed=0

    while [ ! -e "$BPF_PIN_PATH/$map" ] && [ "$elapsed" -lt "$timeout" ]; do
        sleep 1
        elapsed=$((elapsed + 1))
    done

    [ -e "$BPF_PIN_PATH/$map" ]
}

get_ifindex() {
    cat "/sys/class/net/$1/ifindex" 2>/dev/null
}
