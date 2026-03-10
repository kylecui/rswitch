#!/usr/bin/env bash
# scripts/aclctl.sh : simple rule CRUD via bpftool
set -euo pipefail

OBJ=${OBJ:-"./build/bpf/acl_core.bpf.o"}

usage() {
  cat <<EOF
Usage:
  $0 load <IFACE>                  # load/attach XDP
  $0 add-5t <proto> <src_ip> <sport> <dst_ip> <dport> <action> [ifindex]
  $0 add-lpm-src <cidr> <action>
  $0 stats
Notes:
  action: PASS|DROP|REDIRECT
EOF
}

map_id() {
  local name="$1"
  bpftool map show | awk -v n="$name" '$0 ~ n {gsub(":", "", $1); print $1; exit}'
}

load() {
  local iface="$1"
  sudo bpftool prog load $OBJ "/sys/fs/bpf/xdp-acl"
  sudo bpftool net attach xdp pinned "/sys/fs/bpf/xdp-acl" dev "$iface"
}

add_5t() {
  local proto="$1" src="$2" sport="$3" dst="$4" dport="$5" action="$6" ifi="${7:-0}"
  local m=$(map_id map_acl_5t_v4)
  local pnum
  case "$proto" in
    tcp|TCP) pnum=6 ;;
    udp|UDP) pnum=17;;
    *) pnum=0 ;;
  esac
  local act=0
  case "$action" in
    PASS) act=0;;
    DROP) act=1;;
    REDIRECT) act=2;;
    *) act=0;;
  esac
  # key struct layout: proto,u8 ip_v=4,u16 sport,u16 dport,u16 pad,u32 src,u32 dst
  sudo bpftool map update id $m key hex \
    $(printf "%02x" $pnum) 04 00 00 \
    $(printf "%04x" $sport | sed 's/../& /g') \
    $(printf "%04x" $dport | sed 's/../& /g') \
    00 00 \
    $(printf "%08x" $(printf "%d" $(python3 - <<P\nimport socket,struct;print(struct.unpack('>I',socket.inet_aton('$src'))[0])\nP)) | sed 's/../& /g') \
    $(printf "%08x" $(printf "%d" $(python3 - <<P\nimport socket,struct;print(struct.unpack('>I',socket.inet_aton('$dst'))[0])\nP)) | sed 's/../& /g') \
    value hex \
    $(printf "%02x" $act) 00 00 00 \
    $(printf "%08x" $ifi | sed 's/../& /g') \
    00 00 00 00
}

add_lpm_src() {
  local cidr="$1" action="$2"
  local net="${cidr%/*}" pre="${cidr#*/}"
  local m=$(map_id map_acl_lpm_v4_src)
  local act=0
  case "$action" in
    PASS) act=0;;
    DROP) act=1;;
    REDIRECT) act=2;;
    *) act=0;;
  esac
  local netbe=$(python3 - <<P
import socket,struct
print("%08x"%struct.unpack(">I",socket.inet_aton("$net"))[0])
P
)
  sudo bpftool map update id $m key hex \
    $(printf "%08x" $pre | sed 's/../& /g') \
    $(echo $netbe | sed 's/../& /g') \
    value hex \
    $(printf "%02x" $act) 00 00 00 \
    00 00 00 00 \
    00 00 00 00
}

stats() {
  local m=$(map_id map_stats)
  echo "Stats:"
  for i in 0 1 2 3 4; do
    sudo bpftool map lookup id $m key hex $(printf "%08x" $i | sed 's/../& /g') 2>/dev/null | sed 's/.*value: //' || true
  done
}

case "${1:-}" in
  load) load "${2:-eth0}" ;;
  add-5t) shift; add_5t "$@" ;;
  add-lpm-src) shift; add_lpm_src "$@" ;;
  stats) stats ;;
  *) usage ;;
esac
