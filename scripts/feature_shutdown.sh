#!/usr/bin/env bash
#
# disable_all_suspect_offloads.sh
#
# 目标：
#   在指定网卡上，尽可能关闭所有可能干扰 XDP / devmap egress / AF_XDP 的硬件 offload。
#
# 用法：
#   sudo ./disable_all_suspect_offloads.sh             # 默认 ens161
#   sudo ./disable_all_suspect_offloads.sh ens34       # 指定一个网卡
#   sudo ./disable_all_suspect_offloads.sh ens34 ens161  # 多个网卡
#

set -euo pipefail

if [ "$EUID" -ne 0 ]; then
    echo "请用 root 或 sudo 运行这个脚本."
    exit 1
fi

if [ "$#" -eq 0 ]; then
    IFACES=("ens161")
else
    IFACES=("$@")
fi

# 尽可能“狠”的 feature 列表，ethtool -K 会逐个尝试关闭。
FEATURES=(
    # 最重要的一批：直接影响 XDP 包形态/分片
    gro
    lro
    gso
    tso
    sg

    # VLAN 相关（RX/TX/tag/filter）
    rxvlan
    txvlan
    rx-vlan-offload
    tx-vlan-offload
    rx-vlan-filter

    # RX 聚合/forward 相关
    rx-gro-list
    rx-gro-hw
    rx-udp-gro-forwarding
    rx-all

    # 校验/标记类
    rx-fcs
    rxhash

    # 隧道/加密 offload
    rx-udp_tunnel-port-offload
    hw-tc-offload
    esp-hw-offload
    esp-tx-csum-hw-offload
    tls-hw-tx-offload
    tls-hw-rx-offload
    tls-hw-record
    macsec-hw-offload

    # 二层转发/奇怪 offload
    l2-fwd-offload
    tx-nocache-copy
)

for dev in "${IFACES[@]}"; do
    echo ">>> 正在处理网卡: ${dev}"

    if ! ip link show "$dev" &>/dev/null; then
        echo "    [WARN] 网卡 ${dev} 不存在，跳过"
        continue
    fi

    echo "    启动网卡 ${dev}："
    ip link set "$dev" up

    echo "    当前 offload 状态："
    ethtool -k "$dev" | sed 's/^/      /'

    echo "    正在尝试关闭所有可能干扰 XDP/AF_XDP 的特性..."
    for feat in "${FEATURES[@]}"; do
        # 某些驱动不认这个名字，或者该 feature 是 fixed；都无所谓，错误日志只做提示
        if ethtool -K "$dev" "$feat" off 2>/tmp/ethtool_${dev}_${feat}.log; then
            echo "      [OK]  ${feat} 已设置为 off"
        else
            if grep -qiE "fixed|not supported|no such device" /tmp/ethtool_${dev}_${feat}.log 2>/dev/null; then
                echo "      [SKIP] ${feat} 无法修改（驱动不支持或为 fixed），忽略"
            else
                echo "      [WARN] 关闭 ${feat} 时出错，详情："
                sed 's/^/        /' /tmp/ethtool_${dev}_${feat}.log || true
            fi
        fi
        rm -f /tmp/ethtool_${dev}_${feat}.log
    done

    echo "    调整完成后的 offload 状态："
    ethtool -k "$dev" | sed 's/^/      /'
    echo
done

echo "全部完成。该网卡现在更适合作为 XDP/AF_XDP/devmap 的实验环境使用。"
