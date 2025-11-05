#!/bin/bash
# BPF Pin Path 验证脚本
# 验证所有 rSwitch maps 是否正确 pin 到 /sys/fs/bpf/

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "================================================"
echo "rSwitch BPF Pin Path 验证"
echo "================================================"
echo ""

# 检查是否有管理员权限
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}错误：需要 root 权限${NC}"
    echo "请使用: sudo $0"
    exit 1
fi

# 预期的 maps 列表
CORE_MAPS=(
    "rs_ctx_map"
    "rs_progs"
    "rs_port_config_map"
    "rs_vlan_map"
    "rs_stats_map"
    "rs_event_bus"
)

MODULE_MAPS=(
    "rs_mac_table"
)

OPTIONAL_MAPS=(
    "acl_rules"
    "acl_rule_order"
    "acl_config_map"
    "acl_stats"
    "mirror_config_map"
    "port_mirror_map"
    "mirror_stats"
    "voq_ringbuf"
    "voqd_state_map"
    "qos_config_map"
)

echo "1. 检查 Core Infrastructure Maps"
echo "-----------------------------------"
found=0
missing=0
for map in "${CORE_MAPS[@]}"; do
    if [ -e "/sys/fs/bpf/$map" ]; then
        echo -e "${GREEN}✓${NC} $map"
        ((found++))
    else
        echo -e "${RED}✗${NC} $map (missing)"
        ((missing++))
    fi
done
echo ""

echo "2. 检查 Module-Owned Maps"
echo "-----------------------------------"
for map in "${MODULE_MAPS[@]}"; do
    if [ -e "/sys/fs/bpf/$map" ]; then
        echo -e "${GREEN}✓${NC} $map"
        ((found++))
    else
        echo -e "${YELLOW}⚠${NC} $map (not loaded)"
    fi
done
echo ""

echo "3. 检查 Optional Module Maps"
echo "-----------------------------------"
optional_found=0
for map in "${OPTIONAL_MAPS[@]}"; do
    if [ -e "/sys/fs/bpf/$map" ]; then
        echo -e "${GREEN}✓${NC} $map"
        ((optional_found++))
    fi
done
if [ $optional_found -eq 0 ]; then
    echo -e "${YELLOW}  (无可选模块 maps)${NC}"
fi
echo ""

echo "4. 检查旧路径是否残留"
echo "-----------------------------------"
if [ -d "/sys/fs/bpf/rswitch" ]; then
    echo -e "${RED}✗${NC} 发现旧路径: /sys/fs/bpf/rswitch/"
    echo "  建议清理: sudo rm -rf /sys/fs/bpf/rswitch"
else
    echo -e "${GREEN}✓${NC} 无旧路径残留"
fi
echo ""

echo "5. 使用 bpftool 验证"
echo "-----------------------------------"
if command -v bpftool &> /dev/null; then
    rs_map_count=$(bpftool map show 2>/dev/null | grep -c "name rs_" || true)
    echo "  发现 $rs_map_count 个 rs_ 开头的 maps"
    
    if [ $rs_map_count -gt 0 ]; then
        echo ""
        echo "  详细列表:"
        bpftool map show 2>/dev/null | grep "name rs_" | while read line; do
            echo "    $line"
        done
    fi
else
    echo -e "${YELLOW}⚠${NC} bpftool 未安装，跳过"
fi
echo ""

echo "================================================"
echo "总结"
echo "================================================"
echo "  Core Maps 找到: $found/${#CORE_MAPS[@]}"
echo "  Module Maps 找到: ${#MODULE_MAPS[@]}"
echo "  Optional Maps 找到: $optional_found/${#OPTIONAL_MAPS[@]}"

if [ $missing -eq 0 ]; then
    echo ""
    echo -e "${GREEN}✓ 验证通过！所有 core maps 都已正确 pin 到 /sys/fs/bpf/${NC}"
else
    echo ""
    echo -e "${RED}✗ 验证失败！缺少 $missing 个 core maps${NC}"
    echo "  请确保 rSwitch loader 已正确加载"
    exit 1
fi
