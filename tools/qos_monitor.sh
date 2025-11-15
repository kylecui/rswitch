#!/bin/bash
# QoS Real-time Monitor
# Continuously displays QoS statistics and drops

REFRESH_INTERVAL=1  # seconds

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root"
    exit 1
fi

# Check if bpftool is available
if ! command -v bpftool &> /dev/null; then
    echo "Error: bpftool not found"
    exit 1
fi

# Get terminal size
COLUMNS=$(tput cols)
LINES=$(tput lines)

print_header() {
    clear
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}                   ${GREEN}rSwitch QoS Monitor${NC}                              ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

get_map_value() {
    local map_name=$1
    local key=$2
    local field=$3
    
    bpftool map lookup name "$map_name" key $key 2>/dev/null | grep "$field" | awk '{print $2}'
}

display_rate_limiters() {
    echo -e "${YELLOW}Rate Limiters (Token Bucket per Priority):${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    printf "%-10s %-12s %-12s %-14s %-14s %-12s\n" \
        "Priority" "Rate(Mbps)" "Burst(KB)" "TotalPkts" "DroppedPkts" "Drop%"
    echo "──────────────────────────────────────────────────────────────────────────"
    
    for prio in 0 1 2 3; do
        if bpftool map lookup name qos_rate_map key $prio &>/dev/null; then
            # Parse qos_rate_limiter struct
            local data=$(bpftool map lookup name qos_rate_map key $prio 2>/dev/null | grep "value:")
            
            # Extract fields (this is simplified, real parsing would be more complex)
            local rate_bps=$(echo "$data" | awk '{print $3}')
            local burst=$(echo "$data" | awk '{print $4}')
            local total=$(echo "$data" | awk '{print $7}')
            local dropped=$(echo "$data" | awk '{print $9}')
            
            # Convert to human-readable
            local rate_mbps=$((rate_bps / 1000000))
            local burst_kb=$((burst / 1024))
            
            # Calculate drop percentage
            local drop_pct=0
            if [[ $total -gt 0 ]]; then
                drop_pct=$(awk "BEGIN {printf \"%.2f\", ($dropped/$total)*100}")
            fi
            
            # Color code based on drops
            local color=$GREEN
            if [[ $dropped -gt 0 ]]; then
                color=$RED
            fi
            
            printf "${color}%-10s %-12s %-12s %-14s %-14s %-12s${NC}\n" \
                "$prio" "$rate_mbps" "$burst_kb" "$total" "$dropped" "$drop_pct%"
        fi
    done
    
    echo ""
}

display_queue_depths() {
    echo -e "${YELLOW}Queue Depths (Congestion Monitoring):${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    printf "%-10s %-15s %-20s\n" "Priority" "Queue Depth" "Status"
    echo "──────────────────────────────────────────────────────────────────────────"
    
    for prio in 0 1 2 3; do
        if bpftool map lookup name qos_qdepth_map key $prio &>/dev/null; then
            local qdepth=$(bpftool map lookup name qos_qdepth_map key $prio 2>/dev/null | grep "value:" | awk '{print $2}')
            
            # Determine status based on queue depth
            local status="OK"
            local color=$GREEN
            
            if [[ $qdepth -gt 1000 ]]; then
                status="CONGESTED"
                color=$RED
            elif [[ $qdepth -gt 500 ]]; then
                status="WARNING"
                color=$YELLOW
            fi
            
            printf "${color}%-10s %-15s %-20s${NC}\n" "$prio" "$qdepth" "$status"
        fi
    done
    
    echo ""
}

display_classification_stats() {
    echo -e "${YELLOW}Classification Rules:${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    local rule_count=$(bpftool map dump name qos_class_map 2>/dev/null | grep -c "key:" || echo 0)
    echo -e "Total active rules: ${GREEN}$rule_count${NC}"
    
    if [[ $rule_count -gt 0 ]] && [[ $rule_count -lt 20 ]]; then
        echo ""
        printf "%-8s %-10s %-8s → %-10s\n" "Proto" "DPort" "DSCP" "Priority"
        echo "──────────────────────────────────────────────────────────"
        
        bpftool map dump name qos_class_map 2>/dev/null | grep -A1 "key:" | while read -r line; do
            if [[ $line == *"key:"* ]]; then
                proto=$(echo "$line" | awk '{print $2}')
                dscp=$(echo "$line" | awk '{print $3}')
                dport=$(echo "$line" | awk '{print $4}')
            elif [[ $line == *"value:"* ]]; then
                priority=$(echo "$line" | awk '{print $2}')
                printf "%-8s %-10s %-8s → %-10s\n" "$proto" "$dport" "$dscp" "$priority"
            fi
        done | head -10
    fi
    
    echo ""
}

display_afxdp_stats() {
    echo -e "${YELLOW}AF_XDP Redirect Status:${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # Check VOQd state - parse JSON output from bpftool
    if bpftool map show name voqd_state_map &>/dev/null; then
        local json_output=$(bpftool map dump name voqd_state_map -j 2>/dev/null)
        
        # Parse JSON using basic tools (grep + sed)
        # Extract values from JSON: "field": value
        local mode=$(echo "$json_output" | grep -o '"mode":[[:space:]]*[0-9]*' | grep -o '[0-9]*$')
        local running=$(echo "$json_output" | grep -o '"running":[[:space:]]*[0-9]*' | grep -o '[0-9]*$')
        local prio_mask=$(echo "$json_output" | grep -o '"prio_mask":[[:space:]]*[0-9]*' | grep -o '[0-9]*$')
        local failover_count=$(echo "$json_output" | grep -o '"failover_count":[[:space:]]*[0-9]*' | grep -o '[0-9]*$')
        
        # Default values if parsing failed
        mode=${mode:-0}
        running=${running:-0}
        prio_mask=${prio_mask:-0}
        failover_count=${failover_count:-0}
        
        # Convert mode number to string
        case $mode in
            0) mode_str="BYPASS" ;;
            1) mode_str="SHADOW" ;;
            2) mode_str="ACTIVE" ;;
            *) mode_str="UNKNOWN($mode)" ;;
        esac
        
        # Color coding
        local mode_color=$YELLOW
        local running_color=$RED
        
        if [[ $mode -eq 2 ]]; then
            mode_color=$GREEN  # ACTIVE = green
        fi
        
        if [[ $running -eq 1 ]]; then
            running_color=$GREEN  # Running = green
        fi
        
        echo -e "VOQd Mode: ${mode_color}${mode_str}${NC}"
        echo -e "VOQd Running: ${running_color}${running}${NC} (0=stopped, 1=running)"
        echo -e "Priority Mask: ${CYAN}0x$(printf '%02x' $prio_mask)${NC} (intercept priorities)"
        
        if [[ $failover_count -gt 0 ]]; then
            echo -e "Failover Count: ${RED}${failover_count}${NC} (automatic ACTIVE→BYPASS)"
        fi
        
        # Status interpretation
        if [[ $running -eq 0 ]]; then
            echo -e "Status: ${YELLOW}VOQd not running - all traffic in XDP fast-path${NC}"
        elif [[ $mode -eq 0 ]]; then
            echo -e "Status: ${YELLOW}BYPASS mode - VOQd running but not intercepting${NC}"
        elif [[ $mode -eq 1 ]]; then
            echo -e "Status: ${CYAN}SHADOW mode - VOQd observing, XDP forwarding${NC}"
        elif [[ $mode -eq 2 ]]; then
            echo -e "Status: ${GREEN}ACTIVE mode - VOQd handling high-priority flows${NC}"
        fi
    else
        echo -e "${RED}VOQd not configured${NC}"
        echo -e "  (voqd_state_map not found - AF_XDP redirect not available)"
    fi
    
    # Show AF_XDP redirect statistics if available
    if bpftool map show name afxdp_stats_map &>/dev/null; then
        echo ""
        echo "Redirect Statistics:"
        bpftool map dump name afxdp_stats_map 2>/dev/null | head -10
    fi
    
    echo ""
}

display_port_stats() {
    echo -e "${YELLOW}Port Statistics Summary:${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    printf "%-6s %-12s %-12s %-12s %-12s\n" "Port" "RX Pkts" "TX Pkts" "TX Drops" "Drop%"
    echo "──────────────────────────────────────────────────────────────────────────"
    
    if bpftool map show name rs_stats_map &>/dev/null; then
        bpftool map dump name rs_stats_map 2>/dev/null | grep -E "key:|value:" | paste - - | while read line; do
            port=$(echo "$line" | awk '{print $2}')
            rx_pkts=$(echo "$line" | awk '{print $5}')
            tx_pkts=$(echo "$line" | awk '{print $7}')
            tx_drops=$(echo "$line" | awk '{print $9}')
            
            # Calculate drop percentage
            local drop_pct=0
            if [[ $tx_pkts -gt 0 ]]; then
                drop_pct=$(awk "BEGIN {printf \"%.2f\", ($tx_drops/$tx_pkts)*100}")
            fi
            
            # Color code
            local color=$GREEN
            if [[ $tx_drops -gt 0 ]]; then
                color=$RED
            fi
            
            printf "${color}%-6s %-12s %-12s %-12s %-12s${NC}\n" \
                "$port" "$rx_pkts" "$tx_pkts" "$tx_drops" "$drop_pct%"
        done
    else
        echo "Stats map not found"
    fi
    
    echo ""
}

monitor_loop() {
    while true; do
        print_header
        
        display_rate_limiters
        display_queue_depths
        display_afxdp_stats
        display_port_stats
        
        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "Refresh: ${REFRESH_INTERVAL}s | Press Ctrl+C to exit"
        echo -e "Last update: $(date '+%Y-%m-%d %H:%M:%S')"
        
        sleep $REFRESH_INTERVAL
    done
}

# Handle Ctrl+C gracefully
trap 'echo ""; echo "Exiting..."; exit 0' INT

# Start monitoring
monitor_loop
