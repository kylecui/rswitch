#!/bin/bash
# rSwitch One-Line Installer
#
# Install:  curl -sfL https://get.rswitch.dev | sudo bash
# Or:       sudo bash install.sh
#
# Environment overrides:
#   RSWITCH_MGMT_NIC=eth0        — management NIC (auto-detected)
#   RSWITCH_INTERFACES=e1,e2,e3  — switch ports (auto-detected)
#   INSTALL_PREFIX=/opt/rswitch  — installation path (default)
#   RSWITCH_REPO=https://...     — git clone URL
#   RSWITCH_BRANCH=dev           — branch to build
#   RSWITCH_SRC=/path/to/src     — use local source (skip clone)
#   RSWITCH_NO_START=1           — install but don't start services
#   RSWITCH_FORCE=1              — skip confirmation prompts
#
# Exit codes:
#   0 — success
#   1 — pre-flight check failed
#   2 — dependency install failed
#   3 — build failed
#   4 — no switch ports detected
#   5 — install/setup failed

set -euo pipefail

# ── Defaults ─────────────────────────────────────────────────────
INSTALL_PREFIX="${INSTALL_PREFIX:-/opt/rswitch}"
RSWITCH_REPO="${RSWITCH_REPO:-https://github.com/kylecui/rswitch.git}"
RSWITCH_BRANCH="${RSWITCH_BRANCH:-dev}"
BUILD_DIR="${RSWITCH_SRC:-}"     # empty = clone from repo
VERSION="1.0.0"
LOG_FILE="/var/log/rswitch/install.log"

# ── Colors ───────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

# ── Helpers ──────────────────────────────────────────────────────
banner() {
    echo -e "${BLUE}"
    cat <<'BANNER'
       ____          _ _       _
  _ __/ ___|_      _(_) |_ ___| |__
 | '__\___ \ \ /\ / / | __/ __| '_ \
 | |   ___) \ V  V /| | || (__| | | |
 |_|  |____/ \_/\_/ |_|\__\___|_| |_|

  XDP-based Software Switch — Installer
BANNER
    echo -e "${NC}"
}

info()  { echo -e "${GREEN}[rSwitch]${NC} $*" | tee -a "$LOG_FILE" 2>/dev/null; }
warn()  { echo -e "${YELLOW}[WARNING]${NC} $*" | tee -a "$LOG_FILE" 2>/dev/null; }
error() { echo -e "${RED}[ERROR]${NC} $*" | tee -a "$LOG_FILE" 2>/dev/null; }
fatal() { error "$*"; exit 1; }

step() {
    local n="$1"; local total="$2"; shift 2
    echo ""
    echo -e "${BOLD}━━━ Phase ${n}/${total}: $* ━━━${NC}"
}

confirm() {
    if [ "${RSWITCH_FORCE:-0}" = "1" ]; then
        return 0
    fi
    local msg="$1"
    echo -en "${YELLOW}${msg} [Y/n] ${NC}"
    read -r ans
    case "$ans" in
        [Nn]*) return 1 ;;
        *) return 0 ;;
    esac
}

# ── Phase 1: Pre-flight checks ──────────────────────────────────
preflight() {
    step 1 6 "Pre-flight checks"

    # Must be root
    if [ "$EUID" -ne 0 ]; then
        fatal "This installer must be run as root (use sudo)"
    fi
    info "Running as root ✓"

    # Kernel version check (need ≥ 5.8 for XDP + CO-RE)
    local kver
    kver=$(uname -r | cut -d. -f1-2)
    local kmajor kminor
    kmajor=$(echo "$kver" | cut -d. -f1)
    kminor=$(echo "$kver" | cut -d. -f2)

    if [ "$kmajor" -lt 5 ] || { [ "$kmajor" -eq 5 ] && [ "$kminor" -lt 8 ]; }; then
        fatal "Kernel ${kver} too old. rSwitch requires kernel ≥ 5.8 (CO-RE + XDP). Current: $(uname -r)"
    fi
    info "Kernel $(uname -r) ✓"

    # BTF support check
    if [ ! -f /sys/kernel/btf/vmlinux ]; then
        fatal "Kernel BTF not available (/sys/kernel/btf/vmlinux missing). Rebuild kernel with CONFIG_DEBUG_INFO_BTF=y"
    fi
    info "Kernel BTF available ✓"

    # Architecture check
    local arch
    arch=$(uname -m)
    case "$arch" in
        x86_64|aarch64|arm64)
            info "Architecture: ${arch} ✓"
            ;;
        *)
            warn "Architecture ${arch} is untested. Proceeding anyway."
            ;;
    esac

    # Check if already installed
    if [ -d "$INSTALL_PREFIX" ] && [ -f "${INSTALL_PREFIX}/build/rswitch_loader" ]; then
        warn "rSwitch already installed at ${INSTALL_PREFIX}"
        if ! confirm "Overwrite existing installation?"; then
            info "Aborted by user"
            exit 0
        fi
        # Stop existing services before overwrite
        systemctl stop rswitch-mgmtd 2>/dev/null || true
        systemctl stop rswitch 2>/dev/null || true
        info "Stopped existing services"
    fi

    mkdir -p /var/log/rswitch
    info "Pre-flight checks passed"
}

# ── Phase 2: Install dependencies ───────────────────────────────
install_deps() {
    step 2 6 "Installing dependencies"

    # Detect package manager
    if command -v apt-get >/dev/null 2>&1; then
        install_deps_apt
    elif command -v dnf >/dev/null 2>&1; then
        install_deps_dnf
    elif command -v yum >/dev/null 2>&1; then
        install_deps_yum
    else
        warn "Unknown package manager. Please install dependencies manually:"
        warn "  build-essential clang llvm llvm-strip pkg-config"
        warn "  libelf-dev zlib1g-dev libsqlite3-dev"
        warn "  linux-headers-\$(uname -r)"
        warn "  dhcpcd5 ethtool iproute2"
        if ! confirm "Continue anyway?"; then
            exit 2
        fi
        return
    fi

    # Verify critical tools
    for tool in clang llvm-strip make gcc pkg-config; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            fatal "Required tool '${tool}' not found after dependency install"
        fi
    done
    info "All build tools verified ✓"

    # bpftool — try to find or install
    install_bpftool
}

install_deps_apt() {
    info "Detected apt package manager"
    export DEBIAN_FRONTEND=noninteractive

    apt-get update -qq >> "$LOG_FILE" 2>&1 || warn "apt-get update had issues"

    local pkgs=(
        build-essential
        clang
        llvm
        pkg-config
        libelf-dev
        zlib1g-dev
        libsqlite3-dev
        dhcpcd5
        ethtool
        iproute2
        git
    )

    # linux-headers — try current kernel first
    local hdr_pkg="linux-headers-$(uname -r)"
    if apt-cache show "$hdr_pkg" >/dev/null 2>&1; then
        pkgs+=("$hdr_pkg")
    else
        warn "Kernel headers package '${hdr_pkg}' not found in apt. BTF is already available, continuing."
    fi

    # libxdp-dev — optional, don't fail if unavailable
    if apt-cache show libxdp-dev >/dev/null 2>&1; then
        pkgs+=(libxdp-dev)
    else
        warn "libxdp-dev not available — AF_XDP VOQd features may be limited"
    fi

    info "Installing ${#pkgs[@]} packages..."
    if ! apt-get install -y -qq "${pkgs[@]}" >> "$LOG_FILE" 2>&1; then
        error "apt-get install failed. Check ${LOG_FILE}"
        exit 2
    fi
    info "Packages installed ✓"
}

install_deps_dnf() {
    info "Detected dnf package manager"
    local pkgs=(
        gcc make
        clang llvm
        pkgconfig
        elfutils-libelf-devel
        zlib-devel
        sqlite-devel
        dhcp-client
        ethtool
        iproute
        git
        "kernel-devel-$(uname -r)"
    )

    info "Installing ${#pkgs[@]} packages..."
    if ! dnf install -y "${pkgs[@]}" >> "$LOG_FILE" 2>&1; then
        error "dnf install failed. Check ${LOG_FILE}"
        exit 2
    fi
    info "Packages installed ✓"
}

install_deps_yum() {
    info "Detected yum package manager"
    local pkgs=(
        gcc make
        clang llvm
        pkgconfig
        elfutils-libelf-devel
        zlib-devel
        sqlite-devel
        dhclient
        ethtool
        iproute
        git
        "kernel-devel-$(uname -r)"
    )

    info "Installing ${#pkgs[@]} packages..."
    if ! yum install -y "${pkgs[@]}" >> "$LOG_FILE" 2>&1; then
        error "yum install failed. Check ${LOG_FILE}"
        exit 2
    fi
    info "Packages installed ✓"
}

install_bpftool() {
    if command -v bpftool >/dev/null 2>&1; then
        info "bpftool already available: $(which bpftool) ✓"
        return
    fi

    # Try linux-tools package first (Ubuntu/Debian)
    if command -v apt-get >/dev/null 2>&1; then
        local tools_pkg="linux-tools-$(uname -r)"
        if apt-cache show "$tools_pkg" >/dev/null 2>&1; then
            info "Installing bpftool via ${tools_pkg}..."
            apt-get install -y -qq "$tools_pkg" >> "$LOG_FILE" 2>&1 || true
        fi
        # Also try linux-tools-common
        apt-get install -y -qq linux-tools-common 2>>"$LOG_FILE" || true
    fi

    if command -v bpftool >/dev/null 2>&1; then
        info "bpftool installed: $(which bpftool) ✓"
        return
    fi

    # Build bpftool from kernel source as last resort
    warn "bpftool not found in packages. Building from kernel source..."
    local ksrc="/usr/src/linux-headers-$(uname -r)"
    if [ -d "${ksrc}/tools/bpf/bpftool" ]; then
        (cd "${ksrc}/tools/bpf/bpftool" && make -j"$(nproc)" >> "$LOG_FILE" 2>&1 && make install >> "$LOG_FILE" 2>&1) || true
    fi

    if command -v bpftool >/dev/null 2>&1; then
        info "bpftool built and installed ✓"
    else
        warn "bpftool not available — vmlinux.h generation may use fallback"
    fi
}

# ── Phase 3: Build from source ──────────────────────────────────
build_rswitch() {
    step 3 6 "Building rSwitch from source"

    local src_dir=""

    if [ -n "$BUILD_DIR" ]; then
        # Use local source
        src_dir="$BUILD_DIR"
        if [ ! -f "${src_dir}/Makefile" ]; then
            fatal "Local source directory ${src_dir} does not contain a Makefile"
        fi
        info "Using local source: ${src_dir}"
    else
        # Clone from repo
        src_dir="/tmp/rswitch-build-$$"
        info "Cloning ${RSWITCH_REPO} (branch: ${RSWITCH_BRANCH})..."
        if ! git clone --depth 1 --branch "$RSWITCH_BRANCH" --recurse-submodules "$RSWITCH_REPO" "$src_dir" >> "$LOG_FILE" 2>&1; then
            fatal "git clone failed. Check ${LOG_FILE}"
        fi
        info "Source cloned ✓"
    fi

    # Build libbpf from submodule
    local libbpf_src="${src_dir}/external/libbpf/src"
    if [ -d "$libbpf_src" ]; then
        info "Building libbpf..."
        if ! make -C "$libbpf_src" -j"$(nproc)" >> "$LOG_FILE" 2>&1; then
            fatal "libbpf build failed. Check ${LOG_FILE}"
        fi
        if ! make -C "$libbpf_src" install >> "$LOG_FILE" 2>&1; then
            fatal "libbpf install failed. Check ${LOG_FILE}"
        fi
        # Update linker cache for /usr/local/bpf/lib64
        ldconfig /usr/local/bpf/lib64 2>/dev/null || true
        info "libbpf installed ✓"
    else
        warn "libbpf submodule not found at ${libbpf_src}. Assuming system libbpf."
    fi

    # Generate vmlinux.h
    info "Generating vmlinux.h for running kernel..."
    if ! make -C "$src_dir" vmlinux >> "$LOG_FILE" 2>&1; then
        fatal "vmlinux.h generation failed. Is /sys/kernel/btf/vmlinux available?"
    fi
    info "vmlinux.h generated ✓"

    # Build everything
    local nproc_count
    nproc_count=$(nproc)
    info "Building rSwitch (${nproc_count} parallel jobs)..."
    if ! make -C "$src_dir" -j"$nproc_count" >> "$LOG_FILE" 2>&1; then
        error "Build failed. Last 20 lines of log:"
        tail -20 "$LOG_FILE" >&2
        exit 3
    fi
    info "Build complete ✓"

    # Install to INSTALL_PREFIX
    info "Installing to ${INSTALL_PREFIX}..."
    if ! make -C "$src_dir" install INSTALL_PREFIX="$INSTALL_PREFIX" >> "$LOG_FILE" 2>&1; then
        fatal "make install failed"
    fi
    info "Files installed to ${INSTALL_PREFIX} ✓"

    # Copy installer scripts to INSTALL_PREFIX
    cp -f "${src_dir}/scripts/rswitch-detect-ports.sh" "${INSTALL_PREFIX}/scripts/" 2>/dev/null || true
    cp -f "${src_dir}/scripts/rswitch-gen-profile.sh"  "${INSTALL_PREFIX}/scripts/" 2>/dev/null || true
    chmod +x "${INSTALL_PREFIX}/scripts/"*.sh 2>/dev/null || true

    # Clean up temp build dir
    if [ -z "${RSWITCH_SRC:-}" ] && [ -d "$src_dir" ]; then
        rm -rf "$src_dir"
        info "Build directory cleaned up"
    fi
}

# ── Phase 4: Detect interfaces ──────────────────────────────────
detect_interfaces() {
    step 4 6 "Detecting network interfaces"

    # Source the detect script
    local detect_out
    detect_out=$("${INSTALL_PREFIX}/scripts/rswitch-detect-ports.sh" 2>/dev/null) || true

    # Parse output
    eval "$detect_out"

    local mgmt_nic="${RSWITCH_MGMT_NIC:-${MGMT_NIC:-}}"
    local switch_ports="${RSWITCH_INTERFACES:-${SWITCH_PORTS:-}}"
    local port_count="${PORT_COUNT:-0}"

    if [ -z "$mgmt_nic" ]; then
        fatal "Cannot detect management NIC. Set RSWITCH_MGMT_NIC=<iface>"
    fi

    info "Management NIC: ${mgmt_nic} (will NOT be used as switch port)"

    if [ -z "$switch_ports" ] || [ "$port_count" = "0" ]; then
        error "No physical switch ports detected."
        error "Available interfaces:"
        for iface in /sys/class/net/*/; do
            local name
            name=$(basename "$iface")
            [ "$name" = "lo" ] && continue
            local has_pci="no"
            [ -e "${iface}device" ] && has_pci="yes"
            echo "  ${name}  (PCI: ${has_pci})"
        done
        echo ""
        error "Set RSWITCH_INTERFACES=eth1,eth2,... to specify switch ports manually."
        exit 4
    fi

    info "Switch ports (${port_count}): ${switch_ports}"

    # Confirm with user
    echo ""
    echo -e "  ${BOLD}Management NIC${NC}: ${mgmt_nic} (SSH — protected)"
    echo -e "  ${BOLD}Switch ports${NC}:   ${switch_ports}"
    echo ""
    if ! confirm "Proceed with this configuration?"; then
        echo "Set RSWITCH_MGMT_NIC and RSWITCH_INTERFACES to override."
        exit 0
    fi

    # Export for later phases
    export DETECTED_MGMT_NIC="$mgmt_nic"
    export DETECTED_SWITCH_PORTS="$switch_ports"
    export DETECTED_PORT_COUNT="$port_count"
}

# ── Phase 5: Configure systemd and profile ──────────────────────
configure() {
    step 5 6 "Configuring systemd services"

    local ifaces="$DETECTED_SWITCH_PORTS"
    local mgmt_nic="$DETECTED_MGMT_NIC"

    # Generate default profile
    info "Generating default profile..."
    "${INSTALL_PREFIX}/scripts/rswitch-gen-profile.sh" "$ifaces" "${INSTALL_PREFIX}/etc/profiles/default.yaml"
    info "Profile written: ${INSTALL_PREFIX}/etc/profiles/default.yaml ✓"

    # ── Install systemd units ────────────────────────────────────
    # We use the production templates from etc/systemd/ and substitute
    # paths and interface lists.

    info "Installing systemd service units..."

    # rswitch.service — main XDP switch
    cat > /etc/systemd/system/rswitch.service <<EOF
[Unit]
Description=rSwitch XDP-based Software Switch
After=network.target network-online.target
Wants=network-online.target
Documentation=https://github.com/kylecui/rswitch
OnFailure=rswitch-failsafe.service
StartLimitBurst=3
StartLimitIntervalSec=60

[Service]
Type=forking
ExecStartPre=-${INSTALL_PREFIX}/scripts/rswitch-failsafe.sh teardown
ExecStartPre=${INSTALL_PREFIX}/scripts/rswitch-init.sh prepare
ExecStart=${INSTALL_PREFIX}/scripts/rswitch-init.sh start
ExecStop=${INSTALL_PREFIX}/scripts/rswitch-init.sh stop
ExecReload=${INSTALL_PREFIX}/scripts/rswitch-init.sh reload
PIDFile=/run/rswitch/rswitch_loader.pid
Restart=on-failure
RestartSec=5
LimitMEMLOCK=infinity
LimitNOFILE=65535
Environment=RSWITCH_HOME=${INSTALL_PREFIX}
Environment=RSWITCH_PROFILE=default.yaml
Environment=RSWITCH_INTERFACES=${ifaces}

[Install]
WantedBy=multi-user.target
EOF

    # rswitch-mgmtd.service — management daemon
    cat > /etc/systemd/system/rswitch-mgmtd.service <<EOF
[Unit]
Description=rSwitch Management Daemon
Documentation=https://github.com/kylecui/rswitch
BindsTo=rswitch.service
After=rswitch.service

[Service]
Type=simple
Environment=RSWITCH_HOME=${INSTALL_PREFIX}
Environment=RSWITCH_PROFILE=default.yaml
Environment=MGMT_NAMESPACE=rswitch-mgmt
Environment=MGMT_NS_TIMEOUT=60
ExecStart=${INSTALL_PREFIX}/scripts/rswitch-mgmtd-start.sh
Restart=on-failure
RestartSec=5
StartLimitBurst=3
StartLimitIntervalSec=120

[Install]
WantedBy=multi-user.target
EOF

    # rswitch-failsafe.service — L2 bridge fallback
    cat > /etc/systemd/system/rswitch-failsafe.service <<EOF
[Unit]
Description=rSwitch Fail-safe L2 Bridge
Documentation=https://github.com/kylecui/rswitch
Conflicts=rswitch.service

[Service]
Type=oneshot
RemainAfterExit=yes
Environment=FAILSAFE_BRIDGE=rswitch-br
Environment=FAILSAFE_INTERFACES=${ifaces}
ExecStart=${INSTALL_PREFIX}/scripts/rswitch-failsafe.sh setup
ExecStop=${INSTALL_PREFIX}/scripts/rswitch-failsafe.sh teardown
EOF

    # rswitch-watchdog.service — optional watchdog
    cat > /etc/systemd/system/rswitch-watchdog.service <<EOF
[Unit]
Description=rSwitch Watchdog
Documentation=https://github.com/kylecui/rswitch
PartOf=rswitch.service
After=rswitch.service

[Service]
Type=notify
ExecStart=${INSTALL_PREFIX}/build/rswitch-watchdog -i 10 -r
WatchdogSec=30
Restart=on-failure
RestartSec=5
Environment=RSWITCH_WATCHDOG_IFACES=${ifaces}

[Install]
WantedBy=multi-user.target
EOF

    # Suppress DHCP / link-local IPs on switch ports
    # Switch ports must carry only bridged traffic — no IP stack
    info "Configuring IP suppression on switch ports..."
    IFS=',' read -ra SW_PORTS <<< "$ifaces"

    # dhcpcd: add denyinterfaces so it ignores switch ports
    if [ -f /etc/dhcpcd.conf ] || command -v dhcpcd >/dev/null 2>&1; then
        local dhcpcd_changed=0
        for sp in "${SW_PORTS[@]}" veth_voq_in veth_voq_out mgmt-br mgmt-ext; do
            if ! grep -qF "denyinterfaces ${sp}" /etc/dhcpcd.conf 2>/dev/null; then
                echo "denyinterfaces ${sp}" >> /etc/dhcpcd.conf
                dhcpcd_changed=1
            fi
        done
        if [ "$dhcpcd_changed" = "1" ]; then
            systemctl restart dhcpcd 2>/dev/null || true
            info "dhcpcd denyinterfaces configured ✓"
        fi
    fi

    # systemd-networkd: create .network files that disable DHCP/autoconf
    if systemctl is-active systemd-networkd >/dev/null 2>&1; then
        for sp in "${SW_PORTS[@]}"; do
            cat > "/etc/systemd/network/10-rswitch-${sp}.network" <<NETEOF
[Match]
Name=${sp}

[Link]
Unmanaged=yes

[Network]
DHCP=no
LinkLocalAddressing=no
IPv6AcceptRA=no
NETEOF
        done
        systemctl restart systemd-networkd 2>/dev/null || true
        info "systemd-networkd IP suppression configured ✓"
    fi

    # Flush any existing IPs on switch ports right now
    for sp in "${SW_PORTS[@]}"; do
        ip addr flush dev "$sp" 2>/dev/null || true
    done
    info "Switch port IPs flushed ✓"

    # Reload systemd
    systemctl daemon-reload
    info "Systemd units installed ✓"

    # Enable services (but don't start yet)
    systemctl enable rswitch.service >> "$LOG_FILE" 2>&1 || true
    systemctl enable rswitch-mgmtd.service >> "$LOG_FILE" 2>&1 || true
    info "Services enabled for boot ✓"

    # Add CLI tools to PATH via symlinks
    mkdir -p /usr/local/bin
    for tool in rswitchctl rsportctl rsvlanctl rsaclctl rsroutectl rsqosctl \
                rsflowctl rsnatctl rsvoqctl rstunnelctl rswitch-events \
                rs_packet_trace rswitch-telemetry rswitch-sflow; do
        if [ -f "${INSTALL_PREFIX}/build/${tool}" ]; then
            ln -sf "${INSTALL_PREFIX}/build/${tool}" "/usr/local/bin/${tool}"
        fi
    done
    info "CLI tools linked to /usr/local/bin ✓"

    # Generate uninstall script
    generate_uninstall_script
}

# ── Generate uninstall script ────────────────────────────────────
generate_uninstall_script() {
    cat > "${INSTALL_PREFIX}/uninstall.sh" <<'UNINSTALL_EOF'
#!/bin/bash
# rSwitch Uninstall Script — auto-generated by installer
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[rSwitch]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARNING]${NC} $*"; }

INSTALL_PREFIX="__INSTALL_PREFIX__"

echo ""
echo -e "${RED}This will completely remove rSwitch from this system.${NC}"
echo ""
read -rp "Are you sure? [y/N] " ans
case "$ans" in
    [Yy]*) ;;
    *) echo "Aborted."; exit 0 ;;
esac

info "Stopping services..."
systemctl stop rswitch-mgmtd 2>/dev/null || true
systemctl stop rswitch 2>/dev/null || true
systemctl stop rswitch-failsafe 2>/dev/null || true
systemctl stop rswitch-watchdog 2>/dev/null || true

info "Disabling services..."
systemctl disable rswitch-mgmtd rswitch rswitch-failsafe rswitch-watchdog 2>/dev/null || true

info "Removing XDP programs from interfaces..."
for iface in /sys/class/net/*/; do
    name=$(basename "$iface")
    if ip link show "$name" 2>/dev/null | grep -q 'xdp'; then
        ip link set dev "$name" xdp off 2>/dev/null || true
        info "  Removed XDP from $name"
    fi
done

info "Cleaning up management namespace..."
if ip netns list 2>/dev/null | grep -qw rswitch-mgmt; then
    ip netns del rswitch-mgmt 2>/dev/null || true
    info "  Deleted namespace rswitch-mgmt"
fi

info "Removing veth pairs..."
ip link del veth_voq_in 2>/dev/null || true
ip link del mgmt-br 2>/dev/null || true

info "Removing BPF pinned maps..."
rm -rf /sys/fs/bpf/rs_* 2>/dev/null || true
rm -rf /sys/fs/bpf/rswitch_* 2>/dev/null || true

info "Removing systemd units..."
rm -f /etc/systemd/system/rswitch.service
rm -f /etc/systemd/system/rswitch-mgmtd.service
rm -f /etc/systemd/system/rswitch-failsafe.service
rm -f /etc/systemd/system/rswitch-watchdog.service
systemctl daemon-reload 2>/dev/null || true

info "Removing CLI symlinks..."
for tool in rswitchctl rsportctl rsvlanctl rsaclctl rsroutectl rsqosctl \
            rsflowctl rsnatctl rsvoqctl rstunnelctl rswitch-events \
            rs_packet_trace rswitch-telemetry rswitch-sflow; do
    rm -f "/usr/local/bin/${tool}"
done

info "Removing installation directory..."
rm -rf "$INSTALL_PREFIX"

info "Removing IP suppression configs..."
rm -f /etc/systemd/network/10-rswitch-*.network 2>/dev/null || true
if [ -f /etc/dhcpcd.conf ]; then
    sed -i '/^denyinterfaces .*/d' /etc/dhcpcd.conf 2>/dev/null || true
fi
systemctl restart dhcpcd 2>/dev/null || true
systemctl restart systemd-networkd 2>/dev/null || true

info "Removing runtime files..."
rm -rf /run/rswitch 2>/dev/null || true

echo ""
info "rSwitch has been completely removed."
info "Log files remain at /var/log/rswitch/ (remove manually if desired)."
UNINSTALL_EOF

    # Replace placeholder with actual prefix
    sed -i "s|__INSTALL_PREFIX__|${INSTALL_PREFIX}|g" "${INSTALL_PREFIX}/uninstall.sh"
    chmod +x "${INSTALL_PREFIX}/uninstall.sh"
    info "Uninstall script: ${INSTALL_PREFIX}/uninstall.sh ✓"
}

# ── Phase 6: Start services ─────────────────────────────────────
start_services() {
    step 6 6 "Starting rSwitch"

    if [ "${RSWITCH_NO_START:-0}" = "1" ]; then
        info "RSWITCH_NO_START=1 — skipping service start"
        print_summary
        return
    fi

    # Mount bpffs if not already
    mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true

    info "Starting rswitch.service..."
    if ! systemctl start rswitch.service; then
        error "rswitch.service failed to start. Check: journalctl -u rswitch -n 30"
        warn "Fail-safe bridge may activate automatically"
        print_summary
        exit 5
    fi

    info "rSwitch XDP pipeline is running ✓"

    # Wait a moment for namespace to be created, then start mgmtd
    info "Starting rswitch-mgmtd.service..."
    systemctl start rswitch-mgmtd.service &
    local mgmtd_pid=$!

    # Wait for mgmtd (it waits up to 60s for the namespace)
    info "Waiting for management daemon (namespace creation)..."
    local waited=0
    while [ $waited -lt 30 ]; do
        if systemctl is-active rswitch-mgmtd.service >/dev/null 2>&1; then
            break
        fi
        sleep 2
        waited=$((waited + 2))
    done

    if systemctl is-active rswitch-mgmtd.service >/dev/null 2>&1; then
        info "Management daemon running ✓"
    else
        warn "Management daemon may still be starting (namespace wait). Check: journalctl -u rswitch-mgmtd"
    fi

    # Wait for DHCP on management interface
    info "Waiting for management IP via DHCP..."
    local mgmt_ip=""
    for i in $(seq 1 15); do
        mgmt_ip=$(ip netns exec rswitch-mgmt ip -4 addr show mgmt0 2>/dev/null \
                  | grep -oP 'inet \K[0-9.]+' | head -1) || true
        if [ -n "$mgmt_ip" ]; then
            break
        fi
        sleep 2
    done

    if [ -n "$mgmt_ip" ]; then
        info "Management IP: ${mgmt_ip} ✓"
        export MGMT_IP="$mgmt_ip"
    else
        warn "No DHCP lease yet. Portal will be available once DHCP completes."
        warn "Check: sudo ip netns exec rswitch-mgmt ip addr show mgmt0"
    fi

    print_summary
}

# ── Summary ──────────────────────────────────────────────────────
print_summary() {
    echo ""
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}  rSwitch installed successfully!${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "  ${BOLD}Install path${NC}:    ${INSTALL_PREFIX}"
    echo -e "  ${BOLD}Switch ports${NC}:    ${DETECTED_SWITCH_PORTS}"
    echo -e "  ${BOLD}Management NIC${NC}:  ${DETECTED_MGMT_NIC}"
    echo -e "  ${BOLD}Profile${NC}:         ${INSTALL_PREFIX}/etc/profiles/default.yaml"
    if [ -n "${MGMT_IP:-}" ]; then
        echo -e "  ${BOLD}Portal${NC}:          http://${MGMT_IP}:8080"
        echo -e "  ${BOLD}Credentials${NC}:     admin / rswitch"
    fi
    echo ""
    echo -e "  ${BOLD}Services${NC}:"
    echo "    systemctl status rswitch          # XDP pipeline"
    echo "    systemctl status rswitch-mgmtd    # Management portal"
    echo "    journalctl -u rswitch -f          # Live logs"
    echo ""
    echo -e "  ${BOLD}CLI tools${NC}:"
    echo "    rswitchctl show-pipeline           # View loaded modules"
    echo "    rswitchctl show-stats              # Port statistics"
    echo "    rsvlanctl show                     # VLAN table"
    echo ""
    echo -e "  ${BOLD}Uninstall${NC}:"
    echo "    sudo ${INSTALL_PREFIX}/uninstall.sh"
    echo ""
}

# ── Main ─────────────────────────────────────────────────────────
usage() {
    cat <<EOF
Usage: sudo bash install.sh [OPTIONS]

Options:
  -i, --interfaces IFACES   Comma-separated list of switch port NICs
                             (default: auto-detect all physical NICs)
  -m, --mgmt-nic NIC        Management NIC (default: auto-detect)
  -p, --prefix PATH         Installation prefix (default: /opt/rswitch)
  -y, --yes                 Skip confirmation prompts
  -h, --help                Show this help

Examples:
  sudo bash install.sh                         # auto-detect everything
  sudo bash install.sh -i ens34,ens35          # use only ens34 and ens35
  sudo bash install.sh -i ens34,ens35 -m eth0  # specify mgmt NIC
  curl -sfL https://get.rswitch.dev | sudo bash -s -- -i ens34,ens35
EOF
    exit 0
}

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            -i|--interfaces)
                shift
                [ $# -eq 0 ] && fatal "--interfaces requires a value"
                RSWITCH_INTERFACES="$1"
                export RSWITCH_INTERFACES
                ;;
            -m|--mgmt-nic)
                shift
                [ $# -eq 0 ] && fatal "--mgmt-nic requires a value"
                RSWITCH_MGMT_NIC="$1"
                export RSWITCH_MGMT_NIC
                ;;
            -p|--prefix)
                shift
                [ $# -eq 0 ] && fatal "--prefix requires a value"
                INSTALL_PREFIX="$1"
                ;;
            -y|--yes)
                RSWITCH_FORCE=1
                export RSWITCH_FORCE
                ;;
            -h|--help)
                usage
                ;;
            *)
                fatal "Unknown option: $1 (see --help)"
                ;;
        esac
        shift
    done
}

main() {
    parse_args "$@"
    banner
    preflight
    install_deps
    build_rswitch
    detect_interfaces
    configure
    start_services
}

main "$@"
