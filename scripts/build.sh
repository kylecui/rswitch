#!/bin/bash
# Build script for rSwitch

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${SCRIPT_DIR}/.."

cd "${PROJECT_ROOT}"

echo "=== rSwitch Build Script ==="
echo ""

# Check if vmlinux.h exists
if [ ! -f bpf/include/vmlinux.h ]; then
    echo "vmlinux.h not found. Generating..."
    ./scripts/gen_vmlinux.sh
    echo ""
fi

# Check libbpf installation
if [ ! -d /usr/local/bpf/include ] || [ ! -d /usr/local/bpf/lib64 ]; then
    echo "Warning: libbpf not found in /usr/local/bpf/"
    echo "Please install libbpf first:"
    echo "  cd ../external/libbpf/src"
    echo "  make install BUILD_STATIC_ONLY=1 PREFIX=/usr/local/bpf"
    echo ""
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

echo "Building rSwitch..."
make clean
make -j$(nproc)

echo ""
echo "✓ Build complete!"
echo ""
echo "Next steps:"
echo "  1. Configure interfaces in etc/profiles/your-profile.yaml"
echo "  2. Run: sudo ./build/rswitch_loader --profile etc/profiles/l2.yaml"
echo ""
