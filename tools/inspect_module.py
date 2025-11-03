#!/usr/bin/env python3
"""
rSwitch Module Inspector - 验证 BPF 模块的 CO-RE 兼容性和可移植性

用法:
    python3 tools/inspect_module.py <module.bpf.o>
    python3 tools/inspect_module.py --all build/bpf/
"""

import sys
import struct
import subprocess
import os
from pathlib import Path

class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'

def run_cmd(cmd):
    """运行命令并返回输出"""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout, result.returncode

def parse_module_metadata(bpf_obj):
    """解析模块的 .rodata.mod 段"""
    stdout, rc = run_cmd(f"readelf -x .rodata.mod {bpf_obj} 2>/dev/null")
    
    if rc != 0 or "Hex dump" not in stdout:
        return None
    
    # 提取 hex 数据
    lines = [l for l in stdout.split('\n') if l.strip().startswith('0x')]
    raw = ''.join(''.join(l.split()[1:5]) for l in lines)
    
    try:
        # 解析字段 (little-endian)
        raw_bytes = bytes.fromhex(raw)
        
        abi_ver = struct.unpack('<I', raw_bytes[0:4])[0]
        hook = struct.unpack('<I', raw_bytes[8:12])[0]
        stage = struct.unpack('<I', raw_bytes[12:16])[0]
        flags = struct.unpack('<I', raw_bytes[16:20])[0]
        
        # 提取字符串
        name = raw_bytes[32:64].split(b'\x00')[0].decode('utf-8', errors='ignore')
        description = raw_bytes[64:128].split(b'\x00')[0].decode('utf-8', errors='ignore')
        
        return {
            'abi_version': abi_ver,
            'hook': hook,
            'stage': stage,
            'flags': flags,
            'name': name,
            'description': description
        }
    except Exception as e:
        print(f"Warning: Failed to parse metadata: {e}", file=sys.stderr)
        return None

def get_btf_info(bpf_obj):
    """获取 BTF 段信息"""
    stdout, _ = run_cmd(f"llvm-objdump -h {bpf_obj} 2>/dev/null")
    
    btf_size = 0
    btfext_size = 0
    
    for line in stdout.split('\n'):
        if '.BTF ' in line and 'ext' not in line:
            parts = line.split()
            if len(parts) >= 3:
                btf_size = int(parts[2], 16)
        elif '.BTF.ext' in line:
            parts = line.split()
            if len(parts) >= 3:
                btfext_size = int(parts[2], 16)
    
    return btf_size, btfext_size

def check_core_usage(bpf_obj):
    """检查是否使用 bpf_core_* 辅助函数"""
    stdout, _ = run_cmd(f"llvm-objdump -d {bpf_obj} 2>/dev/null")
    return 'bpf_core' in stdout

def format_size(size):
    """格式化大小"""
    if size >= 1024:
        return f"{size/1024:.1f}KB"
    else:
        return f"{size}B"

def format_hook(hook):
    """格式化 hook 类型"""
    hooks = {
        0: "XDP_INGRESS",
        1: "DEVMAP_EGRESS",
        2: "CPUMAP"
    }
    return hooks.get(hook, f"UNKNOWN({hook})")

def format_flags(flags):
    """格式化 flags"""
    flag_names = []
    if flags & (1 << 0): flag_names.append("L2_PARSE")
    if flags & (1 << 1): flag_names.append("L3_PARSE")
    if flags & (1 << 2): flag_names.append("L4_PARSE")
    if flags & (1 << 3): flag_names.append("MODIFY_PKT")
    if flags & (1 << 4): flag_names.append("DROP")
    if flags & (1 << 5): flag_names.append("REDIRECT")
    
    if flag_names:
        return f"0x{flags:x} ({', '.join(flag_names)})"
    else:
        return f"0x{flags:x}"

def inspect_module(bpf_obj, verbose=False):
    """检查单个模块"""
    if not os.path.exists(bpf_obj):
        print(f"{Colors.RED}✗ File not found: {bpf_obj}{Colors.END}")
        return False
    
    print(f"\n{Colors.BOLD}{'='*80}{Colors.END}")
    print(f"{Colors.BOLD}📦 {os.path.basename(bpf_obj)}{Colors.END}")
    print(f"{Colors.BOLD}{'='*80}{Colors.END}")
    
    # 文件大小
    size = os.path.getsize(bpf_obj)
    print(f"File size: {format_size(size)}")
    
    # 模块元数据
    metadata = parse_module_metadata(bpf_obj)
    if metadata:
        print(f"\n{Colors.GREEN}✅ Pluggable Module (has .rodata.mod){Colors.END}")
        print(f"   Module name: {Colors.BOLD}{metadata['name']}{Colors.END}")
        print(f"   Description: {metadata['description']}")
        print(f"   ABI version: v{metadata['abi_version']}")
        print(f"   Hook point:  {format_hook(metadata['hook'])}")
        print(f"   Stage:       {metadata['stage']}")
        print(f"   Flags:       {format_flags(metadata['flags'])}")
    else:
        print(f"\n{Colors.YELLOW}⚙️  Core Component (no .rodata.mod){Colors.END}")
        print(f"   This is a framework built-in component")
    
    # BTF 信息
    btf_size, btfext_size = get_btf_info(bpf_obj)
    
    print(f"\n{Colors.BLUE}CO-RE Compatibility:{Colors.END}")
    
    if btf_size > 0:
        print(f"   {Colors.GREEN}✅ BTF debug info:{Colors.END} {format_size(btf_size)}")
    else:
        print(f"   {Colors.RED}✗ BTF debug info: Missing{Colors.END}")
        return False
    
    if btfext_size > 0:
        print(f"   {Colors.GREEN}✅ CO-RE relocations:{Colors.END} {format_size(btfext_size)}")
    else:
        print(f"   {Colors.YELLOW}⚠️  CO-RE relocations: Missing{Colors.END}")
    
    # bpf_core 使用
    if check_core_usage(bpf_obj):
        print(f"   {Colors.GREEN}✅ Uses bpf_core_* helpers{Colors.END}")
    
    # 可移植性评估
    print(f"\n{Colors.BLUE}Portability Assessment:{Colors.END}")
    
    if btf_size > 0 and btfext_size > 0:
        print(f"   {Colors.GREEN}✅ Portable across kernel versions (5.8+){Colors.END}")
        print(f"   {Colors.GREEN}✅ Can be distributed as binary (.bpf.o){Colors.END}")
        print(f"   {Colors.GREEN}✅ No recompilation needed for kernel upgrades{Colors.END}")
    else:
        print(f"   {Colors.RED}✗ NOT portable - missing CO-RE support{Colors.END}")
        return False
    
    if metadata:
        print(f"\n{Colors.BLUE}Distribution Info:{Colors.END}")
        print(f"   Module can be: {Colors.GREEN}Shared with customers{Colors.END}")
        print(f"   Usage: Add '{metadata['name']}' to YAML profile")
        print(f"   Load: rswitch_loader --module {bpf_obj}")
    
    return True

def inspect_all(directory):
    """检查目录下所有模块"""
    bpf_files = list(Path(directory).glob("*.bpf.o"))
    
    if not bpf_files:
        print(f"{Colors.RED}No .bpf.o files found in {directory}{Colors.END}")
        return
    
    print(f"{Colors.BOLD}Found {len(bpf_files)} BPF modules{Colors.END}\n")
    
    pluggable = 0
    core = 0
    portable = 0
    
    for bpf_obj in sorted(bpf_files):
        success = inspect_module(str(bpf_obj))
        
        metadata = parse_module_metadata(str(bpf_obj))
        if metadata:
            pluggable += 1
        else:
            core += 1
        
        if success:
            portable += 1
    
    # 汇总
    print(f"\n{Colors.BOLD}{'='*80}{Colors.END}")
    print(f"{Colors.BOLD}Summary{Colors.END}")
    print(f"{Colors.BOLD}{'='*80}{Colors.END}")
    print(f"Total modules:           {len(bpf_files)}")
    print(f"Pluggable modules:       {Colors.GREEN}{pluggable}{Colors.END} (can be distributed)")
    print(f"Core components:         {Colors.YELLOW}{core}{Colors.END} (framework built-in)")
    print(f"CO-RE portable:          {Colors.GREEN}{portable}{Colors.END}/{len(bpf_files)}")
    
    if portable == len(bpf_files):
        print(f"\n{Colors.GREEN}{Colors.BOLD}✅ All modules are CO-RE compatible and portable!{Colors.END}")
    else:
        print(f"\n{Colors.YELLOW}⚠️  Some modules need CO-RE support{Colors.END}")

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <module.bpf.o>")
        print(f"       {sys.argv[0]} --all <directory>")
        sys.exit(1)
    
    if sys.argv[1] == '--all':
        directory = sys.argv[2] if len(sys.argv) > 2 else "build/bpf"
        inspect_all(directory)
    else:
        inspect_module(sys.argv[1])

if __name__ == "__main__":
    main()
