# 快速开始

> ⚠️ **翻译状态**: 本文件为翻译框架，完整内容请参阅 [英文原文](../usage/Quick_Start.md)。
>
> 欢迎贡献中文翻译！请参阅 [翻译贡献指南](README.md#如何贡献翻译)。

---

## 概述

rSwitch 是一个基于 XDP/eBPF 的高性能可重构网络交换平台。本文档帮助您在 5 分钟内完成构建和运行。

## 前置条件

```bash
# Debian/Ubuntu
sudo apt update
sudo apt install -y build-essential cmake clang llvm pkg-config \
                     libxdp-dev libbpf-dev linux-headers-$(uname -r)
```

## 构建与运行

```bash
# 初始化子模块
git submodule update --init --recursive

# 构建
make vmlinux && make

# 运行 L2 交换示例
sudo ./build/rswitch_loader \
     --profile etc/profiles/l2.yaml \
     --ifaces ens34,ens35,ens36
```

## 验证

```bash
# 检查加载的 BPF 程序
sudo bpftool prog list | grep rswitch

# 查看 BPF maps
sudo bpftool map show | grep rswitch
```

---

> 📖 完整内容请参阅 [Quick Start (English)](../usage/Quick_Start.md)

*最后更新: 2026-03-10*
