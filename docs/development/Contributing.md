# Contributing to rSwitch

Thank you for your interest in contributing to rSwitch! This guide covers everything you need to get started — from setting up your development environment to submitting your first contribution.

---

## Ways to Contribute

- **BPF Modules**: Write new packet processing modules for the pipeline
- **Core Infrastructure**: Improve the loader, profile parser, or map management
- **CLI Tools**: Enhance `rswitchctl`, `rsvlanctl`, `rsaclctl`, `rsqosctl`
- **VOQd Scheduler**: Improve QoS scheduling, AF_XDP integration
- **Documentation**: Fix errors, add examples, translate to Chinese (zh-CN)
- **Testing**: Add test cases, improve test coverage
- **Bug Reports**: Report issues with clear reproduction steps

---

## Development Environment Setup

### Prerequisites

| Requirement | Minimum Version |
|-------------|-----------------|
| Linux kernel | 5.8+ with `CONFIG_DEBUG_INFO_BTF=y` |
| clang/LLVM | 10+ |
| libbpf | 0.6+ |
| bpftool | 5.8+ |
| cmake | 3.10+ |
| pkg-config | — |

### Install Dependencies (Ubuntu/Debian)

```bash
sudo apt update
sudo apt install -y \
    build-essential cmake clang llvm pkg-config \
    libxdp-dev libbpf-dev linux-headers-$(uname -r) \
    linux-tools-$(uname -r)
```

### Clone and Build

```bash
git clone --recurse-submodules <repository-url>
cd rswitch/

# Generate vmlinux.h (required on first build)
make vmlinux

# Build everything
make
```

### Verify the Build

```bash
# Check that BPF objects were compiled
ls build/bpf/*.bpf.o

# Check that user-space binaries were built
ls build/rswitch_loader build/rswitchctl
```

---

## Project Structure

```
rswitch/
├── bpf/
│   ├── include/          # BPF headers (rswitch_bpf.h, vmlinux.h)
│   ├── core/             # Core BPF (dispatcher, egress, module_abi.h)
│   └── modules/          # BPF modules (vlan, acl, route, etc.)
├── user/
│   ├── loader/           # rswitch_loader (profile parser, module discovery)
│   ├── voqd/             # VOQd QoS scheduler (AF_XDP)
│   └── tools/            # CLI tools
├── etc/profiles/         # YAML profile files
├── scripts/              # Helper scripts
├── test/                 # Tests
├── docs/                 # Documentation (you are here)
├── examples/             # Example configurations and demos
├── external/libbpf/      # libbpf submodule
└── build/                # Build outputs
```

---

## Contribution Workflow

### 1. Pick a Task

- Check the [backlog](../backlog/) for planned work items
- Look for issues labeled `good-first-issue` or `help-wanted`
- For new ideas, open an issue to discuss before implementing

### 2. Create a Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/your-bug-fix
```

### 3. Make Changes

Follow the coding guidelines below. Keep commits focused and atomic.

### 4. Test Your Changes

```bash
# Build
make clean && make

# Load and test (requires root)
sudo ./build/rswitch_loader --profile etc/profiles/l2-simple-managed.yaml --ifaces eth0 --verbose

# Verify pipeline
sudo ./build/rswitchctl show-pipeline

# Run tests (if applicable)
make test
```

### 5. Submit a Pull Request

- Write a clear PR title and description
- Reference any related issues
- Ensure the build passes
- Request review from maintainers

---

## Coding Guidelines

### BPF Module Code

1. **CO-RE compliance**: Use `rswitch_bpf.h` — never include individual `<linux/*.h>` headers
2. **Module registration**: Every module MUST have `RS_DECLARE_MODULE()`
3. **Context check**: Always check `RS_GET_CTX()` return for NULL
4. **Pipeline continuation**: Always call `RS_TAIL_CALL_NEXT()` or `RS_TAIL_CALL_EGRESS()` at the end
5. **Offset masks**: Use `RS_L3_OFFSET_MASK`, `RS_L4_OFFSET_MASK` for packet access
6. **Map lookups**: Always check return values — never dereference without NULL check
7. **Error reporting**: Set `ctx->error` and `ctx->drop_reason` before dropping
8. **License**: BPF programs use `GPL-2.0` (`char _license[] SEC("license") = "GPL";`)

### User-Space Code (C)

1. **Error handling**: Check all system call and library return values
2. **Memory management**: Free all allocated resources; use `profile_free()` for profiles
3. **Logging**: Use the project's logging macros, not raw `printf`
4. **Map access**: Always use the pinned path constants defined in headers

### General

- Use 4-space indentation for C code (matching existing codebase)
- Keep functions focused — one function, one responsibility
- Add comments for non-obvious logic, especially BPF verifier workarounds
- No `// TODO` without an associated issue or backlog item

---

## Adding a New BPF Module

This is the most common contribution type. Follow these steps:

1. **Create** `bpf/modules/your_module.bpf.c` — see [Module Developer Guide](./Module_Developer_Guide.md)
2. **Choose** an appropriate stage number — see [Architecture](./Architecture.md#stage-numbering-convention)
3. **Build** with `make` — new `.bpf.c` files are auto-discovered
4. **Create** a test profile in `etc/profiles/` that includes your module
5. **Test** loading, pipeline order, and packet processing
6. **Document** your module in the PR description (purpose, stage choice, flags used)

### Module Checklist

- [ ] `RS_DECLARE_MODULE()` with correct hook, stage, and flags
- [ ] `RS_GET_CTX()` with NULL check
- [ ] `RS_TAIL_CALL_NEXT()` / `RS_TAIL_CALL_EGRESS()` at end of processing
- [ ] Offset masks for all packet data access
- [ ] NULL checks on all `bpf_map_lookup_elem()` calls
- [ ] Error codes set before dropping (`ctx->error`, `ctx->drop_reason`)
- [ ] Builds without warnings
- [ ] Loads successfully with `rswitch_loader --verbose`
- [ ] Does not break existing profiles

---

## Documentation Contributions

### Structure

Documentation is organized into four categories:

| Directory | Content |
|-----------|---------|
| `docs/usage/` | End-user guides (how to use, CLI reference, troubleshooting) |
| `docs/deployment/` | Installation, configuration, NIC setup, systemd |
| `docs/development/` | Architecture, module guide, API reference, CO-RE, contributing |
| `docs/backlog/` | Development roadmap and planned features |

### Language

- **Primary language**: English
- **Translations**: Chinese (zh-CN) in `docs/zh-CN/` — parallel structure
- Keep both versions in sync when updating documentation

### Style

- Use ATX-style headers (`# H1`, `## H2`)
- Include code examples with language tags (` ```c `, ` ```bash `, ` ```yaml `)
- Use tables for structured comparisons
- Link to related docs using relative paths
- Keep lines under 120 characters where practical

---

## Licensing

rSwitch uses a multi-license approach:

| Component | License |
|-----------|---------|
| BPF programs (`bpf/`) | GPL-2.0-only |
| User-space code (`user/`) | LGPL-2.1-or-later OR BSD-2-Clause |
| Documentation (`docs/`) | CC-BY-4.0 |

By contributing, you agree that your contributions will be licensed under the applicable license for the component you're modifying.

---

## Getting Help

- **Architecture questions**: Read [Architecture.md](./Architecture.md) first
- **Module development**: See [Module Developer Guide](./Module_Developer_Guide.md)
- **API details**: See [API Reference](./API_Reference.md)
- **CO-RE questions**: See [CO-RE Guide](./CO-RE_Guide.md)
- **Deep-dive papers**: Check `docs/paperwork/` for detailed architecture documents
- **Still stuck?**: Open an issue with the `question` label

---

## See Also

- [Architecture.md](./Architecture.md) — System architecture overview
- [Module_Developer_Guide.md](./Module_Developer_Guide.md) — Step-by-step module creation
- [API_Reference.md](./API_Reference.md) — Complete API reference
- [CO-RE_Guide.md](./CO-RE_Guide.md) — Cross-kernel portability
- [Installation](../deployment/Installation.md) — Build environment setup
