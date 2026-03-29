# Contributing to rSwitch

Thank you for your interest in contributing to rSwitch! This document covers
the workflow for building, testing, and submitting changes.

## Prerequisites

- **Clang 16+** (17 or 18 recommended)
- **libbpf** (built from `external/libbpf/src`)
- **libelf**, **zlib** development headers
- **Linux kernel 5.15+** (for BPF_PROG_TEST_RUN and XDP features)
- **bpftool** (for vmlinux.h generation)

## Getting Started

```bash
git clone --recursive <repo-url>
cd rswitch

# Build libbpf
cd external/libbpf/src
make -j$(nproc)
sudo make install PREFIX=/usr/local/bpf
cd ../../../rswitch

# Build everything
make all
```

## Building

```bash
make all           # Build all BPF objects + user-space programs
make test          # Build unit test binaries
make test-ci       # Build CI BPF test binaries
make test-bpf      # Build + run BPF_PROG_TEST_RUN tests (requires root)
make fuzz          # Run fuzz harness (requires root)
make clean         # Remove build artifacts
```

## Testing

### Unit Tests (user-space)

```bash
make test
sudo ./test/unit/run_tests.sh
```

### BPF Tests (requires root)

BPF tests use `BPF_PROG_TEST_RUN` to exercise BPF programs in-kernel
without attaching to a real interface.

```bash
make test-bpf   # Builds AND runs all BPF tests
```

Individual test binaries:
```bash
sudo ./build/test_acl_bpf ./build/bpf/acl.bpf.o output.junit.xml
sudo ./build/test_dispatcher_bpf ./build/bpf/dispatcher.bpf.o output.junit.xml
```

### Integration Tests

```bash
sudo bash ./test/integration/run_all.sh
```

## Code Style

The project uses `clang-format` with the configuration in `.clang-format`.
Key conventions:

- **4-space indentation** (no tabs)
- **K&R brace style** (Linux kernel style)
- **100-column limit**
- **`//` comments** preferred in BPF code
- **Pointer alignment**: `int *ptr` (not `int* ptr`)

Format your changes before committing:
```bash
clang-format -i path/to/file.c
```

## Commit Messages

We use semantic commit messages:

```
<type>(<scope>): <description>

[optional body]
```

Types: `feat`, `fix`, `docs`, `chore`, `refactor`, `test`, `perf`

Examples:
```
feat(acl): add IPv6 source matching
fix(afxdp): correct map pin path for multi-queue
docs: update module development spec for egress stages
test(ci): add BPF_PROG_TEST_RUN tests for VLAN module
```

## Pull Request Workflow

1. Fork the repository and create a feature branch from `dev`
2. Make your changes, following the code style above
3. Add or update tests for your changes
4. Run the full test suite (`make test && make test-bpf`)
5. Commit with semantic messages
6. Open a PR against `dev`

### PR Checklist

- [ ] `make all` compiles without warnings
- [ ] `make test` builds all unit tests
- [ ] New BPF modules include `RS_DECLARE_MODULE()` with correct stage/flags
- [ ] ABI changes bump version in `module_abi.h` per [ABI Policy](docs/development/ABI_POLICY.md)
- [ ] Documentation updated if behavior changed

## CI Multi-Kernel Matrix

The CI pipeline includes a `kernel-compat` job that compiles BPF objects against
multiple kernel header versions to validate CO-RE BTF compatibility:

| Matrix Entry | Source |
|---|---|
| `6.8.0-*` | Ubuntu 24.04 default (runner kernel) |
| `6.5.0-*` | Ubuntu 23.10 |
| `6.2.0-*` | Ubuntu 23.04 |

Runtime tests (`BPF_PROG_TEST_RUN`) execute only on the host kernel.
Multi-kernel runtime testing requires virtme-ng or self-hosted runners.

A `perf-baseline` job measures per-packet latency using `BPF_PROG_TEST_RUN`
with repeat counts. Results are stored as CI artifacts. Absolute numbers are
runner-specific — only relative regression between runs is meaningful.

## Module Development

See the [SDK Quick Start](sdk/docs/SDK_Quick_Start.md) for a tutorial on
writing your first module, and the [Module Development Spec](sdk/docs/Module_Development_Spec.md)
for the full API reference.

### Key Files

| File | Purpose |
|------|---------|
| `sdk/include/rswitch_module.h` | Top-level include for modules |
| `sdk/include/rswitch_abi.h` | ABI structs and version constants |
| `sdk/include/rswitch_helpers.h` | BPF helper macros and packet parsers |
| `sdk/include/rswitch_maps.h` | Core BPF map definitions |
| `sdk/templates/simple_module.bpf.c` | Starter template |
| `sdk/Makefile.module` | Standalone module build system |

## Reporting Issues

Use the [issue templates](.github/ISSUE_TEMPLATE/) for bug reports and
feature requests.

## License

rSwitch is licensed under LGPL-2.1-or-later. BPF kernel programs use
GPL-2.0 SPDX headers (required for BPF helper access). By contributing,
you agree that your contributions will be licensed under the same terms.
