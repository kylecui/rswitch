---
name: Bug Report
about: Report a bug or unexpected behavior in rSwitch
title: "[BUG] "
labels: bug
assignees: ''
---

## Description

A clear, concise description of the bug.

## Environment

- **OS / Kernel**: (e.g., Ubuntu 24.04 / 6.8.0-generic)
- **Clang version**: (output of `clang --version`)
- **libbpf version**: (output of `pkg-config --modversion libbpf` or check Makefile)
- **rSwitch version / commit**: (output of `git rev-parse --short HEAD`)
- **NIC driver**: (output of `ethtool -i <interface>`)

## Steps to Reproduce

1. Step one
2. Step two
3. ...

## Expected Behavior

What you expected to happen.

## Actual Behavior

What actually happened. Include error messages, logs, or kernel traces if available.

## Relevant Logs

<details>
<summary>Logs / dmesg output</summary>

```
Paste logs here
```

</details>

## Additional Context

- Module name (if module-specific):
- Profile in use:
- Are you using AF_XDP? (yes/no):
- Attach any relevant `.bpf.o` or config files.
