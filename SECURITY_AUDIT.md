# rSwitch Security & Quality Audit

**Date**: 2026-04-04
**Scope**: Full codebase — `user/`, `bpf/`, `sdk/`, `loader/`
**Findings**: 20 (3 Critical, 5 High, 8 Medium, 4 Low)
**Status**: All 20 fixed

---

## Critical

### C-1: Command Injection via system()/popen()

**File**: `user/mgmt/mgmtd.c`
**Risk**: Attacker-controlled interface names or IPs passed to `system()` and `popen()` enable arbitrary command execution with daemon privileges.

**Before**:
```c
snprintf(cmd, sizeof(cmd), "ip link set %s up", ifname);
system(cmd);
```

**Fix**: Replaced all `system()`/`popen()` calls with `fork()`+`execvp()` via a safe `run_cmd()` helper. Arguments are passed as discrete argv entries, never interpolated into a shell string. A `run_cmd_output()` variant captures stdout via pipe for cases that previously used `popen()`.

**Affected functions**: `mgmtd_link_set_up`, `mgmtd_link_set_down`, `mgmtd_set_ip_addr`, `mgmtd_create_veth`, `mgmtd_attach_xdp`, `mgmtd_detach_xdp`, `mgmtd_tc_redirect`, and all other callsites that constructed shell commands.

---

### C-2: Plaintext Credentials + Timing-Vulnerable strcmp

**File**: `user/mgmt/mgmtd.c`, `user/mgmt/mgmtd.h`
**Risk**: API credentials stored in plaintext in config; `strcmp()` for password comparison leaks password length via timing side-channel.

**Before**:
```c
if (strcmp(provided_pass, ctx->cfg.api_password) == 0)
```

**Fix**:
1. Passwords are now stored as SHA-256 hashes (hex-encoded). On startup, plaintext passwords in config are hashed and the original overwritten in memory with `explicit_bzero()`.
2. Password verification uses `constant_time_compare()` — a dedicated timing-safe comparison that always examines all bytes regardless of mismatch position.
3. Added `auth_salt[33]` field to `mgmtd_config` in `mgmtd.h` for future salted hashing support.

---

### C-3: CORS Wildcard on Auth Endpoints

**File**: `user/mgmt/mgmtd.c`, `user/mgmt/mgmtd.h`
**Risk**: `Access-Control-Allow-Origin: *` on authentication endpoints allows any website to make credentialed cross-origin requests.

**Fix**: Added `cors_origin[128]` to `mgmtd_config`. The HTTP response handler now emits the configured origin (or omits the header entirely if unconfigured) instead of `*`. Credentials flag is only set when a specific origin is configured.

---

## High

### H-4: Pool Destroy Leak in voq.c

**File**: `user/voqd/voq.c`, `user/voqd/voq.h`
**Risk**: `voq_pool_destroy()` only freed the metadata struct, leaking all `mmap()`'d chunk memory. Long-running daemon would leak megabytes per pool cycle.

**Fix**: Added `chunk_ptrs[]` array, `num_chunks`, and `max_chunks` fields to the pool struct. Each `mmap()` allocation is tracked. `voq_pool_destroy()` now iterates `chunk_ptrs[]` and `munmap()`s every chunk before freeing the pool struct itself.

---

### H-5: Pool Free-List Corruption in voqd_dataplane.c

**File**: `user/voqd/voqd_dataplane.c`, `user/voqd/voqd_dataplane.h`
**Risk**: Free-list implemented as a linked list embedded in freed buffers. Under memory pressure, a use-after-free could corrupt the list and cause silent data corruption.

**Fix**: Replaced embedded free-list with an explicit free-stack: a separate `uint32_t *free_stack` array with `free_top` index. Allocation pops from the stack; deallocation pushes. The free-stack is allocated alongside the data pool and sized to `max_entries`. This eliminates any pointer embedding in user data.

---

### H-6: Consolidate RS_MAX_INTERFACES

**Files**: `sdk/include/rswitch_abi.h`, `user/mgmt/mgmtd.c`
**Risk**: `RS_MAX_INTERFACES` was defined independently in multiple files with potentially divergent values. A mismatch between BPF map sizing and user-space iteration bounds could cause out-of-bounds access.

**Fix**: Canonical definition set in `sdk/include/rswitch_abi.h` as `256`. All other files include this header. Local `#define` removed from `mgmtd.c` — it now uses the value from `rswitch_abi.h` via the include chain.

---

### H-7: Stack-Allocated port_vlan_info pinfo[]

**File**: `user/mgmt/mgmtd.c`
**Risk**: `struct port_vlan_info pinfo[RS_MAX_INTERFACES]` on the stack. With RS_MAX_INTERFACES=256 and the struct containing multiple VLAN arrays, this exceeded safe stack limits (~1MB+), risking stack overflow.

**Fix**: Changed to heap allocation via `calloc()` with NULL-check. Freed at function exit via `free()`. Applied to all functions that previously stack-allocated large `pinfo[]` arrays.

---

### H-8: Unify VLAN Bitmask Indexing

**File**: `user/mgmt/mgmtd.c`
**Risk**: VLAN membership bitmask arrays used inconsistent indexing between BPF and user-space. BPF used `ifindex / 64` + `ifindex % 64`; some user-space code used `(ifindex - 1) / 64` + `(ifindex - 1) % 64`, causing off-by-one misreads.

**Fix**: All user-space VLAN bitmask operations now use `ifindex / 64` and `ifindex % 64`, matching the BPF side. Readback loops start from `ifindex = 1` (skipping the always-unused index 0).

---

## Medium

### M-9: Async-Signal-Unsafe printf in Signal Handler

**File**: `user/voqd/voqd.c`
**Risk**: Signal handler called `printf()` / `syslog()` — functions that take locks internally. If the signal interrupted those same functions, deadlock would occur.

**Fix**: Signal handler now only sets an `_Atomic` flag and calls `write(STDERR_FILENO, ...)` for the minimal required notification. All logging and cleanup deferred to the main loop's shutdown path, which checks the flag.

---

### M-10: volatile bool → _Atomic bool

**File**: `user/voqd/voqd.c`
**Risk**: `volatile bool running` does not guarantee atomicity on all architectures. Concurrent reads/writes between signal handler and main thread could tear.

**Fix**: Changed to `_Atomic bool running` (C11 `<stdatomic.h>`). Reads use `atomic_load()`, writes use `atomic_store()`. This provides guaranteed atomicity and proper memory ordering.

---

### M-11: remove_comment() Ignores Quoted Strings

**File**: `user/loader/profile_parser.c`
**Risk**: The profile parser's comment-stripping function treated `#` inside quoted strings as comment delimiters, silently truncating config values containing `#` (e.g., hex color codes, channel specifiers).

**Fix**: `remove_comment()` now tracks whether it's inside single or double quotes. The `#` character is only treated as a comment delimiter when outside any quoted context. Quote characters are tracked with a simple state toggle.

---

### M-12: Unbounded strcat in Loader

**File**: `user/loader/rswitch_loader.c`
**Risk**: `strcat()` used to build paths without length checking. A sufficiently long module name or path component could overflow the destination buffer.

**Fix**: All `strcat()` calls replaced with bounds-checked alternatives using `snprintf()` or manual length tracking with `strncat()`. Return values are checked; paths that would overflow are rejected with an error log.

---

### M-13: xsk_manager_get_stats() Stub

**File**: `user/voqd/afxdp_socket.c`
**Risk**: `xsk_manager_get_stats()` was a stub returning zeroes, making AF_XDP performance monitoring impossible.

**Fix**: Implementation now iterates the socket array, aggregating `rx_packets`, `rx_bytes`, `tx_packets`, `tx_bytes`, `rx_drops`, and `tx_errors` from each active `xsk_socket`'s stats fields into the output struct.

---

### M-14: Large Stack Buffers in mgmtd.c

**File**: `user/mgmt/mgmtd.c`
**Risk**: Multiple functions declared multi-KB buffers on the stack (`char buf[8192]`, large local arrays). Deep call chains could exhaust the stack.

**Fix**: Large buffers (>4KB) moved to heap allocation via `malloc()`/`calloc()` with NULL-checks. Freed on all exit paths (including error returns). Smaller buffers left on stack where appropriate.

---

### M-15: Extract acl_map_foreach() Helper

**File**: `user/mgmt/mgmtd.c`
**Risk**: ACL map iteration logic (BPF map lookup + next-key loop) was copy-pasted across 5+ functions. Each copy had subtle variations, making bug fixes inconsistent.

**Fix**: Extracted `acl_map_foreach(map_fd, callback, ctx)` — a generic BPF map iterator that takes a callback and user context. All ACL iteration sites now call this helper. Also extracted `acl_find_and_delete_rule(map_fd, rule_id)` which uses the iterator to locate and delete a rule by its stable ID.

---

### M-16: Implement Stable ACL Rule Identifiers

**File**: `user/mgmt/mgmtd.c`
**Risk**: ACL rules identified only by their BPF map key (prefix + priority). Deleting or reordering rules was fragile — the "3rd rule" could shift meaning after any insertion.

**Fix**: Added a monotonically increasing `g_acl_next_rule_id` counter with `acl_next_rule_id()` accessor. Each rule gets a unique `rule_id` assigned at creation time, stored in both `acl_result` and `acl_lpm_value` structs. Delete/update operations now reference rules by stable ID rather than positional index.

---

## Low

### L-17: Consolidate Shared Struct Definitions

**Files**: `bpf/core/map_defs.h`, `user/mgmt/mgmtd.c`
**Risk**: Six structs (`rs_stats`, `rs_module_stats`, `rs_port_config`, `rs_vlan_members`, `rs_module_config_key`, `rs_module_config_value`) and two defines (`RS_MODULE_CONFIG_KEY_LEN`, `RS_MODULE_CONFIG_VAL_LEN`) were duplicated between BPF and user-space. Any field change in one copy but not the other would cause silent data corruption when reading BPF maps.

**Fix**:
1. `bpf/core/map_defs.h`: BPF-specific content (`SEC(".maps")` map instances, `__always_inline` helpers, `rswitch_obs.h` include) gated behind `#ifdef __BPF__`. Shared struct definitions remain accessible to all includers.
2. `user/mgmt/mgmtd.c`: Added `#include "../../bpf/core/map_defs.h"` and removed all 6 duplicate struct definitions and 2 duplicate `#define`s. A tombstone comment marks the removal.

---

### L-18: Update rswitch_common.h Include Path

**File**: `bpf/include/rswitch_common.h`
**Risk**: Redundant `#include "../core/uapi.h"` when the header's content was already available through other includes in the chain.

**Fix**: Removed the redundant include. The necessary types are provided by the existing include chain.

---

### L-19: Integer Overflow in compare_modules()

**File**: `user/loader/rswitch_loader.c`
**Risk**: `compare_modules()` (qsort comparator) used `return a->priority - b->priority`. If priorities had extreme values (e.g., INT_MAX vs negative), the subtraction could overflow, producing wrong sort order.

**Fix**: Replaced with safe three-way comparison: `return (a->priority > b->priority) - (a->priority < b->priority)`. This returns -1, 0, or 1 without any arithmetic that could overflow.

---

### L-20: Unchecked if_indextoname() Calls

**File**: `user/loader/rswitch_loader.c`
**Risk**: `if_indextoname()` returns NULL if the interface index is invalid or the interface has been removed. Unchecked return values would pass NULL to string functions, causing segfault.

**Fix**: All `if_indextoname()` callsites now check for NULL return. On failure, the interface name is set to a placeholder string (e.g., `"unknown"`) or the operation is skipped with an appropriate log message.

---

## Files Modified

| File | Findings Fixed |
|------|---------------|
| `user/mgmt/mgmtd.c` | C-1, C-2, C-3, H-6, H-7, H-8, M-14, M-15, M-16, L-17 |
| `user/mgmt/mgmtd.h` | C-2, C-3 |
| `user/voqd/voqd.c` | M-9, M-10 |
| `user/voqd/voqd_dataplane.c` | H-5 |
| `user/voqd/voqd_dataplane.h` | H-5 |
| `user/voqd/voq.c` | H-4 |
| `user/voqd/voq.h` | H-4 |
| `user/voqd/afxdp_socket.c` | M-13 |
| `user/loader/profile_parser.c` | M-11 |
| `user/loader/rswitch_loader.c` | M-12, L-19, L-20 |
| `sdk/include/rswitch_abi.h` | H-6 |
| `bpf/include/rswitch_common.h` | L-18 |
| `bpf/core/map_defs.h` | L-17 |
