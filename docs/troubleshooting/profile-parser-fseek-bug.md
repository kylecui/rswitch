# Profile Parser fseek Bug - Troubleshooting Documentation

**Date**: February 11, 2026  
**Issue**: Egress modules not loading from YAML profile  
**Status**: ✅ RESOLVED

---

## Problem Statement

When running rSwitch with a profile containing egress modules (`egress_qos`, `egress_vlan`, `egress_final`), the profile parser reported `egress_count=0` despite the YAML file correctly specifying all three modules.

### Expected Behavior
```
Profile loaded: ingress_count=8, egress_count=3
```

### Observed Behavior
```
Profile loaded: ingress_count=8, egress_count=0
```

### Impact
- Egress modules were never inserted into `rs_progs` map
- Egress pipeline chain (`rs_prog_chain`) was not built
- VLAN tagging on egress did not work
- QoS processing on egress was skipped
- Packets exited directly through devmap without egress processing

---

## Root Cause Analysis

### Investigation Method

1. **Loader output analysis**: Observed `egress_count=0` in profile loading output
2. **Profile file verification**: Confirmed YAML contained valid egress module definitions
3. **Code review**: Traced the issue to `parse_module_list()` in `profile_parser.c`

### Root Cause

**Off-by-one `fseek` error in `parse_module_list()` function.**

The function reads lines from the YAML file to parse module lists. When it encounters a new section header (e.g., `egress:`), it needs to "unread" the line by seeking backward so the parent parser can process it. However, the code calculated the seek offset **after** modifying the line buffer.

**The Bug:**

```c
while (fgets(line, sizeof(line), fp)) {
    remove_comment(line);       // Modifies line, may shorten it
    char *trimmed = trim(line); // May return pointer to middle of line
    
    // ...
    
    if (strchr(trimmed, ':') && trimmed[0] != '-') {
        // New section found, need to seek back
        fseek(fp, -(long)strlen(line), SEEK_CUR);  // BUG: line was modified!
        break;
    }
}
```

**Example:**
- Original line in file: `"egress:\n"` (8 bytes including newline)
- After `trim()`: `"egress:"` (7 bytes, newline removed)
- `strlen(line)` returns 7, not 8
- `fseek(fp, -7, SEEK_CUR)` seeks back only 7 bytes
- File position is now 1 byte INTO the `egress:` line
- Next `fgets()` reads `"gress:\n"` - corrupted!
- Parent parser fails to recognize `egress:` section

This caused the egress module list to be completely skipped during parsing.

---

## Solution

### Fix: Save Original Line Length Before Modifications

**File**: `rswitch/user/loader/profile_parser.c`

**Lines**: 145-193 (in `parse_module_list()` function)

```c
while (fgets(line, sizeof(line), fp)) {
    size_t original_len = strlen(line);  // NEW: Save BEFORE any modifications
    
    remove_comment(line);
    char *trimmed = trim(line);
    
    if (!*trimmed || trimmed[0] == '#')
        continue;
    
    // Check for new section header (not a list item)
    if (strchr(trimmed, ':') && trimmed[0] != '-') {
        // Seek back using ORIGINAL length, not modified length
        fseek(fp, -(long)original_len, SEEK_CUR);  // FIX: Use original_len
        break;
    }
    
    // ... rest of list parsing ...
}
```

### Why This Works

1. `fgets()` reads the line including the newline character
2. We immediately save `strlen(line)` which includes the newline
3. `remove_comment()` and `trim()` may modify/shorten the string
4. When seeking back, we use the original length, which correctly positions the file pointer at the start of the unprocessed line

---

## Verification

### 1. Check Profile Parser Output

After the fix, the loader should report correct counts:

```bash
sudo ./build/rswitch_loader -i ens34,ens35,ens36,ens37 -p etc/profiles/all-modules-test.yaml -v
```

**Expected output:**
```
Loading profile: etc/profiles/all-modules-test.yaml
  Parsed ingress modules: 8
  Parsed egress modules: 3
  ...
Building tail-call pipeline:
  [255] stage=170 hook=egress : egress_qos (fd=1149) → next=254
  [254] stage=180 hook=egress : egress_vlan (fd=1135) → next=253
  [253] stage=190 hook=egress : egress_final (fd=1147) [LAST]

Egress entry point: prog_chain[0] = 255 (devmap→first egress module)
Pipeline built: 8 ingress + 3 egress modules
```

### 2. Verify BPF Maps

```bash
# Check prog_chain has egress entries
sudo bpftool map dump pinned /sys/fs/bpf/rs_prog_chain | grep -E '"key": (0|253|254|255)'
```

**Expected output:**
```json
{ "key": 0, "value": 255 }      // Entry point → slot 255
{ "key": 253, "value": 0 }      // egress_final → end
{ "key": 254, "value": 253 }    // egress_vlan → egress_final
{ "key": 255, "value": 254 }    // egress_qos → egress_vlan
```

### 3. Check rs_progs Slots

```bash
# Check egress programs are in high slots
sudo bpftool map dump pinned /sys/fs/bpf/rs_progs | grep -A2 '"key": 25[345]'
```

**Expected output:**
```json
{ "key": 253, "value": <egress_final_fd> }
{ "key": 254, "value": <egress_vlan_fd> }
{ "key": 255, "value": <egress_qos_fd> }
```

### 4. Verify Traffic Flow with trace_pipe

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe | grep -i egress
```

**Expected output shows full egress pipeline:**
```
[rSwitch] Egress tail-call to prog 255
[rSwitch] QoS: processed priority=2 egress=3
[rSwitch] egress_vlan: Isolation check - port 3, VLAN 10
[rSwitch] egress_vlan: Port 3 is member of VLAN 10, allowing
[rSwitch] egress_vlan: port=3, vlan=10, tagged=0, should_tag=1, mode=2
[rSwitch] egress_vlan: Updated L3 offset after tag add: +4 bytes
[rSwitch] Egress final: packet processing complete
```

---

## Key Learnings

### 1. String Modification Before Length Calculation

**Never calculate string length after modifying the string if you need the original length.**

```c
// WRONG pattern
char line[256];
fgets(line, sizeof(line), fp);
modify_string(line);           // Truncates or modifies line
size_t len = strlen(line);     // len is now WRONG for fseek

// CORRECT pattern
char line[256];
fgets(line, sizeof(line), fp);
size_t original_len = strlen(line);  // Save FIRST
modify_string(line);                  // Then modify
// Use original_len for fseek
```

### 2. fseek with SEEK_CUR

When using `fseek(fp, offset, SEEK_CUR)` to "unread" data:
- The offset must match the EXACT number of bytes read by `fgets()`
- `fgets()` includes the newline character in the count
- String manipulation functions often remove or ignore newlines

### 3. YAML Parsing Edge Cases

The profile parser processes YAML in a streaming fashion. Section transitions (e.g., from `ingress:` to `egress:`) rely on detecting the new section header and seeking back. This pattern is fragile when:
- Lines are modified before the seek offset is calculated
- Comments or whitespace affect line length differently than expected

### 4. Debugging Profile Parsing Issues

When module counts are wrong:
1. Add debug prints showing `original_len` vs `strlen(line)` after modifications
2. Print the exact bytes being read: `printf("Read %zu bytes: [%s]\n", len, line);`
3. Verify file position before and after `fseek`: `printf("pos: %ld\n", ftell(fp));`

---

## Related Code Patterns

### Similar Vulnerable Patterns in Codebase

Search for other places that might have the same bug:

```bash
grep -rn "fseek.*strlen" rswitch/user/
grep -rn "fgets.*trim.*fseek" rswitch/user/
```

If found, apply the same fix: save original length before any string modifications.

### Safe Pattern for Line-Based Parsing with Lookahead

```c
// Safe pattern for YAML-style parsing with lookahead
while (fgets(line, sizeof(line), fp)) {
    size_t bytes_read = strlen(line);  // Includes newline if present
    
    // Make a working copy for parsing
    char working[256];
    strncpy(working, line, sizeof(working) - 1);
    working[sizeof(working) - 1] = '\0';
    
    remove_comment(working);
    char *trimmed = trim(working);
    
    // Check for section change
    if (is_new_section(trimmed)) {
        // Seek back using ORIGINAL bytes_read
        fseek(fp, -(long)bytes_read, SEEK_CUR);
        break;
    }
    
    // Process trimmed content
    process_line(trimmed);
}
```

---

## Files Modified

1. **`rswitch/user/loader/profile_parser.c`**
   - Line 150: Added `size_t original_len = strlen(line);` before modifications
   - Line 158: Changed `fseek(fp, -(long)strlen(line), ...)` to `fseek(fp, -(long)original_len, ...)`

---

## Test Environment

- **Host**: `10.174.254.128`
- **User**: `kylecui`
- **Project Path**: `~/dev/rswitch/`
- **Profile**: `etc/profiles/all-modules-test.yaml`
- **Interfaces**: `ens34` (trunk), `ens35` (VLAN 10), `ens36`, `ens37`

---

## Commands Reference

### Build and Test

```bash
cd ~/dev/rswitch

# Build loader
make build/rswitch_loader

# Run with verbose output
sudo ./build/rswitch_loader -i ens34,ens35,ens36,ens37 \
    -p etc/profiles/all-modules-test.yaml -v

# Check egress pipeline
sudo bpftool prog show | grep -E '(egress|qos)'
sudo bpftool map dump pinned /sys/fs/bpf/rs_prog_chain | head -20
```

### Verify VLAN Tagging

```bash
# Watch egress VLAN processing
sudo timeout 10 cat /sys/kernel/debug/tracing/trace_pipe | grep egress_vlan

# Expected: "should_tag=1" and "Updated L3 offset after tag add: +4 bytes"
```

### Clean Up

```bash
sudo pkill -9 rswitch_loader
for iface in ens34 ens35 ens36 ens37; do
    sudo ip link set $iface xdpgeneric off
done
sudo rm -f /sys/fs/bpf/*
```

---

## Prevention Guidelines

### Code Review Checklist for File I/O

When reviewing code that uses `fseek` with `SEEK_CUR`:

- [ ] Is the seek offset calculated from the original data before any modifications?
- [ ] Does `fgets()` return include the newline, but later processing removes it?
- [ ] Is `strlen()` called on a modified vs original buffer?
- [ ] Are there multiple modification steps that could each affect length?

### Unit Test Suggestion

Add a test case for profile parsing with multi-section YAML:

```c
// test_profile_parser.c
void test_egress_module_parsing() {
    const char *yaml = 
        "ingress:\n"
        "  - vlan\n"
        "  - acl\n"
        "egress:\n"          // Section transition
        "  - egress_qos\n"
        "  - egress_vlan\n"
        "  - egress_final\n";
    
    struct rs_profile profile;
    int ret = parse_profile_string(yaml, &profile);
    
    assert(ret == 0);
    assert(profile.ingress_count == 2);
    assert(profile.egress_count == 3);  // This would have failed before fix
    assert(strcmp(profile.egress[0], "egress_qos") == 0);
}
```
