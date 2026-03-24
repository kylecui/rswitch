# BPF Map Pinning in rSwitch

## Canonical Pin Path

All rSwitch BPF maps are pinned to the **flat** path:

```
/sys/fs/bpf/<map_name>
```

This is the default `LIBBPF_PIN_BY_NAME` behavior. Do **not** use subdirectory paths like `/sys/fs/bpf/rswitch/`.

## Module Map Definition

Every map that needs user-space access must include:

```c
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct my_value);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} my_map SEC(".maps");
```

## User-Space Access

Open pinned maps from user-space with:

```c
int fd = bpf_obj_get("/sys/fs/bpf/my_map");
```

## Map Name Conventions

| Prefix | Owner |
|--------|-------|
| `rs_` | Framework shared maps (`rs_ctx_map`, `rs_progs`, `rs_event_bus`) |
| Module-specific | Module-private maps (`acl_5tuple_map`, `rl_bucket_map`) |

## Historical Note

Early development used `/sys/fs/bpf/rswitch/` as a subdirectory pin path. This was deprecated in favor of the flat path to match libbpf defaults. Any references to the old path in archived documentation are outdated.
