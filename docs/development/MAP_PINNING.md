# BPF Map Pinning in rSwitch

## Pin Path Convention

rSwitch uses a two-tier pinning scheme:

| Scope | Pin Path | Example |
|-------|----------|---------|
| **Core shared maps** | `/sys/fs/bpf/<map_name>` (flat, `rs_` prefix) | `/sys/fs/bpf/rs_ctx_map` |
| **User/downstream module maps** | `/sys/fs/bpf/<project>/<map_name>` (subdirectory) | `/sys/fs/bpf/jz_sniff/capture_ring` |

### Core Maps (Flat Path)

All rSwitch framework maps pin directly to `/sys/fs/bpf/` using the `rs_` prefix. This is the default `LIBBPF_PIN_BY_NAME` behavior and ensures all core maps are discoverable at a well-known location.

### User/Downstream Module Maps (Subdirectory Path)

External projects building on rSwitch **should** pin their private maps under a project-specific subdirectory: `/sys/fs/bpf/<project>/`. This provides namespace isolation — multiple downstream projects can coexist without map name collisions.

Create the subdirectory before pinning:

```c
/* In user-space loader or setup script */
mkdir("/sys/fs/bpf/my_project", 0700);
```

Or use `bpf_obj_pin()` with the full path — the kernel creates intermediate directories automatically when using `bpftool`.

## Shared Map Discovery Table

Core maps that downstream modules may need to access:

| Map Name | Type | Purpose | Typical Access |
|----------|------|---------|----------------|
| `rs_ctx_map` | `PERCPU_ARRAY` | Per-packet shared context between pipeline stages | Read/Write by all pipeline modules |
| `rs_progs` | `PROG_ARRAY` | Ingress tail-call program array | Write by loader/hot-reload; indirect use by modules via `RS_TAIL_CALL_NEXT` |
| `rs_progs_egress` | `PROG_ARRAY` | Egress tail-call program array | Write by loader/hot-reload |
| `rs_event_bus` | `RINGBUF` | Structured event ring buffer for observability | Write by modules via `RS_EMIT_EVENT`; read by user-space consumers |
| `rs_port_config_map` | `HASH` | Per-port VLAN and mode configuration | Write by mgmtd; read by VLAN/forwarding modules |
| `rs_stats_map` | `PERCPU_ARRAY` | Per-module pipeline statistics | Write by modules; read by monitoring tools |

> **Note**: Open core maps from user-space with `bpf_obj_get("/sys/fs/bpf/<map_name>")`. For downstream maps, use the full subdirectory path: `bpf_obj_get("/sys/fs/bpf/my_project/my_map")`.

## Module Map Definition

Every map that needs user-space access must include the `pinning` attribute:

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
/* Core rSwitch map */
int fd = bpf_obj_get("/sys/fs/bpf/rs_ctx_map");

/* Downstream project map */
int fd = bpf_obj_get("/sys/fs/bpf/my_project/my_map");
```

## Map Name Conventions

| Prefix / Pattern | Owner | Pin Location |
|------------------|-------|--------------|
| `rs_*` | rSwitch framework shared maps | `/sys/fs/bpf/rs_*` (flat) |
| Module-specific (no `rs_` prefix) | Module-private maps (e.g., `acl_5tuple_map`) | `/sys/fs/bpf/<map_name>` (flat, rSwitch-internal modules) |
| `<project>_*` | Downstream project maps | `/sys/fs/bpf/<project>/<map_name>` (subdirectory) |

## Historical Note

Early development used `/sys/fs/bpf/rswitch/` as a subdirectory for all maps. This was deprecated in favor of the flat `rs_*` prefix for core maps (matching libbpf defaults) while reserving subdirectories for downstream namespace isolation. Any references to `/sys/fs/bpf/rswitch/` in archived documentation are outdated.
