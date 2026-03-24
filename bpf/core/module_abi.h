// SPDX-License-Identifier: GPL-2.0
/* rSwitch Module ABI
 * 
 * This header defines the plugin interface for rSwitch modules.
 * Each module declares itself via RS_DECLARE_MODULE() macro which
 * embeds metadata into .rodata.mod ELF section for auto-discovery.
 */

#ifndef __RSWITCH_MODULE_ABI_H
#define __RSWITCH_MODULE_ABI_H

#ifdef __BPF__
    /* BPF side: types from vmlinux.h */
#else
    #include <linux/types.h>
#endif

/* API stability tier annotations */
#define RS_API_STABLE       /* Guaranteed stable across minor versions */
#define RS_API_EXPERIMENTAL /* May change between minor versions */
#define RS_API_INTERNAL     /* May change at any time, not for modules */

#define RS_DEPRECATED(msg) __attribute__((deprecated(msg)))

#define RS_ABI_VERSION_MAJOR 2
#define RS_ABI_VERSION_MINOR 0
#define RS_ABI_VERSION ((RS_ABI_VERSION_MAJOR << 16) | RS_ABI_VERSION_MINOR)

#define RS_ABI_VERSION_1 ((1u << 16) | 0)  /* Historical: ABI v1.0 */
#define RS_ABI_VERSION_2 RS_ABI_VERSION     /* Current: ABI v2.0 */

#define RS_ABI_MAJOR(v) ((v) >> 16)
#define RS_ABI_MINOR(v) ((v) & 0xFFFF)

/* Hook points where modules can be attached */
enum rs_hook_point {
    RS_HOOK_XDP_INGRESS = 0,    /* Main XDP ingress hook */
    RS_HOOK_XDP_EGRESS  = 1,    /* XDP devmap egress hook */
    RS_HOOK_MAX,
};

/* Module capability flags */
#define RS_FLAG_NEED_L2L3_PARSE    (1u << 0)  /* RS_API_STABLE: Requires parsed L2/L3 headers */
#define RS_FLAG_NEED_VLAN_INFO     (1u << 1)  /* RS_API_STABLE: Requires VLAN information */
#define RS_FLAG_NEED_FLOW_INFO     (1u << 2)  /* RS_API_STABLE: Requires 5-tuple flow info */
#define RS_FLAG_MODIFIES_PACKET    (1u << 3)  /* RS_API_STABLE: May modify packet data */
#define RS_FLAG_MAY_DROP           (1u << 4)  /* RS_API_STABLE: May drop packets */
#define RS_FLAG_CREATES_EVENTS     (1u << 5)  /* RS_API_STABLE: Generates ringbuf events */
#define RS_FLAG_MAY_REDIRECT       (1u << 6)  /* RS_API_STABLE: May redirect packets */

/* Module descriptor - embedded in .rodata.mod section
 * 
 * This structure is read by the loader during module discovery.
 * The loader uses this metadata to:
 * - Verify ABI compatibility
 * - Determine hook point (ingress/egress)
 * - Order modules by stage number
 * - Validate capability requirements
 */
RS_API_STABLE struct rs_module_desc {
    __u32 abi_version;      /* Must be RS_ABI_VERSION */
    __u32 hook;             /* enum rs_hook_point */
    __u32 stage;            /* Pipeline stage (lower = earlier) */
    __u32 flags;            /* Capability flags (RS_FLAG_*) */
    char  name[32];         /* Module name (for logging/debug) */
    char  description[64];  /* Human-readable description */
    __u32 reserved[4];      /* Reserved for future use */
} __attribute__((aligned(8)));

#define RS_MAX_DEPS 4
#define RS_DEP_NAME_LEN 32

RS_API_EXPERIMENTAL struct rs_module_deps {
    __u32 dep_count;
    char deps[RS_MAX_DEPS][RS_DEP_NAME_LEN];
} __attribute__((aligned(8)));

/* Declare a module with metadata
 * 
 * Usage:
 *   RS_DECLARE_MODULE("vlan", RS_HOOK_XDP_INGRESS, 20, 
 *                     RS_FLAG_NEED_L2L3_PARSE | RS_FLAG_MODIFIES_PACKET,
 *                     "VLAN tag processing and peer lookup");
 * 
 * Parameters:
 *   _name: Module name (string literal)
 *   _hook: Hook point (RS_HOOK_XDP_INGRESS or RS_HOOK_XDP_EGRESS)
 *   _stage: Pipeline stage number (10-99, see STAGE CONVENTIONS below)
 *   _flags: Capability flags (RS_FLAG_* bitwise OR)
 *   _desc: Description string (optional, can be empty "")
 * 
 * The macro creates a const volatile structure in the .rodata.mod section
 * which is preserved in the compiled BPF object file and read by the loader.
 */
#define RS_DECLARE_MODULE(_name, _hook, _stage, _flags, _desc) /* RS_API_STABLE */ \
    const volatile struct rs_module_desc __rs_module \
    __attribute__((section(".rodata.mod"), used)) = { \
        .abi_version = RS_ABI_VERSION, \
        .hook = _hook, \
        .stage = _stage, \
        .flags = _flags, \
        .name = _name, \
        .description = _desc, \
    }

#define RS_DEPENDS_ON_1(_dep1) \
    const volatile struct rs_module_deps __rs_module_deps \
    __attribute__((section(".rodata.moddep"), used)) = { \
        .dep_count = 1, \
        .deps = { _dep1 }, \
    }

#define RS_DEPENDS_ON_2(_dep1, _dep2) \
    const volatile struct rs_module_deps __rs_module_deps \
    __attribute__((section(".rodata.moddep"), used)) = { \
        .dep_count = 2, \
        .deps = { _dep1, _dep2 }, \
    }

#define RS_DEPENDS_ON_3(_dep1, _dep2, _dep3) \
    const volatile struct rs_module_deps __rs_module_deps \
    __attribute__((section(".rodata.moddep"), used)) = { \
        .dep_count = 3, \
        .deps = { _dep1, _dep2, _dep3 }, \
    }

#define RS_DEPENDS_ON_4(_dep1, _dep2, _dep3, _dep4) \
    const volatile struct rs_module_deps __rs_module_deps \
    __attribute__((section(".rodata.moddep"), used)) = { \
        .dep_count = 4, \
        .deps = { _dep1, _dep2, _dep3, _dep4 }, \
    }

#define RS_GET_DEP_MACRO(_1, _2, _3, _4, NAME, ...) NAME
#define RS_DEPENDS_ON(...) \
    RS_GET_DEP_MACRO(__VA_ARGS__, RS_DEPENDS_ON_4, RS_DEPENDS_ON_3, RS_DEPENDS_ON_2, RS_DEPENDS_ON_1)(__VA_ARGS__)

/* STAGE NUMBER CONVENTIONS
 * 
 * Modules are executed in ascending stage order within each hook point.
 * Stage numbers are used for ORDERING in profiles - actual slot assignment
 * in rs_progs array is done automatically by the loader:
 *   - Ingress modules: slots 0, 1, 2, ... (ascending from 0)
 *   - Egress modules: slots 255, 254, 253, ... (descending from 255)
 * 
 * This separation prevents slot collision and enables independent pipelines.
 * 
 * INGRESS PIPELINE (Stages 10-99):
 *   10-19: Pre-processing (header validation, normalization)
 *   20-29: VLAN processing (tag manipulation, peer lookup)
 *   30-39: Access control and security policies
 *   40-49: Routing decisions (L2/L3 forwarding table lookup)
 *   50-69: QoS marking and classification
 *   70-79: Mirroring and sampling
 *   80-89: Learning and observability (MAC learning, flow tracking)
 *   90-99: Final decision (lastcall - must be at 90)
 * 
 * EGRESS PIPELINE (Stages 100-199):
 *   100-119: Pre-egress processing
 *   120-139: VLAN tag manipulation (egress tagging)
 *   140-169: Policy enforcement
 *   170-179: QoS enforcement (rate limiting, DSCP remarking)
 *   180-189: Mirroring and telemetry
 *   190-199: Final egress (egress_final - must be last, typically 190)
 * 
 * Example stage assignments:
 *   Ingress:
 *     - vlan.bpf.c:       stage=20 (VLAN ingress processing)
 *     - acl.bpf.c:        stage=30 (Access control)
 *     - route.bpf.c:      stage=50 (IP routing)
 *     - mirror.bpf.c:     stage=70 (Mirroring)
 *     - l2learn.bpf.c:    stage=80 (MAC learning)
 *     - lastcall.bpf.c:   stage=90 (Final forwarding)
 *   Egress:
 *     - qos.bpf.c:        stage=170 (QoS processing)
 *     - egress_vlan.bpf.c: stage=180 (VLAN egress tagging)
 *     - egress_final.bpf.c: stage=190 (Final egress)
 * 
 * Slot assignment example (2 egress modules):
 *   Loader sorts by stage (170 < 190), assigns slots descending:
 *     qos (stage 170) → rs_progs[255]
 *     egress_final (stage 190) → rs_progs[254]
 *   Chain: prog_chain[0]=255, prog_chain[255]=254, prog_chain[254]=0
 */

/* Module stage ranges for reference */
#define RS_STAGE_PREPROCESS     10
#define RS_STAGE_VLAN           20
#define RS_STAGE_ACL            30
#define RS_STAGE_ROUTE          40
#define RS_STAGE_QOS            50
#define RS_STAGE_MIRROR         70
#define RS_STAGE_LEARN          80
#define RS_STAGE_LASTCALL       90

/* User module stage ranges (external modules MUST use these) */
#define RS_STAGE_USER_INGRESS_MIN  200
#define RS_STAGE_USER_INGRESS_MAX  299
#define RS_STAGE_USER_EGRESS_MIN   400
#define RS_STAGE_USER_EGRESS_MAX   499

#endif /* __RSWITCH_MODULE_ABI_H */
