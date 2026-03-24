// SPDX-License-Identifier: GPL-2.0
/*
 * rSwitch Common Header — Backward Compatibility
 *
 * Umbrella include for core rSwitch BPF modules. Pulls in everything:
 * ABI types, BPF helpers, all shared maps, packet parsing, and legacy macros.
 *
 * New SDK modules should prefer:
 *   #include "rswitch_module.h"          (minimal, no maps)
 *   #include "rswitch_maps.h"            (opt-in, only if needed)
 *
 * This header exists so that existing core modules and SDK templates
 * using #include "rswitch_common.h" continue to compile unchanged.
 */

#ifndef __RSWITCH_COMMON_H
#define __RSWITCH_COMMON_H

#include "rswitch_module.h"
#include "rswitch_maps.h"

#if __has_include("rswitch_parsing.h")
#include "rswitch_parsing.h"
#endif

/* Legacy convenience macros (kept for backward compat) */

#define SAFE_MEMCPY(dst, src, size, data_end) ({ \
    int __ret = -1; \
    void *_end = (void *)(data_end); \
    if (CHECK_BOUNDS(NULL, src, size)) { \
        __builtin_memcpy(dst, src, size); \
        __ret = 0; \
    } \
    __ret; \
})

#ifdef DEBUG
#define rs_debug(fmt, ...) \
    bpf_printk("[rSwitch] " fmt, ##__VA_ARGS__)
#else
#define rs_debug(fmt, ...) do {} while (0)
#endif

#define RS_OK       0
#define RS_ERROR    -1
#define RS_DROP     -2
#define RS_PASS     -3

#define RSWITCH_VERSION_MAJOR   1
#define RSWITCH_VERSION_MINOR   0
#define RSWITCH_VERSION_PATCH   0

#endif /* __RSWITCH_COMMON_H */
