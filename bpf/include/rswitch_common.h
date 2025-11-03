// SPDX-License-Identifier: GPL-2.0
/* rSwitch Common Header
 * 
 * Single include point for all rSwitch BPF programs.
 * Modules should include this header to get all necessary definitions.
 * 
 * With CO-RE support: Uses vmlinux.h for kernel type definitions.
 * 
 * Usage in modules:
 *   #include "rswitch_common.h"
 */

#ifndef __RSWITCH_COMMON_H
#define __RSWITCH_COMMON_H

/* CO-RE kernel types and BPF helpers */
#include "rswitch_bpf.h"

/* rSwitch core headers */
#include "../core/module_abi.h"
#include "../core/uapi.h"
#include "../core/map_defs.h"
#include "rswitch_parsing.h"  /* Includes parsing_helpers.h internally */

/* Common BPF helper wrappers for readability */
/* Note: CHECK_BOUNDS is defined in rswitch_bpf.h */

/* Safe memcpy with bounds checking */
#define SAFE_MEMCPY(dst, src, size, data_end) ({ \
    int __ret = -1; \
    void *_end = (void *)(data_end); \
    if (CHECK_BOUNDS(NULL, src, size)) { \
        __builtin_memcpy(dst, src, size); \
        __ret = 0; \
    } \
    __ret; \
})

/* Debug printing (conditional based on DEBUG macro) */
#ifdef DEBUG
#define rs_debug(fmt, ...) \
    bpf_printk("[rSwitch] " fmt, ##__VA_ARGS__)
#else
#define rs_debug(fmt, ...) do {} while (0)
#endif

/* Common return codes */
#define RS_OK       0
#define RS_ERROR    -1
#define RS_DROP     -2
#define RS_PASS     -3

/* Module version for compatibility checking */
#define RSWITCH_VERSION_MAJOR   1
#define RSWITCH_VERSION_MINOR   0
#define RSWITCH_VERSION_PATCH   0

#endif /* __RSWITCH_COMMON_H */
