// SPDX-License-Identifier: GPL-2.0
/* rSwitch Module ABI — Backward Compatibility Wrapper
 *
 * This header is maintained for backward compatibility only.
 * All definitions now live in rswitch_abi.h.
 *
 * New code should use:
 *   #include <rswitch_module.h>
 */

#ifndef __RSWITCH_MODULE_ABI_H
#define __RSWITCH_MODULE_ABI_H

#warning "module_abi.h is deprecated. Use #include <rswitch_module.h> instead. See sdk/docs/SDK_Migration_Guide.md"

#include "rswitch_abi.h"

#endif /* __RSWITCH_MODULE_ABI_H */
