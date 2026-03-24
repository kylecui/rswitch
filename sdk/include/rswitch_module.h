/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * rSwitch Module Entry Point
 *
 * Single include for rSwitch BPF modules. Provides:
 *   - ABI types and constants (rswitch_abi.h)
 *   - BPF helpers, packet parsing, pipeline macros (rswitch_helpers.h)
 *
 * Does NOT include shared map definitions. If your module needs direct
 * access to port config, statistics, MAC table, or VLAN maps, also
 * include <rswitch_maps.h>.
 */

#ifndef __RSWITCH_MODULE_H
#define __RSWITCH_MODULE_H

#include "rswitch_helpers.h"

#endif /* __RSWITCH_MODULE_H */
