// SPDX-License-Identifier: GPL-2.0
#ifndef RSWITCH_AGENT_H
#define RSWITCH_AGENT_H

#include <stdint.h>

#define AGENT_RECONNECT_SEC       5
#define AGENT_STATUS_INTERVAL_SEC 30

int rs_agent_run(const char *controller_host, int controller_port);

#endif
