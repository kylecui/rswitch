// SPDX-License-Identifier: GPL-2.0

#ifndef RSWITCH_WATCHDOG_H
#define RSWITCH_WATCHDOG_H

#include <stddef.h>
#include <stdint.h>

struct rs_health_status {
	int overall;
	int bpf_programs_ok;
	int maps_accessible;
	int voqd_running;
	int counters_incrementing;
	uint64_t uptime_sec;
	uint64_t last_check_ns;
	char details[16][128];
	int detail_count;
};

int rs_watchdog_check_health(struct rs_health_status *status);
int rs_watchdog_export_json(const struct rs_health_status *status, char *buf, size_t size);

#endif
