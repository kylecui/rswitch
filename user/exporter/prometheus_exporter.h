// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef RSWITCH_PROMETHEUS_EXPORTER_H
#define RSWITCH_PROMETHEUS_EXPORTER_H

#include <linux/types.h>
#include <stddef.h>

#define RSWITCH_PROMETHEUS_DEFAULT_PORT 9417
#define RSWITCH_PROMETHEUS_DEFAULT_INTERVAL_SEC 5
#define RSWITCH_PROMETHEUS_VERSION "1.0.0"

struct prometheus_exporter_config {
    __u16 port;
    __u32 refresh_interval_sec;
};

struct prometheus_exporter_ctx;

void prometheus_exporter_default_config(struct prometheus_exporter_config *cfg);
void prometheus_exporter_print_usage(const char *prog);
int prometheus_exporter_parse_args(int argc, char **argv,
                                   struct prometheus_exporter_config *cfg);
int prometheus_exporter_run(const struct prometheus_exporter_config *cfg);

#endif /* RSWITCH_PROMETHEUS_EXPORTER_H */
