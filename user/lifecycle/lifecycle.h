// SPDX-License-Identifier: GPL-2.0
#ifndef RSWITCH_LIFECYCLE_H
#define RSWITCH_LIFECYCLE_H

struct rs_lifecycle_config {
    char state_dir[256];
    int drain_timeout_sec;
    int save_mac_table;
    int save_routes;
    int save_acl_counters;
};

int rs_lifecycle_init(const struct rs_lifecycle_config *config);
int rs_lifecycle_save_state(void);
int rs_lifecycle_restore_state(void);
int rs_lifecycle_shutdown(const struct rs_lifecycle_config *config);
void rs_lifecycle_cleanup(void);

#endif
