// SPDX-License-Identifier: GPL-2.0
#ifndef RSWITCH_RESOURCE_LIMITS_H
#define RSWITCH_RESOURCE_LIMITS_H

#include <stdint.h>

struct rs_resource_config {
    uint32_t mac_table_max;        /* Max MAC table entries (0 = unlimited) */
    uint32_t conntrack_max;        /* Max conntrack entries (0 = unlimited) */
    uint32_t bpf_map_memory_mb;    /* Max BPF map memory budget in MB */
    int cpu_affinity_mask;         /* CPU affinity bitmask (-1 = no pinning) */
    int enable_mlockall;           /* 1 = call mlockall(MCL_CURRENT|MCL_FUTURE) */
    int oom_protect;               /* 1 = set oom_score_adj = -1000 */
    uint32_t fd_limit;             /* File descriptor limit (0 = no change) */
    uint32_t mac_aging_sec;        /* MAC table LRU aging interval seconds */
    uint32_t conntrack_aging_sec;  /* Conntrack aggressive aging on pressure */
};

/* Initialize and apply resource limits */
int rs_resource_limits_init(const struct rs_resource_config *config);

/* Apply CPU affinity to current process */
int rs_resource_set_cpu_affinity(int cpu_mask);

/* Apply memory locking */
int rs_resource_mlockall(void);

/* Set OOM protection for current process */
int rs_resource_oom_protect(void);

/* Set file descriptor limits */
int rs_resource_set_fd_limit(uint32_t limit);

/* Check MAC table pressure -- returns 1 if > 90% capacity */
int rs_resource_mac_pressure(uint32_t current_entries, uint32_t max_entries);

/* Check conntrack pressure -- returns 1 if > 80% capacity */
int rs_resource_conntrack_pressure(uint32_t current_entries, uint32_t max_entries);

/* Evict stale MAC entries (LRU) -- returns number evicted */
int rs_resource_mac_evict_lru(int map_fd, uint32_t max_entries, uint32_t aging_sec);

/* Evict stale conntrack entries -- returns number evicted */
int rs_resource_conntrack_evict(int map_fd, uint32_t max_entries, uint32_t aging_sec);

#endif
