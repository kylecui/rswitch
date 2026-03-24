// SPDX-License-Identifier: LGPL-2.1-or-later
#define _GNU_SOURCE
#include <sched.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <bpf/bpf.h>
#include "resource_limits.h"
#if __has_include("rs_log.h")
#include "rs_log.h"
#else
#include "../common/rs_log.h"
#endif

struct rs_mac_key {
    __u8 mac[6];
    __u16 vlan;
} __attribute__((packed));

struct rs_mac_entry {
    __u32 ifindex;
    __u8 static_entry;
    __u8 reserved[3];
    __u64 last_seen;
    __u32 hit_count;
} __attribute__((packed));

struct rs_conntrack_entry {
    __u8 state;
    __u8 flags;
    __u8 direction;
    __u8 pad;
    __u64 created_ns;
    __u64 last_seen_ns;
    __u64 pkts_orig;
    __u64 pkts_reply;
    __u64 bytes_orig;
    __u64 bytes_reply;
    __u32 timeout_sec;
} __attribute__((aligned(8)));

static __u64 rs_time_now_monotonic_ns(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;

    return (__u64)ts.tv_sec * 1000000000ULL + (__u64)ts.tv_nsec;
}

int rs_resource_limits_init(const struct rs_resource_config *config)
{
    int rc = 0;
    int ret;

    if (!config)
        return -EINVAL;

    RS_LOG_INFO("Applying resource limits");

    if (config->enable_mlockall) {
        RS_LOG_INFO("Applying mlockall");
        ret = rs_resource_mlockall();
        if (ret && rc == 0)
            rc = ret;
    }

    if (config->oom_protect) {
        RS_LOG_INFO("Applying OOM protection");
        ret = rs_resource_oom_protect();
        if (ret && rc == 0)
            rc = ret;
    }

    if (config->cpu_affinity_mask >= 0) {
        RS_LOG_INFO("Applying CPU affinity mask=0x%x", config->cpu_affinity_mask);
        ret = rs_resource_set_cpu_affinity(config->cpu_affinity_mask);
        if (ret && rc == 0)
            rc = ret;
    }

    if (config->fd_limit > 0) {
        RS_LOG_INFO("Applying fd limit=%u", config->fd_limit);
        ret = rs_resource_set_fd_limit(config->fd_limit);
        if (ret && rc == 0)
            rc = ret;
    }

    return rc;
}

int rs_resource_set_cpu_affinity(int cpu_mask)
{
    cpu_set_t set;
    int cpu;
    int has_cpu = 0;

    if (cpu_mask < 0)
        return -EINVAL;

    CPU_ZERO(&set);
    for (cpu = 0; cpu < 32 && cpu < CPU_SETSIZE; cpu++) {
        if (cpu_mask & (1U << cpu)) {
            CPU_SET(cpu, &set);
            has_cpu = 1;
        }
    }

    if (!has_cpu)
        return -EINVAL;

    if (sched_setaffinity(0, sizeof(set), &set) != 0)
        return -errno;

    return 0;
}

int rs_resource_mlockall(void)
{
    if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0) {
        RS_LOG_WARN("mlockall failed (CAP_IPC_LOCK required): %s", strerror(errno));
        return -errno;
    }

    return 0;
}

int rs_resource_oom_protect(void)
{
    FILE *fp = fopen("/proc/self/oom_score_adj", "w");

    if (!fp)
        return -errno;

    if (fputs("-1000", fp) == EOF) {
        int err = errno;
        fclose(fp);
        return -err;
    }

    if (fclose(fp) != 0)
        return -errno;

    return 0;
}

int rs_resource_set_fd_limit(uint32_t limit)
{
    struct rlimit lim;

    if (limit == 0)
        return 0;

    lim.rlim_cur = (rlim_t)limit;
    lim.rlim_max = (rlim_t)limit;

    if (setrlimit(RLIMIT_NOFILE, &lim) != 0)
        return -errno;

    return 0;
}

int rs_resource_mac_pressure(uint32_t current_entries, uint32_t max_entries)
{
    if (max_entries == 0)
        return 0;

    return ((current_entries * 100U) / max_entries) > 90U;
}

int rs_resource_conntrack_pressure(uint32_t current_entries, uint32_t max_entries)
{
    if (max_entries == 0)
        return 0;

    return ((current_entries * 100U) / max_entries) > 80U;
}

int rs_resource_mac_evict_lru(int map_fd, uint32_t max_entries, uint32_t aging_sec)
{
    struct rs_mac_key key;
    struct rs_mac_key next_key;
    int has_key = 0;
    int evicted = 0;
    __u64 now_sec;

    (void)max_entries;

    if (map_fd < 0 || aging_sec == 0)
        return 0;

    now_sec = (__u64)time(NULL);
    if ((__time_t)now_sec < 0)
        return -errno;

    memset(&key, 0, sizeof(key));
    while (bpf_map_get_next_key(map_fd, has_key ? &key : NULL, &next_key) == 0) {
        struct rs_mac_entry entry;

        if (bpf_map_lookup_elem(map_fd, &next_key, &entry) == 0) {
            __u64 last_seen_sec = entry.last_seen;

            if (last_seen_sec > 1000000000000ULL)
                last_seen_sec /= 1000000000ULL;

            if (!entry.static_entry && now_sec > last_seen_sec &&
                (now_sec - last_seen_sec) > (__u64)aging_sec) {
                if (bpf_map_delete_elem(map_fd, &next_key) == 0)
                    evicted++;
            }
        }

        key = next_key;
        has_key = 1;
    }

    return evicted;
}

int rs_resource_conntrack_evict(int map_fd, uint32_t max_entries, uint32_t aging_sec)
{
    __u32 key = 0;
    __u32 next_key = 0;
    int has_key = 0;
    int evicted = 0;
    __u64 now_ns;

    (void)max_entries;

    if (map_fd < 0 || aging_sec == 0)
        return 0;

    now_ns = rs_time_now_monotonic_ns();
    if (now_ns == 0)
        return -errno;

    while (bpf_map_get_next_key(map_fd, has_key ? &key : NULL, &next_key) == 0) {
        struct rs_conntrack_entry entry;

        if (bpf_map_lookup_elem(map_fd, &next_key, &entry) == 0) {
            __u64 age_ns;

            if (now_ns > entry.last_seen_ns)
                age_ns = now_ns - entry.last_seen_ns;
            else
                age_ns = 0;

            if (age_ns > (__u64)aging_sec * 1000000000ULL) {
                if (bpf_map_delete_elem(map_fd, &next_key) == 0)
                    evicted++;
            }
        }

        key = next_key;
        has_key = 1;
    }

    return evicted;
}
