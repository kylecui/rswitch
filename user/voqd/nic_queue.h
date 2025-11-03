/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __NIC_QUEUE_H
#define __NIC_QUEUE_H

#include <stdint.h>

/*
 * NIC Queue Isolation for Hybrid Data Plane
 * 
 * Strategy: Separate TX queues to avoid contention between XDP fast-path
 * and AF_XDP controlled-path.
 * 
 * Queue Allocation:
 *   Queue 0: AF_XDP high-priority (VOQd-controlled)
 *   Queue 1-3: XDP fast-path (devmap redirect)
 * 
 * IRQ Affinity:
 *   Queue 0: Dedicated CPU core for VOQd
 *   Queue 1-3: Shared across other cores (XDP processing)
 */

#define NIC_QUEUE_AFXDP     0   /* AF_XDP TX queue (high-priority) */
#define NIC_QUEUE_XDP_MIN   1   /* XDP fast-path queue range start */
#define NIC_QUEUE_XDP_MAX   3   /* XDP fast-path queue range end */

#define NIC_MIN_COMBINED_QUEUES 4  /* Minimum queues needed for isolation */

/* NIC configuration for a single interface */
struct nic_config {
    char ifname[16];              /* Interface name */
    uint32_t num_queues;          /* Total combined queues available */
    uint32_t afxdp_queue;         /* Queue assigned to AF_XDP */
    uint32_t xdp_queue_start;     /* XDP fast-path queue range start */
    uint32_t xdp_queue_end;       /* XDP fast-path queue range end */
    uint32_t afxdp_cpu;           /* CPU affinity for AF_XDP queue IRQ */
    int isolation_enabled;        /* Queue isolation active */
};

/**
 * nic_queue_probe - Probe NIC capabilities
 * @ifname: Interface name
 * @config: Output configuration
 * 
 * Queries NIC queue capabilities via ethtool.
 * Returns 0 on success, -1 on error.
 */
int nic_queue_probe(const char *ifname, struct nic_config *config);

/**
 * nic_queue_setup_isolation - Configure TX queue isolation
 * @config: NIC configuration
 * 
 * Sets up queue isolation:
 * - Verifies sufficient queues available
 * - No ethtool changes (use existing queues as-is)
 * - Sets IRQ affinity for queue 0 to dedicated CPU
 * 
 * Returns 0 on success, -1 on error.
 */
int nic_queue_setup_isolation(struct nic_config *config);

/**
 * nic_queue_restore_default - Restore default queue configuration
 * @config: NIC configuration
 * 
 * Clears IRQ affinity pinning.
 * Returns 0 on success, -1 on error.
 */
int nic_queue_restore_default(struct nic_config *config);

/**
 * nic_queue_print_config - Display current NIC queue configuration
 * @config: NIC configuration
 */
void nic_queue_print_config(const struct nic_config *config);

/**
 * nic_queue_get_xdp_queue - Get XDP queue for load balancing
 * @config: NIC configuration
 * @hash: Hash value for queue selection (e.g., packet hash)
 * 
 * Returns queue number in XDP range (round-robin or hash-based).
 */
static inline uint32_t nic_queue_get_xdp_queue(const struct nic_config *config, uint32_t hash)
{
    if (!config->isolation_enabled)
        return 0;  /* Default queue */
    
    uint32_t range = config->xdp_queue_end - config->xdp_queue_start + 1;
    return config->xdp_queue_start + (hash % range);
}

#endif /* __NIC_QUEUE_H */
