// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <dirent.h>
#include "nic_queue.h"

/*
 * NIC Queue Isolation Implementation
 * 
 * Manages TX queue separation for hybrid XDP/AF_XDP data plane.
 */

/* Parse ethtool output to get queue count */
static int parse_ethtool_queues(const char *ifname, uint32_t *num_queues)
{
    char cmd[256];
    FILE *fp;
    char line[256];
    uint32_t combined = 0;
    
    snprintf(cmd, sizeof(cmd), "ethtool -l %s 2>/dev/null", ifname);
    fp = popen(cmd, "r");
    if (!fp) {
        fprintf(stderr, "Failed to run ethtool for %s\n", ifname);
        return -1;
    }
    
    /* Parse ethtool -l output:
     * Current hardware settings:
     * Combined:       4
     */
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "Combined:") && strstr(line, "Current")) {
            /* Look ahead for the actual value line */
            continue;
        }
        if (sscanf(line, "Combined: %u", &combined) == 1) {
            break;
        }
    }
    
    pclose(fp);
    
    if (combined == 0) {
        fprintf(stderr, "Could not determine queue count for %s\n", ifname);
        fprintf(stderr, "Tip: Run 'sudo ethtool -l %s' manually\n", ifname);
        return -1;
    }
    
    *num_queues = combined;
    return 0;
}

/* Get IRQ number for a specific queue */
static int get_queue_irq(const char *ifname, uint32_t queue, int *irq_num)
{
    char path[512];
    char link[512];
    DIR *dir;
    struct dirent *entry;
    ssize_t len;
    
    /* Find IRQ via /sys/class/net/<ifname>/device/msi_irqs/ */
    snprintf(path, sizeof(path), "/sys/class/net/%s/device/msi_irqs", ifname);
    
    dir = opendir(path);
    if (!dir) {
        /* Try alternative: parse /proc/interrupts */
        FILE *fp = fopen("/proc/interrupts", "r");
        if (!fp)
            return -1;
        
        char line[512];
        char pattern[128];
        snprintf(pattern, sizeof(pattern), "%s.*%u", ifname, queue);
        
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, ifname) && strstr(line, pattern)) {
                if (sscanf(line, "%d:", irq_num) == 1) {
                    fclose(fp);
                    return 0;
                }
            }
        }
        fclose(fp);
        return -1;
    }
    
    /* For simplicity, use first IRQ + queue offset (NIC-dependent) */
    /* This is a heuristic - production should use proper IRQ mapping */
    int base_irq = -1;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.')
            continue;
        
        int irq = atoi(entry->d_name);
        if (base_irq < 0 || irq < base_irq)
            base_irq = irq;
    }
    closedir(dir);
    
    if (base_irq < 0)
        return -1;
    
    *irq_num = base_irq + queue;
    return 0;
}

/* Set IRQ affinity to specific CPU */
static int set_irq_affinity(int irq, uint32_t cpu)
{
    char path[256];
    FILE *fp;
    uint32_t mask;
    
    snprintf(path, sizeof(path), "/proc/irq/%d/smp_affinity", irq);
    
    fp = fopen(path, "w");
    if (!fp) {
        fprintf(stderr, "Failed to open %s (need root?)\n", path);
        return -1;
    }
    
    /* Set affinity mask (single CPU) */
    mask = 1 << cpu;
    fprintf(fp, "%x", mask);
    fclose(fp);
    
    return 0;
}

/* Clear IRQ affinity (restore default) */
static int clear_irq_affinity(int irq)
{
    char path[256];
    FILE *fp;
    
    snprintf(path, sizeof(path), "/proc/irq/%d/smp_affinity", irq);
    
    fp = fopen(path, "w");
    if (!fp)
        return -1;
    
    /* Set to all CPUs (0xFFFFFFFF for 32-core max) */
    fprintf(fp, "ffffffff");
    fclose(fp);
    
    return 0;
}

int nic_queue_probe(const char *ifname, struct nic_config *config)
{
    memset(config, 0, sizeof(*config));
    strncpy(config->ifname, ifname, sizeof(config->ifname) - 1);
    
    /* Query queue count */
    if (parse_ethtool_queues(ifname, &config->num_queues) < 0)
        return -1;
    
    /* Check if we have enough queues for isolation */
    if (config->num_queues < NIC_MIN_COMBINED_QUEUES) {
        fprintf(stderr, "Warning: %s has only %u queues (need %u for isolation)\n",
                ifname, config->num_queues, NIC_MIN_COMBINED_QUEUES);
        config->isolation_enabled = 0;
        return 0;
    }
    
    /* Set queue assignments */
    config->afxdp_queue = NIC_QUEUE_AFXDP;
    config->xdp_queue_start = NIC_QUEUE_XDP_MIN;
    config->xdp_queue_end = NIC_QUEUE_XDP_MAX < config->num_queues - 1 ?
                             NIC_QUEUE_XDP_MAX : config->num_queues - 1;
    
    /* Default: pin queue 0 to CPU 1 (avoid CPU 0 which often handles system tasks) */
    config->afxdp_cpu = 1;
    
    config->isolation_enabled = 1;
    
    return 0;
}

int nic_queue_setup_isolation(struct nic_config *config)
{
    if (!config->isolation_enabled) {
        printf("Queue isolation not enabled for %s (insufficient queues)\n",
               config->ifname);
        return 0;
    }
    
    printf("Setting up queue isolation for %s:\n", config->ifname);
    printf("  AF_XDP queue: %u (CPU %u)\n", 
           config->afxdp_queue, config->afxdp_cpu);
    printf("  XDP queues: %u-%u\n", 
           config->xdp_queue_start, config->xdp_queue_end);
    
    /* Get IRQ for AF_XDP queue */
    int irq;
    if (get_queue_irq(config->ifname, config->afxdp_queue, &irq) < 0) {
        fprintf(stderr, "Warning: Could not find IRQ for queue %u\n",
                config->afxdp_queue);
        fprintf(stderr, "Tip: Check /proc/interrupts or /sys/class/net/%s/device/msi_irqs/\n",
                config->ifname);
        fprintf(stderr, "Queue isolation enabled, but IRQ affinity not set\n");
        return 0;  /* Non-fatal */
    }
    
    printf("  Queue %u IRQ: %d\n", config->afxdp_queue, irq);
    
    /* Set IRQ affinity */
    if (set_irq_affinity(irq, config->afxdp_cpu) < 0) {
        fprintf(stderr, "Warning: Could not set IRQ affinity (need root)\n");
        return 0;  /* Non-fatal */
    }
    
    printf("  IRQ %d pinned to CPU %u\n", irq, config->afxdp_cpu);
    printf("Queue isolation configured successfully\n");
    
    return 0;
}

int nic_queue_restore_default(struct nic_config *config)
{
    if (!config->isolation_enabled)
        return 0;
    
    printf("Restoring default queue configuration for %s\n", config->ifname);
    
    int irq;
    if (get_queue_irq(config->ifname, config->afxdp_queue, &irq) < 0) {
        return 0;  /* Already warned during setup */
    }
    
    clear_irq_affinity(irq);
    printf("  IRQ %d affinity restored to default\n", irq);
    
    return 0;
}

void nic_queue_print_config(const struct nic_config *config)
{
    printf("NIC Queue Configuration: %s\n", config->ifname);
    printf("  Total queues: %u\n", config->num_queues);
    printf("  Isolation: %s\n", config->isolation_enabled ? "enabled" : "disabled");
    
    if (config->isolation_enabled) {
        printf("  AF_XDP queue: %u (CPU %u)\n",
               config->afxdp_queue, config->afxdp_cpu);
        printf("  XDP queues: %u-%u\n",
               config->xdp_queue_start, config->xdp_queue_end);
    }
}
