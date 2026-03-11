// SPDX-License-Identifier: GPL-2.0
/* 
 * rsvlanctl - rSwitch VLAN Management Tool
 * 
 * Manage VLAN database and port membership.
 * 
 * Usage:
 *   rsvlanctl list
 *   rsvlanctl show <vlan_id>
 *   rsvlanctl create <vlan_id>
 *   rsvlanctl delete <vlan_id>
 *   rsvlanctl add-port <vlan_id> <ifname> [tagged|untagged]
 *   rsvlanctl del-port <vlan_id> <ifname>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#if __has_include("rs_log.h")
#include "rs_log.h"
#else
#include "../common/rs_log.h"
#endif
#include <bpf/bpf.h>

#define PIN_PATH "/sys/fs/bpf"
#define MAX_VLANS 4096

enum rs_vlan_mode {
    RS_VLAN_MODE_OFF = 0,
    RS_VLAN_MODE_ACCESS = 1,
    RS_VLAN_MODE_TRUNK = 2,
    RS_VLAN_MODE_HYBRID = 3,
    RS_VLAN_MODE_QINQ = 4
};

struct rs_port_config {
    __u32 ifindex;
    __u8  enabled;
    __u8  mgmt_type;
    __u8  vlan_mode;
    __u8  learning;

    __u16 pvid;
    __u16 native_vlan;
    __u16 access_vlan;
    __u16 allowed_vlan_count;
    __u16 allowed_vlans[128];
    __u16 tagged_vlan_count;
    __u16 tagged_vlans[64];
    __u16 untagged_vlan_count;
    __u16 untagged_vlans[64];

    __u8  default_prio;
    __u8  trust_dscp;
    __u16 rate_limit_kbps;

    __u8  port_security;
    __u8  max_macs;
    __u16 reserved;

    __u32 reserved2[4];
};

struct rs_qinq_config {
    __u16 s_vlan;
    __u16 c_vlan_start;
    __u16 c_vlan_end;
    __u16 pad;
};

struct rs_vlan_members {
    __u16 vlan_id;
    __u16 member_count;
    __u64 tagged_members[4];
    __u64 untagged_members[4];
    __u32 reserved[4];
};

static int open_vlan_map(void)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/rs_vlan_map", PIN_PATH);
    
    int fd = bpf_obj_get(path);
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open %s: %s", path, strerror(errno));
        RS_LOG_ERROR("Is rSwitch loader running?");
        return -1;
    }
    return fd;
}

static int open_port_config_map(void)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/rs_port_config_map", PIN_PATH);

    int fd = bpf_obj_get(path);
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open %s: %s", path, strerror(errno));
        RS_LOG_ERROR("Is rSwitch loader running?");
        return -1;
    }
    return fd;
}

static int open_qinq_map(void)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/qinq_config_map", PIN_PATH);

    int fd = bpf_obj_get(path);
    if (fd < 0) {
        RS_LOG_ERROR("Failed to open %s: %s", path, strerror(errno));
        RS_LOG_ERROR("Is rSwitch loader running?");
        return -1;
    }
    return fd;
}

static void print_port_list(__u64 *bitmap, int total_count)
{
    int first = 1;
    for (int word = 0; word < 4; word++) {
        for (int bit = 0; bit < 64; bit++) {
            if (bitmap[word] & (1ULL << bit)) {
                __u32 ifindex = word * 64 + bit + 1;
                char ifname[IF_NAMESIZE];
                if (if_indextoname(ifindex, ifname)) {
                    if (!first) printf(", ");
                    printf("%s(ifindex=%u)", ifname, ifindex);
                    first = 0;
                }
            }
        }
    }
    if (first) printf("none");
    printf("\n");
}

static int count_members(__u64 *bitmap)
{
    int count = 0;
    for (int word = 0; word < 4; word++) {
        __u64 val = bitmap[word];
        while (val) {
            count += val & 1;
            val >>= 1;
        }
    }
    return count;
}

static int cmd_list(int map_fd)
{
    __u16 vlan_id = 0;
    __u16 next_vlan;
    int found = 0;
    
    printf("VLAN Database:\n");
    printf("%-6s %-8s %-8s %s\n", "VLAN", "Tagged", "Untagged", "Total");
    printf("--------------------------------------------------------------\n");
    
    /* Iterate all VLANs */
    while (bpf_map_get_next_key(map_fd, &vlan_id, &next_vlan) == 0) {
        struct rs_vlan_members members;
        if (bpf_map_lookup_elem(map_fd, &next_vlan, &members) == 0) {
            int tagged = count_members(members.tagged_members);
            int untagged = count_members(members.untagged_members);
            printf("%-6u %-8d %-8d %d\n", next_vlan, tagged, untagged, tagged + untagged);
            found++;
        }
        vlan_id = next_vlan;
    }
    
    if (!found) {
        printf("No VLANs configured\n");
    } else {
        printf("\nTotal VLANs: %d\n", found);
    }
    
    return 0;
}

static int cmd_show(int map_fd, __u16 vlan_id)
{
    struct rs_vlan_members members;
    
    if (bpf_map_lookup_elem(map_fd, &vlan_id, &members) < 0) {
        RS_LOG_ERROR("VLAN %u not found", vlan_id);
        return 1;
    }
    
    printf("VLAN %u:\n", vlan_id);
    printf("  Member count: %u\n", members.member_count);
    printf("  Tagged ports: ");
    print_port_list(members.tagged_members, members.member_count);
    printf("  Untagged ports: ");
    print_port_list(members.untagged_members, members.member_count);
    
    return 0;
}

static int cmd_create(int map_fd, __u16 vlan_id)
{
    struct rs_vlan_members members;
    
    if (vlan_id < 1 || vlan_id > 4094) {
        RS_LOG_ERROR("Invalid VLAN ID: %u (must be 1-4094)", vlan_id);
        return 1;
    }
    
    /* Check if already exists */
    if (bpf_map_lookup_elem(map_fd, &vlan_id, &members) == 0) {
        RS_LOG_ERROR("VLAN %u already exists", vlan_id);
        return 1;
    }
    
    /* Create empty VLAN */
    memset(&members, 0, sizeof(members));
    members.vlan_id = vlan_id;
    members.member_count = 0;
    
    if (bpf_map_update_elem(map_fd, &vlan_id, &members, BPF_NOEXIST) < 0) {
        RS_LOG_ERROR("Failed to create VLAN %u: %s", vlan_id, strerror(errno));
        return 1;
    }
    
    printf("Created VLAN %u\n", vlan_id);
    return 0;
}

static int cmd_delete(int map_fd, __u16 vlan_id)
{
    if (vlan_id == 1) {
        RS_LOG_ERROR("Cannot delete default VLAN 1");
        return 1;
    }
    
    if (bpf_map_delete_elem(map_fd, &vlan_id) < 0) {
        RS_LOG_ERROR("Failed to delete VLAN %u: %s", vlan_id, strerror(errno));
        return 1;
    }
    
    printf("Deleted VLAN %u\n", vlan_id);
    return 0;
}

static int cmd_add_port(int map_fd, __u16 vlan_id, const char *ifname, int tagged)
{
    struct rs_vlan_members members;
    __u32 ifindex;
    
    ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        RS_LOG_ERROR("Interface %s not found", ifname);
        return 1;
    }
    
    /* Lookup VLAN */
    if (bpf_map_lookup_elem(map_fd, &vlan_id, &members) < 0) {
        RS_LOG_ERROR("VLAN %u not found. Create it first with: rsvlanctl create %u", vlan_id, vlan_id);
        return 1;
    }
    
    /* Calculate bitmask position */
    int word_idx = (ifindex - 1) / 64;
    int bit_idx = (ifindex - 1) % 64;
    
    if (word_idx >= 4) {
        RS_LOG_ERROR("Interface index %u out of range", ifindex);
        return 1;
    }
    
    __u64 bit_mask = 1ULL << bit_idx;
    
    /* Add to appropriate member list */
    if (tagged) {
        if (members.tagged_members[word_idx] & bit_mask) {
            RS_LOG_ERROR("Port %s already a tagged member of VLAN %u", ifname, vlan_id);
            return 1;
        }
        members.tagged_members[word_idx] |= bit_mask;
    } else {
        if (members.untagged_members[word_idx] & bit_mask) {
            RS_LOG_ERROR("Port %s already an untagged member of VLAN %u", ifname, vlan_id);
            return 1;
        }
        members.untagged_members[word_idx] |= bit_mask;
    }
    
    members.member_count++;
    
    /* Update map */
    if (bpf_map_update_elem(map_fd, &vlan_id, &members, BPF_EXIST) < 0) {
        RS_LOG_ERROR("Failed to update VLAN %u: %s", vlan_id, strerror(errno));
        return 1;
    }
    
    printf("Added %s as %s member to VLAN %u\n", ifname, 
           tagged ? "tagged" : "untagged", vlan_id);
    return 0;
}

static int cmd_del_port(int map_fd, __u16 vlan_id, const char *ifname)
{
    struct rs_vlan_members members;
    __u32 ifindex;
    
    ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        RS_LOG_ERROR("Interface %s not found", ifname);
        return 1;
    }
    
    /* Lookup VLAN */
    if (bpf_map_lookup_elem(map_fd, &vlan_id, &members) < 0) {
        RS_LOG_ERROR("VLAN %u not found", vlan_id);
        return 1;
    }
    
    /* Calculate bitmask position */
    int word_idx = (ifindex - 1) / 64;
    int bit_idx = (ifindex - 1) % 64;
    __u64 bit_mask = 1ULL << bit_idx;
    
    /* Remove from both lists */
    int removed = 0;
    if (members.tagged_members[word_idx] & bit_mask) {
        members.tagged_members[word_idx] &= ~bit_mask;
        removed = 1;
    }
    if (members.untagged_members[word_idx] & bit_mask) {
        members.untagged_members[word_idx] &= ~bit_mask;
        removed = 1;
    }
    
    if (!removed) {
        RS_LOG_ERROR("Port %s is not a member of VLAN %u", ifname, vlan_id);
        return 1;
    }
    
    members.member_count--;
    
    /* Update map */
    if (bpf_map_update_elem(map_fd, &vlan_id, &members, BPF_EXIST) < 0) {
        RS_LOG_ERROR("Failed to update VLAN %u: %s", vlan_id, strerror(errno));
        return 1;
    }
    
    printf("Removed %s from VLAN %u\n", ifname, vlan_id);
    return 0;
}

static int parse_vlan_id(const char *str, __u16 *vlan)
{
    long val;
    char *end = NULL;

    errno = 0;
    val = strtol(str, &end, 10);
    if (errno != 0 || end == str || *end != '\0' || val < 1 || val > 4094)
        return -1;

    *vlan = (__u16)val;
    return 0;
}

static int parse_vlan_range(const char *range, __u16 *start, __u16 *end)
{
    const char *dash = strchr(range, '-');
    char start_buf[16];
    char end_buf[16];
    size_t start_len;
    size_t end_len;

    if (!dash)
        return -1;

    start_len = (size_t)(dash - range);
    end_len = strlen(dash + 1);
    if (start_len == 0 || end_len == 0 || start_len >= sizeof(start_buf) || end_len >= sizeof(end_buf))
        return -1;

    memcpy(start_buf, range, start_len);
    start_buf[start_len] = '\0';
    memcpy(end_buf, dash + 1, end_len);
    end_buf[end_len] = '\0';

    if (parse_vlan_id(start_buf, start) < 0 || parse_vlan_id(end_buf, end) < 0)
        return -1;
    if (*start > *end)
        return -1;

    return 0;
}

static int cmd_set_qinq(const char *ifname, __u16 s_vlan, __u16 c_start, __u16 c_end)
{
    int qinq_fd = -1;
    int port_fd = -1;
    __u32 ifindex;
    struct rs_qinq_config qcfg = {0};
    struct rs_port_config pcfg;

    ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        RS_LOG_ERROR("Interface %s not found", ifname);
        return 1;
    }

    qinq_fd = open_qinq_map();
    if (qinq_fd < 0)
        return 1;

    port_fd = open_port_config_map();
    if (port_fd < 0) {
        close(qinq_fd);
        return 1;
    }

    if (bpf_map_lookup_elem(port_fd, &ifindex, &pcfg) < 0) {
        RS_LOG_ERROR("Port %s not configured in rSwitch", ifname);
        close(port_fd);
        close(qinq_fd);
        return 1;
    }

    qcfg.s_vlan = s_vlan;
    qcfg.c_vlan_start = c_start;
    qcfg.c_vlan_end = c_end;

    if (bpf_map_update_elem(qinq_fd, &ifindex, &qcfg, BPF_ANY) < 0) {
        RS_LOG_ERROR("Failed to update QinQ config for %s: %s", ifname, strerror(errno));
        close(port_fd);
        close(qinq_fd);
        return 1;
    }

    pcfg.vlan_mode = RS_VLAN_MODE_QINQ;
    if (bpf_map_update_elem(port_fd, &ifindex, &pcfg, BPF_EXIST) < 0) {
        RS_LOG_ERROR("Failed to set QinQ VLAN mode for %s: %s", ifname, strerror(errno));
        close(port_fd);
        close(qinq_fd);
        return 1;
    }

    printf("Configured QinQ on %s (ifindex=%u): S-VLAN=%u, C-VLAN range=%u-%u\n",
           ifname, ifindex, s_vlan, c_start, c_end);

    close(port_fd);
    close(qinq_fd);
    return 0;
}

static int cmd_show_qinq(void)
{
    int qinq_fd;
    __u32 key;
    __u32 next_key;
    int found = 0;

    qinq_fd = open_qinq_map();
    if (qinq_fd < 0)
        return 1;

    printf("QinQ Configuration:\n");
    printf("%-16s %-8s %-8s %-12s\n", "Interface", "Ifindex", "S-VLAN", "C-VLAN Range");
    printf("--------------------------------------------------------------\n");

    if (bpf_map_get_next_key(qinq_fd, NULL, &next_key) == 0) {
        while (1) {
            struct rs_qinq_config qcfg;
            char ifname[IF_NAMESIZE] = {0};

            if (bpf_map_lookup_elem(qinq_fd, &next_key, &qcfg) == 0) {
                if (!if_indextoname(next_key, ifname))
                    snprintf(ifname, sizeof(ifname), "ifindex-%u", next_key);
                printf("%-16s %-8u %-8u %u-%u\n",
                       ifname, next_key, qcfg.s_vlan, qcfg.c_vlan_start, qcfg.c_vlan_end);
                found++;
            }

            key = next_key;
            if (bpf_map_get_next_key(qinq_fd, &key, &next_key) < 0)
                break;
        }
    }

    if (!found)
        printf("No QinQ ports configured\n");
    else
        printf("\nTotal QinQ ports: %d\n", found);

    close(qinq_fd);
    return 0;
}

static int cmd_del_qinq(const char *ifname)
{
    int qinq_fd = -1;
    int port_fd = -1;
    __u32 ifindex;
    struct rs_port_config pcfg;

    ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        RS_LOG_ERROR("Interface %s not found", ifname);
        return 1;
    }

    qinq_fd = open_qinq_map();
    if (qinq_fd < 0)
        return 1;

    if (bpf_map_delete_elem(qinq_fd, &ifindex) < 0) {
        RS_LOG_ERROR("Failed to delete QinQ config for %s: %s", ifname, strerror(errno));
        close(qinq_fd);
        return 1;
    }

    port_fd = open_port_config_map();
    if (port_fd >= 0 && bpf_map_lookup_elem(port_fd, &ifindex, &pcfg) == 0) {
        pcfg.vlan_mode = RS_VLAN_MODE_OFF;
        bpf_map_update_elem(port_fd, &ifindex, &pcfg, BPF_EXIST);
        close(port_fd);
    }

    printf("Removed QinQ config from %s (ifindex=%u)\n", ifname, ifindex);
    close(qinq_fd);
    return 0;
}

static void usage(const char *prog)
{
    fprintf(stderr, "rSwitch VLAN Management Tool\n\n");
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  %s list\n", prog);
    fprintf(stderr, "  %s show <vlan_id>\n", prog);
    fprintf(stderr, "  %s create <vlan_id>\n", prog);
    fprintf(stderr, "  %s delete <vlan_id>\n", prog);
    fprintf(stderr, "  %s add-port <vlan_id> <ifname> [tagged|untagged]\n", prog);
    fprintf(stderr, "  %s del-port <vlan_id> <ifname>\n", prog);
    fprintf(stderr, "  %s set-qinq <ifname> --s-vlan <id> --c-vlan-range <start>-<end>\n", prog);
    fprintf(stderr, "  %s show-qinq\n", prog);
    fprintf(stderr, "  %s del-qinq <ifname>\n", prog);
    fprintf(stderr, "\nExamples:\n");
    fprintf(stderr, "  %s list\n", prog);
    fprintf(stderr, "  %s create 10\n", prog);
    fprintf(stderr, "  %s add-port 10 ens34 untagged\n", prog);
    fprintf(stderr, "  %s add-port 10 ens35 tagged\n", prog);
    fprintf(stderr, "  %s show 10\n", prog);
    fprintf(stderr, "  %s set-qinq ens35 --s-vlan 200 --c-vlan-range 10-200\n", prog);
    fprintf(stderr, "  %s show-qinq\n", prog);
}

int main(int argc, char **argv)
{
    rs_log_init("rsvlanctl", RS_LOG_LEVEL_INFO);

    int map_fd = -1;
    int ret;
    
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }
    
    const char *cmd = argv[1];

    if (strcmp(cmd, "show-qinq") == 0) {
        return cmd_show_qinq();
    } else if (strcmp(cmd, "del-qinq") == 0 && argc >= 3) {
        return cmd_del_qinq(argv[2]);
    } else if (strcmp(cmd, "set-qinq") == 0 && argc >= 7) {
        __u16 s_vlan = 0;
        __u16 c_start = 0;
        __u16 c_end = 0;

        if (strcmp(argv[3], "--s-vlan") != 0 || strcmp(argv[5], "--c-vlan-range") != 0) {
            usage(argv[0]);
            return 1;
        }

        if (parse_vlan_id(argv[4], &s_vlan) < 0) {
            RS_LOG_ERROR("Invalid --s-vlan value: %s", argv[4]);
            return 1;
        }

        if (parse_vlan_range(argv[6], &c_start, &c_end) < 0) {
            RS_LOG_ERROR("Invalid --c-vlan-range value: %s", argv[6]);
            return 1;
        }

        return cmd_set_qinq(argv[2], s_vlan, c_start, c_end);
    }

    map_fd = open_vlan_map();
    if (map_fd < 0)
        return 1;
    
    if (strcmp(cmd, "list") == 0) {
        ret = cmd_list(map_fd);
    } else if (strcmp(cmd, "show") == 0 && argc >= 3) {
        ret = cmd_show(map_fd, atoi(argv[2]));
    } else if (strcmp(cmd, "create") == 0 && argc >= 3) {
        ret = cmd_create(map_fd, atoi(argv[2]));
    } else if (strcmp(cmd, "delete") == 0 && argc >= 3) {
        ret = cmd_delete(map_fd, atoi(argv[2]));
    } else if (strcmp(cmd, "add-port") == 0 && argc >= 4) {
        int tagged = 0;
        if (argc >= 5 && strcmp(argv[4], "tagged") == 0)
            tagged = 1;
        ret = cmd_add_port(map_fd, atoi(argv[2]), argv[3], tagged);
    } else if (strcmp(cmd, "del-port") == 0 && argc >= 4) {
        ret = cmd_del_port(map_fd, atoi(argv[2]), argv[3]);
    } else {
        usage(argv[0]);
        ret = 1;
    }
    
    close(map_fd);
    return ret;
}
