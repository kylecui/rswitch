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
#include <bpf/bpf.h>

#define PIN_PATH "/sys/fs/bpf"
#define MAX_VLANS 4096

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
        fprintf(stderr, "Failed to open %s: %s\n", path, strerror(errno));
        fprintf(stderr, "Is rSwitch loader running?\n");
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
        fprintf(stderr, "VLAN %u not found\n", vlan_id);
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
        fprintf(stderr, "Invalid VLAN ID: %u (must be 1-4094)\n", vlan_id);
        return 1;
    }
    
    /* Check if already exists */
    if (bpf_map_lookup_elem(map_fd, &vlan_id, &members) == 0) {
        fprintf(stderr, "VLAN %u already exists\n", vlan_id);
        return 1;
    }
    
    /* Create empty VLAN */
    memset(&members, 0, sizeof(members));
    members.vlan_id = vlan_id;
    members.member_count = 0;
    
    if (bpf_map_update_elem(map_fd, &vlan_id, &members, BPF_NOEXIST) < 0) {
        fprintf(stderr, "Failed to create VLAN %u: %s\n", vlan_id, strerror(errno));
        return 1;
    }
    
    printf("Created VLAN %u\n", vlan_id);
    return 0;
}

static int cmd_delete(int map_fd, __u16 vlan_id)
{
    if (vlan_id == 1) {
        fprintf(stderr, "Cannot delete default VLAN 1\n");
        return 1;
    }
    
    if (bpf_map_delete_elem(map_fd, &vlan_id) < 0) {
        fprintf(stderr, "Failed to delete VLAN %u: %s\n", vlan_id, strerror(errno));
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
        fprintf(stderr, "Interface %s not found\n", ifname);
        return 1;
    }
    
    /* Lookup VLAN */
    if (bpf_map_lookup_elem(map_fd, &vlan_id, &members) < 0) {
        fprintf(stderr, "VLAN %u not found. Create it first with: rsvlanctl create %u\n", 
                vlan_id, vlan_id);
        return 1;
    }
    
    /* Calculate bitmask position */
    int word_idx = (ifindex - 1) / 64;
    int bit_idx = (ifindex - 1) % 64;
    
    if (word_idx >= 4) {
        fprintf(stderr, "Interface index %u out of range\n", ifindex);
        return 1;
    }
    
    __u64 bit_mask = 1ULL << bit_idx;
    
    /* Add to appropriate member list */
    if (tagged) {
        if (members.tagged_members[word_idx] & bit_mask) {
            fprintf(stderr, "Port %s already a tagged member of VLAN %u\n", ifname, vlan_id);
            return 1;
        }
        members.tagged_members[word_idx] |= bit_mask;
    } else {
        if (members.untagged_members[word_idx] & bit_mask) {
            fprintf(stderr, "Port %s already an untagged member of VLAN %u\n", ifname, vlan_id);
            return 1;
        }
        members.untagged_members[word_idx] |= bit_mask;
    }
    
    members.member_count++;
    
    /* Update map */
    if (bpf_map_update_elem(map_fd, &vlan_id, &members, BPF_EXIST) < 0) {
        fprintf(stderr, "Failed to update VLAN %u: %s\n", vlan_id, strerror(errno));
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
        fprintf(stderr, "Interface %s not found\n", ifname);
        return 1;
    }
    
    /* Lookup VLAN */
    if (bpf_map_lookup_elem(map_fd, &vlan_id, &members) < 0) {
        fprintf(stderr, "VLAN %u not found\n", vlan_id);
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
        fprintf(stderr, "Port %s is not a member of VLAN %u\n", ifname, vlan_id);
        return 1;
    }
    
    members.member_count--;
    
    /* Update map */
    if (bpf_map_update_elem(map_fd, &vlan_id, &members, BPF_EXIST) < 0) {
        fprintf(stderr, "Failed to update VLAN %u: %s\n", vlan_id, strerror(errno));
        return 1;
    }
    
    printf("Removed %s from VLAN %u\n", ifname, vlan_id);
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
    fprintf(stderr, "\nExamples:\n");
    fprintf(stderr, "  %s list\n", prog);
    fprintf(stderr, "  %s create 10\n", prog);
    fprintf(stderr, "  %s add-port 10 ens34 untagged\n", prog);
    fprintf(stderr, "  %s add-port 10 ens35 tagged\n", prog);
    fprintf(stderr, "  %s show 10\n", prog);
}

int main(int argc, char **argv)
{
    int map_fd;
    int ret;
    
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }
    
    map_fd = open_vlan_map();
    if (map_fd < 0)
        return 1;
    
    const char *cmd = argv[1];
    
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
