// SPDX-License-Identifier: GPL-2.0
/* rSwitch Packet Trace Utility
 * 
 * Dumps parsed packet information from rs_ctx_map for debugging.
 * Shows L2/L3/L4 fields parsed by dispatcher.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define RS_VLAN_MAX_DEPTH 2

struct rs_layers {
    __u16 eth_proto;
    __u16 vlan_ids[RS_VLAN_MAX_DEPTH];
    
    __u8  vlan_depth;
    __u8  ip_proto;
    __u8  pad[2];
    
    __u32 saddr;  // network byte order
    __u32 daddr;
    
    __u16 sport;  // network byte order
    __u16 dport;
    
    __u16 l2_offset;
    __u16 l3_offset;
    __u16 l4_offset;
    __u16 payload_offset;
    __u32 payload_len;
};

struct rs_ctx {
    __u32 ifindex;
    __u32 timestamp;
    
    __u8  parsed;
    __u8  modified;
    __u8  pad[2];
    struct rs_layers layers;
    
    __u16 ingress_vlan;
    __u16 egress_vlan;
    
    __u8  prio;
    __u8  dscp;
    __u8  ecn;
    __u8  traffic_class;
    
    __u32 egress_ifindex;
    __u8  action;
    __u8  mirror;
    __u16 mirror_port;
    
    __u32 error;
    __u32 drop_reason;
};

static const char *proto_name(__u8 proto)
{
    switch (proto) {
    case 1: return "ICMP";
    case 6: return "TCP";
    case 17: return "UDP";
    case 47: return "GRE";
    case 50: return "ESP";
    case 51: return "AH";
    default: return "Unknown";
    }
}

static const char *eth_proto_name(__u16 proto)
{
    switch (proto) {
    case 0x0800: return "IPv4";
    case 0x0806: return "ARP";
    case 0x86DD: return "IPv6";
    case 0x8100: return "802.1Q";
    default: return "Unknown";
    }
}

int main(int argc, char **argv)
{
    int map_fd;
    __u32 key = 0;  // per-CPU map key
    struct rs_ctx ctx;
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    int num_cpus = libbpf_num_possible_cpus();
    struct rs_ctx *values = NULL;
    int pkt_count = 0;
    
    /* Open rs_ctx_map */
    map_fd = bpf_obj_get("/sys/fs/bpf/rs_ctx_map");
    if (map_fd < 0) {
        fprintf(stderr, "Failed to open rs_ctx_map: %s\n", strerror(errno));
        fprintf(stderr, "Make sure rSwitch is loaded.\n");
        return 1;
    }
    
    /* Allocate per-CPU value array */
    values = calloc(num_cpus, sizeof(struct rs_ctx));
    if (!values) {
        fprintf(stderr, "Failed to allocate memory\n");
        close(map_fd);
        return 1;
    }
    
    printf("rSwitch Packet Trace - Monitoring %d CPUs\n", num_cpus);
    printf("Press Ctrl+C to exit\n");
    printf("=========================================\n\n");
    
    while (1) {
        /* Read per-CPU values */
        if (bpf_map_lookup_elem(map_fd, &key, values) == 0) {
            /* Check each CPU's context */
            for (int cpu = 0; cpu < num_cpus; cpu++) {
                ctx = values[cpu];
                
                /* Skip if not parsed */
                if (!ctx.parsed || ctx.ifindex == 0) {
                    continue;
                }
                
                pkt_count++;
                
                printf("\n[%d] Packet on ifindex %u (CPU %d, ts=%u) ---\n", 
                       pkt_count, ctx.ifindex, cpu, ctx.timestamp);
                printf("Ethernet: proto=%s (0x%04x)\n", 
                       eth_proto_name(ctx.layers.eth_proto), ctx.layers.eth_proto);
                
                if (ctx.layers.vlan_depth > 0) {
                    printf("VLAN: depth=%u, IDs=[", ctx.layers.vlan_depth);
                    for (int i = 0; i < ctx.layers.vlan_depth && i < RS_VLAN_MAX_DEPTH; i++) {
                        printf("%s%u", i > 0 ? ", " : "", ctx.layers.vlan_ids[i]);
                    }
                    printf("]\n");
                }
                
                if (ctx.layers.eth_proto == 0x0800 && ctx.layers.saddr != 0) {
                    inet_ntop(AF_INET, &ctx.layers.saddr, src_ip, sizeof(src_ip));
                    inet_ntop(AF_INET, &ctx.layers.daddr, dst_ip, sizeof(dst_ip));
                    
                    printf("IPv4: %s → %s, proto=%s (%u)\n",
                           src_ip, dst_ip, proto_name(ctx.layers.ip_proto), ctx.layers.ip_proto);
                    printf("      DSCP=%u, ECN=%u\n", ctx.dscp, ctx.ecn);
                    
                    if (ctx.layers.ip_proto == 6 || ctx.layers.ip_proto == 17) {
                        printf("Ports: %u → %u\n", 
                               ntohs(ctx.layers.sport), ntohs(ctx.layers.dport));
                    }
                    
                    printf("Offsets: L2=%u, L3=%u, L4=%u, Payload=%u (len=%u)\n",
                           ctx.layers.l2_offset, ctx.layers.l3_offset, 
                           ctx.layers.l4_offset, ctx.layers.payload_offset,
                           ctx.layers.payload_len);
                }
                
                printf("QoS: prio=%u\n", ctx.prio);
                printf("Forwarding: ingress_vlan=%u, egress_ifindex=%u\n",
                       ctx.ingress_vlan, ctx.egress_ifindex);
            }
        }
        
        usleep(50000);  // 50ms polling interval
    }
    
    free(values);
    close(map_fd);
    return 0;
}
