// SPDX-License-Identifier: GPL-2.0
/* Simplified Packet Parsing for rSwitch v1.1-dev
 * 
 * TEMPORARY: Minimal parsing to avoid BPF verifier complexity limits
 * 
 * Supported:
 *  - Ethernet
 *  - VLAN (single tag or double tag)
 *  - IPv4
 *  - TCP/UDP/ICMP
 * 
 * NOT supported (v1.2+):
 *  - IPv6
 *  - Complex protocol options
 * 
 * This parsing code is intentionally simple to keep instruction count low.
 */

#ifndef __RSWITCH_PARSING_SIMPLE_H
#define __RSWITCH_PARSING_SIMPLE_H

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "../core/uapi.h"

/* Ethernet protocols */
#ifndef ETH_P_IP
#define ETH_P_IP    0x0800
#endif
#ifndef ETH_P_8021Q
#define ETH_P_8021Q 0x8100
#endif
#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8
#endif

/* IP protocols */
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif
#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif

/* Network structures (minimal) */
struct ethhdr {
    __u8  h_dest[6];
    __u8  h_source[6];
    __be16 h_proto;
} __attribute__((packed));

struct vlanhdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
} __attribute__((packed));

struct iphdr {
    __u8   ihl:4,
           version:4;
    __u8   tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8   ttl;
    __u8   protocol;
    __be16 check;
    __be32 saddr;
    __be32 daddr;
} __attribute__((packed));

struct tcphdr {
    __be16 source;
    __be16 dest;
    __be32 seq;
    __be32 ack_seq;
    __u16  doff:4,
           res1:4,
           res2:2,
           urg:1,
           ack:1,
           psh:1,
           rst:1,
           syn:1,
           fin:1;
    __be16 window;
    __be16 check;
    __be16 urg_ptr;
} __attribute__((packed));

struct udphdr {
    __be16 source;
    __be16 dest;
    __be16 len;
    __be16 check;
} __attribute__((packed));

struct icmphdr {
    __u8 type;
    __u8 code;
    __be16 checksum;
    union {
        struct {
            __be16 id;
            __be16 sequence;
        } echo;
        __be32 gateway;
    } un;
} __attribute__((packed));

/* Simplified packet parsing - avoids complex loops */
static __always_inline int parse_packet_layers(struct xdp_md *ctx, struct rs_layers *layers)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    void *pos = data;
    
    struct ethhdr *eth;
    struct vlanhdr *vlan;
    struct iphdr *iph;
    __be16 eth_proto;
    __u8 vlan_depth = 0;
    
    /* Zero-initialize */
    __builtin_memset(layers, 0, sizeof(*layers));
    
    /* Parse Ethernet header */
    eth = pos;
    if ((void *)(eth + 1) > data_end)
        return -1;
    
    eth_proto = eth->h_proto;
    pos = (void *)(eth + 1);
    
    /* Parse VLAN tags (up to 2) */
    #pragma unroll
    for (int i = 0; i < 2; i++) {
        if (eth_proto == bpf_htons(ETH_P_8021Q) || eth_proto == bpf_htons(ETH_P_8021AD)) {
            vlan = pos;
            if ((void *)(vlan + 1) > data_end)
                return -1;
            
            if (vlan_depth < 2) {
                layers->vlan_ids[vlan_depth] = bpf_ntohs(vlan->h_vlan_TCI) & 0x0FFF;
            }
            vlan_depth++;
            
            eth_proto = vlan->h_vlan_encapsulated_proto;
            pos = (void *)(vlan + 1);
        } else {
            break;
        }
    }
    
    layers->vlan_depth = vlan_depth;
    layers->l3_offset = pos - data;
    
    /* Parse IPv4 only */
    if (eth_proto != bpf_htons(ETH_P_IP))
        return 0;  /* Not an error - just not IPv4 */
    
    iph = pos;
    if ((void *)(iph + 1) > data_end)
        return -1;
    
    /* Sanity check: version must be 4, IHL at least 5 */
    if (iph->version != 4 || iph->ihl < 5)
        return -1;
    
    layers->saddr = iph->saddr;
    layers->daddr = iph->daddr;
    layers->ip_proto = iph->protocol;
    
    /* Calculate actual IP header length */
    __u8 ihl_bytes = iph->ihl * 4;
    if (ihl_bytes > 60)  /* Max IP header size */
        return -1;
    
    pos = (void *)iph + ihl_bytes;
    if (pos > data_end)
        return -1;
    
    layers->l4_offset = pos - data;
    
    /* Parse L4 (TCP/UDP/ICMP) */
    if (layers->ip_proto == IPPROTO_TCP) {
        struct tcphdr *tcph = pos;
        if ((void *)(tcph + 1) > data_end)
            return 0;  /* Truncated */
        
        layers->sport = bpf_ntohs(tcph->source);
        layers->dport = bpf_ntohs(tcph->dest);
        
    } else if (layers->ip_proto == IPPROTO_UDP) {
        struct udphdr *udph = pos;
        if ((void *)(udph + 1) > data_end)
            return 0;
        
        layers->sport = bpf_ntohs(udph->source);
        layers->dport = bpf_ntohs(udph->dest);
        
    } else if (layers->ip_proto == IPPROTO_ICMP) {
        struct icmphdr *icmph = pos;
        if ((void *)(icmph + 1) > data_end)
            return 0;
        
        layers->sport = (icmph->type << 8) | icmph->code;
    }
    
    return 0;
}

#endif /* __RSWITCH_PARSING_SIMPLE_H */
