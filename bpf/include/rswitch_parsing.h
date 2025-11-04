// SPDX-License-Identifier: GPL-2.0
/* Packet Parsing Adapter for rSwitch
 * 
 * Bridges the legacy parsing_helpers.h functions with the new rs_layers structure.
 * This allows reuse of proven parsing code while adapting to the new API.
 * 
 * CO-RE: Network types are provided by vmlinux.h via rswitch_bpf.h
 */

#ifndef __RSWITCH_PARSING_H
#define __RSWITCH_PARSING_H

/* TEMPORARY: Disable IPv6 to reduce BPF program size
 * IPv6 extension header parsing causes instruction count to exceed 1M limit
 * TODO (v1.2): Optimize IPv6 parsing or split into separate module
 */
#define RS_DISABLE_IPV6

/* Types and helpers from vmlinux.h (via rswitch_bpf.h included by rswitch_common.h) */
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "parsing_helpers.h"
#include "../core/uapi.h"

/* Parse packet and populate rs_layers structure
 * 
 * This function wraps the legacy extract_packet_layers() or uses
 * parsing_helpers.h functions to fill in the new rs_layers structure.
 * 
 * Returns:
 *   0 on success
 *  -1 on parsing failure (malformed packet)
 */
static __always_inline int parse_packet_layers(struct xdp_md *ctx, struct rs_layers *layers)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    /* Zero-initialize layers */
    __builtin_memset(layers, 0, sizeof(*layers));
    
    /* Start parsing from beginning of packet */
    struct hdr_cursor nh = { .pos = data };
    struct ethhdr *eth;
    struct iphdr *iph;
    struct ipv6hdr *ip6h;
    int eth_type, ip_type;
    __u16 vlan_depth = 0;
    
    /* Parse Ethernet header */
    eth_type = parse_ethhdr(&nh, data_end, &eth);
    if (eth_type < 0) {
        return -1;  /* Malformed Ethernet header */
    }
    
    /* Parse VLAN tags (support up to 2 levels as defined in rs_layers) */
    while (eth_type == bpf_htons(ETH_P_8021Q) || eth_type == bpf_htons(ETH_P_8021AD)) {
        struct vlan_hdr *vlan;
        
        /* Bounds check */
        if (nh.pos + sizeof(*vlan) > data_end)
            return -1;
        
        vlan = nh.pos;
        
        /* Extract VLAN ID (mask off priority bits) - support max 2 VLANs */
        if (vlan_depth < 2) {
            layers->vlan_ids[vlan_depth] = bpf_ntohs(vlan->h_vlan_TCI) & 0x0FFF;
            vlan_depth++;
        }
        
        /* Move to next header */
        eth_type = vlan->h_vlan_encapsulated_proto;
        nh.pos += sizeof(*vlan);
    }
    
    layers->vlan_depth = vlan_depth;
    layers->l3_offset = nh.pos - data;
    
    /* Parse L3 header based on ethertype */
    if (eth_type == bpf_htons(ETH_P_IP)) {
        /* IPv4 */
        ip_type = parse_iphdr(&nh, data_end, &iph);
        if (ip_type < 0)
            return -1;
        
        layers->saddr = iph->saddr;
        layers->daddr = iph->daddr;
        layers->ip_proto = iph->protocol;
        
#ifndef RS_DISABLE_IPV6
    } else if (eth_type == bpf_htons(ETH_P_IPV6)) {
        /* IPv6 */
        ip_type = parse_ip6hdr(&nh, data_end, &ip6h);
        if (ip_type < 0)
            return -1;
        
        /* For IPv6, store first 4 bytes of address
         * vmlinux.h defines in6_addr differently, use union access
         */
        #ifdef __BPF__
        /* CO-RE: Access IPv6 address bytes directly */
        __u32 *saddr_p = (__u32 *)&ip6h->saddr;
        __u32 *daddr_p = (__u32 *)&ip6h->daddr;
        layers->saddr = saddr_p[0];
        layers->daddr = daddr_p[0];
        #else
        layers->saddr = ip6h->saddr.s6_addr32[0];
        layers->daddr = ip6h->daddr.s6_addr32[0];
        #endif
        layers->ip_proto = ip6h->nexthdr;
#endif /* RS_DISABLE_IPV6 */
        
    } else if (eth_type == bpf_htons(ETH_P_ARP)) {
        /* ARP packet - no L4 */
        layers->ip_proto = 0;
        layers->l4_offset = 0;
        return 0;
        
    } else {
        /* Other L3 protocols (non-IP) - just record ethertype */
        layers->ip_proto = 0;
        layers->l4_offset = 0;
        return 0;
    }
    
    /* Parse L4 header */
    layers->l4_offset = nh.pos - data;
    
    if (layers->ip_proto == IPPROTO_TCP) {
        struct tcphdr *tcph;
        if (nh.pos + sizeof(*tcph) > data_end)
            return 0;  /* Not an error - just incomplete header */
        
        tcph = nh.pos;
        layers->sport = bpf_ntohs(tcph->source);
        layers->dport = bpf_ntohs(tcph->dest);
        
    } else if (layers->ip_proto == IPPROTO_UDP) {
        struct udphdr *udph;
        if (nh.pos + sizeof(*udph) > data_end)
            return 0;
        
        udph = nh.pos;
        layers->sport = bpf_ntohs(udph->source);
        layers->dport = bpf_ntohs(udph->dest);
        
    } else if (layers->ip_proto == IPPROTO_ICMP || layers->ip_proto == IPPROTO_ICMPV6) {
        struct icmphdr *icmph;
        if (nh.pos + sizeof(*icmph) > data_end)
            return 0;
        
        icmph = nh.pos;
        /* Store ICMP type/code in sport/dport for flow hashing */
        layers->sport = (icmph->type << 8) | icmph->code;
    }
    
    return 0;
}

#endif /* __RSWITCH_PARSING_H */
