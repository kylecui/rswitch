// SPDX-License-Identifier: GPL-2.0
/*
 * rSwitch ARP Learning Module
 * 
 * Passively learns IP-MAC mappings from ARP traffic:
 * - ARP Replies: Learn sender IP→MAC
 * - ARP Requests: Learn sender IP→MAC (requester)
 * 
 * This populates the Route module's ARP table automatically,
 * eliminating the need for manual ARP entries or broadcast flooding.
 * 
 * Pipeline position: Stage 25 (after VLAN parsing, before ACL)
 */

#include "../include/rswitch_common.h"

char _license[] SEC("license") = "GPL";

/* Module metadata */
RS_DECLARE_MODULE("arp_learn", RS_HOOK_XDP_INGRESS, 25,
                  RS_FLAG_NEED_L2L3_PARSE,
                  "Passive ARP learning for route module");

/* ARP header structure */
struct arphdr_eth {
    __be16 ar_hrd;      /* Hardware type (1 = Ethernet) */
    __be16 ar_pro;      /* Protocol type (0x0800 = IPv4) */
    __u8   ar_hln;      /* Hardware address length (6) */
    __u8   ar_pln;      /* Protocol address length (4) */
    __be16 ar_op;       /* Operation (1=request, 2=reply) */
    __u8   ar_sha[6];   /* Sender hardware address */
    __be32 ar_sip;      /* Sender IP address */
    __u8   ar_tha[6];   /* Target hardware address */
    __be32 ar_tip;      /* Target IP address */
} __attribute__((packed));

#define ARPOP_REQUEST 1
#define ARPOP_REPLY   2

/* External ARP table from route module */
struct arp_entry {
    __u8 mac[6];
    __u8 pad[2];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __be32);        /* IP address (network byte order) */
    __type(value, struct arp_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} arp_tbl SEC(".maps");

/* Interface configuration from route module */
struct iface_config {
    __u8 mac[6];
    __u8 is_router;
    __u8 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, struct iface_config);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} iface_cfg SEC(".maps");

/* ARP learning statistics */
struct arp_learn_stats {
    __u64 arp_requests_seen;
    __u64 arp_replies_seen;
    __u64 entries_learned;
    __u64 entries_updated;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct arp_learn_stats);
} arp_learn_stats_map SEC(".maps");

/* Learn IP→MAC mapping from ARP packet */
static __always_inline int learn_arp_entry(__be32 ip, const __u8 *mac)
{
    struct arp_entry new_entry = {0};
    struct arp_entry *existing;
    
    /* Check if this is one of our router interfaces - don't learn our own MACs */
    #pragma unroll
    for (__u32 i = 0; i < 32; i++) {
        __u32 ifkey = i;
        struct iface_config *cfg = bpf_map_lookup_elem(&iface_cfg, &ifkey);
        if (!cfg || !cfg->is_router)
            continue;
        
        if (__builtin_memcmp(mac, cfg->mac, 6) == 0) {
            /* This is our own MAC, skip learning */
            return 0;
        }
    }
    
    /* Check if entry already exists */
    existing = bpf_map_lookup_elem(&arp_tbl, &ip);
    
    __builtin_memcpy(new_entry.mac, mac, 6);
    
    __u32 stats_key = 0;
    struct arp_learn_stats *stats = bpf_map_lookup_elem(&arp_learn_stats_map, &stats_key);
    
    if (existing) {
        /* Update existing entry if MAC changed */
        if (__builtin_memcmp(existing->mac, mac, 6) != 0) {
            bpf_map_update_elem(&arp_tbl, &ip, &new_entry, BPF_ANY);
            
            rs_debug("ARP Learn: Updated %pI4 -> %02x:%02x:%02x:%02x:%02x:%02x",
                     &ip, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            
            if (stats)
                __sync_fetch_and_add(&stats->entries_updated, 1);
        }
    } else {
        /* New entry */
        if (bpf_map_update_elem(&arp_tbl, &ip, &new_entry, BPF_ANY) == 0) {
            rs_debug("ARP Learn: Learned %pI4 -> %02x:%02x:%02x:%02x:%02x:%02x",
                     &ip, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            
            if (stats)
                __sync_fetch_and_add(&stats->entries_learned, 1);
        }
    }
    
    return 0;
}

SEC("xdp")
int arp_learn_ingress(struct xdp_md *xdp_ctx)
{
    void *data = (void *)(long)xdp_ctx->data;
    void *data_end = (void *)(long)xdp_ctx->data_end;
    
    /* Get context */
    struct rs_ctx *ctx = RS_GET_CTX();
    if (!ctx) {
        return XDP_PASS;
    }
    
    /* Only process ARP packets */
    if (ctx->layers.eth_proto != ETH_P_ARP) {
        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_PASS;
    }
    
    /* Verify L3 offset is valid */
    if (!ctx->layers.l3_offset) {
        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_PASS;
    }
    
    /* Parse ARP header */
    struct arphdr_eth *arp = data + (ctx->layers.l3_offset & RS_L3_OFFSET_MASK);
    if ((void *)(arp + 1) > data_end) {
        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_PASS;
    }
    
    /* Validate ARP header */
    if (bpf_ntohs(arp->ar_hrd) != 1 ||        /* Ethernet */
        bpf_ntohs(arp->ar_pro) != ETH_P_IP || /* IPv4 */
        arp->ar_hln != 6 ||                    /* MAC = 6 bytes */
        arp->ar_pln != 4) {                    /* IPv4 = 4 bytes */
        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_PASS;
    }
    
    __u16 ar_op = bpf_ntohs(arp->ar_op);
    __u32 stats_key = 0;
    struct arp_learn_stats *stats = bpf_map_lookup_elem(&arp_learn_stats_map, &stats_key);
    
    if (ar_op == ARPOP_REQUEST) {
        /* ARP Request: Learn sender (requester) */
        rs_debug("ARP Learn: Request for %pI4 from %pI4", &arp->ar_tip, &arp->ar_sip);
        
        if (stats)
            __sync_fetch_and_add(&stats->arp_requests_seen, 1);
        
        learn_arp_entry(arp->ar_sip, arp->ar_sha);
        
    } else if (ar_op == ARPOP_REPLY) {
        /* ARP Reply: Learn sender (replier) */
        rs_debug("ARP Learn: Reply %pI4 is-at %02x:%02x:%02x:%02x:%02x:%02x",
                 &arp->ar_sip,
                 arp->ar_sha[0], arp->ar_sha[1], arp->ar_sha[2],
                 arp->ar_sha[3], arp->ar_sha[4], arp->ar_sha[5]);
        
        if (stats)
            __sync_fetch_and_add(&stats->arp_replies_seen, 1);
        
        learn_arp_entry(arp->ar_sip, arp->ar_sha);
    }
    
    /* Continue to next module (ARP packets still need processing) */
    RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
    return XDP_PASS;
}
