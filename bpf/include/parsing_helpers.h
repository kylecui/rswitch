/* SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-clause) */
/*
 * This file contains parsing functions that can be used in eXDP programs. The
 * functions are marked as __always_inline, and fully defined in this header
 * file to be included in the BPF program.
 *
 * Each helper parses a packet header, including doing bounds checking, and
 * returns the type of its contents if successful, and -1 otherwise.
 *
 * For Ethernet and IP headers, the content type is the type of the payload
 * (h_proto for Ethernet, nexthdr for IPv6), for ICMP it is the ICMP type field.
 * All return values are in host byte order.
 */

#ifndef __PARSING_HELPERS_H
#define __PARSING_HELPERS_H

/* Don't include stddef.h for BPF - vmlinux.h provides types */
#ifndef __BPF__
#include <stddef.h>
#endif

/* BPF programs use vmlinux.h types, user-space uses kernel headers */
#ifndef __BPF__
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/if_arp.h>
#else
/* Constants not always in vmlinux.h */
#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif
#ifndef IPPROTO_HOPOPTS
#define IPPROTO_HOPOPTS 0
#endif
#ifndef IPPROTO_ROUTING
#define IPPROTO_ROUTING 43
#endif
#ifndef IPPROTO_FRAGMENT
#define IPPROTO_FRAGMENT 44
#endif
#ifndef IPPROTO_DSTOPTS
#define IPPROTO_DSTOPTS 60
#endif
#ifndef IPPROTO_MH
#define IPPROTO_MH 135
#endif
#endif
#include <bpf/bpf_endian.h>

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};

/* VLAN header - only define for user-space (BPF gets it from vmlinux.h) */
#ifndef __BPF__
struct vlan_hdr {
	__be16	h_vlan_TCI;
	__be16	h_vlan_encapsulated_proto;
};
#endif

/*
 * Struct icmphdr_common represents the common part of the icmphdr and icmp6hdr
 * structures.
 */
struct icmphdr_common {
	__u8	type;
	__u8	code;
	__sum16	cksum;
};


struct arp_info {
    __be16 htype;   // 硬件类型（通常为 1，即 Ethernet）
    __be16 ptype;   // 协议类型（通常为 ETH_P_IP）
    __u8 hlen;      // 硬件地址长度（MAC 长度 = 6）
    __u8 plen;      // 协议地址长度（IP 长度 = 4）
    __be16 oper;    // 操作码（ARP 请求 = 1，ARP 回复 = 2）
    __u8 sha[ETH_ALEN]; // 发送方 MAC 地址
    __be32 sip;     // 发送方 IP 地址
    __u8 tha[ETH_ALEN]; // 目标 MAC 地址
    __be32 tip;     // 目标 IP 地址
};

/**
 * 解析 ARP 头部，并提取关键信息
 * @param nh       - 头部游标（hdr_cursor）
 * @param data_end - 数据包结束指针
 * @param info     - 用于存储解析后的 ARP 信息
 * @return         - 成功返回 0，失败返回 -1
 */
static __always_inline int parse_arphdr(struct hdr_cursor *nh, void *data_end, struct arp_info *info) {
    struct arphdr *arp;

    if ((void *)(nh->pos + sizeof(struct arphdr)) > data_end)
        return -1;

    arp = (struct arphdr *)nh->pos;

    // 解析 ARP 头部
    info->htype = arp->ar_hrd; // 硬件类型
    info->ptype = arp->ar_pro; // 协议类型
    info->hlen  = arp->ar_hln; // 硬件地址长度
    info->plen  = arp->ar_pln; // 协议地址长度
    info->oper  = arp->ar_op;  // ARP 操作码

    // 确保硬件地址和协议地址长度符合 Ethernet + IPv4
    if (info->hlen != ETH_ALEN || info->plen != 4)
        return -1;

    // 解析 SHA、SIP、THA、TIP
    if ((void *)(nh->pos + sizeof(struct arphdr) + 2 * ETH_ALEN + 2 * sizeof(__be32)) > data_end)
        return -1;

    __u8 *arp_payload = (__u8 *)(nh->pos + sizeof(struct arphdr));

    __builtin_memcpy(info->sha, arp_payload, ETH_ALEN);
    __builtin_memcpy(&info->sip, arp_payload + ETH_ALEN, sizeof(__be32));
    __builtin_memcpy(info->tha, arp_payload + ETH_ALEN + sizeof(__be32), ETH_ALEN);
    __builtin_memcpy(&info->tip, arp_payload + 2 * ETH_ALEN + sizeof(__be32), sizeof(__be32));

    // 更新游标位置
    nh->pos += sizeof(struct arphdr) + 2 * ETH_ALEN + 2 * sizeof(__be32);

    return 0;
}


/* Allow users of header file to redefine VLAN max depth */
#ifndef VLAN_MAX_DEPTH
#define VLAN_MAX_DEPTH 2
#endif

/* Longest chain of IPv6 extension headers to resolve */
#ifndef IPV6_EXT_MAX_CHAIN
#define IPV6_EXT_MAX_CHAIN 7
#endif

#define VLAN_VID_MASK		0x0fff /* VLAN Identifier */
/* Struct for collecting VLANs after parsing via parse_ethhdr_vlan */
struct collect_vlans {
	__u16 id[VLAN_MAX_DEPTH];
};



static __always_inline int proto_is_vlan(__u16 h_proto)
{
	return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
		  h_proto == bpf_htons(ETH_P_8021AD));
}

static __always_inline int parse_ethhdr_vlan(struct hdr_cursor *nh,
											 void *data_end,
											 struct ethhdr **ethhdr,
											 struct collect_vlans *vlans)
{
	struct ethhdr *eth = nh->pos;
	int hdrsize = sizeof(*eth);
	struct vlan_hdr *vlh;
	__u16 h_proto;
	int i;

	/* Byte-count bounds check; check if current pointer + size of header
	* is after data_end.
	*/
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*ethhdr = eth;
	vlh = nh->pos;
	h_proto = eth->h_proto;

	/* Use loop unrolling to avoid the verifier restriction on loops;
	* support up to VLAN_MAX_DEPTH layers of VLAN encapsulation.
	*/
	#pragma unroll
	for (i = 0; i < VLAN_MAX_DEPTH; i++) {
		if (!proto_is_vlan(h_proto))
			break;

		if ((void *)(vlh + 1) > data_end)
			break;

		h_proto = vlh->h_vlan_encapsulated_proto;
		if (vlans) /* collect VLAN ids */
			vlans->id[i] =
				(bpf_ntohs(vlh->h_vlan_TCI) & VLAN_VID_MASK);

		vlh++;
	}

	nh->pos = vlh;
	return h_proto; /* network-byte-order */
}

/* Notice, parse_ethhdr() will skip VLAN tags, by advancing nh->pos and returns
 * next header EtherType, BUT the ethhdr pointer supplied still points to the
 * Ethernet header. Thus, caller can look at eth->h_proto to see if this was a
 * VLAN tagged packet.
 */
static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
										void *data_end,
										struct ethhdr **ethhdr)
{
	/* Expect compiler removes the code that collects VLAN ids */
	return parse_ethhdr_vlan(nh, data_end, ethhdr, NULL);
}

static __always_inline int skip_ip6hdrext(struct hdr_cursor *nh,
					  void *data_end,
					  __u8 next_hdr_type)
{
	for (int i = 0; i < IPV6_EXT_MAX_CHAIN; ++i) {
		struct ipv6_opt_hdr *hdr = (struct ipv6_opt_hdr *)nh->pos;

		if ((void *)(hdr + 1) > data_end)
			return -1;

		switch (next_hdr_type) {
		case IPPROTO_HOPOPTS:
		case IPPROTO_DSTOPTS:
		case IPPROTO_ROUTING:
		#ifdef IPPROTO_MH
		case IPPROTO_MH:
		#endif
			nh->pos = (char *)hdr + (hdr->hdrlen + 1) * 8;
			next_hdr_type = hdr->nexthdr;
			break;
		case IPPROTO_AH:
			nh->pos = (char *)hdr + (hdr->hdrlen + 2) * 4;
			next_hdr_type = hdr->nexthdr;
			break;
		#ifdef IPPROTO_FRAGMENT
		case IPPROTO_FRAGMENT:
		#endif
			nh->pos = (char *)hdr + 8;
			next_hdr_type = hdr->nexthdr;
			break;
		default:
			/* Found a header that is not an IPv6 extension header */
			return next_hdr_type;
		}
	}

	return -1;
}

static __always_inline int parse_ip6hdr(struct hdr_cursor *nh,
					void *data_end,
					struct ipv6hdr **ip6hdr)
{
	struct ipv6hdr *ip6h = (struct ipv6hdr *)nh->pos;

	/* Pointer-arithmetic bounds check; pointer +1 points to after end of
	 * thing being pointed to. We will be using this style in the remainder
	 * of the tutorial.
	 */
	if ((void *)(ip6h + 1) > data_end)
		return -1;

	nh->pos = ip6h + 1;
	*ip6hdr = ip6h;

	return skip_ip6hdrext(nh, data_end, ip6h->nexthdr);
}

static __always_inline int parse_iphdr(struct hdr_cursor *nh,
				       void *data_end,
				       struct iphdr **iphdr)
{
	struct iphdr *iph = (struct iphdr *)nh->pos;
	int hdrsize;

	if ((void *)(iph + 1) > data_end)
		return -1;

	hdrsize = iph->ihl * 4;

	/* Variable-length IPv4 header, need to use byte-based arithmetic */
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos = (char *)nh->pos + hdrsize;
	*iphdr = iph;

	return iph->protocol;
}

static __always_inline int parse_icmp6hdr(struct hdr_cursor *nh,
					  void *data_end,
					  struct icmp6hdr **icmp6hdr)
{
	struct icmp6hdr *icmp6h = (struct icmp6hdr *)nh->pos;

	if ((void *)(icmp6h + 1) > data_end)
		return -1;

	nh->pos   = icmp6h + 1;
	*icmp6hdr = icmp6h;

	return icmp6h->icmp6_type;
}

static __always_inline int parse_icmphdr(struct hdr_cursor *nh,
					 void *data_end,
					 struct icmphdr **icmphdr)
{
	struct icmphdr *icmph = (struct icmphdr *)nh->pos;

	if ((void *)(icmph + 1) > data_end)
		return -1;

	nh->pos  = icmph + 1;
	*icmphdr = icmph;

	return icmph->type;
}

static __always_inline int parse_icmphdr_common(struct hdr_cursor *nh,
						void *data_end,
						struct icmphdr_common **icmphdr)
{
	struct icmphdr_common *h = (struct icmphdr_common *)nh->pos;

	if ((void *)(h + 1) > data_end)
		return -1;

	nh->pos  = h + 1;
	*icmphdr = h;

	return h->type;
}

/*
 * parse_udphdr: parse the udp header and return the length of the udp payload
 */
static __always_inline int parse_udphdr(struct hdr_cursor *nh,
					void *data_end,
					struct udphdr **udphdr)
{
	int len;
	struct udphdr *h = (struct udphdr *)nh->pos;

	if ((void *)(h + 1) > data_end)
		return -1;

	nh->pos  = h + 1;
	*udphdr = h;

	len = bpf_ntohs(h->len) - sizeof(struct udphdr);
	if (len < 0)
		return -1;

	return len;
}

/*
 * parse_tcphdr: parse and return the length of the tcp header
 */
static __always_inline int parse_tcphdr(struct hdr_cursor *nh,
					void *data_end,
					struct tcphdr **tcphdr)
{
	int len;
	struct tcphdr *h = (struct tcphdr *)nh->pos;

	if ((void *)(h + 1) > data_end)
		return -1;

	len = h->doff * 4;
	if ((void *) h + len > data_end)
		return -1;

	nh->pos  = h + 1;
	*tcphdr = h;

	return len;
}

// static __always_inline int extract_packet_layers(struct xdp_md *ctx, 
// 											struct p_layers *layers) 
// {
//     void *data_end = (void *)(long)ctx->data_end;
//     void *data = (void *)(long)ctx->data;
//     __u16 offset = 0; // 记录当前解析位置

//     struct hdr_cursor nh;
//     struct ethhdr *eth;
//     struct iphdr *iph;
//     struct ipv6hdr *ip6h;
//     struct arphdr *arph;
//     struct tcphdr *tcph;
//     struct udphdr *udph;
//     struct vlan_hdr *vlh;
//     int nh_type;

//     // 初始化数据包解析起始位置
//     nh.pos = data;
//     layers->eth_offset = offset; // 以太网头部偏移量

//     // 解析以太网头
//     nh_type = parse_ethhdr(&nh, data_end, &eth);
//     if (nh_type < 0)
//         return -1;
//     offset = nh.pos - data;

//     // 解析 VLAN ID 并进行掩码处理
//     __builtin_memset(layers->vlan_ids, 0, sizeof(layers->vlan_ids));
//     #pragma unroll
//     for (int i = 0; i < VLAN_MAX_DEPTH; i++) {
//         vlh = (struct vlan_hdr *)nh.pos;
//         if ((void *)(vlh + 1) > data_end || !proto_is_vlan(eth->h_proto))
//             break;
//         layers->vlan_ids[i] = bpf_ntohs(vlh->h_vlan_TCI) & VLAN_VID_MASK;
//         nh.pos += sizeof(struct vlan_hdr);
//     }

	

//     // 解析 L3 层协议（IP/IPv6/ARP）
//     layers->l3_offset = offset;
//     layers->l3_proto = bpf_ntohs(nh_type);

//     if (layers->l3_proto == ETH_P_IP) {
//         // 解析 IPv4 头
//         if (parse_iphdr(&nh, data_end, &iph) < 0)
//             return -1;
//         offset = nh.pos - data;
//         layers->l4_offset = offset;
//         layers->l4_proto = iph->protocol;

//         // 解析 L4 层协议（TCP/UDP/ICMP）
//         if (layers->l4_proto == IPPROTO_TCP) {
//             if (parse_tcphdr(&nh, data_end, &tcph) < 0)
//                 return -1;
//         } else if (layers->l4_proto == IPPROTO_UDP) {
//             if (parse_udphdr(&nh, data_end, &udph) < 0)
//                 return -1;
//         }
//     } else if (layers->l3_proto == ETH_P_IPV6) {
//         // 解析 IPv6 头
//         if (parse_ip6hdr(&nh, data_end, &ip6h) < 0)
//             return -1;
//         offset = nh.pos - data;
//         layers->l4_offset = offset;
//         layers->l4_proto = ip6h->nexthdr;
//     } else if (layers->l3_proto == ETH_P_ARP) {
//         // 解析 ARP 头
//         if ((void *)(nh.pos + sizeof(struct arphdr)) > data_end)
//             return -1;
//         layers->l4_offset = 0; // ARP 没有 L4 层
//         layers->l4_proto = 0;
//     } else {
//         // 其它协议，不处理L4及以上。
// 		layers->l4_offset = 0; 
//         layers->l4_proto = 0;
// 		return 0; // 不处理其他协议
//     }
//     return 0;
// }

// DEPRECATED: Old extract_packet_layers using struct p_layers
// Use parse_packet_layers() from rswitch_parsing.h instead
/*
static __always_inline int extract_packet_layers(struct xdp_md *ctx, 
	struct p_layers *layers) 
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	__u16 offset = 0;

	struct collect_vlans vlans = {0}; // 存储 VLAN ID
	struct hdr_cursor nh;
    struct ethhdr *eth;
    struct iphdr *iph;
    struct ipv6hdr *ip6h;
    struct arphdr *arph;
    struct tcphdr *tcph;
    struct udphdr *udph;
    struct vlan_hdr *vlh;
    int nh_type;

	// 初始化数据包解析起始位置
	nh.pos = data;
	layers->eth_offset = 0; // 以太网头部偏移量

	// 解析以太网头部，同时解析 VLAN ID
	nh_type = parse_ethhdr_vlan(&nh, data_end, &eth, &vlans);
	if (nh_type < 0)
		return -1;

	// 存储 VLAN ID（最多支持 VLAN_MAX_DEPTH）
	#pragma unroll
	for (int i = 0; i < VLAN_MAX_DEPTH; i++) {
		layers->vlan_ids[i] = vlans.id[i];
	}

	// 解析 L3 协议（IP/IPv6/ARP）
	layers->l3_offset = nh.pos - data;
	layers->l3_proto = bpf_ntohs(nh_type);

    if (layers->l3_proto == ETH_P_IP) {
        // 解析 IPv4 头
        if (parse_iphdr(&nh, data_end, &iph) < 0)
            return -1;
        offset = nh.pos - data;
        layers->l4_offset = offset;
        layers->l4_proto = iph->protocol;

        // 解析 L4 层协议（TCP/UDP/ICMP）
        if (layers->l4_proto == IPPROTO_TCP) {
            if (parse_tcphdr(&nh, data_end, &tcph) < 0)
                return -1;
        } else if (layers->l4_proto == IPPROTO_UDP) {
            if (parse_udphdr(&nh, data_end, &udph) < 0)
                return -1;
        }
    } else if (layers->l3_proto == ETH_P_IPV6) {
        // 解析 IPv6 头
        if (parse_ip6hdr(&nh, data_end, &ip6h) < 0)
            return -1;
        offset = nh.pos - data;
        layers->l4_offset = offset;
        layers->l4_proto = ip6h->nexthdr;
    } else if (layers->l3_proto == ETH_P_ARP) {
        // 解析 ARP 头
        if ((void *)(nh.pos + sizeof(struct arphdr)) > data_end)
            return -1;
        layers->l4_offset = 0; // ARP 没有 L4 层
        layers->l4_proto = 0;
    } else {
        // 其它协议，不处理L4及以上。
		layers->l4_offset = 0; 
        layers->l4_proto = 0;
		return 0; // 不处理其他协议
    }
    return 0;

	return 0;
}
*/


/* Pops the outermost VLAN tag off the packet. Returns the popped VLAN ID on
 * success or negative errno on failure.
 */
static __always_inline int vlan_tag_pop(struct xdp_md *ctx, struct ethhdr *eth)
{
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr eth_cpy;
	struct vlan_hdr *vlh;
	__be16 h_proto;
	int vlid;

	if (!proto_is_vlan(eth->h_proto))
		return -1;

	/* Careful with the parenthesis here */
	vlh = (void *)(eth + 1);

	/* Still need to do bounds checking */
	if ((void *)&vlh[1] > data_end)
		return -1;

	/* Save vlan ID for returning, h_proto for updating Ethernet header */
	vlid = bpf_ntohs(vlh->h_vlan_TCI);
	h_proto = vlh->h_vlan_encapsulated_proto;

	/* Make a copy of the outer Ethernet header before we cut it off */
	__builtin_memcpy(&eth_cpy, eth, sizeof(eth_cpy));

	/* Actually adjust the head pointer */
	if (bpf_xdp_adjust_head(ctx, (int)sizeof(*vlh)))
		return -1;

	/* Need to re-evaluate data *and* data_end and do new bounds checking
	 * after adjusting head
	 */
	eth = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	if ((void *)&eth[1] > data_end)
		return -1;

	/* Copy back the old Ethernet header and update the proto type */
	__builtin_memcpy(eth, &eth_cpy, sizeof(*eth));
	eth->h_proto = h_proto;

	return vlid;
}

/* Pushes a new VLAN tag after the Ethernet header. Returns 0 on success,
 * -1 on failure.
 */
static __always_inline int vlan_tag_push(struct xdp_md *ctx,
		struct ethhdr *eth, int vlid)
{
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr eth_cpy;
	struct vlan_hdr *vlh;

	/* First copy the original Ethernet header */
	__builtin_memcpy(&eth_cpy, eth, sizeof(eth_cpy));

	/* Then add space in front of the packet */
	if (bpf_xdp_adjust_head(ctx, 0 - (int)sizeof(*vlh)))
		return -1;

	/* Need to re-evaluate data_end and data after head adjustment, and
	 * bounds check, even though we know there is enough space (as we
	 * increased it).
	 */
	data_end = (void *)(long)ctx->data_end;
	eth = (void *)(long)ctx->data;

	if ((void *)&eth[1] > data_end)
		return -1;

	/* Copy back Ethernet header in the right place, populate VLAN tag with
	 * ID and proto, and set outer Ethernet header to VLAN type.
	 */
	__builtin_memcpy(eth, &eth_cpy, sizeof(*eth));

	vlh = (void *)(eth + 1);

	if ((void *)&vlh[1] > data_end)
		return -1;

	vlh->h_vlan_TCI = bpf_htons(vlid);
	vlh->h_vlan_encapsulated_proto = eth->h_proto;

	eth->h_proto = bpf_htons(ETH_P_8021Q);
	return 0;
}

static __always_inline int remove_vlan_tag(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
    if (data + sizeof(struct ethhdr) > data_end) {
        return -1;
    }
	return vlan_tag_pop(ctx, data); // vlan_id or negtive as error. 
}

static __always_inline int add_vlan_tag(struct xdp_md *ctx, __u16 pvid)
{
    void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
    if (data + sizeof(struct ethhdr) > data_end) {
        return -1;
    }
    return vlan_tag_push(ctx, data, pvid); // 0 or -1 as error. 
}

#endif /* __PARSING_HELPERS_H */
