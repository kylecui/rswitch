#ifndef TEST_PACKETS_H
#define TEST_PACKETS_H

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_ETH_ALEN 6

struct test_eth_hdr {
    uint8_t dst[TEST_ETH_ALEN];
    uint8_t src[TEST_ETH_ALEN];
    uint16_t proto;
} __attribute__((packed));

struct test_vlan_hdr {
    uint16_t tci;
    uint16_t encap_proto;
} __attribute__((packed));

struct test_ipv4_hdr {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
} __attribute__((packed));

struct test_tcp_hdr {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
    uint16_t doff_flags;
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
} __attribute__((packed));

struct test_udp_hdr {
    uint16_t source;
    uint16_t dest;
    uint16_t len;
    uint16_t check;
} __attribute__((packed));

struct test_icmp_hdr {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t id;
    uint16_t sequence;
} __attribute__((packed));

struct test_arp_hdr {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t oper;
    uint8_t sha[6];
    uint32_t sip;
    uint8_t tha[6];
    uint32_t dip;
} __attribute__((packed));

struct test_pkt_ipv4_tcp {
    struct test_eth_hdr eth;
    struct test_ipv4_hdr ip;
    struct test_tcp_hdr tcp;
} __attribute__((packed));

struct test_pkt_ipv4_udp {
    struct test_eth_hdr eth;
    struct test_ipv4_hdr ip;
    struct test_udp_hdr udp;
} __attribute__((packed));

struct test_pkt_vlan_ipv4_tcp {
    struct test_eth_hdr eth;
    struct test_vlan_hdr vlan;
    struct test_ipv4_hdr ip;
    struct test_tcp_hdr tcp;
} __attribute__((packed));

struct test_pkt_arp {
    struct test_eth_hdr eth;
    struct test_arp_hdr arp;
} __attribute__((packed));

struct rs_test_pkt {
    uint8_t *data;
    uint32_t len;
};

struct test_pkt_ipv4_icmp {
    struct test_eth_hdr eth;
    struct test_ipv4_hdr ip;
    struct test_icmp_hdr icmp;
} __attribute__((packed));

static inline void test_set_default_macs(struct test_eth_hdr *eth)
{
    static const uint8_t src[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    static const uint8_t dst[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    memcpy(eth->src, src, sizeof(src));
    memcpy(eth->dst, dst, sizeof(dst));
}

static inline void build_ipv4_tcp_pkt(struct test_pkt_ipv4_tcp *pkt,
                                      uint32_t sip,
                                      uint32_t dip,
                                      uint16_t sport,
                                      uint16_t dport,
                                      uint8_t tos)
{
    memset(pkt, 0, sizeof(*pkt));
    test_set_default_macs(&pkt->eth);
    pkt->eth.proto = htons(0x0800);

    pkt->ip.version_ihl = 0x45;
    pkt->ip.tos = tos;
    pkt->ip.tot_len = htons(sizeof(struct test_ipv4_hdr) + sizeof(struct test_tcp_hdr));
    pkt->ip.id = htons(1);
    pkt->ip.frag_off = htons(0);
    pkt->ip.ttl = 64;
    pkt->ip.protocol = 6;
    pkt->ip.check = 0;
    pkt->ip.saddr = htonl(sip);
    pkt->ip.daddr = htonl(dip);

    pkt->tcp.source = htons(sport);
    pkt->tcp.dest = htons(dport);
    pkt->tcp.seq = htonl(1);
    pkt->tcp.ack_seq = 0;
    pkt->tcp.doff_flags = htons((5U << 12) | 0x002);
    pkt->tcp.window = htons(1024);
    pkt->tcp.check = 0;
    pkt->tcp.urg_ptr = 0;
}

static inline void build_ipv4_udp_pkt(struct test_pkt_ipv4_udp *pkt,
                                      uint32_t sip,
                                      uint32_t dip,
                                      uint16_t sport,
                                      uint16_t dport)
{
    memset(pkt, 0, sizeof(*pkt));
    test_set_default_macs(&pkt->eth);
    pkt->eth.proto = htons(0x0800);

    pkt->ip.version_ihl = 0x45;
    pkt->ip.tos = 0;
    pkt->ip.tot_len = htons(sizeof(struct test_ipv4_hdr) + sizeof(struct test_udp_hdr));
    pkt->ip.id = htons(2);
    pkt->ip.frag_off = htons(0);
    pkt->ip.ttl = 64;
    pkt->ip.protocol = 17;
    pkt->ip.check = 0;
    pkt->ip.saddr = htonl(sip);
    pkt->ip.daddr = htonl(dip);

    pkt->udp.source = htons(sport);
    pkt->udp.dest = htons(dport);
    pkt->udp.len = htons(sizeof(struct test_udp_hdr));
    pkt->udp.check = 0;
}

static inline void build_vlan_ipv4_tcp_pkt(struct test_pkt_vlan_ipv4_tcp *pkt,
                                           uint16_t vlan_id,
                                           uint32_t sip,
                                           uint32_t dip,
                                           uint16_t sport,
                                           uint16_t dport)
{
    memset(pkt, 0, sizeof(*pkt));
    test_set_default_macs(&pkt->eth);
    pkt->eth.proto = htons(0x8100);

    pkt->vlan.tci = htons(vlan_id & 0x0fff);
    pkt->vlan.encap_proto = htons(0x0800);

    pkt->ip.version_ihl = 0x45;
    pkt->ip.tos = 0;
    pkt->ip.tot_len = htons(sizeof(struct test_ipv4_hdr) + sizeof(struct test_tcp_hdr));
    pkt->ip.id = htons(3);
    pkt->ip.frag_off = htons(0);
    pkt->ip.ttl = 64;
    pkt->ip.protocol = 6;
    pkt->ip.check = 0;
    pkt->ip.saddr = htonl(sip);
    pkt->ip.daddr = htonl(dip);

    pkt->tcp.source = htons(sport);
    pkt->tcp.dest = htons(dport);
    pkt->tcp.seq = htonl(2);
    pkt->tcp.ack_seq = 0;
    pkt->tcp.doff_flags = htons((5U << 12) | 0x010);
    pkt->tcp.window = htons(2048);
    pkt->tcp.check = 0;
    pkt->tcp.urg_ptr = 0;
}

static inline void build_arp_pkt(struct test_pkt_arp *pkt, uint32_t sip, uint32_t dip)
{
    memset(pkt, 0, sizeof(*pkt));
    test_set_default_macs(&pkt->eth);
    pkt->eth.proto = htons(0x0806);

    pkt->arp.htype = htons(1);
    pkt->arp.ptype = htons(0x0800);
    pkt->arp.hlen = 6;
    pkt->arp.plen = 4;
    pkt->arp.oper = htons(1);
    memcpy(pkt->arp.sha, pkt->eth.src, sizeof(pkt->arp.sha));
    pkt->arp.sip = htonl(sip);
    memset(pkt->arp.tha, 0, sizeof(pkt->arp.tha));
    pkt->arp.dip = htonl(dip);
}

static inline int test_parse_ip4(const char *ip, uint32_t *out)
{
    struct in_addr addr;

    if (!ip || !out)
        return -1;
    if (inet_pton(AF_INET, ip, &addr) != 1)
        return -1;
    *out = ntohl(addr.s_addr);
    return 0;
}

static inline int test_parse_mac(const char *mac, uint8_t out[6])
{
    unsigned int parts[6];
    int i;

    if (!mac || !out)
        return -1;
    if (sscanf(mac, "%x:%x:%x:%x:%x:%x", &parts[0], &parts[1], &parts[2],
               &parts[3], &parts[4], &parts[5]) != 6)
        return -1;

    for (i = 0; i < 6; i++) {
        if (parts[i] > 0xff)
            return -1;
        out[i] = (uint8_t)parts[i];
    }

    return 0;
}

static inline struct rs_test_pkt *rs_test_pkt_alloc(uint32_t len)
{
    struct rs_test_pkt *pkt;

    pkt = (struct rs_test_pkt *)calloc(1, sizeof(*pkt));
    if (!pkt)
        return NULL;

    pkt->data = (uint8_t *)calloc(1, len);
    if (!pkt->data) {
        free(pkt);
        return NULL;
    }

    pkt->len = len;
    return pkt;
}

static inline struct rs_test_pkt *rs_test_pkt_tcp(const char *src_ip,
                                                  const char *dst_ip,
                                                  uint16_t sport,
                                                  uint16_t dport,
                                                  uint8_t flags)
{
    struct rs_test_pkt *out = rs_test_pkt_alloc(sizeof(struct test_pkt_ipv4_tcp));
    struct test_pkt_ipv4_tcp *pkt;
    uint32_t sip;
    uint32_t dip;

    if (!out)
        return NULL;
    if (test_parse_ip4(src_ip, &sip) != 0 || test_parse_ip4(dst_ip, &dip) != 0) {
        free(out->data);
        free(out);
        return NULL;
    }

    pkt = (struct test_pkt_ipv4_tcp *)out->data;
    build_ipv4_tcp_pkt(pkt, sip, dip, sport, dport, 0);
    pkt->tcp.doff_flags = htons((5U << 12) | (flags & 0x3f));
    return out;
}

static inline struct rs_test_pkt *rs_test_pkt_udp(const char *src_ip,
                                                  const char *dst_ip,
                                                  uint16_t sport,
                                                  uint16_t dport)
{
    struct rs_test_pkt *out = rs_test_pkt_alloc(sizeof(struct test_pkt_ipv4_udp));
    struct test_pkt_ipv4_udp *pkt;
    uint32_t sip;
    uint32_t dip;

    if (!out)
        return NULL;
    if (test_parse_ip4(src_ip, &sip) != 0 || test_parse_ip4(dst_ip, &dip) != 0) {
        free(out->data);
        free(out);
        return NULL;
    }

    pkt = (struct test_pkt_ipv4_udp *)out->data;
    build_ipv4_udp_pkt(pkt, sip, dip, sport, dport);
    return out;
}

static inline struct rs_test_pkt *rs_test_pkt_icmp(const char *src_ip,
                                                   const char *dst_ip,
                                                   uint8_t type,
                                                   uint8_t code)
{
    struct rs_test_pkt *out = rs_test_pkt_alloc(sizeof(struct test_pkt_ipv4_icmp));
    struct test_pkt_ipv4_icmp *pkt;
    uint32_t sip;
    uint32_t dip;

    if (!out)
        return NULL;
    if (test_parse_ip4(src_ip, &sip) != 0 || test_parse_ip4(dst_ip, &dip) != 0) {
        free(out->data);
        free(out);
        return NULL;
    }

    pkt = (struct test_pkt_ipv4_icmp *)out->data;
    memset(pkt, 0, sizeof(*pkt));
    test_set_default_macs(&pkt->eth);
    pkt->eth.proto = htons(0x0800);
    pkt->ip.version_ihl = 0x45;
    pkt->ip.tot_len = htons(sizeof(struct test_ipv4_hdr) + sizeof(struct test_icmp_hdr));
    pkt->ip.ttl = 64;
    pkt->ip.protocol = 1;
    pkt->ip.saddr = htonl(sip);
    pkt->ip.daddr = htonl(dip);
    pkt->icmp.type = type;
    pkt->icmp.code = code;
    return out;
}

static inline struct rs_test_pkt *rs_test_pkt_arp(const char *sender_ip,
                                                  const char *sender_mac,
                                                  const char *target_ip,
                                                  uint16_t op)
{
    struct rs_test_pkt *out = rs_test_pkt_alloc(sizeof(struct test_pkt_arp));
    struct test_pkt_arp *pkt;
    uint32_t sip;
    uint32_t dip;

    if (!out)
        return NULL;
    if (test_parse_ip4(sender_ip, &sip) != 0 || test_parse_ip4(target_ip, &dip) != 0) {
        free(out->data);
        free(out);
        return NULL;
    }

    pkt = (struct test_pkt_arp *)out->data;
    build_arp_pkt(pkt, sip, dip);
    if (sender_mac)
        test_parse_mac(sender_mac, pkt->arp.sha);
    memcpy(pkt->eth.src, pkt->arp.sha, sizeof(pkt->eth.src));
    pkt->arp.oper = htons(op);
    return out;
}

static inline struct rs_test_pkt *rs_test_pkt_vlan(uint16_t vlan_id, struct rs_test_pkt *inner)
{
    struct rs_test_pkt *out;
    struct test_eth_hdr *out_eth;
    struct test_vlan_hdr *out_vlan;
    struct test_eth_hdr *in_eth;
    uint32_t payload_len;

    if (!inner || !inner->data || inner->len < sizeof(struct test_eth_hdr))
        return NULL;

    out = rs_test_pkt_alloc((uint32_t)(inner->len + sizeof(struct test_vlan_hdr)));
    if (!out)
        return NULL;

    in_eth = (struct test_eth_hdr *)inner->data;
    out_eth = (struct test_eth_hdr *)out->data;
    out_vlan = (struct test_vlan_hdr *)(out->data + sizeof(struct test_eth_hdr));
    payload_len = inner->len - (uint32_t)sizeof(struct test_eth_hdr);

    memcpy(out_eth->src, in_eth->src, sizeof(out_eth->src));
    memcpy(out_eth->dst, in_eth->dst, sizeof(out_eth->dst));
    out_eth->proto = htons(0x8100);

    out_vlan->tci = htons(vlan_id & 0x0fff);
    out_vlan->encap_proto = in_eth->proto;

    memcpy(out->data + sizeof(struct test_eth_hdr) + sizeof(struct test_vlan_hdr),
           inner->data + sizeof(struct test_eth_hdr),
           payload_len);

    return out;
}

static inline void rs_test_pkt_free(struct rs_test_pkt *pkt)
{
    if (!pkt)
        return;
    free(pkt->data);
    free(pkt);
}

#endif
