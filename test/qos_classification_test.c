// SPDX-License-Identifier: GPL-2.0
/*
 * QoS Classification Test
 *
 * Tests IP DSCP parsing and priority extraction functionality.
 * Standalone test that only uses the classification functions.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <arpa/inet.h>

/* Include only the QoS classification functions (copied from voqd_dataplane.c) */

/* Ethernet frame types */
#define ETH_P_IP    0x0800  /* IPv4 */
#define ETH_P_IPV6  0x86DD  /* IPv6 */

/* IPv4 header structure (simplified) */
struct ipv4_hdr {
	uint8_t version_ihl;     /* Version (4 bits) + IHL (4 bits) */
	uint8_t tos;             /* Type of Service (DSCP + ECN) */
	uint16_t tot_len;        /* Total Length */
	uint16_t id;             /* Identification */
	uint16_t frag_off;       /* Fragment Offset */
	uint8_t ttl;             /* Time to Live */
	uint8_t protocol;        /* Protocol */
	uint16_t check;          /* Header Checksum */
	uint32_t saddr;          /* Source Address */
	uint32_t daddr;          /* Destination Address */
} __attribute__((packed));

/* IPv6 header structure (simplified) */
struct ipv6_hdr {
	uint32_t version_tc_fl;  /* Version (4) + Traffic Class (8) + Flow Label (20) */
	uint16_t payload_len;    /* Payload Length */
	uint8_t next_hdr;        /* Next Header */
	uint8_t hop_limit;       /* Hop Limit */
	uint8_t saddr[16];       /* Source Address */
	uint8_t daddr[16];       /* Destination Address */
} __attribute__((packed));

/* Ethernet header structure */
struct eth_hdr {
	uint8_t dmac[6];         /* Destination MAC */
	uint8_t smac[6];         /* Source MAC */
	uint16_t eth_type;       /* Ethernet Type */
} __attribute__((packed));

/* VLAN header structure (802.1Q) */
struct vlan_hdr {
	uint16_t tci;            /* Tag Control Information */
	uint16_t eth_type;       /* Ethernet Type */
} __attribute__((packed));

/* QoS Priority levels */
#define QOS_PRIO_LOW        0
#define QOS_PRIO_NORMAL     1
#define QOS_PRIO_HIGH       2
#define QOS_PRIO_CRITICAL   3

/* Check if packet is IPv4 */
bool voqd_is_ipv4_packet(const uint8_t *packet, size_t len)
{
	if (len < sizeof(struct eth_hdr) + sizeof(struct ipv4_hdr))
		return false;
	
	const struct eth_hdr *eth = (const struct eth_hdr *)packet;
	uint16_t eth_type = ntohs(eth->eth_type);
	
	/* Handle VLAN tags */
	if (eth_type == 0x8100 || eth_type == 0x88A8) {  /* VLAN */
		if (len < sizeof(struct eth_hdr) + sizeof(struct vlan_hdr) + sizeof(struct ipv4_hdr))
			return false;
		const struct vlan_hdr *vlan = (const struct vlan_hdr *)(packet + sizeof(struct eth_hdr));
		eth_type = ntohs(vlan->eth_type);
	}
	
	return (eth_type == ETH_P_IP);
}

/* Check if packet is IPv6 */
bool voqd_is_ipv6_packet(const uint8_t *packet, size_t len)
{
	if (len < sizeof(struct eth_hdr) + sizeof(struct ipv6_hdr))
		return false;
	
	const struct eth_hdr *eth = (const struct eth_hdr *)packet;
	uint16_t eth_type = ntohs(eth->eth_type);
	
	/* Handle VLAN tags */
	if (eth_type == 0x8100 || eth_type == 0x88A8) {  /* VLAN */
		if (len < sizeof(struct eth_hdr) + sizeof(struct vlan_hdr) + sizeof(struct ipv6_hdr))
			return false;
		const struct vlan_hdr *vlan = (const struct vlan_hdr *)(packet + sizeof(struct eth_hdr));
		eth_type = ntohs(vlan->eth_type);
	}
	
	return (eth_type == ETH_P_IPV6);
}

/* Parse DSCP value from IP packet header */
uint8_t voqd_parse_ip_dscp(const uint8_t *packet, size_t len)
{
	uint8_t dscp = 0;
	
	if (voqd_is_ipv4_packet(packet, len)) {
		/* IPv4: DSCP is in TOS field (bits 0-5) */
		const struct eth_hdr *eth = (const struct eth_hdr *)packet;
		size_t ip_offset = sizeof(struct eth_hdr);
		
		/* Skip VLAN header if present */
		uint16_t eth_type = ntohs(eth->eth_type);
		if (eth_type == 0x8100 || eth_type == 0x88A8) {  /* VLAN */
			ip_offset += sizeof(struct vlan_hdr);
		}
		
		if (ip_offset + sizeof(struct ipv4_hdr) <= len) {
			const struct ipv4_hdr *ip = (const struct ipv4_hdr *)(packet + ip_offset);
			dscp = (ip->tos >> 2) & 0x3F;  /* DSCP is bits 2-7 of TOS */
		}
		
	} else if (voqd_is_ipv6_packet(packet, len)) {
		/* IPv6: DSCP is in Traffic Class field (bits 4-9 of first 32-bit word) */
		const struct eth_hdr *eth = (const struct eth_hdr *)packet;
		size_t ip_offset = sizeof(struct eth_hdr);
		
		/* Skip VLAN header if present */
		uint16_t eth_type = ntohs(eth->eth_type);
		if (eth_type == 0x8100 || eth_type == 0x88A8) {  /* VLAN */
			ip_offset += sizeof(struct vlan_hdr);
		}
		
		if (ip_offset + sizeof(struct ipv6_hdr) <= len) {
			const struct ipv6_hdr *ip = (const struct ipv6_hdr *)(packet + ip_offset);
			/* Extract traffic class from bytes (RFC 2460 format) */
			const uint8_t *bytes = (const uint8_t *)&ip->version_tc_fl;
			uint8_t traffic_class = ((bytes[0] & 0x0F) << 4) | ((bytes[1] >> 4) & 0x0F);
			dscp = (traffic_class >> 2) & 0x3F;
		}
	}
	
	return dscp;
}

/* Extract priority from packet using IP DSCP or fallback to default */
uint8_t voqd_extract_priority_from_packet(const uint8_t *packet, size_t len, 
                                         const uint8_t *dscp_to_prio, uint8_t default_prio)
{
	/* Check if this is an IP packet */
	if (!voqd_is_ipv4_packet(packet, len) && !voqd_is_ipv6_packet(packet, len)) {
		/* Non-IP packet: use default priority */
		return default_prio;
	}
	
	/* Try to parse DSCP from IP header */
	uint8_t dscp = voqd_parse_ip_dscp(packet, len);
	
	/* Map DSCP to priority using lookup table */
	if (dscp_to_prio && dscp < 64) {
		return dscp_to_prio[dscp];
	}
	
	/* Fallback to default priority */
	return default_prio;
}

/* Test packet data (simplified Ethernet + IP headers) */

/* IPv4 packet with DSCP=46 (EF) */
static const uint8_t ipv4_ef_packet[] = {
	/* Ethernet header */
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff,  /* dst MAC */
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  /* src MAC */
	0x08, 0x00,                           /* ethertype IPv4 */
	
	/* IPv4 header */
	0x45,                                 /* version=4, IHL=5 */
	0xb8,                                 /* TOS: DSCP=46 (0xb8 = 10111000, DSCP=46) */
	0x00, 0x3c,                           /* total length */
	0x00, 0x00,                           /* ID */
	0x00, 0x00,                           /* flags + frag offset */
	0x40,                                 /* TTL */
	0x06,                                 /* protocol (TCP) */
	0x00, 0x00,                           /* checksum */
	0xc0, 0xa8, 0x01, 0x01,               /* src IP 192.168.1.1 */
	0xc0, 0xa8, 0x01, 0x02,               /* dst IP 192.168.1.2 */
	
	/* TCP header (simplified) */
	0x00, 0x50, 0x00, 0x50,               /* src/dst ports */
	0x00, 0x00, 0x00, 0x00,               /* seq */
	0x00, 0x00, 0x00, 0x00,               /* ack */
	0x50, 0x00, 0x00, 0x00,               /* flags + window */
};

/* IPv4 packet with DSCP=0 (Best Effort) */
static const uint8_t ipv4_be_packet[] = {
	/* Ethernet header */
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff,  /* dst MAC */
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  /* src MAC */
	0x08, 0x00,                           /* ethertype IPv4 */
	
	/* IPv4 header */
	0x45,                                 /* version=4, IHL=5 */
	0x00,                                 /* TOS: DSCP=0 (Best Effort) */
	0x00, 0x3c,                           /* total length */
	0x00, 0x00,                           /* ID */
	0x00, 0x00,                           /* flags + frag offset */
	0x40,                                 /* TTL */
	0x06,                                 /* protocol (TCP) */
	0x00, 0x00,                           /* checksum */
	0xc0, 0xa8, 0x01, 0x01,               /* src IP 192.168.1.1 */
	0xc0, 0xa8, 0x01, 0x02,               /* dst IP 192.168.1.2 */
};

/* IPv6 packet with DSCP=46 (EF) */
static const uint8_t ipv6_ef_packet[] = {
	/* Ethernet header */
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff,  /* dst MAC */
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  /* src MAC */
	0x86, 0xdd,                           /* ethertype IPv6 */
	
	/* IPv6 header - version=6, traffic class=0xb8 (DSCP=46), flow label=0 */
	0x6b, 0x80, 0x00, 0x00,               /* version=6, traffic class=0xb8, flow label=0 */
	0x00, 0x20,                           /* payload length */
	0x06,                                 /* next header (TCP) */
	0x40,                                 /* hop limit */
	/* src IPv6 */
	0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	/* dst IPv6 */
	0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
};

/* Non-IP packet (ARP) */
static const uint8_t arp_packet[] = {
	/* Ethernet header */
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff,  /* dst MAC */
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  /* src MAC */
	0x08, 0x06,                           /* ethertype ARP */
	
	/* ARP header (simplified) */
	0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01,
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
	0xc0, 0xa8, 0x01, 0x01,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xc0, 0xa8, 0x01, 0x02,
};

int main(int argc, char **argv)
{
	(void)argc;
	(void)argv;
	
	printf("QoS Classification Test\n");
	printf("======================\n\n");
	
	/* Initialize DSCP to priority mapping (same as production) */
	uint8_t dscp_to_prio[64];
	uint8_t default_prio = QOS_PRIO_NORMAL;
	
	for (int i = 0; i < 64; i++) {
		if (i == 46) dscp_to_prio[i] = QOS_PRIO_CRITICAL;  /* EF */
		else if (i >= 32 && i <= 38) dscp_to_prio[i] = QOS_PRIO_HIGH;     /* AF4x */
		else if (i >= 16 && i <= 22) dscp_to_prio[i] = QOS_PRIO_NORMAL;   /* AF2x */
		else if (i >= 8 && i <= 14) dscp_to_prio[i] = QOS_PRIO_LOW;       /* AF1x */
		else dscp_to_prio[i] = QOS_PRIO_LOW;  /* Best Effort and others */
	}
	
	/* Test cases */
	struct {
		const char *name;
		const uint8_t *packet;
		size_t len;
		uint8_t expected_dscp;
		uint8_t expected_prio;
	} tests[] = {
		{"IPv4 EF (DSCP=46)", ipv4_ef_packet, sizeof(ipv4_ef_packet), 46, QOS_PRIO_CRITICAL},
		{"IPv4 BE (DSCP=0)", ipv4_be_packet, sizeof(ipv4_be_packet), 0, QOS_PRIO_LOW},
		{"IPv6 EF (DSCP=46)", ipv6_ef_packet, sizeof(ipv6_ef_packet), 46, QOS_PRIO_CRITICAL},
		{"ARP (non-IP)", arp_packet, sizeof(arp_packet), 0, QOS_PRIO_NORMAL},
	};
	
	int num_tests = sizeof(tests) / sizeof(tests[0]);
	int passed = 0;
	
	for (int i = 0; i < num_tests; i++) {
		const char *name = tests[i].name;
		const uint8_t *packet = tests[i].packet;
		size_t len = tests[i].len;
		uint8_t expected_dscp = tests[i].expected_dscp;
		uint8_t expected_prio = tests[i].expected_prio;
		
		/* Test DSCP parsing */
		uint8_t dscp = voqd_parse_ip_dscp(packet, len);
		const char *dscp_status = (dscp == expected_dscp) ? "PASS" : "FAIL";
		
		/* Test priority extraction */
		uint8_t prio = voqd_extract_priority_from_packet(packet, len, dscp_to_prio, default_prio);
		const char *prio_status = (prio == expected_prio) ? "PASS" : "FAIL";
		
		/* Test packet type detection */
		bool is_ipv4 = voqd_is_ipv4_packet(packet, len);
		bool is_ipv6 = voqd_is_ipv6_packet(packet, len);
		
		printf("Test %d: %s\n", i + 1, name);
		printf("  Packet type: IPv4=%s, IPv6=%s\n",
		       is_ipv4 ? "yes" : "no", is_ipv6 ? "yes" : "no");
		printf("  DSCP: %u (expected %u) [%s]\n", dscp, expected_dscp, dscp_status);
		printf("  Priority: %u (expected %u) [%s]\n", prio, expected_prio, prio_status);
		
		if (dscp == expected_dscp && prio == expected_prio) {
			passed++;
			printf("  ✓ PASS\n");
		} else {
			printf("  ✗ FAIL\n");
		}
		printf("\n");
	}
	
	printf("Results: %d/%d tests passed\n", passed, num_tests);
	
	if (passed == num_tests) {
		printf("🎉 All QoS classification tests passed!\n");
		return 0;
	} else {
		printf("❌ Some tests failed\n");
		return 1;
	}
}