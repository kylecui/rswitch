// SPDX-License-Identifier: GPL-2.0
/* rSwitch Packet Trace v2 - Ringbuf-based
 * 
 * Uses BPF ringbuf to receive packet events from fentry hook.
 * Much more reliable than polling rs_ctx_map.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define RS_VLAN_MAX_DEPTH 2

struct pkt_event {
    __u64 timestamp;
    __u32 ifindex;
    __u32 egress_ifindex;
    
    __u16 eth_proto;
    __u16 vlan_ids[RS_VLAN_MAX_DEPTH];
    __u8  vlan_depth;
    __u8  ip_proto;
    
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    
    __u8  dscp;
    __u8  ecn;
    __u8  prio;
    __u8  pad;
    
    __u16 ingress_vlan;
    __u16 payload_len;
} __attribute__((packed));

static volatile sig_atomic_t stop = 0;

static void sig_handler(int sig)
{
    stop = 1;
}

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

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    struct pkt_event *evt = data;
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    static int pkt_count = 0;
    
    pkt_count++;
    
    printf("\n[%d] Packet on ifindex %u (ts=%llu) ---\n", 
           pkt_count, evt->ifindex, evt->timestamp);
    printf("Ethernet: proto=%s (0x%04x)\n", 
           eth_proto_name(evt->eth_proto), evt->eth_proto);
    
    if (evt->vlan_depth > 0) {
        printf("VLAN: depth=%u, IDs=[", evt->vlan_depth);
        for (int i = 0; i < evt->vlan_depth && i < RS_VLAN_MAX_DEPTH; i++) {
            printf("%s%u", i > 0 ? ", " : "", evt->vlan_ids[i]);
        }
        printf("]\n");
    }
    
    if (evt->eth_proto == 0x0800 && evt->saddr != 0) {
        inet_ntop(AF_INET, &evt->saddr, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &evt->daddr, dst_ip, sizeof(dst_ip));
        
        printf("IPv4: %s → %s, proto=%s (%u)\n",
               src_ip, dst_ip, proto_name(evt->ip_proto), evt->ip_proto);
        printf("      DSCP=%u, ECN=%u\n", evt->dscp, evt->ecn);
        
        if (evt->ip_proto == 6 || evt->ip_proto == 17) {
            printf("Ports: %u → %u\n", 
                   ntohs(evt->sport), ntohs(evt->dport));
        }
        
        printf("Payload len: %u\n", evt->payload_len);
    }
    
    printf("QoS: prio=%u\n", evt->prio);
    printf("Forwarding: ingress_vlan=%u, egress_ifindex=%u\n",
           evt->ingress_vlan, evt->egress_ifindex);
    
    return 0;
}

int main(int argc, char **argv)
{
    struct bpf_object *obj;
    struct ring_buffer *rb = NULL;
    int err;
    
    /* Load BPF program */
    obj = bpf_object__open_file("./build/bpf/packet_trace.bpf.o", NULL);
    err = libbpf_get_error(obj);
    if (err) {
        fprintf(stderr, "Failed to open BPF object: %s\n", strerror(-err));
        return 1;
    }
    
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %s\n", strerror(-err));
        goto cleanup;
    }
    
    /* Attach fentry program */
    err = bpf_object__attach(obj);
    if (err) {
        fprintf(stderr, "Failed to attach BPF programs: %s\n", strerror(-err));
        goto cleanup;
    }
    
    /* Set up ringbuf consumer */
    int ringbuf_fd = bpf_object__find_map_fd_by_name(obj, "pkt_events");
    if (ringbuf_fd < 0) {
        fprintf(stderr, "Failed to find pkt_events map\n");
        err = -1;
        goto cleanup;
    }
    
    rb = ring_buffer__new(ringbuf_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        err = -1;
        goto cleanup;
    }
    
    /* Setup signal handler */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    printf("rSwitch Packet Trace v2 (Ringbuf-based)\n");
    printf("Press Ctrl+C to exit\n");
    printf("=========================================\n\n");
    
    /* Poll for events */
    while (!stop) {
        err = ring_buffer__poll(rb, 100);  /* 100ms timeout */
        if (err == -EINTR) {
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling ringbuf: %d\n", err);
            break;
        }
    }
    
    printf("\nExiting...\n");
    
cleanup:
    ring_buffer__free(rb);
    bpf_object__close(obj);
    return err < 0 ? 1 : 0;
}
