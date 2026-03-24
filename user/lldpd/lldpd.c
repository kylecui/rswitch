// SPDX-License-Identifier: LGPL-2.1-or-later
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <getopt.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#if __has_include("rs_log.h")
#include "rs_log.h"
#else
#include "../common/rs_log.h"
#endif

#include "lldpd.h"

#define LLDP_TLV_END 0
#define LLDP_TLV_CHASSIS_ID 1
#define LLDP_TLV_PORT_ID 2
#define LLDP_TLV_TTL 3
#define LLDP_TLV_SYSTEM_NAME 5
#define LLDP_TLV_SYSTEM_DESC 6
#define LLDP_TLV_SYSTEM_CAPS 7
#define LLDP_CHASSIS_SUBTYPE_MAC 4
#define LLDP_PORT_SUBTYPE_IFNAME 5

static volatile sig_atomic_t g_running = 1;
static int g_neighbor_fd = -1;

struct lldpd_runtime {
    struct ring_buffer *rb;
    int event_bus_fd;
    struct lldpd_config cfg;
    struct lldpd_if_tx tx_ifs[64];
    size_t tx_if_count;
};

static __u64 now_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (__u64)ts.tv_sec * 1000000000ULL + (__u64)ts.tv_nsec;
}

static void signal_handler(int sig)
{
    (void)sig;
    g_running = 0;
}

static void copy_lldp_text(char *dst, size_t dst_len, const __u8 *src, size_t src_len)
{
    size_t n;

    if (!dst || dst_len == 0)
        return;

    n = src_len < (dst_len - 1) ? src_len : (dst_len - 1);
    memcpy(dst, src, n);
    dst[n] = '\0';
}

static void format_mac(char *dst, size_t dst_len, const __u8 *mac)
{
    if (!dst || dst_len == 0)
        return;
    snprintf(dst, dst_len, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void parse_chassis_or_port_id(char *dst, size_t dst_len, const __u8 *value, __u16 len)
{
    __u8 subtype;

    if (len < 1)
        return;

    subtype = value[0];
    if (subtype == LLDP_CHASSIS_SUBTYPE_MAC && len >= 7) {
        format_mac(dst, dst_len, value + 1);
        return;
    }

    copy_lldp_text(dst, dst_len, value + 1, len - 1);
}

static int parse_lldp_frame(const __u8 *frame, __u32 cap_len, struct lldp_neighbor *neighbor)
{
    const struct ethhdr *eth;
    const __u8 *p;
    size_t rem;

    if (!frame || !neighbor || cap_len < sizeof(struct ethhdr))
        return -EINVAL;

    eth = (const struct ethhdr *)frame;
    if (!(eth->h_dest[0] == LLDP_DST_MAC_0 && eth->h_dest[1] == LLDP_DST_MAC_1 &&
          eth->h_dest[2] == LLDP_DST_MAC_2 && eth->h_dest[3] == LLDP_DST_MAC_3 &&
          eth->h_dest[4] == LLDP_DST_MAC_4 && eth->h_dest[5] == LLDP_DST_MAC_5))
        return -EINVAL;

    if (ntohs(eth->h_proto) != LLDP_ETHERTYPE)
        return -EINVAL;

    p = frame + sizeof(struct ethhdr);
    rem = cap_len - sizeof(struct ethhdr);

    while (rem >= 2) {
        __u16 tlv_hdr = ((__u16)p[0] << 8) | p[1];
        __u8 tlv_type = (__u8)(tlv_hdr >> 9);
        __u16 tlv_len = tlv_hdr & 0x01FF;
        const __u8 *value;

        p += 2;
        rem -= 2;
        if (tlv_len > rem)
            break;

        value = p;

        if (tlv_type == LLDP_TLV_END)
            break;

        switch (tlv_type) {
        case LLDP_TLV_CHASSIS_ID:
            parse_chassis_or_port_id(neighbor->chassis_id, sizeof(neighbor->chassis_id), value, tlv_len);
            break;
        case LLDP_TLV_PORT_ID:
            parse_chassis_or_port_id(neighbor->port_id, sizeof(neighbor->port_id), value, tlv_len);
            break;
        case LLDP_TLV_TTL:
            if (tlv_len == 2) {
                __u16 ttl;
                memcpy(&ttl, value, sizeof(ttl));
                neighbor->ttl = ntohs(ttl);
            }
            break;
        case LLDP_TLV_SYSTEM_NAME:
            copy_lldp_text(neighbor->system_name, sizeof(neighbor->system_name), value, tlv_len);
            break;
        case LLDP_TLV_SYSTEM_DESC:
            copy_lldp_text(neighbor->system_desc, sizeof(neighbor->system_desc), value, tlv_len);
            break;
        case LLDP_TLV_SYSTEM_CAPS:
            if (tlv_len >= 4) {
                __u16 supported;
                __u16 enabled;

                memcpy(&supported, value, sizeof(supported));
                memcpy(&enabled, value + 2, sizeof(enabled));
                neighbor->capabilities = ((__u32)ntohs(supported) << 16) | ntohs(enabled);
            }
            break;
        default:
            break;
        }

        p += tlv_len;
        rem -= tlv_len;
    }

    if (neighbor->ttl == 0)
        neighbor->ttl = 120;

    return 0;
}

static int ringbuf_handler(void *ctx, void *data, size_t data_sz)
{
    struct lldpd_runtime *rt = ctx;
    const struct lldp_frame_event *evt = data;
    struct lldp_neighbor neighbor;
    __u32 key;

    (void)rt;

    if (data_sz < offsetof(struct lldp_frame_event, frame))
        return 0;

    if (evt->event_type != RS_EVENT_LLDP_FRAME)
        return 0;

    if (evt->cap_len > LLDP_MAX_FRAME_SIZE || evt->cap_len > evt->frame_len)
        return 0;

    memset(&neighbor, 0, sizeof(neighbor));
    if (parse_lldp_frame(evt->frame, evt->cap_len, &neighbor) < 0)
        return 0;

    neighbor.last_seen_ns = evt->timestamp_ns ? evt->timestamp_ns : now_ns();
    key = evt->ifindex;
    if (bpf_map_update_elem(g_neighbor_fd, &key, &neighbor, BPF_ANY) < 0)
        RS_LOG_WARN("Failed to update lldp_neighbor_map for ifindex %u: %s", key, strerror(errno));

    return 0;
}

static void age_neighbors(void)
{
    __u32 key;
    __u32 next;
    int has_key = 0;
    __u64 now = now_ns();

    while (bpf_map_get_next_key(g_neighbor_fd, has_key ? &key : NULL, &next) == 0) {
        struct lldp_neighbor neigh;

        if (bpf_map_lookup_elem(g_neighbor_fd, &next, &neigh) == 0) {
            int expired = 0;

            if (neigh.ttl == 0) {
                expired = 1;
            } else {
                __u64 ttl_ns = (__u64)neigh.ttl * 1000000000ULL;
                if (now >= neigh.last_seen_ns && now - neigh.last_seen_ns > ttl_ns)
                    expired = 1;
            }

            if (expired)
                bpf_map_delete_elem(g_neighbor_fd, &next);
        }

        key = next;
        has_key = 1;
    }
}

static int add_tlv(__u8 *buf, size_t buf_len, size_t *off, __u8 type, const void *val, __u16 len)
{
    __u16 hdr;

    if (!buf || !off || !val)
        return -EINVAL;
    if (*off + 2 + len > buf_len)
        return -ENOSPC;

    hdr = (__u16)(((type & 0x7F) << 9) | (len & 0x01FF));
    buf[*off] = (__u8)(hdr >> 8);
    buf[*off + 1] = (__u8)(hdr & 0xFF);
    memcpy(buf + *off + 2, val, len);
    *off += 2 + len;
    return 0;
}

static int add_end_tlv(__u8 *buf, size_t buf_len, size_t *off)
{
    if (*off + 2 > buf_len)
        return -ENOSPC;
    buf[*off] = 0;
    buf[*off + 1] = 0;
    *off += 2;
    return 0;
}

static int build_lldpdu(struct lldpd_if_tx *iface, __u8 *frame, size_t frame_len, __u16 ttl, size_t *out_len)
{
    struct ethhdr *eth;
    size_t off = 0;
    __u8 chassis_val[1 + 6];
    __u8 port_val[1 + IFNAMSIZ];
    __u16 ttl_be;
    size_t ifn_len;

    if (!iface || !frame || frame_len < sizeof(struct ethhdr) + 32 || !out_len)
        return -EINVAL;

    eth = (struct ethhdr *)frame;
    eth->h_dest[0] = LLDP_DST_MAC_0;
    eth->h_dest[1] = LLDP_DST_MAC_1;
    eth->h_dest[2] = LLDP_DST_MAC_2;
    eth->h_dest[3] = LLDP_DST_MAC_3;
    eth->h_dest[4] = LLDP_DST_MAC_4;
    eth->h_dest[5] = LLDP_DST_MAC_5;
    memcpy(eth->h_source, iface->mac, 6);
    eth->h_proto = htons(LLDP_ETHERTYPE);
    off += sizeof(*eth);

    chassis_val[0] = LLDP_CHASSIS_SUBTYPE_MAC;
    memcpy(chassis_val + 1, iface->mac, 6);
    if (add_tlv(frame, frame_len, &off, LLDP_TLV_CHASSIS_ID, chassis_val, sizeof(chassis_val)) < 0)
        return -ENOSPC;

    ifn_len = strnlen(iface->ifname, sizeof(iface->ifname));
    port_val[0] = LLDP_PORT_SUBTYPE_IFNAME;
    memcpy(port_val + 1, iface->ifname, ifn_len);
    if (add_tlv(frame, frame_len, &off, LLDP_TLV_PORT_ID, port_val, (__u16)(ifn_len + 1)) < 0)
        return -ENOSPC;

    ttl_be = htons(ttl);
    if (add_tlv(frame, frame_len, &off, LLDP_TLV_TTL, &ttl_be, sizeof(ttl_be)) < 0)
        return -ENOSPC;

    if (add_tlv(frame, frame_len, &off, LLDP_TLV_SYSTEM_NAME, iface->ifname, (__u16)ifn_len) < 0)
        return -ENOSPC;

    if (add_end_tlv(frame, frame_len, &off) < 0)
        return -ENOSPC;

    *out_len = off;
    return 0;
}

static int setup_tx_interface(struct lldpd_if_tx *tx, const char *ifname)
{
    struct ifreq ifr;

    memset(tx, 0, sizeof(*tx));
    strncpy(tx->ifname, ifname, sizeof(tx->ifname) - 1);
    tx->ifindex = if_nametoindex(ifname);
    if (tx->ifindex <= 0)
        return -ENODEV;

    tx->sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (tx->sock_fd < 0)
        return -errno;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(tx->sock_fd, SIOCGIFHWADDR, &ifr) < 0) {
        close(tx->sock_fd);
        tx->sock_fd = -1;
        return -errno;
    }

    memcpy(tx->mac, ifr.ifr_hwaddr.sa_data, 6);
    return 0;
}

static int parse_interfaces(struct lldpd_runtime *rt, const char *list)
{
    char buf[512];
    char *save = NULL;
    char *tok;

    if (!list || list[0] == '\0')
        return 0;

    strncpy(buf, list, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    tok = strtok_r(buf, ",", &save);
    while (tok) {
        if (rt->tx_if_count >= (sizeof(rt->tx_ifs) / sizeof(rt->tx_ifs[0])))
            return -E2BIG;

        while (*tok == ' ' || *tok == '\t')
            tok++;

        if (*tok != '\0') {
            int ret = setup_tx_interface(&rt->tx_ifs[rt->tx_if_count], tok);
            if (ret < 0)
                return ret;
            rt->tx_if_count++;
        }

        tok = strtok_r(NULL, ",", &save);
    }

    return 0;
}

static void close_tx_interfaces(struct lldpd_runtime *rt)
{
    size_t i;

    for (i = 0; i < rt->tx_if_count; i++) {
        if (rt->tx_ifs[i].sock_fd >= 0)
            close(rt->tx_ifs[i].sock_fd);
        rt->tx_ifs[i].sock_fd = -1;
    }
}

static void send_lldp_frames(struct lldpd_runtime *rt)
{
    __u8 frame[512];
    size_t i;

    for (i = 0; i < rt->tx_if_count; i++) {
        struct sockaddr_ll saddr;
        size_t frame_len = 0;

        if (build_lldpdu(&rt->tx_ifs[i], frame, sizeof(frame), (__u16)(rt->cfg.tx_interval_sec * 4), &frame_len) < 0)
            continue;

        memset(&saddr, 0, sizeof(saddr));
        saddr.sll_family = AF_PACKET;
        saddr.sll_ifindex = rt->tx_ifs[i].ifindex;
        saddr.sll_halen = ETH_ALEN;
        saddr.sll_addr[0] = LLDP_DST_MAC_0;
        saddr.sll_addr[1] = LLDP_DST_MAC_1;
        saddr.sll_addr[2] = LLDP_DST_MAC_2;
        saddr.sll_addr[3] = LLDP_DST_MAC_3;
        saddr.sll_addr[4] = LLDP_DST_MAC_4;
        saddr.sll_addr[5] = LLDP_DST_MAC_5;

        if (sendto(rt->tx_ifs[i].sock_fd, frame, frame_len, 0,
                   (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
            RS_LOG_WARN("Failed to transmit LLDP on %s: %s", rt->tx_ifs[i].ifname, strerror(errno));
        }
    }
}

static void print_usage(const char *prog)
{
    printf("Usage: %s [--tx-interval <seconds>] [--interfaces <if1,if2,...>]\n", prog);
}

int main(int argc, char **argv)
{
    struct lldpd_runtime rt;
    static const struct option opts[] = {
        {"tx-interval", required_argument, NULL, 't'},
        {"interfaces", required_argument, NULL, 'i'},
        {"help", no_argument, NULL, 'h'},
        {0, 0, 0, 0}
    };
    int c;
    time_t last_age;
    time_t last_tx;

    memset(&rt, 0, sizeof(rt));
    rt.event_bus_fd = -1;
    rt.cfg.tx_interval_sec = 30;
    rt.cfg.tx_enabled = false;

    rs_log_init("lldpd", RS_LOG_LEVEL_INFO);

    while ((c = getopt_long(argc, argv, "t:i:h", opts, NULL)) != -1) {
        switch (c) {
        case 't':
            rt.cfg.tx_interval_sec = atoi(optarg);
            if (rt.cfg.tx_interval_sec <= 0)
                rt.cfg.tx_interval_sec = 30;
            break;
        case 'i':
            strncpy(rt.cfg.interfaces_raw, optarg, sizeof(rt.cfg.interfaces_raw) - 1);
            rt.cfg.interfaces_raw[sizeof(rt.cfg.interfaces_raw) - 1] = '\0';
            rt.cfg.tx_enabled = true;
            break;
        case 'h':
        default:
            print_usage(argv[0]);
            return 0;
        }
    }

    g_neighbor_fd = bpf_obj_get(LLDP_NEIGHBOR_MAP_PATH);
    if (g_neighbor_fd < 0) {
        RS_LOG_ERROR("Failed to open %s: %s", LLDP_NEIGHBOR_MAP_PATH, strerror(errno));
        return 1;
    }

    rt.event_bus_fd = bpf_obj_get(RS_EVENT_BUS_PATH);
    if (rt.event_bus_fd < 0) {
        RS_LOG_ERROR("Failed to open %s: %s", RS_EVENT_BUS_PATH, strerror(errno));
        close(g_neighbor_fd);
        return 1;
    }

    rt.rb = ring_buffer__new(rt.event_bus_fd, ringbuf_handler, &rt, NULL);
    if (!rt.rb) {
        RS_LOG_ERROR("Failed to create ringbuf consumer: %s", strerror(errno));
        close(rt.event_bus_fd);
        close(g_neighbor_fd);
        return 1;
    }

    if (rt.cfg.tx_enabled) {
        int ret = parse_interfaces(&rt, rt.cfg.interfaces_raw);
        if (ret < 0) {
            RS_LOG_ERROR("Failed to configure LLDP TX interfaces: %s", strerror(-ret));
            ring_buffer__free(rt.rb);
            close(rt.event_bus_fd);
            close(g_neighbor_fd);
            return 1;
        }
        if (rt.tx_if_count == 0)
            rt.cfg.tx_enabled = false;
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    last_age = time(NULL);
    last_tx = time(NULL);
    RS_LOG_INFO("lldpd started (tx_interval=%d, tx_interfaces=%zu)", rt.cfg.tx_interval_sec, rt.tx_if_count);

    while (g_running) {
        int ret = ring_buffer__poll(rt.rb, 200);
        time_t now;

        if (ret < 0 && ret != -EINTR)
            RS_LOG_WARN("ring_buffer__poll returned %d", ret);

        now = time(NULL);
        if (now - last_age >= 1) {
            age_neighbors();
            last_age = now;
        }

        if (rt.cfg.tx_enabled && now - last_tx >= rt.cfg.tx_interval_sec) {
            send_lldp_frames(&rt);
            last_tx = now;
        }
    }

    close_tx_interfaces(&rt);
    ring_buffer__free(rt.rb);
    close(rt.event_bus_fd);
    close(g_neighbor_fd);
    RS_LOG_INFO("lldpd stopped");
    return 0;
}
