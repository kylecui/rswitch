#ifndef RSWITCH_LLDPD_H
#define RSWITCH_LLDPD_H

#include <stdbool.h>
#include <linux/types.h>

#define LLDP_NEIGHBOR_MAP_PATH "/sys/fs/bpf/lldp_neighbor_map"
#define RS_EVENT_BUS_PATH "/sys/fs/bpf/rs_event_bus"

#define RS_EVENT_LLDP_FRAME (0x0100 + 0x30)
#define LLDP_ETHERTYPE 0x88CC
#define LLDP_DST_MAC_0 0x01
#define LLDP_DST_MAC_1 0x80
#define LLDP_DST_MAC_2 0xC2
#define LLDP_DST_MAC_3 0x00
#define LLDP_DST_MAC_4 0x00
#define LLDP_DST_MAC_5 0x0E
#define LLDP_MAX_FRAME_SIZE 2048

struct lldp_neighbor {
    char chassis_id[64];
    char port_id[32];
    char system_name[64];
    char system_desc[128];
    __u16 ttl;
    __u16 pad;
    __u64 last_seen_ns;
    __u32 capabilities;
};

struct lldp_frame_event {
    __u32 event_type;
    __u32 ifindex;
    __u64 timestamp_ns;
    __u32 frame_len;
    __u32 cap_len;
    __u8 frame[LLDP_MAX_FRAME_SIZE];
};

struct lldpd_if_tx {
    int ifindex;
    int sock_fd;
    char ifname[16];
    __u8 mac[6];
};

struct lldpd_config {
    int tx_interval_sec;
    char interfaces_raw[512];
    bool tx_enabled;
};

#endif
