#ifndef RSWITCH_SFLOW_EXPORT_H
#define RSWITCH_SFLOW_EXPORT_H

#include <linux/types.h>

#define RS_EVENT_BUS_PATH "/sys/fs/bpf/rs_event_bus"
#define SFLOW_CONFIG_MAP_PATH "/sys/fs/bpf/sflow_config_map"
#define SFLOW_COUNTER_MAP_PATH "/sys/fs/bpf/sflow_counter_map"
#define RS_STATS_MAP_PATH "/sys/fs/bpf/rs_stats_map"

#define SFLOW_SAMPLE_EVENT_TYPE (0x0500 + 0x10)
#define SFLOW_DEFAULT_COLLECTOR "127.0.0.1:6343"
#define SFLOW_DEFAULT_NETFLOW_COLLECTOR "127.0.0.1:2055"
#define SFLOW_DEFAULT_SAMPLE_RATE 1000
#define SFLOW_DEFAULT_HEADER_BYTES 128
#define SFLOW_MAX_HEADER_BYTES 256

struct sflow_config {
    __u32 enabled;
    __u32 sample_rate;
    __u32 max_header_bytes;
    __u32 pad;
};

struct sflow_counters {
    __u64 packets_seen;
    __u64 packets_sampled;
    __u64 bytes_sampled;
    __u64 sample_drops;
};

struct sflow_sample_event {
    __u32 event_type;
    __u32 ifindex;
    __u64 timestamp_ns;
    __u32 packet_len;
    __u32 captured_len;
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8 protocol;
    __u8 dscp;
    __u16 vlan;
    __u8 header[SFLOW_MAX_HEADER_BYTES];
};

struct rs_stats {
    __u64 rx_packets;
    __u64 rx_bytes;
    __u64 tx_packets;
    __u64 tx_bytes;
    __u64 rx_drops;
    __u64 tx_drops;
    __u64 rx_errors;
    __u64 tx_errors;
};

#endif
