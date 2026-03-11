// SPDX-License-Identifier: GPL-2.0-or-later

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#if __has_include("rs_log.h")
#include "rs_log.h"
#else
#include "../common/rs_log.h"
#endif

#include "sflow_export.h"

#define SFLOW_COUNTER_EXPORT_INTERVAL_SEC 20
#define SFLOW_MAX_DGRAM_SIZE 1400

static volatile sig_atomic_t g_running = 1;

struct exporter_runtime {
    int event_bus_fd;
    int sflow_sock;
    int netflow_sock;
    int sflow_cfg_fd;
    int sflow_counter_fd;
    int rs_stats_fd;
    struct ring_buffer *rb;
    struct sockaddr_in sflow_collector;
    struct sockaddr_in netflow_collector;
    __be32 agent_ip;
    __u32 sample_rate;
    __u32 max_header_bytes;
    __u32 sflow_seq;
    __u32 sflow_flow_seq;
    __u32 sflow_counter_seq;
    __u32 netflow_seq;
    __u32 netflow_src_id;
    __u64 start_ns;
    __u64 sample_pool;
    __u64 sample_drops;
    bool netflow_template_sent;
    time_t netflow_template_last;
};

static void handle_signal(int sig)
{
    (void)sig;
    g_running = 0;
}

static __u64 now_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (__u64)ts.tv_sec * 1000000000ULL + (__u64)ts.tv_nsec;
}

static __u32 uptime_ms(struct exporter_runtime *rt)
{
    __u64 elapsed_ns = now_ns() - rt->start_ns;
    return (__u32)(elapsed_ns / 1000000ULL);
}

static int parse_ip_port(const char *arg, struct sockaddr_in *addr)
{
    char buf[128];
    char *sep;
    long port;

    if (!arg || !addr)
        return -EINVAL;

    memset(addr, 0, sizeof(*addr));
    addr->sin_family = AF_INET;

    strncpy(buf, arg, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    sep = strrchr(buf, ':');
    if (!sep)
        return -EINVAL;

    *sep = '\0';
    sep++;
    port = strtol(sep, NULL, 10);
    if (port <= 0 || port > 65535)
        return -EINVAL;

    if (inet_pton(AF_INET, buf, &addr->sin_addr) != 1)
        return -EINVAL;

    addr->sin_port = htons((uint16_t)port);
    return 0;
}

static int put_u32(__u8 *buf, size_t len, size_t *off, __u32 v)
{
    __u32 n = htonl(v);
    if (*off + sizeof(n) > len)
        return -ENOSPC;
    memcpy(buf + *off, &n, sizeof(n));
    *off += sizeof(n);
    return 0;
}

static int put_u64(__u8 *buf, size_t len, size_t *off, __u64 v)
{
    __u64 n = htobe64(v);
    if (*off + sizeof(n) > len)
        return -ENOSPC;
    memcpy(buf + *off, &n, sizeof(n));
    *off += sizeof(n);
    return 0;
}

static int send_sflow_flow_sample(struct exporter_runtime *rt, const struct sflow_sample_event *evt)
{
    __u8 dgram[SFLOW_MAX_DGRAM_SIZE];
    size_t off = 0;
    size_t sample_len_off;
    size_t sample_body_start;
    size_t record_len_off;
    size_t record_body_start;
    __u32 cap_len = evt->captured_len;
    __u32 pad_len;

    if (cap_len > SFLOW_MAX_HEADER_BYTES)
        cap_len = SFLOW_MAX_HEADER_BYTES;

    rt->sample_pool += rt->sample_rate;

    if (put_u32(dgram, sizeof(dgram), &off, 5) < 0 ||
        put_u32(dgram, sizeof(dgram), &off, 1) < 0 ||
        put_u32(dgram, sizeof(dgram), &off, ntohl(rt->agent_ip)) < 0 ||
        put_u32(dgram, sizeof(dgram), &off, 0) < 0 ||
        put_u32(dgram, sizeof(dgram), &off, rt->sflow_seq++) < 0 ||
        put_u32(dgram, sizeof(dgram), &off, uptime_ms(rt)) < 0 ||
        put_u32(dgram, sizeof(dgram), &off, 1) < 0)
        return -ENOSPC;

    if (put_u32(dgram, sizeof(dgram), &off, 1) < 0)
        return -ENOSPC;

    sample_len_off = off;
    if (put_u32(dgram, sizeof(dgram), &off, 0) < 0)
        return -ENOSPC;

    sample_body_start = off;
    if (put_u32(dgram, sizeof(dgram), &off, rt->sflow_flow_seq++) < 0 ||
        put_u32(dgram, sizeof(dgram), &off, evt->ifindex) < 0 ||
        put_u32(dgram, sizeof(dgram), &off, rt->sample_rate) < 0 ||
        put_u32(dgram, sizeof(dgram), &off, (__u32)rt->sample_pool) < 0 ||
        put_u32(dgram, sizeof(dgram), &off, (__u32)rt->sample_drops) < 0 ||
        put_u32(dgram, sizeof(dgram), &off, evt->ifindex) < 0 ||
        put_u32(dgram, sizeof(dgram), &off, 0) < 0 ||
        put_u32(dgram, sizeof(dgram), &off, 1) < 0)
        return -ENOSPC;

    if (put_u32(dgram, sizeof(dgram), &off, 1) < 0)
        return -ENOSPC;

    record_len_off = off;
    if (put_u32(dgram, sizeof(dgram), &off, 0) < 0)
        return -ENOSPC;

    record_body_start = off;
    if (put_u32(dgram, sizeof(dgram), &off, 1) < 0 ||
        put_u32(dgram, sizeof(dgram), &off, evt->packet_len) < 0 ||
        put_u32(dgram, sizeof(dgram), &off, 0) < 0 ||
        put_u32(dgram, sizeof(dgram), &off, cap_len) < 0)
        return -ENOSPC;

    if (off + cap_len > sizeof(dgram))
        return -ENOSPC;
    memcpy(dgram + off, evt->header, cap_len);
    off += cap_len;

    pad_len = (4 - (cap_len & 3)) & 3;
    if (off + pad_len > sizeof(dgram))
        return -ENOSPC;
    memset(dgram + off, 0, pad_len);
    off += pad_len;

    {
        __u32 record_len = (__u32)(off - record_body_start);
        __u32 sample_len = (__u32)(off - sample_body_start);
        __u32 be_record_len = htonl(record_len);
        __u32 be_sample_len = htonl(sample_len);
        memcpy(dgram + record_len_off, &be_record_len, sizeof(be_record_len));
        memcpy(dgram + sample_len_off, &be_sample_len, sizeof(be_sample_len));
    }

    if (sendto(rt->sflow_sock, dgram, off, 0,
               (const struct sockaddr *)&rt->sflow_collector,
               sizeof(rt->sflow_collector)) < 0)
        return -errno;

    return 0;
}

static int send_sflow_counter_sample(struct exporter_runtime *rt, __u32 ifindex,
                                     const struct rs_stats *stats)
{
    __u8 dgram[SFLOW_MAX_DGRAM_SIZE];
    size_t off = 0;
    size_t sample_len_off;
    size_t sample_body_start;
    size_t record_len_off;
    size_t record_body_start;

    if (put_u32(dgram, sizeof(dgram), &off, 5) < 0 ||
        put_u32(dgram, sizeof(dgram), &off, 1) < 0 ||
        put_u32(dgram, sizeof(dgram), &off, ntohl(rt->agent_ip)) < 0 ||
        put_u32(dgram, sizeof(dgram), &off, 0) < 0 ||
        put_u32(dgram, sizeof(dgram), &off, rt->sflow_seq++) < 0 ||
        put_u32(dgram, sizeof(dgram), &off, uptime_ms(rt)) < 0 ||
        put_u32(dgram, sizeof(dgram), &off, 1) < 0)
        return -ENOSPC;

    if (put_u32(dgram, sizeof(dgram), &off, 2) < 0)
        return -ENOSPC;
    sample_len_off = off;
    if (put_u32(dgram, sizeof(dgram), &off, 0) < 0)
        return -ENOSPC;

    sample_body_start = off;
    if (put_u32(dgram, sizeof(dgram), &off, rt->sflow_counter_seq++) < 0 ||
        put_u32(dgram, sizeof(dgram), &off, ifindex) < 0 ||
        put_u32(dgram, sizeof(dgram), &off, 1) < 0)
        return -ENOSPC;

    if (put_u32(dgram, sizeof(dgram), &off, 1) < 0)
        return -ENOSPC;
    record_len_off = off;
    if (put_u32(dgram, sizeof(dgram), &off, 0) < 0)
        return -ENOSPC;

    record_body_start = off;
    if (put_u32(dgram, sizeof(dgram), &off, ifindex) < 0 ||
        put_u32(dgram, sizeof(dgram), &off, 6) < 0 ||
        put_u64(dgram, sizeof(dgram), &off, 1000000000ULL) < 0 ||
        put_u32(dgram, sizeof(dgram), &off, 1) < 0 ||
        put_u32(dgram, sizeof(dgram), &off, 3) < 0 ||
        put_u64(dgram, sizeof(dgram), &off, stats->rx_bytes) < 0 ||
        put_u32(dgram, sizeof(dgram), &off, (__u32)stats->rx_packets) < 0 ||
        put_u32(dgram, sizeof(dgram), &off, 0) < 0 ||
        put_u32(dgram, sizeof(dgram), &off, 0) < 0 ||
        put_u32(dgram, sizeof(dgram), &off, (__u32)stats->rx_drops) < 0 ||
        put_u32(dgram, sizeof(dgram), &off, (__u32)stats->rx_errors) < 0 ||
        put_u32(dgram, sizeof(dgram), &off, 0) < 0 ||
        put_u64(dgram, sizeof(dgram), &off, stats->tx_bytes) < 0 ||
        put_u32(dgram, sizeof(dgram), &off, (__u32)stats->tx_packets) < 0 ||
        put_u32(dgram, sizeof(dgram), &off, 0) < 0 ||
        put_u32(dgram, sizeof(dgram), &off, 0) < 0 ||
        put_u32(dgram, sizeof(dgram), &off, (__u32)stats->tx_drops) < 0 ||
        put_u32(dgram, sizeof(dgram), &off, (__u32)stats->tx_errors) < 0 ||
        put_u32(dgram, sizeof(dgram), &off, 0) < 0)
        return -ENOSPC;

    {
        __u32 record_len = (__u32)(off - record_body_start);
        __u32 sample_len = (__u32)(off - sample_body_start);
        __u32 be_record_len = htonl(record_len);
        __u32 be_sample_len = htonl(sample_len);
        memcpy(dgram + record_len_off, &be_record_len, sizeof(be_record_len));
        memcpy(dgram + sample_len_off, &be_sample_len, sizeof(be_sample_len));
    }

    if (sendto(rt->sflow_sock, dgram, off, 0,
               (const struct sockaddr *)&rt->sflow_collector,
               sizeof(rt->sflow_collector)) < 0)
        return -errno;

    return 0;
}

static void send_netflow_template(struct exporter_runtime *rt)
{
    __u8 pkt[256];
    size_t off = 0;
    __u16 v16;
    __u32 v32;
    uint32_t now = (uint32_t)time(NULL);

    v16 = htons(9);
    memcpy(pkt + off, &v16, sizeof(v16));
    off += sizeof(v16);
    v16 = htons(1);
    memcpy(pkt + off, &v16, sizeof(v16));
    off += sizeof(v16);
    v32 = htonl(uptime_ms(rt));
    memcpy(pkt + off, &v32, sizeof(v32));
    off += sizeof(v32);
    v32 = htonl(now);
    memcpy(pkt + off, &v32, sizeof(v32));
    off += sizeof(v32);
    v32 = htonl(rt->netflow_seq++);
    memcpy(pkt + off, &v32, sizeof(v32));
    off += sizeof(v32);
    v32 = htonl(rt->netflow_src_id);
    memcpy(pkt + off, &v32, sizeof(v32));
    off += sizeof(v32);

    v16 = htons(0);
    memcpy(pkt + off, &v16, sizeof(v16));
    off += sizeof(v16);
    v16 = htons(44);
    memcpy(pkt + off, &v16, sizeof(v16));
    off += sizeof(v16);

    v16 = htons(256);
    memcpy(pkt + off, &v16, sizeof(v16));
    off += sizeof(v16);
    v16 = htons(9);
    memcpy(pkt + off, &v16, sizeof(v16));
    off += sizeof(v16);

    {
        __u16 fields[][2] = {
            {1, 4}, {2, 4}, {10, 4}, {7, 2}, {8, 4}, {11, 2}, {12, 4}, {4, 1}, {5, 1}
        };
        size_t i;
        for (i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
            v16 = htons(fields[i][0]);
            memcpy(pkt + off, &v16, sizeof(v16));
            off += sizeof(v16);
            v16 = htons(fields[i][1]);
            memcpy(pkt + off, &v16, sizeof(v16));
            off += sizeof(v16);
        }
    }

    sendto(rt->netflow_sock, pkt, off, 0,
           (const struct sockaddr *)&rt->netflow_collector,
           sizeof(rt->netflow_collector));

    rt->netflow_template_sent = true;
    rt->netflow_template_last = time(NULL);
}

static void send_netflow_data(struct exporter_runtime *rt, const struct sflow_sample_event *evt)
{
    __u8 pkt[256];
    size_t off = 0;
    __u16 v16;
    __u32 v32;
    __u8 proto;
    __u8 tos;
    uint32_t now = (uint32_t)time(NULL);

    if (!rt->netflow_template_sent || time(NULL) - rt->netflow_template_last >= 30)
        send_netflow_template(rt);

    v16 = htons(9);
    memcpy(pkt + off, &v16, sizeof(v16));
    off += sizeof(v16);
    v16 = htons(1);
    memcpy(pkt + off, &v16, sizeof(v16));
    off += sizeof(v16);
    v32 = htonl(uptime_ms(rt));
    memcpy(pkt + off, &v32, sizeof(v32));
    off += sizeof(v32);
    v32 = htonl(now);
    memcpy(pkt + off, &v32, sizeof(v32));
    off += sizeof(v32);
    v32 = htonl(rt->netflow_seq++);
    memcpy(pkt + off, &v32, sizeof(v32));
    off += sizeof(v32);
    v32 = htonl(rt->netflow_src_id);
    memcpy(pkt + off, &v32, sizeof(v32));
    off += sizeof(v32);

    v16 = htons(256);
    memcpy(pkt + off, &v16, sizeof(v16));
    off += sizeof(v16);
    v16 = htons(28);
    memcpy(pkt + off, &v16, sizeof(v16));
    off += sizeof(v16);

    v32 = htonl(evt->packet_len);
    memcpy(pkt + off, &v32, sizeof(v32));
    off += sizeof(v32);
    v32 = htonl(1);
    memcpy(pkt + off, &v32, sizeof(v32));
    off += sizeof(v32);
    v32 = htonl(evt->ifindex);
    memcpy(pkt + off, &v32, sizeof(v32));
    off += sizeof(v32);
    memcpy(pkt + off, &evt->src_port, sizeof(evt->src_port));
    off += sizeof(evt->src_port);
    memcpy(pkt + off, &evt->src_ip, sizeof(evt->src_ip));
    off += sizeof(evt->src_ip);
    memcpy(pkt + off, &evt->dst_port, sizeof(evt->dst_port));
    off += sizeof(evt->dst_port);
    memcpy(pkt + off, &evt->dst_ip, sizeof(evt->dst_ip));
    off += sizeof(evt->dst_ip);
    proto = evt->protocol;
    memcpy(pkt + off, &proto, sizeof(proto));
    off += sizeof(proto);
    tos = (evt->dscp & 0x3f) << 2;
    memcpy(pkt + off, &tos, sizeof(tos));
    off += sizeof(tos);

    sendto(rt->netflow_sock, pkt, off, 0,
           (const struct sockaddr *)&rt->netflow_collector,
           sizeof(rt->netflow_collector));
}

static int read_sflow_drop_counters(struct exporter_runtime *rt)
{
    int ncpus;
    struct sflow_counters total = {};
    struct sflow_counters *values;
    __u32 key = 0;

    if (rt->sflow_counter_fd < 0)
        return 0;

    ncpus = libbpf_num_possible_cpus();
    if (ncpus <= 0)
        return -EINVAL;

    values = calloc((size_t)ncpus, sizeof(*values));
    if (!values)
        return -ENOMEM;

    if (bpf_map_lookup_elem(rt->sflow_counter_fd, &key, values) == 0) {
        int i;
        for (i = 0; i < ncpus; i++) {
            total.packets_seen += values[i].packets_seen;
            total.packets_sampled += values[i].packets_sampled;
            total.bytes_sampled += values[i].bytes_sampled;
            total.sample_drops += values[i].sample_drops;
        }
        rt->sample_drops = total.sample_drops;
    }

    free(values);
    return 0;
}

static int ringbuf_handler(void *ctx, void *data, size_t data_sz)
{
    struct exporter_runtime *rt = ctx;
    const struct sflow_sample_event *evt = data;

    if (data_sz < sizeof(*evt))
        return 0;

    if (evt->event_type != SFLOW_SAMPLE_EVENT_TYPE)
        return 0;

    read_sflow_drop_counters(rt);

    if (send_sflow_flow_sample(rt, evt) < 0)
        RS_LOG_WARN("Failed to send sFlow flow sample");

    send_netflow_data(rt, evt);
    return 0;
}

static void export_interface_counters(struct exporter_runtime *rt)
{
    int ncpus;
    struct rs_stats *values;
    __u32 ifindex;

    if (rt->rs_stats_fd < 0)
        return;

    ncpus = libbpf_num_possible_cpus();
    if (ncpus <= 0)
        return;

    values = calloc((size_t)ncpus, sizeof(*values));
    if (!values)
        return;

    for (ifindex = 0; ifindex < 64; ifindex++) {
        struct rs_stats total = {};
        bool nonzero = false;
        int i;

        if (bpf_map_lookup_elem(rt->rs_stats_fd, &ifindex, values) < 0)
            continue;

        for (i = 0; i < ncpus; i++) {
            total.rx_packets += values[i].rx_packets;
            total.rx_bytes += values[i].rx_bytes;
            total.tx_packets += values[i].tx_packets;
            total.tx_bytes += values[i].tx_bytes;
            total.rx_drops += values[i].rx_drops;
            total.tx_drops += values[i].tx_drops;
            total.rx_errors += values[i].rx_errors;
            total.tx_errors += values[i].tx_errors;
        }

        nonzero = total.rx_packets || total.tx_packets || total.rx_bytes || total.tx_bytes ||
                  total.rx_drops || total.tx_drops || total.rx_errors || total.tx_errors;
        if (!nonzero)
            continue;

        if (send_sflow_counter_sample(rt, ifindex, &total) < 0)
            RS_LOG_WARN("Failed to send sFlow counter sample for ifindex=%u", ifindex);
    }

    free(values);
}

static int configure_sampling_map(struct exporter_runtime *rt)
{
    struct sflow_config cfg = {
        .enabled = 1,
        .sample_rate = rt->sample_rate,
        .max_header_bytes = rt->max_header_bytes,
        .pad = 0,
    };
    __u32 key = 0;

    if (rt->sflow_cfg_fd < 0)
        return -EINVAL;

    if (bpf_map_update_elem(rt->sflow_cfg_fd, &key, &cfg, BPF_ANY) < 0)
        return -errno;

    return 0;
}

static void close_runtime(struct exporter_runtime *rt)
{
    if (rt->rb)
        ring_buffer__free(rt->rb);
    if (rt->event_bus_fd >= 0)
        close(rt->event_bus_fd);
    if (rt->sflow_cfg_fd >= 0)
        close(rt->sflow_cfg_fd);
    if (rt->sflow_counter_fd >= 0)
        close(rt->sflow_counter_fd);
    if (rt->rs_stats_fd >= 0)
        close(rt->rs_stats_fd);
    if (rt->sflow_sock >= 0)
        close(rt->sflow_sock);
    if (rt->netflow_sock >= 0)
        close(rt->netflow_sock);
}

int main(int argc, char **argv)
{
    struct exporter_runtime rt;
    static const struct option options[] = {
        {"collector", required_argument, NULL, 'c'},
        {"agent-ip", required_argument, NULL, 'a'},
        {"sample-rate", required_argument, NULL, 's'},
        {"netflow-collector", required_argument, NULL, 'n'},
        {"help", no_argument, NULL, 'h'},
        {0, 0, 0, 0},
    };
    char collector_arg[64] = SFLOW_DEFAULT_COLLECTOR;
    char netflow_arg[64] = SFLOW_DEFAULT_NETFLOW_COLLECTOR;
    char agent_ip_arg[32] = "127.0.0.1";
    time_t last_counter_export;
    int opt;

    memset(&rt, 0, sizeof(rt));
    rt.event_bus_fd = -1;
    rt.sflow_sock = -1;
    rt.netflow_sock = -1;
    rt.sflow_cfg_fd = -1;
    rt.sflow_counter_fd = -1;
    rt.rs_stats_fd = -1;
    rt.sample_rate = SFLOW_DEFAULT_SAMPLE_RATE;
    rt.max_header_bytes = SFLOW_DEFAULT_HEADER_BYTES;
    rt.start_ns = now_ns();
    rt.netflow_src_id = 1;

    rs_log_init("rswitch-sflow", RS_LOG_LEVEL_INFO);

    while ((opt = getopt_long(argc, argv, "c:a:s:n:h", options, NULL)) != -1) {
        switch (opt) {
        case 'c':
            strncpy(collector_arg, optarg, sizeof(collector_arg) - 1);
            collector_arg[sizeof(collector_arg) - 1] = '\0';
            break;
        case 'a':
            strncpy(agent_ip_arg, optarg, sizeof(agent_ip_arg) - 1);
            agent_ip_arg[sizeof(agent_ip_arg) - 1] = '\0';
            break;
        case 's': {
            long rate = strtol(optarg, NULL, 10);
            if (rate > 0)
                rt.sample_rate = (__u32)rate;
            break;
        }
        case 'n':
            strncpy(netflow_arg, optarg, sizeof(netflow_arg) - 1);
            netflow_arg[sizeof(netflow_arg) - 1] = '\0';
            break;
        case 'h':
            RS_LOG_INFO("Usage: %s [--collector IP:port] [--agent-ip IP] [--sample-rate N] [--netflow-collector IP:port]", argv[0]);
            return 0;
        default:
            RS_LOG_ERROR("Invalid arguments");
            return 1;
        }
    }

    if (parse_ip_port(collector_arg, &rt.sflow_collector) < 0) {
        RS_LOG_ERROR("Invalid collector address: %s", collector_arg);
        return 1;
    }

    if (parse_ip_port(netflow_arg, &rt.netflow_collector) < 0) {
        RS_LOG_ERROR("Invalid NetFlow collector address: %s", netflow_arg);
        return 1;
    }

    if (inet_pton(AF_INET, agent_ip_arg, &rt.agent_ip) != 1) {
        RS_LOG_ERROR("Invalid agent IP: %s", agent_ip_arg);
        return 1;
    }

    rt.sflow_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (rt.sflow_sock < 0) {
        RS_LOG_ERROR("Failed to create sFlow UDP socket: %s", strerror(errno));
        return 1;
    }

    rt.netflow_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (rt.netflow_sock < 0) {
        RS_LOG_ERROR("Failed to create NetFlow UDP socket: %s", strerror(errno));
        close_runtime(&rt);
        return 1;
    }

    rt.event_bus_fd = bpf_obj_get(RS_EVENT_BUS_PATH);
    rt.sflow_cfg_fd = bpf_obj_get(SFLOW_CONFIG_MAP_PATH);
    rt.sflow_counter_fd = bpf_obj_get(SFLOW_COUNTER_MAP_PATH);
    rt.rs_stats_fd = bpf_obj_get(RS_STATS_MAP_PATH);

    if (rt.event_bus_fd < 0 || rt.sflow_cfg_fd < 0) {
        RS_LOG_ERROR("Failed to open required BPF maps: %s", strerror(errno));
        close_runtime(&rt);
        return 1;
    }

    if (configure_sampling_map(&rt) < 0)
        RS_LOG_WARN("Failed to update sFlow config map; existing config will be used");

    rt.rb = ring_buffer__new(rt.event_bus_fd, ringbuf_handler, &rt, NULL);
    if (!rt.rb) {
        RS_LOG_ERROR("Failed to create ringbuf consumer: %s", strerror(errno));
        close_runtime(&rt);
        return 1;
    }

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    RS_LOG_INFO("sFlow exporter started collector=%s agent_ip=%s sample_rate=1:%u netflow=%s",
                collector_arg, agent_ip_arg, rt.sample_rate, netflow_arg);

    last_counter_export = time(NULL);
    while (g_running) {
        int ret = ring_buffer__poll(rt.rb, 200);
        time_t now = time(NULL);

        if (ret < 0 && ret != -EINTR)
            RS_LOG_WARN("ring_buffer__poll returned %d", ret);

        if (now - last_counter_export >= SFLOW_COUNTER_EXPORT_INTERVAL_SEC) {
            export_interface_counters(&rt);
            last_counter_export = now;
        }
    }

    RS_LOG_INFO("sFlow exporter shutting down");
    close_runtime(&rt);
    return 0;
}
