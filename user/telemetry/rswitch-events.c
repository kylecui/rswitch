// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * rswitch-events - Event Consumer for rSwitch Telemetry
 * 
 * Consumes events from BPF ringbuf and processes them for:
 * - Real-time logging
 * - Event aggregation
 * - Alerting integration
 * - ML/Analytics pipeline
 * 
 * Event Types:
 * - MAC learning/aging events
 * - ACL drop events 
 * - QoS rate limiting events
 * - Routing failures
 * - Congestion events
 * - Module errors
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/perf_event.h>
#if __has_include("rs_log.h")
#include "rs_log.h"
#else
#include "../common/rs_log.h"
#endif
#include "../../sdk/include/rswitch_obs.h"

enum rs_legacy_event_type {
    RS_LEGACY_EVENT_MAC_LEARNED = 1,
    RS_LEGACY_EVENT_MAC_AGED = 2,
    RS_LEGACY_EVENT_MAC_MOVED = 3,
    RS_LEGACY_EVENT_ACL_DROP = 4,
    RS_LEGACY_EVENT_QOS_RATE_LIMITED = 5,
    RS_LEGACY_EVENT_QOS_CONGESTION = 6,
    RS_LEGACY_EVENT_ROUTE_MISS = 7,
    RS_LEGACY_EVENT_ARP_LEARNED = 8,
    RS_LEGACY_EVENT_VLAN_VIOLATION = 9,
    RS_LEGACY_EVENT_MODULE_ERROR = 10,
};

// Common event header
struct rs_event_header {
    __u8  type;           // enum rs_event_type
    __u8  priority;       // Event priority (0=low, 3=critical)
    __u16 size;           // Total event size including header
    __u32 ifindex;        // Source interface
    __u64 timestamp_ns;   // Kernel timestamp
} __attribute__((packed));

// MAC learning event
struct rs_event_mac_learned {
    struct rs_event_header hdr;
    __u8  mac[6];
    __u16 vlan_id;
    __u32 prev_ifindex;   // 0 if new, != 0 if moved
} __attribute__((packed));

// ACL drop event
struct rs_event_acl_drop {
    struct rs_event_header hdr;
    __u8  proto;
    __u8  acl_level;      // Which ACL level triggered (1-7)
    __u16 sport;
    __u16 dport;
    __u16 pad;
    __u32 src_ip;
    __u32 dst_ip;
} __attribute__((packed));

// QoS rate limiting event
struct rs_event_qos_rate_limited {
    struct rs_event_header hdr;
    __u8  priority;
    __u8  drop_precedence;
    __u16 packet_len;
    __u32 rate_bps;
    __u64 bucket_tokens_remaining;
} __attribute__((packed));

// QoS congestion event
struct rs_event_qos_congestion {
    struct rs_event_header hdr;
    __u32 queue_depth_packets;
    __u32 queue_depth_bytes;
    __u32 threshold_packets;
    __u8  action;         // 0=drop, 1=ecn_mark
    __u8  pad[3];
} __attribute__((packed));

// Route miss event
struct rs_event_route_miss {
    struct rs_event_header hdr;
    __u32 dest_ip;
    __u32 src_ip;
    __u8  ttl;
    __u8  proto;
    __u16 pad;
} __attribute__((packed));

// ARP learning event
struct rs_event_arp_learned {
    struct rs_event_header hdr;
    __u32 ip;
    __u8  mac[6];
    __u8  is_update;      // 0=new, 1=update
    __u8  pad;
} __attribute__((packed));

// Event processing context
struct event_ctx {
    struct ring_buffer *rb;
    volatile int running;
    
    // Event counters
    uint64_t total_events;
    uint64_t events_by_type[16];
    uint64_t events_by_priority[4];
    
    // Configuration
    int verbose;
    int json_output;
    int syslog_enabled;
    const char *output_file;
    FILE *output_fp;
    
    // Rate limiting for noisy events
    struct {
        uint64_t last_event_ns;
        uint32_t event_count;
        uint32_t rate_limit_ms;
    } rate_limit[16];  // Per event type
};

static struct event_ctx g_ctx = {0};

static const char *event_type_names[] = {
    [RS_LEGACY_EVENT_MAC_LEARNED] = "MAC_LEARNED",
    [RS_LEGACY_EVENT_MAC_AGED] = "MAC_AGED", 
    [RS_LEGACY_EVENT_MAC_MOVED] = "MAC_MOVED",
    [RS_LEGACY_EVENT_ACL_DROP] = "ACL_DROP",
    [RS_LEGACY_EVENT_QOS_RATE_LIMITED] = "QOS_RATE_LIMITED",
    [RS_LEGACY_EVENT_QOS_CONGESTION] = "QOS_CONGESTION",
    [RS_LEGACY_EVENT_ROUTE_MISS] = "ROUTE_MISS",
    [RS_LEGACY_EVENT_ARP_LEARNED] = "ARP_LEARNED",
    [RS_LEGACY_EVENT_VLAN_VIOLATION] = "VLAN_VIOLATION",
    [RS_LEGACY_EVENT_MODULE_ERROR] = "MODULE_ERROR",
};

static const char *priority_names[] = {
    [0] = "LOW",
    [1] = "NORMAL", 
    [2] = "HIGH",
    [3] = "CRITICAL",
};

static const char *module_id_to_name(__u16 mod_id)
{
    static char buf[32];

    switch (mod_id) {
    case RS_MOD_DISPATCHER: return "dispatcher";
    case RS_MOD_VLAN: return "vlan";
    case RS_MOD_QOS_CLASSIFY: return "qos_classify";
    case RS_MOD_ACL: return "acl";
    case RS_MOD_ROUTE: return "route";
    case RS_MOD_FLOW_TABLE: return "flow_table";
    case RS_MOD_MIRROR: return "mirror";
    case RS_MOD_L2LEARN: return "l2learn";
    case RS_MOD_SFLOW: return "sflow";
    case RS_MOD_LASTCALL: return "lastcall";
    case RS_MOD_EGRESS: return "egress";
    case RS_MOD_EGRESS_QOS: return "egress_qos";
    case RS_MOD_EGRESS_VLAN: return "egress_vlan";
    case RS_MOD_EGRESS_FINAL: return "egress_final";
    case RS_MOD_VETH_EGRESS: return "veth_egress";
    default:
        if (mod_id >= RS_MOD_USER_BASE) {
            snprintf(buf, sizeof(buf), "user_%u", mod_id);
            return buf;
        }
        return "unknown";
    }
}

static const char *drop_reason_to_name(__u16 reason)
{
    static char reason_buf[32];

    switch (reason) {
    case RS_DROP_PARSE_ETH: return "PARSE_ETH";
    case RS_DROP_PARSE_VLAN_TAG: return "PARSE_VLAN_TAG";
    case RS_DROP_PARSE_IP: return "PARSE_IP";
    case RS_DROP_ACL_DENY: return "ACL_DENY";
    case RS_DROP_NO_ROUTE: return "NO_ROUTE";
    case RS_DROP_TTL_EXCEEDED: return "TTL_EXCEEDED";
    case RS_DROP_QUEUE_FULL: return "QUEUE_FULL";
    case RS_DROP_RATE_EXCEEDED: return "RATE_EXCEEDED";
    case RS_DROP_TAILCALL_FAIL: return "TAILCALL_FAIL";
    case RS_DROP_INTERNAL: return "INTERNAL";
    case RS_DROP_REDIRECT_FAIL: return "REDIRECT_FAIL";
    default:
        snprintf(reason_buf, sizeof(reason_buf), "reason_%u", reason);
        return reason_buf;
    }
}

static const char *obs_event_type_to_name(__u16 type)
{
    switch (type) {
    case RS_EVENT_OBS_SAMPLE:
        return "OBS_SAMPLE";
    case RS_EVENT_OBS_DROP:
        return "OBS_DROP";
    case RS_EVENT_OBS_REDIRECT_ERR:
        return "OBS_REDIRECT_ERR";
    case RS_EVENT_OBS_PROFILE_MARK:
        return "OBS_PROFILE_MARK";
    default:
        return "OBS_UNKNOWN";
    }
}

// Get current time in ISO8601 format
static void get_iso8601_timestamp(char *buf, size_t size)
{
    time_t now = time(NULL);
    struct tm *tm_info = gmtime(&now);
    strftime(buf, size, "%Y-%m-%dT%H:%M:%SZ", tm_info);
}

// Convert kernel timestamp to ISO8601
static void ktime_to_iso8601(__u64 ktime_ns, char *buf, size_t size)
{
    // This is approximate - proper implementation would need boot time offset
    time_t sec = ktime_ns / 1000000000ULL;
    struct tm *tm_info = gmtime(&sec);
    strftime(buf, size, "%Y-%m-%dT%H:%M:%SZ", tm_info);
}

// Check if event should be rate limited
static int should_rate_limit(struct event_ctx *ctx, __u8 event_type, __u64 timestamp_ns)
{
    if (event_type >= 16)
        return 0;
    
    typeof(ctx->rate_limit[0]) *rl = &ctx->rate_limit[event_type];
    
    // Set rate limits per event type
    switch (event_type) {
    case RS_LEGACY_EVENT_MAC_LEARNED:
        rl->rate_limit_ms = 100;  // Max 10/sec
        break;
    case RS_LEGACY_EVENT_ACL_DROP:
        rl->rate_limit_ms = 1000; // Max 1/sec (can be noisy)
        break;
    case RS_LEGACY_EVENT_QOS_RATE_LIMITED:
        rl->rate_limit_ms = 5000; // Max 1/5sec (very noisy)
        break;
    default:
        rl->rate_limit_ms = 0;    // No rate limit
        return 0;
    }
    
    uint64_t elapsed_ms = (timestamp_ns - rl->last_event_ns) / 1000000;
    
    if (elapsed_ms < rl->rate_limit_ms) {
        rl->event_count++;
        return 1;  // Rate limited
    }
    
    rl->last_event_ns = timestamp_ns;
    if (rl->event_count > 0) {
        // Log dropped event count
        if (ctx->verbose) {
            printf("Rate limited %u %s events in last %u ms\n", 
                   rl->event_count, event_type_names[event_type], rl->rate_limit_ms);
        }
        rl->event_count = 0;
    }
    
    return 0;  // Allow
}

// Process MAC learning event
static void process_mac_learned_event(struct event_ctx *ctx, struct rs_event_mac_learned *event)
{
    char timestamp[32];
    ktime_to_iso8601(event->hdr.timestamp_ns, timestamp, sizeof(timestamp));
    
    if (ctx->json_output) {
        fprintf(ctx->output_fp, 
            "{"
            "\"timestamp\": \"%s\", "
            "\"type\": \"MAC_LEARNED\", "
            "\"ifindex\": %u, "
            "\"mac\": \"%02x:%02x:%02x:%02x:%02x:%02x\", "
            "\"vlan\": %u, "
            "\"moved\": %s"
            "}\n",
            timestamp, event->hdr.ifindex,
            event->mac[0], event->mac[1], event->mac[2],
            event->mac[3], event->mac[4], event->mac[5],
            event->vlan_id,
            event->prev_ifindex != 0 ? "true" : "false");
    } else {
        fprintf(ctx->output_fp, "[%s] MAC_LEARNED: %02x:%02x:%02x:%02x:%02x:%02x on ifindex=%u vlan=%u%s\n",
                timestamp,
                event->mac[0], event->mac[1], event->mac[2],
                event->mac[3], event->mac[4], event->mac[5],
                event->hdr.ifindex, event->vlan_id,
                event->prev_ifindex != 0 ? " (moved)" : "");
    }
    
    fflush(ctx->output_fp);
}

// Process ACL drop event
static void process_acl_drop_event(struct event_ctx *ctx, struct rs_event_acl_drop *event)
{
    char timestamp[32], src_ip[16], dst_ip[16];
    ktime_to_iso8601(event->hdr.timestamp_ns, timestamp, sizeof(timestamp));
    
    struct in_addr addr;
    addr.s_addr = event->src_ip;
    strcpy(src_ip, inet_ntoa(addr));
    addr.s_addr = event->dst_ip;
    strcpy(dst_ip, inet_ntoa(addr));
    
    if (ctx->json_output) {
        fprintf(ctx->output_fp,
            "{"
            "\"timestamp\": \"%s\", "
            "\"type\": \"ACL_DROP\", "
            "\"ifindex\": %u, "
            "\"proto\": %u, "
            "\"src_ip\": \"%s\", "
            "\"dst_ip\": \"%s\", "
            "\"sport\": %u, "
            "\"dport\": %u, "
            "\"acl_level\": %u"
            "}\n",
            timestamp, event->hdr.ifindex, event->proto,
            src_ip, dst_ip, ntohs(event->sport), ntohs(event->dport), 
            event->acl_level);
    } else {
        fprintf(ctx->output_fp, "[%s] ACL_DROP: proto=%u %s:%u → %s:%u (L%u) on ifindex=%u\n",
                timestamp, event->proto, src_ip, ntohs(event->sport),
                dst_ip, ntohs(event->dport), event->acl_level, event->hdr.ifindex);
    }
    
    fflush(ctx->output_fp);
}

// Process QoS rate limited event  
static void process_qos_rate_limited_event(struct event_ctx *ctx, struct rs_event_qos_rate_limited *event)
{
    char timestamp[32];
    ktime_to_iso8601(event->hdr.timestamp_ns, timestamp, sizeof(timestamp));
    
    if (ctx->json_output) {
        fprintf(ctx->output_fp,
            "{"
            "\"timestamp\": \"%s\", "
            "\"type\": \"QOS_RATE_LIMITED\", "
            "\"ifindex\": %u, "
            "\"priority\": %u, "
            "\"packet_len\": %u, "
            "\"rate_bps\": %u, "
            "\"tokens_remaining\": %llu"
            "}\n",
            timestamp, event->hdr.ifindex, event->priority, 
            event->packet_len, event->rate_bps, 
            (unsigned long long)event->bucket_tokens_remaining);
    } else {
        fprintf(ctx->output_fp, "[%s] QOS_RATE_LIMITED: priority=%u len=%u rate=%u bps tokens=%llu on ifindex=%u\n",
                timestamp, event->priority, event->packet_len, event->rate_bps,
                (unsigned long long)event->bucket_tokens_remaining, event->hdr.ifindex);
    }
    
    fflush(ctx->output_fp);
}

// Process ARP learned event
static void process_arp_learned_event(struct event_ctx *ctx, struct rs_event_arp_learned *event)
{
    char timestamp[32], ip[16];
    ktime_to_iso8601(event->hdr.timestamp_ns, timestamp, sizeof(timestamp));
    
    struct in_addr addr;
    addr.s_addr = event->ip;
    strcpy(ip, inet_ntoa(addr));
    
    if (ctx->json_output) {
        fprintf(ctx->output_fp,
            "{"
            "\"timestamp\": \"%s\", "
            "\"type\": \"ARP_LEARNED\", "
            "\"ifindex\": %u, "
            "\"ip\": \"%s\", "
            "\"mac\": \"%02x:%02x:%02x:%02x:%02x:%02x\", "
            "\"is_update\": %s"
            "}\n",
            timestamp, event->hdr.ifindex, ip,
            event->mac[0], event->mac[1], event->mac[2],
            event->mac[3], event->mac[4], event->mac[5],
            event->is_update ? "true" : "false");
    } else {
        fprintf(ctx->output_fp, "[%s] ARP_LEARNED: %s → %02x:%02x:%02x:%02x:%02x:%02x%s on ifindex=%u\n",
                timestamp, ip,
                event->mac[0], event->mac[1], event->mac[2],
                event->mac[3], event->mac[4], event->mac[5],
                event->is_update ? " (updated)" : "", event->hdr.ifindex);
    }
    
    fflush(ctx->output_fp);
}

static int is_obs_event(void *data, size_t data_sz)
{
    __u16 etype;

    if (data_sz < sizeof(struct rs_obs_event))
        return 0;

    memcpy(&etype, data, sizeof(etype));
    return (etype >= RS_EVENT_OBS_SAMPLE && etype <= RS_EVENT_OBS_PROFILE_MARK);
}

static void process_obs_sample_event(struct event_ctx *ctx, struct rs_obs_event *evt)
{
    char timestamp[32], src_ip[16], dst_ip[16];
    struct in_addr addr;

    ktime_to_iso8601(evt->ts_ns, timestamp, sizeof(timestamp));
    addr.s_addr = evt->saddr;
    strcpy(src_ip, inet_ntoa(addr));
    addr.s_addr = evt->daddr;
    strcpy(dst_ip, inet_ntoa(addr));

    if (ctx->json_output) {
        fprintf(ctx->output_fp,
            "{"
            "\"timestamp\": \"%s\", "
            "\"type\": \"%s\", "
            "\"ifindex\": %u, "
            "\"pipeline_id\": %u, "
            "\"profile_id\": %u, "
            "\"stage_id\": %u, "
            "\"module_id\": %u, "
            "\"module\": \"%s\", "
            "\"pkt_len\": %u, "
            "\"action\": %u, "
            "\"reason\": %u, "
            "\"reason_name\": \"%s\", "
            "\"ip_proto\": %u, "
            "\"flow_hash\": %u, "
            "\"src_ip\": \"%s\", "
            "\"dst_ip\": \"%s\""
            "}\n",
            timestamp,
            obs_event_type_to_name(evt->event_type),
            evt->ifindex,
            evt->pipeline_id,
            evt->profile_id,
            evt->stage_id,
            evt->module_id,
            module_id_to_name(evt->module_id),
            evt->pkt_len,
            evt->action,
            evt->reason,
            drop_reason_to_name(evt->reason),
            evt->ip_proto,
            evt->flow_hash,
            src_ip,
            dst_ip);
    } else {
        fprintf(ctx->output_fp,
            "[%s] %s: ifindex=%u pipe=%u profile=%u stage=%u module=%s(%u) len=%u action=%u reason=%s(%u) proto=%u hash=%u %s:%u -> %s:%u\n",
            timestamp,
            obs_event_type_to_name(evt->event_type),
            evt->ifindex,
            evt->pipeline_id,
            evt->profile_id,
            evt->stage_id,
            module_id_to_name(evt->module_id),
            evt->module_id,
            evt->pkt_len,
            evt->action,
            drop_reason_to_name(evt->reason),
            evt->reason,
            evt->ip_proto,
            evt->flow_hash,
            src_ip,
            ntohs(evt->sport),
            dst_ip,
            ntohs(evt->dport));
    }

    fflush(ctx->output_fp);
}

static void process_obs_drop_event(struct event_ctx *ctx, struct rs_obs_event *evt)
{
    process_obs_sample_event(ctx, evt);
}

static void process_obs_redirect_err_event(struct event_ctx *ctx, struct rs_obs_event *evt)
{
    process_obs_sample_event(ctx, evt);
}

static void process_obs_profile_mark_event(struct event_ctx *ctx, struct rs_obs_event *evt)
{
    process_obs_sample_event(ctx, evt);
}

// Main event handler callback
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    struct event_ctx *ectx = ctx;

    if (is_obs_event(data, data_sz)) {
        struct rs_obs_event *obs = data;

        ectx->total_events++;
        switch (obs->event_type) {
        case RS_EVENT_OBS_SAMPLE:
            process_obs_sample_event(ectx, obs);
            break;
        case RS_EVENT_OBS_DROP:
            process_obs_drop_event(ectx, obs);
            break;
        case RS_EVENT_OBS_REDIRECT_ERR:
            process_obs_redirect_err_event(ectx, obs);
            break;
        case RS_EVENT_OBS_PROFILE_MARK:
            process_obs_profile_mark_event(ectx, obs);
            break;
        default:
            break;
        }
        return 0;
    }

    struct rs_event_header *hdr = data;
    
    if (data_sz < sizeof(*hdr)) {
        RS_LOG_ERROR("Invalid event: size %zu < header size %zu", data_sz, sizeof(*hdr));
        return 0;
    }
    
    if (hdr->size > data_sz) {
        RS_LOG_ERROR("Invalid event: declared size %u > actual size %zu", hdr->size, data_sz);
        return 0;
    }
    
    // Update counters
    ectx->total_events++;
    if (hdr->type < 16)
        ectx->events_by_type[hdr->type]++;
    if (hdr->priority < 4)
        ectx->events_by_priority[hdr->priority]++;
    
    // Rate limiting check
    if (should_rate_limit(ectx, hdr->type, hdr->timestamp_ns)) {
        return 0;  // Skip this event
    }
    
    // Process by event type
    switch (hdr->type) {
    case RS_LEGACY_EVENT_MAC_LEARNED:
        if (data_sz >= sizeof(struct rs_event_mac_learned))
            process_mac_learned_event(ectx, data);
        break;
        
    case RS_LEGACY_EVENT_ACL_DROP:
        if (data_sz >= sizeof(struct rs_event_acl_drop))
            process_acl_drop_event(ectx, data);
        break;
        
    case RS_LEGACY_EVENT_QOS_RATE_LIMITED:
        if (data_sz >= sizeof(struct rs_event_qos_rate_limited))
            process_qos_rate_limited_event(ectx, data);
        break;
        
    case RS_LEGACY_EVENT_ARP_LEARNED:
        if (data_sz >= sizeof(struct rs_event_arp_learned))
            process_arp_learned_event(ectx, data);
        break;
        
    default:
        if (ectx->verbose) {
            char timestamp[32];
            ktime_to_iso8601(hdr->timestamp_ns, timestamp, sizeof(timestamp));
            fprintf(ectx->output_fp, "[%s] UNKNOWN_EVENT: type=%u priority=%s ifindex=%u\n",
                    timestamp, hdr->type, priority_names[hdr->priority], hdr->ifindex);
            fflush(ectx->output_fp);
        }
        break;
    }
    
    return 0;
}

// Signal handler for graceful shutdown
static void sig_int(int signo)
{
    g_ctx.running = 0;
}

// Print usage
static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [options]\n", prog);
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -j, --json        Output events as JSON\n");
    fprintf(stderr, "  -v, --verbose     Verbose output\n");
    fprintf(stderr, "  -o, --output FILE Write to file instead of stdout\n");
    fprintf(stderr, "  -h, --help        Show this help\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Examples:\n");
    fprintf(stderr, "  %s                     # Stream events to stdout\n", prog);
    fprintf(stderr, "  %s -j                  # Stream as JSON\n", prog);
    fprintf(stderr, "  %s -o events.log       # Log to file\n", prog);
    fprintf(stderr, "  %s -j -o events.jsonl  # JSON logs to file\n", prog);
}

// Show statistics
static void show_stats(struct event_ctx *ctx)
{
    printf("\n=== Event Statistics ===\n");
    printf("Total events: %llu\n", (unsigned long long)ctx->total_events);
    
    printf("\nBy type:\n");
    for (int i = 0; i < 16; i++) {
        if (ctx->events_by_type[i] > 0) {
            const char *name = (i < sizeof(event_type_names)/sizeof(event_type_names[0])) 
                              ? event_type_names[i] : "UNKNOWN";
            printf("  %-20s: %llu\n", name, (unsigned long long)ctx->events_by_type[i]);
        }
    }
    
    printf("\nBy priority:\n");
    for (int i = 0; i < 4; i++) {
        if (ctx->events_by_priority[i] > 0) {
            printf("  %-8s: %llu\n", priority_names[i], (unsigned long long)ctx->events_by_priority[i]);
        }
    }
    printf("\n");
}

int main(int argc, char **argv)
{
    rs_log_init("rswitch-events", RS_LOG_LEVEL_INFO);

    int opt;
    const char *output_file = NULL;
    
    struct option long_options[] = {
        {"json", no_argument, 0, 'j'},
        {"verbose", no_argument, 0, 'v'},
        {"output", required_argument, 0, 'o'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    while ((opt = getopt_long(argc, argv, "jvo:h", long_options, NULL)) != -1) {
        switch (opt) {
        case 'j':
            g_ctx.json_output = 1;
            break;
        case 'v':
            g_ctx.verbose = 1;
            break;
        case 'o':
            output_file = optarg;
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    if (g_ctx.verbose)
        rs_log_set_level(RS_LOG_LEVEL_DEBUG);
    
    // Open output file or use stdout
    if (output_file) {
        g_ctx.output_fp = fopen(output_file, "a");
        if (!g_ctx.output_fp) {
            perror("fopen");
            return 1;
        }
        g_ctx.output_file = output_file;
    } else {
        g_ctx.output_fp = stdout;
    }
    
    // Set up signal handler
    signal(SIGINT, sig_int);
    signal(SIGTERM, sig_int);
    
    // Open BPF ringbuf
    int ringbuf_fd = bpf_obj_get("/sys/fs/bpf/rs_event_ringbuf");
    if (ringbuf_fd < 0) {
        RS_LOG_ERROR("Failed to open event ringbuf (ret=%d)", ringbuf_fd);
        RS_LOG_ERROR("Make sure rSwitch loader is running and events are enabled");
        goto cleanup;
    }
    
    g_ctx.rb = ring_buffer__new(ringbuf_fd, handle_event, &g_ctx, NULL);
    if (!g_ctx.rb) {
        RS_LOG_ERROR("Failed to create ring buffer");
        close(ringbuf_fd);
        goto cleanup;
    }
    
    g_ctx.running = 1;
    
    printf("rSwitch Event Consumer starting\n");
    printf("Output: %s\n", output_file ? output_file : "stdout");
    printf("Format: %s\n", g_ctx.json_output ? "JSON" : "text");
    printf("Press Ctrl+C to stop\n\n");
    
    // Main event loop
    while (g_ctx.running) {
        int ret = ring_buffer__poll(g_ctx.rb, 100 /* timeout_ms */);
        if (ret < 0) {
            RS_LOG_ERROR("Error polling ring buffer: %d", ret);
            break;
        }
    }
    
    printf("\nShutting down...\n");
    show_stats(&g_ctx);
    
    ring_buffer__free(g_ctx.rb);
    close(ringbuf_fd);

cleanup:
    if (g_ctx.output_fp && g_ctx.output_fp != stdout) {
        fclose(g_ctx.output_fp);
    }
    
    return 0;
}
