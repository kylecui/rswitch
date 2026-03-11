#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/types.h>
#include <net/if.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#if __has_include("rs_log.h")
#include "rs_log.h"
#else
#include "../common/rs_log.h"
#endif

#include "../../bpf/core/afxdp_common.h"
#include "prometheus_exporter.h"

#define RS_STATS_MAP_PATH "/sys/fs/bpf/rs_stats_map"
#define RS_MODULE_STATS_MAP_PATH "/sys/fs/bpf/rs_module_stats_map"
#define VOQD_STATE_MAP_PATH "/sys/fs/bpf/voqd_state_map"
#define QDEPTH_MAP_PATH "/sys/fs/bpf/qdepth_map"
#define RS_MAC_TABLE_MAP_PATH "/sys/fs/bpf/rs_mac_table"
#define RS_VLAN_MAP_PATH "/sys/fs/bpf/rs_vlan_map"

#define HTTP_BACKLOG 32
#define HTTP_REQ_BUF 2048
#define METRICS_INIT_CAP (64 * 1024)

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

struct rs_module_stats {
    __u64 packets_processed;
    __u64 packets_forwarded;
    __u64 packets_dropped;
    __u64 packets_error;
    __u64 bytes_processed;
    __u64 last_seen_ns;
    __u32 module_id;
    char name[32];
};

struct metric_family {
    const char *name;
    const char *help;
    const char *type;
};

struct map_handle {
    const char *path;
    int fd;
    bool warned;
};

struct metrics_buf {
    char *data;
    size_t len;
    size_t cap;
};

struct exporter_ctx {
    struct prometheus_exporter_config cfg;
    struct map_handle rs_stats;
    struct map_handle rs_module_stats;
    struct map_handle voqd_state;
    struct map_handle qdepth;
    struct map_handle mac_table;
    struct map_handle vlan_map;
    struct metrics_buf out;
    int ncpus;
    int server_fd;
    struct timespec start_ts;
    struct timespec last_refresh_ts;
};

static volatile sig_atomic_t g_running = 1;

static const struct metric_family g_port_families[] = {
    {"rswitch_port_rx_packets_total", "Total received packets per interface", "counter"},
    {"rswitch_port_tx_packets_total", "Total transmitted packets per interface", "counter"},
    {"rswitch_port_rx_bytes_total", "Total received bytes per interface", "counter"},
    {"rswitch_port_tx_bytes_total", "Total transmitted bytes per interface", "counter"},
    {"rswitch_port_drop_packets_total", "Total dropped packets per interface and direction", "counter"},
    {"rswitch_port_error_packets_total", "Total error packets per interface and direction", "counter"},
};

static const struct metric_family g_module_families[] = {
    {"rswitch_module_packets_processed_total", "Total packets processed per module", "counter"},
    {"rswitch_module_packets_forwarded_total", "Total packets forwarded per module", "counter"},
    {"rswitch_module_packets_dropped_total", "Total packets dropped per module", "counter"},
    {"rswitch_module_bytes_processed_total", "Total bytes processed per module", "counter"},
};

static const struct metric_family g_voqd_families[] = {
    {"rswitch_voqd_mode", "VOQd mode gauge where active mode has value 1", "gauge"},
    {"rswitch_voqd_queue_depth", "VOQd queue depth per port and priority", "gauge"},
};

static const struct metric_family g_static_families[] = {
    {"rswitch_mac_table_entries", "Current number of entries in MAC table", "gauge"},
    {"rswitch_vlan_count", "Current number of configured VLANs", "gauge"},
    {"rswitch_uptime_seconds", "Exporter process uptime in seconds", "gauge"},
    {"rswitch_info", "Static exporter information", "gauge"},
};

static uint64_t ts_ns(const struct timespec *ts)
{
    return (uint64_t)ts->tv_sec * 1000000000ULL + (uint64_t)ts->tv_nsec;
}

static uint64_t monotonic_now_ns(void)
{
    struct timespec ts = {0};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts_ns(&ts);
}

static void handle_signal(int sig)
{
    (void)sig;
    g_running = 0;
}

void prometheus_exporter_default_config(struct prometheus_exporter_config *cfg)
{
    if (!cfg)
        return;
    cfg->port = RSWITCH_PROMETHEUS_DEFAULT_PORT;
    cfg->refresh_interval_sec = RSWITCH_PROMETHEUS_DEFAULT_INTERVAL_SEC;
}

void prometheus_exporter_print_usage(const char *prog)
{
    printf("Usage: %s [options]\n", prog);
    printf("\n");
    printf("Options:\n");
    printf("  -p PORT       Listen port (default: %u)\n", RSWITCH_PROMETHEUS_DEFAULT_PORT);
    printf("  -i INTERVAL   Cache refresh interval seconds (default: %u)\n",
           RSWITCH_PROMETHEUS_DEFAULT_INTERVAL_SEC);
    printf("  -h            Show this help\n");
}

static int parse_u32(const char *s, uint32_t *out)
{
    char *end = NULL;
    unsigned long v;

    if (!s || !out)
        return -EINVAL;
    errno = 0;
    v = strtoul(s, &end, 10);
    if (errno != 0 || !end || *end != '\0' || v > UINT32_MAX)
        return -EINVAL;
    *out = (uint32_t)v;
    return 0;
}

int prometheus_exporter_parse_args(int argc, char **argv,
                                   struct prometheus_exporter_config *cfg)
{
    int opt;

    if (!cfg)
        return -EINVAL;

    while ((opt = getopt(argc, argv, "p:i:h")) != -1) {
        if (opt == 'h') {
            prometheus_exporter_print_usage(argv[0]);
            return 1;
        }
        if (opt == 'p') {
            uint32_t v = 0;
            if (parse_u32(optarg, &v) < 0 || v == 0 || v > 65535) {
                RS_LOG_ERROR("Invalid -p value '%s'", optarg);
                return -EINVAL;
            }
            cfg->port = (__u16)v;
            continue;
        }
        if (opt == 'i') {
            uint32_t v = 0;
            if (parse_u32(optarg, &v) < 0 || v == 0) {
                RS_LOG_ERROR("Invalid -i value '%s'", optarg);
                return -EINVAL;
            }
            cfg->refresh_interval_sec = v;
            continue;
        }
        prometheus_exporter_print_usage(argv[0]);
        return -EINVAL;
    }

    return 0;
}

static void map_close(struct map_handle *m)
{
    if (m && m->fd >= 0) {
        close(m->fd);
        m->fd = -1;
    }
}

static int map_open(struct map_handle *m)
{
    if (!m)
        return -EINVAL;
    if (m->fd >= 0)
        return 0;

    m->fd = bpf_obj_get(m->path);
    if (m->fd < 0) {
        if (!m->warned) {
            RS_LOG_WARN("Map unavailable: %s (%s)", m->path, strerror(errno));
            m->warned = true;
        }
        return -errno;
    }

    if (m->warned)
        RS_LOG_INFO("Map available: %s", m->path);
    m->warned = false;
    return 0;
}

static int map_info(int fd, struct bpf_map_info *info)
{
    __u32 len = sizeof(*info);
    memset(info, 0, sizeof(*info));
    if (bpf_obj_get_info_by_fd(fd, info, &len) < 0)
        return -errno;
    return 0;
}

static int out_reserve(struct metrics_buf *b, size_t extra)
{
    size_t need;
    size_t new_cap;
    char *new_data;

    if (!b)
        return -EINVAL;

    need = b->len + extra + 1;
    if (need <= b->cap)
        return 0;

    new_cap = b->cap ? b->cap : METRICS_INIT_CAP;
    while (new_cap < need)
        new_cap *= 2;

    new_data = realloc(b->data, new_cap);
    if (!new_data)
        return -ENOMEM;

    b->data = new_data;
    b->cap = new_cap;
    return 0;
}

static int out_appendf(struct metrics_buf *b, const char *fmt, ...)
{
    va_list ap;
    va_list ap2;
    int n;

    if (!b || !fmt)
        return -EINVAL;

    va_start(ap, fmt);
    va_copy(ap2, ap);
    n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n < 0) {
        va_end(ap2);
        return -EINVAL;
    }

    if (out_reserve(b, (size_t)n) < 0) {
        va_end(ap2);
        return -ENOMEM;
    }

    vsnprintf(b->data + b->len, b->cap - b->len, fmt, ap2);
    va_end(ap2);
    b->len += (size_t)n;
    return 0;
}

static int out_append_escaped(struct metrics_buf *b, const char *s)
{
    const char *p = s ? s : "";

    for (; *p; p++) {
        if (*p == '\\' || *p == '"') {
            if (out_appendf(b, "\\%c", *p) < 0)
                return -ENOMEM;
        } else if (*p == '\n') {
            if (out_appendf(b, "\\n") < 0)
                return -ENOMEM;
        } else {
            if (out_appendf(b, "%c", *p) < 0)
                return -ENOMEM;
        }
    }

    return 0;
}

static int emit_families(struct metrics_buf *b,
                         const struct metric_family *families,
                         size_t n)
{
    size_t i;

    for (i = 0; i < n; i++) {
        if (out_appendf(b, "# HELP %s %s\n", families[i].name, families[i].help) < 0)
            return -ENOMEM;
        if (out_appendf(b, "# TYPE %s %s\n", families[i].name, families[i].type) < 0)
            return -ENOMEM;
    }

    return 0;
}

static int emit_labeled_u64(struct metrics_buf *b,
                            const char *metric,
                            const char *label_key,
                            const char *label_val,
                            uint64_t value)
{
    if (out_appendf(b, "%s{%s=\"", metric, label_key) < 0)
        return -ENOMEM;
    if (out_append_escaped(b, label_val) < 0)
        return -ENOMEM;
    if (out_appendf(b, "\"} %llu\n", (unsigned long long)value) < 0)
        return -ENOMEM;
    return 0;
}

static int emit_labeled_dir_u64(struct metrics_buf *b,
                                const char *metric,
                                const char *label_key,
                                const char *label_val,
                                const char *dir,
                                uint64_t value)
{
    if (out_appendf(b, "%s{%s=\"", metric, label_key) < 0)
        return -ENOMEM;
    if (out_append_escaped(b, label_val) < 0)
        return -ENOMEM;
    if (out_appendf(b, "\",direction=\"%s\"} %llu\n", dir,
                    (unsigned long long)value) < 0) {
        return -ENOMEM;
    }
    return 0;
}

static void aggregate_port_stats(struct rs_stats *sum,
                                 const void *values,
                                 int ncpus,
                                 size_t value_size)
{
    int c;

    memset(sum, 0, sizeof(*sum));
    for (c = 0; c < ncpus; c++) {
        const struct rs_stats *v;

        v = (const struct rs_stats *)((const char *)values + (size_t)c * value_size);
        sum->rx_packets += v->rx_packets;
        sum->tx_packets += v->tx_packets;
        sum->rx_bytes += v->rx_bytes;
        sum->tx_bytes += v->tx_bytes;
        sum->rx_drops += v->rx_drops;
        sum->tx_drops += v->tx_drops;
        sum->rx_errors += v->rx_errors;
        sum->tx_errors += v->tx_errors;
    }
}

static int emit_port_metrics(struct exporter_ctx *ctx)
{
    struct bpf_map_info info;
    void *values;
    uint32_t key;

    if (emit_families(&ctx->out, g_port_families,
                      sizeof(g_port_families) / sizeof(g_port_families[0])) < 0) {
        return -ENOMEM;
    }

    if (map_open(&ctx->rs_stats) < 0)
        return 0;
    if (map_info(ctx->rs_stats.fd, &info) < 0) {
        map_close(&ctx->rs_stats);
        return 0;
    }

    values = calloc((size_t)ctx->ncpus, info.value_size);
    if (!values)
        return -ENOMEM;

    for (key = 0; key < info.max_entries; key++) {
        struct rs_stats s;
        char ifname[IF_NAMESIZE];
        const char *iface;

        if (bpf_map_lookup_elem(ctx->rs_stats.fd, &key, values) < 0)
            continue;

        aggregate_port_stats(&s, values, ctx->ncpus, info.value_size);
        if (s.rx_packets == 0 && s.tx_packets == 0 && s.rx_bytes == 0 &&
            s.tx_bytes == 0 && s.rx_drops == 0 && s.tx_drops == 0 &&
            s.rx_errors == 0 && s.tx_errors == 0) {
            continue;
        }

        iface = if_indextoname((unsigned int)key, ifname) ? ifname : "unknown";

        if (emit_labeled_u64(&ctx->out, "rswitch_port_rx_packets_total",
                             "interface", iface, s.rx_packets) < 0 ||
            emit_labeled_u64(&ctx->out, "rswitch_port_tx_packets_total",
                             "interface", iface, s.tx_packets) < 0 ||
            emit_labeled_u64(&ctx->out, "rswitch_port_rx_bytes_total",
                             "interface", iface, s.rx_bytes) < 0 ||
            emit_labeled_u64(&ctx->out, "rswitch_port_tx_bytes_total",
                             "interface", iface, s.tx_bytes) < 0 ||
            emit_labeled_dir_u64(&ctx->out, "rswitch_port_drop_packets_total",
                                 "interface", iface, "rx", s.rx_drops) < 0 ||
            emit_labeled_dir_u64(&ctx->out, "rswitch_port_drop_packets_total",
                                 "interface", iface, "tx", s.tx_drops) < 0 ||
            emit_labeled_dir_u64(&ctx->out, "rswitch_port_error_packets_total",
                                 "interface", iface, "rx", s.rx_errors) < 0 ||
            emit_labeled_dir_u64(&ctx->out, "rswitch_port_error_packets_total",
                                 "interface", iface, "tx", s.tx_errors) < 0) {
            free(values);
            return -ENOMEM;
        }
    }

    free(values);
    return 0;
}

static void aggregate_module_stats(struct rs_module_stats *sum,
                                   const void *values,
                                   int ncpus,
                                   size_t value_size,
                                   char *name,
                                   size_t name_len)
{
    int c;

    memset(sum, 0, sizeof(*sum));
    if (name_len > 0)
        name[0] = '\0';

    for (c = 0; c < ncpus; c++) {
        const struct rs_module_stats *v;

        v = (const struct rs_module_stats *)((const char *)values + (size_t)c * value_size);
        sum->packets_processed += v->packets_processed;
        sum->packets_forwarded += v->packets_forwarded;
        sum->packets_dropped += v->packets_dropped;
        sum->packets_error += v->packets_error;
        sum->bytes_processed += v->bytes_processed;

        if (name_len > 0 && name[0] == '\0' && v->name[0] != '\0') {
            strncpy(name, v->name, name_len - 1);
            name[name_len - 1] = '\0';
        }
    }
}

static int emit_module_metrics(struct exporter_ctx *ctx)
{
    struct bpf_map_info info;
    void *values;
    uint32_t key;

    if (emit_families(&ctx->out, g_module_families,
                      sizeof(g_module_families) / sizeof(g_module_families[0])) < 0) {
        return -ENOMEM;
    }

    if (map_open(&ctx->rs_module_stats) < 0)
        return 0;
    if (map_info(ctx->rs_module_stats.fd, &info) < 0) {
        map_close(&ctx->rs_module_stats);
        return 0;
    }

    values = calloc((size_t)ctx->ncpus, info.value_size);
    if (!values)
        return -ENOMEM;

    for (key = 0; key < info.max_entries; key++) {
        struct rs_module_stats s;
        char module_name[32] = {0};
        const char *mod;

        if (bpf_map_lookup_elem(ctx->rs_module_stats.fd, &key, values) < 0)
            continue;

        aggregate_module_stats(&s, values, ctx->ncpus, info.value_size,
                               module_name, sizeof(module_name));

        if (s.packets_processed == 0 && s.packets_forwarded == 0 &&
            s.packets_dropped == 0 && s.bytes_processed == 0 &&
            module_name[0] == '\0') {
            continue;
        }

        mod = module_name[0] ? module_name : "unknown";

        if (emit_labeled_u64(&ctx->out, "rswitch_module_packets_processed_total",
                             "module", mod, s.packets_processed) < 0 ||
            emit_labeled_u64(&ctx->out, "rswitch_module_packets_forwarded_total",
                             "module", mod, s.packets_forwarded) < 0 ||
            emit_labeled_u64(&ctx->out, "rswitch_module_packets_dropped_total",
                             "module", mod, s.packets_dropped) < 0 ||
            emit_labeled_u64(&ctx->out, "rswitch_module_bytes_processed_total",
                             "module", mod, s.bytes_processed) < 0) {
            free(values);
            return -ENOMEM;
        }
    }

    free(values);
    return 0;
}

static int emit_qdepth_metrics(struct exporter_ctx *ctx)
{
    struct qdepth_key cur;
    struct qdepth_key next;

    if (map_open(&ctx->qdepth) < 0)
        return 0;

    if (bpf_map_get_next_key(ctx->qdepth.fd, NULL, &next) != 0)
        return 0;

    while (1) {
        __u32 depth = 0;

        if (bpf_map_lookup_elem(ctx->qdepth.fd, &next, &depth) == 0) {
            if (out_appendf(&ctx->out,
                            "rswitch_voqd_queue_depth{port=\"%u\",priority=\"%u\"} %u\n",
                            next.port, next.prio, depth) < 0) {
                return -ENOMEM;
            }
        }

        cur = next;
        if (bpf_map_get_next_key(ctx->qdepth.fd, &cur, &next) != 0)
            break;
    }

    return 0;
}

static int emit_voqd_metrics(struct exporter_ctx *ctx)
{
    uint32_t key = 0;
    struct voqd_state st = {0};
    const char *mode = "bypass";

    if (emit_families(&ctx->out, g_voqd_families,
                      sizeof(g_voqd_families) / sizeof(g_voqd_families[0])) < 0) {
        return -ENOMEM;
    }

    if (map_open(&ctx->voqd_state) == 0 &&
        bpf_map_lookup_elem(ctx->voqd_state.fd, &key, &st) == 0) {
        if (st.mode == VOQD_MODE_SHADOW)
            mode = "shadow";
        else if (st.mode == VOQD_MODE_ACTIVE)
            mode = "active";
    }

    if (out_appendf(&ctx->out, "rswitch_voqd_mode{mode=\"bypass\"} %d\n",
                    strcmp(mode, "bypass") == 0 ? 1 : 0) < 0 ||
        out_appendf(&ctx->out, "rswitch_voqd_mode{mode=\"shadow\"} %d\n",
                    strcmp(mode, "shadow") == 0 ? 1 : 0) < 0 ||
        out_appendf(&ctx->out, "rswitch_voqd_mode{mode=\"active\"} %d\n",
                    strcmp(mode, "active") == 0 ? 1 : 0) < 0) {
        return -ENOMEM;
    }

    return emit_qdepth_metrics(ctx);
}

static int count_entries(struct map_handle *m, uint64_t *count)
{
    struct bpf_map_info info;
    void *cur = NULL;
    void *next = NULL;
    uint64_t n = 0;

    if (!count)
        return -EINVAL;
    *count = 0;

    if (map_open(m) < 0)
        return -ENOENT;
    if (map_info(m->fd, &info) < 0) {
        map_close(m);
        return -EIO;
    }

    cur = calloc(1, info.key_size);
    next = calloc(1, info.key_size);
    if (!cur || !next) {
        free(cur);
        free(next);
        return -ENOMEM;
    }

    if (bpf_map_get_next_key(m->fd, NULL, next) == 0) {
        while (1) {
            n++;
            memcpy(cur, next, info.key_size);
            if (bpf_map_get_next_key(m->fd, cur, next) != 0)
                break;
        }
    }

    free(cur);
    free(next);
    *count = n;
    return 0;
}

static int emit_static_metrics(struct exporter_ctx *ctx)
{
    uint64_t mac_entries = 0;
    uint64_t vlan_count = 0;
    uint64_t uptime_sec;
    uint64_t elapsed_ns;

    if (emit_families(&ctx->out, g_static_families,
                      sizeof(g_static_families) / sizeof(g_static_families[0])) < 0) {
        return -ENOMEM;
    }

    count_entries(&ctx->mac_table, &mac_entries);
    count_entries(&ctx->vlan_map, &vlan_count);

    elapsed_ns = monotonic_now_ns() - ts_ns(&ctx->start_ts);
    uptime_sec = elapsed_ns / 1000000000ULL;

    if (out_appendf(&ctx->out, "rswitch_mac_table_entries %llu\n",
                    (unsigned long long)mac_entries) < 0 ||
        out_appendf(&ctx->out, "rswitch_vlan_count %llu\n",
                    (unsigned long long)vlan_count) < 0 ||
        out_appendf(&ctx->out, "rswitch_uptime_seconds %llu\n",
                    (unsigned long long)uptime_sec) < 0 ||
        out_appendf(&ctx->out, "rswitch_info{version=\"%s\"} 1\n",
                    RSWITCH_PROMETHEUS_VERSION) < 0) {
        return -ENOMEM;
    }

    return 0;
}

static int refresh_metrics(struct exporter_ctx *ctx)
{
    struct timespec now;

    if (!ctx)
        return -EINVAL;
    ctx->out.len = 0;

    if (emit_port_metrics(ctx) < 0 ||
        emit_module_metrics(ctx) < 0 ||
        emit_voqd_metrics(ctx) < 0 ||
        emit_static_metrics(ctx) < 0) {
        RS_LOG_ERROR("Failed to build metrics payload");
        return -ENOMEM;
    }

    if (out_reserve(&ctx->out, 0) < 0)
        return -ENOMEM;
    ctx->out.data[ctx->out.len] = '\0';

    clock_gettime(CLOCK_MONOTONIC, &now);
    ctx->last_refresh_ts = now;
    return 0;
}

static bool cache_stale(const struct exporter_ctx *ctx)
{
    uint64_t now = monotonic_now_ns();
    uint64_t prev = ts_ns(&ctx->last_refresh_ts);
    uint64_t interval = (uint64_t)ctx->cfg.refresh_interval_sec * 1000000000ULL;
    return (now - prev) >= interval;
}

static int send_response(int fd,
                         int code,
                         const char *status,
                         const char *ctype,
                         const char *body,
                         size_t body_len)
{
    char header[512];
    int hlen;

    hlen = snprintf(header, sizeof(header),
                    "HTTP/1.1 %d %s\r\n"
                    "Content-Type: %s\r\n"
                    "Content-Length: %zu\r\n"
                    "Connection: close\r\n"
                    "\r\n",
                    code, status, ctype, body_len);
    if (hlen < 0)
        return -EINVAL;

    if (send(fd, header, (size_t)hlen, 0) < 0)
        return -errno;
    if (body_len > 0 && send(fd, body, body_len, 0) < 0)
        return -errno;
    return 0;
}

static bool is_metrics_path(const char *path)
{
    if (!path)
        return false;
    if (strcmp(path, "/metrics") == 0)
        return true;
    if (strncmp(path, "/metrics?", 9) == 0)
        return true;
    return false;
}

static int handle_client(struct exporter_ctx *ctx, int cfd)
{
    char req[HTTP_REQ_BUF];
    ssize_t nread;
    char method[8] = {0};
    char path[256] = {0};

    nread = recv(cfd, req, sizeof(req) - 1, 0);
    if (nread <= 0)
        return -EIO;
    req[nread] = '\0';

    if (sscanf(req, "%7s %255s", method, path) != 2)
        return send_response(cfd, 400, "Bad Request", "text/plain", "bad request\n", 12);

    if (strcmp(method, "GET") != 0 || !is_metrics_path(path)) {
        return send_response(cfd, 404, "Not Found", "text/plain", "404 not found\n", 14);
    }

    if (ctx->out.len == 0 || cache_stale(ctx)) {
        if (refresh_metrics(ctx) < 0) {
            return send_response(cfd, 500, "Internal Server Error",
                                 "text/plain", "metrics refresh failed\n", 23);
        }
    }

    return send_response(cfd, 200, "OK",
                         "text/plain; version=0.0.4; charset=utf-8",
                         ctx->out.data, ctx->out.len);
}

static int run_server(struct exporter_ctx *ctx)
{
    struct sockaddr_in addr;
    int opt = 1;

    ctx->server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (ctx->server_fd < 0) {
        RS_LOG_ERROR("socket failed: %s", strerror(errno));
        return -errno;
    }

    if (setsockopt(ctx->server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
        RS_LOG_WARN("setsockopt(SO_REUSEADDR) failed: %s", strerror(errno));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(ctx->cfg.port);

    if (bind(ctx->server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        RS_LOG_ERROR("bind :%u failed: %s", ctx->cfg.port, strerror(errno));
        return -errno;
    }
    if (listen(ctx->server_fd, HTTP_BACKLOG) < 0) {
        RS_LOG_ERROR("listen failed: %s", strerror(errno));
        return -errno;
    }

    RS_LOG_INFO("Prometheus exporter listening on 0.0.0.0:%u", ctx->cfg.port);

    while (g_running) {
        int cfd = accept(ctx->server_fd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR)
                continue;
            RS_LOG_WARN("accept failed: %s", strerror(errno));
            continue;
        }
        handle_client(ctx, cfd);
        close(cfd);
    }

    return 0;
}

static int install_handlers(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;

    if (sigaction(SIGINT, &sa, NULL) < 0)
        return -errno;
    if (sigaction(SIGTERM, &sa, NULL) < 0)
        return -errno;

    signal(SIGPIPE, SIG_IGN);
    return 0;
}

static void ctx_init(struct exporter_ctx *ctx, const struct prometheus_exporter_config *cfg)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->cfg = *cfg;
    ctx->server_fd = -1;

    ctx->rs_stats.path = RS_STATS_MAP_PATH;
    ctx->rs_module_stats.path = RS_MODULE_STATS_MAP_PATH;
    ctx->voqd_state.path = VOQD_STATE_MAP_PATH;
    ctx->qdepth.path = QDEPTH_MAP_PATH;
    ctx->mac_table.path = RS_MAC_TABLE_MAP_PATH;
    ctx->vlan_map.path = RS_VLAN_MAP_PATH;

    ctx->rs_stats.fd = -1;
    ctx->rs_module_stats.fd = -1;
    ctx->voqd_state.fd = -1;
    ctx->qdepth.fd = -1;
    ctx->mac_table.fd = -1;
    ctx->vlan_map.fd = -1;
}

static void ctx_destroy(struct exporter_ctx *ctx)
{
    map_close(&ctx->rs_stats);
    map_close(&ctx->rs_module_stats);
    map_close(&ctx->voqd_state);
    map_close(&ctx->qdepth);
    map_close(&ctx->mac_table);
    map_close(&ctx->vlan_map);

    if (ctx->server_fd >= 0) {
        close(ctx->server_fd);
        ctx->server_fd = -1;
    }

    free(ctx->out.data);
    ctx->out.data = NULL;
    ctx->out.cap = 0;
    ctx->out.len = 0;
}

int prometheus_exporter_run(const struct prometheus_exporter_config *cfg)
{
    struct exporter_ctx ctx;
    int ret;

    if (!cfg)
        return -EINVAL;

    ctx_init(&ctx, cfg);

    if (install_handlers() < 0) {
        RS_LOG_ERROR("Failed to install signal handlers: %s", strerror(errno));
        ctx_destroy(&ctx);
        return 1;
    }

    ctx.ncpus = libbpf_num_possible_cpus();
    if (ctx.ncpus <= 0) {
        RS_LOG_ERROR("libbpf_num_possible_cpus failed");
        ctx_destroy(&ctx);
        return 1;
    }

    clock_gettime(CLOCK_MONOTONIC, &ctx.start_ts);
    ctx.last_refresh_ts = ctx.start_ts;

    if (refresh_metrics(&ctx) < 0)
        RS_LOG_WARN("Initial metric refresh failed; will retry on next scrape");

    ret = run_server(&ctx);
    ctx_destroy(&ctx);
    return ret < 0 ? 1 : 0;
}

int main(int argc, char **argv)
{
    struct prometheus_exporter_config cfg;
    int rc;

    rs_log_init("rswitch-prometheus", RS_LOG_LEVEL_INFO);
    prometheus_exporter_default_config(&cfg);

    rc = prometheus_exporter_parse_args(argc, argv, &cfg);
    if (rc == 1)
        return 0;
    if (rc < 0)
        return 1;

    RS_LOG_INFO("Starting exporter on port %u with refresh interval %u seconds",
                cfg.port, cfg.refresh_interval_sec);
    return prometheus_exporter_run(&cfg);
}
