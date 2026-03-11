// SPDX-License-Identifier: GPL-2.0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <getopt.h>
#include <limits.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "snmpagent.h"
#if __has_include("rs_log.h")
#include "rs_log.h"
#else
#include "../common/rs_log.h"
#endif

#ifndef __BPF__
#ifndef __uint
#define __uint(name, val) int __##name
#endif
#ifndef __type
#define __type(name, val) val *name
#endif
#ifndef __array
#define __array(name, val) val *name
#endif
#ifndef __ulong
#define __ulong(name, val) unsigned long name
#endif
#ifndef SEC
#define SEC(name)
#endif
#define RS_MAC_TABLE_OWNER 1
#define bpf_map_lookup_elem(...) ((void *)0)
#define bpf_map_update_elem(...) (0)
#endif

#include "../../bpf/core/map_defs.h"
#include "../../bpf/core/module_abi.h"

#ifndef __BPF__
#undef bpf_map_lookup_elem
#undef bpf_map_update_elem
#undef RS_MAC_TABLE_OWNER
#undef __uint
#undef __type
#undef __array
#undef __ulong
#undef SEC
#endif

#define SNMP_OUT_BASE_DIR "/var/lib/rswitch"
#define SNMP_OUT_DIR "/var/lib/rswitch/snmp"
#define BPF_PIN_BASE "/sys/fs/bpf"
#define MAX_MODULE_ENTRIES 64
#define MAX_OID_ENTRIES 2048

struct rs_port_entry {
    __u32 port_id;
    struct rs_stats stats;
};

struct rs_module_entry {
    __u32 module_id;
    char name[sizeof(((struct rs_module_stats *)0)->name)];
    __u64 packets;
};

struct snmp_oid_entry {
    char oid[96];
    char type[16];
    char value[256];
};

struct snmp_cache {
    struct rs_port_entry ports[RS_MAX_INTERFACES];
    size_t port_count;
    struct rs_module_entry modules[MAX_MODULE_ENTRIES];
    size_t module_count;
    __u64 vlan_count;
    struct snmp_oid_entry oid_entries[MAX_OID_ENTRIES];
    size_t oid_count;
    time_t start_time;
    time_t last_refresh;
};

static volatile sig_atomic_t g_running = 1;
static struct snmp_cache g_cache;

static void on_signal(int sig)
{
    (void)sig;
    g_running = 0;
}

static int install_signal_handlers(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;

    if (sigaction(SIGINT, &sa, NULL) != 0)
        return -errno;
    if (sigaction(SIGTERM, &sa, NULL) != 0)
        return -errno;

    signal(SIGPIPE, SIG_IGN);
    return 0;
}

static int ensure_output_dir(void)
{
    struct stat st;

    if (stat(SNMP_OUT_BASE_DIR, &st) != 0) {
        if (mkdir(SNMP_OUT_BASE_DIR, 0755) != 0 && errno != EEXIST)
            return -errno;
    } else if (!S_ISDIR(st.st_mode)) {
        return -ENOTDIR;
    }

    if (stat(SNMP_OUT_DIR, &st) != 0) {
        if (mkdir(SNMP_OUT_DIR, 0755) != 0 && errno != EEXIST)
            return -errno;
    } else if (!S_ISDIR(st.st_mode)) {
        return -ENOTDIR;
    }

    return 0;
}

static int write_filef(const char *path, const char *fmt, ...)
{
    FILE *fp;
    va_list ap;

    fp = fopen(path, "w");
    if (!fp)
        return -errno;

    va_start(ap, fmt);
    if (vfprintf(fp, fmt, ap) < 0) {
        va_end(ap);
        fclose(fp);
        return -EIO;
    }
    va_end(ap);

    if (fclose(fp) != 0)
        return -errno;
    return 0;
}

static int open_map_candidates(const char *const *paths, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++) {
        int fd = bpf_obj_get(paths[i]);
        if (fd >= 0)
            return fd;
    }

    return -1;
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

static void aggregate_module_stats(struct rs_module_entry *dst,
                                   const void *values,
                                   int ncpus,
                                   size_t value_size)
{
    int c;

    memset(dst, 0, sizeof(*dst));
    for (c = 0; c < ncpus; c++) {
        const struct rs_module_stats *v;

        v = (const struct rs_module_stats *)((const char *)values + (size_t)c * value_size);
        dst->packets += v->packets_processed;

        if (dst->name[0] == '\0' && v->name[0] != '\0') {
            strncpy(dst->name, v->name, sizeof(dst->name) - 1);
            dst->name[sizeof(dst->name) - 1] = '\0';
        }
    }
}

static __u64 count_map_entries(int fd)
{
    struct bpf_map_info info;
    __u32 info_len = sizeof(info);
    void *cur;
    void *next;
    __u64 count = 0;

    memset(&info, 0, sizeof(info));
    if (bpf_obj_get_info_by_fd(fd, &info, &info_len) != 0)
        return 0;

    cur = calloc(1, info.key_size);
    next = calloc(1, info.key_size);
    if (!cur || !next) {
        free(cur);
        free(next);
        return 0;
    }

    if (bpf_map_get_next_key(fd, NULL, next) == 0) {
        while (1) {
            count++;
            memcpy(cur, next, info.key_size);
            if (bpf_map_get_next_key(fd, cur, next) != 0)
                break;
        }
    }

    free(cur);
    free(next);
    return count;
}

static int add_oid_entry(const char *oid, const char *type, const char *value)
{
    struct snmp_oid_entry *ent;

    if (g_cache.oid_count >= MAX_OID_ENTRIES)
        return -ENOSPC;

    ent = &g_cache.oid_entries[g_cache.oid_count++];
    snprintf(ent->oid, sizeof(ent->oid), "%s", oid);
    snprintf(ent->type, sizeof(ent->type), "%s", type);
    snprintf(ent->value, sizeof(ent->value), "%s", value);
    return 0;
}

static int next_oid_component(const char **s)
{
    long v = 0;

    while (**s == '.')
        (*s)++;
    while (**s >= '0' && **s <= '9') {
        v = v * 10 + (**s - '0');
        (*s)++;
    }
    while (**s != '\0' && **s != '.')
        (*s)++;
    return (int)v;
}

static int compare_oid(const char *a, const char *b)
{
    const char *pa = a;
    const char *pb = b;

    while (*pa != '\0' || *pb != '\0') {
        int va = (*pa == '\0') ? -1 : next_oid_component(&pa);
        int vb = (*pb == '\0') ? -1 : next_oid_component(&pb);

        if (va < vb)
            return -1;
        if (va > vb)
            return 1;
    }

    return 0;
}

static int oid_qsort_cmp(const void *a, const void *b)
{
    const struct snmp_oid_entry *ea = a;
    const struct snmp_oid_entry *eb = b;

    return compare_oid(ea->oid, eb->oid);
}

static void rebuild_oid_cache(void)
{
    char oid[96];
    char value[256];
    size_t i;
    time_t now = time(NULL);
    unsigned long uptime = 0;

    g_cache.oid_count = 0;
    if (now > g_cache.start_time)
        uptime = (unsigned long)(now - g_cache.start_time);

    add_oid_entry(".1.3.6.1.4.1.99999.1.0", "string",
                  "rSwitch Reconfigurable Network Platform");
    add_oid_entry(".1.3.6.1.4.1.99999.1.1", "string", "1.0.0");
    snprintf(value, sizeof(value), "%lu", uptime);
    add_oid_entry(".1.3.6.1.4.1.99999.1.2", "integer", value);
    snprintf(value, sizeof(value), "%zu", g_cache.module_count);
    add_oid_entry(".1.3.6.1.4.1.99999.1.3", "integer", value);

    for (i = 0; i < g_cache.port_count; i++) {
        const struct rs_port_entry *p = &g_cache.ports[i];
        unsigned long long drops = (unsigned long long)(p->stats.rx_drops + p->stats.tx_drops);

        snprintf(oid, sizeof(oid), ".1.3.6.1.4.1.99999.2.1.%u", p->port_id);
        snprintf(value, sizeof(value), "%llu", (unsigned long long)p->stats.rx_packets);
        add_oid_entry(oid, "counter64", value);

        snprintf(oid, sizeof(oid), ".1.3.6.1.4.1.99999.2.2.%u", p->port_id);
        snprintf(value, sizeof(value), "%llu", (unsigned long long)p->stats.tx_packets);
        add_oid_entry(oid, "counter64", value);

        snprintf(oid, sizeof(oid), ".1.3.6.1.4.1.99999.2.3.%u", p->port_id);
        snprintf(value, sizeof(value), "%llu", (unsigned long long)p->stats.rx_bytes);
        add_oid_entry(oid, "counter64", value);

        snprintf(oid, sizeof(oid), ".1.3.6.1.4.1.99999.2.4.%u", p->port_id);
        snprintf(value, sizeof(value), "%llu", (unsigned long long)p->stats.tx_bytes);
        add_oid_entry(oid, "counter64", value);

        snprintf(oid, sizeof(oid), ".1.3.6.1.4.1.99999.2.5.%u", p->port_id);
        snprintf(value, sizeof(value), "%llu", drops);
        add_oid_entry(oid, "counter64", value);
    }

    for (i = 0; i < g_cache.module_count; i++) {
        const struct rs_module_entry *m = &g_cache.modules[i];

        snprintf(oid, sizeof(oid), ".1.3.6.1.4.1.99999.3.1.%u", m->module_id);
        add_oid_entry(oid, "string", m->name[0] ? m->name : "unknown");

        snprintf(oid, sizeof(oid), ".1.3.6.1.4.1.99999.3.2.%u", m->module_id);
        snprintf(value, sizeof(value), "%llu", (unsigned long long)m->packets);
        add_oid_entry(oid, "counter64", value);
    }

    qsort(g_cache.oid_entries, g_cache.oid_count, sizeof(g_cache.oid_entries[0]), oid_qsort_cmp);
}

static int refresh_data(void)
{
    const char *const port_map_paths[] = {
        BPF_PIN_BASE "/rs_port_stats_map",
        BPF_PIN_BASE "/rs_stats_map",
    };
    const char *const module_map_paths[] = {
        BPF_PIN_BASE "/rs_module_stats_map",
        BPF_PIN_BASE "/rs_module_stat_map",
    };
    const char *const vlan_map_paths[] = {
        BPF_PIN_BASE "/rs_vlan_map",
    };
    int ncpus;
    int port_fd = -1;
    int module_fd = -1;
    int vlan_fd = -1;

    ncpus = libbpf_num_possible_cpus();
    if (ncpus <= 0) {
        RS_LOG_WARN("Failed to get CPU count for per-CPU maps");
        return -EINVAL;
    }

    g_cache.port_count = 0;
    g_cache.module_count = 0;
    g_cache.vlan_count = 0;

    port_fd = open_map_candidates(port_map_paths, sizeof(port_map_paths) / sizeof(port_map_paths[0]));
    if (port_fd >= 0) {
        struct bpf_map_info info;
        __u32 info_len = sizeof(info);
        void *values = NULL;
        __u32 key;

        memset(&info, 0, sizeof(info));
        if (bpf_obj_get_info_by_fd(port_fd, &info, &info_len) == 0) {
            values = calloc((size_t)ncpus, info.value_size);
            if (values) {
                for (key = 0; key < info.max_entries && g_cache.port_count < RS_MAX_INTERFACES; key++) {
                    struct rs_stats sum;

                    if (bpf_map_lookup_elem(port_fd, &key, values) != 0)
                        continue;

                    aggregate_port_stats(&sum, values, ncpus, info.value_size);
                    if (sum.rx_packets == 0 && sum.tx_packets == 0 &&
                        sum.rx_bytes == 0 && sum.tx_bytes == 0 &&
                        sum.rx_drops == 0 && sum.tx_drops == 0 &&
                        sum.rx_errors == 0 && sum.tx_errors == 0) {
                        continue;
                    }

                    g_cache.ports[g_cache.port_count].port_id = key;
                    g_cache.ports[g_cache.port_count].stats = sum;
                    g_cache.port_count++;
                }
                free(values);
            }
        }
        close(port_fd);
    }

    module_fd = open_map_candidates(module_map_paths, sizeof(module_map_paths) / sizeof(module_map_paths[0]));
    if (module_fd >= 0) {
        struct bpf_map_info info;
        __u32 info_len = sizeof(info);
        void *values = NULL;
        __u32 key;

        memset(&info, 0, sizeof(info));
        if (bpf_obj_get_info_by_fd(module_fd, &info, &info_len) == 0) {
            values = calloc((size_t)ncpus, info.value_size);
            if (values) {
                for (key = 0; key < info.max_entries && g_cache.module_count < MAX_MODULE_ENTRIES; key++) {
                    struct rs_module_entry ent;

                    if (bpf_map_lookup_elem(module_fd, &key, values) != 0)
                        continue;

                    aggregate_module_stats(&ent, values, ncpus, info.value_size);
                    if (ent.packets == 0 && ent.name[0] == '\0')
                        continue;

                    ent.module_id = key;
                    g_cache.modules[g_cache.module_count++] = ent;
                }
                free(values);
            }
        }
        close(module_fd);
    }

    vlan_fd = open_map_candidates(vlan_map_paths, sizeof(vlan_map_paths) / sizeof(vlan_map_paths[0]));
    if (vlan_fd >= 0) {
        g_cache.vlan_count = count_map_entries(vlan_fd);
        close(vlan_fd);
    }

    rebuild_oid_cache();
    g_cache.last_refresh = time(NULL);
    return 0;
}

static int write_snapshot_files(void)
{
    char path[PATH_MAX];
    FILE *fp;
    size_t i;
    time_t now = time(NULL);
    unsigned long uptime = 0;

    if (now > g_cache.start_time)
        uptime = (unsigned long)(now - g_cache.start_time);

    if (ensure_output_dir() != 0)
        return -1;

    snprintf(path, sizeof(path), "%s/system.txt", SNMP_OUT_DIR);
    if (write_filef(path,
                    "sysDescr=rSwitch Reconfigurable Network Platform\n"
                    "version=1.0.0\n"
                    "uptime=%lu\n"
                    "moduleCount=%zu\n"
                    "vlanCount=%llu\n",
                    uptime, g_cache.module_count,
                    (unsigned long long)g_cache.vlan_count) != 0) {
        return -1;
    }

    snprintf(path, sizeof(path), "%s/ports.txt", SNMP_OUT_DIR);
    fp = fopen(path, "w");
    if (!fp)
        return -1;
    for (i = 0; i < g_cache.port_count; i++) {
        const struct rs_port_entry *p = &g_cache.ports[i];
        unsigned long long drops = (unsigned long long)(p->stats.rx_drops + p->stats.tx_drops);

        fprintf(fp,
                "port=%u rx_packets=%llu tx_packets=%llu rx_bytes=%llu tx_bytes=%llu drops=%llu\n",
                p->port_id,
                (unsigned long long)p->stats.rx_packets,
                (unsigned long long)p->stats.tx_packets,
                (unsigned long long)p->stats.rx_bytes,
                (unsigned long long)p->stats.tx_bytes,
                drops);
    }
    fclose(fp);

    snprintf(path, sizeof(path), "%s/modules.txt", SNMP_OUT_DIR);
    fp = fopen(path, "w");
    if (!fp)
        return -1;
    for (i = 0; i < g_cache.module_count; i++) {
        const struct rs_module_entry *m = &g_cache.modules[i];
        fprintf(fp, "module=%u name=%s packets=%llu\n",
                m->module_id,
                m->name[0] ? m->name : "unknown",
                (unsigned long long)m->packets);
    }
    fclose(fp);

    snprintf(path, sizeof(path), "%s/vlans.txt", SNMP_OUT_DIR);
    if (write_filef(path, "vlan_count=%llu\n",
                    (unsigned long long)g_cache.vlan_count) != 0) {
        return -1;
    }

    snprintf(path, sizeof(path), "%s/oids.txt", SNMP_OUT_DIR);
    fp = fopen(path, "w");
    if (!fp)
        return -1;
    for (i = 0; i < g_cache.oid_count; i++) {
        const struct snmp_oid_entry *e = &g_cache.oid_entries[i];
        fprintf(fp, "%s|%s|%s\n", e->oid, e->type, e->value);
    }
    fclose(fp);

    return 0;
}

static const struct snmp_oid_entry *find_oid_exact(const char *oid)
{
    size_t i;

    for (i = 0; i < g_cache.oid_count; i++) {
        if (compare_oid(g_cache.oid_entries[i].oid, oid) == 0)
            return &g_cache.oid_entries[i];
    }

    return NULL;
}

static const struct snmp_oid_entry *find_oid_next(const char *oid)
{
    size_t i;

    for (i = 0; i < g_cache.oid_count; i++) {
        if (compare_oid(g_cache.oid_entries[i].oid, oid) > 0)
            return &g_cache.oid_entries[i];
    }

    return NULL;
}

static void emit_none(void)
{
    printf("NONE\n");
    fflush(stdout);
}

static void emit_entry(const struct snmp_oid_entry *e)
{
    printf("%s\n", e->oid);
    printf("%s\n", e->type);
    printf("%s\n", e->value);
    fflush(stdout);
}

static void trim_line(char *s)
{
    size_t n;

    if (!s)
        return;

    n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r')) {
        s[n - 1] = '\0';
        n--;
    }
}

static int parse_oid_arg(char *line, char *oid_out, size_t oid_out_len)
{
    char *sp = strchr(line, ' ');

    if (sp) {
        while (*sp == ' ')
            sp++;
        if (*sp != '\0') {
            snprintf(oid_out, oid_out_len, "%s", sp);
            return 0;
        }
    }

    if (!fgets(oid_out, (int)oid_out_len, stdin))
        return -1;
    trim_line(oid_out);
    return oid_out[0] == '\0' ? -1 : 0;
}

static void refresh_if_needed(void)
{
    time_t now = time(NULL);

    if (g_cache.last_refresh == 0 ||
        (now - g_cache.last_refresh) >= SNMPAGENT_POLL_INTERVAL) {
        refresh_data();
    }
}

static int handle_pass_persist(void)
{
    char line[512];
    char oid[128];

    if (g_cache.start_time == 0)
        g_cache.start_time = time(NULL);
    refresh_data();

    while (g_running && fgets(line, sizeof(line), stdin)) {
        trim_line(line);
        if (line[0] == '\0')
            continue;

        if (strcmp(line, "PING") == 0) {
            printf("PONG\n");
            fflush(stdout);
            continue;
        }

        if (strncmp(line, "getnext", 7) == 0 &&
            (line[7] == '\0' || line[7] == ' ' || line[7] == '\t')) {
            const struct snmp_oid_entry *e;

            if (parse_oid_arg(line, oid, sizeof(oid)) != 0) {
                emit_none();
                continue;
            }

            refresh_if_needed();
            e = find_oid_next(oid);
            if (!e)
                emit_none();
            else
                emit_entry(e);
            continue;
        }

        if (strncmp(line, "get", 3) == 0 &&
            (line[3] == '\0' || line[3] == ' ' || line[3] == '\t')) {
            const struct snmp_oid_entry *e;

            if (parse_oid_arg(line, oid, sizeof(oid)) != 0) {
                emit_none();
                continue;
            }

            refresh_if_needed();
            e = find_oid_exact(oid);
            if (!e)
                emit_none();
            else
                emit_entry(e);
            continue;
        }

        emit_none();
    }

    return 0;
}

int rs_snmpagent_run(const char *agentx_socket)
{
    (void)agentx_socket;

    if (install_signal_handlers() != 0) {
        RS_LOG_ERROR("Failed to install signal handlers: %s", strerror(errno));
        return 1;
    }

    if (g_cache.start_time == 0)
        g_cache.start_time = time(NULL);

    RS_LOG_INFO("Starting rswitch-snmpagent in file-export mode");

    while (g_running) {
        if (refresh_data() != 0)
            RS_LOG_WARN("SNMP cache refresh failed");

        if (write_snapshot_files() != 0)
            RS_LOG_WARN("Failed to write SNMP snapshot files");

        for (int i = 0; i < SNMPAGENT_POLL_INTERVAL && g_running; i++)
            sleep(1);
    }

    RS_LOG_INFO("rswitch-snmpagent stopped");
    return 0;
}

static void usage(const char *prog)
{
    printf("Usage: %s [--pass-persist] [-s <agentx_socket>]\n", prog);
    printf("\n");
    printf("Options:\n");
    printf("  --pass-persist      Run stdin/stdout pass_persist protocol mode\n");
    printf("  -s SOCKET           AgentX socket path hint (default: %s)\n", SNMPAGENT_DEFAULT_SOCKET);
    printf("  -h                  Show this help\n");
}

int main(int argc, char **argv)
{
    static const struct option long_opts[] = {
        {"pass-persist", no_argument, 0, 'P'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0},
    };
    const char *agentx_socket = SNMPAGENT_DEFAULT_SOCKET;
    bool pass_persist = false;
    int opt;

    rs_log_init("rswitch-snmpagent", RS_LOG_LEVEL_INFO);

    while ((opt = getopt_long(argc, argv, "s:h", long_opts, NULL)) != -1) {
        switch (opt) {
        case 's':
            agentx_socket = optarg;
            break;
        case 'P':
            pass_persist = true;
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    if (pass_persist)
        return handle_pass_persist();
    return rs_snmpagent_run(agentx_socket);
}
