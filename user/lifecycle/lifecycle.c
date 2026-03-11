// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <fcntl.h>
#include <time.h>
#include <dirent.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "lifecycle.h"
#include "../../bpf/core/afxdp_common.h"

#if __has_include("rs_log.h")
#include "rs_log.h"
#else
#include "../common/rs_log.h"
#endif

#define RS_LIFECYCLE_META_MAGIC 0x52534c43u
#define RS_LIFECYCLE_META_VERSION 1u

#define RS_DEFAULT_STATE_DIR "/var/lib/rswitch/"
#define RS_DEFAULT_DRAIN_TIMEOUT 30

#define RS_PID_FILE "/var/run/rswitch.pid"
#define RS_SHUTDOWN_FLAG_FILE "shutdown.flag"
#define RS_SHUTDOWN_OVERRIDE_FILE "shutdown_override.cfg"

#define RS_FILE_MAC_TABLE "mac_table.dat"
#define RS_FILE_ROUTES "routes.dat"
#define RS_FILE_ACL_COUNTERS "acl_counters.dat"
#define RS_FILE_VOQD_STATE "voqd_state.dat"
#define RS_FILE_META "state_meta.dat"

struct rs_route_lpm_key {
    __u32 prefixlen;
    __u32 addr;
};

struct rs_mac_key {
    __u8 mac[6];
    __u16 vlan;
} __attribute__((packed));

struct rs_mac_entry {
    __u32 ifindex;
    __u8 static_entry;
    __u8 reserved[3];
    __u64 last_seen;
    __u32 hit_count;
} __attribute__((packed));

struct rs_route_entry {
    __u32 nexthop;
    __u32 ifindex;
    __u32 metric;
    __u8 type;
    __u8 pad[3];
    __u32 ecmp_group_id;
};

struct rs_mac_record {
    struct rs_mac_key key;
    struct rs_mac_entry value;
};

struct rs_route_record {
    struct rs_route_lpm_key key;
    struct rs_route_entry value;
};

struct rs_acl_counter_record {
    __u32 key;
    __u64 value;
};

struct rs_state_meta {
    __u32 magic;
    __u32 version;
    __u64 timestamp_sec;
    __u32 mac_entries;
    __u32 route_entries;
    __u32 acl_counter_entries;
    __u32 voqd_state_saved;
};

struct rs_shutdown_override {
    __u32 drain_timeout_sec;
    __u32 reserved;
};

static struct rs_lifecycle_config g_cfg;
static int g_initialized;

static void rs_lifecycle_set_defaults(struct rs_lifecycle_config *cfg)
{
    if (!cfg)
        return;

    memset(cfg, 0, sizeof(*cfg));
    snprintf(cfg->state_dir, sizeof(cfg->state_dir), "%s", RS_DEFAULT_STATE_DIR);
    cfg->drain_timeout_sec = RS_DEFAULT_DRAIN_TIMEOUT;
    cfg->save_mac_table = 1;
    cfg->save_routes = 1;
    cfg->save_acl_counters = 1;
}

static int rs_is_dir(const char *path)
{
    struct stat st;

    if (!path || path[0] == '\0')
        return 0;
    if (stat(path, &st) != 0)
        return 0;
    return S_ISDIR(st.st_mode) ? 1 : 0;
}

static int rs_ensure_dir_recursive(const char *dir)
{
    char tmp[PATH_MAX];
    size_t len;

    if (!dir || dir[0] == '\0')
        return -EINVAL;

    len = strnlen(dir, sizeof(tmp) - 1);
    if (len == 0 || len >= sizeof(tmp) - 1)
        return -ENAMETOOLONG;

    memcpy(tmp, dir, len);
    tmp[len] = '\0';

    if (tmp[len - 1] == '/')
        tmp[len - 1] = '\0';

    for (char *p = tmp + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(tmp, 0755) != 0 && errno != EEXIST)
            return -errno;
        *p = '/';
    }

    if (mkdir(tmp, 0755) != 0 && errno != EEXIST)
        return -errno;

    if (!rs_is_dir(tmp))
        return -ENOTDIR;

    return 0;
}

static int rs_path_join(char *out, size_t out_sz, const char *dir, const char *name)
{
    int n;

    if (!out || !dir || !name)
        return -EINVAL;
    n = snprintf(out, out_sz, "%s%s%s", dir, dir[strlen(dir) - 1] == '/' ? "" : "/", name);
    if (n < 0 || (size_t)n >= out_sz)
        return -ENAMETOOLONG;
    return 0;
}

static int rs_write_pid_file(void)
{
    FILE *fp;

    fp = fopen(RS_PID_FILE, "w");
    if (!fp) {
        RS_LOG_WARN("Failed to open pid file %s: %s", RS_PID_FILE, strerror(errno));
        return -errno;
    }

    fprintf(fp, "%d\n", (int)getpid());
    fclose(fp);
    return 0;
}

static void rs_remove_pid_file(void)
{
    if (unlink(RS_PID_FILE) != 0 && errno != ENOENT)
        RS_LOG_WARN("Failed to remove pid file %s: %s", RS_PID_FILE, strerror(errno));
}

static int rs_open_pinned_map(const char *name)
{
    char path[PATH_MAX];

    if (snprintf(path, sizeof(path), "/sys/fs/bpf/%s", name) >= (int)sizeof(path))
        return -ENAMETOOLONG;

    return bpf_obj_get(path);
}

static int rs_open_first_map(const char *const *names, size_t count, const char **resolved)
{
    for (size_t i = 0; i < count; i++) {
        int fd = rs_open_pinned_map(names[i]);
        if (fd >= 0) {
            if (resolved)
                *resolved = names[i];
            return fd;
        }
    }

    return -ENOENT;
}

static FILE *rs_open_state_file(const char *name, const char *mode, char *path, size_t path_sz)
{
    if (rs_path_join(path, path_sz, g_cfg.state_dir, name) != 0)
        return NULL;
    return fopen(path, mode);
}

static int rs_file_exists(const char *name)
{
    char path[PATH_MAX];

    if (rs_path_join(path, sizeof(path), g_cfg.state_dir, name) != 0)
        return 0;
    return access(path, F_OK) == 0;
}

static int rs_save_mac_table(__u32 *saved)
{
    static const char *names[] = {"rs_mac_table"};
    const char *resolved = NULL;
    int fd = rs_open_first_map(names, 1, &resolved);
    struct rs_mac_key key;
    struct rs_mac_key next_key;
    struct rs_mac_entry value;
    FILE *fp;
    char path[PATH_MAX];
    int has_key = 0;

    *saved = 0;
    if (fd < 0) {
        RS_LOG_WARN("MAC table map not found, skipping save");
        return 0;
    }

    fp = rs_open_state_file(RS_FILE_MAC_TABLE, "wb", path, sizeof(path));
    if (!fp) {
        RS_LOG_ERROR("Failed to open %s for write: %s", path, strerror(errno));
        close(fd);
        return -errno;
    }

    memset(&key, 0, sizeof(key));
    while (bpf_map_get_next_key(fd, has_key ? &key : NULL, &next_key) == 0) {
        struct rs_mac_record rec;

        if (bpf_map_lookup_elem(fd, &next_key, &value) == 0) {
            memcpy(&rec.key, &next_key, sizeof(rec.key));
            memcpy(&rec.value, &value, sizeof(rec.value));
            if (fwrite(&rec, sizeof(rec), 1, fp) != 1) {
                RS_LOG_ERROR("Failed writing MAC state to %s", path);
                fclose(fp);
                close(fd);
                return -EIO;
            }
            (*saved)++;
        }

        key = next_key;
        has_key = 1;
    }

    fclose(fp);
    close(fd);
    RS_LOG_INFO("Saved %u MAC entries from map %s", *saved, resolved ? resolved : "unknown");
    return 0;
}

static int rs_restore_mac_table(__u32 *restored)
{
    static const char *names[] = {"rs_mac_table"};
    int fd = rs_open_first_map(names, 1, NULL);
    FILE *fp;
    char path[PATH_MAX];

    *restored = 0;
    if (!rs_file_exists(RS_FILE_MAC_TABLE))
        return 0;
    if (fd < 0) {
        RS_LOG_WARN("MAC table map not found, skipping restore");
        return 0;
    }

    fp = rs_open_state_file(RS_FILE_MAC_TABLE, "rb", path, sizeof(path));
    if (!fp) {
        close(fd);
        return -errno;
    }

    for (;;) {
        struct rs_mac_record rec;
        size_t n = fread(&rec, 1, sizeof(rec), fp);

        if (n == 0)
            break;
        if (n != sizeof(rec)) {
            RS_LOG_WARN("Ignoring truncated MAC state record in %s", path);
            break;
        }
        if (bpf_map_update_elem(fd, &rec.key, &rec.value, BPF_ANY) == 0)
            (*restored)++;
    }

    fclose(fp);
    close(fd);
    return 0;
}

static int rs_save_routes(__u32 *saved)
{
    static const char *names[] = {"route_tbl"};
    int fd = rs_open_first_map(names, 1, NULL);
    struct rs_route_lpm_key key;
    struct rs_route_lpm_key next_key;
    struct rs_route_entry value;
    FILE *fp;
    char path[PATH_MAX];
    int has_key = 0;

    *saved = 0;
    if (fd < 0) {
        RS_LOG_WARN("Route table map not found, skipping save");
        return 0;
    }

    fp = rs_open_state_file(RS_FILE_ROUTES, "wb", path, sizeof(path));
    if (!fp) {
        close(fd);
        return -errno;
    }

    memset(&key, 0, sizeof(key));
    while (bpf_map_get_next_key(fd, has_key ? &key : NULL, &next_key) == 0) {
        struct rs_route_record rec;

        if (bpf_map_lookup_elem(fd, &next_key, &value) == 0) {
            memcpy(&rec.key, &next_key, sizeof(rec.key));
            memcpy(&rec.value, &value, sizeof(rec.value));
            if (fwrite(&rec, sizeof(rec), 1, fp) != 1) {
                fclose(fp);
                close(fd);
                return -EIO;
            }
            (*saved)++;
        }
        key = next_key;
        has_key = 1;
    }

    fclose(fp);
    close(fd);
    RS_LOG_INFO("Saved %u route entries", *saved);
    return 0;
}

static int rs_restore_routes(__u32 *restored)
{
    static const char *names[] = {"route_tbl"};
    int fd = rs_open_first_map(names, 1, NULL);
    FILE *fp;
    char path[PATH_MAX];

    *restored = 0;
    if (!rs_file_exists(RS_FILE_ROUTES))
        return 0;
    if (fd < 0) {
        RS_LOG_WARN("Route table map not found, skipping restore");
        return 0;
    }

    fp = rs_open_state_file(RS_FILE_ROUTES, "rb", path, sizeof(path));
    if (!fp) {
        close(fd);
        return -errno;
    }

    for (;;) {
        struct rs_route_record rec;
        size_t n = fread(&rec, 1, sizeof(rec), fp);

        if (n == 0)
            break;
        if (n != sizeof(rec)) {
            RS_LOG_WARN("Ignoring truncated route state record in %s", path);
            break;
        }
        if (bpf_map_update_elem(fd, &rec.key, &rec.value, BPF_ANY) == 0)
            (*restored)++;
    }

    fclose(fp);
    close(fd);
    return 0;
}

static int rs_save_acl_counters(__u32 *saved)
{
    static const char *names[] = {"acl_stats_map", "acl_stats"};
    int fd = rs_open_first_map(names, sizeof(names) / sizeof(names[0]), NULL);
    FILE *fp;
    char path[PATH_MAX];
    __u32 key;
    __u32 next_key;
    int has_key = 0;
    int ncpus = libbpf_num_possible_cpus();

    *saved = 0;
    if (fd < 0) {
        RS_LOG_WARN("ACL stats map not found, skipping save");
        return 0;
    }
    if (ncpus <= 0)
        ncpus = 1;

    fp = rs_open_state_file(RS_FILE_ACL_COUNTERS, "wb", path, sizeof(path));
    if (!fp) {
        close(fd);
        return -errno;
    }

    memset(&key, 0, sizeof(key));
    while (bpf_map_get_next_key(fd, has_key ? &key : NULL, &next_key) == 0) {
        __u64 sum = 0;
        __u64 *percpu = calloc((size_t)ncpus, sizeof(__u64));

        if (!percpu) {
            fclose(fp);
            close(fd);
            return -ENOMEM;
        }

        if (bpf_map_lookup_elem(fd, &next_key, percpu) == 0) {
            struct rs_acl_counter_record rec;
            for (int i = 0; i < ncpus; i++)
                sum += percpu[i];

            rec.key = next_key;
            rec.value = sum;
            if (fwrite(&rec, sizeof(rec), 1, fp) != 1) {
                free(percpu);
                fclose(fp);
                close(fd);
                return -EIO;
            }
            (*saved)++;
        }

        free(percpu);
        key = next_key;
        has_key = 1;
    }

    fclose(fp);
    close(fd);
    RS_LOG_INFO("Saved %u ACL counter entries", *saved);
    return 0;
}

static int rs_restore_acl_counters(__u32 *restored)
{
    static const char *names[] = {"acl_stats_map", "acl_stats"};
    int fd = rs_open_first_map(names, sizeof(names) / sizeof(names[0]), NULL);
    FILE *fp;
    char path[PATH_MAX];
    int ncpus = libbpf_num_possible_cpus();

    *restored = 0;
    if (!rs_file_exists(RS_FILE_ACL_COUNTERS))
        return 0;
    if (fd < 0) {
        RS_LOG_WARN("ACL stats map not found, skipping restore");
        return 0;
    }
    if (ncpus <= 0)
        ncpus = 1;

    fp = rs_open_state_file(RS_FILE_ACL_COUNTERS, "rb", path, sizeof(path));
    if (!fp) {
        close(fd);
        return -errno;
    }

    for (;;) {
        struct rs_acl_counter_record rec;
        __u64 *percpu;
        size_t n = fread(&rec, 1, sizeof(rec), fp);

        if (n == 0)
            break;
        if (n != sizeof(rec)) {
            RS_LOG_WARN("Ignoring truncated ACL counter record in %s", path);
            break;
        }

        percpu = calloc((size_t)ncpus, sizeof(__u64));
        if (!percpu) {
            fclose(fp);
            close(fd);
            return -ENOMEM;
        }
        percpu[0] = rec.value;

        if (bpf_map_update_elem(fd, &rec.key, percpu, BPF_ANY) == 0)
            (*restored)++;

        free(percpu);
    }

    fclose(fp);
    close(fd);
    return 0;
}

static int rs_save_voqd_state(__u32 *saved)
{
    static const char *names[] = {"voqd_state_map"};
    int fd = rs_open_first_map(names, 1, NULL);
    struct voqd_state st;
    __u32 key = 0;
    FILE *fp;
    char path[PATH_MAX];

    *saved = 0;
    if (fd < 0)
        return 0;

    if (bpf_map_lookup_elem(fd, &key, &st) != 0) {
        close(fd);
        return 0;
    }

    fp = rs_open_state_file(RS_FILE_VOQD_STATE, "wb", path, sizeof(path));
    if (!fp) {
        close(fd);
        return -errno;
    }

    if (fwrite(&st, sizeof(st), 1, fp) != 1) {
        fclose(fp);
        close(fd);
        return -EIO;
    }

    fclose(fp);
    close(fd);
    *saved = 1;
    return 0;
}

static int rs_restore_voqd_state(__u32 *restored)
{
    static const char *names[] = {"voqd_state_map"};
    int fd = rs_open_first_map(names, 1, NULL);
    struct voqd_state st;
    FILE *fp;
    char path[PATH_MAX];
    __u32 key = 0;

    *restored = 0;
    if (!rs_file_exists(RS_FILE_VOQD_STATE))
        return 0;
    if (fd < 0)
        return 0;

    fp = rs_open_state_file(RS_FILE_VOQD_STATE, "rb", path, sizeof(path));
    if (!fp) {
        close(fd);
        return -errno;
    }

    if (fread(&st, 1, sizeof(st), fp) == sizeof(st)) {
        if (bpf_map_update_elem(fd, &key, &st, BPF_ANY) == 0)
            *restored = 1;
    }

    fclose(fp);
    close(fd);
    return 0;
}

static int rs_write_meta(const struct rs_state_meta *meta)
{
    FILE *fp;
    char path[PATH_MAX];

    fp = rs_open_state_file(RS_FILE_META, "wb", path, sizeof(path));
    if (!fp)
        return -errno;

    if (fwrite(meta, sizeof(*meta), 1, fp) != 1) {
        fclose(fp);
        return -EIO;
    }

    fclose(fp);
    return 0;
}

static int rs_read_meta(struct rs_state_meta *meta)
{
    FILE *fp;
    char path[PATH_MAX];

    memset(meta, 0, sizeof(*meta));
    if (!rs_file_exists(RS_FILE_META))
        return -ENOENT;

    fp = rs_open_state_file(RS_FILE_META, "rb", path, sizeof(path));
    if (!fp)
        return -errno;

    if (fread(meta, 1, sizeof(*meta), fp) != sizeof(*meta)) {
        fclose(fp);
        return -EIO;
    }
    fclose(fp);

    if (meta->magic != RS_LIFECYCLE_META_MAGIC || meta->version != RS_LIFECYCLE_META_VERSION)
        return -EINVAL;

    return 0;
}

static int rs_write_shutdown_flag(const struct rs_lifecycle_config *cfg)
{
    FILE *fp;
    char path[PATH_MAX];
    time_t now = time(NULL);

    fp = rs_open_state_file(RS_SHUTDOWN_FLAG_FILE, "w", path, sizeof(path));
    if (!fp)
        return -errno;

    fprintf(fp, "pid=%d\n", (int)getpid());
    fprintf(fp, "timestamp=%lld\n", (long long)now);
    fprintf(fp, "drain_timeout_sec=%d\n", cfg->drain_timeout_sec);
    fclose(fp);
    return 0;
}

static int rs_maybe_apply_shutdown_override(struct rs_lifecycle_config *cfg)
{
    FILE *fp;
    char path[PATH_MAX];
    struct rs_shutdown_override ov;

    if (rs_path_join(path, sizeof(path), cfg->state_dir, RS_SHUTDOWN_OVERRIDE_FILE) != 0)
        return -EINVAL;
    fp = fopen(path, "rb");
    if (!fp)
        return 0;

    if (fread(&ov, 1, sizeof(ov), fp) == sizeof(ov) && ov.drain_timeout_sec > 0)
        cfg->drain_timeout_sec = (int)ov.drain_timeout_sec;

    fclose(fp);
    if (unlink(path) != 0 && errno != ENOENT)
        RS_LOG_WARN("Failed to remove shutdown override file %s: %s", path, strerror(errno));
    return 0;
}

static int rs_should_unpin_name(const char *name)
{
    return strncmp(name, "rs_", 3) == 0 ||
           strncmp(name, "acl_", 4) == 0 ||
           strncmp(name, "route_", 6) == 0 ||
           strncmp(name, "arp_", 4) == 0 ||
           strncmp(name, "voq_", 4) == 0 ||
           strncmp(name, "voqd_", 5) == 0 ||
           strncmp(name, "qos_", 4) == 0 ||
           strncmp(name, "afxdp_", 6) == 0 ||
           strncmp(name, "mirror_", 7) == 0 ||
           strncmp(name, "iface_", 6) == 0 ||
           strncmp(name, "ingress_", 8) == 0 ||
           strncmp(name, "egress_", 7) == 0 ||
           strcmp(name, "xsks_map") == 0 ||
           strcmp(name, "qdepth_map") == 0;
}

static int rs_unpin_bpf_objects(void)
{
    DIR *dir;
    struct dirent *ent;
    int unlinked = 0;
    int failed = 0;

    dir = opendir("/sys/fs/bpf");
    if (!dir) {
        RS_LOG_WARN("Failed to open /sys/fs/bpf: %s", strerror(errno));
        return -errno;
    }

    while ((ent = readdir(dir)) != NULL) {
        char path[PATH_MAX];
        struct stat st;

        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;
        if (!rs_should_unpin_name(ent->d_name))
            continue;

        if (snprintf(path, sizeof(path), "/sys/fs/bpf/%s", ent->d_name) >= (int)sizeof(path))
            continue;
        if (lstat(path, &st) != 0)
            continue;
        if (!S_ISREG(st.st_mode) && !S_ISLNK(st.st_mode))
            continue;

        if (unlink(path) == 0) {
            unlinked++;
        } else {
            failed++;
            RS_LOG_WARN("Failed to unpin %s: %s", path, strerror(errno));
        }
    }

    closedir(dir);
    RS_LOG_INFO("Unpin completed: %d removed, %d failed", unlinked, failed);
    return failed == 0 ? 0 : -EIO;
}

int rs_lifecycle_init(const struct rs_lifecycle_config *config)
{
    rs_lifecycle_set_defaults(&g_cfg);

    if (config) {
        if (config->state_dir[0] != '\0')
            snprintf(g_cfg.state_dir, sizeof(g_cfg.state_dir), "%s", config->state_dir);
        if (config->drain_timeout_sec > 0)
            g_cfg.drain_timeout_sec = config->drain_timeout_sec;
        g_cfg.save_mac_table = config->save_mac_table;
        g_cfg.save_routes = config->save_routes;
        g_cfg.save_acl_counters = config->save_acl_counters;
    }

    if (rs_ensure_dir_recursive(g_cfg.state_dir) != 0) {
        RS_LOG_ERROR("Failed to create state directory %s", g_cfg.state_dir);
        return -1;
    }

    rs_write_pid_file();
    g_initialized = 1;
    return 0;
}

int rs_lifecycle_save_state(void)
{
    struct rs_state_meta meta;
    __u32 voqd_saved = 0;

    if (!g_initialized && rs_lifecycle_init(NULL) != 0)
        return -1;

    memset(&meta, 0, sizeof(meta));
    meta.magic = RS_LIFECYCLE_META_MAGIC;
    meta.version = RS_LIFECYCLE_META_VERSION;
    meta.timestamp_sec = (uint64_t)time(NULL);

    if (g_cfg.save_mac_table && rs_save_mac_table(&meta.mac_entries) != 0)
        RS_LOG_WARN("MAC state save encountered errors");
    if (g_cfg.save_routes && rs_save_routes(&meta.route_entries) != 0)
        RS_LOG_WARN("Route state save encountered errors");
    if (g_cfg.save_acl_counters && rs_save_acl_counters(&meta.acl_counter_entries) != 0)
        RS_LOG_WARN("ACL counter save encountered errors");

    if (rs_save_voqd_state(&voqd_saved) == 0)
        meta.voqd_state_saved = voqd_saved;

    if (rs_write_meta(&meta) != 0) {
        RS_LOG_ERROR("Failed to persist state metadata");
        return -1;
    }

    RS_LOG_INFO("State save complete: mac=%u routes=%u acl=%u voqd=%u",
                meta.mac_entries, meta.route_entries,
                meta.acl_counter_entries, meta.voqd_state_saved);
    return 0;
}

int rs_lifecycle_restore_state(void)
{
    struct rs_state_meta meta;
    __u32 mac_restored = 0;
    __u32 routes_restored = 0;
    __u32 acl_restored = 0;
    __u32 voqd_restored = 0;
    int err;

    if (!g_initialized && rs_lifecycle_init(NULL) != 0)
        return -1;

    err = rs_read_meta(&meta);
    if (err != 0) {
        RS_LOG_INFO("No persisted lifecycle state found under %s", g_cfg.state_dir);
        return 0;
    }

    if (g_cfg.save_mac_table)
        rs_restore_mac_table(&mac_restored);
    if (g_cfg.save_routes)
        rs_restore_routes(&routes_restored);
    if (g_cfg.save_acl_counters)
        rs_restore_acl_counters(&acl_restored);
    rs_restore_voqd_state(&voqd_restored);

    RS_LOG_INFO("State restore complete: mac=%u routes=%u acl=%u voqd=%u",
                mac_restored, routes_restored, acl_restored, voqd_restored);
    return 0;
}

int rs_lifecycle_shutdown(const struct rs_lifecycle_config *config)
{
    struct rs_lifecycle_config shutdown_cfg;

    if (!g_initialized)
        rs_lifecycle_set_defaults(&g_cfg);

    shutdown_cfg = g_cfg;
    if (config) {
        if (config->state_dir[0] != '\0')
            snprintf(shutdown_cfg.state_dir, sizeof(shutdown_cfg.state_dir), "%s", config->state_dir);
        if (config->drain_timeout_sec > 0)
            shutdown_cfg.drain_timeout_sec = config->drain_timeout_sec;
        shutdown_cfg.save_mac_table = config->save_mac_table;
        shutdown_cfg.save_routes = config->save_routes;
        shutdown_cfg.save_acl_counters = config->save_acl_counters;
    }

    g_cfg = shutdown_cfg;
    if (!g_initialized) {
        if (rs_lifecycle_init(&shutdown_cfg) != 0)
            RS_LOG_WARN("Lifecycle init failed during shutdown, continuing");
    }

    rs_maybe_apply_shutdown_override(&g_cfg);

    RS_LOG_INFO("Initiating graceful shutdown...");
    if (rs_write_shutdown_flag(&g_cfg) != 0)
        RS_LOG_WARN("Failed to write shutdown flag");

    rs_lifecycle_save_state();
    rs_unpin_bpf_objects();

    RS_LOG_INFO("Shutdown complete");
    return 0;
}

void rs_lifecycle_cleanup(void)
{
    char path[PATH_MAX];

    if (g_initialized && rs_path_join(path, sizeof(path), g_cfg.state_dir, RS_SHUTDOWN_FLAG_FILE) == 0) {
        if (unlink(path) != 0 && errno != ENOENT)
            RS_LOG_WARN("Failed to remove shutdown flag %s: %s", path, strerror(errno));
    }

    rs_remove_pid_file();
    g_initialized = 0;
}
