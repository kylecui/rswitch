// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>
#include <limits.h>
#include "audit.h"
#if __has_include("rs_log.h")
#include "rs_log.h"
#else
#include "../common/rs_log.h"
#endif

static int ensure_audit_dir(void)
{
    struct stat st;

    if (stat("/var/log/rswitch", &st) == 0 && S_ISDIR(st.st_mode))
        return 0;

    if (mkdir("/var/log/rswitch", 0755) == 0)
        return 0;

    if (errno == ENOENT) {
        if (mkdir("/var/log", 0755) != 0 && errno != EEXIST)
            return -1;
        if (mkdir("/var/log/rswitch", 0755) == 0)
            return 0;
    }

    if (errno == EEXIST)
        return 0;

    return -1;
}

static const char *severity_string(int sev)
{
    switch (sev) {
    case AUDIT_SEV_INFO:     return "info";
    case AUDIT_SEV_WARNING:  return "warning";
    case AUDIT_SEV_CRITICAL: return "critical";
    default:                 return "unknown";
    }
}

static void json_fprint_escaped(FILE *f, const char *s)
{
    const unsigned char *p = (const unsigned char *)s;

    while (p && *p) {
        switch (*p) {
        case '\\': fputs("\\\\", f); break;
        case '"':  fputs("\\\"", f); break;
        case '\n': fputs("\\n", f);  break;
        case '\r': fputs("\\r", f);  break;
        case '\t': fputs("\\t", f);  break;
        default:
            if (*p < 0x20)
                fprintf(f, "\\u%04x", *p);
            else
                fputc(*p, f);
            break;
        }
        p++;
    }
}

static char *get_current_user(void)
{
    static char user[64];
    char *env_user = getenv("USER");

    if (env_user) {
        snprintf(user, sizeof(user), "%s", env_user);
    } else if (getuid() == 0) {
        snprintf(user, sizeof(user), "root");
    } else {
        snprintf(user, sizeof(user), "uid:%u", getuid());
    }

    return user;
}

int rs_audit_init(void)
{
    if (ensure_audit_dir() != 0) {
        RS_LOG_WARN("Cannot create audit log directory: %s", strerror(errno));
        return -1;
    }

    return 0;
}

static int audit_write_entry(int severity, const char *category,
                              const char *action, int success,
                              const char *detail)
{
    FILE *f;
    struct timespec ts;
    struct tm tm_buf;
    char time_buf[64];

    f = fopen(AUDIT_LOG_PATH, "a");
    if (!f) {
        if (ensure_audit_dir() != 0)
            return -1;
        f = fopen(AUDIT_LOG_PATH, "a");
        if (!f)
            return -1;
    }

    clock_gettime(CLOCK_REALTIME, &ts);
    gmtime_r(&ts.tv_sec, &tm_buf);
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%dT%H:%M:%S", &tm_buf);

    fprintf(f, "{\"timestamp\":\"%s.%03ldZ\",\"severity\":\"", time_buf,
            ts.tv_nsec / 1000000);
    json_fprint_escaped(f, severity_string(severity));
    fprintf(f, "\",\"category\":\"");
    json_fprint_escaped(f, category ? category : "unknown");
    fprintf(f, "\",\"action\":\"");
    json_fprint_escaped(f, action ? action : "unknown");
    fprintf(f, "\",\"user\":\"");
    json_fprint_escaped(f, get_current_user());
    fprintf(f, "\",\"success\":%s,\"detail\":\"", success ? "true" : "false");
    json_fprint_escaped(f, detail ? detail : "");
    fprintf(f, "\"}\n");

    fclose(f);
    return 0;
}

int rs_audit_log(int severity, const char *category, const char *action,
                 const char *detail_fmt, ...)
{
    char detail[512];
    va_list ap;

    if (detail_fmt) {
        va_start(ap, detail_fmt);
        vsnprintf(detail, sizeof(detail), detail_fmt, ap);
        va_end(ap);
    } else {
        detail[0] = '\0';
    }

    return audit_write_entry(severity, category, action, 1, detail);
}

int rs_audit_log_result(int severity, const char *category, const char *action,
                        int success, const char *detail_fmt, ...)
{
    char detail[512];
    va_list ap;

    if (detail_fmt) {
        va_start(ap, detail_fmt);
        vsnprintf(detail, sizeof(detail), detail_fmt, ap);
        va_end(ap);
    } else {
        detail[0] = '\0';
    }

    return audit_write_entry(severity, category, action, success, detail);
}

static int parse_json_string(const char *buf, const char *key,
                              char *out, size_t out_sz)
{
    char pattern[80];
    const char *p;
    const char *start;
    size_t i = 0;

    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    p = strstr(buf, pattern);
    if (!p)
        return -1;
    p = strchr(p, ':');
    if (!p)
        return -1;
    start = strchr(p, '"');
    if (!start)
        return -1;
    start++;

    while (*start && *start != '"' && i + 1 < out_sz) {
        if (*start == '\\' && start[1]) {
            start++;
            switch (*start) {
            case 'n':  out[i++] = '\n'; break;
            case 'r':  out[i++] = '\r'; break;
            case 't':  out[i++] = '\t'; break;
            default:   out[i++] = *start; break;
            }
        } else {
            out[i++] = *start;
        }
        start++;
    }

    out[i] = '\0';
    return 0;
}

static int parse_json_bool(const char *buf, const char *key, int *val)
{
    char pattern[80];
    const char *p;

    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    p = strstr(buf, pattern);
    if (!p)
        return -1;
    p = strchr(p, ':');
    if (!p)
        return -1;
    p++;
    while (*p == ' ' || *p == '\t')
        p++;
    if (strncmp(p, "true", 4) == 0)
        *val = 1;
    else
        *val = 0;
    return 0;
}

int rs_audit_read(struct rs_audit_entry *entries, int max)
{
    FILE *f;
    char line[2048];
    int total = 0;
    int count = 0;
    long *offsets = NULL;
    int cap = 0;

    if (!entries || max <= 0)
        return -1;

    f = fopen(AUDIT_LOG_PATH, "r");
    if (!f)
        return 0;

    while (fgets(line, sizeof(line), f))
        total++;

    if (total == 0) {
        fclose(f);
        return 0;
    }

    cap = total;
    offsets = calloc((size_t)cap, sizeof(long));
    if (!offsets) {
        fclose(f);
        return -1;
    }

    rewind(f);
    total = 0;
    while (total < cap) {
        offsets[total] = ftell(f);
        if (!fgets(line, sizeof(line), f))
            break;
        total++;
    }

    int start = total > max ? total - max : 0;
    for (int i = total - 1; i >= start && count < max; i--) {
        if (fseek(f, offsets[i], SEEK_SET) != 0)
            break;
        if (!fgets(line, sizeof(line), f))
            break;

        memset(&entries[count], 0, sizeof(entries[count]));

        char sev_str[32] = {0};
        parse_json_string(line, "severity", sev_str, sizeof(sev_str));
        if (strcmp(sev_str, "critical") == 0)
            entries[count].severity = AUDIT_SEV_CRITICAL;
        else if (strcmp(sev_str, "warning") == 0)
            entries[count].severity = AUDIT_SEV_WARNING;
        else
            entries[count].severity = AUDIT_SEV_INFO;

        parse_json_string(line, "category", entries[count].category,
                          sizeof(entries[count].category));
        parse_json_string(line, "action", entries[count].action,
                          sizeof(entries[count].action));
        parse_json_string(line, "user", entries[count].user,
                          sizeof(entries[count].user));
        parse_json_string(line, "detail", entries[count].detail,
                          sizeof(entries[count].detail));
        parse_json_bool(line, "success", &entries[count].success);

        count++;
    }

    free(offsets);
    fclose(f);
    return count;
}

int rs_audit_rotate(void)
{
    char archive_path[PATH_MAX];
    struct timespec ts;
    struct tm tm_buf;
    char time_buf[32];

    if (access(AUDIT_LOG_PATH, F_OK) != 0)
        return 0;

    clock_gettime(CLOCK_REALTIME, &ts);
    gmtime_r(&ts.tv_sec, &tm_buf);
    strftime(time_buf, sizeof(time_buf), "%Y%m%d-%H%M%S", &tm_buf);

    snprintf(archive_path, sizeof(archive_path),
             "/var/log/rswitch/audit-%s.json", time_buf);

    if (rename(AUDIT_LOG_PATH, archive_path) != 0) {
        RS_LOG_ERROR("Failed to rotate audit log: %s", strerror(errno));
        return -1;
    }

    RS_LOG_INFO("Audit log rotated to %s", archive_path);
    return 0;
}
