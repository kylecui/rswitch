/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>

#include "rs_log.h"

static const char *level_names[] = {
    "ERROR", "WARN", "INFO", "DEBUG", "TRACE"
};

static const char *level_colors[] = {
    "\033[1;31m",
    "\033[1;33m",
    "\033[1;32m",
    "\033[0;36m",
    "\033[0;90m",
};

static const char *color_reset = "\033[0m";

static char component_name[64] = "rswitch";
static enum rs_log_level current_level = RS_LOG_LEVEL_INFO;
static FILE *log_output = NULL;

void rs_log_init(const char *component, enum rs_log_level level)
{
    if (component) {
        strncpy(component_name, component, sizeof(component_name) - 1);
        component_name[sizeof(component_name) - 1] = '\0';
    }
    current_level = level;
    if (!log_output)
        log_output = stderr;
}

void rs_log_set_level(enum rs_log_level level)
{
    current_level = level;
}

enum rs_log_level rs_log_get_level(void)
{
    return current_level;
}

void rs_log_set_output(FILE *fp)
{
    log_output = fp;
}

void rs_log_write(enum rs_log_level level, const char *file, int line,
                  const char *fmt, ...)
{
    if (level > current_level)
        return;

    FILE *out = log_output ? log_output : stderr;

    struct timespec ts;
    struct tm tm_buf;
    clock_gettime(CLOCK_REALTIME, &ts);
    localtime_r(&ts.tv_sec, &tm_buf);

    const char *basename = strrchr(file, '/');
    basename = basename ? basename + 1 : file;

    int use_color = (out == stderr || out == stdout);

    if (use_color) {
        fprintf(out, "%s%-5s%s %04d-%02d-%02d %02d:%02d:%02d.%03ld [%s] %s:%d: ",
                level_colors[level], level_names[level], color_reset,
                tm_buf.tm_year + 1900, tm_buf.tm_mon + 1, tm_buf.tm_mday,
                tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec,
                ts.tv_nsec / 1000000,
                component_name, basename, line);
    } else {
        fprintf(out, "%-5s %04d-%02d-%02d %02d:%02d:%02d.%03ld [%s] %s:%d: ",
                level_names[level],
                tm_buf.tm_year + 1900, tm_buf.tm_mon + 1, tm_buf.tm_mday,
                tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec,
                ts.tv_nsec / 1000000,
                component_name, basename, line);
    }

    va_list ap;
    va_start(ap, fmt);
    vfprintf(out, fmt, ap);
    va_end(ap);

    fputc('\n', out);
    fflush(out);
}
