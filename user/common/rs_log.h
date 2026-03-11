/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef RS_LOG_H
#define RS_LOG_H

#include <stdio.h>
#include <stdarg.h>

enum rs_log_level {
    RS_LOG_LEVEL_ERROR = 0,
    RS_LOG_LEVEL_WARN  = 1,
    RS_LOG_LEVEL_INFO  = 2,
    RS_LOG_LEVEL_DEBUG = 3,
    RS_LOG_LEVEL_TRACE = 4,
};

/**
 * rs_log_init - Initialize logging for a component.
 * @component: Name shown in log prefix (e.g. "rswitch-loader", "voqd")
 * @level:     Minimum severity to output. Defaults to "rswitch"/INFO if never called.
 */
void rs_log_init(const char *component, enum rs_log_level level);

void rs_log_set_level(enum rs_log_level level);
enum rs_log_level rs_log_get_level(void);

/**
 * rs_log_set_output - Redirect log output (default: stderr).
 * Caller owns the FILE* lifetime.
 */
void rs_log_set_output(FILE *fp);

void rs_log_write(enum rs_log_level level, const char *file, int line,
                  const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));

#define RS_LOG_ERROR(fmt, ...) \
    rs_log_write(RS_LOG_LEVEL_ERROR, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define RS_LOG_WARN(fmt, ...) \
    rs_log_write(RS_LOG_LEVEL_WARN, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define RS_LOG_INFO(fmt, ...) \
    rs_log_write(RS_LOG_LEVEL_INFO, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define RS_LOG_DEBUG(fmt, ...) \
    rs_log_write(RS_LOG_LEVEL_DEBUG, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define RS_LOG_TRACE(fmt, ...) \
    rs_log_write(RS_LOG_LEVEL_TRACE, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#endif
