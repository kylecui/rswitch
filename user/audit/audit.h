// SPDX-License-Identifier: GPL-2.0
#ifndef RSWITCH_AUDIT_H
#define RSWITCH_AUDIT_H

#include <stdint.h>

#define AUDIT_LOG_PATH "/var/log/rswitch/audit.json"
#define AUDIT_MAX_ENTRIES 10000

/* Audit event severity */
#define AUDIT_SEV_INFO     0
#define AUDIT_SEV_WARNING  1
#define AUDIT_SEV_CRITICAL 2

/* Audit event categories */
#define AUDIT_CAT_CONFIG   "config"
#define AUDIT_CAT_MODULE   "module"
#define AUDIT_CAT_ACL      "acl"
#define AUDIT_CAT_PROFILE  "profile"
#define AUDIT_CAT_SYSTEM   "system"
#define AUDIT_CAT_USER     "user"

struct rs_audit_entry {
    uint64_t timestamp;
    int severity;
    char category[32];
    char action[64];
    char user[64];
    char detail[512];
    int success;
};

/* Initialize audit subsystem (create log dir/file if needed) */
int rs_audit_init(void);

/* Log an audit event */
int rs_audit_log(int severity, const char *category, const char *action,
                 const char *detail_fmt, ...);

/* Log an audit event with success/failure indication */
int rs_audit_log_result(int severity, const char *category, const char *action,
                        int success, const char *detail_fmt, ...);

/* Read audit log entries (most recent first, up to max) */
int rs_audit_read(struct rs_audit_entry *entries, int max);

/* Rotate audit log (archive current, start fresh) */
int rs_audit_rotate(void);

#endif
