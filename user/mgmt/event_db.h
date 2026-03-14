// SPDX-License-Identifier: GPL-2.0
#ifndef RSWITCH_EVENT_DB_H
#define RSWITCH_EVENT_DB_H

#include <stdint.h>

#define EVENT_DB_PATH		"/var/lib/rswitch/events.db"
#define EVENT_DB_MAX_ROWS	50000
#define EVENT_DB_PRUNE_BATCH	5000

struct event_row {
	int64_t  id;
	int64_t  timestamp;
	char     severity[16];
	char     category[32];
	char     message[512];
};

int  event_db_open(const char *path);
void event_db_close(void);

int  event_db_insert(const char *severity, const char *category,
		     const char *message, int64_t timestamp);

/*
 * Query events.  Caller provides an array of event_row and max count.
 * Filters are optional (pass NULL / 0 to ignore).
 *   severity  – "info", "warn", "error", or NULL for all
 *   category  – "system", "port", etc., or NULL for all
 *   before    – epoch seconds upper bound (0 = no limit)
 *   after     – epoch seconds lower bound (0 = no limit)
 *   search    – substring match on message (NULL = no filter)
 *   limit     – max rows to return (0 = use default 200)
 * Returns: number of rows written, or -1 on error.
 * Results are ordered newest-first.
 */
int  event_db_query(struct event_row *out, int max,
		    const char *severity, const char *category,
		    int64_t before, int64_t after,
		    const char *search, int limit);

int  event_db_count(void);

#endif
