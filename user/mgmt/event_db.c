// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sqlite3.h>
#include "event_db.h"
#include "../common/rs_log.h"

static sqlite3 *g_db;

static int ensure_dir(const char *path)
{
	char tmp[256];
	char *p;

	snprintf(tmp, sizeof(tmp), "%s", path);
	p = strrchr(tmp, '/');
	if (!p)
		return 0;
	*p = '\0';
	return mkdir(tmp, 0755) == 0 || errno == EEXIST ? 0 : -1;
}

int event_db_open(const char *path)
{
	const char *dbpath = path ? path : EVENT_DB_PATH;
	int rc;

	if (g_db)
		return 0;

	ensure_dir(dbpath);

	rc = sqlite3_open(dbpath, &g_db);
	if (rc != SQLITE_OK) {
		RS_LOG_ERROR("event_db: cannot open %s: %s", dbpath,
			     sqlite3_errmsg(g_db));
		g_db = NULL;
		return -1;
	}

	sqlite3_exec(g_db, "PRAGMA journal_mode=WAL", NULL, NULL, NULL);
	sqlite3_exec(g_db, "PRAGMA synchronous=NORMAL", NULL, NULL, NULL);
	sqlite3_exec(g_db, "PRAGMA busy_timeout=3000", NULL, NULL, NULL);

	rc = sqlite3_exec(g_db,
		"CREATE TABLE IF NOT EXISTS events ("
		"  id        INTEGER PRIMARY KEY AUTOINCREMENT,"
		"  timestamp INTEGER NOT NULL,"
		"  severity  TEXT NOT NULL DEFAULT 'info',"
		"  category  TEXT NOT NULL DEFAULT 'system',"
		"  message   TEXT NOT NULL"
		");"
		"CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp);"
		"CREATE INDEX IF NOT EXISTS idx_events_sev ON events(severity);"
		"CREATE INDEX IF NOT EXISTS idx_events_cat ON events(category);",
		NULL, NULL, NULL);

	if (rc != SQLITE_OK) {
		RS_LOG_ERROR("event_db: schema init failed: %s",
			     sqlite3_errmsg(g_db));
		sqlite3_close(g_db);
		g_db = NULL;
		return -1;
	}

	RS_LOG_INFO("event_db: opened %s", dbpath);
	return 0;
}

void event_db_close(void)
{
	if (g_db) {
		sqlite3_close(g_db);
		g_db = NULL;
	}
}

static void prune_if_needed(void)
{
	char sql[256];

	snprintf(sql, sizeof(sql),
		 "DELETE FROM events WHERE id IN ("
		 "  SELECT id FROM events ORDER BY id ASC LIMIT "
		 "  MAX(0, (SELECT COUNT(*) FROM events) - %d)"
		 ")", EVENT_DB_MAX_ROWS);
	sqlite3_exec(g_db, sql, NULL, NULL, NULL);
}

int event_db_insert(const char *severity, const char *category,
		    const char *message, int64_t timestamp)
{
	static sqlite3_stmt *stmt;
	static int insert_count;
	int rc;

	if (!g_db)
		return -1;

	if (!stmt) {
		rc = sqlite3_prepare_v2(g_db,
			"INSERT INTO events (timestamp, severity, category, message) "
			"VALUES (?, ?, ?, ?)", -1, &stmt, NULL);
		if (rc != SQLITE_OK)
			return -1;
	}

	sqlite3_reset(stmt);
	sqlite3_bind_int64(stmt, 1, timestamp);
	sqlite3_bind_text(stmt, 2, severity ? severity : "info", -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(stmt, 3, category ? category : "system", -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(stmt, 4, message ? message : "", -1, SQLITE_TRANSIENT);

	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE)
		return -1;

	if (++insert_count >= EVENT_DB_PRUNE_BATCH) {
		insert_count = 0;
		prune_if_needed();
	}

	return 0;
}

int event_db_query(struct event_row *out, int max,
		   const char *severity, const char *category,
		   int64_t before, int64_t after,
		   const char *search, int limit)
{
	sqlite3_stmt *stmt = NULL;
	char sql[1024];
	int off = 0;
	int bind = 0;
	int count = 0;
	int rc;

	if (!g_db || !out || max <= 0)
		return -1;

	if (limit <= 0 || limit > max)
		limit = max;

	off = snprintf(sql, sizeof(sql),
		       "SELECT id, timestamp, severity, category, message "
		       "FROM events WHERE 1=1");

	if (severity && severity[0])
		off += snprintf(sql + off, sizeof(sql) - off,
				" AND severity = ?");
	if (category && category[0])
		off += snprintf(sql + off, sizeof(sql) - off,
				" AND category = ?");
	if (after > 0)
		off += snprintf(sql + off, sizeof(sql) - off,
				" AND timestamp >= ?");
	if (before > 0)
		off += snprintf(sql + off, sizeof(sql) - off,
				" AND timestamp <= ?");
	if (search && search[0])
		off += snprintf(sql + off, sizeof(sql) - off,
				" AND message LIKE ?");

	snprintf(sql + off, sizeof(sql) - off,
		 " ORDER BY id DESC LIMIT %d", limit);

	rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
	if (rc != SQLITE_OK)
		return -1;

	bind = 1;
	if (severity && severity[0])
		sqlite3_bind_text(stmt, bind++, severity, -1, SQLITE_TRANSIENT);
	if (category && category[0])
		sqlite3_bind_text(stmt, bind++, category, -1, SQLITE_TRANSIENT);
	if (after > 0)
		sqlite3_bind_int64(stmt, bind++, after);
	if (before > 0)
		sqlite3_bind_int64(stmt, bind++, before);
	if (search && search[0]) {
		char pattern[256];
		snprintf(pattern, sizeof(pattern), "%%%s%%", search);
		sqlite3_bind_text(stmt, bind++, pattern, -1, SQLITE_TRANSIENT);
	}

	while (sqlite3_step(stmt) == SQLITE_ROW && count < max) {
		struct event_row *r = &out[count];
		const char *s;

		r->id = sqlite3_column_int64(stmt, 0);
		r->timestamp = sqlite3_column_int64(stmt, 1);

		s = (const char *)sqlite3_column_text(stmt, 2);
		snprintf(r->severity, sizeof(r->severity), "%s", s ? s : "info");

		s = (const char *)sqlite3_column_text(stmt, 3);
		snprintf(r->category, sizeof(r->category), "%s", s ? s : "system");

		s = (const char *)sqlite3_column_text(stmt, 4);
		snprintf(r->message, sizeof(r->message), "%s", s ? s : "");

		count++;
	}

	sqlite3_finalize(stmt);
	return count;
}

int event_db_count(void)
{
	sqlite3_stmt *stmt = NULL;
	int count = 0;

	if (!g_db)
		return 0;

	if (sqlite3_prepare_v2(g_db, "SELECT COUNT(*) FROM events",
			       -1, &stmt, NULL) == SQLITE_OK) {
		if (sqlite3_step(stmt) == SQLITE_ROW)
			count = sqlite3_column_int(stmt, 0);
		sqlite3_finalize(stmt);
	}

	return count;
}
