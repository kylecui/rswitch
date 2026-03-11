// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <dirent.h>
#include <time.h>
#include <signal.h>
#include <limits.h>
#include <stdint.h>
#include "rollback.h"
#if __has_include("rs_log.h")
#include "rs_log.h"
#else
#include "../common/rs_log.h"
#endif

#define ROLLBACK_ROOT_DIR "/var/lib/rswitch"
#define ROLLBACK_CURRENT_PROFILE "/var/lib/rswitch/current_profile.yaml"
#define ROLLBACK_RUNNING_STATE "/var/lib/rswitch/running_state.json"
#define ROLLBACK_PENDING_APPLY "/var/lib/rswitch/pending_apply.json"
#define SNAPSHOT_META_FILE "snapshot.json"
#define SNAPSHOT_PROFILE_FILE "current_profile.yaml"
#define SNAPSHOT_STATE_FILE "running_state.json"

struct pending_apply_info {
	char profile_path[256];
	char snapshot_id[32];
	int confirm_timeout;
	uint64_t apply_timestamp;
};

static int ensure_dir(const char *path)
{
	struct stat st;

	if (!path || path[0] == '\0')
		return -1;

	if (stat(path, &st) == 0) {
		if (S_ISDIR(st.st_mode))
			return 0;
		errno = ENOTDIR;
		return -1;
	}

	if (mkdir(path, 0755) == 0)
		return 0;

	if (errno == ENOENT) {
		char parent[PATH_MAX];
		char *slash;

		snprintf(parent, sizeof(parent), "%s", path);
		slash = strrchr(parent, '/');
		if (slash && slash != parent) {
			*slash = '\0';
			if (ensure_dir(parent) != 0)
				return -1;
		}
		if (mkdir(path, 0755) == 0 || errno == EEXIST)
			return 0;
	}

	if (errno == EEXIST)
		return 0;

	return -1;
}

static int copy_file(const char *src, const char *dst)
{
	FILE *in;
	FILE *out;
	char buf[8192];
	size_t n;

	in = fopen(src, "rb");
	if (!in)
		return -1;

	out = fopen(dst, "wb");
	if (!out) {
		fclose(in);
		return -1;
	}

	while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
		if (fwrite(buf, 1, n, out) != n) {
			fclose(in);
			fclose(out);
			return -1;
		}
	}

	if (ferror(in)) {
		fclose(in);
		fclose(out);
		return -1;
	}

	fclose(in);
	fclose(out);
	return 0;
}

static int remove_tree(const char *path)
{
	struct stat st;

	if (lstat(path, &st) != 0)
		return -1;

	if (S_ISDIR(st.st_mode)) {
		DIR *dir = opendir(path);
		struct dirent *ent;

		if (!dir)
			return -1;

		while ((ent = readdir(dir)) != NULL) {
			char child[PATH_MAX];

			if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
				continue;

			snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
			if (remove_tree(child) != 0) {
				closedir(dir);
				return -1;
			}
		}

		closedir(dir);
		return rmdir(path);
	}

	return unlink(path);
}

static void json_fprint_escaped(FILE *f, const char *s)
{
	const unsigned char *p = (const unsigned char *)s;

	while (p && *p) {
		switch (*p) {
		case '\\':
			fputs("\\\\", f);
			break;
		case '"':
			fputs("\\\"", f);
			break;
		case '\n':
			fputs("\\n", f);
			break;
		case '\r':
			fputs("\\r", f);
			break;
		case '\t':
			fputs("\\t", f);
			break;
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

static int parse_json_string_field(const char *buf, const char *key, char *out, size_t out_sz)
{
	char pattern[64];
	const char *p;
	const char *start;
	size_t i = 0;

	if (!buf || !key || !out || out_sz == 0)
		return -1;

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
		if (*start == '\\' && start[1] != '\0') {
			start++;
			switch (*start) {
			case 'n':
				out[i++] = '\n';
				break;
			case 'r':
				out[i++] = '\r';
				break;
			case 't':
				out[i++] = '\t';
				break;
			default:
				out[i++] = *start;
				break;
			}
		} else {
			out[i++] = *start;
		}
		start++;
	}

	out[i] = '\0';
	return (*start == '"') ? 0 : -1;
}

static int parse_json_int_field(const char *buf, const char *key, int *value)
{
	char pattern[64];
	const char *p;

	if (!buf || !key || !value)
		return -1;

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

	if (sscanf(p, "%d", value) != 1)
		return -1;

	return 0;
}

static int parse_json_u64_field(const char *buf, const char *key, uint64_t *value)
{
	char pattern[64];
	const char *p;
	unsigned long long v;

	if (!buf || !key || !value)
		return -1;

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

	if (sscanf(p, "%llu", &v) != 1)
		return -1;

	*value = (uint64_t)v;
	return 0;
}

static int read_text_file(const char *path, char *buf, size_t buf_sz)
{
	FILE *f;
	size_t n;

	if (!path || !buf || buf_sz == 0)
		return -1;

	f = fopen(path, "r");
	if (!f)
		return -1;

	n = fread(buf, 1, buf_sz - 1, f);
	if (ferror(f)) {
		fclose(f);
		return -1;
	}
	buf[n] = '\0';
	fclose(f);
	return 0;
}

static int write_snapshot_json(const char *snapshot_dir, const struct rs_snapshot_info *info)
{
	char meta_path[PATH_MAX];
	FILE *f;

	if (!snapshot_dir || !info)
		return -1;

	snprintf(meta_path, sizeof(meta_path), "%s/%s", snapshot_dir, SNAPSHOT_META_FILE);
	f = fopen(meta_path, "w");
	if (!f)
		return -1;

	fprintf(f, "{\n");
	fprintf(f, "  \"id\": \"");
	json_fprint_escaped(f, info->id);
	fprintf(f, "\",\n");
	fprintf(f, "  \"description\": \"");
	json_fprint_escaped(f, info->description);
	fprintf(f, "\",\n");
	fprintf(f, "  \"profile_path\": \"");
	json_fprint_escaped(f, info->profile_path);
	fprintf(f, "\",\n");
	fprintf(f, "  \"timestamp\": %llu,\n", (unsigned long long)info->timestamp);
	fprintf(f, "  \"confirmed\": %d\n", info->confirmed ? 1 : 0);
	fprintf(f, "}\n");
	if (fclose(f) != 0)
		return -1;

	return 0;
}

static int read_snapshot_json(const char *snapshot_dir, struct rs_snapshot_info *info)
{
	char meta_path[PATH_MAX];
	char buf[4096];

	if (!snapshot_dir || !info)
		return -1;

	snprintf(meta_path, sizeof(meta_path), "%s/%s", snapshot_dir, SNAPSHOT_META_FILE);
	if (read_text_file(meta_path, buf, sizeof(buf)) != 0)
		return -1;

	memset(info, 0, sizeof(*info));
	if (parse_json_string_field(buf, "id", info->id, sizeof(info->id)) != 0)
		return -1;
	if (parse_json_string_field(buf, "description", info->description,
					sizeof(info->description)) != 0)
		info->description[0] = '\0';
	if (parse_json_string_field(buf, "profile_path", info->profile_path,
					sizeof(info->profile_path)) != 0)
		info->profile_path[0] = '\0';
	if (parse_json_u64_field(buf, "timestamp", &info->timestamp) != 0)
		info->timestamp = 0;
	if (parse_json_int_field(buf, "confirmed", &info->confirmed) != 0)
		info->confirmed = 0;

	return 0;
}

static int cmp_snapshot_desc(const void *a, const void *b)
{
	const struct rs_snapshot_info *sa = a;
	const struct rs_snapshot_info *sb = b;

	if (sa->timestamp < sb->timestamp)
		return 1;
	if (sa->timestamp > sb->timestamp)
		return -1;
	return strcmp(sb->id, sa->id);
}

static int cmp_snapshot_asc(const void *a, const void *b)
{
	const struct rs_snapshot_info *sa = a;
	const struct rs_snapshot_info *sb = b;

	if (sa->timestamp < sb->timestamp)
		return -1;
	if (sa->timestamp > sb->timestamp)
		return 1;
	return strcmp(sa->id, sb->id);
}

static int create_snapshot_internal(const char *description, char *snapshot_id, size_t snapshot_id_sz)
{
	char id[32];
	char snapshot_dir[PATH_MAX];
	char profile_dst[PATH_MAX];
	char state_dst[PATH_MAX];
	time_t now;
	struct tm tm_now;
	struct rs_snapshot_info info;
	struct rs_snapshot_info all[256];
	int count;

	now = time(NULL);
	if (localtime_r(&now, &tm_now) == NULL)
		return -1;

	if (strftime(id, sizeof(id), "%Y%m%d-%H%M%S", &tm_now) == 0)
		return -1;

	if (ensure_dir(ROLLBACK_ROOT_DIR) != 0 || ensure_dir(ROLLBACK_SNAPSHOT_DIR) != 0) {
		RS_LOG_ERROR("Failed to create rollback directories: %s", strerror(errno));
		return -1;
	}

	snprintf(snapshot_dir, sizeof(snapshot_dir), "%s/%s", ROLLBACK_SNAPSHOT_DIR, id);
	if (mkdir(snapshot_dir, 0755) != 0) {
		RS_LOG_ERROR("Failed to create snapshot dir %s: %s", snapshot_dir, strerror(errno));
		return -1;
	}

	snprintf(profile_dst, sizeof(profile_dst), "%s/%s", snapshot_dir, SNAPSHOT_PROFILE_FILE);
	if (access(ROLLBACK_CURRENT_PROFILE, R_OK) == 0 &&
	    copy_file(ROLLBACK_CURRENT_PROFILE, profile_dst) != 0) {
		RS_LOG_ERROR("Failed to copy current profile into snapshot: %s", strerror(errno));
		remove_tree(snapshot_dir);
		return -1;
	}

	snprintf(state_dst, sizeof(state_dst), "%s/%s", snapshot_dir, SNAPSHOT_STATE_FILE);
	if (access(ROLLBACK_RUNNING_STATE, R_OK) == 0 &&
	    copy_file(ROLLBACK_RUNNING_STATE, state_dst) != 0) {
		RS_LOG_ERROR("Failed to copy running state into snapshot: %s", strerror(errno));
		remove_tree(snapshot_dir);
		return -1;
	}

	memset(&info, 0, sizeof(info));
	snprintf(info.id, sizeof(info.id), "%s", id);
	snprintf(info.description, sizeof(info.description), "%s",
		 description ? description : "snapshot");
	snprintf(info.profile_path, sizeof(info.profile_path), "%s", ROLLBACK_CURRENT_PROFILE);
	info.timestamp = (uint64_t)now;
	info.confirmed = 0;

	if (write_snapshot_json(snapshot_dir, &info) != 0) {
		RS_LOG_ERROR("Failed to write snapshot metadata: %s", strerror(errno));
		remove_tree(snapshot_dir);
		return -1;
	}

	if (snapshot_id && snapshot_id_sz > 0)
		snprintf(snapshot_id, snapshot_id_sz, "%s", id);

	count = rs_rollback_list_snapshots(all, (int)(sizeof(all) / sizeof(all[0])));
	if (count > ROLLBACK_MAX_SNAPSHOTS) {
		qsort(all, (size_t)count, sizeof(all[0]), cmp_snapshot_asc);
		for (int i = 0; i < count - ROLLBACK_MAX_SNAPSHOTS; i++) {
			char old_path[PATH_MAX];

			snprintf(old_path, sizeof(old_path), "%s/%s", ROLLBACK_SNAPSHOT_DIR, all[i].id);
			remove_tree(old_path);
		}
	}

	return 0;
}

static int read_pending_apply(struct pending_apply_info *info)
{
	char buf[2048];

	if (!info)
		return -1;

	if (read_text_file(ROLLBACK_PENDING_APPLY, buf, sizeof(buf)) != 0)
		return -1;

	memset(info, 0, sizeof(*info));
	if (parse_json_string_field(buf, "profile_path", info->profile_path,
					sizeof(info->profile_path)) != 0)
		return -1;
	if (parse_json_string_field(buf, "snapshot_id", info->snapshot_id,
					sizeof(info->snapshot_id)) != 0)
		return -1;
	if (parse_json_int_field(buf, "confirm_timeout", &info->confirm_timeout) != 0)
		return -1;
	if (parse_json_u64_field(buf, "apply_timestamp", &info->apply_timestamp) != 0)
		return -1;

	return 0;
}

int rs_rollback_create_snapshot(const char *description)
{
	return create_snapshot_internal(description, NULL, 0);
}

int rs_rollback_list_snapshots(struct rs_snapshot_info *snapshots, int max)
{
	DIR *dir;
	struct dirent *ent;
	int count = 0;

	if (!snapshots || max <= 0)
		return -1;

	dir = opendir(ROLLBACK_SNAPSHOT_DIR);
	if (!dir) {
		if (errno == ENOENT)
			return 0;
		return -1;
	}

	while ((ent = readdir(dir)) != NULL) {
		char snapshot_dir[PATH_MAX];
		struct stat st;
		struct rs_snapshot_info info;

		if (ent->d_name[0] == '.')
			continue;

		snprintf(snapshot_dir, sizeof(snapshot_dir), "%s/%s", ROLLBACK_SNAPSHOT_DIR, ent->d_name);
		if (stat(snapshot_dir, &st) != 0 || !S_ISDIR(st.st_mode))
			continue;

		if (read_snapshot_json(snapshot_dir, &info) != 0)
			continue;

		if (count < max)
			snapshots[count] = info;
		count++;
	}

	closedir(dir);

	if (count > 1)
		qsort(snapshots, (size_t)(count < max ? count : max), sizeof(snapshots[0]), cmp_snapshot_desc);

	return count < max ? count : max;
}

int rs_rollback_apply(const char *profile_path, int confirm_timeout_sec)
{
	char backup_id[32];
	FILE *f;
	pid_t pid;

	if (!profile_path || profile_path[0] == '\0')
		return -1;
	if (access(profile_path, R_OK) != 0) {
		RS_LOG_ERROR("Profile not readable: %s", profile_path);
		return -1;
	}

	if (confirm_timeout_sec <= 0)
		confirm_timeout_sec = ROLLBACK_DEFAULT_CONFIRM_TIMEOUT;

	if (create_snapshot_internal("auto-backup before apply", backup_id, sizeof(backup_id)) != 0)
		return -1;

	if (ensure_dir(ROLLBACK_ROOT_DIR) != 0) {
		RS_LOG_ERROR("Failed to ensure rollback root dir: %s", strerror(errno));
		return -1;
	}

	f = fopen(ROLLBACK_PENDING_APPLY, "w");
	if (!f) {
		RS_LOG_ERROR("Failed to write pending apply state: %s", strerror(errno));
		return -1;
	}
	fprintf(f, "{\n");
	fprintf(f, "  \"profile_path\": \"");
	json_fprint_escaped(f, profile_path);
	fprintf(f, "\",\n");
	fprintf(f, "  \"snapshot_id\": \"");
	json_fprint_escaped(f, backup_id);
	fprintf(f, "\",\n");
	fprintf(f, "  \"confirm_timeout\": %d,\n", confirm_timeout_sec);
	fprintf(f, "  \"apply_timestamp\": %llu\n", (unsigned long long)time(NULL));
	fprintf(f, "}\n");
	if (fclose(f) != 0) {
		RS_LOG_ERROR("Failed to finalize pending apply file: %s", strerror(errno));
		unlink(ROLLBACK_PENDING_APPLY);
		return -1;
	}

	if (copy_file(profile_path, ROLLBACK_CURRENT_PROFILE) != 0) {
		RS_LOG_ERROR("Failed to apply profile: %s", strerror(errno));
		unlink(ROLLBACK_PENDING_APPLY);
		return -1;
	}

	pid = fork();
	if (pid < 0) {
		RS_LOG_ERROR("Failed to fork rollback watchdog: %s", strerror(errno));
		unlink(ROLLBACK_PENDING_APPLY);
		return -1;
	}

	if (pid == 0) {
		struct pending_apply_info pending;

		signal(SIGTERM, SIG_DFL);
		sleep((unsigned int)confirm_timeout_sec);

		if (access(ROLLBACK_PENDING_APPLY, F_OK) == 0 && read_pending_apply(&pending) == 0) {
			RS_LOG_WARN("Apply confirmation timeout reached, rolling back to snapshot %s",
				    pending.snapshot_id);
			rs_rollback_to(pending.snapshot_id);
			unlink(ROLLBACK_PENDING_APPLY);
		}
		_exit(0);
	}

	RS_LOG_WARN("Profile applied with %d-second confirmation timeout", confirm_timeout_sec);
	return 0;
}

int rs_rollback_confirm(void)
{
	struct pending_apply_info pending;
	char snapshot_dir[PATH_MAX];
	struct rs_snapshot_info info;

	if (read_pending_apply(&pending) != 0)
		return -1;

	if (unlink(ROLLBACK_PENDING_APPLY) != 0 && errno != ENOENT) {
		RS_LOG_ERROR("Failed to clear pending apply state: %s", strerror(errno));
		return -1;
	}

	snprintf(snapshot_dir, sizeof(snapshot_dir), "%s/%s", ROLLBACK_SNAPSHOT_DIR, pending.snapshot_id);
	if (read_snapshot_json(snapshot_dir, &info) == 0) {
		info.confirmed = 1;
		if (write_snapshot_json(snapshot_dir, &info) != 0)
			RS_LOG_WARN("Failed to mark snapshot %s as confirmed", pending.snapshot_id);
	}

	RS_LOG_INFO("Configuration apply confirmed");
	return 0;
}

int rs_rollback_to(const char *snapshot_id)
{
	char id_buf[32];
	char snapshot_path[PATH_MAX];
	char profile_src[PATH_MAX];
	struct rs_snapshot_info snaps[1];

	if (!snapshot_id) {
		if (rs_rollback_list_snapshots(snaps, 1) <= 0)
			return -1;
		snapshot_id = snaps[0].id;
	}

	snprintf(id_buf, sizeof(id_buf), "%s", snapshot_id);
	snprintf(snapshot_path, sizeof(snapshot_path), "%s/%s", ROLLBACK_SNAPSHOT_DIR, id_buf);
	snprintf(profile_src, sizeof(profile_src), "%s/%s", snapshot_path, SNAPSHOT_PROFILE_FILE);

	if (access(profile_src, R_OK) != 0) {
		RS_LOG_ERROR("Snapshot profile not found for %s", id_buf);
		return -1;
	}

	if (ensure_dir(ROLLBACK_ROOT_DIR) != 0) {
		RS_LOG_ERROR("Failed to ensure rollback root dir: %s", strerror(errno));
		return -1;
	}

	if (copy_file(profile_src, ROLLBACK_CURRENT_PROFILE) != 0) {
		RS_LOG_ERROR("Failed to rollback to snapshot %s: %s", id_buf, strerror(errno));
		return -1;
	}

	RS_LOG_INFO("Rolled back to snapshot %s", id_buf);
	return 0;
}

int rs_rollback_pending_status(char *snapshot_id, int *remaining_sec)
{
	struct pending_apply_info pending;
	time_t now;
	int remain;

	if (read_pending_apply(&pending) != 0)
		return -1;

	now = time(NULL);
	remain = pending.confirm_timeout - (int)(now - (time_t)pending.apply_timestamp);
	if (remain < 0)
		remain = 0;

	if (snapshot_id)
		snprintf(snapshot_id, 32, "%s", pending.snapshot_id);
	if (remaining_sec)
		*remaining_sec = remain;

	return 0;
}
