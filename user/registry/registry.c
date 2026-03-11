// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>
#include <limits.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "registry.h"
#if __has_include("rs_log.h")
#include "rs_log.h"
#else
#include "../common/rs_log.h"
#endif
#include "../../bpf/core/module_abi.h"

#define REGISTRY_PACKAGES_DIR "/var/lib/rswitch/registry/packages"
#define REGISTRY_LOCAL_BUILD_DIR "./build/bpf"

struct rs_registry_record {
	struct rs_registry_entry entry;
	char local_path[PATH_MAX];
	char package_path[PATH_MAX];
};

static void hook_to_string(unsigned int hook, char *buf, size_t buf_sz)
{
	if (!buf || buf_sz == 0)
		return;
	if (hook == RS_HOOK_XDP_EGRESS)
		snprintf(buf, buf_sz, "egress");
	else
		snprintf(buf, buf_sz, "ingress");
}

static int parse_abi_version(const char *abi, unsigned int *major, unsigned int *minor)
{
	if (!abi || !major || !minor)
		return -1;
	if (sscanf(abi, "%u.%u", major, minor) != 2)
		return -1;
	return 0;
}

static int read_module_metadata_from_obj(const char *path, struct rs_module_desc *desc)
{
	struct bpf_object *obj;
	struct bpf_map *map;
	const void *data;
	size_t size;
	int err;

	obj = bpf_object__open(path);
	err = libbpf_get_error(obj);
	if (err) {
		RS_LOG_ERROR("Failed to open %s: %s", path, strerror(-err));
		return -1;
	}

	bpf_object__for_each_map(map, obj) {
		const char *map_name = bpf_map__name(map);

		if (!strstr(map_name, ".rodata.mod"))
			continue;

		data = bpf_map__initial_value(map, &size);
		if (!data) {
			RS_LOG_ERROR("No data in .rodata.mod section of %s", path);
			bpf_object__close(obj);
			return -1;
		}

		if (size == 0 || size < sizeof(*desc))
			size = sizeof(*desc);

		memcpy(desc, data, sizeof(*desc));
		bpf_object__close(obj);
		return 0;
	}

	bpf_object__close(obj);
	RS_LOG_ERROR("No .rodata.mod section found in %s", path);
	return -1;
}

static int shell_quote(const char *src, char *dst, size_t dst_sz)
{
	size_t d = 0;

	if (!src || !dst || dst_sz < 3)
		return -1;

	dst[d++] = '\'';
	for (size_t i = 0; src[i] != '\0'; i++) {
		if (src[i] == '\'') {
			if (d + 4 >= dst_sz)
				return -1;
			dst[d++] = '\'';
			dst[d++] = '\\';
			dst[d++] = '\'';
			dst[d++] = '\'';
		} else {
			if (d + 1 >= dst_sz)
				return -1;
			dst[d++] = src[i];
		}
	}

	if (d + 2 > dst_sz)
		return -1;

	dst[d++] = '\'';
	dst[d] = '\0';
	return 0;
}

static int copy_file(const char *src, const char *dst)
{
	FILE *in = NULL;
	FILE *out = NULL;
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

	fclose(in);
	fclose(out);
	return 0;
}

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

static int parse_json_uint_field(const char *buf, const char *key, unsigned int *value)
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

	if (sscanf(p, "%u", value) != 1)
		return -1;

	return 0;
}

static int string_contains_case_insensitive(const char *haystack, const char *needle)
{
	if (!needle || needle[0] == '\0')
		return 1;
	if (!haystack)
		return 0;

	for (size_t i = 0; haystack[i] != '\0'; i++) {
		size_t j = 0;
		while (needle[j] != '\0' && haystack[i + j] != '\0' &&
		       tolower((unsigned char)haystack[i + j]) == tolower((unsigned char)needle[j])) {
			j++;
		}
		if (needle[j] == '\0')
			return 1;
	}
	return 0;
}

static int load_registry_index(struct rs_registry_record *records, int max_records)
{
	FILE *f;
	char *buf = NULL;
	long sz;
	const char *p;
	int count = 0;

	if (!records || max_records <= 0)
		return -1;

	f = fopen(REGISTRY_INDEX_FILE, "r");
	if (!f)
		return -1;

	if (fseek(f, 0, SEEK_END) != 0) {
		fclose(f);
		return -1;
	}
	sz = ftell(f);
	if (sz < 0) {
		fclose(f);
		return -1;
	}
	if (fseek(f, 0, SEEK_SET) != 0) {
		fclose(f);
		return -1;
	}

	buf = calloc(1, (size_t)sz + 1);
	if (!buf) {
		fclose(f);
		return -1;
	}

	if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
		free(buf);
		fclose(f);
		return -1;
	}
	fclose(f);

	p = strchr(buf, '[');
	if (!p) {
		free(buf);
		return -1;
	}

	while (*p && count < max_records) {
		const char *obj_start = strchr(p, '{');
		const char *q;
		int depth = 0;
		size_t obj_len;
		char *obj;

		if (!obj_start)
			break;

		q = obj_start;
		while (*q) {
			if (*q == '{')
				depth++;
			else if (*q == '}') {
				depth--;
				if (depth == 0)
					break;
			}
			q++;
		}

		if (*q != '}')
			break;

		obj_len = (size_t)(q - obj_start + 1);
		obj = calloc(1, obj_len + 1);
		if (!obj)
			break;
		memcpy(obj, obj_start, obj_len);

		memset(&records[count], 0, sizeof(records[count]));
		if (parse_json_string_field(obj, "name", records[count].entry.name,
					    sizeof(records[count].entry.name)) == 0 &&
		    parse_json_string_field(obj, "version", records[count].entry.version,
					    sizeof(records[count].entry.version)) == 0 &&
		    parse_json_string_field(obj, "abi_version", records[count].entry.abi_version,
					    sizeof(records[count].entry.abi_version)) == 0 &&
		    parse_json_string_field(obj, "author", records[count].entry.author,
					    sizeof(records[count].entry.author)) == 0 &&
		    parse_json_string_field(obj, "description", records[count].entry.description,
					    sizeof(records[count].entry.description)) == 0 &&
		    parse_json_uint_field(obj, "stage", &records[count].entry.stage) == 0 &&
		    parse_json_string_field(obj, "hook", records[count].entry.hook,
					    sizeof(records[count].entry.hook)) == 0 &&
		    parse_json_uint_field(obj, "flags", &records[count].entry.flags) == 0 &&
		    parse_json_string_field(obj, "license", records[count].entry.license,
					    sizeof(records[count].entry.license)) == 0 &&
		    parse_json_string_field(obj, "checksum", records[count].entry.checksum,
					    sizeof(records[count].entry.checksum)) == 0) {
			parse_json_string_field(obj, "local_path", records[count].local_path,
						sizeof(records[count].local_path));
			parse_json_string_field(obj, "package_path", records[count].package_path,
						sizeof(records[count].package_path));
			count++;
		}

		free(obj);
		p = q + 1;
	}

	free(buf);
	return count;
}

static int add_record(struct rs_registry_record *records, int *count, int max_records,
		      const struct rs_module_desc *desc, const char *version,
		      const char *author, const char *license, const char *checksum,
		      const char *local_path, const char *package_path)
{
	struct rs_registry_record *rec;

	if (!records || !count || !desc || *count >= max_records)
		return -1;

	rec = &records[*count];
	memset(rec, 0, sizeof(*rec));

	snprintf(rec->entry.name, sizeof(rec->entry.name), "%s", desc->name);
	snprintf(rec->entry.version, sizeof(rec->entry.version), "%s", version ? version : "0.0.0");
	snprintf(rec->entry.abi_version, sizeof(rec->entry.abi_version), "%u.%u",
		 RS_ABI_MAJOR(desc->abi_version), RS_ABI_MINOR(desc->abi_version));
	snprintf(rec->entry.author, sizeof(rec->entry.author), "%s", author ? author : "local");
	snprintf(rec->entry.description, sizeof(rec->entry.description), "%s", desc->description);
	rec->entry.stage = desc->stage;
	hook_to_string(desc->hook, rec->entry.hook, sizeof(rec->entry.hook));
	rec->entry.flags = desc->flags;
	snprintf(rec->entry.license, sizeof(rec->entry.license), "%s", license ? license : "unknown");
	snprintf(rec->entry.checksum, sizeof(rec->entry.checksum), "%s", checksum ? checksum : "sha256:unknown");

	if (local_path)
		snprintf(rec->local_path, sizeof(rec->local_path), "%s", local_path);
	if (package_path)
		snprintf(rec->package_path, sizeof(rec->package_path), "%s", package_path);

	(*count)++;
	return 0;
}

static int metadata_from_rsmod(const char *rsmod_path, struct rs_module_desc *desc)
{
	char tmp_tpl[] = "/tmp/rs_registry_pkg_XXXXXX";
	char tmp_obj[PATH_MAX];
	char q_tmp[PATH_MAX * 2];
	char q_pkg[PATH_MAX * 2];
	char cmd[4096];
	char cleanup_cmd[PATH_MAX * 2 + 64];
	char *tmp_dir;
	int ret = -1;

	if (!rsmod_path || !desc)
		return -1;

	tmp_dir = mkdtemp(tmp_tpl);
	if (!tmp_dir)
		return -1;

	if (shell_quote(tmp_dir, q_tmp, sizeof(q_tmp)) != 0 ||
	    shell_quote(rsmod_path, q_pkg, sizeof(q_pkg)) != 0)
		goto cleanup;

	snprintf(cmd, sizeof(cmd), "tar xzf %s -C %s", q_pkg, q_tmp);
	if (system(cmd) != 0)
		goto cleanup;

	snprintf(tmp_obj, sizeof(tmp_obj), "%s/module.bpf.o", tmp_dir);
	if (access(tmp_obj, F_OK) != 0)
		goto cleanup;

	if (read_module_metadata_from_obj(tmp_obj, desc) != 0)
		goto cleanup;

	ret = 0;

cleanup:
	if (q_tmp[0] != '\0') {
		snprintf(cleanup_cmd, sizeof(cleanup_cmd), "rm -rf %s", q_tmp);
		system(cleanup_cmd);
	} else if (tmp_dir) {
		snprintf(cleanup_cmd, sizeof(cleanup_cmd), "rm -rf '%s'", tmp_dir);
		system(cleanup_cmd);
	}
	return ret;
}

int rs_registry_update_index(void)
{
	DIR *dir;
	struct dirent *ent;
	struct rs_registry_record records[256];
	int count = 0;
	FILE *f;

	if (ensure_dir("/var/lib/rswitch") != 0 ||
	    ensure_dir("/var/lib/rswitch/registry") != 0 ||
	    ensure_dir(REGISTRY_PACKAGES_DIR) != 0) {
		RS_LOG_ERROR("Failed to create registry directories: %s", strerror(errno));
		return 1;
	}

	dir = opendir(REGISTRY_LOCAL_BUILD_DIR);
	if (dir) {
		while ((ent = readdir(dir)) != NULL && count < (int)(sizeof(records) / sizeof(records[0]))) {
			char path[PATH_MAX];
			size_t len;
			struct rs_module_desc desc = {0};

			if (ent->d_name[0] == '.')
				continue;

			len = strlen(ent->d_name);
			if (len < 6 || strcmp(ent->d_name + len - 6, ".bpf.o") != 0)
				continue;

			snprintf(path, sizeof(path), "%s/%s", REGISTRY_LOCAL_BUILD_DIR, ent->d_name);
			if (read_module_metadata_from_obj(path, &desc) != 0)
				continue;

			desc.name[sizeof(desc.name) - 1] = '\0';
			desc.description[sizeof(desc.description) - 1] = '\0';
			add_record(records, &count, (int)(sizeof(records) / sizeof(records[0])),
				   &desc, "local", "builtin", "GPL-2.0", "sha256:unknown",
				   path, "");
		}
		closedir(dir);
	}

	dir = opendir(REGISTRY_PACKAGES_DIR);
	if (dir) {
		while ((ent = readdir(dir)) != NULL && count < (int)(sizeof(records) / sizeof(records[0]))) {
			char pkg_path[PATH_MAX];
			size_t len;
			struct rs_module_desc desc = {0};

			if (ent->d_name[0] == '.')
				continue;

			len = strlen(ent->d_name);
			if (len < 6 || strcmp(ent->d_name + len - 6, ".rsmod") != 0)
				continue;

			snprintf(pkg_path, sizeof(pkg_path), "%s/%s", REGISTRY_PACKAGES_DIR, ent->d_name);
			if (metadata_from_rsmod(pkg_path, &desc) != 0)
				continue;

			desc.name[sizeof(desc.name) - 1] = '\0';
			desc.description[sizeof(desc.description) - 1] = '\0';
			add_record(records, &count, (int)(sizeof(records) / sizeof(records[0])),
				   &desc, "0.0.0", "publisher", "unknown", "sha256:unknown",
				   "", pkg_path);
		}
		closedir(dir);
	}

	f = fopen(REGISTRY_INDEX_FILE, "w");
	if (!f) {
		RS_LOG_ERROR("Failed to write registry index %s: %s", REGISTRY_INDEX_FILE, strerror(errno));
		return 1;
	}

	fprintf(f, "{\n  \"modules\": [\n");
	for (int i = 0; i < count; i++) {
		struct rs_registry_record *rec = &records[i];

		fprintf(f, "    {\n");
		fprintf(f, "      \"name\": \"");
		json_fprint_escaped(f, rec->entry.name);
		fprintf(f, "\",\n      \"version\": \"");
		json_fprint_escaped(f, rec->entry.version);
		fprintf(f, "\",\n      \"abi_version\": \"");
		json_fprint_escaped(f, rec->entry.abi_version);
		fprintf(f, "\",\n      \"author\": \"");
		json_fprint_escaped(f, rec->entry.author);
		fprintf(f, "\",\n      \"description\": \"");
		json_fprint_escaped(f, rec->entry.description);
		fprintf(f, "\",\n      \"stage\": %u,\n", rec->entry.stage);
		fprintf(f, "      \"hook\": \"");
		json_fprint_escaped(f, rec->entry.hook);
		fprintf(f, "\",\n      \"flags\": %u,\n", rec->entry.flags);
		fprintf(f, "      \"license\": \"");
		json_fprint_escaped(f, rec->entry.license);
		fprintf(f, "\",\n      \"checksum\": \"");
		json_fprint_escaped(f, rec->entry.checksum);
		fprintf(f, "\",\n      \"local_path\": \"");
		json_fprint_escaped(f, rec->local_path);
		fprintf(f, "\",\n      \"package_path\": \"");
		json_fprint_escaped(f, rec->package_path);
		fprintf(f, "\"\n    }%s\n", i + 1 < count ? "," : "");
	}
	fprintf(f, "  ]\n}\n");
	fclose(f);

	printf("Updated registry index: %s (%d modules)\n", REGISTRY_INDEX_FILE, count);
	return 0;
}

int rs_registry_search(const char *query, struct rs_registry_entry *results, int max_results)
{
	struct rs_registry_record records[512];
	int loaded;
	int out = 0;

	if (!results || max_results <= 0)
		return -1;

	loaded = load_registry_index(records, (int)(sizeof(records) / sizeof(records[0])));
	if (loaded < 0) {
		RS_LOG_ERROR("Failed to load registry index: %s", REGISTRY_INDEX_FILE);
		return -1;
	}

	for (int i = 0; i < loaded && out < max_results; i++) {
		if (string_contains_case_insensitive(records[i].entry.name, query) ||
		    string_contains_case_insensitive(records[i].entry.description, query)) {
			results[out++] = records[i].entry;
		}
	}

	return out;
}

int rs_registry_info(const char *name, struct rs_registry_entry *entry)
{
	struct rs_registry_record records[512];
	int loaded;

	if (!name || !entry)
		return -1;

	loaded = load_registry_index(records, (int)(sizeof(records) / sizeof(records[0])));
	if (loaded < 0)
		return -1;

	for (int i = 0; i < loaded; i++) {
		if (strcmp(records[i].entry.name, name) == 0) {
			*entry = records[i].entry;
			return 0;
		}
	}

	return -1;
}

int rs_registry_install(const char *name, const char *version)
{
	struct rs_registry_record records[512];
	struct rs_registry_record *match = NULL;
	int loaded;
	unsigned int abi_major = 0;
	unsigned int abi_minor = 0;
	char dst_path[PATH_MAX];

	if (!name || name[0] == '\0') {
		RS_LOG_ERROR("Module name is required");
		return 1;
	}

	loaded = load_registry_index(records, (int)(sizeof(records) / sizeof(records[0])));
	if (loaded < 0) {
		RS_LOG_ERROR("Failed to load registry index. Run: rswitchctl module update-index");
		return 1;
	}

	for (int i = 0; i < loaded; i++) {
		if (strcmp(records[i].entry.name, name) != 0)
			continue;
		if (version && version[0] != '\0' && strcmp(records[i].entry.version, version) != 0)
			continue;
		match = &records[i];
		break;
	}

	if (!match) {
		if (version && version[0] != '\0')
			RS_LOG_ERROR("Module '%s@%s' not found in registry", name, version);
		else
			RS_LOG_ERROR("Module '%s' not found in registry", name);
		return 1;
	}

	if (version && version[0] != '\0' && strcmp(match->entry.version, version) != 0) {
		RS_LOG_ERROR("Version mismatch: requested %s, found %s", version, match->entry.version);
		return 1;
	}

	if (parse_abi_version(match->entry.abi_version, &abi_major, &abi_minor) != 0) {
		RS_LOG_ERROR("Invalid ABI in registry entry: %s", match->entry.abi_version);
		return 1;
	}

	if (abi_major != RS_ABI_VERSION_MAJOR || abi_minor > RS_ABI_VERSION_MINOR) {
		RS_LOG_ERROR("ABI mismatch (platform %u.%u, module %u.%u)",
			     RS_ABI_VERSION_MAJOR, RS_ABI_VERSION_MINOR, abi_major, abi_minor);
		return 1;
	}

	if (ensure_dir(REGISTRY_LOCAL_BUILD_DIR) != 0) {
		RS_LOG_ERROR("Failed to create %s: %s", REGISTRY_LOCAL_BUILD_DIR, strerror(errno));
		return 1;
	}

	snprintf(dst_path, sizeof(dst_path), "%s/%s.bpf.o", REGISTRY_LOCAL_BUILD_DIR, match->entry.name);

	if (match->local_path[0] != '\0') {
		if (access(match->local_path, R_OK) != 0) {
			RS_LOG_ERROR("Source object not readable: %s", match->local_path);
			return 1;
		}
		if (strcmp(match->local_path, dst_path) != 0 && copy_file(match->local_path, dst_path) != 0) {
			RS_LOG_ERROR("Failed to install module: %s", strerror(errno));
			return 1;
		}
		printf("Installed module '%s' to %s\n", match->entry.name, dst_path);
		return 0;
	}

	if (match->package_path[0] != '\0') {
		char tmp_tpl[] = "/tmp/rs_registry_install_XXXXXX";
		char src_obj[PATH_MAX];
		char q_pkg[PATH_MAX * 2];
		char q_tmp[PATH_MAX * 2];
		char cmd[4096];
		char cleanup_cmd[PATH_MAX * 2 + 64];
		char *tmp_dir = mkdtemp(tmp_tpl);
		int ret = 1;

		if (!tmp_dir) {
			RS_LOG_ERROR("Failed to create temporary directory: %s", strerror(errno));
			return 1;
		}
		q_tmp[0] = '\0';
		if (shell_quote(match->package_path, q_pkg, sizeof(q_pkg)) != 0 ||
		    shell_quote(tmp_dir, q_tmp, sizeof(q_tmp)) != 0) {
			RS_LOG_ERROR("Path too long while installing package");
			goto install_pkg_cleanup;
		}
		snprintf(cmd, sizeof(cmd), "tar xzf %s -C %s", q_pkg, q_tmp);
		if (system(cmd) != 0) {
			RS_LOG_ERROR("Failed to extract package: %s", match->package_path);
			goto install_pkg_cleanup;
		}
		snprintf(src_obj, sizeof(src_obj), "%s/module.bpf.o", tmp_dir);
		if (access(src_obj, R_OK) != 0) {
			RS_LOG_ERROR("module.bpf.o missing in package %s", match->package_path);
			goto install_pkg_cleanup;
		}
		if (copy_file(src_obj, dst_path) != 0) {
			RS_LOG_ERROR("Failed to install module: %s", strerror(errno));
			goto install_pkg_cleanup;
		}
		ret = 0;

install_pkg_cleanup:
		if (q_tmp[0] != '\0') {
			snprintf(cleanup_cmd, sizeof(cleanup_cmd), "rm -rf %s", q_tmp);
			system(cleanup_cmd);
		} else {
			snprintf(cleanup_cmd, sizeof(cleanup_cmd), "rm -rf '%s'", tmp_dir);
			system(cleanup_cmd);
		}
		if (ret != 0)
			return 1;

		printf("Installed module '%s' from package to %s\n", match->entry.name, dst_path);
		return 0;
	}

	RS_LOG_ERROR("Registry entry has no install source");
	return 1;
}

int rs_registry_publish(const char *rsmod_path)
{
	const char *base;
	char dst_path[PATH_MAX];

	if (!rsmod_path || rsmod_path[0] == '\0') {
		RS_LOG_ERROR(".rsmod path is required");
		return 1;
	}

	if (access(rsmod_path, R_OK) != 0) {
		RS_LOG_ERROR("Package not readable: %s", rsmod_path);
		return 1;
	}

	if (ensure_dir("/var/lib/rswitch") != 0 ||
	    ensure_dir("/var/lib/rswitch/registry") != 0 ||
	    ensure_dir(REGISTRY_PACKAGES_DIR) != 0) {
		RS_LOG_ERROR("Failed to create registry directories: %s", strerror(errno));
		return 1;
	}

	base = strrchr(rsmod_path, '/');
	base = base ? base + 1 : rsmod_path;
	if (base[0] == '\0') {
		RS_LOG_ERROR("Invalid package path: %s", rsmod_path);
		return 1;
	}

	snprintf(dst_path, sizeof(dst_path), "%s/%s", REGISTRY_PACKAGES_DIR, base);
	if (copy_file(rsmod_path, dst_path) != 0) {
		RS_LOG_ERROR("Failed to publish package: %s", strerror(errno));
		return 1;
	}

	printf("Published: %s\n", dst_path);
	return rs_registry_update_index();
}
