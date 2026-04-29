// SPDX-License-Identifier: GPL-2.0

#define _GNU_SOURCE

#include "mongoose.h"
#include "mgmtd.h"
#include "mgmt_iface.h"
#include "event_db.h"
#include "../loader/profile_parser.h"

#if __has_include("rs_log.h")
#include "rs_log.h"
#else
#include "../common/rs_log.h"
#endif

#include <signal.h>
#include <getopt.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>
#include <ctype.h>
#include <limits.h>
#include <linux/limits.h>
#include <dirent.h>
#include <sys/stat.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/utsname.h>
#include <pthread.h>
#include <sys/wait.h>

#if defined(__has_include)
#if __has_include(<openssl/sha.h>)
#include <openssl/sha.h>
#define HAVE_OPENSSL_SHA 1
#else
#define HAVE_OPENSSL_SHA 0
#endif
#else
#define HAVE_OPENSSL_SHA 0
#endif

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/types.h>

#include "../watchdog/watchdog.h"
#include "../topology/topology.h"
#include "../audit/audit.h"
#include "../rollback/rollback.h"
#include "../lifecycle/lifecycle.h"
#include "../../bpf/core/map_defs.h"

#ifndef RS_ABI_VERSION_MAJOR
#define RS_ABI_VERSION_MAJOR 0
#endif
#ifndef RS_ABI_VERSION_MINOR
#define RS_ABI_VERSION_MINOR 0
#endif

#ifndef RS_MAX_INTERFACES
#define RS_MAX_INTERFACES 256
#endif

#define RS_STATS_MAP_PATH "/sys/fs/bpf/rs_stats_map"
#define RS_MODULE_STATS_MAP_PATH "/sys/fs/bpf/rs_module_stats_map"
#define RS_PORT_CONFIG_MAP_PATH "/sys/fs/bpf/rs_port_config_map"
#define RS_VLAN_MAP_PATH "/sys/fs/bpf/rs_vlan_map"
#define RS_MAC_TABLE_MAP_PATH "/sys/fs/bpf/rs_mac_table"
#define RS_MODULE_CONFIG_MAP_PATH "/sys/fs/bpf/rs_module_config_map"
#define VOQD_STATE_MAP_PATH "/sys/fs/bpf/voqd_state_map"
#define QDEPTH_MAP_PATH "/sys/fs/bpf/qdepth_map"
#define ACL_5TUPLE_MAP_PATH "/sys/fs/bpf/acl_5tuple_map"
#define ACL_PDP_MAP_PATH "/sys/fs/bpf/acl_pdp_map"
#define ACL_PSP_MAP_PATH "/sys/fs/bpf/acl_psp_map"
#define ACL_PP_MAP_PATH "/sys/fs/bpf/acl_pp_map"
#define ACL_CONFIG_MAP_PATH "/sys/fs/bpf/acl_config_map"
#define ACL_LPM_SRC_MAP_PATH "/sys/fs/bpf/acl_lpm_src_map"
#define ACL_LPM_DST_MAP_PATH "/sys/fs/bpf/acl_lpm_dst_map"
#define ROUTE_TBL_MAP_PATH "/sys/fs/bpf/route_tbl"
#define RS_EVENT_BUS_PATH "/sys/fs/bpf/rs_event_bus"
#define DHCP_SNOOP_CONFIG_MAP_PATH "/sys/fs/bpf/dhcp_snoop_config_map"
#define DHCP_TRUSTED_PORTS_MAP_PATH "/sys/fs/bpf/dhcp_trusted_ports_map"

/* Event type ranges (must match uapi.h) */
#define RS_EVENT_L2_BASE        0x0100
#define RS_EVENT_ACL_BASE       0x0200
#define RS_EVENT_DHCP_SNOOP     (RS_EVENT_ACL_BASE + 0x20) /* 0x0220 */
#define RS_EVENT_MIRROR_BASE    0x0400
#define RS_EVENT_ERROR_BASE     0xFF00

/* DHCP snooping structures (must match dhcp_snoop.bpf.c) */
struct dhcp_snoop_config {
	__u32 enabled;
	__u32 drop_rogue_server;
	__u32 trusted_port_count;
	__u32 pad;
};

enum dhcp_snoop_action_e {
	DHCP_SNOOP_ACTION_OBSERVED       = 0,
	DHCP_SNOOP_ACTION_ROGUE_DROP     = 1,
	DHCP_SNOOP_ACTION_BINDING_CREATE = 2,
};

struct acl_5tuple_key {
	__u8 proto;
	__u8 pad[3];
	__u32 src_ip;
	__u32 dst_ip;
	__u16 sport;
	__u16 dport;
} __attribute__((packed));

struct acl_result {
	__u8 action;
	__u8 log_event;
	__u16 redirect_ifindex;
	__u32 stats_id;
	__u32 rule_id;
	__u8  priority;
	__u8  pad[3];
} __attribute__((packed));

struct acl_proto_dstip_port_key {
	__u8 proto;
	__u8 pad[3];
	__u32 dst_ip;
	__u16 dst_port;
	__u16 pad2;
} __attribute__((packed));

struct acl_proto_srcip_port_key {
	__u8 proto;
	__u8 pad[3];
	__u32 src_ip;
	__u16 dst_port;
	__u16 pad2;
} __attribute__((packed));

struct acl_proto_port_key {
	__u8 proto;
	__u8 pad;
	__u16 dst_port;
} __attribute__((packed));

struct acl_config {
	__u8 default_action;
	__u8 enabled;
	__u8 log_drops;
	__u8 pad;
};

struct lpm_key {
	__u32 prefixlen;
	__u32 addr;
};

struct acl_lpm_value {
	__u8 action;
	__u8 log_event;
	__u16 redirect_ifindex;
	__u32 stats_id;
	__u32 rule_id;
	__u8  priority;
	__u8  proto;
	__u16 sport;
	__u16 dport;
	__u16 pad;
	__u32 other_ip;
} __attribute__((packed));

struct route_entry {
	__u32 nexthop;
	__u32 ifindex;
	__u32 metric;
	__u8 type;
	__u8 pad[3];
	__u32 ecmp_group_id;
};

#define MODULE_MAX_ENTRIES 64
#define AUDIT_READ_MAX 256
#define SNAPSHOT_READ_MAX 256

/* rs_stats, rs_module_stats, rs_port_config, rs_vlan_members,
 * rs_module_config_key, rs_module_config_value, RS_MODULE_CONFIG_KEY_LEN,
 * RS_MODULE_CONFIG_VAL_LEN — now provided by bpf/core/map_defs.h (L-17) */

struct profile_module_info {
	char name[64];
	char type[16]; /* "ingress" or "egress" */
};

struct mgmtd_ctx {
	struct mgmtd_config cfg;
	struct rs_mgmt_iface_config mgmt_cfg;
	struct timespec start_ts;
	int loader_managed_veth;
	char profile_name[128];
	char profile_path[PATH_MAX];
	struct profile_module_info profile_modules[128];
	int profile_module_count;
	/* DHCP snooping config cached from profile */
	int dhcp_snoop_enabled;
	int dhcp_snoop_drop_rogue;
	char dhcp_trusted_ports[16][32];
	int dhcp_trusted_port_count;
};

static volatile sig_atomic_t g_running = 1;
static struct mgmtd_ctx g_ctx;
static struct mg_mgr *g_mgr;

static struct {
	int stats_fd;
	int module_stats_fd;
	int port_config_fd;
	int vlan_fd;
	int mac_table_fd;
	int module_config_fd;
	int voqd_state_fd;
	int qdepth_fd;
	int acl_5tuple_fd;
	int acl_pdp_fd;
	int acl_psp_fd;
	int acl_pp_fd;
	int acl_config_fd;
	int acl_lpm_src_fd;
	int acl_lpm_dst_fd;
	int route_tbl_fd;
	int dhcp_snoop_config_fd;
	int dhcp_trusted_ports_fd;
	int ncpus;
	bool initialized;
} g_maps = { .stats_fd = -1, .module_stats_fd = -1, .port_config_fd = -1,
	     .vlan_fd = -1, .mac_table_fd = -1, .module_config_fd = -1,
	     .voqd_state_fd = -1, .qdepth_fd = -1, .acl_5tuple_fd = -1,
	     .acl_pdp_fd = -1, .acl_psp_fd = -1, .acl_pp_fd = -1,
	     .acl_config_fd = -1, .acl_lpm_src_fd = -1, .acl_lpm_dst_fd = -1,
	     .route_tbl_fd = -1,
	     .dhcp_snoop_config_fd = -1, .dhcp_trusted_ports_fd = -1,
	     .ncpus = 0, .initialized = false };

/* ── Live event tracking state ── */

struct port_link_state {
	__u32 ifindex;
	char name[IF_NAMESIZE];
	int link_up;
	int valid;
};

static int g_prev_health = -1;
static struct port_link_state g_port_links[RS_MAX_INTERFACES];
static int g_port_link_count;
static int g_event_bus_fd = -1;
static struct ring_buffer *g_event_rb;
static pthread_t g_event_thread;
static volatile int g_event_thread_running;
static int g_stats_event_counter;
static __u32 g_acl_next_rule_id = 1;
static int g_acl_rule_ids_seeded;

#define STATS_EVENT_INTERVAL 15

static struct mg_str extract_name_from_uri(struct mg_http_message *hm, const char *prefix);
static __u32 acl_next_rule_id(void);

static int profile_name_valid(const char *name)
{
	const unsigned char *p;

	if (!name || name[0] == '\0')
		return 0;
	if (strstr(name, "..") || strchr(name, '/'))
		return 0;

	for (p = (const unsigned char *) name; *p != '\0'; p++) {
		if (isalnum(*p) || *p == '.' || *p == '_' || *p == '-' || *p == ' ')
			continue;
		return 0;
	}

	return 1;
}

static int timing_safe_compare(const void *a, const void *b, size_t len)
{
	const volatile unsigned char *pa = a;
	const volatile unsigned char *pb = b;
	unsigned char result = 0;
	size_t i;

	for (i = 0; i < len; i++)
		result |= pa[i] ^ pb[i];

	return result != 0;
}

static int is_hex_sha256(const char *s)
{
	int i;

	if (!s || strlen(s) != 64)
		return 0;

	for (i = 0; i < 64; i++) {
		if (!isxdigit((unsigned char) s[i]))
			return 0;
	}

	return 1;
}

static void bytes_to_hex(const unsigned char *in, size_t in_len, char *out, size_t out_len)
{
	static const char hex[] = "0123456789abcdef";
	size_t i;

	if (!in || !out || out_len < (in_len * 2 + 1)) {
		if (out && out_len > 0)
			out[0] = '\0';
		return;
	}

	for (i = 0; i < in_len; i++) {
		out[i * 2] = hex[(in[i] >> 4) & 0x0f];
		out[i * 2 + 1] = hex[in[i] & 0x0f];
	}
	out[in_len * 2] = '\0';
}

static int fill_random_bytes(unsigned char *buf, size_t len)
{
	FILE *fp;
	size_t nread;

	if (!buf || len == 0)
		return -1;

	fp = fopen("/dev/urandom", "rb");
	if (!fp)
		return -1;
	nread = fread(buf, 1, len, fp);
	fclose(fp);

	if (nread != len)
		return -1;

	return 0;
}

static int generate_salt(char *out, size_t out_len)
{
	unsigned char salt_bytes[16];

	if (!out || out_len < 33)
		return -1;

	if (fill_random_bytes(salt_bytes, sizeof(salt_bytes)) != 0)
		return -1;

	bytes_to_hex(salt_bytes, sizeof(salt_bytes), out, out_len);
	return out[0] != '\0' ? 0 : -1;
}

static int hash_password(const char *password, const char *salt, char *out, size_t out_len)
{
	unsigned char digest[32];
	const char *pw;
	const char *sa;

	if (!out || out_len < 65)
		return -1;

	pw = password ? password : "";
	sa = salt ? salt : "";

#if HAVE_OPENSSL_SHA
	{
		unsigned char k0[64];
		unsigned char ipad[64];
		unsigned char opad[64];
		unsigned char inner[32];
		unsigned char key_hash[32];
		size_t i;
		size_t key_len = strlen(sa);
		SHA256_CTX ctx;

		memset(k0, 0, sizeof(k0));
		if (key_len > 64) {
			if (SHA256((const unsigned char *) sa, key_len, key_hash) == NULL)
				return -1;
			memcpy(k0, key_hash, sizeof(key_hash));
		} else {
			memcpy(k0, sa, key_len);
		}

		for (i = 0; i < sizeof(k0); i++) {
			ipad[i] = (unsigned char) (k0[i] ^ 0x36);
			opad[i] = (unsigned char) (k0[i] ^ 0x5c);
		}

		if (SHA256_Init(&ctx) != 1)
			return -1;
		if (SHA256_Update(&ctx, ipad, sizeof(ipad)) != 1)
			return -1;
		if (SHA256_Update(&ctx, pw, strlen(pw)) != 1)
			return -1;
		if (SHA256_Final(inner, &ctx) != 1)
			return -1;

		if (SHA256_Init(&ctx) != 1)
			return -1;
		if (SHA256_Update(&ctx, opad, sizeof(opad)) != 1)
			return -1;
		if (SHA256_Update(&ctx, inner, sizeof(inner)) != 1)
			return -1;
		if (SHA256_Final(digest, &ctx) != 1)
			return -1;
	}
#else
	{
		size_t i;
		size_t pw_len = strlen(pw);
		size_t salt_len = strlen(sa);

		for (i = 0; i < sizeof(digest); i++)
			digest[i] = (unsigned char) (0xA5u ^ (unsigned char) (i * 17u));

		for (int round = 0; round < 2048; round++) {
			for (i = 0; i < pw_len; i++) {
				size_t j = (i + (size_t) round) % sizeof(digest);
				digest[j] = (unsigned char) ((digest[j] + (unsigned char) pw[i] + (unsigned char) (round & 0xff)) ^
						      (unsigned char) ((digest[(j + 7) % sizeof(digest)] << 1) |
						      (digest[(j + 7) % sizeof(digest)] >> 7)));
			}
			for (i = 0; i < salt_len; i++) {
				size_t j = (i * 3 + (size_t) round) % sizeof(digest);
				digest[j] ^= (unsigned char) (sa[i] + (unsigned char) i + (unsigned char) (round & 0xff));
				digest[(j + 13) % sizeof(digest)] = (unsigned char)
					((digest[(j + 13) % sizeof(digest)] << 3) |
					 (digest[(j + 13) % sizeof(digest)] >> 5));
			}
		}
	}
#endif

	bytes_to_hex(digest, sizeof(digest), out, out_len);
	return out[0] != '\0' ? 0 : -1;
}

static void normalize_auth_config(struct mgmtd_config *cfg)
{
	char hashed[65];

	if (!cfg)
		return;

	if (cfg->auth_password[0] && !is_hex_sha256(cfg->auth_password)) {
		if (cfg->auth_salt[0] == '\0' &&
		    generate_salt(cfg->auth_salt, sizeof(cfg->auth_salt)) != 0)
			strncpy(cfg->auth_salt, "00000000000000000000000000000000",
				sizeof(cfg->auth_salt) - 1);
		if (hash_password(cfg->auth_password, cfg->auth_salt, hashed, sizeof(hashed)) == 0)
			strncpy(cfg->auth_password, hashed, sizeof(cfg->auth_password) - 1);
	}
}

static int shell_safe_token_valid(const char *s)
{
	const unsigned char *p;

	if (!s || s[0] == '\0')
		return 0;

	for (p = (const unsigned char *) s; *p != '\0'; p++) {
		if (isalnum(*p) || *p == '.' || *p == '_' || *p == '-')
			continue;
		return 0;
	}

	return 1;
}

static int has_shell_metachar(const char *s)
{
	const char *p;

	if (!s)
		return 0;

	for (p = s; *p != '\0'; p++) {
		switch (*p) {
		case ';':
		case '|':
		case '&':
		case '$':
		case '\\':
		case '`':
		case '(':
		case ')':
		case '{':
		case '}':
		case '<':
		case '>':
		case '!':
		case '#':
		case '~':
			return 1;
		default:
			break;
		}
	}

	return 0;
}

/*
 * Parse CIDR notation (e.g., "10.174.229.0/24") or plain IP (e.g., "10.1.2.3")
 * Returns 0 on success, -1 on failure
 * Output: ip in network byte order, prefixlen in bits (32 for single host)
 */
static int parse_cidr(const char *str, __u32 *ip, __u32 *prefixlen)
{
	char buf[64];
	char *slash;
	struct in_addr addr;
	long prefix;
	char *endptr;

	if (!str || !ip || !prefixlen)
		return -1;

	/* Copy to mutable buffer */
	if (strlen(str) >= sizeof(buf))
		return -1;
	strcpy(buf, str);

	/* Check for CIDR notation (slash) */
	slash = strchr(buf, '/');
	if (slash) {
		*slash = '\0';
		prefix = strtol(slash + 1, &endptr, 10);
		if (*endptr != '\0' || prefix < 0 || prefix > 32)
			return -1;
		*prefixlen = (__u32)prefix;
	} else {
		/* Single IP = /32 */
		*prefixlen = 32;
	}

	/* Parse IP address */
	if (inet_pton(AF_INET, buf, &addr) != 1)
		return -1;

	*ip = addr.s_addr;
	return 0;
}

static int extract_profile_name(struct mg_http_message *hm, const char *prefix,
				       char *out, size_t out_len)
{
	struct mg_str name;
	int decoded_len;

	if (!out || out_len == 0)
		return -EINVAL;

	name = extract_name_from_uri(hm, prefix);
	if (name.len == 0)
		return -EINVAL;

	decoded_len = mg_url_decode(name.buf, name.len, out, out_len, 0);
	if (decoded_len <= 0 || (size_t) decoded_len >= out_len)
		return -EINVAL;
	out[decoded_len] = '\0';

	if (!profile_name_valid(out))
		return -EINVAL;

	return 0;
}

static void set_active_profile_path(const char *path)
{
	FILE *fp;
	const char *base;

	if (!path || path[0] == '\0')
		return;

	strncpy(g_ctx.profile_path, path, sizeof(g_ctx.profile_path) - 1);
	g_ctx.profile_path[sizeof(g_ctx.profile_path) - 1] = '\0';

	base = strrchr(path, '/');
	if (base)
		base++;
	else
		base = path;

	strncpy(g_ctx.profile_name, base, sizeof(g_ctx.profile_name) - 1);
	g_ctx.profile_name[sizeof(g_ctx.profile_name) - 1] = '\0';

	if (mkdir("/var/lib/rswitch", 0755) != 0 && errno != EEXIST)
		return;

	fp = fopen("/var/lib/rswitch/active_profile", "w");
	if (!fp)
		return;

	fprintf(fp, "%s\n", path);
	fclose(fp);
}

static int detect_loader_ifaces(char *ifaces, size_t ifaces_len)
{
	DIR *proc;
	struct dirent *de;

	if (!ifaces || ifaces_len == 0)
		return -EINVAL;
	ifaces[0] = '\0';

	proc = opendir("/proc");
	if (!proc)
		return -errno;

	while ((de = readdir(proc)) != NULL) {
		char *endptr = NULL;
		long pid = strtol(de->d_name, &endptr, 10);
		char comm_path[64];
		char cmdline_path[64];
		FILE *fp;
		char comm[64];
		char cmdline[4096];
		size_t nread;
		size_t i;

		if (endptr == NULL || *endptr != '\0' || pid <= 0)
			continue;

		snprintf(comm_path, sizeof(comm_path), "/proc/%ld/comm", pid);
		fp = fopen(comm_path, "r");
		if (!fp)
			continue;
		if (!fgets(comm, sizeof(comm), fp)) {
			fclose(fp);
			continue;
		}
		fclose(fp);
		comm[strcspn(comm, "\r\n")] = '\0';
		if (strcmp(comm, "rswitch_loader") != 0)
			continue;

		snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%ld/cmdline", pid);
		fp = fopen(cmdline_path, "r");
		if (!fp)
			continue;
		nread = fread(cmdline, 1, sizeof(cmdline) - 1, fp);
		fclose(fp);
		if (nread == 0)
			continue;
		cmdline[nread] = '\0';

		i = 0;
		while (i < nread) {
			char *arg = &cmdline[i];
			size_t arg_len = strlen(arg);

			if (arg_len == 0) {
				i++;
				continue;
			}

			if ((strcmp(arg, "--ifaces") == 0 || strcmp(arg, "-i") == 0) &&
			    i + arg_len + 1 < nread) {
				char *val = &cmdline[i + arg_len + 1];
				size_t val_len = strlen(val);

				if (val_len > 0 && val_len < ifaces_len) {
					strncpy(ifaces, val, ifaces_len - 1);
					ifaces[ifaces_len - 1] = '\0';
					closedir(proc);
					return 0;
				}
			}

			i += arg_len + 1;
		}
	}

	closedir(proc);
	return -ENOENT;
}

static __u32 resolve_ifindex(const char *name)
{
	__u32 idx = if_nametoindex(name);
	if (idx)
		return idx;
	char path[256];
	snprintf(path, sizeof(path), "/sys/class/net/%s/ifindex", name);
	FILE *f = fopen(path, "r");
	if (!f)
		return 0;
	unsigned int val = 0;
	if (fscanf(f, "%u", &val) != 1)
		val = 0;
	fclose(f);
	return (__u32)val;
}

#define MAX_SESSIONS 64
#define SESSION_TOKEN_LEN 32

struct auth_session {
	char token[SESSION_TOKEN_LEN * 2 + 1];
	time_t created;
	time_t last_seen;
	char remote_ip[64];
};

static struct {
	struct auth_session sessions[MAX_SESSIONS];
	int count;
	int failed_attempts;
	time_t lockout_until;
} g_auth = { .count = 0, .failed_attempts = 0, .lockout_until = 0 };

static struct {
	unsigned long conn_id;
	char token[SESSION_TOKEN_LEN * 2 + 1];
	int active;
} g_pending_cookie[MAX_SESSIONS];

static bool method_is(struct mg_str method, const char *s);
static void json_printf(struct mg_connection *c, int status, const char *fmt, ...);
static int ifindex_to_name_sysfs(__u32 ifindex, char *out, size_t out_sz);
static const char *cors_origin_header(char *buf, size_t buf_len);

static struct mg_str mg_http_body(const struct mg_http_message *hm)
{
	if (!hm)
		return mg_str_n("", 0);
	return hm->body;
}

static void auth_set_pending_cookie(unsigned long conn_id, const char *token)
{
	int i;

	if (!token || token[0] == '\0')
		return;

	for (i = 0; i < MAX_SESSIONS; i++) {
		if (g_pending_cookie[i].active && g_pending_cookie[i].conn_id == conn_id) {
			strncpy(g_pending_cookie[i].token, token,
				sizeof(g_pending_cookie[i].token) - 1);
			g_pending_cookie[i].token[sizeof(g_pending_cookie[i].token) - 1] = '\0';
			return;
		}
	}

	for (i = 0; i < MAX_SESSIONS; i++) {
		if (!g_pending_cookie[i].active) {
			g_pending_cookie[i].active = 1;
			g_pending_cookie[i].conn_id = conn_id;
			strncpy(g_pending_cookie[i].token, token,
				sizeof(g_pending_cookie[i].token) - 1);
			g_pending_cookie[i].token[sizeof(g_pending_cookie[i].token) - 1] = '\0';
			return;
		}
	}

	g_pending_cookie[0].active = 1;
	g_pending_cookie[0].conn_id = conn_id;
	strncpy(g_pending_cookie[0].token, token, sizeof(g_pending_cookie[0].token) - 1);
	g_pending_cookie[0].token[sizeof(g_pending_cookie[0].token) - 1] = '\0';
}

static int auth_take_pending_cookie(unsigned long conn_id, char *token, size_t token_len)
{
	int i;

	if (!token || token_len == 0)
		return 0;

	for (i = 0; i < MAX_SESSIONS; i++) {
		if (g_pending_cookie[i].active && g_pending_cookie[i].conn_id == conn_id) {
			strncpy(token, g_pending_cookie[i].token, token_len - 1);
			token[token_len - 1] = '\0';
			g_pending_cookie[i].active = 0;
			g_pending_cookie[i].conn_id = 0;
			g_pending_cookie[i].token[0] = '\0';
			return 1;
		}
	}

	return 0;
}

static void generate_session_token(char *buf, size_t len)
{
	unsigned char bytes[SESSION_TOKEN_LEN];
	FILE *fp;
	size_t i;

	if (!buf || len < (SESSION_TOKEN_LEN * 2 + 1)) {
		if (buf && len > 0)
			buf[0] = '\0';
		return;
	}

	fp = fopen("/dev/urandom", "rb");
	if (!fp || fread(bytes, 1, sizeof(bytes), fp) != sizeof(bytes)) {
		uint32_t seed = (uint32_t) time(NULL) ^ (uint32_t) (uintptr_t) buf;
		if (fp)
			fclose(fp);
		srand(seed);
		for (i = 0; i < sizeof(bytes); i++)
			bytes[i] = (unsigned char) (rand() & 0xFF);
	} else {
		fclose(fp);
	}

	for (i = 0; i < sizeof(bytes); i++)
		snprintf(buf + (i * 2), len - (i * 2), "%02x", bytes[i]);
	buf[SESSION_TOKEN_LEN * 2] = '\0';
}

static struct auth_session *find_session(const char *token)
{
	int i;

	if (!token || token[0] == '\0')
		return NULL;

	for (i = 0; i < g_auth.count; i++) {
		if (strcmp(g_auth.sessions[i].token, token) == 0)
			return &g_auth.sessions[i];
	}

	return NULL;
}

static struct auth_session *create_session(const char *remote_ip)
{
	struct auth_session *s;
	time_t now = time(NULL);

	if (g_auth.count < MAX_SESSIONS) {
		s = &g_auth.sessions[g_auth.count++];
	} else {
		int oldest = 0;
		int i;

		for (i = 1; i < MAX_SESSIONS; i++) {
			if (g_auth.sessions[i].last_seen < g_auth.sessions[oldest].last_seen)
				oldest = i;
		}
		s = &g_auth.sessions[oldest];
	}

	memset(s, 0, sizeof(*s));
	generate_session_token(s->token, sizeof(s->token));
	s->created = now;
	s->last_seen = now;
	if (remote_ip && remote_ip[0] != '\0')
		strncpy(s->remote_ip, remote_ip, sizeof(s->remote_ip) - 1);

	return s;
}

static void expire_sessions(void)
{
	time_t now = time(NULL);
	int timeout = g_ctx.cfg.session_timeout > 0 ? g_ctx.cfg.session_timeout : 3600;
	int i = 0;

	while (i < g_auth.count) {
		if ((now - g_auth.sessions[i].last_seen) > timeout) {
			if (i != g_auth.count - 1)
				g_auth.sessions[i] = g_auth.sessions[g_auth.count - 1];
			g_auth.count--;
			continue;
		}
		i++;
	}
}

static int extract_session_cookie(const struct mg_str *cookie_hdr, char *token, size_t token_len)
{
	char buf[512];
	char *part;
	char *saveptr = NULL;

	if (!cookie_hdr || !token || token_len == 0)
		return 0;

	if (cookie_hdr->len == 0 || cookie_hdr->len >= sizeof(buf))
		return 0;

	memcpy(buf, cookie_hdr->buf, cookie_hdr->len);
	buf[cookie_hdr->len] = '\0';

	part = strtok_r(buf, ";", &saveptr);
	while (part) {
		while (*part == ' ' || *part == '\t')
			part++;
		if (strncmp(part, "rs_session=", 11) == 0) {
			strncpy(token, part + 11, token_len - 1);
			token[token_len - 1] = '\0';
			return 1;
		}
		part = strtok_r(NULL, ";", &saveptr);
	}

	return 0;
}

static int check_auth(struct mg_connection *c, struct mg_http_message *hm)
{
	char token[SESSION_TOKEN_LEN * 2 + 1];
	struct mg_str *cookie_hdr;
	struct auth_session *session;
	time_t now;

	if (!c || !hm)
		return 0;

	if (!g_ctx.cfg.auth_enabled)
		return 1;

	if (method_is(hm->method, "OPTIONS"))
		return 1;

	now = time(NULL);

	expire_sessions();

	cookie_hdr = mg_http_get_header(hm, "Cookie");
	if (cookie_hdr && extract_session_cookie(cookie_hdr, token, sizeof(token))) {
		session = find_session(token);
		if (session) {
			session->last_seen = now;
			return 1;
		}
	}

	if (g_auth.lockout_until > now) {
		json_printf(c, 429,
			"{\"error\":\"too many authentication failures\",\"retry_after\":%ld}",
			(long) (g_auth.lockout_until - now));
		return 0;
	}

	/* No valid session cookie — return 401 (no WWW-Authenticate header
	 * so the browser won't show a native Basic Auth popup).
	 * The JS login form handles credential input via /api/auth/login. */
	{
		char cors[512];
		char hdrs[1024];
		snprintf(hdrs, sizeof(hdrs),
			 "Content-Type: application/json\r\n%s",
			 cors_origin_header(cors, sizeof(cors)));
		mg_http_reply(c, 401, hdrs,
			      "{\"error\":\"authentication required\"}");
	}
	return 0;
}

static int auth_parse_json_cred(struct mg_str body, const char *path, char *out, size_t out_len)
{
	int off;
	int tok_len;

	if (!path || !out || out_len == 0)
		return 0;

	off = mg_json_get(body, path, &tok_len);
	if (off < 0 || tok_len < 2)
		return 0;

	if (body.buf[off] != '"' || body.buf[off + tok_len - 1] != '"')
		return 0;

	mg_snprintf(out, out_len, "%.*s", tok_len - 2, body.buf + off + 1);
	return 1;
}

static void handle_auth_login(struct mg_connection *c, struct mg_http_message *hm)
{
	char user[64];
	char pass[128];
	char user_in[64];
	char user_cfg[64];
	char pass_hash[65];
	char stored_hash[65];
	char remote_ip[64];
	struct auth_session *session;
	struct mg_str body;
	time_t now;
	int max_fails;

	if (!c || !hm) {
		json_printf(c, 400, "{\"error\":\"invalid request\"}");
		return;
	}

	body = mg_http_body(hm);
	now = time(NULL);

	if (g_auth.lockout_until > now) {
		json_printf(c, 429,
			"{\"error\":\"too many authentication failures\",\"retry_after\":%ld}",
			(long) (g_auth.lockout_until - now));
		return;
	}

	if (!auth_parse_json_cred(body, "$.username", user, sizeof(user)) ||
	    !auth_parse_json_cred(body, "$.password", pass, sizeof(pass))) {
		json_printf(c, 400, "{\"error\":\"username and password required\"}");
		return;
	}

	if (g_ctx.cfg.auth_password[0] == '\0') {
		json_printf(c, 401, "{\"error\":\"no password configured\"}");
		return;
	}

	if (hash_password(pass, g_ctx.cfg.auth_salt, pass_hash, sizeof(pass_hash)) != 0) {
		json_printf(c, 500, "{\"error\":\"auth hash failed\"}");
		return;
	}

	memset(user_in, 0, sizeof(user_in));
	memset(user_cfg, 0, sizeof(user_cfg));
	strncpy(user_in, user, sizeof(user_in) - 1);
	strncpy(user_cfg, g_ctx.cfg.auth_user, sizeof(user_cfg) - 1);

	memset(stored_hash, 0, sizeof(stored_hash));
	if (is_hex_sha256(g_ctx.cfg.auth_password))
		memcpy(stored_hash, g_ctx.cfg.auth_password, 64);

	if (timing_safe_compare(user_in, user_cfg, sizeof(user_in)) == 0 &&
	    timing_safe_compare(pass_hash, stored_hash, 64) == 0) {
		session = NULL;
		memset(remote_ip, 0, sizeof(remote_ip));
		mg_snprintf(remote_ip, sizeof(remote_ip), "%M", mg_print_ip, &c->rem);
		session = create_session(remote_ip);
		if (session)
			auth_set_pending_cookie(c->id, session->token);
		g_auth.failed_attempts = 0;
		g_auth.lockout_until = 0;
		json_printf(c, 200, "{\"ok\":true}");
		return;
	}

	g_auth.failed_attempts++;
	max_fails = g_ctx.cfg.rate_limit_max_fails > 0 ? g_ctx.cfg.rate_limit_max_fails : 5;
	if (g_auth.failed_attempts >= max_fails) {
		int lockout_sec =
			g_ctx.cfg.rate_limit_lockout_sec > 0 ? g_ctx.cfg.rate_limit_lockout_sec : 300;
		g_auth.lockout_until = now + lockout_sec;
		g_auth.failed_attempts = 0;
	}

	json_printf(c, 401, "{\"error\":\"invalid credentials\"}");
}

static int remove_session_by_token(const char *token)
{
	int i;

	if (!token || token[0] == '\0')
		return 0;

	for (i = 0; i < g_auth.count; i++) {
		if (strcmp(g_auth.sessions[i].token, token) == 0) {
			if (i != g_auth.count - 1)
				g_auth.sessions[i] = g_auth.sessions[g_auth.count - 1];
			memset(&g_auth.sessions[g_auth.count - 1], 0, sizeof(g_auth.sessions[g_auth.count - 1]));
			g_auth.count--;
			return 1;
		}
	}

	return 0;
}

static void handle_auth_logout(struct mg_connection *c, struct mg_http_message *hm)
{
	char token[SESSION_TOKEN_LEN * 2 + 1];
	struct mg_str *cookie_hdr;

	if (!c || !hm) {
		json_printf(c, 400, "{\"error\":\"invalid request\"}");
		return;
	}

	token[0] = '\0';
	cookie_hdr = mg_http_get_header(hm, "Cookie");
	if (cookie_hdr)
		extract_session_cookie(cookie_hdr, token, sizeof(token));

	remove_session_by_token(token);

	{
		char cors[512];
		char hdrs[1024];
		snprintf(hdrs, sizeof(hdrs),
			 "Content-Type: application/json\r\n%s"
			 "Set-Cookie: rs_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax\r\n",
			 cors_origin_header(cors, sizeof(cors)));
		mg_http_reply(c, 200, hdrs, "{\"ok\":true}");
	}
}

static const char *cors_origin_header(char *buf, size_t buf_len)
{
	if (g_ctx.cfg.cors_origin[0] == '\0') {
		buf[0] = '\0';
		return buf;
	}
	snprintf(buf, buf_len,
		 "Access-Control-Allow-Origin: %s\r\n"
		 "Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\n"
		 "Access-Control-Allow-Headers: Content-Type, Authorization\r\n",
		 g_ctx.cfg.cors_origin);
	return buf;
}

static void json_printf(struct mg_connection *c, int status, const char *fmt, ...)
{
	char body[65536];
	char headers[1024];
	char cors[512];
	char cookie_token[SESSION_TOKEN_LEN * 2 + 1];
	va_list ap;
	int n;

	if (!c || !fmt)
		return;

	va_start(ap, fmt);
	n = vsnprintf(body, sizeof(body), fmt, ap);
	va_end(ap);

	if (n < 0)
		n = 0;
	if ((size_t) n >= sizeof(body))
		n = (int) sizeof(body) - 1;
	body[n] = '\0';

	snprintf(headers, sizeof(headers),
		 "Content-Type: application/json\r\n%s",
		 cors_origin_header(cors, sizeof(cors)));

	if (auth_take_pending_cookie(c->id, cookie_token, sizeof(cookie_token))) {
		size_t off = strlen(headers);
		snprintf(headers + off, sizeof(headers) - off,
			 "Set-Cookie: rs_session=%s; Path=/; HttpOnly; SameSite=Lax\r\n",
			 cookie_token);
	}

	mg_http_reply(c, status, headers, "%s", body);
}

static void handle_signal(int sig)
{
	(void) sig;
	g_running = 0;
}

static uint64_t monotonic_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;
	return (uint64_t) ts.tv_sec * 1000000000ULL + (uint64_t) ts.tv_nsec;
}

static uint64_t uptime_sec(void)
{
	uint64_t now = monotonic_ns();
	uint64_t start = (uint64_t) g_ctx.start_ts.tv_sec * 1000000000ULL +
			 (uint64_t) g_ctx.start_ts.tv_nsec;

	if (now <= start)
		return 0;
	return (now - start) / 1000000000ULL;
}

static int extract_id_from_uri(struct mg_http_message *hm, const char *prefix)
{
	const char *p;
	char tmp[32];
	size_t i = 0;
	size_t prefix_len;

	if (!hm || !prefix)
		return -1;

	prefix_len = strlen(prefix);
	if (hm->uri.len < prefix_len)
		return -1;
	if (strncmp(hm->uri.buf, prefix, prefix_len) != 0)
		return -1;

	p = hm->uri.buf + prefix_len;
	while ((size_t) (p - hm->uri.buf) < hm->uri.len && *p != '/' && i + 1 < sizeof(tmp)) {
		if (*p < '0' || *p > '9')
			return -1;
		tmp[i++] = *p++;
	}
	tmp[i] = '\0';

	if (i == 0)
		return -1;
	return atoi(tmp);
}

static struct mg_str extract_name_from_uri(struct mg_http_message *hm, const char *prefix)
{
	struct mg_str out = mg_str_n(NULL, 0);
	const char *p;
	size_t prefix_len;

	if (!hm || !prefix)
		return out;

	prefix_len = strlen(prefix);
	if (hm->uri.len < prefix_len)
		return out;
	if (strncmp(hm->uri.buf, prefix, prefix_len) != 0)
		return out;

	p = hm->uri.buf + prefix_len;
	out.buf = (char *) p;
	while ((size_t) (p - hm->uri.buf) < hm->uri.len && *p != '/')
		p++;
	out.len = (size_t) (p - out.buf);
	return out;
}

static void json_escape(const char *src, char *dst, size_t dst_len)
{
	size_t si = 0;
	size_t di = 0;

	if (!dst || dst_len == 0)
		return;
	dst[0] = '\0';
	if (!src)
		return;

	while (src[si] != '\0' && di + 2 < dst_len) {
		unsigned char ch = (unsigned char) src[si++];
		switch (ch) {
		case '\\':
		case '"':
			dst[di++] = '\\';
			dst[di++] = (char) ch;
			break;
		case '\n':
			dst[di++] = '\\';
			dst[di++] = 'n';
			break;
		case '\r':
			dst[di++] = '\\';
			dst[di++] = 'r';
			break;
		case '\t':
			dst[di++] = '\\';
			dst[di++] = 't';
			break;
		default:
			if (ch < 0x20)
				continue;
			dst[di++] = (char) ch;
			break;
		}
	}
	dst[di] = '\0';
}

static int tokenize_cmd_simple(const char *cmd, char *storage, size_t storage_len,
			       char *argv[], size_t argv_len)
{
	char *saveptr;
	char *tok;
	size_t argc = 0;
	size_t cmd_len;

	if (!cmd || !storage || storage_len == 0 || !argv || argv_len < 2)
		return -EINVAL;

	while (*cmd && isspace((unsigned char) *cmd))
		cmd++;
	if (*cmd == '\0')
		return -EINVAL;

	cmd_len = strlen(cmd);
	if (cmd_len + 1 > storage_len)
		return -ENAMETOOLONG;

	memcpy(storage, cmd, cmd_len + 1);
	tok = strtok_r(storage, " \t\r\n", &saveptr);
	while (tok) {
		if (argc + 1 >= argv_len)
			return -E2BIG;
		argv[argc++] = tok;
		tok = strtok_r(NULL, " \t\r\n", &saveptr);
	}
	if (argc == 0)
		return -EINVAL;
	argv[argc] = NULL;
	return 0;
}

static int safe_exec(const char *path, char *const argv[])
{
	char *ns_argv[96];
	char *const *exec_argv = argv;
	const char *exec_path = path;
	int status;
	pid_t pid;

	if (!path || !argv || !argv[0])
		return -EINVAL;

	if (g_ctx.cfg.use_namespace) {
		size_t i = 0;
		ns_argv[i++] = "nsenter";
		ns_argv[i++] = "--net=/proc/1/ns/net";
		ns_argv[i++] = "--";
		while (argv[i - 3] && i + 1 < (sizeof(ns_argv) / sizeof(ns_argv[0]))) {
			ns_argv[i] = argv[i - 3];
			i++;
		}
		if (argv[i - 3])
			return -E2BIG;
		ns_argv[i] = NULL;
		exec_path = "nsenter";
		exec_argv = ns_argv;
	}

	pid = fork();
	if (pid < 0)
		return -errno;

	if (pid == 0) {
		execvp(exec_path, exec_argv);
		_exit(127);
	}

	for (;;) {
		if (waitpid(pid, &status, 0) < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		break;
	}

	if (WIFEXITED(status))
		return WEXITSTATUS(status);
	if (WIFSIGNALED(status))
		return 128 + WTERMSIG(status);
	return -ECHILD;
}

static int safe_exec_output(const char *path, char *const argv[], char *buf, size_t buf_len)
{
	char *ns_argv[96];
	char *const *exec_argv = argv;
	const char *exec_path = path;
	int status;
	int pipefd[2];
	pid_t pid;
	size_t off = 0;

	if (!path || !argv || !argv[0] || !buf || buf_len == 0)
		return -EINVAL;

	if (g_ctx.cfg.use_namespace) {
		size_t i = 0;
		ns_argv[i++] = "nsenter";
		ns_argv[i++] = "--net=/proc/1/ns/net";
		ns_argv[i++] = "--";
		while (argv[i - 3] && i + 1 < (sizeof(ns_argv) / sizeof(ns_argv[0]))) {
			ns_argv[i] = argv[i - 3];
			i++;
		}
		if (argv[i - 3])
			return -E2BIG;
		ns_argv[i] = NULL;
		exec_path = "nsenter";
		exec_argv = ns_argv;
	}

	if (pipe(pipefd) != 0)
		return -errno;

	pid = fork();
	if (pid < 0) {
		int e = errno;
		close(pipefd[0]);
		close(pipefd[1]);
		return -e;
	}

	if (pid == 0) {
		close(pipefd[0]);
		if (dup2(pipefd[1], STDOUT_FILENO) < 0)
			_exit(127);
		close(pipefd[1]);
		execvp(exec_path, exec_argv);
		_exit(127);
	}

	close(pipefd[1]);
	buf[0] = '\0';
	while (off + 1 < buf_len) {
		ssize_t n = read(pipefd[0], buf + off, buf_len - off - 1);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			close(pipefd[0]);
			return -errno;
		}
		if (n == 0)
			break;
		off += (size_t) n;
	}
	buf[off] = '\0';
	close(pipefd[0]);

	for (;;) {
		if (waitpid(pid, &status, 0) < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		break;
	}

	if (WIFEXITED(status))
		return WEXITSTATUS(status);
	if (WIFSIGNALED(status))
		return 128 + WTERMSIG(status);
	return -ECHILD;
}

static int build_cmd(char *out, size_t out_len, const char *cmd)
{
	const char *start;
	size_t len;

	if (!out || out_len == 0 || !cmd)
		return -EINVAL;

	start = cmd;
	while (*start && isspace((unsigned char) *start))
		start++;
	if (*start == '\0')
		return -EINVAL;

	len = strlen(start);
	if (len + 1 > out_len)
		return -ENAMETOOLONG;

	memcpy(out, start, len + 1);
	return 0;
}

static int run_cmd_json(const char *cmd, char *buf, size_t buf_len)
{
	char actual[1024];
	char storage[1024];
	char *argv[64];
	int rc;

	if (!cmd || !buf || buf_len == 0)
		return -EINVAL;

	rc = build_cmd(actual, sizeof(actual), cmd);
	if (rc != 0)
		return rc;

	rc = tokenize_cmd_simple(actual, storage, sizeof(storage), argv, sizeof(argv) / sizeof(argv[0]));
	if (rc != 0)
		return rc;

	return safe_exec_output(argv[0], argv, buf, buf_len);
}

static int cmd_system(const char *cmd)
{
	char actual[1024];
	char storage[1024];
	char *argv[64];
	int rc;

	if (!cmd)
		return -EINVAL;

	rc = build_cmd(actual, sizeof(actual), cmd);
	if (rc != 0)
		return rc;

	rc = tokenize_cmd_simple(actual, storage, sizeof(storage), argv, sizeof(argv) / sizeof(argv[0]));
	if (rc != 0)
		return rc;

	return safe_exec(argv[0], argv);
}

void mgmtd_default_config(struct mgmtd_config *cfg)
{
	if (!cfg)
		return;

	memset(cfg, 0, sizeof(*cfg));
	cfg->port = MGMTD_DEFAULT_PORT;
	strncpy(cfg->web_root, MGMTD_DEFAULT_WEB_ROOT, sizeof(cfg->web_root) - 1);
	cfg->use_namespace = 0;
	strncpy(cfg->listen_addr, "http://0.0.0.0:8080", sizeof(cfg->listen_addr) - 1);
	cfg->ws_poll_ms = MGMTD_WS_POLL_MS;
	cfg->auth_enabled = 0;
	strncpy(cfg->auth_user, "admin", sizeof(cfg->auth_user) - 1);
	/* No default password — must be configured */
	strncpy(cfg->auth_password, "", sizeof(cfg->auth_password) - 1);
	if (generate_salt(cfg->auth_salt, sizeof(cfg->auth_salt)) != 0)
		strncpy(cfg->auth_salt, "00000000000000000000000000000000",
			sizeof(cfg->auth_salt) - 1);
	cfg->session_timeout = 3600;
	cfg->rate_limit_max_fails = 5;
	cfg->rate_limit_lockout_sec = 300;
	cfg->cors_origin[0] = '\0';
}

void api_system_register(void)
{
}

void api_ports_register(void)
{
}

void api_modules_register(void)
{
}

void api_config_register(void)
{
}

static void map_try_open(int *fd, const char *path)
{
	if (!fd || !path)
		return;
	if (*fd >= 0)
		return;

	*fd = bpf_obj_get(path);
	if (*fd < 0)
		RS_LOG_WARN("Map unavailable: %s (%s)", path, strerror(errno));
}

static int mgmtd_maps_init(void)
{
	if (g_maps.ncpus <= 0) {
		g_maps.ncpus = libbpf_num_possible_cpus();
		if (g_maps.ncpus <= 0)
			g_maps.ncpus = 1;
	}

	map_try_open(&g_maps.stats_fd, RS_STATS_MAP_PATH);
	map_try_open(&g_maps.module_stats_fd, RS_MODULE_STATS_MAP_PATH);
	map_try_open(&g_maps.port_config_fd, RS_PORT_CONFIG_MAP_PATH);
	map_try_open(&g_maps.vlan_fd, RS_VLAN_MAP_PATH);
	map_try_open(&g_maps.mac_table_fd, RS_MAC_TABLE_MAP_PATH);
	map_try_open(&g_maps.module_config_fd, RS_MODULE_CONFIG_MAP_PATH);
	map_try_open(&g_maps.voqd_state_fd, VOQD_STATE_MAP_PATH);
	map_try_open(&g_maps.qdepth_fd, QDEPTH_MAP_PATH);
	map_try_open(&g_maps.acl_5tuple_fd, ACL_5TUPLE_MAP_PATH);
	map_try_open(&g_maps.acl_pdp_fd, ACL_PDP_MAP_PATH);
	map_try_open(&g_maps.acl_psp_fd, ACL_PSP_MAP_PATH);
	map_try_open(&g_maps.acl_pp_fd, ACL_PP_MAP_PATH);
	map_try_open(&g_maps.acl_config_fd, ACL_CONFIG_MAP_PATH);
	map_try_open(&g_maps.acl_lpm_src_fd, ACL_LPM_SRC_MAP_PATH);
	map_try_open(&g_maps.acl_lpm_dst_fd, ACL_LPM_DST_MAP_PATH);
	map_try_open(&g_maps.route_tbl_fd, ROUTE_TBL_MAP_PATH);
	map_try_open(&g_maps.dhcp_snoop_config_fd, DHCP_SNOOP_CONFIG_MAP_PATH);
	map_try_open(&g_maps.dhcp_trusted_ports_fd, DHCP_TRUSTED_PORTS_MAP_PATH);

	g_maps.initialized = true;
	return 0;
}

static void mgmtd_maps_close(void)
{
	if (g_maps.stats_fd >= 0)
		close(g_maps.stats_fd);
	if (g_maps.module_stats_fd >= 0)
		close(g_maps.module_stats_fd);
	if (g_maps.port_config_fd >= 0)
		close(g_maps.port_config_fd);
	if (g_maps.vlan_fd >= 0)
		close(g_maps.vlan_fd);
	if (g_maps.mac_table_fd >= 0)
		close(g_maps.mac_table_fd);
	if (g_maps.module_config_fd >= 0)
		close(g_maps.module_config_fd);
	if (g_maps.voqd_state_fd >= 0)
		close(g_maps.voqd_state_fd);
	if (g_maps.qdepth_fd >= 0)
		close(g_maps.qdepth_fd);
	if (g_maps.acl_5tuple_fd >= 0)
		close(g_maps.acl_5tuple_fd);
	if (g_maps.acl_pdp_fd >= 0)
		close(g_maps.acl_pdp_fd);
	if (g_maps.acl_psp_fd >= 0)
		close(g_maps.acl_psp_fd);
	if (g_maps.acl_pp_fd >= 0)
		close(g_maps.acl_pp_fd);
	if (g_maps.acl_config_fd >= 0)
		close(g_maps.acl_config_fd);
	if (g_maps.acl_lpm_src_fd >= 0)
		close(g_maps.acl_lpm_src_fd);
	if (g_maps.acl_lpm_dst_fd >= 0)
		close(g_maps.acl_lpm_dst_fd);
	if (g_maps.route_tbl_fd >= 0)
		close(g_maps.route_tbl_fd);
	if (g_maps.dhcp_snoop_config_fd >= 0)
		close(g_maps.dhcp_snoop_config_fd);
	if (g_maps.dhcp_trusted_ports_fd >= 0)
		close(g_maps.dhcp_trusted_ports_fd);

	g_maps.stats_fd = -1;
	g_maps.module_stats_fd = -1;
	g_maps.port_config_fd = -1;
	g_maps.vlan_fd = -1;
	g_maps.mac_table_fd = -1;
	g_maps.module_config_fd = -1;
	g_maps.voqd_state_fd = -1;
	g_maps.qdepth_fd = -1;
	g_maps.acl_5tuple_fd = -1;
	g_maps.acl_pdp_fd = -1;
	g_maps.acl_psp_fd = -1;
	g_maps.acl_pp_fd = -1;
	g_maps.acl_config_fd = -1;
	g_maps.acl_lpm_src_fd = -1;
	g_maps.acl_lpm_dst_fd = -1;
	g_maps.route_tbl_fd = -1;
	g_maps.dhcp_snoop_config_fd = -1;
	g_maps.dhcp_trusted_ports_fd = -1;
	g_maps.initialized = false;
}

static int mgmtd_maps_ensure(void)
{
	return mgmtd_maps_init();
}

static int ifindex_exists(unsigned int ifidx)
{
	char name[IF_NAMESIZE] = "";
	if_indextoname(ifidx, name);
	if (name[0] == '\0')
		ifindex_to_name_sysfs(ifidx, name, sizeof(name));
	return name[0] != '\0';
}

static void cleanup_stale_port_configs(void)
{
	__u32 keys_to_delete[256];
	int delete_count = 0;
	__u32 key, next;

	if (g_maps.port_config_fd < 0)
		return;

	if (bpf_map_get_next_key(g_maps.port_config_fd, NULL, &next) != 0)
		return;

	do {
		key = next;
		struct rs_port_config p;
		if (bpf_map_lookup_elem(g_maps.port_config_fd, &key, &p) == 0) {
			if (!ifindex_exists(p.ifindex) && delete_count < 256)
				keys_to_delete[delete_count++] = key;
		}
	} while (bpf_map_get_next_key(g_maps.port_config_fd, &key, &next) == 0);

	for (int i = 0; i < delete_count; i++) {
		if (bpf_map_delete_elem(g_maps.port_config_fd, &keys_to_delete[i]) == 0)
			RS_LOG_INFO("Cleaned up stale port_config entry: ifindex=%u", keys_to_delete[i]);
	}

	if (g_maps.vlan_fd < 0)
		return;

	__u16 vlan_key, vlan_next;
	if (bpf_map_get_next_key(g_maps.vlan_fd, NULL, &vlan_next) != 0)
		return;

	do {
		vlan_key = vlan_next;
		struct rs_vlan_members vm;
		if (bpf_map_lookup_elem(g_maps.vlan_fd, &vlan_key, &vm) != 0)
			continue;
		int modified = 0;
		for (int arr_idx = 0; arr_idx < 4; arr_idx++) {
			for (int bit_pos = 0; bit_pos < 64; bit_pos++) {
				__u64 mask = 1ULL << bit_pos;
				if ((vm.tagged_members[arr_idx] & mask) || (vm.untagged_members[arr_idx] & mask)) {
					unsigned int ifidx = (unsigned int)(arr_idx * 64 + bit_pos + 1);
					if (ifidx == 0)
						continue;
					if (!ifindex_exists(ifidx)) {
						vm.tagged_members[arr_idx] &= ~mask;
						vm.untagged_members[arr_idx] &= ~mask;
						modified = 1;
						RS_LOG_INFO("Removing stale ifindex %u from VLAN %u", ifidx, vlan_key);
					}
				}
			}
		}
		if (modified) {
			vm.member_count = 0;
			for (int a = 0; a < 4; a++) {
				vm.member_count += (unsigned int)__builtin_popcountll(vm.tagged_members[a]);
				vm.member_count += (unsigned int)__builtin_popcountll(vm.untagged_members[a]);
			}
			bpf_map_update_elem(g_maps.vlan_fd, &vlan_key, &vm, BPF_ANY);
		}
	} while (bpf_map_get_next_key(g_maps.vlan_fd, &vlan_key, &vlan_next) == 0);
}

static int aggregate_port_stats(__u32 ifindex, struct rs_stats *sum)
{
	struct rs_stats *cpu_vals;
	int i;

	if (!sum)
		return -EINVAL;
	if (g_maps.stats_fd < 0)
		return -ENOENT;

	cpu_vals = calloc((size_t) g_maps.ncpus, sizeof(*cpu_vals));
	if (!cpu_vals)
		return -ENOMEM;

	if (bpf_map_lookup_elem(g_maps.stats_fd, &ifindex, cpu_vals) != 0) {
		free(cpu_vals);
		return -errno;
	}

	memset(sum, 0, sizeof(*sum));
	for (i = 0; i < g_maps.ncpus; i++) {
		sum->rx_packets += cpu_vals[i].rx_packets;
		sum->rx_bytes += cpu_vals[i].rx_bytes;
		sum->tx_packets += cpu_vals[i].tx_packets;
		sum->tx_bytes += cpu_vals[i].tx_bytes;
		sum->rx_drops += cpu_vals[i].rx_drops;
		sum->tx_drops += cpu_vals[i].tx_drops;
		sum->rx_errors += cpu_vals[i].rx_errors;
		sum->tx_errors += cpu_vals[i].tx_errors;
	}

	free(cpu_vals);
	return 0;
}

static int aggregate_module_stats(__u32 module_id, struct rs_module_stats *sum)
{
	struct rs_module_stats *cpu_vals;
	int i;

	if (!sum)
		return -EINVAL;
	if (g_maps.module_stats_fd < 0)
		return -ENOENT;

	cpu_vals = calloc((size_t) g_maps.ncpus, sizeof(*cpu_vals));
	if (!cpu_vals)
		return -ENOMEM;

	if (bpf_map_lookup_elem(g_maps.module_stats_fd, &module_id, cpu_vals) != 0) {
		free(cpu_vals);
		return -errno;
	}

	memset(sum, 0, sizeof(*sum));
	for (i = 0; i < g_maps.ncpus; i++) {
		sum->packets_processed += cpu_vals[i].packets_processed;
		sum->packets_forwarded += cpu_vals[i].packets_forwarded;
		sum->packets_dropped += cpu_vals[i].packets_dropped;
		sum->packets_error += cpu_vals[i].packets_error;
		sum->bytes_processed += cpu_vals[i].bytes_processed;
		if (cpu_vals[i].last_seen_ns > sum->last_seen_ns)
			sum->last_seen_ns = cpu_vals[i].last_seen_ns;
		if (sum->name[0] == '\0' && cpu_vals[i].name[0] != '\0')
			strncpy(sum->name, cpu_vals[i].name, sizeof(sum->name) - 1);
		if (cpu_vals[i].module_id != 0)
			sum->module_id = cpu_vals[i].module_id;
	}

	free(cpu_vals);
	return 0;
}

static int count_port_entries(void)
{
	__u32 key;
	__u32 next;
	int count = 0;

	if (g_maps.port_config_fd < 0)
		return RS_MAX_INTERFACES;

	if (bpf_map_get_next_key(g_maps.port_config_fd, NULL, &next) != 0)
		return 0;

	while (1) {
		count++;
		key = next;
		if (bpf_map_get_next_key(g_maps.port_config_fd, &key, &next) != 0)
			break;
	}

	return count;
}

static int count_module_entries(void)
{
	int count = 0;
	__u32 key;

	if (g_maps.module_stats_fd < 0)
		return 0;

	for (key = 0; key < MODULE_MAX_ENTRIES; key++) {
		struct rs_module_stats st;

		if (aggregate_module_stats(key, &st) != 0)
			continue;
		if (st.name[0] == '\0' && st.packets_processed == 0 && st.bytes_processed == 0)
			continue;
		count++;
	}

	return count;
}

int mgmtd_ws_client_count(struct mg_mgr *mgr)
{
	struct mg_connection *c;
	int count = 0;

	if (!mgr)
		return 0;

	for (c = mgr->conns; c != NULL; c = c->next) {
		if (c->is_websocket && c->data[0] == 'W')
			count++;
	}

	return count;
}

void mgmtd_ws_broadcast(struct mg_mgr *mgr, const char *json, size_t len)
{
	struct mg_connection *c;

	if (!mgr || !json)
		return;

	for (c = mgr->conns; c != NULL; c = c->next) {
		if (c->is_websocket && c->data[0] == 'W')
			mg_ws_send(c, json, len, WEBSOCKET_OP_TEXT);
	}
}

static const char *audit_sev_to_str(int severity)
{
	switch (severity) {
	case AUDIT_SEV_WARNING:  return "warn";
	case AUDIT_SEV_CRITICAL: return "error";
	default:                 return "info";
	}
}

static void mgmtd_broadcast_event(int severity, const char *category,
				   const char *action, const char *detail)
{
	char payload[1024];
	struct timespec ts;

	if (!g_mgr)
		return;

	clock_gettime(CLOCK_REALTIME, &ts);

	{
		char msg[512];
		const char *sev_str = audit_sev_to_str(severity);
		const char *cat_str = category ? category : "system";

		snprintf(msg, sizeof(msg), "[%s] %s: %s",
			 cat_str,
			 action ? action : "unknown",
			 detail ? detail : "");

		event_db_insert(sev_str, cat_str, msg,
				(int64_t)ts.tv_sec);

		snprintf(payload, sizeof(payload),
			 "{\"type\":\"event\",\"severity\":\"%s\","
			 "\"category\":\"%s\","
			 "\"message\":\"%s\",\"timestamp\":%llu}",
			 sev_str, cat_str, msg,
			 (unsigned long long)ts.tv_sec);
	}

	mgmtd_ws_broadcast(g_mgr, payload, strlen(payload));
}

static void mgmtd_audit_log(int severity, const char *category,
			     const char *action, int success,
			     const char *detail_fmt, ...)
	__attribute__((format(printf, 5, 6)));

static void mgmtd_audit_log(int severity, const char *category,
			     const char *action, int success,
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

	rs_audit_log_result(severity, category, action, success, "%s", detail);
	mgmtd_broadcast_event(severity, category, action, detail);
}

static const char *bpf_event_category(uint32_t event_type)
{
	switch (event_type & 0xFF00) {
	case RS_EVENT_L2_BASE:    return "bpf";
	case RS_EVENT_ACL_BASE:   return "bpf";
	case RS_EVENT_MIRROR_BASE: return "bpf";
	case RS_EVENT_ERROR_BASE: return "bpf";
	default:                  return "bpf";
	}
}

static const char *bpf_event_action(uint32_t event_type)
{
	switch (event_type) {
	case 0x0101: return "mac_learned";
	case 0x0102: return "mac_moved";
	case 0x0103: return "mac_aged";
	case 0x0201: return "acl_hit";
	case 0x0202: return "acl_deny";
	case RS_EVENT_DHCP_SNOOP: return "dhcp_snoop";
	case 0xFF01: return "parse_error";
	case 0xFF02: return "map_full";
	default:     return "bpf_event";
	}
}

static int event_bus_callback(void *ctx, void *data, size_t size)
{
	uint32_t event_type;
	char detail[256];

	(void) ctx;

	if (size < sizeof(uint32_t))
		return 0;

	event_type = *(uint32_t *)data;

	if (event_type >= RS_EVENT_L2_BASE && event_type <= 0x0103 && size >= 20) {
		uint8_t *mac = (uint8_t *)data + 8;
		uint16_t vlan = 0;
		uint32_t ifidx = 0;

		if (size >= 18)
			memcpy(&vlan, (uint8_t *)data + 14, sizeof(vlan));
		if (size >= 22)
			memcpy(&ifidx, (uint8_t *)data + 16, sizeof(ifidx));

		snprintf(detail, sizeof(detail),
			 "MAC %02x:%02x:%02x:%02x:%02x:%02x VLAN=%u ifindex=%u",
			 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
			 vlan, ifidx);
	} else if (event_type == RS_EVENT_DHCP_SNOOP && size >= 24) {
		uint32_t ifidx = 0;
		uint8_t msg_type = 0, action = 0;
		uint32_t yiaddr = 0;
		uint8_t chaddr[6] = {0};
		char portname[IF_NAMESIZE];

		memcpy(&ifidx, (uint8_t *)data + 4, sizeof(ifidx));
		msg_type = *((uint8_t *)data + 8);
		action = *((uint8_t *)data + 9);
		memcpy(&yiaddr, (uint8_t *)data + 12, sizeof(yiaddr));
		memcpy(chaddr, (uint8_t *)data + 16, sizeof(chaddr));

		snprintf(portname, sizeof(portname), "port%u", ifidx);
		ifindex_to_name_sysfs(ifidx, portname, sizeof(portname));

		const char *msg_str = "unknown";
		if (msg_type == 1) msg_str = "DISCOVER";
		else if (msg_type == 2) msg_str = "OFFER";
		else if (msg_type == 3) msg_str = "REQUEST";
		else if (msg_type == 5) msg_str = "ACK";

		const char *act_str = "observed";
		if (action == DHCP_SNOOP_ACTION_ROGUE_DROP) act_str = "ROGUE_DROP";
		else if (action == DHCP_SNOOP_ACTION_BINDING_CREATE) act_str = "BINDING_CREATE";

		uint8_t *ip = (uint8_t *)&yiaddr;
		snprintf(detail, sizeof(detail),
			 "DHCP %s on %s [%s] IP=%u.%u.%u.%u MAC=%02x:%02x:%02x:%02x:%02x:%02x",
			 msg_str, portname, act_str,
			 ip[0], ip[1], ip[2], ip[3],
			 chaddr[0], chaddr[1], chaddr[2],
			 chaddr[3], chaddr[4], chaddr[5]);

		int sev = AUDIT_SEV_INFO;
		if (action == DHCP_SNOOP_ACTION_ROGUE_DROP)
			sev = AUDIT_SEV_CRITICAL;

		mgmtd_broadcast_event(sev, "dhcp", act_str, detail);
		return 0;
	} else if (event_type >= RS_EVENT_ACL_BASE && event_type <= 0x0202) {
		snprintf(detail, sizeof(detail), "event_type=0x%04x size=%zu",
			 event_type, size);
	} else if (event_type >= RS_EVENT_ERROR_BASE) {
		snprintf(detail, sizeof(detail), "error event 0x%04x size=%zu",
			 event_type, size);
	} else {
		snprintf(detail, sizeof(detail), "type=0x%04x size=%zu",
			 event_type, size);
	}

	mgmtd_broadcast_event(
		event_type >= RS_EVENT_ERROR_BASE ? AUDIT_SEV_CRITICAL : AUDIT_SEV_INFO,
		bpf_event_category(event_type),
		bpf_event_action(event_type),
		detail);

	return 0;
}

static void *event_bus_thread(void *arg)
{
	(void) arg;

	while (g_event_thread_running && g_event_rb)
		ring_buffer__poll(g_event_rb, 200);

	return NULL;
}

static void event_bus_init(void)
{
	g_event_bus_fd = bpf_obj_get(RS_EVENT_BUS_PATH);
	if (g_event_bus_fd < 0) {
		RS_LOG_WARN("Event bus not available: %s", strerror(errno));
		return;
	}

	g_event_rb = ring_buffer__new(g_event_bus_fd, event_bus_callback, NULL, NULL);
	if (!g_event_rb) {
		RS_LOG_WARN("Failed to create ringbuf consumer");
		close(g_event_bus_fd);
		g_event_bus_fd = -1;
		return;
	}

	g_event_thread_running = 1;
	if (pthread_create(&g_event_thread, NULL, event_bus_thread, NULL) != 0) {
		RS_LOG_WARN("Failed to start event bus thread");
		ring_buffer__free(g_event_rb);
		g_event_rb = NULL;
		close(g_event_bus_fd);
		g_event_bus_fd = -1;
		return;
	}

	RS_LOG_INFO("BPF event bus consumer started");
}

static void event_bus_cleanup(void)
{
	if (g_event_thread_running) {
		g_event_thread_running = 0;
		pthread_join(g_event_thread, NULL);
	}
	if (g_event_rb)
		ring_buffer__free(g_event_rb);
	if (g_event_bus_fd >= 0)
		close(g_event_bus_fd);
	g_event_rb = NULL;
	g_event_bus_fd = -1;
}

static void handle_system_info(struct mg_connection *c, struct mg_http_message *hm, void *userdata)
{
	char hostname[128] = { 0 };
	char mgmt_ip[64] = "unknown";
	char kernel[128] = "unknown";
	char profile[256] = "unknown";
	struct mgmtd_ctx *ctx = userdata;
	struct utsname un;
	unsigned long mem_total_kb = 0, mem_avail_kb = 0;
	int cpu_percent = 0;
	FILE *fp;

	(void) hm;
	if (!ctx)
		ctx = &g_ctx;

	if (gethostname(hostname, sizeof(hostname)) != 0)
		strncpy(hostname, "unknown", sizeof(hostname) - 1);

	if (rs_mgmt_iface_get_ip(&ctx->mgmt_cfg, mgmt_ip, sizeof(mgmt_ip)) != 0)
		strncpy(mgmt_ip, "unassigned", sizeof(mgmt_ip) - 1);

	if (uname(&un) == 0)
		snprintf(kernel, sizeof(kernel), "%s %s", un.sysname, un.release);

	fp = fopen("/proc/meminfo", "r");
	if (fp) {
		char line[256];
		while (fgets(line, sizeof(line), fp)) {
			if (strncmp(line, "MemTotal:", 9) == 0)
				sscanf(line + 9, " %lu", &mem_total_kb);
			else if (strncmp(line, "MemAvailable:", 13) == 0)
				sscanf(line + 13, " %lu", &mem_avail_kb);
		}
		fclose(fp);
	}

	fp = fopen("/proc/stat", "r");
	if (fp) {
		char line[512];
		if (fgets(line, sizeof(line), fp)) {
			unsigned long long user, nice, sys, idle, iowait, irq, softirq;
			if (sscanf(line, "cpu %llu %llu %llu %llu %llu %llu %llu",
				   &user, &nice, &sys, &idle, &iowait, &irq, &softirq) >= 4) {
				unsigned long long total = user + nice + sys + idle + iowait + irq + softirq;
				if (total > 0)
					cpu_percent = (int) (100 - (idle * 100 / total));
			}
		}
		fclose(fp);
	}

	if (g_ctx.profile_name[0] != '\0')
		strncpy(profile, g_ctx.profile_name, sizeof(profile) - 1);
	else {
		fp = fopen("/var/lib/rswitch/active_profile", "r");
		if (fp) {
			if (fgets(profile, sizeof(profile), fp))
				profile[strcspn(profile, "\r\n")] = '\0';
			fclose(fp);
		} else {
			char rp[PATH_MAX];
			ssize_t n = readlink("/var/lib/rswitch/active_profile", rp, sizeof(rp) - 1);
			if (n > 0) {
				rp[n] = '\0';
				strncpy(profile, rp, sizeof(profile) - 1);
			}
		}
	}

	json_printf(c, 200,
		    "{\"hostname\":\"%s\",\"version\":\"1.0.0\","
		    "\"abi\":{\"major\":%u,\"minor\":%u},"
		    "\"uptime\":%llu,\"port_count\":%d,\"management_ip\":\"%s\","
		    "\"kernel\":\"%s\",\"cpu_percent\":%d,"
		    "\"memory\":{\"used_mb\":%lu,\"total_mb\":%lu},"
		    "\"profile\":\"%s\"}",
		    hostname, RS_ABI_VERSION_MAJOR, RS_ABI_VERSION_MINOR,
		    (unsigned long long) uptime_sec(),
		    count_port_entries(), mgmt_ip, kernel, cpu_percent,
		    (mem_total_kb - mem_avail_kb) / 1024, mem_total_kb / 1024,
		    profile);
}

static void handle_system_health(struct mg_connection *c, struct mg_http_message *hm, void *userdata)
{
	struct rs_health_status st;
	char out[8192];

	(void) hm;
	(void) userdata;

	if (rs_watchdog_check_health(&st) != 0) {
		json_printf(c, 500, "{\"error\":\"health check failed\"}");
		return;
	}

	if (rs_watchdog_export_json(&st, out, sizeof(out)) != 0) {
		json_printf(c, 500, "{\"error\":\"health json export failed\"}");
		return;
	}

	json_printf(c, 200, "%s", out);
}

static void handle_system_reboot(struct mg_connection *c, struct mg_http_message *hm, void *userdata)
{
	(void) hm;
	(void) userdata;

	mgmtd_audit_log(AUDIT_SEV_WARNING, AUDIT_CAT_SYSTEM, "reboot", 1,
			    "reboot requested via mgmtd API");
	json_printf(c, 200, "{\"status\":\"rebooting\"}");
	c->is_draining = 1;
	sync();
	safe_exec("/sbin/reboot", (char *const[]) {"reboot", NULL});
}

static void handle_system_shutdown(struct mg_connection *c, struct mg_http_message *hm, void *userdata)
{
	(void) hm;
	(void) userdata;

	mgmtd_audit_log(AUDIT_SEV_WARNING, AUDIT_CAT_SYSTEM, "shutdown", 1,
			    "shutdown requested via mgmtd API");
	json_printf(c, 200, "{\"status\":\"shutting_down\"}");
	c->is_draining = 1;
	sync();
	safe_exec("/sbin/shutdown", (char *const[]) {"/sbin/shutdown", "-h", "now", NULL});
}

static void handle_network_get(struct mg_connection *c, struct mg_http_message *hm, void *userdata)
{
	struct mgmtd_ctx *ctx = userdata;
	char current_ip[64] = "";
	char gw_buf[128] = "";
	char route_buf[1024];
	char *argv[10];
	char *via;
	char *end;

	(void) hm;
	if (!ctx) ctx = &g_ctx;

	rs_mgmt_iface_get_ip(&ctx->mgmt_cfg, current_ip, sizeof(current_ip));

	argv[0] = "ip";
	argv[1] = "netns";
	argv[2] = "exec";
	argv[3] = ctx->mgmt_cfg.mgmt_ns;
	argv[4] = "ip";
	argv[5] = "-4";
	argv[6] = "route";
	argv[7] = "show";
	argv[8] = "default";
	argv[9] = NULL;
	if (safe_exec_output("ip", argv, route_buf, sizeof(route_buf)) == 0) {
		via = strstr(route_buf, "via ");
		if (via) {
			via += 4;
			end = via;
			while (*end && !isspace((unsigned char) *end))
				end++;
			if (end > via) {
				size_t n = (size_t) (end - via);
				if (n >= sizeof(gw_buf))
					n = sizeof(gw_buf) - 1;
				memcpy(gw_buf, via, n);
				gw_buf[n] = '\0';
			}
		}
	}

	json_printf(c, 200,
		    "{\"mode\":\"%s\",\"current_ip\":\"%s\","
		    "\"static_ip\":\"%s\",\"gateway\":\"%s\","
		    "\"current_gateway\":\"%s\",\"mgmt_vlan\":%d,"
		    "\"interface\":\"%s\",\"namespace\":\"%s\"}",
		    ctx->mgmt_cfg.mode == 1 ? "static" : "dhcp",
		    current_ip, ctx->mgmt_cfg.static_ip,
		    ctx->mgmt_cfg.gateway, gw_buf,
		    ctx->mgmt_cfg.mgmt_vlan,
		    ctx->mgmt_cfg.veth_ns, ctx->mgmt_cfg.mgmt_ns);
}

static void handle_network_put(struct mg_connection *c, struct mg_http_message *hm, void *userdata)
{
	struct mgmtd_ctx *ctx = userdata;
	char *mode_str, *ip_str, *gw_str;

	if (!ctx) ctx = &g_ctx;

	mode_str = mg_json_get_str(hm->body, "$.mode");
	ip_str = mg_json_get_str(hm->body, "$.static_ip");
	gw_str = mg_json_get_str(hm->body, "$.gateway");

	if (!mode_str) {
		json_printf(c, 400, "{\"error\":\"mode required (dhcp or static)\"}");
		return;
	}

	if (strcmp(mode_str, "static") == 0) {
		if (!ip_str || ip_str[0] == '\0') {
			json_printf(c, 400, "{\"error\":\"static_ip required for static mode\"}");
			free(mode_str);
			if (ip_str) free(ip_str);
			if (gw_str) free(gw_str);
			return;
		}
		ctx->mgmt_cfg.mode = 1;
		memset(ctx->mgmt_cfg.static_ip, 0, sizeof(ctx->mgmt_cfg.static_ip));
		strncpy(ctx->mgmt_cfg.static_ip, ip_str, sizeof(ctx->mgmt_cfg.static_ip) - 1);
		memset(ctx->mgmt_cfg.gateway, 0, sizeof(ctx->mgmt_cfg.gateway));
		if (gw_str)
			strncpy(ctx->mgmt_cfg.gateway, gw_str, sizeof(ctx->mgmt_cfg.gateway) - 1);
	} else if (strcmp(mode_str, "dhcp") == 0) {
		ctx->mgmt_cfg.mode = 0;
		memset(ctx->mgmt_cfg.static_ip, 0, sizeof(ctx->mgmt_cfg.static_ip));
		memset(ctx->mgmt_cfg.gateway, 0, sizeof(ctx->mgmt_cfg.gateway));
	} else {
		json_printf(c, 400, "{\"error\":\"mode must be dhcp or static\"}");
		free(mode_str);
		if (ip_str) free(ip_str);
		if (gw_str) free(gw_str);
		return;
	}

	free(mode_str);
	if (ip_str) free(ip_str);
	if (gw_str) free(gw_str);

	if (rs_mgmt_iface_reconfigure(&ctx->mgmt_cfg) != 0) {
		json_printf(c, 500, "{\"error\":\"failed to reconfigure network\"}");
		mgmtd_audit_log(AUDIT_SEV_WARNING, AUDIT_CAT_SYSTEM, "network_reconfig", 0,
				    "management network reconfigure failed");
		return;
	}

	mgmtd_audit_log(AUDIT_SEV_INFO, AUDIT_CAT_SYSTEM, "network_reconfig", 1,
			    ctx->mgmt_cfg.mode == 1 ? "switched to static IP" : "switched to DHCP");

	json_printf(c, 200, "{\"status\":\"ok\",\"mode\":\"%s\"}",
		    ctx->mgmt_cfg.mode == 1 ? "static" : "dhcp");
}

static int ifindex_to_name_sysfs(__u32 ifindex, char *out, size_t out_sz)
{
	DIR *d;
	struct dirent *de;

	if (if_indextoname(ifindex, out))
		return 0;

	d = opendir("/sys/class/net");
	if (!d)
		return -1;
	while ((de = readdir(d)) != NULL) {
		char path[256];
		FILE *fp;
		unsigned int idx;

		if (de->d_name[0] == '.')
			continue;
		snprintf(path, sizeof(path), "/sys/class/net/%s/ifindex", de->d_name);
		fp = fopen(path, "r");
		if (!fp)
			continue;
		if (fscanf(fp, "%u", &idx) == 1 && idx == ifindex) {
			fclose(fp);
			closedir(d);
			strncpy(out, de->d_name, out_sz - 1);
			out[out_sz - 1] = '\0';
			return 0;
		}
		fclose(fp);
	}
	closedir(d);
	return -1;
}

static void handle_ports_list(struct mg_connection *c, struct mg_http_message *hm, void *userdata)
{
	__u32 key, next;
	char *out = malloc(65536);
	size_t out_sz = 65536;
	size_t off = 0;
	int first = 1;
	int port_id = 0;

	(void) hm;
	(void) userdata;

	if (!out) {
		mg_http_reply(c, 500, "Content-Type: application/json\r\n", "{\"error\":\"out of memory\"}\n");
		return;
	}

	if (mgmtd_maps_ensure() != 0 || g_maps.port_config_fd < 0) {
		json_printf(c, 503, "{\"ports\":[]}");
		free(out);
		return;
	}

	off += (size_t) snprintf(out + off, out_sz - off, "{\"ports\":[");
	if (bpf_map_get_next_key(g_maps.port_config_fd, NULL, &next) == 0) {
		while (1) {
			struct rs_port_config p;
			if (bpf_map_lookup_elem(g_maps.port_config_fd, &next, &p) == 0) {
				char name[IF_NAMESIZE] = "";
				char oper[32] = "unknown";
				int speed_val = 0;
				int link_up = 0;
				struct rs_stats st;
				__u64 rx_pkt = 0, tx_pkt = 0;

				if_indextoname(p.ifindex, name);
				if (name[0] == '\0')
					ifindex_to_name_sysfs(p.ifindex, name, sizeof(name));
				if (name[0] == '\0')
					goto next_port;

				{
					char path[128];
					FILE *fp;
					snprintf(path, sizeof(path), "/sys/class/net/%s/operstate", name);
					fp = fopen(path, "r");
					if (fp) {
						if (fgets(oper, sizeof(oper), fp))
							oper[strcspn(oper, "\r\n")] = '\0';
						fclose(fp);
					}
					link_up = (strcmp(oper, "up") == 0) ? 1 : 0;
				}

				{
					char path[128];
					FILE *fp;
					snprintf(path, sizeof(path), "/sys/class/net/%s/speed", name);
					fp = fopen(path, "r");
					if (fp) {
						if (fscanf(fp, "%d", &speed_val) != 1)
							speed_val = 0;
						fclose(fp);
					}
					if (speed_val < 0)
						speed_val = 0;
				}

				if (aggregate_port_stats(p.ifindex, &st) == 0) {
					rx_pkt = st.rx_packets;
					tx_pkt = st.tx_packets;
				}

				off += (size_t) snprintf(out + off, out_sz - off,
						 "%s{\"port_id\":%d,\"ifindex\":%u,\"name\":\"%s\"," 
						 "\"enabled\":%u,\"admin_state\":\"%s\"," 
						 "\"link_up\":%s,\"speed\":%d," 
						 "\"vlan_mode\":%u,\"pvid\":%u," 
						 "\"rx_packets\":%llu,\"tx_packets\":%llu}",
						 first ? "" : ",",
						 port_id, p.ifindex, name,
						 p.enabled, p.enabled ? "up" : "down",
						 link_up ? "true" : "false", speed_val,
						 p.vlan_mode, p.pvid,
						 (unsigned long long) rx_pkt, (unsigned long long) tx_pkt);
				first = 0;
				port_id++;
			}

next_port:
			key = next;
			if (bpf_map_get_next_key(g_maps.port_config_fd, &key, &next) != 0)
				break;
			if (off + 512 >= out_sz)
				break;
		}
	}

	snprintf(out + off, out_sz - off, "]}");
	json_printf(c, 200, "%s", out);
	free(out);
}

static void handle_port_stats(struct mg_connection *c, struct mg_http_message *hm, void *userdata)
{
	int port_id;
	struct rs_stats s;
	__u32 key, next, ifindex = 0;
	int idx = 0;

	(void) userdata;

	port_id = extract_id_from_uri(hm, "/api/ports/");
	if (port_id < 0) {
		json_printf(c, 400, "{\"error\":\"invalid port_id\"}");
		return;
	}

	if (mgmtd_maps_ensure() != 0 || g_maps.port_config_fd < 0) {
		json_printf(c, 503, "{\"error\":\"maps unavailable\"}");
		return;
	}

	if (bpf_map_get_next_key(g_maps.port_config_fd, NULL, &next) == 0) {
		do {
			struct rs_port_config p;
			if (bpf_map_lookup_elem(g_maps.port_config_fd, &next, &p) == 0) {
				if (idx == port_id) {
					ifindex = p.ifindex;
					break;
				}
				idx++;
			}
			key = next;
		} while (bpf_map_get_next_key(g_maps.port_config_fd, &key, &next) == 0);
	}

	if (ifindex == 0) {
		json_printf(c, 404, "{\"error\":\"port not found\"}");
		return;
	}

	if (aggregate_port_stats(ifindex, &s) != 0)
		memset(&s, 0, sizeof(s));

	json_printf(c, 200,
		    "{\"ifindex\":%u,\"rx_packets\":%llu,\"tx_packets\":%llu,"
		    "\"rx_bytes\":%llu,\"tx_bytes\":%llu,\"rx_drops\":%llu,"
		    "\"tx_drops\":%llu,\"rx_errors\":%llu,\"tx_errors\":%llu}",
		    ifindex,
		    (unsigned long long) s.rx_packets,
		    (unsigned long long) s.tx_packets,
		    (unsigned long long) s.rx_bytes,
		    (unsigned long long) s.tx_bytes,
		    (unsigned long long) s.rx_drops,
		    (unsigned long long) s.tx_drops,
		    (unsigned long long) s.rx_errors,
		    (unsigned long long) s.tx_errors);
}

static __u32 port_id_to_ifindex(int port_id)
{
	__u32 key, next;
	int idx = 0;

	if (g_maps.port_config_fd < 0)
		return 0;
	if (bpf_map_get_next_key(g_maps.port_config_fd, NULL, &next) != 0)
		return 0;
	do {
		struct rs_port_config p;
		if (bpf_map_lookup_elem(g_maps.port_config_fd, &next, &p) == 0) {
			if (idx == port_id)
				return p.ifindex;
			idx++;
		}
		key = next;
	} while (bpf_map_get_next_key(g_maps.port_config_fd, &key, &next) == 0);
	return 0;
}

static void handle_port_config_update(struct mg_connection *c, struct mg_http_message *hm, void *userdata)
{
	int port_id;
	__u32 ifindex;
	struct rs_port_config cfg;
	long enabled, vlan_mode, pvid;
	char *admin_state;
	long speed_val;
	long mtu_val;

	(void) userdata;

	port_id = extract_id_from_uri(hm, "/api/ports/");
	if (port_id < 0) {
		json_printf(c, 400, "{\"error\":\"invalid port_id\"}");
		return;
	}

	if (mgmtd_maps_ensure() != 0 || g_maps.port_config_fd < 0) {
		json_printf(c, 503, "{\"error\":\"port config map unavailable\"}");
		return;
	}

	ifindex = port_id_to_ifindex(port_id);
	if (ifindex == 0) {
		json_printf(c, 404, "{\"error\":\"port not found\"}");
		return;
	}

	memset(&cfg, 0, sizeof(cfg));
	cfg.ifindex = ifindex;
	bpf_map_lookup_elem(g_maps.port_config_fd, &cfg.ifindex, &cfg);

	enabled = mg_json_get_long(hm->body, "$.enabled", cfg.enabled);
	vlan_mode = mg_json_get_long(hm->body, "$.vlan_mode", cfg.vlan_mode);
	pvid = mg_json_get_long(hm->body, "$.pvid", cfg.pvid);

	cfg.enabled = (__u8) enabled;
	cfg.vlan_mode = (__u8) vlan_mode;
	cfg.pvid = (__u16) pvid;

	admin_state = mg_json_get_str(hm->body, "$.admin_state");
	if (admin_state) {
		char name[IF_NAMESIZE] = { 0 };
		if (!if_indextoname(ifindex, name))
			ifindex_to_name_sysfs(ifindex, name, sizeof(name));
		if (name[0]) {
			char cmd[256];
			snprintf(cmd, sizeof(cmd), "ip link set %s %s", name, admin_state);
			cmd_system(cmd);
			cfg.enabled = (strcmp(admin_state, "up") == 0) ? 1 : 0;
		}
		free(admin_state);
	}

	speed_val = mg_json_get_long(hm->body, "$.speed", 0);
	if (speed_val > 0) {
		char name[IF_NAMESIZE] = { 0 };
		if (!if_indextoname(ifindex, name))
			ifindex_to_name_sysfs(ifindex, name, sizeof(name));
		if (name[0]) {
			char cmd[256];
			snprintf(cmd, sizeof(cmd), "ethtool -s %s speed %ld", name, speed_val);
			cmd_system(cmd);
		}
	}

	mtu_val = mg_json_get_long(hm->body, "$.mtu", 0);
	if (mtu_val > 0) {
		char name[IF_NAMESIZE] = { 0 };
		if (!if_indextoname(ifindex, name))
			ifindex_to_name_sysfs(ifindex, name, sizeof(name));
		if (name[0]) {
			char cmd[256];
			snprintf(cmd, sizeof(cmd), "ip link set %s mtu %ld", name, mtu_val);
			cmd_system(cmd);
		}
	}

	if (bpf_map_update_elem(g_maps.port_config_fd, &cfg.ifindex, &cfg, BPF_ANY) != 0) {
		json_printf(c, 500, "{\"error\":\"failed to update port config\"}");
		return;
	}

	mgmtd_audit_log(AUDIT_SEV_INFO, AUDIT_CAT_CONFIG, "port_config_update", 1,
			    "ifindex=%u enabled=%u vlan_mode=%u pvid=%u",
			    ifindex, cfg.enabled, cfg.vlan_mode, cfg.pvid);
	json_printf(c, 200, "{\"status\":\"ok\"}");
}

static void handle_modules_list(struct mg_connection *c, struct mg_http_message *hm, void *userdata)
{
	char *out = malloc(65536);
	size_t out_sz = 65536;
	size_t off = 0;
	int first = 1;
	int i;

	(void) hm;
	(void) userdata;

	if (!out) {
		mg_http_reply(c, 500, "Content-Type: application/json\r\n", "{\"error\":\"out of memory\"}\n");
		return;
	}

	mgmtd_maps_ensure();

	off += (size_t) snprintf(out + off, out_sz - off, "{\"modules\":[");

	for (i = 0; i < g_ctx.profile_module_count; i++) {
		struct rs_module_stats st;
		__u64 pkts = 0, drops = 0, fwd = 0, bytes = 0;
		int found_stats = 0;
		__u32 k;

		if (g_maps.module_stats_fd >= 0) {
			for (k = 0; k < MODULE_MAX_ENTRIES; k++) {
				if (aggregate_module_stats(k, &st) != 0)
					continue;
				if (st.name[0] != '\0' &&
				    strcmp(st.name, g_ctx.profile_modules[i].name) == 0) {
					pkts = st.packets_processed;
					fwd = st.packets_forwarded;
					drops = st.packets_dropped;
					bytes = st.bytes_processed;
					found_stats = 1;
					break;
				}
			}
		}

		off += (size_t) snprintf(out + off, out_sz - off,
					 "%s{\"name\":\"%s\",\"module_id\":%d,"
					 "\"type\":\"%s\",\"state\":\"loaded\",\"loaded\":true,"
					 "\"packets\":%llu,\"drops\":%llu,"
					 "\"packets_processed\":%llu,\"packets_forwarded\":%llu,"
					 "\"packets_dropped\":%llu,\"bytes_processed\":%llu}",
					 first ? "" : ",",
					 g_ctx.profile_modules[i].name,
					 i,
					 g_ctx.profile_modules[i].type,
					 (unsigned long long) pkts,
					 (unsigned long long) drops,
					 (unsigned long long) pkts,
					 (unsigned long long) fwd,
					 (unsigned long long) drops,
					 (unsigned long long) bytes);
		first = 0;
		if (off + 512 >= out_sz)
			break;
	}

	snprintf(out + off, out_sz - off, "]}");
	json_printf(c, 200, "%s", out);
	free(out);
}

static int resolve_module_by_name(struct mg_http_message *hm, const char *prefix,
					  struct rs_module_stats *out)
{
	struct mg_str name_str = extract_name_from_uri(hm, prefix);
	char name_buf[64];
	__u32 k;
	int numeric_id;
	int i;

	if (name_str.len == 0)
		return -1;

	numeric_id = extract_id_from_uri(hm, prefix);
	if (numeric_id >= 0 && numeric_id < MODULE_MAX_ENTRIES) {
		if (aggregate_module_stats((__u32) numeric_id, out) == 0 && out->name[0] != '\0')
			return 0;
	}

	if (name_str.len >= sizeof(name_buf))
		return -1;
	memcpy(name_buf, name_str.buf, name_str.len);
	name_buf[name_str.len] = '\0';

	/* Strip trailing /stats or /reload or /config from name */
	{
		char *slash = strchr(name_buf, '/');
		if (slash)
			*slash = '\0';
	}

	for (k = 0; k < MODULE_MAX_ENTRIES; k++) {
		struct rs_module_stats st;
		if (aggregate_module_stats(k, &st) != 0)
			continue;
		if (st.name[0] != '\0' && strcmp(st.name, name_buf) == 0) {
			*out = st;
			return 0;
		}
	}

	/* Fallback: match by profile module name and return stats by module_id */
	for (i = 0; i < g_ctx.profile_module_count; i++) {
		if (strcmp(g_ctx.profile_modules[i].name, name_buf) == 0) {
			memset(out, 0, sizeof(*out));
			aggregate_module_stats((__u32) i, out);
			out->module_id = (__u32) i;
			strncpy(out->name, name_buf, sizeof(out->name) - 1);
			return 0;
		}
	}
	return -1;
}

static void handle_module_stats(struct mg_connection *c, struct mg_http_message *hm, void *userdata)
{
	struct rs_module_stats st;

	(void) userdata;

	if (mgmtd_maps_ensure() != 0) {
		json_printf(c, 503, "{\"error\":\"maps unavailable\"}");
		return;
	}

	if (resolve_module_by_name(hm, "/api/modules/", &st) != 0) {
		json_printf(c, 404, "{\"error\":\"module not found\"}");
		return;
	}

	json_printf(c, 200,
		    "{\"name\":\"%s\",\"module_id\":%u,"
		    "\"packets\":%llu,\"bytes\":%llu,\"drops\":%llu,\"errors\":%llu,"
		    "\"packets_processed\":%llu,\"packets_forwarded\":%llu,"
		    "\"packets_dropped\":%llu,\"packets_error\":%llu,"
		    "\"bytes_processed\":%llu,\"last_seen_ns\":%llu}",
		    st.name, st.module_id,
		    (unsigned long long) st.packets_processed,
		    (unsigned long long) st.bytes_processed,
		    (unsigned long long) st.packets_dropped,
		    (unsigned long long) st.packets_error,
		    (unsigned long long) st.packets_processed,
		    (unsigned long long) st.packets_forwarded,
		    (unsigned long long) st.packets_dropped,
		    (unsigned long long) st.packets_error,
		    (unsigned long long) st.bytes_processed,
		    (unsigned long long) st.last_seen_ns);
}

static void handle_module_reload(struct mg_connection *c, struct mg_http_message *hm, void *userdata)
{
	struct rs_module_stats st;

	(void) userdata;

	if (mgmtd_maps_ensure() != 0) {
		json_printf(c, 503, "{\"error\":\"maps unavailable\"}");
		return;
	}

	if (resolve_module_by_name(hm, "/api/modules/", &st) != 0) {
		json_printf(c, 404, "{\"error\":\"module not found\"}");
		return;
	}

	mgmtd_audit_log(AUDIT_SEV_INFO, AUDIT_CAT_MODULE, "module_reload", 1,
			    "module=%s id=%u", st.name, st.module_id);
	json_printf(c, 200, "{\"status\":\"ok\",\"module\":\"%s\"}", st.name);
}

static void handle_module_config_update(struct mg_connection *c, struct mg_http_message *hm, void *userdata)
{
	struct rs_module_config_key key;
	struct rs_module_config_value val;
	char *module_name;
	char *param_name;
	char *str_val;
	long int_val;

	(void) userdata;

	if (mgmtd_maps_ensure() != 0 || g_maps.module_config_fd < 0) {
		json_printf(c, 503, "{\"error\":\"module config map unavailable\"}");
		return;
	}

	module_name = mg_json_get_str(hm->body, "$.module_name");
	param_name = mg_json_get_str(hm->body, "$.param_name");
	str_val = mg_json_get_str(hm->body, "$.value");
	int_val = mg_json_get_long(hm->body, "$.value", 0);

	if (!module_name || !param_name) {
		free(module_name);
		free(param_name);
		free(str_val);
		json_printf(c, 400, "{\"error\":\"module_name and param_name required\"}");
		return;
	}

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));
	strncpy(key.module_name, module_name, sizeof(key.module_name) - 1);
	strncpy(key.param_name, param_name, sizeof(key.param_name) - 1);

	if (str_val) {
		val.type = 2;
		strncpy(val.str_val, str_val, sizeof(val.str_val) - 1);
	} else {
		val.type = 0;
		val.int_val = int_val;
	}

	if (bpf_map_update_elem(g_maps.module_config_fd, &key, &val, BPF_ANY) != 0) {
		free(module_name);
		free(param_name);
		free(str_val);
		json_printf(c, 500, "{\"error\":\"failed to update module config\"}");
		return;
	}

	mgmtd_audit_log(AUDIT_SEV_INFO, AUDIT_CAT_CONFIG, "module_config_update", 1,
			    "module=%s param=%s", key.module_name, key.param_name);

	free(module_name);
	free(param_name);
	free(str_val);
	json_printf(c, 200, "{\"status\":\"ok\"}");
}

static void handle_vlans_list(struct mg_connection *c, struct mg_http_message *hm, void *userdata)
{
	__u16 key, next;
	char *out = malloc(65536);
	size_t out_sz = 65536;
	size_t off = 0;
	int first = 1;

	(void) hm;
	(void) userdata;

	if (!out) {
		mg_http_reply(c, 500, "Content-Type: application/json\r\n", "{\"error\":\"out of memory\"}\n");
		return;
	}

	if (mgmtd_maps_ensure() != 0 || g_maps.vlan_fd < 0) {
		json_printf(c, 503, "{\"vlans\":[]}");
		free(out);
		return;
	}

	off += (size_t) snprintf(out + off, out_sz - off, "{\"vlans\":[");
	if (bpf_map_get_next_key(g_maps.vlan_fd, NULL, &next) == 0) {
		while (1) {
			struct rs_vlan_members v;
			if (bpf_map_lookup_elem(g_maps.vlan_fd, &next, &v) == 0) {
				int i, j;
				off += (size_t) snprintf(out + off, out_sz - off,
						 "%s{\"id\":%u,\"vlan_id\":%u,\"name\":\"VLAN %u\"," 
						 "\"member_count\":%u,\"tagged_ports\":[",
						 first ? "" : ",", v.vlan_id, v.vlan_id, v.vlan_id,
						 v.member_count);

				{
					int tp_first = 1;
					for (i = 0; i < 4; i++) {
						for (j = 0; j < 64; j++) {
							if (v.tagged_members[i] & (1ULL << j)) {
								int ifidx = i * 64 + j + 1;
								if (ifidx == 0) continue;
							off += (size_t) snprintf(out + off, out_sz - off,
									 "%s%d", tp_first ? "" : ",", ifidx);
								tp_first = 0;
							}
						}
					}
				}

				off += (size_t) snprintf(out + off, out_sz - off,
						 "],\"untagged_ports\":[");

				{
					int up_first = 1;
					for (i = 0; i < 4; i++) {
						for (j = 0; j < 64; j++) {
							if (v.untagged_members[i] & (1ULL << j)) {
								int ifidx = i * 64 + j + 1;
								if (ifidx == 0) continue;
							off += (size_t) snprintf(out + off, out_sz - off,
									 "%s%d", up_first ? "" : ",", ifidx);
								up_first = 0;
							}
						}
					}
				}

				/* Add port_names object: maps ifindex -> interface name */
				off += (size_t) snprintf(out + off, out_sz - off,
						 "],\"port_names\":{");
				{
					int pn_first = 1;
					for (i = 0; i < 4; i++) {
						for (j = 0; j < 64; j++) {
							__u64 mask = 1ULL << j;
							if ((v.tagged_members[i] & mask) || (v.untagged_members[i] & mask)) {
								int ifidx = i * 64 + j + 1;
								if (ifidx == 0) continue;
								char name[IF_NAMESIZE] = "";
								if_indextoname((unsigned int)ifidx, name);
								if (name[0] == '\0')
									ifindex_to_name_sysfs(ifidx, name, sizeof(name));
								if (name[0] != '\0') {
									off += (size_t) snprintf(out + off, out_sz - off,
											 "%s\"%d\":\"%s\"",
											 pn_first ? "" : ",", ifidx, name);
									pn_first = 0;
								}
							}
						}
					}
				}

				off += (size_t) snprintf(out + off, out_sz - off, "}}");
				first = 0;
			}

			key = next;
			if (bpf_map_get_next_key(g_maps.vlan_fd, &key, &next) != 0)
				break;
			if (off + 512 >= out_sz)
				break;
		}
	}

	snprintf(out + off, out_sz - off, "]}");
	json_printf(c, 200, "%s", out);
	free(out);
}

/*
 * sync_port_vlan_config() — Auto-derive per-port VLAN config from rs_vlan_map.
 *
 * Scans all VLAN entries and for each port that appears in any VLAN,
 * determines the correct vlan_mode, pvid, allowed_vlans, tagged_vlans,
 * untagged_vlans and writes the updated config to rs_port_config_map.
 *
 * Rules:
 *   - Port appears ONLY in untagged VLANs → ACCESS mode, access_vlan = lowest untagged VLAN
 *   - Port appears ONLY in tagged VLANs  → TRUNK mode, allowed_vlans = tagged list, native_vlan = 1
 *   - Port appears in both              → HYBRID mode, both lists populated, pvid = lowest untagged
 *   - Port appears in NO VLANs          → leave config unchanged (preserves loader defaults)
 *
 * Non-VLAN fields (enabled, learning, QoS, security) are always preserved.
 */
#define SYNC_MAX_PORTS 256

struct port_vlan_info {
	__u16 tagged_vlans[128];
	int   tagged_count;
	__u16 untagged_vlans[64];
	int   untagged_count;
};

static void sync_port_vlan_config(void)
{
	struct port_vlan_info *pinfo;
	__u16 vlan_key, vlan_next;
	struct rs_vlan_members vm;
	int i, j, port_idx;

	if (g_maps.vlan_fd < 0 || g_maps.port_config_fd < 0)
		return;

	pinfo = calloc(SYNC_MAX_PORTS, sizeof(*pinfo));
	if (!pinfo)
		return;

	/* Pass 1: scan all VLANs, accumulate per-port tagged/untagged lists */
	if (bpf_map_get_next_key(g_maps.vlan_fd, NULL, &vlan_next) != 0)
		goto apply;  /* No VLANs at all — still need to reset ports */

	do {
		vlan_key = vlan_next;
		if (bpf_map_lookup_elem(g_maps.vlan_fd, &vlan_key, &vm) != 0)
			continue;

		for (i = 0; i < 4; i++) {
			for (j = 0; j < 64; j++) {
				port_idx = i * 64 + j + 1;  /* +1: bitmap uses (ifindex-1) convention */
				if (port_idx <= 0 || port_idx >= SYNC_MAX_PORTS)
					continue;

				if (vm.tagged_members[i] & (1ULL << j)) {
					struct port_vlan_info *pi = &pinfo[port_idx];
					if (pi->tagged_count < 128)
						pi->tagged_vlans[pi->tagged_count++] = vlan_key;
				}
				if (vm.untagged_members[i] & (1ULL << j)) {
					struct port_vlan_info *pi = &pinfo[port_idx];
					if (pi->untagged_count < 64)
						pi->untagged_vlans[pi->untagged_count++] = vlan_key;
				}
			}
		}
	} while (bpf_map_get_next_key(g_maps.vlan_fd, &vlan_key, &vlan_next) == 0);

apply:
	/* Pass 2: collect all port keys first, then update (avoids map mutation during iteration) */
	{
		__u32 port_keys[SYNC_MAX_PORTS];
		int port_count = 0;
		__u32 port_key, port_next;

		if (bpf_map_get_next_key(g_maps.port_config_fd, NULL, &port_next) == 0) {
			do {
				port_key = port_next;
				if (port_key > 0 && port_key < SYNC_MAX_PORTS && port_count < SYNC_MAX_PORTS)
					port_keys[port_count++] = port_key;
			} while (bpf_map_get_next_key(g_maps.port_config_fd, &port_key, &port_next) == 0);
		}

		for (int p = 0; p < port_count; p++) {
			port_key = port_keys[p];
			struct rs_port_config cfg;

			if (bpf_map_lookup_elem(g_maps.port_config_fd, &port_key, &cfg) != 0)
				continue;

			if (cfg.vlan_mode == 4 /* RS_VLAN_MODE_QINQ */)
				continue;

			struct port_vlan_info *pi = &pinfo[port_key];
			int has_tagged = pi->tagged_count > 0;
			int has_untagged = pi->untagged_count > 0;

			if (!has_tagged && !has_untagged)
				continue;

			memset(cfg.allowed_vlans, 0, sizeof(cfg.allowed_vlans));
			cfg.allowed_vlan_count = 0;
			memset(cfg.tagged_vlans, 0, sizeof(cfg.tagged_vlans));
			cfg.tagged_vlan_count = 0;
			memset(cfg.untagged_vlans, 0, sizeof(cfg.untagged_vlans));
			cfg.untagged_vlan_count = 0;

			if (has_tagged && !has_untagged) {
				cfg.vlan_mode = 2; /* RS_VLAN_MODE_TRUNK */
				cfg.native_vlan = 1;
				for (i = 0; i < pi->tagged_count && i < 128; i++)
					cfg.allowed_vlans[i] = pi->tagged_vlans[i];
				cfg.allowed_vlan_count = (__u16) pi->tagged_count;
			} else if (!has_tagged && has_untagged) {
				cfg.vlan_mode = 1; /* RS_VLAN_MODE_ACCESS */
				cfg.access_vlan = pi->untagged_vlans[0];
				cfg.pvid = pi->untagged_vlans[0];
			} else {
				cfg.vlan_mode = 3; /* RS_VLAN_MODE_HYBRID */
				cfg.pvid = pi->untagged_vlans[0];
				for (i = 0; i < pi->tagged_count && i < 64; i++)
					cfg.tagged_vlans[i] = pi->tagged_vlans[i];
				cfg.tagged_vlan_count = (__u16) (pi->tagged_count > 64 ? 64 : pi->tagged_count);
				for (i = 0; i < pi->untagged_count && i < 64; i++)
					cfg.untagged_vlans[i] = pi->untagged_vlans[i];
				cfg.untagged_vlan_count = (__u16) (pi->untagged_count > 64 ? 64 : pi->untagged_count);
				int ac = 0;
				for (i = 0; i < pi->tagged_count && ac < 128; i++)
					cfg.allowed_vlans[ac++] = pi->tagged_vlans[i];
				for (i = 0; i < pi->untagged_count && ac < 128; i++)
					cfg.allowed_vlans[ac++] = pi->untagged_vlans[i];
				cfg.allowed_vlan_count = (__u16) ac;
			}

			bpf_map_update_elem(g_maps.port_config_fd, &port_key, &cfg, BPF_ANY);

			RS_LOG_INFO("sync_port_vlan: ifindex=%u mode=%s pvid=%u tagged=%d untagged=%d",
				    port_key,
				    cfg.vlan_mode == 1 ? "ACCESS" :
				    cfg.vlan_mode == 2 ? "TRUNK" :
				    cfg.vlan_mode == 3 ? "HYBRID" : "OFF",
				    cfg.pvid, pi->tagged_count, pi->untagged_count);
		}
	}

	free(pinfo);
}

static void handle_vlan_create(struct mg_connection *c, struct mg_http_message *hm, void *userdata)
{
	struct rs_vlan_members v;
	long vlan_id;
	__u16 key;
	int i, port, member_count = 0;
	char path[32];

	(void) userdata;

	if (mgmtd_maps_ensure() != 0 || g_maps.vlan_fd < 0) {
		json_printf(c, 503, "{\"error\":\"vlan map unavailable\"}");
		return;
	}

	vlan_id = mg_json_get_long(hm->body, "$.vlan_id", -1);
	if (vlan_id < 0)
		vlan_id = mg_json_get_long(hm->body, "$.id", -1);
	if (vlan_id <= 0 || vlan_id > 4095) {
		json_printf(c, 400, "{\"error\":\"invalid vlan_id\"}");
		return;
	}

	memset(&v, 0, sizeof(v));
	v.vlan_id = (__u16) vlan_id;

	for (i = 0; i < 256; i++) {
		snprintf(path, sizeof(path), "$.tagged_ports[%d]", i);
		port = (int) mg_json_get_long(hm->body, path, -1);
		if (port < 0)
			break;
		if (port > 0 && port <= 256) {
			int word = port / 64;  /* H-8: match BPF ifindex/64 indexing */
			int bit = port % 64;
			v.tagged_members[word] |= (1ULL << bit);
			member_count++;
		}
	}

	for (i = 0; i < 256; i++) {
		snprintf(path, sizeof(path), "$.untagged_ports[%d]", i);
		port = (int) mg_json_get_long(hm->body, path, -1);
		if (port < 0)
			break;
		if (port > 0 && port <= 256) {
			int word = port / 64;  /* H-8: match BPF ifindex/64 indexing */
			int bit = port % 64;
			v.untagged_members[word] |= (1ULL << bit);
			member_count++;
		}
	}

	v.member_count = (__u16) member_count;
	if (v.member_count == 0)
		v.member_count = (__u16) mg_json_get_long(hm->body, "$.member_count", 0);
	key = (__u16) vlan_id;

	if (bpf_map_update_elem(g_maps.vlan_fd, &key, &v, BPF_ANY) != 0) {
		json_printf(c, 500, "{\"error\":\"failed to create vlan\"}");
		return;
	}

	mgmtd_audit_log(AUDIT_SEV_INFO, AUDIT_CAT_CONFIG, "vlan_create", 1,
			    "vlan_id=%ld members=%d", vlan_id, member_count);
	sync_port_vlan_config();
	json_printf(c, 201, "{\"status\":\"created\",\"vlan_id\":%ld}", vlan_id);
}

static void handle_vlan_update(struct mg_connection *c, struct mg_http_message *hm, void *userdata)
{
	int vlan_id;
	struct rs_vlan_members v;
	__u16 key;
	int i, port, member_count = 0;
	char path[32];

	(void) userdata;

	vlan_id = extract_id_from_uri(hm, "/api/vlans/");
	if (vlan_id <= 0 || vlan_id > 4095) {
		json_printf(c, 400, "{\"error\":\"invalid vlan id\"}");
		return;
	}

	if (mgmtd_maps_ensure() != 0 || g_maps.vlan_fd < 0) {
		json_printf(c, 503, "{\"error\":\"vlan map unavailable\"}");
		return;
	}

	key = (__u16) vlan_id;
	if (bpf_map_lookup_elem(g_maps.vlan_fd, &key, &v) != 0) {
		json_printf(c, 404, "{\"error\":\"vlan not found\"}");
		return;
	}

	/* Rebuild port bitmasks from JSON arrays (same logic as create) */
	memset(v.tagged_members, 0, sizeof(v.tagged_members));
	memset(v.untagged_members, 0, sizeof(v.untagged_members));

	for (i = 0; i < 256; i++) {
		snprintf(path, sizeof(path), "$.tagged_ports[%d]", i);
		port = (int) mg_json_get_long(hm->body, path, -1);
		if (port < 0)
			break;
		if (port > 0 && port <= 256) {
			int word = port / 64;  /* H-8: match BPF ifindex/64 indexing */
			int bit = port % 64;
			v.tagged_members[word] |= (1ULL << bit);
			member_count++;
		}
	}

	for (i = 0; i < 256; i++) {
		snprintf(path, sizeof(path), "$.untagged_ports[%d]", i);
		port = (int) mg_json_get_long(hm->body, path, -1);
		if (port < 0)
			break;
		if (port > 0 && port <= 256) {
			int word = port / 64;  /* H-8: match BPF ifindex/64 indexing */
			int bit = port % 64;
			v.untagged_members[word] |= (1ULL << bit);
			member_count++;
		}
	}

	v.vlan_id = key;
	v.member_count = (__u16) member_count;

	if (bpf_map_update_elem(g_maps.vlan_fd, &key, &v, BPF_ANY) != 0) {
		json_printf(c, 500, "{\"error\":\"failed to update vlan\"}");
		return;
	}

	mgmtd_audit_log(AUDIT_SEV_INFO, AUDIT_CAT_CONFIG, "vlan_update", 1,
			    "vlan_id=%d member_count=%d", vlan_id, member_count);
	sync_port_vlan_config();
	json_printf(c, 200, "{\"status\":\"ok\"}");
}

static void handle_vlan_delete(struct mg_connection *c, struct mg_http_message *hm, void *userdata)
{
	int vlan_id;
	__u16 key;

	(void) userdata;

	vlan_id = extract_id_from_uri(hm, "/api/vlans/");
	if (vlan_id <= 0 || vlan_id > 4095) {
		json_printf(c, 400, "{\"error\":\"invalid vlan id\"}");
		return;
	}

	if (mgmtd_maps_ensure() != 0 || g_maps.vlan_fd < 0) {
		json_printf(c, 503, "{\"error\":\"vlan map unavailable\"}");
		return;
	}

	key = (__u16) vlan_id;
	if (bpf_map_delete_elem(g_maps.vlan_fd, &key) != 0) {
		json_printf(c, 404, "{\"error\":\"vlan not found\"}");
		return;
	}

	mgmtd_audit_log(AUDIT_SEV_INFO, AUDIT_CAT_CONFIG, "vlan_delete", 1,
			    "vlan_id=%d", vlan_id);
	sync_port_vlan_config();
	json_printf(c, 200, "{\"status\":\"deleted\"}");
}

static void handle_acls_list(struct mg_connection *c, struct mg_http_message *hm, void *userdata)
{
	char *out = malloc(65536);
	size_t out_sz = 65536;
	size_t off = 0;
	int first = 1;

	(void) hm;
	(void) userdata;

	if (!out) {
		mg_http_reply(c, 500, "Content-Type: application/json\r\n", "{\"error\":\"out of memory\"}\n");
		return;
	}

	if (mgmtd_maps_ensure() != 0) {
		json_printf(c, 200, "{\"acls\":[]}");
		free(out);
		return;
	}

	off += (size_t) snprintf(out + off, out_sz - off, "{\"acls\":[");

	if (g_maps.acl_5tuple_fd >= 0) {
		struct acl_5tuple_key k, nk;
		struct acl_result res;
		int has_prev = 0;

		memset(&k, 0, sizeof(k));
		while (bpf_map_get_next_key(g_maps.acl_5tuple_fd, has_prev ? &k : NULL, &nk) == 0) {
			if (bpf_map_lookup_elem(g_maps.acl_5tuple_fd, &nk, &res) == 0) {
				char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
				struct in_addr sa, da;
				sa.s_addr = nk.src_ip;
				da.s_addr = nk.dst_ip;
				inet_ntop(AF_INET, &sa, src, sizeof(src));
				inet_ntop(AF_INET, &da, dst, sizeof(dst));

				if (res.rule_id == 0) {
					res.rule_id = acl_next_rule_id();
					bpf_map_update_elem(g_maps.acl_5tuple_fd, &nk, &res, BPF_ANY);
				}
				off += (size_t) snprintf(out + off, out_sz - off,
						 "%s{\"id\":%d,\"type\":\"5tuple\","
						 "\"priority\":%u,\"action\":\"%s\","
						 "\"protocol\":%u,\"src_ip\":\"%s\",\"src_port\":%u,"
						 "\"dst_ip\":\"%s\",\"dst_port\":%u,\"hits\":0}",
						 first ? "" : ",",
						 res.rule_id, res.priority,
						 res.action == 0 ? "permit" : (res.action == 1 ? "deny" : "redirect"),
						 nk.proto, src, ntohs(nk.sport),
						 dst, ntohs(nk.dport));
				first = 0;
			}
			k = nk;
			has_prev = 1;
			if (off + 512 >= out_sz)
				break;
		}
	}

	if (g_maps.acl_pdp_fd >= 0) {
		struct acl_proto_dstip_port_key k, nk;
		struct acl_result res;
		int has_prev = 0;

		memset(&k, 0, sizeof(k));
		while (bpf_map_get_next_key(g_maps.acl_pdp_fd, has_prev ? &k : NULL, &nk) == 0) {
			if (bpf_map_lookup_elem(g_maps.acl_pdp_fd, &nk, &res) == 0) {
				char dst[INET_ADDRSTRLEN];
				struct in_addr da;
				da.s_addr = nk.dst_ip;
				inet_ntop(AF_INET, &da, dst, sizeof(dst));

				if (res.rule_id == 0) {
					res.rule_id = acl_next_rule_id();
					bpf_map_update_elem(g_maps.acl_pdp_fd, &nk, &res, BPF_ANY);
				}
				off += (size_t) snprintf(out + off, out_sz - off,
						 "%s{\"id\":%d,\"type\":\"proto_dst\","
						 "\"priority\":%u,\"action\":\"%s\","
						 "\"protocol\":%u,\"src_ip\":\"any\",\"src_port\":0,"
						 "\"dst_ip\":\"%s\",\"dst_port\":%u,\"hits\":0}",
						 first ? "" : ",",
						 res.rule_id, res.priority,
						 res.action == 0 ? "permit" : (res.action == 1 ? "deny" : "redirect"),
						 nk.proto, dst, ntohs(nk.dst_port));
				first = 0;
			}
			k = nk;
			has_prev = 1;
			if (off + 512 >= out_sz)
				break;
		}
	}

	if (g_maps.acl_psp_fd >= 0) {
		struct acl_proto_srcip_port_key k, nk;
		struct acl_result res;
		int has_prev = 0;

		memset(&k, 0, sizeof(k));
		while (bpf_map_get_next_key(g_maps.acl_psp_fd, has_prev ? &k : NULL, &nk) == 0) {
			if (bpf_map_lookup_elem(g_maps.acl_psp_fd, &nk, &res) == 0) {
				char src[INET_ADDRSTRLEN];
				struct in_addr sa;
				sa.s_addr = nk.src_ip;
				inet_ntop(AF_INET, &sa, src, sizeof(src));

				if (res.rule_id == 0) {
					res.rule_id = acl_next_rule_id();
					bpf_map_update_elem(g_maps.acl_psp_fd, &nk, &res, BPF_ANY);
				}
				off += (size_t) snprintf(out + off, out_sz - off,
						 "%s{\"id\":%d,\"type\":\"proto_src\","
						 "\"priority\":%u,\"action\":\"%s\","
						 "\"protocol\":%u,\"src_ip\":\"%s\",\"src_port\":0,"
						 "\"dst_ip\":\"any\",\"dst_port\":%u,\"hits\":0}",
						 first ? "" : ",",
						 res.rule_id, res.priority,
						 res.action == 0 ? "permit" : (res.action == 1 ? "deny" : "redirect"),
						 nk.proto, src, ntohs(nk.dst_port));
				first = 0;
			}
			k = nk;
			has_prev = 1;
			if (off + 512 >= out_sz)
				break;
		}
	}

	if (g_maps.acl_pp_fd >= 0) {
		struct acl_proto_port_key k, nk;
		struct acl_result res;
		int has_prev = 0;

		memset(&k, 0, sizeof(k));
		while (bpf_map_get_next_key(g_maps.acl_pp_fd, has_prev ? &k : NULL, &nk) == 0) {
			if (bpf_map_lookup_elem(g_maps.acl_pp_fd, &nk, &res) == 0) {
				if (res.rule_id == 0) {
					res.rule_id = acl_next_rule_id();
					bpf_map_update_elem(g_maps.acl_pp_fd, &nk, &res, BPF_ANY);
				}
				off += (size_t) snprintf(out + off, out_sz - off,
						 "%s{\"id\":%d,\"type\":\"proto_port\","
						 "\"priority\":%u,\"action\":\"%s\","
						 "\"protocol\":%u,\"src_ip\":\"any\",\"src_port\":0,"
						 "\"dst_ip\":\"any\",\"dst_port\":%u,\"hits\":0}",
						 first ? "" : ",",
						 res.rule_id, res.priority,
						 res.action == 0 ? "permit" : (res.action == 1 ? "deny" : "redirect"),
						 nk.proto, ntohs(nk.dst_port));
				first = 0;
			}
			k = nk;
			has_prev = 1;
			if (off + 512 >= out_sz)
				break;
		}
	}

	if (g_maps.acl_lpm_src_fd >= 0) {
		struct lpm_key k, nk;
		struct acl_lpm_value val;
		int has_prev = 0;

		memset(&k, 0, sizeof(k));
		while (bpf_map_get_next_key(g_maps.acl_lpm_src_fd, has_prev ? &k : NULL, &nk) == 0) {
			if (bpf_map_lookup_elem(g_maps.acl_lpm_src_fd, &nk, &val) == 0) {
				char src[INET_ADDRSTRLEN + 4];
				char dst[INET_ADDRSTRLEN + 4];
				struct in_addr sa, da;
				sa.s_addr = nk.addr;
				inet_ntop(AF_INET, &sa, src, INET_ADDRSTRLEN);
				if (nk.prefixlen < 32) {
					char tmp[INET_ADDRSTRLEN + 4];
					snprintf(tmp, sizeof(tmp), "%s/%u", src, nk.prefixlen);
					strcpy(src, tmp);
				}
				if (val.other_ip != 0) {
					da.s_addr = val.other_ip;
					inet_ntop(AF_INET, &da, dst, INET_ADDRSTRLEN);
				} else {
					strcpy(dst, "any");
				}

				if (val.rule_id == 0) {
					val.rule_id = acl_next_rule_id();
					bpf_map_update_elem(g_maps.acl_lpm_src_fd, &nk, &val, BPF_ANY);
				}
				off += (size_t) snprintf(out + off, out_sz - off,
						 "%s{\"id\":%d,\"type\":\"lpm_src\","
						 "\"priority\":%u,\"action\":\"%s\","
						 "\"protocol\":%u,\"src_ip\":\"%s\",\"src_port\":%u,"
						 "\"dst_ip\":\"%s\",\"dst_port\":%u,\"hits\":0}",
						 first ? "" : ",",
						 val.rule_id, val.priority,
						 val.action == 0 ? "permit" : (val.action == 1 ? "deny" : "redirect"),
						 val.proto, src, ntohs(val.sport),
						 dst, ntohs(val.dport));
				first = 0;
			}
			k = nk;
			has_prev = 1;
			if (off + 512 >= out_sz)
				break;
		}
	}

	if (g_maps.acl_lpm_dst_fd >= 0) {
		struct lpm_key k, nk;
		struct acl_lpm_value val;
		int has_prev = 0;

		memset(&k, 0, sizeof(k));
		while (bpf_map_get_next_key(g_maps.acl_lpm_dst_fd, has_prev ? &k : NULL, &nk) == 0) {
			if (bpf_map_lookup_elem(g_maps.acl_lpm_dst_fd, &nk, &val) == 0) {
				char src[INET_ADDRSTRLEN + 4];
				char dst[INET_ADDRSTRLEN + 4];
				struct in_addr sa, da;
				da.s_addr = nk.addr;
				inet_ntop(AF_INET, &da, dst, INET_ADDRSTRLEN);
				if (nk.prefixlen < 32) {
					char tmp[INET_ADDRSTRLEN + 4];
					snprintf(tmp, sizeof(tmp), "%s/%u", dst, nk.prefixlen);
					strcpy(dst, tmp);
				}
				if (val.other_ip != 0) {
					sa.s_addr = val.other_ip;
					inet_ntop(AF_INET, &sa, src, INET_ADDRSTRLEN);
				} else {
					strcpy(src, "any");
				}

				if (val.rule_id == 0) {
					val.rule_id = acl_next_rule_id();
					bpf_map_update_elem(g_maps.acl_lpm_dst_fd, &nk, &val, BPF_ANY);
				}
				off += (size_t) snprintf(out + off, out_sz - off,
						 "%s{\"id\":%d,\"type\":\"lpm_dst\","
						 "\"priority\":%u,\"action\":\"%s\","
						 "\"protocol\":%u,\"src_ip\":\"%s\",\"src_port\":%u,"
						 "\"dst_ip\":\"%s\",\"dst_port\":%u,\"hits\":0}",
						 first ? "" : ",",
						 val.rule_id, val.priority,
						 val.action == 0 ? "permit" : (val.action == 1 ? "deny" : "redirect"),
						 val.proto, src, ntohs(val.sport),
						 dst, ntohs(val.dport));
				first = 0;
			}
			k = nk;
			has_prev = 1;
			if (off + 512 >= out_sz)
				break;
		}
	}

	snprintf(out + off, out_sz - off, "]}");
	json_printf(c, 200, "%s", out);
	free(out);
}

/* Helper: Count total ACL rules across all maps */
static int acl_count_rules(void)
{
	int count = 0;

	if (g_maps.acl_5tuple_fd >= 0) {
		struct acl_5tuple_key k, nk;
		memset(&k, 0, sizeof(k));
		int has_prev = 0;
		while (bpf_map_get_next_key(g_maps.acl_5tuple_fd, has_prev ? &k : NULL, &nk) == 0) {
			count++;
			k = nk;
			has_prev = 1;
		}
	}

	if (g_maps.acl_pdp_fd >= 0) {
		struct acl_proto_dstip_port_key k, nk;
		memset(&k, 0, sizeof(k));
		int has_prev = 0;
		while (bpf_map_get_next_key(g_maps.acl_pdp_fd, has_prev ? &k : NULL, &nk) == 0) {
			count++;
			k = nk;
			has_prev = 1;
		}
	}

	if (g_maps.acl_psp_fd >= 0) {
		struct acl_proto_srcip_port_key k, nk;
		memset(&k, 0, sizeof(k));
		int has_prev = 0;
		while (bpf_map_get_next_key(g_maps.acl_psp_fd, has_prev ? &k : NULL, &nk) == 0) {
			count++;
			k = nk;
			has_prev = 1;
		}
	}

	if (g_maps.acl_pp_fd >= 0) {
		struct acl_proto_port_key k, nk;
		memset(&k, 0, sizeof(k));
		int has_prev = 0;
		while (bpf_map_get_next_key(g_maps.acl_pp_fd, has_prev ? &k : NULL, &nk) == 0) {
			count++;
			k = nk;
			has_prev = 1;
		}
	}

	if (g_maps.acl_lpm_src_fd >= 0) {
		struct lpm_key k, nk;
		memset(&k, 0, sizeof(k));
		int has_prev = 0;
		while (bpf_map_get_next_key(g_maps.acl_lpm_src_fd, has_prev ? &k : NULL, &nk) == 0) {
			count++;
			k = nk;
			has_prev = 1;
		}
	}

	if (g_maps.acl_lpm_dst_fd >= 0) {
		struct lpm_key k, nk;
		memset(&k, 0, sizeof(k));
		int has_prev = 0;
		while (bpf_map_get_next_key(g_maps.acl_lpm_dst_fd, has_prev ? &k : NULL, &nk) == 0) {
			count++;
			k = nk;
			has_prev = 1;
		}
	}

	return count;
}

static __u32 acl_next_rule_id(void)
{
	if (g_acl_next_rule_id == 0)
		g_acl_next_rule_id = 1;
	return g_acl_next_rule_id++;
}

static int acl_map_foreach(int map_fd, size_t key_size, size_t value_size,
			   int (*cb)(void *key, void *value, void *ctx),
			   void *ctx)
{
	void *key = NULL, *next = NULL, *val = NULL;
	int first = 1;

	if (map_fd < 0 || key_size == 0 || value_size == 0 || !cb)
		return 0;

	key = calloc(1, key_size);
	next = calloc(1, key_size);
	val = calloc(1, value_size);
	if (!key || !next || !val) {
		free(key);
		free(next);
		free(val);
		return -1;
	}

	while (bpf_map_get_next_key(map_fd, first ? NULL : key, next) == 0) {
		if (bpf_map_lookup_elem(map_fd, next, val) == 0) {
			if (cb(next, val, ctx) != 0)
				break;
		}
		memcpy(key, next, key_size);
		first = 0;
	}

	free(key);
	free(next);
	free(val);
	return 0;
}

struct acl_seed_ctx {
	int map_fd;
	__u32 max_rule_id;
	int assign_missing;
};

static int acl_seed_result_cb(void *key, void *value, void *ctx)
{
	struct acl_seed_ctx *s = ctx;
	struct acl_result *res = value;

	if (res->rule_id == 0 && s->assign_missing) {
		res->rule_id = acl_next_rule_id();
		bpf_map_update_elem(s->map_fd, key, res, BPF_ANY);
	}
	if (res->rule_id > s->max_rule_id)
		s->max_rule_id = res->rule_id;
	return 0;
}

static int acl_seed_lpm_cb(void *key, void *value, void *ctx)
{
	struct acl_seed_ctx *s = ctx;
	struct acl_lpm_value *val = value;

	if (val->rule_id == 0 && s->assign_missing) {
		val->rule_id = acl_next_rule_id();
		bpf_map_update_elem(s->map_fd, key, val, BPF_ANY);
	}
	if (val->rule_id > s->max_rule_id)
		s->max_rule_id = val->rule_id;
	return 0;
}

static void acl_seed_rule_ids_if_needed(void)
{
	struct acl_seed_ctx s;

	if (g_acl_rule_ids_seeded)
		return;

	memset(&s, 0, sizeof(s));
	s.assign_missing = 0;

	if (g_maps.acl_5tuple_fd >= 0) {
		s.map_fd = g_maps.acl_5tuple_fd;
		acl_map_foreach(g_maps.acl_5tuple_fd, sizeof(struct acl_5tuple_key),
				sizeof(struct acl_result), acl_seed_result_cb, &s);
	}
	if (g_maps.acl_pdp_fd >= 0) {
		s.map_fd = g_maps.acl_pdp_fd;
		acl_map_foreach(g_maps.acl_pdp_fd, sizeof(struct acl_proto_dstip_port_key),
				sizeof(struct acl_result), acl_seed_result_cb, &s);
	}
	if (g_maps.acl_psp_fd >= 0) {
		s.map_fd = g_maps.acl_psp_fd;
		acl_map_foreach(g_maps.acl_psp_fd, sizeof(struct acl_proto_srcip_port_key),
				sizeof(struct acl_result), acl_seed_result_cb, &s);
	}
	if (g_maps.acl_pp_fd >= 0) {
		s.map_fd = g_maps.acl_pp_fd;
		acl_map_foreach(g_maps.acl_pp_fd, sizeof(struct acl_proto_port_key),
				sizeof(struct acl_result), acl_seed_result_cb, &s);
	}
	if (g_maps.acl_lpm_src_fd >= 0) {
		s.map_fd = g_maps.acl_lpm_src_fd;
		acl_map_foreach(g_maps.acl_lpm_src_fd, sizeof(struct lpm_key),
				sizeof(struct acl_lpm_value), acl_seed_lpm_cb, &s);
	}
	if (g_maps.acl_lpm_dst_fd >= 0) {
		s.map_fd = g_maps.acl_lpm_dst_fd;
		acl_map_foreach(g_maps.acl_lpm_dst_fd, sizeof(struct lpm_key),
				sizeof(struct acl_lpm_value), acl_seed_lpm_cb, &s);
	}

	g_acl_next_rule_id = (s.max_rule_id == (__u32) -1) ? 1 : (s.max_rule_id + 1);
	s.assign_missing = 1;

	if (g_maps.acl_5tuple_fd >= 0) {
		s.map_fd = g_maps.acl_5tuple_fd;
		acl_map_foreach(g_maps.acl_5tuple_fd, sizeof(struct acl_5tuple_key),
				sizeof(struct acl_result), acl_seed_result_cb, &s);
	}
	if (g_maps.acl_pdp_fd >= 0) {
		s.map_fd = g_maps.acl_pdp_fd;
		acl_map_foreach(g_maps.acl_pdp_fd, sizeof(struct acl_proto_dstip_port_key),
				sizeof(struct acl_result), acl_seed_result_cb, &s);
	}
	if (g_maps.acl_psp_fd >= 0) {
		s.map_fd = g_maps.acl_psp_fd;
		acl_map_foreach(g_maps.acl_psp_fd, sizeof(struct acl_proto_srcip_port_key),
				sizeof(struct acl_result), acl_seed_result_cb, &s);
	}
	if (g_maps.acl_pp_fd >= 0) {
		s.map_fd = g_maps.acl_pp_fd;
		acl_map_foreach(g_maps.acl_pp_fd, sizeof(struct acl_proto_port_key),
				sizeof(struct acl_result), acl_seed_result_cb, &s);
	}
	if (g_maps.acl_lpm_src_fd >= 0) {
		s.map_fd = g_maps.acl_lpm_src_fd;
		acl_map_foreach(g_maps.acl_lpm_src_fd, sizeof(struct lpm_key),
				sizeof(struct acl_lpm_value), acl_seed_lpm_cb, &s);
	}
	if (g_maps.acl_lpm_dst_fd >= 0) {
		s.map_fd = g_maps.acl_lpm_dst_fd;
		acl_map_foreach(g_maps.acl_lpm_dst_fd, sizeof(struct lpm_key),
				sizeof(struct acl_lpm_value), acl_seed_lpm_cb, &s);
	}

	if (s.max_rule_id >= g_acl_next_rule_id)
		g_acl_next_rule_id = s.max_rule_id + 1;
	g_acl_rule_ids_seeded = 1;
}

struct acl_delete_ctx {
	__u32 target_rule_id;
	int found;
	size_t key_size;
	unsigned char key_data[32];
};

static int acl_delete_result_find_cb(void *key, void *value, void *ctx)
{
	struct acl_result *res = value;
	struct acl_delete_ctx *d = ctx;

	if (res->rule_id == d->target_rule_id) {
		memcpy(d->key_data, key, d->key_size);
		d->found = 1;
		return 1;
	}
	return 0;
}

static int acl_delete_lpm_find_cb(void *key, void *value, void *ctx)
{
	struct acl_lpm_value *val = value;
	struct acl_delete_ctx *d = ctx;

	if (val->rule_id == d->target_rule_id) {
		memcpy(d->key_data, key, d->key_size);
		d->found = 1;
		return 1;
	}
	return 0;
}

static int acl_find_and_delete_rule(struct acl_delete_ctx *d, int map_fd,
				    size_t key_size, size_t value_size,
				    int (*find_cb)(void *key, void *value, void *ctx))
{
	if (map_fd < 0)
		return 0;

	d->key_size = key_size;
	d->found = 0;
	acl_map_foreach(map_fd, key_size, value_size, find_cb, d);
	if (!d->found)
		return 0;

	bpf_map_delete_elem(map_fd, d->key_data);
	return 1;
}

/* Helper: Set ACL enabled state */
static int acl_set_enabled(int enable)
{
	if (g_maps.acl_config_fd < 0)
		return -1;

	struct acl_config cfg;
	__u32 key = 0;

	if (bpf_map_lookup_elem(g_maps.acl_config_fd, &key, &cfg) < 0) {
		/* Initialize config if not exists */
		memset(&cfg, 0, sizeof(cfg));
		cfg.default_action = 0; /* PASS */
	}

	cfg.enabled = enable ? 1 : 0;

	if (bpf_map_update_elem(g_maps.acl_config_fd, &key, &cfg, BPF_ANY) < 0) {
		RS_LOG_ERROR("Failed to update ACL config: %s", strerror(errno));
		return -1;
	}

	RS_LOG_INFO("ACL %s (auto)", enable ? "enabled" : "disabled");
	return 0;
}

/* Helper: Check if ACL is currently enabled */
static int acl_is_enabled(void)
{
	if (g_maps.acl_config_fd < 0)
		return 0;

	struct acl_config cfg;
	__u32 key = 0;

	if (bpf_map_lookup_elem(g_maps.acl_config_fd, &key, &cfg) < 0)
		return 0;

	return cfg.enabled ? 1 : 0;
}

static void handle_acl_create(struct mg_connection *c, struct mg_http_message *hm, void *userdata)
{
	struct acl_result res;
	char *action_str, *src_ip_str, *dst_ip_str, *proto_str;
	long src_port, dst_port, priority;
	__u8 proto = 0;
	__u32 src_ip = 0, dst_ip = 0;
	__u32 src_prefixlen = 32, dst_prefixlen = 32;
	int has_src_ip = 0, has_dst_ip = 0;
	int src_is_cidr = 0, dst_is_cidr = 0;
	const char *map_used = "unknown";

	(void) userdata;

	if (mgmtd_maps_ensure() != 0) {
		json_printf(c, 503, "{\"error\":\"acl map unavailable\"}");
		return;
	}
	acl_seed_rule_ids_if_needed();

	memset(&res, 0, sizeof(res));

	action_str = mg_json_get_str(hm->body, "$.action");
	src_ip_str = mg_json_get_str(hm->body, "$.src_ip");
	dst_ip_str = mg_json_get_str(hm->body, "$.dst_ip");
	proto_str = mg_json_get_str(hm->body, "$.protocol");
	src_port = mg_json_get_long(hm->body, "$.src_port", 0);
	dst_port = mg_json_get_long(hm->body, "$.dst_port", 0);
	priority = mg_json_get_long(hm->body, "$.priority", 0);

	/* Parse protocol */
	if (proto_str) {
		if (strcmp(proto_str, "tcp") == 0 || strcmp(proto_str, "TCP") == 0)
			proto = 6;
		else if (strcmp(proto_str, "udp") == 0 || strcmp(proto_str, "UDP") == 0)
			proto = 17;
		else if (strcmp(proto_str, "icmp") == 0 || strcmp(proto_str, "ICMP") == 0)
			proto = 1;
		else if (strcmp(proto_str, "any") != 0)
			proto = (__u8) atoi(proto_str);
		free(proto_str);
	} else {
		proto = (__u8) mg_json_get_long(hm->body, "$.protocol", 0);
	}

	/* Parse source IP with CIDR support */
	if (src_ip_str) {
		if (strcmp(src_ip_str, "any") != 0 && strcmp(src_ip_str, "") != 0) {
			if (parse_cidr(src_ip_str, &src_ip, &src_prefixlen) == 0) {
				has_src_ip = 1;
				src_is_cidr = (src_prefixlen < 32) ? 1 : 0;
			}
		}
		free(src_ip_str);
	}

	/* Parse destination IP with CIDR support */
	if (dst_ip_str) {
		if (strcmp(dst_ip_str, "any") != 0 && strcmp(dst_ip_str, "") != 0) {
			if (parse_cidr(dst_ip_str, &dst_ip, &dst_prefixlen) == 0) {
				has_dst_ip = 1;
				dst_is_cidr = (dst_prefixlen < 32) ? 1 : 0;
			}
		}
		free(dst_ip_str);
	}

	/* Parse action */
	if (action_str) {
		if (strcmp(action_str, "deny") == 0 || strcmp(action_str, "drop") == 0)
			res.action = 1;
		else if (strcmp(action_str, "redirect") == 0)
			res.action = 2;
		else
			res.action = 0;
		free(action_str);
	}
	res.priority = (__u8) (priority > 7 ? 7 : priority);
	res.stats_id = 0;
	res.rule_id = acl_next_rule_id();

	/*
	 * Select appropriate ACL map based on which fields are specified:
	 * - CIDR src IP (prefixlen < 32): LPM source map (Level 5)
	 * - CIDR dst IP (prefixlen < 32): LPM destination map (Level 6)
	 * - Both exact IPs: 5-tuple map (exact match)
	 * - Dst IP only: proto_dst map (Level 2)
	 * - Src IP only: proto_src map (Level 3)
	 * - Neither IP: proto_port map (Level 4)
	 */
	if (src_is_cidr && has_src_ip) {
		struct lpm_key key;
		struct acl_lpm_value lpm_val;
		memset(&key, 0, sizeof(key));
		memset(&lpm_val, 0, sizeof(lpm_val));
		key.prefixlen = src_prefixlen;
		key.addr = src_ip;
		lpm_val.action = res.action;
		lpm_val.log_event = res.log_event;
		lpm_val.redirect_ifindex = res.redirect_ifindex;
		lpm_val.stats_id = res.stats_id;
		lpm_val.rule_id = res.rule_id;
		lpm_val.priority = res.priority;
		lpm_val.other_ip = has_dst_ip ? dst_ip : 0;
		lpm_val.proto = proto;
		lpm_val.sport = htons((__u16) src_port);
		lpm_val.dport = htons((__u16) dst_port);

		if (g_maps.acl_lpm_src_fd < 0) {
			json_printf(c, 503, "{\"error\":\"LPM source ACL map unavailable\"}");
			return;
		}
		if (bpf_map_update_elem(g_maps.acl_lpm_src_fd, &key, &lpm_val, BPF_ANY) != 0) {
			json_printf(c, 500, "{\"error\":\"failed to add ACL rule: %s\"}", strerror(errno));
			return;
		}
		map_used = "lpm_src";

	} else if (dst_is_cidr && has_dst_ip) {
		struct lpm_key key;
		struct acl_lpm_value lpm_val;
		memset(&key, 0, sizeof(key));
		memset(&lpm_val, 0, sizeof(lpm_val));
		key.prefixlen = dst_prefixlen;
		key.addr = dst_ip;
		lpm_val.action = res.action;
		lpm_val.log_event = res.log_event;
		lpm_val.redirect_ifindex = res.redirect_ifindex;
		lpm_val.stats_id = res.stats_id;
		lpm_val.rule_id = res.rule_id;
		lpm_val.priority = res.priority;
		lpm_val.other_ip = has_src_ip ? src_ip : 0;
		lpm_val.proto = proto;
		lpm_val.sport = htons((__u16) src_port);
		lpm_val.dport = htons((__u16) dst_port);

		if (g_maps.acl_lpm_dst_fd < 0) {
			json_printf(c, 503, "{\"error\":\"LPM destination ACL map unavailable\"}");
			return;
		}
		if (bpf_map_update_elem(g_maps.acl_lpm_dst_fd, &key, &lpm_val, BPF_ANY) != 0) {
			json_printf(c, 500, "{\"error\":\"failed to add ACL rule: %s\"}", strerror(errno));
			return;
		}
		map_used = "lpm_dst";

	} else if (has_src_ip && has_dst_ip) {
		struct acl_5tuple_key key;
		memset(&key, 0, sizeof(key));
		key.proto = proto;
		key.src_ip = src_ip;
		key.dst_ip = dst_ip;
		key.sport = htons((__u16) src_port);
		key.dport = htons((__u16) dst_port);

		if (g_maps.acl_5tuple_fd < 0) {
			json_printf(c, 503, "{\"error\":\"5-tuple ACL map unavailable\"}");
			return;
		}
		if (bpf_map_update_elem(g_maps.acl_5tuple_fd, &key, &res, BPF_ANY) != 0) {
			json_printf(c, 500, "{\"error\":\"failed to add ACL rule: %s\"}", strerror(errno));
			return;
		}
		map_used = "5tuple";

	} else if (has_dst_ip && !has_src_ip) {
		struct acl_proto_dstip_port_key key;
		memset(&key, 0, sizeof(key));
		key.proto = proto;
		key.dst_ip = dst_ip;
		key.dst_port = htons((__u16) dst_port);

		if (g_maps.acl_pdp_fd < 0) {
			json_printf(c, 503, "{\"error\":\"proto_dst ACL map unavailable\"}");
			return;
		}
		if (bpf_map_update_elem(g_maps.acl_pdp_fd, &key, &res, BPF_ANY) != 0) {
			json_printf(c, 500, "{\"error\":\"failed to add ACL rule: %s\"}", strerror(errno));
			return;
		}
		map_used = "proto_dst";

	} else if (has_src_ip && !has_dst_ip) {
		struct acl_proto_srcip_port_key key;
		memset(&key, 0, sizeof(key));
		key.proto = proto;
		key.src_ip = src_ip;
		key.dst_port = htons((__u16) dst_port);

		if (g_maps.acl_psp_fd < 0) {
			json_printf(c, 503, "{\"error\":\"proto_src ACL map unavailable\"}");
			return;
		}
		if (bpf_map_update_elem(g_maps.acl_psp_fd, &key, &res, BPF_ANY) != 0) {
			json_printf(c, 500, "{\"error\":\"failed to add ACL rule: %s\"}", strerror(errno));
			return;
		}
		map_used = "proto_src";

	} else {
		struct acl_proto_port_key key;
		memset(&key, 0, sizeof(key));
		key.proto = proto;
		key.dst_port = htons((__u16) dst_port);

		if (g_maps.acl_pp_fd < 0) {
			json_printf(c, 503, "{\"error\":\"proto_port ACL map unavailable\"}");
			return;
		}
		if (bpf_map_update_elem(g_maps.acl_pp_fd, &key, &res, BPF_ANY) != 0) {
			json_printf(c, 500, "{\"error\":\"failed to add ACL rule: %s\"}", strerror(errno));
			return;
		}
		map_used = "proto_port";
	}

	if (!acl_is_enabled()) {
		acl_set_enabled(1);
	}

	mgmtd_audit_log(AUDIT_SEV_INFO, AUDIT_CAT_ACL, "acl_add", 1,
			    "proto=%u src_port=%ld dst_port=%ld action=%u map=%s",
			    proto, src_port, dst_port, res.action, map_used);
	json_printf(c, 200, "{\"status\":\"ok\",\"map\":\"%s\",\"id\":%u}",
		    map_used, res.rule_id);
}

static void handle_acl_delete(struct mg_connection *c, struct mg_http_message *hm, void *userdata)
{
	int target_id;
	struct acl_delete_ctx d;
	int deleted = 0;

	(void) userdata;

	target_id = extract_id_from_uri(hm, "/api/acls/");
	if (target_id < 0) {
		json_printf(c, 400, "{\"error\":\"invalid acl id\"}");
		return;
	}

	if (mgmtd_maps_ensure() != 0) {
		json_printf(c, 503, "{\"error\":\"maps unavailable\"}");
		return;
	}
	acl_seed_rule_ids_if_needed();

	memset(&d, 0, sizeof(d));
	d.target_rule_id = (__u32) target_id;

	deleted = acl_find_and_delete_rule(&d, g_maps.acl_5tuple_fd,
					 sizeof(struct acl_5tuple_key), sizeof(struct acl_result),
					 acl_delete_result_find_cb);
	if (!deleted)
		deleted = acl_find_and_delete_rule(&d, g_maps.acl_pdp_fd,
					 sizeof(struct acl_proto_dstip_port_key), sizeof(struct acl_result),
					 acl_delete_result_find_cb);
	if (!deleted)
		deleted = acl_find_and_delete_rule(&d, g_maps.acl_psp_fd,
					 sizeof(struct acl_proto_srcip_port_key), sizeof(struct acl_result),
					 acl_delete_result_find_cb);
	if (!deleted)
		deleted = acl_find_and_delete_rule(&d, g_maps.acl_pp_fd,
					 sizeof(struct acl_proto_port_key), sizeof(struct acl_result),
					 acl_delete_result_find_cb);
	if (!deleted)
		deleted = acl_find_and_delete_rule(&d, g_maps.acl_lpm_src_fd,
					 sizeof(struct lpm_key), sizeof(struct acl_lpm_value),
					 acl_delete_lpm_find_cb);
	if (!deleted)
		deleted = acl_find_and_delete_rule(&d, g_maps.acl_lpm_dst_fd,
					 sizeof(struct lpm_key), sizeof(struct acl_lpm_value),
					 acl_delete_lpm_find_cb);

	if (!deleted) {
		json_printf(c, 404, "{\"error\":\"acl rule not found\"}");
		return;
	}

	/* Auto-disable ACL when last rule is removed */
	if (acl_count_rules() == 0 && acl_is_enabled()) {
		acl_set_enabled(0);
	}

	mgmtd_audit_log(AUDIT_SEV_INFO, AUDIT_CAT_ACL, "acl_delete", 1,
			    "acl_id=%d", target_id);
	json_printf(c, 200, "{\"status\":\"deleted\",\"id\":%d}", target_id);
}

static void handle_acl_update(struct mg_connection *c, struct mg_http_message *hm, void *userdata)
{
	int target_id;
	struct acl_delete_ctx d;
	int found = 0;
	struct acl_result res;
	char *action_str, *src_ip_str, *dst_ip_str, *proto_str;
	long src_port, dst_port, priority;
	__u8 proto = 0;
	__u32 src_ip = 0, dst_ip = 0;
	__u32 src_prefixlen = 32, dst_prefixlen = 32;
	int has_src_ip = 0, has_dst_ip = 0;
	int src_is_cidr = 0, dst_is_cidr = 0;
	const char *map_used = "unknown";

	(void) userdata;

	target_id = extract_id_from_uri(hm, "/api/acls/");
	if (target_id < 0) {
		json_printf(c, 400, "{\"error\":\"invalid acl id\"}");
		return;
	}

	if (mgmtd_maps_ensure() != 0) {
		json_printf(c, 503, "{\"error\":\"maps unavailable\"}");
		return;
	}
	acl_seed_rule_ids_if_needed();

	memset(&d, 0, sizeof(d));
	d.target_rule_id = (__u32) target_id;

	found = acl_find_and_delete_rule(&d, g_maps.acl_5tuple_fd,
				       sizeof(struct acl_5tuple_key), sizeof(struct acl_result),
				       acl_delete_result_find_cb);
	if (!found)
		found = acl_find_and_delete_rule(&d, g_maps.acl_pdp_fd,
				       sizeof(struct acl_proto_dstip_port_key), sizeof(struct acl_result),
				       acl_delete_result_find_cb);
	if (!found)
		found = acl_find_and_delete_rule(&d, g_maps.acl_psp_fd,
				       sizeof(struct acl_proto_srcip_port_key), sizeof(struct acl_result),
				       acl_delete_result_find_cb);
	if (!found)
		found = acl_find_and_delete_rule(&d, g_maps.acl_pp_fd,
				       sizeof(struct acl_proto_port_key), sizeof(struct acl_result),
				       acl_delete_result_find_cb);
	if (!found)
		found = acl_find_and_delete_rule(&d, g_maps.acl_lpm_src_fd,
				       sizeof(struct lpm_key), sizeof(struct acl_lpm_value),
				       acl_delete_lpm_find_cb);
	if (!found)
		found = acl_find_and_delete_rule(&d, g_maps.acl_lpm_dst_fd,
				       sizeof(struct lpm_key), sizeof(struct acl_lpm_value),
				       acl_delete_lpm_find_cb);

	if (!found) {
		json_printf(c, 404, "{\"error\":\"acl rule not found\"}");
		return;
	}

	memset(&res, 0, sizeof(res));

	action_str = mg_json_get_str(hm->body, "$.action");
	src_ip_str = mg_json_get_str(hm->body, "$.src_ip");
	dst_ip_str = mg_json_get_str(hm->body, "$.dst_ip");
	proto_str = mg_json_get_str(hm->body, "$.protocol");
	src_port = mg_json_get_long(hm->body, "$.src_port", 0);
	dst_port = mg_json_get_long(hm->body, "$.dst_port", 0);
	priority = mg_json_get_long(hm->body, "$.priority", 0);

	if (proto_str) {
		if (strcmp(proto_str, "tcp") == 0 || strcmp(proto_str, "TCP") == 0)
			proto = 6;
		else if (strcmp(proto_str, "udp") == 0 || strcmp(proto_str, "UDP") == 0)
			proto = 17;
		else if (strcmp(proto_str, "icmp") == 0 || strcmp(proto_str, "ICMP") == 0)
			proto = 1;
		else if (strcmp(proto_str, "any") != 0)
			proto = (__u8) atoi(proto_str);
		free(proto_str);
	} else {
		proto = (__u8) mg_json_get_long(hm->body, "$.protocol", 0);
	}

	if (src_ip_str) {
		if (strcmp(src_ip_str, "any") != 0 && strcmp(src_ip_str, "") != 0) {
			if (parse_cidr(src_ip_str, &src_ip, &src_prefixlen) == 0) {
				has_src_ip = 1;
				src_is_cidr = (src_prefixlen < 32) ? 1 : 0;
			}
		}
		free(src_ip_str);
	}

	if (dst_ip_str) {
		if (strcmp(dst_ip_str, "any") != 0 && strcmp(dst_ip_str, "") != 0) {
			if (parse_cidr(dst_ip_str, &dst_ip, &dst_prefixlen) == 0) {
				has_dst_ip = 1;
				dst_is_cidr = (dst_prefixlen < 32) ? 1 : 0;
			}
		}
		free(dst_ip_str);
	}

	if (action_str) {
		if (strcmp(action_str, "deny") == 0 || strcmp(action_str, "drop") == 0)
			res.action = 1;
		else if (strcmp(action_str, "redirect") == 0)
			res.action = 2;
		else
			res.action = 0;
		free(action_str);
	}
	res.priority = (__u8) (priority > 7 ? 7 : priority);
	res.stats_id = 0;
	res.rule_id = (__u32) target_id;

	if (src_is_cidr && has_src_ip) {
		struct lpm_key key;
		struct acl_lpm_value lpm_val;
		memset(&key, 0, sizeof(key));
		memset(&lpm_val, 0, sizeof(lpm_val));
		key.prefixlen = src_prefixlen;
		key.addr = src_ip;
		lpm_val.action = res.action;
		lpm_val.log_event = res.log_event;
		lpm_val.redirect_ifindex = res.redirect_ifindex;
		lpm_val.stats_id = res.stats_id;
		lpm_val.rule_id = res.rule_id;
		lpm_val.priority = res.priority;
		lpm_val.other_ip = has_dst_ip ? dst_ip : 0;
		lpm_val.proto = proto;
		lpm_val.sport = htons((__u16) src_port);
		lpm_val.dport = htons((__u16) dst_port);

		if (g_maps.acl_lpm_src_fd < 0 ||
		    bpf_map_update_elem(g_maps.acl_lpm_src_fd, &key, &lpm_val, BPF_ANY) != 0) {
			json_printf(c, 500, "{\"error\":\"failed to update ACL rule\"}");
			return;
		}
		map_used = "lpm_src";

	} else if (dst_is_cidr && has_dst_ip) {
		struct lpm_key key;
		struct acl_lpm_value lpm_val;
		memset(&key, 0, sizeof(key));
		memset(&lpm_val, 0, sizeof(lpm_val));
		key.prefixlen = dst_prefixlen;
		key.addr = dst_ip;
		lpm_val.action = res.action;
		lpm_val.log_event = res.log_event;
		lpm_val.redirect_ifindex = res.redirect_ifindex;
		lpm_val.stats_id = res.stats_id;
		lpm_val.rule_id = res.rule_id;
		lpm_val.priority = res.priority;
		lpm_val.other_ip = has_src_ip ? src_ip : 0;
		lpm_val.proto = proto;
		lpm_val.sport = htons((__u16) src_port);
		lpm_val.dport = htons((__u16) dst_port);

		if (g_maps.acl_lpm_dst_fd < 0 ||
		    bpf_map_update_elem(g_maps.acl_lpm_dst_fd, &key, &lpm_val, BPF_ANY) != 0) {
			json_printf(c, 500, "{\"error\":\"failed to update ACL rule\"}");
			return;
		}
		map_used = "lpm_dst";

	} else if (has_src_ip && has_dst_ip) {
		struct acl_5tuple_key key;
		memset(&key, 0, sizeof(key));
		key.proto = proto;
		key.src_ip = src_ip;
		key.dst_ip = dst_ip;
		key.sport = htons((__u16) src_port);
		key.dport = htons((__u16) dst_port);

		if (g_maps.acl_5tuple_fd < 0 ||
		    bpf_map_update_elem(g_maps.acl_5tuple_fd, &key, &res, BPF_ANY) != 0) {
			json_printf(c, 500, "{\"error\":\"failed to update ACL rule\"}");
			return;
		}
		map_used = "5tuple";

	} else if (has_dst_ip && !has_src_ip) {
		struct acl_proto_dstip_port_key key;
		memset(&key, 0, sizeof(key));
		key.proto = proto;
		key.dst_ip = dst_ip;
		key.dst_port = htons((__u16) dst_port);

		if (g_maps.acl_pdp_fd < 0 ||
		    bpf_map_update_elem(g_maps.acl_pdp_fd, &key, &res, BPF_ANY) != 0) {
			json_printf(c, 500, "{\"error\":\"failed to update ACL rule\"}");
			return;
		}
		map_used = "proto_dst";

	} else if (has_src_ip && !has_dst_ip) {
		struct acl_proto_srcip_port_key key;
		memset(&key, 0, sizeof(key));
		key.proto = proto;
		key.src_ip = src_ip;
		key.dst_port = htons((__u16) dst_port);

		if (g_maps.acl_psp_fd < 0 ||
		    bpf_map_update_elem(g_maps.acl_psp_fd, &key, &res, BPF_ANY) != 0) {
			json_printf(c, 500, "{\"error\":\"failed to update ACL rule\"}");
			return;
		}
		map_used = "proto_src";

	} else {
		struct acl_proto_port_key key;
		memset(&key, 0, sizeof(key));
		key.proto = proto;
		key.dst_port = htons((__u16) dst_port);

		if (g_maps.acl_pp_fd < 0 ||
		    bpf_map_update_elem(g_maps.acl_pp_fd, &key, &res, BPF_ANY) != 0) {
			json_printf(c, 500, "{\"error\":\"failed to update ACL rule\"}");
			return;
		}
		map_used = "proto_port";
	}

	mgmtd_audit_log(AUDIT_SEV_INFO, AUDIT_CAT_ACL, "acl_update", 1,
			    "acl_id=%d proto=%u action=%u map=%s", target_id, proto, res.action, map_used);
	json_printf(c, 200, "{\"status\":\"updated\",\"map\":\"%s\",\"id\":%d}",
		    map_used, target_id);
}

static void handle_routes_list(struct mg_connection *c, struct mg_http_message *hm, void *userdata)
{
	char *out = malloc(65536);
	size_t out_sz = 65536;
	size_t off = 0;
	int first = 1;

	(void) hm;
	(void) userdata;

	if (!out) {
		mg_http_reply(c, 500, "Content-Type: application/json\r\n", "{\"error\":\"out of memory\"}\n");
		return;
	}

	if (mgmtd_maps_ensure() != 0 || g_maps.route_tbl_fd < 0) {
		json_printf(c, 200, "{\"routes\":[]}");
		free(out);
		return;
	}

	off += (size_t) snprintf(out + off, out_sz - off, "{\"routes\":[");

	{
		struct lpm_key k, nk;
		struct route_entry entry;
		int has_prev = 0;

		memset(&k, 0, sizeof(k));
		while (bpf_map_get_next_key(g_maps.route_tbl_fd, has_prev ? &k : NULL, &nk) == 0) {
			if (bpf_map_lookup_elem(g_maps.route_tbl_fd, &nk, &entry) == 0) {
				char prefix_str[32], nh_str[INET_ADDRSTRLEN];
				char ifname[IF_NAMESIZE] = "unknown";
				struct in_addr a;
				char ip_str[INET_ADDRSTRLEN];

				a.s_addr = nk.addr;
				inet_ntop(AF_INET, &a, ip_str, sizeof(ip_str));
				snprintf(prefix_str, sizeof(prefix_str), "%s/%u", ip_str, nk.prefixlen);

				if (entry.nexthop != 0) {
					struct in_addr nh;
					nh.s_addr = entry.nexthop;
					inet_ntop(AF_INET, &nh, nh_str, sizeof(nh_str));
				} else {
					strncpy(nh_str, "0.0.0.0", sizeof(nh_str));
				}

			if (entry.ifindex > 0) {
				if (!if_indextoname(entry.ifindex, ifname))
					ifindex_to_name_sysfs(entry.ifindex, ifname, sizeof(ifname));
			}

				off += (size_t) snprintf(out + off, out_sz - off,
						 "%s{\"prefix\":\"%s\",\"next_hop\":\"%s\","
						 "\"interface\":\"%s\",\"ifindex\":%u,"
						 "\"metric\":%u,\"type\":\"%s\"}",
						 first ? "" : ",",
						 prefix_str, nh_str, ifname, entry.ifindex,
						 entry.metric,
						 entry.type == 0 ? "direct" : "static");
				first = 0;
			}
			k = nk;
			has_prev = 1;
			if (off + 512 >= out_sz)
				break;
		}
	}

	snprintf(out + off, out_sz - off, "]}");
	json_printf(c, 200, "%s", out);
	free(out);
}

static void handle_route_add(struct mg_connection *c, struct mg_http_message *hm, void *userdata)
{
	struct lpm_key key;
	struct route_entry entry;
	char *prefix_str, *nexthop_str, *iface_str;
	long metric;
	struct in_addr addr;

	(void) userdata;

	if (mgmtd_maps_ensure() != 0 || g_maps.route_tbl_fd < 0) {
		json_printf(c, 503, "{\"error\":\"route map unavailable\"}");
		return;
	}

	memset(&key, 0, sizeof(key));
	memset(&entry, 0, sizeof(entry));

	prefix_str = mg_json_get_str(hm->body, "$.prefix");
	nexthop_str = mg_json_get_str(hm->body, "$.next_hop");
	iface_str = mg_json_get_str(hm->body, "$.interface");
	metric = mg_json_get_long(hm->body, "$.metric", 0);

	if (!prefix_str) {
		free(nexthop_str);
		free(iface_str);
		json_printf(c, 400, "{\"error\":\"prefix required\"}");
		return;
	}

	{
		char buf[64];
		char *slash;
		strncpy(buf, prefix_str, sizeof(buf) - 1);
		buf[sizeof(buf) - 1] = '\0';
		slash = strchr(buf, '/');
		if (slash) {
			*slash = '\0';
			key.prefixlen = (__u32) atoi(slash + 1);
		} else {
			key.prefixlen = 32;
		}
		if (inet_pton(AF_INET, buf, &addr) == 1)
			key.addr = addr.s_addr;
	}
	free(prefix_str);

	if (nexthop_str) {
		if (strcmp(nexthop_str, "0.0.0.0") != 0 && inet_pton(AF_INET, nexthop_str, &addr) == 1)
			entry.nexthop = addr.s_addr;
		free(nexthop_str);
	}

	if (iface_str) {
		entry.ifindex = resolve_ifindex(iface_str);
		if (entry.ifindex == 0)
			entry.ifindex = (__u32) atoi(iface_str);
		free(iface_str);
	} else {
		entry.ifindex = (__u32) mg_json_get_long(hm->body, "$.ifindex", 0);
	}

	entry.metric = (__u32) metric;
	entry.type = (entry.nexthop == 0) ? 0 : 1;

	if (bpf_map_update_elem(g_maps.route_tbl_fd, &key, &entry, BPF_ANY) != 0) {
		json_printf(c, 500, "{\"error\":\"failed to add route: %s\"}", strerror(errno));
		return;
	}

	mgmtd_audit_log(AUDIT_SEV_INFO, AUDIT_CAT_CONFIG, "route_add", 1,
			    "prefix added via mgmt portal");
	json_printf(c, 200, "{\"status\":\"ok\"}");
}

static void handle_route_delete(struct mg_connection *c, struct mg_http_message *hm, void *userdata)
{
	struct lpm_key key;
	struct mg_str route_id;
	char buf[128];
	char *slash;
	struct in_addr addr;

	(void) userdata;

	if (mgmtd_maps_ensure() != 0 || g_maps.route_tbl_fd < 0) {
		json_printf(c, 503, "{\"error\":\"route map unavailable\"}");
		return;
	}

	route_id = extract_name_from_uri(hm, "/api/routes/");
	if (route_id.len == 0 || route_id.len >= sizeof(buf)) {
		json_printf(c, 400, "{\"error\":\"invalid route prefix\"}");
		return;
	}

	memset(&key, 0, sizeof(key));
	memcpy(buf, route_id.buf, route_id.len);
	buf[route_id.len] = '\0';

	slash = strchr(buf, '/');
	if (!slash) {
		slash = strstr(buf, "%2F");
		if (!slash)
			slash = strstr(buf, "%2f");
		if (slash) {
			key.prefixlen = (__u32) atoi(slash + 3);
			*slash = '\0';
		} else {
			key.prefixlen = 32;
		}
	} else {
		key.prefixlen = (__u32) atoi(slash + 1);
		*slash = '\0';
	}

	if (inet_pton(AF_INET, buf, &addr) != 1) {
		json_printf(c, 400, "{\"error\":\"invalid IP in prefix\"}");
		return;
	}
	key.addr = addr.s_addr;

	if (bpf_map_delete_elem(g_maps.route_tbl_fd, &key) != 0) {
		json_printf(c, 404, "{\"error\":\"route not found\"}");
		return;
	}

	mgmtd_audit_log(AUDIT_SEV_INFO, AUDIT_CAT_CONFIG, "route_delete", 1,
			    "route deleted via mgmt portal");
	json_printf(c, 200, "{\"status\":\"deleted\"}");
}

static void handle_nat_rules(struct mg_connection *c, struct mg_http_message *hm, void *userdata)
{
	char *out = malloc(65536);
	char *esc = malloc(131072);

	(void) hm;
	(void) userdata;

	if (!out) {
		free(esc);
		mg_http_reply(c, 500, "Content-Type: application/json\r\n", "{\"error\":\"out of memory\"}\n");
		return;
	}
	if (!esc) {
		free(out);
		mg_http_reply(c, 500, "Content-Type: application/json\r\n", "{\"error\":\"out of memory\"}\n");
		return;
	}

	if (run_cmd_json("rsnatctl show", out, 65536) != 0) {
		json_printf(c, 500, "{\"error\":\"rsnatctl show failed\"}");
		free(esc);
		free(out);
		return;
	}

	json_escape(out, esc, 131072);
	json_printf(c, 200, "{\"output\":\"%s\"}", esc);
	free(esc);
	free(out);
}

static void handle_nat_add(struct mg_connection *c, struct mg_http_message *hm, void *userdata)
{
	char *args;
	char cmd[1024];

	(void) userdata;

	args = mg_json_get_str(hm->body, "$.args");
	if (!args)
		args = strdup("");
	if (!args) {
		json_printf(c, 500, "{\"error\":\"oom\"}");
		return;
	}
	if (has_shell_metachar(args)) {
		free(args);
		json_printf(c, 400, "{\"error\":\"invalid args\"}");
		return;
	}

	snprintf(cmd, sizeof(cmd), "rsnatctl add %s", args);
	free(args);
	if (cmd_system(cmd) != 0) {
		json_printf(c, 500, "{\"error\":\"rsnatctl add failed\"}");
		return;
	}

	json_printf(c, 200, "{\"status\":\"ok\"}");
}

static void handle_nat_conntrack(struct mg_connection *c, struct mg_http_message *hm, void *userdata)
{
	char *out = malloc(65536);
	char *esc = malloc(131072);

	(void) hm;
	(void) userdata;

	if (!out) {
		free(esc);
		mg_http_reply(c, 500, "Content-Type: application/json\r\n", "{\"error\":\"out of memory\"}\n");
		return;
	}
	if (!esc) {
		free(out);
		mg_http_reply(c, 500, "Content-Type: application/json\r\n", "{\"error\":\"out of memory\"}\n");
		return;
	}

	if (run_cmd_json("rsnatctl conntrack", out, 65536) != 0) {
		json_printf(c, 500, "{\"error\":\"rsnatctl conntrack failed\"}");
		free(esc);
		free(out);
		return;
	}

	json_escape(out, esc, 131072);
	json_printf(c, 200, "{\"output\":\"%s\"}", esc);
	free(esc);
	free(out);
}

static const char *profile_dir(void)
{
	static char dir[PATH_MAX];
	const char *home;

	if (dir[0])
		return dir;
	home = getenv("RSWITCH_HOME");
	if (home && home[0])
		snprintf(dir, sizeof(dir), "%s/etc/profiles/", home);
	else
		snprintf(dir, sizeof(dir), "/etc/rswitch/profiles/");
	return dir;
}

static void handle_profiles_list(struct mg_connection *c, struct mg_http_message *hm, void *userdata)
{
	DIR *dir;
	struct dirent *de;
	char out[16384];
	size_t off = 0;
	int first = 1;

	(void) hm;
	(void) userdata;

	dir = opendir(profile_dir());
	if (!dir) {
		json_printf(c, 200, "{\"profiles\":[]}");
		return;
	}

	off += (size_t) snprintf(out + off, sizeof(out) - off, "{\"profiles\":[");
	while ((de = readdir(dir)) != NULL) {
		if (de->d_name[0] == '.')
			continue;
		off += (size_t) snprintf(out + off, sizeof(out) - off, "%s\"%s\"",
					 first ? "" : ",", de->d_name);
		first = 0;
		if (off + 256 >= sizeof(out))
			break;
	}
	closedir(dir);
	snprintf(out + off, sizeof(out) - off, "]}");
	json_printf(c, 200, "%s", out);
}

static void handle_profiles_active(struct mg_connection *c, struct mg_http_message *hm, void *userdata)
{
	char path[PATH_MAX];
	char resolved[PATH_MAX];
	ssize_t n;
	FILE *fp;

	(void) hm;
	(void) userdata;

	memset(path, 0, sizeof(path));
	memset(resolved, 0, sizeof(resolved));

	n = readlink("/var/lib/rswitch/active_profile", path, sizeof(path) - 1);
	if (n > 0) {
		path[n] = '\0';
		json_printf(c, 200, "{\"active\":\"%s\"}", path);
		return;
	}

	fp = fopen("/var/lib/rswitch/active_profile", "r");
	if (!fp || !fgets(resolved, sizeof(resolved), fp)) {
		if (fp)
			fclose(fp);
		if (g_ctx.profile_path[0] != '\0') {
			json_printf(c, 200, "{\"active\":\"%s\"}", g_ctx.profile_path);
			return;
		}
		json_printf(c, 404, "{\"error\":\"no active profile\"}");
		return;
	}
	fclose(fp);
	resolved[strcspn(resolved, "\r\n")] = '\0';
	json_printf(c, 200, "{\"active\":\"%s\"}", resolved);
}

static void handle_profiles_apply(struct mg_connection *c, struct mg_http_message *hm, void *userdata)
{
	char *profile;
	char cmd[2048];
	char profile_path[PATH_MAX];
	char ifaces[256];
	const char *ifaces_env;

	(void) userdata;

	profile = mg_json_get_str(hm->body, "$.profile");
	if (!profile || !profile_name_valid(profile)) {
		free(profile);
		json_printf(c, 400, "{\"error\":\"profile required\"}");
		return;
	}

	snprintf(profile_path, sizeof(profile_path), "%s%s", profile_dir(), profile);

	ifaces_env = getenv("RSWITCH_INTERFACES");
	if (ifaces_env && ifaces_env[0]) {
		strncpy(ifaces, ifaces_env, sizeof(ifaces) - 1);
		ifaces[sizeof(ifaces) - 1] = '\0';
	} else if (detect_loader_ifaces(ifaces, sizeof(ifaces)) != 0) {
		free(profile);
		json_printf(c, 500, "{\"error\":\"unable to detect switch interfaces\"}");
		return;
	}
	if (!shell_safe_token_valid(profile) || !shell_safe_token_valid(ifaces)) {
		free(profile);
		json_printf(c, 400, "{\"error\":\"invalid profile or interfaces\"}");
		return;
	}

	set_active_profile_path(profile_path);

	mgmtd_audit_log(AUDIT_SEV_INFO, AUDIT_CAT_PROFILE, "profile_apply", 1,
			    "profile=%s", profile);

	json_printf(c, 200, "{\"status\":\"restarting\"}");
	c->is_draining = 1;

	/*
	 * Use a transient systemd service to run the restart outside
	 * mgmtd's cgroup (BindsTo kills the mgmtd cgroup during restart).
	 * A runtime drop-in overrides RSWITCH_PROFILE from the unit file,
	 * since Environment= in the unit takes precedence over the global
	 * manager environment set by systemctl set-environment.
	 *
	 * We also create a drop-in for rswitch-mgmtd so it picks up the
	 * new profile environment. The restart of rswitch will trigger
	 * mgmtd restart via BindsTo, so both read the new profile.
	 */
	if (g_ctx.cfg.use_namespace)
		snprintf(cmd, sizeof(cmd),
			 "nsenter --net=/proc/1/ns/net --"
			 " systemd-run --slice=system --no-block"
			 " /bin/sh -c '"
			 "sleep 1"
			 " && mkdir -p /run/systemd/system/rswitch.service.d"
			 " && mkdir -p /run/systemd/system/rswitch-mgmtd.service.d"
			 " && printf \"[Service]\\nEnvironment=RSWITCH_PROFILE=%s RSWITCH_INTERFACES=%s\\n\""
			 " > /run/systemd/system/rswitch.service.d/profile-override.conf"
			 " && printf \"[Service]\\nEnvironment=RSWITCH_PROFILE=%s\\n\""
			 " > /run/systemd/system/rswitch-mgmtd.service.d/profile-override.conf"
			 " && systemctl daemon-reload"
			 " && systemctl restart rswitch'",
			 profile, ifaces, profile);
	else
		snprintf(cmd, sizeof(cmd),
			 "systemd-run --slice=system --no-block"
			 " /bin/sh -c '"
			 "sleep 1"
			 " && mkdir -p /run/systemd/system/rswitch.service.d"
			 " && mkdir -p /run/systemd/system/rswitch-mgmtd.service.d"
			 " && printf \"[Service]\\nEnvironment=RSWITCH_PROFILE=%s RSWITCH_INTERFACES=%s\\n\""
			 " > /run/systemd/system/rswitch.service.d/profile-override.conf"
			 " && printf \"[Service]\\nEnvironment=RSWITCH_PROFILE=%s\\n\""
			 " > /run/systemd/system/rswitch-mgmtd.service.d/profile-override.conf"
			 " && systemctl daemon-reload"
			 " && systemctl restart rswitch'",
			 profile, ifaces, profile);

	/*
	 * Keep system() here intentionally: this restart path requires shell
	 * redirections/pipelines and chained systemd-run commands. Inputs are
	 * constrained to [a-zA-Z0-9_.-] before interpolation.
	 */
	free(profile);
	system(cmd);
}

static void handle_profile_read(struct mg_connection *c, struct mg_http_message *hm, void *userdata)
{
	char path[PATH_MAX];
	char namebuf[256];
	FILE *fp;
	char *raw;
	char *escaped;
	size_t nread;

	(void) userdata;

	if (extract_profile_name(hm, "/api/profiles/", namebuf, sizeof(namebuf)) != 0) {
		json_printf(c, 400, "{\"error\":\"invalid profile name\"}");
		return;
	}

	snprintf(path, sizeof(path), "%s%s", profile_dir(), namebuf);
	fp = fopen(path, "r");
	if (!fp) {
		json_printf(c, 404, "{\"error\":\"profile not found\"}");
		return;
	}

	raw = malloc(65536);
	escaped = malloc(131072);
	if (!raw || !escaped) {
		free(raw);
		free(escaped);
		fclose(fp);
		mg_http_reply(c, 500, "Content-Type: application/json\r\n", "{\"error\":\"out of memory\"}\n");
		return;
	}
	nread = fread(raw, 1, 65536 - 1, fp);
	fclose(fp);
	raw[nread] = '\0';

	json_escape(raw, escaped, 131072);
	json_printf(c, 200, "{\"name\":\"%s\",\"content\":\"%s\"}", namebuf, escaped);
	free(escaped);
	free(raw);
}

static void handle_profile_save(struct mg_connection *c, struct mg_http_message *hm, void *userdata)
{
	char namebuf[256];
	char path[PATH_MAX];
	char *content;
	FILE *fp;

	(void) userdata;

	if (extract_profile_name(hm, "/api/profiles/", namebuf, sizeof(namebuf)) != 0) {
		json_printf(c, 400, "{\"error\":\"invalid profile name\"}");
		return;
	}

	content = mg_json_get_str(hm->body, "$.content");
	if (!content) {
		json_printf(c, 400, "{\"error\":\"content required\"}");
		return;
	}

	snprintf(path, sizeof(path), "%s%s", profile_dir(), namebuf);
	fp = fopen(path, "w");
	if (!fp) {
		free(content);
		json_printf(c, 500, "{\"error\":\"failed to write profile\"}");
		return;
	}
	fputs(content, fp);
	fclose(fp);

	mgmtd_audit_log(AUDIT_SEV_INFO, AUDIT_CAT_PROFILE, "profile_save", 1,
			    "profile=%s", namebuf);
	free(content);
	json_printf(c, 200, "{\"status\":\"ok\"}");
}

static void handle_profile_delete(struct mg_connection *c, struct mg_http_message *hm, void *userdata)
{
	char namebuf[256];
	char path[PATH_MAX];

	(void) userdata;

	if (extract_profile_name(hm, "/api/profiles/", namebuf, sizeof(namebuf)) != 0) {
		json_printf(c, 400, "{\"error\":\"invalid profile name\"}");
		return;
	}

	snprintf(path, sizeof(path), "%s%s", profile_dir(), namebuf);
	if (unlink(path) != 0) {
		json_printf(c, 404, "{\"error\":\"profile not found\"}");
		return;
	}

	mgmtd_audit_log(AUDIT_SEV_INFO, AUDIT_CAT_PROFILE, "profile_delete", 1,
			    "profile=%s", namebuf);
	json_printf(c, 200, "{\"status\":\"ok\"}");
}

static void handle_topology(struct mg_connection *c, struct mg_http_message *hm, void *userdata)
{
	struct rs_topology topo;
	char *out = malloc(65536);
	size_t out_sz = 65536;
	size_t off = 0;
	int i;

	(void) hm;
	(void) userdata;

	if (!out) {
		mg_http_reply(c, 500, "Content-Type: application/json\r\n", "{\"error\":\"out of memory\"}\n");
		return;
	}

	if (rs_topology_discover(&topo) != 0) {
		json_printf(c, 500, "{\"error\":\"topology discovery failed\"}");
		free(out);
		return;
	}

	off += (size_t) snprintf(out + off, out_sz - off, "{\"nodes\":[");
	for (i = 0; i < topo.node_count; i++) {
		off += (size_t) snprintf(out + off, out_sz - off,
					 "%s{\"name\":\"%s\",\"mgmt_addr\":\"%s\","
					 "\"description\":\"%s\",\"port_count\":%d}",
					 i ? "," : "",
					 topo.nodes[i].system_name,
					 topo.nodes[i].mgmt_addr,
					 topo.nodes[i].description,
					 topo.nodes[i].port_count);
		if (off + 512 >= out_sz)
			break;
	}

	off += (size_t) snprintf(out + off, out_sz - off, "],\"links\":[");
	for (i = 0; i < topo.link_count; i++) {
		const char *local_name = "";
		const char *remote_name = "";

		if (topo.links[i].local_node_idx >= 0 && topo.links[i].local_node_idx < topo.node_count)
			local_name = topo.nodes[topo.links[i].local_node_idx].system_name;
		if (topo.links[i].remote_node_idx >= 0 && topo.links[i].remote_node_idx < topo.node_count)
			remote_name = topo.nodes[topo.links[i].remote_node_idx].system_name;

		off += (size_t) snprintf(out + off, out_sz - off,
					 "%s{\"local_node\":\"%s\",\"local_port\":\"%s\","
					 "\"remote_node\":\"%s\",\"remote_port\":\"%s\","
					 "\"speed\":\"%s\"}",
					 i ? "," : "",
					 local_name,
					 topo.links[i].local_port,
					 remote_name,
					 topo.links[i].remote_port,
					 topo.links[i].link_speed);
		if (off + 512 >= out_sz)
			break;
	}

	snprintf(out + off, out_sz - off, "]}");
	json_printf(c, 200, "%s", out);
	free(out);
}

static void handle_config_snapshots(struct mg_connection *c, struct mg_http_message *hm, void *userdata)
{
	struct rs_snapshot_info snaps[SNAPSHOT_READ_MAX];
	int n;
	int i;
	char *out = malloc(65536);
	size_t out_sz = 65536;
	size_t off = 0;

	(void) hm;
	(void) userdata;

	if (!out) {
		mg_http_reply(c, 500, "Content-Type: application/json\r\n", "{\"error\":\"out of memory\"}\n");
		return;
	}

	n = rs_rollback_list_snapshots(snaps, SNAPSHOT_READ_MAX);
	if (n < 0) {
		json_printf(c, 500, "{\"error\":\"failed to list snapshots\"}");
		free(out);
		return;
	}

	off += (size_t) snprintf(out + off, out_sz - off, "{\"snapshots\":[");
	for (i = 0; i < n; i++) {
		off += (size_t) snprintf(out + off, out_sz - off,
					 "%s{\"id\":\"%s\",\"description\":\"%s\","
					 "\"profile_path\":\"%s\",\"timestamp\":%llu,\"confirmed\":%d}",
					 i ? "," : "",
					 snaps[i].id,
					 snaps[i].description,
					 snaps[i].profile_path,
					 (unsigned long long) snaps[i].timestamp,
					 snaps[i].confirmed);
		if (off + 512 >= out_sz)
			break;
	}

	snprintf(out + off, out_sz - off, "]}");
	json_printf(c, 200, "%s", out);
	free(out);
}

/* Build state file path from profile path: /path/to/profile.yaml -> /path/to/profile.yaml.state.json */
static void get_state_file_path(char *out, size_t out_len)
{
	if (g_ctx.profile_path[0] != '\0') {
		snprintf(out, out_len, "%s.state.json", g_ctx.profile_path);
	} else {
		snprintf(out, out_len, "/var/lib/rswitch/running_state.json");
	}
}

static int save_running_state_to_file(void)
{
	FILE *f;
	int first;
	char state_path[PATH_MAX];
	char dir_path[PATH_MAX];
	char *last_slash;
	struct stat st;

	get_state_file_path(state_path, sizeof(state_path));

	/* Extract directory from state_path */
	strncpy(dir_path, state_path, sizeof(dir_path) - 1);
	dir_path[sizeof(dir_path) - 1] = '\0';
	last_slash = strrchr(dir_path, '/');
	if (last_slash) {
		*last_slash = '\0';
		if (stat(dir_path, &st) != 0) {
			if (mkdir(dir_path, 0755) != 0 && errno != EEXIST) {
				RS_LOG_ERROR("Failed to create %s: %s", dir_path, strerror(errno));
				return -1;
			}
		}
	}

	f = fopen(state_path, "w");
	if (!f) {
		RS_LOG_ERROR("Failed to open %s for writing: %s", state_path, strerror(errno));
		return -1;
	}

	fprintf(f, "{\n");
	fprintf(f, "  \"timestamp\": %llu,\n", (unsigned long long)time(NULL));

	if (mgmtd_maps_ensure() != 0) {
		fprintf(f, "  \"acls\": [],\n");
		fprintf(f, "  \"vlans\": [],\n");
		fprintf(f, "  \"routes\": []\n");
		fprintf(f, "}\n");
		fclose(f);
		return 0;
	}

	fprintf(f, "  \"acl_config\": {\n");
	if (g_maps.acl_config_fd >= 0) {
		struct acl_config cfg;
		__u32 key = 0;
		if (bpf_map_lookup_elem(g_maps.acl_config_fd, &key, &cfg) == 0) {
			fprintf(f, "    \"enabled\": %s,\n", cfg.enabled ? "true" : "false");
			fprintf(f, "    \"default_action\": %d,\n", cfg.default_action);
			fprintf(f, "    \"log_drops\": %s\n", cfg.log_drops ? "true" : "false");
		} else {
			fprintf(f, "    \"enabled\": false\n");
		}
	} else {
		fprintf(f, "    \"enabled\": false\n");
	}
	fprintf(f, "  },\n");

	fprintf(f, "  \"acls\": [\n");
	first = 1;

	if (g_maps.acl_5tuple_fd >= 0) {
		struct acl_5tuple_key k, nk;
		struct acl_result res;
		int has_prev = 0;
		memset(&k, 0, sizeof(k));
		while (bpf_map_get_next_key(g_maps.acl_5tuple_fd, has_prev ? &k : NULL, &nk) == 0) {
			if (bpf_map_lookup_elem(g_maps.acl_5tuple_fd, &nk, &res) == 0) {
				char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
				struct in_addr sa, da;
				sa.s_addr = nk.src_ip;
				da.s_addr = nk.dst_ip;
				inet_ntop(AF_INET, &sa, src, sizeof(src));
				inet_ntop(AF_INET, &da, dst, sizeof(dst));
			fprintf(f, "%s    {\"type\": \"5tuple\", \"proto\": %u, \"src_ip\": \"%s\", "
				"\"src_port\": %u, \"dst_ip\": \"%s\", \"dst_port\": %u, \"action\": %u, \"priority\": %u, \"id\": %u}\n",
				first ? "" : ",", nk.proto, src, ntohs(nk.sport), dst, ntohs(nk.dport), res.action, res.priority, res.rule_id);
				first = 0;
			}
			k = nk;
			has_prev = 1;
		}
	}

	if (g_maps.acl_pdp_fd >= 0) {
		struct acl_proto_dstip_port_key k, nk;
		struct acl_result res;
		int has_prev = 0;
		memset(&k, 0, sizeof(k));
		while (bpf_map_get_next_key(g_maps.acl_pdp_fd, has_prev ? &k : NULL, &nk) == 0) {
			if (bpf_map_lookup_elem(g_maps.acl_pdp_fd, &nk, &res) == 0) {
				char dst[INET_ADDRSTRLEN];
				struct in_addr da;
				da.s_addr = nk.dst_ip;
				inet_ntop(AF_INET, &da, dst, sizeof(dst));
			fprintf(f, "%s    {\"type\": \"proto_dst\", \"proto\": %u, \"dst_ip\": \"%s\", "
				"\"dst_port\": %u, \"action\": %u, \"priority\": %u, \"id\": %u}\n",
				first ? "" : ",", nk.proto, dst, ntohs(nk.dst_port), res.action, res.priority, res.rule_id);
				first = 0;
			}
			k = nk;
			has_prev = 1;
		}
	}

	if (g_maps.acl_psp_fd >= 0) {
		struct acl_proto_srcip_port_key k, nk;
		struct acl_result res;
		int has_prev = 0;
		memset(&k, 0, sizeof(k));
		while (bpf_map_get_next_key(g_maps.acl_psp_fd, has_prev ? &k : NULL, &nk) == 0) {
			if (bpf_map_lookup_elem(g_maps.acl_psp_fd, &nk, &res) == 0) {
				char src[INET_ADDRSTRLEN];
				struct in_addr sa;
				sa.s_addr = nk.src_ip;
				inet_ntop(AF_INET, &sa, src, sizeof(src));
			fprintf(f, "%s    {\"type\": \"proto_src\", \"proto\": %u, \"src_ip\": \"%s\", "
				"\"dst_port\": %u, \"action\": %u, \"priority\": %u, \"id\": %u}\n",
				first ? "" : ",", nk.proto, src, ntohs(nk.dst_port), res.action, res.priority, res.rule_id);
				first = 0;
			}
			k = nk;
			has_prev = 1;
		}
	}

	if (g_maps.acl_pp_fd >= 0) {
		struct acl_proto_port_key k, nk;
		struct acl_result res;
		int has_prev = 0;
		memset(&k, 0, sizeof(k));
		while (bpf_map_get_next_key(g_maps.acl_pp_fd, has_prev ? &k : NULL, &nk) == 0) {
			if (bpf_map_lookup_elem(g_maps.acl_pp_fd, &nk, &res) == 0) {
			fprintf(f, "%s    {\"type\": \"proto_port\", \"proto\": %u, \"dst_port\": %u, \"action\": %u, \"priority\": %u, \"id\": %u}\n",
				first ? "" : ",", nk.proto, ntohs(nk.dst_port), res.action, res.priority, res.rule_id);
				first = 0;
			}
			k = nk;
			has_prev = 1;
		}
	}

	if (g_maps.acl_lpm_src_fd >= 0) {
		struct lpm_key k, nk;
		struct acl_lpm_value val;
		int has_prev = 0;
		memset(&k, 0, sizeof(k));
		while (bpf_map_get_next_key(g_maps.acl_lpm_src_fd, has_prev ? &k : NULL, &nk) == 0) {
			if (bpf_map_lookup_elem(g_maps.acl_lpm_src_fd, &nk, &val) == 0) {
				char src[INET_ADDRSTRLEN];
				char dst[INET_ADDRSTRLEN];
				struct in_addr sa, da;
				sa.s_addr = nk.addr;
				inet_ntop(AF_INET, &sa, src, sizeof(src));
				if (val.other_ip != 0) {
					da.s_addr = val.other_ip;
					inet_ntop(AF_INET, &da, dst, sizeof(dst));
				} else {
					strcpy(dst, "any");
				}
			fprintf(f, "%s    {\"type\": \"lpm_src\", \"src_ip\": \"%s\", \"prefix_len\": %u, "
				"\"dst_ip\": \"%s\", \"proto\": %u, \"src_port\": %u, \"dst_port\": %u, \"action\": %u, \"priority\": %u, \"id\": %u}\n",
				first ? "" : ",", src, nk.prefixlen,
				dst, val.proto, ntohs(val.sport), ntohs(val.dport), val.action, val.priority, val.rule_id);
				first = 0;
			}
			k = nk;
			has_prev = 1;
		}
	}

	if (g_maps.acl_lpm_dst_fd >= 0) {
		struct lpm_key k, nk;
		struct acl_lpm_value val;
		int has_prev = 0;
		memset(&k, 0, sizeof(k));
		while (bpf_map_get_next_key(g_maps.acl_lpm_dst_fd, has_prev ? &k : NULL, &nk) == 0) {
			if (bpf_map_lookup_elem(g_maps.acl_lpm_dst_fd, &nk, &val) == 0) {
				char src[INET_ADDRSTRLEN];
				char dst[INET_ADDRSTRLEN];
				struct in_addr sa, da;
				da.s_addr = nk.addr;
				inet_ntop(AF_INET, &da, dst, sizeof(dst));
				if (val.other_ip != 0) {
					sa.s_addr = val.other_ip;
					inet_ntop(AF_INET, &sa, src, sizeof(src));
				} else {
					strcpy(src, "any");
				}
			fprintf(f, "%s    {\"type\": \"lpm_dst\", \"dst_ip\": \"%s\", \"prefix_len\": %u, "
				"\"src_ip\": \"%s\", \"proto\": %u, \"src_port\": %u, \"dst_port\": %u, \"action\": %u, \"priority\": %u, \"id\": %u}\n",
				first ? "" : ",", dst, nk.prefixlen,
				src, val.proto, ntohs(val.sport), ntohs(val.dport), val.action, val.priority, val.rule_id);
				first = 0;
			}
			k = nk;
			has_prev = 1;
		}
	}
	fprintf(f, "  ],\n");

	fprintf(f, "  \"vlans\": [\n");
	first = 1;
	if (g_maps.vlan_fd >= 0) {
		__u16 vlan_id = 0, next_vlan;
		struct rs_vlan_members v;
		while (bpf_map_get_next_key(g_maps.vlan_fd, &vlan_id, &next_vlan) == 0) {
			if (bpf_map_lookup_elem(g_maps.vlan_fd, &next_vlan, &v) == 0) {
				fprintf(f, "%s    {\"vlan_id\": %u, \"member_count\": %u}\n",
					first ? "" : ",", v.vlan_id, v.member_count);
				first = 0;
			}
			vlan_id = next_vlan;
		}
	}
	fprintf(f, "  ],\n");

	fprintf(f, "  \"routes\": [\n");
	first = 1;
	if (g_maps.route_tbl_fd >= 0) {
		struct lpm_key rk, nk;
		struct route_entry re;
		int has_prev = 0;
		memset(&rk, 0, sizeof(rk));
		while (bpf_map_get_next_key(g_maps.route_tbl_fd, has_prev ? &rk : NULL, &nk) == 0) {
			if (bpf_map_lookup_elem(g_maps.route_tbl_fd, &nk, &re) == 0) {
				char dst[INET_ADDRSTRLEN], gw[INET_ADDRSTRLEN];
				struct in_addr da, ga;
				da.s_addr = nk.addr;
				ga.s_addr = re.nexthop;
				inet_ntop(AF_INET, &da, dst, sizeof(dst));
				inet_ntop(AF_INET, &ga, gw, sizeof(gw));
				fprintf(f, "%s    {\"prefix\": \"%s\", \"prefix_len\": %u, \"nexthop\": \"%s\", \"ifindex\": %u}\n",
					first ? "" : ",", dst, nk.prefixlen, gw, re.ifindex);
				first = 0;
			}
			rk = nk;
			has_prev = 1;
		}
	}
	fprintf(f, "  ]\n");

	fprintf(f, "}\n");

	if (fclose(f) != 0) {
		RS_LOG_ERROR("Failed to close %s: %s", state_path, strerror(errno));
		return -1;
	}

	RS_LOG_INFO("Saved running state to %s", state_path);
	return 0;
}

static void handle_config_save(struct mg_connection *c, struct mg_http_message *hm, void *userdata)
{
	char state_path[PATH_MAX];

	(void) hm;
	(void) userdata;

	get_state_file_path(state_path, sizeof(state_path));

	if (save_running_state_to_file() != 0) {
		json_printf(c, 500, "{\"error\":\"failed to save running config\"}");
		return;
	}

	mgmtd_audit_log(AUDIT_SEV_INFO, AUDIT_CAT_CONFIG, "config_save", 1, "path=%s", state_path);
	json_printf(c, 200, "{\"status\":\"saved\",\"path\":\"%s\"}", state_path);
}

static int apply_acl_from_json(const char *type, __u8 proto, const char *src_ip_str,
			       __u16 src_port, const char *dst_ip_str, __u16 dst_port,
			       __u8 action, __u32 prefix_len, __u8 priority, __u32 rule_id)
{
	struct acl_result res;
	struct in_addr addr;
	__u32 src_ip = 0, dst_ip = 0;

	memset(&res, 0, sizeof(res));
	res.action = action;
	res.priority = priority;
	res.rule_id = rule_id ? rule_id : acl_next_rule_id();

	if (src_ip_str && src_ip_str[0] && strcmp(src_ip_str, "any") != 0)
		if (inet_pton(AF_INET, src_ip_str, &addr) == 1)
			src_ip = addr.s_addr;

	if (dst_ip_str && dst_ip_str[0] && strcmp(dst_ip_str, "any") != 0)
		if (inet_pton(AF_INET, dst_ip_str, &addr) == 1)
			dst_ip = addr.s_addr;

	if (strcmp(type, "5tuple") == 0) {
		struct acl_5tuple_key key;
		memset(&key, 0, sizeof(key));
		key.proto = proto;
		key.src_ip = src_ip;
		key.dst_ip = dst_ip;
		key.sport = htons(src_port);
		key.dport = htons(dst_port);
		if (g_maps.acl_5tuple_fd >= 0)
			return bpf_map_update_elem(g_maps.acl_5tuple_fd, &key, &res, BPF_ANY);
	} else if (strcmp(type, "proto_dst") == 0) {
		struct acl_proto_dstip_port_key key;
		memset(&key, 0, sizeof(key));
		key.proto = proto;
		key.dst_ip = dst_ip;
		key.dst_port = htons(dst_port);
		if (g_maps.acl_pdp_fd >= 0)
			return bpf_map_update_elem(g_maps.acl_pdp_fd, &key, &res, BPF_ANY);
	} else if (strcmp(type, "proto_src") == 0) {
		struct acl_proto_srcip_port_key key;
		memset(&key, 0, sizeof(key));
		key.proto = proto;
		key.src_ip = src_ip;
		key.dst_port = htons(dst_port);
		if (g_maps.acl_psp_fd >= 0)
			return bpf_map_update_elem(g_maps.acl_psp_fd, &key, &res, BPF_ANY);
	} else if (strcmp(type, "proto_port") == 0) {
		struct acl_proto_port_key key;
		memset(&key, 0, sizeof(key));
		key.proto = proto;
		key.dst_port = htons(dst_port);
		if (g_maps.acl_pp_fd >= 0)
			return bpf_map_update_elem(g_maps.acl_pp_fd, &key, &res, BPF_ANY);
	} else if (strcmp(type, "lpm_src") == 0) {
		struct lpm_key key;
		struct acl_lpm_value lpm_val;
		memset(&key, 0, sizeof(key));
		memset(&lpm_val, 0, sizeof(lpm_val));
		key.prefixlen = prefix_len;
		key.addr = src_ip;
		lpm_val.action = res.action;
		lpm_val.log_event = res.log_event;
		lpm_val.redirect_ifindex = res.redirect_ifindex;
		lpm_val.rule_id = res.rule_id;
		lpm_val.priority = res.priority;
		lpm_val.other_ip = dst_ip;
		lpm_val.proto = proto;
		lpm_val.sport = htons(src_port);
		lpm_val.dport = htons(dst_port);
		if (g_maps.acl_lpm_src_fd >= 0)
			return bpf_map_update_elem(g_maps.acl_lpm_src_fd, &key, &lpm_val, BPF_ANY);
	} else if (strcmp(type, "lpm_dst") == 0) {
		struct lpm_key key;
		struct acl_lpm_value lpm_val;
		memset(&key, 0, sizeof(key));
		memset(&lpm_val, 0, sizeof(lpm_val));
		key.prefixlen = prefix_len;
		key.addr = dst_ip;
		lpm_val.action = res.action;
		lpm_val.log_event = res.log_event;
		lpm_val.redirect_ifindex = res.redirect_ifindex;
		lpm_val.rule_id = res.rule_id;
		lpm_val.priority = res.priority;
		lpm_val.other_ip = src_ip;
		lpm_val.proto = proto;
		lpm_val.sport = htons(src_port);
		lpm_val.dport = htons(dst_port);
		if (g_maps.acl_lpm_dst_fd >= 0)
			return bpf_map_update_elem(g_maps.acl_lpm_dst_fd, &key, &lpm_val, BPF_ANY);
	}
	return -1;
}

static int load_state_from_file(void)
{
	char state_path[PATH_MAX];
	FILE *f;
	char *buf;
	long fsize;
	struct mg_str json;
	int acl_count = 0;
	int i, n;

	get_state_file_path(state_path, sizeof(state_path));

	f = fopen(state_path, "r");
	if (!f) {
		RS_LOG_INFO("No state file found at %s, starting fresh", state_path);
		return 0;
	}

	fseek(f, 0, SEEK_END);
	fsize = ftell(f);
	fseek(f, 0, SEEK_SET);

	if (fsize <= 0 || fsize > 1024 * 1024) {
		fclose(f);
		RS_LOG_WARN("State file %s has invalid size %ld", state_path, fsize);
		return -1;
	}

	buf = malloc((size_t)fsize + 1);
	if (!buf) {
		fclose(f);
		return -1;
	}

	if (fread(buf, 1, (size_t)fsize, f) != (size_t)fsize) {
		free(buf);
		fclose(f);
		return -1;
	}
	buf[fsize] = '\0';
	fclose(f);

	json.buf = buf;
	json.len = (size_t)fsize;

	if (mgmtd_maps_ensure() != 0) {
		RS_LOG_WARN("BPF maps not available, cannot restore state");
		free(buf);
		return -1;
	}

	n = 0;
	for (i = 0; ; i++) {
		char path[64];
		char *type_str, *src_ip_str, *dst_ip_str;
		long proto_l, src_port_l, dst_port_l, action_l, prefix_len_l, priority_l, id_l;

		snprintf(path, sizeof(path), "$.acls[%d].type", i);
		type_str = mg_json_get_str(json, path);
		if (!type_str)
			break;

		snprintf(path, sizeof(path), "$.acls[%d].proto", i);
		proto_l = mg_json_get_long(json, path, 0);

		snprintf(path, sizeof(path), "$.acls[%d].src_ip", i);
		src_ip_str = mg_json_get_str(json, path);

		snprintf(path, sizeof(path), "$.acls[%d].src_port", i);
		src_port_l = mg_json_get_long(json, path, 0);

		snprintf(path, sizeof(path), "$.acls[%d].dst_ip", i);
		dst_ip_str = mg_json_get_str(json, path);

		snprintf(path, sizeof(path), "$.acls[%d].dst_port", i);
		dst_port_l = mg_json_get_long(json, path, 0);

		snprintf(path, sizeof(path), "$.acls[%d].action", i);
		action_l = mg_json_get_long(json, path, 0);

		snprintf(path, sizeof(path), "$.acls[%d].prefix_len", i);
		prefix_len_l = mg_json_get_long(json, path, 32);

		snprintf(path, sizeof(path), "$.acls[%d].priority", i);
		priority_l = mg_json_get_long(json, path, 0);

		snprintf(path, sizeof(path), "$.acls[%d].id", i);
		id_l = mg_json_get_long(json, path, 0);

		if (apply_acl_from_json(type_str, (__u8)proto_l,
					src_ip_str, (__u16)src_port_l,
					dst_ip_str, (__u16)dst_port_l,
					(__u8)action_l, (__u32)prefix_len_l,
					(__u8)priority_l, (__u32)id_l) == 0) {
			n++;
		}

		free(type_str);
		free(src_ip_str);
		free(dst_ip_str);
	}
	acl_count = n;

	/*
	 * If ACL rules were restored, auto-enable ACL enforcement.
	 * This fixes the case where state file has rules but enabled=false
	 * (e.g., user deleted all rules, state saved, then added rules via API
	 * but mgmtd restarted before state was saved again).
	 * Having rules without enforcement enabled is never the desired state.
	 */
	if (acl_count > 0 && g_maps.acl_config_fd >= 0) {
		struct acl_config cfg;
		__u32 key = 0;

		if (bpf_map_lookup_elem(g_maps.acl_config_fd, &key, &cfg) == 0) {
			if (!cfg.enabled) {
				RS_LOG_INFO("Auto-enabling ACL (restored %d rules)", acl_count);
			}
			cfg.enabled = 1;
			bpf_map_update_elem(g_maps.acl_config_fd, &key, &cfg, BPF_ANY);
		}
	}

	RS_LOG_INFO("Restored %d ACL rules from %s", acl_count, state_path);
	free(buf);
	return 0;
}

static void handle_config_reset(struct mg_connection *c, struct mg_http_message *hm, void *userdata)
{
	char state_path[PATH_MAX];

	(void) hm;
	(void) userdata;

	get_state_file_path(state_path, sizeof(state_path));

	if (unlink(state_path) != 0 && errno != ENOENT) {
		json_printf(c, 500, "{\"error\":\"failed to delete state file: %s\"}", strerror(errno));
		return;
	}

	mgmtd_audit_log(AUDIT_SEV_WARNING, AUDIT_CAT_CONFIG, "config_reset", 1, "path=%s", state_path);
	json_printf(c, 200, "{\"status\":\"reset\",\"message\":\"State file deleted. Restart mgmtd to reload base profile.\"}");
}

static const char *proto_to_str(__u8 proto)
{
	switch (proto) {
	case 1: return "icmp";
	case 6: return "tcp";
	case 17: return "udp";
	default: return "any";
	}
}

static void handle_config_export(struct mg_connection *c, struct mg_http_message *hm, void *userdata)
{
	char *profile_name;
	char new_profile_path[PATH_MAX];
	FILE *f;
	time_t now;
	struct tm *tm_info;
	char time_str[64];
	int first;

	(void) userdata;

	profile_name = mg_json_get_str(hm->body, "$.name");
	if (!profile_name || profile_name[0] == '\0') {
		free(profile_name);
		json_printf(c, 400, "{\"error\":\"profile name required\"}");
		return;
	}

	if (!profile_name_valid(profile_name)) {
		free(profile_name);
		json_printf(c, 400, "{\"error\":\"invalid profile name\"}");
		return;
	}

	snprintf(new_profile_path, sizeof(new_profile_path), "%s%s", profile_dir(), profile_name);

	if (access(new_profile_path, F_OK) == 0) {
		free(profile_name);
		json_printf(c, 409, "{\"error\":\"profile already exists\"}");
		return;
	}

	f = fopen(new_profile_path, "w");
	if (!f) {
		free(profile_name);
		json_printf(c, 500, "{\"error\":\"failed to create profile: %s\"}", strerror(errno));
		return;
	}

	now = time(NULL);
	tm_info = localtime(&now);
	strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);

	fprintf(f, "# rSwitch Profile - exported from running config\n");
	fprintf(f, "# Exported: %s\n", time_str);
	if (g_ctx.profile_path[0])
		fprintf(f, "# Base profile: %s\n", g_ctx.profile_path);
	fprintf(f, "\n");

	fprintf(f, "name: %s\n", profile_name);
	fprintf(f, "version: \"1.0\"\n");
	fprintf(f, "description: Exported running configuration\n\n");

	if (g_ctx.profile_path[0]) {
		const char *base = strrchr(g_ctx.profile_path, '/');
		if (base)
			base++;
		else
			base = g_ctx.profile_path;
		fprintf(f, "extends: \"%s\"\n\n", base);
	}

	if (mgmtd_maps_ensure() == 0) {
		int has_acls = 0;

		if (g_maps.acl_5tuple_fd >= 0) {
			struct acl_5tuple_key k;
			memset(&k, 0, sizeof(k));
			if (bpf_map_get_next_key(g_maps.acl_5tuple_fd, NULL, &k) == 0)
				has_acls = 1;
		}
		if (!has_acls && g_maps.acl_pdp_fd >= 0) {
			struct acl_proto_dstip_port_key k;
			memset(&k, 0, sizeof(k));
			if (bpf_map_get_next_key(g_maps.acl_pdp_fd, NULL, &k) == 0)
				has_acls = 1;
		}
		if (!has_acls && g_maps.acl_psp_fd >= 0) {
			struct acl_proto_srcip_port_key k;
			memset(&k, 0, sizeof(k));
			if (bpf_map_get_next_key(g_maps.acl_psp_fd, NULL, &k) == 0)
				has_acls = 1;
		}
		if (!has_acls && g_maps.acl_pp_fd >= 0) {
			struct acl_proto_port_key k;
			memset(&k, 0, sizeof(k));
			if (bpf_map_get_next_key(g_maps.acl_pp_fd, NULL, &k) == 0)
				has_acls = 1;
		}

		if (has_acls) {
			fprintf(f, "acls:\n");
			first = 1;

			if (g_maps.acl_5tuple_fd >= 0) {
				struct acl_5tuple_key k, nk;
				struct acl_result res;
				int has_prev = 0;
				memset(&k, 0, sizeof(k));
				while (bpf_map_get_next_key(g_maps.acl_5tuple_fd,
							    has_prev ? &k : NULL, &nk) == 0) {
					if (bpf_map_lookup_elem(g_maps.acl_5tuple_fd, &nk, &res) == 0) {
						char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
						struct in_addr sa, da;
						sa.s_addr = nk.src_ip;
						da.s_addr = nk.dst_ip;
						inet_ntop(AF_INET, &sa, src, sizeof(src));
						inet_ntop(AF_INET, &da, dst, sizeof(dst));
						fprintf(f, "  - protocol: %s\n", proto_to_str(nk.proto));
						fprintf(f, "    src_ip: %s\n", src);
						fprintf(f, "    src_port: %u\n", ntohs(nk.sport));
						fprintf(f, "    dst_ip: %s\n", dst);
						fprintf(f, "    dst_port: %u\n", ntohs(nk.dport));
						fprintf(f, "    action: %s\n", res.action == 1 ? "deny" : "permit");
						first = 0;
					}
					k = nk;
					has_prev = 1;
				}
			}

			if (g_maps.acl_pdp_fd >= 0) {
				struct acl_proto_dstip_port_key k, nk;
				struct acl_result res;
				int has_prev = 0;
				memset(&k, 0, sizeof(k));
				while (bpf_map_get_next_key(g_maps.acl_pdp_fd,
							    has_prev ? &k : NULL, &nk) == 0) {
					if (bpf_map_lookup_elem(g_maps.acl_pdp_fd, &nk, &res) == 0) {
						char dst[INET_ADDRSTRLEN];
						struct in_addr da;
						da.s_addr = nk.dst_ip;
						inet_ntop(AF_INET, &da, dst, sizeof(dst));
						fprintf(f, "  - protocol: %s\n", proto_to_str(nk.proto));
						fprintf(f, "    dst_ip: %s\n", dst);
						fprintf(f, "    dst_port: %u\n", ntohs(nk.dst_port));
						fprintf(f, "    action: %s\n", res.action == 1 ? "deny" : "permit");
						first = 0;
					}
					k = nk;
					has_prev = 1;
				}
			}

			if (g_maps.acl_psp_fd >= 0) {
				struct acl_proto_srcip_port_key k, nk;
				struct acl_result res;
				int has_prev = 0;
				memset(&k, 0, sizeof(k));
				while (bpf_map_get_next_key(g_maps.acl_psp_fd,
							    has_prev ? &k : NULL, &nk) == 0) {
					if (bpf_map_lookup_elem(g_maps.acl_psp_fd, &nk, &res) == 0) {
						char src[INET_ADDRSTRLEN];
						struct in_addr sa;
						sa.s_addr = nk.src_ip;
						inet_ntop(AF_INET, &sa, src, sizeof(src));
						fprintf(f, "  - protocol: %s\n", proto_to_str(nk.proto));
						fprintf(f, "    src_ip: %s\n", src);
						fprintf(f, "    dst_port: %u\n", ntohs(nk.dst_port));
						fprintf(f, "    action: %s\n", res.action == 1 ? "deny" : "permit");
						first = 0;
					}
					k = nk;
					has_prev = 1;
				}
			}

			if (g_maps.acl_pp_fd >= 0) {
				struct acl_proto_port_key k, nk;
				struct acl_result res;
				int has_prev = 0;
				memset(&k, 0, sizeof(k));
				while (bpf_map_get_next_key(g_maps.acl_pp_fd,
							    has_prev ? &k : NULL, &nk) == 0) {
					if (bpf_map_lookup_elem(g_maps.acl_pp_fd, &nk, &res) == 0) {
						fprintf(f, "  - protocol: %s\n", proto_to_str(nk.proto));
						fprintf(f, "    dst_port: %u\n", ntohs(nk.dst_port));
						fprintf(f, "    action: %s\n", res.action == 1 ? "deny" : "permit");
						first = 0;
					}
					k = nk;
					has_prev = 1;
				}
			}
			fprintf(f, "\n");
		}
	}

	fclose(f);

	mgmtd_audit_log(AUDIT_SEV_INFO, AUDIT_CAT_PROFILE, "profile_export", 1,
			    "name=%s path=%s", profile_name, new_profile_path);
	json_printf(c, 201, "{\"status\":\"exported\",\"path\":\"%s\"}", new_profile_path);
	free(profile_name);
}

static void handle_config_snapshot_create(struct mg_connection *c, struct mg_http_message *hm, void *userdata)
{
	char *desc;

	(void) userdata;

	desc = mg_json_get_str(hm->body, "$.description");
	if (rs_rollback_create_snapshot(desc ? desc : "manual snapshot") != 0) {
		free(desc);
		json_printf(c, 500, "{\"error\":\"snapshot create failed\"}");
		return;
	}

	mgmtd_audit_log(AUDIT_SEV_INFO, AUDIT_CAT_CONFIG, "snapshot_create", 1,
			    "description=%s", desc ? desc : "manual snapshot");
	free(desc);
	json_printf(c, 201, "{\"status\":\"created\"}");
}

static void handle_config_rollback(struct mg_connection *c, struct mg_http_message *hm, void *userdata)
{
	struct mg_str snapshot = extract_name_from_uri(hm, "/api/config/rollback/");
	char id[64];

	(void) userdata;

	if (snapshot.len == 0 || snapshot.len >= sizeof(id)) {
		json_printf(c, 400, "{\"error\":\"invalid snapshot id\"}");
		return;
	}

	memcpy(id, snapshot.buf, snapshot.len);
	id[snapshot.len] = '\0';

	if (rs_rollback_to(id) != 0) {
		json_printf(c, 500, "{\"error\":\"rollback failed\"}");
		return;
	}

	mgmtd_audit_log(AUDIT_SEV_WARNING, AUDIT_CAT_CONFIG, "rollback", 1,
			    "snapshot=%s", id);
	json_printf(c, 200, "{\"status\":\"ok\",\"snapshot\":\"%s\"}", id);
}

static void handle_config_audit(struct mg_connection *c, struct mg_http_message *hm, void *userdata)
{
	struct rs_audit_entry entries[AUDIT_READ_MAX];
	int n;
	int i;
	char *out = malloc(131072);
	size_t out_sz = 131072;
	size_t off = 0;

	(void) hm;
	(void) userdata;

	if (!out) {
		mg_http_reply(c, 500, "Content-Type: application/json\r\n", "{\"error\":\"out of memory\"}\n");
		return;
	}

	n = rs_audit_read(entries, AUDIT_READ_MAX);
	if (n < 0) {
		json_printf(c, 500, "{\"error\":\"audit read failed\"}");
		free(out);
		return;
	}

	off += (size_t) snprintf(out + off, out_sz - off, "{\"audit\":[");
	for (i = 0; i < n; i++) {
		char esc_detail[1024];

		json_escape(entries[i].detail, esc_detail, sizeof(esc_detail));
		off += (size_t) snprintf(out + off, out_sz - off,
					 "%s{\"timestamp\":%llu,\"severity\":%d,\"category\":\"%s\","
					 "\"action\":\"%s\",\"user\":\"%s\",\"detail\":\"%s\","
					 "\"success\":%d}",
					 i ? "," : "",
					 (unsigned long long) entries[i].timestamp,
					 entries[i].severity,
					 entries[i].category,
					 entries[i].action,
					 entries[i].user,
					 esc_detail,
					 entries[i].success);
		if (off + 1024 >= out_sz)
			break;
	}

	snprintf(out + off, out_sz - off, "]}");
	json_printf(c, 200, "%s", out);
	free(out);
}

static void ws_timer_fn(void *arg)
{
	struct mg_mgr *mgr = arg;
	char payload[1024];
	uint64_t total_rx = 0;
	uint64_t total_tx = 0;
	int port_count;
	int module_count;
	int ws_clients;
	__u32 ifindex;

	if (!mgr)
		return;

	ws_clients = mgmtd_ws_client_count(mgr);
	if (ws_clients == 0)
		return;

	mgmtd_maps_ensure();

	for (ifindex = 0; ifindex < RS_MAX_INTERFACES; ifindex++) {
		struct rs_stats st;
		if (aggregate_port_stats(ifindex, &st) != 0)
			continue;
		total_rx += st.rx_packets;
		total_tx += st.tx_packets;
	}

	port_count = count_port_entries();
	module_count = count_module_entries();

	snprintf(payload, sizeof(payload),
		 "{\"type\":\"stats\",\"uptime\":%llu,\"port_count\":%d,"
		 "\"module_count\":%d,\"rx_total\":%llu,\"tx_total\":%llu}",
		 (unsigned long long) uptime_sec(),
		 port_count,
		 module_count,
		 (unsigned long long) total_rx,
		 (unsigned long long) total_tx);

	mgmtd_ws_broadcast(mgr, payload, strlen(payload));

	/* Health change detection */
	{
		struct rs_health_status hs;

		if (rs_watchdog_check_health(&hs) == 0) {
			if (g_prev_health >= 0 && hs.overall != g_prev_health) {
			const char *label_old = g_prev_health == 0 ? "healthy" :
						g_prev_health == 1 ? "degraded" : "critical";
			const char *label_new = hs.overall == 0 ? "healthy" :
						hs.overall == 1 ? "degraded" : "critical";
			int sev = hs.overall > g_prev_health ?
				  AUDIT_SEV_WARNING : AUDIT_SEV_INFO;

			if (hs.overall >= 2)
					sev = AUDIT_SEV_CRITICAL;

				snprintf(payload, sizeof(payload),
					 "health transitioned %s -> %s (score %d -> %d)",
					 label_old, label_new, g_prev_health, hs.overall);
				mgmtd_broadcast_event(sev, "system", "health_change",
						      payload);
			}
			g_prev_health = hs.overall;
		}
	}

	/* Port link-state change detection */
	if (g_maps.port_config_fd >= 0) {
		__u32 key, next;
		int idx = 0;

		if (bpf_map_get_next_key(g_maps.port_config_fd, NULL, &next) == 0) {
			do {
				struct rs_port_config p;

				if (bpf_map_lookup_elem(g_maps.port_config_fd, &next, &p) == 0 &&
				    idx < RS_MAX_INTERFACES) {
					char name[IF_NAMESIZE] = "unknown";
					char oper[32] = "unknown";
					int link_up;
					FILE *fp;
					char path[128];

					ifindex_to_name_sysfs(p.ifindex, name, sizeof(name));

					snprintf(path, sizeof(path),
						 "/sys/class/net/%s/operstate", name);
					fp = fopen(path, "r");
					if (fp) {
						if (fgets(oper, sizeof(oper), fp))
							oper[strcspn(oper, "\r\n")] = '\0';
						fclose(fp);
					}
					link_up = (strcmp(oper, "up") == 0) ? 1 : 0;

					if (g_port_links[idx].valid &&
					    g_port_links[idx].ifindex == p.ifindex &&
					    g_port_links[idx].link_up != link_up) {
						int sev = link_up ? AUDIT_SEV_INFO :
								    AUDIT_SEV_WARNING;

						snprintf(payload, sizeof(payload),
							 "%s (ifindex %u) link %s",
							 name, p.ifindex,
							 link_up ? "up" : "down");
						mgmtd_broadcast_event(sev, "port",
								      "link_change",
								      payload);
					}

					g_port_links[idx].ifindex = p.ifindex;
					strncpy(g_port_links[idx].name, name,
						sizeof(g_port_links[idx].name) - 1);
					g_port_links[idx].link_up = link_up;
					g_port_links[idx].valid = 1;
					idx++;
				}

				key = next;
			} while (bpf_map_get_next_key(g_maps.port_config_fd, &key, &next) == 0);
		}
		g_port_link_count = idx;
	}

	/* Periodic stats summary as event (every STATS_EVENT_INTERVAL polls) */
	g_stats_event_counter++;
	if (g_stats_event_counter >= STATS_EVENT_INTERVAL) {
		g_stats_event_counter = 0;
		snprintf(payload, sizeof(payload),
			 "ports=%d modules=%d rx=%llu tx=%llu uptime=%llus",
			 port_count, g_ctx.profile_module_count,
			 (unsigned long long) total_rx,
			 (unsigned long long) total_tx,
			 (unsigned long long) uptime_sec());
		mgmtd_broadcast_event(AUDIT_SEV_INFO, "stats", "summary", payload);
	}
}

static void handle_preflight(struct mg_connection *c)
{
	char cors[512];
	char hdrs[1024];
	snprintf(hdrs, sizeof(hdrs),
		 "%sAccess-Control-Max-Age: 86400\r\n",
		 cors_origin_header(cors, sizeof(cors)));
	mg_http_reply(c, 204, hdrs, "");
}

static void handle_dhcp_snoop_get(struct mg_connection *c, struct mg_http_message *hm,
				  void *userdata)
{
	char out[4096];
	size_t off = 0;

	(void) hm;
	(void) userdata;

	mgmtd_maps_ensure();

	int enabled = 0, drop_rogue = 0;
	if (g_maps.dhcp_snoop_config_fd >= 0) {
		__u32 key = 0;
		struct dhcp_snoop_config cfg;
		if (bpf_map_lookup_elem(g_maps.dhcp_snoop_config_fd, &key, &cfg) == 0) {
			enabled = cfg.enabled ? 1 : 0;
			drop_rogue = cfg.drop_rogue_server ? 1 : 0;
		}
	}

	off += (size_t) snprintf(out + off, sizeof(out) - off,
				 "{\"enabled\":%s,\"drop_rogue_server\":%s,"
				 "\"trusted_ports\":[",
				 enabled ? "true" : "false",
				 drop_rogue ? "true" : "false");

	int port_count = 0;
	if (g_maps.dhcp_trusted_ports_fd >= 0) {
		__u32 key = 0, next_key = 0;
		__u32 trusted = 0;
		int first_iter = 1;
		char ifname[IF_NAMESIZE] = {0};

		while (bpf_map_get_next_key(g_maps.dhcp_trusted_ports_fd,
					    first_iter ? NULL : &key, &next_key) == 0) {
			first_iter = 0;
			memset(ifname, 0, sizeof(ifname));
			if (bpf_map_lookup_elem(g_maps.dhcp_trusted_ports_fd,
						&next_key, &trusted) == 0 && trusted) {
				ifindex_to_name_sysfs(next_key, ifname, sizeof(ifname));
				off += (size_t) snprintf(out + off, sizeof(out) - off,
							 "%s{\"ifindex\":%u,\"name\":\"%s\"}",
							 port_count > 0 ? "," : "",
							 next_key,
							 ifname[0] ? ifname : "unknown");
				port_count++;
			}
			key = next_key;
			if (off + 256 >= sizeof(out))
				break;
		}
	}

	off += (size_t) snprintf(out + off, sizeof(out) - off,
				 "],\"trusted_port_count\":%d}", port_count);

	{
		char cors[512];
		char hdrs[1024];
		snprintf(hdrs, sizeof(hdrs),
			 "Content-Type: application/json\r\n%s",
			 cors_origin_header(cors, sizeof(cors)));
		mg_http_reply(c, 200, hdrs, "%.*s", (int) off, out);
	}
}

static void handle_dhcp_snoop_config_update(struct mg_connection *c, struct mg_http_message *hm,
					    void *userdata)
{
	(void) userdata;

	mgmtd_maps_ensure();

	if (g_maps.dhcp_snoop_config_fd < 0) {
		json_printf(c, 503, "{\"error\":\"dhcp_snoop_config_map not available\"}");
		return;
	}

	int enabled = -1, drop_rogue = -1;
	bool bval;
	if (mg_json_get_bool(hm->body, "$.enabled", &bval))
		enabled = bval ? 1 : 0;
	if (mg_json_get_bool(hm->body, "$.drop_rogue_server", &bval))
		drop_rogue = bval ? 1 : 0;

	__u32 key = 0;
	struct dhcp_snoop_config cfg = {0};
	bpf_map_lookup_elem(g_maps.dhcp_snoop_config_fd, &key, &cfg);

	if (enabled >= 0)
		cfg.enabled = (__u32) enabled;
	if (drop_rogue >= 0)
		cfg.drop_rogue_server = (__u32) drop_rogue;

	if (bpf_map_update_elem(g_maps.dhcp_snoop_config_fd, &key, &cfg, BPF_ANY) < 0) {
		json_printf(c, 500, "{\"error\":\"failed to update config: %s\"}", strerror(errno));
		return;
	}

	g_ctx.dhcp_snoop_enabled = cfg.enabled;
	g_ctx.dhcp_snoop_drop_rogue = cfg.drop_rogue_server;

	RS_LOG_INFO("DHCP snooping config updated: enabled=%u drop_rogue=%u",
		    cfg.enabled, cfg.drop_rogue_server);
	mgmtd_broadcast_event(AUDIT_SEV_INFO, "dhcp", "config_update",
			      cfg.enabled ? "DHCP snooping enabled" : "DHCP snooping disabled");

	json_printf(c, 200, "{\"ok\":true,\"enabled\":%s,\"drop_rogue_server\":%s}",
		    cfg.enabled ? "true" : "false",
		    cfg.drop_rogue_server ? "true" : "false");
}

static void sync_trusted_port_count(void)
{
	if (g_maps.dhcp_snoop_config_fd < 0 || g_maps.dhcp_trusted_ports_fd < 0)
		return;

	__u32 count = 0, key = 0, next_key;
	while (bpf_map_get_next_key(g_maps.dhcp_trusted_ports_fd,
				    count ? &key : NULL, &next_key) == 0) {
		key = next_key;
		count++;
	}

	__u32 cfg_key = 0;
	struct dhcp_snoop_config cfg = {0};
	bpf_map_lookup_elem(g_maps.dhcp_snoop_config_fd, &cfg_key, &cfg);
	cfg.trusted_port_count = count;
	bpf_map_update_elem(g_maps.dhcp_snoop_config_fd, &cfg_key, &cfg, BPF_ANY);
}

static void handle_dhcp_snoop_trusted_ports(struct mg_connection *c, struct mg_http_message *hm,
					    void *userdata)
{
	(void) userdata;

	mgmtd_maps_ensure();

	if (g_maps.dhcp_trusted_ports_fd < 0) {
		json_printf(c, 503, "{\"error\":\"dhcp_trusted_ports_map not available\"}");
		return;
	}

	char *action_str = mg_json_get_str(hm->body, "$.action");
	char *port_str = mg_json_get_str(hm->body, "$.port");
	if (!action_str || !port_str) {
		free(action_str);
		free(port_str);
		json_printf(c, 400,
			    "{\"error\":\"required: {action:'add'|'remove', port:'ifname'}\"}");
		return;
	}

	__u32 ifidx = resolve_ifindex(port_str);
	if (ifidx == 0) {
		json_printf(c, 404, "{\"error\":\"interface not found: %s\"}", port_str);
		free(action_str);
		free(port_str);
		return;
	}

	if (strcmp(action_str, "add") == 0) {
		__u32 trusted = 1;
		if (bpf_map_update_elem(g_maps.dhcp_trusted_ports_fd,
					&ifidx, &trusted, BPF_ANY) < 0) {
			json_printf(c, 500, "{\"error\":\"map update failed: %s\"}",
				    strerror(errno));
			free(action_str);
			free(port_str);
			return;
		}
		RS_LOG_INFO("DHCP trusted port added: %s (ifindex=%u)", port_str, ifidx);
		mgmtd_broadcast_event(AUDIT_SEV_INFO, "dhcp", "trusted_port_add", port_str);
		sync_trusted_port_count();
	} else if (strcmp(action_str, "remove") == 0) {
		if (bpf_map_delete_elem(g_maps.dhcp_trusted_ports_fd, &ifidx) < 0 &&
		    errno != ENOENT) {
			json_printf(c, 500, "{\"error\":\"map delete failed: %s\"}",
				    strerror(errno));
			free(action_str);
			free(port_str);
			return;
		}
		RS_LOG_INFO("DHCP trusted port removed: %s (ifindex=%u)", port_str, ifidx);
		mgmtd_broadcast_event(AUDIT_SEV_INFO, "dhcp", "trusted_port_remove", port_str);
		sync_trusted_port_count();
	} else {
		json_printf(c, 400, "{\"error\":\"action must be 'add' or 'remove'\"}");
		free(action_str);
		free(port_str);
		return;
	}

	free(action_str);
	free(port_str);
	json_printf(c, 200, "{\"ok\":true}");
}

static void handle_api_events(struct mg_connection *c, struct mg_http_message *hm)
{
	char severity[32] = {0}, category[32] = {0}, search[128] = {0};
	char before_s[32] = {0}, after_s[32] = {0}, limit_s[16] = {0};
	int64_t before = 0, after = 0;
	int limit = 200;
	struct event_row *rows;
	int count, total;
	char *buf;
	int off, bufsz;

	mg_http_get_var(&hm->query, "severity", severity, sizeof(severity));
	mg_http_get_var(&hm->query, "category", category, sizeof(category));
	mg_http_get_var(&hm->query, "search", search, sizeof(search));
	mg_http_get_var(&hm->query, "before", before_s, sizeof(before_s));
	mg_http_get_var(&hm->query, "after", after_s, sizeof(after_s));
	mg_http_get_var(&hm->query, "limit", limit_s, sizeof(limit_s));

	if (before_s[0])
		before = strtoll(before_s, NULL, 10);
	if (after_s[0])
		after = strtoll(after_s, NULL, 10);
	if (limit_s[0]) {
		limit = atoi(limit_s);
		if (limit <= 0 || limit > 1000)
			limit = 200;
	}

	rows = calloc(limit, sizeof(*rows));
	if (!rows) {
		json_printf(c, 500, "{\"error\":\"out of memory\"}");
		return;
	}

	count = event_db_query(rows, limit,
			       severity[0] ? severity : NULL,
			       category[0] ? category : NULL,
			       before, after,
			       search[0] ? search : NULL,
			       limit);
	total = event_db_count();

	if (count < 0)
		count = 0;

	bufsz = 256 + count * 700;
	buf = malloc(bufsz);
	if (!buf) {
		free(rows);
		json_printf(c, 500, "{\"error\":\"out of memory\"}");
		return;
	}

	off = snprintf(buf, bufsz, "{\"events\":[");
	for (int i = 0; i < count; i++) {
		/* JSON-escape message — escape quotes and backslashes */
		char escaped[1024];
		int ej = 0;
		for (int k = 0; rows[i].message[k] && ej < (int)sizeof(escaped) - 2; k++) {
			char ch = rows[i].message[k];
			if (ch == '"' || ch == '\\') {
				escaped[ej++] = '\\';
			}
			escaped[ej++] = ch;
		}
		escaped[ej] = '\0';

		off += snprintf(buf + off, bufsz - off,
				"%s{\"id\":%lld,\"timestamp\":%lld,"
				"\"severity\":\"%s\",\"category\":\"%s\","
				"\"message\":\"%s\"}",
				i > 0 ? "," : "",
				(long long)rows[i].id,
				(long long)rows[i].timestamp,
				rows[i].severity,
				rows[i].category,
				escaped);
	}
	off += snprintf(buf + off, bufsz - off, "],\"total\":%d}", total);

	{
		char cors[512];
		char hdrs[1024];
		snprintf(hdrs, sizeof(hdrs),
			 "Content-Type: application/json\r\n%s",
			 cors_origin_header(cors, sizeof(cors)));
		mg_http_reply(c, 200, hdrs, "%s", buf);
	}

	free(buf);
	free(rows);
}

static bool method_is(struct mg_str method, const char *s)
{
	return mg_strcmp(method, mg_str(s)) == 0;
}

static void dispatch_api(struct mg_connection *c, struct mg_http_message *hm, void *userdata)
{
	if (method_is(hm->method, "POST") && mg_match(hm->uri, mg_str("/api/auth/login"), NULL))
		return handle_auth_login(c, hm);

	if (method_is(hm->method, "POST") && mg_match(hm->uri, mg_str("/api/auth/logout"), NULL)) {
		if (!check_auth(c, hm))
			return;
		return handle_auth_logout(c, hm);
	}

	if (!check_auth(c, hm))
		return;

	if (method_is(hm->method, "GET") && mg_match(hm->uri, mg_str("/api/system/info"), NULL))
		return handle_system_info(c, hm, userdata);
	if (method_is(hm->method, "GET") && mg_match(hm->uri, mg_str("/api/system/health"), NULL))
		return handle_system_health(c, hm, userdata);
	if (method_is(hm->method, "POST") && mg_match(hm->uri, mg_str("/api/system/reboot"), NULL))
		return handle_system_reboot(c, hm, userdata);
	if (method_is(hm->method, "POST") && mg_match(hm->uri, mg_str("/api/system/shutdown"), NULL))
		return handle_system_shutdown(c, hm, userdata);
	if (method_is(hm->method, "GET") && mg_match(hm->uri, mg_str("/api/system/network"), NULL))
		return handle_network_get(c, hm, userdata);
	if (method_is(hm->method, "PUT") && mg_match(hm->uri, mg_str("/api/system/network"), NULL))
		return handle_network_put(c, hm, userdata);

	if (method_is(hm->method, "GET") && mg_match(hm->uri, mg_str("/api/ports"), NULL))
		return handle_ports_list(c, hm, userdata);
	if (method_is(hm->method, "GET") && mg_match(hm->uri, mg_str("/api/ports/#/stats"), NULL))
		return handle_port_stats(c, hm, userdata);
	if (method_is(hm->method, "PUT") && mg_match(hm->uri, mg_str("/api/ports/#/config"), NULL))
		return handle_port_config_update(c, hm, userdata);

	if (method_is(hm->method, "GET") && mg_match(hm->uri, mg_str("/api/modules"), NULL))
		return handle_modules_list(c, hm, userdata);
	if (method_is(hm->method, "GET") && mg_match(hm->uri, mg_str("/api/modules/#/stats"), NULL))
		return handle_module_stats(c, hm, userdata);
	if (method_is(hm->method, "POST") && mg_match(hm->uri, mg_str("/api/modules/#/reload"), NULL))
		return handle_module_reload(c, hm, userdata);
	if (method_is(hm->method, "PUT") && mg_match(hm->uri, mg_str("/api/modules/#/config"), NULL))
		return handle_module_config_update(c, hm, userdata);

	if (method_is(hm->method, "GET") && mg_match(hm->uri, mg_str("/api/vlans"), NULL))
		return handle_vlans_list(c, hm, userdata);
	if (method_is(hm->method, "POST") && mg_match(hm->uri, mg_str("/api/vlans"), NULL))
		return handle_vlan_create(c, hm, userdata);
	if (method_is(hm->method, "PUT") && mg_match(hm->uri, mg_str("/api/vlans/#"), NULL))
		return handle_vlan_update(c, hm, userdata);
	if (method_is(hm->method, "DELETE") && mg_match(hm->uri, mg_str("/api/vlans/#"), NULL))
		return handle_vlan_delete(c, hm, userdata);

	if (method_is(hm->method, "GET") && mg_match(hm->uri, mg_str("/api/acls"), NULL))
		return handle_acls_list(c, hm, userdata);
	if (method_is(hm->method, "POST") && mg_match(hm->uri, mg_str("/api/acls"), NULL))
		return handle_acl_create(c, hm, userdata);
	if (method_is(hm->method, "PUT") && mg_match(hm->uri, mg_str("/api/acls/#"), NULL))
		return handle_acl_update(c, hm, userdata);
	if (method_is(hm->method, "DELETE") && mg_match(hm->uri, mg_str("/api/acls/#"), NULL))
		return handle_acl_delete(c, hm, userdata);

	if (method_is(hm->method, "GET") && mg_match(hm->uri, mg_str("/api/routes"), NULL))
		return handle_routes_list(c, hm, userdata);
	if (method_is(hm->method, "POST") && mg_match(hm->uri, mg_str("/api/routes"), NULL))
		return handle_route_add(c, hm, userdata);
	if (method_is(hm->method, "DELETE") && mg_match(hm->uri, mg_str("/api/routes/#"), NULL))
		return handle_route_delete(c, hm, userdata);

	if (method_is(hm->method, "GET") && mg_match(hm->uri, mg_str("/api/nat/rules"), NULL))
		return handle_nat_rules(c, hm, userdata);
	if (method_is(hm->method, "POST") && mg_match(hm->uri, mg_str("/api/nat/rules"), NULL))
		return handle_nat_add(c, hm, userdata);
	if (method_is(hm->method, "GET") && mg_match(hm->uri, mg_str("/api/nat/conntrack"), NULL))
		return handle_nat_conntrack(c, hm, userdata);

	if (method_is(hm->method, "GET") && mg_match(hm->uri, mg_str("/api/profiles"), NULL))
		return handle_profiles_list(c, hm, userdata);
	if (method_is(hm->method, "GET") && mg_match(hm->uri, mg_str("/api/profiles/active"), NULL))
		return handle_profiles_active(c, hm, userdata);
	if (method_is(hm->method, "POST") && mg_match(hm->uri, mg_str("/api/profiles/apply"), NULL))
		return handle_profiles_apply(c, hm, userdata);
	if (method_is(hm->method, "GET") && mg_match(hm->uri, mg_str("/api/profiles/#"), NULL))
		return handle_profile_read(c, hm, userdata);
	if (method_is(hm->method, "PUT") && mg_match(hm->uri, mg_str("/api/profiles/#"), NULL))
		return handle_profile_save(c, hm, userdata);
	if (method_is(hm->method, "DELETE") && mg_match(hm->uri, mg_str("/api/profiles/#"), NULL))
		return handle_profile_delete(c, hm, userdata);

	if (method_is(hm->method, "GET") && mg_match(hm->uri, mg_str("/api/topology"), NULL))
		return handle_topology(c, hm, userdata);

	if (method_is(hm->method, "GET") && mg_match(hm->uri, mg_str("/api/config/snapshots"), NULL))
		return handle_config_snapshots(c, hm, userdata);
	if (method_is(hm->method, "POST") && mg_match(hm->uri, mg_str("/api/config/save"), NULL))
		return handle_config_save(c, hm, userdata);
	if (method_is(hm->method, "POST") && mg_match(hm->uri, mg_str("/api/config/reset"), NULL))
		return handle_config_reset(c, hm, userdata);
	if (method_is(hm->method, "POST") && mg_match(hm->uri, mg_str("/api/config/export"), NULL))
		return handle_config_export(c, hm, userdata);
	if (method_is(hm->method, "POST") && mg_match(hm->uri, mg_str("/api/config/snapshot"), NULL))
		return handle_config_snapshot_create(c, hm, userdata);
	if (method_is(hm->method, "POST") && mg_match(hm->uri, mg_str("/api/config/rollback/#"), NULL))
		return handle_config_rollback(c, hm, userdata);
	if (method_is(hm->method, "GET") && mg_match(hm->uri, mg_str("/api/config/audit"), NULL))
		return handle_config_audit(c, hm, userdata);

	if (method_is(hm->method, "GET") && mg_match(hm->uri, mg_str("/api/events"), NULL))
		return handle_api_events(c, hm);

	if (method_is(hm->method, "GET") && mg_match(hm->uri, mg_str("/api/dhcp-snooping"), NULL))
		return handle_dhcp_snoop_get(c, hm, userdata);
	if (method_is(hm->method, "POST") && mg_match(hm->uri, mg_str("/api/dhcp-snooping/config"), NULL))
		return handle_dhcp_snoop_config_update(c, hm, userdata);
	if (method_is(hm->method, "POST") && mg_match(hm->uri, mg_str("/api/dhcp-snooping/trusted-ports"), NULL))
		return handle_dhcp_snoop_trusted_ports(c, hm, userdata);

	json_printf(c, 404, "{\"error\":\"route not found\"}");
}

static void ev_handler(struct mg_connection *c, int ev, void *ev_data)
{
	struct mg_http_serve_opts opts;
	struct mg_http_message *hm;
	struct mgmtd_ctx *ctx = c ? c->fn_data : NULL;

	if (!ctx)
		ctx = &g_ctx;

	if (ev == MG_EV_HTTP_MSG) {
		hm = ev_data;

		if (method_is(hm->method, "OPTIONS")) {
			handle_preflight(c);
			return;
		}

		if (mg_match(hm->uri, mg_str("/api/ws"), NULL)) {
			if (!check_auth(c, hm)) {
				RS_LOG_INFO("WebSocket auth rejected id=%lu", c->id);
				return;
			}
			mg_ws_upgrade(c, hm, NULL);
			c->data[0] = 'W';
			RS_LOG_INFO("WebSocket client upgraded id=%lu", c->id);
			/* Send a welcome event so the client sees something immediately */
			{
				char welcome[256];
				struct timespec wts;
				clock_gettime(CLOCK_REALTIME, &wts);
				snprintf(welcome, sizeof(welcome),
					 "{\"type\":\"event\",\"severity\":\"info\","
					 "\"category\":\"system\","
					 "\"message\":\"[system] connected: WebSocket stream active\","
					 "\"timestamp\":%llu}",
					 (unsigned long long)wts.tv_sec);
				mg_ws_send(c, welcome, strlen(welcome),
					   WEBSOCKET_OP_TEXT);
			}
			return;
		}

		if (mg_match(hm->uri, mg_str("/api/#"), NULL) || mg_match(hm->uri, mg_str("/api"), NULL)) {
			dispatch_api(c, hm, ctx);
			return;
		}

		memset(&opts, 0, sizeof(opts));
		opts.root_dir = ctx->cfg.web_root;
		{
			static char serve_hdrs[1024];
			char cors[512];
			snprintf(serve_hdrs, sizeof(serve_hdrs),
				 "%sCache-Control: no-cache\r\n",
				 cors_origin_header(cors, sizeof(cors)));
			opts.extra_headers = serve_hdrs;
		}
		mg_http_serve_dir(c, hm, &opts);
	} else if (ev == MG_EV_WS_MSG) {
		struct mg_ws_message *wm = ev_data;
		RS_LOG_INFO("WS msg from id=%lu len=%zu", c->id, wm ? wm->data.len : 0);
	}
}

static void print_usage(const char *prog)
{
	printf("Usage: %s [options]\n", prog);
	printf("Options:\n");
	printf("  -p PORT       Listen port (default: %d)\n", MGMTD_DEFAULT_PORT);
	printf("  -w WEBROOT    Static web root (default: %s)\n", MGMTD_DEFAULT_WEB_ROOT);
	printf("  -n            Run with management namespace setup\n");
	printf("  -f PROFILE    Load management config from profile YAML\n");
	printf("  -u USER       HTTP Basic auth username override\n");
	printf("  -P PASS       HTTP Basic auth password override\n");
	printf("  -h            Show this help\n");
}

int main(int argc, char **argv)
{
	struct mg_mgr mgr;
	struct mg_connection *listener;
	int opt;
	char profile_path[PATH_MAX] = { 0 };
	int cli_auth_user_set = 0;
	int cli_auth_pass_set = 0;
	char cli_auth_user[64] = { 0 };
	char cli_auth_pass[128] = { 0 };

	memset(&g_ctx, 0, sizeof(g_ctx));
	mgmtd_default_config(&g_ctx.cfg);
	rs_mgmt_iface_default_config(&g_ctx.mgmt_cfg);

	while ((opt = getopt(argc, argv, "p:w:nf:u:P:h")) != -1) {
		switch (opt) {
		case 'p':
			g_ctx.cfg.port = atoi(optarg);
			if (g_ctx.cfg.port <= 0 || g_ctx.cfg.port > 65535) {
				RS_LOG_ERROR("Invalid port: %s", optarg);
				return 1;
			}
			break;
		case 'w':
			strncpy(g_ctx.cfg.web_root, optarg, sizeof(g_ctx.cfg.web_root) - 1);
			break;
		case 'n':
			g_ctx.cfg.use_namespace = 1;
			break;
		case 'f':
			strncpy(profile_path, optarg, sizeof(profile_path) - 1);
			break;
		case 'u':
			strncpy(g_ctx.cfg.auth_user, optarg, sizeof(g_ctx.cfg.auth_user) - 1);
			strncpy(cli_auth_user, optarg, sizeof(cli_auth_user) - 1);
			cli_auth_user_set = 1;
			break;
		case 'P':
			strncpy(g_ctx.cfg.auth_password, optarg, sizeof(g_ctx.cfg.auth_password) - 1);
			strncpy(cli_auth_pass, optarg, sizeof(cli_auth_pass) - 1);
			cli_auth_pass_set = 1;
			break;
		case 'h':
		default:
			print_usage(argv[0]);
			return opt == 'h' ? 0 : 1;
		}
	}

	if (profile_path[0] != '\0') {
		struct rs_profile profile;
		int ret;

		profile_init(&profile);
		ret = profile_load_with_inheritance(profile_path, &profile);
		if (ret < 0) {
			RS_LOG_ERROR("Failed to load profile '%s': %d", profile_path, ret);
			profile_free(&profile);
			return 1;
		}

		if (profile.mgmt.enabled) {
			g_ctx.cfg.port = profile.mgmt.port;
			strncpy(g_ctx.cfg.web_root, profile.mgmt.web_root, sizeof(g_ctx.cfg.web_root) - 1);

			/* Validate web_root directory exists, fallback to default if not */
			struct stat web_root_st;
			if (g_ctx.cfg.web_root[0] == '\0' ||
			    stat(g_ctx.cfg.web_root, &web_root_st) != 0 ||
			    !S_ISDIR(web_root_st.st_mode)) {
				const char *rswitch_home = getenv("RSWITCH_HOME");
				char fallback_web_root[256];
				if (rswitch_home && rswitch_home[0]) {
					snprintf(fallback_web_root, sizeof(fallback_web_root),
						 "%s/web", rswitch_home);
				} else {
					strncpy(fallback_web_root, MGMTD_DEFAULT_WEB_ROOT,
						sizeof(fallback_web_root) - 1);
					fallback_web_root[sizeof(fallback_web_root) - 1] = '\0';
				}
				RS_LOG_WARN("web_root '%s' invalid or missing, using fallback: %s",
					    g_ctx.cfg.web_root, fallback_web_root);
				strncpy(g_ctx.cfg.web_root, fallback_web_root,
					sizeof(g_ctx.cfg.web_root) - 1);
			}

			g_ctx.cfg.use_namespace = profile.mgmt.use_namespace;
			g_ctx.cfg.auth_enabled = profile.mgmt.auth_enabled;
			strncpy(g_ctx.cfg.auth_user, profile.mgmt.auth_user, sizeof(g_ctx.cfg.auth_user) - 1);
			strncpy(g_ctx.cfg.auth_password, profile.mgmt.auth_password,
				sizeof(g_ctx.cfg.auth_password) - 1);
			g_ctx.cfg.session_timeout = profile.mgmt.session_timeout;
			g_ctx.cfg.rate_limit_max_fails = profile.mgmt.rate_limit_max_fails;
			g_ctx.cfg.rate_limit_lockout_sec = profile.mgmt.rate_limit_lockout_sec;

			strncpy(g_ctx.mgmt_cfg.mgmt_ns, profile.mgmt.namespace_name,
				sizeof(g_ctx.mgmt_cfg.mgmt_ns) - 1);
			g_ctx.mgmt_cfg.mode = profile.mgmt.iface_mode;
			strncpy(g_ctx.mgmt_cfg.static_ip, profile.mgmt.static_ip,
				sizeof(g_ctx.mgmt_cfg.static_ip) - 1);
			strncpy(g_ctx.mgmt_cfg.gateway, profile.mgmt.gateway,
				sizeof(g_ctx.mgmt_cfg.gateway) - 1);
			g_ctx.mgmt_cfg.mgmt_vlan = profile.mgmt.mgmt_vlan;
		}

		strncpy(g_ctx.profile_name, profile.name, sizeof(g_ctx.profile_name) - 1);
		strncpy(g_ctx.profile_path, profile_path, sizeof(g_ctx.profile_path) - 1);

		g_ctx.profile_module_count = 0;
		for (int i = 0; i < profile.ingress_count && g_ctx.profile_module_count < 128; i++) {
			strncpy(g_ctx.profile_modules[g_ctx.profile_module_count].name,
				profile.ingress_modules[i].name,
				sizeof(g_ctx.profile_modules[0].name) - 1);
			strncpy(g_ctx.profile_modules[g_ctx.profile_module_count].type,
				"ingress", sizeof(g_ctx.profile_modules[0].type) - 1);
			g_ctx.profile_module_count++;
		}
		for (int i = 0; i < profile.egress_count && g_ctx.profile_module_count < 128; i++) {
			strncpy(g_ctx.profile_modules[g_ctx.profile_module_count].name,
				profile.egress_modules[i].name,
				sizeof(g_ctx.profile_modules[0].name) - 1);
			strncpy(g_ctx.profile_modules[g_ctx.profile_module_count].type,
				"egress", sizeof(g_ctx.profile_modules[0].type) - 1);
			g_ctx.profile_module_count++;
		}

		/* Populate DHCP snooping BPF maps from profile config */
		g_ctx.dhcp_snoop_enabled = profile.dhcp_snooping.enabled;
		g_ctx.dhcp_snoop_drop_rogue = profile.dhcp_snooping.drop_rogue_server;
		g_ctx.dhcp_trusted_port_count = profile.dhcp_snooping.trusted_port_count;
		for (int i = 0; i < profile.dhcp_snooping.trusted_port_count && i < 16; i++)
			strncpy(g_ctx.dhcp_trusted_ports[i],
				profile.dhcp_snooping.trusted_ports[i],
				sizeof(g_ctx.dhcp_trusted_ports[0]) - 1);

		if (profile.dhcp_snooping.enabled) {
			int fd = bpf_obj_get(DHCP_SNOOP_CONFIG_MAP_PATH);
			if (fd >= 0) {
				__u32 key = 0;
				struct dhcp_snoop_config cfg = {
					.enabled = 1,
					.drop_rogue_server = profile.dhcp_snooping.drop_rogue_server ? 1 : 0,
					.trusted_port_count = (__u32) profile.dhcp_snooping.trusted_port_count,
				};
				if (bpf_map_update_elem(fd, &key, &cfg, BPF_ANY) == 0)
					RS_LOG_INFO("DHCP snooping enabled (drop_rogue=%d, trusted_ports=%d)",
						    cfg.drop_rogue_server, cfg.trusted_port_count);
				else
					RS_LOG_WARN("Failed to update dhcp_snoop_config_map: %s",
						    strerror(errno));
				close(fd);
			} else {
				RS_LOG_WARN("dhcp_snoop_config_map not available: %s",
					    strerror(errno));
			}

			fd = bpf_obj_get(DHCP_TRUSTED_PORTS_MAP_PATH);
			if (fd >= 0) {
				for (int i = 0; i < profile.dhcp_snooping.trusted_port_count; i++) {
				__u32 ifidx = resolve_ifindex(
					profile.dhcp_snooping.trusted_ports[i]);
					if (ifidx == 0) {
						RS_LOG_WARN("DHCP trusted port '%s' not found",
							    profile.dhcp_snooping.trusted_ports[i]);
						continue;
					}
					__u32 trusted = 1;
					if (bpf_map_update_elem(fd, &ifidx, &trusted, BPF_ANY) == 0)
						RS_LOG_INFO("DHCP trusted port %s (ifindex=%u)",
							    profile.dhcp_snooping.trusted_ports[i],
							    ifidx);
					else
						RS_LOG_WARN("Failed to set trusted port %s: %s",
							    profile.dhcp_snooping.trusted_ports[i],
							    strerror(errno));
				}
				close(fd);
			} else {
				RS_LOG_WARN("dhcp_trusted_ports_map not available: %s",
					    strerror(errno));
			}
		}

		profile_free(&profile);
	}

	if (cli_auth_user_set)
		strncpy(g_ctx.cfg.auth_user, cli_auth_user, sizeof(g_ctx.cfg.auth_user) - 1);

	if (cli_auth_pass_set)
		strncpy(g_ctx.cfg.auth_password, cli_auth_pass, sizeof(g_ctx.cfg.auth_password) - 1);

	if (cli_auth_user_set || cli_auth_pass_set)
		g_ctx.cfg.auth_enabled = 1;

	normalize_auth_config(&g_ctx.cfg);

	snprintf(g_ctx.cfg.listen_addr, sizeof(g_ctx.cfg.listen_addr), "http://0.0.0.0:%d", g_ctx.cfg.port);

	rs_log_init("rswitch-mgmtd", RS_LOG_LEVEL_INFO);
	if (rs_audit_init() != 0)
		RS_LOG_WARN("Audit init failed");

	if (clock_gettime(CLOCK_MONOTONIC, &g_ctx.start_ts) != 0)
		memset(&g_ctx.start_ts, 0, sizeof(g_ctx.start_ts));

	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);

	if (g_ctx.cfg.use_namespace) {
		__u32 existing = if_nametoindex(g_ctx.mgmt_cfg.veth_host);
		if (existing) {
			if (rs_mgmt_iface_ns_probe(g_ctx.mgmt_cfg.mgmt_ns)) {
				RS_LOG_INFO("mgmt-br exists (ifindex=%u), namespace healthy, loader-managed mode", existing);
				g_ctx.loader_managed_veth = 1;
			} else {
			RS_LOG_WARN("Inconsistent state: mgmt-br exists but namespace %s not enterable - recreating",
				    g_ctx.mgmt_cfg.mgmt_ns);
				safe_exec("ip", (char *const[]) {"ip", "link", "del", g_ctx.mgmt_cfg.veth_host, NULL});
				if (rs_mgmt_iface_create(&g_ctx.mgmt_cfg) != 0)
					RS_LOG_WARN("Management namespace create failed");
			}
		} else {
			if (rs_mgmt_iface_create(&g_ctx.mgmt_cfg) != 0)
				RS_LOG_WARN("Management namespace create failed");
		}
		if (rs_mgmt_iface_obtain_ip(&g_ctx.mgmt_cfg) != 0)
			RS_LOG_WARN("Management IP obtain failed");
	}

	mgmtd_maps_init();
	cleanup_stale_port_configs();
	load_state_from_file();
	event_bus_init();
	if (event_db_open(NULL) != 0)
		RS_LOG_WARN("Event database init failed — events will not be persisted");

	/*
	 * Always enter the mgmt namespace when use_namespace is set.
	 * This ensures the HTTP listener binds on mgmt0's address,
	 * reachable via XDP-forwarded traffic. BPF map FDs and the
	 * event-bus ringbuf opened above remain valid across setns().
	 */
	if (g_ctx.cfg.use_namespace) {
		if (rs_mgmt_iface_enter_netns(g_ctx.mgmt_cfg.mgmt_ns) == 0)
			RS_LOG_INFO("Entered namespace %s for HTTP listener",
				    g_ctx.mgmt_cfg.mgmt_ns);
		else
			RS_LOG_WARN("Failed to enter namespace %s — "
				    "portal may not be reachable via mgmt IP",
				    g_ctx.mgmt_cfg.mgmt_ns);
	}

	mg_mgr_init(&mgr);
	g_mgr = &mgr;
	listener = mg_http_listen(&mgr, g_ctx.cfg.listen_addr, ev_handler, &g_ctx);
	if (!listener) {
		RS_LOG_ERROR("Failed to listen on %s", g_ctx.cfg.listen_addr);
		mg_mgr_free(&mgr);
		event_db_close();
		event_bus_cleanup();
		mgmtd_maps_close();
		if (g_ctx.cfg.use_namespace && !g_ctx.loader_managed_veth)
			rs_mgmt_iface_destroy(&g_ctx.mgmt_cfg);
		return 1;
	}

	RS_LOG_INFO("rSwitch Management Portal listening on %s", g_ctx.cfg.listen_addr);

	if (g_ctx.cfg.use_namespace) {
		if (rs_mgmt_iface_start_mdns(&g_ctx.mgmt_cfg) == 0)
			RS_LOG_INFO("mDNS responder enabled for rswitch.local");
		else
			RS_LOG_WARN("Failed to start mDNS responder");
	}

	mg_timer_add(&mgr, (uint64_t) g_ctx.cfg.ws_poll_ms, MG_TIMER_REPEAT, ws_timer_fn, &mgr);

	while (g_running)
		mg_mgr_poll(&mgr, 100);

	g_mgr = NULL;
	mg_mgr_free(&mgr);
	event_db_close();
	event_bus_cleanup();
	mgmtd_maps_close();

	if (g_ctx.cfg.use_namespace && !g_ctx.loader_managed_veth)
		rs_mgmt_iface_destroy(&g_ctx.mgmt_cfg);

	return 0;
}
