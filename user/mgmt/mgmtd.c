// SPDX-License-Identifier: GPL-2.0

#define _GNU_SOURCE

#include "mongoose.h"
#include "mgmtd.h"
#include "mgmt_iface.h"
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
#include <limits.h>
#include <linux/limits.h>
#include <dirent.h>
#include <sys/stat.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/utsname.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/types.h>

#include "../watchdog/watchdog.h"
#include "../topology/topology.h"
#include "../audit/audit.h"
#include "../rollback/rollback.h"
#include "../lifecycle/lifecycle.h"
#include "../../bpf/core/module_abi.h"

#ifndef RS_MAX_INTERFACES
#define RS_MAX_INTERFACES 64
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
#define ROUTE_TBL_MAP_PATH "/sys/fs/bpf/route_tbl"

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

struct lpm_key {
	__u32 prefixlen;
	__u32 addr;
};

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

#define RS_MODULE_CONFIG_KEY_LEN 32
#define RS_MODULE_CONFIG_VAL_LEN 64

struct rs_stats {
	__u64 rx_packets;
	__u64 rx_bytes;
	__u64 tx_packets;
	__u64 tx_bytes;
	__u64 rx_drops;
	__u64 tx_drops;
	__u64 rx_errors;
	__u64 tx_errors;
};

struct rs_module_stats {
	__u64 packets_processed;
	__u64 packets_forwarded;
	__u64 packets_dropped;
	__u64 packets_error;
	__u64 bytes_processed;
	__u64 last_seen_ns;
	__u32 module_id;
	char name[32];
};

struct rs_port_config {
	__u32 ifindex;
	__u8 enabled;
	__u8 mgmt_type;
	__u8 vlan_mode;
	__u8 learning;
	__u16 pvid;
	__u16 native_vlan;
	__u16 access_vlan;
	__u16 allowed_vlan_count;
	__u16 allowed_vlans[128];
	__u16 tagged_vlan_count;
	__u16 tagged_vlans[64];
	__u16 untagged_vlan_count;
	__u16 untagged_vlans[64];
	__u8 default_prio;
	__u8 trust_dscp;
	__u16 rate_limit_kbps;
	__u8 port_security;
	__u8 max_macs;
	__u16 reserved;
	__u32 reserved2[4];
};

struct rs_vlan_members {
	__u16 vlan_id;
	__u16 member_count;
	__u64 tagged_members[4];
	__u64 untagged_members[4];
	__u32 reserved[4];
};

struct rs_module_config_key {
	char module_name[RS_MODULE_CONFIG_KEY_LEN];
	char param_name[RS_MODULE_CONFIG_KEY_LEN];
};

struct rs_module_config_value {
	__u32 type;
	union {
		__s64 int_val;
		__u32 bool_val;
		char str_val[56];
	};
};

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
	int route_tbl_fd;
	int ncpus;
	bool initialized;
} g_maps = { .stats_fd = -1, .module_stats_fd = -1, .port_config_fd = -1,
	     .vlan_fd = -1, .mac_table_fd = -1, .module_config_fd = -1,
	     .voqd_state_fd = -1, .qdepth_fd = -1, .acl_5tuple_fd = -1,
	     .acl_pdp_fd = -1, .acl_psp_fd = -1, .acl_pp_fd = -1,
	     .acl_config_fd = -1, .route_tbl_fd = -1, .ncpus = 0,
	     .initialized = false };

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
	mg_http_reply(c, 401,
		      "Content-Type: application/json\r\n"
		      "Access-Control-Allow-Origin: *\r\n"
		      "Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\n"
		      "Access-Control-Allow-Headers: Content-Type, Authorization\r\n",
		      "{\"error\":\"authentication required\"}");
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

	if (strcmp(user, g_ctx.cfg.auth_user) == 0 && strcmp(pass, g_ctx.cfg.auth_password) == 0) {
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

	mg_http_reply(c, 200,
		      "Content-Type: application/json\r\n"
		      "Access-Control-Allow-Origin: *\r\n"
		      "Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\n"
		      "Access-Control-Allow-Headers: Content-Type, Authorization\r\n"
		      "Set-Cookie: rs_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax\r\n",
		      "{\"ok\":true}");
}

static void json_printf(struct mg_connection *c, int status, const char *fmt, ...)
{
	char body[65536];
	char headers[1024];
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
		 "Content-Type: application/json\r\n"
		 "Access-Control-Allow-Origin: *\r\n"
		 "Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\n"
		 "Access-Control-Allow-Headers: Content-Type, Authorization\r\n");

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

static int build_cmd(char *out, size_t out_len, const char *cmd)
{
	if (!out || out_len == 0 || !cmd)
		return -EINVAL;

	if (g_ctx.cfg.use_namespace) {
		if (snprintf(out, out_len, "ip netns exec default-ns %s", cmd) >= (int) out_len)
			return -ENAMETOOLONG;
	} else {
		if (snprintf(out, out_len, "%s", cmd) >= (int) out_len)
			return -ENAMETOOLONG;
	}

	return 0;
}

static int run_cmd_json(const char *cmd, char *buf, size_t buf_len)
{
	char actual[1024];
	FILE *fp;
	size_t off = 0;

	if (!cmd || !buf || buf_len == 0)
		return -EINVAL;

	if (build_cmd(actual, sizeof(actual), cmd) != 0)
		return -EINVAL;

	fp = popen(actual, "r");
	if (!fp)
		return -errno;

	buf[0] = '\0';
	while (!feof(fp) && off + 1 < buf_len) {
		size_t n = fread(buf + off, 1, buf_len - off - 1, fp);
		off += n;
		if (n == 0)
			break;
	}
	buf[off] = '\0';

	if (pclose(fp) < 0)
		return -errno;
	return 0;
}

static int cmd_system(const char *cmd)
{
	char actual[1024];
	int ret;

	if (build_cmd(actual, sizeof(actual), cmd) != 0)
		return -EINVAL;

	ret = system(actual);
	if (ret < 0)
		return -errno;
	return ret;
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
	strncpy(cfg->auth_password, "rswitch", sizeof(cfg->auth_password) - 1);
	cfg->session_timeout = 3600;
	cfg->rate_limit_max_fails = 5;
	cfg->rate_limit_lockout_sec = 300;
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
	map_try_open(&g_maps.route_tbl_fd, ROUTE_TBL_MAP_PATH);

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
	if (g_maps.route_tbl_fd >= 0)
		close(g_maps.route_tbl_fd);

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
	g_maps.route_tbl_fd = -1;
	g_maps.initialized = false;
}

static int mgmtd_maps_ensure(void)
{
	return mgmtd_maps_init();
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

	snprintf(payload, sizeof(payload),
		 "{\"type\":\"event\",\"severity\":\"%s\","
		 "\"message\":\"[%s] %s: %s\",\"timestamp\":%llu}",
		 audit_sev_to_str(severity),
		 category ? category : "system",
		 action ? action : "unknown",
		 detail ? detail : "",
		 (unsigned long long)ts.tv_sec);

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
	int ret;

	(void) hm;
	(void) userdata;

	mgmtd_audit_log(AUDIT_SEV_WARNING, AUDIT_CAT_SYSTEM, "reboot", 1,
			    "reboot requested via mgmtd API");
	ret = cmd_system("reboot");
	if (ret != 0) {
		json_printf(c, 500, "{\"status\":\"failed\",\"code\":%d}", ret);
		return;
	}

	json_printf(c, 200, "{\"status\":\"ok\"}");
}

static void handle_system_shutdown(struct mg_connection *c, struct mg_http_message *hm, void *userdata)
{
	(void) hm;
	(void) userdata;

	mgmtd_audit_log(AUDIT_SEV_WARNING, AUDIT_CAT_SYSTEM, "shutdown", 1,
			    "shutdown requested via mgmtd API");
	g_running = 0;
	json_printf(c, 200, "{\"status\":\"stopping\"}");
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
	char out[65536];
	size_t off = 0;
	int first = 1;
	int port_id = 0;

	(void) hm;
	(void) userdata;

	if (mgmtd_maps_ensure() != 0 || g_maps.port_config_fd < 0) {
		json_printf(c, 503, "{\"ports\":[]}");
		return;
	}

	off += (size_t) snprintf(out + off, sizeof(out) - off, "{\"ports\":[");
	if (bpf_map_get_next_key(g_maps.port_config_fd, NULL, &next) == 0) {
		while (1) {
			struct rs_port_config p;
			if (bpf_map_lookup_elem(g_maps.port_config_fd, &next, &p) == 0) {
				char name[IF_NAMESIZE] = "unknown";
				char oper[32] = "unknown";
				int speed_val = 0;
				int link_up = 0;
				struct rs_stats st;
				__u64 rx_pkt = 0, tx_pkt = 0;

				if_indextoname(p.ifindex, name);
				if (name[0] == 'u' || name[0] == '\0')
					ifindex_to_name_sysfs(p.ifindex, name, sizeof(name));

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

				off += (size_t) snprintf(out + off, sizeof(out) - off,
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

			key = next;
			if (bpf_map_get_next_key(g_maps.port_config_fd, &key, &next) != 0)
				break;
			if (off + 512 >= sizeof(out))
				break;
		}
	}

	snprintf(out + off, sizeof(out) - off, "]}");
	json_printf(c, 200, "%s", out);
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
	char out[65536];
	size_t off = 0;
	int first = 1;
	int i;

	(void) hm;
	(void) userdata;

	mgmtd_maps_ensure();

	off += (size_t) snprintf(out + off, sizeof(out) - off, "{\"modules\":[");

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

		off += (size_t) snprintf(out + off, sizeof(out) - off,
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
		if (off + 512 >= sizeof(out))
			break;
	}

	snprintf(out + off, sizeof(out) - off, "]}");
	json_printf(c, 200, "%s", out);
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
	char out[65536];
	size_t off = 0;
	int first = 1;

	(void) hm;
	(void) userdata;

	if (mgmtd_maps_ensure() != 0 || g_maps.vlan_fd < 0) {
		json_printf(c, 503, "{\"vlans\":[]}");
		return;
	}

	off += (size_t) snprintf(out + off, sizeof(out) - off, "{\"vlans\":[");
	if (bpf_map_get_next_key(g_maps.vlan_fd, NULL, &next) == 0) {
		while (1) {
			struct rs_vlan_members v;
			if (bpf_map_lookup_elem(g_maps.vlan_fd, &next, &v) == 0) {
				int i, j;
				off += (size_t) snprintf(out + off, sizeof(out) - off,
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
								off += (size_t) snprintf(out + off, sizeof(out) - off,
										 "%s%d", tp_first ? "" : ",", ifidx);
								tp_first = 0;
							}
						}
					}
				}

				off += (size_t) snprintf(out + off, sizeof(out) - off,
						 "],\"untagged_ports\":[");

				{
					int up_first = 1;
					for (i = 0; i < 4; i++) {
						for (j = 0; j < 64; j++) {
							if (v.untagged_members[i] & (1ULL << j)) {
								int ifidx = i * 64 + j + 1;
								off += (size_t) snprintf(out + off, sizeof(out) - off,
										 "%s%d", up_first ? "" : ",", ifidx);
								up_first = 0;
							}
						}
					}
				}

				off += (size_t) snprintf(out + off, sizeof(out) - off, "]}");
				first = 0;
			}

			key = next;
			if (bpf_map_get_next_key(g_maps.vlan_fd, &key, &next) != 0)
				break;
			if (off + 512 >= sizeof(out))
				break;
		}
	}

	snprintf(out + off, sizeof(out) - off, "]}");
	json_printf(c, 200, "%s", out);
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
			int word = (port - 1) / 64;
			int bit = (port - 1) % 64;
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
			int word = (port - 1) / 64;
			int bit = (port - 1) % 64;
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
	json_printf(c, 201, "{\"status\":\"created\",\"vlan_id\":%ld}", vlan_id);
}

static void handle_vlan_update(struct mg_connection *c, struct mg_http_message *hm, void *userdata)
{
	int vlan_id;
	struct rs_vlan_members v;
	long member_count;
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
	if (bpf_map_lookup_elem(g_maps.vlan_fd, &key, &v) != 0)
		memset(&v, 0, sizeof(v));

	member_count = mg_json_get_long(hm->body, "$.member_count", v.member_count);
	v.vlan_id = key;
	v.member_count = (__u16) member_count;

	if (bpf_map_update_elem(g_maps.vlan_fd, &key, &v, BPF_ANY) != 0) {
		json_printf(c, 500, "{\"error\":\"failed to update vlan\"}");
		return;
	}

	mgmtd_audit_log(AUDIT_SEV_INFO, AUDIT_CAT_CONFIG, "vlan_update", 1,
			    "vlan_id=%d member_count=%u", vlan_id, v.member_count);
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
	json_printf(c, 200, "{\"status\":\"deleted\"}");
}

static void handle_acls_list(struct mg_connection *c, struct mg_http_message *hm, void *userdata)
{
	char out[65536];
	size_t off = 0;
	int first = 1;
	int acl_idx = 0;

	(void) hm;
	(void) userdata;

	if (mgmtd_maps_ensure() != 0) {
		json_printf(c, 200, "{\"acls\":[]}");
		return;
	}

	off += (size_t) snprintf(out + off, sizeof(out) - off, "{\"acls\":[");

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

				off += (size_t) snprintf(out + off, sizeof(out) - off,
						 "%s{\"id\":%d,\"type\":\"5tuple\","
						 "\"priority\":%u,\"action\":\"%s\","
						 "\"protocol\":%u,\"src_ip\":\"%s\",\"src_port\":%u,"
						 "\"dst_ip\":\"%s\",\"dst_port\":%u,\"hits\":0}",
						 first ? "" : ",",
						 acl_idx, res.stats_id,
						 res.action == 0 ? "permit" : (res.action == 1 ? "deny" : "redirect"),
						 nk.proto, src, ntohs(nk.sport),
						 dst, ntohs(nk.dport));
				first = 0;
				acl_idx++;
			}
			k = nk;
			has_prev = 1;
			if (off + 512 >= sizeof(out))
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

				off += (size_t) snprintf(out + off, sizeof(out) - off,
						 "%s{\"id\":%d,\"type\":\"proto_dst\","
						 "\"priority\":%u,\"action\":\"%s\","
						 "\"protocol\":%u,\"src_ip\":\"any\",\"src_port\":0,"
						 "\"dst_ip\":\"%s\",\"dst_port\":%u,\"hits\":0}",
						 first ? "" : ",",
						 acl_idx, res.stats_id,
						 res.action == 0 ? "permit" : (res.action == 1 ? "deny" : "redirect"),
						 nk.proto, dst, ntohs(nk.dst_port));
				first = 0;
				acl_idx++;
			}
			k = nk;
			has_prev = 1;
			if (off + 512 >= sizeof(out))
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

				off += (size_t) snprintf(out + off, sizeof(out) - off,
						 "%s{\"id\":%d,\"type\":\"proto_src\","
						 "\"priority\":%u,\"action\":\"%s\","
						 "\"protocol\":%u,\"src_ip\":\"%s\",\"src_port\":0,"
						 "\"dst_ip\":\"any\",\"dst_port\":%u,\"hits\":0}",
						 first ? "" : ",",
						 acl_idx, res.stats_id,
						 res.action == 0 ? "permit" : (res.action == 1 ? "deny" : "redirect"),
						 nk.proto, src, ntohs(nk.dst_port));
				first = 0;
				acl_idx++;
			}
			k = nk;
			has_prev = 1;
			if (off + 512 >= sizeof(out))
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
				off += (size_t) snprintf(out + off, sizeof(out) - off,
						 "%s{\"id\":%d,\"type\":\"proto_port\","
						 "\"priority\":%u,\"action\":\"%s\","
						 "\"protocol\":%u,\"src_ip\":\"any\",\"src_port\":0,"
						 "\"dst_ip\":\"any\",\"dst_port\":%u,\"hits\":0}",
						 first ? "" : ",",
						 acl_idx, res.stats_id,
						 res.action == 0 ? "permit" : (res.action == 1 ? "deny" : "redirect"),
						 nk.proto, ntohs(nk.dst_port));
				first = 0;
				acl_idx++;
			}
			k = nk;
			has_prev = 1;
			if (off + 512 >= sizeof(out))
				break;
		}
	}

	snprintf(out + off, sizeof(out) - off, "]}");
	json_printf(c, 200, "%s", out);
}

static void handle_acl_create(struct mg_connection *c, struct mg_http_message *hm, void *userdata)
{
	struct acl_5tuple_key key;
	struct acl_result res;
	char *action_str, *src_ip_str, *dst_ip_str, *proto_str;
	long src_port, dst_port, priority;
	struct in_addr addr;

	(void) userdata;

	if (mgmtd_maps_ensure() != 0 || g_maps.acl_5tuple_fd < 0) {
		json_printf(c, 503, "{\"error\":\"acl map unavailable\"}");
		return;
	}

	memset(&key, 0, sizeof(key));
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
			key.proto = 6;
		else if (strcmp(proto_str, "udp") == 0 || strcmp(proto_str, "UDP") == 0)
			key.proto = 17;
		else if (strcmp(proto_str, "icmp") == 0 || strcmp(proto_str, "ICMP") == 0)
			key.proto = 1;
		else
			key.proto = (__u8) atoi(proto_str);
		free(proto_str);
	} else {
		key.proto = (__u8) mg_json_get_long(hm->body, "$.protocol", 0);
	}

	if (src_ip_str) {
		if (strcmp(src_ip_str, "any") != 0 && inet_pton(AF_INET, src_ip_str, &addr) == 1)
			key.src_ip = addr.s_addr;
		free(src_ip_str);
	}
	if (dst_ip_str) {
		if (strcmp(dst_ip_str, "any") != 0 && inet_pton(AF_INET, dst_ip_str, &addr) == 1)
			key.dst_ip = addr.s_addr;
		free(dst_ip_str);
	}

	key.sport = htons((__u16) src_port);
	key.dport = htons((__u16) dst_port);

	if (action_str) {
		if (strcmp(action_str, "deny") == 0 || strcmp(action_str, "drop") == 0)
			res.action = 1;
		else if (strcmp(action_str, "redirect") == 0)
			res.action = 2;
		else
			res.action = 0;
		free(action_str);
	}
	res.stats_id = (__u32) priority;

	if (bpf_map_update_elem(g_maps.acl_5tuple_fd, &key, &res, BPF_ANY) != 0) {
		json_printf(c, 500, "{\"error\":\"failed to add ACL rule: %s\"}", strerror(errno));
		return;
	}

	mgmtd_audit_log(AUDIT_SEV_INFO, AUDIT_CAT_ACL, "acl_add", 1,
			    "proto=%u src_port=%ld dst_port=%ld action=%u", key.proto,
			    src_port, dst_port, res.action);
	json_printf(c, 200, "{\"status\":\"ok\"}");
}

static void handle_acl_delete(struct mg_connection *c, struct mg_http_message *hm, void *userdata)
{
	int target_id;
	int cur_id = 0;
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

	if (g_maps.acl_5tuple_fd >= 0) {
		struct acl_5tuple_key k, nk;
		int has_prev = 0;
		memset(&k, 0, sizeof(k));
		while (bpf_map_get_next_key(g_maps.acl_5tuple_fd, has_prev ? &k : NULL, &nk) == 0) {
			if (cur_id == target_id) {
				bpf_map_delete_elem(g_maps.acl_5tuple_fd, &nk);
				deleted = 1;
				break;
			}
			cur_id++;
			k = nk;
			has_prev = 1;
		}
	}

	if (!deleted && g_maps.acl_pdp_fd >= 0) {
		struct acl_proto_dstip_port_key k, nk;
		int has_prev = 0;
		memset(&k, 0, sizeof(k));
		while (bpf_map_get_next_key(g_maps.acl_pdp_fd, has_prev ? &k : NULL, &nk) == 0) {
			if (cur_id == target_id) {
				bpf_map_delete_elem(g_maps.acl_pdp_fd, &nk);
				deleted = 1;
				break;
			}
			cur_id++;
			k = nk;
			has_prev = 1;
		}
	}

	if (!deleted && g_maps.acl_psp_fd >= 0) {
		struct acl_proto_srcip_port_key k, nk;
		int has_prev = 0;
		memset(&k, 0, sizeof(k));
		while (bpf_map_get_next_key(g_maps.acl_psp_fd, has_prev ? &k : NULL, &nk) == 0) {
			if (cur_id == target_id) {
				bpf_map_delete_elem(g_maps.acl_psp_fd, &nk);
				deleted = 1;
				break;
			}
			cur_id++;
			k = nk;
			has_prev = 1;
		}
	}

	if (!deleted && g_maps.acl_pp_fd >= 0) {
		struct acl_proto_port_key k, nk;
		int has_prev = 0;
		memset(&k, 0, sizeof(k));
		while (bpf_map_get_next_key(g_maps.acl_pp_fd, has_prev ? &k : NULL, &nk) == 0) {
			if (cur_id == target_id) {
				bpf_map_delete_elem(g_maps.acl_pp_fd, &nk);
				deleted = 1;
				break;
			}
			cur_id++;
			k = nk;
			has_prev = 1;
		}
	}

	if (!deleted) {
		json_printf(c, 404, "{\"error\":\"acl rule not found\"}");
		return;
	}

	mgmtd_audit_log(AUDIT_SEV_INFO, AUDIT_CAT_ACL, "acl_delete", 1,
			    "acl_id=%d", target_id);
	json_printf(c, 200, "{\"status\":\"deleted\"}");
}

static void handle_routes_list(struct mg_connection *c, struct mg_http_message *hm, void *userdata)
{
	char out[65536];
	size_t off = 0;
	int first = 1;

	(void) hm;
	(void) userdata;

	if (mgmtd_maps_ensure() != 0 || g_maps.route_tbl_fd < 0) {
		json_printf(c, 200, "{\"routes\":[]}");
		return;
	}

	off += (size_t) snprintf(out + off, sizeof(out) - off, "{\"routes\":[");

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

				off += (size_t) snprintf(out + off, sizeof(out) - off,
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
			if (off + 512 >= sizeof(out))
				break;
		}
	}

	snprintf(out + off, sizeof(out) - off, "]}");
	json_printf(c, 200, "%s", out);
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
		entry.ifindex = if_nametoindex(iface_str);
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
	char out[65536];
	char esc[131072];

	(void) hm;
	(void) userdata;

	if (run_cmd_json("rsnatctl show", out, sizeof(out)) != 0) {
		json_printf(c, 500, "{\"error\":\"rsnatctl show failed\"}");
		return;
	}

	json_escape(out, esc, sizeof(esc));
	json_printf(c, 200, "{\"output\":\"%s\"}", esc);
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
	char out[65536];
	char esc[131072];

	(void) hm;
	(void) userdata;

	if (run_cmd_json("rsnatctl conntrack", out, sizeof(out)) != 0) {
		json_printf(c, 500, "{\"error\":\"rsnatctl conntrack failed\"}");
		return;
	}

	json_escape(out, esc, sizeof(esc));
	json_printf(c, 200, "{\"output\":\"%s\"}", esc);
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

	dir = opendir("/etc/rswitch/profiles/");
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
	char cmd[1024];

	(void) userdata;

	profile = mg_json_get_str(hm->body, "$.profile");
	if (!profile || profile[0] == '\0') {
		free(profile);
		json_printf(c, 400, "{\"error\":\"profile required\"}");
		return;
	}

	snprintf(cmd, sizeof(cmd), "rswitch_loader -f /etc/rswitch/profiles/%s", profile);
	if (cmd_system(cmd) != 0) {
		free(profile);
		json_printf(c, 500, "{\"error\":\"profile apply failed\"}");
		return;
	}

	mgmtd_audit_log(AUDIT_SEV_INFO, AUDIT_CAT_PROFILE, "profile_apply", 1,
			    "profile=%s", profile);
	free(profile);
	json_printf(c, 200, "{\"status\":\"ok\"}");
}

static void handle_topology(struct mg_connection *c, struct mg_http_message *hm, void *userdata)
{
	struct rs_topology topo;
	char out[65536];
	size_t off = 0;
	int i;

	(void) hm;
	(void) userdata;

	if (rs_topology_discover(&topo) != 0) {
		json_printf(c, 500, "{\"error\":\"topology discovery failed\"}");
		return;
	}

	off += (size_t) snprintf(out + off, sizeof(out) - off, "{\"nodes\":[");
	for (i = 0; i < topo.node_count; i++) {
		off += (size_t) snprintf(out + off, sizeof(out) - off,
					 "%s{\"name\":\"%s\",\"mgmt_addr\":\"%s\","
					 "\"description\":\"%s\",\"port_count\":%d}",
					 i ? "," : "",
					 topo.nodes[i].system_name,
					 topo.nodes[i].mgmt_addr,
					 topo.nodes[i].description,
					 topo.nodes[i].port_count);
		if (off + 512 >= sizeof(out))
			break;
	}

	off += (size_t) snprintf(out + off, sizeof(out) - off, "],\"links\":[");
	for (i = 0; i < topo.link_count; i++) {
		const char *local_name = "";
		const char *remote_name = "";

		if (topo.links[i].local_node_idx >= 0 && topo.links[i].local_node_idx < topo.node_count)
			local_name = topo.nodes[topo.links[i].local_node_idx].system_name;
		if (topo.links[i].remote_node_idx >= 0 && topo.links[i].remote_node_idx < topo.node_count)
			remote_name = topo.nodes[topo.links[i].remote_node_idx].system_name;

		off += (size_t) snprintf(out + off, sizeof(out) - off,
					 "%s{\"local_node\":\"%s\",\"local_port\":\"%s\","
					 "\"remote_node\":\"%s\",\"remote_port\":\"%s\","
					 "\"speed\":\"%s\"}",
					 i ? "," : "",
					 local_name,
					 topo.links[i].local_port,
					 remote_name,
					 topo.links[i].remote_port,
					 topo.links[i].link_speed);
		if (off + 512 >= sizeof(out))
			break;
	}

	snprintf(out + off, sizeof(out) - off, "]}");
	json_printf(c, 200, "%s", out);
}

static void handle_config_snapshots(struct mg_connection *c, struct mg_http_message *hm, void *userdata)
{
	struct rs_snapshot_info snaps[SNAPSHOT_READ_MAX];
	int n;
	int i;
	char out[65536];
	size_t off = 0;

	(void) hm;
	(void) userdata;

	n = rs_rollback_list_snapshots(snaps, SNAPSHOT_READ_MAX);
	if (n < 0) {
		json_printf(c, 500, "{\"error\":\"failed to list snapshots\"}");
		return;
	}

	off += (size_t) snprintf(out + off, sizeof(out) - off, "{\"snapshots\":[");
	for (i = 0; i < n; i++) {
		off += (size_t) snprintf(out + off, sizeof(out) - off,
					 "%s{\"id\":\"%s\",\"description\":\"%s\","
					 "\"profile_path\":\"%s\",\"timestamp\":%llu,\"confirmed\":%d}",
					 i ? "," : "",
					 snaps[i].id,
					 snaps[i].description,
					 snaps[i].profile_path,
					 (unsigned long long) snaps[i].timestamp,
					 snaps[i].confirmed);
		if (off + 512 >= sizeof(out))
			break;
	}

	snprintf(out + off, sizeof(out) - off, "]}");
	json_printf(c, 200, "%s", out);
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
	char out[131072];
	size_t off = 0;

	(void) hm;
	(void) userdata;

	n = rs_audit_read(entries, AUDIT_READ_MAX);
	if (n < 0) {
		json_printf(c, 500, "{\"error\":\"audit read failed\"}");
		return;
	}

	off += (size_t) snprintf(out + off, sizeof(out) - off, "{\"audit\":[");
	for (i = 0; i < n; i++) {
		char esc_detail[1024];

		json_escape(entries[i].detail, esc_detail, sizeof(esc_detail));
		off += (size_t) snprintf(out + off, sizeof(out) - off,
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
		if (off + 1024 >= sizeof(out))
			break;
	}

	snprintf(out + off, sizeof(out) - off, "]}");
	json_printf(c, 200, "%s", out);
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
}

static void handle_preflight(struct mg_connection *c)
{
	mg_http_reply(c, 204,
		      "Access-Control-Allow-Origin: *\r\n"
		      "Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\n"
		      "Access-Control-Allow-Headers: Content-Type, Authorization\r\n"
		      "Access-Control-Max-Age: 86400\r\n",
		      "");
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

	if (method_is(hm->method, "GET") && mg_match(hm->uri, mg_str("/api/topology"), NULL))
		return handle_topology(c, hm, userdata);

	if (method_is(hm->method, "GET") && mg_match(hm->uri, mg_str("/api/config/snapshots"), NULL))
		return handle_config_snapshots(c, hm, userdata);
	if (method_is(hm->method, "POST") && mg_match(hm->uri, mg_str("/api/config/snapshot"), NULL))
		return handle_config_snapshot_create(c, hm, userdata);
	if (method_is(hm->method, "POST") && mg_match(hm->uri, mg_str("/api/config/rollback/#"), NULL))
		return handle_config_rollback(c, hm, userdata);
	if (method_is(hm->method, "GET") && mg_match(hm->uri, mg_str("/api/config/audit"), NULL))
		return handle_config_audit(c, hm, userdata);

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
			if (!check_auth(c, hm))
				return;
			mg_ws_upgrade(c, hm, NULL);
			c->data[0] = 'W';
			RS_LOG_INFO("WebSocket client upgraded id=%lu", c->id);
			return;
		}

		if (mg_match(hm->uri, mg_str("/api/#"), NULL) || mg_match(hm->uri, mg_str("/api"), NULL)) {
			dispatch_api(c, hm, ctx);
			return;
		}

		memset(&opts, 0, sizeof(opts));
		opts.root_dir = ctx->cfg.web_root;
		opts.extra_headers =
			"Access-Control-Allow-Origin: *\r\n"
			"Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\n"
			"Access-Control-Allow-Headers: Content-Type, Authorization\r\n";
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

		profile_free(&profile);
	}

	if (cli_auth_user_set)
		strncpy(g_ctx.cfg.auth_user, cli_auth_user, sizeof(g_ctx.cfg.auth_user) - 1);

	if (cli_auth_pass_set)
		strncpy(g_ctx.cfg.auth_password, cli_auth_pass, sizeof(g_ctx.cfg.auth_password) - 1);

	/* Implicitly enable auth when credentials are provided via CLI */
	if (cli_auth_user_set || cli_auth_pass_set)
		g_ctx.cfg.auth_enabled = 1;

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
			RS_LOG_INFO("mgmt-br exists (ifindex=%u), loader-managed mode", existing);
			g_ctx.loader_managed_veth = 1;
		} else {
			if (rs_mgmt_iface_create(&g_ctx.mgmt_cfg) != 0)
				RS_LOG_WARN("Management namespace create failed");
		}
		if (rs_mgmt_iface_obtain_ip(&g_ctx.mgmt_cfg) != 0)
			RS_LOG_WARN("Management IP obtain failed");
	}

	mgmtd_maps_init();

	mg_mgr_init(&mgr);
	g_mgr = &mgr;
	listener = mg_http_listen(&mgr, g_ctx.cfg.listen_addr, ev_handler, &g_ctx);
	if (!listener) {
		RS_LOG_ERROR("Failed to listen on %s", g_ctx.cfg.listen_addr);
		mg_mgr_free(&mgr);
		mgmtd_maps_close();
		if (g_ctx.cfg.use_namespace && !g_ctx.loader_managed_veth)
			rs_mgmt_iface_destroy(&g_ctx.mgmt_cfg);
		return 1;
	}

	RS_LOG_INFO("rSwitch Management Portal listening on %s", g_ctx.cfg.listen_addr);
	mg_timer_add(&mgr, (uint64_t) g_ctx.cfg.ws_poll_ms, MG_TIMER_REPEAT, ws_timer_fn, &mgr);

	while (g_running)
		mg_mgr_poll(&mgr, 100);

	g_mgr = NULL;
	mg_mgr_free(&mgr);
	mgmtd_maps_close();

	if (g_ctx.cfg.use_namespace && !g_ctx.loader_managed_veth)
		rs_mgmt_iface_destroy(&g_ctx.mgmt_cfg);

	return 0;
}
