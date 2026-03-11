// SPDX-License-Identifier: GPL-2.0
#ifndef RSWITCH_MGMTD_H
#define RSWITCH_MGMTD_H

#include "mongoose.h"

#define MGMTD_DEFAULT_PORT     8080
#define MGMTD_DEFAULT_WEB_ROOT "/usr/share/rswitch/web"
#define MGMTD_WS_POLL_MS       2000

struct mgmtd_config {
	int port;
	char web_root[256];
	int use_namespace;	    /* 1=run in mgmt namespace, 0=run in default */
	char listen_addr[64];	    /* e.g. "http://0.0.0.0:8080" */
	int ws_poll_ms;		    /* WebSocket broadcast interval */
	int auth_enabled;
	char auth_user[64];
	char auth_password[128];
	int session_timeout;
	int rate_limit_max_fails;
	int rate_limit_lockout_sec;
};

/* Forward declarations for API handler registration */
struct mg_connection;
struct mg_http_message;

void mgmtd_default_config(struct mgmtd_config *cfg);

/* Route handler function type */
typedef void (*mgmtd_handler_fn)(struct mg_connection *c,
				  struct mg_http_message *hm,
				  void *userdata);

/* API handler registration (called from api_*.c files) */
void api_system_register(void);
void api_ports_register(void);
void api_modules_register(void);
void api_config_register(void);

/* WebSocket broadcast helpers */
void mgmtd_ws_broadcast(struct mg_mgr *mgr, const char *json, size_t len);
int mgmtd_ws_client_count(struct mg_mgr *mgr);

#endif
