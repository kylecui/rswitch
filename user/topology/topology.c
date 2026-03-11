// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>
#include <limits.h>
#include "topology.h"
#if __has_include("rs_log.h")
#include "rs_log.h"
#else
#include "../common/rs_log.h"
#endif

static int parse_json_string_field(const char *buf, const char *key, char *out, size_t out_sz)
{
	char pattern[64];
	char fmt[32];
	const char *p;
	const char *colon;

	if (!buf || !key || !out || out_sz == 0)
		return -1;

	out[0] = '\0';
	snprintf(pattern, sizeof(pattern), "\"%s\"", key);
	p = strstr(buf, pattern);
	if (!p)
		return -1;

	colon = strchr(p, ':');
	if (!colon)
		return -1;

	snprintf(fmt, sizeof(fmt), " \"%%%zu[^\"]\"", out_sz - 1);
	if (sscanf(colon + 1, fmt, out) != 1)
		return -1;

	out[out_sz - 1] = '\0';
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
	buf[n] = '\0';
	fclose(f);
	return 0;
}

static void infer_local_port_from_file(const char *filename, char *out, size_t out_sz)
{
	const char *dot;
	size_t len;

	if (!filename || !out || out_sz == 0)
		return;

	dot = strrchr(filename, '.');
	if (!dot)
		dot = filename + strlen(filename);

	len = (size_t)(dot - filename);
	if (len >= out_sz)
		len = out_sz - 1;

	memcpy(out, filename, len);
	out[len] = '\0';
}

static int find_node_by_name(const struct rs_topology *topo, const char *name)
{
	if (!topo || !name || name[0] == '\0')
		return -1;

	for (int i = 0; i < topo->node_count; i++) {
		if (strcmp(topo->nodes[i].system_name, name) == 0)
			return i;
	}

	return -1;
}

static int add_or_get_node(struct rs_topology *topo, const char *name,
				   const char *mgmt, const char *desc)
{
	int idx;

	if (!topo || !name || name[0] == '\0')
		return -1;

	idx = find_node_by_name(topo, name);
	if (idx >= 0) {
		if (mgmt && mgmt[0] != '\0' && topo->nodes[idx].mgmt_addr[0] == '\0')
			snprintf(topo->nodes[idx].mgmt_addr, sizeof(topo->nodes[idx].mgmt_addr), "%s", mgmt);
		if (desc && desc[0] != '\0' && topo->nodes[idx].description[0] == '\0')
			snprintf(topo->nodes[idx].description, sizeof(topo->nodes[idx].description), "%s", desc);
		return idx;
	}

	if (topo->node_count >= TOPO_MAX_NODES)
		return -1;

	idx = topo->node_count++;
	snprintf(topo->nodes[idx].system_name, sizeof(topo->nodes[idx].system_name), "%s", name);
	if (mgmt)
		snprintf(topo->nodes[idx].mgmt_addr, sizeof(topo->nodes[idx].mgmt_addr), "%s", mgmt);
	if (desc)
		snprintf(topo->nodes[idx].description, sizeof(topo->nodes[idx].description), "%s", desc);

	return idx;
}

static void infer_speed(const char *caps, char *speed, size_t speed_sz)
{
	if (!speed || speed_sz == 0)
		return;

	if (!caps || caps[0] == '\0') {
		snprintf(speed, speed_sz, "unknown");
		return;
	}

	if (strstr(caps, "100G"))
		snprintf(speed, speed_sz, "100G");
	else if (strstr(caps, "40G"))
		snprintf(speed, speed_sz, "40G");
	else if (strstr(caps, "25G"))
		snprintf(speed, speed_sz, "25G");
	else if (strstr(caps, "10G"))
		snprintf(speed, speed_sz, "10G");
	else if (strstr(caps, "1G"))
		snprintf(speed, speed_sz, "1G");
	else
		snprintf(speed, speed_sz, "unknown");
}

static void json_print_escaped(const char *s)
{
	const unsigned char *p = (const unsigned char *)s;

	if (!s)
		return;

	while (*p) {
		switch (*p) {
		case '\\':
			fputs("\\\\", stdout);
			break;
		case '"':
			fputs("\\\"", stdout);
			break;
		case '\n':
			fputs("\\n", stdout);
			break;
		case '\r':
			fputs("\\r", stdout);
			break;
		case '\t':
			fputs("\\t", stdout);
			break;
		default:
			if (*p < 0x20)
				printf("\\u%04x", *p);
			else
				putchar(*p);
			break;
		}
		p++;
	}
}

int rs_topology_discover(struct rs_topology *topo)
{
	DIR *dir;
	struct dirent *de;
	char hostname[64];

	if (!topo)
		return -1;

	memset(topo, 0, sizeof(*topo));

	if (gethostname(hostname, sizeof(hostname)) != 0)
		snprintf(hostname, sizeof(hostname), "local-switch");
	hostname[sizeof(hostname) - 1] = '\0';

	if (add_or_get_node(topo, hostname, "", "local") != 0) {
		RS_LOG_ERROR("Failed to add local topology node");
		return -1;
	}

	dir = opendir(TOPO_LLDP_DATA_DIR);
	if (!dir) {
		if (errno == ENOENT)
			return 0;
		RS_LOG_ERROR("Failed to open %s: %s", TOPO_LLDP_DATA_DIR, strerror(errno));
		return -1;
	}

	while ((de = readdir(dir)) != NULL) {
		char path[PATH_MAX];
		char json[8192];
		char system_name[64] = {0};
		char mgmt_addr[46] = {0};
		char remote_port[32] = {0};
		char description[128] = {0};
		char capabilities[128] = {0};
		char local_port[32] = {0};
		char link_speed[16] = {0};
		int remote_idx;

		if (de->d_name[0] == '.')
			continue;
		if (!strstr(de->d_name, ".json"))
			continue;

		snprintf(path, sizeof(path), "%s/%s", TOPO_LLDP_DATA_DIR, de->d_name);
		if (read_text_file(path, json, sizeof(json)) != 0)
			continue;

		parse_json_string_field(json, "system_name", system_name, sizeof(system_name));
		parse_json_string_field(json, "mgmt_addr", mgmt_addr, sizeof(mgmt_addr));
		parse_json_string_field(json, "port_id", remote_port, sizeof(remote_port));
		parse_json_string_field(json, "port_desc", description, sizeof(description));
		parse_json_string_field(json, "capabilities", capabilities, sizeof(capabilities));

		if (system_name[0] == '\0') {
			if (mgmt_addr[0] != '\0')
				snprintf(system_name, sizeof(system_name), "%s", mgmt_addr);
			else
				snprintf(system_name, sizeof(system_name), "unknown");
		}

		if (remote_port[0] == '\0')
			snprintf(remote_port, sizeof(remote_port), "unknown");

		if (parse_json_string_field(json, "local_port", local_port, sizeof(local_port)) != 0 &&
		    parse_json_string_field(json, "ifname", local_port, sizeof(local_port)) != 0)
			infer_local_port_from_file(de->d_name, local_port, sizeof(local_port));

		if (parse_json_string_field(json, "link_speed", link_speed, sizeof(link_speed)) != 0)
			infer_speed(capabilities, link_speed, sizeof(link_speed));

		remote_idx = add_or_get_node(topo, system_name, mgmt_addr, description);
		if (remote_idx < 0)
			continue;

		if (topo->link_count >= TOPO_MAX_LINKS)
			continue;

		topo->links[topo->link_count].local_node_idx = 0;
		topo->links[topo->link_count].remote_node_idx = remote_idx;
		snprintf(topo->links[topo->link_count].local_port,
			 sizeof(topo->links[topo->link_count].local_port), "%s", local_port);
		snprintf(topo->links[topo->link_count].remote_port,
			 sizeof(topo->links[topo->link_count].remote_port), "%s", remote_port);
		snprintf(topo->links[topo->link_count].link_speed,
			 sizeof(topo->links[topo->link_count].link_speed), "%s", link_speed);
		topo->link_count++;

		topo->nodes[0].port_count++;
		topo->nodes[remote_idx].port_count++;
	}

	closedir(dir);
	return 0;
}

void rs_topology_print(const struct rs_topology *topo)
{
	if (!topo)
		return;

	printf("Network Topology\n\n");
	printf("Nodes:\n");
	printf("%-5s %-24s %-18s %-6s %s\n", "Index", "System Name", "Management IP", "Ports", "Description");
	printf("%-5s %-24s %-18s %-6s %s\n", "-----", "-----------", "-------------", "-----", "-----------");
	for (int i = 0; i < topo->node_count; i++) {
		printf("%-5d %-24s %-18s %-6d %s\n",
		       i,
		       topo->nodes[i].system_name[0] ? topo->nodes[i].system_name : "-",
		       topo->nodes[i].mgmt_addr[0] ? topo->nodes[i].mgmt_addr : "-",
		       topo->nodes[i].port_count,
		       topo->nodes[i].description[0] ? topo->nodes[i].description : "-");
	}

	printf("\nLinks:\n");
	printf("%-20s %-24s %-20s %s\n", "Local Port", "Remote System", "Remote Port", "Speed");
	printf("%-20s %-24s %-20s %s\n", "----------", "-------------", "-----------", "-----");
	for (int i = 0; i < topo->link_count; i++) {
		int remote = topo->links[i].remote_node_idx;
		printf("%-20s %-24s %-20s %s\n",
		       topo->links[i].local_port,
		       (remote >= 0 && remote < topo->node_count) ? topo->nodes[remote].system_name : "unknown",
		       topo->links[i].remote_port,
		       topo->links[i].link_speed);
	}

	printf("\n%d nodes, %d links discovered\n", topo->node_count, topo->link_count);
}

void rs_topology_print_json(const struct rs_topology *topo)
{
	if (!topo) {
		printf("{\"nodes\":[],\"links\":[]}\n");
		return;
	}

	printf("{\"nodes\":[");
	for (int i = 0; i < topo->node_count; i++) {
		printf("%s{\"name\":\"", i ? "," : "");
		json_print_escaped(topo->nodes[i].system_name);
		printf("\",\"mgmt_addr\":\"");
		json_print_escaped(topo->nodes[i].mgmt_addr);
		printf("\",\"description\":\"");
		json_print_escaped(topo->nodes[i].description);
		printf("\",\"port_count\":%d}", topo->nodes[i].port_count);
	}

	printf("],\"links\":[");
	for (int i = 0; i < topo->link_count; i++) {
		int local = topo->links[i].local_node_idx;
		int remote = topo->links[i].remote_node_idx;
		const char *local_name = (local >= 0 && local < topo->node_count) ? topo->nodes[local].system_name : "";
		const char *remote_name = (remote >= 0 && remote < topo->node_count) ? topo->nodes[remote].system_name : "";

		printf("%s{\"local_node\":\"", i ? "," : "");
		json_print_escaped(local_name);
		printf("\",\"local_port\":\"");
		json_print_escaped(topo->links[i].local_port);
		printf("\",\"remote_node\":\"");
		json_print_escaped(remote_name);
		printf("\",\"remote_port\":\"");
		json_print_escaped(topo->links[i].remote_port);
		printf("\",\"speed\":\"");
		json_print_escaped(topo->links[i].link_speed);
		printf("\"}");
	}
	printf("]}\n");
}
