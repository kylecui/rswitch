// SPDX-License-Identifier: GPL-2.0

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#include "../common/rs_log.h"
#include "mgmt_iface.h"

static int run_cmd(const char *cmd)
{
	int ret = system(cmd);
	if (ret < 0)
		return -errno;
	if (WIFEXITED(ret))
		return WEXITSTATUS(ret) == 0 ? 0 : -EINVAL;
	return -EINVAL;
}

static int run_cmd_output(const char *cmd, char *buf, int buf_len)
{
	FILE *fp;
	char *nl;

	fp = popen(cmd, "r");
	if (!fp)
		return -errno;

	if (!fgets(buf, buf_len, fp)) {
		pclose(fp);
		return -ENOENT;
	}

	pclose(fp);
	nl = strchr(buf, '\n');
	if (nl)
		*nl = '\0';
	return 0;
}

void rs_mgmt_iface_default_config(struct rs_mgmt_iface_config *cfg)
{
	if (!cfg)
		return;
	memset(cfg, 0, sizeof(*cfg));
	strncpy(cfg->parent_iface, "eth0", sizeof(cfg->parent_iface) - 1);
	strncpy(cfg->mgmt_ns, MGMT_NS_NAME, sizeof(cfg->mgmt_ns) - 1);
	strncpy(cfg->veth_host, MGMT_VETH_HOST, sizeof(cfg->veth_host) - 1);
	strncpy(cfg->veth_ns, MGMT_VETH_NS, sizeof(cfg->veth_ns) - 1);
	cfg->mode = 0;
	cfg->mgmt_vlan = 0;
}

static int ns_exists(const char *ns_name)
{
	char cmd[256];
	snprintf(cmd, sizeof(cmd), "ip netns list 2>/dev/null | grep -qw '%s'", ns_name);
	return run_cmd(cmd) == 0;
}

static int create_namespace(const char *ns_name)
{
	char cmd[256];

	if (ns_exists(ns_name)) {
		RS_LOG_INFO("Namespace %s already exists", ns_name);
		return 0;
	}

	snprintf(cmd, sizeof(cmd), "ip netns add %s", ns_name);
	if (run_cmd(cmd) != 0) {
		RS_LOG_ERROR("Failed to create namespace %s", ns_name);
		return -EIO;
	}

	RS_LOG_INFO("Created namespace %s", ns_name);
	return 0;
}

static int create_veth_pair(const struct rs_mgmt_iface_config *cfg)
{
	char cmd[512];

	snprintf(cmd, sizeof(cmd),
		 "ip link add %s type veth peer name %s",
		 cfg->veth_host, cfg->veth_ns);
	if (run_cmd(cmd) != 0) {
		RS_LOG_ERROR("Failed to create veth pair %s <-> %s",
			     cfg->veth_host, cfg->veth_ns);
		return -EIO;
	}

	snprintf(cmd, sizeof(cmd),
		 "ip link set %s netns %s",
		 cfg->veth_ns, cfg->mgmt_ns);
	if (run_cmd(cmd) != 0) {
		RS_LOG_ERROR("Failed to move %s into namespace %s",
			     cfg->veth_ns, cfg->mgmt_ns);
		return -EIO;
	}

	snprintf(cmd, sizeof(cmd), "ip link set %s up", cfg->veth_host);
	run_cmd(cmd);

	snprintf(cmd, sizeof(cmd),
		 "ip netns exec %s ip link set %s up",
		 cfg->mgmt_ns, cfg->veth_ns);
	run_cmd(cmd);

	snprintf(cmd, sizeof(cmd),
		 "ip netns exec %s ip link set lo up",
		 cfg->mgmt_ns);
	run_cmd(cmd);

	RS_LOG_INFO("Created veth pair: %s (host) <-> %s (ns:%s)",
		    cfg->veth_host, cfg->veth_ns, cfg->mgmt_ns);
	return 0;
}

/*
 * No explicit forwarding setup needed — mgmt-br participates as an
 * XDP pipeline port.  The loader registers it in rs_xdp_devmap,
 * rs_port_config_map, and the VLAN membership bitmap so that L2
 * flooding/unicast forwarding reaches mgmt-br through the same BPF
 * pipeline that connects the physical switch ports.
 *
 * Previously this function set up link-local addresses + iptables NAT.
 * That approach is removed in favour of the XDP-integrated model.
 */

int rs_mgmt_iface_create(const struct rs_mgmt_iface_config *cfg)
{
	int ret;

	if (!cfg)
		return -EINVAL;

	ret = create_namespace(cfg->mgmt_ns);
	if (ret < 0)
		return ret;

	ret = create_veth_pair(cfg);
	if (ret < 0)
		return ret;

	run_cmd("mkdir -p " MGMT_STATE_DIR);
	return 0;
}

int rs_mgmt_iface_obtain_ip(const struct rs_mgmt_iface_config *cfg)
{
	char cmd[512];

	if (!cfg)
		return -EINVAL;

	if (cfg->mode == 1 && cfg->static_ip[0] != '\0') {
		snprintf(cmd, sizeof(cmd),
			 "ip netns exec %s ip addr add %s dev %s 2>/dev/null || true",
			 cfg->mgmt_ns, cfg->static_ip, cfg->veth_ns);
		if (run_cmd(cmd) != 0) {
			RS_LOG_ERROR("Failed to assign static IP %s", cfg->static_ip);
			return -EIO;
		}
		RS_LOG_INFO("Static IP %s assigned to %s", cfg->static_ip, cfg->veth_ns);
		return 0;
	}

	snprintf(cmd, sizeof(cmd),
		 "ip netns exec %s dhcpcd -b %s 2>/dev/null",
		 cfg->mgmt_ns, cfg->veth_ns);

	if (run_cmd(cmd) != 0) {
		RS_LOG_WARN("DHCP client failed to start on %s", cfg->veth_ns);
		return -EIO;
	} else {
		RS_LOG_INFO("DHCP started on %s in namespace %s",
			    cfg->veth_ns, cfg->mgmt_ns);
	}

	return 0;
}

int rs_mgmt_iface_get_ip(const struct rs_mgmt_iface_config *cfg,
			  char *buf, int buf_len)
{
	char cmd[512];

	if (!cfg || !buf || buf_len <= 0)
		return -EINVAL;

	snprintf(cmd, sizeof(cmd),
		 "ip netns exec %s ip -4 addr show %s scope global "
		 "2>/dev/null | grep -oP 'inet \\K[^/]+'",
		 cfg->mgmt_ns, cfg->veth_ns);

	if (run_cmd_output(cmd, buf, buf_len) != 0) {
		snprintf(cmd, sizeof(cmd),
			 "ip netns exec %s ip -4 addr show %s "
			 "2>/dev/null | grep -oP 'inet \\K[^/]+'",
			 cfg->mgmt_ns, cfg->veth_ns);

		if (run_cmd_output(cmd, buf, buf_len) != 0)
			return -ENOENT;
	}

	return 0;
}

int rs_mgmt_iface_destroy(const struct rs_mgmt_iface_config *cfg)
{
	char cmd[512];

	if (!cfg)
		return -EINVAL;

	snprintf(cmd, sizeof(cmd),
		 "ip netns exec %s dhcpcd -k %s 2>/dev/null || true",
		 cfg->mgmt_ns, cfg->veth_ns);
	run_cmd(cmd);

	snprintf(cmd, sizeof(cmd),
		 "ip link del %s 2>/dev/null || true", cfg->veth_host);
	run_cmd(cmd);

	snprintf(cmd, sizeof(cmd),
		 "ip netns del %s 2>/dev/null || true", cfg->mgmt_ns);
	run_cmd(cmd);

	RS_LOG_INFO("Management interface destroyed");
	return 0;
}

int rs_mgmt_iface_is_healthy(const struct rs_mgmt_iface_config *cfg)
{
	char cmd[512];

	if (!cfg)
		return 0;

	if (!ns_exists(cfg->mgmt_ns))
		return 0;

	snprintf(cmd, sizeof(cmd),
		 "ip netns exec %s ip link show %s up 2>/dev/null | grep -q UP",
		 cfg->mgmt_ns, cfg->veth_ns);

	return run_cmd(cmd) == 0 ? 1 : 0;
}
