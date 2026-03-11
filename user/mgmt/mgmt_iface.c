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

static int setup_forwarding(const struct rs_mgmt_iface_config *cfg)
{
	char cmd[512];

	snprintf(cmd, sizeof(cmd),
		 "ip addr add 169.254.1.1/30 dev %s 2>/dev/null || true",
		 cfg->veth_host);
	run_cmd(cmd);

	snprintf(cmd, sizeof(cmd),
		 "ip netns exec %s ip addr add 169.254.1.2/30 dev %s",
		 cfg->mgmt_ns, cfg->veth_ns);
	run_cmd(cmd);

	snprintf(cmd, sizeof(cmd),
		 "ip netns exec %s ip route add default via 169.254.1.1",
		 cfg->mgmt_ns);
	run_cmd(cmd);

	run_cmd("sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1");

	snprintf(cmd, sizeof(cmd),
		 "iptables -t nat -A POSTROUTING -s 169.254.1.0/30 "
		 "-o %s -j MASQUERADE 2>/dev/null || true",
		 cfg->parent_iface);
	run_cmd(cmd);

	snprintf(cmd, sizeof(cmd),
		 "iptables -A FORWARD -i %s -o %s -j ACCEPT 2>/dev/null || true",
		 cfg->veth_host, cfg->parent_iface);
	run_cmd(cmd);

	snprintf(cmd, sizeof(cmd),
		 "iptables -A FORWARD -i %s -o %s "
		 "-m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true",
		 cfg->parent_iface, cfg->veth_host);
	run_cmd(cmd);

	RS_LOG_INFO("Forwarding configured: %s <-> %s via NAT",
		    cfg->veth_host, cfg->parent_iface);
	return 0;
}

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

	ret = setup_forwarding(cfg);
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
		 "ip netns exec %s dhclient -nw %s 2>/dev/null",
		 cfg->mgmt_ns, cfg->veth_ns);

	if (run_cmd(cmd) != 0) {
		RS_LOG_WARN("DHCP failed on %s, using link-local only", cfg->veth_ns);
		snprintf(cmd, sizeof(cmd),
			 "ip netns exec %s ip addr add 169.254.1.2/30 dev %s 2>/dev/null || true",
			 cfg->mgmt_ns, cfg->veth_ns);
		run_cmd(cmd);
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
		 "ip netns exec %s dhclient -r %s 2>/dev/null || true",
		 cfg->mgmt_ns, cfg->veth_ns);
	run_cmd(cmd);

	snprintf(cmd, sizeof(cmd),
		 "ip link del %s 2>/dev/null || true", cfg->veth_host);
	run_cmd(cmd);

	snprintf(cmd, sizeof(cmd),
		 "iptables -t nat -D POSTROUTING -s 169.254.1.0/30 "
		 "-o %s -j MASQUERADE 2>/dev/null || true",
		 cfg->parent_iface);
	run_cmd(cmd);

	snprintf(cmd, sizeof(cmd),
		 "iptables -D FORWARD -i %s -o %s -j ACCEPT 2>/dev/null || true",
		 cfg->veth_host, cfg->parent_iface);
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
