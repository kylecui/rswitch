// SPDX-License-Identifier: GPL-2.0

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <net/if.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <sys/ioctl.h>
#include <net/if_arp.h>
#include <dirent.h>
#include <fcntl.h>
#include <sched.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../common/rs_log.h"
#include "mgmt_iface.h"

#define RS_PORT_CONFIG_MAP_PATH    "/sys/fs/bpf/rs_port_config_map"
#define RS_IFINDEX_TO_PORT_MAP_PATH "/sys/fs/bpf/rs_ifindex_to_port_map"
#define RS_VLAN_MAP_PATH           "/sys/fs/bpf/rs_vlan_map"
#define RS_XDP_DEVMAP_PATH         "/sys/fs/bpf/rs_xdp_devmap"
#define RS_MAC_TABLE_PATH          "/sys/fs/bpf/rs_mac_table"

#define RS_VLAN_MODE_ACCESS 1
#define RS_MAX_VLANS 4

#define MDNS_PORT 5353
#define MDNS_ADDR "224.0.0.251"

static volatile int g_mdns_running;
static pthread_t g_mdns_thread;
static struct rs_mgmt_iface_config g_mdns_cfg;

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

struct rs_port_config {
	__u32 ifindex;
	__u8  enabled;
	__u8  mgmt_type;
	__u8  vlan_mode;
	__u8  learning;
	__u16 pvid;
	__u16 native_vlan;
	__u16 access_vlan;
	__u16 allowed_vlan_count;
	__u16 allowed_vlans[128];
	__u16 tagged_vlan_count;
	__u16 tagged_vlans[64];
	__u16 untagged_vlan_count;
	__u16 untagged_vlans[64];
	__u8  default_prio;
	__u8  trust_dscp;
	__u16 rate_limit_kbps;
	__u8  port_security;
	__u8  max_macs;
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

struct rs_mac_key {
	__u8 mac[6];
	__u16 vlan;
} __attribute__((packed));

struct rs_mac_entry {
	__u32 ifindex;
	__u8  static_entry;
	__u8  reserved[3];
	__u64 last_seen;
	__u32 hit_count;
} __attribute__((packed));

static int get_ns_iface_mac(const char *ns_name, const char *iface_name, __u8 *mac)
{
	char cmd[256];
	char mac_str[32];
	int ret;

	snprintf(cmd, sizeof(cmd),
		 "ip netns exec %s cat /sys/class/net/%s/address 2>/dev/null",
		 ns_name, iface_name);

	ret = run_cmd_output(cmd, mac_str, sizeof(mac_str));
	if (ret != 0)
		return ret;

	/* Parse MAC address string "aa:bb:cc:dd:ee:ff" */
	unsigned int m[6];
	if (sscanf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x",
		   &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) != 6) {
		return -EINVAL;
	}

	for (int i = 0; i < 6; i++)
		mac[i] = (__u8)m[i];

	return 0;
}

static int register_mgmt_br_xdp(const struct rs_mgmt_iface_config *cfg)
{
	__u32 mgmt_ifindex;
	__u16 mgmt_vlan;
	int port_config_fd, ifindex_to_port_fd, vlan_map_fd, devmap_fd;
	int err = 0;

	mgmt_ifindex = if_nametoindex(cfg->veth_host);
	if (mgmt_ifindex == 0) {
		RS_LOG_WARN("mgmt-br ifindex lookup failed");
		return -ENOENT;
	}

	mgmt_vlan = cfg->mgmt_vlan > 0 ? cfg->mgmt_vlan : 1;

	port_config_fd = bpf_obj_get(RS_PORT_CONFIG_MAP_PATH);
	ifindex_to_port_fd = bpf_obj_get(RS_IFINDEX_TO_PORT_MAP_PATH);
	vlan_map_fd = bpf_obj_get(RS_VLAN_MAP_PATH);
	devmap_fd = bpf_obj_get(RS_XDP_DEVMAP_PATH);

	if (port_config_fd < 0 || ifindex_to_port_fd < 0 ||
	    vlan_map_fd < 0 || devmap_fd < 0) {
		RS_LOG_WARN("BPF maps not available (loader not running?)");
		if (port_config_fd >= 0) close(port_config_fd);
		if (ifindex_to_port_fd >= 0) close(ifindex_to_port_fd);
		if (vlan_map_fd >= 0) close(vlan_map_fd);
		if (devmap_fd >= 0) close(devmap_fd);
		return -ENOENT;
	}

	__u32 port_idx = 254;
	err = bpf_map_update_elem(ifindex_to_port_fd, &mgmt_ifindex, &port_idx, BPF_ANY);
	if (err)
		RS_LOG_WARN("Failed to set ifindex->port for mgmt-br: %s", strerror(errno));

	struct rs_port_config pcfg = {
		.ifindex = mgmt_ifindex,
		.enabled = 1,
		.mgmt_type = 1,
		.vlan_mode = RS_VLAN_MODE_ACCESS,
		.learning = 1,
		.pvid = mgmt_vlan,
		.native_vlan = mgmt_vlan,
		.access_vlan = mgmt_vlan,
	};
	err = bpf_map_update_elem(port_config_fd, &mgmt_ifindex, &pcfg, BPF_ANY);
	if (err)
		RS_LOG_WARN("Failed to configure mgmt-br port: %s", strerror(errno));
	else
		RS_LOG_INFO("mgmt-br port_config: ifindex=%u, ACCESS vlan=%u", mgmt_ifindex, mgmt_vlan);

	struct rs_vlan_members vlan = {0};
	__u16 vkey = mgmt_vlan;
	bpf_map_lookup_elem(vlan_map_fd, &vkey, &vlan);
	vlan.vlan_id = mgmt_vlan;

	int word_idx = (mgmt_ifindex - 1) / 64;
	int bit_idx = (mgmt_ifindex - 1) % 64;
	if (word_idx < RS_MAX_VLANS) {
		vlan.untagged_members[word_idx] |= (1ULL << bit_idx);
		vlan.member_count++;
	}
	err = bpf_map_update_elem(vlan_map_fd, &vkey, &vlan, BPF_ANY);
	if (err)
		RS_LOG_WARN("Failed to add mgmt-br to VLAN %u: %s", mgmt_vlan, strerror(errno));
	else
		RS_LOG_INFO("VLAN %u: added mgmt-br (ifindex=%u) as untagged member", mgmt_vlan, mgmt_ifindex);

	struct bpf_devmap_val xdp_val = {
		.ifindex = mgmt_ifindex,
		.bpf_prog = { .fd = -1 },
	};
	err = bpf_map_update_elem(devmap_fd, &mgmt_ifindex, &xdp_val, BPF_ANY);
	if (err)
		RS_LOG_WARN("Failed to add mgmt-br to XDP devmap: %s", strerror(errno));
	else
		RS_LOG_INFO("mgmt-br added to XDP devmap (ifindex=%u)", mgmt_ifindex);

	/* Get XDP dispatcher from an existing switch port.
	 * rs_progs[0] contains the first module (dhcp_snoop), not the dispatcher.
	 * The dispatcher is attached to switch ports by the loader. */
	int disp_prog_fd = -1;
	__u32 disp_prog_id = 0;
	__u32 mgmt_xdp_flags = XDP_FLAGS_SKB_MODE;

	/* Dynamic discovery: scan all network interfaces for XDP programs.
	 * This avoids hardcoding interface names which differ across machines. */
	DIR *netdir = opendir("/sys/class/net");
	if (netdir) {
		struct dirent *entry;
		while ((entry = readdir(netdir)) != NULL) {
			if (entry->d_name[0] == '.')
				continue;
			if (strcmp(entry->d_name, "lo") == 0 ||
			    strcmp(entry->d_name, "mgmt-br") == 0 ||
			    strncmp(entry->d_name, "veth", 4) == 0)
				continue;

			__u32 ifidx = if_nametoindex(entry->d_name);
			if (ifidx == 0)
				continue;

			struct bpf_xdp_query_opts opts = { .sz = sizeof(opts) };
			if (bpf_xdp_query(ifidx, 0, &opts) == 0 && opts.prog_id > 0) {
				disp_prog_id = opts.prog_id;
				if (opts.skb_prog_id > 0)
					mgmt_xdp_flags = XDP_FLAGS_SKB_MODE;
				else
					mgmt_xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
				RS_LOG_INFO("Found XDP dispatcher on %s (prog_id=%u, %s mode)",
					    entry->d_name, disp_prog_id,
					    (opts.skb_prog_id > 0) ? "generic" : "native");
				break;
			}
		}
		closedir(netdir);
	} else {
		RS_LOG_WARN("Cannot open /sys/class/net for XDP probe: %s",
			    strerror(errno));
	}

	if (disp_prog_id > 0) {
		disp_prog_fd = bpf_prog_get_fd_by_id(disp_prog_id);
		if (disp_prog_fd < 0)
			RS_LOG_WARN("Failed to get FD for dispatcher prog ID %u: %s",
				    disp_prog_id, strerror(errno));
	}

	if (disp_prog_fd >= 0) {
		err = bpf_xdp_attach(mgmt_ifindex, disp_prog_fd, mgmt_xdp_flags, NULL);
		if (err)
			RS_LOG_WARN("Failed to attach XDP to mgmt-br: %s", strerror(-err));
		else
			RS_LOG_INFO("XDP dispatcher attached to mgmt-br (%s mode)",
				    (mgmt_xdp_flags == XDP_FLAGS_SKB_MODE) ? "generic" : "native");
		close(disp_prog_fd);
	} else {
		RS_LOG_WARN("No XDP dispatcher found, mgmt-br may not receive traffic");
	}

	int mac_table_fd = bpf_obj_get(RS_MAC_TABLE_PATH);
	if (mac_table_fd >= 0) {
		__u8 mgmt0_mac[6];
		if (get_ns_iface_mac(cfg->mgmt_ns, cfg->veth_ns, mgmt0_mac) == 0) {
			struct rs_mac_key mkey = {0};
			memcpy(mkey.mac, mgmt0_mac, 6);
			mkey.vlan = mgmt_vlan;

			struct rs_mac_entry mentry = {
				.ifindex = mgmt_ifindex,
				.static_entry = 1,
				.last_seen = 0,
				.hit_count = 0,
			};

			err = bpf_map_update_elem(mac_table_fd, &mkey, &mentry, BPF_ANY);
			if (err)
				RS_LOG_WARN("Failed to add MAC entry for mgmt0: %s", strerror(errno));
			else
				RS_LOG_INFO("MAC table: %02x:%02x:%02x:%02x:%02x:%02x -> mgmt-br (ifindex=%u, vlan=%u)",
					    mgmt0_mac[0], mgmt0_mac[1], mgmt0_mac[2],
					    mgmt0_mac[3], mgmt0_mac[4], mgmt0_mac[5],
					    mgmt_ifindex, mgmt_vlan);
		} else {
			RS_LOG_WARN("Could not get mgmt0 MAC address");
		}
		close(mac_table_fd);
	} else {
		RS_LOG_WARN("MAC table not available: %s", strerror(errno));
	}

	close(port_config_fd);
	close(ifindex_to_port_fd);
	close(vlan_map_fd);
	close(devmap_fd);

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

	/* Register mgmt-br in BPF maps so DHCP traffic can reach it.
	 * This is only needed when running standalone (loader not active).
	 * If maps aren't available, we continue anyway — loader may be
	 * managing the interface.                                        */
	ret = register_mgmt_br_xdp(cfg);
	if (ret < 0)
		RS_LOG_WARN("Could not register mgmt-br in XDP pipeline");

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
		if (cfg->gateway[0] != '\0') {
			snprintf(cmd, sizeof(cmd),
				 "ip netns exec %s ip route replace default via %s dev %s",
				 cfg->mgmt_ns, cfg->gateway, cfg->veth_ns);
			if (run_cmd(cmd) != 0)
				RS_LOG_WARN("Failed to set gateway %s", cfg->gateway);
		}
		RS_LOG_INFO("Static IP %s assigned to %s", cfg->static_ip, cfg->veth_ns);
		return 0;
	}

	/* Clear stale dhcpcd control sockets inherited from the root
	 * namespace — otherwise dhcpcd connects to the host daemon
	 * instead of starting a fresh instance for mgmt0.           */
	snprintf(cmd, sizeof(cmd),
		 "ip netns exec %s rm -f /run/dhcpcd/sock /run/dhcpcd/unpriv.sock "
		 "/run/dhcpcd.pid /run/dhcpcd.unpriv.pid 2>/dev/null || true",
		 cfg->mgmt_ns);
	run_cmd(cmd);

	snprintf(cmd, sizeof(cmd),
		 "ip netns exec %s dhcpcd --persistent --noipv4ll -b %s 2>/dev/null",
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

int rs_mgmt_iface_enter_netns(const char *ns_name)
{
	char path[128];
	int fd;

	snprintf(path, sizeof(path), "/var/run/netns/%s", ns_name);
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -errno;

	if (setns(fd, CLONE_NEWNET) < 0) {
		int err = errno;
		close(fd);
		return -err;
	}
	close(fd);
	return 0;
}

int rs_mgmt_iface_ns_probe(const char *ns_name)
{
	char path[128];
	int ns_fd, self_fd, ret = 0;

	/* Save current namespace so we can restore after probe */
	self_fd = open("/proc/self/ns/net", O_RDONLY);
	if (self_fd < 0)
		return 0;

	/* Try to open target namespace */
	snprintf(path, sizeof(path), "/var/run/netns/%s", ns_name);
	ns_fd = open(path, O_RDONLY);
	if (ns_fd < 0) {
		close(self_fd);
		return 0;
	}

	/* Try setns to verify namespace is enterable */
	if (setns(ns_fd, CLONE_NEWNET) == 0) {
		ret = 1;
		/* Restore original namespace */
		setns(self_fd, CLONE_NEWNET);
	}

	close(ns_fd);
	close(self_fd);
	return ret;
}

/* Build an unsolicited mDNS A-record response (announcement or query reply).
 * |tid| is the DNS transaction ID (0 for announcements).
 * Returns the packet length, or 0 on failure. */
static size_t mdns_build_a_record(uint8_t *out, size_t outsz, uint16_t tid,
				   const struct in_addr *ip)
{
	if (outsz < 45)
		return 0;

	size_t off = 0;
	/* Header: tid, flags=0x8400 (authoritative response), ancount=1 */
	out[off++] = (tid >> 8) & 0xff;
	out[off++] = tid & 0xff;
	out[off++] = 0x84; out[off++] = 0x00;  /* QR=1, AA=1 */
	out[off++] = 0x00; out[off++] = 0x00;  /* qdcount=0 */
	out[off++] = 0x00; out[off++] = 0x01;  /* ancount=1 */
	out[off++] = 0x00; out[off++] = 0x00;  /* nscount=0 */
	out[off++] = 0x00; out[off++] = 0x00;  /* arcount=0 */

	/* Name: rswitch.local */
	out[off++] = 7;
	memcpy(out + off, "rswitch", 7); off += 7;
	out[off++] = 5;
	memcpy(out + off, "local", 5); off += 5;
	out[off++] = 0;

	/* Type A, class IN + cache-flush bit */
	out[off++] = 0x00; out[off++] = 0x01;
	out[off++] = 0x80; out[off++] = 0x01;
	/* TTL: 120s */
	out[off++] = 0x00; out[off++] = 0x00;
	out[off++] = 0x00; out[off++] = 0x78;
	/* RDLENGTH=4, RDATA=IPv4 */
	out[off++] = 0x00; out[off++] = 0x04;
	memcpy(out + off, ip, 4); off += 4;

	return off;
}

#define MDNS_ANNOUNCE_INTERVAL  60   /* periodic re-announce interval (seconds) */
#define MDNS_STARTUP_ANNOUNCES  3    /* RFC 6762 §8.3: send 3 at startup */

static void *mdns_responder_thread(void *arg)
{
	(void)arg;
	int sock = -1;
	struct sockaddr_in addr, mcast;
	struct ip_mreq mreq;
	uint8_t buf[512];
	uint8_t resp[256];
	char mgmt_ip[64];
	struct in_addr ip_addr;

	if (rs_mgmt_iface_enter_netns(g_mdns_cfg.mgmt_ns) < 0) {
		RS_LOG_ERROR("mDNS: failed to enter namespace %s", g_mdns_cfg.mgmt_ns);
		return NULL;
	}

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		RS_LOG_ERROR("mDNS: socket failed: %s", strerror(errno));
		return NULL;
	}

	int reuse = 1;
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(MDNS_PORT);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		RS_LOG_ERROR("mDNS: bind failed: %s", strerror(errno));
		close(sock);
		return NULL;
	}

	int joined = 0;
	unsigned int backoff = 1;  /* exponential backoff: 1s -> 2s -> 4s -> ... -> 30s cap */

	while (g_mdns_running && !joined) {
		if (rs_mgmt_iface_get_ip(&g_mdns_cfg, mgmt_ip, sizeof(mgmt_ip)) == 0 &&
		    inet_pton(AF_INET, mgmt_ip, &ip_addr) == 1) {
			mreq.imr_multiaddr.s_addr = inet_addr(MDNS_ADDR);
			mreq.imr_interface = ip_addr;
			if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) == 0) {
				joined = 1;
				RS_LOG_INFO("mDNS: joined multicast on %s", mgmt_ip);
			}
		}
		if (!joined) {
			RS_LOG_DEBUG("mDNS: waiting for IP / multicast join (retry in %us)", backoff);
			sleep(backoff);
			if (backoff < 30)
				backoff = (backoff * 2 > 30) ? 30 : backoff * 2;
		}
	}

	if (!joined) {
		/* g_mdns_running was cleared — clean shutdown */
		RS_LOG_INFO("mDNS: shutdown before multicast join completed");
		close(sock);
		return NULL;
	}

	memset(&mcast, 0, sizeof(mcast));
	mcast.sin_family = AF_INET;
	mcast.sin_port = htons(MDNS_PORT);
	mcast.sin_addr.s_addr = inet_addr(MDNS_ADDR);

	RS_LOG_INFO("mDNS responder started in namespace %s", g_mdns_cfg.mgmt_ns);

	/* Startup announcements — RFC 6762 §8.3 */
	for (int i = 0; i < MDNS_STARTUP_ANNOUNCES && g_mdns_running; i++) {
		if (rs_mgmt_iface_get_ip(&g_mdns_cfg, mgmt_ip, sizeof(mgmt_ip)) == 0 &&
		    inet_pton(AF_INET, mgmt_ip, &ip_addr) == 1) {
			size_t plen = mdns_build_a_record(resp, sizeof(resp), 0, &ip_addr);
			if (plen > 0) {
				sendto(sock, resp, plen, 0,
				       (struct sockaddr *)&mcast, sizeof(mcast));
				RS_LOG_INFO("mDNS: announce rswitch.local -> %s (%d/%d)",
					    mgmt_ip, i + 1, MDNS_STARTUP_ANNOUNCES);
			}
		}
		if (i < MDNS_STARTUP_ANNOUNCES - 1)
			sleep(1);
	}

	struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	unsigned int idle_ticks = 0;

	while (g_mdns_running) {
		struct sockaddr_in from;
		socklen_t fromlen = sizeof(from);
		ssize_t n = recvfrom(sock, buf, sizeof(buf), 0,
				     (struct sockaddr *)&from, &fromlen);

		if (n <= 0) {
			idle_ticks++;
			if (idle_ticks >= MDNS_ANNOUNCE_INTERVAL) {
				idle_ticks = 0;
				if (rs_mgmt_iface_get_ip(&g_mdns_cfg, mgmt_ip, sizeof(mgmt_ip)) == 0 &&
				    inet_pton(AF_INET, mgmt_ip, &ip_addr) == 1) {
					size_t plen = mdns_build_a_record(resp, sizeof(resp), 0, &ip_addr);
					if (plen > 0) {
						sendto(sock, resp, plen, 0,
						       (struct sockaddr *)&mcast, sizeof(mcast));
						RS_LOG_DEBUG("mDNS: periodic announce rswitch.local -> %s", mgmt_ip);
					}
				}
			}
			continue;
		}

		if (n < 12)
			continue;

		uint16_t flags = (buf[2] << 8) | buf[3];
		if (flags & 0x8000)
			continue;

		uint16_t qdcount = (buf[4] << 8) | buf[5];
		if (qdcount < 1)
			continue;

		size_t off = 12;
		char name[256] = {0};
		size_t name_off = 0;
		while (off < (size_t)n && buf[off] != 0) {
			uint8_t len = buf[off++];
			if (off + len > (size_t)n)
				break;
			if (name_off > 0)
				name[name_off++] = '.';
			memcpy(name + name_off, buf + off, len);
			name_off += len;
			off += len;
		}
		off++;

		if (off + 4 > (size_t)n)
			continue;
		uint16_t qtype = (buf[off] << 8) | buf[off + 1];
		if (qtype != 1)
			continue;

		if (strcasecmp(name, "rswitch.local") != 0)
			continue;

		if (rs_mgmt_iface_get_ip(&g_mdns_cfg, mgmt_ip, sizeof(mgmt_ip)) != 0)
			continue;
		if (inet_pton(AF_INET, mgmt_ip, &ip_addr) != 1)
			continue;

		uint16_t tid = ((uint16_t)buf[0] << 8) | buf[1];
		size_t roff = mdns_build_a_record(resp, sizeof(resp), tid, &ip_addr);
		if (roff > 0) {
			sendto(sock, resp, roff, 0, (struct sockaddr *)&mcast, sizeof(mcast));
			RS_LOG_DEBUG("mDNS: responded rswitch.local -> %s", mgmt_ip);
		}
	}

	close(sock);
	RS_LOG_INFO("mDNS responder stopped");
	return NULL;
}

int rs_mgmt_iface_start_mdns(const struct rs_mgmt_iface_config *cfg)
{
	if (!cfg)
		return -EINVAL;

	if (g_mdns_running)
		return 0;

	memcpy(&g_mdns_cfg, cfg, sizeof(g_mdns_cfg));
	g_mdns_running = 1;

	if (pthread_create(&g_mdns_thread, NULL, mdns_responder_thread, NULL) != 0) {
		g_mdns_running = 0;
		return -errno;
	}

	pthread_detach(g_mdns_thread);
	return 0;
}

void rs_mgmt_iface_stop_mdns(void)
{
	if (!g_mdns_running)
		return;

	g_mdns_running = 0;
}

int rs_mgmt_iface_destroy(const struct rs_mgmt_iface_config *cfg)
{
	char cmd[512];

	if (!cfg)
		return -EINVAL;

	rs_mgmt_iface_stop_mdns();

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

int rs_mgmt_iface_reconfigure(const struct rs_mgmt_iface_config *cfg)
{
	char cmd[512];

	if (!cfg)
		return -EINVAL;

	snprintf(cmd, sizeof(cmd),
		 "ip netns exec %s dhcpcd -k %s 2>/dev/null || true",
		 cfg->mgmt_ns, cfg->veth_ns);
	run_cmd(cmd);

	snprintf(cmd, sizeof(cmd),
		 "ip netns exec %s ip addr flush dev %s scope global 2>/dev/null || true",
		 cfg->mgmt_ns, cfg->veth_ns);
	run_cmd(cmd);

	snprintf(cmd, sizeof(cmd),
		 "ip netns exec %s ip route flush dev %s 2>/dev/null || true",
		 cfg->mgmt_ns, cfg->veth_ns);
	run_cmd(cmd);

	return rs_mgmt_iface_obtain_ip(cfg);
}
