// SPDX-License-Identifier: GPL-2.0
#ifndef RSWITCH_MGMT_IFACE_H
#define RSWITCH_MGMT_IFACE_H

#define MGMT_NS_NAME    "rswitch-mgmt"
#define MGMT_VETH_HOST  "mgmt-br"
#define MGMT_VETH_NS    "mgmt0"
#define MGMT_DEFAULT_PORT 8080
#define MGMT_STATE_DIR  "/var/lib/rswitch/mgmt"

struct rs_mgmt_iface_config {
	char parent_iface[32];   /* physical port to bridge with (e.g. "eth0") */
	char mgmt_ns[64];       /* namespace name (default: rswitch-mgmt) */
	char veth_host[32];     /* host-side veth name */
	char veth_ns[32];       /* namespace-side veth name */
	int  mode;              /* 0=dhcp, 1=static */
	char static_ip[46];     /* static IP (CIDR notation, e.g. "10.0.0.1/24") */
	char gateway[46];       /* default gateway (e.g. "10.0.0.1"), empty = none */
	int  mgmt_vlan;         /* management VLAN tag (0 = untagged) */
};

/* Initialize default configuration */
void rs_mgmt_iface_default_config(struct rs_mgmt_iface_config *cfg);

/*
 * Create management namespace and veth pair.
 * The host-side veth (mgmt-br) is left unconfigured — the rswitch loader
 * registers it in the XDP pipeline (devmap, port_config, VLAN membership)
 * so that L2 forwarding reaches it through the same BPF path as physical ports.
 * Returns 0 on success, negative errno on failure.
 */
int rs_mgmt_iface_create(const struct rs_mgmt_iface_config *cfg);

/*
 * Obtain IP address on the management interface.
 * Runs DHCP client or applies static IP inside the namespace.
 * Returns 0 on success, negative errno on failure.
 */
int rs_mgmt_iface_obtain_ip(const struct rs_mgmt_iface_config *cfg);

/*
 * Get the current management IP address.
 * Fills buf with the IP string.
 * Returns 0 on success, -ENOENT if no IP assigned.
 */
int rs_mgmt_iface_get_ip(const struct rs_mgmt_iface_config *cfg,
			  char *buf, int buf_len);

/*
 * Tear down management interface and namespace.
 * Returns 0 on success.
 */
int rs_mgmt_iface_destroy(const struct rs_mgmt_iface_config *cfg);

/*
 * Check if management interface is up and has an IP.
 * Returns 1 if healthy, 0 if not.
 */
int rs_mgmt_iface_is_healthy(const struct rs_mgmt_iface_config *cfg);

/*
 * Reconfigure management IP at runtime.
 * Tears down existing IP config, applies new mode (dhcp/static).
 * Returns 0 on success, negative errno on failure.
 */
int rs_mgmt_iface_reconfigure(const struct rs_mgmt_iface_config *cfg);

/*
 * Start mDNS responder for rswitch.local in the management namespace.
 * Returns 0 on success, negative errno on failure.
 */
int rs_mgmt_iface_start_mdns(const struct rs_mgmt_iface_config *cfg);

/*
 * Stop mDNS responder.
 */
void rs_mgmt_iface_stop_mdns(void);

/*
 * Enter a network namespace by name.
 * Calls setns(CLONE_NEWNET) to switch the calling thread's network namespace.
 * Returns 0 on success, negative errno on failure.
 */
int rs_mgmt_iface_enter_netns(const char *ns_name);

/*
 * Probe if a namespace exists and is enterable.
 * Attempts to open /var/run/netns/{name} and verify setns() would succeed.
 * Does NOT actually switch namespaces (restores original ns after probe).
 * Returns 1 if namespace is healthy (exists and enterable), 0 otherwise.
 */
int rs_mgmt_iface_ns_probe(const char *ns_name);

#endif
