// SPDX-License-Identifier: GPL-2.0
#ifndef RSWITCH_TOPOLOGY_H
#define RSWITCH_TOPOLOGY_H

#include <stdint.h>

#define TOPO_MAX_NODES 64
#define TOPO_MAX_LINKS 256
#define TOPO_LLDP_DATA_DIR "/var/lib/rswitch/lldp"

struct rs_topo_node {
	char system_name[64];
	char mgmt_addr[46];    /* management IP */
	char description[128];
	int port_count;
};

struct rs_topo_link {
	int local_node_idx;
	int remote_node_idx;
	char local_port[32];
	char remote_port[32];
	char link_speed[16];   /* e.g., "10G", "25G" */
};

struct rs_topology {
	struct rs_topo_node nodes[TOPO_MAX_NODES];
	int node_count;
	struct rs_topo_link links[TOPO_MAX_LINKS];
	int link_count;
};

/* Discover topology from LLDP neighbor data */
int rs_topology_discover(struct rs_topology *topo);

/* Print topology as ASCII table */
void rs_topology_print(const struct rs_topology *topo);

/* Print topology as JSON */
void rs_topology_print_json(const struct rs_topology *topo);

#endif
