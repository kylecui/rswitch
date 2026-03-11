// SPDX-License-Identifier: GPL-2.0
#ifndef RSWITCH_SNMPAGENT_H
#define RSWITCH_SNMPAGENT_H

#define SNMPAGENT_DEFAULT_SOCKET "/var/agentx/master"
#define SNMPAGENT_POLL_INTERVAL  10  /* seconds */

/* rSwitch enterprise OID: 1.3.6.1.4.1.99999 (placeholder) */
#define RSWITCH_ENTERPRISE_OID  "1.3.6.1.4.1.99999"

/* Sub-tree OIDs under enterprise */
#define OID_RSWITCH_INFO        ".1"   /* system info */
#define OID_RSWITCH_PORTS       ".2"   /* port stats */
#define OID_RSWITCH_MODULES     ".3"   /* module stats */
#define OID_RSWITCH_VLANS       ".4"   /* VLAN info */
#define OID_RSWITCH_QOS         ".5"   /* QoS stats */

/* Main agent run loop */
int rs_snmpagent_run(const char *agentx_socket);

#endif
