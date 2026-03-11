// SPDX-License-Identifier: GPL-2.0
#ifndef RSWITCH_CONTROLLER_H
#define RSWITCH_CONTROLLER_H

#include <stdint.h>

#define CONTROLLER_DEFAULT_PORT  9418
#define CONTROLLER_MAX_AGENTS    64
#define CONTROLLER_PROTO_VERSION 1
#define CONTROLLER_HEARTBEAT_SEC 10

#define MSG_REGISTER     0x01
#define MSG_HEARTBEAT    0x02
#define MSG_CONFIG_PUSH  0x03
#define MSG_STATUS_REQ   0x04
#define MSG_STATUS_RESP  0x05
#define MSG_PROFILE_PUSH 0x06
#define MSG_ACK          0x07
#define MSG_ERROR        0x08

struct rs_ctrl_msg {
    uint8_t version;
    uint8_t type;
    uint16_t length;
};

struct rs_agent_info {
    char hostname[64];
    char version[32];
    uint32_t num_modules;
    uint32_t uptime_sec;
};

int rs_controller_run(int port, const char *config_dir);

#endif
