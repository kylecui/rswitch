#pragma once
#include <stdbool.h>
#include <stdint.h>

/* Shared structs between BPF and userland */

struct voq_meta {
    __u64 ts_ns;
    __u32 eg_port;
    __u32 prio;     // 0..3
    __u32 len;
    __u8  ecn;
} __attribute__((packed));

struct qos_cfg {
    __u32 dscp2prio[64];
    __u32 port_default;
};
