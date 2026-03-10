
// bpf/include/common.h
#ifndef XDP_ACL_COMMON_H
#define XDP_ACL_COMMON_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Actions
enum acl_action_type {
    ACL_PASS = 0,
    ACL_DROP = 1,
    ACL_REDIRECT = 2,
    ACL_MIRROR = 3,      // placeholder: sample + PASS in this demo
    ACL_RATE_LIMIT = 4,  // placeholder
};

struct acl_action {
    __u8  type;
    __u8  reserved;
    __u16 pad;
    __u32 ifindex;      // for REDIRECT
    __u32 mark;         // future use (classid/mark)
};

// 5-tuple IPv4 (demo keeps IPv6 for later extension)
struct key_5t_v4 {
    __u8  proto;      // IPPROTO_*
    __u8  ip_v;       // 4
    __u16 l4_sport;
    __u16 l4_dport;
    __u16 pad;
    __u32 src_v4;     // network byte order
    __u32 dst_v4;     // network byte order
} __attribute__((packed));

// LPM v4 key
struct lpm_v4_key {
    __u32 prefixlen;
    __u32 ip; // network order
};

// Stats slots
enum stat_idx {
    STAT_HIT_5T = 0,
    STAT_HIT_LPM = 1,
    STAT_PASS = 2,
    STAT_DROP = 3,
    STAT_REDIRECT = 4,
    STAT_MAX
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct key_5t_v4);
    __type(value, struct acl_action);
    __uint(max_entries, 262144);
} map_acl_5t_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_v4_key);
    __type(value, struct acl_action);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 131072);
} map_acl_lpm_v4_src SEC(".maps"), map_acl_lpm_v4_dst SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} map_stats SEC(".maps");

// Optional XSK map for AF_XDP redirect (queue-index keyed)
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __type(key, __u32);     // rx_queue_index
    __type(value, __u32);   // xsk socket fd (userland inserts)
    __uint(max_entries, 64); // adjust to NIC queues
} xsks_map SEC(".maps");

// perf-event ringbuf for optional sampling/mirror (not used heavily here)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} rb_events SEC(".maps");

static __always_inline void incr_stat(__u32 idx) {
    __u64 *v = bpf_map_lookup_elem(&map_stats, &idx);
    if (v) __sync_fetch_and_add(v, 1);
}

#endif // XDP_ACL_COMMON_H
