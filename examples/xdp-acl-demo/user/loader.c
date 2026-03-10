
// user/loader.c
// Build: gcc -O2 -Wall -I. -I../bpf -lelf -lz -lbpf loader.c -o xdp-acl-loader
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

static void die(const char *msg) {
    perror(msg);
    exit(1);
}

static int set_rlimit() {
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    return setrlimit(RLIMIT_MEMLOCK, &r);
}

static int attach_xdp(struct bpf_object *obj, const char *ifname) {
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_acl_core");
    if (!prog) {
        fprintf(stderr, "program not found\n");
        return -1;
    }
    int ifindex = if_nametoindex(ifname);
    if (!ifindex) die("if_nametoindex");

    int prog_fd = bpf_program__fd(prog);
    int err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_DRV_MODE, NULL);
    if (err) {
        fprintf(stderr, "XDP attach (drv) failed, fallback to generic...\n");
        err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL);
        if (err) die("bpf_xdp_attach");
    }
    return 0;
}

static int map_fd(struct bpf_object *obj, const char *name) {
    struct bpf_map *m = bpf_object__find_map_by_name(obj, name);
    if (!m) { fprintf(stderr, "map %s not found\n", name); return -1; }
    int fd = bpf_map__fd(m);
    if (fd < 0) fprintf(stderr, "map %s fd err\n", name);
    return fd;
}

static __u32 ipv4(const char *s) {
    unsigned o1,o2,o3,o4;
    if (sscanf(s, "%u.%u.%u.%u", &o1,&o2,&o3,&o4) != 4) return 0;
    return htonl((o1<<24)|(o2<<16)|(o3<<8)|o4);
}

struct key_5t_v4 {
    __u8  proto;
    __u8  ip_v;
    __u16 l4_sport;
    __u16 l4_dport;
    __u16 pad;
    __u32 src_v4;
    __u32 dst_v4;
} __attribute__((packed));

struct lpm_v4_key {
    __u32 prefixlen;
    __u32 ip;
};

struct acl_action {
    __u8  type;
    __u8  reserved;
    __u16 pad;
    __u32 ifindex;
    __u32 mark;
};

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <ifname> <bpf-o-file> [demo-rules]\n", argv[0]);
        fprintf(stderr, "Example: %s eth0 ../build/bpf/acl_core.bpf.o demo\n", argv[0]);
        return 1;
    }
    const char *ifname = argv[1];
    const char *bpfobj = argv[2];

    if (set_rlimit()) die("setrlimit");

    struct bpf_object *obj = NULL;
    struct bpf_object_open_opts open_opts = {};
    obj = bpf_object__open_file(bpfobj, &open_opts);
    if (!obj) die("bpf_object__open_file");
    if (bpf_object__load(obj)) die("bpf_object__load");

    if (attach_xdp(obj, ifname)) die("attach_xdp");

    int map5t = map_fd(obj, "map_acl_5t_v4");
    int mapsrc = map_fd(obj, "map_acl_lpm_v4_src");
    // int mapdst = map_fd(obj, "map_acl_lpm_v4_dst");

    if (argc >= 4 && strcmp(argv[3], "demo") == 0) {
        // Insert a DROP rule for TCP 443 from 10.1.2.3 to any
        struct key_5t_v4 k = {0};
        k.proto = IPPROTO_TCP; k.ip_v = 4;
        k.l4_sport = htons(443); k.l4_dport = 0;
        k.src_v4 = ipv4("10.1.2.3"); k.dst_v4 = 0;
        struct acl_action a = {.type = 1 /*DROP*/};
        if (bpf_map_update_elem(map5t, &k, &a, BPF_ANY))
            perror("update 5t");

        // Allow src 192.168.1.0/24 via LPM
        struct lpm_v4_key lpm = {24, ipv4("192.168.1.0")};
        struct acl_action allow = {.type = 0 /*PASS*/};
        if (bpf_map_update_elem(mapsrc, &lpm, &allow, BPF_ANY))
            perror("update lpm");
        printf("Inserted demo rules.\n");
    }

    printf("XDP ACL loaded on %s. Press Ctrl-C to exit (program will stay attached).\n", ifname);
    // Keep running
    for (;;) pause();
    return 0;
}
