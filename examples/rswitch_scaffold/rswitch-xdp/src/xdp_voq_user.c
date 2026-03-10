// src/xdp_voq_user.c
// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "rswitch_common.h"

#ifndef XDP_FLAGS_UPDATE_IF_NOEXIST
#include <linux/if_link.h>
#endif

static void bump_memlock_rlimit(void) {
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        perror("setrlimit(RLIMIT_MEMLOCK)");
        exit(1);
    }
}

static int set_devmap_entry(int map_fd, uint32_t idx, int ifindex) {
    return bpf_map_update_elem(map_fd, &idx, &ifindex, 0);
}

static int load_qos_from_json(const char *path, struct qos_cfg *cfg) {
    // Minimal parser: support a very small subset via fgets/sscanf for demo
    // In production, use cJSON/yyjson.
    memset(cfg, 0, sizeof(*cfg));
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        unsigned key, val;
        if (sscanf(line, " \"default_port\" : %u", &val) == 1) {
            cfg->port_default = val;
        } else if (sscanf(line, " \"46\" : %u", &val) == 1) {
            cfg->dscp2prio[46] = val;
        } else if (sscanf(line, " \"40\" : %u", &val) == 1) {
            cfg->dscp2prio[40] = val;
        } else if (sscanf(line, " \"34\" : %u", &val) == 1) {
            cfg->dscp2prio[34] = val;
        }
    }
    fclose(f);
    return 0;
}

static const struct option long_opts[] = {
    {"iface",   required_argument, 0, 'i'},
    {"mode",    required_argument, 0, 'm'}, // native|generic
    {"pin",     required_argument, 0, 'p'},
    {"devport", required_argument, 0, 'd'},
    {"qos",     required_argument, 0, 'q'},
    {0,0,0,0}
};

extern unsigned char _binary_xdp_voq_kern_o_start[];
extern unsigned char _binary_xdp_voq_kern_o_end[];

int main(int argc, char **argv) {
    const char *iface = NULL, *mode = "native", *pinbase = "/sys/fs/bpf/rswitch", *qos_path = "./etc/qos.json";
    int devport = 0;
    int opt;
    while ((opt = getopt_long(argc, argv, "i:m:p:d:q:", long_opts, NULL)) != -1) {
        switch (opt) {
            case 'i': iface = optarg; break;
            case 'm': mode = optarg; break;
            case 'p': pinbase = optarg; break;
            case 'd': devport = atoi(optarg); break;
            case 'q': qos_path = optarg; break;
            default:
                fprintf(stderr, "usage: %s --iface IFACE [--mode native|generic] [--pin DIR] [--devport IDX] [--qos FILE]\n", argv[0]);
                return 1;
        }
    }
    if (!iface) {
        fprintf(stderr, "iface required\n");
        return 1;
    }

    bump_memlock_rlimit();

    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_link *link = NULL;
    int err;

    obj = bpf_object__open_file("xdp_voq_kern.o", NULL);
    if (libbpf_get_error(obj)) {
        err = -libbpf_get_error(obj);
        fprintf(stderr, "open bpf obj failed: %d\n", err);
        return 1;
    }
    prog = bpf_object__find_program_by_title(obj, "xdp");
    if (!prog) {
        fprintf(stderr, "program 'xdp' not found\n");
        return 1;
    }
    if ((err = bpf_object__load(obj))) {
        fprintf(stderr, "load bpf obj failed: %d\n", err);
        return 1;
    }

    int ifindex = if_nametoindex(iface);
    if (!ifindex) { perror("if_nametoindex"); return 1; }

    __u32 xdp_flags = 0;
    if (strcmp(mode, "generic")==0) xdp_flags = XDP_FLAGS_SKB_MODE;
    else xdp_flags = XDP_FLAGS_DRV_MODE;

    link = bpf_program__attach_xdp(prog, ifindex);
    if (libbpf_get_error(link)) {
        err = -libbpf_get_error(link);
        fprintf(stderr, "attach xdp failed: %d (try --mode generic?)\n", err);
        return 1;
    }

    // Pin maps
    mkdir(pinbase, 0755);
    struct bpf_map *map;
    bpf_object__for_each_map(map, obj) {
        const char *name = bpf_map__name(map);
        char path[256]; snprintf(path, sizeof(path), "%s/%s", pinbase, name);
        bpf_map__set_pin_path(map, path);
        if ((err = bpf_map__pin(map))) {
            if (err != -EEXIST) fprintf(stderr, "pin map %s failed: %d\n", name, err);
        }
    }

    // Configure devmap (single entry demo)
    int devmap_fd = bpf_object__find_map_fd_by_name(obj, "tx_devmap");
    if (devmap_fd < 0) { fprintf(stderr, "tx_devmap not found\n"); return 1; }
    if ((err = set_devmap_entry(devmap_fd, devport, ifindex))) {
        fprintf(stderr, "set devmap[%d]=ifindex(%d) failed: %d\n", devport, ifindex, err);
    }

    // Configure QoS map
    int qos_fd = bpf_object__find_map_fd_by_name(obj, "qos_map");
    if (qos_fd < 0) { fprintf(stderr, "qos_map not found\n"); return 1; }
    struct qos_cfg cfg = {0};
    if (load_qos_from_json(qos_path, &cfg) < 0) {
        // fallback defaults
        cfg.port_default = devport;
        cfg.dscp2prio[46]=3; cfg.dscp2prio[40]=3; cfg.dscp2prio[34]=2;
    }
    __u32 key=0;
    if ((err = bpf_map_update_elem(qos_fd, &key, &cfg, BPF_ANY))) {
        fprintf(stderr, "update qos_map failed: %d\n", err);
    }

    printf("[+] XDP program attached on %s (ifindex %d), devmap->%d, pin=%s\n", iface, ifindex, devport, pinbase);
    printf("    Press Ctrl-C to detach\n");
    while (1) pause();
    return 0;
}
