// SPDX-License-Identifier: GPL-2.0

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <getopt.h>
#include <net/if.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#ifndef __BPF__
#ifndef __uint
#define __uint(name, val) int __##name
#endif
#ifndef __type
#define __type(name, val) val *name
#endif
#ifndef __array
#define __array(name, val) val *name
#endif
#ifndef __ulong
#define __ulong(name, val) unsigned long name
#endif
#ifndef SEC
#define SEC(name)
#endif
#define RS_MAC_TABLE_OWNER 1
#undef bpf_map_lookup_elem
#undef bpf_map_update_elem
#define bpf_map_lookup_elem(...) ((void *)0)
#define bpf_map_update_elem(...) (0)
#endif

#include "../../bpf/core/uapi.h"
#include "../../bpf/core/map_defs.h"
#include "../common/rs_log.h"
#include "lacpd.h"

#ifndef __BPF__
#undef RS_MAC_TABLE_OWNER
#undef __uint
#undef __type
#undef __array
#undef __ulong
#undef SEC
#undef bpf_map_lookup_elem
#undef bpf_map_update_elem
#endif

#define LACPD_PIN_BASE "/sys/fs/bpf"

struct lacpd_port {
    __u32 ifindex;
    __u32 agg_id;
    __u32 actor_key;
    __u32 partner_key;
    __u8 state;
    __u8 selected;
    __u16 actor_port_priority;
    __u16 partner_port_priority;
    __u8 actor_system_id[6];
    __u8 partner_system_id[6];
    __u64 last_rx_ns;
};

struct lacpd_ctx {
    int lacp_agg_map_fd;
    int lacp_agg_members_map_fd;
    int event_bus_fd;
    struct ring_buffer *ringbuf;
    struct lacpd_port ports[LACPD_MAX_MEMBERS];
    __u32 port_count;
    __u32 tx_hash_mode;
    __u32 mode;
    __u64 short_timeout_ns;
    __u64 long_timeout_ns;
    __u64 effective_timeout_ns;
    __u8 actor_system_id[6];
    __u32 default_agg_id;
    __u32 default_actor_key;
    __u16 default_port_priority;
    volatile sig_atomic_t running;
};

static struct lacpd_ctx g_ctx;

static __u64 monotonic_ns(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (__u64)ts.tv_sec * 1000000000ULL + (__u64)ts.tv_nsec;
}

static bool is_zero_mac(const __u8 mac[6])
{
    return mac[0] == 0 && mac[1] == 0 && mac[2] == 0 &&
           mac[3] == 0 && mac[4] == 0 && mac[5] == 0;
}

static int parse_mac(const char *s, __u8 out[6])
{
    unsigned int b0, b1, b2, b3, b4, b5;
    int n = sscanf(s, "%x:%x:%x:%x:%x:%x", &b0, &b1, &b2, &b3, &b4, &b5);

    if (n != 6)
        return -1;
    if (b0 > 255 || b1 > 255 || b2 > 255 || b3 > 255 || b4 > 255 || b5 > 255)
        return -1;

    out[0] = (__u8)b0;
    out[1] = (__u8)b1;
    out[2] = (__u8)b2;
    out[3] = (__u8)b3;
    out[4] = (__u8)b4;
    out[5] = (__u8)b5;
    return 0;
}

static int set_system_id_from_ifname(const char *ifname, __u8 out[6])
{
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name) - 1);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) != 0) {
        close(fd);
        return -1;
    }

    memcpy(out, ifr.ifr_hwaddr.sa_data, 6);
    close(fd);
    return 0;
}

static int open_pinned_map(const char *name)
{
    char path[256];

    snprintf(path, sizeof(path), "%s/%s", LACPD_PIN_BASE, name);
    return bpf_obj_get(path);
}

static struct lacpd_port *find_port_by_ifindex(struct lacpd_ctx *ctx, __u32 ifindex)
{
    __u32 i;

    for (i = 0; i < ctx->port_count; i++) {
        if (ctx->ports[i].ifindex == ifindex)
            return &ctx->ports[i];
    }
    return NULL;
}

static int update_port_map(struct lacpd_ctx *ctx, const struct lacpd_port *port)
{
    struct lacp_port_info info;

    memset(&info, 0, sizeof(info));
    info.agg_id = port->agg_id;
    info.partner_key = port->partner_key;
    info.actor_key = port->actor_key;
    info.state = port->state;
    info.selected = port->selected;
    info.last_lacpdu_ts = port->last_rx_ns;

    return bpf_map_update_elem(ctx->lacp_agg_map_fd, &port->ifindex, &info, BPF_ANY);
}

static int update_agg_members_map(struct lacpd_ctx *ctx, __u32 agg_id)
{
    struct lacp_agg_members members;
    __u32 i;
    int ret;

    memset(&members, 0, sizeof(members));
    members.tx_hash_mode = ctx->tx_hash_mode;

    for (i = 0; i < ctx->port_count; i++) {
        struct lacpd_port *port = &ctx->ports[i];

        if (port->agg_id != agg_id)
            continue;
        if (!port->selected)
            continue;
        if (port->state != LACP_STATE_DISTRIBUTING)
            continue;
        if (members.member_count >= LACPD_MAX_MEMBERS)
            break;
        members.members[members.member_count++] = port->ifindex;
    }

    if (members.member_count == 0)
        return bpf_map_delete_elem(ctx->lacp_agg_members_map_fd, &agg_id);

    ret = bpf_map_update_elem(ctx->lacp_agg_members_map_fd, &agg_id, &members, BPF_ANY);
    return ret;
}

static __u32 hash_u32(__u32 v)
{
    v ^= v >> 16;
    v *= 0x7feb352dU;
    v ^= v >> 15;
    v *= 0x846ca68bU;
    v ^= v >> 16;
    return v;
}

static __u32 lacpd_select_member(const struct lacp_agg_members *members, __u32 hash)
{
    if (!members || members->member_count == 0)
        return 0;
    return members->members[hash % members->member_count];
}

static void negotiate_port_state(struct lacpd_ctx *ctx, struct lacpd_port *port,
                                 __u16 partner_key, __u8 actor_state,
                                 __u16 partner_port_priority,
                                 const __u8 partner_system_id[6])
{
    bool key_match;
    bool aggregate;
    bool collecting;
    bool distributing;
    struct lacp_agg_members members;

    port->partner_key = partner_key;
    port->partner_port_priority = partner_port_priority;
    memcpy(port->partner_system_id, partner_system_id, 6);

    key_match = (partner_key != 0) && ((__u32)partner_key == port->actor_key);
    aggregate = (actor_state & 0x04U) != 0;
    collecting = (actor_state & 0x10U) != 0;
    distributing = (actor_state & 0x20U) != 0;

    if (!key_match || !aggregate) {
        port->state = LACP_STATE_DETACHED;
        port->selected = 0;
    } else {
        port->state = LACP_STATE_ATTACHED;
        port->selected = 1;
        if (collecting)
            port->state = LACP_STATE_COLLECTING;
        if (collecting && (distributing || ctx->mode == LACPD_MODE_ACTIVE))
            port->state = LACP_STATE_DISTRIBUTING;
    }

    if (update_port_map(ctx, port) != 0) {
        RS_LOG_ERROR("failed to write lacp_agg_map for ifindex=%u: %s",
                     port->ifindex, strerror(errno));
    }
    if (update_agg_members_map(ctx, port->agg_id) != 0 && errno != ENOENT) {
        RS_LOG_ERROR("failed to write lacp_agg_members_map for agg_id=%u: %s",
                     port->agg_id, strerror(errno));
    }

    memset(&members, 0, sizeof(members));
    if (bpf_map_lookup_elem(ctx->lacp_agg_members_map_fd, &port->agg_id, &members) == 0) {
        __u32 selected = lacpd_select_member(&members, hash_u32(port->ifindex ^ port->actor_key));
        if (selected != 0) {
            RS_LOG_DEBUG("agg_id=%u selected_ifindex=%u tx_hash_mode=%u members=%u",
                         port->agg_id, selected, members.tx_hash_mode, members.member_count);
        }
    }

    RS_LOG_INFO("ifindex=%u state=%u selected=%u actor_key=%u partner_key=%u partner_prio=%u",
                port->ifindex, port->state, port->selected,
                port->actor_key, port->partner_key, port->partner_port_priority);
}

static void apply_timeouts(struct lacpd_ctx *ctx)
{
    __u64 now = monotonic_ns();
    __u32 i;

    for (i = 0; i < ctx->port_count; i++) {
        struct lacpd_port *port = &ctx->ports[i];
        __u64 elapsed;

        if (port->last_rx_ns == 0)
            continue;
        if (now < port->last_rx_ns)
            continue;

        elapsed = now - port->last_rx_ns;
        if (elapsed < ctx->effective_timeout_ns)
            continue;

        port->state = LACP_STATE_DETACHED;
        port->selected = 0;
        port->partner_key = 0;
        memset(port->partner_system_id, 0, sizeof(port->partner_system_id));
        if (update_port_map(ctx, port) != 0) {
            RS_LOG_ERROR("timeout update failed for ifindex=%u: %s", port->ifindex, strerror(errno));
        }
        if (update_agg_members_map(ctx, port->agg_id) != 0 && errno != ENOENT) {
            RS_LOG_ERROR("timeout members update failed for agg_id=%u: %s",
                         port->agg_id, strerror(errno));
        }
        RS_LOG_WARN("ifindex=%u timed out and moved to DETACHED", port->ifindex);
    }
}

static int handle_lacp_event(void *ctx_data, void *data, size_t size)
{
    struct lacpd_ctx *ctx = ctx_data;
    const struct lacp_event *event = data;
    struct lacpd_port *port;

    if (size < sizeof(struct lacp_event))
        return 0;
    if (event->event_type != LACPD_EVENT_TYPE)
        return 0;

    port = find_port_by_ifindex(ctx, event->ifindex);
    if (!port)
        return 0;

    if (!event->parsed) {
        RS_LOG_DEBUG("invalid LACPDU on ifindex=%u", event->ifindex);
        return 0;
    }

    port->last_rx_ns = monotonic_ns();
    negotiate_port_state(ctx, port, event->partner_key, event->actor_state,
                         event->partner_port_priority, event->partner_system_id);
    return 0;
}

static int add_ports_from_list(struct lacpd_ctx *ctx, const char *ports_csv)
{
    char *buf;
    char *token;

    buf = strdup(ports_csv);
    if (!buf)
        return -ENOMEM;

    token = strtok(buf, ",");
    while (token) {
        struct lacpd_port *port;
        unsigned int ifindex;

        if (ctx->port_count >= LACPD_MAX_MEMBERS) {
            free(buf);
            return -E2BIG;
        }

        ifindex = if_nametoindex(token);
        if (ifindex == 0) {
            RS_LOG_ERROR("interface not found: %s", token);
            free(buf);
            return -EINVAL;
        }

        port = &ctx->ports[ctx->port_count++];
        memset(port, 0, sizeof(*port));
        port->ifindex = ifindex;
        port->agg_id = ctx->default_agg_id;
        port->actor_key = ctx->default_actor_key;
        port->state = LACP_STATE_DETACHED;
        port->selected = 0;
        port->actor_port_priority = ctx->default_port_priority;
        memcpy(port->actor_system_id, ctx->actor_system_id, 6);

        token = strtok(NULL, ",");
    }

    free(buf);
    return 0;
}

static void sync_actor_system_id_to_ports(struct lacpd_ctx *ctx)
{
    __u32 i;

    for (i = 0; i < ctx->port_count; i++)
        memcpy(ctx->ports[i].actor_system_id, ctx->actor_system_id, 6);
}

static int infer_actor_system_id(struct lacpd_ctx *ctx)
{
    char ifname[IF_NAMESIZE] = {0};

    if (ctx->port_count == 0)
        return -EINVAL;
    if (!if_indextoname(ctx->ports[0].ifindex, ifname))
        return -EINVAL;
    if (set_system_id_from_ifname(ifname, ctx->actor_system_id) != 0)
        return -EINVAL;
    return 0;
}

static void signal_handler(int sig)
{
    (void)sig;
    g_ctx.running = 0;
}

static int init_maps(struct lacpd_ctx *ctx)
{
    ctx->lacp_agg_map_fd = open_pinned_map("lacp_agg_map");
    if (ctx->lacp_agg_map_fd < 0) {
        RS_LOG_ERROR("failed to open lacp_agg_map: %s", strerror(errno));
        return -errno;
    }

    ctx->lacp_agg_members_map_fd = open_pinned_map("lacp_agg_members_map");
    if (ctx->lacp_agg_members_map_fd < 0) {
        RS_LOG_ERROR("failed to open lacp_agg_members_map: %s", strerror(errno));
        return -errno;
    }

    ctx->event_bus_fd = open_pinned_map("rs_event_bus");
    if (ctx->event_bus_fd < 0) {
        RS_LOG_ERROR("failed to open rs_event_bus: %s", strerror(errno));
        return -errno;
    }

    return 0;
}

static void close_maps(struct lacpd_ctx *ctx)
{
    if (ctx->ringbuf)
        ring_buffer__free(ctx->ringbuf);
    if (ctx->event_bus_fd >= 0)
        close(ctx->event_bus_fd);
    if (ctx->lacp_agg_members_map_fd >= 0)
        close(ctx->lacp_agg_members_map_fd);
    if (ctx->lacp_agg_map_fd >= 0)
        close(ctx->lacp_agg_map_fd);
}

static void usage(const char *prog)
{
    RS_LOG_INFO("usage: %s --ports if0,if1 [options]", prog);
    RS_LOG_INFO("options:");
    RS_LOG_INFO("  --mode active|passive");
    RS_LOG_INFO("  --timeout short|long");
    RS_LOG_INFO("  --short-timeout <seconds>");
    RS_LOG_INFO("  --long-timeout <seconds>");
    RS_LOG_INFO("  --agg-id <id>");
    RS_LOG_INFO("  --actor-key <key>");
    RS_LOG_INFO("  --actor-system-id <mac>");
    RS_LOG_INFO("  --port-priority <value>");
    RS_LOG_INFO("  --tx-hash-mode 0|1|2|3");
}

static int parse_args(struct lacpd_ctx *ctx, int argc, char **argv)
{
    int opt;
    int option_index = 0;
    const char *ports_csv = NULL;
    const char *timeout_mode = "short";

    static struct option long_opts[] = {
        {"ports", required_argument, 0, 'p'},
        {"mode", required_argument, 0, 'm'},
        {"timeout", required_argument, 0, 't'},
        {"short-timeout", required_argument, 0, 's'},
        {"long-timeout", required_argument, 0, 'l'},
        {"agg-id", required_argument, 0, 'a'},
        {"actor-key", required_argument, 0, 'k'},
        {"actor-system-id", required_argument, 0, 'S'},
        {"port-priority", required_argument, 0, 'r'},
        {"tx-hash-mode", required_argument, 0, 'x'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0},
    };

    while ((opt = getopt_long(argc, argv, "p:m:t:s:l:a:k:S:r:x:h", long_opts, &option_index)) != -1) {
        switch (opt) {
        case 'p':
            ports_csv = optarg;
            break;
        case 'm':
            if (strcmp(optarg, "active") == 0)
                ctx->mode = LACPD_MODE_ACTIVE;
            else if (strcmp(optarg, "passive") == 0)
                ctx->mode = LACPD_MODE_PASSIVE;
            else
                return -EINVAL;
            break;
        case 't':
            timeout_mode = optarg;
            break;
        case 's':
            ctx->short_timeout_ns = strtoull(optarg, NULL, 10) * 1000000000ULL;
            break;
        case 'l':
            ctx->long_timeout_ns = strtoull(optarg, NULL, 10) * 1000000000ULL;
            break;
        case 'a':
            ctx->default_agg_id = strtoul(optarg, NULL, 10);
            break;
        case 'k':
            ctx->default_actor_key = strtoul(optarg, NULL, 10);
            break;
        case 'S':
            if (parse_mac(optarg, ctx->actor_system_id) != 0)
                return -EINVAL;
            break;
        case 'r':
            ctx->default_port_priority = (__u16)strtoul(optarg, NULL, 10);
            break;
        case 'x':
            ctx->tx_hash_mode = strtoul(optarg, NULL, 10);
            if (ctx->tx_hash_mode > 3)
                return -EINVAL;
            break;
        case 'h':
            usage(argv[0]);
            return 1;
        default:
            return -EINVAL;
        }
    }

    if (!ports_csv)
        return -EINVAL;

    if (strcmp(timeout_mode, "short") == 0)
        ctx->effective_timeout_ns = ctx->short_timeout_ns;
    else if (strcmp(timeout_mode, "long") == 0)
        ctx->effective_timeout_ns = ctx->long_timeout_ns;
    else
        return -EINVAL;

    return add_ports_from_list(ctx, ports_csv);
}

static int seed_initial_state(struct lacpd_ctx *ctx)
{
    __u32 i;

    for (i = 0; i < ctx->port_count; i++) {
        int ret;

        ret = update_port_map(ctx, &ctx->ports[i]);
        if (ret != 0) {
            RS_LOG_ERROR("failed to seed port state ifindex=%u: %s", ctx->ports[i].ifindex, strerror(errno));
            return -errno;
        }
    }

    if (update_agg_members_map(ctx, ctx->default_agg_id) != 0 && errno != ENOENT) {
        RS_LOG_ERROR("failed to seed agg members agg_id=%u: %s", ctx->default_agg_id, strerror(errno));
        return -errno;
    }

    return 0;
}

int main(int argc, char **argv)
{
    int ret;

    memset(&g_ctx, 0, sizeof(g_ctx));
    g_ctx.lacp_agg_map_fd = -1;
    g_ctx.lacp_agg_members_map_fd = -1;
    g_ctx.event_bus_fd = -1;
    g_ctx.mode = LACPD_MODE_ACTIVE;
    g_ctx.short_timeout_ns = 1000000000ULL;
    g_ctx.long_timeout_ns = 30000000000ULL;
    g_ctx.effective_timeout_ns = g_ctx.short_timeout_ns;
    g_ctx.default_agg_id = 1;
    g_ctx.default_actor_key = 1;
    g_ctx.default_port_priority = 128;
    g_ctx.tx_hash_mode = 2;
    g_ctx.running = 1;

    rs_log_init("rswitch-lacpd", RS_LOG_LEVEL_INFO);

    ret = parse_args(&g_ctx, argc, argv);
    if (ret == 1)
        return 0;
    if (ret != 0) {
        usage(argv[0]);
        RS_LOG_ERROR("invalid arguments");
        return 1;
    }

    if (is_zero_mac(g_ctx.actor_system_id)) {
        if (infer_actor_system_id(&g_ctx) != 0) {
            RS_LOG_ERROR("failed to infer actor system id, provide --actor-system-id");
            return 1;
        }
    }

    sync_actor_system_id_to_ports(&g_ctx);

    ret = init_maps(&g_ctx);
    if (ret != 0) {
        close_maps(&g_ctx);
        return 1;
    }

    ret = seed_initial_state(&g_ctx);
    if (ret != 0) {
        close_maps(&g_ctx);
        return 1;
    }

    g_ctx.ringbuf = ring_buffer__new(g_ctx.event_bus_fd, handle_lacp_event, &g_ctx, NULL);
    if (!g_ctx.ringbuf) {
        RS_LOG_ERROR("failed to create ring buffer consumer");
        close_maps(&g_ctx);
        return 1;
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    RS_LOG_INFO("lacpd started mode=%s timeout_ns=%llu tx_hash_mode=%u ports=%u",
                g_ctx.mode == LACPD_MODE_ACTIVE ? "active" : "passive",
                (unsigned long long)g_ctx.effective_timeout_ns,
                g_ctx.tx_hash_mode,
                g_ctx.port_count);

    while (g_ctx.running) {
        ret = ring_buffer__poll(g_ctx.ringbuf, 200);
        if (ret < 0 && ret != -EINTR) {
            RS_LOG_ERROR("ringbuf poll failed: %d", ret);
            break;
        }
        apply_timeouts(&g_ctx);
    }

    RS_LOG_INFO("lacpd shutting down");
    close_maps(&g_ctx);
    return 0;
}
