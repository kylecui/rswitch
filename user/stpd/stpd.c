// SPDX-License-Identifier: GPL-2.0

#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

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
#define bpf_map_lookup_elem(...) ((void *)0)
#define bpf_map_update_elem(...) (0)
#endif

#include "../../bpf/core/uapi.h"
#include "../../bpf/core/map_defs.h"
#include "../common/rs_log.h"
#include "stpd.h"

#ifndef __BPF__
#undef bpf_map_lookup_elem
#undef bpf_map_update_elem
#undef RS_MAC_TABLE_OWNER
#undef __uint
#undef __type
#undef __array
#undef __ulong
#undef SEC
#endif

#define STP_MAP_PIN_PATH "/sys/fs/bpf/stp_port_state_map"
#define STP_RINGBUF_PIN_PATH "/sys/fs/bpf/rs_event_bus"

#define STP_DEFAULT_HELLO_NS (2ULL * 1000000000ULL)
#define STP_DEFAULT_MAX_AGE_NS (20ULL * 1000000000ULL)
#define STP_DEFAULT_FORWARD_DELAY_NS (15ULL * 1000000000ULL)

#define STP_MAX_TRACKED_PORTS 256

struct stpd_port_runtime {
    bool active;
    __u32 ifindex;
    struct stp_port_state state;
    __u64 learning_since_ns;
    __u64 last_hello_ns;
};

struct stpd_ctx {
    int stp_map_fd;
    int event_ringbuf_fd;
    struct ring_buffer *rb;
    bool running;
    __u64 hello_time_ns;
    __u64 max_age_ns;
    __u64 forward_delay_ns;
    struct stpd_port_runtime ports[STP_MAX_TRACKED_PORTS];
};

static struct stpd_ctx g_ctx;

static __u64 monotonic_ns(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;

    return ((__u64)ts.tv_sec * 1000000000ULL) + (__u64)ts.tv_nsec;
}

static struct stpd_port_runtime *stpd_get_port(struct stpd_ctx *ctx, __u32 ifindex, bool create)
{
    size_t i;
    struct stpd_port_runtime *free_slot = NULL;

    for (i = 0; i < STP_MAX_TRACKED_PORTS; i++) {
        if (ctx->ports[i].active && ctx->ports[i].ifindex == ifindex)
            return &ctx->ports[i];
        if (!ctx->ports[i].active && !free_slot)
            free_slot = &ctx->ports[i];
    }

    if (!create || !free_slot)
        return NULL;

    memset(free_slot, 0, sizeof(*free_slot));
    free_slot->active = true;
    free_slot->ifindex = ifindex;
    free_slot->state.state = STP_STATE_DISCARDING;
    free_slot->state.role = 0;
    free_slot->state.bridge_priority = 32768;
    free_slot->state.path_cost = 20000;
    free_slot->state.last_bpdu_ts = 0;
    free_slot->learning_since_ns = 0;
    free_slot->last_hello_ns = monotonic_ns();
    return free_slot;
}

static int stpd_write_port_state(struct stpd_ctx *ctx, struct stpd_port_runtime *port)
{
    if (bpf_map_update_elem(ctx->stp_map_fd, &port->ifindex, &port->state, BPF_ANY) != 0) {
        RS_LOG_ERROR("stpd: failed map update ifindex=%u: %s", port->ifindex, strerror(errno));
        return -errno;
    }
    return 0;
}

static int stpd_set_state(struct stpd_ctx *ctx, struct stpd_port_runtime *port, __u32 state, __u64 now_ns)
{
    if (port->state.state == state)
        return 0;

    port->state.state = state;
    if (state == STP_STATE_LEARNING)
        port->learning_since_ns = now_ns;
    if (state == STP_STATE_DISCARDING)
        port->learning_since_ns = 0;

    RS_LOG_INFO("stpd: ifindex=%u state=%u", port->ifindex, state);
    return stpd_write_port_state(ctx, port);
}

static void stpd_apply_topology_change(struct stpd_ctx *ctx, __u64 now_ns)
{
    size_t i;

    for (i = 0; i < STP_MAX_TRACKED_PORTS; i++) {
        if (!ctx->ports[i].active)
            continue;
        if (ctx->ports[i].state.state == STP_STATE_FORWARDING)
            stpd_set_state(ctx, &ctx->ports[i], STP_STATE_LEARNING, now_ns);
    }
}

static void stpd_parse_bpdu(const struct stp_bpdu_event *evt, __u8 *flags,
                            __u32 *bridge_priority, __u32 *path_cost)
{
    __u32 len = evt->bpdu_len;
    const __u8 *p = evt->data;
    __be16 prio_be;
    __be32 cost_be;

    *flags = 0;
    *bridge_priority = 32768;
    *path_cost = 20000;

    if (len < 22)
        return;

    *flags = p[21];

    if (len >= 24) {
        memcpy(&prio_be, &p[22], sizeof(prio_be));
        *bridge_priority = ntohs(prio_be);
    }

    if (len >= 34) {
        memcpy(&cost_be, &p[30], sizeof(cost_be));
        *path_cost = ntohl(cost_be);
    }
}

static int stpd_process_bpdu_event(struct stpd_ctx *ctx, const struct stp_bpdu_event *evt)
{
    struct stpd_port_runtime *port;
    __u8 flags;
    __u32 bridge_priority;
    __u32 path_cost;
    __u64 now_ns;

    now_ns = monotonic_ns();
    if (now_ns == 0)
        now_ns = evt->timestamp_ns;

    port = stpd_get_port(ctx, evt->ifindex, true);
    if (!port)
        return -ENOMEM;

    stpd_parse_bpdu(evt, &flags, &bridge_priority, &path_cost);

    port->state.last_bpdu_ts = evt->timestamp_ns;
    port->state.bridge_priority = bridge_priority;
    port->state.path_cost = path_cost;
    port->state.role = 0;
    port->last_hello_ns = now_ns;

    if (flags & 0x01)
        stpd_apply_topology_change(ctx, now_ns);

    if (port->state.state == STP_STATE_DISCARDING)
        stpd_set_state(ctx, port, STP_STATE_LEARNING, now_ns);

    return stpd_write_port_state(ctx, port);
}

static void stpd_run_timers(struct stpd_ctx *ctx)
{
    size_t i;
    __u64 now_ns = monotonic_ns();

    if (now_ns == 0)
        return;

    for (i = 0; i < STP_MAX_TRACKED_PORTS; i++) {
        struct stpd_port_runtime *port = &ctx->ports[i];
        __u64 since_bpdu;

        if (!port->active)
            continue;

        since_bpdu = (port->state.last_bpdu_ts > 0 && now_ns > port->state.last_bpdu_ts) ?
            (now_ns - port->state.last_bpdu_ts) : 0;

        if (port->state.last_bpdu_ts > 0 && since_bpdu >= ctx->max_age_ns) {
            stpd_set_state(ctx, port, STP_STATE_DISCARDING, now_ns);
            continue;
        }

        if (port->state.state == STP_STATE_LEARNING &&
            port->learning_since_ns > 0 &&
            now_ns - port->learning_since_ns >= ctx->forward_delay_ns) {
            stpd_set_state(ctx, port, STP_STATE_FORWARDING, now_ns);
        }

        if (now_ns - port->last_hello_ns >= ctx->hello_time_ns)
            port->last_hello_ns = now_ns;
    }
}

static int stpd_ringbuf_cb(void *ctx, void *data, size_t size)
{
    struct stpd_ctx *stp = ctx;
    const struct stp_bpdu_event *evt = data;

    if (size < sizeof(__u32))
        return 0;

    if (evt->event_type != STP_EVENT_BPDU)
        return 0;

    if (size < sizeof(*evt)) {
        RS_LOG_WARN("stpd: short event size=%zu", size);
        return 0;
    }

    if (evt->ifindex == 0)
        return 0;

    if (stpd_process_bpdu_event(stp, evt) < 0)
        RS_LOG_WARN("stpd: bpdu process failed ifindex=%u", evt->ifindex);

    return 0;
}

static void stpd_signal_handler(int sig)
{
    RS_LOG_INFO("stpd: signal=%d", sig);
    g_ctx.running = false;
}

static int stpd_init(struct stpd_ctx *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->stp_map_fd = -1;
    ctx->event_ringbuf_fd = -1;

    ctx->running = true;
    ctx->hello_time_ns = STP_DEFAULT_HELLO_NS;
    ctx->max_age_ns = STP_DEFAULT_MAX_AGE_NS;
    ctx->forward_delay_ns = STP_DEFAULT_FORWARD_DELAY_NS;

    ctx->stp_map_fd = bpf_obj_get(STP_MAP_PIN_PATH);
    if (ctx->stp_map_fd < 0) {
        RS_LOG_ERROR("stpd: open map %s failed: %s", STP_MAP_PIN_PATH, strerror(errno));
        return -errno;
    }

    ctx->event_ringbuf_fd = bpf_obj_get(STP_RINGBUF_PIN_PATH);
    if (ctx->event_ringbuf_fd < 0) {
        RS_LOG_ERROR("stpd: open ringbuf %s failed: %s", STP_RINGBUF_PIN_PATH, strerror(errno));
        close(ctx->stp_map_fd);
        ctx->stp_map_fd = -1;
        return -errno;
    }

    ctx->rb = ring_buffer__new(ctx->event_ringbuf_fd, stpd_ringbuf_cb, ctx, NULL);
    if (!ctx->rb) {
        RS_LOG_ERROR("stpd: ring_buffer__new failed: %s", strerror(errno));
        close(ctx->event_ringbuf_fd);
        close(ctx->stp_map_fd);
        ctx->event_ringbuf_fd = -1;
        ctx->stp_map_fd = -1;
        return -errno;
    }

    return 0;
}

static void stpd_cleanup(struct stpd_ctx *ctx)
{
    if (ctx->rb) {
        ring_buffer__free(ctx->rb);
        ctx->rb = NULL;
    }

    if (ctx->event_ringbuf_fd >= 0) {
        close(ctx->event_ringbuf_fd);
        ctx->event_ringbuf_fd = -1;
    }

    if (ctx->stp_map_fd >= 0) {
        close(ctx->stp_map_fd);
        ctx->stp_map_fd = -1;
    }
}

int main(int argc, char **argv)
{
    int ret;
    (void)argc;
    (void)argv;

    rs_log_init("rswitch-stpd", RS_LOG_LEVEL_INFO);

    signal(SIGINT, stpd_signal_handler);
    signal(SIGTERM, stpd_signal_handler);

    ret = stpd_init(&g_ctx);
    if (ret < 0)
        return 1;

    RS_LOG_INFO("stpd: started");

    while (g_ctx.running) {
        ret = ring_buffer__poll(g_ctx.rb, 200);
        if (ret < 0 && ret != -EINTR) {
            RS_LOG_ERROR("stpd: ring poll failed: %d", ret);
            break;
        }
        stpd_run_timers(&g_ctx);
    }

    stpd_cleanup(&g_ctx);
    RS_LOG_INFO("stpd: stopped");
    return 0;
}
