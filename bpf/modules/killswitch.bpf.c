// SPDX-License-Identifier: GPL-2.0
/*
 * rSwitch Killswitch Module — Emergency stop via magic UDP packet
 *
 * Stage 5: Runs before ALL other modules in the ingress pipeline.
 * Checks every UDP packet against a configured port + 32-byte secret.
 * On match, latches an action into rs_killswitch_map for userspace.
 *
 * Fast path cost: 1 protocol check + 1 port compare (non-UDP packets).
 * Match path: + 32-byte memcmp (bounded, unrolled).
 */

#include "../include/rswitch_common.h"
#include "../../sdk/include/rswitch_killswitch.h"

enum {
    RS_THIS_STAGE_ID  = 5,
    RS_THIS_MODULE_ID = 5,
};

char _license[] SEC("license") = "GPL";

RS_DECLARE_MODULE(
    "killswitch",
    RS_HOOK_XDP_INGRESS,
    5,
    RS_FLAG_NEED_L2L3_PARSE,
    "Killswitch - Emergency stop via magic UDP packet"
);

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rs_killswitch_state);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_killswitch_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rs_killswitch_cfg);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_killswitch_cfg SEC(".maps");

static __always_inline int compare_key(const __u8 *payload, const __u8 *key,
                                       void *data_end)
{
    /* Bounds: caller ensures payload + RS_KILLSWITCH_KEY_LEN <= data_end */
    #pragma unroll
    for (int i = 0; i < RS_KILLSWITCH_KEY_LEN; i++) {
        if (payload[i] != key[i])
            return 0;
    }
    return 1;
}

static __always_inline void latch_action(struct rs_killswitch_state *state,
                                         __u32 action, __u32 ifindex)
{
    /* Monotonic: REBOOT (2) overrides STOP (1), never downgrade */
    if (action > state->action) {
        state->action = action;
        state->trigger_ifindex = ifindex;
        state->trigger_ts = bpf_ktime_get_ns();
    }
    __sync_fetch_and_add(&state->trigger_count, 1);
}

SEC("xdp")
int killswitch_ingress(struct xdp_md *ctx)
{
    struct rs_ctx *rctx = RS_GET_CTX();
    if (!rctx)
        return XDP_DROP;

    if (rctx->layers.ip_proto != 17) /* IPPROTO_UDP */
        goto pass;

    __u32 key = 0;
    struct rs_killswitch_cfg *cfg = bpf_map_lookup_elem(&rs_killswitch_cfg, &key);
    if (!cfg || !cfg->enabled)
        goto pass;

    if (rctx->layers.dport != cfg->udp_port)
        goto pass;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u16 payload_off = rctx->layers.payload_offset & RS_PAYLOAD_MASK;

    __u8 *payload = data + payload_off;
    if ((void *)(payload + RS_KILLSWITCH_KEY_LEN + 1) > data_end)
        goto pass;

    /* Check STOP key */
    if (compare_key(payload, cfg->stop_key, data_end)) {
        struct rs_killswitch_state *state =
            bpf_map_lookup_elem(&rs_killswitch_map, &key);
        if (state)
            latch_action(state, RS_KILLSWITCH_ACTION_STOP, rctx->ifindex);
        goto pass;
    }

    /* Check REBOOT key */
    if (compare_key(payload, cfg->reboot_key, data_end)) {
        struct rs_killswitch_state *state =
            bpf_map_lookup_elem(&rs_killswitch_map, &key);
        if (state)
            latch_action(state, RS_KILLSWITCH_ACTION_REBOOT, rctx->ifindex);
        goto pass;
    }

pass:
    RS_TAIL_CALL_NEXT(ctx, rctx);
    return XDP_PASS;
}
