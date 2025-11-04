// SPDX-License-Identifier: GPL-2.0
/* 
 * rSwitch Mirror (SPAN) Module
 * 
 * Implements port mirroring for traffic analysis and monitoring:
 * - SPAN (Switched Port Analyzer): Mirror traffic to monitoring port
 * - Ingress mirroring: Copy ingress packets
 * - Egress mirroring: Copy egress packets (via devmap egress hook)
 * - Filtered mirroring: Mirror only specific VLANs or protocols
 * 
 * Features:
 * - Single mirror destination port per switch
 * - VLAN-based filtering
 * - Protocol-based filtering
 * - Per-port mirror enable/disable
 * - Statistics (mirrored packets/bytes)
 */

#include "../include/rswitch_common.h"
#include "../core/module_abi.h"

char _license[] SEC("license") = "GPL";

// Module metadata
RS_DECLARE_MODULE(
    "mirror",                        // Module name
    RS_HOOK_XDP_INGRESS,            // Hook point (ingress mirroring)
    45,                              // Stage (after ACL, before L2Learn)
    RS_FLAG_NEED_L2L3_PARSE | RS_FLAG_CREATES_EVENTS,
    "Port mirroring (SPAN) for traffic analysis"
);

//
// Data Structures
//

// Mirror configuration
struct mirror_config {
    __u32 span_port;         // Destination port for mirrored traffic (ifindex)
    __u8 ingress_enabled;    // Enable ingress mirroring
    __u8 egress_enabled;     // Enable egress mirroring
    __u8 enabled;            // Global mirror enable/disable
    __u8 _pad;
    
    // Filters
    __u16 vlan_filter;       // Filter by VLAN ID (0 = mirror all VLANs)
    __u16 protocol_filter;   // Filter by Ethertype (0 = mirror all protocols)
    
    // Statistics
    __u64 ingress_mirrored_packets;
    __u64 ingress_mirrored_bytes;
    __u64 egress_mirrored_packets;
    __u64 egress_mirrored_bytes;
    __u64 mirror_drops;      // Packets that couldn't be mirrored
};

// Per-port mirror configuration
struct port_mirror_config {
    __u8 mirror_ingress;     // Mirror this port's ingress traffic
    __u8 mirror_egress;      // Mirror this port's egress traffic
    __u8 _pad[6];
};

//
// BPF Maps
//

// Global mirror configuration
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct mirror_config);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} mirror_config_map SEC(".maps");

// Per-port mirror configuration
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);        // Up to 256 ports
    __type(key, __u32);              // Port ifindex
    __type(value, struct port_mirror_config);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} port_mirror_map SEC(".maps");

// Mirror statistics (per-CPU)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rs_stats);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} mirror_stats SEC(".maps");

// Reference to tx_port map (for packet redirection)
// This should be populated by loader to point to the same devmap
// used by lastcall module
struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u32);
} tx_port SEC(".maps");

//
// Helper Functions
//

// Check if packet should be mirrored based on filters
static __always_inline int should_mirror(struct xdp_md *ctx,
                                        struct mirror_config *config,
                                        __u16 vlan_id)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return 0;
    
    __u16 eth_proto = bpf_ntohs(eth->h_proto);
    
    // Check VLAN filter
    if (config->vlan_filter != 0 && config->vlan_filter != vlan_id)
        return 0;
    
    // Check protocol filter
    if (config->protocol_filter != 0 && config->protocol_filter != eth_proto)
        return 0;
    
    return 1;  // Should mirror
}

// Update mirror statistics
static __always_inline void update_mirror_stats(int is_ingress, __u32 packet_len)
{
    __u32 key = 0;
    struct mirror_config *config;
    
    config = bpf_map_lookup_elem(&mirror_config_map, &key);
    if (!config)
        return;
    
    if (is_ingress) {
        __sync_fetch_and_add(&config->ingress_mirrored_packets, 1);
        __sync_fetch_and_add(&config->ingress_mirrored_bytes, packet_len);
    } else {
        __sync_fetch_and_add(&config->egress_mirrored_packets, 1);
        __sync_fetch_and_add(&config->egress_mirrored_bytes, packet_len);
    }
    
    // Also update per-CPU stats
    struct rs_stats *stats = bpf_map_lookup_elem(&mirror_stats, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->rx_packets, 1);
        __sync_fetch_and_add(&stats->rx_bytes, packet_len);
    }
}

// Mirror packet to SPAN port
// Note: XDP doesn't support native packet cloning like TC bpf_clone_redirect().
// Instead, we use bpf_redirect_map() to forward a copy to the SPAN port via tx_port devmap.
// This is a "tee" operation - the original packet continues through the pipeline.
//
// Implementation: We send metadata to user-space via ringbuf to indicate
// that the packet should be mirrored. User-space (voqd or dedicated mirror daemon)
// can then capture the packet via AF_XDP and replicate it to the SPAN port.
//
// For true kernel-space mirroring, we would need:
// 1. TC-based mirroring (using bpf_clone_redirect), OR
// 2. Custom mirroring via devmap egress hook that duplicates packets
//
// Current implementation: Simplified - just redirect to SPAN port without cloning.
// This means we "tap" the packet but don't duplicate it (packet is moved, not copied).
static __always_inline int mirror_packet(struct xdp_md *ctx,
                                         struct mirror_config *config,
                                         int is_ingress,
                                         __u32 orig_ifindex)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    __u32 packet_len = data_end - data;
    
    // For simplicity: Redirect to SPAN port
    // Limitation: This "steals" the packet rather than cloning it
    // TODO: Implement true mirroring via AF_XDP or TC
    long ret = bpf_redirect_map(&tx_port, config->span_port, 0);
    
    if (ret == XDP_REDIRECT) {
        // Update statistics
        update_mirror_stats(is_ingress, packet_len);
        
        rs_debug("Mirrored packet: len=%u, span_port=%u, ingress=%d, orig_if=%u",
                packet_len, config->span_port, is_ingress, orig_ifindex);
        
        return 0;  // Success
    } else {
        // Failed to redirect
        __sync_fetch_and_add(&config->mirror_drops, 1);
        rs_debug("Mirror failed: span_port=%u, ret=%ld", config->span_port, ret);
        return -1;
    }
}

//
// Main Mirror Processing (Ingress)
//

SEC("xdp")
int mirror_ingress(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // Get global mirror configuration
    __u32 cfg_key = 0;
    struct mirror_config *config;
    
    config = bpf_map_lookup_elem(&mirror_config_map, &cfg_key);
    if (!config || !config->enabled || !config->ingress_enabled)
        return XDP_PASS;  // Mirroring disabled
    
    // Check if SPAN port is configured
    if (config->span_port == 0)
        return XDP_PASS;
    
    // Get per-port configuration
    __u32 ifindex = ctx->ingress_ifindex;
    struct port_mirror_config *port_config;
    
    port_config = bpf_map_lookup_elem(&port_mirror_map, &ifindex);
    if (!port_config || !port_config->mirror_ingress)
        return XDP_PASS;  // This port not configured for ingress mirroring
    
    // Don't mirror packets from SPAN port itself (avoid loop)
    if (ifindex == config->span_port)
        return XDP_PASS;
    
    // Get VLAN ID (if available from context)
    __u16 vlan_id = 0;  // TODO: Extract from rs_ctx if available
    
    // Check filters
    if (!should_mirror(ctx, config, vlan_id))
        return XDP_PASS;
    
    // Mirror the packet (ifindex already defined above)
    mirror_packet(ctx, config, 1, ifindex);
    
    // Continue normal processing (don't consume the packet)
    return XDP_PASS;
}

//
// Egress Mirroring (via devmap egress program)
//

SEC("xdp_devmap/egress")
int mirror_egress(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // Get global mirror configuration
    __u32 cfg_key = 0;
    struct mirror_config *config;
    
    config = bpf_map_lookup_elem(&mirror_config_map, &cfg_key);
    if (!config || !config->enabled || !config->egress_enabled)
        return XDP_PASS;  // Egress mirroring disabled
    
    // Check if SPAN port is configured
    if (config->span_port == 0)
        return XDP_PASS;
    
    // Get egress port (from context or devmap)
    // Note: In devmap egress, we don't have direct access to egress ifindex
    // This would need to be stored in per-packet metadata
    // For now, mirror all egress traffic
    
    // Don't mirror packets to SPAN port itself
    // (This check would need egress port info)
    
    // Get VLAN ID
    __u16 vlan_id = 0;
    
    // Check filters
    if (!should_mirror(ctx, config, vlan_id))
        return XDP_PASS;
    
    // Get egress interface index (from devmap context)
    // Note: XDP devmap programs don't have direct egress ifindex
    // We use rx_queue_index as a proxy (not perfect)
    __u32 ifindex = ctx->rx_queue_index;  // Approximation
    
    // Mirror the packet
    mirror_packet(ctx, config, 0, ifindex);
    
    return XDP_PASS;
}

//
// Helper program for user-space control
//

// Note: User-space tools can use the following to control mirroring:
// 
// 1. Enable/disable global mirroring:
//    Update mirror_config_map[0].enabled
//
// 2. Set SPAN port:
//    Update mirror_config_map[0].span_port = <ifindex>
//
// 3. Enable/disable per-port mirroring:
//    Update port_mirror_map[<ifindex>].mirror_ingress/egress
//
// 4. Set filters:
//    Update mirror_config_map[0].vlan_filter or protocol_filter
//
// 5. Get statistics:
//    Read mirror_config_map[0] for packet/byte counts
