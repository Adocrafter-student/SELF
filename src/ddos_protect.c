#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "ddos_events.h"

// Log levels
#define LOG_LEVEL_DEBUG   0
#define LOG_LEVEL_INFO    1
#define LOG_LEVEL_WARNING 2
#define LOG_LEVEL_ERROR   3

// Log entry structure
struct log_entry {
    __u32 level;
    __u32 ip;
    __u64 packets;
    __u8 code;      // Event code from ddos_event_code enum
    __u64 timestamp;
};

// Log buffer map
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(pinning, LIBBPF_PIN_BY_NAME);  // Pin the map
    __uint(max_entries, 1024);
} log_buffer SEC(".maps");

// Key for our IP map
struct ip_key {
    __u32 ip;
    __u16 port;
};

// Value for our IP map
struct traffic_stats {
    __u64 packet_count;
    __u64 last_seen;
    __u64 bytes;
    __u64 blocked;
};

// Constants for simple rate-limiting
#define PACKET_THRESHOLD 1000             // Packets before we start blocking
#define RATE_WINDOW      60000000000ULL   // 60 seconds in nanoseconds

// eBPF Hash Map for storing IP traffic data
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000000);
    __type(key, struct ip_key);
    __type(value, struct traffic_stats);
} ip_traffic_map SEC(".maps");

// Helper function to log events
static __always_inline void log_event(struct xdp_md *ctx,
                                     __u32 level,
                                     __u32 ip,
                                     __u64 packets,
                                     __u8 code)
{
    struct log_entry entry = {
        .level = level,
        .ip = ip,
        .packets = packets,
        .code = code,
        .timestamp = bpf_ktime_get_ns()
    };
    
    bpf_perf_event_output(ctx, &log_buffer, BPF_F_CURRENT_CPU, &entry, sizeof(entry));
}

// Helper function to process the packet
static __always_inline int process_packet(struct xdp_md *ctx, void *data, void *data_end)
{
    // Parse Ethernet
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    // We only handle IPv4
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
        return XDP_PASS;
    }

    // Parse IP header
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }

    // Prepare the map key
    struct ip_key key = {0};
    key.ip = ip->saddr;

    // Figure out if it's TCP or UDP so we can store the source port
    void *l4hdr = (void *)ip + sizeof(*ip);

    // Basic boundary check: we need at least the size of a TCP or UDP header
    if (l4hdr + sizeof(struct tcphdr) > data_end) {
        // Not enough room even for a TCP/UDP header, just pass
        return XDP_PASS;
    }

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4hdr;
        if ((void *)(tcp + 1) > data_end) {
            return XDP_PASS;
        }
        key.port = tcp->source;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = l4hdr;
        if ((void *)(udp + 1) > data_end) {
            return XDP_PASS;
        }
        key.port = udp->source;
    } else {
        key.port = 0;  // For non-TCP/UDP, just store 0 as port
    }

    // Current time in nanoseconds
    __u64 now = bpf_ktime_get_ns();

    // Packet length
    __u64 pkt_size = (void *)data_end - (void *)data;

    // Lookup existing stats in the map
    struct traffic_stats *stats = bpf_map_lookup_elem(&ip_traffic_map, &key);
    if (stats) {
        // Reset if the last packet was too long ago
        if (now - stats->last_seen > RATE_WINDOW) {
            stats->packet_count = 0;
            stats->blocked = 0;
            log_event(ctx, LOG_LEVEL_INFO, key.ip, stats->packet_count, EV_RESET);
        }

        stats->packet_count += 1;
        stats->bytes += pkt_size;
        stats->last_seen = now;

        // If above threshold, block
        if (stats->packet_count > PACKET_THRESHOLD) {
            stats->blocked += 1;
            bpf_map_update_elem(&ip_traffic_map, &key, stats, BPF_ANY);
            log_event(ctx, LOG_LEVEL_WARNING, key.ip, stats->packet_count, EV_BLOCK);
            return XDP_DROP;
        }

        bpf_map_update_elem(&ip_traffic_map, &key, stats, BPF_ANY);
    } else {
        // Insert a new entry
        struct traffic_stats new_stats = {
            .packet_count = 1,
            .last_seen    = now,
            .bytes        = pkt_size,
            .blocked      = 0,
        };
        bpf_map_update_elem(&ip_traffic_map, &key, &new_stats, BPF_ANY);
        log_event(ctx, LOG_LEVEL_DEBUG, key.ip, 1, EV_NEW_IP);
    }

    return XDP_PASS;
}

// Our XDP entrypoint
SEC("xdp")
int xdp_ddos_protect(struct xdp_md *ctx)
{
    // Pointers to the start/end of the packet
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Just call our helper
    return process_packet(ctx, data, data_end);
}

// Required license
char _license[] SEC("license") = "GPL";
