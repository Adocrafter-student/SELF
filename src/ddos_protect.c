#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "ddos_events.h"
#include "self_defs.h"

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
    __u64 block_until;  // Timestamp kada blokada ističe (0 = permanentna)
};

// Constants for simple rate-limiting
#define PACKET_THRESHOLD 1000             // Packets before we start blocking
#define RATE_WINDOW      60000000000ULL   // 60 seconds in nanoseconds
#define WINDOW_NS        5000000000ULL    // 5 seconds in nanoseconds

// eBPF Hash Map for storing IP traffic data
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1000000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, struct ip_key);
    __type(value, struct traffic_stats);
} ip_traffic_map SEC(".maps");

// eBPF Hash Map for storing blocked IPs
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u32);  // IP address
    __type(value, __u64); // Block until timestamp (0 = permanent)
} blocked_ips_map SEC(".maps");

// Structure for SYN tracking value
struct syn_val {
    __u64 ts_ns;   // last SYN timestamp
};

// Tracks half-open SYN counts per source IP
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1000000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key,   __u32);  // src IP only
    __type(value, struct syn_val);
} ip_syn_count_map SEC(".maps");

// Tracks fully established flows: key = 4-tuple, value = __u64 flag
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1000000);
    __type(key, struct flow_key);
    __type(value, __u64);
} established_map SEC(".maps");

// Per-IP suspicion score
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1000000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u32);     // src IP only
    __type(value, __u8);    // 0–100 score
} score_map SEC(".maps");

// 4-tuple key for TCP/UDP flow
struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 proto;
};

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

// Helper function to potentially ban an IP based on its score
static __always_inline void maybe_ban_ip(__u32 sip, __u64 now, __u8 score)
{
    __u64 expire = 0;

    if (score >= SCORE_PERMANENT_BAN)     expire = BAN_PERMANENT;
    else if (score >= SCORE_15_DAYS_BAN)  expire = now + BAN_15_DAYS;
    else if (score >= SCORE_4_DAYS_BAN)   expire = now + BAN_4_DAYS;
    else if (score >= SCORE_1_DAY_BAN)    expire = now + BAN_1_DAY;
    else if (score >= SCORE_15_MIN_BAN)   expire = now + BAN_15_MIN;
    else if (score >= SCORE_1_MIN_BAN)    expire = now + BAN_1_MIN;
    else if (score >= SCORE_15_SEC_BAN)   expire = now + BAN_15_SEC;
    else return; // below 10: no ban yet

    bpf_map_update_elem(&blocked_ips_map, &sip, &expire, BPF_ANY);
}

// Helper function to handle TCP SYN packets
static __always_inline void handle_tcp_syn(struct xdp_md *ctx,
                                          struct iphdr *ip,
                                          struct tcphdr *tcp,
                                          __u64 now)
{
    __u32 sip = ip->saddr;
    struct syn_val new_val = { .ts_ns = now }; // Only need timestamp

    struct syn_val *val = bpf_map_lookup_elem(&ip_syn_count_map, &sip);

    if (!val || (now - val->ts_ns > WINDOW_NS)) {
        // First SYN from this IP in this window, or map entry expired
        bpf_map_update_elem(&ip_syn_count_map, &sip, &new_val, BPF_ANY);
        log_event(ctx, LOG_LEVEL_DEBUG, sip, 0, EV_FIRST_SYN); // Optional: Log first SYN
    } else {
        // Second (or later) SYN within the window -> penalty
        __u8 new_score = SCORE_HALF_OPEN_INC; // Start with the increment value
        __u8 *scr = bpf_map_lookup_elem(&score_map, &sip);
        if (scr) { // If score exists, add increment, checking for max
            new_score = (*scr + SCORE_HALF_OPEN_INC <= SCORE_MAX) ? *scr + SCORE_HALF_OPEN_INC : SCORE_MAX;
        }
        // Update map with the calculated new_score
        bpf_map_update_elem(&score_map, &sip, &new_score, BPF_ANY);
        maybe_ban_ip(sip, now, new_score);

        log_event(ctx, LOG_LEVEL_WARNING, sip, new_score, EV_SYN_RETRY_PENALTY); // Log the penalty

        // Reset the SYN counter after penalty
        new_val.ts_ns = now; // Update timestamp to restart window
        bpf_map_update_elem(&ip_syn_count_map, &sip, &new_val, BPF_ANY);
    }
}

// Helper function to handle TCP ACK packets (handshake completion)
static __always_inline void handle_tcp_ack(struct xdp_md *ctx,
                                         struct iphdr *ip,
                                         struct tcphdr *tcp,
                                         __u64 now)
{
    struct flow_key fk = { ip->saddr, ip->daddr, tcp->source, tcp->dest, IPPROTO_TCP };

    // Check if not already established
    __u32 sip = ip->saddr;
    struct syn_val *sv = bpf_map_lookup_elem(&ip_syn_count_map, &sip);
    __u64 *est = bpf_map_lookup_elem(&established_map, &fk);

    // Only mark established if not already established AND we've seen a SYN from this IP
    if (!est && sv) {
        __u64 one = 1;
        bpf_map_update_elem(&established_map, &fk, &one, BPF_ANY);

        // Add reverse flow key for bidirectional fast-path
        struct flow_key rev_fk = { fk.dst_ip, fk.src_ip, fk.dst_port, fk.src_port, fk.proto };
        bpf_map_update_elem(&established_map, &rev_fk, &one, BPF_ANY);

        // Delete the SYN tracking entry now that handshake is complete
        bpf_map_delete_elem(&ip_syn_count_map, &sip);

        // Decrement score for successful handshake completion (if score exists)
        __u8 *scr = bpf_map_lookup_elem(&score_map, &ip->saddr);
        if (scr) {
            __u8 old = *scr;
            __u8 dec = SCORE_HANDSHAKE_DEC;
            __u8 new = old > dec ? old - dec : 0;
            if (new != old) { // Update only if changed
                bpf_map_update_elem(&score_map, &ip->saddr, &new, BPF_ANY);
            }
        }
        log_event(ctx, LOG_LEVEL_INFO, fk.src_ip, 0, EV_HANDSHAKE_COMPLETE);
    }
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

    // Fast path for established flows
    void *l4hdr_fast = (void *)ip + sizeof(*ip);
    if (l4hdr_fast + sizeof(struct tcphdr) > data_end) {
        return XDP_PASS;
    }

    __u16 src_port = 0, dst_port = 0;
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4hdr_fast;
        if ((void *)(tcp + 1) > data_end) {
            return XDP_PASS;
        }
        src_port = tcp->source;
        dst_port = tcp->dest;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = l4hdr_fast;
        if ((void *)(udp + 1) > data_end) {
            return XDP_PASS;
        }
        src_port = udp->source;
        dst_port = udp->dest;
    }

    struct flow_key fk = { ip->saddr, ip->daddr, src_port, dst_port, ip->protocol };
    __u64 *est = bpf_map_lookup_elem(&established_map, &fk);
    if (est) {
        log_event(ctx, LOG_LEVEL_INFO, fk.src_ip, 0, EV_ESTABLISHED);
        return XDP_PASS;
    }

    // Check if IP is blocked
    __u64 *block_until = bpf_map_lookup_elem(&blocked_ips_map, &ip->saddr);
    if (block_until) {
        __u64 now = bpf_ktime_get_ns();
        if (*block_until == 0 || now < *block_until) {
            // IP is blocked, drop the packet
            log_event(ctx, LOG_LEVEL_WARNING, ip->saddr, 0, EV_MANUAL_BLOCK);
            return XDP_DROP;
        } else {
            // Block has expired, remove from blocked map and log the unblock
            bpf_map_delete_elem(&blocked_ips_map, &ip->saddr);
            log_event(ctx, LOG_LEVEL_INFO, ip->saddr, 0, EV_UNBLOCK);
        }
    }

    // Prepare the map key
    struct ip_key key = {0};
    key.ip = ip->saddr;

    // Figure out if it's TCP or UDP so we can store the source port
    void *l4hdr = (void *)ip + sizeof(*ip);

    // Current time in nanoseconds - get once
    __u64 now = bpf_ktime_get_ns();

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

        // Track SYN packets
        if (tcp->syn && !tcp->ack) {
            handle_tcp_syn(ctx, ip, tcp, now);
        }

        // Detect handshake completion / ACK received
        if (tcp->ack && !tcp->syn) {
            handle_tcp_ack(ctx, ip, tcp, now);
        }

    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = l4hdr;
        if ((void *)(udp + 1) > data_end) {
            return XDP_PASS;
        }
        key.port = udp->source;
    } else {
        key.port = 0;  // For non-TCP/UDP, just store 0 as port
    }

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
