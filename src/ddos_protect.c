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

// Tracks half-open SYNs: key = 4-tuple, value = __u64 timestamp
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1000000);
    __type(key, struct flow_key);
    __type(value, __u64);
} syn_map SEC(".maps");

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
            struct flow_key fk = { ip->saddr, ip->daddr, tcp->source, tcp->dest, IPPROTO_TCP };
            __u64 now = bpf_ktime_get_ns();
            __u64 *prev_ts = bpf_map_lookup_elem(&syn_map, &fk);
            
            if (!prev_ts) {
                // first SYN for this 4-tuple: record timestamp
                bpf_map_update_elem(&syn_map, &fk, &now, BPF_ANY);
            } else {
                // second SYN (handshake never completed): treat as a failed handshake
                bpf_map_delete_elem(&syn_map, &fk);

                // now we bump score once and maybe ban
                __u32 sip = fk.src_ip;
                __u8 *scr = bpf_map_lookup_elem(&score_map, &sip);
                __u8 zero = 0;
                if (!scr) {
                    bpf_map_update_elem(&score_map, &sip, &zero, BPF_ANY);
                    scr = &zero;
                }
                __u8 new = (*scr + SCORE_HALF_OPEN_INC <= SCORE_MAX)
                           ? *scr + SCORE_HALF_OPEN_INC
                           : SCORE_MAX;
                bpf_map_update_elem(&score_map, &sip, &new, BPF_ANY);
                maybe_ban_ip(sip, now, new);
            }
        }

        // Detect handshake completion
        if (tcp->ack && !tcp->syn) {
            struct flow_key fk = { ip->saddr, ip->daddr, tcp->source, tcp->dest, IPPROTO_TCP };
            __u64 *syn_ts = bpf_map_lookup_elem(&syn_map, &fk);
            if (syn_ts) {
                __u64 one = 1;
                bpf_map_delete_elem(&syn_map, &fk);
                bpf_map_update_elem(&established_map, &fk, &one, BPF_ANY);

                // Decrement score for successful handshake
                __u8 *scr = bpf_map_lookup_elem(&score_map, &ip->saddr);
                if (scr) {
                    __u8 old = *scr;
                    __u8 dec = SCORE_HANDSHAKE_DEC;
                    __u8 new = old > dec ? old - dec : 0;
                    bpf_map_update_elem(&score_map, &ip->saddr, &new, BPF_ANY);
                }

                log_event(ctx, LOG_LEVEL_INFO, fk.src_ip, 0, EV_HANDSHAKE_COMPLETE);
            }
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
#if 0
        if (stats->packet_count > PACKET_THRESHOLD) {
            stats->blocked += 1;
            bpf_map_update_elem(&ip_traffic_map, &key, stats, BPF_ANY);
            log_event(ctx, LOG_LEVEL_WARNING, key.ip, stats->packet_count, EV_BLOCK);
            return XDP_DROP;
        }
#endif

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
