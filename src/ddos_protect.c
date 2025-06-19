// Licensed under CC BY-NC 4.0 (https://creativecommons.org/licenses/by-nc/4.0/)
// © 2025 Adnan Duharkic — Non-commercial use only
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/icmp.h>
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

// Tracks packet & byte counts per IP per window
struct flood_stats {
    __u64 pkt_count;
    __u64 byte_count;
    __u64 last_ts;   // nanoseconds of last reset
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1000000);
    __uint(pinning,    LIBBPF_PIN_BY_NAME);
    __type(key,   __u32);        // src IP
    __type(value, struct flood_stats);
} flood_stats_map SEC(".maps");

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

// Helper: detect & score L3/4 floods per-IP
static __always_inline void handle_flood(struct xdp_md *ctx,
                                         __u32 sip,
                                         __u64 pkt_size,
                                         __u64 now,
                                         __u64 pkt_thresh,
                                         __u64 bytes_thresh
                                         )
{
    struct flood_stats *st =
        bpf_map_lookup_elem(&flood_stats_map, &sip);
    struct flood_stats upd = {1, pkt_size, now}; // Initialize with current packet

    if (st && (now - st->last_ts <= FLOOD_WINDOW_NS)) {
        // Within the window, accumulate
        upd.pkt_count  = st->pkt_count + 1;
        upd.byte_count = st->byte_count + pkt_size;
        upd.last_ts    = st->last_ts;
    } else {
        // Window expired or first packet, log reset
        log_event(ctx, LOG_LEVEL_DEBUG, sip, 0, EV_FLOOD_RESET);
    }
    // threshold check
    if (upd.pkt_count > pkt_thresh || upd.byte_count > bytes_thresh) {
        // bump score & maybe ban
        __u8 new_score = SCORE_FLOOD_INC;
        __u8 *scr = bpf_map_lookup_elem(&score_map, &sip);
        if (scr) {
            __u8 sum = *scr + SCORE_FLOOD_INC;
            new_score = sum > SCORE_MAX ? SCORE_MAX : sum;
        }
        bpf_map_update_elem(&score_map, &sip, &new_score, BPF_ANY);
        maybe_ban_ip(sip, now, new_score);
        log_event(ctx, LOG_LEVEL_WARNING, sip, new_score, EV_FLOOD_DETECTED);

        // Reseting stats after penalty by setting counts to 0 and updating timestamp
        upd.pkt_count  = 0;
        upd.byte_count = 0;
        upd.last_ts    = now;
    }

    bpf_map_update_elem(&flood_stats_map, &sip, &upd, BPF_ANY);
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

    // Early blocked-IP check
    __u32 sip = ip->saddr;
    __u64 now = bpf_ktime_get_ns();
    __u64 *block_until = bpf_map_lookup_elem(&blocked_ips_map, &sip);
    if (block_until) {
        if (*block_until == 0 || now < *block_until) {
            log_event(ctx, LOG_LEVEL_WARNING, sip, 0, EV_MANUAL_BLOCK);
            return XDP_DROP;
        }
        // ban expired
        bpf_map_delete_elem(&blocked_ips_map, &sip);
        log_event(ctx, LOG_LEVEL_INFO, sip, 0, EV_UNBLOCK);
    }

    __u64 pkt_size = (void *)data_end - (void *)data;
    __u16 src_port = 0, dst_port = 0;
    struct ip_key key = {0};
    key.ip = ip->saddr;

    if (ip->protocol == IPPROTO_TCP) {
        void *l4 = (void*)ip + ip->ihl*4;
        struct tcphdr *tcp = l4;
        if ((void*)(tcp + 1) > data_end)
            return XDP_PASS;
        src_port = tcp->source;
        dst_port = tcp->dest;
        key.port = src_port;

        // Fast-path for established flows
        struct flow_key fk = { ip->saddr, ip->daddr, src_port, dst_port, IPPROTO_TCP };
        if (bpf_map_lookup_elem(&established_map, &fk)) {
            log_event(ctx, LOG_LEVEL_INFO, fk.src_ip, 0, EV_ESTABLISHED);
            return XDP_PASS;
        }

        // Flood detection only for data packets (ACK without SYN)
        if (tcp->ack && !tcp->syn)
            handle_flood(ctx, ip->saddr, pkt_size, now, TCP_PKT_THRESH, TCP_BYTES_THRESH);

        // SYN tracking
        if (tcp->syn && !tcp->ack)
            handle_tcp_syn(ctx, ip, tcp, now);

        // Handshake complete
        if (tcp->ack && !tcp->syn)
            handle_tcp_ack(ctx, ip, tcp, now);

    }
    else if (ip->protocol == IPPROTO_UDP) {
        void *l4 = (void*)ip + ip->ihl*4;
        struct udphdr *udp = l4;
        if ((void*)(udp + 1) > data_end)
            return XDP_PASS;
        src_port = udp->source;
        dst_port = udp->dest;
        key.port = src_port;
        handle_flood(ctx, ip->saddr, pkt_size, now, UDP_PKT_THRESH, UDP_BYTES_THRESH);
    }
    else if (ip->protocol == IPPROTO_ICMP) {
        void *l4 = (void*)ip + ip->ihl*4;
        struct icmphdr *icmp = l4;
        if ((void*)(icmp + 1) > data_end)
            return XDP_PASS;
        key.port = 0;
        handle_flood(ctx, ip->saddr, pkt_size, now, ICMP_PKT_THRESH, ICMP_BYTES_THRESH);
    } else {
        // not TCP/UDP/ICMP
        return XDP_PASS;
    }

    // Packet statistics
    struct traffic_stats *stats = bpf_map_lookup_elem(&ip_traffic_map, &key);
    if (stats) {
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
