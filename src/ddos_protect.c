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
#include <stdbool.h>
#include "ddos_events.h"
#include "self_defs.h"
#include "bpf_shared_config.h"

// BPF map to hold configuration
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u32);
    __type(value, struct bpf_config);
} self_config_map SEC(".maps");

// Helper to get configuration
static __always_inline const struct bpf_config *get_config()
{
    __u32 key = 0;
    return bpf_map_lookup_elem(&self_config_map, &key);
}

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

// Value for our IP map
struct traffic_stats {
    __u64 passed_packets;
    __u64 passed_bytes;
    __u64 blocked_packets;
    __u64 blocked_bytes;
};

// New struct for global, non-sampled counters
struct global_stats {
    __u64 total_passed_packets;
    __u64 total_passed_bytes;
    __u64 total_blocked_packets;
    __u64 total_blocked_bytes;
};

// Constants for simple rate-limiting
#define PACKET_THRESHOLD 1000             // Packets before we start blocking
#define RATE_WINDOW      60000000000ULL   // 60 seconds in nanoseconds
#define WINDOW_NS        5000000000ULL    // 5 seconds in nanoseconds

// eBPF Hash Map for storing per-IP traffic stats
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1000000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u32);
    __type(value, struct traffic_stats);
} ip_stats_map SEC(".maps");

// Per-CPU array for global, non-sampled statistics
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u32);
    __type(value, struct global_stats);
} global_stats_map SEC(".maps");

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

// eBPF Hash Map for storing whitelisted IPs
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u32);  // IP address
    __type(value, __u8); // 1 if whitelisted
} whitelist_map SEC(".maps");

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

// Helper function to update traffic statistics for an IP
static __always_inline void update_stats(struct xdp_md *ctx,
                                         __u32 sip,
                                         __u64 pkt_size,
                                         bool is_blocked,
                                         const struct bpf_config *cfg)
{
    // --- Global (non-sampled) stats update ---
    __u32 key = 0;
    struct global_stats *g_stats = bpf_map_lookup_elem(&global_stats_map, &key);
    if (g_stats) {
        if (is_blocked) {
            g_stats->total_blocked_packets++;
            g_stats->total_blocked_bytes += pkt_size;
        } else {
            g_stats->total_passed_packets++;
            g_stats->total_passed_bytes += pkt_size;
        }
    }

    // --- Per-IP (sampled) stats update ---
    // If sampling rate is 0 or not set, do not record stats to avoid heavy load
    if (!cfg || cfg->stats_sampling_rate == 0)
        return;

    // Sample 1 out of every N packets, where N is the sampling rate
    if ((bpf_get_prandom_u32() % cfg->stats_sampling_rate) != 0)
        return;

    struct traffic_stats *stats = bpf_map_lookup_elem(&ip_stats_map, &sip);
    if (stats) {
        if (is_blocked) {
            stats->blocked_packets++;
            stats->blocked_bytes += pkt_size;
        } else {
            stats->passed_packets++;
            stats->passed_bytes += pkt_size;
        }
        bpf_map_update_elem(&ip_stats_map, &sip, stats, BPF_ANY);
    } else {
        // New IP, create stats entry
        struct traffic_stats new_stats = {
            .passed_packets = is_blocked ? 0 : 1,
            .passed_bytes = is_blocked ? 0 : pkt_size,
            .blocked_packets = is_blocked ? 1 : 0,
            .blocked_bytes = is_blocked ? pkt_size : 0,
        };
        bpf_map_update_elem(&ip_stats_map, &sip, &new_stats, BPF_ANY);
        log_event(ctx, LOG_LEVEL_DEBUG, sip, 1, EV_NEW_IP);
    }
}


// Helper function to potentially ban an IP based on its score
static __always_inline void maybe_ban_ip(__u32 sip, __u64 now, __u8 score, const struct bpf_config *cfg)
{
    __u64 expire = 0;

    if (!cfg) return;

    if (score >= cfg->score_permanent_ban)     expire = BAN_PERMANENT;
    else if (score >= cfg->score_15_days_ban)  expire = now + BAN_15_DAYS;
    else if (score >= cfg->score_4_days_ban)   expire = now + BAN_4_DAYS;
    else if (score >= cfg->score_1_day_ban)    expire = now + BAN_1_DAY;
    else if (score >= cfg->score_15_min_ban)   expire = now + BAN_15_MIN;
    else if (score >= cfg->score_1_min_ban)    expire = now + BAN_1_MIN;
    else if (score >= cfg->score_15_sec_ban)   expire = now + BAN_15_SEC;
    else return;

    bpf_map_update_elem(&blocked_ips_map, &sip, &expire, BPF_ANY);
}

// Helper function to handle TCP SYN packets
static __always_inline void handle_tcp_syn(struct xdp_md *ctx,
                                          struct iphdr *ip,
                                          struct tcphdr *tcp,
                                          __u64 now,
                                          const struct bpf_config *cfg)
{
    if (!cfg) return;

    __u32 sip = ip->saddr;
    struct syn_val new_val = { .ts_ns = now };

    struct syn_val *val = bpf_map_lookup_elem(&ip_syn_count_map, &sip);

    if (!val || (now - val->ts_ns > WINDOW_NS)) {
        bpf_map_update_elem(&ip_syn_count_map, &sip, &new_val, BPF_ANY);
        log_event(ctx, LOG_LEVEL_DEBUG, sip, 0, EV_FIRST_SYN);
    } else {
        __u8 new_score = cfg->score_half_open_inc;
        __u8 *scr = bpf_map_lookup_elem(&score_map, &sip);
        if (scr) {
            new_score = (*scr + cfg->score_half_open_inc <= cfg->score_max) ? *scr + cfg->score_half_open_inc : cfg->score_max;
        }
        bpf_map_update_elem(&score_map, &sip, &new_score, BPF_ANY);
        maybe_ban_ip(sip, now, new_score, cfg);

        log_event(ctx, LOG_LEVEL_WARNING, sip, new_score, EV_SYN_RETRY_PENALTY);

        new_val.ts_ns = now;
        bpf_map_update_elem(&ip_syn_count_map, &sip, &new_val, BPF_ANY);
    }
}

// Helper function to handle TCP ACK packets (handshake completion)
static __always_inline void handle_tcp_ack(struct xdp_md *ctx,
                                         struct iphdr *ip,
                                         struct tcphdr *tcp,
                                         __u64 now,
                                         const struct bpf_config *cfg)
{
    if (!cfg) return;

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
            __u8 dec = cfg->score_handshake_dec;
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
                                         const struct bpf_config *cfg,
                                         __u64 pkt_thresh,
                                         __u64 bytes_thresh)
{
    if (!cfg) return;

    struct flood_stats *st = bpf_map_lookup_elem(&flood_stats_map, &sip);
    struct flood_stats upd = {1, pkt_size, now};

    if (st && (now - st->last_ts <= cfg->flood_window_ns)) {
        upd.pkt_count  = st->pkt_count + 1;
        upd.byte_count = st->byte_count + pkt_size;
        upd.last_ts    = st->last_ts;
    } else {
        log_event(ctx, LOG_LEVEL_DEBUG, sip, 0, EV_FLOOD_RESET);
    }

    if (upd.pkt_count > pkt_thresh || upd.byte_count > bytes_thresh) {
        __u8 new_score = cfg->score_flood_inc;
        __u8 *scr = bpf_map_lookup_elem(&score_map, &sip);
        if (scr) {
            __u8 sum = *scr + cfg->score_flood_inc;
            new_score = sum > cfg->score_max ? cfg->score_max : sum;
        }
        bpf_map_update_elem(&score_map, &sip, &new_score, BPF_ANY);
        maybe_ban_ip(sip, now, new_score, cfg);
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
    const struct bpf_config *cfg = get_config();
    if (!cfg)
        return XDP_PASS;

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
    __u64 pkt_size = (void *)data_end - (void *)data;

    // Early blocked-IP check
    __u32 sip = ip->saddr;

    // Whitelist check
    __u8 *is_whitelisted = bpf_map_lookup_elem(&whitelist_map, &sip);
    if (is_whitelisted && *is_whitelisted == 1) {
        return XDP_PASS;
    }

    __u64 now = bpf_ktime_get_ns();
    __u64 *block_until = bpf_map_lookup_elem(&blocked_ips_map, &sip);
    if (block_until) {
        if (*block_until == 0 || now < *block_until) {
            log_event(ctx, LOG_LEVEL_WARNING, sip, 0, EV_MANUAL_BLOCK);
            update_stats(ctx, sip, pkt_size, true, cfg);
            return XDP_DROP;
        }
        // ban expired
        bpf_map_delete_elem(&blocked_ips_map, &sip);
        log_event(ctx, LOG_LEVEL_INFO, sip, 0, EV_UNBLOCK);
    }

    __u16 src_port = 0, dst_port = 0;

    if (ip->protocol == IPPROTO_TCP) {
        void *l4 = (void*)ip + ip->ihl*4;
        struct tcphdr *tcp = l4;
        if ((void*)(tcp + 1) > data_end)
            return XDP_PASS;
        src_port = tcp->source;
        dst_port = tcp->dest;

        // Fast-path for established flows
        struct flow_key fk = { ip->saddr, ip->daddr, src_port, dst_port, IPPROTO_TCP };
        if (bpf_map_lookup_elem(&established_map, &fk)) {
            log_event(ctx, LOG_LEVEL_INFO, fk.src_ip, 0, EV_ESTABLISHED);
            update_stats(ctx, sip, pkt_size, false, cfg);
            return XDP_PASS;
        }

        // SYN tracking
        if (tcp->syn && !tcp->ack)
            handle_tcp_syn(ctx, ip, tcp, now, cfg);

        // Handshake complete
        if (tcp->ack && !tcp->syn) {
            handle_tcp_ack(ctx, ip, tcp, now, cfg);
            if (dst_port == bpf_htons(80) || dst_port == bpf_htons(443)) {
                handle_flood(ctx, ip->saddr, pkt_size, now, cfg, cfg->http_pkt_thresh, cfg->http_bytes_thresh);
            } else {
                // General TCP flood detection for non-HTTP traffic
                handle_flood(ctx, ip->saddr, pkt_size, now, cfg, cfg->tcp_pkt_thresh, cfg->tcp_bytes_thresh);
            }
        }

    }
    else if (ip->protocol == IPPROTO_UDP) {
        void *l4 = (void*)ip + ip->ihl*4;
        struct udphdr *udp = l4;
        if ((void*)(udp + 1) > data_end)
            return XDP_PASS;
        src_port = udp->source;
        dst_port = udp->dest;
        handle_flood(ctx, ip->saddr, pkt_size, now, cfg, cfg->udp_pkt_thresh, cfg->udp_bytes_thresh);
    }
    else if (ip->protocol == IPPROTO_ICMP) {
        void *l4 = (void*)ip + ip->ihl*4;
        struct icmphdr *icmp = l4;
        if ((void*)(icmp + 1) > data_end)
            return XDP_PASS;
        handle_flood(ctx, ip->saddr, pkt_size, now, cfg, cfg->icmp_pkt_thresh, cfg->icmp_bytes_thresh);
    } else {
        // not TCP/UDP/ICMP
        return XDP_PASS;
    }

    // Packet statistics
    update_stats(ctx, sip, pkt_size, false, cfg);

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
