// Licensed under CC BY-NC 4.0 (https://creativecommons.org/licenses/by-nc/4.0/)
// © 2025 Adnan Duharkic — Non-commercial use only
#ifndef SELF_TOOL_H
#define SELF_TOOL_H

#include <stdint.h>
#include <errno.h>

// Enumeracija za komande
enum self_tool_cmd {
    SELF_TOOL_CMD_LIST = 0,
    SELF_TOOL_CMD_CLEAR_STATS,
    SELF_TOOL_CMD_CLEAR_SCORES,
    SELF_TOOL_CMD_CLEAR_BLOCKED,
    SELF_TOOL_CMD_CLEAR_ALL,
    SELF_TOOL_CMD_STATS,
    SELF_TOOL_CMD_BLOCK,
    SELF_TOOL_CMD_LIST_BLOCKED,
    SELF_TOOL_CMD_UNBLOCK,
    SELF_TOOL_CMD_ESTABLISHED,
    SELF_TOOL_CMD_SCORES,
    SELF_TOOL_CMD_LIST_FLOOD,
    SELF_TOOL_CMD_CONFIG,
    SELF_TOOL_CMD_WHITELIST_ADD,
    SELF_TOOL_CMD_WHITELIST_SHOW,
    SELF_TOOL_CMD_WHITELIST_REMOVE,
    SELF_TOOL_CMD_MAX
};

// Enumeracija za indekse mapa
enum map_index {
    MAP_IDX_TRAFFIC = 0,
    MAP_IDX_BLOCKED_IPS,
    MAP_IDX_ESTABLISHED,
    MAP_IDX_SCORES,
    MAP_IDX_FLOOD_STATS,
    MAP_IDX_CONFIG,
    MAP_IDX_WHITELIST,
    MAP_IDX_MAX
};

// Strukture koje odgovaraju BPF mapi
struct ip_key {
    uint32_t ip;
    uint16_t port;
};

struct traffic_stats {
    uint64_t packet_count;
    uint64_t last_seen;
    uint64_t bytes;
    uint64_t blocked;
    uint64_t block_until;  // Timestamp kada blokada ističe (0 = permanentna)
};

// Struktura za skor IP adrese
struct ip_score {
    uint32_t ip;
    uint8_t score;  // Skor od 0-100
};

// 4-tuple key for TCP/UDP flow (mora odgovarati BPF struct)
struct flow_key {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;
};

struct flood_stats {
    uint64_t pkt_count;
    uint64_t byte_count;
    uint64_t last_ts;   // nanoseconds of last reset
};

struct bpf_config {
    // Score thresholds
    int32_t score_permanent_ban;
    int32_t score_15_days_ban;
    int32_t score_4_days_ban;
    int32_t score_1_day_ban;
    int32_t score_15_min_ban;
    int32_t score_1_min_ban;
    int32_t score_15_sec_ban;
    int32_t score_half_open_inc;
    int32_t score_handshake_dec;
    int32_t score_flood_inc;
    int32_t score_max;

    // Flood detection
    uint64_t flood_window_ns;

    // Thresholds
    int32_t generic_pkt_thresh;
    int32_t generic_bytes_thresh;
    int32_t icmp_pkt_thresh;
    int32_t icmp_bytes_thresh;
    int32_t udp_pkt_thresh;
    int32_t udp_bytes_thresh;
    int32_t tcp_pkt_thresh;
    int32_t tcp_bytes_thresh;
    int32_t http_pkt_thresh;
    int32_t http_bytes_thresh;
};

#endif // SELF_TOOL_H 