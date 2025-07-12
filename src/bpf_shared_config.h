// Licensed under CC BY-NC 4.0 (https://creativecommons.org/licenses/by-nc/4.0/)
// © 2025 Adnan Duharkic — Non-commercial use only
#ifndef BPF_SHARED_CONFIG_H
#define BPF_SHARED_CONFIG_H

#include <stdint.h>

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
};

#endif // BPF_SHARED_CONFIG_H 