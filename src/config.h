// Licensed under CC BY-NC 4.0 (https://creativecommons.org/licenses/by-nc/4.0/)
// © 2025 Adnan Duharkic — Non-commercial use only
#ifndef SELF_CONFIG_H
#define SELF_CONFIG_H

#include <stdint.h>

struct self_config {
    // Score thresholds
    int score_permanent_ban;
    int score_15_days_ban;
    int score_4_days_ban;
    int score_1_day_ban;
    int score_15_min_ban;
    int score_1_min_ban;
    int score_15_sec_ban;
    int score_half_open_inc;
    int score_handshake_dec;
    int score_flood_inc;
    int score_max;

    // Flood detection
    uint64_t flood_window_ns;

    // Thresholds
    int generic_pkt_thresh;
    int generic_bytes_thresh;
    int icmp_pkt_thresh;
    int icmp_bytes_thresh;
    int udp_pkt_thresh;
    int udp_bytes_thresh;
    int tcp_pkt_thresh;
    int tcp_bytes_thresh;
};

int load_config_from_yaml(const char *filepath, struct self_config *config);

#endif // SELF_CONFIG_H 