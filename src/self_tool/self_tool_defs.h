// Licensed under CC BY-NC 4.0 (https://creativecommons.org/licenses/by-nc/4.0/)
// © 2025 Adnan Duharkic — Non-commercial use only
#ifndef SELF_TOOL_DEFS_H
#define SELF_TOOL_DEFS_H

#include <stdint.h>

// Enumeracija za komande
enum self_tool_cmd {
    SELF_TOOL_CMD_LIST = 0,
    SELF_TOOL_CMD_CLEAR,
    SELF_TOOL_CMD_STATS,
    SELF_TOOL_CMD_MAX
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
};

#endif // SELF_TOOL_DEFS_H 