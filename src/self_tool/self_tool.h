#ifndef SELF_TOOL_H
#define SELF_TOOL_H

#include <stdint.h>
#include <errno.h>

// Enumeracija za komande
enum self_tool_cmd {
    SELF_TOOL_CMD_LIST = 0,
    SELF_TOOL_CMD_CLEAR,
    SELF_TOOL_CMD_STATS,
    SELF_TOOL_CMD_BLOCK,
    SELF_TOOL_CMD_LIST_BLOCKED,
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
    uint64_t block_until;  // Timestamp kada blokada ističe (0 = permanentna)
};

#endif // SELF_TOOL_H 