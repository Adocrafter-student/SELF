// Licensed under CC BY-NC 4.0 (https://creativecommons.org/licenses/by-nc/4.0/)
// © 2025 Adnan Duharkic — Non-commercial use only
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "self_tool.h"
#include "self_defs.h"

#define BPF_OBJ_PATH "/usr/lib/self/ddos_protect.o"

static const char *map_paths[MAP_IDX_MAX] = {
    [MAP_IDX_TRAFFIC]     = "/sys/fs/bpf/ip_traffic_map",
    [MAP_IDX_BLOCKED_IPS] = "/sys/fs/bpf/blocked_ips_map",
    [MAP_IDX_ESTABLISHED] = "/sys/fs/bpf/established_map",
    [MAP_IDX_SCORES]      = "/sys/fs/bpf/score_map",
    [MAP_IDX_FLOOD_STATS] = "/sys/fs/bpf/flood_stats_map",
    [MAP_IDX_CONFIG]      = "/sys/fs/bpf/self_config_map",
    [MAP_IDX_WHITELIST]   = "/sys/fs/bpf/whitelist_map",
};

static int open_maps(int *map_fds) {
    for (int i = 0; i < MAP_IDX_MAX; i++) {
        map_fds[i] = bpf_obj_get(map_paths[i]);
        if (map_fds[i] < 0) {
            fprintf(stderr, "Failed to open BPF map (%s): %s\n", map_paths[i], strerror(errno));
            // Close already opened maps
            for (int j = 0; j < i; j++) {
                close(map_fds[j]);
            }
            return -1;
        }
    }
    return 0;
}

static void close_maps(int *map_fds) {
    for (int i = 0; i < MAP_IDX_MAX; i++) {
        if (map_fds[i] >= 0) {
            close(map_fds[i]);
        }
    }
}

// Funkcije za formatiranje izlaza
static inline const char *ip_to_str(uint32_t ip) {
    static char ip_str[INET_ADDRSTRLEN];
    struct in_addr addr = {.s_addr = ip};
    inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
    return ip_str;
}

static inline uint16_t port_to_host(uint16_t port) {
    return ntohs(port);
}

// Funkcije za prikaz podataka
void print_ip_stats(const struct ip_key *key, const struct traffic_stats *stats) {
    printf("IP: %s, Port: %u\n", ip_to_str(key->ip), port_to_host(key->port));
    printf("  Packets: %llu\n", (unsigned long long)stats->packet_count);
    printf("  Bytes: %llu\n", (unsigned long long)stats->bytes);
    printf("  Blocked: %llu\n", (unsigned long long)stats->blocked);
    printf("  Last seen: %llu seconds ago\n", 
           (unsigned long long)((time(NULL) - stats->last_seen/1000000000)));
    printf("----------------------------------------\n");
}

// Helper function to parse duration string (e.g. "2d13h14m5s")
static int parse_duration(const char *duration_str, time_t *seconds) {
    if (!duration_str || !*duration_str) {
        *seconds = 0; // Permanent block
        return 0;
    }

    *seconds = 0;
    char *end;
    const char *p = duration_str;

    while (*p) {
        long val = strtol(p, &end, 10);
        if (p == end) return -1;

        switch (*end) {
            case 'd': *seconds += val * 86400; break;
            case 'h': *seconds += val * 3600; break;
            case 'm': *seconds += val * 60; break;
            case 's': *seconds += val; break;
            default: return -1;
        }
        p = end + 1;
    }

    // Cap at 30 days
    if (*seconds > 30 * 86400) {
        *seconds = 30 * 86400;
    }

    return 0;
}

static int block_ip(int map_fd, const char *ip_str, const char *duration_str) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) != 1) {
        printf("Invalid IP address: %s\n", ip_str);
        return -1;
    }

    time_t block_seconds;
    if (parse_duration(duration_str, &block_seconds) != 0) {
        printf("Invalid duration format. Use format like: 2d13h14m5s\n");
        return -1;
    }

    __u64 block_until = 0;
    if (block_seconds > 0) {
        struct timespec ts;
        if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
            printf("Failed to get monotonic time: %s\n", strerror(errno));
            return -1;
        }
        __u64 now_ns = ((__u64)ts.tv_sec * 1000000000ULL) + ts.tv_nsec;
        block_until = now_ns + ((__u64)block_seconds * 1000000000ULL);
    }

    if (bpf_map_update_elem(map_fd, &addr.s_addr, &block_until, BPF_ANY) != 0) {
        printf("Failed to block IP: %s\n", strerror(errno));
        return -1;
    }

    printf("IP %s blocked", ip_str);
    if (block_seconds > 0) {
        printf(" for %s", duration_str);
    } else {
        printf(" permanently");
    }
    printf("\n");

    return 0;
}

// Helper function to format duration
static void format_duration(__u64 block_until, char *buf, size_t buf_size) {
    if (block_until == 0) {
        snprintf(buf, buf_size, "permanent");
        return;
    }

    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        snprintf(buf, buf_size, "error");
        return;
    }
    __u64 now_ns = ((__u64)ts.tv_sec * 1000000000ULL) + ts.tv_nsec;

    if (now_ns >= block_until) {
        snprintf(buf, buf_size, "expired");
        return;
    }

    __u64 remaining = (block_until - now_ns) / 1000000000ULL; // Convert to seconds
    int days = remaining / 86400;
    remaining %= 86400;
    int hours = remaining / 3600;
    remaining %= 3600;
    int minutes = remaining / 60;
    int seconds = remaining % 60;

    if (days > 0) {
        snprintf(buf, buf_size, "%dd%dh%dm%ds", days, hours, minutes, seconds);
    } else if (hours > 0) {
        snprintf(buf, buf_size, "%dh%dm%ds", hours, minutes, seconds);
    } else if (minutes > 0) {
        snprintf(buf, buf_size, "%dm%ds", minutes, seconds);
    } else {
        snprintf(buf, buf_size, "%ds", seconds);
    }
}

static int list_blocked_ips(int map_fd) {
    __u32 key = 0, next_key;
    __u64 block_until;
    int ret, count = 0;
    char duration_buf[32];
    char ip_str[INET_ADDRSTRLEN];

    printf("Currently blocked IP addresses:\n");
    printf("----------------------------------------\n");

    while ((ret = bpf_map_get_next_key(map_fd, &key, &next_key)) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &block_until) == 0) {
            struct in_addr addr = {.s_addr = next_key};
            inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
            
            format_duration(block_until, duration_buf, sizeof(duration_buf));
            printf("IP: %s\n", ip_str);
            printf("  Block duration: %s\n", duration_buf);
            printf("----------------------------------------\n");
            count++;
        }
        key = next_key;
    }

    if (count == 0) {
        printf("No blocked IP addresses found.\n");
    } else {
        printf("Total blocked IPs: %d\n", count);
    }

    return 0;
}

static int unblock_ip(int map_fd, const char *ip_str) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) != 1) {
        printf("Invalid IP address: %s\n", ip_str);
        return -1;
    }

    if (bpf_map_delete_elem(map_fd, &addr.s_addr) != 0) {
        if (errno == ENOENT) {
            printf("IP %s is not currently blocked\n", ip_str);
        } else {
            printf("Failed to unblock IP: %s\n", strerror(errno));
        }
        return -1;
    }

    printf("IP %s unblocked successfully\n", ip_str);
    return 0;
}

static int list_established_flows(int map_fd) {
    struct flow_key key = {0}, next_key;
    __u64 value;
    int ret, count = 0;
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    printf("Listing all established flows:\n");
    printf("----------------------------------------\n");

    while ((ret = bpf_map_get_next_key(map_fd, &key, &next_key)) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0) {
            struct in_addr src_addr = {.s_addr = next_key.src_ip};
            struct in_addr dst_addr = {.s_addr = next_key.dst_ip};
            inet_ntop(AF_INET, &src_addr, src_ip, sizeof(src_ip));
            inet_ntop(AF_INET, &dst_addr, dst_ip, sizeof(dst_ip));

            printf("Flow: %s:%u -> %s:%u (proto: %u)\n",
                   src_ip, ntohs(next_key.src_port),
                   dst_ip, ntohs(next_key.dst_port),
                   next_key.proto);
            printf("----------------------------------------\n");
            count++;
        }
        key = next_key;
    }

    if (count == 0) {
        printf("No established flows found.\n");
    } else {
        printf("Total established flows: %d\n", count);
    }

    return 0;
}

static int list_scores(int map_fd) {
    __u32 key = 0, next_key;
    __u8 score;
    int ret, count = 0;
    char ip_str[INET_ADDRSTRLEN];

    printf("Listing all IP scores:\n");
    printf("----------------------------------------\n");

    while ((ret = bpf_map_get_next_key(map_fd, &key, &next_key)) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &score) == 0) {
            struct in_addr addr = {.s_addr = next_key};
            inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
            
            printf("IP: %s\n", ip_str);
            printf("  Score: %u/%u\n", score, SCORE_MAX);
            printf("----------------------------------------\n");
            count++;
        }
        key = next_key;
    }

    if (count == 0) {
        printf("No IP scores found.\n");
    } else {
        printf("Total IPs with scores: %d\n", count);
    }

    return 0;
}

// Function to list flood statistics
static int list_flood_stats(int map_fd) {
    __u32 key = 0, next_key;
    struct flood_stats stats;
    int ret, count = 0;
    char ip_str[INET_ADDRSTRLEN];

    printf("Listing current flood statistics per IP:\n");
    printf("----------------------------------------\n");

    while ((ret = bpf_map_get_next_key(map_fd, &key, &next_key)) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &stats) == 0) {
            struct in_addr addr = {.s_addr = next_key};
            inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
            
            printf("IP: %s\n", ip_str);
            printf("  Packet Count: %llu\n", (unsigned long long)stats.pkt_count);
            printf("  Byte Count: %llu\n", (unsigned long long)stats.byte_count);
            // Calculate time since last reset
            struct timespec ts;
            clock_gettime(CLOCK_MONOTONIC, &ts);
            __u64 now_ns = ((__u64)ts.tv_sec * 1000000000ULL) + ts.tv_nsec;
            double time_since_reset_s = (stats.last_ts > 0) ? (double)(now_ns - stats.last_ts) / 1e9 : -1.0;
            printf("  Last Reset: %.2f seconds ago\n", time_since_reset_s);
            printf("----------------------------------------\n");
            count++;
        }
        key = next_key;
    }

    if (count == 0) {
        printf("No flood statistics entries found.\n");
    } else {
        printf("Total IPs with flood stats: %d\n", count);
    }

    return 0;
}

static int show_config(int map_fd) {
    struct bpf_config cfg;
    __u32 key = 0;

    if (bpf_map_lookup_elem(map_fd, &key, &cfg) != 0) {
        printf("Failed to read config map: %s\n", strerror(errno));
        return -1;
    }

    printf("Current SELF Configuration:\n");
    printf("----------------------------------------\n");
    printf("Score Thresholds:\n");
    printf("  Permanent Ban: %d\n", cfg.score_permanent_ban);
    printf("  15 Days Ban: %d\n", cfg.score_15_days_ban);
    printf("  4 Days Ban: %d\n", cfg.score_4_days_ban);
    printf("  1 Day Ban: %d\n", cfg.score_1_day_ban);
    printf("  15 Minutes Ban: %d\n", cfg.score_15_min_ban);
    printf("  1 Minute Ban: %d\n", cfg.score_1_min_ban);
    printf("  15 Seconds Ban: %d\n", cfg.score_15_sec_ban);
    printf("\nScore Adjustments:\n");
    printf("  Half-open Connection: +%d\n", cfg.score_half_open_inc);
    printf("  Handshake Complete: -%d\n", cfg.score_handshake_dec);
    printf("  Flood Detection: +%d\n", cfg.score_flood_inc);
    printf("  Maximum Score: %d\n", cfg.score_max);
    printf("\nFlood Detection:\n");
    printf("  Window: %lu ns\n", cfg.flood_window_ns);
    printf("\nThresholds:\n");
    printf("  Generic: %d packets, %d bytes\n", cfg.generic_pkt_thresh, cfg.generic_bytes_thresh);
    printf("  ICMP: %d packets, %d bytes\n", cfg.icmp_pkt_thresh, cfg.icmp_bytes_thresh);
    printf("  UDP: %d packets, %d bytes\n", cfg.udp_pkt_thresh, cfg.udp_bytes_thresh);
    printf("  TCP: %d packets, %d bytes\n", cfg.tcp_pkt_thresh, cfg.tcp_bytes_thresh);
    printf("  HTTP: %d packets, %d bytes\n", cfg.http_pkt_thresh, cfg.http_bytes_thresh);
    printf("----------------------------------------\n");

    return 0;
}

static int whitelist_add(int map_fd, const char *ip_str) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) != 1) {
        printf("Invalid IP address: %s\n", ip_str);
        return -1;
    }

    __u8 whitelisted = 1;
    if (bpf_map_update_elem(map_fd, &addr.s_addr, &whitelisted, BPF_ANY) != 0) {
        printf("Failed to add IP to whitelist: %s\n", strerror(errno));
        return -1;
    }

    printf("IP %s added to whitelist successfully\n", ip_str);
    return 0;
}

static int whitelist_remove(int map_fd, const char *ip_str) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) != 1) {
        printf("Invalid IP address: %s\n", ip_str);
        return -1;
    }

    if (bpf_map_delete_elem(map_fd, &addr.s_addr) != 0) {
        if (errno == ENOENT) {
            printf("IP %s is not in the whitelist\n", ip_str);
        } else {
            printf("Failed to remove IP from whitelist: %s\n", strerror(errno));
        }
        return -1;
    }

    printf("IP %s removed from whitelist successfully\n", ip_str);
    return 0;
}

static int list_whitelist(int map_fd) {
    __u32 key = 0, next_key;
    __u8 whitelisted;
    int ret, count = 0;
    char ip_str[INET_ADDRSTRLEN];

    printf("Currently whitelisted IP addresses:\n");
    printf("----------------------------------------\n");

    while ((ret = bpf_map_get_next_key(map_fd, &key, &next_key)) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &whitelisted) == 0) {
            struct in_addr addr = {.s_addr = next_key};
            inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
            
            printf("IP: %s\n", ip_str);
            printf("----------------------------------------\n");
            count++;
        }
        key = next_key;
    }

    if (count == 0) {
        printf("No whitelisted IP addresses found.\n");
    } else {
        printf("Total whitelisted IPs: %d\n", count);
    }

    return 0;
}

static void print_usage(const char *prog_name) {
    printf("Usage: %s <command> [options]\n", prog_name);
    printf("Commands:\n");
    printf("  list          - List all IP addresses and their statistics\n");
    printf("  clear         - Clear all entries from the map\n");
    printf("  stats         - Show overall statistics\n");
    printf("  block         - Block an IP address\n");
    printf("  list-blocked  - List all currently blocked IP addresses\n");
    printf("  unblock       - Unblock an IP address\n");
    printf("  established   - List all established TCP flows\n");
    printf("  scores        - List all IP scores\n");
    printf("  flood-stats   - List current flood statistics per IP\n");
    printf("  config        - Show current SELF configuration\n");
    printf("  whitelist-add - Add an IP address to the whitelist\n");
    printf("  whitelist-show- Show all whitelisted IP addresses\n");
    printf("  whitelist-remove- Remove an IP address from the whitelist\n");
    printf("\nBlock command usage:\n");
    printf("  %s block <ip> [duration]\n", prog_name);
    printf("  duration format: 2d13h14m5s (days, hours, minutes, seconds)\n");
    printf("  If duration is not specified, IP will be blocked permanently\n");
    printf("  Maximum block duration is 30 days\n");
    printf("\nUnblock command usage:\n");
    printf("  %s unblock <ip>\n", prog_name);
    printf("\nWhitelist add command usage:\n");
    printf("  %s whitelist-add <ip>\n", prog_name);
    printf("\nWhitelist remove command usage:\n");
    printf("  %s whitelist-remove <ip>\n", prog_name);
}

static int list_entries(int map_fd) {
    struct ip_key key = {0}, next_key;
    struct traffic_stats stats;
    int ret, count = 0;

    printf("Listing all IP addresses and their statistics:\n");
    printf("----------------------------------------\n");

    while ((ret = bpf_map_get_next_key(map_fd, &key, &next_key)) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &stats) == 0) {
            print_ip_stats(&next_key, &stats);
            count++;
        }
        key = next_key;
    }

    if (count == 0) {
        printf("No entries found in the map.\n");
    } else {
        printf("Total entries: %d\n", count);
    }

    return 0;
}

static int clear_map(int map_fd) {
    struct ip_key key = {0}, next_key;
    int ret, count = 0;

    printf("Clearing all entries from the map...\n");

    while ((ret = bpf_map_get_next_key(map_fd, &key, &next_key)) == 0) {
        if (bpf_map_delete_elem(map_fd, &next_key) == 0) {
            count++;
        }
        key = next_key;
    }

    printf("Cleared %d entries.\n", count);
    return 0;
}

static int show_stats(int map_fd) {
    struct ip_key key = {0}, next_key;
    struct traffic_stats stats;
    int ret;
    uint64_t total_packets = 0;
    uint64_t total_bytes = 0;
    uint64_t total_blocked = 0;
    int count = 0;

    while ((ret = bpf_map_get_next_key(map_fd, &key, &next_key)) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &stats) == 0) {
            total_packets += stats.packet_count;
            total_bytes += stats.bytes;
            total_blocked += stats.blocked;
            count++;
        }
        key = next_key;
    }

    printf("Overall Statistics:\n");
    printf("----------------------------------------\n");
    printf("Total IP addresses: %d\n", count);
    printf("Total packets: %llu\n", (unsigned long long)total_packets);
    printf("Total bytes: %llu\n", (unsigned long long)total_bytes);
    printf("Total blocked packets: %llu\n", (unsigned long long)total_blocked);
    printf("----------------------------------------\n");

    return 0;
}

int main(int argc, char **argv) {
    int map_fds[MAP_IDX_MAX];
    int err;
    enum self_tool_cmd cmd;

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    // Parse command
    if (strcmp(argv[1], "list") == 0) {
        cmd = SELF_TOOL_CMD_LIST;
    } else if (strcmp(argv[1], "clear") == 0) {
        cmd = SELF_TOOL_CMD_CLEAR;
    } else if (strcmp(argv[1], "stats") == 0) {
        cmd = SELF_TOOL_CMD_STATS;
    } else if (strcmp(argv[1], "block") == 0) {
        if (argc < 3) {
            printf("Error: IP address required for block command\n");
            print_usage(argv[0]);
            return 1;
        }
        cmd = SELF_TOOL_CMD_BLOCK;
    } else if (strcmp(argv[1], "list-blocked") == 0) {
        cmd = SELF_TOOL_CMD_LIST_BLOCKED;
    } else if (strcmp(argv[1], "unblock") == 0) {
        if (argc < 3) {
            printf("Error: IP address required for unblock command\n");
            print_usage(argv[0]);
            return 1;
        }
        cmd = SELF_TOOL_CMD_UNBLOCK;
    } else if (strcmp(argv[1], "established") == 0) {
        cmd = SELF_TOOL_CMD_ESTABLISHED;
    } else if (strcmp(argv[1], "scores") == 0) {
        cmd = SELF_TOOL_CMD_SCORES;
    } else if (strcmp(argv[1], "flood-stats") == 0) {
        cmd = SELF_TOOL_CMD_LIST_FLOOD;
    } else if (strcmp(argv[1], "config") == 0) {
        cmd = SELF_TOOL_CMD_CONFIG;
    } else if (strcmp(argv[1], "whitelist-add") == 0) {
        if (argc < 3) {
            printf("Error: IP address required for whitelist-add command\n");
            print_usage(argv[0]);
            return 1;
        }
        cmd = SELF_TOOL_CMD_WHITELIST_ADD;
    } else if (strcmp(argv[1], "whitelist-show") == 0) {
        cmd = SELF_TOOL_CMD_WHITELIST_SHOW;
    } else if (strcmp(argv[1], "whitelist-remove") == 0) {
        if (argc < 3) {
            printf("Error: IP address required for whitelist-remove command\n");
            print_usage(argv[0]);
            return 1;
        }
        cmd = SELF_TOOL_CMD_WHITELIST_REMOVE;
    } else {
        printf("Unknown command: %s\n", argv[1]);
        print_usage(argv[0]);
        return 1;
    }

    // Open the maps
    if (open_maps(map_fds) != 0) {
        return 1;
    }

    // Execute command
    switch (cmd) {
        case SELF_TOOL_CMD_LIST:
            err = list_entries(map_fds[MAP_IDX_TRAFFIC]);
            break;
        case SELF_TOOL_CMD_CLEAR:
            err = clear_map(map_fds[MAP_IDX_TRAFFIC]);
            break;
        case SELF_TOOL_CMD_STATS:
            err = show_stats(map_fds[MAP_IDX_TRAFFIC]);
            break;
        case SELF_TOOL_CMD_BLOCK:
            err = block_ip(map_fds[MAP_IDX_BLOCKED_IPS], argv[2], argc > 3 ? argv[3] : NULL);
            break;
        case SELF_TOOL_CMD_LIST_BLOCKED:
            err = list_blocked_ips(map_fds[MAP_IDX_BLOCKED_IPS]);
            break;
        case SELF_TOOL_CMD_UNBLOCK:
            err = unblock_ip(map_fds[MAP_IDX_BLOCKED_IPS], argv[2]);
            break;
        case SELF_TOOL_CMD_ESTABLISHED:
            err = list_established_flows(map_fds[MAP_IDX_ESTABLISHED]);
            break;
        case SELF_TOOL_CMD_SCORES:
            err = list_scores(map_fds[MAP_IDX_SCORES]);
            break;
        case SELF_TOOL_CMD_LIST_FLOOD:
            err = list_flood_stats(map_fds[MAP_IDX_FLOOD_STATS]);
            break;
        case SELF_TOOL_CMD_CONFIG:
            err = show_config(map_fds[MAP_IDX_CONFIG]);
            break;
        case SELF_TOOL_CMD_WHITELIST_ADD:
            err = whitelist_add(map_fds[MAP_IDX_WHITELIST], argv[2]);
            break;
        case SELF_TOOL_CMD_WHITELIST_SHOW:
            err = list_whitelist(map_fds[MAP_IDX_WHITELIST]);
            break;
        case SELF_TOOL_CMD_WHITELIST_REMOVE:
            err = whitelist_remove(map_fds[MAP_IDX_WHITELIST], argv[2]);
            break;
        default:
            err = 1;
            break;
    }

    close_maps(map_fds);
    return err;
} 