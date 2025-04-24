#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "self_tool.h"

#define MAP_PATH "/sys/fs/bpf/ip_traffic_map"
#define BLOCKED_IPS_MAP_PATH "/sys/fs/bpf/blocked_ips_map"
#define ESTABLISHED_MAP_PATH "/sys/fs/bpf/established_map"
#define BPF_OBJ_PATH "/usr/lib/self/ddos_protect.o"

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
    printf("\nBlock command usage:\n");
    printf("  %s block <ip> [duration]\n", prog_name);
    printf("  duration format: 2d13h14m5s (days, hours, minutes, seconds)\n");
    printf("  If duration is not specified, IP will be blocked permanently\n");
    printf("  Maximum block duration is 30 days\n");
    printf("\nUnblock command usage:\n");
    printf("  %s unblock <ip>\n", prog_name);
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
    int map_fd, blocked_map_fd, established_map_fd, err;
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
    } else {
        printf("Unknown command: %s\n", argv[1]);
        print_usage(argv[0]);
        return 1;
    }

    // Open the maps
    map_fd = bpf_obj_get(MAP_PATH);
    if (map_fd < 0) {
        printf("Failed to open BPF map: %s\n", strerror(-map_fd));
        return 1;
    }

    blocked_map_fd = bpf_obj_get(BLOCKED_IPS_MAP_PATH);
    if (blocked_map_fd < 0) {
        printf("Failed to open blocked IPs map: %s\n", strerror(-blocked_map_fd));
        close(map_fd);
        return 1;
    }

    established_map_fd = bpf_obj_get(ESTABLISHED_MAP_PATH);
    if (established_map_fd < 0) {
        printf("Failed to open established flows map: %s\n", strerror(-established_map_fd));
        close(map_fd);
        close(blocked_map_fd);
        return 1;
    }

    // Execute command
    switch (cmd) {
        case SELF_TOOL_CMD_LIST:
            err = list_entries(map_fd);
            break;
        case SELF_TOOL_CMD_CLEAR:
            err = clear_map(map_fd);
            break;
        case SELF_TOOL_CMD_STATS:
            err = show_stats(map_fd);
            break;
        case SELF_TOOL_CMD_BLOCK:
            err = block_ip(blocked_map_fd, argv[2], argc > 3 ? argv[3] : NULL);
            break;
        case SELF_TOOL_CMD_LIST_BLOCKED:
            err = list_blocked_ips(blocked_map_fd);
            break;
        case SELF_TOOL_CMD_UNBLOCK:
            err = unblock_ip(blocked_map_fd, argv[2]);
            break;
        case SELF_TOOL_CMD_ESTABLISHED:
            err = list_established_flows(established_map_fd);
            break;
        default:
            err = 1;
            break;
    }

    close(map_fd);
    close(blocked_map_fd);
    close(established_map_fd);
    return err;
} 