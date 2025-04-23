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

static void print_usage(const char *prog_name) {
    printf("Usage: %s <command>\n", prog_name);
    printf("Commands:\n");
    printf("  list    - List all IP addresses and their statistics\n");
    printf("  clear   - Clear all entries from the map\n");
    printf("  stats   - Show overall statistics\n");
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
    int map_fd, err;
    enum self_tool_cmd cmd;

    if (argc != 2) {
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
    } else {
        printf("Unknown command: %s\n", argv[1]);
        print_usage(argv[0]);
        return 1;
    }

    // Open the map
    map_fd = bpf_obj_get(MAP_PATH);
    if (map_fd < 0) {
        printf("Failed to open BPF map: %s\n", strerror(-map_fd));
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
        default:
            err = 1;
            break;
    }

    close(map_fd);
    return err;
} 