#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <errno.h>
#include <arpa/inet.h>
#include <signal.h>
#include <string.h>
#include "logger.h"

#define BPF_OBJ_PATH "/usr/lib/self/ddos_protect.o"
#define DEFAULT_INTERFACE "eth0"

// Key for the map
struct ip_key {
    __u32 ip;
    __u16 port;
};

// Value for the map
struct traffic_stats {
    __u64 packet_count;
    __u64 last_seen;
    __u64 bytes;
    __u64 blocked;
};

// Globals
int map_fd   = -1;
int prog_fd  = -1;
volatile int running = 1;
int verbose = 0;
char interface[IF_NAMESIZE] = DEFAULT_INTERFACE;

/* Attach/detach helpers using the older bpf_set_link_xdp_fd() approach */
static int attach_xdp(int ifindex, int fd, __u32 flags)
{
    int err = bpf_set_link_xdp_fd(ifindex, fd, flags);
    if (err < 0) {
        LOG_ERROR("attach_xdp: err(%d): %s", err, strerror(-err));
    }
    return err;
}

static int detach_xdp(int ifindex, __u32 flags)
{
    int err = bpf_set_link_xdp_fd(ifindex, -1, flags);
    if (err < 0) {
        LOG_ERROR("detach_xdp: err(%d): %s", err, strerror(-err));
    }
    return err;
}

static void signal_handler(int sig)
{
    LOG_INFO("Received signal %d, stopping...", sig);
    running = 0;
}

// Libbpf debug callback
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (verbose || level <= LIBBPF_WARN) {
        vfprintf(stderr, format, args);
    }
    return 0;
}

// Function to load and attach the BPF program
static int load_bpf_program(int test_only)
{
    struct bpf_object *obj = NULL;
    struct bpf_program *bpf_prog;
    int ifindex, err;

    // Set up libbpf debug logging
    libbpf_set_print(libbpf_print_fn);

    LOG_INFO("Opening BPF object file: %s", BPF_OBJ_PATH);
    
    // 1) Open the object file
    obj = bpf_object__open_file(BPF_OBJ_PATH, NULL);
    if (libbpf_get_error(obj)) {
        LOG_ERROR("Failed to open BPF object file: %s", BPF_OBJ_PATH);
        LOG_ERROR("Error code: %ld", libbpf_get_error(obj));
        return -1;
    }

    LOG_INFO("Loading BPF object into kernel...");
    err = bpf_object__load(obj);
    if (err) {
        LOG_ERROR("Failed to load BPF object: %s", strerror(-err));
                if (err == -EPERM) {
            LOG_ERROR("Permission denied. Are you running as root?");
        }
        
        bpf_object__close(obj);
        return -1;
    }

    bpf_prog = bpf_object__find_program_by_name(obj, "xdp_ddos_protect");
    if (!bpf_prog) {
        LOG_ERROR("Could not find program 'xdp_ddos_protect'");
        bpf_object__close(obj);
        return -1;
    }

    // 4) Grab the FD for the program
    prog_fd = bpf_program__fd(bpf_prog);
    if (prog_fd < 0) {
        LOG_ERROR("Failed to get program fd");
        bpf_object__close(obj);
        return -1;
    }

    // 5) Locate the map "ip_traffic_map"
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "ip_traffic_map");
    if (!map) {
        LOG_ERROR("Failed to find map 'ip_traffic_map'");
        bpf_object__close(obj);
        return -1;
    }
    map_fd = bpf_map__fd(map);
    if (map_fd < 0) {
        LOG_ERROR("Invalid map fd");
        bpf_object__close(obj);
        return -1;
    }
    LOG_INFO("Map opened successfully, fd: %d", map_fd);

    // Pin the map to the filesystem only if it doesn't exist
    if (access("/sys/fs/bpf/ip_traffic_map", F_OK) != 0) {
        if (bpf_obj_pin(map_fd, "/sys/fs/bpf/ip_traffic_map")) {
            LOG_ERROR("Failed to pin map: %s", strerror(errno));
            bpf_object__close(obj);
            return -1;
        }
        LOG_INFO("Map pinned successfully to /sys/fs/bpf/ip_traffic_map");
    } else {
        LOG_INFO("Map already exists at /sys/fs/bpf/ip_traffic_map");
    }

    if (test_only) {
        LOG_INFO("Test mode: BPF program loaded successfully. Not attaching to interface.");
        bpf_object__close(obj);
        return 0;
    }

    //Attach the XDP program to the specified interface
    LOG_INFO("Attaching to interface: %s", interface);
    ifindex = if_nametoindex(interface);
    if (!ifindex) {
        LOG_ERROR("Failed to get ifindex for interface %s", interface);
        LOG_ERROR("Available interfaces:");
        system("ip link show | grep -E '^[0-9]+:' | cut -d' ' -f2 | tr -d ':'");
        bpf_object__close(obj);
        return -1;
    }
    err = attach_xdp(ifindex, prog_fd, 0 /* flags, e.g. XDP_FLAGS_SKB_MODE */);
    if (err < 0) {
        LOG_ERROR("Failed to attach XDP on %s", interface);
        bpf_object__close(obj);
        return -1;
    }

    return 0;
}

// Thread to monitor our BPF map
static void *monitor_traffic(void *arg)
{
    while (running) {
        LOG_DEBUG("[Monitor] Checking traffic statistics...");

        if (map_fd < 0) {
            LOG_ERROR("map_fd is invalid");
            sleep(2);
            continue;
        }

        // We'll iterate through up to some # of entries
        struct ip_key key = {0}, next_key;
        struct traffic_stats stats;
        int ret, count = 0;

        while ((ret = bpf_map_get_next_key(map_fd, &key, &next_key)) == 0) {
            if (bpf_map_lookup_elem(map_fd, &next_key, &stats) == 0) {
                // Convert IP to string
                char ip_str[INET_ADDRSTRLEN];
                struct in_addr addr = {.s_addr = next_key.ip};
                inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));

                LOG_DEBUG("IP: %s, Port: %u, Packets: %llu, Blocked: %llu",
                       ip_str, ntohs(next_key.port),
                       (unsigned long long)stats.packet_count,
                       (unsigned long long)stats.blocked);
                count++;
            }
            key = next_key;
        }

        if (count == 0) {
            LOG_DEBUG("No traffic entries in the map");
        }

        sleep(5);
    }
    return NULL;
}

void print_usage(char *prog_name) {
    LOG_INFO("Usage: %s [options]", prog_name);
    LOG_INFO("Options:");
    LOG_INFO("  --test             Test if the BPF program can be loaded without attaching it");
    LOG_INFO("  --verbose          Print verbose debug information");
    LOG_INFO("  --interface=<if>   Specify network interface to monitor (default: %s)", DEFAULT_INTERFACE);
    LOG_INFO("  --help             Display this help message");
}

int main(int argc, char **argv)
{
    int test_mode = 0;
    
    // Initialize logger
    if (logger_init() != 0) {
        fprintf(stderr, "Failed to initialize logger\n");
        return EXIT_FAILURE;
    }
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--test") == 0) {
            test_mode = 1;
        } else if (strcmp(argv[i], "--verbose") == 0) {
            verbose = 1;
            logger_set_verbose(1);
        } else if (strncmp(argv[i], "--interface=", 12) == 0) {
            strncpy(interface, argv[i] + 12, IF_NAMESIZE - 1);
            interface[IF_NAMESIZE - 1] = '\0';
        } else if (strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            logger_close();
            return 0;
        } else {
            LOG_ERROR("Unknown option: %s", argv[i]);
            print_usage(argv[0]);
            logger_close();
            return 1;
        }
    }

    // Increase memlock limits for eBPF
    struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        LOG_WARNING("setrlimit(RLIMIT_MEMLOCK) failed: %s", strerror(errno));
        LOG_WARNING("This might prevent the BPF program from loading");
    }

    // Handle Ctrl+C / SIGTERM
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    LOG_INFO("[Main] Loading eBPF program...");
    if (load_bpf_program(test_mode) != 0) {
        LOG_ERROR("Error loading BPF program");
        logger_close();
        return EXIT_FAILURE;
    }
    
    // If in test mode, exit successfully after loading the program
    if (test_mode) {
        LOG_INFO("Test successful: BPF program loaded.");
        logger_close();
        return 0;
    }

    //monitoring thread
    pthread_t monitor_thread;
    if (pthread_create(&monitor_thread, NULL, monitor_traffic, NULL) != 0) {
        LOG_ERROR("Failed to create monitor thread: %s", strerror(errno));
        logger_close();
        return EXIT_FAILURE;
    }

    LOG_INFO("[Main] eBPF program running on interface %s. Monitoring started.", interface);
    if (verbose) {
        LOG_INFO("Running in verbose mode");
    }
    LOG_INFO("Press Ctrl+C to exit.");

    // Wait until user stops
    pthread_join(monitor_thread, NULL);

    // Detach XDP before exit
    int ifindex = if_nametoindex(interface);
    if (ifindex) {
        detach_xdp(ifindex, 0);
    }

    LOG_INFO("[Main] Exiting.");
    logger_close();
    return 0;
}
