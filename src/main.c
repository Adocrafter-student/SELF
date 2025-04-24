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
#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include "ddos_events.h"
#include <sys/stat.h>
#include <fcntl.h>

// Log levels
#define LOG_LEVEL_DEBUG   0
#define LOG_LEVEL_INFO    1
#define LOG_LEVEL_WARNING 2
#define LOG_LEVEL_ERROR   3

#define BPF_OBJ_PATH "/usr/lib/self/ddos_protect.o"
#define DEFAULT_INTERFACE "eth0"
#define BLOCKED_IPS_MAP_PATH "/sys/fs/bpf/blocked_ips_map"

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

// Log entry structure
struct log_entry {
    __u32 level;
    __u32 ip;
    __u64 packets;
    __u8 code;      // Event code from ddos_event_code enum
    __u64 timestamp;
};

// Globals
int map_fd   = -1;
int prog_fd  = -1;
volatile int running = 1;
int verbose = 0;
char interface[IF_NAMESIZE] = DEFAULT_INTERFACE;
static int log_buffer_fd = -1;
static void *log_buffer_mmap = NULL;

// Global link handle
static struct bpf_link *prog_link = NULL;

// Global variables for log handling
static pthread_t log_thread;

// New attach/detach helpers using the link API
static int attach_xdp(struct bpf_program *bpf_prog, const char *ifname, __u32 flags)
{
    int ifindex = if_nametoindex(ifname);
    if (ifindex <= 0) {
        LOG_ERROR("if_nametoindex(%s) failed", ifname);
        return -1;
    }
    prog_link = bpf_program__attach_xdp(bpf_prog, ifindex);
    if (libbpf_get_error(prog_link)) {
        LOG_ERROR("bpf_program__attach_xdp failed: %ld", libbpf_get_error(prog_link));
        bpf_link__destroy(prog_link);
        prog_link = NULL;
        return -1;
    }
    return 0;
}

static void detach_xdp(void)
{
    if (prog_link) {
        bpf_link__destroy(prog_link);
        prog_link = NULL;
    }
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

// Function to handle log events
static void handle_log_event(void *ctx, int cpu, void *data, __u32 size)
{
    struct log_entry *entry = data;
    char ip_str[INET_ADDRSTRLEN];
    struct in_addr addr = {.s_addr = entry->ip};
    inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));

    const char *event_str = "Unknown event";
    if (entry->code < sizeof(ddos_event_strings)/sizeof(ddos_event_strings[0])) {
        event_str = ddos_event_strings[entry->code];
    }

    switch (entry->level) {
        case LOG_LEVEL_DEBUG:
            LOG_DEBUG("%s (IP: %s, packets: %llu)", event_str, ip_str, entry->packets);
            break;
        case LOG_LEVEL_INFO:
            LOG_INFO("%s (IP: %s, packets: %llu)", event_str, ip_str, entry->packets);
            break;
        case LOG_LEVEL_WARNING:
            LOG_WARNING("%s (IP: %s, packets: %llu)", event_str, ip_str, entry->packets);
            break;
        case LOG_LEVEL_ERROR:
            LOG_ERROR("%s (IP: %s, packets: %llu)", event_str, ip_str, entry->packets);
            break;
    }
}

// Log reader thread function
static void *log_reader_thread(void *arg)
{
    struct perf_buffer *pb = NULL;
    
    // Create perf buffer with proper callback functions
    pb = perf_buffer__new(log_buffer_fd, 8, handle_log_event, NULL, NULL, NULL);
    if (libbpf_get_error(pb)) {
        LOG_ERROR("Failed to create perf buffer");
        return NULL;
    }

    // Process events
    while (running) {
        int err = perf_buffer__poll(pb, 100);
        if (err < 0 && err != -EINTR) {
            LOG_ERROR("Error polling perf buffer: %d", err);
            break;
        }
    }

    perf_buffer__free(pb);
    return NULL;
}

// Function to cleanup pinned maps
static void cleanup_pinned_maps(void)
{
    const char *map_paths[] = {
        "/sys/fs/bpf/log_buffer",
        "/sys/fs/bpf/ip_traffic_map",
        BLOCKED_IPS_MAP_PATH,
        NULL
    };

    for (int i = 0; map_paths[i] != NULL; i++) {
        if (access(map_paths[i], F_OK) == 0) {
            if (unlink(map_paths[i]) != 0) {
                LOG_WARNING("Failed to unlink pinned map %s: %s", 
                           map_paths[i], strerror(errno));
            } else {
                LOG_INFO("Removed pinned map %s", map_paths[i]);
            }
        }
    }
}

// Function to load and attach the BPF program
static int load_bpf_program(int test_only)
{
    struct bpf_object *obj = NULL;
    struct bpf_program *bpf_prog;
    int err;

    // Cleanup existing pinned maps
    cleanup_pinned_maps();

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

    // Get log buffer map
    struct bpf_map *log_map = bpf_object__find_map_by_name(obj, "log_buffer");
    if (!log_map) {
        LOG_ERROR("Failed to find log buffer map");
        goto cleanup;
    }

    log_buffer_fd = bpf_map__fd(log_map);
    if (log_buffer_fd < 0) {
        LOG_ERROR("Failed to get log buffer fd");
        goto cleanup;
    }

    // Set up perf buffer
    struct perf_event_attr attr = {
        .type = PERF_TYPE_SOFTWARE,
        .size = sizeof(struct perf_event_attr),
        .config = PERF_COUNT_SW_BPF_OUTPUT,
        .sample_type = PERF_SAMPLE_RAW,
        .wakeup_events = 1,
    };

    int perf_fd = syscall(SYS_perf_event_open, &attr, -1, 0, -1, 0);
    if (perf_fd < 0) {
        LOG_ERROR("Failed to create perf event: %s", strerror(errno));
        bpf_object__close(obj);
        return -1;
    }

    if (bpf_map_update_elem(log_buffer_fd, &(int){0}, &perf_fd, BPF_ANY)) {
        LOG_ERROR("Failed to update perf event map: %s", strerror(errno));
        close(perf_fd);
        bpf_object__close(obj);
        return -1;
    }

    // Map the perf buffer
    log_buffer_mmap = mmap(NULL, getpagesize() * 2, PROT_READ | PROT_WRITE, 
                          MAP_SHARED, perf_fd, 0);
    if (log_buffer_mmap == MAP_FAILED) {
        LOG_ERROR("Failed to mmap perf buffer: %s", strerror(errno));
        close(perf_fd);
        bpf_object__close(obj);
        return -1;
    }

    // Create log reader thread
    if (pthread_create(&log_thread, NULL, log_reader_thread, NULL)) {
        LOG_ERROR("Failed to create log reader thread");
        goto cleanup;
    }

    // Pin the blocked IPs map to the filesystem only if it doesn't exist
    struct bpf_map *blocked_map = bpf_object__find_map_by_name(obj, "blocked_ips_map");
    if (!blocked_map) {
        LOG_ERROR("Failed to find blocked IPs map");
        goto cleanup;
    }

    int blocked_map_fd = bpf_map__fd(blocked_map);
    if (blocked_map_fd < 0) {
        LOG_ERROR("Failed to get blocked IPs map fd");
        goto cleanup;
    }

    if (access(BLOCKED_IPS_MAP_PATH, F_OK) != 0) {
        if (bpf_obj_pin(blocked_map_fd, BLOCKED_IPS_MAP_PATH)) {
            LOG_ERROR("Failed to pin blocked IPs map: %s", strerror(errno));
            bpf_object__close(obj);
            return -1;
        }
        LOG_INFO("Blocked IPs map pinned successfully to %s", BLOCKED_IPS_MAP_PATH);
    } else {
        LOG_INFO("Blocked IPs map already exists at %s", BLOCKED_IPS_MAP_PATH);
    }

    if (test_only) {
        LOG_INFO("Test mode: BPF program loaded successfully. Not attaching to interface.");
        bpf_object__close(obj);
        return 0;
    }

    //Attach the XDP program to the specified interface
    LOG_INFO("Attaching to interface: %s", interface);
    if (attach_xdp(bpf_prog, interface, 0) < 0) {
        LOG_ERROR("Failed to attach XDP on %s", interface);
        bpf_object__close(obj);
        return -1;
    }

    return 0;

cleanup:
    bpf_object__close(obj);
    return -1;
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

// Forward declaration of cleanup function
static void cleanup(void);

// Update main function to use cleanup
int main(int argc, char **argv)
{
    int test_mode = 0;
    
    // Initialize logger with INFO level
    if (logger_init() != 0) {
        fprintf(stderr, "Failed to initialize logger\n");
        return EXIT_FAILURE;
    }
    logger_set_level(LOG_LEVEL_INFO);  // Set default log level to INFO
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--test") == 0) {
            test_mode = 1;
        } else if (strcmp(argv[i], "--verbose") == 0) {
            verbose = 1;
            logger_set_verbose(1);
            logger_set_level(LOG_LEVEL_DEBUG);  // Set to DEBUG if verbose mode
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

    // Start log reader thread
    pthread_t log_thread;
    if (pthread_create(&log_thread, NULL, log_reader_thread, NULL) != 0) {
        LOG_ERROR("Failed to create log reader thread: %s", strerror(errno));
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
    pthread_join(log_thread, NULL);

    // Detach XDP before exit
    detach_xdp();

    LOG_INFO("[Main] Exiting.");
    logger_close();

    // Register cleanup handler
    atexit(cleanup);
    return 0;
}

// Cleanup function definition
static void cleanup(void)
{
    running = 0;
    
    // Wait for log thread to finish
    if (log_thread) {
        pthread_join(log_thread, NULL);
    }

    detach_xdp();
    if (log_buffer_mmap) {
        munmap(log_buffer_mmap, getpagesize() * 2);
        log_buffer_mmap = NULL;
    }
    if (map_fd >= 0) {
        close(map_fd);
        map_fd = -1;
    }
    if (prog_fd >= 0) {
        close(prog_fd);
        prog_fd = -1;
    }
}
