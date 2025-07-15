// Licensed under CC BY-NC 4.0 (https://creativecommons.org/licenses/by-nc/4.0/)
// © 2025 Adnan Duharkic — Non-commercial use only
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

// XDP flags if not already defined
#ifndef XDP_FLAGS_SKB_MODE
#define XDP_FLAGS_SKB_MODE (1U << 1)
#endif
#include <sys/mman.h>
#include <sys/syscall.h>
#include "ddos_events.h"
#include <sys/stat.h>
#include <fcntl.h>
#include "config.h"
#include "bpf_shared_config.h"

// Log levels
#define LOG_LEVEL_DEBUG   0
#define LOG_LEVEL_INFO    1
#define LOG_LEVEL_WARNING 2
#define LOG_LEVEL_ERROR   3

#define BPF_OBJ_PATH "/usr/lib/self/ddos_protect.o"
#define DEFAULT_INTERFACE "eth0"
#define BLOCKED_IPS_MAP_PATH "/sys/fs/bpf/blocked_ips_map"
#define IP_SYN_COUNT_MAP_PATH "/sys/fs/bpf/ip_syn_count_map"
#define ESTABLISHED_MAP_PATH "/sys/fs/bpf/established_map"
#define SCORE_MAP_PATH "/sys/fs/bpf/score_map"
#define FLOOD_STATS_MAP_PATH "/sys/fs/bpf/flood_stats_map"
#define SELF_CONFIG_MAP_PATH "/sys/fs/bpf/self_config_map"
#define IP_STATS_MAP_PATH "/sys/fs/bpf/ip_stats_map"
#define GLOBAL_STATS_MAP_PATH "/sys/fs/bpf/global_stats_map"
#define WHITELIST_MAP_PATH "/sys/fs/bpf/whitelist_map"
#define WHITELIST_CONF_PATH "/etc/self/whitelist.conf"

// Value for the map
struct traffic_stats {
    __u64 passed_packets;
    __u64 passed_bytes;
    __u64 blocked_packets;
    __u64 blocked_bytes;
};

// Log entry structure
struct log_entry {
    __u32 level;
    __u32 ip;
    __u64 packets;
    __u8 code;      // Event code from ddos_event_code enum
    __u64 timestamp;
};

// Structure for flood statistics
struct flood_stats {
    __u64 pkt_count;
    __u64 byte_count;
    __u64 last_ts;   // nanoseconds of last reset
};

// Globals
int map_fd   = -1;
int prog_fd  = -1;
volatile int running = 1;
int verbose = 0;
char interface[IF_NAMESIZE] = DEFAULT_INTERFACE;
static int log_buffer_fd = -1;
static void *log_buffer_mmap = NULL;

// Global link handle and attachment info
static struct bpf_link *prog_link = NULL;
static int attached_ifindex = -1;
static int attached_prog_fd = -1;
static bool using_generic_xdp = false;

// Global variables for log handling
static pthread_t log_thread;

// New attach/detach helpers using the link API with generic XDP fallback
static int attach_xdp(struct bpf_program *bpf_prog, const char *ifname, __u32 flags)
{
    int ifindex = if_nametoindex(ifname);
    if (ifindex <= 0) {
        LOG_ERROR("if_nametoindex(%s) failed", ifname);
        return -1;
    }
    
    // Try native XDP first
    prog_link = bpf_program__attach_xdp(bpf_prog, ifindex);
    if (libbpf_get_error(prog_link)) {
        long err = libbpf_get_error(prog_link);
        LOG_WARNING("Native XDP attach failed: %ld, trying generic XDP", err);
        bpf_link__destroy(prog_link);
        prog_link = NULL;
        
        // Try generic XDP mode as fallback
        int prog_fd = bpf_program__fd(bpf_prog);
        if (prog_fd < 0) {
            LOG_ERROR("Failed to get program fd for generic XDP");
            return -1;
        }
        
                 int ret = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL);
         if (ret < 0) {
             LOG_ERROR("Generic XDP attach also failed: %d", ret);
             return -1;
         }
         
         // Store info for generic XDP cleanup
         attached_ifindex = ifindex;
         attached_prog_fd = prog_fd;
         using_generic_xdp = true;
         
         LOG_INFO("Successfully attached using generic XDP mode");
         return 0;
    }
    
    LOG_INFO("Successfully attached using native XDP mode");
    return 0;
}

static void detach_xdp(void)
{
    if (prog_link) {
        bpf_link__destroy(prog_link);
        prog_link = NULL;
    } else if (using_generic_xdp && attached_ifindex >= 0) {
        // Detach generic XDP
        int ret = bpf_xdp_detach(attached_ifindex, XDP_FLAGS_SKB_MODE, NULL);
        if (ret < 0) {
            LOG_ERROR("Failed to detach generic XDP: %d", ret);
        } else {
            LOG_INFO("Successfully detached generic XDP");
        }
        attached_ifindex = -1;
        attached_prog_fd = -1;
        using_generic_xdp = false;
    }
}

static int update_bpf_config_map(struct bpf_object *bpf_obj, const struct self_config *config)
{
    struct bpf_map *map = bpf_object__find_map_by_name(bpf_obj, "self_config_map");
    if (!map) {
        LOG_ERROR("Failed to find 'self_config_map' in BPF object");
        return -1;
    }

    struct bpf_config bpf_cfg = {
        .score_permanent_ban = config->score_permanent_ban,
        .score_15_days_ban = config->score_15_days_ban,
        .score_4_days_ban = config->score_4_days_ban,
        .score_1_day_ban = config->score_1_day_ban,
        .score_15_min_ban = config->score_15_min_ban,
        .score_1_min_ban = config->score_1_min_ban,
        .score_15_sec_ban = config->score_15_sec_ban,
        .score_half_open_inc = config->score_half_open_inc,
        .score_handshake_dec = config->score_handshake_dec,
        .score_flood_inc = config->score_flood_inc,
        .score_max = config->score_max,
        .flood_window_ns = config->flood_window_ns,
        .generic_pkt_thresh = config->generic_pkt_thresh,
        .generic_bytes_thresh = config->generic_bytes_thresh,
        .icmp_pkt_thresh = config->icmp_pkt_thresh,
        .icmp_bytes_thresh = config->icmp_bytes_thresh,
        .udp_pkt_thresh = config->udp_pkt_thresh,
        .udp_bytes_thresh = config->udp_bytes_thresh,
        .tcp_pkt_thresh = config->tcp_pkt_thresh,
        .tcp_bytes_thresh = config->tcp_bytes_thresh,
        .http_pkt_thresh = config->http_pkt_thresh,
        .http_bytes_thresh = config->http_bytes_thresh,
        .stats_sampling_rate = config->stats_sampling_rate,
    };

    __u32 key = 0;
    int err = bpf_map_update_elem(bpf_map__fd(map), &key, &bpf_cfg, BPF_ANY);
    if (err) {
        LOG_ERROR("Failed to update 'self_config_map': %s", strerror(errno));
        return -1;
    }

    LOG_INFO("BPF config map updated successfully.");
    return 0;
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
    } else {
        LOG_WARNING("Received unknown event code: %u", entry->code);
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
        IP_STATS_MAP_PATH,
        GLOBAL_STATS_MAP_PATH,
        BLOCKED_IPS_MAP_PATH,
        IP_SYN_COUNT_MAP_PATH,
        ESTABLISHED_MAP_PATH,
        SCORE_MAP_PATH,
        FLOOD_STATS_MAP_PATH,
        SELF_CONFIG_MAP_PATH,
        WHITELIST_MAP_PATH,
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

// Helper for pinning BPF maps
static int pin_bpf_map(struct bpf_object *obj, const char *map_name, const char *pin_path) {
    struct bpf_map *map = bpf_object__find_map_by_name(obj, map_name);
    if (!map) {
        LOG_ERROR("Failed to find map '%s'", map_name);
        return -1;
    }
    int fd = bpf_map__fd(map);
    if (fd < 0) {
        LOG_ERROR("Invalid fd for map '%s'", map_name);
        return -1;
    }
    if (access(pin_path, F_OK) != 0) {
        if (bpf_obj_pin(fd, pin_path)) {
            LOG_ERROR("Failed to pin map '%s': %s", map_name, strerror(errno));
            return -1;
        }
        LOG_INFO("%s pinned successfully to %s", map_name, pin_path);
    } else {
        LOG_INFO("%s already exists at %s", map_name, pin_path);
    }

    if (strcmp(map_name, "ip_stats_map") == 0) {
        map_fd = fd;
        LOG_INFO("ip_stats_map fd is %d", map_fd);
    }

    return 0;
}

// Function to load and attach the BPF program
static int load_bpf_program(int test_only, const struct self_config *config)
{
    struct bpf_object *obj = NULL;
    struct bpf_program *bpf_prog;
    int err;

    // Cleanup existing pinned maps - REMOVED TO ALLOW PERSISTENCE
    // cleanup_pinned_maps();

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

    if (update_bpf_config_map(obj, config) != 0) {
        LOG_ERROR("Failed to update BPF config map");
        goto cleanup;
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

    // Pin all relevant maps using the helper
    if (pin_bpf_map(obj, "ip_stats_map", IP_STATS_MAP_PATH) < 0) goto cleanup;
    if (pin_bpf_map(obj, "global_stats_map", GLOBAL_STATS_MAP_PATH) < 0) goto cleanup;
    if (pin_bpf_map(obj, "log_buffer", "/sys/fs/bpf/log_buffer") < 0) goto cleanup;
    if (pin_bpf_map(obj, "blocked_ips_map", BLOCKED_IPS_MAP_PATH) < 0) goto cleanup;
    if (pin_bpf_map(obj, "ip_syn_count_map", IP_SYN_COUNT_MAP_PATH) < 0) goto cleanup;
    if (pin_bpf_map(obj, "established_map", ESTABLISHED_MAP_PATH) < 0) goto cleanup;
    if (pin_bpf_map(obj, "score_map", SCORE_MAP_PATH) < 0) goto cleanup;
    if (pin_bpf_map(obj, "flood_stats_map", FLOOD_STATS_MAP_PATH) < 0) goto cleanup;
    if (pin_bpf_map(obj, "self_config_map", SELF_CONFIG_MAP_PATH) < 0) goto cleanup;
    if (pin_bpf_map(obj, "whitelist_map", WHITELIST_MAP_PATH) < 0) goto cleanup;

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

    // Attach the XDP program to the specified interface
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
    struct self_config config;
    
    // Initialize logger with INFO level
    if (logger_init() != 0) {
        fprintf(stderr, "Failed to initialize logger\n");
        return EXIT_FAILURE;
    }
    logger_set_level(LOG_LEVEL_INFO);  // Set default log level to INFO
    
    // Load config from YAML
    if (load_config_from_yaml("/etc/self/self_metric.yaml", &config) != 0) {
        LOG_ERROR("Failed to load configuration from YAML. Exiting.");
        return EXIT_FAILURE;
    }

    LOG_INFO("Configuration loaded successfully:");
    LOG_INFO("  Score for permanent ban: %d", config.score_permanent_ban);
    LOG_INFO("  TCP packet threshold: %d", config.tcp_pkt_thresh);


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
    if (load_bpf_program(test_mode, &config) != 0) {
        LOG_ERROR("Error loading BPF program");
        logger_close();
        return EXIT_FAILURE;
    }
    
    LOG_INFO("[Main] Loading whitelist...");
    int whitelist_map_fd = bpf_obj_get(WHITELIST_MAP_PATH);
    if (whitelist_map_fd < 0) {
        LOG_ERROR("Failed to get whitelist map FD, whitelist will not be loaded.");
    } else {
        if (load_whitelist(whitelist_map_fd, WHITELIST_CONF_PATH) != 0) {
            LOG_ERROR("Error loading whitelist.");
        }
        close(whitelist_map_fd);
    }

    // If in test mode, exit successfully after loading the program
    if (test_mode) {
        LOG_INFO("Test successful: BPF program loaded.");
        logger_close();
        return 0;
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
