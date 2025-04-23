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

// Print messages only in verbose mode
#define verbose_printf(...) do { if (verbose) printf(__VA_ARGS__); } while(0)

/* Attach/detach helpers using the older bpf_set_link_xdp_fd() approach */
static int attach_xdp(int ifindex, int fd, __u32 flags)
{
    int err = bpf_set_link_xdp_fd(ifindex, fd, flags);
    if (err < 0) {
        fprintf(stderr, "attach_xdp: err(%d): %s\n", err, strerror(-err));
    }
    return err;
}

static int detach_xdp(int ifindex, __u32 flags)
{
    int err = bpf_set_link_xdp_fd(ifindex, -1, flags);
    if (err < 0) {
        fprintf(stderr, "detach_xdp: err(%d): %s\n", err, strerror(-err));
    }
    return err;
}

static void signal_handler(int sig)
{
    printf("Received signal %d, stopping...\n", sig);
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

    printf("Opening BPF object file: %s\n", BPF_OBJ_PATH);
    
    // 1) Open the object file
    obj = bpf_object__open_file(BPF_OBJ_PATH, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object file: %s\n", BPF_OBJ_PATH);
        fprintf(stderr, "Error code: %ld\n", libbpf_get_error(obj));
        return -1;
    }

    // 2) Load it into the kernel
    printf("Loading BPF object into kernel...\n");
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %s\n", strerror(-err));
        
        // Check for specific error conditions
        if (err == -EPERM) {
            fprintf(stderr, "Permission denied. Are you running as root?\n");
        }
        
        bpf_object__close(obj);
        return -1;
    }

    // 3) Find our XDP program by name
    bpf_prog = bpf_object__find_program_by_name(obj, "xdp_ddos_protect");
    if (!bpf_prog) {
        fprintf(stderr, "Could not find program 'xdp_ddos_protect'\n");
        bpf_object__close(obj);
        return -1;
    }

    // 4) Grab the FD for the program
    prog_fd = bpf_program__fd(bpf_prog);
    if (prog_fd < 0) {
        fprintf(stderr, "Failed to get program fd\n");
        bpf_object__close(obj);
        return -1;
    }

    // 5) Locate the map "ip_traffic_map"
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "ip_traffic_map");
    if (!map) {
        fprintf(stderr, "Failed to find map 'ip_traffic_map'\n");
        bpf_object__close(obj);
        return -1;
    }
    map_fd = bpf_map__fd(map);
    if (map_fd < 0) {
        fprintf(stderr, "Invalid map fd\n");
        bpf_object__close(obj);
        return -1;
    }
    printf("Map opened successfully, fd: %d\n", map_fd);

    // If we're only testing, stop here
    if (test_only) {
        printf("Test mode: BPF program loaded successfully. Not attaching to interface.\n");
        bpf_object__close(obj);
        return 0;
    }

    // 6) Attach the XDP program to the specified interface
    printf("Attaching to interface: %s\n", interface);
    ifindex = if_nametoindex(interface);
    if (!ifindex) {
        fprintf(stderr, "Failed to get ifindex for interface %s\n", interface);
        fprintf(stderr, "Available interfaces:\n");
        system("ip link show | grep -E '^[0-9]+:' | cut -d' ' -f2 | tr -d ':'");
        bpf_object__close(obj);
        return -1;
    }
    err = attach_xdp(ifindex, prog_fd, 0 /* flags, e.g. XDP_FLAGS_SKB_MODE */);
    if (err < 0) {
        fprintf(stderr, "Failed to attach XDP on %s\n", interface);
        bpf_object__close(obj);
        return -1;
    }

    return 0;
}

// Thread to monitor our BPF map
static void *monitor_traffic(void *arg)
{
    while (running) {
        verbose_printf("[Monitor] Checking traffic statistics...\n");

        if (map_fd < 0) {
            fprintf(stderr, "map_fd is invalid\n");
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

                verbose_printf(" IP: %s, Port: %u, Packets: %llu, Blocked: %llu\n",
                       ip_str, ntohs(next_key.port),
                       (unsigned long long)stats.packet_count,
                       (unsigned long long)stats.blocked);
                count++;
            }
            key = next_key; // proceed iteration
        }

        if (count == 0) {
            verbose_printf(" No traffic entries in the map\n");
        }

        sleep(5);
    }
    return NULL;
}

void print_usage(char *prog_name) {
    printf("Usage: %s [options]\n", prog_name);
    printf("Options:\n");
    printf("  --test             Test if the BPF program can be loaded without attaching it\n");
    printf("  --verbose          Print verbose debug information\n");
    printf("  --interface=<if>   Specify network interface to monitor (default: %s)\n", DEFAULT_INTERFACE);
    printf("  --help             Display this help message\n");
}

int main(int argc, char **argv)
{
    int test_mode = 0;
    
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--test") == 0) {
            test_mode = 1;
        } else if (strcmp(argv[i], "--verbose") == 0) {
            verbose = 1;
        } else if (strncmp(argv[i], "--interface=", 12) == 0) {
            strncpy(interface, argv[i] + 12, IF_NAMESIZE - 1);
            interface[IF_NAMESIZE - 1] = '\0';
        } else if (strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    // Increase memlock limits for eBPF
    struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        perror("setrlimit(RLIMIT_MEMLOCK)");
        fprintf(stderr, "This might prevent the BPF program from loading\n");
        // Continue anyway as it might still work
    }

    // Handle Ctrl+C / SIGTERM
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("[Main] Loading eBPF program...\n");
    if (load_bpf_program(test_mode) != 0) {
        fprintf(stderr, "Error loading BPF program\n");
        return EXIT_FAILURE;
    }
    
    // If in test mode, exit successfully after loading the program
    if (test_mode) {
        printf("Test successful: BPF program loaded.\n");
        return 0;
    }

    // Start monitoring thread
    pthread_t monitor_thread;
    if (pthread_create(&monitor_thread, NULL, monitor_traffic, NULL) != 0) {
        perror("pthread_create");
        return EXIT_FAILURE;
    }

    printf("[Main] eBPF program running on interface %s. Monitoring started.\n", interface);
    if (verbose) {
        printf("Running in verbose mode\n");
    }
    printf("Press Ctrl+C to exit.\n");

    // Wait until user stops
    pthread_join(monitor_thread, NULL);

    // Detach XDP before exit
    int ifindex = if_nametoindex(interface);
    if (ifindex) {
        detach_xdp(ifindex, 0);
    }

    printf("[Main] Exiting.\n");
    return 0;
}
