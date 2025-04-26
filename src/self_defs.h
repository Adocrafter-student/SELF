#ifndef SELF_DEFS_H
#define SELF_DEFS_H

// Score thresholds for banning
#define SCORE_PERMANENT_BAN    90  // Permanent ban
#define SCORE_15_DAYS_BAN     80  // 15 days ban
#define SCORE_4_DAYS_BAN      70  // 4 days ban
#define SCORE_1_DAY_BAN       50  // 1 day ban
#define SCORE_15_MIN_BAN      30  // 15 minutes ban
#define SCORE_1_MIN_BAN       20  // 1 minute ban
#define SCORE_15_SEC_BAN      10  // 15 seconds ban

// Time constants in nanoseconds
#define NANOSEC_PER_SEC       1000000000ULL
#define NANOSEC_PER_MIN       (60ULL * NANOSEC_PER_SEC)
#define NANOSEC_PER_HOUR      (60ULL * NANOSEC_PER_MIN)
#define NANOSEC_PER_DAY       (24ULL * NANOSEC_PER_HOUR)

// Ban durations in nanoseconds
#define BAN_PERMANENT         0ULL
#define BAN_15_DAYS          (15ULL * NANOSEC_PER_DAY)
#define BAN_4_DAYS           (4ULL * NANOSEC_PER_DAY)
#define BAN_1_DAY            (1ULL * NANOSEC_PER_DAY)
#define BAN_15_MIN           (15ULL * NANOSEC_PER_MIN)
#define BAN_1_MIN            (1ULL * NANOSEC_PER_MIN)
#define BAN_15_SEC           (15ULL * NANOSEC_PER_SEC)

// Score increments/decrements
#define SCORE_HALF_OPEN_INC   2   // Score increase for half-open connection
#define SCORE_HANDSHAKE_DEC   5  // Score decrease for successful handshake
#define SCORE_MAX            100  // Maximum possible score

// Flood detection window
#define FLOOD_WINDOW_NS    1000000000ULL      // 1 second in ns

// Generic fallback thresholds
#define PKT_THRESH         300                // ~300 packets/sec
#define BYTES_THRESH       (2 * 1024 * 1024)  // 2 MB/s
#define SCORE_FLOOD_INC    15                 // bump for flood detection

// Protocol-specific thresholds
#define ICMP_PKT_THRESH    100                // ICMP: easier to trigger
#define ICMP_BYTES_THRESH  (256 * 1024)       // 256 KB/s

#define UDP_PKT_THRESH     300                // UDP: slightly higher
#define UDP_BYTES_THRESH   (1 * 1024 * 1024)  // 1 MB/s

#define TCP_PKT_THRESH     1000                // TCP: conservative
#define TCP_BYTES_THRESH   (1 * 1024 * 1024)  // 1 MB/s

#endif // SELF_DEFS_H 