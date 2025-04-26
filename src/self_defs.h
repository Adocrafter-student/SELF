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

#endif // SELF_DEFS_H 