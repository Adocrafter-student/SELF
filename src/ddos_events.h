#ifndef DDOS_EVENTS_H
#define DDOS_EVENTS_H

// Event codes for logging
enum ddos_event_code {
    EV_NEW_IP = 0,        // New IP address detected
    EV_RESET = 1,         // Rate limit reset for IP
    EV_BLOCK = 2,         // IP blocked due to threshold
    EV_UNBLOCK = 3,       // IP unblocked after cooldown
    EV_STATS_UPDATE = 4,  // Traffic statistics update
    EV_ERROR = 5,         // Error condition
    EV_DEBUG = 6,         // Debug information
    EV_MANUAL_BLOCK = 7,  // IP manually blocked
    EV_MAX = 8            // Maximum event code
};

// String mappings for event codes
static const char *ddos_event_strings[] = {
    [EV_NEW_IP] = "[kern] New IP address detected",
    [EV_RESET] = "[kern] Rate limit reset",
    [EV_BLOCK] = "[kern] IP blocked - threshold exceeded",
    [EV_UNBLOCK] = "[kern] IP unblocked - cooldown period ended",
    [EV_STATS_UPDATE] = "[kern] Traffic statistics updated",
    [EV_ERROR] = "[kern] Error occurred",
    [EV_DEBUG] = "[kern] Debug information",
    [EV_MANUAL_BLOCK] = "[kern] IP manually blocked",
    [EV_MAX] = "Unknown event"
};

#endif // DDOS_EVENTS_H 