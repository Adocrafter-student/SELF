// Licensed under CC BY-NC 4.0 (https://creativecommons.org/licenses/by-nc/4.0/)
// © 2025 Adnan Duharkic — Non-commercial use only
#include "config.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <yaml.h>
#include <time.h>
#include <stdarg.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>

// Helper function to write debug logs to /tmp/yaml_parse.log
static void debug_log(const char *format, ...) {
    FILE *log_file = fopen("/tmp/yaml_parse.log", "a");
    if (!log_file) return;
    
    time_t now = time(NULL);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));
    
    fprintf(log_file, "[%s] ", time_str);
    
    va_list args;
    va_start(args, format);
    vfprintf(log_file, format, args);
    va_end(args);
    
    fprintf(log_file, "\n");
    fclose(log_file);
}

// Helper to assign a value based on the key hierarchy
static void assign_config_value(struct self_config *config, char keys[4][256], int level, const char *value) {
    char *top_level_key = keys[1];
    char *second_level_key = keys[2];
    char *third_level_key = keys[3];

    debug_log("assign_config_value - level: %d, top: '%s', second: '%s', third: '%s', value: '%s'", 
              level, top_level_key, second_level_key, third_level_key, value);

    if (level == 2 && strcmp(top_level_key, "flood_detection") == 0) {
        if (strcmp(second_level_key, "window_ns") == 0) {
            config->flood_window_ns = atoll(value);
            debug_log("SET: flood_window_ns = %llu", config->flood_window_ns);
        }
    } else if (level == 2 && strcmp(top_level_key, "scores") == 0) {
        if (strcmp(second_level_key, "permanent_ban") == 0) {
            config->score_permanent_ban = atoi(value);
            debug_log("SET: score_permanent_ban = %d", config->score_permanent_ban);
        }
        else if (strcmp(second_level_key, "ban_15_days") == 0) {
            config->score_15_days_ban = atoi(value);
            debug_log("SET: score_15_days_ban = %d", config->score_15_days_ban);
        }
        else if (strcmp(second_level_key, "ban_4_days") == 0) {
            config->score_4_days_ban = atoi(value);
            debug_log("SET: score_4_days_ban = %d", config->score_4_days_ban);
        }
        else if (strcmp(second_level_key, "ban_1_day") == 0) {
            config->score_1_day_ban = atoi(value);
            debug_log("SET: score_1_day_ban = %d", config->score_1_day_ban);
        }
        else if (strcmp(second_level_key, "ban_15_min") == 0) {
            config->score_15_min_ban = atoi(value);
            debug_log("SET: score_15_min_ban = %d", config->score_15_min_ban);
        }
        else if (strcmp(second_level_key, "ban_1_min") == 0) {
            config->score_1_min_ban = atoi(value);
            debug_log("SET: score_1_min_ban = %d", config->score_1_min_ban);
        }
        else if (strcmp(second_level_key, "ban_15_sec") == 0) {
            config->score_15_sec_ban = atoi(value);
            debug_log("SET: score_15_sec_ban = %d", config->score_15_sec_ban);
        }
        else if (strcmp(second_level_key, "half_open_inc") == 0) {
            config->score_half_open_inc = atoi(value);
            debug_log("SET: score_half_open_inc = %d", config->score_half_open_inc);
        }
        else if (strcmp(second_level_key, "handshake_dec") == 0) {
            config->score_handshake_dec = atoi(value);
            debug_log("SET: score_handshake_dec = %d", config->score_handshake_dec);
        }
        else if (strcmp(second_level_key, "flood_inc") == 0) {
            config->score_flood_inc = atoi(value);
            debug_log("SET: score_flood_inc = %d", config->score_flood_inc);
        }
        else if (strcmp(second_level_key, "max") == 0) {
            config->score_max = atoi(value);
            debug_log("SET: score_max = %d", config->score_max);
        }
    } else if (level == 2 && strcmp(top_level_key, "statistics") == 0) {
        if (strcmp(second_level_key, "sampling_rate") == 0) {
            config->stats_sampling_rate = atoi(value);
            debug_log("SET: stats_sampling_rate = %d", config->stats_sampling_rate);
        }
    } else if (level == 3 && strcmp(top_level_key, "thresholds") == 0) {
        if (strcmp(third_level_key, "packets") == 0) {
            if (strcmp(second_level_key, "generic") == 0) {
                config->generic_pkt_thresh = atoi(value);
                debug_log("SET: generic_pkt_thresh = %d", config->generic_pkt_thresh);
            }
            else if (strcmp(second_level_key, "icmp") == 0) {
                config->icmp_pkt_thresh = atoi(value);
                debug_log("SET: icmp_pkt_thresh = %d", config->icmp_pkt_thresh);
            }
            else if (strcmp(second_level_key, "udp") == 0) {
                config->udp_pkt_thresh = atoi(value);
                debug_log("SET: udp_pkt_thresh = %d", config->udp_pkt_thresh);
            }
            else if (strcmp(second_level_key, "tcp") == 0) {
                config->tcp_pkt_thresh = atoi(value);
                debug_log("SET: tcp_pkt_thresh = %d", config->tcp_pkt_thresh);
            }
            else if (strcmp(second_level_key, "http") == 0) {
                config->http_pkt_thresh = atoi(value);
                debug_log("SET: http_pkt_thresh = %d", config->http_pkt_thresh);
            }
        } else if (strcmp(third_level_key, "bytes") == 0) {
            if (strcmp(second_level_key, "generic") == 0) {
                config->generic_bytes_thresh = atoi(value);
                debug_log("SET: generic_bytes_thresh = %d", config->generic_bytes_thresh);
            }
            else if (strcmp(second_level_key, "icmp") == 0) {
                config->icmp_bytes_thresh = atoi(value);
                debug_log("SET: icmp_bytes_thresh = %d", config->icmp_bytes_thresh);
            }
            else if (strcmp(second_level_key, "udp") == 0) {
                config->udp_bytes_thresh = atoi(value);
                debug_log("SET: udp_bytes_thresh = %d", config->udp_bytes_thresh);
            }
            else if (strcmp(second_level_key, "tcp") == 0) {
                config->tcp_bytes_thresh = atoi(value);
                debug_log("SET: tcp_bytes_thresh = %d", config->tcp_bytes_thresh);
            }
            else if (strcmp(second_level_key, "http") == 0) {
                config->http_bytes_thresh = atoi(value);
                debug_log("SET: http_bytes_thresh = %d", config->http_bytes_thresh);
            }
        }
    } else {
        debug_log("NO MATCH: level=%d, top='%s', second='%s', third='%s', value='%s'", 
                  level, top_level_key, second_level_key, third_level_key, value);
    }
}

int load_config_from_yaml(const char *filepath, struct self_config *config) {
    debug_log("=== Starting YAML parsing of file: %s ===", filepath);
    
    FILE *fh = fopen(filepath, "r");
    if (!fh) {
        debug_log("ERROR: Could not open config file %s", filepath);
        fprintf(stderr, "Error: Could not open config file %s\n", filepath);
        return -1;
    }

    yaml_parser_t parser;
    yaml_event_t event;
    char key_stack[4][256];
    int level = 0;
    int is_key = 0;
    
    // Initialize key_stack
    memset(key_stack, 0, sizeof(key_stack));
    debug_log("Initialized key_stack and parser");

    yaml_parser_initialize(&parser);
    yaml_parser_set_input_file(&parser, fh);

    do {
        if (!yaml_parser_parse(&parser, &event)) {
            debug_log("ERROR: Failed to parse YAML: %s", parser.problem);
            fprintf(stderr, "Error parsing YAML file: %s\n", parser.problem);
            goto error;
        }

        switch (event.type) {
            case YAML_STREAM_START_EVENT:
                debug_log("EVENT: STREAM_START");
                break;
            case YAML_DOCUMENT_START_EVENT:
                debug_log("EVENT: DOCUMENT_START");
                break;
            case YAML_MAPPING_START_EVENT:
                debug_log("EVENT: MAPPING_START (level: %d -> %d)", level, level + 1);
                level++;
                is_key = 1;
                break;
            case YAML_MAPPING_END_EVENT:
                debug_log("EVENT: MAPPING_END (level: %d -> %d)", level, level - 1);
                level--;
                break;
            case YAML_SEQUENCE_START_EVENT:
                debug_log("EVENT: SEQUENCE_START (level: %d -> %d)", level, level + 1);
                level++;
                is_key = 1;
                break;
            case YAML_SEQUENCE_END_EVENT:
                debug_log("EVENT: SEQUENCE_END (level: %d -> %d)", level, level - 1);
                level--;
                break;
            case YAML_SCALAR_EVENT:
                if (is_key) {
                    strncpy(key_stack[level], (char*)event.data.scalar.value, 255);
                    key_stack[level][255] = '\0';
                    debug_log("EVENT: SCALAR KEY '%s' at level %d (is_key=%d)", 
                             key_stack[level], level, is_key);
                } else {
                    debug_log("EVENT: SCALAR VALUE '%s' at level %d (is_key=%d)", 
                             (char*)event.data.scalar.value, level, is_key);
                    debug_log("KEY_STACK: [1]='%s' [2]='%s' [3]='%s'", 
                             key_stack[1], key_stack[2], key_stack[3]);
                    assign_config_value(config, key_stack, level, (char*)event.data.scalar.value);
                }
                is_key = !is_key;
                break;
            case YAML_STREAM_END_EVENT:
                debug_log("EVENT: STREAM_END");
                goto parsing_complete;
            case YAML_DOCUMENT_END_EVENT:
                debug_log("EVENT: DOCUMENT_END");
                goto parsing_complete;
                break;
            default:
                debug_log("EVENT: UNKNOWN type %d", event.type);
                goto parsing_complete;
                break;
        }

        yaml_event_delete(&event);

    } while (1);

parsing_complete:
    yaml_parser_delete(&parser);
    fclose(fh);
    debug_log("=== YAML parsing completed successfully ===");
    
    // Log final configuration values
    debug_log("FINAL CONFIG VALUES:");
    debug_log("  score_permanent_ban: %d", config->score_permanent_ban);
    debug_log("  score_15_days_ban: %d", config->score_15_days_ban);
    debug_log("  score_4_days_ban: %d", config->score_4_days_ban);
    debug_log("  score_1_day_ban: %d", config->score_1_day_ban);
    debug_log("  score_15_min_ban: %d", config->score_15_min_ban);
    debug_log("  score_1_min_ban: %d", config->score_1_min_ban);
    debug_log("  score_15_sec_ban: %d", config->score_15_sec_ban);
    debug_log("  score_half_open_inc: %d", config->score_half_open_inc);
    debug_log("  score_handshake_dec: %d", config->score_handshake_dec);
    debug_log("  score_flood_inc: %d", config->score_flood_inc);
    debug_log("  score_max: %d", config->score_max);
    debug_log("  flood_window_ns: %llu", config->flood_window_ns);
    debug_log("  stats_sampling_rate: %d", config->stats_sampling_rate);
    debug_log("  generic_pkt_thresh: %d", config->generic_pkt_thresh);
    debug_log("  generic_bytes_thresh: %d", config->generic_bytes_thresh);
    debug_log("  icmp_pkt_thresh: %d", config->icmp_pkt_thresh);
    debug_log("  icmp_bytes_thresh: %d", config->icmp_bytes_thresh);
    debug_log("  udp_pkt_thresh: %d", config->udp_pkt_thresh);
    debug_log("  udp_bytes_thresh: %d", config->udp_bytes_thresh);
    debug_log("  tcp_pkt_thresh: %d", config->tcp_pkt_thresh);
    debug_log("  tcp_bytes_thresh: %d", config->tcp_bytes_thresh);
    debug_log("  http_pkt_thresh: %d", config->http_pkt_thresh);
    debug_log("  http_bytes_thresh: %d", config->http_bytes_thresh);
    
    return 0;

error:
    debug_log("=== YAML parsing failed ===");
    yaml_parser_delete(&parser);
    fclose(fh);
    return -1;
}

int load_whitelist(int map_fd, const char *filepath) {
    FILE *f = fopen(filepath, "r");
    if (!f) {
        // It's not a critical error if the whitelist file doesn't exist.
        fprintf(stderr, "Info: whitelist file %s not found, skipping.\n", filepath);
        return 0;
    }

    char line[256];
    int count = 0;
    while (fgets(line, sizeof(line), f)) {
        // remove newline
        line[strcspn(line, "\n")] = 0;
        
        if (strlen(line) == 0 || line[0] == '#') {
            continue; // Skip empty lines and comments
        }

        struct in_addr addr;
        if (inet_pton(AF_INET, line, &addr) != 1) {
            fprintf(stderr, "Warning: invalid IP address in whitelist: %s\n", line);
            continue;
        }

        __u32 ip_val = addr.s_addr;
        __u8 whitelisted = 1;

        if (bpf_map_update_elem(map_fd, &ip_val, &whitelisted, BPF_ANY) != 0) {
            fprintf(stderr, "Warning: failed to add IP to whitelist map: %s\n", line);
        } else {
            count++;
        }
    }

    printf("Loaded %d IPs into the whitelist.\n", count);
    fclose(f);
    return 0;
} 