#ifndef LOGGER_H
#define LOGGER_H

#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdarg.h>

// Log levels
typedef enum {
    LOG_DEBUG = 0,
    LOG_INFO = 1,
    LOG_WARNING = 2,
    LOG_ERROR = 3
} log_level_t;

// Initialize the logger
int logger_init(void);

// Close the logger
void logger_close(void);

// Main logging function
void logger_log(log_level_t level, const char *format, ...);

// Set verbose mode
void logger_set_verbose(int v);

// Set log level
void logger_set_level(log_level_t level);

// Convenience macros
#define LOG_DEBUG(...) logger_log(LOG_DEBUG, __VA_ARGS__)
#define LOG_INFO(...) logger_log(LOG_INFO, __VA_ARGS__)
#define LOG_WARNING(...) logger_log(LOG_WARNING, __VA_ARGS__)
#define LOG_ERROR(...) logger_log(LOG_ERROR, __VA_ARGS__)

#endif // LOGGER_H 