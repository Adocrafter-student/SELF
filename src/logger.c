#include "logger.h"
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

#define LOG_FILE "/var/log/self.log"
#define LOG_BUFFER_SIZE 1024

static FILE *log_file = NULL;
static int verbose = 0;
static log_level_t current_level = LOG_INFO;  // Default log level

static const char* level_to_string(log_level_t level) {
    switch (level) {
        case LOG_DEBUG:   return "DEBUG";
        case LOG_INFO:    return "INFO";
        case LOG_WARNING: return "WARNING";
        case LOG_ERROR:   return "ERROR";
        default:          return "UNKNOWN";
    }
}

int logger_init(void) {
    int fd = open(LOG_FILE, O_CREAT | O_WRONLY | O_APPEND, 0644);
    if (fd == -1) {
        fprintf(stderr, "Failed to open log file: %s\n", strerror(errno));
        return -1;
    }
    close(fd);

    log_file = fopen(LOG_FILE, "a");
    if (!log_file) {
        fprintf(stderr, "Failed to open log file for writing: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

void logger_close(void) {
    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
}

void logger_log(log_level_t level, const char *format, ...) {
    if (!log_file) return;
    
    // Skip logging if level is below current level
    if (level < current_level) return;

    char buffer[LOG_BUFFER_SIZE];
    time_t now;
    struct tm *timeinfo;
    va_list args;

    time(&now);
    timeinfo = localtime(&now);

    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo);
    
    fprintf(log_file, "[%s] [%s] ", buffer, level_to_string(level));

    va_start(args, format);
    vfprintf(log_file, format, args);
    va_end(args);

    fprintf(log_file, "\n");
    fflush(log_file);

    if (verbose) {
        if (level == LOG_ERROR || level == LOG_WARNING) {
            va_start(args, format);
            vfprintf(stderr, format, args);
            va_end(args);
            fprintf(stderr, "\n");
        } else {
            va_start(args, format);
            vfprintf(stdout, format, args);
            va_end(args);
            fprintf(stdout, "\n");
        }
    }
}

void logger_set_verbose(int v) {
    verbose = v;
}

void logger_set_level(log_level_t level) {
    current_level = level;
} 