/*
 * terminal.h - Terminal output and formatting
 *
 * Provides functions and macros for formatted console output with support
 * for ANSI color codes (when connected to a TTY) and hierarchical log levels
 * (ERROR, INFO, WARN, DEBUG, TRACE).
 */

#ifndef ZZ_TERMINAL_H
#define ZZ_TERMINAL_H

#include <stdio.h>

#include "handler.h"
#include "log.h"

#define ZZ_MAC_COLUMN_WIDTH ZZ_MAC_ADDR_STRING_SIZE

/* Conditionally apply ANSI color codes to a string.
 * If output is to a TTY, wraps the string with color escape sequences.
 * Otherwise, returns the string as-is for non-TTY output (e.g., pipes, files). */
#define ZZ_ANSI(codes, str) \
    (zz->setup.is_tty_output ? "\x1b[" codes "m" str "\x1b[0m" : str)

/* Message prefixes with color coding for different log levels:
 * ERR   - Red [!] for errors (always shown)
 * INFO  - Green [+] for informational messages
 * WARN  - Yellow [!] for warnings
 * DEBUG - Blue [*] for debug messages
 * TRACE - Cyan [.] for trace/detailed messages */
#define ZZ_ERR_PREFIX   ZZ_ANSI("31", "[!]")
#define ZZ_INFO_PREFIX  ZZ_ANSI("32", "[+]")
#define ZZ_WARN_PREFIX  ZZ_ANSI("33", "[!]")
#define ZZ_DEBUG_PREFIX ZZ_ANSI("34", "[*]")
#define ZZ_TRACE_PREFIX ZZ_ANSI("36", "[.]")

/* Generic print macro that conditionally outputs formatted messages.
 * Uses do-while(0) idiom to create a safe statement block. */
#define zz_print(type, condition, format, ...) \
    do { \
        if (condition) { \
            fprintf(stderr, "%s " format "\n", \
                    ZZ_##type##_PREFIX, \
                    ##__VA_ARGS__); \
        } \
    } while (0)

/* Logging macros for different verbosity levels.
 * Each macro checks if the current log level is high enough to display the message.
 * Higher levels include all lower levels (e.g., DEBUG includes ERROR+INFO+WARN+DEBUG).
 *
 * Usage examples:
 *   zz_err("Failed to open file: %s", filename);     // Always shown
 *   zz_info("Starting packet capture");              // Shown with -v or higher
 *   zz_warn("Interface not in monitor mode");        // Shown with -vv or higher
 *   zz_debug("Processing packet #%d", count);        // Shown with -vvv or higher
 *   zz_trace("Entering function %s", __func__);      // Shown with -vvvv only
 */
#define zz_err(format, ...)   zz_print(ERR,   1, format, ##__VA_ARGS__)
#define zz_info(format, ...)  zz_print(INFO,  (zz->setup.log_level >= ZZ_LOG_INFO),  format, ##__VA_ARGS__)
#define zz_warn(format, ...)  zz_print(WARN,  (zz->setup.log_level >= ZZ_LOG_WARN),  format, ##__VA_ARGS__)
#define zz_debug(format, ...) zz_print(DEBUG, (zz->setup.log_level >= ZZ_LOG_DEBUG), format, ##__VA_ARGS__)
#define zz_trace(format, ...) zz_print(TRACE, (zz->setup.log_level >= ZZ_LOG_TRACE), format, ##__VA_ARGS__)

/* Legacy alias for backward compatibility (zz_out is now zz_info) */
#define zz_out(format, ...) zz_info(format, ##__VA_ARGS__)

/* Legacy alias for backward compatibility (zz_log is now zz_debug) */
#define zz_log(format, ...) zz_debug(format, ##__VA_ARGS__)

/* Print command-line usage information */
void zz_print_usage(void);

/* Print the error message stored in zz->error_buffer */
void zz_print_error(const zz_handler *zz);

/* Print final statistics (BSSs found, handshakes captured, etc.) */
void zz_print_stats(zz_handler *zz);

#endif
