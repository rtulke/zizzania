/*
 * terminal.h - Terminal output and formatting
 *
 * Provides functions and macros for formatted console output with support
 * for ANSI color codes (when connected to a TTY) and different message types
 * (normal output, errors, verbose logging).
 */

#ifndef ZZ_TERMINAL_H
#define ZZ_TERMINAL_H

#include <stdio.h>

#include "handler.h"

#define ZZ_MAC_COLUMN_WIDTH ZZ_MAC_ADDR_STRING_SIZE

/* Conditionally apply ANSI color codes to a string.
 * If output is to a TTY, wraps the string with color escape sequences.
 * Otherwise, returns the string as-is for non-TTY output (e.g., pipes, files). */
#define ZZ_ANSI(codes, str) \
    (zz->setup.is_tty_output ? "\x1b[" codes "m" str "\x1b[0m" : str)

/* Message prefixes with color coding:
 * OUT - Green [+] for normal output/success messages
 * ERR - Red [!] for error messages
 * LOG - Blue [*] for verbose logging/debug messages */
#define ZZ_OUT_PREFIX ZZ_ANSI("32", "[+]")
#define ZZ_ERR_PREFIX ZZ_ANSI("31", "[!]")
#define ZZ_LOG_PREFIX ZZ_ANSI("34", "[*]")

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

/* Convenience macros for different message types:
 * zz_out - Always prints (success/info messages)
 * zz_err - Always prints (error messages)
 * zz_log - Only prints when verbose mode is enabled */
#define zz_out(format, ...) zz_print(OUT, 1, format, ##__VA_ARGS__)
#define zz_err(format, ...) zz_print(ERR, 1, format, ##__VA_ARGS__)
#define zz_log(format, ...) zz_print(LOG, zz->setup.is_verbose, format, ##__VA_ARGS__)

/* Print command-line usage information */
void zz_print_usage();

/* Print the error message stored in zz->error_buffer */
void zz_print_error(const zz_handler *zz);

/* Print final statistics (BSSs found, handshakes captured, etc.) */
void zz_print_stats(zz_handler *zz);

#endif
