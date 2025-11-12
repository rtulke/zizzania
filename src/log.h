/*
 * log.h - Logging level definitions
 *
 * Defines a hierarchical logging system with 5 levels from ERROR to TRACE.
 * Higher levels include all lower levels (e.g., DEBUG includes ERROR+INFO+WARN+DEBUG).
 */

#ifndef ZZ_LOG_H
#define ZZ_LOG_H

/*
 * Log levels (0-4)
 * Each level includes all messages from lower levels.
 */
typedef enum {
    ZZ_LOG_ERROR = 0,  /* Critical errors only (always shown) */
    ZZ_LOG_INFO  = 1,  /* Informational messages (normal operation) */
    ZZ_LOG_WARN  = 2,  /* Warnings (potential issues) */
    ZZ_LOG_DEBUG = 3,  /* Debug information (verbose) */
    ZZ_LOG_TRACE = 4   /* Trace information (very verbose, function calls, packet details) */
} zz_log_level;

/*
 * Command-line verbosity mapping:
 *   (no -v)   → ZZ_LOG_ERROR (0) - errors only
 *   -v        → ZZ_LOG_INFO  (1) - errors + info
 *   -vv       → ZZ_LOG_WARN  (2) - errors + info + warnings
 *   -vvv      → ZZ_LOG_DEBUG (3) - errors + info + warnings + debug
 *   -vvvv     → ZZ_LOG_TRACE (4) - errors + info + warnings + debug + trace
 */

/* Human-readable log level names for output */
static const char *ZZ_LOG_LEVEL_NAMES[] = {
    "ERROR",
    "INFO",
    "WARN",
    "DEBUG",
    "TRACE"
};

#endif
