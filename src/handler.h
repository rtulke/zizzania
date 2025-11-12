/*
 * handler.h - Central state management
 *
 * Defines the main zz_handler structure that contains all program state
 * including configuration, pcap handles, tracked networks and clients,
 * and the deauthentication attack subsystem. This is the "god object"
 * passed to most functions throughout the codebase.
 */

#ifndef ZZ_HANDLER_H
#define ZZ_HANDLER_H

#include <pcap/pcap.h>

#include "clients.h"
#include "killer.h"
#include "members.h"
#include "bsss.h"

/* Size of error message buffer (includes space for pcap errors) */
#define ZZ_ERROR_BUFFER_SIZE (1024 + PCAP_ERRBUF_SIZE)

/*
 * Main handler structure - contains all program state
 * This structure is passed to virtually all functions and contains:
 *   - User configuration (setup)
 *   - Packet capture handles (pcap, dumper)
 *   - Tracked networks and clients (bsss, clients)
 *   - Deauthentication attack state (killer)
 *   - Error reporting (error_buffer)
 */
typedef struct zz_handler {
    /* Configuration and command-line options */
    struct {
        char *input;                      /* Input file path (NULL for live capture) */
        char *output;                     /* Output pcap file path */
        unsigned is_live:1;               /* Capturing from live interface vs file */
        unsigned is_passive:1;            /* Passive mode: no deauth attacks */
        unsigned log_level:3;             /* Logging verbosity level (0=ERROR, 1=INFO, 2=WARN, 3=DEBUG, 4=TRACE) */
        unsigned is_tty_output:1;         /* Output is to a TTY (enables colors) */
        unsigned no_rfmon:1;              /* Don't set monitor mode (already set) */
        unsigned dump_group_traffic:1;    /* Include broadcast/multicast traffic in output */
        unsigned early_quit:1;            /* Quit after first complete handshake */
        unsigned bssids_exclude_first:1;  /* Apply BSSID exclude filter before include */
        unsigned stations_exclude_first:1;/* Apply station exclude filter before include */
        int channel;                      /* Wi-Fi channel to monitor (-1 for current) */
        int n_deauths;                    /* Number of deauth frames per burst */
        int killer_max_attempts;          /* Max deauth attempts before giving up */
        int killer_interval;              /* Interval between deauth bursts (seconds) */
        int max_handshake;                /* Max handshake message number to capture (1-4) */
        zz_members included_bssids;       /* BSSIDs to include (whitelist) */
        zz_members excluded_bssids;       /* BSSIDs to exclude (blacklist) */
        zz_members included_stations;     /* Stations to include (whitelist) */
        zz_members excluded_stations;     /* Stations to exclude (blacklist) */
    } setup;

    double epoch;  /* Timestamp of first packet (used for relative time display) */

    pcap_t *pcap;          /* libpcap handle for packet capture */
    pcap_dumper_t *dumper; /* libpcap handle for writing output pcap */

    zz_bsss bsss;       /* Hash table of tracked access points (BSSs) */
    zz_clients clients; /* Hash table of tracked client stations */
    zz_bss_pool bss_pool;     /* Memory pool for BSS records */
    zz_client_pool client_pool; /* Memory pool for client records */
    zz_killer killer;   /* Deauthentication attack subsystem */
    unsigned long killer_pipe_drops; /* Number of killer pipe messages dropped (EAGAIN) */

    unsigned killer_initialized:1; /* Killer subsystem successfully initialized */
    unsigned is_done:1; /* Flag to signal shutdown */

    char error_buffer[ZZ_ERROR_BUFFER_SIZE]; /* Error message storage */
} zz_handler;

/*
 * Initialize the handler structure to a clean state.
 * Must be called before using any other handler functions.
 *
 * Parameters:
 *   zz - Handler to initialize
 *
 * Returns:
 *   1 on success, 0 on failure
 */
int zz_initialize(zz_handler *zz);

/*
 * Start packet capture and processing.
 * Opens the capture interface or file, starts the dispatcher thread,
 * and begins the main packet processing loop.
 *
 * Parameters:
 *   zz - Initialized handler with configuration set
 *
 * Returns:
 *   1 on success, 0 on failure (error message in zz->error_buffer)
 */
int zz_start(zz_handler *zz);

/*
 * Clean up and finalize the handler.
 * Closes pcap handles, frees memory, writes final statistics.
 *
 * Parameters:
 *   zz - Handler to finalize
 *
 * Returns:
 *   1 on success, 0 on failure
 */
int zz_finalize(zz_handler *zz);

/*
 * Record an error message in the handler's error buffer.
 * Uses printf-style formatting.
 *
 * Parameters:
 *   zz - Handler to store error in
 *   format - Printf-style format string
 *   ... - Format arguments
 *
 * Returns:
 *   Always returns 0 (for convenient return from calling functions)
 */
int zz_error(zz_handler *zz, const char *format, ...);

#endif
