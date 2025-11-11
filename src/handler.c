/*
 * handler.c - Main handler lifecycle and initialization
 *
 * Implements the three main lifecycle functions (initialize, start, finalize)
 * and manages pcap setup, BPF filtering, packet dumping, and the main capture
 * loop. This is the orchestration layer that ties together all subsystems.
 */

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#include "dispatcher.h"
#include "dissector.h"
#include "handler.h"
#include "iface.h"
#include "terminal.h"
#include "util.h"

/* Snapshot length (capture size limit):
 * - MIN_SNAPLEN for live capture without output (just tracking handshakes)
 * - MAX_SNAPLEN when saving to file (capture everything) */
#define MIN_SNAPLEN 256
#define MAX_SNAPLEN 65535

/* BPF filter to capture only relevant frames:
 * - Data frames (for client activity tracking)
 * - QoS data frames (newer standard)
 * - Beacon frames (for SSID extraction) */
#define BPF "wlan[0] == " ZZ_STRING(ZZ_FCF_DATA) \
        " || wlan[0] == " ZZ_STRING(ZZ_FCF_QOS_DATA) \
        " || wlan[0] == " ZZ_STRING(ZZ_FCF_BEACON)

/*
 * Create and configure the pcap handle for packet capture.
 * Handles both live capture (from network interface) and file reading.
 * For live capture, sets up monitor mode, promiscuous mode, and channel.
 *
 * Parameters:
 *   zz - Handler to configure
 *
 * Returns:
 *   1 on success, 0 on failure (error in zz->error_buffer)
 */
static int create_pcap(zz_handler *zz) {
    char pcap_error_buffer[PCAP_ERRBUF_SIZE];

    /* Live capture from network interface */
    if (zz->setup.is_live) {
        /* Create pcap handle (not yet activated) */
        *pcap_error_buffer = '\0';
        zz->pcap = pcap_create(zz->setup.input, pcap_error_buffer);

        /* Log any warnings (pcap_create can succeed with warnings) */
        if (zz->pcap && *pcap_error_buffer) {
            zz_log("WARNING: %s", pcap_error_buffer);
        }

        /* Configure capture parameters before activation */
        if (zz->pcap) {
            int snaplen;

            /* Set snapshot length based on whether we're saving output */
            snaplen = zz->setup.output ? MAX_SNAPLEN : MIN_SNAPLEN;

            /* Configure pcap options and activate:
             * - snaplen: maximum bytes to capture per packet
             * - promisc: promiscuous mode (capture all traffic)
             * - rfmon: monitor mode (unless disabled with -M) */
            if (pcap_set_snaplen(zz->pcap, snaplen) != 0 ||
                pcap_set_promisc(zz->pcap, 1) != 0 ||
                (!zz->setup.no_rfmon && pcap_set_rfmon(zz->pcap, 1)) ||
                pcap_activate(zz->pcap)) {
                zz_error(zz, "libpcap: %s", pcap_geterr(zz->pcap));
                return 0;
            }

            /* Set wireless channel if specified */
            if (zz->setup.is_live && zz->setup.channel > 0) {
                zz_log("Setting '%s' to channel %d", zz->setup.input, zz->setup.channel);
                if (!zz_set_channel(zz)) {
                    zz_error(zz, "Cannot set '%s' to channel %d: %s",
                             zz->setup.input, zz->setup.channel, strerror(errno));
                    return 0;
                }
            }
        }
    }
    /* File-based capture from pcap file */
    else {
        zz->pcap = pcap_open_offline(zz->setup.input, pcap_error_buffer);
        zz->setup.is_passive = 1;  /* Force passive mode for file input */
    }

    /* Check if pcap handle was successfully created */
    if (!zz->pcap) {
        zz_error(zz, "libpcap: %s", pcap_error_buffer);
        return 0;
    }

    return 1;
}

/*
 * Verify that the interface is in monitor mode.
 * Monitor mode (RFMON) is required to capture raw 802.11 frames.
 * Checks the data link type to ensure it's DLT_IEEE802_11_RADIO.
 *
 * Parameters:
 *   zz - Handler with pcap handle
 *
 * Returns:
 *   1 if monitor mode is active, 0 otherwise
 */
static int check_monitor(zz_handler *zz) {
    int dlt;

    /* Skip check for file input */
    if (!zz->setup.is_live) {
        return 1;
    }

    /* Get and log the data link type */
    dlt = pcap_datalink(zz->pcap);
    zz_log("Datalink type '%s'", pcap_datalink_val_to_name(dlt));

    /* Verify it's the expected type (802.11 with radiotap headers) */
    if (dlt != DLT_IEEE802_11_RADIO) {
        const char *expected_dlt;

        expected_dlt = pcap_datalink_val_to_name(DLT_IEEE802_11_RADIO);
        zz_error(zz, "Wrong device type/mode '%s'; '%s' expected",
                 pcap_datalink_val_to_name(dlt), expected_dlt);
        return 0;
    }

    return 1;
}

/*
 * Set BPF (Berkeley Packet Filter) on the pcap handle.
 * The BPF pre-filters packets in kernel space to only pass data,
 * QoS data, and beacon frames, significantly reducing processing overhead.
 *
 * Parameters:
 *   zz - Handler with pcap handle
 *
 * Returns:
 *   1 on success, 0 on failure
 */
static int set_bpf(zz_handler *zz) {
    struct bpf_program fp;

    /* Compile the BPF filter expression */
    if (pcap_compile(zz->pcap, &fp, BPF, 1, -1) != 0) {
        zz_error(zz, "libpcap: %s", pcap_geterr(zz->pcap));
        return 0;
    }

    /* Install the compiled filter */
    if (pcap_setfilter(zz->pcap, &fp) != 0) {
        zz_error(zz, "libpcap: %s", pcap_geterr(zz->pcap));
        return 0;
    }

    /* Free the compiled filter (it's been installed) */
    pcap_freecode(&fp);
    return 1;
}

/*
 * Open the output pcap dumper for writing captured packets.
 * If an output file is specified, opens it for writing filtered packets.
 *
 * Parameters:
 *   zz - Handler with output filename
 *
 * Returns:
 *   1 on success, 0 on failure
 */
static int open_dumper(zz_handler *zz) {
    if (zz->setup.output) {
        zz_log("Dumping packets to '%s'", zz->setup.output);

        /* Open the output pcap file */
        zz->dumper = pcap_dump_open(zz->pcap, zz->setup.output);
        if (!zz->dumper) {
            zz_error(zz, "libpcap: %s", pcap_geterr(zz->pcap));
            return 0;
        }
    }

    return 1;
}

/*
 * Main packet capture loop.
 * Starts the dispatcher thread (which handles deauth attacks and signals),
 * then runs the pcap packet loop until completion or interruption.
 *
 * Parameters:
 *   zz - Handler with all subsystems initialized
 *
 * Returns:
 *   1 on success, 0 on error
 */
static int packet_loop(zz_handler *zz) {
    pthread_t dispatcher;
    int error;
    int dispatcher_return;

    /* Start the dispatcher thread (handles periodic killer invocation) */
    if (!zz_dispatcher_start(zz, &dispatcher)) {
        return 0;
    }

    /* Print status message */
    if (zz->setup.is_live) {
        zz_out("Waiting for traffic, press Ctrl-C to exit...");
    } else {
        zz_out("Parsing '%s'", zz->setup.input);
    }

    /* Run the main packet capture loop.
     * This blocks until:
     * - EOF (file input)
     * - User interruption (Ctrl-C)
     * - Error
     * - zz->is_done is set (e.g., early quit after handshake) */
    error = 0;
    switch (pcap_loop(zz->pcap, -1, zz_dissect_packet, (u_char *)zz)) {
    case 0: /* End of file */
        zz_log("EOF for '%s'", zz->setup.input);
        break;

    case -1: /* Error */
        zz_error(zz, "libpcap: %s", pcap_geterr(zz->pcap));
        error = 1;
        break;

    case -2: /* User termination (pcap_breakloop called) */
        break;
    }

    /* Signal shutdown to dispatcher */
    zz_out("Terminating...");
    zz->is_done = 1;

    /* Wait for dispatcher thread to complete */
    if (pthread_join(dispatcher, (void *)&dispatcher_return) != 0) {
        zz_error(zz, "Cannot join the dispatcher");
        return 0;
    }

    return !error && dispatcher_return;
}

/*
 * Initialize the handler to a clean state.
 * Zeroes all fields, initializes data structures, and sets default values
 * for configuration options.
 *
 * Parameters:
 *   zz - Handler to initialize
 *
 * Returns:
 *   Always returns 1 (success)
 */
int zz_initialize(zz_handler *zz) {
    /* Zero all fields */
    memset(zz, 0, sizeof(zz_handler));

    /* Initialize filter sets */
    zz_members_new(&zz->setup.included_bssids);
    zz_members_new(&zz->setup.excluded_bssids);
    zz_members_new(&zz->setup.included_stations);
    zz_members_new(&zz->setup.excluded_stations);

    /* Initialize tracking structures */
    zz_bsss_new(&zz->bsss);
    zz_clients_new(&zz->clients);

    /* Detect TTY for ANSI color output */
    zz->setup.is_tty_output = isatty(2); /* stderr */

    /* Set default configuration values */

    /* Require full 4-way handshake by default */
    zz->setup.max_handshake = 4;

    /* Send one deauth frame at a time by default */
    zz->setup.n_deauths = 1;

    /* Killer timing defaults */
    zz->setup.killer_max_attempts = 10;  /* Try up to 10 times */
    zz->setup.killer_interval = 5;       /* 5 seconds between attempts */

    return 1;
}

static void reset_tracking_state(zz_handler *zz) {
    zz_members_free(&zz->setup.included_bssids);
    zz_members_new(&zz->setup.included_bssids);

    zz_members_free(&zz->setup.excluded_bssids);
    zz_members_new(&zz->setup.excluded_bssids);

    zz_members_free(&zz->setup.included_stations);
    zz_members_new(&zz->setup.included_stations);

    zz_members_free(&zz->setup.excluded_stations);
    zz_members_new(&zz->setup.excluded_stations);

    zz_bsss_free(zz, &zz->bsss);
    zz_bsss_new(&zz->bsss);

    zz_clients_free(zz, &zz->clients);
    zz_clients_new(&zz->clients);
}

/*
 * Start packet capture and processing.
 * This is the main entry point that orchestrates:
 *   1. Creating pcap handle
 *   2. Dropping root privileges
 *   3. Verifying monitor mode
 *   4. Setting BPF filter
 *   5. Opening output dumper
 *   6. Running packet loop
 *
 * Each step must succeed for the next to proceed.
 *
 * Parameters:
 *   zz - Initialized handler with configuration
 *
 * Returns:
 *   1 on success, 0 on any failure
 */
int zz_start(zz_handler *zz) {
    int killer_started = 0;

    if (!create_pcap(zz)) {
        goto fail;
    }

    if (!zz_drop_root(zz)) {
        goto fail;
    }

    if (!check_monitor(zz)) {
        goto fail;
    }

    if (!set_bpf(zz)) {
        goto fail;
    }

    if (!open_dumper(zz)) {
        goto fail;
    }

    if (zz->setup.is_live && !zz->setup.is_passive && !zz->killer_initialized) {
        if (!zz_killer_new(zz, &zz->killer)) {
            goto fail;
        }
        zz->killer_initialized = 1;
        killer_started = 1;
    }

    if (!packet_loop(zz)) {
        goto fail;
    }

    return 1;

fail:
    if (zz->dumper) {
        pcap_dump_close(zz->dumper);
        zz->dumper = NULL;
    }
    if (killer_started) {
        zz_killer_free(zz, &zz->killer);
        zz->killer_initialized = 0;
    }
    if (zz->pcap) {
        pcap_close(zz->pcap);
        zz->pcap = NULL;
    }

    reset_tracking_state(zz);

    return 0;
}

/*
 * Clean up and finalize the handler.
 * Closes files, frees memory, and releases all resources.
 *
 * Parameters:
 *   zz - Handler to finalize
 *
 * Returns:
 *   Always returns 1 (success)
 */
int zz_finalize(zz_handler *zz) {
    /* Close output pcap file if open */
    if (zz->dumper) {
        zz_log("Closing packet dump '%s'", zz->setup.output);
        pcap_dump_close(zz->dumper);
        zz->dumper = NULL;
    }

    /* Free all filter sets */
    zz_members_free(&zz->setup.included_bssids);
    zz_members_new(&zz->setup.included_bssids);

    zz_members_free(&zz->setup.excluded_bssids);
    zz_members_new(&zz->setup.excluded_bssids);

    zz_members_free(&zz->setup.included_stations);
    zz_members_new(&zz->setup.included_stations);

    zz_members_free(&zz->setup.excluded_stations);
    zz_members_new(&zz->setup.excluded_stations);

    /* Free tracking structures */
    zz_bsss_free(zz, &zz->bsss);
    zz_bsss_new(&zz->bsss);
    zz_bsss_pool_destroy(zz);

    zz_clients_free(zz, &zz->clients);
    zz_clients_new(&zz->clients);
    zz_clients_pool_destroy(zz);

    /* Free killer subsystem if it was initialized */
    if (zz->killer_initialized) {
        zz_killer_free(zz, &zz->killer);
        zz->killer_initialized = 0;
    }

    /* Close pcap handle */
    if (zz->pcap) {
        pcap_close(zz->pcap);
        zz->pcap = NULL;
    }

    return 1;
}

/*
 * Record an error message in the handler's error buffer.
 * Uses printf-style formatting for flexible error messages.
 *
 * Parameters:
 *   zz - Handler to store error in
 *   format - Printf-style format string
 *   ... - Format arguments
 *
 * Returns:
 *   Always returns 0 for convenient use in error paths:
 *   `return zz_error(zz, "message");`
 */
int zz_error(zz_handler *zz, const char *format, ...) {
    int chk;
    va_list ap;

    /* Format the error message into the buffer */
    va_start(ap, format);
    chk = vsnprintf(zz->error_buffer, ZZ_ERROR_BUFFER_SIZE, format, ap);
    va_end(ap);

    /* Return 0 for convenient error handling */
    return chk > 0 && chk < ZZ_ERROR_BUFFER_SIZE;
}
