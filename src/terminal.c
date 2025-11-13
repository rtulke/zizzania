/*
 * terminal.c - Terminal output and statistics display
 *
 * Implements functions for printing usage information, error messages,
 * and final statistics to the user. Handles formatting of network
 * information and provides helpful command suggestions for cracking
 * and decryption.
 */

#include <stdio.h>
#include <string.h>

#include "handler.h"
#include "release.h"
#include "terminal.h"

/*
 * Print command-line usage information to stderr.
 * Shows the program version, copyright, all available options with
 * descriptions, and an example command line.
 */
void zz_print_usage(void) {
    #define LN(x) x "\n"
    fprintf(stderr,
            LN("AirSnare v" ZZ_VERSION " - " ZZ_DESCRIPTION)
            LN("Copyright (c) " ZZ_YEAR " " ZZ_AUTHOR)
            LN("")
            LN("Usage:")
            LN("")
            LN("    --config <file>  Load settings from configuration file")
            LN("")
            LN("    airsnare (-r <file> | -i <device> [-M] [-c <channel>] [-q]")
            LN("              (-n | [-d <count>] [-a <count>] [-t <seconds>]))")
            LN("             [-b <match>...] [-B <match>...] [-x b]")
            LN("             [-s <match>...] [-S <match>...] [-x s]")
            LN("             [-2 | -3]")
            LN("             [-w <file> [-g]] [-v]")
            LN("")
            LN("    -r <file>     Read packets from <file> (- for stdin)")
            LN("    -i <device>   Use <device> for both capture and injection")
            LN("    -M            Do not set <devidce> in RFMON mode (useful for airmon-ng)")
            LN("    -c <channel>  Tune the <device> on <channel>")
            LN("    -q            Quit after capturing the first handshake")
            LN("    -n            Passively wait for WPA handshakes")
            LN("    -d <count>    Send groups of <count> deauthentication frames")
            LN("    -a <count>    Perform <count> deauthentications before giving up")
            LN("    -t <seconds>  Time to wait between two deauthentication attempts")
            LN("    -b <match>    Include the given BSSID (<address>[/<mask>])")
            LN("    -B <match>    Exclude the given BSSID (<address>[/<mask>])")
            LN("    -s <match>    Include the given station (<address>[/<mask>])")
            LN("    -S <match>    Exclude the given station (<address>[/<mask>])")
            LN("    -x b|s        First exclude then include BSSIDs (b) or stations (s)")
            LN("    -2            Settle for the first two handshake messages")
            LN("    -3            Settle for the first three handshake messages")
            LN("    -w <file>     Write packets to <file> (- for stdout)")
            LN("    -g            Also dump multicast and broadcast traffic")
            LN("    -v            Print verbose messages to stderr (toggle with SIGUSR1)")
            LN("")
            LN("Example:")
            LN("")
            LN("    airsnare -i wlan0 -c 1 -b ac:1d:1f:1e:dd:ad/ff:ff:ff:00:00:00 -w out.pcap")
            LN(""));
    #undef LN
}

/*
 * Print the error message stored in the handler's error buffer.
 * Uses the zz_err macro which adds a red [!] prefix if outputting to a TTY.
 *
 * Parameters:
 *   zz - Handler containing the error message
 */
void zz_print_error(const zz_handler *zz) {
    zz_err("%s", zz->error_buffer);
}

/*
 * Print final statistics and helpful command suggestions.
 * Displays:
 *   - Packet statistics (received/dropped) from libpcap
 *   - Per-BSS statistics: SSID, handshakes captured, stations, data packets
 *   - Suggested aircrack-ng and airdecap-ng commands for cracking/decryption
 *
 * Parameters:
 *   zz - Handler containing captured data and statistics
 */
void zz_print_stats(zz_handler *zz) {
    struct pcap_stat stats;
    zz_bss *tmp, *bss;
    int n_allowed_ssid;

    /* Print libpcap packet statistics if available */
    if (pcap_stats(zz->pcap, &stats) == 0) {
        zz_out("");
        zz_out("Packet statistics");
        zz_out("  - Received ....... %u", stats.ps_recv);
        zz_out("  - Dropped ........ %u", stats.ps_drop + stats.ps_ifdrop);
        if (zz->killer_pipe_drops > 0) {
            zz_out("  - Killer drops ... %lu", zz->killer_pipe_drops);
        }
    }

    /* Iterate through all discovered BSSs and print statistics for allowed ones */
    n_allowed_ssid = 0;
    HASH_ITER(hh, zz->bsss, bss, tmp) {
        char bssid_str[ZZ_MAC_ADDR_STRING_SIZE];

        /* Skip BSSs that were filtered out by include/exclude rules */
        if (!bss->is_allowed) {
            continue;
        }
        n_allowed_ssid++;

        /* Format BSSID as string for display */
        zz_mac_addr_sprint(bssid_str, bss->bssid);

        /* Print BSS statistics */
        zz_out("");
        zz_out("SSID $'%s' (%-*s)", bss->ssid, ZZ_MAC_COLUMN_WIDTH, bssid_str);
        zz_out("  - Handshakes ..... %ld", bss->n_handshakes);
        zz_out("  - Stations ....... %u", zz_members_count(&bss->stations));
        zz_out("  - Data packets ... %ld", bss->n_data_packets);

        /* If we captured handshakes and have an output file, show crack/decrypt commands */
        if (bss->n_handshakes > 0 && (!zz->setup.is_live || zz->setup.output)) {
            const char *file;

            /* Determine the filename to use in commands */
            file = (zz->setup.output ? zz->setup.output : zz->setup.input);
            file = (strcmp(file, "-") == 0 ? "CAPTURE" : file);

            /* Print aircrack-ng command for password cracking */
            zz_out("  - Crack with ..... aircrack-ng -w 'WORDLIST' -b %s '%s'", bssid_str, file);

            /* Print airdecap-ng command for decrypting traffic with known password */
            zz_out("  - Decrypt with ... airdecap-ng -e $'%s' -b %s -p 'PASSPHRASE' '%s'",
                   bss->ssid, bssid_str, file);
        }
    }

    /* If no BSSs were found or allowed, print a message */
    if (n_allowed_ssid == 0) {
        zz_out("");
        zz_out("No BSS found");
        return;
    }
}
