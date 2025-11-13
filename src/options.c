/*
 * options.c - Command-line option parsing and validation
 *
 * Parses command-line arguments using getopt, validates option combinations,
 * and populates the zz_handler setup structure with user configuration.
 * Performs extensive validation to catch incompatible option combinations.
 */

#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "handler.h"
#include "log.h"

enum {
    OPT_CONFIG = 1000
};

/*
 * Parse a string as a natural number (positive integer).
 * Helper function for parsing numeric command-line arguments.
 *
 * Parameters:
 *   string - String to parse
 *   value - Output integer value
 *
 * Returns:
 *   1 on success, 0 on parse error (not a number, negative, overflow)
 */
static int parse_natural(const char *string, int *value) {
    long int tmp;
    char *chk = NULL;

    /* Attempt conversion from string to long */
    errno = 0;
    tmp = strtol(string, &chk, 10);

    /* Validate: no overflow, positive, fits in int */
    if (errno == ERANGE || tmp <= 0 || tmp > INT_MAX) {
        return 0;
    } else {
        *value = tmp;
        return 1;
    }
}

static int parse_mac_filter_option(zz_handler *zz, int option, const char *argument) {
    const char *mask_ptr;
    zz_mac_addr mac_addr;
    zz_mac_addr mac_mask;
    zz_members *members;

    if (!zz_mac_addr_sscan(&mac_addr, argument, "/")) {
        zz_error(zz, "Invalid MAC address '%s'", argument);
        return 0;
    }

    mask_ptr = strchr(argument, '/');
    if (mask_ptr) {
        if (!zz_mac_addr_sscan(&mac_mask, mask_ptr + 1, "")) {
            zz_error(zz, "Invalid MAC address mask '%s'", mask_ptr + 1);
            return 0;
        }
    } else {
        mac_mask = -1;
    }

    switch (option) {
    case 'b': members = &zz->setup.included_bssids; break;
    case 'B': members = &zz->setup.excluded_bssids; break;
    case 's': members = &zz->setup.included_stations; break;
    case 'S': members = &zz->setup.excluded_stations; break;
    default:
        zz_error(zz, "Unknown MAC filter option -%c", option);
        return 0;
    }

    if (zz_members_put_mask(members, mac_addr, mac_mask) == -1) {
        zz_error(zz, "Cannot store MAC filter '%s': %s",
                 argument, strerror(errno));
        return 0;
    }

    return 1;
}

/*
 * Parse command-line arguments and configure the handler.
 * Uses getopt to process options, validates all combinations, and sets up
 * the zz->setup structure accordingly.
 *
 * Option categories:
 *   Input:   -r (file) or -i (interface)
 *   Output:  -w (pcap file), -g (include broadcast/multicast)
 *   Channel: -c (channel number), -M (no RFMON setup)
 *   Attack:  -n (passive), -d (deauth count), -a (attempts), -t (interval)
 *   Filter:  -b/-B (BSSID include/exclude), -s/-S (station include/exclude), -x (order)
 *   Capture: -2/-3 (partial handshake), -q (early quit)
 *   Output:  -v (verbose)
 *
 * Parameters:
 *   zz - Handler to configure
 *   argc - Argument count from main()
 *   argv - Argument vector from main()
 *
 * Returns:
 *   1 on success, 0 on error (with error message in zz->error_buffer)
 */
int zz_parse_options(zz_handler *zz, int argc, char *argv[]) {
    int opt;
    int cli_inputs = 0;        /* Count of CLI input specifications */
    int cli_outputs = 0;       /* Count of CLI output specifications */
    int max_handshake_2 = 0;   /* Flag for -2 option */
    int max_handshake_3 = 0;   /* Flag for -3 option */
    static const struct option long_options[] = {
        { "config", required_argument, NULL, OPT_CONFIG },
        { 0, 0, 0, 0 }
    };

    /* Disable getopt's built-in error messages - we handle them ourselves */
    opterr = 0;

    /* Apply default configuration files (system first, then user) */
    if (!zz_config_load(zz, ZZ_CONFIG_SYSTEM_PATH, 1)) {
        return 0;
    }
    if (!zz_config_load(zz, ZZ_CONFIG_USER_PATH, 1)) {
        return 0;
    }

    /* Parse all options */
    while ((opt = getopt_long(argc, argv,
                              ":i:Mc:nd:a:t:r:b:B:s:S:x:w:23gqv",
                              long_options, NULL)) != -1) {
        switch (opt) {

        case OPT_CONFIG: /* Load explicit configuration file */
            if (!zz_config_load(zz, optarg, 0)) {
                return 0;
            }
            break;

        case 'i':  /* Live capture from interface */
        case 'r':  /* Read from pcap file */
            cli_inputs++;
            zz_config_reset_input(zz);
            zz->setup.input = optarg;
            zz->setup.is_live = (opt == 'i');
            break;

        case 'M':  /* Don't set monitor (RFMON) mode */
            zz->setup.no_rfmon = 1;
            break;

        case 'c':  /* Set wireless channel */
            if (!parse_natural(optarg, &zz->setup.channel)) {
                zz_error(zz, "Invalid channel '%s'", optarg);
                return 0;
            }
            break;

        case 'n':  /* Passive mode (no deauth attacks) */
            zz->setup.is_passive = 1;
            break;

        case 'd':  /* Number of deauth frames per burst */
            if (!parse_natural(optarg, &zz->setup.n_deauths)) {
                zz_error(zz, "Invalid deauthentication count '%s'", optarg);
                return 0;
            }
            break;

        case 'a':  /* Maximum deauth attempts before giving up */
            if (!parse_natural(optarg, &zz->setup.killer_max_attempts)) {
                zz_error(zz, "Invalid max deauthentication attempts '%s'", optarg);
                return 0;
            }
            break;

        case 't':  /* Time between deauth attempts (seconds) */
            if (!parse_natural(optarg, &zz->setup.killer_interval)) {
                zz_error(zz, "Invalid deauthentication interval '%s'", optarg);
                return 0;
            }
            break;

        case 'b':  /* Include BSSID (whitelist) */
        case 'B':  /* Exclude BSSID (blacklist) */
        case 's':  /* Include station (whitelist) */
        case 'S':  /* Exclude station (blacklist) */
            if (!parse_mac_filter_option(zz, opt, optarg)) {
                return 0;
            }
            break;

        case 'x':  /* Filter application order */
            if (strcmp(optarg, "b") == 0) {
                zz->setup.bssids_exclude_first = 1;  /* Apply BSSID exclude before include */
            } else if (strcmp(optarg, "s") == 0) {
                zz->setup.stations_exclude_first = 1;  /* Apply station exclude before include */
            } else {
                zz_error(zz, "Invalid argument '%s' for option -%c", optarg, optopt);
                return 0;
            }
            break;

        case 'w':  /* Write output to pcap file */
            zz->setup.output = optarg;
            cli_outputs++;
            break;

        case '2':  /* Capture only first 2 handshake messages (enough for unicast) */
            zz->setup.max_handshake = 2;
            max_handshake_2 = 1;
            break;

        case '3':  /* Capture first 3 handshake messages */
            zz->setup.max_handshake = 3;
            max_handshake_3 = 1;
            break;

        case 'g':  /* Dump broadcast/multicast group traffic */
            zz->setup.dump_group_traffic = 1;
            break;

        case 'q':  /* Quit after first complete handshake */
            zz->setup.early_quit = 1;
            break;

        case 'v':  /* Increase verbosity level */
            /* Each -v increases log level: -v → INFO, -vv → WARN, -vvv → DEBUG, -vvvv → TRACE */
            if (zz->setup.log_level < ZZ_LOG_TRACE) {
                zz->setup.log_level++;
            }
            break;

        case '?':  /* Unknown option */
            zz_error(zz, "Unknown option -%c", optopt);
            return 0;

        default:   /* Option missing required argument */
            zz_error(zz, "Option -%c requires an argument", optopt);
            return 0;
        }
    }

    /* Validation phase: check for missing/conflicting options */

    /* Must specify at least one input source (config or CLI) */
    if (!zz->setup.input) {
        zz_error(zz, "No input specified, use either -r or -i");
        return 0;
    }
    if (cli_inputs > 1) {
        zz_error(zz, "Multiple inputs specified");
        return 0;
    }

    /* Can specify at most one output file */
    if (cli_outputs > 1) {
        zz_error(zz, "Multiple outputs specified");
        return 0;
    }

    /* Check for unparsed arguments */
    if (optind != argc) {
        zz_error(zz, "Unparsed option '%s'", argv[optind]);
        return 0;
    }

    /* Live-only options can't be used with file input (-r) */
    const int custom_n_deauths =
        (zz->setup.n_deauths != ZZ_DEFAULT_N_DEAUTHS);
    const int custom_killer_attempts =
        (zz->setup.killer_max_attempts != ZZ_DEFAULT_KILLER_ATTEMPTS);
    const int custom_killer_interval =
        (zz->setup.killer_interval != ZZ_DEFAULT_KILLER_INTERVAL);
    const int attack_options =
        custom_n_deauths || custom_killer_attempts || custom_killer_interval;

    if (!zz->setup.is_live &&
        (zz->setup.no_rfmon || zz->setup.channel > 0 || zz->setup.is_passive ||
         attack_options)) {
        zz_error(zz, "Options -M, -c, -n, -d, -a, -t require live capture (-i); cannot use with -r");
        return 0;
    }

    /* Attack-related options conflict with passive mode */
    if (zz->setup.is_passive && attack_options) {
        zz_error(zz, "Options -d, -a, -t (deauth attacks) conflict with -n (passive mode)");
        return 0;
    }

    /* Early quit only makes sense for live capture */
    if (!zz->setup.is_live && zz->setup.early_quit) {
        zz_error(zz, "Option -q (early quit) requires live capture; use -i instead of -r");
        return 0;
    }

    /* Group traffic dump option requires output file */
    if (zz->setup.dump_group_traffic && !zz->setup.output) {
        zz_error(zz, "Option -g (dump group traffic) requires output file; add -w <file>");
        return 0;
    }

    /* Can't specify both -2 and -3 */
    if (max_handshake_2 && max_handshake_3) {
        zz_error(zz, "Cannot use both -2 and -3; choose one handshake capture mode");
        return 0;
    }

    return 1;  /* All validations passed */
}
