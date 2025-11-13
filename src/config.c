/*
 * config.c - User configuration file loader
 *
 * Supports parsing simple key=value files that configure AirSnare before
 * command-line arguments are processed. Later configuration sources
 * override earlier ones (system → user → explicit --config → CLI).
 */

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#include "config.h"
#include "ieee802.h"
#include "log.h"
#include "members.h"

/* Forward declarations */
static int apply_entry(zz_handler *zz, const char *source, unsigned line,
                       const char *key, const char *value);

static char *trim(char *s) {
    char *start = s;
    char *end;

    while (*start && isspace((unsigned char)*start)) {
        start++;
    }

    end = start + strlen(start);
    while (end > start && isspace((unsigned char)*(end - 1))) {
        end--;
    }
    *end = '\0';
    return start;
}

static void strip_inline_comment(char *s) {
    int in_single = 0;
    int in_double = 0;

    for (char *p = s; *p; ++p) {
        if (*p == '\'' && !in_double) {
            in_single = !in_single;
            continue;
        }
        if (*p == '"' && !in_single) {
            in_double = !in_double;
            continue;
        }
        if (!in_single && !in_double && (*p == '#' || *p == ';')) {
            *p = '\0';
            break;
        }
    }
}

static char *unquote(char *value) {
    size_t len = strlen(value);
    if (len >= 2) {
        char quote = value[0];
        if ((quote == '"' || quote == '\'') && value[len - 1] == quote) {
            value[len - 1] = '\0';
            return value + 1;
        }
    }
    return value;
}

void zz_config_reset_input(zz_handler *zz) {
    if (zz->config_input_owned) {
        free(zz->config_input_owned);
        zz->config_input_owned = NULL;
    }
    zz->setup.input = NULL;
}

void zz_config_reset_output(zz_handler *zz) {
    if (zz->config_output_owned) {
        free(zz->config_output_owned);
        zz->config_output_owned = NULL;
    }
    zz->setup.output = NULL;
}

static int set_owned_string(zz_handler *zz, const char *value,
                            char **owned_slot, char **target,
                            const char *source, unsigned line) {
    char *dup = strdup(value);
    if (!dup) {
        zz_error(zz, "%s:%u: Cannot allocate memory for option", source, line);
        return 0;
    }

    if (*owned_slot) {
        free(*owned_slot);
    }
    *owned_slot = dup;
    *target = dup;
    return 1;
}

static int expand_path(zz_handler *zz, const char *value, char *buffer,
                       size_t size, const char *source, unsigned line) {
    if (!value || !*value) {
        zz_error(zz, "%s:%u: Empty path", source, line);
        return 0;
    }

    if (value[0] == '~') {
        const char *home = getenv("HOME");
        if (!home) {
            zz_error(zz, "%s:%u: Cannot expand '~', HOME not set", source, line);
            return 0;
        }
        if (snprintf(buffer, size, "%s%s", home, value + 1) >= (int)size) {
            zz_error(zz, "%s:%u: Expanded path is too long", source, line);
            return 0;
        }
    } else {
        if (strlen(value) >= size) {
            zz_error(zz, "%s:%u: Path '%s' is too long", source, line, value);
            return 0;
        }
        strcpy(buffer, value);
    }

    return 1;
}

static int parse_bool(zz_handler *zz, const char *source, unsigned line,
                      const char *key, const char *value, int *out) {
    if (strcasecmp(value, "1") == 0 ||
        strcasecmp(value, "true") == 0 ||
        strcasecmp(value, "yes") == 0 ||
        strcasecmp(value, "on") == 0) {
        *out = 1;
        return 1;
    }

    if (strcasecmp(value, "0") == 0 ||
        strcasecmp(value, "false") == 0 ||
        strcasecmp(value, "no") == 0 ||
        strcasecmp(value, "off") == 0) {
        *out = 0;
        return 1;
    }

    zz_error(zz, "%s:%u: Invalid boolean for '%s': '%s'",
             source, line, key, value);
    return 0;
}

static int parse_int_option(zz_handler *zz, const char *source, unsigned line,
                            const char *key, const char *value,
                            int min, int max, int *out) {
    long tmp;
    char *end = NULL;

    errno = 0;
    tmp = strtol(value, &end, 10);
    if (errno == ERANGE || end == value) {
        zz_error(zz, "%s:%u: Invalid integer for '%s': '%s'",
                 source, line, key, value);
        return 0;
    }
    while (*end && isspace((unsigned char)*end)) {
        end++;
    }
    if (*end != '\0' || tmp < min || tmp > max) {
        zz_error(zz, "%s:%u: Value '%s' for '%s' must be between %d and %d",
                 source, line, value, key, min, max);
        return 0;
    }

    *out = (int)tmp;
    return 1;
}

static int add_mac_filter(zz_handler *zz, char option,
                          const char *argument,
                          const char *source, unsigned line) {
    zz_mac_addr mac_addr;
    zz_mac_addr mac_mask;
    zz_members *members;
    const char *mask_ptr;

    if (!zz_mac_addr_sscan(&mac_addr, argument, "/")) {
        zz_error(zz, "%s:%u: Invalid MAC address '%s'",
                 source, line, argument);
        return 0;
    }

    mask_ptr = strchr(argument, '/');
    if (mask_ptr) {
        if (!zz_mac_addr_sscan(&mac_mask, mask_ptr + 1, "")) {
            zz_error(zz, "%s:%u: Invalid MAC mask '%s'",
                     source, line, mask_ptr + 1);
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
        zz_error(zz, "%s:%u: Unknown MAC filter selector '%c'",
                 source, line, option);
        return 0;
    }

    if (zz_members_put_mask(members, mac_addr, mac_mask) == -1) {
        zz_error(zz, "%s:%u: Cannot store MAC filter '%s': %s",
                 source, line, argument, strerror(errno));
        return 0;
    }

    return 1;
}

static int add_mac_list(zz_handler *zz, char option, const char *value,
                        const char *source, unsigned line) {
    int result = 1;
    char *work = strdup(value);
    if (!work) {
        zz_error(zz, "%s:%u: Cannot allocate memory while parsing '%s'",
                 source, line, value);
        return 0;
    }

    char *cursor = work;
    char *token;
    while ((token = strsep(&cursor, ",")) != NULL) {
        char *item = trim(token);
        if (*item == '\0') {
            continue;
        }
        if (!add_mac_filter(zz, option, item, source, line)) {
            result = 0;
            break;
        }
    }

    free(work);
    return result;
}

static int set_interface(zz_handler *zz, const char *value,
                         const char *source, unsigned line) {
    if (!set_owned_string(zz, value,
                          &zz->config_input_owned, &zz->setup.input,
                          source, line)) {
        return 0;
    }
    zz->setup.is_live = 1;
    return 1;
}

static int set_pcap_input(zz_handler *zz, const char *value,
                          const char *source, unsigned line) {
    char expanded[PATH_MAX];
    if (!expand_path(zz, value, expanded, sizeof(expanded), source, line)) {
        return 0;
    }
    if (!set_owned_string(zz, expanded,
                          &zz->config_input_owned, &zz->setup.input,
                          source, line)) {
        return 0;
    }
    zz->setup.is_live = 0;
    return 1;
}

static int set_output_path(zz_handler *zz, const char *value,
                           const char *source, unsigned line) {
    char expanded[PATH_MAX];
    if (!expand_path(zz, value, expanded, sizeof(expanded), source, line)) {
        return 0;
    }
    return set_owned_string(zz, expanded,
                            &zz->config_output_owned, &zz->setup.output,
                            source, line);
}

static int set_log_level(zz_handler *zz, const char *source, unsigned line,
                         const char *value) {
    int level = -1;

    if (strcasecmp(value, "error") == 0) level = ZZ_LOG_ERROR;
    else if (strcasecmp(value, "info") == 0) level = ZZ_LOG_INFO;
    else if (strcasecmp(value, "warn") == 0 ||
             strcasecmp(value, "warning") == 0) level = ZZ_LOG_WARN;
    else if (strcasecmp(value, "debug") == 0) level = ZZ_LOG_DEBUG;
    else if (strcasecmp(value, "trace") == 0) level = ZZ_LOG_TRACE;
    else {
        char *end = NULL;
        long tmp;

        errno = 0;
        tmp = strtol(value, &end, 10);
        if (errno == 0 && end != value && *end == '\0' &&
            tmp >= ZZ_LOG_ERROR && tmp <= ZZ_LOG_TRACE) {
            level = (int)tmp;
        }
    }

    if (level == -1) {
        zz_error(zz, "%s:%u: Invalid log level '%s'", source, line, value);
        return 0;
    }

    zz->setup.log_level = (unsigned)level;
    return 1;
}

static int apply_entry(zz_handler *zz, const char *source, unsigned line,
                       const char *key, const char *value) {
    if (strcmp(key, "interface") == 0 ||
        strcmp(key, "input") == 0 ||
        strcmp(key, "live_interface") == 0) {
        return set_interface(zz, value, source, line);
    }

    if (strcmp(key, "pcap") == 0 ||
        strcmp(key, "input_file") == 0 ||
        strcmp(key, "read_file") == 0) {
        return set_pcap_input(zz, value, source, line);
    }

    if (strcmp(key, "output") == 0 ||
        strcmp(key, "write_file") == 0) {
        return set_output_path(zz, value, source, line);
    }

    if (strcmp(key, "channel") == 0) {
        return parse_int_option(zz, source, line, key, value, 1, INT_MAX,
                                &zz->setup.channel);
    }

    if (strcmp(key, "passive") == 0) {
        int flag;
        if (!parse_bool(zz, source, line, key, value, &flag)) {
            return 0;
        }
        zz->setup.is_passive = flag;
        return 1;
    }

    if (strcmp(key, "no_rfmon") == 0) {
        int flag;
        if (!parse_bool(zz, source, line, key, value, &flag)) {
            return 0;
        }
        zz->setup.no_rfmon = flag;
        return 1;
    }

    if (strcmp(key, "deauth_count") == 0) {
        return parse_int_option(zz, source, line, key, value, 1, INT_MAX,
                                &zz->setup.n_deauths);
    }

    if (strcmp(key, "deauth_attempts") == 0) {
        return parse_int_option(zz, source, line, key, value, 1, INT_MAX,
                                &zz->setup.killer_max_attempts);
    }

    if (strcmp(key, "deauth_interval") == 0) {
        return parse_int_option(zz, source, line, key, value, 1, INT_MAX,
                                &zz->setup.killer_interval);
    }

    if (strcmp(key, "max_handshake") == 0) {
        return parse_int_option(zz, source, line, key, value, 2, 4,
                                &zz->setup.max_handshake);
    }

    if (strcmp(key, "dump_group_traffic") == 0 ||
        strcmp(key, "dump_multicast") == 0) {
        int flag;
        if (!parse_bool(zz, source, line, key, value, &flag)) {
            return 0;
        }
        zz->setup.dump_group_traffic = flag;
        return 1;
    }

    if (strcmp(key, "early_quit") == 0) {
        int flag;
        if (!parse_bool(zz, source, line, key, value, &flag)) {
            return 0;
        }
        zz->setup.early_quit = flag;
        return 1;
    }

    if (strcmp(key, "log_level") == 0) {
        return set_log_level(zz, source, line, value);
    }

    if (strcmp(key, "bssid_include") == 0 ||
        strcmp(key, "include_bssid") == 0) {
        return add_mac_list(zz, 'b', value, source, line);
    }

    if (strcmp(key, "bssid_exclude") == 0 ||
        strcmp(key, "exclude_bssid") == 0) {
        return add_mac_list(zz, 'B', value, source, line);
    }

    if (strcmp(key, "station_include") == 0 ||
        strcmp(key, "include_station") == 0) {
        return add_mac_list(zz, 's', value, source, line);
    }

    if (strcmp(key, "station_exclude") == 0 ||
        strcmp(key, "exclude_station") == 0) {
        return add_mac_list(zz, 'S', value, source, line);
    }

    if (strcmp(key, "bssid_exclude_first") == 0) {
        int flag;
        if (!parse_bool(zz, source, line, key, value, &flag)) {
            return 0;
        }
        zz->setup.bssids_exclude_first = flag;
        return 1;
    }

    if (strcmp(key, "station_exclude_first") == 0) {
        int flag;
        if (!parse_bool(zz, source, line, key, value, &flag)) {
            return 0;
        }
        zz->setup.stations_exclude_first = flag;
        return 1;
    }

    zz_error(zz, "%s:%u: Unknown configuration key '%s'",
             source, line, key);
    return 0;
}

int zz_config_load(zz_handler *zz, const char *path, int optional) {
    FILE *fp;
    char resolved[PATH_MAX];
    char *line = NULL;
    size_t linecap = 0;
    ssize_t linelen;
    unsigned lineno = 0;
    int status = 1;

    if (!path) {
        return 1;
    }

    if (!expand_path(zz, path, resolved, sizeof(resolved), path, 0)) {
        return optional ? 1 : 0;
    }

    fp = fopen(resolved, "r");
    if (!fp) {
        if (optional && errno == ENOENT) {
            return 1;
        }
        zz_error(zz, "Cannot open config '%s': %s",
                 resolved, strerror(errno));
        return 0;
    }

    while ((linelen = getline(&line, &linecap, fp)) != -1) {
        char *key;
        char *value;

        lineno++;
        (void)linelen;

        key = trim(line);
        if (*key == '\0' || *key == '#' || *key == ';') {
            continue;
        }

        char *eq = strchr(key, '=');
        if (!eq) {
            zz_error(zz, "%s:%u: Missing '='", resolved, lineno);
            status = 0;
            break;
        }

        *eq = '\0';
        value = trim(eq + 1);
        strip_inline_comment(value);
        value = trim(value);
        value = unquote(value);

        key = trim(key);
        for (char *p = key; *p; ++p) {
            *p = tolower((unsigned char)*p);
        }

        if (*value == '\0' &&
            (strcmp(key, "interface") == 0 || strcmp(key, "pcap") == 0 ||
             strcmp(key, "input") == 0 || strcmp(key, "input_file") == 0)) {
            zz_error(zz, "%s:%u: Empty value for '%s'", resolved, lineno, key);
            status = 0;
            break;
        }

        if (!apply_entry(zz, resolved, lineno, key, value)) {
            status = 0;
            break;
        }
    }

    free(line);
    fclose(fp);
    return status;
}
