/*
 * config.h - User configuration loading helpers
 *
 * Provides functions to load configuration files that populate the
 * zz_handler setup structure as well as helpers to manage config-owned
 * strings. Configuration files supplement or override command-line
 * options and are applied before parsing argv.
 */

#ifndef ZZ_CONFIG_H
#define ZZ_CONFIG_H

#include "handler.h"

/* Default configuration paths (system-wide first, then user-specific) */
#define ZZ_CONFIG_SYSTEM_PATH "/etc/airsnare.conf"
#define ZZ_CONFIG_USER_PATH   "~/.airsnarerc"

int zz_config_load(zz_handler *zz, const char *path, int optional);
void zz_config_reset_input(zz_handler *zz);
void zz_config_reset_output(zz_handler *zz);

#endif
