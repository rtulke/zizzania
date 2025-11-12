/*
 * options.h - Command-line option parsing
 *
 * Handles parsing of command-line arguments and populates the
 * zz_handler setup structure with user configuration.
 */

#ifndef ZZ_OPTIONS_H
#define ZZ_OPTIONS_H

#include "handler.h"

/*
 * Print command-line usage information to stderr.
 * Shows all available options with descriptions and examples.
 */
void zz_print_usage(void);

/*
 * Parse command-line arguments and configure the handler.
 * Processes all command-line flags and arguments, validating input
 * and setting up the zz->setup structure accordingly.
 *
 * Parameters:
 *   zz - Handler to configure
 *   argc - Argument count from main()
 *   argv - Argument vector from main()
 *
 * Returns:
 *   1 on success, 0 on failure (invalid arguments, error in zz->error_buffer)
 */
int zz_parse_options(zz_handler *zz, int argc, char *argv[]);

#endif
