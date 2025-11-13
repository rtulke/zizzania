/*
 * airsnare.c - Main program entry point
 *
 * Simple main function that orchestrates the program lifecycle:
 * initialize → parse options → start capture → print stats → finalize
 */

#include <stdlib.h>

#include "options.h"
#include "terminal.h"

/*
 * Main program entry point.
 * Follows a simple linear flow with error handling at each stage:
 *   1. Initialize handler structure
 *   2. Parse and validate command-line arguments
 *   3. Start packet capture and processing
 *   4. Print final statistics
 *   5. Clean up and exit
 *
 * Returns:
 *   EXIT_SUCCESS on normal completion, EXIT_FAILURE on any error
 */
int main(int argc, char *argv[]) {
    zz_handler zz;

    /* Initialize the handler to a clean state */
    if (!zz_initialize(&zz)) {
        zz_print_error(&zz);
        return EXIT_FAILURE;
    }

    /* Parse command-line options and configure the handler */
    if (!zz_parse_options(&zz, argc, argv)) {
        zz_print_usage();
        zz_print_error(&zz);
        zz_finalize(&zz);
        return EXIT_FAILURE;
    }

    /* Start packet capture and processing (blocks until complete) */
    if (!zz_start(&zz)) {
        zz_print_error(&zz);
        zz_finalize(&zz);
        return EXIT_FAILURE;
    }

    /* Print final statistics (BSSs found, handshakes captured, etc.) */
    zz_print_stats(&zz);

    /* Clean up resources and close files */
    if (!zz_finalize(&zz)) {
        zz_print_error(&zz);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
