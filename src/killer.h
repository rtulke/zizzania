/*
 * killer.h - Deauthentication attack subsystem
 *
 * Manages the injection of IEEE 802.11 deauthentication frames to force
 * clients to reassociate, thereby triggering WPA handshakes. Maintains
 * a queue of targets, handles retry logic, and communicates with the
 * packet dissector via a pipe.
 */

#ifndef ZZ_KILLER_H
#define ZZ_KILLER_H

#include <pthread.h>

#include "ieee802.h"

struct zz_handler;

/* Forward declaration - full definition in killer.c */
struct zz_target;
struct zz_target_pool_chunk;

#define ZZ_TARGET_POOL_CHUNK 64

typedef struct zz_target_pool {
    struct zz_target *free_list;
    struct zz_target_pool_chunk *chunks;
} zz_target_pool;

/*
 * Killer subsystem state
 * Manages deauthentication attack targets and inter-thread communication.
 */
typedef struct {
    struct zz_target *targets;  /* Hash table of clients targeted for deauth */
    int pipe[2];                /* Pipe for communication from dissector to killer */
    pthread_mutex_t pipe_lock;  /* Guards pipe writes */
    zz_target_pool target_pool; /* Memory pool for target entries */
} zz_killer;

/*
 * Initialize a new killer subsystem.
 * Sets up the pipe and initializes the target hash table.
 *
 * Parameters:
 *   zz - Handler used for error reporting
 *   killer - Killer structure to initialize
 */
int zz_killer_new(struct zz_handler *zz, zz_killer *killer);

/*
 * Clean up and free killer resources.
 * Closes pipe, frees all targets from the hash table.
 *
 * Parameters:
 *   zz - Handler used for logging
 *   killer - Killer structure to free
 */
void zz_killer_free(struct zz_handler *zz, zz_killer *killer);

/*
 * Drain pending messages and send scheduled deauthentication frames.
 *
 * Parameters:
 *   zz - Handler with runtime configuration
 *   killer - Killer subsystem
 *
 * Returns:
 *   1 on success, 0 on failure (error stored via zz_error)
 */
int zz_killer_run(struct zz_handler *zz, zz_killer *killer);

#endif
