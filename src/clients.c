/*
 * clients.c - Client station tracking
 *
 * Implements a hash table of client stations indexed by (station, bssid) tuple.
 * Each client entry tracks handshake state, replay counters, and EAPOL headers
 * needed for WPA/WPA2 handshake capture.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "handler.h"
#include "clients.h"

#define ZZ_CLIENT_POOL_CHUNK 64

struct zz_client_pool_chunk {
    zz_client nodes[ZZ_CLIENT_POOL_CHUNK];
    struct zz_client_pool_chunk *next;
};

static int client_pool_grow(zz_handler *zz) {
    struct zz_client_pool_chunk *chunk = malloc(sizeof(*chunk));
    size_t i;

    if (!chunk) {
        zz_error(zz, "Cannot grow client pool: %s", strerror(errno));
        return 0;
    }

    chunk->next = zz->client_pool.chunks;
    zz->client_pool.chunks = chunk;

    for (i = 0; i < ZZ_CLIENT_POOL_CHUNK; i++) {
        chunk->nodes[i].next_free = zz->client_pool.free_list;
        zz->client_pool.free_list = &chunk->nodes[i];
    }

    return 1;
}

static zz_client *client_pool_acquire(zz_handler *zz) {
    if (!zz->client_pool.free_list) {
        if (!client_pool_grow(zz)) {
            return NULL;
        }
    }

    zz_client *client = zz->client_pool.free_list;
    zz->client_pool.free_list = client->next_free;
    memset(client, 0, sizeof(*client));
    return client;
}

static void client_pool_release(zz_handler *zz, zz_client *client) {
    client->next_free = zz->client_pool.free_list;
    zz->client_pool.free_list = client;
}

static void client_pool_destroy(zz_handler *zz) {
    struct zz_client_pool_chunk *chunk = zz->client_pool.chunks;
    while (chunk) {
        struct zz_client_pool_chunk *next = chunk->next;
        free(chunk);
        chunk = next;
    }
    zz->client_pool.chunks = NULL;
    zz->client_pool.free_list = NULL;
}

/*
 * Initialize a new empty clients hash table.
 * Sets the pointer to NULL (uthash convention for empty table).
 *
 * Parameters:
 *   clients - Pointer to clients collection (will be set to NULL)
 */
void zz_clients_new(zz_clients *clients) {
    *clients = NULL;
}

/*
 * Look up or create a client entry in the hash table.
 * The key is the combination of (station MAC, BSSID), allowing a station
 * to be tracked separately for each AP it connects to.
 *
 * If the client doesn't exist, it's created with zero-initialized state.
 * This is a "get or create" pattern that simplifies client management.
 *
 * Parameters:
 *   zz - Handler used for error reporting
 *   clients - Clients hash table
 *   station - Client station MAC address
 *   bssid - Access point BSSID
 *   client - Output pointer to the found/created client structure
 *
 * Returns:
 *   1 if client was newly created, 0 if it already existed,
 *   -1 on allocation failure
 */
int zz_clients_lookup(zz_handler *zz, zz_clients *clients,
                      zz_mac_addr station, zz_mac_addr bssid,
                      zz_client **client) {
    /* Create composite key from station and BSSID.
     * The two MAC addresses are stored adjacently in memory, forming
     * a 16-byte key (2 * sizeof(zz_mac_addr)) */
    const zz_mac_addr key[] = {station, bssid};

    /* Try to find existing client using the composite key */
    HASH_FIND(hh, *clients, key, sizeof(key), *client);
    if (*client) {
        return 0;  /* Client already exists */
    }

    /* Client not found - create and initialize a new one */
    *client = client_pool_acquire(zz);
    if (*client == NULL) {
        return -1;
    }
    (*client)->station = station;
    (*client)->bssid = bssid;

    /* Add to hash table. Hash key starts at 'station' field and spans both
     * station and bssid (which are adjacent in memory) */
    HASH_ADD(hh, *clients, station, sizeof(key), *client);
    return 1;  /* New client created */
}

/*
 * Free all clients and the hash table.
 * Iterates through the table, removes each entry, and frees its memory.
 *
 * Parameters:
 *   clients - Clients hash table to free
 */
void zz_clients_free(zz_handler *zz, zz_clients *clients) {
    zz_client *tmp, *client;

    HASH_ITER(hh, *clients, client, tmp) {
        HASH_DEL(*clients, client);
        client_pool_release(zz, client);
    }

    *clients = NULL;
}

void zz_clients_pool_destroy(zz_handler *zz) {
    client_pool_destroy(zz);
}
