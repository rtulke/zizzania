/*
 * bsss.c - Access point (BSS) tracking
 *
 * Implements a hash table of Basic Service Sets (access points) indexed by BSSID.
 * Each BSS entry tracks the SSID, filter status, associated stations with
 * handshakes, and traffic statistics.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "handler.h"
#include "bsss.h"

#define ZZ_BSS_POOL_CHUNK 32

struct zz_bss_pool_chunk {
    zz_bss nodes[ZZ_BSS_POOL_CHUNK];
    struct zz_bss_pool_chunk *next;
};

static int bss_pool_grow(zz_handler *zz) {
    struct zz_bss_pool_chunk *chunk = malloc(sizeof(*chunk));
    size_t i;

    if (!chunk) {
        zz_error(zz, "Cannot grow BSS pool: %s", strerror(errno));
        return 0;
    }

    chunk->next = zz->bss_pool.chunks;
    zz->bss_pool.chunks = chunk;

    for (i = 0; i < ZZ_BSS_POOL_CHUNK; i++) {
        chunk->nodes[i].next_free = zz->bss_pool.free_list;
        zz->bss_pool.free_list = &chunk->nodes[i];
    }

    return 1;
}

static zz_bss *bss_pool_acquire(zz_handler *zz) {
    if (!zz->bss_pool.free_list) {
        if (!bss_pool_grow(zz)) {
            return NULL;
        }
    }

    zz_bss *bss = zz->bss_pool.free_list;
    zz->bss_pool.free_list = bss->next_free;
    memset(bss, 0, sizeof(*bss));
    return bss;
}

static void bss_pool_release(zz_handler *zz, zz_bss *bss) {
    bss->next_free = zz->bss_pool.free_list;
    zz->bss_pool.free_list = bss;
}

static void bss_pool_destroy(zz_handler *zz) {
    struct zz_bss_pool_chunk *chunk = zz->bss_pool.chunks;
    while (chunk) {
        struct zz_bss_pool_chunk *next = chunk->next;
        free(chunk);
        chunk = next;
    }
    zz->bss_pool.chunks = NULL;
    zz->bss_pool.free_list = NULL;
}

/*
 * Initialize a new empty BSSs hash table.
 * Sets the pointer to NULL (uthash convention for empty table).
 *
 * Parameters:
 *   bsss - Pointer to BSSs collection (will be set to NULL)
 */
void zz_bsss_new(zz_bsss *bsss) {
    *bsss = NULL;
}

/*
 * Look up or create a BSS entry in the hash table.
 * If the BSS doesn't exist, it's created with zero-initialized state
 * and an empty stations set.
 *
 * This is a "get or create" pattern that simplifies BSS management.
 *
 * Parameters:
 *   zz - Handler used for error reporting
 *   bsss - BSSs hash table
 *   bssid - Access point BSSID to look up
 *   bss - Output pointer to the found/created BSS structure
 *
 * Returns:
 *   1 if BSS was newly created, 0 if it already existed,
 *   -1 on allocation failure
 */
int zz_bsss_lookup(zz_handler *zz, zz_bsss *bsss, zz_mac_addr bssid, zz_bss **bss) {
    /* Try to find existing BSS by BSSID */
    HASH_FIND(hh, *bsss, &bssid, sizeof(zz_mac_addr), *bss);
    if (*bss) {
        return 0;  /* BSS already exists */
    }

    /* BSS not found - create and initialize a new one */
    *bss = bss_pool_acquire(zz);
    if (*bss == NULL) {
        return -1;
    }
    (*bss)->bssid = bssid;
    zz_members_new(&(*bss)->stations);  /* Initialize empty stations set */

    /* Add to hash table, keyed by bssid field */
    HASH_ADD(hh, *bsss, bssid, sizeof(zz_mac_addr), *bss);
    return 1;  /* New BSS created */
}

/*
 * Free all BSSs and the hash table.
 * Iterates through the table, frees each BSS's stations set,
 * and then frees the BSS itself.
 *
 * Parameters:
 *   bsss - BSSs hash table to free
 */
void zz_bsss_free(zz_handler *zz, zz_bsss *bsss) {
    zz_bss *tmp, *bss;

    HASH_ITER(hh, *bsss, bss, tmp) {
        HASH_DEL(*bsss, bss);
        zz_members_free(&bss->stations);  /* Free the stations set first */
        bss_pool_release(zz, bss);
    }

    *bsss = NULL;
}

void zz_bsss_pool_destroy(zz_handler *zz) {
    bss_pool_destroy(zz);
}
