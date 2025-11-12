/*
 * members.c - MAC address set management
 *
 * Implements a hash-table-based set of MAC addresses with optional subnet
 * masks for pattern matching. Used for include/exclude filtering of both
 * BSSIDs (access points) and station addresses.
 */

#include <stdlib.h>

#include "uthash_config.h"
#include <uthash.h>

#include "members.h"

/*
 * Internal device structure stored in the hash table.
 * Each entry represents a MAC address with an optional mask for
 * subnet-style matching (e.g., match all addresses starting with XX:XX:XX).
 */
struct zz_device {
    zz_mac_addr addr;    /* MAC address (also used as hash key) */
    zz_mac_addr mask;    /* Subnet mask for pattern matching (-1 for exact match) */
    UT_hash_handle hh;   /* uthash handle */
};

/*
 * Initialize a new empty members set.
 * Sets the pointer to NULL (uthash convention for empty table).
 *
 * Parameters:
 *   members - Pointer to members set (will be set to NULL)
 */
void zz_members_new(zz_members *members) {
    *members = NULL;
}

/*
 * Add a MAC address to the set with exact matching (no mask).
 * This is a convenience wrapper around zz_members_put_mask() with mask=-1.
 *
 * Parameters:
 *   members - Members set to add to
 *   mac_addr - MAC address to add
 *
 * Returns:
 *   1 if added (was not already present), 0 if already in set
 */
int zz_members_put(zz_members *members, zz_mac_addr mac_addr) {
    return zz_members_put_mask(members, mac_addr, -1);
}

/*
 * Add a MAC address with a subnet mask to the set.
 * The mask allows matching ranges of addresses. For example:
 *   addr=0x001122000000, mask=0xffffff000000 matches all 00:11:22:XX:XX:XX
 *
 * Parameters:
 *   members - Members set to add to
 *   mac_addr - MAC address to add
 *   mac_mask - Subnet mask (-1 for exact match)
 *
 * Returns:
 *   1 if added (was not already present), 0 if already in set
 */
int zz_members_put_mask(zz_members *members, zz_mac_addr mac_addr, zz_mac_addr mac_mask) {
    struct zz_device *device;

    /* Check if this exact address is already in the set */
    HASH_FIND(hh, *members, &mac_addr, sizeof(zz_mac_addr), device);
    if (device) {
        return 0;  /* Already present */
    }

    /* Create new device entry and add to hash table */
    device = malloc(sizeof(struct zz_device));
    if (device == NULL) {
        return -1;
    }
    device->addr = mac_addr;
    device->mask = mac_mask;
    HASH_ADD(hh, *members, addr, sizeof(zz_mac_addr), device);
    return 1;
}

/*
 * Check if an exact MAC address exists in the set.
 * This does NOT apply mask matching - only exact address lookup.
 *
 * Parameters:
 *   members - Members set to search
 *   mac_addr - MAC address to look up
 *
 * Returns:
 *   1 if found, 0 if not found
 */
int zz_members_has(const zz_members *members, zz_mac_addr mac_addr) {
    struct zz_device *device;

    HASH_FIND(hh, *members, &mac_addr, sizeof(zz_mac_addr), device);
    return !!device;  /* Convert pointer to boolean */
}

/*
 * Check if a MAC address matches any entry in the set (with mask support).
 * Iterates through all entries and applies each mask to test for a match.
 * For example, if the set contains 00:11:22:00:00:00/ff:ff:ff:00:00:00,
 * it will match 00:11:22:33:44:55.
 *
 * Parameters:
 *   members - Members set to search
 *   mac_addr - MAC address to test
 *
 * Returns:
 *   1 if mac_addr matches any entry (considering masks), 0 otherwise
 */
int zz_members_match(const zz_members *members, zz_mac_addr mac_addr) {
    struct zz_device *tmp, *device;

    /* Iterate through all devices in the set */
    HASH_ITER(hh, *members, device, tmp) {
        /* Apply mask to both addresses and compare */
        if ((mac_addr & device->mask) == (device->addr & device->mask)) {
            return 1;  /* Match found */
        }
    }

    return 0;  /* No match */
}

int zz_members_filter_allows(zz_mac_addr mac_addr, int exclude_first,
                             const zz_members *include, const zz_members *exclude) {
    const int include_empty = zz_members_is_empty(include);
    const int exclude_empty = zz_members_is_empty(exclude);

    if (!include_empty && !exclude_empty) {
        if (exclude_first) {
            return zz_members_match(include, mac_addr) ||
                   !zz_members_match(exclude, mac_addr);
        }
        return zz_members_match(include, mac_addr) &&
               !zz_members_match(exclude, mac_addr);
    }

    if (!include_empty) {
        return zz_members_match(include, mac_addr);
    }

    if (!exclude_empty) {
        return !zz_members_match(exclude, mac_addr);
    }

    return 1;
}

/*
 * Get the number of entries in the set.
 *
 * Parameters:
 *   members - Members set to count
 *
 * Returns:
 *   Number of MAC address entries in the set
 */
unsigned zz_members_count(const zz_members *members) {
    return HASH_COUNT(*members);
}

/*
 * Check if the set is empty.
 *
 * Parameters:
 *   members - Members set to check
 *
 * Returns:
 *   1 if empty (no entries), 0 if contains at least one entry
 */
int zz_members_is_empty(const zz_members *members) {
    return HASH_COUNT(*members) == 0;
}

/*
 * Free all memory associated with the members set.
 * Iterates through the hash table, removes each entry, and frees it.
 *
 * Parameters:
 *   members - Members set to free
 */
void zz_members_free(zz_members *members) {
    struct zz_device *tmp, *device;

    HASH_ITER(hh, *members, device, tmp) {
        HASH_DEL(*members, device);
        free(device);
    }
}
