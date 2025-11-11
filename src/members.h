/*
 * members.h - MAC address filtering and membership management
 *
 * Provides data structures and functions for managing sets of MAC addresses
 * with support for subnet masks. Used to implement include/exclude filters
 * for both BSSIDs (access points) and station addresses.
 */

#ifndef ZZ_MEMBERS_H
#define ZZ_MEMBERS_H

#include "ieee802.h"

/* Opaque pointer to internal device structure. Members is implemented
 * as a hash table of MAC addresses with optional masks. */
struct zz_device;
typedef struct zz_device *zz_members;

/* Initialize a new empty members set */
void zz_members_new(zz_members *members);

/* Add a MAC address to the set (exact match only)
 * Returns: 1 when added, 0 if it already exists, -1 on allocation failure */
int zz_members_put(zz_members *members, zz_mac_addr mac_addr);

/* Add a MAC address with a subnet mask to the set (allows matching ranges)
 * Example: mac_addr=00:11:22:00:00:00, mac_mask=ff:ff:ff:00:00:00
 *          will match all addresses starting with 00:11:22
 * Returns: 1 when added, 0 if it already exists, -1 on allocation failure */
int zz_members_put_mask(zz_members *members, zz_mac_addr mac_addr, zz_mac_addr mac_mask);

/* Check if an exact MAC address exists in the set (no mask matching)
 * Returns: 1 if found, 0 if not found */
int zz_members_has(const zz_members *members, zz_mac_addr mac_addr);

/* Check if a MAC address matches any entry in the set (with mask support)
 * This applies subnet masks for pattern matching
 * Returns: 1 if matches, 0 if no match */
int zz_members_match(const zz_members *members, zz_mac_addr mac_addr);

int zz_members_filter_allows(zz_mac_addr mac_addr, int exclude_first,
                             const zz_members *include, const zz_members *exclude);

/* Get the number of entries in the set
 * Returns: count of MAC address entries */
unsigned zz_members_count(const zz_members *members);

/* Check if the set is empty
 * Returns: 1 if empty, 0 if contains entries */
int zz_members_is_empty(const zz_members *members);

/* Free all memory associated with the members set */
void zz_members_free(zz_members *members);

#endif
