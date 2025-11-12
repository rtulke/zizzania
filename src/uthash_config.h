/*
 * uthash_config.h - uthash performance tuning configuration
 *
 * This file must be included BEFORE <uthash.h> in all files that use
 * hash tables. It configures uthash performance parameters optimized
 * for wireless network monitoring scenarios with potentially large
 * numbers of clients and access points.
 *
 * These settings are platform-independent and work identically on
 * Linux and macOS.
 */

#ifndef ZZ_UTHASH_CONFIG_H
#define ZZ_UTHASH_CONFIG_H

/*
 * Initial hash table size (number of buckets).
 *
 * Default uthash uses 32 buckets initially. For wireless monitoring,
 * we expect moderate to large numbers of entries (dozens to hundreds
 * of clients/APs), so we start with 128 buckets to reduce initial
 * rehashing overhead.
 *
 * Must be a power of 2. uthash will automatically expand when the
 * load factor exceeds the capacity threshold.
 */
#define HASH_INITIAL_NUM_BUCKETS 128U
#define HASH_INITIAL_NUM_BUCKETS_LOG2 7U  /* log2(128) = 7 */

/*
 * Bloom filter for negative lookups.
 *
 * Enables a Bloom filter to speed up HASH_FIND operations when the
 * key is not present in the table. This is common in our use case
 * when filtering packets against allow/deny lists.
 *
 * HASH_BLOOM value is the log2 of the number of bits in the filter:
 *   16 = 2^16 = 65536 bits = 8 KB
 *   20 = 2^20 = 1048576 bits = 128 KB
 *
 * We use 16 (8KB) as a good balance between memory and performance.
 * The filter gives ~99% accuracy for negative lookups with minimal
 * memory overhead.
 */
#define HASH_BLOOM 16

#endif
