#ifndef BUILD_SUPPORT_UTHASH_H
#define BUILD_SUPPORT_UTHASH_H

/*
 * Minimal uthash-compatible implementation for AirSnare offline builds.
 * Supports the subset of macros used within this repository:
 *   HASH_ADD, HASH_FIND, HASH_DEL, HASH_ITER, HASH_COUNT.
 *
 * This simplified version keeps a doubly linked list per "hash" table and
 * performs linear lookups. It is suitable for development builds when the
 * official uthash release cannot be downloaded. Replace with upstream
 * uthash 2.1.0 for production deployments.
 */

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct UT_hash_table {
    void *head_ptr;
    void *tail_ptr;
    unsigned num_items;
} UT_hash_table;

typedef struct UT_hash_handle {
    UT_hash_table *tbl;
    void *prev;
    void *next;
    const void *key;
    unsigned keylen;
} UT_hash_handle;

#define _UTHASH_PTRTYPE(head) __typeof__(*(head)) *
#define _UTHASH_CAST(head) ((_UTHASH_PTRTYPE(head))(head))

#define UTHASH_ALLOC_TABLE(_tblptr)                                   \
    do {                                                              \
        _tblptr = (UT_hash_table *)calloc(1, sizeof(UT_hash_table));  \
        if (!(_tblptr)) {                                            \
            abort();                                                  \
        }                                                             \
    } while (0)

#define HASH_ADD(hh, head, fieldname, keylen_in, add)                                \
    do {                                                                             \
        __typeof__(add) _ha_add = (add);                                             \
        __typeof__(&(head)) _ha_head = &(head);                                      \
        UT_hash_table *_ha_tbl;                                                      \
        if (*_ha_head == NULL) {                                                     \
            UTHASH_ALLOC_TABLE(_ha_tbl);                                             \
        } else {                                                                     \
            _ha_tbl = (*_ha_head)->hh.tbl;                                           \
            if (_ha_tbl == NULL) {                                                   \
                UTHASH_ALLOC_TABLE(_ha_tbl);                                         \
                (*_ha_head)->hh.tbl = _ha_tbl;                                       \
            }                                                                        \
        }                                                                            \
        _ha_add->hh.tbl = _ha_tbl;                                                   \
        _ha_add->hh.prev = NULL;                                                     \
        _ha_add->hh.next = *_ha_head;                                                \
        _ha_add->hh.key = (const void *)&(_ha_add->fieldname);                       \
        _ha_add->hh.keylen = (unsigned)(keylen_in);                                  \
        if (*_ha_head) {                                                             \
            (*_ha_head)->hh.prev = _ha_add;                                          \
        } else {                                                                     \
            _ha_tbl->tail_ptr = _ha_add;                                             \
        }                                                                            \
        *_ha_head = _ha_add;                                                         \
        _ha_tbl->head_ptr = *_ha_head;                                               \
        _ha_tbl->num_items++;                                                        \
    } while (0)

#define HASH_FIND(hh, head, keyptr, keylen_in, out)                                  \
    do {                                                                             \
        out = NULL;                                                                  \
        const void *_hf_key = (const void *)(keyptr);                                \
        unsigned _hf_keylen = (unsigned)(keylen_in);                                 \
        _UTHASH_PTRTYPE(head) _hf_it = _UTHASH_CAST(head);                           \
        while (_hf_it) {                                                             \
            if (_hf_it->hh.keylen == _hf_keylen &&                                   \
                memcmp(_hf_it->hh.key, _hf_key, _hf_keylen) == 0) {                  \
                out = _hf_it;                                                        \
                break;                                                               \
            }                                                                        \
            _hf_it = (_UTHASH_PTRTYPE(head))(_hf_it->hh.next);                       \
        }                                                                            \
    } while (0)

#define HASH_DEL(head, delptr)                                                       \
    do {                                                                             \
        __typeof__(delptr) _hd_del = (delptr);                                       \
        __typeof__(&(head)) _hd_head = &(head);                                      \
        UT_hash_table *_hd_tbl = _hd_del->hh.tbl;                                    \
        if (_hd_del->hh.prev) {                                                      \
            ((__typeof__(_hd_del))_hd_del->hh.prev)->hh.next = _hd_del->hh.next;     \
        } else {                                                                     \
            *_hd_head = (__typeof__(head))(_hd_del->hh.next);                        \
            if (*_hd_head) {                                                         \
                (*_hd_head)->hh.prev = NULL;                                         \
            }                                                                        \
        }                                                                            \
        if (_hd_del->hh.next) {                                                      \
            ((__typeof__(_hd_del))_hd_del->hh.next)->hh.prev = _hd_del->hh.prev;     \
        } else if (_hd_tbl) {                                                        \
            _hd_tbl->tail_ptr = _hd_del->hh.prev;                                    \
        }                                                                            \
        if (_hd_tbl) {                                                               \
            _hd_tbl->head_ptr = *_hd_head;                                           \
            if (_hd_tbl->num_items > 0) {                                            \
                _hd_tbl->num_items--;                                                \
            }                                                                        \
            if (_hd_tbl->num_items == 0) {                                           \
                free(_hd_tbl);                                                       \
            }                                                                        \
        }                                                                            \
        _hd_del->hh.prev = NULL;                                                     \
        _hd_del->hh.next = NULL;                                                     \
        _hd_del->hh.tbl = NULL;                                                      \
        _hd_del->hh.key = NULL;                                                      \
        _hd_del->hh.keylen = 0;                                                      \
    } while (0)

#define HASH_ITER(hh, head, el, tmp)                                                 \
    for ((el) = (head);                                                             \
         (el) != NULL && (((tmp) = (__typeof__(el))((el)->hh.next)), 1);             \
         (el) = (tmp))

#define HASH_COUNT(head)                                                            \
    (((head) != NULL && (head)->hh.tbl != NULL) ? (head)->hh.tbl->num_items : 0U)

#ifdef __cplusplus
}
#endif

#endif /* BUILD_SUPPORT_UTHASH_H */
