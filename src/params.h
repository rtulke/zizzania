/*
 * params.h - Runtime parameters and timeouts
 *
 * This file defines timing parameters that control the behavior of the
 * handshake capture and deauthentication attack processes.
 */

#ifndef ZZ_PARAMS_H
#define ZZ_PARAMS_H

/* Grace period (in seconds) to wait for a natural handshake completion
 * before starting to send deauthentication frames to a client. This allows
 * passive capture first before resorting to active attacks. */
#define ZZ_KILLER_GRACE_TIME 3

/* Maximum time window (in microseconds) during which handshake messages
 * are considered part of the same handshake session. If another handshake
 * message arrives after this timeout, the previous handshake information
 * is considered invalid and the handshake sequence is restarted. */
#define ZZ_MAX_HANDSHAKE_TIME 500000

#define ZZ_USEC_PER_SEC 1000000ULL

#define ZZ_KILLER_IDLE_THRESHOLD(max_attempts, interval) \
    (((max_attempts) > 0 ? ((max_attempts) - 1) : 0) * (interval))

#endif
