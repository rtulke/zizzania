/*
 * handshake.c - WPA/WPA2 handshake state machine
 *
 * Implements the core logic for tracking WPA 4-way handshake progress.
 * Maintains per-client state (which messages received, replay counters,
 * timestamps) and determines when a complete handshake has been captured.
 * Also handles timeouts, retransmissions, and invalidation scenarios.
 */

#include "clients.h"
#include "handshake.h"
#include "ieee802.h"
#include "params.h"
#include "terminal.h"

/* Compute absolute difference between two values */
#define abs(x, y) ((x) > (y) ? (x) - (y) : (y) - (x))

/* Check if first 'max' bits of handshake bitmask are all set.
 * For example, if max=4, checks if bits 0-3 are all 1 (full 4-way handshake).
 * If max=2, checks if bits 0-1 are all 1 (partial 2-message handshake). */
#define is_done(handshake, max) \
    ((((handshake) & ((1 << (max)) - 1)) == ((1 << (max)) - 1)))

static int identify_handshake_message(const struct ieee8021x_authentication_header *auth,
                                      unsigned *handshake_id, uint64_t *replay_counter_1) {
    const uint16_t flags = be16toh(auth->flags);

    if ((flags & ZZ_EAPOL_MASK_1) == ZZ_EAPOL_FLAGS_1) {
        *handshake_id = 0;
        *replay_counter_1 = be64toh(auth->replay_counter);
        return 1;
    }
    if ((flags & ZZ_EAPOL_MASK_2) == ZZ_EAPOL_FLAGS_2) {
        *handshake_id = 1;
        *replay_counter_1 = be64toh(auth->replay_counter);
        return 1;
    }
    if ((flags & ZZ_EAPOL_MASK_3) == ZZ_EAPOL_FLAGS_3) {
        *handshake_id = 2;
        *replay_counter_1 = be64toh(auth->replay_counter) - 1;
        return 1;
    }
    if ((flags & ZZ_EAPOL_MASK_4) == ZZ_EAPOL_FLAGS_4) {
        *handshake_id = 3;
        *replay_counter_1 = be64toh(auth->replay_counter) - 1;
        return 1;
    }

    return 0;
}

static int validate_replay_counter(const zz_client *client, unsigned handshake_id,
                                   const struct ieee8021x_authentication_header *auth) {
    const uint64_t counter = be64toh(auth->replay_counter);

    switch (handshake_id) {
    case 0:
    case 1:
        return counter == client->replay_counter;
    case 2:
    case 3:
        return counter == client->replay_counter + 1;
    default:
        return 1;
    }
}

/*
 * Process a packet through the WPA handshake state machine.
 * This is the heart of AirSnare's handshake tracking logic. It maintains
 * per-client state and determines what actions should be taken based on
 * the packet type and current handshake progress.
 *
 * State machine logic:
 *   1. For new clients: initialize tracking state
 *   2. For EAPOL frames:
 *      - Identify which handshake message (1-4) based on flags
 *      - Validate replay counter sequence
 *      - Detect retransmissions (exact duplicate)
 *      - Handle timeouts (reinitialize if too much time passed)
 *      - Handle invalidation (received unexpected message, restart)
 *      - Check for handshake completion (all required messages received)
 *   3. For data frames:
 *      - Update last activity timestamp
 *      - Trigger retracking if client became active again after long idle
 *
 * The function returns an outcome structure that tells the dissector:
 *   - Whether to ignore this packet
 *   - Whether to dump this packet to output
 *   - Whether to (re)start tracking/deauthentication
 *   - Whether a complete handshake was captured
 *
 * Parameters:
 *   zz - Handler with configuration
 *   station - Client MAC address
 *   bssid - Access point BSSID
 *   packet_header - Packet metadata (timestamp, etc.)
 *   auth - EAPOL authentication header (NULL for data frames)
 *
 * Returns:
 *   Outcome structure indicating what actions to take
 */
zz_packet_outcome zz_process_packet(zz_handler *zz,
    zz_mac_addr station, zz_mac_addr bssid,
    const struct pcap_pkthdr *packet_header,
    const struct ieee8021x_authentication_header *auth) {
    zz_client *client;
    time_t last_data_ts;
    zz_packet_outcome outcome = {0};
    int lookup_status;

    /* Lookup or create client descriptor.
     * The lookup function returns 1 if this is a newly created client. */
    lookup_status = zz_clients_lookup(zz, &zz->clients, station, bssid, &client);
    if (lookup_status == -1) {
        zz->is_done = 1;
        pcap_breakloop(zz->pcap);
        return outcome;
    }
    if (lookup_status == 1) {
        /* New client discovered - initiate tracking */
        outcome.new_client = 1;
    }

    /* Update last activity timestamp.
     * Save old timestamp before updating (used later to detect "came back alive"). */
    last_data_ts = client->last_data_ts;
    client->last_data_ts = packet_header->ts.tv_sec;

    /* Branch 1: EAPOL authentication message (handshake frame) */
    if (auth) {
        unsigned handshake_id;
        uint64_t ts;
        uint64_t replay_counter_1; /* Expected replay counter for message #1 */
        int initialize = 0;

        /* Convert timestamp to microseconds for precise timeout calculations */
        ts = ((uint64_t)packet_header->ts.tv_sec * ZZ_USEC_PER_SEC +
              (packet_header->ts.tv_usec % ZZ_USEC_PER_SEC));

        if (!identify_handshake_message(auth, &handshake_id, &replay_counter_1)) {
            zz_trace("Unrecognizable EAPOL flags 0x%04hx", be16toh(auth->flags));
            outcome.ignore = 1;
            outcome.ignore_reason = ZZ_IGNORE_REASON_INVALID_EAPOL;
            return outcome;
        }

        /* Store message number for logging (1-based, not 0-based) */
        outcome.handshake_info = handshake_id + 1;

        /* Determine whether to initialize/reinitialize handshake tracking.
         * We reinitialize in three scenarios:
         *   1. First handshake message ever for this client
         *   2. Timeout: too much time passed since last message
         *   3. Invalidation: received conflicting message (not a retransmission) */

        /* Scenario 1: First handshake message ever for this client */
        if (!client->handshake) {
            initialize = 1;
            outcome.track_reason = ZZ_TRACK_REASON_FIRST_HANDSHAKE;
        }
        /* Scenario 2: Handshake timeout - too much time passed.
         * Even if this is a retransmission, we restart the tracking because
         * the previous attempt is considered stale. */
        else if (abs(client->last_handshake_ts, ts) > ZZ_MAX_HANDSHAKE_TIME) {
            initialize = 1;
            outcome.track_reason = ZZ_TRACK_REASON_EXPIRATION;
        }
        /* Already received this handshake message ID before */
        else if (client->handshake & (1 << handshake_id)) {
            /* Check if this is an exact duplicate (retransmission).
             * If the EAPOL header is identical to what we saved, it's a retransmission. */
            if (memcmp(&client->headers[handshake_id], auth,
                       sizeof(struct ieee8021x_authentication_header)) == 0) {
                outcome.ignore = 1;
                outcome.ignore_reason = ZZ_IGNORE_REASON_RETRANSMISSION;
                return outcome;
            }
            /* Scenario 3: Not a retransmission but we already have this message.
             * This indicates a conflicting handshake attempt. Reinitialize. */
            else {
                initialize = 1;
                outcome.track_reason = ZZ_TRACK_REASON_INVALIDATION;
            }
        }
        /* Normal case: First time receiving this message in current handshake */
        else {
            if (!validate_replay_counter(client, handshake_id, auth)) {
                outcome.ignore = 1;
                outcome.ignore_reason = ZZ_IGNORE_REASON_INVALID_COUNTER;
                return outcome;
            }

            client->handshake |= 1 << handshake_id;
            memcpy(&client->headers[handshake_id], auth,
                   sizeof(struct ieee8021x_authentication_header));

            if (handshake_id < zz->setup.max_handshake &&
                is_done(client->handshake, zz->setup.max_handshake)) {
                outcome.got_handshake = 1;
            }
        }

        /* Perform initialization if any of the scenarios triggered it */
        if (initialize) {
            /* Request grace time: delay first deauth attack to allow natural
             * handshake completion. This avoids disrupting an ongoing handshake. */
            outcome.grace_time = 1;

            /* Request tracking/deauthentication to start */
            outcome.track_client = 1;

            /* Reset client state to start fresh handshake tracking */
            client->last_handshake_ts = ts;
            client->replay_counter = replay_counter_1;
            client->handshake = 1 << handshake_id;  /* Set only this message bit */
            memcpy(&client->headers[handshake_id], auth,
                   sizeof(struct ieee8021x_authentication_header));
        }
    }
    /* Branch 2: Regular data packet (not EAPOL) */
    else {
        /* Check if client "came back alive" after a long idle period.
         * This is useful when the killer gave up on deauthenticating this client
         * (ran out of attempts), but the client is still active and hasn't
         * completed its handshake. We can restart the deauth process.
         *
         * The "long" time threshold is set to match the killer's give-up time:
         * (max_attempts - 1) * interval seconds. */
        if (last_data_ts &&
            !is_done(client->handshake, zz->setup.max_handshake) &&
            (packet_header->ts.tv_sec - last_data_ts >
             ZZ_KILLER_IDLE_THRESHOLD(zz->setup.killer_max_attempts,
                                      zz->setup.killer_interval))) {
            outcome.track_client = 1;
            outcome.track_reason = ZZ_TRACK_REASON_ALIVE;
        }
    }

    /* Decide whether to dump this packet to output file.
     * Dump if:
     *   - It's a valid EAPOL message (regardless of handshake state), OR
     *   - Client has completed the required handshake (dump its data traffic too) */
    if (auth || is_done(client->handshake, zz->setup.max_handshake)) {
        outcome.dump_packet = 1;
    }

    return outcome;
}
