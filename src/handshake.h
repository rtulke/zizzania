/*
 * handshake.h - WPA/WPA2 handshake tracking and validation
 *
 * Handles detection and tracking of the IEEE 802.1X 4-way handshake
 * used in WPA/WPA2 authentication. Validates EAPOL frames, tracks
 * handshake progress using bitmasks, and detects retransmissions.
 */

#ifndef ZZ_HANDSHAKE_H
#define ZZ_HANDSHAKE_H

#include "handler.h"

/* Reasons why a packet might be ignored (not processed) */
enum {
    ZZ_IGNORE_REASON_RETRANSMISSION,  /* Duplicate frame (same replay counter) */
    ZZ_IGNORE_REASON_INVALID_EAPOL,   /* EAPOL frame format is invalid */
    ZZ_IGNORE_REASON_INVALID_COUNTER  /* Replay counter inconsistency */
};

/* Reasons why a client might be tracked for deauthentication */
enum {
    ZZ_TRACK_REASON_ALIVE,            /* Client is active (sending data) */
    ZZ_TRACK_REASON_FIRST_HANDSHAKE,  /* First handshake message received */
    ZZ_TRACK_REASON_EXPIRATION,       /* Handshake timed out, need to restart */
    ZZ_TRACK_REASON_INVALIDATION      /* Handshake invalidated, need new attempt */
};

/*
 * Packet processing outcome - returned by zz_process_packet()
 * Contains flags indicating what actions to take based on the packet analysis.
 * Uses bitfields for compact storage.
 */
typedef struct {
    unsigned new_client:1;       /* This is the first time we've seen this client */
    unsigned ignore:1;           /* Packet should be ignored (don't process further) */
    unsigned ignore_reason:2;    /* Reason for ignoring (ZZ_IGNORE_REASON_*) */
    unsigned track_client:1;     /* Add/update client in killer's target list */
    unsigned track_reason:2;     /* Reason for tracking (ZZ_TRACK_REASON_*) */
    unsigned grace_time:1;       /* Client is in grace period (wait before deauth) */
    unsigned dump_packet:1;      /* Write this packet to output pcap */
    unsigned got_handshake:1;    /* Complete handshake achieved */
    unsigned handshake_info:3;   /* Which handshake message (1-4) or bitmask info */
} zz_packet_outcome;

/*
 * Process an EAPOL packet and update handshake state.
 * This is the main handshake tracking function that:
 *   - Validates EAPOL frame format
 *   - Identifies which handshake message (1-4) it represents
 *   - Detects retransmissions using replay counters
 *   - Updates client handshake state bitmask
 *   - Determines if packet should be dumped and if client needs deauth
 *
 * Parameters:
 *   zz - Main handler with client tracking state
 *   station - MAC address of the client station
 *   bssid - MAC address of the access point
 *   packet_header - libpcap packet metadata (timestamp, length)
 *   auth - Pointer to EAPOL authentication header in the packet
 *
 * Returns:
 *   zz_packet_outcome structure with flags indicating required actions
 */
zz_packet_outcome zz_process_packet(zz_handler *zz,
    zz_mac_addr station, zz_mac_addr bssid,
    const struct pcap_pkthdr *packet_header,
    const struct ieee8021x_authentication_header *auth);

/*
 * Send a message to the killer subsystem to track/untrack a client.
 * This function is declared here to avoid circular dependencies between
 * handshake.h and killer.h.
 *
 * Parameters:
 *   killer - Killer subsystem state
 *   station - Client MAC address
 *   bssid - Access point MAC address
 *   outcome - Packet outcome indicating why client should be tracked
 */
int zz_killer_post_message(zz_handler *zz, zz_killer *killer,
                            zz_mac_addr station, zz_mac_addr bssid,
                            zz_packet_outcome outcome);
#endif
