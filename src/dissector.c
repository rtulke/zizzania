/*
 * dissector.c - Packet dissection and parsing
 *
 * Implements the main packet dissection callback that's invoked by pcap_loop
 * for every captured packet. Parses 802.11 frame headers, extracts addresses,
 * handles beacon frames, applies filters, and delegates to the handshake
 * state machine. This is the entry point for all packet processing.
 */

#include <errno.h>
#include <string.h>
#include <strings.h>

#include "dissector.h"
#include "handshake.h"
#include "ieee802.h"
#include "terminal.h"

/* Convert struct timeval to floating-point seconds */
#define TV_TO_SEC(tv) ((tv).tv_sec + (tv).tv_usec / 1000000.)

/* Logging macro that includes relative timestamp (seconds since first packet) */
#define log_ts(zz, packet_header, format, ...) \
    zz_log("%.3f - " format, \
           TV_TO_SEC((packet_header)->ts) - (zz)->epoch, ##__VA_ARGS__)

struct zz_frame_addresses {
    zz_mac_addr bssid;
    zz_mac_addr station;
    zz_mac_addr source;
    zz_mac_addr destination;
    int is_beacon;
};

static int parse_frame_addresses(zz_handler *zz, const struct pcap_pkthdr *packet_header,
                                 const struct ieee80211_mac_header *mac_header,
                                 struct zz_frame_addresses *frame);
static int handle_beacon_frame(zz_handler *zz, const struct pcap_pkthdr *packet_header,
                               const uint8_t *packet, const uint8_t *cursor,
                               zz_bss *bss, const char *bssid_str, int is_beacon);
static int process_packet_outcome(zz_handler *zz, const struct pcap_pkthdr *packet_header,
                                  const uint8_t *packet, zz_bss *bss,
                                  const struct ieee8021x_authentication_header *authentication_header,
                                  zz_packet_outcome outcome,
                                  zz_mac_addr station, zz_mac_addr bssid,
                                  const char *station_str, const char *bssid_str);

/*
 * Extract SSID from beacon frame tagged parameters.
 * Beacon frames contain a variable-length list of tagged parameters,
 * each with a type-length-value (TLV) structure. This function scans
 * the list looking for the SSID parameter (type 0).
 *
 * Parameters:
 *   params - Start of tagged parameters section
 *   length - Total length of parameters section
 *   ssid - Output pointer to SSID string (not null-terminated)
 *   ssid_length - Output SSID length in bytes
 */
static void get_ssid(const uint8_t *params, uint32_t length,
                     const char **ssid, int *ssid_length) {
    const uint8_t *ptr;

    /* Initialize outputs to empty (prevents valgrind warnings) */
    *ssid = NULL;
    *ssid_length = 0;

    /* Scan through tagged parameters (TLV format: type, length, value) */
    ptr = params;
    while (ptr < params + length) {
        uint8_t param_type;
        uint8_t param_length;

        /* Read type and length fields */
        param_type = *ptr++;
        param_length = *ptr++;

        /* Check if this is the SSID parameter (type 0) */
        if (param_type == ZZ_BEACON_SSID_PARAM_TYPE) {
            *ssid_length = param_length;
            *ssid = (const char *)ptr;
            return;
        }

        /* Skip to next parameter */
        ptr += param_length;
    }
}

static int parse_frame_addresses(zz_handler *zz, const struct pcap_pkthdr *packet_header,
                                 const struct ieee80211_mac_header *mac_header,
                                 struct zz_frame_addresses *frame) {
    memset(frame, 0, sizeof(*frame));

    if (!mac_header->from_ds && !mac_header->to_ds) {
        if (((const uint8_t *)mac_header)[0] != ZZ_FCF_BEACON) {
            return 0;
        }

        frame->is_beacon = 1;
        frame->destination = zz_mac_addr_from_array(mac_header->address_1);
        frame->source = zz_mac_addr_from_array(mac_header->address_2);
        frame->bssid = zz_mac_addr_from_array(mac_header->address_3);
        frame->station = 0;
        return 1;
    }

    if (mac_header->from_ds && !mac_header->to_ds) {
        frame->destination = zz_mac_addr_from_array(mac_header->address_1);
        frame->bssid = zz_mac_addr_from_array(mac_header->address_2);
        frame->source = zz_mac_addr_from_array(mac_header->address_3);
        frame->station = frame->destination;
        return 1;
    }

    if (mac_header->to_ds && !mac_header->from_ds) {
        frame->bssid = zz_mac_addr_from_array(mac_header->address_1);
        frame->source = zz_mac_addr_from_array(mac_header->address_2);
        frame->destination = zz_mac_addr_from_array(mac_header->address_3);
        frame->station = frame->source;
        return 1;
    }

    log_ts(zz, packet_header, "Skipping packet due to frame direction");
    return 0;
}

static int handle_beacon_frame(zz_handler *zz, const struct pcap_pkthdr *packet_header,
                               const uint8_t *packet, const uint8_t *cursor,
                               zz_bss *bss, const char *bssid_str, int is_beacon) {
    if (!is_beacon) {
        return 0;
    }

    if (!bss->has_beacon) {
        int ssid_length;
        const char *ssid;

        if (zz->dumper) {
            pcap_dump((u_char *)zz->dumper, packet_header, packet);
        }

        get_ssid(cursor + ZZ_BEACON_SSID_PARAMS_OFFSET,
                 packet_header->caplen - (cursor - packet),
                 &ssid, &ssid_length);
        memcpy(bss->ssid, ssid, ssid_length);
        bss->has_beacon = 1;
        zz_ssid_escape_sprint(bss->ssid, ssid, ssid_length);
        zz_out("BSS discovered %s $'%s'", bssid_str, bss->ssid);
    }

    return 1;
}

static int process_packet_outcome(zz_handler *zz, const struct pcap_pkthdr *packet_header,
                                  const uint8_t *packet, zz_bss *bss,
                                  const struct ieee8021x_authentication_header *authentication_header,
                                  zz_packet_outcome outcome,
                                  zz_mac_addr station, zz_mac_addr bssid,
                                  const char *station_str, const char *bssid_str) {
    const char *extra_info = "";

    if (outcome.ignore) {
        switch (outcome.ignore_reason) {
        case ZZ_IGNORE_REASON_RETRANSMISSION:
            log_ts(zz, packet_header, "%s @ %s $'%s' - Handshake message #%d (retransmission)",
                   station_str, bssid_str, bss->ssid, outcome.handshake_info);
            break;
        case ZZ_IGNORE_REASON_INVALID_EAPOL:
            log_ts(zz, packet_header, "%s @ %s $'%s' - Ignoring invalid key flags",
                   station_str, bssid_str, bss->ssid);
            break;
        case ZZ_IGNORE_REASON_INVALID_COUNTER:
            log_ts(zz, packet_header, "%s @ %s $'%s' - Ignoring invalid replay counter",
                   station_str, bssid_str, bss->ssid);
            break;
        }

        return 0;
    }

    if (outcome.dump_packet) {
        if (!authentication_header) {
            bss->n_data_packets++;
        }

        if (zz->dumper) {
            pcap_dump((u_char *)zz->dumper, packet_header, packet);
        }
    }

    if (outcome.new_client || outcome.track_client) {
        if (zz->setup.is_live && !zz->setup.is_passive) {
            if (!zz_killer_post_message(zz, &zz->killer, station, bssid, outcome)) {
                zz->is_done = 1;
                pcap_breakloop(zz->pcap);
                return 0;
            }
        }
    }

    if (outcome.track_client) {
        switch (outcome.track_reason) {
        case ZZ_TRACK_REASON_ALIVE:
            log_ts(zz, packet_header, "%s @ %s $'%s' - Activity detected again",
                   station_str, bssid_str, bss->ssid);
            break;
        case ZZ_TRACK_REASON_FIRST_HANDSHAKE:
            extra_info = " (first attempt detected)";
            break;
        case ZZ_TRACK_REASON_EXPIRATION:
            extra_info = " (causes restart due to expiration)";
            break;
        case ZZ_TRACK_REASON_INVALIDATION:
            extra_info = " (caused restart due to invalidation)";
            break;
        }
    }

    if (outcome.handshake_info) {
        log_ts(zz, packet_header, "%s @ %s $'%s' - Handshake message #%d%s",
               station_str, bssid_str, bss->ssid, outcome.handshake_info, extra_info);
    }

    if (outcome.new_client) {
        zz_out("New client %s @ %s $'%s'", station_str, bssid_str, bss->ssid);
    }

    if (outcome.got_handshake) {
        zz_out("^_^ Full handshake for %s @ %s $'%s'", station_str, bssid_str, bss->ssid);

        if (zz->setup.is_live && !zz->setup.is_passive) {
            if (!zz_killer_post_message(zz, &zz->killer, station, bssid, outcome)) {
                zz->is_done = 1;
                pcap_breakloop(zz->pcap);
                return 0;
            }
        }

        bss->n_handshakes++;
        if (zz_members_put(&bss->stations, station) == -1) {
            zz_log("Cannot record station membership for %s: %s",
                   bss->ssid, strerror(errno));
        }

        if (zz->setup.is_live && zz->setup.early_quit) {
            pcap_breakloop(zz->pcap);
        }
    }

    return 1;
}

/*
 * Check if a MAC address passes the include/exclude filters.
 * Implements configurable filter logic with optional order reversal.
 *
 * Filter logic:
 *   - If both include and exclude are present:
 *       - If exclude_first: allowed if (in include) OR (not in exclude)
 *       - Otherwise: allowed if (in include) AND (not in exclude)
 *   - If only include is present: allowed if in include (whitelist)
 *   - If only exclude is present: allowed if not in exclude (blacklist)
 *   - If neither is present: allowed (no filtering)
 *
 * The order can be controlled via -x option for fine-grained filtering.
 *
 * Parameters:
 *   mac_addr - MAC address to check
 *   exclude_first - Whether to apply exclude filter before include (0/1)
 *   include - Whitelist set (can be empty)
 *   exclude - Blacklist set (can be empty)
 *
 * Returns:
 *   1 if allowed, 0 if blocked
 */

/*
 * Main packet dissection callback.
 * This is the central function invoked by pcap_loop() for every captured packet.
 * It performs layer-by-layer parsing and delegates to the handshake state machine.
 *
 * Processing flow:
 *   1. Parse radiotap header (capture metadata)
 *   2. Parse 802.11 MAC header (frame type, addresses, flags)
 *   3. Determine frame direction and extract addresses:
 *      - Beacon: AP → broadcast
 *      - FromDS: AP → station (download)
 *      - ToDS: station → AP (upload)
 *   4. Apply BSSID filtering (whitelist/blacklist)
 *   5. Handle beacon frames (extract and save SSID)
 *   6. Apply station filtering
 *   7. Handle broadcast/multicast traffic
 *   8. Parse LLC+SNAP header (needed for EAPOL)
 *   9. Detect and parse EAPOL frames (WPA handshake messages)
 *  10. Call handshake state machine (zz_process_packet)
 *  11. Handle outcome: dump packets, track clients, update stats
 *
 * This function implements the BPF filter logic in user space, applying
 * additional filtering beyond what the kernel BPF does.
 *
 * Parameters:
 *   _zz - Opaque pointer to zz_handler (cast from u_char* for pcap callback)
 *   packet_header - Packet metadata (timestamp, capture length, wire length)
 *   packet - Raw packet data starting with radiotap header
 */
void zz_dissect_packet(u_char *_zz, const struct pcap_pkthdr *packet_header,
                       const uint8_t *packet) {
    zz_handler *zz = (zz_handler *)_zz;
    struct ieee80211_radiotap_header *radiotap_header;
    struct ieee80211_mac_header *mac_header;
    struct ieee8022_llc_snap_header *llc_snap_header;
    struct ieee8021x_authentication_header *authentication_header;
    char bssid_str[ZZ_MAC_ADDR_STRING_SIZE];
    char station_str[ZZ_MAC_ADDR_STRING_SIZE];
    struct zz_frame_addresses frame;
    const uint8_t *cursor;
    uint32_t safe_size;
    int bss_status;
    int is_eapol;
    zz_bss *bss;
    zz_packet_outcome outcome;

    /* Save the timestamp of the first packet as epoch (reference point).
     * All subsequent timestamps will be relative to this for readability. */
    if (!zz->epoch) {
        zz->epoch = TV_TO_SEC(packet_header->ts);
    }

    /* Phase 1: Parse radiotap header (variable-length capture metadata) */

    /* Verify minimum packet size for radiotap header */
    safe_size = sizeof(struct ieee80211_radiotap_header);
    if (packet_header->caplen < safe_size) {
        log_ts(zz, packet_header, "Skipping too short packet %u bytes", packet_header->caplen);
        return;
    }

    /* Start parsing from the beginning */
    cursor = packet;

    /* Extract radiotap header and skip past it (variable length) */
    radiotap_header = (struct ieee80211_radiotap_header *)cursor;
    cursor += le16toh(radiotap_header->length);

    /* Phase 2: Parse 802.11 MAC header */

    /* Verify packet has enough space for MAC header */
    safe_size = (cursor - packet) + sizeof(struct ieee80211_mac_header);
    if (packet_header->caplen < safe_size) {
        log_ts(zz, packet_header, "Skipping too short packet %u bytes", packet_header->caplen);
        return;
    }

    /* Extract MAC header and advance cursor.
     * QoS data frames have an additional 2-byte QoS control field. */
    mac_header = (struct ieee80211_mac_header *)cursor;
    cursor += sizeof(struct ieee80211_mac_header) +
              (cursor[0] == ZZ_FCF_QOS_DATA ? ZZ_QOS_CONTROL_SIZE : 0);

    if (!parse_frame_addresses(zz, packet_header, mac_header, &frame)) {
        return;
    }

    /* Phase 4: Prepare string representations for logging */
    zz_mac_addr_sprint(bssid_str, frame.bssid);
    zz_mac_addr_sprint(station_str, frame.station);

    /* Phase 5: Lookup or create BSS descriptor and apply BSSID filtering */
    bss_status = zz_bsss_lookup(zz, &zz->bsss, frame.bssid, &bss);
    if (bss_status == -1) {
        zz->is_done = 1;
        pcap_breakloop(zz->pcap);
        return;
    }

    /* Get or create the BSS structure for this access point.
     * On first encounter (lookup returns 1), check if this BSS passes filters. */
    if (bss_status == 1) {
        /* Determine if we should operate on this BSS based on include/exclude lists */
        bss->is_allowed = zz_members_filter_allows(frame.bssid,
            zz->setup.bssids_exclude_first,
            &zz->setup.included_bssids,
            &zz->setup.excluded_bssids);
    }

    /* Skip all traffic from filtered-out access points */
    if (!bss->is_allowed) {
        #ifdef DEBUG
        if (!frame.is_beacon) {
            log_ts(zz, packet_header, "%s @ %s $'%s' - Skipping excluded BSS traffic", station_str, bssid_str, bss->ssid);
        }
        #endif
        return;
    }

    /* Phase 6: Handle beacon frames (extract SSID) */

    if (handle_beacon_frame(zz, packet_header, packet, cursor, bss, bssid_str, frame.is_beacon)) {
        return;
    }

    /* Phase 7: Apply station filtering */

    /* Check if this station passes the include/exclude filters (-s/-S options) */
    if (!zz_members_filter_allows(frame.station,
            zz->setup.stations_exclude_first,
            &zz->setup.included_stations,
            &zz->setup.excluded_stations)) {
        log_ts(zz, packet_header, "%s @ %s $'%s' - Skipping excluded station", station_str, bssid_str, bss->ssid);
        return;
    }

    /* Phase 8: Handle broadcast/multicast traffic */

    /* Check if destination is broadcast (FF:FF:FF:FF:FF:FF) or multicast (bit 0 set) */
    if (frame.destination == ZZ_MAC_ADDR_BCAST ||
        frame.destination & ZZ_MAC_ADDR_MCAST_MASK) {

        /* Only dump group traffic if explicitly requested (-g option) and we
         * already have a handshake for this BSS (so we can decrypt it later).
         * This captures EAPOL group key messages and encrypted broadcast data. */
        if (zz->setup.dump_group_traffic && bss->n_handshakes > 0) {
            bss->n_data_packets++;

            if (zz->dumper) {
                pcap_dump((u_char *)zz->dumper, packet_header, packet);
            }
        }

        /* Group traffic doesn't contain handshake messages, so stop here */
        return;
    }

    /* Phase 9: Parse LLC+SNAP header and detect EAPOL frames */

    /* Extract LLC+SNAP header (IEEE 802.2 logical link control).
     * This encapsulates higher-layer protocols like EAPOL. */
    llc_snap_header = (struct ieee8022_llc_snap_header *)cursor;
    cursor += sizeof(struct ieee8022_llc_snap_header);

    /* Check if this is an EAPOL frame (WPA handshake message).
     * An EAPOL frame must have:
     *   1. Sufficient remaining packet length
     *   2. SNAP header with correct DSAP (0xAA), SSAP (0xAA), Control (0x03)
     *   3. EtherType set to EAPOL (0x888E) */
    safe_size = (cursor - packet) + sizeof(struct ieee8021x_authentication_header);
    is_eapol = (packet_header->caplen >= safe_size &&
                llc_snap_header->dsap == ZZ_DSAP_SNAP &&
                llc_snap_header->ssap == ZZ_SSAP_SNAP &&
                llc_snap_header->control == ZZ_CONTROL_SNAP &&
                llc_snap_header->type == htobe16(ZZ_EAPOL_ETHERTYPE));

    /* Extract EAPOL authentication header if present */
    if (is_eapol) {
        authentication_header = (struct ieee8021x_authentication_header *)cursor;
    } else {
        authentication_header = NULL;  /* Regular data frame (not EAPOL) */
    }

    /* Phase 10: Invoke handshake state machine */

    /* Process this packet through the state machine.
     * This tracks handshake progress, detects retransmissions, handles timeouts,
     * and determines what action to take. */
    outcome = zz_process_packet(zz, frame.station, frame.bssid, packet_header,
                                authentication_header);

    if (!process_packet_outcome(zz, packet_header, packet, bss, authentication_header,
                                outcome, frame.station, frame.bssid,
                                station_str, bssid_str)) {
        return;
    }
}
