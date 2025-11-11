/*
 * ieee802.h - IEEE 802.11 protocol definitions and utilities
 *
 * This file contains structure definitions, constants, and utility functions
 * for working with IEEE 802.11 (Wi-Fi) frames, including:
 *   - Radiotap headers (capture metadata)
 *   - IEEE 802.11 MAC headers
 *   - LLC/SNAP headers
 *   - 802.1X EAPOL authentication frames (WPA handshake)
 *   - Deauthentication frames
 *   - MAC address manipulation functions
 */

#ifndef ZZ_IEEE_802_H
#define ZZ_IEEE_802_H

#include <stdint.h>

#include "endian.h"

/* Size of a MAC address string in format "XX:XX:XX:XX:XX:XX\0" */
#define ZZ_MAC_ADDR_STRING_SIZE 18
#define ZZ_QOS_CONTROL_SIZE 2

/* Special MAC address values */
#define ZZ_MAC_ADDR_BCAST      0xffffffffffffULL  /* Broadcast: ff:ff:ff:ff:ff:ff */
#define ZZ_MAC_ADDR_MCAST_MASK (1ULL << 40)       /* Bit indicating multicast address */

/* Frame Control Field (FCF) type/subtype combinations
 * These are the combined type+subtype values from the first byte of FCF */
#define ZZ_FCF_BEACON           0x80  /* Management: Beacon frame */
#define ZZ_FCF_DATA             0x08  /* Data: Standard data frame */
#define ZZ_FCF_QOS_DATA         0x88  /* Data: QoS data frame */
#define ZZ_FCF_DEAUTHENTICATION 0xc0  /* Management: Deauthentication frame */

/* LLC/SNAP header constants for identifying SNAP encapsulation
 * SNAP is used to carry protocols like EAPOL over 802.11 */
#define ZZ_DSAP_SNAP    0xaa  /* Destination Service Access Point */
#define ZZ_SSAP_SNAP    0xaa  /* Source Service Access Point */
#define ZZ_CONTROL_SNAP 0x03  /* Control field value for SNAP */

/* Beacon frame SSID extraction constants */
#define ZZ_BEACON_SSID_PARAMS_OFFSET 0x0c  /* Offset to tagged parameters section */
#define ZZ_BEACON_SSID_PARAM_TYPE    0x00  /* Tag number for SSID element */
#define ZZ_BEACON_MAX_SSID_LENGTH    0xff  /* Max SSID length (spec says 32, but we handle up to 255) */
/* SSID characters may need escaping (\xHH format), so max escaped length is 4x */
#define ZZ_BEACON_MAX_SSID_ESCAPED_LENGTH  ZZ_BEACON_MAX_SSID_LENGTH * 4

/* EAPOL (Extensible Authentication Protocol over LAN) constants
 * Used for WPA/WPA2 4-way handshake detection */
#define ZZ_EAPOL_ETHERTYPE 0x888e /* EtherType for EAPOL frames (network byte order) */

/* EAPOL key information field masks and expected values for each handshake message.
 * These are used to identify which of the 4 handshake messages a frame represents.
 * The key_info field contains flags like: key_type, install, ack, mic, secure, etc. */
#define ZZ_EAPOL_MASK_1  0x1fc8 /* 0b0001111111001000 - Mask for message 1 */
#define ZZ_EAPOL_MASK_2  0x1fc8 /* 0b0001111111001000 - Mask for message 2 */
#define ZZ_EAPOL_MASK_3  0x1f88 /* 0b0001111110001000 - Mask for message 3 */
#define ZZ_EAPOL_MASK_4  0x1fc8 /* 0b0001111111001000 - Mask for message 4 */

#define ZZ_EAPOL_FLAGS_1 0x0088 /* 0b0000000010001000 - Expected flags for message 1 (from AP) */
#define ZZ_EAPOL_FLAGS_2 0x0108 /* 0b0000000100001000 - Expected flags for message 2 (from STA) */
#define ZZ_EAPOL_FLAGS_3 0x1388 /* 0b0001001110001000 - Expected flags for message 3 (from AP) */
#define ZZ_EAPOL_FLAGS_4 0x0308 /* 0b0000001100001000 - Expected flags for message 4 (from STA) */

/* Deauthentication frame construction helpers */
#define ZZ_DEAUTHENTICATION_SEQUENCE(x) (((x) & ((1 << 12) - 1)) << 4)  /* Encode sequence number */
#define ZZ_DEAUTHENTICATION_REASON      0x07  /* Reason code: Class 3 frame from non-associated STA */

/* MAC address type: stored as 48-bit value in a 64-bit integer */
typedef uint64_t zz_mac_addr;

/*
 * Radiotap header - capture metadata prepended by the wireless driver
 * This header is always in little-endian byte order regardless of platform.
 * It contains information about the capture (signal strength, channel, etc.)
 * and its length varies based on which fields are present.
 */
struct ieee80211_radiotap_header {
    uint8_t version;     /* Radiotap version (currently 0) */
    uint8_t padding;     /* Padding for alignment */
    uint16_t length;     /* Total length of radiotap header including all fields */
    uint32_t present;    /* Bitmask indicating which optional fields are present */
}
__attribute__((__packed__));

/*
 * IEEE 802.11 MAC header - the main wireless frame header
 * Contains frame control information and up to 4 MAC addresses depending on
 * the to_ds and from_ds flags (distribution system flags).
 * This structure covers the fixed portion; QoS and other extensions follow.
 */
struct ieee80211_mac_header {
    /* Frame Control Field (FCF) - first 2 bytes define frame type and flags */
    uint8_t version:2;           /* Protocol version (always 0 for current 802.11) */
    uint8_t type:2;              /* Frame type: 00=management, 01=control, 10=data */
    uint8_t sub_type:4;          /* Frame subtype (beacon, data, deauth, etc.) */
    uint8_t to_ds:1;             /* Frame going to distribution system (to AP) */
    uint8_t from_ds:1;           /* Frame coming from distribution system (from AP) */
    uint8_t more_fragments:1;    /* More fragments follow this one */
    uint8_t retry:1;             /* Frame is a retransmission */
    uint8_t power_management:1;  /* Station is in power-save mode */
    uint8_t more_data:1;         /* More data buffered for this station */
    uint8_t wep:1;               /* Frame is encrypted (WEP/WPA/WPA2) */
    uint8_t order:1;             /* Strictly ordered flag */

    uint16_t duration;           /* Duration/ID field (microseconds or association ID) */
    uint8_t address_1[6];        /* Receiver address (destination) */
    uint8_t address_2[6];        /* Transmitter address (source) */
    uint8_t address_3[6];        /* Filtering address (BSSID or other) */
    uint16_t sequence_control;   /* Fragment and sequence numbers */
}
__attribute__((__packed__));

/*
 * IEEE 802.2 LLC/SNAP header - used to encapsulate higher-layer protocols
 * SNAP (Subnetwork Access Protocol) allows carrying protocols like EAPOL
 * over 802.11 frames. The LLC portion should be 0xaa 0xaa 0x03 for SNAP.
 */
struct ieee8022_llc_snap_header {
    /* LLC (Logical Link Control) header */
    uint8_t dsap;       /* Destination SAP (should be 0xaa for SNAP) */
    uint8_t ssap;       /* Source SAP (should be 0xaa for SNAP) */
    uint8_t control;    /* Control field (should be 0x03 for SNAP) */

    /* SNAP header */
    uint8_t oui[3];     /* Organizationally Unique Identifier (usually 0x000000) */
    uint16_t type;      /* EtherType (0x888e for EAPOL/802.1X authentication) */
}
__attribute__((__packed__));

/*
 * IEEE 802.1X EAPOL-Key frame header - used for WPA/WPA2 4-way handshake
 * This structure contains the EAPOL authentication information including
 * nonces, replay counters, and MIC (Message Integrity Code) used to
 * derive and verify the Pairwise Transient Key (PTK).
 */
struct ieee8021x_authentication_header {
    uint8_t version;            /* EAPOL protocol version */
    uint8_t type;               /* EAPOL packet type (3 = EAPOL-Key) */
    uint16_t length;            /* Length of EAPOL payload */
    uint8_t descriptor_type;    /* Key descriptor type (2 = EAPOL RSN) */
    uint16_t flags;             /* Key information flags (used to identify handshake message 1-4) */
    uint16_t key_length;        /* Length of the PTK in bytes */
    uint64_t replay_counter;    /* Replay counter to detect retransmissions */
    uint8_t key_nonce[32];      /* Random nonce (ANonce from AP, SNonce from STA) */
    uint8_t key_iv[16];         /* EAPOL-Key IV (initialization vector) */
    uint8_t key_rsc[8];         /* Receive sequence counter */
    uint8_t reserved[8];        /* Reserved field */
    uint8_t key_mic[16];        /* Message Integrity Code for frame authentication */
    uint16_t key_data_length;   /* Length of key data field that follows */
}
__attribute__((__packed__));

/*
 * IEEE 802.11 Deauthentication frame payload
 * Contains only the reason code explaining why the deauthentication occurred.
 * This comes after the standard MAC header.
 */
struct ieee80211_deauthentication_header {
    uint16_t reason;  /* Reason code for deauthentication */
}
__attribute__((__packed__));

/*
 * Convert a 6-byte MAC address array to internal zz_mac_addr format
 * Parameters:
 *   array - 6-byte MAC address in network byte order
 * Returns:
 *   MAC address as 64-bit integer
 */
zz_mac_addr zz_mac_addr_from_array(const uint8_t *array);

/*
 * Convert internal zz_mac_addr format to 6-byte array
 * Parameters:
 *   octets - Output buffer (must be at least 6 bytes)
 *   addr - MAC address as 64-bit integer
 */
void zz_mac_addr_to_array(uint8_t *octets, zz_mac_addr addr);

/*
 * Format a MAC address as a string "XX:XX:XX:XX:XX:XX"
 * Parameters:
 *   buffer - Output buffer (must be at least ZZ_MAC_ADDR_STRING_SIZE bytes)
 *   addr - MAC address to format
 */
void zz_mac_addr_sprint(char *buffer, zz_mac_addr addr);

/*
 * Parse a MAC address from a string with optional mask
 * Supports formats: "XX:XX:XX:XX:XX:XX" or "XX:XX:XX:XX:XX:XX/YY:YY:YY:YY:YY:YY"
 * Parameters:
 *   addr - Output MAC address
 *   buffer - Input string to parse
 *   terminators - String of characters that mark end of MAC address
 * Returns:
 *   1 on success, 0 on parse error
 */
int zz_mac_addr_sscan(zz_mac_addr *addr, const char *buffer, const char *terminators);

/*
 * Escape non-printable characters in SSID for safe display
 * Non-printable characters are converted to \xHH hexadecimal format
 * Parameters:
 *   buffer - Output buffer (must be at least ZZ_BEACON_MAX_SSID_ESCAPED_LENGTH + 1)
 *   ssid - Input SSID string (may contain binary data)
 *   ssid_length - Length of SSID in bytes
 */
void zz_ssid_escape_sprint(char *buffer, const char *ssid, int ssid_length);

#endif
