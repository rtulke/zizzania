/*
 * iface.c - Network interface configuration
 *
 * Platform-specific code for setting the wireless channel on the capture
 * interface. Linux uses ioctl() with wireless extensions; macOS is not
 * supported and requires manual channel configuration.
 */

#ifdef __APPLE__

/* macOS implementation */

#include <errno.h>

#include "handler.h"

/*
 * Set wireless channel (macOS version).
 * Channel switching is not supported on macOS through this interface.
 * Users must manually configure the channel using the airport utility:
 *   sudo airport --channel=<N>
 *
 * Parameters:
 *   zz - Handler (not used on macOS)
 *
 * Returns:
 *   Always returns 0 (not supported), sets errno to ENOTSUP
 */
int zz_set_channel(zz_handler *zz) {
    errno = ENOTSUP;  /* Operation not supported */
    return 0;
}

#else

/* Linux implementation */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <linux/if.h>
#include <linux/wireless.h>

#include "handler.h"

/*
 * Set wireless channel using ioctl() and wireless extensions.
 * This is a helper function that performs the actual ioctl call.
 *
 * Parameters:
 *   fd - Socket file descriptor for ioctl
 *   iface - Network interface name (e.g., "wlan0")
 *   channel - Wi-Fi channel number (1-14 for 2.4GHz, 36+ for 5GHz)
 *
 * Returns:
 *   1 on success, 0 on failure
 */
static int iwreq_freq(int fd, const char *iface, int channel) {
    struct iwreq iwreq;

    /* Prepare the wireless request structure */
    memset(&iwreq, 0, sizeof(struct iwreq));
    strncpy(iwreq.ifr_name, iface, IFNAMSIZ);
    iwreq.u.freq.m = channel;  /* Channel number */
    iwreq.u.freq.e = 0;        /* Exponent (0 means channel number, not frequency) */

    /* Execute the ioctl to set the frequency/channel */
    return (ioctl(fd, SIOCSIWFREQ, &iwreq) == 0);
}

/*
 * Set wireless channel (Linux version).
 * Opens a socket and uses ioctl() with SIOCSIWFREQ to configure the
 * wireless interface channel. Requires the interface to be in monitor mode.
 *
 * Parameters:
 *   zz - Handler containing interface name and target channel
 *
 * Returns:
 *   1 on success, 0 on failure
 */
int zz_set_channel(zz_handler *zz) {
    int fd;

    /* Sanity checks: must be live capture with valid channel */
    if (!zz->setup.is_live || zz->setup.channel <= 0) {
        errno = EINVAL;
        return 0;
    }

    /* Open a socket for ioctl communication */
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        return 0;
    }

    /* Set the channel and return the result */
    {
        int result = iwreq_freq(fd, zz->setup.input, zz->setup.channel);
        close(fd);
        return result;
    }
}

#endif
