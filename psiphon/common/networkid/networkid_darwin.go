//go:build darwin && !ios && cgo

/*
 * Copyright (c) 2026, Psiphon Inc.
 * All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package networkid

// There is deliberately no darwin && !cgo implementation. Distinguishing Wi-Fi
// from wired requires the SIOCGIFMEDIA ioctl, and no libc-routed ioctl in
// golang.org/x/sys/unix can carry struct ifmediareq. The only pure-Go path is
// its generic Syscall, which makes a direct SVC kernel trap. A pure-Go build
// could still name match VPN interfaces, but would report UNKNOWN for every
// physical network, so darwin without cgo falls back to networkid_disabled.go.

/*
#include <errno.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <unistd.h>

// The ioctl is issued here, rather than with golang.org/x/sys/unix, as that
// package exports no libc-routed ioctl able to carry struct ifmediareq, and its
// generic Syscall makes a direct SVC kernel trap. This also leaves the layout of
// ifmediareq, declared under #pragma pack(4), to the compiler.
//
// Returns 0 on success, storing the current media word, or errno on failure.
static int networkIDInterfaceMedia(const char *interfaceName, int *media) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return errno;
    }

    struct ifmediareq req;
    memset(&req, 0, sizeof(req));
    strlcpy(req.ifm_name, interfaceName, sizeof(req.ifm_name));

    int err = 0;
    if (ioctl(fd, SIOCGIFMEDIA, &req) < 0) {
        err = errno;
    } else {
        *media = req.ifm_current;
    }

    close(fd);
    return err;
}
*/
import "C"

import (
	"net"
	"syscall"
	"unsafe"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
)

// Values from <net/if_media.h>, which is defined in Go as the iOS SDKs omit
// that header while still providing struct ifmediareq and SIOCGIFMEDIA.
const (
	ifmEther     = int32(0x00000020)
	ifmIEEE80211 = int32(0x00000080)
	ifmNmask     = int32(0x000000e0)
)

// getConnectionType returns the connection type ("WIRED", "WIFI", "VPN") of the
// network reached through the given interface, or "UNKNOWN".
//
// "MOBILE" is never reported, as <net/if_media.h> defines no cellular media
// type: a tethered device on macOS presents as ethernet, and an iOS cellular
// interface has no media type at all.
func getConnectionType(iface *net.Interface) string {

	if isVPNInterfaceName(iface.Name) {
		return "VPN"
	}

	media, err := getInterfaceMedia(iface.Name)
	if err != nil {
		return "UNKNOWN"
	}

	return connectionTypeFromMedia(media)
}

func connectionTypeFromMedia(media int32) string {
	switch media & ifmNmask {
	case ifmIEEE80211:
		return "WIFI"
	case ifmEther:
		return "WIRED"
	}
	return "UNKNOWN"
}

func getInterfaceMedia(interfaceName string) (int32, error) {

	name := C.CString(interfaceName)
	defer C.free(unsafe.Pointer(name))

	var media C.int

	if errno := C.networkIDInterfaceMedia(name, &media); errno != 0 {
		return 0, errors.Trace(syscall.Errno(errno))
	}

	return int32(media), nil
}
