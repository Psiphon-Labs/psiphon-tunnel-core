//go:build windows

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

package deviceregion

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// These are kernel32 National Language Support calls. They read per-user
// settings, require no permission, prompt no user, and are unrelated to the
// Windows location service.
//
// NewLazySystemDLL resolves from the system directory only, and each procedure
// is resolved with Find, so that a missing export yields no signal rather than
// preventing the binary from loading. GetUserDefaultGeoName in particular
// requires Windows 10 version 1709.
var (
	modkernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procGetUserDefaultGeoName         = modkernel32.NewProc("GetUserDefaultGeoName")
	procGetUserDefaultLocaleName      = modkernel32.NewProc("GetUserDefaultLocaleName")
	procGetDynamicTimeZoneInformation = modkernel32.NewProc("GetDynamicTimeZoneInformation")
)

// localeNameMaxLength is LOCALE_NAME_MAX_LENGTH.
const localeNameMaxLength = 85

// timeZoneIDInvalid is TIME_ZONE_ID_INVALID. The other return values, including
// TIME_ZONE_ID_UNKNOWN, all populate TimeZoneKeyName.
const timeZoneIDInvalid = 0xffffffff

// dynamicTimeZoneInformation is DYNAMIC_TIME_ZONE_INFORMATION.
//
// The dynamic form is required rather than TIME_ZONE_INFORMATION, which
// golang.org/x/sys/windows already wraps: only this one carries
// TimeZoneKeyName, the invariant registry key name such as "Tokyo Standard
// Time". StandardName and DaylightName are localized display names and are
// unusable as lookup keys.
type dynamicTimeZoneInformation struct {
	Bias                        int32
	StandardName                [32]uint16
	StandardDate                windows.Systemtime
	StandardBias                int32
	DaylightName                [32]uint16
	DaylightDate                windows.Systemtime
	DaylightBias                int32
	TimeZoneKeyName             [128]uint16
	DynamicDaylightTimeDisabled uint8
}

// A layout mismatch would silently read the wrong bytes rather than fail, and
// this package is often built without a Windows machine to test on, so the
// total size and the offset of the field actually read are both asserted at
// compile time.
var (
	_ [432]byte = [unsafe.Sizeof(dynamicTimeZoneInformation{})]byte{}
	_ [172]byte = [unsafe.Offsetof(dynamicTimeZoneInformation{}.TimeZoneKeyName)]byte{}
)

// platformSignals reads the home-location setting, time zone, and locale.
func platformSignals() rawSignals {
	return rawSignals{
		Geo:        userDefaultGeoName(),
		TimezoneID: dynamicTimeZoneKeyName(),
		LocaleName: userDefaultLocaleName(),
	}
}

// userDefaultGeoName returns the user's home location, an ISO 3166-1 alpha-2
// code, or a UN M.49 numeric code for a region that is not a country. The
// numeric form is rejected by parseRegionCode.
func userDefaultGeoName() string {

	if procGetUserDefaultGeoName.Find() != nil {
		return ""
	}

	// A geographic name is at most a few characters; GEO_NAME values are two
	// letters or three digits.
	buffer := make([]uint16, 16)

	result, _, _ := procGetUserDefaultGeoName.Call(
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)))

	if result == 0 {
		return ""
	}

	return windows.UTF16ToString(buffer)
}

// userDefaultLocaleName returns the user's default locale name, such as
// "en-CA".
func userDefaultLocaleName() string {

	if procGetUserDefaultLocaleName.Find() != nil {
		return ""
	}

	buffer := make([]uint16, localeNameMaxLength)

	result, _, _ := procGetUserDefaultLocaleName.Call(
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)))

	if result == 0 {
		return ""
	}

	return windows.UTF16ToString(buffer)
}

// dynamicTimeZoneKeyName returns the invariant time zone key name, such as
// "Tokyo Standard Time".
func dynamicTimeZoneKeyName() string {

	if procGetDynamicTimeZoneInformation.Find() != nil {
		return ""
	}

	var information dynamicTimeZoneInformation

	result, _, _ := procGetDynamicTimeZoneInformation.Call(
		uintptr(unsafe.Pointer(&information)))

	if result == timeZoneIDInvalid {
		return ""
	}

	return windows.UTF16ToString(information.TimeZoneKeyName[:])
}
