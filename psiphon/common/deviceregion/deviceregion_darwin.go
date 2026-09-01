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

package deviceregion

/*
#cgo LDFLAGS: -framework CoreFoundation

#include <CoreFoundation/CoreFoundation.h>

// Values from CFLocaleCopyCurrent and CFTimeZoneCopySystem are owned and
// released here. Values from CFLocaleGetValue, CFLocaleGetIdentifier, and
// CFTimeZoneGetName are unowned and must not be released.

static int deviceRegionCopyString(CFStringRef s, char *buffer, int length) {
    if (s == NULL) {
        return 0;
    }
    return CFStringGetCString(s, buffer, length, kCFStringEncodingUTF8) ? 1 : 0;
}

static int deviceRegionLocaleIdentifier(char *buffer, int length) {
    CFLocaleRef locale = CFLocaleCopyCurrent();
    if (locale == NULL) {
        return 0;
    }
    int ok = deviceRegionCopyString(CFLocaleGetIdentifier(locale), buffer, length);
    CFRelease(locale);
    return ok;
}

static int deviceRegionCountryCode(char *buffer, int length) {
    CFLocaleRef locale = CFLocaleCopyCurrent();
    if (locale == NULL) {
        return 0;
    }
    int ok = deviceRegionCopyString(
        (CFStringRef)CFLocaleGetValue(locale, kCFLocaleCountryCode), buffer, length);
    CFRelease(locale);
    return ok;
}

static int deviceRegionTimeZoneName(char *buffer, int length) {
    CFTimeZoneRef timeZone = CFTimeZoneCopySystem();
    if (timeZone == NULL) {
        return 0;
    }
    int ok = deviceRegionCopyString(CFTimeZoneGetName(timeZone), buffer, length);
    CFRelease(timeZone);
    return ok;
}
*/
import "C"

import "unsafe"

// platformSignals reads the time zone and locale via Core Foundation. This file
// serves both macOS and iOS, as the ios target implies darwin.
//
// Core Foundation is preferred over the POSIX environment because an
// application launched from Finder inherits no LANG. The POSIX readings remain
// as a fallback, and are the sole source when cgo is disabled and this file is
// excluded; see deviceregion_other.go.
func platformSignals() rawSignals {
	return darwinSignals(cfTimeZoneName(), cfLocaleIdentifier(), cfCountryCode())
}

// darwinSignals applies the fallbacks to the Core Foundation readings. It is
// separate from platformSignals, and takes the readings as arguments, so that
// the fallback order is testable on a machine where Core Foundation succeeds.
func darwinSignals(cfTimeZone, cfLocale, cfCountry string) rawSignals {

	timezoneID := cfTimeZone
	if _, ok := regionFromTimezoneID(timezoneID); !ok {
		timezoneID = posixTimezoneID()
	}

	localeName := cfLocale

	// The locale identifier normally carries the region, as in "en_CA". When it
	// does not, the region setting is still available on its own, expressed
	// here as a BCP 47 tag with an undetermined language.
	if _, ok := regionFromLocaleName(localeName); !ok {
		if code := cfCountry; code != "" {
			localeName = "und-" + code
		}
	}

	if _, ok := regionFromLocaleName(localeName); !ok {
		localeName = posixLocaleName()
	}

	return rawSignals{
		TimezoneID: timezoneID,
		LocaleName: localeName,
	}
}

func cfTimeZoneName() string {
	return cfString(128, func(buffer *C.char, length C.int) C.int {
		return C.deviceRegionTimeZoneName(buffer, length)
	})
}

func cfLocaleIdentifier() string {
	return cfString(128, func(buffer *C.char, length C.int) C.int {
		return C.deviceRegionLocaleIdentifier(buffer, length)
	})
}

func cfCountryCode() string {
	return cfString(16, func(buffer *C.char, length C.int) C.int {
		return C.deviceRegionCountryCode(buffer, length)
	})
}

// cfString runs one of the Core Foundation accessors above into a buffer and
// returns the resulting C string.
func cfString(length int, call func(*C.char, C.int) C.int) string {

	buffer := make([]byte, length)

	if call((*C.char)(unsafe.Pointer(&buffer[0])), C.int(len(buffer))) != 1 {
		return ""
	}

	for i, b := range buffer {
		if b == 0 {
			return string(buffer[:i])
		}
	}

	return string(buffer)
}
