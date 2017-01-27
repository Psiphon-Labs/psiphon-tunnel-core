/*
 * Copyright (c) 2017, Psiphon Inc.
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

package common

import (
	"net/http"
	"sync/atomic"
)

var registeredUserAgentPicker atomic.Value

func RegisterUserAgentPicker(generator func() string) {
	registeredUserAgentPicker.Store(generator)
}

func PickUserAgent() string {
	generator := registeredUserAgentPicker.Load()
	if generator != nil {
		return generator.(func() string)()
	}
	return ""
}

// UserAgentIfUnset returns an http.Header object and a boolean
// representing whether or not its User-Agent header was modified.
// Any modifications are made to a copy of the original header map
func UserAgentIfUnset(h http.Header) (http.Header, bool) {
	var dialHeaders http.Header

	if _, ok := h["User-Agent"]; !ok {
		dialHeaders = make(map[string][]string)

		if h != nil {
			for k, v := range h {
				dialHeaders[k] = v
			}
		}

		if FlipCoin() {
			dialHeaders.Set("User-Agent", PickUserAgent())
		} else {
			dialHeaders.Set("User-Agent", "")
		}

		return dialHeaders, true
	}

	return h, false
}
