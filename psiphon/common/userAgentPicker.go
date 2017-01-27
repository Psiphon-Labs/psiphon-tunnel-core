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

func UserAgentIfUnset(h http.Header) (http.Header, bool) {
	selectedUserAgent := false
	if _, ok := h["User-Agent"]; !ok {
		if h == nil {
			h = make(map[string][]string)
		}

		if FlipCoin() {
			h.Set("User-Agent", PickUserAgent())
		} else {
			h.Set("User-Agent", "")
		}

		selectedUserAgent = true
	}

	return h, selectedUserAgent
}
