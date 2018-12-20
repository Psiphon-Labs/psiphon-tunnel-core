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

package psiphon

import (
	"net/http"
	"sync/atomic"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
)

var registeredUserAgentPicker atomic.Value

func RegisterUserAgentPicker(picker func() string) {
	registeredUserAgentPicker.Store(picker)
}

func pickUserAgent() string {
	picker := registeredUserAgentPicker.Load()
	if picker != nil {
		return picker.(func() string)()
	}
	return ""
}

// PickUserAgentIfUnset selects a User-Agent header if one is not set.
func PickUserAgentIfUnset(
	p *parameters.ClientParametersSnapshot, headers http.Header) (bool, string) {

	if _, ok := headers["User-Agent"]; !ok {

		userAgent := ""
		if p.WeightedCoinFlip(parameters.PickUserAgentProbability) {
			userAgent = pickUserAgent()
		}

		return true, userAgent
	}

	return false, ""
}
