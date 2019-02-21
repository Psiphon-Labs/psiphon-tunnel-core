/*
 * Copyright (c) 2019, Psiphon Inc.
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

package server

import (
	"sync/atomic"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
)

var registeredSSHServerVersionPicker atomic.Value

func RegisterSSHServerVersionPicker(picker func(*prng.Seed) string) {
	registeredSSHServerVersionPicker.Store(picker)
}

func pickSSHServerVersion(seed *prng.Seed) string {
	picker := registeredSSHServerVersionPicker.Load()
	if picker != nil {
		return picker.(func(*prng.Seed) string)(seed)
	}
	return ""
}
