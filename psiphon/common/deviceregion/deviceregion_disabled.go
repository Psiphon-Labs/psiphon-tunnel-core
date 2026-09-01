//go:build ios || android

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

// iOS and Android obtain the device region from getDeviceRegion in their
// respective mobile libraries, so the detection implemented in this package,
// along with its time zone tables, is left out of those builds. Get returns an
// empty region, which callers already handle: see deviceregion.go, which
// declares the API reproduced here and must be kept in agreement with it.

type Source string

type Detail struct {
	Region     string
	Source     Source
	Candidates map[Source]string
}

func Get() string {
	return ""
}

func GetDetail() Detail {
	return Detail{}
}
