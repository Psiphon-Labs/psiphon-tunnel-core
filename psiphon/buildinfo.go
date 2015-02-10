/*
 * Copyright (c) 2015, Psiphon Inc.
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

import "strings"

/*
These values should be filled in at build time using the `-X` option[1] to the
Go linker (probably via `-ldflags` option to `go build` -- like `-ldflags "-X var1 abc -X var2 xyz"`).
[1]: http://golang.org/cmd/ld/
Without those build flags, the build info in the notice will simply be empty strings.
Suggestions for how to fill in the values will be given for each variable.
*/
// -X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon.buildDate `date --iso-8601=seconds`
var buildDate string

// -X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon.buildRepo `git config --get remote.origin.url`
var buildRepo string

// -X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon.buildRev `git rev-parse HEAD`
var buildRev string

func NoticeBuildInfo() {
	NoticeInfo(
		"Built: %#v from %#v at rev %#v",
		strings.TrimSpace(buildDate),
		strings.TrimSpace(buildRepo),
		strings.TrimSpace(buildRev))
}
