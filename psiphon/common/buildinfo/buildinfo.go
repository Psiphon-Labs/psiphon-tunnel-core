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

package buildinfo

import (
	"strings"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/values"
)

/*
These values should be filled in at build time using the `-X` option[1] to the
Go linker (probably via `-ldflags` option to `go build` -- like `-ldflags "-X var1=abc -X var2=xyz"`).
[1]: http://golang.org/cmd/ld/
Without those build flags, the build info in the notice will simply be empty strings.
Suggestions for how to fill in the values will be given for each variable.
Note that any passed value must contain no whitespace.
*/
// -X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/buildinfo.buildDate=`date --iso-8601=seconds`
var buildDate string

// -X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/buildinfo.buildRepo=`git config --get remote.origin.url`
var buildRepo string

// -X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/buildinfo.buildRev=`git rev-parse --short HEAD`
var buildRev string

// -X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/buildinfo.goVersion=`go version | perl -ne '/go version (.*?) / && print $1'`
var goVersion string

// BuildInfo captures relevant build information here for use in clients or servers
type BuildInfo struct {
	BuildDate string `json:"buildDate"`
	BuildRepo string `json:"buildRepo"`
	BuildRev  string `json:"buildRev"`
	GoVersion string `json:"goVersion"`
	ValuesRev string `json:"valuesRev"`
}

// ToMap converts 'BuildInfo' struct to 'map[string]interface{}'
func (bi *BuildInfo) ToMap() map[string]interface{} {

	buildInfoMap := map[string]interface{}{
		"buildDate": bi.BuildDate,
		"buildRepo": bi.BuildRepo,
		"buildRev":  bi.BuildRev,
		"goVersion": bi.GoVersion,
		"valuesRev": bi.ValuesRev,
	}

	return buildInfoMap
}

// GetBuildInfo returns an instance of the BuildInfo struct
func GetBuildInfo() *BuildInfo {

	buildInfo := BuildInfo{
		BuildDate: strings.TrimSpace(buildDate),
		BuildRepo: strings.TrimSpace(buildRepo),
		BuildRev:  strings.TrimSpace(buildRev),
		GoVersion: strings.TrimSpace(goVersion),
		ValuesRev: values.GetRevision(),
	}

	return &buildInfo
}
