/*
 * Copyright (c) 2016, Psiphon Inc.
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

// PsinetDatabase serves Psiphon API data requests. It's safe for
// concurrent usage.
type PsinetDatabase struct {
}

// NewPsinetDatabase initializes a PsinetDatabase. It loads the specified
// file, which should be in the Psiphon automation jsonpickle format, and
// prepares to serve data requests.
// The input "" is valid and returns a functional PsinetDatabase with no
// data.
func NewPsinetDatabase(filename string) (*PsinetDatabase, error) {

	// TODO: implement

	return &PsinetDatabase{}, nil
}

// GetHomepages returns a list of  home pages for the specified sponsor,
// region, and platform.
func (psinet *PsinetDatabase) GetHomepages(sponsorID, clientRegion, clientPlatform string) []string {

	// TODO: implement

	return make([]string, 0)
}

// GetUpgradeClientVersion returns a new client version when an upgrade is
// indicated for the specified client current version. The result is "" when
// no upgrade is available.
func (psinet *PsinetDatabase) GetUpgradeClientVersion(clientVersion, clientPlatform string) string {

	// TODO: implement

	return ""
}

// GetHttpsRequestRegexes returns bytes transferred stats regexes for the
// specified sponsor.
func (psinet *PsinetDatabase) GetHttpsRequestRegexes(sponsorID string) []map[string]string {

	return make([]map[string]string, 0)
}

// DiscoverServers selects new encoded server entries to be "discovered" by
// the client, using the discoveryValue as the input into the discovery algorithm.
func (psinet *PsinetDatabase) DiscoverServers(propagationChannelID string, discoveryValue int) []string {

	// TODO: implement

	return make([]string, 0)
}
