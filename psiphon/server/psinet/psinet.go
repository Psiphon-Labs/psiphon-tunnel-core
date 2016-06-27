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

// Package psiphon/server/psinet implements psinet database services. The psinet
// database is a JSON-format file containing information about the Psiphon network,
// including sponsors, home pages, stats regexes, available upgrades, and other
// servers for discovery. This package also implements the Psiphon discovery algorithm.
package psinet

import (
	"sync"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
)

// Database serves Psiphon API data requests. It's safe for
// concurrent usage. The Reload function supports hot reloading
// of Psiphon network data while the server is running.
type Database struct {
	sync.RWMutex

	// TODO: implement
}

// NewDatabase initializes a Database, calling Load on the specified
// filename.
func NewDatabase(filename string) (*Database, error) {

	database := &Database{}

	err := database.Reload(filename)
	if err != nil {
		return nil, psiphon.ContextError(err)
	}

	return database, nil
}

// Reload [re]initializes the Database with the Psiphon network data
// in the specified file. This function obtains a write lock on
// the database, blocking all readers.
// The input "" is valid and initializes a functional Database
// with no data. When Reload fails, the previous Database state is
// retained.
func (db *Database) Reload(filename string) error {
	db.Lock()
	defer db.Unlock()

	// TODO: implement

	return nil
}

// GetHomepages returns a list of  home pages for the specified sponsor,
// region, and platform.
func (db *Database) GetHomepages(sponsorID, clientRegion, clientPlatform string) []string {
	db.RLock()
	defer db.RUnlock()

	// TODO: implement

	return make([]string, 0)
}

// GetUpgradeClientVersion returns a new client version when an upgrade is
// indicated for the specified client current version. The result is "" when
// no upgrade is available.
func (db *Database) GetUpgradeClientVersion(clientVersion, clientPlatform string) string {
	db.RLock()
	defer db.RUnlock()

	// TODO: implement

	return ""
}

// GetHttpsRequestRegexes returns bytes transferred stats regexes for the
// specified sponsor.
func (db *Database) GetHttpsRequestRegexes(sponsorID string) []map[string]string {
	db.RLock()
	defer db.RUnlock()

	return make([]map[string]string, 0)
}

// DiscoverServers selects new encoded server entries to be "discovered" by
// the client, using the discoveryValue as the input into the discovery algorithm.
func (db *Database) DiscoverServers(propagationChannelID string, discoveryValue int) []string {
	db.RLock()
	defer db.RUnlock()

	// TODO: implement

	return make([]string, 0)
}
