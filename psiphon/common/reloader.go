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

package common

import (
	"hash/crc64"
	"io/ioutil"
	"sync"
)

// Reloader represents a read-only, in-memory reloadable data object. For example,
// a JSON data file that is loaded into memory and accessed for read-only lookups;
// and from time to time may be reloaded from the same file, updating the memory
// copy.
type Reloader interface {

	// Reload reloads the data object. Reload returns a flag indicating if the
	// reloadable target has changed and reloaded or remains unchanged. By
	// convention, when reloading fails the Reloader should revert to its previous
	// in-memory state.
	Reload() (bool, error)

	// WillReload indicates if the data object is capable of reloading.
	WillReload() bool

	// LogDescription returns a description to be used for logging
	// events related to the Reloader.
	LogDescription() string
}

// ReloadableFile is a file-backed Reloader. This type is intended to be embedded
// in other types that add the actual reloadable data structures.
//
// ReloadableFile has a multi-reader mutex for synchronization. Its Reload() function
// will obtain a write lock before reloading the data structures. The actual reloading
// action is to be provided via the reloadAction callback, which receives the content
// of reloaded files and must process the new data (for example, unmarshall the contents
// into data structures). All read access to the data structures should be guarded by
// RLocks on the ReloadableFile mutex.
//
// reloadAction must ensure that data structures revert to their previous state when
// a reload fails.
//
type ReloadableFile struct {
	sync.RWMutex
	fileName     string
	checksum     uint64
	reloadAction func([]byte) error
}

// NewReloadableFile initializes a new ReloadableFile
func NewReloadableFile(
	fileName string,
	reloadAction func([]byte) error) ReloadableFile {

	return ReloadableFile{
		fileName:     fileName,
		reloadAction: reloadAction,
	}
}

// WillReload indicates whether the ReloadableFile is capable
// of reloading.
func (reloadable *ReloadableFile) WillReload() bool {
	return reloadable.fileName != ""
}

var crc64table = crc64.MakeTable(crc64.ISO)

// Reload checks if the underlying file has changed and, when changed, invokes
// the reloadAction callback which should reload the in-memory data structures.
//
// In some case (e.g., traffic rules and OSL), there are penalties associated
// with proceeding with reload, so care is taken to not invoke the reload action
// unless the contents have changed.
//
// The file content is loaded and a checksum is taken to determine whether it
// has changed. Neither file size (may not change when content changes) nor
// modified date (may change when identical file is repaved) is a sufficient
// indicator.
//
// All data structure readers should be blocked by the ReloadableFile mutex.
//
// Reload must not be called from multiple concurrent goroutines.
func (reloadable *ReloadableFile) Reload() (bool, error) {

	if !reloadable.WillReload() {
		return false, nil
	}

	// Check whether the file has changed _before_ blocking readers

	reloadable.RLock()
	fileName := reloadable.fileName
	previousChecksum := reloadable.checksum
	reloadable.RUnlock()

	content, err := ioutil.ReadFile(fileName)
	if err != nil {
		return false, ContextError(err)
	}

	checksum := crc64.Checksum(content, crc64table)

	if checksum == previousChecksum {
		return false, nil
	}

	// ...now block readers

	reloadable.Lock()
	defer reloadable.Unlock()

	err = reloadable.reloadAction(content)
	if err != nil {
		return false, ContextError(err)
	}

	reloadable.checksum = checksum

	return true, nil
}

func (reloadable *ReloadableFile) LogDescription() string {
	return reloadable.fileName
}
