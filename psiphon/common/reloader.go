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
	"os"
	"sync"
)

// IsFileChanged uses os.Stat to check if the name, size, or last mod time of the
// file has changed (which is a heuristic, but sufficiently robust for users of this
// function). Returns nil if file has not changed; otherwise, returns a changed
// os.FileInfo which may be used to check for subsequent changes.
func IsFileChanged(path string, previousFileInfo os.FileInfo) (os.FileInfo, error) {

	fileInfo, err := os.Stat(path)
	if err != nil {
		return nil, ContextError(err)
	}

	changed := previousFileInfo == nil ||
		fileInfo.Name() != previousFileInfo.Name() ||
		fileInfo.Size() != previousFileInfo.Size() ||
		fileInfo.ModTime() != previousFileInfo.ModTime()

	if !changed {
		return nil, nil
	}

	return fileInfo, nil
}

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
// will obtain a write lock before reloading the data structures. Actually reloading
// action is to be provided via the reloadAction callback (for example, read the contents
// of the file and unmarshall the contents into data structures). All read access to
// the data structures should be guarded by RLocks on the ReloadableFile mutex.
//
// reloadAction must ensure that data structures revert to their previous state when
// a reload fails.
//
type ReloadableFile struct {
	sync.RWMutex
	fileName     string
	fileInfo     os.FileInfo
	reloadAction func(string) error
}

// NewReloadableFile initializes a new ReloadableFile
func NewReloadableFile(
	fileName string,
	reloadAction func(string) error) ReloadableFile {

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

// Reload checks if the underlying file has changed (using IsFileChanged semantics, which
// are heuristics) and, when changed, invokes the reloadAction callback which should
// reload, from the file, the in-memory data structures.
// All data structure readers should be blocked by the ReloadableFile mutex.
func (reloadable *ReloadableFile) Reload() (bool, error) {

	if !reloadable.WillReload() {
		return false, nil
	}

	// Check whether the file has changed _before_ blocking readers

	reloadable.RLock()
	changedFileInfo, err := IsFileChanged(reloadable.fileName, reloadable.fileInfo)
	reloadable.RUnlock()
	if err != nil {
		return false, ContextError(err)
	}

	if changedFileInfo == nil {
		return false, nil
	}

	// ...now block readers

	reloadable.Lock()
	defer reloadable.Unlock()

	err = reloadable.reloadAction(reloadable.fileName)
	if err != nil {
		return false, ContextError(err)
	}

	reloadable.fileInfo = changedFileInfo

	return true, nil
}

func (reloadable *ReloadableFile) LogDescription() string {
	return reloadable.fileName
}
