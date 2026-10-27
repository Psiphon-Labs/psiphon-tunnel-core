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
	"crypto/sha256"
	"encoding/hex"
	std_errors "errors"
	"io"
	"io/ioutil"
	"os"
	"sync"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
)

// Reloader represents a read-only, in-memory reloadable data object. For example,
// a JSON data file that is loaded into memory and accessed for read-only lookups;
// and from time to time may be reloaded from the same file, updating the memory
// copy.
type Reloader interface {

	// Reload reloads the data object. Each result includes a flag indicating if
	// the reloadable target was reloaded or remains unchanged. By convention,
	// when reloading fails the Reloader should revert to its previous in-memory
	// state.
	//
	// Reload returns per-file results containing hashes and all errors; use
	// ReloadResults.Err to check for failure. Post actions run in order after
	// a successful reload, outside data locks; their failures do not revert
	// loaded state or clear Reloaded. Reload must not be called concurrently.
	Reload(postActions ...func() error) ReloadResults

	// WillReload indicates if the data object is capable of reloading.
	WillReload() bool

	// ReloadLogDescription returns a description to be used for logging
	// events related to the Reloader.
	ReloadLogDescription() string
}

// ReloadResult describes one file observed during a reload attempt.
type ReloadResult struct {
	Description string
	Reloaded    bool
	HashSHA256  string
	Errors      []error
}

// ReloadResults is the set of per-file results from one Reload call.
type ReloadResults []ReloadResult

// Err returns all per-file load and post-action errors joined, or nil when
// there are no errors.
func (results ReloadResults) Err() error {
	var errs []error
	for _, result := range results {
		errs = append(errs, result.Errors...)
	}
	return std_errors.Join(errs...)
}

// Reloaded indicates whether any result reloaded.
func (results ReloadResults) Reloaded() bool {
	for _, result := range results {
		if result.Reloaded {
			return true
		}
	}
	return false
}

// ReloadableFile is a file-backed Reloader. This type is intended to be embedded
// in other types that add the actual reloadable data structures.
//
// ReloadableFile has a multi-reader mutex for synchronization. Its Reload() function
// will obtain a write lock before reloading the data structures. The actual reloading
// action is to be provided via the reloadAction callback, which receives the content
// of reloaded files, along with file modification time, and must process the new data
// (for example, unmarshall the contents into data structures). All read access to the
// data structures should be guarded by RLocks on the ReloadableFile mutex.
//
// reloadAction must ensure that data structures revert to their previous state when
// a reload fails.
type ReloadableFile struct {
	sync.RWMutex
	filename        string
	loadFileContent bool
	hasLoaded       bool
	fileHash        [sha256.Size]byte
	reloadAction    func([]byte, time.Time) error
}

// NewReloadableFile initializes a new ReloadableFile.
//
// When loadFileContent is true, the file content is loaded and passed to
// reloadAction; otherwise, reloadAction receives a nil argument and is
// responsible for loading the file. The latter option allows for cases where
// the file contents must be streamed, memory mapped, etc.
//
// The returned ReloadableFile contains a sync.RWMutex and must not be copied
// after first use.
func NewReloadableFile(
	filename string,
	loadFileContent bool,
	reloadAction func([]byte, time.Time) error) ReloadableFile {

	return ReloadableFile{
		filename:        filename,
		loadFileContent: loadFileContent,
		reloadAction:    reloadAction,
	}
}

// WillReload indicates whether the ReloadableFile is capable
// of reloading.
func (reloadable *ReloadableFile) WillReload() bool {
	return reloadable.filename != ""
}

// Reload checks if the underlying file has changed and, when changed, invokes
// the reloadAction callback which should reload the in-memory data structures.
//
// In some case (e.g., traffic rules and OSL), there are penalties associated
// with proceeding with reload, so care is taken to not invoke the reload action
// unless the contents have changed.
//
// The file content is loaded and a hash is taken to determine whether it
// has changed. Neither file size (may not change when content changes) nor
// modified date (may change when identical file is repaved) is a sufficient
// indicator.
//
// All data structure readers should be blocked by the ReloadableFile mutex.
//
// Reload must not be called from multiple concurrent goroutines.
func (reloadable *ReloadableFile) Reload(postActions ...func() error) ReloadResults {

	if !reloadable.WillReload() {
		return nil
	}

	result := ReloadResult{Description: reloadable.ReloadLogDescription()}
	err := reloadable.reload(&result)
	if err != nil {
		result.Errors = append(result.Errors, err)
	} else if result.Reloaded {
		for _, action := range postActions {
			err := action()
			if err != nil {
				result.Errors = append(result.Errors, err)
			}
		}
	}

	return ReloadResults{result}
}

func (reloadable *ReloadableFile) reload(result *ReloadResult) error {

	// Check whether the file has changed _before_ blocking readers

	reloadable.RLock()
	filename := reloadable.filename
	hasLoaded := reloadable.hasLoaded
	previousFileHash := reloadable.fileHash
	reloadable.RUnlock()

	// Record the file modification time _before_ loading, as reload actions will
	// assume that the content is at least as fresh as the modification time.
	fileInfo, err := os.Stat(filename)
	if err != nil {
		return errors.Trace(err)
	}
	fileModTime := fileInfo.ModTime()

	file, err := os.Open(filename)
	if err != nil {
		return errors.Trace(err)
	}
	defer file.Close()

	hash := sha256.New()

	_, err = io.Copy(hash, file)
	if err != nil {
		return errors.Trace(err)
	}

	fileHash := [sha256.Size]byte(hash.Sum(nil))
	result.HashSHA256 = hex.EncodeToString(fileHash[:])

	if hasLoaded && fileHash == previousFileHash {
		return nil
	}

	// It's possible for the file content to revert to its previous value
	// between the hashing operation and subsequent content load. We accept
	// the false positive in this unlikely case.

	var content []byte
	if reloadable.loadFileContent {
		_, err = file.Seek(0, 0)
		if err != nil {
			return errors.Trace(err)
		}
		content, err = ioutil.ReadAll(file)
		if err != nil {
			return errors.Trace(err)
		}
	}

	// Don't keep file open during reloadAction call.
	file.Close()

	// ...now block readers and reload

	reloadable.Lock()
	defer reloadable.Unlock()

	if reloadable.reloadAction != nil {
		err := reloadable.reloadAction(content, fileModTime)
		if err != nil {
			return errors.Trace(err)
		}
	}

	reloadable.hasLoaded = true
	reloadable.fileHash = fileHash
	result.Reloaded = true

	return nil
}

func (reloadable *ReloadableFile) ReloadLogDescription() string {
	return reloadable.filename
}
