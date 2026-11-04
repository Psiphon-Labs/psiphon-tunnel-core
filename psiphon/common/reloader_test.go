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
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReloader(t *testing.T) {

	dirname, err := ioutil.TempDir("", "psiphon-reloader-test")
	if err != nil {
		t.Fatalf("TempDir failed: %s", err)
	}
	defer os.RemoveAll(dirname)

	filename := filepath.Join(dirname, "reloader_test.dat")

	initialContents := []byte("contents1\n")
	modifiedContents := []byte("contents2\n")

	var file struct {
		ReloadableFile
		contents []byte
	}

	file.ReloadableFile = NewReloadableFile(
		"test-config",
		filename,
		true,
		func(fileContent []byte, _ time.Time) error {
			file.contents = fileContent
			return nil
		})

	// Test: initial load

	err = ioutil.WriteFile(filename, initialContents, 0600)
	if err != nil {
		t.Fatalf("WriteFile failed: %s", err)
	}

	results := file.Reload()
	err = results.Err()
	if err != nil {
		t.Fatalf("Reload failed: %s", err)
	}

	if !results.Reloaded() {
		t.Fatalf("Unexpected non-reload")
	}

	if !bytes.Equal(file.contents, initialContents) {
		t.Fatalf("Unexpected contents")
	}

	if len(results) != 1 || results[0].Name != "test-config" || results[0].FilePath != filename {
		t.Fatalf("unexpected reload identity: %+v", results)
	}

	// Test: reload unchanged file

	results = file.Reload(func() error {
		t.Fatal("post action called for unchanged file")
		return nil
	})
	err = results.Err()
	if err != nil {
		t.Fatalf("Reload failed: %s", err)
	}

	if results.Reloaded() {
		t.Fatalf("Unexpected reload")
	}

	if !bytes.Equal(file.contents, initialContents) {
		t.Fatalf("Unexpected contents")
	}

	// Test: reload changed file

	err = ioutil.WriteFile(filename, modifiedContents, 0600)
	if err != nil {
		t.Fatalf("WriteFile failed: %s", err)
	}

	results = file.Reload()
	err = results.Err()
	if err != nil {
		t.Fatalf("Reload failed: %s", err)
	}

	if !results.Reloaded() {
		t.Fatalf("Unexpected non-reload")
	}

	if !bytes.Equal(file.contents, modifiedContents) {
		t.Fatalf("Unexpected contents")
	}

	loadError := errors.New("load failed")
	file.reloadAction = func([]byte, time.Time) error { return loadError }
	err = os.WriteFile(filename, initialContents, 0600)
	if err != nil {
		t.Fatal(err)
	}
	results = file.Reload(func() error {
		t.Fatal("post action called after failed load")
		return nil
	})
	err = results.Err()
	if !errors.Is(err, loadError) || len(results) != 1 || results.Reloaded() ||
		len(results[0].Errors) != 1 || !errors.Is(results[0].Errors[0], loadError) ||
		results[0].HashSHA256 != fmt.Sprintf("%x", sha256.Sum256(initialContents)) ||
		!bytes.Equal(file.contents, modifiedContents) {
		t.Fatalf("unexpected failed reload: %+v, %v", results, err)
	}

	file.reloadAction = func(content []byte, _ time.Time) error {
		file.contents = content
		return nil
	}
	postErrors := []error{errors.New("first post action"), errors.New("second post action")}
	var calls []int
	postAction := func(i int) func() error {
		return func() error {
			file.RLock()
			defer file.RUnlock()
			if !bytes.Equal(file.contents, initialContents) {
				t.Fatal("post action did not observe reloaded contents")
			}
			calls = append(calls, i)
			return postErrors[i]
		}
	}
	results = file.Reload(postAction(0), postAction(1))
	err = results.Err()
	if len(results) != 1 || !results.Reloaded() || len(results[0].Errors) != 2 ||
		!errors.Is(err, postErrors[0]) || !errors.Is(err, postErrors[1]) ||
		len(calls) != 2 || calls[0] != 0 || calls[1] != 1 {
		t.Fatalf("unexpected post action results: %+v, %v, %v", results, err, calls)
	}

	results = file.Reload(postAction(0))
	err = results.Err()
	if err != nil || len(results) != 1 || results.Reloaded() || len(calls) != 2 {
		t.Fatalf("unexpected retry after post action failure: %+v, %v", results, err)
	}
	err = os.Remove(filename)
	if err != nil {
		t.Fatal(err)
	}
	results = file.Reload()
	err = results.Err()
	if err == nil || len(results) != 1 || results[0].HashSHA256 != "" || len(results[0].Errors) != 1 ||
		results[0].Name != "test-config" || results[0].FilePath != filename {
		t.Fatalf("unexpected missing file result: %+v, %v", results, err)
	}
}
