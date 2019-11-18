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

	reloaded, err := file.Reload()
	if err != nil {
		t.Fatalf("Reload failed: %s", err)
	}

	if !reloaded {
		t.Fatalf("Unexpected non-reload")
	}

	if !bytes.Equal(file.contents, initialContents) {
		t.Fatalf("Unexpected contents")
	}

	// Test: reload unchanged file

	reloaded, err = file.Reload()
	if err != nil {
		t.Fatalf("Reload failed: %s", err)
	}

	if reloaded {
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

	reloaded, err = file.Reload()
	if err != nil {
		t.Fatalf("Reload failed: %s", err)
	}

	if !reloaded {
		t.Fatalf("Unexpected non-reload")
	}

	if !bytes.Equal(file.contents, modifiedContents) {
		t.Fatalf("Unexpected contents")
	}
}
