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
	"testing"
	"time"
)

func TestReloader(t *testing.T) {

	fileName := "reloader_test.dat"
	initialContents := []byte("contents1\n")
	modifiedContents := []byte("contents2\n")

	var file struct {
		ReloadableFile
		contents []byte
	}

	file.ReloadableFile = NewReloadableFile(
		fileName,
		func(filename string) error {
			contents, err := ioutil.ReadFile(filename)
			if err != nil {
				return err
			}
			file.contents = contents
			return nil
		})

	// Test: initial load

	err := ioutil.WriteFile(fileName, initialContents, 0600)
	if err != nil {
		t.Fatalf("WriteFile failed: %s", err)
	}

	time.Sleep(2 * time.Second)
	fileInfo, err := os.Stat(fileName)
	if err != nil {
		t.Fatalf("Stat failed: %s", err)
	}
	t.Logf("ModTime: %s", fileInfo.ModTime())

	reloaded, err := file.Reload()
	if err != nil {
		t.Fatalf("Reload failed: %s", err)
	}

	if !reloaded {
		t.Fatalf("Unexpected non-reload")
	}

	if bytes.Compare(file.contents, initialContents) != 0 {
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

	if bytes.Compare(file.contents, initialContents) != 0 {
		t.Fatalf("Unexpected contents")
	}

	// Test: reload changed file

	err = ioutil.WriteFile(fileName, modifiedContents, 0600)
	if err != nil {
		t.Fatalf("WriteFile failed: %s", err)
	}

	// TODO: without the sleeps, the os.Stat ModTime doesn't
	// change and IsFileChanged fails to detect the modification.

	time.Sleep(2 * time.Second)
	fileInfo, err = os.Stat(fileName)
	if err != nil {
		t.Fatalf("Stat failed: %s", err)
	}
	t.Logf("ModTime: %s", fileInfo.ModTime())

	reloaded, err = file.Reload()
	if err != nil {
		t.Fatalf("Reload failed: %s", err)
	}

	if !reloaded {
		t.Fatalf("Unexpected non-reload")
	}

	if bytes.Compare(file.contents, modifiedContents) != 0 {
		t.Fatalf("Unexpected contents")
	}
}
