/*
 * Copyright (c) 2018, Psiphon Inc.
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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWriteRuntimeProfiles(t *testing.T) {

	testDirName, err := ioutil.TempDir("", "psiphon-profiles-test")
	if err != nil {
		fmt.Printf("TempDir failed: %s\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(testDirName)

	before := time.Now()
	WriteRuntimeProfiles(&testLogger{}, testDirName, "suffix", 1, 1)

	// The manifest is written last and lists every profile written, by base
	// name, so a collector knows the collection is complete and what to ship.
	content, err := os.ReadFile(filepath.Join(testDirName, profileManifestName))
	if err != nil {
		t.Fatalf("read manifest: %s", err)
	}
	var manifest profileManifest
	if err := json.Unmarshal(content, &manifest); err != nil {
		t.Fatalf("parse manifest: %s", err)
	}
	if manifest.CompletedAt.Before(before) {
		t.Fatalf("manifest completed_at %s precedes the run", manifest.CompletedAt)
	}
	listed := make(map[string]bool)
	for _, name := range manifest.Files {
		listed[name] = true
		if _, err := os.Stat(filepath.Join(testDirName, name)); err != nil {
			t.Fatalf("manifest lists %s, which is missing: %s", name, err)
		}
	}
	for _, name := range []string{"goroutine", "heap", "threadcreate", "cpu", "block", "mutex"} {
		if !listed[name+".profile.suffix"] {
			t.Fatalf("manifest %v does not list %s.profile.suffix", manifest.Files, name)
		}
	}
	if _, err := os.Stat(filepath.Join(testDirName, profileManifestName+".tmp")); !os.IsNotExist(err) {
		t.Fatalf("temporary manifest left behind: %v", err)
	}
}

func TestWriteRuntimeProfilesCreatesDirectory(t *testing.T) {

	testDirName, err := ioutil.TempDir("", "psiphon-profiles-test")
	if err != nil {
		fmt.Printf("TempDir failed: %s\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(testDirName)

	// The output directory, and its parent, do not exist yet.
	outputDirectory := filepath.Join(testDirName, "missing", "profiles")

	WriteRuntimeProfiles(&testLogger{}, outputDirectory, "", 0, 0)

	for _, name := range []string{"goroutine.profile", "heap.profile", "threadcreate.profile", profileManifestName} {
		if _, err := os.Stat(filepath.Join(outputDirectory, name)); err != nil {
			t.Fatalf("%s not written into the created directory: %s", name, err)
		}
	}
}

func TestWriteRuntimeProfilesNoManifestWithoutProfiles(t *testing.T) {

	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}

	testDirName, err := ioutil.TempDir("", "psiphon-profiles-test")
	if err != nil {
		fmt.Printf("TempDir failed: %s\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(testDirName)

	// A read-only output directory: every profile open fails, so nothing is
	// collected and no manifest may claim otherwise.
	if err := os.Chmod(testDirName, 0555); err != nil {
		t.Fatalf("chmod: %s", err)
	}
	defer os.Chmod(testDirName, 0755)

	WriteRuntimeProfiles(&tolerantTestLogger{}, testDirName, "", 0, 0)

	for _, name := range []string{profileManifestName, profileManifestName + ".tmp"} {
		if _, err := os.Stat(filepath.Join(testDirName, name)); !os.IsNotExist(err) {
			t.Fatalf("%s written for a collection with no profiles: %v", name, err)
		}
	}
}

type testLogger struct {
}

func (logger *testLogger) WithTrace() LogTrace {
	return &testLoggerTrace{}
}

func (logger *testLogger) WithTraceFields(fields LogFields) LogTrace {
	return &testLoggerTrace{}
}

func (logger *testLogger) LogMetric(metric string, fields LogFields) {
	panic("unexpected log call")
}

func (logger *testLogger) IsLogLevelDebug() bool {
	return true
}

type testLoggerTrace struct {
}

func (logger *testLoggerTrace) Debug(args ...interface{}) {
}

func (logger *testLoggerTrace) Info(args ...interface{}) {
}

func (logger *testLoggerTrace) Warning(args ...interface{}) {
	panic("unexpected log call")
}

func (logger *testLoggerTrace) Error(args ...interface{}) {
	panic("unexpected log call")
}

// tolerantTestLogger is a testLogger whose trace logs accept errors, for the
// tests that provoke expected failures.
type tolerantTestLogger struct {
	testLogger
}

func (logger *tolerantTestLogger) WithTrace() LogTrace {
	return &tolerantTestLoggerTrace{}
}

func (logger *tolerantTestLogger) WithTraceFields(fields LogFields) LogTrace {
	return &tolerantTestLoggerTrace{}
}

type tolerantTestLoggerTrace struct {
	testLoggerTrace
}

func (logger *tolerantTestLoggerTrace) Warning(args ...interface{}) {
}

func (logger *tolerantTestLoggerTrace) Error(args ...interface{}) {
}
