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
	"fmt"
	"io/ioutil"
	"os"
	"testing"
)

func TestWriteRuntimeProfiles(t *testing.T) {

	testDirName, err := ioutil.TempDir("", "psiphon-profiles-test")
	if err != nil {
		fmt.Printf("TempDir failed: %s\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(testDirName)

	WriteRuntimeProfiles(&testLogger{}, testDirName, "suffix", 1, 1)
}

type testLogger struct {
}

func (logger *testLogger) panic() {
	panic("unexpected log call")
}

func (logger *testLogger) WithContext() LogContext {
	return &testLoggerContext{}
}

func (logger *testLogger) WithTraceFields(fields LogFields) LogContext {
	return &testLoggerContext{}
}

func (logger *testLogger) LogMetric(metric string, fields LogFields) {
	panic("unexpected log call")
}

type testLoggerContext struct {
}

func (context *testLoggerContext) Debug(args ...interface{}) {
}

func (context *testLoggerContext) Info(args ...interface{}) {
}

func (context *testLoggerContext) Warning(args ...interface{}) {
	panic("unexpected log call")
}

func (context *testLoggerContext) Error(args ...interface{}) {
	panic("unexpected log call")
}
