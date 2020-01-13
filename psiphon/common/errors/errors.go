/*
 * Copyright (c) 2019, Psiphon Inc.
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

/*

Package errors provides error wrapping helpers that add inline, single frame
stack trace information to error messages.

*/
package errors

import (
	"fmt"
	"runtime"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/stacktrace"
)

// TraceNew returns a new error with the given message, wrapped with the caller
// stack frame information.
func TraceNew(message string) error {
	err := fmt.Errorf("%s", message)
	pc, _, line, _ := runtime.Caller(1)
	return fmt.Errorf("%s#%d: %w", stacktrace.GetFunctionName(pc), line, err)
}

// BackTraceNew returns a new error with the given message, wrapped with the
// caller stack frame information going back up the stack until the caller of
// the specified function name is encountered.
func BackTraceNew(backTraceFuncName, message string) error {
	err := fmt.Errorf("%s", message)
	return fmt.Errorf("%s%w", backTrace(backTraceFuncName), err)
}

// Tracef returns a new error with the given formatted message, wrapped with
// the caller stack frame information.
func Tracef(format string, args ...interface{}) error {
	err := fmt.Errorf(format, args...)
	pc, _, line, _ := runtime.Caller(1)
	return fmt.Errorf("%s#%d: %w", stacktrace.GetFunctionName(pc), line, err)
}

// Trace wraps the given error with the caller stack frame information.
func Trace(err error) error {
	if err == nil {
		return nil
	}
	pc, _, line, _ := runtime.Caller(1)
	return fmt.Errorf("%s#%d: %w", stacktrace.GetFunctionName(pc), line, err)
}

// TraceMsg wraps the given error with the caller stack frame information
// and the given message.
func TraceMsg(err error, message string) error {
	if err == nil {
		return nil
	}
	pc, _, line, _ := runtime.Caller(1)
	return fmt.Errorf("%s#%d: %s: %w", stacktrace.GetFunctionName(pc), line, message, err)
}

func backTrace(backTraceFuncName string) string {
	stop := false
	trace := ""
	// Skip starts at 2, assuming backTrace is called as a helper function.
	for n := 2; ; n++ {
		pc, _, line, ok := runtime.Caller(n)
		if !ok {
			break
		}
		funcName := stacktrace.GetFunctionName(pc)
		trace = fmt.Sprintf("%s#%d: ", funcName, line) + trace
		if stop {
			break
		}
		if funcName == backTraceFuncName {
			// Stop after the _next_ function
			stop = true
		}
	}
	return trace
}
