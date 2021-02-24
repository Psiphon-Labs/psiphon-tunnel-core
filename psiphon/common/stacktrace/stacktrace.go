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

Package stacktrace provides helpers for handling stack trace information.

*/
package stacktrace

import (
	"fmt"
	"runtime"
	"strings"
)

// GetFunctionName is a helper that extracts a simple function name from
// full name returned by runtime.Func.Name(). This is used to declutter
// error messages containing function names.
func GetFunctionName(pc uintptr) string {
	funcName := runtime.FuncForPC(pc).Name()
	index := strings.LastIndex(funcName, "/")
	if index != -1 {
		funcName = funcName[index+1:]
	}
	return funcName
}

// GetParentFunctionName returns the caller's parent function name and source
// file line number.
func GetParentFunctionName() string {
	pc, _, line, _ := runtime.Caller(2)
	return fmt.Sprintf("%s#%d", GetFunctionName(pc), line)
}
