/*
Copyright 2014 Zachary Klippenstein

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*
 * Copyright (c) 2023, Psiphon Inc.
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

package regen

import (
	"bytes"
	"fmt"
	"io"
	"regexp/syntax"
)

// inspectRegexpToString returns a string describing a regular expression.
func inspectRegexpToString(r *syntax.Regexp) string {
	var buffer bytes.Buffer
	inspectRegexpToWriter(&buffer, r)
	return buffer.String()
}

func inspectRegexpToWriter(w io.Writer, r ...*syntax.Regexp) {
	for _, regexp := range r {
		inspectWithIndent(regexp, "", w)
	}
}

func inspectWithIndent(r *syntax.Regexp, indent string, w io.Writer) {
	fmt.Fprintf(w, "%s{\n", indent)
	fmt.Fprintf(w, "%s  Op: %s\n", indent, opToString(r.Op))
	fmt.Fprintf(w, "%s  Flags: %x\n", indent, r.Flags)
	if len(r.Sub) > 0 {
		fmt.Fprintf(w, "%s  Sub: [\n", indent)
		for _, subR := range r.Sub {
			inspectWithIndent(subR, indent+"    ", w)
		}
		fmt.Fprintf(w, "%s  ]\n", indent)
	} else {
		fmt.Fprintf(w, "%s  Sub: []\n", indent)
	}
	fmt.Fprintf(w, "%s  Rune: %s (%s)\n", indent, runesToUTF8(r.Rune...), runesToDecimalString(r.Rune))
	fmt.Fprintf(w, "%s  [Min, Max]: [%d, %d]\n", indent, r.Min, r.Max)
	fmt.Fprintf(w, "%s  Cap: %d\n", indent, r.Cap)
	fmt.Fprintf(w, "%s  Name: %s\n", indent, r.Name)
}

// runesToUTF8 converts a slice of runes to the Unicode string they represent.
func runesToUTF8(runes ...rune) []byte {
	var buffer bytes.Buffer
	for _, r := range runes {
		buffer.WriteRune(r)
	}
	return buffer.Bytes()
}

// runesToBytes converst a slice of runes to a slice of bytes.
// Returns an error if runes not in the range [0-255].
func runesToBytes(runes ...rune) ([]byte, error) {
	var buffer bytes.Buffer
	for _, r := range runes {
		if r < 0 || r > 255 {
			return nil, fmt.Errorf("RunesToBytes: rune out of range")
		}
		buffer.WriteByte(byte(r))
	}
	return buffer.Bytes(), nil
}

// RunesToDecimalString converts a slice of runes to their comma-separated decimal values.
func runesToDecimalString(runes []rune) string {
	var buffer bytes.Buffer
	for _, r := range runes {
		buffer.WriteString(fmt.Sprintf("%d, ", r))
	}
	return buffer.String()
}

// opToString gets the string name of a regular expression operation.
func opToString(op syntax.Op) string {
	switch op {
	case syntax.OpNoMatch:
		return "OpNoMatch"
	case syntax.OpEmptyMatch:
		return "OpEmptyMatch"
	case syntax.OpLiteral:
		return "OpLiteral"
	case syntax.OpCharClass:
		return "OpCharClass"
	case syntax.OpAnyCharNotNL:
		return "OpAnyCharNotNL"
	case syntax.OpAnyChar:
		return "OpAnyChar"
	case syntax.OpBeginLine:
		return "OpBeginLine"
	case syntax.OpEndLine:
		return "OpEndLine"
	case syntax.OpBeginText:
		return "OpBeginText"
	case syntax.OpEndText:
		return "OpEndText"
	case syntax.OpWordBoundary:
		return "OpWordBoundary"
	case syntax.OpNoWordBoundary:
		return "OpNoWordBoundary"
	case syntax.OpCapture:
		return "OpCapture"
	case syntax.OpStar:
		return "OpStar"
	case syntax.OpPlus:
		return "OpPlus"
	case syntax.OpQuest:
		return "OpQuest"
	case syntax.OpRepeat:
		return "OpRepeat"
	case syntax.OpConcat:
		return "OpConcat"
	case syntax.OpAlternate:
		return "OpAlternate"
	}

	panic(fmt.Sprintf("invalid op: %d", op))
}
