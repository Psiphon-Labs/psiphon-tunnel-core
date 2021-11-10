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

package wildcard

import (
	"fmt"
	"testing"
)

const target = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."

func TestMatch(t *testing.T) {

	testCases := []struct {
		pattern string
		target  string
		match   bool
	}{
		{"*", target, true},
		{target, target, true},
		{"Lorem*", target, true},
		{"*aliqua.", target, true},
		{"*tempor*", target, true},
		{"*dolor*eiusmod*magna*", target, true},
		{"Lorem*dolor*eiusmod*magna*", target, true},
		{"*ipsum*elit*aliqua.", target, true},
		{"Lorem*dolor*eiusmod*dolore*aliqua.", target, true},
		{"*dolor* sit*", target, true},
		{"*aliqua.*", target, true},

		{"", target, false},
		{"L-rem*", target, false},
		{"L-rem**", target, false},
		{"*aliqua-", target, false},
		{"*temp-r*", target, false},
		{"*dolor*ei-smod*magna*", target, false},
		{"Lorem*dolor*eiu-mod*magna*", target, false},
		{"*ipsum*eli-*aliqua.", target, false},
		{"Lorem*dolor*eiusm-d*dolore*aliqua.", target, false},

		{"Lorem**", target, true},
		{"**aliqua.", target, true},
		{"**tempor**", target, true},
	}

	for _, testCase := range testCases {
		t.Run(fmt.Sprintf("match: %+v", testCase), func(t *testing.T) {
			if Match(testCase.pattern, testCase.target) != testCase.match {
				t.Errorf("unexpected result")
			}
		})
	}
}

func BenchmarkFixedMatch(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if !Match(target, target) {
			b.Fatalf("unexpected result")
		}
	}
}

func BenchmarkPrefixMatch(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if !Match("Lorem*", target) {
			b.Fatalf("unexpected result")
		}
	}
}

func BenchmarkSuffixMatch(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if !Match("*aliqua.", target) {
			b.Fatalf("unexpected result")
		}
	}
}

func BenchmarkMultipleMatch(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if !Match("*dolor*eiusmod*magna*", target) {
			b.Fatalf("unexpected result")
		}
	}
}
