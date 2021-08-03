/*
 * Copyright (c) 2021, Psiphon Inc.
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
	"strings"
	"testing"
	"unicode"
)

func TestPortList(t *testing.T) {

	var p *PortList

	err := json.Unmarshal([]byte("[1.5]"), &p)
	if err == nil {
		t.Fatalf("unexpected parse of float port number")
	}

	err = json.Unmarshal([]byte("[-1]"), &p)
	if err == nil {
		t.Fatalf("unexpected parse of negative port number")
	}

	err = json.Unmarshal([]byte("[0]"), &p)
	if err == nil {
		t.Fatalf("unexpected parse of invalid port number")
	}

	err = json.Unmarshal([]byte("[65536]"), &p)
	if err == nil {
		t.Fatalf("unexpected parse of invalid port number")
	}

	err = json.Unmarshal([]byte("[[2,1]]"), &p)
	if err == nil {
		t.Fatalf("unexpected parse of invalid port range")
	}

	p = nil

	if p.Lookup(1) != false {
		t.Fatalf("unexpected nil PortList Lookup result")
	}

	if !p.IsEmpty() {
		t.Fatalf("unexpected nil PortList IsEmpty result")
	}

	err = json.Unmarshal([]byte("[]"), &p)
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if !p.IsEmpty() {
		t.Fatalf("unexpected IsEmpty result")
	}

	err = json.Unmarshal([]byte("[1]"), &p)
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if p.IsEmpty() {
		t.Fatalf("unexpected IsEmpty result")
	}

	s := struct {
		List1 *PortList
		List2 *PortList
	}{}

	jsonString := `
    {
        "List1" : [1,2,[10,20],100,[1000,2000]],
        "List2" : [3,4,5,[300,400],1000,2000,[3000,3996],3997,3998,3999,4000]
    }
    `

	err = json.Unmarshal([]byte(jsonString), &s)
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	// Marshal and re-Unmarshal to exercise PortList.MarshalJSON.

	jsonBytes, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	strip := func(s string) string {
		return strings.Map(func(r rune) rune {
			if unicode.IsSpace(r) {
				return -1
			}
			return r
		}, s)
	}

	if strip(jsonString) != strip(string(jsonBytes)) {

		t.Fatalf("unexpected JSON encoding")
	}

	err = json.Unmarshal(jsonBytes, &s)
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	s.List1.OptimizeLookups()
	if s.List1.lookup != nil {
		t.Fatalf("unexpected lookup initialization")
	}

	s.List2.OptimizeLookups()
	if s.List2.lookup == nil {
		t.Fatalf("unexpected lookup initialization")
	}

	for port := 0; port < 65536; port++ {

		lookup1 := s.List1.Lookup(port)
		expected1 := port == 1 ||
			port == 2 ||
			(port >= 10 && port <= 20) ||
			port == 100 ||
			(port >= 1000 && port <= 2000)
		if lookup1 != expected1 {
			t.Fatalf("unexpected port lookup: %d %v", port, lookup1)
		}

		lookup2 := s.List2.Lookup(port)
		expected2 := port == 3 ||
			port == 4 ||
			port == 5 ||
			(port >= 300 && port <= 400) ||
			port == 1000 || port == 2000 ||
			(port >= 3000 && port <= 4000)
		if lookup2 != expected2 {
			t.Fatalf("unexpected port lookup: %d %v", port, lookup2)
		}
	}
}

func BenchmarkPortListLinear(b *testing.B) {

	s := struct {
		List PortList
	}{}

	jsonStruct := `
    {
        "List" : [1,2,3,4,5,6,7,8,9,[10,20]]
    }
    `

	err := json.Unmarshal([]byte(jsonStruct), &s)
	if err != nil {
		b.Fatalf("Unmarshal failed: %v", err)
	}
	s.List.OptimizeLookups()
	if s.List.lookup != nil {
		b.Fatalf("unexpected lookup initialization")
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		for port := 0; port < 65536; port++ {
			s.List.Lookup(port)
		}
	}
}

func BenchmarkPortListMap(b *testing.B) {

	s := struct {
		List PortList
	}{}

	jsonStruct := `
    {
        "List" : [1,2,3,4,5,6,7,8,9,10,[11,20]]
    }
    `

	err := json.Unmarshal([]byte(jsonStruct), &s)
	if err != nil {
		b.Fatalf("Unmarshal failed: %v", err)
	}
	s.List.OptimizeLookups()
	if s.List.lookup == nil {
		b.Fatalf("unexpected lookup initialization")
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		for port := 0; port < 65536; port++ {
			s.List.Lookup(port)
		}
	}
}
