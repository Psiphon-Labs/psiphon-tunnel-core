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
	"bytes"
	"encoding/json"
	"strconv"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
)

// PortList provides a lookup for a configured list of IP ports and port
// ranges. PortList is intended for use with JSON config files and is
// initialized via UnmarshalJSON.
//
// A JSON port list field should look like:
//
// "FieldName": [1, 2, 3, [10, 20], [30, 40]]
//
// where the ports in the list are 1, 2, 3, 10-20, 30-40. UnmarshalJSON
// validates that each port is in the range 1-65535 and that ranges have two
// elements in increasing order. PortList is designed to be backwards
// compatible with existing JSON config files where port list fields were
// defined as `[]int`.
type PortList struct {
	portRanges [][2]int
	lookup     map[int]bool
}

const lookupThreshold = 10

// OptimizeLookups converts the internal port list representation to use a
// map, which increases the performance of lookups for longer lists with an
// increased memory footprint tradeoff. OptimizeLookups is not safe to use
// concurrently with Lookup and should be called immediately after
// UnmarshalJSON and before performing lookups.
func (p *PortList) OptimizeLookups() {
	if p == nil {
		return
	}
	// TODO: does the threshold take long ranges into account?
	if len(p.portRanges) > lookupThreshold {
		p.lookup = make(map[int]bool)
		for _, portRange := range p.portRanges {
			for i := portRange[0]; i <= portRange[1]; i++ {
				p.lookup[i] = true
			}
		}
	}
}

// IsEmpty returns true for a nil PortList or a PortList with no entries.
func (p *PortList) IsEmpty() bool {
	if p == nil {
		return true
	}
	return len(p.portRanges) == 0
}

// Lookup returns true if the specified port is in the port list and false
// otherwise. Lookups on a nil PortList are allowed and return false.
func (p *PortList) Lookup(port int) bool {
	if p == nil {
		return false
	}
	if p.lookup != nil {
		return p.lookup[port]
	}
	for _, portRange := range p.portRanges {
		if port >= portRange[0] && port <= portRange[1] {
			return true
		}
	}
	return false
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (p *PortList) UnmarshalJSON(b []byte) error {

	p.portRanges = nil
	p.lookup = nil

	if bytes.Equal(b, []byte("null")) {
		return nil
	}

	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.UseNumber()

	var array []interface{}

	err := decoder.Decode(&array)
	if err != nil {
		return errors.Trace(err)
	}

	p.portRanges = make([][2]int, len(array))

	for i, portRange := range array {

		var startPort, endPort int64

		if portNumber, ok := portRange.(json.Number); ok {

			port, err := portNumber.Int64()
			if err != nil {
				return errors.Trace(err)
			}

			startPort = port
			endPort = port

		} else if array, ok := portRange.([]interface{}); ok {

			if len(array) != 2 {
				return errors.TraceNew("invalid range size")
			}

			portNumber, ok := array[0].(json.Number)
			if !ok {
				return errors.TraceNew("invalid type")
			}
			port, err := portNumber.Int64()
			if err != nil {
				return errors.Trace(err)
			}
			startPort = port

			portNumber, ok = array[1].(json.Number)
			if !ok {
				return errors.TraceNew("invalid type")
			}
			port, err = portNumber.Int64()
			if err != nil {
				return errors.Trace(err)
			}
			endPort = port

		} else {

			return errors.TraceNew("invalid type")
		}

		if startPort < 1 || startPort > 65535 {
			return errors.TraceNew("invalid range start")
		}

		if endPort < 1 || endPort > 65535 || endPort < startPort {
			return errors.TraceNew("invalid range end")
		}

		p.portRanges[i] = [2]int{int(startPort), int(endPort)}
	}

	return nil
}

// MarshalJSON implements the json.Marshaler interface.
func (p *PortList) MarshalJSON() ([]byte, error) {
	var json bytes.Buffer
	json.WriteString("[")
	for i, portRange := range p.portRanges {
		if i > 0 {
			json.WriteString(",")
		}
		if portRange[0] == portRange[1] {
			json.WriteString(strconv.Itoa(portRange[0]))
		} else {
			json.WriteString("[")
			json.WriteString(strconv.Itoa(portRange[0]))
			json.WriteString(",")
			json.WriteString(strconv.Itoa(portRange[1]))
			json.WriteString("]")
		}
	}
	json.WriteString("]")
	return json.Bytes(), nil
}
