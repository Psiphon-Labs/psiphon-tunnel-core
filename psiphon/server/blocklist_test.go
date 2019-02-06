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

package server

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
)

func TestBlocklist(t *testing.T) {

	testDataDirName, err := ioutil.TempDir("", "psiphon-blocklist-test")
	if err != nil {
		t.Fatalf("TempDir failed: %s", err)
	}
	defer os.RemoveAll(testDataDirName)

	filename := filepath.Join(testDataDirName, "blocklist")

	hit := net.ParseIP("0.0.0.0")
	miss := net.ParseIP("255.255.255.255")
	sources := []string{"source1", "source2", "source3", "source4", "source4"}
	subjects := []string{"subject1", "subject2", "subject3", "subject4", "subject4"}
	hitPresent := []int{0, 1}
	entriesPerSource := 100000

	file, err := os.Create(filename)
	if err != nil {
		t.Fatalf("Open failed: %s", err)
	}
	defer file.Close()

	for i := 0; i < len(sources); i++ {
		_, err := fmt.Fprintf(file, "# comment\n# comment\n# comment\n")
		if err != nil {
			t.Fatalf("Fprintf failed: %s", err)
		}
		for j := 0; j < entriesPerSource; j++ {
			var IPAddress string
			if j == entriesPerSource/2 && common.ContainsInt(hitPresent, i) {
				IPAddress = hit.String()
			} else {
				IPAddress = fmt.Sprintf(
					"%d.%d.%d.%d",
					prng.Range(1, 254), prng.Range(1, 254),
					prng.Range(1, 254), prng.Range(1, 254))
			}
			_, err := fmt.Fprintf(file, "%s,%s,%s\n",
				IPAddress, sources[i], subjects[i])
			if err != nil {
				t.Fatalf("Fprintf failed: %s", err)
			}
		}
	}

	file.Close()

	b, err := NewBlocklist(filename)
	if err != nil {
		t.Fatalf("NewBlocklist failed: %s", err)
	}

	tags := b.Lookup(hit)

	if tags == nil {
		t.Fatalf("unexpected miss")
	}

	if len(tags) != len(hitPresent) {
		t.Fatalf("unexpected hit tag count")
	}

	for _, tag := range tags {
		sourceFound := false
		subjectFound := false
		for _, i := range hitPresent {
			if tag.Source == sources[i] {
				sourceFound = true
			}
			if tag.Subject == subjects[i] {
				subjectFound = true
			}
		}
		if !sourceFound || !subjectFound {
			t.Fatalf("unexpected hit tag")
		}
	}

	if b.Lookup(miss) != nil {
		t.Fatalf("unexpected hit")
	}

	numLookups := 10
	numIterations := 1000000

	lookups := make([]net.IP, numLookups)

	for i := 0; i < numLookups; i++ {
		lookups[i] = net.ParseIP(
			fmt.Sprintf(
				"%d.%d.%d.%d",
				prng.Range(1, 254), prng.Range(1, 254),
				prng.Range(1, 254), prng.Range(1, 254)))
	}

	start := time.Now()

	for i := 0; i < numIterations; i++ {
		_ = b.Lookup(lookups[i%numLookups])
	}

	t.Logf(
		"average time per lookup in %d entries: %s",
		len(sources)*entriesPerSource,
		time.Since(start)/time.Duration(numIterations))
}
