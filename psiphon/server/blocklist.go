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
	"encoding/csv"
	"fmt"
	"io"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
)

// Blocklist provides a fast lookup of IP addresses that are candidates for
// egress blocking. This is intended to be used to block malware and other
// malicious traffic.
//
// The Reload function supports hot reloading of rules data while the server
// is running.
//
// Limitations: currently supports only IPv4 addresses, and is implemented
// with an in-memory Go map, which limits the practical size of the blocklist.
type Blocklist struct {
	common.ReloadableFile
	loaded int32
	data   atomic.Value
}

// BlocklistTag indicates the source containing an IP address and the subject,
// or name of the suspected malicious traffic.
type BlocklistTag struct {
	Source  string
	Subject string
}

type blocklistData struct {
	lookup          map[[net.IPv4len]byte][]BlocklistTag
	internedStrings map[string]string
}

// NewBlocklist creates a new block list.
//
// The input file must be a 3 field comma-delimited and optional quote-escaped
// CSV. Fields: <IPv4 address>,<source>,<subject>.
//
// IP addresses may appear multiple times in the input file; each distinct
// source/subject is associated with the IP address and returned in the Lookup
// tag list.
func NewBlocklist(filename string) (*Blocklist, error) {

	blocklist := &Blocklist{}

	blocklist.ReloadableFile = common.NewReloadableFile(
		filename,
		false,
		func(_ []byte, _ time.Time) error {

			newData, err := loadBlocklistFromFile(filename)
			if err != nil {
				return common.ContextError(err)
			}

			blocklist.data.Store(newData)
			atomic.StoreInt32(&blocklist.loaded, 1)

			return nil
		})

	_, err := blocklist.Reload()
	if err != nil {
		return nil, common.ContextError(err)
	}

	return blocklist, nil
}

// Lookup returns the blocklist tags for any IP address that is on the
// blocklist, or returns nil for any IP address not on the blocklist. Lookup
// may be called oncurrently. The caller must not modify the return value.
func (b *Blocklist) Lookup(IPAddress net.IP) []BlocklistTag {

	// When not configured, no blocklist is loaded/initialized.
	if atomic.LoadInt32(&b.loaded) != 1 {
		return nil
	}

	var key [net.IPv4len]byte
	IPv4Address := IPAddress.To4()
	if IPv4Address == nil {
		return nil
	}
	copy(key[:], IPv4Address)

	// As data is an atomic.Value, it's not necessary to call
	// ReloadableFile.RLock/ReloadableFile.RUnlock in this case.

	tags, ok := b.data.Load().(*blocklistData).lookup[key]
	if !ok {
		return nil
	}
	return tags
}

func loadBlocklistFromFile(filename string) (*blocklistData, error) {

	data := newBlocklistData()

	file, err := os.Open(filename)
	if err != nil {
		return nil, common.ContextError(err)
	}
	defer file.Close()

	reader := csv.NewReader(file)

	reader.FieldsPerRecord = 3
	reader.Comment = '#'
	reader.ReuseRecord = true

	for {
		record, err := reader.Read()

		if err == io.EOF {
			break
		} else if err != nil {
			return nil, common.ContextError(err)
		}

		IPAddress := net.ParseIP(record[0])
		if IPAddress == nil {
			return nil, common.ContextError(
				fmt.Errorf("invalid IP address: %s", record[0]))
		}
		IPv4Address := IPAddress.To4()
		if IPAddress == nil {
			return nil, common.ContextError(
				fmt.Errorf("invalid IPv4 address: %s", record[0]))
		}

		var key [net.IPv4len]byte
		copy(key[:], IPv4Address)

		// Intern the source and subject strings so we only store one copy of
		// each in memory. These values are expected to repeat often.
		source := data.internString(record[1])
		subject := data.internString(record[2])

		tag := BlocklistTag{
			Source:  source,
			Subject: subject,
		}

		tags := data.lookup[key]

		found := false
		for _, existingTag := range tags {
			if tag == existingTag {
				found = true
				break
			}
		}

		if !found {
			data.lookup[key] = append(tags, tag)
		}
	}

	return data, nil
}

func newBlocklistData() *blocklistData {
	return &blocklistData{
		lookup:          make(map[[net.IPv4len]byte][]BlocklistTag),
		internedStrings: make(map[string]string),
	}
}

func (data *blocklistData) internString(str string) string {
	if internedStr, ok := data.internedStrings[str]; ok {
		return internedStr
	}
	data.internedStrings[str] = str
	return str
}
