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
	"io"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
)

// Blocklist provides a fast lookup of IP addresses and domains that are
// candidates for egress blocking. This is intended to be used to block
// malware and other malicious traffic.
//
// The Reload function supports hot reloading of rules data while the server
// is running.
//
// Limitations: the blocklist is implemented with in-memory Go maps, which
// limits the practical size of the blocklist.
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
	lookupIP        map[[net.IPv6len]byte][]BlocklistTag
	lookupDomain    map[string][]BlocklistTag
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
				return errors.Trace(err)
			}

			blocklist.data.Store(newData)
			atomic.StoreInt32(&blocklist.loaded, 1)

			return nil
		})

	_, err := blocklist.Reload()
	if err != nil {
		return nil, errors.Trace(err)
	}

	return blocklist, nil
}

// LookupIP returns the blocklist tags for any IP address that is on the
// blocklist, or returns nil for any IP address not on the blocklist. Lookup
// may be called concurrently. The caller must not modify the return value.
func (b *Blocklist) LookupIP(IPAddress net.IP) []BlocklistTag {

	// When not configured, no blocklist is loaded/initialized.
	if atomic.LoadInt32(&b.loaded) != 1 {
		return nil
	}

	// IPAddress may be an IPv4 or IPv6 address. To16 will return the 16-byte
	// representation of an IPv4 address, with the net.v4InV6Prefix prefix.

	var key [net.IPv6len]byte
	IPAddress16 := IPAddress.To16()
	if IPAddress16 == nil {
		return nil
	}
	copy(key[:], IPAddress16)

	// As data is an atomic.Value, it's not necessary to call
	// ReloadableFile.RLock/ReloadableFile.RUnlock in this case.

	tags, ok := b.data.Load().(*blocklistData).lookupIP[key]
	if !ok {
		return nil
	}
	return tags
}

// LookupDomain returns the blocklist tags for any domain that is on the
// blocklist, or returns nil for any domain not on the blocklist. Lookup may
// be called concurrently. The caller must not modify the return value.
func (b *Blocklist) LookupDomain(domain string) []BlocklistTag {

	if atomic.LoadInt32(&b.loaded) != 1 {
		return nil
	}

	tags, ok := b.data.Load().(*blocklistData).lookupDomain[domain]
	if !ok {
		return nil
	}
	return tags
}

func loadBlocklistFromFile(filename string) (*blocklistData, error) {

	data := newBlocklistData()

	file, err := os.Open(filename)
	if err != nil {
		return nil, errors.Trace(err)
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
			return nil, errors.Trace(err)
		}

		// Intern the source and subject strings so we only store one copy of
		// each in memory. These values are expected to repeat often.
		source := data.internString(record[1])
		subject := data.internString(record[2])

		tag := BlocklistTag{
			Source:  source,
			Subject: subject,
		}

		IPAddress := net.ParseIP(record[0])
		if IPAddress != nil {

			IPAddress16 := IPAddress.To16()
			if IPAddress16 == nil {
				return nil, errors.Tracef("invalid IP address: %s", record[0])
			}

			var key [net.IPv6len]byte
			copy(key[:], IPAddress16)

			tags := data.lookupIP[key]

			found := false
			for _, existingTag := range tags {
				if tag == existingTag {
					found = true
					break
				}
			}

			if !found {
				data.lookupIP[key] = append(tags, tag)
			}

		} else {

			key := record[0]

			tags := data.lookupDomain[key]

			found := false
			for _, existingTag := range tags {
				if tag == existingTag {
					found = true
					break
				}
			}

			if !found {
				data.lookupDomain[key] = append(tags, tag)
			}
		}
	}

	return data, nil
}

func newBlocklistData() *blocklistData {
	return &blocklistData{
		lookupIP:        make(map[[net.IPv6len]byte][]BlocklistTag),
		lookupDomain:    make(map[string][]BlocklistTag),
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
