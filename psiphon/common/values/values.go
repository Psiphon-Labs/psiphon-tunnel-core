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

Package values provides a mechanism for specifying and selecting dynamic
values employed by the Psiphon client and server.

*/
package values

import (
	"bytes"
	"encoding/gob"
	"strings"
	"sync/atomic"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"golang.org/x/crypto/nacl/secretbox"
)

// ValueSpec specifies a value selection space.
type ValueSpec struct {
	Parts   []PartSpec
	Padding []byte
}

type PartSpec struct {
	Items              []string
	MinCount, MaxCount int
}

// NewPickOneSpec creates a simple spec to select one item from a list as a
// value.
func NewPickOneSpec(items []string) *ValueSpec {
	return &ValueSpec{Parts: []PartSpec{{Items: items, MinCount: 1, MaxCount: 1}}}
}

// GetValue selects a value according to the spec. An optional seed may
// be specified to support replay.
func (spec *ValueSpec) GetValue(seed *prng.Seed) string {
	rangeFunc := prng.Range
	intnFunc := prng.Intn
	if seed != nil {
		PRNG := prng.NewPRNGWithSeed(seed)
		rangeFunc = PRNG.Range
		intnFunc = PRNG.Intn
	}
	var value strings.Builder
	for _, part := range spec.Parts {
		count := rangeFunc(part.MinCount, part.MaxCount)
		for i := 0; i < count; i++ {
			value.WriteString(part.Items[intnFunc(len(part.Items))])
		}
	}
	return value.String()
}

// Obfuscate creates an obfuscated blob from a spec.
func (spec *ValueSpec) Obfuscate(
	obfuscationKey []byte,
	minPadding, maxPadding int) ([]byte, error) {

	if len(obfuscationKey) != 32 {
		return nil, errors.TraceNew("invalid key length")
	}
	var key [32]byte
	copy(key[:], []byte(obfuscationKey))

	spec.Padding = prng.Padding(minPadding, maxPadding)

	var obfuscatedValueSpec bytes.Buffer
	err := gob.NewEncoder(&obfuscatedValueSpec).Encode(spec)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return secretbox.Seal(
		nil, []byte(obfuscatedValueSpec.Bytes()), &[24]byte{}, &key), nil
}

// DeobfuscateValueSpec reconstitutes an obfuscated spec.
func DeobfuscateValueSpec(obfuscatedValueSpec, obfuscationKey []byte) *ValueSpec {

	if len(obfuscationKey) != 32 {
		return nil
	}
	var key [32]byte
	copy(key[:], obfuscationKey)

	deobfuscatedValueSpec, ok := secretbox.Open(nil, obfuscatedValueSpec, &[24]byte{}, &key)
	if !ok {
		return nil
	}

	spec := new(ValueSpec)
	err := gob.NewDecoder(bytes.NewBuffer(deobfuscatedValueSpec)).Decode(spec)
	if err != nil {
		return nil
	}
	spec.Padding = nil

	return spec
}

var (
	revision              atomic.Value
	sshClientVersionsSpec atomic.Value
	sshServerVersionsSpec atomic.Value
	userAgentsSpec        atomic.Value
	hostNamesSpec         atomic.Value
)

// SetRevision set the revision value, which may be used to track which value
// specs are active. The revision is not managed by this package and must be
// set by the package user.
func SetRevision(rev string) {
	revision.Store(rev)
}

// GetRevision gets the previously set revision.
func GetRevision() string {
	rev, ok := revision.Load().(string)
	if !ok {
		return "none"
	}
	return rev
}

// SetSSHClientVersionsSpec sets the corresponding value spec.
func SetSSHClientVersionsSpec(spec *ValueSpec) {
	if spec == nil {
		return
	}
	sshClientVersionsSpec.Store(spec)
}

// GetSSHClientVersion selects a value based on the previously set spec, or
// returns a default when no spec is set.
func GetSSHClientVersion() string {
	spec, ok := sshClientVersionsSpec.Load().(*ValueSpec)
	if !ok {
		return ""
	}
	return spec.GetValue(nil)
}

// SetSSHServerVersionsSpec sets the corresponding value spec.
func SetSSHServerVersionsSpec(spec *ValueSpec) {
	if spec == nil {
		return
	}
	sshServerVersionsSpec.Store(spec)
}

// GetSSHServerVersion selects a value based on the previously set spec, or
// returns a default when no spec is set.
func GetSSHServerVersion(seed *prng.Seed) string {
	spec, ok := sshServerVersionsSpec.Load().(*ValueSpec)
	if !ok {
		return ""
	}
	return spec.GetValue(seed)
}

// SetUserAgentsSpec sets the corresponding value spec.
func SetUserAgentsSpec(spec *ValueSpec) {
	if spec == nil {
		return
	}
	userAgentsSpec.Store(spec)
}

// GetUserAgent selects a value based on the previously set spec, or
// returns a default when no spec is set.
func GetUserAgent() string {
	spec, ok := userAgentsSpec.Load().(*ValueSpec)
	if !ok {
		return ""
	}
	return spec.GetValue(nil)
}

// SetHostNamesSpec sets the corresponding value spec.
func SetHostNamesSpec(spec *ValueSpec) {
	if spec == nil {
		return
	}
	hostNamesSpec.Store(spec)
}

// GetHostName selects a value based on the previously set spec, or
// returns a default when no spec is set.
func GetHostName() string {
	spec, ok := hostNamesSpec.Load().(*ValueSpec)
	if !ok {
		return "www.example.org"
	}
	return spec.GetValue(nil)
}
