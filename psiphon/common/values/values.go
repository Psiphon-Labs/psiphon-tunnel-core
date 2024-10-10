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
	"fmt"
	"regexp/syntax"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/regen"
	"golang.org/x/crypto/nacl/secretbox"
)

// ValueSpec specifies a value selection space.
type ValueSpec struct {
	Probability float64
	Parts       []PartSpec
	Padding     []byte
}

type PartSpec struct {
	Items              []string
	MinCount, MaxCount int
}

// NewPickOneSpec creates a simple spec to select one item from a list as a
// value.
func NewPickOneSpec(items []string) *ValueSpec {
	return &ValueSpec{
		Probability: 1.0,
		Parts:       []PartSpec{{Items: items, MinCount: 1, MaxCount: 1}},
	}
}

// GetValue selects a value according to the spec. An optional seed may
// be specified to support replay.
func (spec *ValueSpec) GetValue(PRNG *prng.PRNG) string {
	rangeFunc := prng.Range
	intnFunc := prng.Intn
	if PRNG != nil {
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
	cookieNamesSpec       atomic.Value
	contentTypeSpec       atomic.Value
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
	if !ok || !prng.FlipWeightedCoin(spec.Probability) {
		return generate(prng.DefaultPRNG(), "SSH-2\\.0-OpenSSH_[7-8]\\.[0-9]")
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
	var PRNG *prng.PRNG
	if seed != nil {
		PRNG = prng.NewPRNGWithSeed(seed)
	}
	spec, ok := sshServerVersionsSpec.Load().(*ValueSpec)
	if !ok || !PRNG.FlipWeightedCoin(spec.Probability) {
		return generate(PRNG, "SSH-2\\.0-OpenSSH_[7-8]\\.[0-9]")
	}
	return spec.GetValue(PRNG)
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
	if !ok || !prng.FlipWeightedCoin(spec.Probability) {
		return generateUserAgent()
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
	if !ok || !prng.FlipWeightedCoin(spec.Probability) {
		return generate(prng.DefaultPRNG(), "[a-z]{4,15}(\\.com|\\.net|\\.org)")
	}
	return spec.GetValue(nil)
}

// SetCookieNamesSpec sets the corresponding value spec.
func SetCookieNamesSpec(spec *ValueSpec) {
	if spec == nil {
		return
	}
	cookieNamesSpec.Store(spec)
}

// GetCookieName selects a value based on the previously set spec, or
// returns a default when no spec is set.
func GetCookieName(PRNG *prng.PRNG) string {
	spec, ok := cookieNamesSpec.Load().(*ValueSpec)
	if !ok || !PRNG.FlipWeightedCoin(spec.Probability) {
		return generate(PRNG, "[a-z_]{2,10}")
	}
	return spec.GetValue(PRNG)
}

// SetContentTypesSpec sets the corresponding value spec.
func SetContentTypesSpec(spec *ValueSpec) {
	if spec == nil {
		return
	}
	contentTypeSpec.Store(spec)
}

// GetContentType selects a value based on the previously set spec, or
// returns a default when no spec is set.
func GetContentType(PRNG *prng.PRNG) string {
	spec, ok := contentTypeSpec.Load().(*ValueSpec)
	if !ok || !PRNG.FlipWeightedCoin(spec.Probability) {
		return generate(PRNG, "application/octet-stream|audio/mpeg|image/jpeg|video/mpeg")
	}
	return spec.GetValue(PRNG)
}

// generate string given the regexp pattern.
// generate is intended to be used with hardcoded inputs, and panics on error.
func generate(PRNG *prng.PRNG, pattern string) string {

	args := &regen.GeneratorArgs{
		RngSource: PRNG,
		Flags:     syntax.OneLine | syntax.NonGreedy,
	}
	rg, err := regen.NewGenerator(pattern, args)
	if err != nil {
		panic(err.Error())
	}
	value, err := rg.Generate()
	if err != nil {
		panic(err.Error())
	}
	return string(value)
}

var (
	userAgentGeneratorMutex sync.Mutex
	userAgentGenerators     []*userAgentGenerator
)

type userAgentGenerator struct {
	version   func() string
	generator regen.Generator
}

func generateUserAgent() string {

	userAgentGeneratorMutex.Lock()
	defer userAgentGeneratorMutex.Unlock()

	if userAgentGenerators == nil {

		// Initialize user agent generators once and reuse. This saves the
		// overhead of parsing the relatively complex regular expressions on
		// each GetUserAgent call.

		// These regular expressions and version ranges are adapted from:
		//
		// https://github.com/tarampampam/random-user-agent/blob/d0dd4059ac518e8b0f79510d050877c685539fbc/src/useragent/generator.ts
		// https://github.com/tarampampam/random-user-agent/blob/d0dd4059ac518e8b0f79510d050877c685539fbc/src/useragent/versions.ts

		chromeVersion := func() string {
			return fmt.Sprintf("%d.0.%d.%d",
				prng.Range(101, 104), prng.Range(4951, 5162), prng.Range(80, 212))
		}

		safariVersion := func() string {
			return fmt.Sprintf("%d.%d.%d",
				prng.Range(537, 611), prng.Range(1, 36), prng.Range(1, 15))
		}

		makeGenerator := func(pattern string) regen.Generator {
			args := &regen.GeneratorArgs{
				RngSource: prng.DefaultPRNG(),
				Flags:     syntax.OneLine | syntax.NonGreedy,
			}
			rg, err := regen.NewGenerator(pattern, args)
			if err != nil {
				panic(err.Error())
			}
			return rg
		}

		userAgentGenerators = []*userAgentGenerator{
			{chromeVersion, makeGenerator("Mozilla/5\\.0 \\(Macintosh; Intel Mac OS X 1[01]_(1|)[0-5]\\) AppleWebKit/537\\.36 \\(KHTML, like Gecko\\) Chrome/__VER__ Safari/537\\.36")},
			{chromeVersion, makeGenerator("Mozilla/5\\.0 \\(Windows NT 1(0|0|1)\\.0; (WOW64|Win64)(; x64|; x64|)\\) AppleWebKit/537\\.36 \\(KHTML, like Gecko\\) Chrome/__VER__ Safari/537\\.36")},
			{chromeVersion, makeGenerator("Mozilla/5\\.0 \\(Linux; Android (9|10|10|11|12); [a-zA-Z0-9_]{5,10}\\) AppleWebKit/537\\.36 \\(KHTML, like Gecko\\) Chrome/__VER__ Mobile Safari/537\\.36")},
			{safariVersion, makeGenerator("Mozilla/5\\.0 \\(iPhone; CPU iPhone OS 1[3-5]_[1-5] like Mac OS X\\) AppleWebKit/(__VER__|__VER__|600\\.[1-8]\\.[12][0-7]|537\\.36) \\(KHTML, like Gecko\\) Version/1[0-4]\\.[0-7](\\.[1-9][0-7]|) Mobile/[A-Z0-9]{6} Safari/__VER__")},
			{safariVersion, makeGenerator("Mozilla/5\\.0 \\(Macintosh; Intel Mac OS X 1[01]_(1|)[0-7](_[1-7]|)\\) AppleWebKit/(__VER__|__VER__|600\\.[1-8]\\.[12][0-7]|537\\.36) \\(KHTML, like Gecko\\) Version/1[0-4]\\.[0-7](\\.[1-9][0-7]|) Safari/__VER__")},
		}
	}

	g := userAgentGenerators[prng.Range(0, len(userAgentGenerators)-1)]

	bytes, err := g.generator.Generate()
	if err != nil {
		panic(err.Error())
	}
	value := string(bytes)
	value = strings.ReplaceAll(value, "__VER__", g.version())
	return value
}
