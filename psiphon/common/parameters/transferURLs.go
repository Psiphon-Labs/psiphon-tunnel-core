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

package parameters

import (
	"encoding/base64"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
)

// TransferURL specifies a URL for uploading or downloading resources along
// with parameters for the transfer strategy.
type TransferURL struct {

	// URL is the location of the resource. This string is slightly obfuscated
	// with base64 encoding to mitigate trivial binary executable string scanning.
	URL string `json:",omitempty"`

	// SkipVerify indicates whether to verify HTTPS certificates. In some
	// circumvention scenarios, verification is not possible. This must
	// only be set to true when the resource has its own verification mechanism.
	// Overridden when a FrontingSpec in FrontingSpecs has verification fields
	// set.
	SkipVerify bool `json:",omitempty"`

	// OnlyAfterAttempts specifies how to schedule this URL when transferring
	// the same resource (same entity, same ETag) from multiple different
	// candidate locations. For a value of N, this URL is only a candidate
	// after N rounds of attempting the transfer to or from other URLs.
	OnlyAfterAttempts int `json:",omitempty"`

	// B64EncodedPublicKey is a base64-encoded RSA public key to be used for
	// encrypting the resource, when uploading, or for verifying a signature of
	// the resource, when downloading. Required by some operations, such as
	// uploading feedback.
	B64EncodedPublicKey string `json:",omitempty"`

	// RequestHeaders are optional HTTP headers to set on any requests made to
	// the destination.
	RequestHeaders map[string]string `json:",omitempty"`

	// FrontingSpecs is an optional set of domain fronting configurations to
	// apply to any requests made to the destination.
	FrontingSpecs FrontingSpecs `json:",omitempty"`
}

// TransferURLs is a list of transfer URLs.
type TransferURLs []*TransferURL

// DecodeAndValidate validates a list of transfer URLs.
//
// At least one TransferURL in the list must have OnlyAfterAttempts of 0,
// or no TransferURL would be selected on the first attempt.
func (t TransferURLs) DecodeAndValidate() error {

	hasOnlyAfterZero := false
	for _, transferURL := range t {

		// TransferURL FrontingSpecs are permitted to specify SkipVerify
		// because transfers have additional security at the payload level.
		allowSkipVerify := true
		err := transferURL.FrontingSpecs.Validate(allowSkipVerify)
		if err != nil {
			return errors.Trace(err)
		}

		if transferURL.OnlyAfterAttempts == 0 {
			hasOnlyAfterZero = true
		}
		decodedURL, err := base64.StdEncoding.DecodeString(transferURL.URL)
		if err != nil {
			return errors.Tracef("failed to decode URL: %s", err)
		}

		transferURL.URL = string(decodedURL)
	}

	if !hasOnlyAfterZero {
		return errors.Tracef("must be at least one TransferURL with OnlyAfterAttempts = 0")
	}

	return nil
}

// CanonicalURL returns the canonical URL, to be used as a key when storing
// information related to the TransferURLs, such as an ETag.
func (t TransferURLs) CanonicalURL() string {

	// The first OnlyAfterAttempts = 0 URL is the canonical URL. This
	// is the value used as the key for SetUrlETag when multiple download
	// URLs can be used to fetch a single entity.

	for _, transferURL := range t {
		if transferURL.OnlyAfterAttempts == 0 {
			return transferURL.URL
		}
	}

	return ""
}

// Select chooses a TransferURL from the list.
//
// The TransferURL is selected based at random from the candidates allowed in
// the specified attempt.
func (t TransferURLs) Select(attempt int) *TransferURL {

	candidates := make([]int, 0)
	for index, URL := range t {
		if attempt >= URL.OnlyAfterAttempts {
			candidates = append(candidates, index)
		}
	}

	if len(candidates) < 1 {
		// This case is not expected, as DecodeAndValidate should reject configs
		// that would have no candidates for 0 attempts.
		return nil
	}

	selection := prng.Intn(len(candidates))
	transferURL := t[candidates[selection]]

	return transferURL
}
