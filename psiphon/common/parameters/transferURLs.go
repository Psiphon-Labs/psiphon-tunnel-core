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
	URL string

	// SkipVerify indicates whether to verify HTTPS certificates. It some
	// circumvention scenarios, verification is not possible. This must
	// only be set to true when the resource has its own verification mechanism.
	SkipVerify bool

	// OnlyAfterAttempts specifies how to schedule this URL when transferring
	// the same resource (same entity, same ETag) from multiple different
	// candidate locations. For a value of N, this URL is only a candidate
	// after N rounds of attempting the transfer to or from other URLs.
	OnlyAfterAttempts int
}

// TransferURLs is a list of transfer URLs.
type TransferURLs []*TransferURL

// DecodeAndValidate validates a list of download URLs.
//
// At least one TransferURL in the list must have OnlyAfterAttempts of 0,
// or no TransferURL would be selected on the first attempt.
func (t TransferURLs) DecodeAndValidate() error {

	hasOnlyAfterZero := false
	for _, transferURL := range t {
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

// Select chooses a TransferURL from the list.
//
// The first return value is the canonical URL, to be used
// as a key when storing information related to the TransferURLs,
// such as an ETag.
//
// The second return value is the chosen transfer URL, which is
// selected based at random from the candidates allowed in the
// specified attempt.
func (t TransferURLs) Select(attempt int) (string, string, bool) {

	// The first OnlyAfterAttempts = 0 URL is the canonical URL. This
	// is the value used as the key for SetUrlETag when multiple download
	// URLs can be used to fetch a single entity.

	canonicalURL := ""
	for _, transferURL := range t {
		if transferURL.OnlyAfterAttempts == 0 {
			canonicalURL = transferURL.URL
			break
		}
	}

	candidates := make([]int, 0)
	for index, URL := range t {
		if attempt >= URL.OnlyAfterAttempts {
			candidates = append(candidates, index)
		}
	}

	if len(candidates) < 1 {
		// This case is not expected, as decodeAndValidateTransferURLs
		// should reject configs that would have no candidates for
		// 0 attempts.
		return "", "", true
	}

	selection := prng.Intn(len(candidates))
	transferURL := t[candidates[selection]]

	return transferURL.URL, canonicalURL, transferURL.SkipVerify
}
