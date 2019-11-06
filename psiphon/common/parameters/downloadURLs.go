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

// DownloadURL specifies a URL for downloading resources along with parameters
// for the download strategy.
type DownloadURL struct {

	// URL is the location of the resource. This string is slightly obfuscated
	// with base64 encoding to mitigate trivial binary executable string scanning.
	URL string

	// SkipVerify indicates whether to verify HTTPS certificates. It some
	// circumvention scenarios, verification is not possible. This must
	// only be set to true when the resource has its own verification mechanism.
	SkipVerify bool

	// OnlyAfterAttempts specifies how to schedule this URL when downloading
	// the same resource (same entity, same ETag) from multiple different
	// candidate locations. For a value of N, this URL is only a candidate
	// after N rounds of attempting the download from other URLs.
	OnlyAfterAttempts int
}

// DownloadURLs is a list of download URLs.
type DownloadURLs []*DownloadURL

// DecodeAndValidate validates a list of download URLs.
//
// At least one DownloadURL in the list must have OnlyAfterAttempts of 0,
// or no DownloadURL would be selected on the first attempt.
func (d DownloadURLs) DecodeAndValidate() error {

	hasOnlyAfterZero := false
	for _, downloadURL := range d {
		if downloadURL.OnlyAfterAttempts == 0 {
			hasOnlyAfterZero = true
		}
		decodedURL, err := base64.StdEncoding.DecodeString(downloadURL.URL)
		if err != nil {
			return errors.Tracef("failed to decode URL: %s", err)
		}

		downloadURL.URL = string(decodedURL)
	}

	if !hasOnlyAfterZero {
		return errors.Tracef("must be at least one DownloadURL with OnlyAfterAttempts = 0")
	}

	return nil
}

// Select chooses a DownloadURL from the list.
//
// The first return value is the canonical URL, to be used
// as a key when storing information related to the DownloadURLs,
// such as an ETag.
//
// The second return value is the chosen download URL, which is
// selected based at random from the candidates allowed in the
// specified attempt.
func (d DownloadURLs) Select(attempt int) (string, string, bool) {

	// The first OnlyAfterAttempts = 0 URL is the canonical URL. This
	// is the value used as the key for SetUrlETag when multiple download
	// URLs can be used to fetch a single entity.

	canonicalURL := ""
	for _, downloadURL := range d {
		if downloadURL.OnlyAfterAttempts == 0 {
			canonicalURL = downloadURL.URL
			break
		}
	}

	candidates := make([]int, 0)
	for index, URL := range d {
		if attempt >= URL.OnlyAfterAttempts {
			candidates = append(candidates, index)
		}
	}

	if len(candidates) < 1 {
		// This case is not expected, as decodeAndValidateDownloadURLs
		// should reject configs that would have no candidates for
		// 0 attempts.
		return "", "", true
	}

	selection := prng.Intn(len(candidates))
	downloadURL := d[candidates[selection]]

	return downloadURL.URL, canonicalURL, downloadURL.SkipVerify
}
