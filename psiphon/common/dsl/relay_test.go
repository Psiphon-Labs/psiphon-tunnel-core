/*
 * Copyright (c) 2026, Psiphon Inc.
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

package dsl

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/internal/testutils"
)

func TestRelayReloadFileError(t *testing.T) {
	tlsConfig, err := testutils.NewTestDSLTLSConfig()
	if err != nil {
		t.Fatal(err)
	}

	for _, changeCA := range []bool{false, true} {
		t.Run(fmt.Sprintf("changed=%t", changeCA), func(t *testing.T) {
			caFilename, certificateFilename, keyFilename, err := tlsConfig.WriteRelayFiles(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			relay, err := NewRelay(&RelayConfig{
				CACertificatesFilename:  caFilename,
				HostCertificateFilename: certificateFilename,
				HostKeyFilename:         keyFilename,
			})
			if err != nil {
				t.Fatal(err)
			}
			originalTLSConfig := relay.tlsConfig
			postActionCalls := 0
			postAction := func() error {
				postActionCalls++
				return nil
			}

			caContents := tlsConfig.CACertificatePEM
			if changeCA {
				// Change the hash while retaining a valid CA bundle.
				caContents = append([]byte("\n"), caContents...)
				err = os.WriteFile(caFilename, caContents, 0600)
				if err != nil {
					t.Fatal(err)
				}
			}
			err = os.Remove(certificateFilename)
			if err != nil {
				t.Fatal(err)
			}

			expectedHashes := []string{
				fmt.Sprintf("%x", sha256.Sum256(caContents)),
				"",
				fmt.Sprintf("%x", sha256.Sum256(tlsConfig.RelayKeyPEM)),
			}
			// The same errors must remain visible after the new CA hash has
			// already been observed on a previous attempt.
			for attempt := 0; attempt < 2; attempt++ {
				results := relay.Reload(postAction)
				err = results.Err()
				if !errors.Is(err, os.ErrNotExist) || len(results) != len(expectedHashes) {
					t.Fatalf("unexpected failed reload: %+v, %v", results, err)
				}
				for i, result := range results {
					if result.Reloaded || result.HashSHA256 != expectedHashes[i] ||
						len(result.Errors) != 1 || !errors.Is(result.Errors[0], os.ErrNotExist) {
						t.Fatalf("unexpected result for file %d: %+v", i, result)
					}
					hasContext := strings.Contains(result.Errors[0].Error(), "TLS configuration reload failed")
					if hasContext != (i != 1) {
						t.Fatalf("unexpected error context for file %d: %v", i, result.Errors)
					}
				}
				if relay.tlsConfig != originalTLSConfig || postActionCalls != 0 {
					t.Fatal("failed reload applied TLS configuration or ran post action")
				}
			}

			// Restore the missing file with its original contents. A pending
			// CA change must be applied even though no file hash changes now.
			err = os.WriteFile(certificateFilename, tlsConfig.RelayCertificatePEM, 0600)
			if err != nil {
				t.Fatal(err)
			}
			expectedHashes[1] = fmt.Sprintf("%x", sha256.Sum256(tlsConfig.RelayCertificatePEM))
			results := relay.Reload(postAction)
			err = results.Err()
			if err != nil || len(results) != len(expectedHashes) {
				t.Fatalf("unexpected retry results: %+v, %v", results, err)
			}
			for i, result := range results {
				if result.Reloaded != changeCA || result.HashSHA256 != expectedHashes[i] || len(result.Errors) != 0 {
					t.Fatalf("unexpected retry result for file %d: %+v", i, result)
				}
			}
			expectedPostActionCalls := 0
			if changeCA {
				expectedPostActionCalls = 1
			}
			if (relay.tlsConfig != originalTLSConfig) != changeCA || postActionCalls != expectedPostActionCalls {
				t.Fatal("unexpected TLS configuration or post action after retry")
			}

			results = relay.Reload(postAction)
			err = results.Err()
			if err != nil || results.Reloaded() || postActionCalls != expectedPostActionCalls {
				t.Fatalf("unexpected reload after recovery: %+v, %v", results, err)
			}
		})
	}
}
