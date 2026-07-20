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

package ssh

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net"
	"strings"
	"testing"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"golang.org/x/sync/errgroup"
)

func TestRandomizedSSHKEXes(t *testing.T) {
	err := runTestRandomizedSSHKEXes(false)
	if err != nil {
		t.Errorf("runTestRandomizedSSHKEXes failed: %s", err)
		return
	}
}

func TestLegacyRandomizedSSHKEXes(t *testing.T) {
	err := runTestRandomizedSSHKEXes(true)
	if err != nil {
		t.Errorf("runTestRandomizedSSHKEXes failed: %s", err)
		return
	}
}

func runTestRandomizedSSHKEXes(legacyClient bool) error {

	rsaKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return errors.Trace(err)
	}

	signer, err := NewSignerFromKey(rsaKey)
	if err != nil {
		return errors.Trace(err)
	}

	publicKey := signer.PublicKey()

	username := "username"
	password := "password"

	testLegacyClient = legacyClient
	defer func() {
		testLegacyClient = false
	}()

	testCases := []struct {
		name                     string
		doPeerKEXPRNGSeed        bool
		doServerKEXRandomization bool
		noEncryptThenMACHash     bool
		expectFailure            bool
	}{
		{"randomized server with prediction", true, true, false, false},
		{"randomized server with prediction, no Encrypt-then-MAC", true, true, true, false},
		{"randomized server without prediction", false, true, false, true},
		{"OSSH non-randomized server", false, false, true, false},
		{"non-randomized server, Encrypt-then-MAC allowed", false, false, false, false},
	}

	for _, testCase := range testCases {

		failed := false

		for i := 0; i < 1000; i++ {

			clientSeed, err := prng.NewSeed()
			if err != nil {
				return errors.Trace(err)
			}

			serverSeed, err := prng.NewSeed()
			if err != nil {
				return errors.Trace(err)
			}

			clientConn, serverConn, err := netPipe()
			if err != nil {
				return errors.Trace(err)
			}

			testGroup, _ := errgroup.WithContext(context.Background())

			// Client

			testGroup.Go(func() error {

				certChecker := &CertChecker{
					HostKeyFallback: func(addr string, remote net.Addr, key PublicKey) error {
						if !bytes.Equal(publicKey.Marshal(), key.Marshal()) {
							return errors.TraceNew("unexpected host public key")
						}
						return nil
					},
				}

				clientConfig := &ClientConfig{
					User:            username,
					Auth:            []AuthMethod{Password(password)},
					HostKeyCallback: certChecker.CheckHostKey,
				}

				clientConfig.KEXPRNGSeed = clientSeed

				clientConfig.NoEncryptThenMACHash = testCase.noEncryptThenMACHash

				if testCase.doPeerKEXPRNGSeed {
					clientConfig.PeerKEXPRNGSeed = serverSeed
				}

				clientSSHConn, _, _, err := NewClientConn(clientConn, "", clientConfig)
				if err != nil {
					return errors.Trace(err)
				}

				if !legacyClient {
					// Ensure SHA-1 is not negotiated.
					isSHA1 := func(s string) bool {
						return strings.Contains(s, "sha1") ||
							s == KeyAlgoRSA || s == CertAlgoRSAv01 ||
							s == InsecureKeyAlgoDSA || s == InsecureCertAlgoDSAv01
					}
					algorithms := clientSSHConn.(AlgorithmsConnMetadata).Algorithms()
					if isSHA1(algorithms.KeyExchange) ||
						isSHA1(algorithms.HostKey) ||
						isSHA1(algorithms.Read.MAC) ||
						isSHA1(algorithms.Write.MAC) {
						return errors.Tracef(
							"SHA-1 algorithm negotiated: kex=%q hostkey=%q read_mac=%q write_mac=%q",
							algorithms.KeyExchange,
							algorithms.HostKey,
							algorithms.Read.MAC,
							algorithms.Write.MAC)
					}
				}

				clientSSHConn.Close()
				clientConn.Close()
				return nil
			})

			// Server

			testGroup.Go(func() error {

				insecurePasswordCallback := func(c ConnMetadata, pass []byte) (*Permissions, error) {
					if c.User() == username && string(pass) == password {
						return nil, nil
					}
					return nil, errors.TraceNew("authentication failed")
				}

				serverConfig := &ServerConfig{
					PasswordCallback: insecurePasswordCallback,
				}
				serverConfig.NoEncryptThenMACHash = testCase.noEncryptThenMACHash
				serverConfig.AddHostKey(signer)

				if testCase.doServerKEXRandomization {
					serverConfig.KEXPRNGSeed = serverSeed
				}

				serverSSHConn, _, _, err := NewServerConn(serverConn, serverConfig)
				if err != nil {
					return errors.Trace(err)
				}

				serverSSHConn.Close()
				serverConn.Close()
				return nil
			})

			err = testGroup.Wait()
			if err != nil {

				if testCase.expectFailure {
					failed = true
					break
				}
				return errors.Tracef("%s: unexpected failure to negotiate: %v", testCase.name, err)
			}
		}

		if testCase.expectFailure && !failed {
			return errors.Tracef("%s: unexpected success", testCase.name)
		}
	}
	return nil
}
