/*
 * Copyright (c) 2016, Psiphon Inc.
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

package obfuscator

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/crypto/ssh"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/transforms"
)

func TestObfuscator(t *testing.T) {

	keyword := prng.HexString(32)

	maxPadding := 256

	paddingPRNGSeed, err := prng.NewSeed()
	if err != nil {
		t.Fatalf("prng.NewSeed failed: %s", err)
	}

	var irregularLogFields common.LogFields

	// creates a seed of fixed value for testing

	config := &ObfuscatorConfig{
		IsOSSH:          true,
		Keyword:         keyword,
		MaxPadding:      &maxPadding,
		PaddingPRNGSeed: paddingPRNGSeed,
		ObfuscatorSeedTransformerParameters: &transforms.ObfuscatorSeedTransformerParameters{
			TransformName: "",
			TransformSeed: &prng.Seed{1},
			TransformSpec: transforms.Spec{{"^.{6}", "000000"}},
		},
		SeedHistory: NewSeedHistory(&SeedHistoryConfig{ClientIPTTL: 500 * time.Millisecond}),
		IrregularLogger: func(_ string, err error, logFields common.LogFields) {
			if logFields == nil {
				logFields = make(common.LogFields)
			}
			logFields["tunnel_error"] = err.Error()
			irregularLogFields = logFields
			t.Logf("IrregularLogger: %+v", logFields)
		},
	}

	client, err := NewClientObfuscator(config)
	if err != nil {
		t.Fatalf("NewClientObfuscator failed: %s", err)
	}

	preamble, _ := client.SendPreamble()

	server, err := NewServerObfuscator(config, "", bytes.NewReader(preamble))
	if err != nil {
		t.Fatalf("NewServerObfuscator failed: %s", err)
	}

	clientMessage := []byte("client hello")

	b := append([]byte(nil), clientMessage...)
	client.ObfuscateClientToServer(b)
	server.ObfuscateClientToServer(b)

	if !bytes.Equal(clientMessage, b) {
		t.Fatalf("unexpected client message")
	}

	serverMessage := []byte("server hello")

	b = append([]byte(nil), serverMessage...)
	client.ObfuscateServerToClient(b)
	server.ObfuscateServerToClient(b)

	if !bytes.Equal(serverMessage, b) {
		t.Fatalf("unexpected client message")
	}

	// Test: duplicate obfuscation seed cases

	client, err = NewClientObfuscator(config)
	if err != nil {
		t.Fatalf("NewClientObfuscator failed: %s", err)
	}

	preamble, _ = client.SendPreamble()

	clientIP := "192.168.0.1"

	_, err = NewServerObfuscator(config, clientIP, bytes.NewReader(preamble))
	if err != nil {
		t.Fatalf("NewServerObfuscator failed: %s", err)
	}

	irregularLogFields = nil

	_, err = NewServerObfuscator(config, clientIP, bytes.NewReader(preamble))
	if err == nil {
		t.Fatalf("NewServerObfuscator unexpectedly succeeded")
	}

	duplicateClientID := irregularLogFields["duplicate_client_ip"]
	if duplicateClientID != "equal" {
		t.Fatalf("Unexpected duplicate_client_ip: %s", duplicateClientID)
	}

	irregularLogFields = nil

	_, err = NewServerObfuscator(config, "192.168.0.2", bytes.NewReader(preamble))
	if err == nil {
		t.Fatalf("NewServerObfuscator unexpectedly succeeded")
	}

	duplicateClientID = irregularLogFields["duplicate_client_ip"]
	if duplicateClientID != "unequal" {
		t.Fatalf("Unexpected duplicate_client_ip: %s", duplicateClientID)
	}

	time.Sleep(600 * time.Millisecond)

	irregularLogFields = nil

	_, err = NewServerObfuscator(config, clientIP, bytes.NewReader(preamble))
	if err == nil {
		t.Fatalf("NewServerObfuscator unexpectedly succeeded")
	}

	duplicateClientID = irregularLogFields["duplicate_client_ip"]
	if duplicateClientID != "unknown" {
		t.Fatalf("Unexpected duplicate_client_ip: %s", duplicateClientID)
	}
}

func TestObfuscatorSeedTransformParameters(t *testing.T) {

	keyword := prng.HexString(32)

	maxPadding := 256

	paddingPRNGSeed, err := prng.NewSeed()
	if err != nil {
		t.Fatalf("prng.NewSeed failed: %s", err)
	}

	type test struct {
		name                 string
		transformerParamters *transforms.ObfuscatorSeedTransformerParameters

		// nil means seedMessage looks random (transformer was not applied)
		expectedResult       []byte
		expectedResultLength int
	}

	tests := []test{
		{
			name: "4 byte transform",
			transformerParamters: &transforms.ObfuscatorSeedTransformerParameters{
				TransformName: "four-zeros",
				TransformSeed: &prng.Seed{0},
				TransformSpec: transforms.Spec{{"^.{8}", "00000000"}},
			},
			expectedResult:       []byte{0, 0, 0, 0},
			expectedResultLength: 4,
		},
		{
			name: "invalid '%' character in the regex",
			transformerParamters: &transforms.ObfuscatorSeedTransformerParameters{
				TransformName: "invalid-spec",
				TransformSeed: &prng.Seed{0},
				TransformSpec: transforms.Spec{{"^.{8}", "%00000000"}},
			},
			expectedResult:       nil,
			expectedResultLength: 0,
		},
	}

	for _, tt := range tests {

		t.Run(tt.name, func(t *testing.T) {

			config := &ObfuscatorConfig{
				IsOSSH:                              true,
				Keyword:                             keyword,
				MaxPadding:                          &maxPadding,
				PaddingPRNGSeed:                     paddingPRNGSeed,
				ObfuscatorSeedTransformerParameters: tt.transformerParamters,
			}

			client, err := NewClientObfuscator(config)
			if err != nil {
				// if there is a expectedResult, then the error is unexpected
				if tt.expectedResult != nil {
					t.Fatalf("NewClientObfuscator failed: %s", err)
				}
				return
			}

			preamble, _ := client.SendPreamble()

			if tt.expectedResult == nil {

				// Verify that the seed message looks random.
				// obfuscator seed is generated with common.MakeSecureRandomBytes,
				// and is not affected by the config.
				popcount := 0
				for _, b := range preamble[:tt.expectedResultLength] {
					popcount += bits.OnesCount(uint(b))
				}
				popcount_per_byte := float64(popcount) / float64(tt.expectedResultLength)
				if popcount_per_byte < 3.6 || popcount_per_byte > 4.4 {
					t.Fatalf("unexpected popcount_per_byte: %f", popcount_per_byte)
				}

			} else if !bytes.Equal(preamble[:tt.expectedResultLength], tt.expectedResult) {
				t.Fatalf("unexpected seed message")
			}

		})

	}

}

// TestClientObfuscatorPrefixGen tests the generated prefix, terminator, and
// prefix header for the client obfuscator.
func TestClientObfuscatorPrefix(t *testing.T) {

	// fix keyword and seed for reproducing the same prefix

	keyword := prng.HexString(32)

	prefixSeed, err := prng.NewSeed()
	if err != nil {
		t.Fatalf("prng.NewSeed failed: %s", err)
	}

	generatePrefix := func(spec string) []byte {
		prefixSpec := OSSHPrefixSpec{
			Spec: transforms.Spec{{"", spec}},
			Seed: prefixSeed,
		}
		b, _, _ := makeTerminatedPrefixWithPadding(&prefixSpec, keyword, OBFUSCATE_CLIENT_TO_SERVER_IV)
		// Strips the terminator.
		return b[:len(b)-PREFIX_TERMINATOR_LENGTH]
	}

	type test struct {
		name       string
		prefixSpec transforms.Spec
		// The expected prefix bytes with padding (if any) and terminator.
		paddedTerminatedPrefixBytes []byte
		// Length of the prefix without padding and terminator.
		prefixLen int
	}

	tests := []test{
		{
			name:                        "24 byte prefix",
			prefixSpec:                  transforms.Spec{{"", "\\x00{24}"}},
			paddedTerminatedPrefixBytes: bytes.Repeat([]byte{0}, 24),
			prefixLen:                   24,
		},
		{
			name:                        "long prefix",
			prefixSpec:                  transforms.Spec{{"", "\\x00{1000}\\x00{1000}\\x00{1000}\\x00{1000}"}},
			paddedTerminatedPrefixBytes: bytes.Repeat([]byte{0}, 4000),
			prefixLen:                   4000,
		},
		{
			name:                        "short prefix spec",
			prefixSpec:                  transforms.Spec{{"", "\\x00\\x00\\x00\\x00"}},
			paddedTerminatedPrefixBytes: generatePrefix("\\x00\\x00\\x00\\x00"),
			prefixLen:                   4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			paddingPRNGSeed, err := prng.NewSeed()
			if err != nil {
				t.Fatalf("prng.NewSeed failed: %s", err)
			}

			config := &ObfuscatorConfig{
				IsOSSH:          true,
				Keyword:         keyword,
				PaddingPRNGSeed: paddingPRNGSeed,
				ClientPrefixSpec: &OSSHPrefixSpec{
					Name: tt.name,
					Spec: tt.prefixSpec,
					Seed: prefixSeed,
				},
			}

			client, err := NewClientObfuscator(config)
			if err != nil {
				t.Fatalf("NewClientObfuscator failed: %s", err)
			}

			preambleBytes, prefixLen := client.SendPreamble()
			preamble := bytes.NewBuffer(preambleBytes)

			// check prefix excluding any padding
			prefix := preamble.Next(prefixLen)
			if !bytes.Equal(prefix, tt.paddedTerminatedPrefixBytes[:tt.prefixLen]) {
				t.Fatalf("expected prefix to be all zeros")
			}

			// skips padding if any
			if tt.prefixLen < PREAMBLE_HEADER_LENGTH {
				preamble.Next(PREAMBLE_HEADER_LENGTH - tt.prefixLen)
			}

			// check terminator
			terminator := preamble.Next(PREFIX_TERMINATOR_LENGTH)
			expectedTerminator, err := makeTerminator(keyword, tt.paddedTerminatedPrefixBytes[:PREAMBLE_HEADER_LENGTH], OBFUSCATE_CLIENT_TO_SERVER_IV)
			if err != nil {
				t.Fatalf("makeTerminator failed: %s", err)
			}
			if !bytes.Equal(terminator, expectedTerminator) {
				t.Fatalf("unexpected terminator")
			}

			// OSSH key derivation
			seed := preamble.Next(OBFUSCATE_SEED_LENGTH)
			clientToServerCipher, _, err := initObfuscatorCiphers(config, seed)
			if err != nil {
				t.Fatalf("initObfuscatorCiphers failed: %s", err)
			}

			// skip OSSH initial client message
			osshInitialClientMsg := preamble.Next(8 + client.paddingLength) // 8: 4 bytes each for magic value and padding length
			clientToServerCipher.XORKeyStream(osshInitialClientMsg, osshInitialClientMsg)

			// read prefix header
			prefixHeader, err := readPrefixHeader(preamble, clientToServerCipher)
			if err != nil {
				t.Fatalf("readPrefixHeader failed: %s", err)
			}
			if prefixHeader.SpecName != tt.name {
				t.Fatalf("unexpected spec name")
			}
		})
	}

}

// TestServerObfuscatorPrefix tests server obfuscator reading prefixed
// stream from client obfuscator, and generating expected prefix.
func TestServerObfuscatorPrefix(t *testing.T) {

	keyword := prng.HexString(32)

	paddingPRNGSeed, err := prng.NewSeed()
	if err != nil {
		t.Fatalf("prng.NewSeed failed: %s", err)
	}

	prefixSeed, err := prng.NewSeed()
	if err != nil {
		t.Fatalf("prng.NewSeed failed: %s", err)
	}

	clientPrefixLen := prng.Intn(976) + PREAMBLE_HEADER_LENGTH // max 1000

	clientPrefixSpec := &OSSHPrefixSpec{
		Name: "zero-prefix",
		Spec: transforms.Spec{{"", fmt.Sprintf("\\x00{%d}", clientPrefixLen)}},
		Seed: prefixSeed,
	}

	serverPrefixSpec := transforms.Spec{{"", "(SERVER){4}"}}

	expectedServerPrefix := bytes.Repeat([]byte("SERVER"), 4)
	serverTermInd := 24 // index of terminator in server prefix

	config := &ObfuscatorConfig{
		IsOSSH:            true,
		Keyword:           keyword,
		PaddingPRNGSeed:   paddingPRNGSeed,
		ClientPrefixSpec:  clientPrefixSpec,
		ServerPrefixSpecs: transforms.Specs{"zero-prefix": serverPrefixSpec},
	}

	client, err := NewClientObfuscator(config)
	if err != nil {
		t.Fatalf("NewClientObfuscator failed: %s", err)
	}

	preamble, _ := client.SendPreamble()
	reader := WrapConnWithSkipReader(newConn(preamble))

	// test server obfuscator
	server, err := NewServerObfuscator(config, "", reader)
	if err != nil {
		t.Fatalf("NewServerObfuscator failed: %s", err)
	}

	// check server prefix reply
	serverPrefix, _ := server.SendPreamble()
	if !bytes.Equal(serverPrefix[:serverTermInd], expectedServerPrefix) {
		t.Fatalf("unexpected server prefix")
	}

	// check server terminator after prefix
	serverTerminator := serverPrefix[serverTermInd:]
	expectedTerminator, err := makeTerminator(keyword, serverPrefix, OBFUSCATE_SERVER_TO_CLIENT_IV)
	if err != nil {
		t.Fatalf("makeTerminator failed: %s", err)
	}
	if !bytes.Equal(serverTerminator, expectedTerminator) {
		t.Fatalf("unexpected terminator")
	}

	// check client terminator doesn't match server terminator
	clientTerminator := preamble[clientPrefixLen : clientPrefixLen+PREFIX_TERMINATOR_LENGTH]
	if bytes.Equal(clientTerminator, serverTerminator) {
		t.Fatalf("client terminator should not match server terminator")
	}

	clientMessage := []byte("client hello")

	b := append([]byte(nil), clientMessage...)
	client.ObfuscateClientToServer(b)
	server.ObfuscateClientToServer(b)

	if !bytes.Equal(clientMessage, b) {
		t.Fatalf("unexpected client message")
	}

	serverMessage := []byte("server hello")

	b = append([]byte(nil), serverMessage...)
	client.ObfuscateServerToClient(b)
	server.ObfuscateServerToClient(b)

	if !bytes.Equal(serverMessage, b) {
		t.Fatalf("unexpected client message")
	}

}

func TestIrregularConnections(t *testing.T) {
	keyword := prng.HexString(32)

	maxPadding := 256

	paddingPRNGSeed, err := prng.NewSeed()
	if err != nil {
		t.Fatalf("prng.NewSeed failed: %s", err)
	}

	var irregularLogFields common.LogFields

	clientPrefixSpec := &OSSHPrefixSpec{
		Name: "zeros",
		Spec: transforms.Spec{{"", "CLIENT\\x00{94}"}}, // 100 byte prefix
		Seed: &prng.Seed{0},
	}

	seedHistory := NewSeedHistory(&SeedHistoryConfig{ClientIPTTL: 500 * time.Millisecond})

	makeConfig := func(clientPrefix *OSSHPrefixSpec) *ObfuscatorConfig {
		return &ObfuscatorConfig{
			IsOSSH:           true,
			Keyword:          keyword,
			MaxPadding:       &maxPadding,
			PaddingPRNGSeed:  paddingPRNGSeed,
			ClientPrefixSpec: clientPrefix,
			SeedHistory:      seedHistory,
			IrregularLogger: func(_ string, err error, logFields common.LogFields) {
				if logFields == nil {
					logFields = make(common.LogFields)
				}
				logFields["tunnel_error"] = err.Error()
				irregularLogFields = logFields
				t.Logf("IrregularLogger: %+v", logFields)
			},
		}
	}

	config := makeConfig(clientPrefixSpec)
	seedInd := 100 + PREFIX_TERMINATOR_LENGTH

	// Prefixed client cases
	client, err := NewClientObfuscator(config)
	if err != nil {
		t.Fatalf("NewClientObfuscator failed: %s", err)
	}

	if client.osshPrefixHeader == nil {
		t.Fatalf("unexpected nil prefixHeader")
	}

	preamble, _ := client.SendPreamble()
	seed := hex.EncodeToString(preamble[seedInd : seedInd+OBFUSCATE_SEED_LENGTH])

	clientIP := "192.168.0.1"

	// Test: successful connection
	clientReader := WrapConnWithSkipReader(newConn(preamble))
	server, err := NewServerObfuscator(config, clientIP, clientReader)
	if err != nil {
		t.Fatalf("NewServerObfuscator failed: %s", err)
	}
	if server.osshPrefixHeader == nil {
		t.Fatalf("unexpected nil prefixHeader")
	}

	irregularLogFields = nil

	// Test: replayed prefixed connection with same IP
	clientReader = WrapConnWithSkipReader(newConn(preamble))
	_, err = NewServerObfuscator(config, clientIP, clientReader)
	if err == nil {
		t.Fatalf("NewServerObfuscator unexpectedly succeeded")
	}

	duplicateClientID := irregularLogFields["duplicate_client_ip"]
	if duplicateClientID != "equal" {
		t.Fatalf("Unexpected duplicate_client_ip: %s", duplicateClientID)
	}

	duplicateSeed := irregularLogFields["duplicate_seed"]
	if duplicateSeed != seed {
		t.Fatalf("Unexpected duplicate_seed: %s", duplicateSeed)
	}

	irregularLogFields = nil

	// Test: replayed prefixed connection with different IP
	clientReader = WrapConnWithSkipReader(newConn(preamble))
	_, err = NewServerObfuscator(config, "192.168.0.2", clientReader)
	if err == nil {
		t.Fatalf("NewServerObfuscator unexpectedly succeeded")
	}

	duplicateClientID = irregularLogFields["duplicate_client_ip"]
	if duplicateClientID != "unequal" {
		t.Fatalf("Unexpected duplicate_client_ip: %s", duplicateClientID)
	}

	duplicateSeed = irregularLogFields["duplicate_seed"]
	if duplicateSeed != seed {
		t.Fatalf("Unexpected duplicate_seed: %s", duplicateSeed)
	}

	irregularLogFields = nil

	// Test: replayed prefixed connection with same IP, but TTL expired
	time.Sleep(600 * time.Millisecond)

	clientReader = WrapConnWithSkipReader(newConn(preamble))
	_, err = NewServerObfuscator(config, clientIP, clientReader)
	if err == nil {
		t.Fatalf("NewServerObfuscator unexpectedly succeeded")
	}

	duplicateClientID = irregularLogFields["duplicate_client_ip"]
	if duplicateClientID != "unknown" {
		t.Fatalf("Unexpected duplicate_client_ip: %s", duplicateClientID)
	}

	duplicateSeed = irregularLogFields["duplicate_seed"]
	if duplicateSeed != seed {
		t.Fatalf("Unexpected duplicate_seed: %s", duplicateSeed)
	}

	irregularLogFields = nil

	// Test: Tacked on prefix from another connection, repeated seed
	previousPrefix := bytes.Repeat([]byte{1}, PREAMBLE_HEADER_LENGTH)
	terminator, err := makeTerminator(keyword, previousPrefix, OBFUSCATE_CLIENT_TO_SERVER_IV)
	if err != nil {
		t.Fatalf("makeTerminator failed: %s", err)
	}
	b := append(previousPrefix, terminator...)
	b = append(b, preamble[seedInd:]...)

	clientReader = WrapConnWithSkipReader(newConn(b))
	_, err = NewServerObfuscator(config, clientIP, clientReader)

	if err == nil {
		t.Fatalf("NewServerObfuscator failed: %s", err)
	}

	duplicateSeed = irregularLogFields["duplicate_seed"]
	if duplicateSeed != seed {
		t.Fatalf("Unexpected duplicate_seed: %s", duplicateSeed)
	}

	irregularLogFields = nil

	// Test: irregular logging of invalid magic value
	client, err = NewClientObfuscator(config)
	if err != nil {
		t.Fatalf("NewClientObfuscator failed: %s", err)
	}

	preamble, _ = client.SendPreamble()
	seedInd = 100 + PREFIX_TERMINATOR_LENGTH
	preamble[seedInd+OBFUSCATE_SEED_LENGTH] = 0x00 // mutate magic value

	clientReader = WrapConnWithSkipReader(newConn(preamble))
	server, err = NewServerObfuscator(config, clientIP, clientReader)
	if server != nil || err == nil {
		t.Fatalf("NewServerObfuscator unexpectedly succeeded")
	}

	tunnelError := irregularLogFields["tunnel_error"].(string)
	if !strings.Contains(tunnelError, "invalid magic value") {
		t.Fatalf("Unexpected tunnel_error: %s", tunnelError)
	}

	irregularLogFields = nil

	// Test: irregular logging of invalid padding length
	client, err = NewClientObfuscator(config)
	if err != nil {
		t.Fatalf("NewClientObfuscator failed: %s", err)
	}

	preamble, _ = client.SendPreamble()
	seedInd = 100 + PREFIX_TERMINATOR_LENGTH
	preamble[seedInd+OBFUSCATE_SEED_LENGTH+4] = 0x00 // mutate padding length

	clientReader = WrapConnWithSkipReader(newConn(preamble))
	server, err = NewServerObfuscator(config, clientIP, clientReader)
	if server != nil || err == nil {
		t.Fatalf("NewServerObfuscator unexpectedly succeeded")
	}

	tunnelError = irregularLogFields["tunnel_error"].(string)
	if !strings.Contains(tunnelError, "invalid padding length") {
		t.Fatalf("Unexpected tunnel_error: %s", tunnelError)
	}

	irregularLogFields = nil

}

func TestObfuscatedSSHConn(t *testing.T) {

	t.Run("non-prefixed", func(t *testing.T) {
		obfuscatedSSHConnTestHelper(t, nil, nil)
	})

	t.Run("prefixed", func(t *testing.T) {
		// prefixed obfuscated SSH
		seed, err := prng.NewSeed()
		if err != nil {
			t.Fatalf("prng.NewSeed failed: %s", err)
		}

		clientPrefixSpec := &OSSHPrefixSpec{
			Name: "spec-name",
			Spec: transforms.Spec{{"", "CLIENT"}},
			Seed: seed,
		}

		serverPrefixSpecs := transforms.Specs{
			"spec-name": transforms.Spec{{"", "SERVER"}},
		}

		obfuscatedSSHConnTestHelper(t, clientPrefixSpec, serverPrefixSpecs)
	})
}

func obfuscatedSSHConnTestHelper(
	t *testing.T, clientPrefixSpec *OSSHPrefixSpec, serverPrefixSpecs transforms.Specs) {

	t.Helper()

	keyword := prng.HexString(32)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %s", err)
	}

	serverAddress := listener.Addr().String()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey failed: %s", err)
	}

	hostKey, err := ssh.NewSignerFromKey(rsaKey)
	if err != nil {
		t.Fatalf("NewSignerFromKey failed: %s", err)
	}

	sshCertChecker := &ssh.CertChecker{
		HostKeyFallback: func(addr string, remote net.Addr, publicKey ssh.PublicKey) error {
			if !bytes.Equal(hostKey.PublicKey().Marshal(), publicKey.Marshal()) {
				return errors.New("unexpected host public key")
			}
			return nil
		},
	}

	result := make(chan error, 1)

	go func() {

		conn, err := listener.Accept()
		defer listener.Close()

		if err == nil {
			conn, err = NewServerObfuscatedSSHConn(
				conn,
				keyword,
				NewSeedHistory(nil),
				serverPrefixSpecs,
				func(_ string, err error, logFields common.LogFields) {
					t.Logf("IrregularLogger: %s %+v", err, logFields)
				})
		}

		if err == nil {
			config := &ssh.ServerConfig{
				NoClientAuth: true,
			}
			config.AddHostKey(hostKey)

			_, _, _, err = ssh.NewServerConn(conn, config)
		}

		obfuscatedConn := conn.(*ObfuscatedSSHConn)
		if obfuscatedConn.readState != OBFUSCATION_READ_STATE_FINISHED {
			result <- errors.New("server readState not finished")
		}

		if obfuscatedConn.writeState != OBFUSCATION_WRITE_STATE_FINISHED {
			result <- errors.New("server writeState not finished")
		}

		if err != nil {
			select {
			case result <- err:
			default:
			}
		}
	}()

	go func() {

		conn, err := net.DialTimeout("tcp", serverAddress, 5*time.Second)

		var paddingPRNGSeed *prng.Seed
		if err == nil {
			paddingPRNGSeed, err = prng.NewSeed()
		}

		if err == nil {
			conn, err = NewClientObfuscatedSSHConn(
				conn,
				keyword,
				paddingPRNGSeed,
				nil, clientPrefixSpec, nil, nil, nil)
		}

		var KEXPRNGSeed *prng.Seed
		if err == nil {
			KEXPRNGSeed, err = prng.NewSeed()
		}

		if err == nil {
			config := &ssh.ClientConfig{
				HostKeyCallback: sshCertChecker.CheckHostKey,
			}
			config.KEXPRNGSeed = KEXPRNGSeed
			_, _, _, err = ssh.NewClientConn(conn, "", config)
		}

		obfuscatedConn := conn.(*ObfuscatedSSHConn)
		if obfuscatedConn.readState != OBFUSCATION_READ_STATE_FINISHED {
			result <- errors.New("client readState not finished")
		}

		if obfuscatedConn.writeState != OBFUSCATION_WRITE_STATE_FINISHED {
			result <- errors.New("client writeState not finished")
		}

		// Sends nil on success
		select {
		case result <- err:
		default:
		}
	}()

	err = <-result
	if err != nil {
		t.Fatalf("obfuscated SSH handshake failed: %s", err)
	}
}

func newConn(b []byte) net.Conn {
	conn1, conn2 := net.Pipe()

	go func() {
		defer conn2.Close()
		conn2.Write(b)
	}()

	return conn1
}
