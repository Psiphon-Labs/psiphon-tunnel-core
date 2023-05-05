/*
 * Copyright (c) 2015, Psiphon Inc.
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

package protocol

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"testing"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
)

const (
	_VALID_NORMAL_SERVER_ENTRY                    = `192.168.0.1 80 <webServerSecret> <webServerCertificate> {"ipAddress":"192.168.0.1","webServerPort":"80","webServerSecret":"<webServerSecret>","webServerCertificate":"<webServerCertificate>","sshPort":22,"sshUsername":"<sshUsername>","sshPassword":"<sshPassword>","sshHostKey":"<sshHostKey>","sshObfuscatedPort":443,"sshObfuscatedKey":"<sshObfuscatedKey>","capabilities":["handshake","SSH","OSSH","VPN"],"region":"CA","meekServerPort":8080,"meekCookieEncryptionPublicKey":"<meekCookieEncryptionPublicKey>","meekObfuscatedKey":"<meekObfuscatedKey>","meekFrontingDomain":"<meekFrontingDomain>","meekFrontingHost":"<meekFrontingHost>"}`
	_VALID_BLANK_LEGACY_SERVER_ENTRY              = `    {"ipAddress":"192.168.0.1","webServerPort":"80","webServerSecret":"<webServerSecret>","webServerCertificate":"<webServerCertificate>","sshPort":22,"sshUsername":"<sshUsername>","sshPassword":"<sshPassword>","sshHostKey":"<sshHostKey>","sshObfuscatedPort":443,"sshObfuscatedKey":"<sshObfuscatedKey>","capabilities":["handshake","SSH","OSSH","VPN"],"region":"CA","meekServerPort":8080,"meekCookieEncryptionPublicKey":"<meekCookieEncryptionPublicKey>","meekObfuscatedKey":"<meekObfuscatedKey>","meekFrontingDomain":"<meekFrontingDomain>","meekFrontingHost":"<meekFrontingHost>"}`
	_VALID_FUTURE_SERVER_ENTRY                    = `192.168.0.1 80 <webServerSecret> <webServerCertificate> {"ipAddress":"192.168.0.1","webServerPort":"80","webServerSecret":"<webServerSecret>","webServerCertificate":"<webServerCertificate>","sshPort":22,"sshUsername":"<sshUsername>","sshPassword":"<sshPassword>","sshHostKey":"<sshHostKey>","sshObfuscatedPort":443,"sshObfuscatedKey":"<sshObfuscatedKey>","capabilities":["handshake","SSH","OSSH","VPN"],"region":"CA","meekServerPort":8080,"meekCookieEncryptionPublicKey":"<meekCookieEncryptionPublicKey>","meekObfuscatedKey":"<meekObfuscatedKey>","meekFrontingDomain":"<meekFrontingDomain>","meekFrontingHost":"<meekFrontingHost>","dummyFutureField":"dummyFutureField"}`
	_INVALID_WINDOWS_REGISTRY_LEGACY_SERVER_ENTRY = `192.168.0.1 80 <webServerSecret> <webServerCertificate> {"sshPort":22,"sshUsername":"<sshUsername>","sshPassword":"<sshPassword>","sshHostKey":"<sshHostKey>","sshObfuscatedPort":443,"sshObfuscatedKey":"<sshObfuscatedKey>","capabilities":["handshake","SSH","OSSH","VPN"],"region":"CA","meekServerPort":8080,"meekCookieEncryptionPublicKey":"<meekCookieEncryptionPublicKey>","meekObfuscatedKey":"<meekObfuscatedKey>","meekFrontingDomain":"<meekFrontingDomain>","meekFrontingHost":"<meekFrontingHost>"}`
	_INVALID_MALFORMED_IP_ADDRESS_SERVER_ENTRY    = `192.168.0.1 80 <webServerSecret> <webServerCertificate> {"ipAddress":"192.168.0.","webServerPort":"80","webServerSecret":"<webServerSecret>","webServerCertificate":"<webServerCertificate>","sshPort":22,"sshUsername":"<sshUsername>","sshPassword":"<sshPassword>","sshHostKey":"<sshHostKey>","sshObfuscatedPort":443,"sshObfuscatedKey":"<sshObfuscatedKey>","capabilities":["handshake","SSH","OSSH","VPN"],"region":"CA","meekServerPort":8080,"meekCookieEncryptionPublicKey":"<meekCookieEncryptionPublicKey>","meekObfuscatedKey":"<meekObfuscatedKey>","meekFrontingDomain":"<meekFrontingDomain>","meekFrontingHost":"<meekFrontingHost>"}`
	_EXPECTED_IP_ADDRESS                          = `192.168.0.1`
	_EXPECTED_DUMMY_FUTURE_FIELD                  = `dummyFutureField`
)

var testEncodedServerEntryList = hex.EncodeToString([]byte(_VALID_NORMAL_SERVER_ENTRY)) + "\n" +
	hex.EncodeToString([]byte(_VALID_BLANK_LEGACY_SERVER_ENTRY)) + "\n" +
	hex.EncodeToString([]byte(_VALID_FUTURE_SERVER_ENTRY)) + "\n" +
	hex.EncodeToString([]byte(_INVALID_WINDOWS_REGISTRY_LEGACY_SERVER_ENTRY)) + "\n" +
	hex.EncodeToString([]byte(_INVALID_MALFORMED_IP_ADDRESS_SERVER_ENTRY))

// DecodeServerEntryList should return 3 valid decoded entries from the input list of 5
func TestDecodeServerEntryList(t *testing.T) {

	serverEntries, err := DecodeServerEntryList(
		testEncodedServerEntryList, common.GetCurrentTimestamp(), SERVER_ENTRY_SOURCE_EMBEDDED)
	if err != nil {
		t.Error(err.Error())
		t.FailNow()
	}

	if len(serverEntries) != 3 {
		t.Error("unexpected number of valid server entries")
	}

	numFutureFields := 0

	for _, serverEntryFields := range serverEntries {
		if serverEntryFields.GetIPAddress() != _EXPECTED_IP_ADDRESS {
			t.Errorf("unexpected IP address in decoded server entry: %s", serverEntryFields.GetIPAddress())
		}
		if futureField, ok := serverEntryFields[_EXPECTED_DUMMY_FUTURE_FIELD]; ok {
			if futureFieldStr, ok := futureField.(string); ok && futureFieldStr == _EXPECTED_DUMMY_FUTURE_FIELD {
				numFutureFields += 1
			}
		}
	}

	if numFutureFields != 1 {
		t.Error("unexpected number of retained future fields")
	}
}

func TestStreamingServerEntryDecoder(t *testing.T) {

	decoder := NewStreamingServerEntryDecoder(
		bytes.NewReader([]byte(testEncodedServerEntryList)),
		common.GetCurrentTimestamp(), SERVER_ENTRY_SOURCE_EMBEDDED)

	serverEntries := make([]ServerEntryFields, 0)

	for {
		serverEntryFields, err := decoder.Next()
		if err != nil {
			t.Error(err.Error())
			t.FailNow()
		}

		if serverEntryFields == nil {
			break
		}

		serverEntries = append(serverEntries, serverEntryFields)
	}

	if len(serverEntries) != 3 {
		t.Error("unexpected number of valid server entries")
	}

	numFutureFields := 0

	for _, serverEntryFields := range serverEntries {
		if serverEntryFields.GetIPAddress() != _EXPECTED_IP_ADDRESS {
			t.Errorf("unexpected IP address in decoded server entry: %s", serverEntryFields.GetIPAddress())
		}
		if futureField, ok := serverEntryFields[_EXPECTED_DUMMY_FUTURE_FIELD]; ok {
			if futureFieldStr, ok := futureField.(string); ok && futureFieldStr == _EXPECTED_DUMMY_FUTURE_FIELD {
				numFutureFields += 1
			}
		}
	}

	if numFutureFields != 1 {
		t.Error("unexpected number of retained future fields")
	}
}

// Directly call DecodeServerEntryFields and ValidateServerEntry with invalid inputs
func TestInvalidServerEntries(t *testing.T) {

	testCases := [2]string{_INVALID_WINDOWS_REGISTRY_LEGACY_SERVER_ENTRY, _INVALID_MALFORMED_IP_ADDRESS_SERVER_ENTRY}

	for _, testCase := range testCases {
		encodedServerEntry := hex.EncodeToString([]byte(testCase))
		serverEntryFields, err := DecodeServerEntryFields(
			encodedServerEntry, common.GetCurrentTimestamp(), SERVER_ENTRY_SOURCE_EMBEDDED)
		if err != nil {
			t.Error(err.Error())
		}
		err = ValidateServerEntryFields(serverEntryFields)
		if err == nil {
			t.Errorf("server entry should not validate: %s", testCase)
		}
	}
}

// Directly call DecodeServerEntry
func TestDecodeServerEntryStruct(t *testing.T) {

	serverEntry, err := DecodeServerEntry(
		hex.EncodeToString([]byte(_VALID_NORMAL_SERVER_ENTRY)),
		common.GetCurrentTimestamp(), SERVER_ENTRY_SOURCE_EMBEDDED)
	if err != nil {
		t.Error(err.Error())
		t.FailNow()
	}
	if serverEntry.IpAddress != _EXPECTED_IP_ADDRESS {
		t.Errorf("unexpected IP address in decoded server entry: %s", serverEntry.IpAddress)
	}
}

func TestServerEntryListSignatures(t *testing.T) {
	testServerEntryListSignatures(t, true)
	testServerEntryListSignatures(t, false)
}

func testServerEntryListSignatures(t *testing.T, setExplicitTag bool) {

	publicKey, privateKey, err := NewServerEntrySignatureKeyPair()
	if err != nil {
		t.Fatalf("NewServerEntrySignatureKeyPair failed: %s", err)
	}

	n := 16
	serverEntry := &ServerEntry{
		IpAddress:                     prng.HexString(n),
		WebServerPort:                 strconv.Itoa(prng.Intn(n)),
		WebServerSecret:               prng.HexString(n),
		WebServerCertificate:          prng.HexString(n),
		SshPort:                       prng.Intn(n),
		SshUsername:                   prng.HexString(n),
		SshPassword:                   prng.HexString(n),
		SshHostKey:                    prng.HexString(n),
		SshObfuscatedPort:             prng.Intn(n),
		SshObfuscatedQUICPort:         prng.Intn(n),
		SshObfuscatedTapDancePort:     prng.Intn(n),
		SshObfuscatedConjurePort:      prng.Intn(n),
		SshObfuscatedKey:              prng.HexString(n),
		Capabilities:                  []string{prng.HexString(n)},
		Region:                        prng.HexString(n),
		MeekServerPort:                prng.Intn(n),
		MeekCookieEncryptionPublicKey: prng.HexString(n),
		MeekObfuscatedKey:             prng.HexString(n),
		MeekFrontingHost:              prng.HexString(n),
		MeekFrontingHosts:             []string{prng.HexString(n)},
		MeekFrontingDomain:            prng.HexString(n),
		MeekFrontingAddresses:         []string{prng.HexString(n)},
		MeekFrontingAddressesRegex:    prng.HexString(n),
		MeekFrontingDisableSNI:        false,
		TacticsRequestPublicKey:       prng.HexString(n),
		TacticsRequestObfuscatedKey:   prng.HexString(n),
		ConfigurationVersion:          1,
	}

	if setExplicitTag {
		serverEntry.Tag = prng.HexString(n)
	}

	// Convert ServerEntry to ServerEntryFields

	marshaledServerEntry, err := json.Marshal(serverEntry)
	if err != nil {
		t.Fatalf("Marshal failed: %s", err)
	}

	var serverEntryFields ServerEntryFields

	err = json.Unmarshal(marshaledServerEntry, &serverEntryFields)
	if err != nil {
		t.Fatalf("Unmarshal failed: %s", err)
	}

	// Check that local fields are ignored in the signature

	if !setExplicitTag {
		serverEntryFields.SetTag(prng.HexString(n))
	}
	serverEntryFields.SetLocalSource(prng.HexString(n))
	serverEntryFields.SetLocalTimestamp(prng.HexString(n))

	// Set dummy signature to check that its overwritten

	serverEntryFields["signature"] = prng.HexString(n)

	err = serverEntryFields.AddSignature(publicKey, privateKey)
	if err != nil {
		t.Fatalf("AddSignature failed: %s", err)
	}

	err = serverEntryFields.VerifySignature(publicKey)
	if err != nil {
		t.Fatalf("VerifySignature failed: %s", err)
	}

	// A 2nd VerifySignature call checks that the first VerifySignature
	// call leaves the server entry fields intact

	err = serverEntryFields.VerifySignature(publicKey)
	if err != nil {
		t.Fatalf("VerifySignature failed: %s", err)
	}

	// Modify local local fields and check that signature remains valid

	if !setExplicitTag {
		serverEntryFields.SetTag(prng.HexString(n))
	}
	serverEntryFields.SetLocalSource(prng.HexString(n))
	serverEntryFields.SetLocalTimestamp(prng.HexString(n))

	err = serverEntryFields.VerifySignature(publicKey)
	if err != nil {
		t.Fatalf("VerifySignature failed: %s", err)
	}

	// Check that verification fails when using the wrong public key

	incorrectPublicKey, _, err := NewServerEntrySignatureKeyPair()
	if err != nil {
		t.Fatalf("NewServerEntrySignatureKeyPair failed: %s", err)
	}

	err = serverEntryFields.VerifySignature(incorrectPublicKey)
	if err == nil {
		t.Fatalf("VerifySignature unexpectedly succeeded")
	}

	// Check that an expected, non-local field causes verification to fail

	serverEntryFields[prng.HexString(n)] = prng.HexString(n)

	err = serverEntryFields.VerifySignature(publicKey)
	if err == nil {
		t.Fatalf("AddSignature unexpectedly succeeded")
	}

	// Check that modifying a signed field causes verification to fail

	fieldName := "sshObfuscatedKey"
	if setExplicitTag {
		fieldName = "tag"
	}

	serverEntryFields[fieldName] = prng.HexString(n)

	err = serverEntryFields.VerifySignature(publicKey)
	if err == nil {
		t.Fatalf("AddSignature unexpectedly succeeded")
	}
}

func TestIsValidDialAddress(t *testing.T) {

	serverEntry := &ServerEntry{
		IpAddress:                  "192.168.0.1",
		SshPort:                    1,
		SshObfuscatedPort:          2,
		SshObfuscatedQUICPort:      3,
		Capabilities:               []string{"handshake", "SSH", "OSSH", "QUIC", "FRONTED-MEEK"},
		MeekFrontingAddressesRegex: "[ab]+",
		MeekServerPort:             443,
	}

	testCases := []struct {
		description     string
		networkProtocol string
		dialHost        string
		dialPortNumber  int
		isValid         bool
	}{
		{
			"valid IP dial",
			"tcp", "192.168.0.1", 1,
			true,
		},
		{
			"valid domain dial",
			"tcp", "aaabbbaaabbb", 443,
			true,
		},
		{
			"valid UDP dial",
			"tcp", "192.168.0.1", 1,
			true,
		},
		{
			"invalid network dial",
			"udp", "192.168.0.1", 1,
			false,
		},
		{
			"invalid IP dial",
			"tcp", "192.168.0.2", 1,
			false,
		},
		{
			"invalid domain dial",
			"tcp", "aaabbbcccbbb", 443,
			false,
		},
		{
			"invalid port dial",
			"tcp", "192.168.0.1", 4,
			false,
		},
		{
			"invalid domain port dial",
			"tcp", "aaabbbaaabbb", 80,
			false,
		},
		{
			"invalid domain newline dial",
			"tcp", "aaabbbaaabbb\nccc", 443,
			false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.description, func(t *testing.T) {
			if testCase.isValid != serverEntry.IsValidDialAddress(
				testCase.networkProtocol, testCase.dialHost, testCase.dialPortNumber) {

				t.Errorf("unexpected IsValidDialAddress result")
			}
		})
	}
}
