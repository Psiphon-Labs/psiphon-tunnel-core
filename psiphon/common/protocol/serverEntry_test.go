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
	"testing"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
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
