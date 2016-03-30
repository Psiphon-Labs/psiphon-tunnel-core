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

package psiphon

import (
	"encoding/hex"
	"testing"
)

const (
	_VALID_NORMAL_SERVER_ENTRY                    = `192.168.0.1 80 <webServerSecret> <webServerCertificate> {"ipAddress":"192.168.0.1","webServerPort":"80","webServerSecret":"<webServerSecret>","webServerCertificate":"<webServerCertificate>","sshPort":22,"sshUsername":"<sshUsername>","sshPassword":"<sshPassword>","sshHostKey":"<sshHostKey>","sshObfuscatedPort":443,"sshObfuscatedKey":"<sshObfuscatedKey>","capabilities":["handshake","SSH","OSSH","VPN"],"region":"CA","meekServerPort":8080,"meekCookieEncryptionPublicKey":"<meekCookieEncryptionPublicKey>","meekObfuscatedKey":"<meekObfuscatedKey>","meekFrontingDomain":"<meekFrontingDomain>","meekFrontingHost":"<meekFrontingHost>"}`
	_VALID_BLANK_LEGACY_SERVER_ENTRY              = `    {"ipAddress":"192.168.0.1","webServerPort":"80","webServerSecret":"<webServerSecret>","webServerCertificate":"<webServerCertificate>","sshPort":22,"sshUsername":"<sshUsername>","sshPassword":"<sshPassword>","sshHostKey":"<sshHostKey>","sshObfuscatedPort":443,"sshObfuscatedKey":"<sshObfuscatedKey>","capabilities":["handshake","SSH","OSSH","VPN"],"region":"CA","meekServerPort":8080,"meekCookieEncryptionPublicKey":"<meekCookieEncryptionPublicKey>","meekObfuscatedKey":"<meekObfuscatedKey>","meekFrontingDomain":"<meekFrontingDomain>","meekFrontingHost":"<meekFrontingHost>"}`
	_INVALID_WINDOWS_REGISTRY_LEGACY_SERVER_ENTRY = `192.168.0.1 80 <webServerSecret> <webServerCertificate> {"sshPort":22,"sshUsername":"<sshUsername>","sshPassword":"<sshPassword>","sshHostKey":"<sshHostKey>","sshObfuscatedPort":443,"sshObfuscatedKey":"<sshObfuscatedKey>","capabilities":["handshake","SSH","OSSH","VPN"],"region":"CA","meekServerPort":8080,"meekCookieEncryptionPublicKey":"<meekCookieEncryptionPublicKey>","meekObfuscatedKey":"<meekObfuscatedKey>","meekFrontingDomain":"<meekFrontingDomain>","meekFrontingHost":"<meekFrontingHost>"}`
	_INVALID_MALFORMED_IP_ADDRESS_SERVER_ENTRY    = `192.168.0.1 80 <webServerSecret> <webServerCertificate> {"ipAddress":"192.168.0.","webServerPort":"80","webServerSecret":"<webServerSecret>","webServerCertificate":"<webServerCertificate>","sshPort":22,"sshUsername":"<sshUsername>","sshPassword":"<sshPassword>","sshHostKey":"<sshHostKey>","sshObfuscatedPort":443,"sshObfuscatedKey":"<sshObfuscatedKey>","capabilities":["handshake","SSH","OSSH","VPN"],"region":"CA","meekServerPort":8080,"meekCookieEncryptionPublicKey":"<meekCookieEncryptionPublicKey>","meekObfuscatedKey":"<meekObfuscatedKey>","meekFrontingDomain":"<meekFrontingDomain>","meekFrontingHost":"<meekFrontingHost>"}`
	_EXPECTED_IP_ADDRESS                          = `192.168.0.1`
)

// DecodeAndValidateServerEntryList should return 2 valid decoded entries from the input list of 4
func TestDecodeAndValidateServerEntryList(t *testing.T) {

	testEncodedServerEntryList := hex.EncodeToString([]byte(_VALID_NORMAL_SERVER_ENTRY)) + "\n" +
		hex.EncodeToString([]byte(_VALID_BLANK_LEGACY_SERVER_ENTRY)) + "\n" +
		hex.EncodeToString([]byte(_INVALID_WINDOWS_REGISTRY_LEGACY_SERVER_ENTRY)) + "\n" +
		hex.EncodeToString([]byte(_INVALID_MALFORMED_IP_ADDRESS_SERVER_ENTRY))

	serverEntries, err := DecodeAndValidateServerEntryList(
		testEncodedServerEntryList, GetCurrentTimestamp(), SERVER_ENTRY_SOURCE_EMBEDDED)
	if err != nil {
		t.Error(err.Error())
		t.FailNow()
	}
	if len(serverEntries) != 2 {
		t.Error("unexpected number of valid server entries")
	}
	for _, serverEntry := range serverEntries {
		if serverEntry.IpAddress != _EXPECTED_IP_ADDRESS {
			t.Error("unexpected IP address in decoded server entry: %s", serverEntry.IpAddress)
		}
	}
}

// Directly call DecodeServerEntry and ValidateServerEntry with invalid inputs
func TestInvalidServerEntries(t *testing.T) {

	testCases := [2]string{_INVALID_WINDOWS_REGISTRY_LEGACY_SERVER_ENTRY, _INVALID_MALFORMED_IP_ADDRESS_SERVER_ENTRY}

	for _, testCase := range testCases {
		encodedServerEntry := hex.EncodeToString([]byte(testCase))
		serverEntry, err := DecodeServerEntry(
			encodedServerEntry, GetCurrentTimestamp(), SERVER_ENTRY_SOURCE_EMBEDDED)
		if err != nil {
			t.Error(err.Error())
		}
		err = ValidateServerEntry(serverEntry)
		if err == nil {
			t.Error("server entry should not validate: %s", testCase)
		}
	}
}
