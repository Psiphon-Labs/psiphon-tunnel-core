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

package transferstats

import (
	"bufio"
	"bytes"
	"net/http"
)

// getHostname attempts to determine the hostname of the server from the request data.
func getHostname(buffer []byte) (hostname string, ok bool) {
	// Check if this is a HTTP request
	bufferReader := bufio.NewReader(bytes.NewReader(buffer))
	httpReq, httpErr := http.ReadRequest(bufferReader)
	if httpErr == nil {
		return httpReq.Host, true
	}

	// Check if it's a TLS request
	hostname, ok = getTLSHostname(buffer)

	return
}

/*
TLS Record Protocol:
Record layer content type (1B): handshake is 22: 22
SSL version (2B): SSL3 is {3,0}, TLS 1.0 is {3,1}, TLS 1.2 is {3,2} TLS 1.2 is {3,3}; seems to typically be {3,1}: 3 1
Plaintext envelope length (2B): maximum of 2^14, but usually much smaller: 2 0
TLS Handshake Protocol:
Handshake type (1B): client hello is 1: 1
Handshake length (3B): will always be 4 bytes smaller than the envelope length (because the envelope length counts the handshake type and the bytes of this length, but this length does not): 0 1 252
Protocol version (2B): see "SSL version" above; seems to typically be {3,3}: 3 3
Random data (32B): 131 89 82 204 123 41 188 215 100 17 206 199 21 202 81 139 145 138 26 95 144 92 183 186 186 36 234 203 207 196 238 115
Session ID length (1B): 32
Session ID: 80 149 254 248 148 156 249 42 173 29 7 58 44 0 92 173 203 11 94 252 117 212 24 20 47 131 135 204 150 37 247 229
Cipher suites length (2B): 0 24
Cipher suites: e.g., TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 is 0xc02b: 192 43 192 47 192 10 192 9 192 19 192 20 0 51 0 50 0 57 0 47 0 53 0 10
Compression methods length (1B): 1
Compression methods: 0
Extensions length (2B): 1 155
  ...some number of extension defs here...
  Extension type (2B): server_name is 0x0000: 0 0
  Extension length (2B): 0 25
  SNI list length (2B): 0 23
  SNI type (1B): host_name is 0x00: 0
  SNI hostname length (2B): 0 20
  SNI hostname: e.g., upload.wikimedia.org: 117 112 108 111 97 100 46 119 105 107 105 109 101 100 105 97 46 111 114 103
  ...more extensions...
*/
// getTLSHostname attempts to interpret the buffer as a TLS client hello and
// extract the SNI hostname from it.
func getTLSHostname(buffer []byte) (hostname string, ok bool) {
	bufLen := uint32(len(buffer))

	// If the buffer is smaller than this, it can't possibly be a TLS client hello.
	if bufLen < 60 {
		return
	}

	pos := uint32(0)

	// Make sure this is a handshake
	if buffer[pos] != 22 {
		return
	}
	pos += 1

	// We'll check the first byte of the SSL version
	// NOTE: Not future proof.
	if buffer[pos] != 3 {
		return
	}
	pos += 2

	plaintextLen := uint32(buffer[pos])<<8 | uint32(buffer[pos+1])
	if plaintextLen < (60-3) || plaintextLen > bufLen {
		return
	}
	pos += 2

	// Make sure handshake type is client hello
	if buffer[pos] != 1 {
		return
	}
	pos += 1

	// Make sure handshake length is expected size.
	handshakeLen := uint32(buffer[pos])<<16 | uint32(buffer[pos+1])<<8 | uint32(buffer[pos+2])
	if handshakeLen+4 != plaintextLen {
		return
	}
	pos += 3

	// Check the first byte of protocol version
	// NOTE: Not future proof.
	if buffer[pos] != 3 {
		return
	}
	pos += 2

	// Skip 32 bytes of random data
	pos += 32

	sessionIDLen := uint32(buffer[pos])
	pos += 1
	if sessionIDLen > bufLen-pos {
		return
	}
	pos += sessionIDLen

	// At this point we can't trust that our initial minimum length check will
	// save us from going out-of-bounds on the buffer slice, so we'll have to
	// do buffer length checks as we go.

	// Skip over the cipher suites. In theory we could check them, but we're not going to.
	if pos+2 > bufLen {
		return
	}
	cipherSuitesLen := uint32(buffer[pos])<<8 | uint32(buffer[pos+1])
	pos += 2
	if cipherSuitesLen > bufLen-pos {
		return
	}
	pos += cipherSuitesLen

	// Skip compression methods
	if pos+1 > bufLen {
		return
	}
	compressionMethodsLen := uint32(buffer[pos])
	pos += 1
	if compressionMethodsLen > bufLen-pos {
		return
	}
	pos += compressionMethodsLen

	// Extensions
	if pos+2 > bufLen {
		return
	}
	extensionsLen := uint32(buffer[pos])<<8 | uint32(buffer[pos+1])
	pos += 2
	if extensionsLen > bufLen-pos {
		return
	}

	// Go through each extension entry, looking for the SNI
	for {
		if pos+2 > bufLen {
			return
		}
		extensionType := uint32(buffer[pos])<<8 | uint32(buffer[pos+1])
		pos += 2

		if pos+2 > bufLen {
			return
		}
		extensionLen := uint32(buffer[pos])<<8 | uint32(buffer[pos+1])
		pos += 2

		// server_name extension type is 0x0000
		if extensionType != 0 {
			pos += extensionLen
			continue
		}

		// Basic santiy check on the SNI list length
		if pos+2 > bufLen {
			return
		}
		sniListLen := uint32(buffer[pos])<<8 | uint32(buffer[pos+1])
		pos += 2
		if sniListLen > extensionLen {
			return
		}

		// Check the SNI type. There's only one allowed value in the spec: hostname (0x00)
		if pos+1 > bufLen {
			return
		}
		sniType := uint32(buffer[pos])
		pos += 1
		if sniType != 0 {
			return
		}

		// Finally, the goal: the hostname
		if pos+2 > bufLen {
			return
		}
		hostnameLen := uint32(buffer[pos])<<8 | uint32(buffer[pos+1])
		pos += 2
		if hostnameLen > bufLen-pos {
			return
		}
		hostname = string(buffer[pos : pos+hostnameLen])
		return hostname, true
	}
}
