/*
 * Copyright (c) 2026, Psiphon Inc.
 * All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

package tlsdialer

import "errors"

const (
	tlsHandshakeTypeClientHello uint8  = 1
	tlsExtensionServerName      uint16 = 0
)

// sniFragmentOffset returns the ClientHello fragmentation point that starts
// the second TLS record at the first byte of the SNI hostname. It returns zero
// when the ClientHello is malformed or does not contain an SNI hostname.
func sniFragmentOffset(clientHello []byte) int {
	split, err := clientHelloSNIFragmentOffset(clientHello)
	if err != nil {
		return 0
	}
	return split
}

func clientHelloSNIFragmentOffset(data []byte) (int, error) {
	if len(data) < 4 {
		return 0, errors.New("TLS ClientHello too short")
	}
	if data[0] != tlsHandshakeTypeClientHello {
		return 0, errors.New("TLS handshake message is not ClientHello")
	}

	messageLength := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if messageLength != len(data)-4 {
		return 0, errors.New("unexpected TLS ClientHello length")
	}

	position := 4
	if !skipClientHelloBytes(data, &position, 2+32) {
		return 0, errors.New("malformed TLS ClientHello header")
	}

	sessionIDLength, ok := readClientHelloUint8(data, &position)
	if !ok || !skipClientHelloBytes(data, &position, int(sessionIDLength)) {
		return 0, errors.New("malformed TLS ClientHello session ID")
	}

	cipherSuitesLength, ok := readClientHelloUint16(data, &position)
	if !ok || cipherSuitesLength == 0 || cipherSuitesLength%2 != 0 ||
		!skipClientHelloBytes(data, &position, int(cipherSuitesLength)) {
		return 0, errors.New("malformed TLS ClientHello cipher suites")
	}

	compressionMethodsLength, ok := readClientHelloUint8(data, &position)
	if !ok || compressionMethodsLength == 0 ||
		!skipClientHelloBytes(data, &position, int(compressionMethodsLength)) {
		return 0, errors.New("malformed TLS ClientHello compression methods")
	}

	if position == len(data) {
		return 0, errors.New("missing TLS ClientHello SNI extension")
	}

	extensionsLength, ok := readClientHelloUint16(data, &position)
	if !ok {
		return 0, errors.New("malformed TLS ClientHello extensions")
	}
	extensionsEnd := position + int(extensionsLength)
	if extensionsEnd != len(data) {
		return 0, errors.New("malformed TLS ClientHello extensions length")
	}

	for position < extensionsEnd {
		extensionType, ok := readClientHelloUint16(data, &position)
		if !ok {
			return 0, errors.New("malformed TLS ClientHello extension type")
		}
		extensionLength, ok := readClientHelloUint16(data, &position)
		if !ok {
			return 0, errors.New("malformed TLS ClientHello extension length")
		}
		extensionStart := position
		extensionEnd := position + int(extensionLength)
		if extensionEnd > extensionsEnd {
			return 0, errors.New("malformed TLS ClientHello extension data")
		}

		if extensionType == tlsExtensionServerName {
			return clientHelloSNIHostnameOffset(data, extensionStart, extensionEnd)
		}

		position = extensionEnd
	}

	return 0, errors.New("missing TLS ClientHello SNI extension")
}

func clientHelloSNIHostnameOffset(data []byte, start, end int) (int, error) {
	position := start
	serverNameListLength, ok := readClientHelloUint16(data, &position)
	if !ok {
		return 0, errors.New("malformed TLS SNI extension")
	}
	serverNameListEnd := position + int(serverNameListLength)
	if serverNameListEnd != end || serverNameListLength == 0 {
		return 0, errors.New("malformed TLS SNI name list")
	}

	for position < serverNameListEnd {
		nameType, ok := readClientHelloUint8(data, &position)
		if !ok {
			return 0, errors.New("malformed TLS SNI name type")
		}
		nameLength, ok := readClientHelloUint16(data, &position)
		if !ok {
			return 0, errors.New("malformed TLS SNI name length")
		}
		nameStart := position
		nameEnd := position + int(nameLength)
		if nameEnd > serverNameListEnd {
			return 0, errors.New("malformed TLS SNI name")
		}
		if nameType == 0 {
			if nameLength == 0 {
				return 0, errors.New("empty TLS SNI hostname")
			}
			return nameStart, nil
		}
		position = nameEnd
	}

	return 0, errors.New("missing TLS SNI hostname")
}

func readClientHelloUint8(data []byte, position *int) (uint8, bool) {
	if *position >= len(data) {
		return 0, false
	}
	value := data[*position]
	*position += 1
	return value, true
}

func readClientHelloUint16(data []byte, position *int) (uint16, bool) {
	if len(data)-*position < 2 {
		return 0, false
	}
	value := uint16(data[*position])<<8 | uint16(data[*position+1])
	*position += 2
	return value, true
}

func skipClientHelloBytes(data []byte, position *int, length int) bool {
	if length < 0 || len(data)-*position < length {
		return false
	}
	*position += length
	return true
}
