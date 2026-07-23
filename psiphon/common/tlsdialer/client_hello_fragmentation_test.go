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

import (
	"bytes"
	"encoding/binary"
	"testing"

	utls "github.com/Psiphon-Labs/utls"
)

func TestSNIFragmentOffset(t *testing.T) {
	const serverName = "example.org"

	for _, prefixExtensions := range [][][]byte{
		nil,
		{{0x00, 0x0a, 0x00, 0x02, 0x00, 0x1d}},
	} {
		clientHello := makeTestClientHello(serverName, prefixExtensions...)
		offset := sniFragmentOffset(clientHello)
		if offset <= 0 || offset >= len(clientHello) {
			t.Fatalf("unexpected SNI fragment offset: %d", offset)
		}
		if !bytes.HasPrefix(clientHello[offset:], []byte(serverName)) {
			t.Fatalf("fragment does not start at SNI hostname: %x", clientHello[offset:])
		}
	}
}

func TestSNIFragmentOffsetFallback(t *testing.T) {
	validClientHello := makeTestClientHello("example.org")

	tests := []struct {
		name        string
		clientHello []byte
	}{
		{name: "empty"},
		{name: "not ClientHello", clientHello: append([]byte{2}, validClientHello[1:]...)},
		{name: "invalid message length", clientHello: append([]byte{}, validClientHello[:len(validClientHello)-1]...)},
		{name: "missing SNI", clientHello: makeTestClientHello("")},
		{name: "invalid extensions length", clientHello: corruptTestClientHelloExtensionsLength(validClientHello)},
		{name: "invalid SNI name length", clientHello: corruptTestClientHelloSNINameLength(validClientHello)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if offset := sniFragmentOffset(test.clientHello); offset != 0 {
				t.Fatalf("unexpected SNI fragment offset: %d", offset)
			}
		})
	}
}

func TestSNIFragmentOffsetUTLSClientHello(t *testing.T) {
	const serverName = "example.org"
	conn := utls.UClient(nil, &utls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
	}, utls.HelloChrome_120)
	if err := conn.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}

	clientHello := conn.HandshakeState.Hello.Raw
	offset, err := clientHelloSNIFragmentOffset(clientHello)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(clientHello[offset:], []byte(serverName)) {
		t.Fatalf("fragment does not start at SNI hostname: %x", clientHello[offset:])
	}
}

func makeTestClientHello(serverName string, prefixExtensions ...[]byte) []byte {
	body := make([]byte, 0)
	body = binary.BigEndian.AppendUint16(body, 0x0303)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)
	body = binary.BigEndian.AppendUint16(body, 2)
	body = binary.BigEndian.AppendUint16(body, 0x1301)
	body = append(body, 1, 0)

	extensions := make([]byte, 0)
	for _, extension := range prefixExtensions {
		extensions = append(extensions, extension...)
	}
	if serverName != "" {
		extensions = binary.BigEndian.AppendUint16(extensions, tlsExtensionServerName)
		extensions = binary.BigEndian.AppendUint16(extensions, uint16(len(serverName)+5))
		extensions = binary.BigEndian.AppendUint16(extensions, uint16(len(serverName)+3))
		extensions = append(extensions, 0)
		extensions = binary.BigEndian.AppendUint16(extensions, uint16(len(serverName)))
		extensions = append(extensions, serverName...)
	}
	if len(extensions) > 0 {
		body = binary.BigEndian.AppendUint16(body, uint16(len(extensions)))
		body = append(body, extensions...)
	}

	clientHello := []byte{tlsHandshakeTypeClientHello, 0, 0, 0}
	messageLength := len(body)
	clientHello[1] = byte(messageLength >> 16)
	clientHello[2] = byte(messageLength >> 8)
	clientHello[3] = byte(messageLength)
	return append(clientHello, body...)
}

func corruptTestClientHelloExtensionsLength(clientHello []byte) []byte {
	corrupt := append([]byte{}, clientHello...)
	// Fixed fields: handshake header, version, random, empty session ID,
	// one cipher suite, and one compression method.
	extensionsLengthOffset := 4 + 2 + 32 + 1 + 2 + 2 + 1 + 1
	corrupt[extensionsLengthOffset+1]++
	return corrupt
}

func corruptTestClientHelloSNINameLength(clientHello []byte) []byte {
	corrupt := append([]byte{}, clientHello...)
	offset := sniFragmentOffset(corrupt)
	corrupt[offset-1]++
	return corrupt
}
