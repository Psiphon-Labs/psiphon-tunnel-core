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

package light

import (
	"bytes"
	"encoding/binary"
	"io"
	"math"
	"net"
	"sync"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/fxamacker/cbor/v2"
)

const (
	lightProtocolVersion          = byte(0x01)
	stopPadding                   = uint16(0xffff)
	stopPaddingWriteSizeThreshold = 1280
	paddingMinTargetSize          = 900
	paddingMaxTargetSize          = 1400
)

// lightConn is layered over the proxy TLS connection and adds a light proxy
// header; and traffic shape obfuscation with initial payload padding and
// large write splitting.
type lightConn struct {
	net.Conn
	header *lightHeader

	readMutex       sync.Mutex
	doneReadPadding bool
	readBuffer      bytes.Buffer

	writeMutex       sync.Mutex
	doneWriteHeader  bool
	doneWritePadding bool
	writeBuffer      bytes.Buffer
}

// lightHeader is the header sent from the client to the proxy. With CBOR
// encoding and parameter packing (hex strings to binary, enum strings to
// single bytes), the expected header size is under 150 bytes.
type lightHeader struct {
	SponsorID          []byte `cbor:"1,keyasint,omitempty"`
	ClientPlatform     uint8  `cbor:"2,keyasint,omitempty"`
	ClientBuildRev     []byte `cbor:"3,keyasint,omitempty"`
	ClientID           []byte `cbor:"4,keyasint,omitempty"`
	DeviceRegion       string `cbor:"5,keyasint,omitempty"`
	SessionID          []byte `cbor:"6,keyasint,omitempty"`
	ProxyEntryTracker  int64  `cbor:"7,keyasint,omitempty"`
	NetworkType        uint8  `cbor:"8,keyasint,omitempty"`
	ConnectionNum      int64  `cbor:"9,keyasint,omitempty"`
	DestinationAddress string `cbor:"10,keyasint,omitempty"`
	TLSProfile         uint8  `cbor:"11,keyasint,omitempty"`
	TCPDuration        int64  `cbor:"12,keyasint,omitempty"`
	TLSDuration        int64  `cbor:"13,keyasint,omitempty"`
}

func newLightHeader(
	sponsorID []byte,
	clientPlatform uint8,
	clientBuildRev []byte,
	clientID []byte,
	deviceRegion string,
	sessionID []byte,
	proxyEntryTracker int64,
	networkType uint8,
	connectionNum int64,
	destinationAddress string,
	tlsProfile uint8,
	tcpDuration int64,
	tlsDuration int64) (*lightHeader, error) {

	if len(deviceRegion) > 2 {
		// Truncate any unexpectedly long device region, which should be an ISO
		// 3166-1 alpha-2 country code.
		deviceRegion = deviceRegion[0:2]
	}

	return &lightHeader{
		SponsorID:          sponsorID,
		ClientPlatform:     clientPlatform,
		ClientBuildRev:     clientBuildRev,
		ClientID:           clientID,
		DeviceRegion:       deviceRegion,
		SessionID:          sessionID,
		ProxyEntryTracker:  proxyEntryTracker,
		NetworkType:        networkType,
		ConnectionNum:      connectionNum,
		DestinationAddress: destinationAddress,
		TLSProfile:         tlsProfile,
		TCPDuration:        tcpDuration,
		TLSDuration:        tlsDuration,
	}, nil
}

func newLightConn(conn net.Conn, header *lightHeader) *lightConn {
	return &lightConn{
		Conn:   conn,
		header: header,
	}
}

func (conn *lightConn) Read(b []byte) (int, error) {
	conn.readMutex.Lock()
	defer conn.readMutex.Unlock()

	if len(b) == 0 {
		return 0, nil
	}

	// Consume any previously buffered payload.

	if conn.readBuffer.Len() > 0 {
		n, _ := conn.readBuffer.Read(b)
		if conn.readBuffer.Len() == 0 {
			conn.readBuffer = bytes.Buffer{}
		}
		return n, nil
	}

	// After stopPadding, the stream is strictly client payload without any
	// framing or padding.

	if conn.doneReadPadding {
		n, err := conn.Conn.Read(b)
		return n, errors.Trace(err)
	}

	// Read the padding size.

	var wirePaddingSize [2]byte
	_, err := io.ReadFull(conn.Conn, wirePaddingSize[:])
	if err != nil {
		return 0, errors.Trace(err)
	}
	paddingSize := binary.BigEndian.Uint16(wirePaddingSize[:])

	if paddingSize == stopPadding {
		conn.doneReadPadding = true
		n, err := conn.Conn.Read(b)
		return n, errors.Trace(err)
	}

	// Read the size of the payload, and then read that number of payload
	// bytes, which advances to the next padding frame.

	var wirePayloadSize [2]byte
	_, err = io.ReadFull(conn.Conn, wirePayloadSize[:])
	if err != nil {
		return 0, errors.Trace(err)
	}
	payloadSize := int(binary.BigEndian.Uint16(wirePayloadSize[:]))

	if payloadSize == 0 {
		return 0, errors.TraceNew("invalid payload size")
	}

	if paddingSize > 0 {
		_, err = io.CopyN(io.Discard, conn.Conn, int64(paddingSize))
		if err != nil {
			return 0, errors.Trace(err)
		}
	}

	if payloadSize <= len(b) {
		n, err := io.ReadFull(conn.Conn, b[:payloadSize])
		if err != nil {
			return n, errors.Trace(err)
		}
		return payloadSize, nil
	}

	n, err := io.ReadFull(conn.Conn, b)
	if err != nil {
		return n, errors.Trace(err)
	}

	// When len(b) is insufficient to store the full payload, read into a buffer.

	remaining := payloadSize - len(b)
	if remaining > 0 {
		conn.readBuffer.Grow(remaining)
		n, err := conn.readBuffer.ReadFrom(
			io.LimitReader(conn.Conn, int64(remaining)))
		if err != nil {
			return len(b), errors.Trace(err)
		}
		if n != int64(remaining) {
			return len(b), errors.TraceNew("short read")
		}
	}

	return len(b), nil
}

func (conn *lightConn) Write(b []byte) (int, error) {
	conn.writeMutex.Lock()
	defer conn.writeMutex.Unlock()

	if len(b) == 0 {
		return 0, nil
	}

	// After stopPadding, the stream is strictly client payload without any
	// framing or padding.

	if conn.doneWritePadding {
		// doneWritePadding implies doneWriteHeader.
		n, err := conn.splitWrite(b)
		return n, errors.Trace(err)
	}

	conn.writeBuffer.Reset()

	// Send the light header once, on first write, before the framed padding
	// and payload. This assumes that, for the inner traffic, the client is
	// always the first writer.

	if conn.header != nil && !conn.doneWriteHeader {
		wireHeader, err := conn.encodeHeader()
		if err != nil {
			return 0, errors.Trace(err)
		}
		conn.writeBuffer.Write(wireHeader)
		conn.doneWriteHeader = true
	}

	// Pad initial inner protocol payloads until a size threshold is observed.
	// This is a heuristic intended to obfuscate traffic shapes for many
	// possible inner protocols with small, predictable size handshake
	// payloads.
	//
	// Pad so that the TLS record is within the target range. First calculate
	// the size of the TLS record excluding the padding: the light header, if
	// written now; the inner protocol payload; 2 bytes for the padding
	// header; and 17 bytes for the TLS overhead with the record
	// (inner content type and typical AEAD).
	//
	// The padding target range follows VLESS conventions.

	releaseWriteBuffer := false
	size := conn.writeBuffer.Len() + len(b) + 2 + 17
	if !conn.doneWritePadding {
		if size > stopPaddingWriteSizeThreshold {
			var wirePaddingSize [2]byte
			binary.BigEndian.PutUint16(wirePaddingSize[:], stopPadding)
			conn.writeBuffer.Write(wirePaddingSize[:])
			conn.doneWritePadding = true
			releaseWriteBuffer = true
		} else {
			// The wirePayloadSize is 2 bytes.
			size += 2
			min := paddingMinTargetSize - size
			if min < 0 {
				min = 0
			}
			max := paddingMaxTargetSize - size
			if max < 0 {
				max = 0
			}
			padding := prng.Padding(min, max)
			if len(padding) >= int(stopPadding) {
				return 0, errors.TraceNew("unexpected padding size")
			}
			var wirePaddingSize [2]byte
			binary.BigEndian.PutUint16(wirePaddingSize[:], uint16(len(padding)))
			if len(b) > math.MaxUint16 {
				// Should not happen assuming stopPaddingWriteSizeThreshold < 2^16.
				return 0, errors.TraceNew("unexpected payload size")
			}
			var wirePayloadSize [2]byte
			binary.BigEndian.PutUint16(wirePayloadSize[:], uint16(len(b)))
			conn.writeBuffer.Write(wirePaddingSize[:])
			conn.writeBuffer.Write(wirePayloadSize[:])
			conn.writeBuffer.Write(padding)
		}
	}

	overhead := conn.writeBuffer.Len()

	conn.writeBuffer.Write(b)

	n, err := conn.splitWrite(conn.writeBuffer.Bytes())
	if releaseWriteBuffer {
		conn.writeBuffer = bytes.Buffer{}
	}

	// Report payload bytes written, ignoring header and padding.
	n -= overhead
	if n < 0 {
		n = 0
	}

	return n, errors.Trace(err)
}

func (conn *lightConn) splitWrite(b []byte) (int, error) {

	// Split any large writes which exceed the maximum TLS record size. This
	// is to avoid outer TLS record traffic shape patterns such as an
	// alternating full/small record when the inner protocol writes are just
	// over the maximum TLS record size. This is a heuristic intended to
	// cover many possible inner protocols.

	maxTLSRecordSize := 16384
	bytesWritten := 0
	for len(b) > 0 {
		n := len(b)
		if n > maxTLSRecordSize {
			max := maxTLSRecordSize
			min := max / 2
			n = prng.Range(min, max)
		}
		m, err := conn.Conn.Write(b[:n])
		bytesWritten += m
		if err != nil {
			return bytesWritten, errors.Trace(err)
		}
		b = b[m:]
	}
	return bytesWritten, nil
}

func (conn *lightConn) encodeHeader() ([]byte, error) {

	cborHeader, err := protocol.CBOREncoding.Marshal(conn.header)
	if err != nil {
		return nil, errors.Trace(err)
	}

	headerSize := len(cborHeader)
	if headerSize > math.MaxUint16 {
		return nil, errors.TraceNew("header size overflow")
	}

	var wireHeaderSize [2]byte
	binary.BigEndian.PutUint16(wireHeaderSize[:], uint16(headerSize))

	var buf bytes.Buffer
	buf.WriteByte(lightProtocolVersion)
	buf.Write(wireHeaderSize[:])
	buf.Write(cborHeader)

	return buf.Bytes(), nil
}

func (conn *lightConn) readHeader() (*lightHeader, error) {

	var wireProtocolVersion [1]byte
	_, err := io.ReadFull(conn.Conn, wireProtocolVersion[:])
	if err != nil {
		return nil, errors.Trace(err)
	}

	if wireProtocolVersion[0] != lightProtocolVersion {
		return nil, errors.TraceNew("unknown protocol version")
	}

	var wireHeaderSize [2]byte
	_, err = io.ReadFull(conn.Conn, wireHeaderSize[:])
	if err != nil {
		return nil, errors.Trace(err)
	}

	// This is no header size sanity check, as the maximum possible wire size
	// is only 64K.

	headerSize := int(binary.BigEndian.Uint16(wireHeaderSize[:]))

	wireHeader := make([]byte, headerSize)
	_, err = io.ReadFull(conn.Conn, wireHeader)
	if err != nil {
		return nil, errors.Trace(err)
	}

	var header *lightHeader
	err = cbor.Unmarshal(wireHeader, &header)
	if err != nil {
		return nil, errors.Trace(err)
	}

	if header == nil {
		return nil, errors.TraceNew("unexpected nil header")
	}

	return header, nil
}
