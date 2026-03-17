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

package server

import (
	"bufio"
	"bytes"
	"crypto/subtle"
	"encoding/binary"
	std_errors "errors"
	"io"
	"net"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	proxyproto "github.com/pires/go-proxyproto"
	"github.com/zeebo/blake3"
)

const (
	proxyProtocolHeaderVersion      = uint16(1)
	proxyProtocolHeaderVersionSize  = 2
	proxyProtocolHeaderKeyIDSize    = 4
	proxyProtocolHeaderPreambleSize = proxyProtocolHeaderVersionSize +
		proxyProtocolHeaderKeyIDSize
	proxyProtocolHeaderTimestampSize = 8
	proxyProtocolHeaderMACKeySize    = 32
	proxyProtocolHeaderMACDigestSize = 32
	proxyProtocolHeaderMACTLVType    = proxyproto.PP2Type(0xEA)
	proxyProtocolHeaderMACTLVSize    = proxyProtocolHeaderPreambleSize +
		proxyProtocolHeaderTimestampSize +
		proxyProtocolHeaderMACDigestSize
)

// makeProxyProtocolHeader creates a HAProxy PROXY protocol v2 header with a
// custom authentication TLV and returns the serialized wire format.
//
// The PROXY header is populated with the given source IP and destination IP
// and port; the source port is unspecified and encoded as 0. The network
// protocol is recorded as TCP.
//
// Authentication is provided by a MAC digest using the provided MAC key. The
// current timestamp is included in the MAC to facilitate replay detection.
//
// The authentication data is added as an application-specific TLV with type
// 0xEA and the following fields:
//
// Bytes  0–1   : Version (16-bit unsigned integer representing the authentication scheme version)
// Bytes  2–5   : Key ID (32-bit unsigned integer identifying the MAC key)
// Bytes  6–13  : Timestamp (64-bit unsigned integer representing milliseconds since the Unix epoch, UTC)
// Bytes 14–45  : MAC digest (256 bits)
// Total        : 46 bytes
//
// The current authentication version 1 and uses BLAKE3 in keyed mode, with a
// 32 byte input key and 32 byte output digest. Integer values are encoded in
// network byte order, big endian.
//
// makeProxyProtocolHeader serializes the PROXY header with the authentication
// TLV in the final TLV position and all-zero bytes in the MAC digest field.
// A MAC is computed over this entire message, and the resulting digest is
// written back into the MAC digest field to produce the final result.
//
// MAC input:
//
//	+---------------------------------------------------------------------+
//	| PROXY v2 header                                                     |
//	| [...]                                                               |
//	| Authentication TLV (end position)                                   |
//	|  +--------+--------+---------------------------------------------+  |
//	|  |Version | Key ID | Timestamp | 00 00 00 00 ... 00 00           |  |
//	|  +--------+--------+---------------------------------------------+  |
//	+---------------------------------------------------------------------+
//
// Output:
//
//	+---------------------------------------------------------------------+
//	| PROXY v2 header                                                     |
//	| [...]                                                               |
//	| Authentication TLV (end position)                                   |
//	|  +--------+--------+---------------------------------------------+  |
//	|  |Version | Key ID | Timestamp | Computed MAC digest             |  |
//	|  +--------+--------+---------------------------------------------+  |
//	+---------------------------------------------------------------------+
func makeProxyProtocolHeader(
	keyID []byte,
	key []byte,
	sourceIP net.IP,
	destinationIP net.IP,
	destinationPort int) ([]byte, error) {

	if len(keyID) != proxyProtocolHeaderKeyIDSize {
		return nil, errors.TraceNew("invalid key ID")
	}

	if len(key) != proxyProtocolHeaderMACKeySize {
		return nil, errors.TraceNew("invalid key size")
	}

	// Create the PROXY v2 header

	sourceAddr := net.TCPAddr{IP: sourceIP, Port: 0}
	destinationAddr := net.TCPAddr{IP: destinationIP, Port: destinationPort}

	header := proxyproto.HeaderProxyFromAddrs(2, &sourceAddr, &destinationAddr)

	// Add the authentication TLV with all-zero byte MAC digest

	offset := 0
	var macTLV [proxyProtocolHeaderMACTLVSize]byte

	binary.BigEndian.PutUint16(
		macTLV[offset:offset+proxyProtocolHeaderVersionSize],
		proxyProtocolHeaderVersion)
	offset += proxyProtocolHeaderVersionSize

	copy(macTLV[offset:offset+proxyProtocolHeaderKeyIDSize], keyID)
	offset += proxyProtocolHeaderKeyIDSize

	binary.BigEndian.PutUint64(
		macTLV[offset:offset+proxyProtocolHeaderTimestampSize],
		uint64(time.Now().UTC().UnixMilli()))

	tlvs := [1]proxyproto.TLV{
		{
			Type:  proxyProtocolHeaderMACTLVType,
			Value: macTLV[:],
		},
	}

	err := header.SetTLVs(tlvs[:])
	if err != nil {
		return nil, errors.Trace(err)
	}

	// Serialize the PROXY header

	wireHeader, err := header.Format()
	if err != nil {
		return nil, errors.Trace(err)
	}

	// MAC the entire header and update the digest field

	hasher, err := blake3.NewKeyed(key)
	if err != nil {
		return nil, errors.Trace(err)
	}
	if hasher.Size() != proxyProtocolHeaderMACDigestSize {
		return nil, errors.TraceNew("unexpected digest size")
	}
	_, _ = hasher.Write(wireHeader)
	_, _ = hasher.Digest().Read(
		wireHeader[len(wireHeader)-proxyProtocolHeaderMACDigestSize:])

	return wireHeader, nil
}

// verifyProxyProtocolHeader verifies the input wire format PROXY v2 header
// using the MAC in the authentication TLV and returns the network address
// information from the header and the timestamp from the authentication
// TLV.
func verifyProxyProtocolHeader(
	keyID []byte,
	key []byte,
	wireHeader []byte) (

	timestamp time.Time,
	sourceIP net.IP,
	destinationIP net.IP,
	destinationPort int,
	retErr error) {

	if len(keyID) != proxyProtocolHeaderKeyIDSize {
		retErr = errors.TraceNew("invalid key ID")
		return
	}

	if len(key) != proxyProtocolHeaderMACKeySize {
		retErr = errors.TraceNew("invalid key size")
		return
	}

	if len(wireHeader) < proxyProtocolHeaderMACTLVSize {
		retErr = errors.TraceNew("invalid header size")
		return
	}

	offset := len(wireHeader) - proxyProtocolHeaderMACTLVSize
	wirePreamble := wireHeader[offset : offset+proxyProtocolHeaderPreambleSize]
	wireVersion := binary.BigEndian.Uint16(wirePreamble[0:proxyProtocolHeaderVersionSize])
	if wireVersion != proxyProtocolHeaderVersion {
		retErr = errors.TraceNew("unknown version")
		return
	}
	wireKeyID := wirePreamble[proxyProtocolHeaderVersionSize:]
	if subtle.ConstantTimeCompare(keyID, wireKeyID) != 1 {
		retErr = errors.TraceNew("unexpected key ID")
		return
	}

	wireDigest := wireHeader[len(wireHeader)-proxyProtocolHeaderMACDigestSize:]

	var digest [proxyProtocolHeaderMACDigestSize]byte

	hasher, err := blake3.NewKeyed(key)
	if err != nil {
		retErr = errors.Trace(err)
		return
	}
	if hasher.Size() != proxyProtocolHeaderMACDigestSize {
		retErr = errors.TraceNew("unexpected digest size")
		return
	}
	var zeroMAC [proxyProtocolHeaderMACDigestSize]byte
	_, _ = hasher.Write(wireHeader[:len(wireHeader)-proxyProtocolHeaderMACDigestSize])
	_, _ = hasher.Write(zeroMAC[:])
	_, _ = hasher.Digest().Read(digest[:])

	if subtle.ConstantTimeCompare(digest[:], wireDigest) != 1 {
		retErr = errors.TraceNew("invalid MAC")
		return
	}

	offset = len(wireHeader) - proxyProtocolHeaderMACTLVSize + proxyProtocolHeaderPreambleSize
	wireTimestamp := wireHeader[offset : offset+proxyProtocolHeaderTimestampSize]
	timestamp = time.UnixMilli(int64(binary.BigEndian.Uint64(wireTimestamp)))

	header, err := proxyproto.Read(
		bufio.NewReader(bytes.NewReader(wireHeader)))
	if err != nil {
		retErr = errors.Trace(err)
		return
	}

	if header.Version != 2 ||
		header.Command != proxyproto.PROXY ||
		(header.TransportProtocol != proxyproto.TCPv4 &&
			header.TransportProtocol != proxyproto.TCPv6) {
		retErr = errors.TraceNew("unexpected header")
		return
	}

	switch v := header.SourceAddr.(type) {
	case *net.TCPAddr:
		sourceIP = v.IP
	default:
		retErr = errors.TraceNew("unexpected source addr type")
		return
	}

	switch v := header.DestinationAddr.(type) {
	case *net.TCPAddr:
		destinationIP = v.IP
		destinationPort = v.Port
	default:
		retErr = errors.TraceNew("unexpected destination addr type")
		return
	}

	return
}

// addOrReplaceProxyProtocolHeader detects and removes any HAProxy PROXY
// protocol header from the input stream and prepends the specified new
// header to the output stream. Any bytes read in the detection process that
// are not part of a PROXY header are relayed to the output stream. A count
// of bytes read is returned.
//
// addOrReplaceProxyProtocolHeader blocks on first reading the input stream
// and is compatible only with client-first network protocols.
//
// If the input stream begins with a PROXY v1/v2 signature, it must follow
// with the rest of a valid PROXY header. Input streams that send only the
// signture or a subset of the signature and nothing more will stall. Input
// streams that send a matching signature followed by non-PROXY protocol
// header bytes will result in an error.
func addOrReplaceProxyProtocolHeader(
	in io.Reader,
	out io.Writer,
	newHeader []byte) (bytesRead int64, retErr error) {

	// Allocate only a small buffer, sufficient to read PROXY v1/v2 prefixes.

	bufferSize := 64
	countingReader := newCountingReader(in)
	bufferedReader := bufio.NewReaderSize(countingReader, bufferSize)

	_, err := proxyproto.Read(bufferedReader)
	bytesRead += countingReader.getBytesRead()
	if err != nil && !std_errors.Is(err, proxyproto.ErrNoProxyProtocol) {
		retErr = errors.Trace(err)
		return
	}

	// The new header is written only after reading input bytes. Potentially
	// batch up the new header and buffered bytes writes.

	_, err = out.Write(newHeader)
	if err != nil {
		retErr = errors.Trace(err)
		return
	}

	buffered := bufferedReader.Buffered()
	if buffered > 0 {
		bufferedBytes, err := bufferedReader.Peek(buffered)
		if err != nil {
			retErr = errors.Trace(err)
			return
		}
		_, err = out.Write(bufferedBytes)
		if err != nil {
			retErr = errors.Trace(err)
			return
		}
	}

	return
}

type countingReader struct {
	reader    io.Reader
	bytesRead int64
}

func newCountingReader(reader io.Reader) *countingReader {
	return &countingReader{reader: reader}
}

func (r *countingReader) Read(p []byte) (int, error) {
	bytesRead, err := r.reader.Read(p)
	r.bytesRead += int64(bytesRead)
	return bytesRead, err
}

func (r *countingReader) getBytesRead() int64 {
	return r.bytesRead
}
