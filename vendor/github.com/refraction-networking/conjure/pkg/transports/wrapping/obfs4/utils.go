/*
 * Copyright (c) 2014, Yawning Angel <yawning at schwanenlied dot me>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  * Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

// I brought this in mostly for the constants and findMarkMac.

package obfs4

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"

	"github.com/refraction-networking/obfs4/common/drbg"
	"github.com/refraction-networking/obfs4/common/ntor"
	"github.com/refraction-networking/obfs4/transports/obfs4/framing"
)

const (
	MaxHandshakeLength = 8192

	ClientMinPadLength = (ServerMinHandshakeLength + InlineSeedFrameLength) -
		ClientMinHandshakeLength
	ClientMaxPadLength       = MaxHandshakeLength - ClientMinHandshakeLength
	ClientMinHandshakeLength = ntor.RepresentativeLength + MarkLength + MacLength

	ServerMinPadLength = 0
	ServerMaxPadLength = MaxHandshakeLength - (ServerMinHandshakeLength +
		InlineSeedFrameLength)
	ServerMinHandshakeLength = ntor.RepresentativeLength + ntor.AuthLength +
		MarkLength + MacLength

	MarkLength = sha256.Size / 2
	MacLength  = sha256.Size / 2

	PacketOverhead          = 2 + 1
	SeedPacketPayloadLength = drbg.SeedLength

	InlineSeedFrameLength = framing.FrameOverhead + PacketOverhead + SeedPacketPayloadLength
)

func generateMark(nodeID *ntor.NodeID, pubkey *ntor.PublicKey, representative *ntor.Representative) []byte {
	h := hmac.New(sha256.New, append(pubkey.Bytes()[:], nodeID.Bytes()[:]...))
	h.Write(representative.Bytes()[:])
	sum := h.Sum(nil)[:MarkLength]
	return sum
}

func findMarkMac(mark, buf []byte, startPos, maxPos int, fromTail bool) (pos int) {
	if len(mark) != MarkLength {
		panic(fmt.Sprintf("BUG: Invalid mark length: %d", len(mark)))
	}

	endPos := len(buf)
	if startPos > len(buf) {
		return -1
	}
	if endPos > maxPos {
		endPos = maxPos
	}
	if endPos-startPos < MarkLength+MacLength {
		return -1
	}

	if fromTail {
		// The server can optimize the search process by only examining the
		// tail of the buffer.  The client can't send valid data past M_C |
		// MAC_C as it does not have the server's public key yet.
		pos = endPos - (MarkLength + MacLength)
		if !hmac.Equal(buf[pos:pos+MarkLength], mark) {
			return -1
		}

		return
	}

	// The client has to actually do a substring search since the server can
	// and will send payload trailing the response.
	pos = bytes.Index(buf[startPos:endPos], mark)
	if pos == -1 {
		return -1
	}

	// Ensure that there is enough trailing data for the MAC.
	if startPos+pos+MarkLength+MacLength > endPos {
		return -1
	}

	// Return the index relative to the start of the slice.
	pos += startPos
	return
}
