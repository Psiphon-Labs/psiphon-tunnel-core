// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package ciphersuite provides the crypto operations needed for a DTLS CipherSuite
package ciphersuite

import (
	"encoding/binary"
	"errors"

	"github.com/pion/dtls/v2/pkg/protocol"
	"github.com/pion/dtls/v2/pkg/protocol/recordlayer"
)

var (
	errNotEnoughRoomForNonce = &protocol.InternalError{Err: errors.New("buffer not long enough to contain nonce")} //nolint:goerr113
	errDecryptPacket         = &protocol.TemporaryError{Err: errors.New("failed to decrypt packet")}               //nolint:goerr113
	errInvalidMAC            = &protocol.TemporaryError{Err: errors.New("invalid mac")}                            //nolint:goerr113
	errFailedToCast          = &protocol.FatalError{Err: errors.New("failed to cast")}                             //nolint:goerr113
)

func generateAEADAdditionalData(h *recordlayer.Header, payloadLen int) []byte {
	var additionalData [13]byte
	// SequenceNumber MUST be set first
	// we only want uint48, clobbering an extra 2 (using uint64, Golang doesn't have uint48)
	binary.BigEndian.PutUint64(additionalData[:], h.SequenceNumber)
	binary.BigEndian.PutUint16(additionalData[:], h.Epoch)
	additionalData[8] = byte(h.ContentType)
	additionalData[9] = h.Version.Major
	additionalData[10] = h.Version.Minor
	binary.BigEndian.PutUint16(additionalData[len(additionalData)-2:], uint16(payloadLen))

	return additionalData[:]
}

// [Psiphon]
// Backport of https://github.com/pion/dtls/commit/61762dee8217991882c5eb79856b9e7a73ee349f. In
// newer pion/dtls, AEAD nonce generation has moved to common code in aead.encrypt. In this older
// fork, apply the fix to both CCM.Encrypt and GCM.Encrypt via this helper function.
//
// As in the upstream fix, nonce generation is changed from random bytes, which is more vulnerable
// to reuse, to instead follow the scheme recommended in
// https://www.rfc-editor.org/rfc/rfc9325#name-nonce-reuse-in-tls-12.
func generateAEADNonce(writeIV []byte, h *recordlayer.Header) []byte {
	if gcmNonceLength != 12 || ccmNonceLength != 12 {
		panic("unexpected nonce length")
	}
	nonce := make([]byte, 12)
	copy(nonce, writeIV[:4])
	seq64 := (uint64(h.Epoch) << 48) | (h.SequenceNumber & 0x0000ffffffffffff)
	binary.BigEndian.PutUint64(nonce[4:], seq64)
	return nonce
}

// examinePadding returns, in constant time, the length of the padding to remove
// from the end of payload. It also returns a byte which is equal to 255 if the
// padding was valid and 0 otherwise. See RFC 2246, Section 6.2.3.2.
//
// https://github.com/golang/go/blob/039c2081d1178f90a8fa2f4e6958693129f8de33/src/crypto/tls/conn.go#L245
func examinePadding(payload []byte) (toRemove int, good byte) {
	if len(payload) < 1 {
		return 0, 0
	}

	paddingLen := payload[len(payload)-1]
	t := uint(len(payload)-1) - uint(paddingLen)
	// if len(payload) >= (paddingLen - 1) then the MSB of t is zero
	good = byte(int32(^t) >> 31)

	// The maximum possible padding length plus the actual length field
	toCheck := 256
	// The length of the padded data is public, so we can use an if here
	if toCheck > len(payload) {
		toCheck = len(payload)
	}

	for i := 0; i < toCheck; i++ {
		t := uint(paddingLen) - uint(i)
		// if i <= paddingLen then the MSB of t is zero
		mask := byte(int32(^t) >> 31)
		b := payload[len(payload)-1-i]
		good &^= mask&paddingLen ^ mask&b
	}

	// We AND together the bits of good and replicate the result across
	// all the bits.
	good &= good << 4
	good &= good << 2
	good &= good << 1
	good = uint8(int8(good) >> 7)

	toRemove = int(paddingLen) + 1

	return toRemove, good
}
