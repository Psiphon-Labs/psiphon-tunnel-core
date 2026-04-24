// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package ciphersuite provides the crypto operations needed for a DTLS CipherSuite
package ciphersuite

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/pion/dtls/v3/internal/util"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
	"golang.org/x/crypto/cryptobyte"
)

const (
	// 8 bytes of 0xff.
	// https://datatracker.ietf.org/doc/html/rfc9146#name-record-payload-protection
	seqNumPlaceholder = 0xffffffffffffffff
)

var (
	//nolint:err113
	errNotEnoughRoomForNonce = &protocol.InternalError{Err: errors.New("buffer not long enough to contain nonce")}
	//nolint:err113
	errDecryptPacket = &protocol.TemporaryError{Err: errors.New("failed to decrypt packet")}
	//nolint:err113
	errInvalidMAC = &protocol.TemporaryError{Err: errors.New("invalid mac")}
	//nolint:err113
	errFailedToCast = &protocol.FatalError{Err: errors.New("failed to cast")}
)

// aead provides a generic API to Encrypt/Decrypt DTLS 1.2 Packets.
type aead struct {
	localAEAD     cipher.AEAD
	remoteAEAD    cipher.AEAD
	localWriteIV  []byte
	remoteWriteIV []byte
	nonceLength   int
	tagLength     int

	// buffer pool for (fixed-size) nonces.
	nonceBufferPool sync.Pool
}

// newAEAD creates a generic DTLS AEAD-based Cipher.
func newAEAD(
	localAEAD cipher.AEAD,
	localWriteIV []byte,
	remoteAEAD cipher.AEAD,
	remoteWriteIV []byte,
	nonceLength int,
	tagLength int,
) *aead {
	return &aead{
		localAEAD:     localAEAD,
		localWriteIV:  localWriteIV,
		remoteAEAD:    remoteAEAD,
		remoteWriteIV: remoteWriteIV,
		nonceLength:   nonceLength,
		tagLength:     tagLength,
		nonceBufferPool: sync.Pool{
			New: func() any {
				b := make([]byte, nonceLength)
				return &b // nolint:nlreturn
			},
		},
	}
}

// encrypt encrypts a DTLS RecordLayer message.
func (a *aead) encrypt(pkt *recordlayer.RecordLayer, raw []byte) ([]byte, error) {
	payload := raw[pkt.Header.Size():]
	raw = raw[:pkt.Header.Size()]

	// Get nonce buffer from pool
	noncePtr := a.nonceBufferPool.Get().(*[]byte) // nolint:forcetypeassert
	nonce := *noncePtr

	copy(nonce, a.localWriteIV[:4])

	// https://www.rfc-editor.org/rfc/rfc9325#name-nonce-reuse-in-tls-12
	seq64 := (uint64(pkt.Header.Epoch) << 48) | (pkt.Header.SequenceNumber & 0x0000ffffffffffff)
	binary.BigEndian.PutUint64(nonce[4:], seq64)

	var additionalData []byte
	if pkt.Header.ContentType == protocol.ContentTypeConnectionID {
		additionalData = generateAEADAdditionalDataCID(&pkt.Header, len(payload))
	} else {
		additionalData = generateAEADAdditionalData(&pkt.Header, len(payload))
	}
	finalSize := len(raw) + 8 + len(payload) + a.tagLength
	r := make([]byte, finalSize)
	copy(r, raw)
	copy(r[len(raw):], nonce[4:])

	a.localAEAD.Seal(r[len(raw)+8:len(raw)+8], nonce, payload, additionalData)

	// Update recordLayer size to include explicit nonce
	binary.BigEndian.PutUint16(r[pkt.Header.Size()-2:], uint16(len(r)-pkt.Header.Size())) //nolint:gosec //G115

	// Return nonce buffer to pool
	a.nonceBufferPool.Put(noncePtr)

	return r, nil
}

// decrypt decrypts a DTLS RecordLayer message.
func (a *aead) decrypt(header recordlayer.Header, in []byte) ([]byte, error) {
	err := header.Unmarshal(in)
	switch {
	case err != nil:
		return nil, err
	case header.ContentType == protocol.ContentTypeChangeCipherSpec:
		// Nothing to encrypt with ChangeCipherSpec
		return in, nil
	case len(in) <= (8 + header.Size()):
		return nil, errNotEnoughRoomForNonce
	}

	// Get nonce buffer from pool
	noncePtr := a.nonceBufferPool.Get().(*[]byte) // nolint:forcetypeassert
	nonce := *noncePtr

	copy(nonce[:4], a.remoteWriteIV[:4])
	copy(nonce[4:], in[header.Size():header.Size()+8])
	out := in[header.Size()+8:]

	var additionalData []byte
	if header.ContentType == protocol.ContentTypeConnectionID {
		additionalData = generateAEADAdditionalDataCID(&header, len(out)-a.tagLength)
	} else {
		additionalData = generateAEADAdditionalData(&header, len(out)-a.tagLength)
	}
	out, err = a.remoteAEAD.Open(out[:0], nonce, out, additionalData)
	if err != nil {
		// Return nonce buffer to pool
		a.nonceBufferPool.Put(noncePtr)

		return nil, fmt.Errorf("%w: %v", errDecryptPacket, err) //nolint:errorlint
	}

	// Return nonce buffer to pool
	a.nonceBufferPool.Put(noncePtr)

	return append(in[:header.Size()], out...), nil
}

func generateAEADAdditionalData(h *recordlayer.Header, payloadLen int) []byte {
	var additionalData [13]byte

	// SequenceNumber MUST be set first
	// we only want uint48, clobbering an extra 2 (using uint64, Golang doesn't have uint48)
	binary.BigEndian.PutUint64(additionalData[:], h.SequenceNumber)
	binary.BigEndian.PutUint16(additionalData[:], h.Epoch)
	additionalData[8] = byte(h.ContentType)
	additionalData[9] = h.Version.Major
	additionalData[10] = h.Version.Minor
	//nolint:gosec //G115
	binary.BigEndian.PutUint16(additionalData[len(additionalData)-2:], uint16(payloadLen))

	return additionalData[:]
}

// generateAEADAdditionalDataCID generates additional data for AEAD ciphers
// according to https://datatracker.ietf.org/doc/html/rfc9146#name-aead-ciphers
func generateAEADAdditionalDataCID(h *recordlayer.Header, payloadLen int) []byte {
	var builder cryptobyte.Builder

	builder.AddUint64(seqNumPlaceholder)
	builder.AddUint8(uint8(protocol.ContentTypeConnectionID))
	builder.AddUint8(uint8(len(h.ConnectionID))) //nolint:gosec //G115
	builder.AddUint8(uint8(protocol.ContentTypeConnectionID))
	builder.AddUint8(h.Version.Major)
	builder.AddUint8(h.Version.Minor)
	builder.AddUint16(h.Epoch)
	util.AddUint48(&builder, h.SequenceNumber)
	builder.AddBytes(h.ConnectionID)
	builder.AddUint16(uint16(payloadLen)) //nolint:gosec //G115

	return builder.BytesOrPanic()
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
	t := uint(len(payload)-1) - uint(paddingLen) //nolint:gosec //G115
	// if len(payload) >= (paddingLen - 1) then the MSB of t is zero
	good = byte(int32(^t) >> 31) //nolint:gosec //G115

	// The maximum possible padding length plus the actual length field
	toCheck := min(
		// The length of the padded data is public, so we can use an if here
		256, len(payload))

	for i := 0; i < toCheck; i++ {
		t := uint(paddingLen) - uint(i) //nolint:gosec //G115
		// if i <= paddingLen then the MSB of t is zero
		mask := byte(int32(^t) >> 31) //nolint:gosec //G115
		b := payload[len(payload)-1-i]
		good &^= mask&paddingLen ^ mask&b
	}

	// We AND together the bits of good and replicate the result across
	// all the bits.
	good &= good << 4
	good &= good << 2
	good &= good << 1
	good = uint8(int8(good) >> 7) //nolint:gosec //G115

	toRemove = int(paddingLen) + 1

	return toRemove, good
}
