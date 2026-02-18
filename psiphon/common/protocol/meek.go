/*
 * Copyright (c) 2025, Psiphon Inc.
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
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	std_errors "errors"
	"io"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"golang.org/x/crypto/hkdf"
)

const (
	meekPayloadPaddingPrefixNoPadding = 0
	meekPayloadPaddingPrefixPadding   = 1

	meekPayloadPaddingDirectionRequests  = "meek-payload-padding-requests"
	meekPayloadPaddingDirectionResponses = "meek-payload-padding-responses"

	meekPayloadPaddingReceiverConsumeStatePrefix    = 0
	meekPayloadPaddingReceiverConsumeStateSizeByte1 = 1
	meekPayloadPaddingReceiverConsumeStateSizeByte2 = 2
	meekPayloadPaddingReceiverConsumeStatePadding   = 3

	MeekPayloadPaddingPrefixSize = 1
)

// MeekPayloadPaddingState provides support for padding empty meek payloads,
// to vary request and response traffic shapes.
//
// The padding is to be prepended directly to the payloads, the request and
// response bodies, and is intended to be indistinguishable from the fully
// encrypted OSSH payload which is observable in HTTP and decrypted HTTPS.
// The padding header prefix and size are obfuscated with a stream cipher,
// while the padding itself is plain random bytes.
//
// Both the meek client and server will use two MeekPayloadPaddingState
// instances in payload padding mode: one for request padding and one for
// response padding. Each client/server pair requires the obfuscation cipher
// state to be kept in sync; the caller is responsible for handling meek
// retries in such a way that this synchronization is maintained.
//
// MeekPayloadPaddingState also supports omitting padding entirely, with some
// probability, to further vary traffic shapes.
//
// Each MeekPayloadPaddingState instance may only be used for one direction
// only, sending or receiving.
type MeekPayloadPaddingState struct {
	stream cipher.Stream

	// Sender state
	omitPaddingProbability    float64
	minPaddingSize            int
	maxPaddingSize            int
	senderPaddingHeaderBuffer bytes.Buffer

	// Receiver state
	receiverConsumeState          int
	receiverPaddingBytesRemaining int
	receiverPaddingPreamble       [3]byte
	receiverConsumeBuffer         [1024]byte
}

// NewMeekRequestPayloadPaddingState initializes a MeekPayloadPaddingState for
// sending or receiving padded requests.
func NewMeekRequestPayloadPaddingState(
	obfuscatedMeekKey string,
	obfuscatedMeekCookie string,
	omitPaddingProbability float64,
	minPaddingSize int,
	maxPaddingSize int) (*MeekPayloadPaddingState, error) {

	state, err := newMeekPayloadPaddingState(
		meekPayloadPaddingDirectionRequests,
		obfuscatedMeekKey,
		obfuscatedMeekCookie,
		omitPaddingProbability,
		minPaddingSize,
		maxPaddingSize)
	if err != nil {
		return state, errors.Trace(err)
	}
	return state, nil
}

// NewMeekResponsePayloadPaddingState initializes a MeekPayloadPaddingState for
// sending or receiving padded responses.
func NewMeekResponsePayloadPaddingState(
	obfuscatedMeekKey string,
	obfuscatedMeekCookie string,
	omitPaddingProbability float64,
	minPaddingSize int,
	maxPaddingSize int) (*MeekPayloadPaddingState, error) {

	state, err := newMeekPayloadPaddingState(
		meekPayloadPaddingDirectionResponses,
		obfuscatedMeekKey,
		obfuscatedMeekCookie,
		omitPaddingProbability,
		minPaddingSize,
		maxPaddingSize)
	if err != nil {
		return state, errors.Trace(err)
	}
	return state, nil
}

func newMeekPayloadPaddingState(
	direction string,
	obfuscatedMeekKey string,
	obfuscatedMeekCookie string,
	omitPaddingProbability float64,
	minPaddingSize int,
	maxPaddingSize int) (*MeekPayloadPaddingState, error) {

	// Maximum padding length of 65533 is the max meek request size, 65536,
	// less 3 byte padding header with prefix and length bytes.

	if minPaddingSize < 0 ||
		minPaddingSize > maxPaddingSize ||
		maxPaddingSize > 65533 {

		return nil, errors.TraceNew("invalid padding size")
	}

	state := &MeekPayloadPaddingState{
		omitPaddingProbability: omitPaddingProbability,
		minPaddingSize:         minPaddingSize,
		maxPaddingSize:         maxPaddingSize,
	}

	// For the cipher stream applied to the padding header, derive a unique
	// key using a value unknown to an adversary (obfuscatedMeekKey), a
	// unique nonce per flow (obfuscatedMeekCookie), and a unique salt or
	// context for the direction (request/response), all ensuring that the
	// adversary observing the stream cannot distinguish the encrypted
	// padding header from random bytes either by directly decrypting it or
	// xoring various bytes together.
	//
	// A stream cipher is used to minimize payload overhead. Given the unique
	// key per flow and direction, an all zeroes IV suffices, saving payload
	// bytes. There's no authentication, also to save payload bytes and
	// maximize shape distribution; The underlying SSH layer provides proper
	// authentication and full transport security for actual tunneled traffic.

	var key [32]byte
	var iv [aes.BlockSize]byte

	_, err := io.ReadFull(
		hkdf.New(
			sha256.New,
			[]byte(obfuscatedMeekKey),
			[]byte(obfuscatedMeekCookie),
			[]byte(direction)),
		key[:])
	if err != nil {
		return nil, errors.Trace(err)
	}

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, errors.Trace(err)
	}

	state.stream = cipher.NewCTR(block, iv[:])

	return state, nil
}

// SenderGetNextPadding returns the next obfuscated padding header and padding
// bytes. When addPadding is false, the returned header contains only the
// NoPadding prefix. Otherwise, a full padding header and padding bytes are
// returned. With omitPaddingProbability, in the addPadding true case an
// empty header may be returned, allowing for zero byte payloads, saving some
// data and further varying the traffic shape.
//
// The returned slice is only valid until the next SenderGetNextPadding call.
//
// Not safe for concurrent use.
func (state *MeekPayloadPaddingState) SenderGetNextPadding(
	addPadding bool) ([]byte, error) {

	// As a future enhancement, consider adding a new state and prefix,
	// meekPayloadPaddingPrefixEndPadding. After sufficient packets, this
	// prefix is sent, and no further padding, including prefix, will be
	// added. The challenge with this is that meek resiliency and
	// MeekRedialTLSProbability both result in new TCP flows for the same
	// meek session, flow which would presumably need to start adding padding
	// again, requiring some mechanism to signal this; with an intermediary
	// such as a CDN, the server won't be able to infer new TCP flows simply
	// at the socket

	state.senderPaddingHeaderBuffer.Reset()

	if addPadding && prng.FlipWeightedCoin(state.omitPaddingProbability) {

		// With the given probability, select no padding header at all.
		return state.senderPaddingHeaderBuffer.Bytes(), nil
	}

	if !addPadding {

		var preamble [1]byte
		preamble[0] = meekPayloadPaddingPrefixNoPadding
		state.stream.XORKeyStream(preamble[:], preamble[:])
		state.senderPaddingHeaderBuffer.Write(preamble[:])
		return state.senderPaddingHeaderBuffer.Bytes(), nil
	}

	paddingSize := prng.Range(state.minPaddingSize, state.maxPaddingSize)

	var preamble [3]byte
	preamble[0] = meekPayloadPaddingPrefixPadding
	binary.BigEndian.PutUint16(preamble[1:3], uint16(paddingSize))
	state.stream.XORKeyStream(preamble[:], preamble[:])
	state.senderPaddingHeaderBuffer.Write(preamble[:])
	state.senderPaddingHeaderBuffer.Write(prng.Bytes(paddingSize))
	return state.senderPaddingHeaderBuffer.Bytes(), nil
}

var ErrMeekPaddingStateImmediateEOF = std_errors.New("immediate EOF")

// ReceiverConsumePadding reads and consumes payload padding from the input
// reader.
//
// The padding consists of a preamble with a 1 byte prefix, an optional 2 byte
// size; followed the specified number of padding bytes, if any. The padding
// header is deobfuscated using a cipher stream that should be kept in sync
// with the corresponding sender state.
//
// ReceiverConsumePadding supports reading as little as 1 byte at a time from the
// reader and statefully resuming on subsequent calls. retContinue true and a
// non-nil retErr indicates a partial read; the caller should call
// ReceiverConsumePadding to resume. There is no retContinue true and nil retErr
// case.
//
// A special return value for retErr of ErrMeekPaddingStateImmediateEOF
// indicates that the reader had 0 bytes, and this may be treated as an "omit
// padding" case.
//
// retBytesRead is the number of bytes read from reader, even in error cases.
//
// Not safe for concurrent use.
func (state *MeekPayloadPaddingState) ReceiverConsumePadding(
	reader io.Reader) (retBytesRead int64, retContinue bool, retErr error) {

	bytesRead := int64(0)
	for {

		// Use a state machine and read one byte at a time. This allows
		// MeekPayloadPaddingState.ReceiverConsumePadding to handle meek payload
		// partial reads which may return as little as one byte and an error.

		switch state.receiverConsumeState {

		case meekPayloadPaddingReceiverConsumeStatePrefix:

			n, err := io.ReadFull(reader, state.receiverPaddingPreamble[0:1])
			// Only 1 byte is requested, so there's no partial-read-with-error
			// case to handle.
			if err != nil {
				if err == io.EOF {

					// If the request/response body is empty, ReadFull will
					// immediately return io.EOF. The caller can use the
					// special ErrImmediateEOF return value to treat this
					// case as a success, allowing for actual empty payloads
					// in addition to padded payloads.

					return 0, false, ErrMeekPaddingStateImmediateEOF
				}
				return bytesRead, true, errors.TraceReader(err)
			}

			bytesRead += int64(n)
			state.stream.XORKeyStream(
				state.receiverPaddingPreamble[0:1],
				state.receiverPaddingPreamble[0:1])

			switch state.receiverPaddingPreamble[0] {

			case meekPayloadPaddingPrefixNoPadding:
				// With NoPadding, there's only 1 byte to read, so go back to
				// the start state.
				state.receiverConsumeState = meekPayloadPaddingReceiverConsumeStatePrefix

			case meekPayloadPaddingPrefixPadding:
				// Next states: read the 2 padding size bytes.
				state.receiverConsumeState = meekPayloadPaddingReceiverConsumeStateSizeByte1

			default:
				return bytesRead, false, errors.TraceNew("unknown padding prefix")
			}

		case meekPayloadPaddingReceiverConsumeStateSizeByte1:

			n, err := io.ReadFull(reader, state.receiverPaddingPreamble[1:2])
			if err != nil {
				return bytesRead, true, errors.TraceReader(err)
			}
			bytesRead += int64(n)
			state.stream.XORKeyStream(
				state.receiverPaddingPreamble[1:2],
				state.receiverPaddingPreamble[1:2])

			state.receiverConsumeState = meekPayloadPaddingReceiverConsumeStateSizeByte2

		case meekPayloadPaddingReceiverConsumeStateSizeByte2:

			n, err := io.ReadFull(reader, state.receiverPaddingPreamble[2:3])
			if err != nil {
				return bytesRead, true, errors.TraceReader(err)
			}
			bytesRead += int64(n)
			state.stream.XORKeyStream(
				state.receiverPaddingPreamble[2:3],
				state.receiverPaddingPreamble[2:3])

			// Since the obfuscation cipher has no authentication, we may
			// proceed with a corrupt or manipulated padding size; but the 2
			// bytes can only represent up to the max padding size of ~64K anyway.

			state.receiverPaddingBytesRemaining = int(
				binary.BigEndian.Uint16(state.receiverPaddingPreamble[1:3]))
			state.receiverConsumeState = meekPayloadPaddingReceiverConsumeStatePadding

		case meekPayloadPaddingReceiverConsumeStatePadding:

			// The size of receiverConsumeBuffer is chosen as a tradeoff
			// between memory overhead and I/O calls.

			for state.receiverPaddingBytesRemaining > 0 {
				m := state.receiverPaddingBytesRemaining
				if m > len(state.receiverConsumeBuffer) {
					m = len(state.receiverConsumeBuffer)
				}
				n, err := io.ReadFull(reader, state.receiverConsumeBuffer[0:m])
				bytesRead += int64(n)
				state.receiverPaddingBytesRemaining -= n
				if err != nil {
					return bytesRead, true, errors.TraceReader(err)
				}
			}
			// After all padding bytes are read, go back to the start state.
			state.receiverConsumeState = meekPayloadPaddingReceiverConsumeStatePrefix

		default:
			return bytesRead, false, errors.TraceNew("unknown consume padding state")

		}

		if state.receiverConsumeState == meekPayloadPaddingReceiverConsumeStatePrefix {
			// Done when back to the start state.
			break
		}
		// Else loop and read the next byte(s) for the next state.
	}

	return bytesRead, false, nil
}
