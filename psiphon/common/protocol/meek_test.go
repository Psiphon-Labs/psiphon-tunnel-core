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
	"io"
	"testing"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
)

func TestMeekPayloadPadding(t *testing.T) {

	err := runTestMeekPayloadPadding()
	if err != nil {
		t.Fatal(err.Error())
		return
	}
}

func runTestMeekPayloadPadding() error {

	key := prng.HexString(16)
	cookie := prng.HexString(16)

	// Test: invalid configurations

	_, err := NewMeekRequestPayloadPaddingState(key, cookie, 0.0, -1, 0)
	if err == nil {
		return errors.TraceNew("unexpected success")
	}

	_, err = NewMeekRequestPayloadPaddingState(key, cookie, 0.0, 2, 1)
	if err == nil {
		return errors.TraceNew("unexpected success")
	}

	_, err = NewMeekRequestPayloadPaddingState(key, cookie, 0.0, 0, 65534)
	if err == nil {
		return errors.TraceNew("unexpected success")
	}

	// Test: immediate EOF

	receiver, err := NewMeekRequestPayloadPaddingState(key, cookie, 0.0, 0, 0)
	if err != nil {
		return errors.Trace(err)
	}

	bytesRead, morePadding, err := receiver.ReceiverConsumePadding(
		bytes.NewReader(nil))
	if bytesRead != 0 || morePadding || err != ErrMeekPaddingStateImmediateEOF {
		return errors.TraceNew("unexpected consume return values")
	}

	// Test: unknown prefix

	sender, err := NewMeekRequestPayloadPaddingState(key, cookie, 0.0, 1, 1)
	if err != nil {
		return errors.Trace(err)
	}

	receiver, err = NewMeekRequestPayloadPaddingState(key, cookie, 0.0, 0, 0)
	if err != nil {
		return errors.Trace(err)
	}

	paddingHeader, err := sender.SenderGetNextPadding(false)
	if err != nil {
		return errors.Trace(err)
	}
	if len(paddingHeader) != 1 {
		return errors.TraceNew("unexpected padding header length")
	}

	corrupt := append([]byte(nil), paddingHeader...)
	corrupt[0] ^= 0x02 // flips decrypted prefix from 0 to 2

	bytesRead, morePadding, err = receiver.ReceiverConsumePadding(
		bytes.NewReader(corrupt))
	if bytesRead != 1 || morePadding || err == nil {
		return errors.TraceNew("unexpected consume return values")
	}

	// Test: incomplete padding size

	sender, err = NewMeekRequestPayloadPaddingState(key, cookie, 0.0, 1, 1)
	if err != nil {
		return errors.Trace(err)
	}

	receiver, err = NewMeekRequestPayloadPaddingState(key, cookie, 0.0, 0, 0)
	if err != nil {
		return errors.Trace(err)
	}

	paddingHeader, err = sender.SenderGetNextPadding(true)
	if err != nil {
		return errors.Trace(err)
	}
	if len(paddingHeader) < 3 {
		return errors.TraceNew("unexpected padding header length")
	}

	bytesRead, morePadding, err = receiver.ReceiverConsumePadding(
		bytes.NewReader(paddingHeader[:1]))
	if bytesRead != 1 || !morePadding || err == nil {
		return errors.TraceNew("unexpected consume return values")
	}

	// Test: incomplete padding

	sender, err = NewMeekRequestPayloadPaddingState(key, cookie, 0.0, 1, 1)
	if err != nil {
		return errors.Trace(err)
	}

	receiver, err = NewMeekRequestPayloadPaddingState(key, cookie, 0.0, 0, 0)
	if err != nil {
		return errors.Trace(err)
	}

	paddingHeader, err = sender.SenderGetNextPadding(true)
	if err != nil {
		return errors.Trace(err)
	}
	if len(paddingHeader) < 4 {
		return errors.TraceNew("unexpected padded header length")
	}

	bytesRead, morePadding, err = receiver.ReceiverConsumePadding(
		bytes.NewReader(paddingHeader[:3]))
	if bytesRead != 3 || !morePadding || err == nil {
		return errors.TraceNew("unexpected consume return values")
	}

	// Test: round trips

	const (
		roundTrips = 1000

		emptyPayloadProbability = 0.5

		requestMinSize = 1
		requestMaxSize = 131072

		responseMinSize = 1
		responseMaxSize = 131072

		omitPaddingProbability = 0.5

		minPaddingSize = 1
		maxPaddingSize = 65533
	)

	clientRequestPaddingState, err := NewMeekRequestPayloadPaddingState(
		key, cookie, omitPaddingProbability, minPaddingSize, maxPaddingSize)
	if err != nil {
		return errors.Trace(err)
	}

	serverRequestPaddingState, err := NewMeekRequestPayloadPaddingState(
		key, cookie, 0.0, 0, 0)
	if err != nil {
		return errors.Trace(err)
	}

	serverResponsePaddingState, err := NewMeekResponsePayloadPaddingState(
		key, cookie, omitPaddingProbability, minPaddingSize, maxPaddingSize)
	if err != nil {
		return errors.Trace(err)
	}

	clientResponsePaddingState, err := NewMeekResponsePayloadPaddingState(
		key, cookie, 0.0, 0, 0)
	if err != nil {
		return errors.Trace(err)
	}

	for i := 0; i < roundTrips; i++ {

		// Client sends potentially padded request to server.

		requestSize := 0
		if !prng.FlipWeightedCoin(emptyPayloadProbability) {
			requestSize = prng.Range(requestMinSize, requestMaxSize)
		}

		requestPaddingHeader, err := clientRequestPaddingState.SenderGetNextPadding(
			requestSize == 0)
		if err != nil {
			return errors.Trace(err)
		}

		if requestSize > 0 {
			if len(requestPaddingHeader) != 1 {
				return errors.TraceNew("unexpected request no-padding header")
			}
		} else {
			if len(requestPaddingHeader) != 0 && len(requestPaddingHeader) < 4 {
				return errors.TraceNew("unexpected request padding header")
			}
		}

		readRequest := func() error {

			if len(requestPaddingHeader) == 0 {
				return nil
			}

			reader := bytes.NewReader(requestPaddingHeader)

			failAfterOneByte := prng.FlipCoin()
			var r io.Reader
			r = reader
			if failAfterOneByte {
				// Exercise the padding reader state machine by returning at most
				// one byte per read.
				r = newOneByteReader(reader)
			}

			for {
				bytesRead, morePadding, err := serverRequestPaddingState.ReceiverConsumePadding(r)
				if err != nil && !morePadding {
					return errors.Trace(err)
				}
				if failAfterOneByte && bytesRead != 1 {
					return errors.Tracef("unexpected request padding 1 bytes read: %d", bytesRead)
				}
				if !failAfterOneByte && bytesRead != int64(len(requestPaddingHeader)) {
					return errors.Tracef("unexpected request padding all bytes read: %d", bytesRead)
				}
				if !morePadding {
					if reader.Len() > 0 {
						return errors.TraceNew("unexpected unread request padding")
					}
					break
				}
			}
			return nil
		}

		err = readRequest()
		if err != nil {
			return errors.Trace(err)
		}

		// Server sends potentially padded response to client.

		responseSize := 0
		if !prng.FlipWeightedCoin(emptyPayloadProbability) {
			responseSize = prng.Range(responseMinSize, responseMaxSize)
		}

		responsePaddingHeader, err := serverResponsePaddingState.SenderGetNextPadding(
			responseSize == 0)
		if err != nil {
			return errors.Trace(err)
		}

		if responseSize > 0 {
			if len(responsePaddingHeader) != 1 {
				return errors.TraceNew("unexpected response no-padding header")
			}
		} else {
			if len(responsePaddingHeader) != 0 && len(responsePaddingHeader) < 4 {
				return errors.TraceNew("unexpected response padding header")
			}
		}

		readResponse := func() error {

			if len(responsePaddingHeader) == 0 {
				return nil
			}
			reader := bytes.NewReader(responsePaddingHeader)

			failAfterOneByte := prng.FlipCoin()
			var r io.Reader
			r = reader
			if failAfterOneByte {
				// Exercise the padding reader state machine by returning at most
				// one byte per read.
				r = newOneByteReader(reader)
			}

			for {
				bytesRead, morePadding, err := clientResponsePaddingState.ReceiverConsumePadding(r)
				if err != nil && !morePadding {
					return errors.Trace(err)
				}
				if failAfterOneByte && bytesRead != 1 {
					return errors.Tracef("unexpected response padding 1 bytes read: %d", bytesRead)
				}
				if !failAfterOneByte && bytesRead != int64(len(responsePaddingHeader)) {
					return errors.Tracef("unexpected response padding all bytes read: %d", bytesRead)
				}
				if !morePadding {
					if reader.Len() > 0 {
						return errors.TraceNew("unexpected unread response padding")
					}
					break
				}
			}
			return nil
		}

		err = readResponse()
		if err != nil {
			return errors.Trace(err)
		}
	}

	return nil
}

func FuzzMeekPayloadPaddingReceiverConsume(f *testing.F) {

	// Test: ReceiverConsumePadding handles fuzzed inputs without panicking.

	f.Add(true, 0, 0)
	f.Add(false, 0, 0)
	f.Add(true, 255, 3)
	f.Fuzz(func(t *testing.T, addPadding bool, mutate int, truncate int) {
		err := runFuzzMeekPayloadPaddingReceiverConsume(addPadding, mutate, truncate)
		if err != nil {
			t.Fatal(err.Error())
			return
		}
	})
}

func runFuzzMeekPayloadPaddingReceiverConsume(
	addPadding bool, mutate int, truncate int) error {

	key := prng.HexString(16)
	cookie := prng.HexString(16)

	for i := 0; i < 2; i++ {

		var sender, receiver *MeekPayloadPaddingState
		var err error

		if i == 0 {
			sender, err = NewMeekRequestPayloadPaddingState(key, cookie, 0.0, 1, 256)
			if err != nil {
				return errors.Trace(err)
			}
			receiver, err = NewMeekRequestPayloadPaddingState(key, cookie, 0.0, 0, 0)
			if err != nil {
				return errors.Trace(err)
			}
		} else {
			sender, err = NewMeekResponsePayloadPaddingState(key, cookie, 0.0, 1, 256)
			if err != nil {
				return errors.Trace(err)
			}
			receiver, err = NewMeekResponsePayloadPaddingState(key, cookie, 0.0, 0, 0)
			if err != nil {
				return errors.Trace(err)
			}
		}

		payload, err := sender.SenderGetNextPadding(addPadding)
		if err != nil {
			return errors.Trace(err)
		}

		input := append([]byte(nil), payload...)

		if len(input) > 0 {
			cut := uint(truncate) % uint(len(input)+1)
			input = input[:cut]
		}
		if len(input) > 0 && mutate != 0 {
			input[prng.Intn(len(input))] ^= byte(mutate)
		}

		_, _, _ = receiver.ReceiverConsumePadding(bytes.NewReader(input))
	}

	return nil
}

type oneByteReader struct {
	reader io.Reader
	fail   bool
}

func newOneByteReader(reader io.Reader) *oneByteReader {
	return &oneByteReader{
		reader: reader,
	}
}

func (r *oneByteReader) Read(p []byte) (int, error) {
	if r.fail {
		r.fail = false
		return 0, io.EOF
	}
	n, err := r.reader.Read(p[0:1])
	r.fail = true
	return n, err
}
