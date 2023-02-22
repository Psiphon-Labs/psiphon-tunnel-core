/*
 * Copyright (c) 2023, Psiphon Inc.
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

package transforms

import (
	"bytes"
	"context"
	"math"
	"net"
	"net/textproto"
	"strconv"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
)

type HTTPTransformerParameters struct {
	// ProtocolTransformName specifies the name associated with
	// ProtocolTransformSpec and is used for metrics.
	ProtocolTransformName string

	// ProtocolTransformSpec specifies a transform to apply to the HTTP request.
	// See: "github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/transforms".
	//
	// HTTP transforms include strategies discovered by the Geneva team,
	// https://geneva.cs.umd.edu.
	ProtocolTransformSpec Spec

	// ProtocolTransformSeed specifies the seed to use for generating random
	// data in the ProtocolTransformSpec transform. To replay a transform,
	// specify the same seed.
	ProtocolTransformSeed *prng.Seed
}

const (
	// httpTransformerReadHeader HTTPTransformer is waiting to finish reading
	// the next HTTP request header.
	httpTransformerReadHeader = 0
	// httpTransformerReadWriteBody HTTPTransformer is waiting to finish reading
	// and writing the current HTTP request body.
	httpTransformerReadWriteBody = 1
)

// HTTPTransformer wraps a net.Conn, intercepting Write calls and applying the
// specified protocol transform.
//
// The HTTP request to be written (input to the Write) is converted to a
// string, transformed, and converted back to binary and then actually written
// to the underlying net.Conn.
//
// HTTPTransformer is not safe for concurrent use.
type HTTPTransformer struct {
	transform Spec
	seed      *prng.Seed

	// state is the HTTPTransformer state. Possible values are
	// httpTransformerReadingHeader and httpTransformerReadingBody.
	state int64
	// b is the accumulated bytes of the current HTTP request.
	b []byte
	// remain is the number of remaining HTTP request body bytes to read into b.
	remain uint64

	net.Conn
}

// Warning: Does not handle chunked encoding. Must be called synchronously.
func (t *HTTPTransformer) Write(b []byte) (int, error) {

	if t.state == httpTransformerReadHeader {

		t.b = append(t.b, b...)

		// Wait until the entire HTTP request header has been read. Must check
		// all accumulated bytes incase the "\r\n\r\n" separator is written over
		// multiple Write() calls; from reading the net/http code the entire
		// HTTP request is written in a single Write() call.

		sep := []byte("\r\n\r\n")

		headerBodyLines := bytes.SplitN(t.b, sep, 2) // split header and body

		if len(headerBodyLines) > 1 {

			// read Content-Length before applying transform

			var headerLines [][]byte

			lines := bytes.Split(headerBodyLines[0], []byte("\r\n"))
			if len(lines) > 1 {
				// skip request line, e.g. "GET /foo HTTP/1.1"
				headerLines = lines[1:]
			}

			var cl []byte
			contentLengthHeader := []byte("Content-Length:")

			for _, header := range headerLines {

				if bytes.HasPrefix(header, contentLengthHeader) {

					cl = textproto.TrimBytes(header[len(contentLengthHeader):])
					break
				}
			}
			if len(cl) == 0 {
				// Irrecoverable error because either Content-Length header
				// missing, or Content-Length header value is empty, e.g.
				// "Content-Length: ", and request body length cannot be
				// determined.
				//
				// b buffered in t.b, return len(b) in an attempt to get
				// through the current Write() sequence instead of getting
				// stuck.
				return len(b), errors.TraceNew("Content-Length missing")
			}

			contentLength, err := strconv.ParseUint(string(cl), 10, 63)
			if err != nil {
				// Irrecoverable error because Content-Length is malformed and
				// request body length cannot be determined.
				//
				// b buffered in t.b, return len(b) in an attempt to get
				// through the current Write() sequence instead of getting
				// stuck.
				return len(b), errors.Trace(err)
			}

			t.remain = contentLength

			// transform and write header

			headerLen := len(headerBodyLines[0]) + len(sep)
			header := t.b[:headerLen]

			if t.transform != nil {
				newHeaderS, err := t.transform.Apply(t.seed, string(header))
				if err != nil {
					// TODO: consider logging an error and skiping transform
					// instead of returning an error, if the transform is broken
					// then all subsequent applications may fail.
					//
					// b buffered in t.b, return len(b) in an attempt to get
					// through the current Write() sequence instead of getting
					// stuck.
					return len(b), errors.Trace(err)
				}

				newHeader := []byte(newHeaderS)

				// only allocate new slice if header length changed
				if len(newHeader) == len(header) {
					copy(t.b[:len(header)], newHeader)
				} else {
					t.b = append(newHeader, t.b[len(header):]...)
				}

				header = newHeader
			}

			if math.MaxUint64-t.remain < uint64(len(header)) {
				// Irrecoverable error because request is malformed:
				// Content-Length + len(header) > math.MaxUint64.
				//
				// b buffered in t.b, return len(b) in an attempt to get
				// through the current Write() sequence instead of getting
				// stuck.
				return len(b), errors.TraceNew("t.remain + uint64(len(header)) overflows")
			}
			t.remain += uint64(len(header))

			n, err := t.writeBuffer()

			written := len(b) // all bytes of b buffered in t.b

			if n < len(header) ||
				len(t.b) > 0 && t.remain == 0 {
				// All bytes of b were not written, but all bytes of b have been
				// buffered in t.b. Drop 1 byte of b from t.b to pretend 1 byte
				// of b was not written to trigger another Write() call. This
				// handles the scenario where all request bytes have been
				// received but writing to the underlying net.Conn fails and
				// another Write() call cannot be expected unless a value
				// less than len(b) is returned. An alternative solution would
				// be to retry writes, or spawn a goroutine which writes t.b,
				// but we want to return the error to the caller immediately so
				// it can act accordingly.
				written = len(b) - 1
				t.b = t.b[:len(t.b)-1]
			}

			if t.remain > 0 {
				t.state = httpTransformerReadWriteBody
			}

			return written, err
		}

		// b buffered in t.b and the entire HTTP request header has not been
		// recieved so another Write() call is expected.
		return len(b), nil
	}

	// HTTP request header has been transformed. Write any remaining bytes of
	// HTTP request header and then write HTTP request body.

	// Must write buffered bytes first, in-order, to write bytes to underlying
	// Conn in the same order they were received in.
	_, err := t.writeBuffer()
	if err != nil {
		// b not written or buffered
		return 0, errors.Trace(err)
	}

	// Only write bytes of current request
	writeN := uint64(len(b))
	if writeN > t.remain {
		writeN = t.remain
	}

	n, err := t.Conn.Write(b[:writeN])

	// Do not need to check for underflow because n <= t.remain
	t.remain -= uint64(n)

	if t.remain <= 0 {
		// Entire request, header and body, has been written. Return to
		// waiting for next HTTP request header to arrive.
		//
		// Return the number of bytes written to the underlying Conn instead of
		// calling t.Write() with any remaining bytes of b which were not
		// written or buffered, i.e. when n < len(b). The caller must call
		// Write() again with the unwritten, and unbuffered, bytes of b.
		t.state = httpTransformerReadHeader
		t.remain = 0
	}

	return n, err
}

func (t *HTTPTransformer) writeBuffer() (written int, err error) {

	// Continue writing buffered bytes until either all buffered bytes have
	// been written or all remaining bytes of the current HTTP request have
	// been written.
	for len(t.b) > 0 && t.remain > 0 {

		// Write all buffered bytes of the current request
		writeN := uint64(len(t.b))
		if writeN > t.remain {
			// t.b contains bytes of the next request(s), only write current
			// request bytes.
			writeN = t.remain
		}

		// Check for potential overflow before Write() call
		if math.MaxInt-written < int(writeN) {
			return written, errors.TraceNew("written + bytesToWrite overflows")
		}

		var n int
		n, err = t.Conn.Write(t.b[:writeN])
		written += n

		// Do not need to check for underflow because n <= t.remain
		t.remain -= uint64(n)

		if n == len(t.b) {
			t.b = nil
		} else {
			t.b = t.b[n:]
		}

		// Stop writing and return if there was an error
		if err != nil {
			return
		}
	}

	return
}

func WrapDialerWithHTTPTransformer(dialer common.Dialer, params *HTTPTransformerParameters) common.Dialer {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := dialer(ctx, network, addr)
		if err != nil {
			return nil, errors.Trace(err)
		}
		return &HTTPTransformer{
			Conn:      conn,
			transform: params.ProtocolTransformSpec,
			seed:      params.ProtocolTransformSeed,
		}, nil
	}
}
