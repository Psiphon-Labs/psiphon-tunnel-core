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
	stderrors "errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
)

type httpNormalizerTest struct {
	name               string
	input              string
	maxHeaderSize      int
	prohibitedHeaders  []string
	headerOrder        []string
	chunkSize          int
	connReadErrs       []error
	validateMeekCookie func([]byte) ([]byte, error)
	wantOutput         string
	wantError          error
}

func runHTTPNormalizerTest(tt *httpNormalizerTest, useNormalizer bool) error {

	conn := testConn{
		readErrs:   tt.connReadErrs,
		readBuffer: []byte(tt.input),
	}

	passthroughMessage := "passthrough"

	passthroughConn := testConn{
		readBuffer: []byte(passthroughMessage),
	}

	var normalizer net.Conn
	if useNormalizer {
		n := NewHTTPNormalizer(&conn)
		n.maxReqLineAndHeadersSize = tt.maxHeaderSize
		n.headerWriteOrder = tt.headerOrder
		n.prohibitedHeaders = tt.prohibitedHeaders
		n.validateMeekCookie = tt.validateMeekCookie

		if n.validateMeekCookie != nil {

			n.passthroughAddress = "127.0.0.1:0"
			n.passthroughDialer = func(network, address string) (net.Conn, error) {

				if network != "tcp" {
					return nil, errors.Tracef("expected network tcp but got \"%s\"", network)
				}

				if address != n.passthroughAddress {
					return nil, errors.Tracef("expected address \"%s\" but got \"%s\"", n.passthroughAddress, address)
				}

				return &passthroughConn, nil // return underlying conn
			}
		}
		normalizer = n
	} else {
		normalizer = &conn
	}
	defer normalizer.Close()

	remain := len(tt.wantOutput)
	var acc []byte
	var err error

	// Write input bytes to normalizer in chunks and then check
	// output.
	for {
		if remain <= 0 {
			break
		}

		b := make([]byte, tt.chunkSize)

		expectedErr := len(conn.readErrs) > 0

		var n int
		n, err = normalizer.Read(b)
		if err != nil && !expectedErr {
			// err checked outside loop
			break
		}

		if n > 0 {
			remain -= n
			acc = append(acc, b[:n]...)
		}
	}

	// Calling Read on an instance of HTTPNormalizer will return io.EOF once a
	// passthrough has been activated.
	if tt.validateMeekCookie != nil && err == io.EOF {

		// wait for passthrough to complete

		timeout := time.After(time.Second)

		for len(passthroughConn.ReadBuffer()) != 0 || len(conn.ReadBuffer()) != 0 {

			select {
			case <-timeout:
				return errors.TraceNew("timed out waiting for passthrough to complete")
			case <-time.After(10 * time.Millisecond):
			}
		}

		// Subsequent reads should return EOF

		b := make([]byte, 1)
		_, err := normalizer.Read(b)
		if err != io.EOF {
			return errors.TraceNew("expected EOF")
		}

		// Subsequent writes should not impact conn or passthroughConn

		_, err = normalizer.Write([]byte("ignored"))
		if !stderrors.Is(err, ErrPassthroughActive) {
			return errors.Tracef("expected error io.EOF but got %v", err)
		}

		if string(acc) != "" {
			return errors.TraceNew("expected to read no bytes")
		}

		if string(passthroughConn.ReadBuffer()) != "" {
			return errors.TraceNew("expected read buffer to be emptied")
		}

		if string(passthroughConn.WriteBuffer()) != tt.wantOutput {
			return errors.Tracef("expected \"%s\" of len %d but got \"%s\" of len %d", escapeNewlines(tt.wantOutput), len(tt.wantOutput), escapeNewlines(string(passthroughConn.WriteBuffer())), len(passthroughConn.WriteBuffer()))
		}

		if string(conn.ReadBuffer()) != "" {
			return errors.TraceNew("expected read buffer to be emptied")
		}

		if string(conn.WriteBuffer()) != passthroughMessage {
			return errors.Tracef("expected \"%s\" of len %d but got \"%s\" of len %d", escapeNewlines(passthroughMessage), len(passthroughMessage), escapeNewlines(string(conn.WriteBuffer())), len(conn.WriteBuffer()))
		}
	}

	if tt.wantError == nil {
		if err != nil {
			return errors.TraceMsg(err, "unexpected error")
		}
	} else {
		// tt.wantError != nil
		if err == nil {
			return errors.Tracef("expected error %v", tt.wantError)
		} else if !strings.Contains(err.Error(), tt.wantError.Error()) {
			return errors.Tracef("expected error %v got %v", tt.wantError, err)
		}
	}
	if tt.wantError == nil && string(acc) != tt.wantOutput {
		return errors.Tracef("expected \"%s\" of len %d but got \"%s\" of len %d", escapeNewlines(tt.wantOutput), len(tt.wantOutput), escapeNewlines(string(acc)), len(acc))
	}

	return nil
}

func TestHTTPNormalizerHTTPRequest(t *testing.T) {

	tests := []httpNormalizerTest{
		{
			name:       "no cookie in chunks",
			input:      "POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcd",
			wantOutput: "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\nabcd",
			chunkSize:  1,
		},
		{
			name:        "no cookie in single read",
			input:       "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\nabcd",
			headerOrder: []string{"Host", "Content-Length"},
			wantOutput:  "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\nabcd",
			chunkSize:   999,
		},
		{
			name:        "no cookie, first read lands in body",
			input:       "POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcd",
			headerOrder: []string{"Host", "Content-Length"},
			wantOutput:  "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\nabcd",
			chunkSize:   40, // first read goes up to and including "b"
		},
		{
			name:        "no cookie with spaces",
			input:       "POST / HTTP/1.1\r\n      Content-Length:   4  \r\n\r\nabcd",
			headerOrder: []string{"Host", "Content-Length"},
			wantOutput:  "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\nabcd",
			chunkSize:   1,
		},
		{
			name:        "cookie and range",
			input:       "POST / HTTP/1.1\r\nContent-Length: 4\r\n    Cookie: X\r\nRange: 1234 \r\n\r\nabcd",
			headerOrder: []string{"Host", "Content-Length", "Cookie", "Range"},
			wantOutput:  "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\nCookie: X\r\nRange: 1234\r\n\r\nabcd",
			chunkSize:   1,
		},
		{
			name:         "partial write and errors",
			input:        "POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcd",
			headerOrder:  []string{"Host", "Content-Length"},
			wantOutput:   "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\nabcd",
			chunkSize:    1,
			connReadErrs: []error{stderrors.New("err1"), stderrors.New("err2")},
		},
		{
			name:       "Content-Length missing",
			input:      "POST / HTTP/1.1\r\n\r\nabcd",
			wantOutput: "POST / HTTP/1.1\r\n\r\nabcd", // set to ensure all bytes are read
			wantError:  stderrors.New("Content-Length missing"),
			chunkSize:  1,
		},
		{
			name:       "invalid Content-Length header value",
			input:      "POST / HTTP/1.1\r\nContent-Length: X\r\n\r\nabcd",
			wantOutput: "POST / HTTP/1.1\r\nContent-Length: X\r\nHost: example.com\r\n\r\nabcd", // set to ensure all bytes are read
			wantError:  stderrors.New("strconv.ParseUint: parsing \"X\": invalid syntax"),
			chunkSize:  1,
		},
		{
			name:       "incorrect Content-Length header value",
			input:      "POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nabcd",
			wantOutput: "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\n\r\nabc",
			chunkSize:  1,
		},
		{
			name:        "single HTTP request written in a single write",
			input:       "POST / HTTP/1.1\r\nRemoved: removed\r\nContent-Length: 4\r\n\r\nabcd",
			headerOrder: []string{"Host", "Content-Length"},
			wantOutput:  "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\nabcd",
			chunkSize:   999,
		},
		{
			name:        "multiple HTTP requests written in a single write",
			input:       "POST / HTTP/1.1\r\nRemoved: removed\r\nContent-Length: 4\r\n\r\nabcdPOST / HTTP/1.1\r\nContent-Length: 2\r\n\r\n12",
			headerOrder: []string{"Host", "Content-Length"},
			wantOutput:  "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\nabcdPOST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 2\r\n\r\n12",
			chunkSize:   999,
		},
		{
			name:        "multiple HTTP requests written in chunks",
			input:       "POST / HTTP/1.1\r\nRemoved: removed\r\nContent-Length: 4\r\n\r\nabcdPOST / HTTP/1.1\r\nContent-Length: 2\r\n\r\n12",
			headerOrder: []string{"Host", "Content-Length"},
			wantOutput:  "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\nabcdPOST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 2\r\n\r\n12",
			chunkSize:   3,
		},
		{
			name:        "multiple HTTP requests first read lands in middle of last request",
			input:       "POST / HTTP/1.1\r\nRemoved: removed\r\nContent-Length: 4\r\n\r\nabcdPOST / HTTP/1.1\r\nContent-Length: 2\r\n\r\n12POST / HTTP/1.1\r\nContent-Length: 2\r\n\r\nxyx",
			headerOrder: []string{"Host", "Content-Length"},
			wantOutput:  "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\nabcdPOST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 2\r\n\r\n12",
			chunkSize:   109,
		},
		{
			name:        "longer",
			input:       "POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcd",
			headerOrder: []string{"Host", "Content-Length"},
			wantOutput:  "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\nabcd",
			chunkSize:   1,
		},
		{
			name:        "shorter",
			input:       "POST / HTTP/1.1111111111111111111\r\nContent-Length: 4\r\n\r\nabcd",
			headerOrder: []string{"Host", "Content-Length"},
			wantOutput:  "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\nabcd",
			chunkSize:   1,
		},
		{
			name:  "missing cookie",
			input: "POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcd",
			validateMeekCookie: func([]byte) ([]byte, error) {
				return nil, errors.TraceNew("invalid cookie")
			},
			wantOutput: "POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcd",
			chunkSize:  1,
			wantError:  io.EOF,
		},
		{
			name:  "invalid cookie",
			input: "POST / HTTP/1.1\r\nCookie: invalid\r\nContent-Length: 4\r\n\r\nabcd",
			validateMeekCookie: func([]byte) ([]byte, error) {
				return nil, errors.TraceNew("invalid cookie")
			},
			wantOutput: "POST / HTTP/1.1\r\nCookie: invalid\r\nContent-Length: 4\r\n\r\nabcd",
			chunkSize:  1,
			wantError:  io.EOF,
		},
		{
			name:        "valid cookie",
			input:       "POST / HTTP/1.1\r\nHost: example.com\r\nCookie: valid\r\nContent-Length: 4\r\nRange: unused\r\nSkipped: skipped\r\n\r\nabcd",
			headerOrder: []string{"Host", "Cookie", "Content-Length", "Range"},
			validateMeekCookie: func([]byte) ([]byte, error) {
				return nil, nil
			},
			wantOutput: "POST / HTTP/1.1\r\nHost: example.com\r\nCookie: valid\r\nContent-Length: 4\r\nRange: unused\r\n\r\nabcd",
			chunkSize:  1,
		},
		{
			name:          "exceeds max Request-Line, and headers, size",
			input:         "POST / HTTP/1.1\r\nContent-Length: 4\r\nCookie: X\r\nRange: 1234 \r\n\r\nabcd",
			maxHeaderSize: 47, // up to end of Cookie header
			wantOutput:    "POST / HTTP/1.1\r\nContent-Length: 4\r\nCookie: X\r\nRange: 1234 \r\n\r\nabcd",
			chunkSize:     1,
			wantError:     stderrors.New("exceeds maxReqLineAndHeadersSize"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			err := runHTTPNormalizerTest(&tt, true)
			if err != nil {
				t.Fatalf("runHTTPNormalizerTest failed: %v", err)
			}
		})
	}
}

// Caveats:
//   - Does not test or handle mutiple requests in a single connection
//   - Does not test the scenario where the first request in a connection
//     passes validation and then a subsequent request fails which triggers
//     a passthrough - in this scenario both the listener and passthrough
//     listener will receive bytes.
func TestHTTPNormalizerHTTPServer(t *testing.T) {

	type test struct {
		name              string
		request           string
		maxHeaderSize     int
		prohibitedHeaders []string
		wantPassthrough   bool
		wantRecv          string
	}

	tests := []test{
		{
			name:     "valid cookie",
			request:  "POST / HTTP/1.1\r\nCookie: valid\r\nContent-Length: 4\r\n\r\nabcd",
			wantRecv: "POST / HTTP/1.1\r\nHost: example.com\r\nCookie: valid\r\nContent-Length: 4\r\n\r\nabcd",
		},
		{
			name:            "missing cookie",
			request:         "POST HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcd",
			wantPassthrough: true,
			wantRecv:        "POST HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcd",
		},
		{
			name:            "invalid cookie",
			request:         "POST HTTP/1.1\r\nCookie: invalid\r\nContent-Length: 4\r\n\r\nabcd",
			wantPassthrough: true,
			wantRecv:        "POST HTTP/1.1\r\nCookie: invalid\r\nContent-Length: 4\r\n\r\nabcd",
		},
		{
			name:              "valid cookie with prohibited headers",
			request:           "POST / HTTP/1.1\r\nCookie: valid\r\nProhibited: prohibited\r\nContent-Length: 4\r\n\r\nabcd",
			prohibitedHeaders: []string{"Prohibited"},
			wantPassthrough:   true,
			wantRecv:          "POST / HTTP/1.1\r\nCookie: valid\r\nProhibited: prohibited\r\nContent-Length: 4\r\n\r\nabcd",
		},
		{
			name:            "valid cookie but exceeds max header size",
			request:         "POST / HTTP/1.1\r\nCookie: valid\r\nContent-Length: 4\r\n\r\nabcd",
			wantPassthrough: true,
			maxHeaderSize:   32, // up to end of Cookie header
			wantRecv:        "POST / HTTP/1.1\r\nCookie: valid\r\nContent-Length: 4\r\n\r\nabcd",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("net.Listen failed %v", err)
			}
			defer listener.Close()

			passthrough, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("net.Listen failed %v", err)
			}
			defer passthrough.Close()

			listener = WrapListenerWithHTTPNormalizer(listener)
			normalizer := listener.(*HTTPNormalizerListener)
			normalizer.PassthroughAddress = passthrough.Addr().String()
			normalizer.PassthroughDialer = net.Dial
			normalizer.MaxReqLineAndHeadersSize = tt.maxHeaderSize
			normalizer.ProhibitedHeaders = tt.prohibitedHeaders
			normalizer.PassthroughLogPassthrough = func(clientIP string, tunnelError error, logFields map[string]interface{}) {}

			validateMeekCookieResult := "payload"
			normalizer.ValidateMeekCookie = func(clientIP string, cookie []byte) ([]byte, error) {
				if string(cookie) == "valid" {
					return []byte(validateMeekCookieResult), nil
				}
				return nil, stderrors.New("invalid cookie")
			}
			normalizer.HeaderWriteOrder = []string{"Host", "Cookie", "Content-Length"}

			type listenerState struct {
				lType                    string // listener type, "listener" or "passthrough"
				err                      error
				recv                     []byte
				validateMeekCookieResult []byte // set if listener is "passthrough"
			}

			runListener := func(listener net.Listener, listenerType string, recv chan *listenerState) {

				conn, err := listener.Accept()
				if err != nil {
					recv <- &listenerState{
						lType: listenerType,
						err:   errors.TraceMsg(err, "listener.Accept failed"),
					}
					return
				}

				defer conn.Close()

				b := make([]byte, len(tt.wantRecv))

				// A single Read should be sufficient because multiple requests
				// in a single connection are not supported by this test.
				n, err := conn.Read(b)
				if err != nil {
					recv <- &listenerState{
						lType: listenerType,
						err:   errors.TraceMsg(err, "conn.Read failed"),
					}
					return
				}
				b = b[:n]

				var validateMeekCookieResult []byte
				if n, ok := conn.(*HTTPNormalizer); ok {
					validateMeekCookieResult = n.ValidateMeekCookieResult
				}

				_, err = conn.Write([]byte(listenerType))
				if err != nil {
					if stderrors.Is(err, ErrPassthroughActive) {
						return
					}
					recv <- &listenerState{
						lType:                    listenerType,
						err:                      errors.TraceMsg(err, "conn.Write failed"),
						validateMeekCookieResult: validateMeekCookieResult,
					}
					return
				}

				recv <- &listenerState{
					lType:                    listenerType,
					recv:                     b,
					err:                      nil,
					validateMeekCookieResult: validateMeekCookieResult,
				}
			}

			recv := make(chan *listenerState)

			listenerType := "listener"
			passthroughType := "passthrough"

			go runListener(listener, listenerType, recv)
			go runListener(passthrough, passthroughType, recv)

			conn, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				t.Fatalf("net.Dial failed %v", err)
			}
			defer conn.Close()

			n, err := conn.Write([]byte(tt.request))
			if err != nil {
				t.Fatalf("conn.Write failed %v", err)
			}
			if n != len(tt.request) {
				t.Fatalf("expected to write %d bytes but wrote %d", len(tt.request), n)
			}

			// read response

			b := make([]byte, 512)
			n, err = conn.Read(b)
			if err != nil {
				t.Fatalf("conn.Read failed %v", err)
			}
			b = b[:n]

			if tt.wantPassthrough && string(b) != passthroughType {
				t.Fatalf("expected passthrough but got response from listener")
			} else if !tt.wantPassthrough && string(b) != listenerType {
				t.Fatalf("expected no passthrough but got response from passthrough")
			}

			r := <-recv

			if r.err != nil {
				t.Fatalf("listener failed %v", r.err)
			}

			if !bytes.Equal(r.recv, []byte(tt.wantRecv)) {
				t.Fatalf("expected \"%s\" of len %d but got \"%s\" of len %d", escapeNewlines(string(tt.wantRecv)), len(tt.wantRecv), escapeNewlines(string(r.recv)), len(r.recv))
			}

			if r.lType != "passthrough" && string(r.validateMeekCookieResult) != validateMeekCookieResult {

				t.Fatalf("expected validateMeekCookieResult value \"%s\" but got \"%s\"", validateMeekCookieResult, string(r.validateMeekCookieResult))
			}

			// Check that other listener did not get a connection

			n, err = conn.Read(b)
			if err != nil && err != io.EOF {
				t.Fatalf("conn.Read failed %v", err)
			}
			if n != 0 {
				t.Fatalf("expected to read 0 bytes")
			}

			select {
			case r := <-recv:
				t.Fatalf("unexpected response from %s: %v \"%s\"", r.lType, r.err, string(r.recv))
			case <-time.After(10 * time.Millisecond):
			}
		})
	}
}

func BenchmarkHTTPNormalizer(b *testing.B) {

	inReq := "POST / HTTP/1.1\r\nContent-Length: 400\r\n\r\nxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	outReq := "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 400\r\n\r\nxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

	input := ""
	output := ""

	// Concatenate many requests to simulate a single connection running over
	// the normalizer.
	for i := 0; i < 100; i++ {
		input += inReq
		output += outReq
	}

	// TODO: test different chunk sizes
	test := &httpNormalizerTest{
		name:       "no cookie in chunks",
		input:      input,
		wantOutput: output,
		chunkSize:  1,
	}

	for n := 0; n < b.N; n++ {

		// TODO: does test setup and teardown in runHTTPNormalizerTest skew
		// the benchmark
		err := runHTTPNormalizerTest(test, true)
		if err != nil {
			b.Fatalf("runHTTPNormalizerTest failed: %v", err)
		}
	}
}
