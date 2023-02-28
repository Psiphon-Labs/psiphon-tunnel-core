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
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
)

func TestHTTPTransformerHTTPRequest(t *testing.T) {

	type test struct {
		name           string
		input          string
		wantOutput     string
		wantError      error
		chunkSize      int
		transform      Spec
		connWriteLimit int
		connWriteLens  []int
		connWriteErrs  []error
	}

	tests := []test{
		{
			name:       "written in chunks",
			input:      "POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcd",
			wantOutput: "POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcd",
			chunkSize:  1,
		},
		{
			name:       "write header then body", // behaviour of net/http code
			input:      "POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcd",
			wantOutput: "POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcd",
			chunkSize:  38,
		},
		{
			name:          "write header then body with error",
			input:         "POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcd",
			wantOutput:    "POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcd",
			chunkSize:     38,
			connWriteErrs: []error{nil, errors.New("err1")},
			wantError:     errors.New("err1"),
		},
		{
			name:       "written in a single write",
			input:      "POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcd",
			wantOutput: "POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcd",
			chunkSize:  999,
		},
		{
			name:          "written in single write with error",
			input:         "POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcd",
			wantOutput:    "POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcd",
			chunkSize:     999,
			connWriteErrs: []error{errors.New("err1")},
			wantError:     errors.New("err1"),
		},
		{
			name:           "written with partial write and errors",
			input:          "POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcd",
			wantOutput:     "POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcd",
			chunkSize:      1,
			connWriteLimit: 1,
			connWriteErrs:  []error{errors.New("err1"), errors.New("err2")},
			wantError:      errors.New("err1"),
		},
		{
			name:       "transform not applied to body",
			input:      "POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcd",
			wantOutput: "POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcd",
			chunkSize:  1,
			transform:  Spec{[2]string{"abcd", "efgh"}},
		},
		{
			name:      "Content-Length missing",
			input:     "POST / HTTP/1.1\r\n\r\nabcd",
			wantError: errors.New("Content-Length missing"),
			chunkSize: 1,
		},
		{
			name:      "Content-Length overflow",
			input:     fmt.Sprintf("POST / HTTP/1.1\r\nContent-Length: %d\r\n\r\nabcd", uint64(math.MaxUint64)),
			wantError: errors.New("strconv.ParseUint: parsing \"18446744073709551615\": value out of range"),
			chunkSize: 1,
		},
		{
			name:       "incorrect Content-Length header value",
			input:      "POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nabcd",
			wantOutput: "POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc",
			chunkSize:  1,
		},
		{
			name:       "transform",
			input:      "POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcd",
			wantOutput: "POST / HTTP/1.1\r\nContent-Length: 100\r\n\r\nabcd",
			chunkSize:  1,
			transform:  Spec{[2]string{"4", "100"}},
		},
		{
			name:           "transform with partial write and errors in header write",
			input:          "POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcd",
			wantOutput:     "POST / HTTP/1.1\r\nContent-Length: 100\r\n\r\nabcd",
			chunkSize:      1,
			transform:      Spec{[2]string{"4", "100"}},
			connWriteLimit: 1,
			connWriteErrs:  []error{errors.New("err1"), errors.New("err2")},
			wantError:      errors.New("err1"),
		},
		{
			name:           "transform with chunk write and errors in body write",
			input:          "POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcd",
			wantOutput:     "POST / HTTP/1.1\r\nContent-Length: 100\r\n\r\nabcd",
			chunkSize:      39,
			transform:      Spec{[2]string{"4", "100"}},
			connWriteLimit: 1,
			connWriteErrs:  []error{errors.New("err1"), errors.New("err2"), errors.New("err3")},
			wantError:      errors.New("err1"),
		},
		//
		// Below tests document unsupported behavior.
		//
		{
			name:          "written in a single write with errors and partial writes",
			input:         "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n",
			wantOutput:    "POST / HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
			chunkSize:     999,
			transform:     Spec{[2]string{"Host: example.com\r\n", ""}},
			connWriteErrs: []error{errors.New("err1"), nil, errors.New("err2"), nil, nil, errors.New("err3")},
			connWriteLens: []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
			wantError:     errors.New("err1"),
		},
		{
			name:          "written in a single write with error and partial write",
			input:         "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\nabcd",
			wantOutput:    "POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcd",
			chunkSize:     999,
			transform:     Spec{[2]string{"Host: example.com\r\n", ""}},
			connWriteErrs: []error{errors.New("err1")},
			connWriteLens: []int{28}, // write lands mid "\r\n\r\n"
			wantError:     errors.New("err1"),
		},
		{
			name:       "multiple HTTP requests written in a single write",
			input:      "POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcdPOST / HTTP/1.1\r\nContent-Length: 2\r\n\r\n12",
			wantOutput: "POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcdPOST / HTTP/1.1\r\nContent-Length: 2\r\n\r\n12",
			chunkSize:  999,
			wantError:  errors.New("multiple HTTP requests in single Write() not supported"),
		},
		{
			name:       "multiple HTTP requests written in a single write with transform",
			input:      "POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcdPOST / HTTP/1.1\r\nContent-Length: 4\r\n\r\n12POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\n34",
			wantOutput: "POST / HTTP/1.1\r\nContent-Length: 100\r\n\r\nabcdPOST / HTTP/1.1\r\nContent-Length: 100\r\n\r\n12POST / HTTP/1.1\r\nContent-Length: 100\r\n\r\n34",
			chunkSize:  999,
			transform:  Spec{[2]string{"4", "100"}},
			wantError:  errors.New("multiple HTTP requests in single Write() not supported"),
		},
		// Multiple HTTP requests written in a single write. A write will occur
		// where it contains both the end of the previous HTTP request and the
		// start of a new one.
		{
			name:       "multiple HTTP requests written in chunks",
			input:      "POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcdPOST / HTTP/1.1\r\nContent-Length: 2\r\n\r\n12",
			wantOutput: "POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcdPOST / HTTP/1.1\r\nContent-Length: 2\r\n\r\n12",
			chunkSize:  4,
			wantError:  errors.New("multiple HTTP requests in single Write() not supported"),
		},
		// Multiple HTTP requests written in a single write with transform. A
		// write will occur where it contains both the end of the previous HTTP
		// request and the start of a new one.
		{
			name:       "multiple HTTP requests written in chunks with transform",
			input:      "POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcdPOST / HTTP/1.1\r\nContent-Length: 4\r\n\r\n12",
			wantOutput: "POST / HTTP/1.1\r\nContent-Length: 100\r\n\r\nabcdPOST / HTTP/1.1\r\nContent-Length: 100\r\n\r\n12",
			chunkSize:  4, // ensure one write contains bytes from both reqs
			transform:  Spec{[2]string{"4", "100"}},
			wantError:  errors.New("multiple HTTP requests in single Write() not supported"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			seed, err := prng.NewSeed()
			if err != nil {
				t.Fatalf("prng.NewSeed failed %v", err)
			}

			conn := testConn{
				writeLimit: tt.connWriteLimit,
				writeLens:  tt.connWriteLens,
				writeErrs:  tt.connWriteErrs,
			}

			transformer := &HTTPTransformer{
				transform: tt.transform,
				seed:      seed,
				Conn:      &conn,
			}

			remain := []byte(tt.input)

			// Write input bytes to transformer in chunks and then check
			// output.
			for {
				if len(remain) == 0 {
					break
				}

				var b []byte
				if len(remain) < tt.chunkSize || tt.chunkSize == 0 {
					b = remain
				} else {
					b = remain[:tt.chunkSize]
				}

				var n int
				n, err = transformer.Write(b)
				if err != nil {
					// The underlying transport will be a reliable stream
					// transport, i.e. TCP, and we expect the caller to stop
					// writing after an error is returned.
					break
				}

				remain = remain[n:]
			}
			if tt.wantError == nil {
				if err != nil {
					t.Fatalf("unexpected error %v", err)
				}
				if string(conn.b) != tt.wantOutput {
					t.Fatalf("expected \"%s\" of len %d but got \"%s\" of len %d", escapeNewlines(tt.wantOutput), len(tt.wantOutput), escapeNewlines(string(conn.b)), len(conn.b))
				}
			} else {
				// tt.wantError != nil
				if err == nil {
					t.Fatalf("expected error %v", tt.wantError)
				} else if !strings.Contains(err.Error(), tt.wantError.Error()) {
					t.Fatalf("expected error %v got %v", tt.wantError, err)
				}
			}
		})
	}
}

func TestHTTPTransformerHTTPServer(t *testing.T) {

	type test struct {
		name           string
		request        func(string) *http.Request
		wantBody       string
		transform      Spec
		connWriteLimit int
		connWriteLens  []int
		connWriteErrs  []error
		wantError      error
	}

	tests := []test{
		{
			name:      "request body truncated",
			transform: Spec{[2]string{"Content-Length: 4", "Content-Length: 3"}},
			request: func(addr string) *http.Request {

				body := bytes.NewReader([]byte("abcd"))

				req, err := http.NewRequest("POST", "http://"+addr, body)
				if err != nil {
					panic(err)
				}

				return req
			},
			wantBody: "abc",
		},
		// Expect HTTP request to abort after a single Write() call on
		// underlying net.Conn fails.
		{
			name:      "transport fails",
			transform: Spec{[2]string{"", ""}},
			request: func(addr string) *http.Request {

				body := bytes.NewReader([]byte("abcd"))

				req, err := http.NewRequest("POST", "http://"+addr, body)
				if err != nil {
					panic(err)
				}

				return req
			},
			wantBody:      "abc",
			connWriteErrs: []error{errors.New("test error")},
			wantError:     errors.New("test error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			seed, err := prng.NewSeed()
			if err != nil {
				t.Fatalf("prng.NewSeed failed %v", err)
			}

			params := &HTTPTransformerParameters{
				ProtocolTransformName: "spec",
				ProtocolTransformSpec: tt.transform,
				ProtocolTransformSeed: seed,
			}

			dialer := func(ctx context.Context, network, address string) (net.Conn, error) {

				if network != "tcp" {
					return nil, errors.New("expected network tcp")
				}

				conn, err := net.Dial(network, address)
				if err != nil {
					return nil, err
				}

				wrappedConn := testConn{
					Conn:       conn,
					writeLimit: tt.connWriteLimit,
					writeLens:  tt.connWriteLens,
					writeErrs:  tt.connWriteErrs,
				}

				return &wrappedConn, nil
			}

			httpTransport := &http.Transport{
				DialContext: WrapDialerWithHTTPTransformer(dialer, params),
			}

			type serverRequest struct {
				req  *http.Request
				body []byte
			}

			serverReq := make(chan *serverRequest, 1)

			mux := http.NewServeMux()

			mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				b, err := io.ReadAll(r.Body)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
				}
				go func() {
					serverReq <- &serverRequest{
						req:  r,
						body: b,
					}
					close(serverReq)
				}()
			})

			s := &http.Server{
				Addr:    "127.0.0.1:8080",
				Handler: mux,
			}

			go func() {
				s.ListenAndServe()
			}()

			client := http.Client{
				Transport: httpTransport,
				Timeout:   2 * time.Second,
			}

			req := tt.request(s.Addr)

			resp, err := client.Do(req)

			// first shutdown server, then check err
			shutdownErr := s.Shutdown(context.Background())
			if shutdownErr != nil {
				t.Fatalf("s.Shutdown failed %v", shutdownErr)
			}

			if tt.wantError == nil {
				if err != nil {
					t.Fatalf("client.Do failed %v", err)
				}
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("expected 200 but got %d", resp.StatusCode)
				}

				r := <-serverReq

				if tt.wantBody != string(r.body) {
					t.Fatalf("expected body %s but got %s", tt.wantBody, string(r.body))
				}
			} else {
				// tt.wantError != nil
				if err == nil {
					t.Fatalf("expected error %v", tt.wantError)
				} else if !strings.Contains(err.Error(), tt.wantError.Error()) {
					t.Fatalf("expected error %v got %v", tt.wantError, err)
				}
			}
		})
	}
}

func escapeNewlines(s string) string {
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	return s
}

type testConn struct {
	// b is the accumulated bytes from Write() calls.
	b []byte
	// writeLimit is the max number of bytes that will be written in a Write()
	// call.
	writeLimit int
	// writeLens are returned from Write() calls in order and determine the
	// max number of bytes that will be written. Overrides writeLimit if
	// non-empty. If empty, then the value of writeLimit is returned.
	writeLens []int
	// writeErrs are returned from Write() calls in order. If empty, then a nil
	// error is returned.
	writeErrs []error

	net.Conn
}

func (c *testConn) Read(b []byte) (n int, err error) {
	return c.Conn.Read(b)
}

func (c *testConn) Write(b []byte) (n int, err error) {

	if len(c.writeErrs) > 0 {
		err = c.writeErrs[0]
		c.writeErrs = c.writeErrs[1:]
	}

	if len(c.writeLens) > 0 {
		n = c.writeLens[0]
		c.writeLens = c.writeLens[1:]
		if len(b) <= n {
			c.b = append(c.b, b...)
			n = len(b)
		} else {
			c.b = append(c.b, b[:n]...)
		}
	} else if c.writeLimit != 0 && c.writeLimit < len(b) {
		c.b = append(c.b, b[:c.writeLimit]...)
		n = c.writeLimit
	} else {
		c.b = append(c.b, b...)
		n = len(b)
	}

	// Only write to net.Conn if set
	if c.Conn != nil && n > 0 {
		c.Conn.Write(b[:n])
	}

	return
}

func (c *testConn) Close() error {
	return c.Conn.Close()
}

func (c *testConn) LocalAddr() net.Addr {
	return c.Conn.LocalAddr()
}

func (c *testConn) RemoteAddr() net.Addr {
	return c.Conn.RemoteAddr()
}

func (c *testConn) SetDeadline(t time.Time) error {
	return c.Conn.SetDeadline(t)
}

func (c *testConn) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}

func (c *testConn) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)
}
