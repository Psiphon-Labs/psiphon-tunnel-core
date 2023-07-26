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

package server

import (
	"bytes"
	"context"
	stderrors "errors"
	"fmt"
	"math/rand"
	"net"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
)

type protocolDemuxTest struct {
	name           string
	classifiers    []protocolClassifier
	classifierType []string
	// conns made on demand so the same test instance can be reused across
	// tests.
	conns []func() net.Conn
	// NOTE: duplicate expected key and value not supported. E.g.
	// {"1": {"A", "A"}} will result in a test failure, but
	// {"1": {"A"}, "2": {"A"}} will not.
	// Expected stream of bytes to read from each conn type. Test will halt
	// if any of the values are not observed.
	expected map[string][]string
}

func runProtocolDemuxTest(tt *protocolDemuxTest) error {
	conns := make(chan net.Conn)
	l := testListener{conns: conns}

	go func() {
		// send conns downstream in random order
		randOrd := rand.Perm(len(tt.conns))
		for i := range randOrd {
			conns <- tt.conns[i]()
		}
	}()

	mux, protoListeners := newProtocolDemux(context.Background(), l, tt.classifiers)

	errs := make([]chan error, len(protoListeners))
	for i := range errs {
		errs[i] = make(chan error)
	}

	for i, protoListener := range protoListeners {

		ind := i
		l := protoListener

		go func() {

			defer close(errs[ind])

			protoListenerType := tt.classifierType[ind]

			expectedValues, ok := tt.expected[protoListenerType]
			if !ok {
				errs[ind] <- fmt.Errorf("conn type %s not found", protoListenerType)
				return
			}

			expectedValuesNotSeen := make(map[string]struct{})
			for _, v := range expectedValues {
				expectedValuesNotSeen[v] = struct{}{}
			}

			// Keep accepting conns until all conns of
			// protoListenerType are retrieved from the mux.
			for len(expectedValuesNotSeen) > 0 {

				conn, err := l.Accept()
				if err != nil {
					errs[ind] <- err
					return
				}

				connType := conn.(*bufferedConn).Conn.(*testConn).connType
				if connType != protoListenerType {
					errs[ind] <- fmt.Errorf("expected conn type %s but got %s for %s", protoListenerType, connType, conn.(*bufferedConn).buffer.String())
					return
				}

				var acc []byte
				b := make([]byte, 1) // TODO: randomize read buffer size

				for {
					n, err := conn.Read(b)
					if err != nil {
						errs[ind] <- err
						return
					}
					if n == 0 {
						break
					}
					acc = append(acc, b[:n]...)
				}

				if _, ok := expectedValuesNotSeen[string(acc)]; !ok {
					errs[ind] <- fmt.Errorf("unexpected value %s", string(acc))
					return
				}

				delete(expectedValuesNotSeen, string(acc))
			}
		}()
	}

	runErr := make(chan error)

	go func() {
		defer close(runErr)

		err := mux.run()
		if err != nil && !stderrors.Is(err, context.Canceled) {
			runErr <- err
		}
	}()

	for i := range errs {
		err := <-errs[i]
		if err != nil {
			return errors.Trace(err)
		}
	}

	err := mux.Close()
	if err != nil {
		return errors.Trace(err)
	}

	err = <-runErr
	if err != nil && !stderrors.Is(err, net.ErrClosed) {
		return errors.Trace(err)
	}

	return nil
}

func TestProtocolDemux(t *testing.T) {

	aClassifier := protocolClassifier{
		match: func(b []byte) bool {
			return bytes.HasPrefix(b, []byte("AAA"))
		},
	}

	bClassifier := protocolClassifier{
		match: func(b []byte) bool {
			return bytes.HasPrefix(b, []byte("BBBB"))
		},
	}
	// TODO: could add delay between each testConn returning bytes to simulate
	// network delay.
	tests := []protocolDemuxTest{
		{
			name: "single conn",
			classifiers: []protocolClassifier{
				aClassifier,
			},
			classifierType: []string{"A"},
			conns: []func() net.Conn{
				func() net.Conn {
					return &testConn{connType: "A", b: []byte("AAA")}
				},
			},
			expected: map[string][]string{
				"A": {"AAA"},
			},
		},
		{
			name: "multiple conns one of each type",
			classifiers: []protocolClassifier{
				aClassifier,
				bClassifier,
			},
			classifierType: []string{"A", "B"},
			conns: []func() net.Conn{
				func() net.Conn {
					return &testConn{connType: "A", b: []byte("AAAzzzzz")}
				},
				func() net.Conn {
					return &testConn{connType: "B", b: []byte("BBBBzzzzz")}
				},
			},
			expected: map[string][]string{
				"A": {"AAAzzzzz"},
				"B": {"BBBBzzzzz"},
			},
		},
		{
			name: "multiple conns multiple of each type",
			classifiers: []protocolClassifier{
				aClassifier,
				bClassifier,
			},
			classifierType: []string{"A", "B"},
			conns: []func() net.Conn{
				func() net.Conn {
					return &testConn{connType: "A", b: []byte("AAA1zzzzz")}
				},
				func() net.Conn {
					return &testConn{connType: "B", b: []byte("BBBB1zzzzz")}
				},
				func() net.Conn {
					return &testConn{connType: "A", b: []byte("AAA2zzzzz")}
				},
				func() net.Conn {
					return &testConn{connType: "B", b: []byte("BBBB2zzzzz")}
				},
			},
			expected: map[string][]string{
				"A": {"AAA1zzzzz", "AAA2zzzzz"},
				"B": {"BBBB1zzzzz", "BBBB2zzzzz"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			err := runProtocolDemuxTest(&tt)
			if err != nil {
				t.Fatalf("runProtocolDemuxTest failed: %v", err)
			}
		})
	}
}

func BenchmarkProtocolDemux(b *testing.B) {

	rand.Seed(time.Now().UnixNano())

	aClassifier := protocolClassifier{
		match: func(b []byte) bool {
			return bytes.HasPrefix(b, []byte("AAA"))
		},
		minBytesToMatch: 3,
		maxBytesToMatch: 3,
	}

	bClassifier := protocolClassifier{
		match: func(b []byte) bool {
			return bytes.HasPrefix(b, []byte("BBBB"))
		},
		minBytesToMatch: 4,
		maxBytesToMatch: 4,
	}

	cClassifier := protocolClassifier{
		match: func(b []byte) bool {
			return bytes.HasPrefix(b, []byte("C"))
		},
		minBytesToMatch: 1,
		maxBytesToMatch: 1,
	}

	connTypeToPrefix := map[string]string{
		"A": "AAA",
		"B": "BBBB",
		"C": "C",
	}
	var conns []func() net.Conn
	connsPerConnType := 100
	expected := make(map[string][]string)

	for connType, connTypePrefix := range connTypeToPrefix {

		for i := 0; i < connsPerConnType; i++ {

			s := fmt.Sprintf("%s%s%d", connTypePrefix, getRandAlphanumericString(9999), i) // include index to prevent collision even though improbable

			connTypeCopy := connType // avoid capturing loop variable

			conns = append(conns, func() net.Conn {
				conn := testConn{
					connType: connTypeCopy,
					b:        []byte(s),
				}
				return &conn
			})

			expected[connType] = append(expected[connType], s)
		}
	}

	test := &protocolDemuxTest{
		name: "multiple conns multiple of each type",
		classifiers: []protocolClassifier{
			aClassifier,
			bClassifier,
			cClassifier,
		},
		classifierType: []string{"A", "B", "C"},
		conns:          conns,
		expected:       expected,
	}

	for n := 0; n < b.N; n++ {
		err := runProtocolDemuxTest(test)
		if err != nil {
			b.Fatalf("runProtocolDemuxTest failed: %v", err)
		}
	}
}

func getRandAlphanumericString(n int) string {
	var alphanumericals = []rune("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, n)
	for i := range b {
		b[i] = alphanumericals[rand.Intn(len(alphanumericals))]
	}
	return string(b)
}

type testListener struct {
	conns chan net.Conn
}

func (l testListener) Accept() (net.Conn, error) {

	conn := <-l.conns
	if conn == nil {
		// no more conns
		return nil, net.ErrClosed
	}

	return conn, nil
}

func (l testListener) Close() error {
	close(l.conns)
	return nil
}

func (l testListener) Addr() net.Addr {
	return nil
}

type testConn struct {
	// connType is the type of the underlying connection.
	connType string
	// b is the bytes to return over Read() calls.
	b []byte
	// maxReadLen is the maximum number of bytes to return from b in a single
	// Read() call if > 0; otherwise no limit is imposed.
	maxReadLen int
	// readErrs are returned from Read() calls in order. If empty, then a nil
	// error is returned.
	readErrs []error
}

func (c *testConn) Read(b []byte) (n int, err error) {
	if len(c.readErrs) > 0 {
		err := c.readErrs[0]
		c.readErrs = c.readErrs[1:]
		return 0, err
	}

	numBytes := len(b)

	if numBytes > c.maxReadLen && c.maxReadLen != 0 {
		numBytes = c.maxReadLen
	}

	if numBytes > len(c.b) {
		numBytes = len(c.b)
	}

	n = copy(b, c.b[:numBytes])

	c.b = c.b[n:]

	return n, nil
}

func (c *testConn) Write(b []byte) (n int, err error) {
	return 0, stderrors.New("not supported")
}

func (c *testConn) Close() error {
	return nil
}

func (c *testConn) LocalAddr() net.Addr {
	return nil
}

func (c *testConn) RemoteAddr() net.Addr {
	return nil
}

func (c *testConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *testConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *testConn) SetWriteDeadline(t time.Time) error {
	return nil
}
