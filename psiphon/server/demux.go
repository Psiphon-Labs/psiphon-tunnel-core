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
	std_errors "errors"
	"net"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/sirupsen/logrus"
)

// protocolDemux enables a single listener to support multiple protocols
// by demultiplexing each conn it accepts into the corresponding protocol
// handler.
type protocolDemux struct {
	ctx                       context.Context
	cancelFunc                context.CancelFunc
	innerListener             net.Listener
	classifiers               []protocolClassifier
	connClassificationTimeout time.Duration

	conns []chan net.Conn
}

type protocolClassifier struct {
	// If set, then the classifier only needs a sample of at least this many
	// bytes to determine whether there is a match or not.
	minBytesToMatch int
	// If set, then the classifier only needs a sample of up to this many bytes
	// to determine whether there is a match or not. If match returns false with
	// a sample of size greater than or equal to maxBytesToMatch, then match
	// will always return false regardless of which bytes are appended to
	// the given sample.
	maxBytesToMatch int
	// Returns true if the sample corresponds to the protocol represented by
	// this classifier.
	match func(sample []byte) bool
}

// newProtocolDemux returns a newly initialized ProtocolDemux and an
// array of protocol listeners. For each protocol classifier in classifiers
// there will be a corresponding protocol listener at the same index in the
// array of returned protocol listeners. If connClassificationTimeout is >0,
// then any conn not classified in this amount of time will be closed.
//
// Limitation: the conn is also closed after reading maxBytesToMatch and
// failing to find a match, which can be a fingerprint for a raw conn with no
// preceding anti-probing measure, such as TLS passthrough.
func newProtocolDemux(
	ctx context.Context,
	listener net.Listener,
	classifiers []protocolClassifier,
	connClassificationTimeout time.Duration) (*protocolDemux, []protoListener) {

	ctx, cancelFunc := context.WithCancel(ctx)

	conns := make([]chan net.Conn, len(classifiers))
	for i := range classifiers {
		conns[i] = make(chan net.Conn)
	}

	p := protocolDemux{
		ctx:                       ctx,
		cancelFunc:                cancelFunc,
		innerListener:             listener,
		conns:                     conns,
		classifiers:               classifiers,
		connClassificationTimeout: connClassificationTimeout,
	}

	protoListeners := make([]protoListener, len(classifiers))
	for i := range classifiers {
		protoListeners[i] = protoListener{
			index: i,
			mux:   &p,
		}
	}

	return &p, protoListeners
}

// run runs the protocol demultiplexer; this function blocks while the
// ProtocolDemux accepts new conns and routes them to the corresponding
// protocol listener returned from NewProtocolDemux.
//
// To stop the protocol demultiplexer and cleanup underlying resources
// call Close().
func (mux *protocolDemux) run() error {

	maxBytesToMatch := 0
	for _, classifer := range mux.classifiers {
		if classifer.maxBytesToMatch == 0 {
			maxBytesToMatch = 0
			break
		} else if classifer.maxBytesToMatch > maxBytesToMatch {
			maxBytesToMatch = classifer.maxBytesToMatch
		}
	}

	// Set read buffer to max amount of bytes needed to classify each
	// Conn if finite.
	readBufferSize := 512 // default size
	if maxBytesToMatch > 0 {
		readBufferSize = maxBytesToMatch
	}

	for mux.ctx.Err() == nil {

		// Accept new conn and spawn a goroutine where it is read until
		// either:
		// - It matches one of the configured protocols and is sent downstream
		//   to the corresponding protocol listener
		// - It does not match any of the configured protocols, an error
		//   occurs, or mux.connClassificationTimeout elapses before the conn
		//   is classified and the conn is closed
		// New conns are accepted, and classified, continuously even if the
		// downstream consumers are not ready to process them, which could
		// result in spawning many goroutines that become blocked until the
		// downstream consumers manage to catch up. Although, this scenario
		// should be unlikely because the producer - accepting new conns - is
		// bounded by network I/O and the consumer is not. Generally, the
		// consumer continuously loops accepting new conns, from its
		// corresponding protocol listener, and immediately spawns a goroutine
		// to handle each new conn after it is accepted.

		conn, err := mux.innerListener.Accept()
		if err != nil {
			if mux.ctx.Err() == nil {
				log.WithTraceFields(LogFields{"error": err}).Debug("accept failed")
			}
			continue
		}

		go func() {

			type classifiedConnResult struct {
				index       int
				acc         bytes.Buffer
				err         error
				errLogLevel logrus.Level
			}

			resultChannel := make(chan *classifiedConnResult, 2)

			var connClassifiedAfterFunc *time.Timer

			if mux.connClassificationTimeout > 0 {
				connClassifiedAfterFunc = time.AfterFunc(mux.connClassificationTimeout, func() {
					resultChannel <- &classifiedConnResult{
						err:         std_errors.New("conn classification timeout"),
						errLogLevel: logrus.DebugLevel,
					}
				})
			}

			go func() {
				var acc bytes.Buffer
				b := make([]byte, readBufferSize)

				for mux.ctx.Err() == nil {

					n, err := conn.Read(b)
					if err != nil {
						resultChannel <- &classifiedConnResult{
							err:         errors.TraceMsg(err, "read conn failed"),
							errLogLevel: logrus.DebugLevel,
						}
						return
					}

					acc.Write(b[:n])

					for i, classifier := range mux.classifiers {
						if acc.Len() >= classifier.minBytesToMatch && classifier.match(acc.Bytes()) {
							resultChannel <- &classifiedConnResult{
								index: i,
								acc:   acc,
							}
							return
						}
					}

					if maxBytesToMatch != 0 && acc.Len() > maxBytesToMatch {
						// No match. Sample does not match any classifier and is
						// longer than required by each.
						resultChannel <- &classifiedConnResult{
							err:         std_errors.New("no classifier match for conn"),
							errLogLevel: logrus.WarnLevel,
						}
						return
					}
				}

				resultChannel <- &classifiedConnResult{
					err:         mux.ctx.Err(),
					errLogLevel: logrus.DebugLevel,
				}
			}()

			result := <-resultChannel

			if connClassifiedAfterFunc != nil {
				connClassifiedAfterFunc.Stop()
			}

			if result.err != nil {
				log.WithTraceFields(LogFields{"error": result.err}).Log(result.errLogLevel, "conn classification failed")

				err := conn.Close()
				if err != nil {
					log.WithTraceFields(LogFields{"error": err}).Debug("close failed")
				}
				return
			}

			// Found a match, replay buffered bytes in new conn and send
			// downstream.
			// TODO: subtract the time it took to classify the conn from the
			// subsequent SSH handshake timeout (sshHandshakeTimeout).
			bConn := newBufferedConn(conn, result.acc)
			select {
			case mux.conns[result.index] <- bConn:
			case <-mux.ctx.Done():
				bConn.Close()
			}
		}()
	}

	return mux.ctx.Err()
}

func (mux *protocolDemux) acceptForIndex(index int) (net.Conn, error) {

	// First check pool of accepted and classified conns.

	for mux.ctx.Err() == nil {
		select {
		case conn := <-mux.conns[index]:
			return conn, nil
		case <-mux.ctx.Done():
			return nil, errors.Trace(mux.ctx.Err())
		}
	}

	return nil, mux.ctx.Err()
}

func (mux *protocolDemux) Close() error {

	mux.cancelFunc()

	err := mux.innerListener.Close()
	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

type protoListener struct {
	index int
	mux   *protocolDemux
}

func (p protoListener) Accept() (net.Conn, error) {
	return p.mux.acceptForIndex(p.index)
}

func (p protoListener) Close() error {
	// Do nothing. Listeners must be shutdown with ProtocolDemux.Close.
	return nil
}

func (p protoListener) Addr() net.Addr {
	return p.mux.innerListener.Addr()
}

type bufferedConn struct {
	buffer *bytes.Buffer
	net.Conn
}

func newBufferedConn(conn net.Conn, buffer bytes.Buffer) *bufferedConn {
	return &bufferedConn{
		Conn:   conn,
		buffer: &buffer,
	}
}

func (conn *bufferedConn) Read(b []byte) (n int, err error) {

	if conn.buffer != nil && conn.buffer.Len() > 0 {
		n := copy(b, conn.buffer.Bytes())
		conn.buffer.Next(n)

		return n, err
	}

	// Allow memory to be reclaimed by gc now because Conn may be long
	// lived and otherwise this memory would be held for its duration.
	conn.buffer = nil

	return conn.Conn.Read(b)
}

// GetMetrics implements the common.MetricsSource interface.
func (conn *bufferedConn) GetMetrics() common.LogFields {
	// Relay any metrics from the underlying conn.
	m, ok := conn.Conn.(common.MetricsSource)
	if ok {
		return m.GetMetrics()
	}
	return nil
}
