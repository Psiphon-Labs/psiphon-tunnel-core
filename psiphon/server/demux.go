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
	"net"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
)

// protocolDemux enables a single listener to support multiple protocols
// by demultiplexing each conn it accepts into the corresponding protocol
// handler.
type protocolDemux struct {
	ctx           context.Context
	cancelFunc    context.CancelFunc
	innerListener net.Listener
	classifiers   []protocolClassifier
	accept        chan struct{}

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
// array of returned protocol listeners.
func newProtocolDemux(ctx context.Context, listener net.Listener, classifiers []protocolClassifier) (*protocolDemux, []protoListener) {

	ctx, cancelFunc := context.WithCancel(ctx)

	conns := make([]chan net.Conn, len(classifiers))
	for i := range classifiers {
		conns[i] = make(chan net.Conn)
	}

	p := protocolDemux{
		ctx:           ctx,
		cancelFunc:    cancelFunc,
		innerListener: listener,
		conns:         conns,
		classifiers:   classifiers,
		accept:        make(chan struct{}, 1),
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

		// Accept first conn immediately and then wait for downstream listeners
		// to request new conns.

		conn, err := mux.innerListener.Accept()
		if err != nil {
			if mux.ctx.Err() == nil {
				log.WithTraceFields(LogFields{"error": err}).Debug("accept failed")
				// TODO: add backoff before continue?
			}
			continue
		}

		go func() {

			var acc bytes.Buffer
			b := make([]byte, readBufferSize)

			for mux.ctx.Err() == nil {

				n, err := conn.Read(b)
				if err != nil {
					log.WithTraceFields(LogFields{"error": err}).Debug("read conn failed")
					break // conn will be closed
				}

				acc.Write(b[:n])

				for i, detector := range mux.classifiers {

					if acc.Len() >= detector.minBytesToMatch {

						if detector.match(acc.Bytes()) {

							// Found a match, replay buffered bytes in new conn
							// and downstream.
							go func() {
								bConn := newBufferedConn(conn, acc)
								select {
								case mux.conns[i] <- bConn:
								case <-mux.ctx.Done():
									bConn.Close()
								}
							}()

							return
						}
					}
				}

				if maxBytesToMatch != 0 && acc.Len() > maxBytesToMatch {

					// No match. Sample does not match any detector and is
					// longer than required by each.
					log.WithTrace().Warning("no detector match for conn")

					break // conn will be closed
				}
			}

			// cleanup conn
			err := conn.Close()
			if err != nil {
				log.WithTraceFields(LogFields{"error": err}).Debug("close conn failed")
			}
		}()

		// Wait for one of the downstream listeners to request another conn.
		select {
		case <-mux.accept:
		case <-mux.ctx.Done():
			return mux.ctx.Err()
		}
	}

	return mux.ctx.Err()
}

func (mux *protocolDemux) acceptForIndex(index int) (net.Conn, error) {

	// First check pool of accepted and classified conns.

	for mux.ctx.Err() == nil {
		select {
		case conn := <-mux.conns[index]:
			// trigger another accept
			select {
			case mux.accept <- struct{}{}:
			default: // don't block when a signal is already buffered
			}
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
