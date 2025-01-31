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

package server

import (
	"bytes"
	"io"
	"net"
	"testing"

	"github.com/Jigsaw-Code/outline-sdk/transport"
	"github.com/Jigsaw-Code/outline-sdk/transport/shadowsocks"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
)

func TestShadowsocksServer(t *testing.T) {

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen failed %v", err)
	}
	defer listener.Close()

	numIrregularTunnels := 0

	irregularTunnelLogger := func(clientIP string, tunnelError error, logFields common.LogFields) {
		numIrregularTunnels++
	}

	secretText := "TEST"

	listener, err = ListenShadowsocks(nil, listener, secretText, irregularTunnelLogger)
	if err != nil {
		t.Fatalf("ListenShadowsocks failed %v", err)
	}

	type listenerState struct {
		err  error
		recv []byte
	}

	wantRecv := []byte("hello world")

	runListener := func(listener net.Listener, recv chan *listenerState) {
		conn, err := listener.Accept()
		if err != nil {
			recv <- &listenerState{
				err: errors.TraceMsg(err, "listener.Accept failed"),
			}
			return
		}

		defer conn.Close()

		b := make([]byte, len(wantRecv))

		// A single Read should be sufficient because multiple requests
		// in a single connection are not supported by this test.
		n, err := conn.Read(b)
		if err != nil {
			recv <- &listenerState{
				err: errors.TraceMsg(err, "conn.Read failed"),
			}
			return
		}
		b = b[:n]

		_, err = conn.Write(b)
		if err != nil {
			recv <- &listenerState{
				err: errors.TraceMsg(err, "conn.Write failed"),
			}
			return
		}

		recv <- &listenerState{
			recv: b,
			err:  nil,
		}
	}

	recv := make(chan *listenerState)

	go runListener(listener, recv)

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("net.Dial failed %v", err)
	}
	defer conn.Close()

	key, err := shadowsocks.NewEncryptionKey(shadowsocks.CHACHA20IETFPOLY1305, secretText)
	if err != nil {
		t.Fatalf("shadowsocks.NewEncryptionKey failed %v", err)
	}

	// Based on shadowsocks.DialStream
	clientToServerRecorder := NewWriteRecorder(conn)
	ssw := shadowsocks.NewWriter(clientToServerRecorder, key)
	serverToClientRecorder := NewReadRecorder(conn)
	ssr := shadowsocks.NewReader(serverToClientRecorder, key)
	conn = transport.WrapConn(conn.(*net.TCPConn), ssr, ssw)

	n, err := conn.Write(wantRecv)
	if err != nil {
		t.Fatalf("conn.Write failed %v", err)
	}
	if n != len(wantRecv) {
		t.Fatalf("expected to write %d bytes but wrote %d", len(wantRecv), n)
	}

	// read response

	b := make([]byte, 512)
	n, err = conn.Read(b)
	if err != nil {
		t.Fatalf("conn.Read failed %v", err)
	}
	b = b[:n]

	r := <-recv

	if r.err != nil {
		t.Fatalf("listener failed %v", r.err)
	}

	if !bytes.Equal(r.recv, wantRecv) {
		t.Fatalf("expected \"%s\" of len %d but got \"%s\" of len %d", string(wantRecv), len(wantRecv), string(r.recv), len(r.recv))
	}

	// Server echos bytes back
	if !bytes.Equal(b, wantRecv) {
		t.Fatalf("expected \"%s\" of len %d but got \"%s\" of len %d", string(wantRecv), len(wantRecv), string(b), len(b))
	}

	if numIrregularTunnels > 0 {
		t.Fatal("expected no irregular tunnels")
	}

	// Mimic a replay attack

	go runListener(listener, recv)

	conn, err = net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("net.Dial failed %v", err)
	}
	defer conn.Close()

	_, err = conn.Write(clientToServerRecorder.Bytes())
	if err != nil {
		t.Fatalf("conn.Read failed %v", err)
	}

	r = <-recv

	if r.err == nil {
		t.Fatalf("expected error")
	}

	if numIrregularTunnels != 1 {
		t.Fatal("expected 1 irregular tunnel")
	}

	// Mimic a reflection attack

	go runListener(listener, recv)

	conn, err = net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("net.Dial failed %v", err)
	}
	defer conn.Close()

	_, err = conn.Write(serverToClientRecorder.Bytes())
	if err != nil {
		t.Fatalf("conn.Read failed %v", err)
	}

	r = <-recv

	if r.err == nil {
		t.Fatalf("expected error")
	}

	if numIrregularTunnels != 2 {
		t.Fatal("expected 2 irregular tunnels")
	}
}

type writeRecorder struct {
	io.Writer
	bytes.Buffer
}

func NewWriteRecorder(writer io.Writer) *writeRecorder {
	return &writeRecorder{
		Writer: writer,
	}
}

func (w *writeRecorder) Write(p []byte) (n int, err error) {
	_, err = w.Buffer.Write(p)
	if err != nil {
		panic(err)
	}

	return w.Writer.Write(p)
}

type readRecorder struct {
	io.Reader
	bytes.Buffer
}

func NewReadRecorder(reader io.Reader) *readRecorder {
	return &readRecorder{
		Reader: reader,
	}
}

func (r *readRecorder) Read(p []byte) (n int, err error) {
	n, err = r.Reader.Read(p)
	r.Buffer.Write(p[:n])
	return n, err
}
