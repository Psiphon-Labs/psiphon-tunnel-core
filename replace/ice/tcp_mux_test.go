// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ice

import (
	"io"
	"net"
	"testing"

	"github.com/pion/logging"
	"github.com/pion/stun"
	"github.com/pion/transport/v2/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var _ TCPMux = &TCPMuxDefault{}

func TestTCPMux_Recv(t *testing.T) {
	for name, bufSize := range map[string]int{
		"no buffer":    0,
		"buffered 4MB": 4 * 1024 * 1024,
	} {
		bufSize := bufSize
		t.Run(name, func(t *testing.T) {
			report := test.CheckRoutines(t)
			defer report()

			loggerFactory := logging.NewDefaultLoggerFactory()

			listener, err := net.ListenTCP("tcp", &net.TCPAddr{
				IP:   net.IP{127, 0, 0, 1},
				Port: 0,
			})
			require.NoError(t, err, "error starting listener")
			defer func() {
				_ = listener.Close()
			}()

			tcpMux := NewTCPMuxDefault(TCPMuxParams{
				Listener:        listener,
				Logger:          loggerFactory.NewLogger("ice"),
				ReadBufferSize:  20,
				WriteBufferSize: bufSize,
			})

			defer func() {
				_ = tcpMux.Close()
			}()

			require.NotNil(t, tcpMux.LocalAddr(), "tcpMux.LocalAddr() is nil")

			conn, err := net.DialTCP("tcp", nil, tcpMux.LocalAddr().(*net.TCPAddr))
			require.NoError(t, err, "error dialing test TCP connection")

			msg := stun.New()
			msg.Type = stun.MessageType{Method: stun.MethodBinding, Class: stun.ClassRequest}
			msg.Add(stun.AttrUsername, []byte("myufrag:otherufrag"))
			msg.Encode()

			n, err := writeStreamingPacket(conn, msg.Raw)
			require.NoError(t, err, "error writing TCP STUN packet")

			pktConn, err := tcpMux.GetConnByUfrag("myufrag", false, listener.Addr().(*net.TCPAddr).IP)
			require.NoError(t, err, "error retrieving muxed connection for ufrag")
			defer func() {
				_ = pktConn.Close()
			}()

			recv := make([]byte, n)
			n2, rAddr, err := pktConn.ReadFrom(recv)
			require.NoError(t, err, "error receiving data")
			assert.Equal(t, conn.LocalAddr(), rAddr, "remote tcp address mismatch")
			assert.Equal(t, n, n2, "received byte size mismatch")
			assert.Equal(t, msg.Raw, recv, "received bytes mismatch")

			// Check echo response
			n, err = pktConn.WriteTo(recv, conn.LocalAddr())
			require.NoError(t, err, "error writing echo STUN packet")
			recvEcho := make([]byte, n)
			n3, err := readStreamingPacket(conn, recvEcho)
			require.NoError(t, err, "error receiving echo data")
			assert.Equal(t, n2, n3, "received byte size mismatch")
			assert.Equal(t, msg.Raw, recvEcho, "received bytes mismatch")
		})
	}
}

func TestTCPMux_NoDeadlockWhenClosingUnusedPacketConn(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()

	loggerFactory := logging.NewDefaultLoggerFactory()

	listener, err := net.ListenTCP("tcp", &net.TCPAddr{
		IP:   net.IP{127, 0, 0, 1},
		Port: 0,
	})
	require.NoError(t, err, "error starting listener")
	defer func() {
		_ = listener.Close()
	}()

	tcpMux := NewTCPMuxDefault(TCPMuxParams{
		Listener:       listener,
		Logger:         loggerFactory.NewLogger("ice"),
		ReadBufferSize: 20,
	})

	_, err = tcpMux.GetConnByUfrag("test", false, listener.Addr().(*net.TCPAddr).IP)
	require.NoError(t, err, "error getting conn by ufrag")

	require.NoError(t, tcpMux.Close(), "error closing tcpMux")

	conn, err := tcpMux.GetConnByUfrag("test", false, listener.Addr().(*net.TCPAddr).IP)
	assert.Nil(t, conn, "should receive nil because mux is closed")
	assert.Equal(t, io.ErrClosedPipe, err, "should receive error because mux is closed")
}
