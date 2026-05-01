// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ice

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/pion/logging"
	"github.com/pion/transport/v4/packetio"
)

type activeTCPConn struct {
	readBuffer, writeBuffer *packetio.Buffer
	localAddr, remoteAddr   atomic.Value
	conn                    atomic.Value // stores net.Conn
	closed                  atomic.Bool
}

func newActiveTCPConn(
	ctx context.Context,
	localAddress string,
	remoteAddress netip.AddrPort,
	log logging.LeveledLogger,
) (a *activeTCPConn) {
	a = &activeTCPConn{
		readBuffer:  packetio.NewBuffer(),
		writeBuffer: packetio.NewBuffer(),
	}

	laddr, err := getTCPAddrOnInterface(localAddress)
	if err != nil {
		a.closed.Store(true)
		log.Infof("Failed to dial TCP address %s: %v", remoteAddress, err)

		return a
	}
	a.localAddr.Store(laddr)

	go func() {
		defer func() {
			a.closed.Store(true)
		}()

		dialer := &net.Dialer{
			LocalAddr: laddr,
		}
		conn, err := dialer.DialContext(ctx, "tcp", remoteAddress.String())
		if err != nil {
			log.Infof("Failed to dial TCP address %s: %v", remoteAddress, err)

			return
		}
		a.conn.Store(conn)
		a.remoteAddr.Store(conn.RemoteAddr())

		go func() {
			buff := make([]byte, receiveMTU)

			for !a.closed.Load() {
				n, err := readStreamingPacket(conn, buff)
				if err != nil {
					log.Infof("Failed to read streaming packet: %s", err)

					break
				}

				if _, err := a.readBuffer.Write(buff[:n]); err != nil {
					log.Infof("Failed to write to buffer: %s", err)

					break
				}
			}
		}()

		buff := make([]byte, receiveMTU)

		for !a.closed.Load() {
			n, err := a.writeBuffer.Read(buff)
			if err != nil {
				log.Infof("Failed to read from buffer: %s", err)

				break
			}

			if _, err = writeStreamingPacket(conn, buff[:n]); err != nil {
				log.Infof("Failed to write streaming packet: %s", err)

				break
			}
		}

		if err := conn.Close(); err != nil {
			log.Infof("Failed to close connection: %s", err)
		}
	}()

	return a
}

func (a *activeTCPConn) ReadFrom(buff []byte) (n int, srcAddr net.Addr, err error) {
	if a.closed.Load() {
		return 0, nil, io.ErrClosedPipe
	}

	n, err = a.readBuffer.Read(buff)
	// RemoteAddr is assuredly set *after* we can read from the buffer
	srcAddr = a.RemoteAddr()

	return
}

func (a *activeTCPConn) WriteTo(buff []byte, _ net.Addr) (n int, err error) {
	if a.closed.Load() {
		return 0, io.ErrClosedPipe
	}

	return a.writeBuffer.Write(buff)
}

func (a *activeTCPConn) Close() error {
	a.closed.Store(true)
	_ = a.readBuffer.Close()
	_ = a.writeBuffer.Close()
	if c, ok := a.conn.Load().(net.Conn); ok {
		_ = c.Close()
	}

	return nil
}

func (a *activeTCPConn) LocalAddr() net.Addr {
	if v, ok := a.localAddr.Load().(*net.TCPAddr); ok {
		return v
	}

	return &net.TCPAddr{}
}

// RemoteAddr returns the remote address of the connection which is only
// set once a background goroutine has successfully dialed. That means
// this may return ":0" for the address prior to that happening. If this
// becomes an issue, we can introduce a synchronization point between Dial
// and these methods.
func (a *activeTCPConn) RemoteAddr() net.Addr {
	if v, ok := a.remoteAddr.Load().(*net.TCPAddr); ok {
		return v
	}

	return &net.TCPAddr{}
}

func (a *activeTCPConn) SetDeadline(t time.Time) error {
	if a.closed.Load() {
		return io.EOF
	}
	if c, ok := a.conn.Load().(net.Conn); ok {
		return c.SetDeadline(t)
	}

	return io.EOF
}

func (a *activeTCPConn) SetReadDeadline(t time.Time) error {
	if a.closed.Load() {
		return io.EOF
	}
	if c, ok := a.conn.Load().(net.Conn); ok {
		return c.SetReadDeadline(t)
	}

	return io.EOF
}

func (a *activeTCPConn) SetWriteDeadline(t time.Time) error {
	if a.closed.Load() {
		return io.EOF
	}
	if c, ok := a.conn.Load().(net.Conn); ok {
		return c.SetWriteDeadline(t)
	}

	return io.EOF
}

func getTCPAddrOnInterface(address string) (*net.TCPAddr, error) {
	addr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		return nil, err
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = l.Close()
	}()

	tcpAddr, ok := l.Addr().(*net.TCPAddr)
	if !ok {
		return nil, errInvalidAddress
	}

	return tcpAddr, nil
}
