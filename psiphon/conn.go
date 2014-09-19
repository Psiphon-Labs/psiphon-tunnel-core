/*
 * Copyright (c) 2014, Psiphon Inc.
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

package psiphon

import (
	"errors"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
)

// Conn is a customized network connection that:
// - can be interrupted while connecting;
// - turns on TCP keep alive;
// - implements idle read/write timeouts;
// - supports sending a signal to a channel when it disconnects;
// - can be bound to a specific system device (for Android VpnService
//   routing compatibility, for example).
type Conn struct {
	net.Conn
	mutex        sync.Mutex
	socketFd     int
	isClosed     bool
	closedSignal chan bool
	readTimeout  time.Duration
	writeTimeout time.Duration
}

// NewConn creates a new, connected Conn. The connection can be interrupted
// using pendingConns.interrupt(): the new Conn is added to pendingConns
// before the socket connect beings. The caller is responsible for removing the
// returned Conn from pendingConns.
// To implement device binding and interruptible connecting, the lower-level
// syscall APIs are used. The sequence of syscalls in this implementation are
// taken from: https://code.google.com/p/go/issues/detail?id=6966
func Dial(
	ipAddress string, port int,
	readTimeout, writeTimeout time.Duration,
	pendingConns *PendingConns) (conn *Conn, err error) {

	socketFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, err
	}
	err = syscall.SetsockoptInt(socketFd, syscall.IPPROTO_TCP, syscall.TCP_KEEPALIVE, TCP_KEEP_ALIVE_PERIOD_SECONDS)
	if err != nil {
		syscall.Close(socketFd)
		return nil, err
	}
	/*
		// TODO: requires root, which we won't have on Android in VpnService mode
		//       an alternative may be to use http://golang.org/pkg/syscall/#UnixRights to
		//       send the fd to the main Android process which receives the fd with
		//       http://developer.android.com/reference/android/net/LocalSocket.html#getAncillaryFileDescriptors%28%29
		//       and then calls
		//       http://developer.android.com/reference/android/net/VpnService.html#protect%28int%29.
		//       See, for example:
		//       https://code.google.com/p/ics-openvpn/source/browse/main/src/main/java/de/blinkt/openvpn/core/OpenVpnManagementThread.java#164
		const SO_BINDTODEVICE = 0x19 // only defined for Linux
		err = syscall.SetsockoptString(socketFd, syscall.SOL_SOCKET, SO_BINDTODEVICE, deviceName)
	*/
	conn = &Conn{
		socketFd:     socketFd,
		readTimeout:  readTimeout,
		writeTimeout: writeTimeout}
	pendingConns.Add(conn)
	// TODO: domain name resolution (for meek)
	var addr [4]byte
	copy(addr[:], net.ParseIP(ipAddress).To4())
	sockAddr := syscall.SockaddrInet4{Addr: addr, Port: port}
	err = syscall.Connect(conn.socketFd, &sockAddr)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(conn.socketFd), "")
	defer file.Close()
	conn.Conn, err = net.FileConn(file)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// SetClosedSignal sets the channel which will be signaled
// when the connection is closed. This function returns an error
// if the connection is already closed (and would never send
// the signal).
func (conn *Conn) SetClosedSignal(closedSignal chan bool) (err error) {
	// TEMP **** needs comments
	conn.mutex.Lock()
	defer conn.mutex.Unlock()
	if conn.isClosed {
		return errors.New("connection is already closed")
	}
	conn.closedSignal = closedSignal
	return nil
}

// Close terminates a connected (net.Conn) or connecting (socketFd) Conn.
// A mutex syncs access to conn struct, allowing Close() to be called
// from a goroutine that wants to interrupt the primary goroutine using
// the connection.
func (conn *Conn) Close() (err error) {
	var closedSignal chan bool
	conn.mutex.Lock()
	if !conn.isClosed {
		if conn.Conn == nil {
			err = syscall.Close(conn.socketFd)
		} else {
			err = conn.Conn.Close()
		}
		closedSignal = conn.closedSignal
		conn.isClosed = true
	}
	conn.mutex.Unlock()
	if closedSignal != nil {
		select {
		case closedSignal <- true:
		default:
		}
	}
	return err
}

// Read wraps standard Read to add an idle timeout. The connection
// is explicitly closed on timeout.
func (conn *Conn) Read(buffer []byte) (n int, err error) {
	// Note: no mutex on the conn.readTimeout access
	if conn.readTimeout != 0 {
		err = conn.Conn.SetReadDeadline(time.Now().Add(conn.readTimeout))
		if err != nil {
			return 0, err
		}
	}
	n, err = conn.Conn.Read(buffer)
	if err != nil {
		conn.Close()
	}
	return
}

// Write wraps standard Write to add an idle timeout The connection
// is explicitly closed on timeout.
func (conn *Conn) Write(buffer []byte) (n int, err error) {
	// Note: no mutex on the conn.writeTimeout access
	if conn.writeTimeout != 0 {
		err = conn.Conn.SetWriteDeadline(time.Now().Add(conn.writeTimeout))
		if err != nil {
			return 0, err
		}
	}
	n, err = conn.Conn.Write(buffer)
	if err != nil {
		conn.Close()
	}
	return
}

// PendingConns is a synchronized list of Conns that's used to coordinate
// interrupting a set of goroutines establishing connections.
type PendingConns struct {
	mutex sync.Mutex
	conns []*Conn
}

func (pendingConns *PendingConns) Add(conn *Conn) {
	pendingConns.mutex.Lock()
	defer pendingConns.mutex.Unlock()
	pendingConns.conns = append(pendingConns.conns, conn)
}

func (pendingConns *PendingConns) Remove(conn *Conn) {
	pendingConns.mutex.Lock()
	defer pendingConns.mutex.Unlock()
	for index, pendingConn := range pendingConns.conns {
		if conn == pendingConn {
			pendingConns.conns = append(pendingConns.conns[:index], pendingConns.conns[index+1:]...)
			break
		}
	}
}

func (pendingConns *PendingConns) Interrupt() {
	pendingConns.mutex.Lock()
	defer pendingConns.mutex.Unlock()
	for _, conn := range pendingConns.conns {
		conn.Close()
	}
}
