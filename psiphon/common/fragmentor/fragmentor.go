/*
 * Copyright (c) 2018, Psiphon Inc.
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

package fragmentor

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
)

const (
	MAX_FRAGMENTOR_NOTICES               = 3
	MAX_FRAGMENTOR_ITERATIONS_PER_NOTICE = 5
)

// Conn implements simple fragmentation of application-level messages/packets
// into multiple TCP packets by splitting writes into smaller sizes and adding
// delays between writes.
//
// The intent of Conn is both to frustrate firewalls that perform DPI on
// application-level messages that cross TCP packets as well as to perform a
// simple size and timing transformation to the traffic shape of the initial
// portion of a TCP flow.
type Conn struct {
	net.Conn
	noticeEmitter   func(string)
	runCtx          context.Context
	stopRunning     context.CancelFunc
	isClosed        int32
	writeMutex      sync.Mutex
	numNotices      int
	bytesToFragment int
	bytesFragmented int
	minWriteBytes   int
	maxWriteBytes   int
	minDelay        time.Duration
	maxDelay        time.Duration
}

// NewConn creates a new Conn.
func NewConn(
	conn net.Conn,
	noticeEmitter func(string),
	bytesToFragment, minWriteBytes, maxWriteBytes int,
	minDelay, maxDelay time.Duration) *Conn {

	runCtx, stopRunning := context.WithCancel(context.Background())
	return &Conn{
		Conn:            conn,
		noticeEmitter:   noticeEmitter,
		runCtx:          runCtx,
		stopRunning:     stopRunning,
		bytesToFragment: bytesToFragment,
		minWriteBytes:   minWriteBytes,
		maxWriteBytes:   maxWriteBytes,
		minDelay:        minDelay,
		maxDelay:        maxDelay,
	}
}

func (c *Conn) Write(buffer []byte) (int, error) {

	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()

	if c.bytesFragmented >= c.bytesToFragment {
		return c.Conn.Write(buffer)
	}

	totalBytesWritten := 0

	emitNotice := c.noticeEmitter != nil &&
		c.numNotices < MAX_FRAGMENTOR_NOTICES

	// TODO: use strings.Builder in Go 1.10
	var notice bytes.Buffer

	if emitNotice {
		remoteAddrStr := "(nil)"
		remoteAddr := c.Conn.RemoteAddr()
		if remoteAddr != nil {
			remoteAddrStr = remoteAddr.String()
		}
		fmt.Fprintf(&notice,
			"fragment %s %d bytes:",
			remoteAddrStr, len(buffer))
	}

	for iterations := 0; len(buffer) > 0; iterations += 1 {

		delay, err := common.MakeSecureRandomPeriod(
			c.minDelay, c.maxDelay)
		if err != nil {
			delay = c.minDelay
		}

		timer := time.NewTimer(delay)
		err = nil
		select {
		case <-c.runCtx.Done():
			err = c.runCtx.Err()
		case <-timer.C:
		}
		timer.Stop()

		if err != nil {
			return totalBytesWritten, err
		}

		minWriteBytes := c.minWriteBytes
		if minWriteBytes > len(buffer) {
			minWriteBytes = len(buffer)
		}

		maxWriteBytes := c.maxWriteBytes
		if maxWriteBytes > len(buffer) {
			maxWriteBytes = len(buffer)
		}

		writeBytes, err := common.MakeSecureRandomRange(
			minWriteBytes, maxWriteBytes)
		if err != nil {
			writeBytes = maxWriteBytes
		}

		bytesWritten, err := c.Conn.Write(buffer[:writeBytes])

		totalBytesWritten += bytesWritten
		c.bytesFragmented += bytesWritten

		if err != nil {
			return totalBytesWritten, err
		}

		if emitNotice {
			if iterations < MAX_FRAGMENTOR_ITERATIONS_PER_NOTICE {
				fmt.Fprintf(&notice, " [%s] %d", delay, bytesWritten)
			} else if iterations == MAX_FRAGMENTOR_ITERATIONS_PER_NOTICE {
				fmt.Fprintf(&notice, "...")
			}
		}

		buffer = buffer[writeBytes:]
	}

	if emitNotice {
		c.noticeEmitter(notice.String())
		c.numNotices += 1
	}

	return totalBytesWritten, nil
}

func (c *Conn) Close() (err error) {
	if !atomic.CompareAndSwapInt32(&c.isClosed, 0, 1) {
		return nil
	}
	c.stopRunning()
	return c.Conn.Close()
}

func (c *Conn) IsClosed() bool {
	return atomic.LoadInt32(&c.isClosed) == 1
}
