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

package psiphon

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
)

const (
	MAX_FRAGMENTOR_NOTICES               = 3
	MAX_FRAGMENTOR_ITERATIONS_PER_NOTICE = 5
)

// NewTCPFragmentorDialer creates a TCP dialer that wraps dialed conns in
// FragmentorConn. A single FragmentorProbability coin flip is made and all
// conns get the same treatment.
func NewTCPFragmentorDialer(
	config *DialConfig,
	tunnelProtocol string,
	clientParameters *parameters.ClientParameters) Dialer {

	p := clientParameters.Get()
	coinFlip := p.WeightedCoinFlip(parameters.FragmentorProbability)
	p = nil

	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if network != "tcp" {
			return nil, common.ContextError(fmt.Errorf("%s unsupported", network))
		}
		return DialTCPFragmentor(ctx, addr, config, tunnelProtocol, clientParameters, &coinFlip)
	}
}

// DialTCPFragmentor performs a DialTCP and wraps the dialed conn in a
// FragmentorConn, subject to FragmentorProbability and FragmentorLimitProtocols.
func DialTCPFragmentor(
	ctx context.Context,
	addr string,
	config *DialConfig,
	tunnelProtocol string,
	clientParameters *parameters.ClientParameters,
	coinFlip *bool) (net.Conn, error) {

	conn, err := DialTCP(ctx, addr, config)
	if err != nil {
		return nil, common.ContextError(err)
	}

	p := clientParameters.Get()

	protocols := p.TunnelProtocols(parameters.FragmentorLimitProtocols)
	if len(protocols) > 0 && !common.Contains(protocols, tunnelProtocol) {
		return conn, nil
	}

	if !p.WeightedCoinFlip(parameters.FragmentorProbability) {
		return conn, nil
	}

	totalBytes, err := common.MakeSecureRandomRange(
		p.Int(parameters.FragmentorMinTotalBytes),
		p.Int(parameters.FragmentorMaxTotalBytes))
	if err != nil {
		totalBytes = 0
		NoticeAlert("MakeSecureRandomRange failed: %s", common.ContextError(err))
	}

	if totalBytes == 0 {
		return conn, nil
	}

	runCtx, stopRunning := context.WithCancel(context.Background())

	return &FragmentorConn{
		Conn:            conn,
		runCtx:          runCtx,
		stopRunning:     stopRunning,
		bytesToFragment: totalBytes,
		minWriteBytes:   p.Int(parameters.FragmentorMinWriteBytes),
		maxWriteBytes:   p.Int(parameters.FragmentorMaxWriteBytes),
		minDelay:        p.Duration(parameters.FragmentorMinDelay),
		maxDelay:        p.Duration(parameters.FragmentorMaxDelay),
	}, nil
}

// FragmentorConn implements simple fragmentation of application-level
// messages/packets into multiple TCP packets by splitting writes into smaller
// sizes and adding delays between writes.
//
// The intent of FragmentorConn is both to frustrate firewalls that perform
// DPI on application-level messages that cross TCP packets as well as to
// perform a simple size and timing transformation to the traffic shape of the
// initial portion of a TCP flow.
type FragmentorConn struct {
	net.Conn
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

func (fragmentor *FragmentorConn) Write(buffer []byte) (int, error) {

	fragmentor.writeMutex.Lock()
	defer fragmentor.writeMutex.Unlock()

	if fragmentor.bytesFragmented >= fragmentor.bytesToFragment {
		return fragmentor.Conn.Write(buffer)
	}

	totalBytesWritten := 0

	emitNotice := fragmentor.numNotices < MAX_FRAGMENTOR_NOTICES

	// TODO: use strings.Builder in Go 1.10
	var notice bytes.Buffer

	if emitNotice {
		remoteAddrStr := "(nil)"
		remoteAddr := fragmentor.Conn.RemoteAddr()
		if remoteAddr != nil {
			remoteAddrStr = remoteAddr.String()
		}
		fmt.Fprintf(&notice,
			"fragment %s %d bytes:",
			remoteAddrStr, len(buffer))
	}

	for iterations := 0; len(buffer) > 0; iterations += 1 {

		delay, err := common.MakeSecureRandomPeriod(
			fragmentor.minDelay, fragmentor.maxDelay)
		if err != nil {
			delay = fragmentor.minDelay
		}

		timer := time.NewTimer(delay)
		err = nil
		select {
		case <-fragmentor.runCtx.Done():
			err = fragmentor.runCtx.Err()
		case <-timer.C:
		}
		timer.Stop()

		if err != nil {
			return totalBytesWritten, err
		}

		minWriteBytes := fragmentor.minWriteBytes
		if minWriteBytes > len(buffer) {
			minWriteBytes = len(buffer)
		}

		maxWriteBytes := fragmentor.maxWriteBytes
		if maxWriteBytes > len(buffer) {
			maxWriteBytes = len(buffer)
		}

		writeBytes, err := common.MakeSecureRandomRange(
			minWriteBytes, maxWriteBytes)
		if err != nil {
			writeBytes = maxWriteBytes
		}

		bytesWritten, err := fragmentor.Conn.Write(buffer[:writeBytes])

		totalBytesWritten += bytesWritten
		fragmentor.bytesFragmented += bytesWritten

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
		NoticeInfo(notice.String())
		fragmentor.numNotices += 1
	}

	return totalBytesWritten, nil
}

func (fragmentor *FragmentorConn) Close() (err error) {
	if !atomic.CompareAndSwapInt32(&fragmentor.isClosed, 0, 1) {
		return nil
	}
	fragmentor.stopRunning()
	return fragmentor.Conn.Close()
}

func (fragmentor *FragmentorConn) IsClosed() bool {
	return atomic.LoadInt32(&fragmentor.isClosed) == 1
}
