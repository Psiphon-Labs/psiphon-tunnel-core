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
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
)

const (
	MAX_FRAGMENTOR_NOTICES               = 3
	MAX_FRAGMENTOR_ITERATIONS_PER_NOTICE = 5
)

// Config specifies a fragmentor configuration. NewUpstreamConfig and
// NewDownstreamConfig will generate configurations based on the given
// client parameters.
type Config struct {
	isUpstream      bool
	bytesToFragment int
	minWriteBytes   int
	maxWriteBytes   int
	minDelay        time.Duration
	maxDelay        time.Duration
}

// NewUpstreamConfig creates a new Config; may return nil.
func NewUpstreamConfig(
	p *parameters.ClientParametersSnapshot, tunnelProtocol string) *Config {
	return newConfig(p, true, tunnelProtocol)
}

// NewDownstreamConfig creates a new Config; may return nil.
func NewDownstreamConfig(
	p *parameters.ClientParametersSnapshot, tunnelProtocol string) *Config {
	return newConfig(p, false, tunnelProtocol)
}

func newConfig(
	p *parameters.ClientParametersSnapshot,
	isUpstream bool,
	tunnelProtocol string) *Config {

	coinFlip := p.WeightedCoinFlip(parameters.FragmentorDownstreamProbability)
	tunnelProtocols := p.TunnelProtocols(parameters.FragmentorDownstreamLimitProtocols)

	if !coinFlip || (len(tunnelProtocols) > 0 && common.Contains(tunnelProtocols, tunnelProtocol)) {
		return nil
	}

	bytesToFragment, err := common.MakeSecureRandomRange(
		p.Int(parameters.FragmentorDownstreamMinTotalBytes),
		p.Int(parameters.FragmentorDownstreamMaxTotalBytes))
	if err != nil {
		bytesToFragment = 0
	}

	if bytesToFragment == 0 {
		return nil
	}

	return &Config{
		isUpstream:      isUpstream,
		bytesToFragment: bytesToFragment,
		minWriteBytes:   p.Int(parameters.FragmentorDownstreamMinWriteBytes),
		maxWriteBytes:   p.Int(parameters.FragmentorDownstreamMaxWriteBytes),
		minDelay:        p.Duration(parameters.FragmentorDownstreamMinDelay),
		maxDelay:        p.Duration(parameters.FragmentorDownstreamMaxDelay),
	}
}

// IsFragmenting indicates whether the fragmentor configuration results in any
// fragmentation; config may be nil.
func (config *Config) IsFragmenting() bool {
	return config != nil && config.bytesToFragment > 0
}

// GetMetrics returns the fragmentor configuration as log fields; config may
// be nil.
func (config *Config) GetMetrics() common.LogFields {
	logFields := make(common.LogFields)
	if config != nil {
		var prefix string
		if config.isUpstream {
			prefix = "upstream_"
		} else {
			prefix = "downstream_"
		}
		logFields[prefix+"bytes_to_fragment"] = config.bytesToFragment
		logFields[prefix+"min_write_bytes"] = config.minWriteBytes
		logFields[prefix+"max_write_bytes"] = config.maxWriteBytes
		logFields[prefix+"min_delay"] = int(config.minDelay / time.Microsecond)
		logFields[prefix+"max_delay"] = int(config.maxDelay / time.Microsecond)
	}
	return logFields
}

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
	config          *Config
	noticeEmitter   func(string)
	runCtx          context.Context
	stopRunning     context.CancelFunc
	isClosed        int32
	writeMutex      sync.Mutex
	numNotices      int
	bytesFragmented int
}

// NewConn creates a new Conn.
func NewConn(
	config *Config,
	noticeEmitter func(string),
	conn net.Conn) *Conn {

	runCtx, stopRunning := context.WithCancel(context.Background())
	return &Conn{
		Conn:          conn,
		config:        config,
		noticeEmitter: noticeEmitter,
		runCtx:        runCtx,
		stopRunning:   stopRunning,
	}
}

// GetMetrics implements the common.MetricsSource interface.
func (c *Conn) GetMetrics() common.LogFields {
	return c.config.GetMetrics()
}

func (c *Conn) Write(buffer []byte) (int, error) {

	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()

	if c.bytesFragmented >= c.config.bytesToFragment {
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
			c.config.minDelay, c.config.maxDelay)
		if err != nil {
			delay = c.config.minDelay
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

		minWriteBytes := c.config.minWriteBytes
		if minWriteBytes > len(buffer) {
			minWriteBytes = len(buffer)
		}

		maxWriteBytes := c.config.maxWriteBytes
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
