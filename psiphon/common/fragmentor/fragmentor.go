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
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
)

const (
	MAX_FRAGMENTOR_NOTICES               = 3
	MAX_FRAGMENTOR_ITERATIONS_PER_NOTICE = 5
)

// Config specifies a fragmentor configuration. NewUpstreamConfig and
// NewDownstreamConfig will generate configurations based on the given
// client parameters.
type Config struct {
	isUpstream    bool
	probability   float64
	minTotalBytes int
	maxTotalBytes int
	minWriteBytes int
	maxWriteBytes int
	minDelay      time.Duration
	maxDelay      time.Duration
	fragmentPRNG  *prng.PRNG
}

// NewUpstreamConfig creates a new Config; may return nil. Specifying the PRNG
// seed allows for optional replay of a fragmentor sequence.
func NewUpstreamConfig(
	p parameters.ClientParametersAccessor, tunnelProtocol string, seed *prng.Seed) *Config {
	return newConfig(p, true, tunnelProtocol, seed)
}

// NewDownstreamConfig creates a new Config; may return nil. Specifying the
// PRNG seed allows for optional replay of a fragmentor sequence.
func NewDownstreamConfig(
	p parameters.ClientParametersAccessor, tunnelProtocol string, seed *prng.Seed) *Config {
	return newConfig(p, false, tunnelProtocol, seed)
}

func newConfig(
	p parameters.ClientParametersAccessor,
	isUpstream bool,
	tunnelProtocol string,
	seed *prng.Seed) *Config {

	if !protocol.TunnelProtocolIsCompatibleWithFragmentor(tunnelProtocol) {
		return nil
	}

	probability := parameters.FragmentorProbability
	limitProtocols := parameters.FragmentorLimitProtocols
	minTotalBytes := parameters.FragmentorMinTotalBytes
	maxTotalBytes := parameters.FragmentorMaxTotalBytes
	minWriteBytes := parameters.FragmentorMinWriteBytes
	maxWriteBytes := parameters.FragmentorMaxWriteBytes
	minDelay := parameters.FragmentorMinDelay
	maxDelay := parameters.FragmentorMaxDelay

	if !isUpstream {
		probability = parameters.FragmentorDownstreamProbability
		limitProtocols = parameters.FragmentorDownstreamLimitProtocols
		minTotalBytes = parameters.FragmentorDownstreamMinTotalBytes
		maxTotalBytes = parameters.FragmentorDownstreamMaxTotalBytes
		minWriteBytes = parameters.FragmentorDownstreamMinWriteBytes
		maxWriteBytes = parameters.FragmentorDownstreamMaxWriteBytes
		minDelay = parameters.FragmentorDownstreamMinDelay
		maxDelay = parameters.FragmentorDownstreamMaxDelay
	}

	tunnelProtocols := p.TunnelProtocols(limitProtocols)

	// When maxTotalBytes is 0 or the protocol is not a candidate for
	// fragmentation, it's a certainty that no fragmentation will be
	// performed.
	//
	// It's also possible that the weighted coin flip or random selection of
	// bytesToFragment will result in no fragmentation. However, as "seed" may
	// be nil, PRNG calls are deferred and these values are not yet known.
	//
	// TODO: when "seed" is not nil, the coin flip/range could be done here.

	if p.Int(maxTotalBytes) == 0 ||
		(len(tunnelProtocols) > 0 && !common.Contains(tunnelProtocols, tunnelProtocol)) {

		return nil
	}

	var fragmentPRNG *prng.PRNG
	if seed != nil {
		fragmentPRNG = prng.NewPRNGWithSeed(seed)
	}

	return &Config{
		isUpstream:    isUpstream,
		probability:   p.Float(probability),
		minTotalBytes: p.Int(minTotalBytes),
		maxTotalBytes: p.Int(maxTotalBytes),
		minWriteBytes: p.Int(minWriteBytes),
		maxWriteBytes: p.Int(maxWriteBytes),
		minDelay:      p.Duration(minDelay),
		maxDelay:      p.Duration(maxDelay),
		fragmentPRNG:  fragmentPRNG,
	}
}

// MayFragment indicates whether the fragmentor configuration may result in
// any fragmentation; config can be nil. When MayFragment is false, the caller
// should skip wrapping the associated conn with a fragmentor.Conn.
func (config *Config) MayFragment() bool {
	return config != nil
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
	fragmentPRNG    *prng.PRNG
	bytesToFragment int
	bytesFragmented int
	maxBytesWritten int
	minBytesWritten int
	minDelayed      time.Duration
	maxDelayed      time.Duration
}

// NewConn creates a new Conn. When no seed was provided in the Config,
// SetPRNG must be called before the first Write.
func NewConn(
	config *Config,
	noticeEmitter func(string),
	conn net.Conn) *Conn {

	runCtx, stopRunning := context.WithCancel(context.Background())
	return &Conn{
		Conn:            conn,
		config:          config,
		noticeEmitter:   noticeEmitter,
		runCtx:          runCtx,
		stopRunning:     stopRunning,
		fragmentPRNG:    config.fragmentPRNG,
		bytesToFragment: -1,
	}
}

// GetMetrics implements the common.MetricsSource interface.
func (c *Conn) GetMetrics() common.LogFields {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()

	logFields := make(common.LogFields)

	if c.bytesFragmented == 0 {
		return logFields
	}

	var prefix string
	if c.config.isUpstream {
		prefix = "upstream_"
	} else {
		prefix = "downstream_"
	}

	logFields[prefix+"bytes_fragmented"] = c.bytesFragmented
	logFields[prefix+"min_bytes_written"] = c.minBytesWritten
	logFields[prefix+"max_bytes_written"] = c.maxBytesWritten
	logFields[prefix+"min_delayed"] = int(c.minDelayed / time.Microsecond)
	logFields[prefix+"max_delayed"] = int(c.maxDelayed / time.Microsecond)

	return logFields
}

var upstreamMetricsNames = []string{
	"upstream_bytes_fragmented",
	"upstream_min_bytes_written",
	"upstream_max_bytes_written",
	"upstream_min_delayed",
	"upstream_max_delayed",
}

// GetUpstreamMetricsNames returns the upstream metrics parameter names.
func GetUpstreamMetricsNames() []string {
	return upstreamMetricsNames
}

// SetPRNG sets the PRNG to be used by the fragmentor. Specifying a PRNG
// allows for optional replay of a fragmentor sequence. SetPRNG is intended to
// be used with obfuscator.GetDerivedPRNG and allows for setting the PRNG
// after a conn has already been wrapped with a fragmentor.Conn (but before
// the first Write).
//
// If no seed is specified in NewUp/DownstreamConfig and SetPRNG is not called
// before the first Write, the Write will fail. If a seed was specified, or
// SetPRNG was already called, SetPRNG has no effect.
func (c *Conn) SetPRNG(PRNG *prng.PRNG) {

	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()

	if c.fragmentPRNG == nil {
		c.fragmentPRNG = PRNG
	}
}

func (c *Conn) Write(buffer []byte) (int, error) {

	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()

	if c.fragmentPRNG == nil {
		return 0, errors.TraceNew("missing fragmentPRNG")
	}

	if c.bytesToFragment == -1 {
		if !c.fragmentPRNG.FlipWeightedCoin(c.config.probability) {
			c.bytesToFragment = 0
		} else {
			c.bytesToFragment = c.fragmentPRNG.Range(
				c.config.minTotalBytes, c.config.maxTotalBytes)
		}
	}

	if c.bytesFragmented >= c.bytesToFragment {
		return c.Conn.Write(buffer)
	}

	totalBytesWritten := 0

	emitNotice := c.noticeEmitter != nil &&
		c.numNotices < MAX_FRAGMENTOR_NOTICES

	// TODO: use strings.Builder in Go 1.10
	var notice bytes.Buffer

	if emitNotice {
		fmt.Fprintf(&notice, "fragment %d bytes:", len(buffer))
	}

	for iterations := 0; len(buffer) > 0; iterations += 1 {

		delay := c.fragmentPRNG.Period(c.config.minDelay, c.config.maxDelay)

		timer := time.NewTimer(delay)

		var err error
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

		writeBytes := c.fragmentPRNG.Range(minWriteBytes, maxWriteBytes)

		bytesWritten, err := c.Conn.Write(buffer[:writeBytes])

		totalBytesWritten += bytesWritten
		c.bytesFragmented += bytesWritten

		if err != nil {
			return totalBytesWritten, err
		}

		if c.minBytesWritten == 0 || c.minBytesWritten > bytesWritten {
			c.minBytesWritten = bytesWritten
		}
		if c.maxBytesWritten < bytesWritten {
			c.maxBytesWritten = bytesWritten
		}

		if c.minDelayed == 0 || c.minDelayed > delay {
			c.minDelayed = delay
		}
		if c.maxDelayed < delay {
			c.maxDelayed = delay
		}

		if emitNotice {
			if iterations < MAX_FRAGMENTOR_ITERATIONS_PER_NOTICE {
				fmt.Fprintf(&notice, " [%s] %d", delay, bytesWritten)
			} else if iterations == MAX_FRAGMENTOR_ITERATIONS_PER_NOTICE {
				fmt.Fprintf(&notice, "...")
			}
		}

		buffer = buffer[writeBytes:]

		// As soon as bytesToFragment has been satisfied, don't fragment the
		// remainder of this write buffer.
		if c.bytesFragmented >= c.bytesToFragment {
			bytesWritten, err := c.Conn.Write(buffer)
			totalBytesWritten += bytesWritten
			if err != nil {
				return totalBytesWritten, err
			} else {
				buffer = nil
			}
		}
	}

	if emitNotice {
		c.noticeEmitter(notice.String())
		c.numNotices += 1
	}

	return totalBytesWritten, nil
}

func (c *Conn) CloseWrite() error {
	if closeWriter, ok := c.Conn.(common.CloseWriter); ok {
		return closeWriter.CloseWrite()
	}
	return errors.TraceNew("underlying conn is not a CloseWriter")
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
