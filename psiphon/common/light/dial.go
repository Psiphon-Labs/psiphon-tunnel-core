/*
 * Copyright (c) 2026, Psiphon Inc.
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

package light

import (
	"context"
	"net"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
)

// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// The code in this file is largely copied from
// https://github.com/golang/go/blob/go1.26.3/src/net/dial.go and ipsock.go.
// Go's net.Dialer Happy Eyeballs and multi-address fallback is not exposed
// in a way that it can be used with a custom DNS resolver, the proxy's
// caching DNS resolve, so the logic is extracted here.

type netTCPAddrs [2][]net.TCPAddr

// Based on net.addrList.partition, with strategy net.isIPv4.
//
// Partitions IPv4 and IPv6, with whichever family appears first being the
// primary.
func netPartitionAddrs(addrs []net.IPAddr, port int) netTCPAddrs {
	var partitioned netTCPAddrs
	var primaryLabel bool
	for i, addr := range addrs {
		label := addr.IP.To4() != nil
		if i == 0 || label == primaryLabel {
			primaryLabel = label
			partitioned[0] = append(partitioned[0], net.TCPAddr{IP: addr.IP, Port: port, Zone: addr.Zone})
		} else {
			partitioned[1] = append(partitioned[1], net.TCPAddr{IP: addr.IP, Port: port, Zone: addr.Zone})
		}
	}
	return partitioned
}

func netIPAddrs(IP net.IP, port int) netTCPAddrs {
	var addrs netTCPAddrs
	addrs[0] = []net.TCPAddr{{IP: IP, Port: port}}
	return addrs
}

func (addrs netTCPAddrs) isEmpty() bool {
	return len(addrs[0]) == 0
}

// From net.sysDialer.dialParallel.
//
// dialParallel races two copies of dialSerial, giving the first a
// head start. It returns the first established connection and
// closes the others. Otherwise it returns an error from the first
// primary address.
func netDialParallel(
	ctx context.Context,
	fallbackDelay time.Duration,
	addrs netTCPAddrs,
	dialer *net.Dialer) (net.Conn, error) {

	primaries := addrs[0]
	fallbacks := addrs[1]

	if len(fallbacks) == 0 {
		conn, err := netDialSerial(ctx, primaries, dialer)
		return conn, errors.Trace(err)
	}

	returned := make(chan struct{})
	defer close(returned)

	type dialResult struct {
		net.Conn
		error
		primary bool
		done    bool
	}
	results := make(chan dialResult) // unbuffered

	startRacer := func(ctx context.Context, primary bool) {
		ras := primaries
		if !primary {
			ras = fallbacks
		}
		c, err := netDialSerial(ctx, ras, dialer)
		select {
		case results <- dialResult{Conn: c, error: err, primary: primary, done: true}:
		case <-returned:
			if c != nil {
				c.Close()
			}
		}
	}

	var primary, fallback dialResult

	// Start the main racer.
	primaryCtx, primaryCancel := context.WithCancel(ctx)
	defer primaryCancel()
	go startRacer(primaryCtx, true)

	// Start the timer for the fallback racer.
	fallbackTimer := time.NewTimer(fallbackDelay)
	defer fallbackTimer.Stop()

	for {
		select {
		case <-fallbackTimer.C:
			fallbackCtx, fallbackCancel := context.WithCancel(ctx)
			defer fallbackCancel()
			go startRacer(fallbackCtx, false)

		case res := <-results:
			if res.error == nil {
				return res.Conn, nil
			}
			if res.primary {
				primary = res
			} else {
				fallback = res
			}
			if primary.done && fallback.done {
				return nil, primary.error
			}
			if res.primary && fallbackTimer.Stop() {
				// If we were able to stop the timer, that means it
				// was running (hadn't yet started the fallback), but
				// we just got an error on the primary path, so start
				// the fallback immediately (in 0 nanoseconds).
				fallbackTimer.Reset(0)
			}
		}
	}
}

// From net.sysDialer.dialSerial.
//
// dialSerial connects to a list of addresses in sequence, returning
// either the first successful connection, or the first error.
func netDialSerial(ctx context.Context, ras []net.TCPAddr, dialer *net.Dialer) (net.Conn, error) {
	var firstErr error // The error from the first address is most relevant.

	for i, ra := range ras {
		select {
		case <-ctx.Done():
			return nil, errors.Trace(ctx.Err())
		default:
		}

		dialCtx := ctx
		if deadline, hasDeadline := ctx.Deadline(); hasDeadline {
			partialDeadline, err := partialDeadline(time.Now(), deadline, len(ras)-i)
			if err != nil {
				// Ran out of time.
				if firstErr == nil {
					firstErr = errors.Trace(err)
				}
				break
			}
			if partialDeadline.Before(deadline) {
				var cancel context.CancelFunc
				dialCtx, cancel = context.WithDeadline(ctx, partialDeadline)
				defer cancel()
			}
		}

		c, err := dialer.DialContext(dialCtx, "tcp", ra.String())
		if err == nil {
			return c, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}

	if firstErr == nil {
		firstErr = errors.TraceNew("missing address")
	}
	return nil, firstErr
}

// From net.partialDeadline.
func partialDeadline(now, deadline time.Time, addrsRemaining int) (time.Time, error) {
	if deadline.IsZero() {
		return deadline, nil
	}
	timeRemaining := deadline.Sub(now)
	if timeRemaining <= 0 {
		return time.Time{}, errors.TraceNew("timeout")
	}
	// Tentatively allocate equal time to each remaining address.
	timeout := timeRemaining / time.Duration(addrsRemaining)
	// If the time per address is too short, steal from the end of the list.
	const saneMinimum = 2 * time.Second
	if timeout < saneMinimum {
		if timeRemaining < saneMinimum {
			timeout = timeRemaining
		} else {
			timeout = saneMinimum
		}
	}
	return now.Add(timeout), nil
}
