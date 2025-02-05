// Copyright 2024 Jigsaw Operations LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"time"
)

/*
HappyEyeballsStreamDialer is a [StreamDialer] that uses [Happy Eyeballs v2] to establish a connection
to the destination address.

Happy Eyeballs v2 reduces the connection delay when compared to v1, with significant differences when one of the
address lookups times out. V1 will wait for both the IPv4 and IPv6 lookups to return before attempting connections,
while V2 starts connections as soon as it gets a lookup result, with a slight delay if IPv4 arrives before IPv6.

Go and most platforms provide V1 only, so you will benefit from using the HappyEyeballsStreamDialer in place of the
standard dialer, even if you are not using custom transports.

[Happy Eyeballs v2]: https://datatracker.ietf.org/doc/html/rfc8305
*/
type HappyEyeballsStreamDialer struct {
	// Dialer is used to establish the connection attempts. If nil, a direct TCP connection is established.
	Dialer StreamDialer
	// Resolve is a function to map a host name to IP addresses. See HappyEyeballsResolver.
	Resolve HappyEyeballsResolveFunc
}

// HappyEyeballsResolveFunc performs concurrent hostname resolution for [HappyEyeballsStreamDialer].
//
// The function should return a channel quickly, and then send the resolution results to it
// as they become available. HappyEyeballsStreamDialer will read the resolutions from the channel.
// The returned channel must be closed when there are no
// more resolutions pending, to indicate that the resolution is done. If that is not
// done, HappyEyeballsStreamDialer will keep waiting.
//
// It's recommended to return a buffered channel with size equal to the number of
// lookups, so that it will never block on write.
// If the channel is unbuffered, you must use select when writing to the channel against
// ctx.Done(), to make sure you don't write when HappyEyeballsStreamDialer is no longer reading.
// Othewise your goroutine will get stuck.
//
// It's recommended to resolve IPv6 and IPv4 in parallel, so the connection attempts
// are started as soon as addresses are received. That's the primary benefit of Happy
// Eyeballs v2. If you resolve in series, and only send the addresses when both
// resolutions are done, you will get behavior similar to Happy Eyeballs v1.
type HappyEyeballsResolveFunc = func(ctx context.Context, hostname string) <-chan HappyEyeballsResolution

// HappyEyeballsResolution represents a result of a hostname resolution.
// Happy Eyeballs sorts the IPs in a specific way, updating the order as
// new results are received. It's recommended to returns all IPs you receive
// as a group, rather than one IP at a time, since a later IP may be preferred.
type HappyEyeballsResolution struct {
	IPs []netip.Addr
	Err error
}

// NewParallelHappyEyeballsResolveFunc creates a [HappyEyeballsResolveFunc] that uses the given list of functions to resolve host names.
// The given functions will all run in parallel, with results being output as they are received.
// Typically you will pass one function for IPv6 and one for IPv4 to achieve Happy Eyballs v2 behavior.
// It takes care of creating the channel and the parallelization and coordination between the calls.
func NewParallelHappyEyeballsResolveFunc(resolveFuncs ...func(ctx context.Context, hostname string) ([]netip.Addr, error)) HappyEyeballsResolveFunc {
	return func(ctx context.Context, host string) <-chan HappyEyeballsResolution {
		// Use a buffered channel with space for both lookups, to ensure the goroutines won't
		// block on channel write if the Happy Eyeballs algorithm is cancelled and no longer reading.
		resultsCh := make(chan HappyEyeballsResolution, len(resolveFuncs))
		if len(resolveFuncs) == 0 {
			close(resultsCh)
			return resultsCh
		}

		var pending atomic.Int32
		pending.Store(int32(len(resolveFuncs)))
		for _, resolve := range resolveFuncs {
			go func(resolve func(ctx context.Context, hostname string) ([]netip.Addr, error), hostname string) {
				ips, err := resolve(ctx, hostname)
				resultsCh <- HappyEyeballsResolution{ips, err}
				if pending.Add(-1) == 0 {
					// Close results channel when no other goroutine is pending.
					close(resultsCh)
				}
			}(resolve, host)
		}
		return resultsCh
	}
}

var _ StreamDialer = (*HappyEyeballsStreamDialer)(nil)

func (d *HappyEyeballsStreamDialer) dial(ctx context.Context, addr string) (StreamConn, error) {
	if d.Dialer != nil {
		return d.Dialer.DialStream(ctx, addr)
	}
	return (&TCPDialer{}).DialStream(ctx, addr)
}

func newClosedChan() <-chan struct{} {
	closedCh := make(chan struct{})
	close(closedCh)
	return closedCh
}

// DialStream implements [StreamDialer].
func (d *HappyEyeballsStreamDialer) DialStream(ctx context.Context, addr string) (StreamConn, error) {
	hostname, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse address: %w", err)
	}
	if net.ParseIP(hostname) != nil {
		// Host is already an IP address, just dial the address.
		return d.dial(ctx, addr)
	}

	// Indicates to attempts that the dialing process is done, so they don't get stuck.
	ctx, dialDone := context.WithCancel(ctx)
	defer dialDone()

	// HOSTNAME RESOLUTION QUERY HANDLING
	// https://datatracker.ietf.org/doc/html/rfc8305#section-3
	resolutionCh := d.Resolve(ctx, hostname)

	// CONNECTION ATTEMPTS
	// https://datatracker.ietf.org/doc/html/rfc8305#section-5
	// We keep IPv4s and IPv6 separate and track the last one attempted so we can
	// alternate the address family in the connection attempts.
	ip4s := make([]netip.Addr, 0, 1)
	ip6s := make([]netip.Addr, 0, 1)
	var lastDialed netip.Addr
	// Keep track of the lookup and dial errors separately. We prefer the dial errors
	// when returning.
	var lookupErr error
	var dialErr error
	// Channel to wait for before a new dial attempt. It starts
	// with a closed channel that doesn't block because there's no
	// wait initially.
	var attemptDelayCh <-chan struct{} = newClosedChan()
	type DialResult struct {
		Conn StreamConn
		Err  error
	}
	dialCh := make(chan DialResult)

	// Channel that triggers when a new connection can be made. Starts blocked (nil)
	// because we need IPs first.
	var readyToDialCh <-chan struct{} = nil
	// We keep track of pending operations (lookups and IPs to dial) so we can stop when
	// there's no more work to wait for.
	for opsPending := 1; opsPending > 0; {
		if len(ip6s) == 0 && len(ip4s) == 0 {
			// No IPs. Keep dial disabled.
			readyToDialCh = nil
		} else {
			// There are IPs to dial.
			if !lastDialed.IsValid() && len(ip6s) == 0 && resolutionCh != nil {
				// Attempts haven't started and IPv6 lookup is not done yet. Set up Resolution Delay, as per
				// https://datatracker.ietf.org/doc/html/rfc8305#section-8, if it hasn't been set up yet.
				if readyToDialCh == nil {
					resolutionDelayCtx, cancelResolutionDelay := context.WithTimeout(ctx, 50*time.Millisecond)
					defer cancelResolutionDelay()
					readyToDialCh = resolutionDelayCtx.Done()
				}
			} else {
				// Wait for the previous attempt.
				readyToDialCh = attemptDelayCh
			}
		}
		select {
		// Receive lookup results.
		case lookupRes, ok := <-resolutionCh:
			if !ok {
				opsPending--
				// Set to nil to make the read on lookupCh block and to signal lookup is done.
				resolutionCh = nil
			}
			if lookupRes.Err != nil {
				lookupErr = errors.Join(lookupErr, lookupRes.Err)
				continue
			}
			opsPending += len(lookupRes.IPs)
			// TODO: sort IPs as per https://datatracker.ietf.org/doc/html/rfc8305#section-4
			for _, ip := range lookupRes.IPs {
				if ip.Is6() {
					ip6s = append(ip6s, ip)
				} else {
					ip4s = append(ip4s, ip)
				}
			}

		// Wait for Connection Attempt Delay or attempt done.
		// This case is disabled above when len(ip6s) == 0 && len(ip4s) == 0.
		case <-readyToDialCh:
			var toDial netip.Addr
			// Alternate between IPv6 and IPv4.
			if len(ip6s) == 0 || (lastDialed.Is6() && len(ip4s) > 0) {
				toDial = ip4s[0]
				ip4s = ip4s[1:]
			} else {
				toDial = ip6s[0]
				ip6s = ip6s[1:]
			}
			// Reset Connection Attempt Delay, as per https://datatracker.ietf.org/doc/html/rfc8305#section-8
			// We don't tie the delay context to the parent because we don't want the readyToDialCh case
			// to trigger on the parent cancellation.
			delayCtx, cancelDelay := context.WithTimeout(context.Background(), 250*time.Millisecond)
			attemptDelayCh = delayCtx.Done()
			go func(addr string, cancelDelay context.CancelFunc) {
				// Cancel the wait if the dial return early.
				defer cancelDelay()
				conn, err := d.dial(ctx, addr)
				select {
				case <-ctx.Done():
					if conn != nil {
						conn.Close()
					}
				case dialCh <- DialResult{conn, err}:
				}
			}(net.JoinHostPort(toDial.String(), port), cancelDelay)
			lastDialed = toDial

		// Receive dial result.
		case dialRes := <-dialCh:
			opsPending--
			if dialRes.Err != nil {
				dialErr = errors.Join(dialErr, dialRes.Err)
				continue
			}
			return dialRes.Conn, nil

		// Dial has been canceled. Return.
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if dialErr != nil {
		return nil, dialErr
	}
	if lookupErr != nil {
		return nil, lookupErr
	}
	return nil, errors.New("address lookup returned no IPs")
}
