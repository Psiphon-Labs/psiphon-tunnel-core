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

package portmapper

import (
	"context"
	"io"
	"net"
	"net/netip"
)

// ServiceState is what is known about one port mapping service on the
// current network.
type ServiceState int

const (
	// ServiceNotSeen: the service has not answered anything.
	ServiceNotSeen ServiceState = iota

	// ServiceSeen: the service answered discovery. Whether it grants
	// mappings is not known; some gateways answer discovery with mapping
	// switched off.
	ServiceSeen

	// ServiceGranted: the service granted a mapping.
	ServiceGranted

	// ServiceRefused: the service answered and did not grant a mapping.
	ServiceRefused
)

func (s ServiceState) String() string {
	switch s {
	case ServiceNotSeen:
		return "not seen"
	case ServiceSeen:
		return "seen"
	case ServiceGranted:
		return "granted"
	case ServiceRefused:
		return "refused"
	}
	return "unknown"
}

// Verification is the result of Verify.
type Verification struct {
	PMP  ServiceState
	PCP  ServiceState
	UPnP ServiceState

	// External is the external address of the trial mapping. It is the
	// zero Addr when no service granted one. It is the address the gateway
	// reports, which is not reachable from the Internet when the gateway
	// is itself behind a NAT; whether it is of use is for the caller to
	// decide.
	External netip.Addr
}

// Granted reports whether a service granted the trial mapping.
func (v Verification) Granted() bool {
	return v.PMP == ServiceGranted || v.PCP == ServiceGranted || v.UPnP == ServiceGranted
}

// Verify finds out whether this network grants port mappings, by asking for
// one. It probes the network if this Client has not done so, then creates a
// trial mapping to a local port reserved for the purpose and releases it at
// once. The trial mapping is never used for traffic and does not become the
// Client's mapping.
//
// What Verify learns is recorded in the Client and inherited by its clones:
// later mapping requests ask the service that granted the trial mapping
// first, and a service that refused it last.
//
// A network that grants no mapping is not an error; see
// Verification.Granted. In the Verification, ServiceGranted always means
// that the service granted this call's trial mapping.
//
// When ctx is done before the trial is, Verify returns the context's error,
// and the trial mapping is still released once the gateway has answered.
func (c *Client) Verify(ctx context.Context) (Verification, error) {
	c.mu.Lock()
	probed := c.probed
	protocol := c.protocol
	c.mu.Unlock()
	if !probed {
		if _, err := c.Probe(ctx); err != nil {
			return Verification{}, err
		}
	}

	localPort, reservation, err := reserveLocalPort(protocol)
	if err != nil {
		return Verification{}, err
	}

	// The trial runs on a clone so that its mapping never becomes this
	// Client's. It asks for no particular external port: a preferred port
	// is meant for the mapping that carries traffic.
	trial := c.Clone(nil)
	trial.SetLocalPort(localPort)
	trial.SetPreferredExternalPort(0)

	// The trial has to show a grant for itself. A service that granted an
	// earlier mapping counts only as seen until it grants this one.
	trial.mu.Lock()
	for p, state := range trial.services {
		if state == ServiceGranted {
			trial.services[p] = ServiceSeen
		}
	}
	trial.mu.Unlock()

	// The trial is not cut short when ctx is done, and runs to its end in
	// the background. A mapping request that is abandoned midway may still
	// be granted by the gateway, and nothing would then release the
	// mapping.
	type trialResult struct {
		services [3]ServiceState
		gw, myIP netip.Addr
		external netip.AddrPort
		err      error
	}
	done := make(chan trialResult, 1)
	go func() {
		trialCtx, cancel := context.WithTimeout(context.Background(), mappingCreateTimeout)
		defer cancel()

		var result trialResult
		_, result.external, result.err = trial.createOrGetMapping(trialCtx)

		trial.mu.Lock()
		result.services = trial.services
		result.gw, result.myIP = trial.lastGW, trial.lastMyIP
		trial.mu.Unlock()

		// Closing the clone releases the trial mapping.
		trial.Close()
		reservation.Close()
		done <- result
	}()

	var result trialResult
	select {
	case result = <-done:
	case <-ctx.Done():
		return Verification{}, ctx.Err()
	}

	// Record what the trial proved, unless this Client has moved to another
	// network meanwhile.
	c.mu.Lock()
	if c.probed && c.lastGW == result.gw && c.lastMyIP == result.myIP {
		for p, state := range result.services {
			if state == ServiceGranted || state == ServiceRefused {
				c.services[p] = state
			}
		}
	}
	c.mu.Unlock()

	v := Verification{
		PMP:  result.services[protocolPMP],
		PCP:  result.services[protocolPCP],
		UPnP: result.services[protocolUPnP],
	}
	if result.err != nil {
		if IsNoMappingError(result.err) {
			return v, nil
		}
		return v, result.err
	}
	v.External = result.external.Addr()
	return v, nil
}

// reserveLocalPort binds a local port, so that the trial mapping points at a
// port that no service on this machine listens on. Closing the returned
// Closer gives the port back.
func reserveLocalPort(protocol MapProtocol) (uint16, io.Closer, error) {
	var reservation io.Closer
	var addr net.Addr
	if protocol == MapProtocolTCP {
		listener, err := net.Listen("tcp4", ":0")
		if err != nil {
			return 0, nil, err
		}
		reservation, addr = listener, listener.Addr()
	} else {
		conn, err := net.ListenPacket("udp4", ":0")
		if err != nil {
			return 0, nil, err
		}
		reservation, addr = conn, conn.LocalAddr()
	}
	addrPort, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		reservation.Close()
		return 0, nil, err
	}
	return addrPort.Port(), reservation, nil
}
