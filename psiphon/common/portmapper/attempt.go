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
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"time"
)

// ErrPortMappingRefused is wrapped in the NoMappingError returned when a
// gateway answered a mapping request without granting it, and no other
// protocol granted one.
var ErrPortMappingRefused = errors.New("port mapping refused by the gateway")

// MappingOutcome is the result of one attempt to create or renew a mapping.
type MappingOutcome int

const (
	// MappingGranted reports that a mapping is in place.
	MappingGranted MappingOutcome = iota + 1

	// MappingRefused reports that a port mapping service answered and did
	// not grant a mapping.
	MappingRefused

	// MappingNoAnswer reports that no port mapping service answered.
	MappingNoAnswer
)

func (o MappingOutcome) String() string {
	switch o {
	case MappingGranted:
		return "granted"
	case MappingRefused:
		return "refused"
	case MappingNoAnswer:
		return "no answer"
	}
	return "unknown"
}

// reportOutcome delivers the result of a create that returned mapping and err
// to the mapping outcome callback.
func (c *Client) reportOutcome(mapping mapping, err error) {
	if c.onOutcome == nil {
		return
	}
	var outcome MappingOutcome
	switch {
	case err == nil && mapping != nil:
		outcome = MappingGranted
	case err == nil:
		// The mapping was granted, and invalidated before the create
		// returned it.
		return
	case errors.Is(err, errMappingInvalidated), errors.Is(err, context.Canceled):
		return
	case errors.Is(err, ErrPortMappingRefused):
		outcome = MappingRefused
	default:
		outcome = MappingNoAnswer
	}
	go c.onOutcome(outcome)
}

// mappingProtocol is one of the port mapping protocols.
type mappingProtocol int

const (
	protocolPMP mappingProtocol = iota
	protocolPCP
	protocolUPnP
)

// attemptOutcome is how one step of a create ended.
type attemptOutcome int

const (
	// attemptNoAnswer: nothing answered, or the gateway reported that
	// nothing is listening.
	attemptNoAnswer attemptOutcome = iota

	// attemptGranted: the mapping is in place and published.
	attemptGranted

	// attemptRefused: the gateway answered and did not grant a mapping.
	attemptRefused

	// attemptAbandoned: the create was cancelled, or the client was closed
	// or reconfigured meanwhile. No further step is tried.
	attemptAbandoned
)

// mappingRequest is what one create asks of the gateway. It is fixed when
// the create starts.
type mappingRequest struct {
	gw         netip.Addr
	internal   netip.AddrPort
	protocol   MapProtocol
	prevPort   uint16
	generation uint64
	pcpNonce   pcpNonce
}

// plannedAttempt is one step of a create.
type plannedAttempt struct {
	// upnp selects UPnP. Otherwise the step is the NAT-PMP/PCP exchange,
	// and first is the protocol whose request format is sent first.
	upnp  bool
	first mappingProtocol

	// known reports that discovery, or the mapping being renewed, saw this
	// service. A service that is not known is given only silenceDeadline to
	// answer.
	known bool
}

// attemptPlanLocked returns the steps of a create, in the order they are
// tried: the protocol of the mapping being renewed, then the services
// discovery saw, then the rest. Every enabled protocol with something to
// ask appears in the plan, so a create fails only when none of them grants
// a mapping.
//
// c.mu must be held.
func (c *Client) attemptPlanLocked() []plannedAttempt {
	pmpEnabled := !c.debug.DisablePMP()
	pcpEnabled := !c.debug.DisablePCP()

	knownPMP := pmpEnabled && c.pmpPubIP.IsValid()
	knownPCP := pcpEnabled && !c.pcpSawTime.IsZero()

	renewing := mappingProtocol(-1)
	if c.mapping != nil {
		switch c.mapping.MappingType() {
		case "pmp":
			renewing = protocolPMP
		case "pcp":
			renewing = protocolPCP
		case "upnp":
			renewing = protocolUPnP
		}
	}

	var plan []plannedAttempt

	// UPnP can only be asked when there is a device to ask: one from
	// discovery, or the one that granted the mapping being renewed.
	upnp := c.haveUPnPDeviceLocked()
	if upnp && renewing == protocolUPnP {
		plan = append(plan, plannedAttempt{upnp: true, known: true})
		upnp = false
	}

	// NAT-PMP and PCP share a port on the gateway and are one step: each
	// tells the client when the gateway speaks only the other.
	var pxp *plannedAttempt
	if pmpEnabled || pcpEnabled {
		pxp = &plannedAttempt{known: knownPMP || knownPCP}
		switch {
		case renewing == protocolPMP && pmpEnabled:
			pxp.first, pxp.known = protocolPMP, true
		case renewing == protocolPCP && pcpEnabled:
			pxp.first, pxp.known = protocolPCP, true
		case knownPMP:
			pxp.first = protocolPMP
		case knownPCP:
			pxp.first = protocolPCP
		case pmpEnabled:
			pxp.first = protocolPMP
		default:
			pxp.first = protocolPCP
		}
	}

	if pxp != nil && pxp.known {
		plan = append(plan, *pxp)
		pxp = nil
	}
	if upnp {
		plan = append(plan, plannedAttempt{upnp: true, known: true})
	}
	if pxp != nil {
		plan = append(plan, *pxp)
	}
	return plan
}

// upnpStepContext returns the context for a UPnP step that is followed by
// the steps in later. A UPnP step is a series of HTTP requests, and a device
// that accepts them and does not answer would otherwise use up the whole
// create. The time that the NAT-PMP/PCP step still to come may need is kept
// back, so that every protocol is asked.
func (c *Client) upnpStepContext(
	ctx context.Context,
	later []plannedAttempt,
) (context.Context, context.CancelFunc) {

	deadline, ok := ctx.Deadline()
	if !ok {
		return ctx, func() {}
	}
	var reserve time.Duration
	for _, step := range later {
		if step.upnp {
			continue
		}
		// The first format, then the other; see tryPxP.
		if step.known {
			reserve += c.knownRequestTimeout
		} else {
			reserve += c.silenceDeadline
		}
		reserve += c.silenceDeadline
	}
	if reserve == 0 {
		return ctx, func() {}
	}
	return context.WithDeadline(ctx, deadline.Add(-reserve))
}

// mappingInvalidated reports whether the client was closed, or its mapping
// invalidated, since a create began under generation.
func (c *Client) mappingInvalidated(generation uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed || c.mappingGeneration != generation
}

// publishMapping makes m the client's mapping, unless the client was closed
// or the mapping invalidated since the create began. In that case the
// mapping, which exists on the gateway, is released rather than leaked
// until its lease expires.
func (c *Client) publishMapping(m mapping, generation uint64) bool {
	c.mu.Lock()
	if c.closed || c.mappingGeneration != generation {
		c.mu.Unlock()
		releaseMapping(m)
		return false
	}
	superseded := c.replaceMappingLocked(m)
	c.mu.Unlock()
	if superseded != nil {
		c.releaseSuperseded(superseded)
	}
	return true
}

// replaceMappingLocked makes m the client's mapping. It returns the mapping
// that m replaces when that one may still be a separate forwarding rule on
// the gateway, for the caller to pass to releaseSuperseded once c.mu is no
// longer held; otherwise the rule would stay until its lease expires, and
// a UPnP lease may be permanent.
//
// Only a UPnP mapping with another external port is returned. A UPnP
// mapping is released by its external port, so releasing it cannot remove
// the rule behind m. A NAT-PMP or PCP mapping is released by its internal
// port, which m shares, so it is left to expire.
//
// c.mu must be held.
func (c *Client) replaceMappingLocked(m mapping) (superseded mapping) {
	old := c.mapping
	c.mapping = m
	if old != nil && old.MappingType() == "upnp" &&
		old.External().Port() != m.External().Port() {
		return old
	}
	return nil
}

// pxpReply is how the gateway answered one NAT-PMP or PCP request.
type pxpReply int

const (
	// pxpSilent: nothing answered before the wait ended.
	pxpSilent pxpReply = iota

	// pxpUnreachable: the gateway reported that nothing listens on the
	// port.
	pxpUnreachable

	// pxpGranted: the mapping is in place and published.
	pxpGranted

	// pxpRefused: the gateway answered with an error.
	pxpRefused

	// pxpOtherVersion: the gateway speaks the other of NAT-PMP and PCP.
	pxpOtherVersion

	// pxpAbandoned: the create was cancelled, or the mapping was granted
	// and then released because the client was closed or reconfigured.
	pxpAbandoned
)

// tryPxP asks the gateway for a mapping over NAT-PMP or PCP, starting with
// the request format of step.first.
//
// A request in the other format follows unless the first one is granted: a
// gateway that speaks only one of the protocols may say so, refuse, or
// ignore a request it does not understand. Only the gateway's report that
// nothing listens on the port, which both protocols share, rules out both.
func (c *Client) tryPxP(
	ctx context.Context,
	req mappingRequest,
	step plannedAttempt,
) (netip.AddrPort, attemptOutcome) {

	conn, err := c.dialPxP(ctx, req.gw)
	if err != nil {
		c.vlogf("NAT-PMP/PCP: %v", err)
		return netip.AddrPort{}, attemptNoAnswer
	}
	defer conn.Close()
	defer closeCloserOnContextDone(ctx, conn)()

	other := protocolPCP
	if step.first == protocolPCP {
		other = protocolPMP
	}

	outcome := attemptNoAnswer
	for i, format := range []mappingProtocol{step.first, other} {
		if format == protocolPMP && c.debug.DisablePMP() ||
			format == protocolPCP && c.debug.DisablePCP() {
			continue
		}

		// Only a service that was seen is expected to answer, and so is
		// worth waiting for and asking again.
		wait, retransmit := c.silenceDeadline, false
		if step.known && i == 0 {
			wait, retransmit = c.knownRequestTimeout, true
		}

		// A reply in the other protocol's format moves the first request on
		// to the other format. Once that has happened, such a reply can
		// only be a late answer to the first request, and is ignored.
		follow := i == 0

		var external netip.AddrPort
		var reply pxpReply
		if format == protocolPMP {
			external, reply = c.pmpExchange(ctx, conn, req, wait, retransmit, follow)
		} else {
			external, reply = c.pcpExchange(ctx, conn, req, wait, retransmit, follow)
		}
		switch reply {
		case pxpGranted:
			return external, attemptGranted
		case pxpAbandoned:
			return netip.AddrPort{}, attemptAbandoned
		case pxpUnreachable:
			return netip.AddrPort{}, outcome
		case pxpRefused:
			outcome = attemptRefused
		}
	}
	return netip.AddrPort{}, outcome
}

// dialPxP returns a UDP socket connected to the gateway's NAT-PMP/PCP port.
// The socket is connected so that the gateway's ICMP port unreachable reply,
// which says at once that it runs neither service, reaches the client as a
// read error. An unconnected socket never sees that reply.
func (c *Client) dialPxP(ctx context.Context, gw netip.Addr) (*net.UDPConn, error) {
	// As in listenPacket, the Control (BindToDevice) hook is not applied
	// to the loopback sockets used in tests.
	dialer := net.Dialer{}
	if c.testPxPPort == 0 && c.testUPnPPort == 0 {
		dialer.Control = c.control
	}
	conn, err := dialer.DialContext(
		ctx, "udp4", netip.AddrPortFrom(gw, c.pxpPort()).String())
	if err != nil {
		return nil, err
	}
	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		conn.Close()
		return nil, errors.New("unexpected connection type")
	}
	enablePortUnreachable(udpConn)
	return udpConn, nil
}

// pxpRoundTrip sends a request and hands each reply to handle, until handle
// returns a verdict, the gateway reports that nothing listens on the port,
// or wait has passed. With retransmit, an unanswered request is sent again
// at doubling intervals.
func (c *Client) pxpRoundTrip(
	ctx context.Context,
	conn *net.UDPConn,
	send func() error,
	wait time.Duration,
	retransmit bool,
	handle func(pkt []byte) (reply pxpReply, done bool),
) pxpReply {

	failed := func(err error) pxpReply {
		if ctx.Err() == context.Canceled {
			return pxpAbandoned
		}
		if isPortUnreachable(err) {
			c.vlogf("NAT-PMP/PCP: the gateway reports that nothing listens on port %d", c.pxpPort())
			return pxpUnreachable
		}
		return pxpSilent
	}

	deadline := time.Now().Add(wait)
	interval := wait
	if retransmit && pxpRetransmitInterval < wait {
		interval = pxpRetransmitInterval
	}

	buf := make([]byte, 1500)
	for {
		if err := send(); err != nil {
			return failed(err)
		}

		readDeadline := time.Now().Add(interval)
		if readDeadline.After(deadline) {
			readDeadline = deadline
		}
		conn.SetReadDeadline(readDeadline)

		for {
			n, err := conn.Read(buf)
			if err != nil {
				var netErr net.Error
				if errors.As(err, &netErr) && netErr.Timeout() && ctx.Err() == nil {
					break
				}
				return failed(err)
			}
			if reply, done := handle(buf[:n]); done {
				return reply
			}
		}

		if !time.Now().Before(deadline) {
			return pxpSilent
		}
		interval *= 2
	}
}

// pmpExchange asks for a mapping in the NAT-PMP request format. With
// followOtherVersion, a reply that shows the gateway speaks only PCP ends
// the exchange with pxpOtherVersion; without it, such a reply is ignored.
func (c *Client) pmpExchange(
	ctx context.Context,
	conn *net.UDPConn,
	req mappingRequest,
	wait time.Duration,
	retransmit bool,
	followOtherVersion bool,
) (netip.AddrPort, pxpReply) {

	// A NAT-PMP mapping takes two replies: one for the external address and
	// one for the port. The address is asked for every time, since it can
	// change while the gateway stays the same.
	m := &pmpMapping{
		c:        c,
		gw:       netip.AddrPortFrom(req.gw, c.pxpPort()),
		internal: req.internal,
		protocol: req.protocol,
	}

	send := func() error {
		if _, err := conn.Write(pmpReqExternalAddrPacket); err != nil {
			return err
		}
		_, err := conn.Write(buildPMPRequestMappingPacket(
			req.internal.Port(), req.prevPort, pmpMapLifetimeSec, req.protocol))
		return err
	}

	reply := c.pxpRoundTrip(ctx, conn, send, wait, retransmit, func(pkt []byte) (pxpReply, bool) {
		if len(pkt) < 4 {
			return 0, false
		}
		if pkt[0] == pcpVersion {
			// A gateway that speaks only PCP answers in the PCP format.
			if followOtherVersion && pcpResultCode(pkt[3]) == pcpCodeUnsupportedVersion {
				return pxpOtherVersion, true
			}
			return 0, false
		}
		if pkt[0] != pmpVersion {
			c.logf("unknown PMP/PCP version number: %d", pkt[0])
			return 0, false
		}

		switch code := pmpResultCode(binary.BigEndian.Uint16(pkt[2:4])); code {
		case pmpCodeOK:
		case pmpCodeUnsupportedVersion:
			if followOtherVersion {
				return pxpOtherVersion, true
			}
			return 0, false
		default:
			c.logf("NAT-PMP refused the request: op=0x%x result=%v", pkt[1], code)
			return pxpRefused, true
		}

		pres, ok := parsePMPResponse(pkt)
		if !ok {
			c.logf("unexpected PMP response: % 02x", pkt)
			return 0, false
		}
		if pres.OpCode == pmpOpReply|pmpOpMapPublicAddr {
			m.external = netip.AddrPortFrom(pres.PublicAddr, m.external.Port())
		}
		if pres.OpCode == pmpOpReply|pmpMapOp(req.protocol) {
			m.external = netip.AddrPortFrom(m.external.Addr(), pres.ExternalPort)
			d := time.Duration(pres.MappingValidSeconds) * time.Second
			now := c.clock()
			m.goodUntil = now.Add(d)
			m.renewAfter = now.Add(d / 2) // renew in half the time
			m.epoch = pres.SecondsSinceEpoch
		}
		if !m.externalValid() {
			return 0, false
		}
		if !c.publishMapping(m, req.generation) {
			return pxpAbandoned, true
		}
		return pxpGranted, true
	})

	if reply != pxpGranted {
		return netip.AddrPort{}, reply
	}
	return m.external, reply
}

// pcpExchange asks for a mapping in the PCP request format. With
// followOtherVersion, a reply that shows the gateway speaks only NAT-PMP
// ends the exchange with pxpOtherVersion; without it, such a reply is
// ignored.
func (c *Client) pcpExchange(
	ctx context.Context,
	conn *net.UDPConn,
	req mappingRequest,
	wait time.Duration,
	retransmit bool,
	followOtherVersion bool,
) (netip.AddrPort, pxpReply) {

	// TODO replace wildcardIP here with previous external if known.
	pkt := buildPCPRequestMappingPacket(
		req.internal.Addr(), req.internal.Port(), req.prevPort,
		pcpMapLifetimeSec, wildcardIP, req.pcpNonce, req.protocol)
	send := func() error {
		_, err := conn.Write(pkt)
		return err
	}

	var external netip.AddrPort
	reply := c.pxpRoundTrip(ctx, conn, send, wait, retransmit, func(pkt []byte) (pxpReply, bool) {
		if len(pkt) < 4 {
			return 0, false
		}
		if pkt[0] == pmpVersion {
			// A gateway that speaks only NAT-PMP answers a PCP request with
			// a NAT-PMP error.
			if followOtherVersion {
				return pxpOtherVersion, true
			}
			return 0, false
		}
		if pkt[0] != pcpVersion {
			c.logf("unknown PMP/PCP version number: %d", pkt[0])
			return 0, false
		}
		if pcpResultCode(pkt[3]) == pcpCodeUnsupportedVersion {
			if followOtherVersion {
				return pxpOtherVersion, true
			}
			return 0, false
		}

		// Ignore responses related to another client. A response packet
		// is a 24-byte header followed by an operation specific payload.
		// For a MAP operation, the first 12 bytes of the payload are the
		// client-generated nonce.
		if len(pkt) < 36 || !bytes.Equal(pkt[24:36], req.pcpNonce[:]) {
			c.logf("ignoring PCP response with missing or mismatched nonce")
			return 0, false
		}

		// PCP returns everything a mapping needs in a single packet.
		m, err := parsePCPMapResponse(pkt, req.protocol, c.clock())
		if err != nil {
			c.logf("failed to get PCP mapping: %v", err)
			return pxpRefused, true
		}
		m.c = c
		m.internal = req.internal
		m.gw = netip.AddrPortFrom(req.gw, c.pxpPort())
		if !c.publishMapping(m, req.generation) {
			return pxpAbandoned, true
		}
		external = m.external
		return pxpGranted, true
	})

	return external, reply
}
