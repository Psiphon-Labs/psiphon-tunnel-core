//go:build !PSIPHON_DISABLE_INPROXY

/*
 * Copyright (c) 2023, Psiphon Inc.
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

package inproxy

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/portmapper"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/portmapper/gateway"
)

// portMapper represents a UDP port mapping from a local port to an external,
// publicly addressable IP and port. Port mapping is implemented using
// psiphon/common/portmapper -- a hard fork of tailscale.com/net/portmapper --
// which probes the local network and gateway for UPnP-IGD, NAT-PMP, and PCP
// port mapping capabilities.
type portMapper struct {
	havePortMappingOnce   sync.Once
	portMappingAddress    chan string
	portMappingFailedOnce sync.Once
	portMappingFailed     chan struct{}
	client                *portmapper.Client
	portMappingLogger     func(format string, args ...any)
}

// newPortMapper initializes a new port mapper, configured to map to the
// specified localPort. newPortMapper does not initiate any network
// operations.
//
// newPortMapper requires a PortMappingProbe initialized by probePortMapping:
// rather than run a full Client.Probe per port mapping, the port mapping
// service discovery from one probe run is reused by cloning the probe's
// client. The clone inherits the probe client's BindToDevice hook and gateway
// lookup.
func newPortMapper(
	logger common.Logger,
	probe *PortMappingProbe,
	localPort int) (*portMapper, error) {

	if probe == nil || probe.client == nil {
		return nil, errors.TraceNew("missing probe")
	}

	portMappingLogger := func(format string, args ...any) {
		logger.WithTrace().Info(
			"port mapping: " + formatPortMappingLog(format, args...))
	}

	p := &portMapper{
		portMappingAddress: make(chan string, 1),
		portMappingFailed:  make(chan struct{}),
		portMappingLogger:  portMappingLogger,
	}

	// Clone the probe's client, reusing its port mapping service discovery
	// (probe-once / map-many).
	//
	// The onChange callback will not be invoked until after the
	// GetCachedMappingOrStartCreatingOne call in portMapper.start, so the
	// p.client reference within the callback is valid.
	p.client = probe.client.Clone(func() {
		if !p.client.HaveMapping() {
			return
		}
		p.havePortMappingOnce.Do(func() {
			address, ok := p.client.GetCachedMappingOrStartCreatingOne()
			if ok {
				p.deliver(address)
			} else {

				// This is not an expected case; there should be a port
				// mapping when the callback is invoked.
				portMappingLogger("unexpected missing port mapping")
				p.signalFailed()
			}
		})
	})

	// The port mapping attempt reports when it ends without a port mapping:
	// every port mapping service was asked, and each either refused or did
	// not answer.
	p.client.SetOnMappingOutcome(func(outcome portmapper.MappingOutcome) {
		if outcome != portmapper.MappingGranted {
			portMappingLogger("no port mapping: %v", outcome)
			p.signalFailed()
		}
	})

	p.client.SetLocalPort(uint16(localPort))

	return p, nil
}

// start initiates the port mapping attempt.
func (p *portMapper) start() {
	p.portMappingLogger("started")
	// There is no cached mapping at this point.
	_, _ = p.client.GetCachedMappingOrStartCreatingOne()
}

// deliver sends the port mapping external address to the
// portMappingExternalAddress channel, when the address is usable.
//
// A port mapping whose external address is not usable is not added to the
// SDP, and the receipt of a port mapping address ends the await for ICE
// candidate gathering. Such a port mapping is instead signaled as a failed
// attempt, so that ICE candidate gathering is awaited.
func (p *portMapper) deliver(address netip.AddrPort) {
	if !isUsablePortMappingIP(net.IP(address.Addr().Unmap().AsSlice())) {
		p.portMappingLogger("external address is not usable")
		p.signalFailed()
		return
	}
	// With sync.Once and a buffer size of 1, this send won't block.
	p.portMappingAddress <- address.String()
	p.portMappingLogger("address obtained")
}

// portMappingExternalAddress returns a channel which receives a successful
// port mapping external address, if any.
func (p *portMapper) portMappingExternalAddress() <-chan string {
	return p.portMappingAddress
}

// portMappingAttemptFailed returns a channel which is closed when the port
// mapping attempt has ended without a port mapping. No address will be
// received from portMappingExternalAddress after that.
func (p *portMapper) portMappingAttemptFailed() <-chan struct{} {
	return p.portMappingFailed
}

func (p *portMapper) signalFailed() {
	p.portMappingFailedOnce.Do(func() {
		close(p.portMappingFailed)
	})
}

// close releases the port mapping
func (p *portMapper) close() error {

	// A mapping create in progress at the time of the Close call releases
	// any mapping it goes on to obtain, rather than publishing it.

	err := p.client.Close()
	p.portMappingLogger("closed")
	return errors.Trace(err)
}

func formatPortMappingLog(format string, args ...any) string {
	truncatePrefix := "[v1] UPnP reply"
	if strings.HasPrefix(format, truncatePrefix) {
		// Omit packet portion of this log, but still log the event
		return truncatePrefix
	}
	return fmt.Sprintf(format, args...)
}

// PortMappingProbe records information about the port mapping services found
// in a port mapping service probe.
type PortMappingProbe struct {
	client *portmapper.Client

	// verified indicates that a port mapping service granted a trial port
	// mapping, with a usable external address, so port mappings are expected
	// to be established on this network.
	verified bool
}

// probePortMapping discovers and reports which port mapping protocols are
// supported on this network. probePortMapping caches a PortMappingProbe for
// use in subsequent port mapping establishment.
//
// A port mapping service that answers discovery does not necessarily grant
// port mappings; for example, some routers answer UPnP discovery with port
// mapping switched off. To find out, probePortMapping asks for a trial port
// mapping, to a local port reserved for the purpose, and releases it before
// returning. Port mapping types are reported only when the trial port mapping
// was granted, with a usable external address; see verifiedPortMappingTypes.
//
// It is intended that in-proxy proxies make a blocking call to
// probePortMapping on start up (and after a network change) in order to
// report fresh port mapping type metrics, for matching optimization in the
// ProxyAnnounce request.
//
// The port mapper's UPnP/NAT-PMP/PCP sockets are bound via
// coordinator.BindToDevice, which works on all platforms. The probe's
// BindToDevice and gateway lookup are inherited by the port mapping clients
// cloned from the probe.
func probePortMapping(
	ctx context.Context,
	logger common.Logger,
	coordinator WebRTCDialCoordinator) (PortMappingTypes, *PortMappingProbe, error) {

	portMappingLogger := func(format string, args ...any) {
		logger.WithTrace().Info(
			"port mapping probe: " + formatPortMappingLog(format, args...))
	}

	// Discover the gateway on the same interface the port mapping sockets are
	// bound to (coordinator.BindToDevice). In a split-interface in-proxy
	// proxy, that is the downstream interface, not the system default route --
	// binding sockets to the downstream interface while probing the
	// default-route (upstream) gateway would target the wrong router. An empty
	// interface name selects default-route discovery (the non-split and mobile
	// cases).
	gatewayInterfaceName := coordinator.BindToDeviceInterfaceName()

	client := portmapper.NewClient(portmapper.Config{
		Logf: portMappingLogger,
		GatewayLookupFunc: func() (gw, myIP netip.Addr, ok bool) {
			// TODO: use gateway.Candidates. This will require support for
			// multiple possible portmappings.
			return gateway.HomeRouterIP(gatewayInterfaceName)
		},
		BindToDevice: coordinator.BindToDevice,
	})

	// Verify runs Probe and then the trial port mapping.
	//
	// ErrGatewayRange is "skipping portmap; gateway range likely lacks
	// support". The probe did not fail, and no service will be reported as
	// granting a port mapping. Drop through and report PortMappingTypeNone
	// in this case. Currently, this is the only special case; and Probe
	// doesn't wrap this error with the type NoMappingError.

	verification, err := client.Verify(ctx)
	if err != nil && err != portmapper.ErrGatewayRange {
		return nil, nil, errors.Trace(err)
	}

	portMappingTypes := verifiedPortMappingTypes(verification)

	verified := len(portMappingTypes) > 0

	portMappingLogger(
		"UPnP %v, NAT-PMP %v, PCP %v, verified %v",
		verification.UPnP,
		verification.PMP,
		verification.PCP,
		verified)

	if !verified {

		// An empty lists means discovery is needed or the available port mappings
		// are unknown; a list with None indicates that no port mapping
		// type granted a usable trial port mapping.

		portMappingTypes = append(portMappingTypes, PortMappingTypeNone)
	}

	var probe *PortMappingProbe

	servicesFound := verification.UPnP != portmapper.ServiceNotSeen ||
		verification.PMP != portmapper.ServiceNotSeen ||
		verification.PCP != portmapper.ServiceNotSeen

	// A trial port mapping that was granted with an external address that
	// is not usable shows that this network's port mappings cannot be used.
	unusable := verification.Granted() && !verified

	if servicesFound && !unusable {

		// Return a probe for use in subsequent port mappings only when
		// services were found. This includes the case where the trial port
		// mapping was not granted, as that may be a temporary condition.
		//
		// Limitation: when the trial port mapping was not granted, a
		// subsequent successful port mapping does not update the reported
		// port mapping types or the verified flag, as one success does not
		// establish that port mappings are reliably granted.
		//
		// It is not necessary to call PortMappingProbe.client.Close, as it is
		// not holding open any actual mappings.

		probe = &PortMappingProbe{
			client:   client,
			verified: verified,
		}
	}

	return portMappingTypes, probe, nil
}

// verifiedPortMappingTypes returns the port mapping types to report for a
// network, given the result of its trial port mapping. No types are returned
// unless the trial port mapping was granted, with a usable external address.
//
// The type that granted the trial port mapping is first in the list. Once one
// type has granted it, the others are not asked, so the types that follow
// are those that answered discovery and are not known to grant port
// mappings. A type that refused the trial port mapping is omitted.
func verifiedPortMappingTypes(
	verification portmapper.Verification) PortMappingTypes {

	portMappingTypes := PortMappingTypes{}

	if !verification.Granted() ||
		!isUsablePortMappingIP(net.IP(verification.External.Unmap().AsSlice())) {

		return portMappingTypes
	}

	for _, service := range []struct {
		state           portmapper.ServiceState
		portMappingType PortMappingType
	}{
		{verification.UPnP, PortMappingTypeUPnP},
		{verification.PMP, PortMappingTypePMP},
		{verification.PCP, PortMappingTypePCP},
	} {
		switch service.state {
		case portmapper.ServiceGranted:
			portMappingTypes = append(
				PortMappingTypes{service.portMappingType}, portMappingTypes...)
		case portmapper.ServiceSeen:
			portMappingTypes = append(portMappingTypes, service.portMappingType)
		}
	}

	return portMappingTypes
}

// isUsablePortMappingIP indicates whether a port mapping with the specified
// external IP address is added to the SDP as an ICE candidate; see
// prepareSDPAddresses. A network whose port mappings are not added to the
// SDP is not reported as supporting port mapping.
func isUsablePortMappingIP(IP net.IP) bool {
	return IP != nil && IP.To4() != nil && !common.IsBogon(IP)
}
