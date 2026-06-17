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
	havePortMappingOnce sync.Once
	portMappingAddress  chan string
	client              *portmapper.Client
	portMappingLogger   func(format string, args ...any)
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
		portMappingLogger:  portMappingLogger,
	}

	// Clone the probe's client, reusing its port mapping service discovery
	// (probe-once / map-many). Clone is a proper fork API and replaces the
	// previous unsafe-reflection copy of the dependency's unexported fields.
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
				// With sync.Once and a buffer size of 1, this send won't block.
				p.portMappingAddress <- address.String()
				portMappingLogger("address obtained")
			} else {

				// This is not an expected case; there should be a port
				// mapping when the callback is invoked.
				//
				// TODO: deliver "" to the channel? Otherwise, receiving on
				// portMapper.portMappingExternalAddress will hang, or block
				// until a context is done.
				portMappingLogger("unexpected missing port mapping")
			}
		})
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

// portMappingExternalAddress returns a channel which receives a successful
// port mapping external address, if any.
func (p *portMapper) portMappingExternalAddress() <-chan string {
	return p.portMappingAddress
}

// respondingPortMappingTypes returns the port mapping types that have
// responded recently for this port mapper's client. It is used for reporting
// metrics, and replaces the previous approach of scraping
// tailscale.com/net/portmapper process-global metrics counters.
//
// Limitation: the return value does not indicate which of several responding
// port mapping types was used for a particular dial.
func (p *portMapper) respondingPortMappingTypes() PortMappingTypes {
	upnp, pmp, pcp := p.client.RespondingPortMappingTypes()
	portMappingTypes := PortMappingTypes{}
	if upnp {
		portMappingTypes = append(portMappingTypes, PortMappingTypeUPnP)
	}
	if pmp {
		portMappingTypes = append(portMappingTypes, PortMappingTypePMP)
	}
	if pcp {
		portMappingTypes = append(portMappingTypes, PortMappingTypePCP)
	}
	return portMappingTypes
}

// close releases the port mapping
func (p *portMapper) close() error {

	// TODO: it's not clear whether a concurrent createOrGetMapping, in
	// progress at the time of the Close call, will dispose of any created
	// mapping if it completes after Close.

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
}

// probePortMapping discovers and reports which port mapping protocols are
// supported on this network. probePortMapping does not establish a port
// mapping. probePortMapping caches a PortMappingProbe for use in subsequent
// port mapping establishment.
//
// It is intended that in-proxy proxies make a blocking call to
// probePortMapping on start up (and after a network change) in order to
// report fresh port mapping type metrics, for matching optimization in the
// ProxyAnnounce request.
//
// The port mapper's UPnP/NAT-PMP/PCP sockets are bound via
// coordinator.BindToDevice, which works on all platforms; this replaces the
// previous process-global, Android-only netns.SetAndroidProtectFunc hook. The
// probe's BindToDevice and gateway lookup are inherited by the port mapping
// clients cloned from the probe.
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
			return gateway.HomeRouterIP(gatewayInterfaceName)
		},
		BindToDevice: coordinator.BindToDevice,
	})

	// ErrGatewayRange is "skipping portmap; gateway range likely lacks
	// support". The probe did not fail, and the result fields will all be
	// false. Drop through and report PortMappingTypeNone in this case.
	// Currently, this is the only special case; and Probe doesn't wrap this
	// error with the type NoMappingError.

	result, err := client.Probe(ctx)
	if err != nil && err != portmapper.ErrGatewayRange {
		return nil, nil, errors.Trace(err)
	}

	portMappingTypes := PortMappingTypes{}
	if result.UPnP {
		portMappingTypes = append(portMappingTypes, PortMappingTypeUPnP)
	}
	if result.PMP {
		portMappingTypes = append(portMappingTypes, PortMappingTypePMP)
	}
	if result.PCP {
		portMappingTypes = append(portMappingTypes, PortMappingTypePCP)
	}

	var probe *PortMappingProbe

	if len(portMappingTypes) == 0 {

		// An empty lists means discovery is needed or the available port mappings
		// are unknown; a list with None indicates that a probe returned no
		// supported port mapping types.

		portMappingTypes = append(portMappingTypes, PortMappingTypeNone)

	} else {

		// Return a probe for use in subsequent port mappings only when
		// services were found.
		//
		// It is not necessary to call PortMappingProbe.client.Close, as it is
		// not holding open any actual mappings.

		probe = &PortMappingProbe{
			client: client,
		}
	}

	return portMappingTypes, probe, nil
}
