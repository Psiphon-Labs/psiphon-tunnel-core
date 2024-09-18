//go:build PSIPHON_ENABLE_INPROXY

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
	"strings"
	"sync"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"tailscale.com/net/portmapper"
	"tailscale.com/util/clientmetric"
)

// initPortMapper resets port mapping metrics state associated with the
// current network when the network changes, as indicated by
// WebRTCDialCoordinator.NetworkID. initPortMapper also configures the port
// mapping routines to use WebRTCDialCoordinator.BindToDevice. Varying
// WebRTCDialCoordinator.BindToDevice between dials in a single process is not
// supported.
func initPortMapper(coordinator WebRTCDialCoordinator) {

	// It's safe for multiple, concurrent client dials to call
	// resetRespondingPortMappingTypes: as long as the network ID does not
	// change, calls won't clear any valid port mapping type metrics that
	// were just recorded.
	resetRespondingPortMappingTypes(coordinator.NetworkID())

	// WebRTCDialCoordinator.BindToDevice is set as a global variable in
	// tailscale.com/net/portmapper. It's safe to repeatedly call
	// setPortMapperBindToDevice here, under the assumption that
	// WebRTCDialCoordinator.BindToDevice is the same single, static function
	// for all dials. This assumption is true for Psiphon.
	setPortMapperBindToDevice(coordinator)
}

// portMapper represents a UDP port mapping from a local port to an external,
// publicly addressable IP and port. Port mapping is implemented using
// tailscale.com/net/portmapper, which probes the local network and gateway
// for UPnP-IGD, NAT-PMP, and PCP port mapping capabilities.
type portMapper struct {
	havePortMappingOnce sync.Once
	portMappingAddress  chan string
	client              *portmapper.Client
	portMappingLogger   func(format string, args ...any)
}

// newPortMapper initializes a new port mapper, configured to map to the
// specified localPort. newPortMapper does not initiate any network
// operations (it's safe to call when DisablePortMapping is set).
func newPortMapper(
	logger common.Logger,
	localPort int) *portMapper {

	portMappingLogger := func(format string, args ...any) {
		logger.WithTrace().Info(
			"port mapping: " + formatPortMappingLog(format, args...))
	}

	p := &portMapper{
		portMappingAddress: make(chan string, 1),
		portMappingLogger:  portMappingLogger,
	}

	// This code assumes assumes tailscale NewClient call does only
	// initialization; this is the case as of tailscale.com/net/portmapper
	// v1.36.2.
	//
	// This code further assumes that the onChanged callback passed to
	// NewClient will not be invoked until after the
	// GetCachedMappingOrStartCreatingOne call in portMapper.start; and so
	// the p.client reference within callback will be valid.

	client := portmapper.NewClient(portMappingLogger, nil, nil, nil, func() {
		p.havePortMappingOnce.Do(func() {
			address, ok := p.client.GetCachedMappingOrStartCreatingOne()
			if ok {
				// With sync.Once and a buffer size of 1, this send won't block.
				p.portMappingAddress <- address.String()
				portMappingLogger("address obtained")
			} else {

				// This is not an expected case; there should be a port
				// mapping when NewClient is invoked.
				//
				// TODO: deliver "" to the channel? Otherwise, receiving on
				// portMapper.portMappingExternalAddress will hang, or block
				// until a context is done.
				portMappingLogger("unexpected missing port mapping")
			}
		})
	})

	p.client = client

	p.client.SetLocalPort(uint16(localPort))

	return p
}

// start initiates the port mapping attempt.
func (p *portMapper) start() {
	p.portMappingLogger("started")
	_, _ = p.client.GetCachedMappingOrStartCreatingOne()
}

// portMappingExternalAddress returns a channel which receives a successful
// port mapping external address, if any.
func (p *portMapper) portMappingExternalAddress() <-chan string {
	return p.portMappingAddress
}

// close releases the port mapping
func (p *portMapper) close() error {
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

// probePortMapping discovers and reports which port mapping protocols are
// supported on this network. probePortMapping does not establish a port mapping.
//
// It is intended that in-proxies amake a blocking call to probePortMapping on
// start up (and after a network change) in order to report fresh port
// mapping type metrics, for matching optimization in the ProxyAnnounce
// request. Clients don't incur the delay of a probe call -- which produces
// no port mapping -- and instead opportunistically grab port mapping type
// metrics via getRespondingPortMappingTypes.
func probePortMapping(
	ctx context.Context,
	logger common.Logger) (PortMappingTypes, error) {

	portMappingLogger := func(format string, args ...any) {
		logger.WithTrace().Info(
			"port mapping probe: " + formatPortMappingLog(format, args...))
	}

	client := portmapper.NewClient(portMappingLogger, nil, nil, nil, nil)
	defer client.Close()

	result, err := client.Probe(ctx)
	if err != nil {
		return nil, errors.Trace(err)
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

	// An empty lists means discovery is needed or the available port mappings
	// are unknown; a list with None indicates that a probe returned no
	// supported port mapping types.

	if len(portMappingTypes) == 0 {
		portMappingTypes = append(portMappingTypes, PortMappingTypeNone)
	}

	return portMappingTypes, nil
}

var respondingPortMappingTypesMutex sync.Mutex
var respondingPortMappingTypesNetworkID string

// resetRespondingPortMappingTypes clears tailscale.com/net/portmapper global
// metrics fields which indicate which port mapping types are responding on
// the current network. These metrics should be cleared whenever the current
// network changes, as indicated by networkID.
//
// Limitations: there may be edge conditions where a
// tailscale.com/net/portmapper client logs metrics concurrent to
// resetRespondingPortMappingTypes being called with a new networkID. If
// incorrect port mapping type metrics are supported, the Broker may log
// incorrect statistics. However, Broker client/in-proxy matching is based on
// actually established port mappings.
func resetRespondingPortMappingTypes(networkID string) {

	respondingPortMappingTypesMutex.Lock()
	defer respondingPortMappingTypesMutex.Unlock()

	if respondingPortMappingTypesNetworkID != networkID {
		// Iterating over all metric fields appears to be the only API available.
		for _, metric := range clientmetric.Metrics() {
			switch metric.Name() {
			case "portmap_upnp_ok", "portmap_pmp_ok", "portmap_pcp_ok":
				metric.Set(0)
			}
		}
		respondingPortMappingTypesNetworkID = networkID
	}
}

// getRespondingPortMappingTypes returns the port mapping types that responded
// during recent portMapper.start invocations as well as probePortMapping
// invocations. The returned list is used for reporting metrics. See
// resetRespondingPortMappingTypes for considerations due to accessing
// tailscale.com/net/portmapper global metrics fields.
//
// To avoid delays, we do not run probePortMapping for regular client dials,
// and so instead use this tailscale.com/net/portmapper metrics field
// approach.
//
// Limitations: the return value represents all port mapping types that
// responded in this session, since the last network change
// (resetRespondingPortMappingTypes call); and do not indicate which of
// several port mapping types may have been used for a particular dial.
func getRespondingPortMappingTypes(networkID string) PortMappingTypes {

	respondingPortMappingTypesMutex.Lock()
	defer respondingPortMappingTypesMutex.Unlock()

	portMappingTypes := PortMappingTypes{}

	if respondingPortMappingTypesNetworkID != networkID {
		// The network changed since the last resetRespondingPortMappingTypes
		// call, and resetRespondingPortMappingTypes has not yet been called
		// again. Ignore the current metrics.
		return portMappingTypes
	}

	// Iterating over all metric fields appears to be the only API available.
	for _, metric := range clientmetric.Metrics() {
		if metric.Name() == "portmap_upnp_ok" && metric.Value() > 1 {
			portMappingTypes = append(portMappingTypes, PortMappingTypeUPnP)
		}
		if metric.Name() == "portmap_pmp_ok" && metric.Value() > 1 {
			portMappingTypes = append(portMappingTypes, PortMappingTypePMP)
		}
		if metric.Name() == "portmap_pcp_ok" && metric.Value() > 1 {
			portMappingTypes = append(portMappingTypes, PortMappingTypePCP)
		}
	}
	return portMappingTypes
}
