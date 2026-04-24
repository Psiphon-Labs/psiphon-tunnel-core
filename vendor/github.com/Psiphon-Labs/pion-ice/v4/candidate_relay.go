// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ice

import (
	"net"
	"net/netip"
)

const (
	// These preference values come from libwebrtc
	//nolint:lll
	// https://source.chromium.org/chromium/chromium/src/+/main:third_party/webrtc/p2p/base/p2p_constants.h;l=126;drc=bf712ec1a13783224debb691ba88ad5c15b93194
	preferenceRelayTLS  = 0
	preferenceRelayTCP  = 1
	preferenceRelayDTLS = 2
	preferenceRelayUDP  = 3
)

// CandidateRelay ...
type CandidateRelay struct {
	candidateBase

	relayProtocol string
	onClose       func() error
}

// CandidateRelayConfig is the config required to create a new CandidateRelay.
type CandidateRelayConfig struct {
	CandidateID   string
	Network       string
	Address       string
	Port          int
	Component     uint16
	Priority      uint32
	Foundation    string
	RelAddr       string
	RelPort       int
	RelayProtocol string
	OnClose       func() error
}

// NewCandidateRelay creates a new relay candidate.
func NewCandidateRelay(config *CandidateRelayConfig) (*CandidateRelay, error) {
	candidateID := config.CandidateID

	if candidateID == "" {
		candidateID = globalCandidateIDGenerator.Generate()
	}

	ipAddr, err := netip.ParseAddr(config.Address)
	if err != nil {
		return nil, err
	}

	networkType, err := determineNetworkType(config.Network, ipAddr)
	if err != nil {
		return nil, err
	}

	return &CandidateRelay{
		candidateBase: candidateBase{
			id:            candidateID,
			networkType:   networkType,
			candidateType: CandidateTypeRelay,
			address:       config.Address,
			port:          config.Port,
			resolvedAddr: &net.UDPAddr{
				IP:   ipAddr.AsSlice(),
				Port: config.Port,
				Zone: ipAddr.Zone(),
			},
			component:          config.Component,
			foundationOverride: config.Foundation,
			priorityOverride:   config.Priority,
			relatedAddress: &CandidateRelatedAddress{
				Address: config.RelAddr,
				Port:    config.RelPort,
			},
			relayLocalPreference:  relayProtocolPreference(config.RelayProtocol),
			remoteCandidateCaches: map[AddrPort]Candidate{},
		},
		relayProtocol: config.RelayProtocol,
		onClose:       config.OnClose,
	}, nil
}

// RelayProtocol returns the protocol used between the endpoint and the relay server.
func (c *CandidateRelay) RelayProtocol() string {
	return c.relayProtocol
}

func (c *CandidateRelay) close() error {
	err := c.candidateBase.close()
	if c.onClose != nil {
		err = c.onClose()
		c.onClose = nil
	}

	return err
}

func (c *CandidateRelay) copy() (Candidate, error) {
	cc, err := c.candidateBase.copy()
	if err != nil {
		return nil, err
	}

	if ccr, ok := cc.(*CandidateRelay); ok {
		ccr.relayProtocol = c.relayProtocol
	}

	return cc, nil
}

// relayProtocolPreference returns the preference for the relay protocol.
func relayProtocolPreference(relayProtocol string) uint16 {
	switch relayProtocol {
	case relayProtocolTLS:
		return preferenceRelayTLS
	case tcp:
		return preferenceRelayTCP
	case relayProtocolDTLS:
		return preferenceRelayDTLS
	default:
		return preferenceRelayUDP
	}
}
