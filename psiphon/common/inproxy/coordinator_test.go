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
	"net"
	"sync"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
)

type testBrokerDialCoordinator struct {
	mutex                             sync.Mutex
	networkID                         string
	networkType                       NetworkType
	commonCompartmentIDs              []ID
	personalCompartmentIDs            []ID
	disableWaitToShareSession         bool
	brokerClientPrivateKey            SessionPrivateKey
	brokerPublicKey                   SessionPublicKey
	brokerRootObfuscationSecret       ObfuscationSecret
	brokerClientRoundTripper          RoundTripper
	brokerClientRoundTripperSucceeded func(RoundTripper)
	brokerClientRoundTripperFailed    func(RoundTripper)
	brokerClientNoMatch               func(RoundTripper)
	metricsForBrokerRequests          common.LogFields
	sessionHandshakeRoundTripTimeout  time.Duration
	announceRequestTimeout            time.Duration
	announceDelay                     time.Duration
	announceMaxBackoffDelay           time.Duration
	announceDelayJitter               float64
	answerRequestTimeout              time.Duration
	offerRequestTimeout               time.Duration
	offerRequestPersonalTimeout       time.Duration
	offerRetryDelay                   time.Duration
	offerRetryJitter                  float64
	relayedPacketRequestTimeout       time.Duration
	dslRequestTimeout                 time.Duration
}

func (t *testBrokerDialCoordinator) NetworkID() string {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.networkID
}

func (t *testBrokerDialCoordinator) NetworkType() NetworkType {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.networkType
}

func (t *testBrokerDialCoordinator) CommonCompartmentIDs() []ID {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.commonCompartmentIDs
}

func (t *testBrokerDialCoordinator) PersonalCompartmentIDs() []ID {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.personalCompartmentIDs
}

func (t *testBrokerDialCoordinator) DisableWaitToShareSession() bool {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.disableWaitToShareSession
}

func (t *testBrokerDialCoordinator) BrokerClientPrivateKey() SessionPrivateKey {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.brokerClientPrivateKey
}

func (t *testBrokerDialCoordinator) BrokerPublicKey() SessionPublicKey {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.brokerPublicKey
}

func (t *testBrokerDialCoordinator) BrokerRootObfuscationSecret() ObfuscationSecret {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.brokerRootObfuscationSecret
}

func (t *testBrokerDialCoordinator) BrokerClientRoundTripper() (RoundTripper, error) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.brokerClientRoundTripper, nil
}

func (t *testBrokerDialCoordinator) BrokerClientRoundTripperSucceeded(roundTripper RoundTripper) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.brokerClientRoundTripperSucceeded(roundTripper)
}

func (t *testBrokerDialCoordinator) BrokerClientRoundTripperFailed(roundTripper RoundTripper) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.brokerClientRoundTripperFailed(roundTripper)
}

func (t *testBrokerDialCoordinator) BrokerClientNoMatch(roundTripper RoundTripper) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.brokerClientNoMatch(roundTripper)
}

func (t *testBrokerDialCoordinator) MetricsForBrokerRequests() common.LogFields {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.metricsForBrokerRequests
}

func (t *testBrokerDialCoordinator) SessionHandshakeRoundTripTimeout() time.Duration {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.sessionHandshakeRoundTripTimeout
}

func (t *testBrokerDialCoordinator) AnnounceRequestTimeout() time.Duration {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.announceRequestTimeout
}

func (t *testBrokerDialCoordinator) AnnounceDelay() time.Duration {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.announceDelay
}

func (t *testBrokerDialCoordinator) AnnounceMaxBackoffDelay() time.Duration {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.announceMaxBackoffDelay
}

func (t *testBrokerDialCoordinator) AnnounceDelayJitter() float64 {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.announceDelayJitter
}

func (t *testBrokerDialCoordinator) AnswerRequestTimeout() time.Duration {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.answerRequestTimeout
}

func (t *testBrokerDialCoordinator) OfferRequestTimeout() time.Duration {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.offerRequestTimeout
}

func (t *testBrokerDialCoordinator) OfferRequestPersonalTimeout() time.Duration {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.offerRequestPersonalTimeout
}

func (t *testBrokerDialCoordinator) OfferRetryDelay() time.Duration {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.offerRetryDelay
}

func (t *testBrokerDialCoordinator) OfferRetryJitter() float64 {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.offerRetryJitter
}

func (t *testBrokerDialCoordinator) RelayedPacketRequestTimeout() time.Duration {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.relayedPacketRequestTimeout
}

func (t *testBrokerDialCoordinator) DSLRequestTimeout() time.Duration {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.dslRequestTimeout
}

type testWebRTCDialCoordinator struct {
	mutex                           sync.Mutex
	networkID                       string
	networkType                     NetworkType
	clientRootObfuscationSecret     ObfuscationSecret
	doDTLSRandomization             bool
	useMediaStreams                 bool
	trafficShapingParameters        *TrafficShapingParameters
	stunServerAddress               string
	stunServerAddressRFC5780        string
	stunServerAddressSucceeded      func(RFC5780 bool, address string)
	stunServerAddressFailed         func(RFC5780 bool, address string)
	discoverNAT                     bool
	disableSTUN                     bool
	disablePortMapping              bool
	disableInboundForMobileNetworks bool
	disableIPv6ICECandidates        bool
	natType                         NATType
	setNATType                      func(NATType)
	portMappingTypes                PortMappingTypes
	portMappingProbe                *PortMappingProbe
	setPortMappingTypes             func(PortMappingTypes)
	bindToDevice                    func(int) error
	discoverNATTimeout              time.Duration
	webRTCAnswerTimeout             time.Duration
	webRTCAwaitPortMappingTimeout   time.Duration
	webRTCAwaitReadyToProxyTimeout  time.Duration
	proxyDestinationDialTimeout     time.Duration
	proxyRelayInactivityTimeout     time.Duration
}

func (t *testWebRTCDialCoordinator) NetworkID() string {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.networkID
}

func (t *testWebRTCDialCoordinator) NetworkType() NetworkType {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.networkType
}

func (t *testWebRTCDialCoordinator) ClientRootObfuscationSecret() ObfuscationSecret {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.clientRootObfuscationSecret
}

func (t *testWebRTCDialCoordinator) DoDTLSRandomization() bool {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.doDTLSRandomization
}

func (t *testWebRTCDialCoordinator) UseMediaStreams() bool {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.useMediaStreams
}

func (t *testWebRTCDialCoordinator) TrafficShapingParameters() *TrafficShapingParameters {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.trafficShapingParameters
}

func (t *testWebRTCDialCoordinator) STUNServerAddress(RFC5780 bool) string {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	if RFC5780 {
		return t.stunServerAddressRFC5780
	}
	return t.stunServerAddress
}

func (t *testWebRTCDialCoordinator) STUNServerAddressSucceeded(RFC5780 bool, address string) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.stunServerAddressSucceeded(RFC5780, address)
}

func (t *testWebRTCDialCoordinator) STUNServerAddressFailed(RFC5780 bool, address string) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.stunServerAddressFailed(RFC5780, address)
}

func (t *testWebRTCDialCoordinator) DiscoverNAT() bool {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.discoverNAT
}

func (t *testWebRTCDialCoordinator) DisableSTUN() bool {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.disableSTUN
}

func (t *testWebRTCDialCoordinator) DisablePortMapping() bool {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.disablePortMapping
}

func (t *testWebRTCDialCoordinator) DisableInboundForMobileNetworks() bool {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.disableInboundForMobileNetworks
}

func (t *testWebRTCDialCoordinator) DisableIPv6ICECandidates() bool {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.disableIPv6ICECandidates
}

func (t *testWebRTCDialCoordinator) NATType() NATType {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.natType
}

func (t *testWebRTCDialCoordinator) SetNATType(natType NATType) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.natType = natType
	t.setNATType(natType)
}

func (t *testWebRTCDialCoordinator) PortMappingTypes() PortMappingTypes {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.portMappingTypes
}

func (t *testWebRTCDialCoordinator) SetPortMappingTypes(portMappingTypes PortMappingTypes) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.portMappingTypes = append(PortMappingTypes{}, portMappingTypes...)
	t.setPortMappingTypes(portMappingTypes)
}

func (t *testWebRTCDialCoordinator) PortMappingProbe() *PortMappingProbe {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.portMappingProbe
}

func (t *testWebRTCDialCoordinator) SetPortMappingProbe(portMappingProbe *PortMappingProbe) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.portMappingProbe = portMappingProbe
}

func (t *testWebRTCDialCoordinator) ResolveAddress(ctx context.Context, network, address string) (string, error) {

	// Note: can't use common/resolver due to import cycle

	hostname, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", errors.Trace(err)
	}

	r := &net.Resolver{}
	IPs, err := r.LookupIP(ctx, network, hostname)
	if err != nil {
		return "", errors.Trace(err)
	}

	return net.JoinHostPort(IPs[0].String(), port), nil
}

// lossyConn randomly drops 1% of packets sent or received.
type lossyConn struct {
	net.PacketConn
}

func (conn *lossyConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, addr, err := conn.PacketConn.ReadFrom(p)
		if err != nil {
			return n, addr, err
		}
		if prng.FlipWeightedCoin(0.01) {
			// Drop packet
			continue
		}
		return n, addr, err
	}
}

func (conn *lossyConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if prng.FlipWeightedCoin(0.01) {
		// Drop packet
		return len(p), nil
	}
	return conn.PacketConn.WriteTo(p, addr)
}

// UDPListen wraps the returned net.PacketConn in lossyConn to simulate packet
// loss.
func (t *testWebRTCDialCoordinator) UDPListen(_ context.Context) (net.PacketConn, error) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, errors.Trace(err)
	}
	return &lossyConn{conn}, nil
}

// UDPConn wraps the returned net.PacketConn in lossyConn to simulate packet
// loss.
func (t *testWebRTCDialCoordinator) UDPConn(_ context.Context, network, remoteAddress string) (net.PacketConn, error) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	switch network {
	case "udp", "udp4", "udp6":
	default:
		return nil, errors.TraceNew("invalid network")
	}
	conn, err := net.Dial(network, remoteAddress)
	if err != nil {
		return nil, errors.Trace(err)
	}
	return &lossyConn{conn.(*net.UDPConn)}, nil
}

func (t *testWebRTCDialCoordinator) BindToDevice(fileDescriptor int) error {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return errors.Trace(t.bindToDevice(fileDescriptor))
}

func (t *testWebRTCDialCoordinator) ProxyUpstreamDial(ctx context.Context, network, address string) (net.Conn, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, errors.Trace(err)
	}
	return conn, nil
}

func (t *testWebRTCDialCoordinator) DiscoverNATTimeout() time.Duration {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.discoverNATTimeout
}

func (t *testWebRTCDialCoordinator) WebRTCAnswerTimeout() time.Duration {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.webRTCAnswerTimeout
}

func (t *testWebRTCDialCoordinator) WebRTCAwaitPortMappingTimeout() time.Duration {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.webRTCAwaitPortMappingTimeout
}

func (t *testWebRTCDialCoordinator) WebRTCAwaitReadyToProxyTimeout() time.Duration {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.webRTCAwaitReadyToProxyTimeout
}

func (t *testWebRTCDialCoordinator) ProxyDestinationDialTimeout() time.Duration {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.proxyDestinationDialTimeout
}

func (t *testWebRTCDialCoordinator) ProxyRelayInactivityTimeout() time.Duration {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.proxyRelayInactivityTimeout
}
