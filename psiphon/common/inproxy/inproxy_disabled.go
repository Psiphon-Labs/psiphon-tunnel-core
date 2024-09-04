//go:build !PSIPHON_ENABLE_INPROXY

/*
 * Copyright (c) 2024, Psiphon Inc.
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
	std_errors "errors"
	"net"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
)

// The inproxy package has a broad API that referenced throughout the psiphon
// and psiphon/server packages.
//
// When PSIPHON_ENABLE_INPROXY is not specified, inproxy components are
// disabled and large dependencies, including pion and tailscale, are not
// referenced and excluded from builds. The stub types and functions here are
// sufficient to omit all pion and tailscale references. The remaining, broad
// inproxy API surface is not stubbed out.
//
// Client/proxy and server/broker integrations in psiphon and psiphon/server
// should all check inproxy.Enabled and, when false, skip or fail early
// before trying to use inproxy components.

// Enabled indicates if in-proxy functionality is enabled.
func Enabled() bool {
	return false
}

var errNotEnabled = std_errors.New("operation not enabled")

const (
	dataChannelAwaitTimeout = time.Duration(0)
)

type webRTCConn struct {
}

type webRTCConfig struct {
	Logger                      common.Logger
	EnableDebugLogging          bool
	WebRTCDialCoordinator       WebRTCDialCoordinator
	ClientRootObfuscationSecret ObfuscationSecret
	DoDTLSRandomization         bool
	TrafficShapingParameters    *DataChannelTrafficShapingParameters
	ReliableTransport           bool
}

func (conn *webRTCConn) SetRemoteSDP(
	peerSDP WebRTCSessionDescription,
	hasPersonalCompartmentIDs bool) error {

	return errors.Trace(errNotEnabled)
}

// AwaitInitialDataChannel returns when the data channel is established, or
// when an error has occured.
func (conn *webRTCConn) AwaitInitialDataChannel(ctx context.Context) error {
	return errors.Trace(errNotEnabled)
}

func (conn *webRTCConn) Close() error {
	return errors.Trace(errNotEnabled)
}

func (conn *webRTCConn) IsClosed() bool {
	return false
}

func (conn *webRTCConn) Read(p []byte) (int, error) {
	return 0, errors.Trace(errNotEnabled)
}

func (conn *webRTCConn) Write(p []byte) (int, error) {
	return 0, errors.Trace(errNotEnabled)
}

func (conn *webRTCConn) LocalAddr() net.Addr {
	return nil
}

func (conn *webRTCConn) RemoteAddr() net.Addr {
	return nil
}

func (conn *webRTCConn) SetDeadline(t time.Time) error {
	return errors.Trace(errNotEnabled)
}

func (conn *webRTCConn) SetReadDeadline(t time.Time) error {
	return errors.Trace(errNotEnabled)
}

func (conn *webRTCConn) SetWriteDeadline(t time.Time) error {
	return errors.Trace(errNotEnabled)
}

func (conn *webRTCConn) GetMetrics() common.LogFields {
	return nil
}

type webRTCSDPMetrics struct {
	iceCandidateTypes     []ICECandidateType
	hasIPv6               bool
	hasPrivateIP          bool
	filteredICECandidates []string
}

func newWebRTCConnWithOffer(
	ctx context.Context,
	config *webRTCConfig,
	hasPersonalCompartmentIDs bool) (
	*webRTCConn, WebRTCSessionDescription, *webRTCSDPMetrics, error) {
	return nil, WebRTCSessionDescription{}, nil, errors.Trace(errNotEnabled)
}

func newWebRTCConnWithAnswer(
	ctx context.Context,
	config *webRTCConfig,
	peerSDP WebRTCSessionDescription,
	hasPersonalCompartmentIDs bool) (
	*webRTCConn, WebRTCSessionDescription, *webRTCSDPMetrics, error) {

	return nil, WebRTCSessionDescription{}, nil, errors.Trace(errNotEnabled)
}

func filterSDPAddresses(
	encodedSDP []byte,
	errorOnNoCandidates bool,
	lookupGeoIP LookupGeoIP,
	expectedGeoIPData common.GeoIPData,
	allowPrivateIPAddressCandidates bool,
	filterPrivateIPAddressCandidates bool) ([]byte, *webRTCSDPMetrics, error) {
	return nil, nil, errors.Trace(errNotEnabled)
}

func initPortMapper(coordinator WebRTCDialCoordinator) {
}

func probePortMapping(
	ctx context.Context,
	logger common.Logger) (PortMappingTypes, error) {

	return nil, errors.Trace(errNotEnabled)
}

func discoverNATMapping(
	ctx context.Context,
	conn net.PacketConn,
	serverAddress string) (NATMapping, error) {

	return NATMappingUnknown, errors.Trace(errNotEnabled)
}

func discoverNATFiltering(
	ctx context.Context,
	conn net.PacketConn,
	serverAddress string) (NATFiltering, error) {

	return NATFilteringUnknown, errors.Trace(errNotEnabled)
}
