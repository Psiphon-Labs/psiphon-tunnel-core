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
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/stacktrace"
)

type testBrokerDialCoordinator struct {
	mutex                             sync.Mutex
	networkID                         string
	networkType                       NetworkType
	commonCompartmentIDs              []ID
	personalCompartmentIDs            []ID
	brokerClientPrivateKey            SessionPrivateKey
	brokerPublicKey                   SessionPublicKey
	brokerRootObfuscationSecret       ObfuscationSecret
	brokerClientRoundTripper          RoundTripper
	brokerClientRoundTripperSucceeded func(RoundTripper)
	brokerClientRoundTripperFailed    func(RoundTripper)
	sessionHandshakeRoundTripTimeout  time.Duration
	announceRequestTimeout            time.Duration
	announceDelay                     time.Duration
	announceDelayJitter               float64
	answerRequestTimeout              time.Duration
	offerRequestTimeout               time.Duration
	offerRetryDelay                   time.Duration
	offerRetryJitter                  float64
	relayedPacketRequestTimeout       time.Duration
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

type testWebRTCDialCoordinator struct {
	mutex                           sync.Mutex
	networkID                       string
	networkType                     NetworkType
	clientRootObfuscationSecret     ObfuscationSecret
	doDTLSRandomization             bool
	trafficShapingParameters        *DataChannelTrafficShapingParameters
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
	setPortMappingTypes             func(PortMappingTypes)
	bindToDevice                    func(int) error
	discoverNATTimeout              time.Duration
	webRTCAnswerTimeout             time.Duration
	webRTCAwaitDataChannelTimeout   time.Duration
	proxyDestinationDialTimeout     time.Duration
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

func (t *testWebRTCDialCoordinator) DataChannelTrafficShapingParameters() *DataChannelTrafficShapingParameters {
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

func (t *testWebRTCDialCoordinator) UDPListen(_ context.Context) (net.PacketConn, error) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	conn, err := net.ListenUDP("udp", nil)
	return conn, errors.Trace(err)
}

func (t *testWebRTCDialCoordinator) UDPConn(_ context.Context, network, remoteAddress string) (net.PacketConn, error) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	switch network {
	case "udp", "udp4", "udp6":
	default:
		return nil, errors.TraceNew("invalid network")
	}
	conn, err := net.Dial(network, remoteAddress)
	return conn.(*net.UDPConn), errors.Trace(err)
}

func (t *testWebRTCDialCoordinator) BindToDevice(fileDescriptor int) error {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return errors.Trace(t.bindToDevice(fileDescriptor))
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

func (t *testWebRTCDialCoordinator) WebRTCAwaitDataChannelTimeout() time.Duration {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.webRTCAwaitDataChannelTimeout
}

func (t *testWebRTCDialCoordinator) ProxyDestinationDialTimeout() time.Duration {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.proxyDestinationDialTimeout
}

type testLogger struct {
	logLevelDebug int32
}

func newTestLogger() *testLogger {
	return &testLogger{logLevelDebug: 1}
}

func (logger *testLogger) WithTrace() common.LogTrace {
	return &testLoggerTrace{
		logger: logger,
		trace:  stacktrace.GetParentFunctionName(),
	}
}

func (logger *testLogger) WithTraceFields(fields common.LogFields) common.LogTrace {
	return &testLoggerTrace{
		logger: logger,
		trace:  stacktrace.GetParentFunctionName(),
		fields: fields,
	}
}

func (logger *testLogger) LogMetric(metric string, fields common.LogFields) {
	jsonFields, _ := json.Marshal(fields)
	fmt.Printf(
		"[%s] METRIC: %s: %s\n",
		time.Now().UTC().Format(time.RFC3339),
		metric,
		string(jsonFields))
}

func (logger *testLogger) IsLogLevelDebug() bool {
	return atomic.LoadInt32(&logger.logLevelDebug) == 1
}

func (logger *testLogger) SetLogLevelDebug(logLevelDebug bool) {
	value := int32(0)
	if logLevelDebug {
		value = 1
	}
	atomic.StoreInt32(&logger.logLevelDebug, value)
}

type testLoggerTrace struct {
	logger *testLogger
	trace  string
	fields common.LogFields
}

func (logger *testLoggerTrace) log(priority, message string) {
	now := time.Now().UTC().Format(time.RFC3339)
	if len(logger.fields) == 0 {
		fmt.Printf(
			"[%s] %s: %s: %s\n",
			now, priority, logger.trace, message)
	} else {
		fields := common.LogFields{}
		for k, v := range logger.fields {
			switch v := v.(type) {
			case error:
				// Workaround for Go issue 5161: error types marshal to "{}"
				fields[k] = v.Error()
			default:
				fields[k] = v
			}
		}
		jsonFields, _ := json.Marshal(fields)
		fmt.Printf(
			"[%s] %s: %s: %s %s\n",
			now, priority, logger.trace, message, string(jsonFields))
	}
}

func (logger *testLoggerTrace) Debug(args ...interface{}) {
	if !logger.logger.IsLogLevelDebug() {
		return
	}
	logger.log("DEBUG", fmt.Sprint(args...))
}

func (logger *testLoggerTrace) Info(args ...interface{}) {
	logger.log("INFO", fmt.Sprint(args...))
}

func (logger *testLoggerTrace) Warning(args ...interface{}) {
	logger.log("WARNING", fmt.Sprint(args...))
}

func (logger *testLoggerTrace) Error(args ...interface{}) {
	logger.log("ERROR", fmt.Sprint(args...))
}
