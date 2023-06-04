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

type testDialParameters struct {
	mutex                             sync.Mutex
	commonCompartmentIDs              []ID
	personalCompartmentIDs            []ID
	networkID                         string
	networkType                       NetworkType
	brokerClientPrivateKey            SessionPrivateKey
	brokerPublicKey                   SessionPublicKey
	brokerRootObfuscationSecret       ObfuscationSecret
	brokerClientRoundTripper          RoundTripper
	brokerClientRoundTripperSucceeded func(RoundTripper)
	brokerClientRoundTripperFailed    func(RoundTripper)
	clientRootObfuscationSecret       ObfuscationSecret
	doDTLSRandomization               bool
	trafficShapingParameters          *DataChannelTrafficShapingParameters
	stunServerAddress                 string
	stunServerAddressRFC5780          string
	stunServerAddressSucceeded        func(RFC5780 bool, address string)
	stunServerAddressFailed           func(RFC5780 bool, address string)
	discoverNAT                       bool
	disableSTUN                       bool
	disablePortMapping                bool
	disableInboundForMobleNetworks    bool
	natType                           NATType
	setNATType                        func(NATType)
	portMappingTypes                  PortMappingTypes
	setPortMappingTypes               func(PortMappingTypes)
	bindToDevice                      func(int) error
	discoverNATTimeout                time.Duration
	offerRequestTimeout               time.Duration
	offerRetryDelay                   time.Duration
	offerRetryJitter                  float64
	announceRequestTimeout            time.Duration
	announceRetryDelay                time.Duration
	announceRetryJitter               float64
	webRTCAnswerTimeout               time.Duration
	answerRequestTimeout              time.Duration
	proxyClientConnectTimeout         time.Duration
	proxyDestinationDialTimeout       time.Duration
}

func (t *testDialParameters) CommonCompartmentIDs() []ID {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.commonCompartmentIDs
}

func (t *testDialParameters) PersonalCompartmentIDs() []ID {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.personalCompartmentIDs
}

func (t *testDialParameters) NetworkID() string {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.networkID
}

func (t *testDialParameters) NetworkType() NetworkType {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.networkType
}

func (t *testDialParameters) BrokerClientPrivateKey() SessionPrivateKey {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.brokerClientPrivateKey
}

func (t *testDialParameters) BrokerPublicKey() SessionPublicKey {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.brokerPublicKey
}

func (t *testDialParameters) BrokerRootObfuscationSecret() ObfuscationSecret {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.brokerRootObfuscationSecret
}

func (t *testDialParameters) BrokerClientRoundTripper() (RoundTripper, error) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.brokerClientRoundTripper, nil
}

func (t *testDialParameters) BrokerClientRoundTripperSucceeded(roundTripper RoundTripper) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.brokerClientRoundTripperSucceeded(roundTripper)
}

func (t *testDialParameters) BrokerClientRoundTripperFailed(roundTripper RoundTripper) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.brokerClientRoundTripperFailed(roundTripper)
}

func (t *testDialParameters) ClientRootObfuscationSecret() ObfuscationSecret {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.clientRootObfuscationSecret
}

func (t *testDialParameters) DoDTLSRandomization() bool {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.doDTLSRandomization
}

func (t *testDialParameters) DataChannelTrafficShapingParameters() *DataChannelTrafficShapingParameters {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.trafficShapingParameters
}

func (t *testDialParameters) STUNServerAddress(RFC5780 bool) string {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	if RFC5780 {
		return t.stunServerAddressRFC5780
	}
	return t.stunServerAddress
}

func (t *testDialParameters) STUNServerAddressSucceeded(RFC5780 bool, address string) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.stunServerAddressSucceeded(RFC5780, address)
}

func (t *testDialParameters) STUNServerAddressFailed(RFC5780 bool, address string) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.stunServerAddressFailed(RFC5780, address)
}

func (t *testDialParameters) DiscoverNAT() bool {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.discoverNAT
}

func (t *testDialParameters) DisableSTUN() bool {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.disableSTUN
}

func (t *testDialParameters) DisablePortMapping() bool {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.disablePortMapping
}

func (t *testDialParameters) DisableInboundForMobleNetworks() bool {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.disableInboundForMobleNetworks
}

func (t *testDialParameters) NATType() NATType {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.natType
}

func (t *testDialParameters) SetNATType(natType NATType) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.natType = natType
	t.setNATType(natType)
}

func (t *testDialParameters) PortMappingTypes() PortMappingTypes {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.portMappingTypes
}

func (t *testDialParameters) SetPortMappingTypes(portMappingTypes PortMappingTypes) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.portMappingTypes = append(PortMappingTypes{}, portMappingTypes...)
	t.setPortMappingTypes(portMappingTypes)
}

func (t *testDialParameters) ResolveAddress(ctx context.Context, address string) (string, error) {
	// No hostnames are resolved in the test.
	return address, nil
}

func (t *testDialParameters) UDPListen() (net.PacketConn, error) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	conn, err := net.ListenUDP("udp", nil)
	return conn, errors.Trace(err)
}

func (t *testDialParameters) BindToDevice(fileDescriptor int) error {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return errors.Trace(t.bindToDevice(fileDescriptor))
}

func (t *testDialParameters) DiscoverNATTimeout() time.Duration {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.discoverNATTimeout
}

func (t *testDialParameters) OfferRequestTimeout() time.Duration {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.offerRequestTimeout
}

func (t *testDialParameters) OfferRetryDelay() time.Duration {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.offerRetryDelay
}

func (t *testDialParameters) OfferRetryJitter() float64 {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.offerRetryJitter
}

func (t *testDialParameters) AnnounceRequestTimeout() time.Duration {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.announceRequestTimeout
}

func (t *testDialParameters) AnnounceRetryDelay() time.Duration {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.announceRetryDelay
}

func (t *testDialParameters) AnnounceRetryJitter() float64 {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.announceRetryJitter
}

func (t *testDialParameters) WebRTCAnswerTimeout() time.Duration {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.webRTCAnswerTimeout
}

func (t *testDialParameters) AnswerRequestTimeout() time.Duration {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.answerRequestTimeout
}

func (t *testDialParameters) ProxyClientConnectTimeout() time.Duration {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.proxyClientConnectTimeout
}

func (t *testDialParameters) ProxyDestinationDialTimeout() time.Duration {
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
