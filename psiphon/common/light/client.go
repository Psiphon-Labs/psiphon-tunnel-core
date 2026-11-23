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

package light

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/obfuscator"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/quic"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/transforms"
)

const (
	// Matches default parameters.LightProxyInactivityTimeout
	clientInactivityTimeout = 2 * time.Minute

	// NoInactivityTimeout disables the client read inactivity timeout.
	NoInactivityTimeout time.Duration = -1
)

// TCPDialer is a callback that dials a TCP connection. The dialer allows for
// integrating Psiphon features including BindToDevice support, optional
// custom DNS resolver, and BPF.
type TCPDialer func(
	ctx context.Context, addr string) (net.Conn, error)

// ClientTLSDialer is a callback that dials a TLS connection over the provided
// underlying TCP connection. The dialer allows for integrating Psiphon features
// including utls, passthrough, public-key pin verification, session caching,
// and replay.
//
// The specified tlsProfile must be a utls TLS 1.3 ClientHello parrot
// fingerprint, or a randomized fingerprint that produces a TLS 1.3
// ClientHello with the given randomizedTLSProfileSeed.
//
// dialAddress is the proxy entry dial address used for underlyingConn, which
// may differ from the connected address, and is suitable for use as a TLS
// session cache key.
type ClientTLSDialer func(
	ctx context.Context,
	underlyingConn net.Conn,
	dialAddress string,
	tlsProfile string,
	randomizedTLSProfileSeed *prng.Seed,
	sni string,
	fragmentClientHello bool,
	tlsPadding int,
	passthroughMessage []byte,
	verifyPin string) (net.Conn, error)

// ClientQUICDialer establishes a QUIC connection to the Light proxy.
// The dialer allows for integrating Psiphon obfuscation features.
type ClientQUICDialer func(
	ctx context.Context,
	address string,
	sni string,
	quicVersion string,
	clientHelloSeed *prng.Seed,
	obfuscatedQUICPaddingSeed *prng.Seed,
	obfuscatedQUICNonceTransformerParameters *transforms.ObfuscatorSeedTransformerParameters,
	disablePathMTUDiscovery bool,
	obfuscationKey string,
	verifyPin string) (net.Conn, error)

// ClientConfig specifies the configuration of a light proxy client.
type ClientConfig struct {
	// Logger emits client events and must be non-nil.
	Logger common.Logger

	// EmitNetworkParameters indicates whether logged client events include
	// network parameters, such as the SNI and TLS profile. When nil, network
	// parameters are not logged.
	EmitNetworkParameters func() bool

	// TCPDialer establishes the TCP connection used by TLSDialer.
	// Both dialers must be non-nil to enable TLS ingress.
	TCPDialer TCPDialer

	// TLSDialer establishes the TLS connection to the Light proxy.
	TLSDialer ClientTLSDialer

	// QUICDialer establishes the QUIC connection to the Light proxy.
	// A nil value disables QUIC ingress.
	QUICDialer ClientQUICDialer

	// TunnelMode enables proxy-to-server tunnels using signed dial authorizations.
	TunnelMode bool

	// SponsorID is the hex client sponsor ID.
	SponsorID string

	// ClientPlatform identifies the client platform.
	ClientPlatform string

	// ClientBuildRev is the hex client build revision.
	ClientBuildRev string

	// DeviceRegion is the device's ISO 3166-1 alpha-2 country code.
	DeviceRegion string

	// SessionID is the hex client session identifier.
	SessionID string

	// ProxyEntryTracker identifies the selected proxy entry.
	ProxyEntryTracker int64

	// ProxyEntry is a CBOR-encoded SignedProxyEntry.
	ProxyEntry []byte
}

// Client is a light proxy client which supports multiple concurrent dials.
type Client struct {
	config              *ClientConfig
	sponsorID           []byte
	clientPlatform      uint8
	clientBuildRev      []byte
	sessionID           []byte
	proxyEntry          *ProxyEntry
	proxyEntryTracker   string
	proxyID             string
	obfuscationKey      string
	verifyPin           string
	protocols           []string
	selectProtocolCount atomic.Uint32
	hasIPv6             bool
	connectionNumber    atomic.Int64

	metricsMutex      sync.Mutex
	dialIPv4Count     int
	dialIPv6Count     int
	dialFailedCount   int
	dialCanceledCount int
}

type ClientMetrics struct {
	ProxyID           string
	ProxyEntryTracker int64
	HasIPv6           bool
	DialIPv4Count     int
	DialIPv6Count     int
	DialFailedCount   int
	DialCanceledCount int
}

// NewClient initializes a Client.
func NewClient(config *ClientConfig) (*Client, error) {

	if config == nil || config.Logger == nil {
		return nil, errors.TraceNew("invalid config")
	}

	// Perform one-time checks and conversions for all parameters that are
	// common across dials.

	sponsorID, err := hex.DecodeString(config.SponsorID)
	if err != nil {
		return nil, errors.Trace(err)
	}

	clientPlatform := encodeClientPlatform(config.ClientPlatform)

	// Truncate odd length client build revs to enable conversion to binary.
	// This is a fail safe: the build script should set a sufficiently long,
	// even-length build rev.
	hexClientBuildRev := config.ClientBuildRev
	if len(hexClientBuildRev)%2 == 1 {
		hexClientBuildRev = hexClientBuildRev[:len(hexClientBuildRev)-1]
	}

	clientBuildRev, err := hex.DecodeString(hexClientBuildRev)
	if err != nil {
		return nil, errors.Trace(err)
	}

	sessionID, err := hex.DecodeString(config.SessionID)
	if err != nil {
		return nil, errors.Trace(err)
	}

	if len(config.ProxyEntry) == 0 {
		return nil, errors.TraceNew("missing proxy entry")
	}

	proxyEntryTracker := fmt.Sprintf("%016x", config.ProxyEntryTracker)

	proxyEntry, err := DecodeAndValidateProxyEntry(config.ProxyEntry)
	if err != nil {
		return nil, errors.Trace(err)
	}
	protocols := getLightProtocols(proxyEntry.DialAddresses)

	supportedProtocols := make([]string, 0, len(protocols))
	for _, protocol := range protocols {
		switch protocol {
		case LIGHT_PROTOCOL_TLS:
			if config.TCPDialer != nil && config.TLSDialer != nil {
				supportedProtocols = append(supportedProtocols, protocol)
			}
		case LIGHT_PROTOCOL_QUIC:
			if config.QUICDialer != nil {
				supportedProtocols = append(supportedProtocols, protocol)
			}
		}
	}
	if len(supportedProtocols) == 0 {
		return nil, errors.TraceNew("no supported proxy protocols")
	}

	obfuscationKey := hex.EncodeToString(proxyEntry.ObfuscationKey)
	verifyPin := base64.StdEncoding.EncodeToString(proxyEntry.VerifyPin)

	hasIPv6 := false
	for _, address := range proxyEntry.DialAddresses {
		if net.ParseIP(address.IPAddress).To4() == nil {
			hasIPv6 = true
			break
		}
	}

	client := &Client{
		config:            config,
		sponsorID:         sponsorID,
		clientPlatform:    clientPlatform,
		clientBuildRev:    clientBuildRev,
		sessionID:         sessionID,
		proxyEntryTracker: proxyEntryTracker,
		proxyEntry:        proxyEntry,
		proxyID:           proxyEntry.ProxyID,
		obfuscationKey:    obfuscationKey,
		verifyPin:         verifyPin,
		protocols:         supportedProtocols,
		hasIPv6:           hasIPv6,
	}
	client.selectProtocolCount.Store(
		uint32(prng.Intn(len(supportedProtocols))))

	return client, nil
}

// GetDialAddresses returns the proxy entry's dial addresses.
// The caller must not mutate the returned slice or its elements.
func (client *Client) GetDialAddresses() []ProxyAddress {
	return client.proxyEntry.DialAddresses
}

// GetRecommendedSNI returns the recommended SNI included in the proxy entry,
// if any.
func (client *Client) GetRecommendedSNI() string {
	return client.proxyEntry.RecommendedSNI
}

// GetRecommendedSNIRegex returns the recommended SNI regex included in the
// proxy entry, if any.
func (client *Client) GetRecommendedSNIRegex() string {
	return client.proxyEntry.RecommendedSNIRegex
}

// GetRecommendedSNIProbability returns the recommended SNI probability
// included in the proxy entry.
func (client *Client) GetRecommendedSNIProbability() float64 {
	return client.proxyEntry.RecommendedSNIProbability
}

// GetRecommendedTLSProfile returns the recommended TLS profile included in
// the proxy entry, if any.
func (client *Client) GetRecommendedTLSProfile() string {
	return client.proxyEntry.RecommendedTLSProfile
}

// GetRecommendedTLSProfileProbability returns the recommended TLS profile
// probability included in the proxy entry.
func (client *Client) GetRecommendedTLSProfileProbability() float64 {
	return client.proxyEntry.RecommendedTLSProfileProbability
}

// GetRecommendedFragmentClientHelloProbability returns the recommended
// FragmentClientHello probability included in the proxy entry.
func (client *Client) GetRecommendedFragmentClientHelloProbability() float64 {
	return client.proxyEntry.RecommendedFragmentClientHelloProbability
}

// GetRecommendedTLSPaddingProbability returns the recommended TLS padding
// probability included in the proxy entry.
func (client *Client) GetRecommendedTLSPaddingProbability() float64 {
	return client.proxyEntry.RecommendedTLSPaddingProbability
}

// GetRecommendedMinTLSPadding returns the recommended minimum TLS padding
// included in the proxy entry.
func (client *Client) GetRecommendedMinTLSPadding() int {
	return client.proxyEntry.RecommendedMinTLSPadding
}

// GetRecommendedMaxTLSPadding returns the recommended maximum TLS padding
// included in the proxy entry.
func (client *Client) GetRecommendedMaxTLSPadding() int {
	return client.proxyEntry.RecommendedMaxTLSPadding
}

// SupportsProtocol reports whether protocol is advertised by the proxy entry
// and supported by the configured client dialers.
func (client *Client) SupportsProtocol(protocol string) bool {
	return common.Contains(client.protocols, protocol)
}

// SelectProtocol selects one protocol advertised by the proxy entry and
// supported by the configured client dialers. Selection is round-robin, from
// a random start, so that consecutive or concurrent fresh dials try each
// protocol.
func (client *Client) SelectProtocol() string {
	n := client.selectProtocolCount.Add(1)
	return client.protocols[int(n%uint32(len(client.protocols)))]
}

// GetMetrics returns ClientMetrics stats for the light client. If
// resetCounters is true, cumulative dial success/failed/cancel metrics
// counters are reset to zero after reporting current values.
func (client *Client) GetMetrics(resetCounters bool) *ClientMetrics {
	client.metricsMutex.Lock()
	defer client.metricsMutex.Unlock()

	metrics := &ClientMetrics{
		ProxyID:           client.proxyID,
		ProxyEntryTracker: client.config.ProxyEntryTracker,
		HasIPv6:           client.hasIPv6,
		DialIPv4Count:     client.dialIPv4Count,
		DialIPv6Count:     client.dialIPv6Count,
		DialFailedCount:   client.dialFailedCount,
		DialCanceledCount: client.dialCanceledCount,
	}

	if resetCounters {
		client.dialIPv4Count = 0
		client.dialIPv6Count = 0
		client.dialFailedCount = 0
		client.dialCanceledCount = 0
	}

	return metrics
}

// Dial connects to the specified destination.
//
// The light proxy protocol requires the client to write first, and the light
// header is prepended to the client's first write.
//
// inactivityTimeout specifies the read inactivity timeout. When zero, the
// default timeout is applied. NoInactivityTimeout disables the timeout.
//
// With ClientConfig.TunnelMode set, tunnelDialParameters must be non-nil
// and destinationAddress must be empty. Otherwise, tunnelDialParameters
// must be nil and destinationAddress must be non-empty.
//
// ingressProtocol must be advertised by the proxy entry and supported by the
// configured client dialers. When empty, SelectProtocol selects one.
//
// For TLS ingress, tlsProfile must be a utls TLS 1.3 ClientHello parrot
// fingerprint, or a randomized fingerprint that produces a TLS 1.3
// ClientHello with the given randomizedTLSProfileSeed.
func (client *Client) Dial(
	ctx context.Context,
	additionalLogFields common.LogFields,
	inactivityTimeout time.Duration,
	networkType string,
	ingressProtocol string,
	tlsProfile string,
	randomizedTLSProfileSeed *prng.Seed,
	quicVersion string,
	quicDialRootObfuscationSeed *prng.Seed,
	obfuscatedQUICNonceTransformerParameters *transforms.ObfuscatorSeedTransformerParameters,
	disablePathMTUDiscovery bool,
	sni string,
	fragmentClientHello bool,
	tlsPadding int,
	destinationAddress string,
	tunnelDialParameters *TunnelDialParameters) (
	retConn *ClientConn,
	retErr error) {

	if ingressProtocol == "" {
		ingressProtocol = client.SelectProtocol()
	} else if !common.Contains(client.protocols, ingressProtocol) {
		return nil, errors.TraceNew("unsupported proxy protocol")
	}

	var ingressTLSProfile uint8
	var ingressQUICVersion uint8
	switch ingressProtocol {
	case LIGHT_PROTOCOL_TLS:
		ingressTLSProfile = encodeTLSProfile(tlsProfile)
		if client.config.TunnelMode && ingressTLSProfile == 0 {
			return nil, errors.TraceNew("invalid ingress TLS profile")
		}

	case LIGHT_PROTOCOL_QUIC:
		ingressQUICVersion = encodeQUICVersion(quicVersion)
		if ingressQUICVersion == 0 ||
			!common.Contains(protocol.SupportedQUICv1Versions, quicVersion) {

			return nil, errors.TraceNew("invalid ingress QUIC version")
		}

		needsRootSeed :=
			protocol.QUICVersionHasRandomizedClientHello(quicVersion) ||
				protocol.QUICVersionIsObfuscated(quicVersion)
		if needsRootSeed && quicDialRootObfuscationSeed == nil {
			return nil, errors.TraceNew(
				"missing ingress QUIC dial root obfuscation seed")
		}
		if !needsRootSeed && quicDialRootObfuscationSeed != nil {
			return nil, errors.TraceNew(
				"unexpected ingress QUIC dial root obfuscation seed")
		}
	}

	var tunnelDialAuthorization []byte
	var egressProtocol uint8
	var egressTLSProfile uint8
	var egressRandomizedTLSProfileSeed []byte
	var egressQUICVersion uint8
	var egressQUICDialRootObfuscationSeed []byte
	var egressSNI string

	if client.config.TunnelMode {
		if tunnelDialParameters == nil {
			return nil, errors.TraceNew("missing tunnel dial parameters")
		}
		if destinationAddress != "" {
			return nil, errors.TraceNew("unexpected destination address")
		}
		if len(tunnelDialParameters.TunnelDialAuthorization) == 0 ||
			len(tunnelDialParameters.TunnelDialAuthorization) >
				maxTunnelDialAuthorizationSize {

			return nil, errors.TraceNew("invalid tunnel dial authorization")
		}

		egressProtocol = tunnelDialParameters.EgressProtocol
		switch egressProtocol {
		case TransportTLS:
			if tunnelDialParameters.EgressQUICVersion != "" {
				return nil, errors.TraceNew(
					"unexpected egress QUIC version")
			}
			if tunnelDialParameters.EgressQUICDialRootObfuscationSeed != nil {
				return nil, errors.TraceNew(
					"unexpected egress QUIC dial root obfuscation seed")
			}
			egressTLSProfile = encodeTLSProfile(
				tunnelDialParameters.EgressTLSProfile)
			if egressTLSProfile == 0 {
				return nil, errors.TraceNew("invalid egress TLS profile")
			}
			if protocol.TLSProfileIsRandomized(
				tunnelDialParameters.EgressTLSProfile) {

				if tunnelDialParameters.EgressRandomizedTLSProfileSeed == nil {
					return nil, errors.TraceNew(
						"missing egress randomized TLS profile seed")
				}
				egressRandomizedTLSProfileSeed = append(
					[]byte(nil),
					tunnelDialParameters.EgressRandomizedTLSProfileSeed[:]...)

			} else if tunnelDialParameters.EgressRandomizedTLSProfileSeed != nil {
				return nil, errors.TraceNew(
					"unexpected egress randomized TLS profile seed")
			}

		case TransportQUIC:
			if tunnelDialParameters.EgressTLSProfile != "" ||
				tunnelDialParameters.EgressRandomizedTLSProfileSeed != nil {

				return nil, errors.TraceNew(
					"unexpected egress TLS parameters")
			}

			egressQUICVersion = encodeQUICVersion(
				tunnelDialParameters.EgressQUICVersion)
			if egressQUICVersion == 0 {
				return nil, errors.TraceNew("invalid egress QUIC version")
			}

			needsRootSeed :=
				protocol.QUICVersionHasRandomizedClientHello(
					tunnelDialParameters.EgressQUICVersion) ||
					protocol.QUICVersionIsObfuscated(
						tunnelDialParameters.EgressQUICVersion)

			if needsRootSeed &&
				tunnelDialParameters.EgressQUICDialRootObfuscationSeed == nil {

				return nil, errors.TraceNew(
					"missing egress QUIC dial root obfuscation seed")
			}
			if !needsRootSeed &&
				tunnelDialParameters.EgressQUICDialRootObfuscationSeed != nil {

				return nil, errors.TraceNew(
					"unexpected egress QUIC dial root obfuscation seed")
			}
			if tunnelDialParameters.EgressQUICDialRootObfuscationSeed != nil {
				egressQUICDialRootObfuscationSeed = append(
					[]byte(nil),
					tunnelDialParameters.
						EgressQUICDialRootObfuscationSeed[:]...)
			}

		default:
			return nil, errors.TraceNew("unsupported egress protocol")
		}

		if len(tunnelDialParameters.EgressSNI) > maxTunnelSNI {
			return nil, errors.TraceNew("invalid egress SNI")
		}

		tunnelDialAuthorization = append(
			[]byte(nil), tunnelDialParameters.TunnelDialAuthorization...)
		egressSNI = tunnelDialParameters.EgressSNI

	} else {
		if tunnelDialParameters != nil {
			return nil, errors.TraceNew("unexpected tunnel dial parameters")
		}
		if destinationAddress == "" {
			return nil, errors.TraceNew("missing destination address")
		}
	}

	switch {
	case inactivityTimeout == NoInactivityTimeout:
		// ActivityMonitoredConn uses zero to disable its timeout.
		inactivityTimeout = 0
	case inactivityTimeout < 0:
		return nil, errors.TraceNew("invalid inactivity timeout")
	case inactivityTimeout == 0:
		inactivityTimeout = clientInactivityTimeout
	}

	// In fallback mode, start at 1 to distinguish from the zero value the proxy
	// records if the header is not delivered. Tunnel headers omit this counter.
	connectionNum := client.connectionNumber.Add(1)

	dialAddressIPv4, dialAddressIPv6 :=
		client.selectDialAddresses(ingressProtocol)

	logFields := common.LogFields{
		"proxyID":           client.proxyID,
		"proxyEntryTracker": client.proxyEntryTracker,
		"connectionNum":     connectionNum,
		"protocol":          ingressProtocol,
		"hasIPv6":           dialAddressIPv6 != "",
	}
	if client.config.EmitNetworkParameters != nil &&
		client.config.EmitNetworkParameters() {

		logFields["SNI"] = sni
		if ingressProtocol == LIGHT_PROTOCOL_TLS {
			logFields["tlsProfile"] = tlsProfile
			logFields["tlsFragment"] = fragmentClientHello
			logFields["tlsPadding"] = tlsPadding
		} else {
			logFields["quicVersion"] = quicVersion
		}
	}
	logFields.Add(additionalLogFields)

	client.config.Logger.WithTraceFields(
		logFields).Info("light proxy connection start")

	// Log the connection outcome. If the dial fails, log accumulated fields
	// here. Otherwise, log on Close.
	defer func() {
		if retErr != nil {
			ctxErr := ctx.Err()

			client.metricsMutex.Lock()
			if ctxErr == context.Canceled {
				client.dialCanceledCount += 1
			} else {
				client.dialFailedCount += 1
			}
			client.metricsMutex.Unlock()

			if ctxErr != context.Canceled {
				logFields["error"] = retErr.Error()
				client.config.Logger.WithTraceFields(
					logFields).Warning("light proxy dial failed")
			} else {
				client.config.Logger.WithTraceFields(
					logFields).Info("light proxy dial canceled")
			}
		}
	}()

	start := time.Now()

	var dial func(context.Context, string, bool) (net.Conn, error)
	switch ingressProtocol {
	case LIGHT_PROTOCOL_TLS:
		dial = func(ctx context.Context, address string, _ bool) (
			net.Conn, error) {

			conn, err := client.config.TCPDialer(ctx, address)
			return conn, errors.Trace(err)
		}

	case LIGHT_PROTOCOL_QUIC:
		dial = func(ctx context.Context, address string, isIPv6 bool) (
			net.Conn, error) {

			var clientHelloSeed, paddingSeed *prng.Seed
			if quicDialRootObfuscationSeed != nil {
				var err error
				clientHelloSeed, paddingSeed, err =
					deriveQUICDialIPAddressFamilySeeds(
						quicDialRootObfuscationSeed, quicVersion, isIPv6)
				if err != nil {
					return nil, errors.Trace(err)
				}
			}

			conn, err := client.config.QUICDialer(
				ctx,
				address,
				sni,
				quicVersion,
				clientHelloSeed,
				paddingSeed,
				obfuscatedQUICNonceTransformerParameters,
				disablePathMTUDiscovery,
				client.obfuscationKey,
				client.verifyPin)
			return conn, errors.Trace(err)
		}
	}

	dialConn, isIPv6, err := dialLightProxyAddresses(
		ctx, dialAddressIPv4, dialAddressIPv6, dial)
	if err != nil {
		return nil, errors.Trace(err)
	}
	defer func() {
		if retErr != nil {
			_ = dialConn.Close()
		}
	}()

	var TCPDuration, TLSDuration, QUICDuration time.Duration
	if ingressProtocol == LIGHT_PROTOCOL_TLS {
		TCPDuration = time.Since(start)
		logFields["TCPDuration"] = TCPDuration.String()
	} else {
		QUICDuration = time.Since(start)
		logFields["QUICDuration"] = QUICDuration.String()
	}
	logFields["isIPv6"] = isIPv6

	bytesCounter := &bytesCounter{}
	// Wrapping here counts outer TLS handshake bytes, but not QUIC
	// handshake packets.
	//
	// activeOnWrite is false: buffered writes can succeed even when the peer
	// is unreachable. They must not keep extending the inactivity deadline.
	activityConn, err := common.NewActivityMonitoredConn(
		dialConn, inactivityTimeout, false, nil, bytesCounter)
	if err != nil {
		return nil, errors.Trace(err)
	}

	var ingressConn net.Conn = activityConn
	if ingressProtocol == LIGHT_PROTOCOL_TLS {
		passthroughMessage, err := obfuscator.MakeTLSPassthroughMessage(
			true, client.obfuscationKey)
		if err != nil {
			return nil, errors.Trace(err)
		}

		start = time.Now()
		dialAddress := dialAddressIPv4
		if isIPv6 {
			dialAddress = dialAddressIPv6
		}
		ingressConn, err = client.config.TLSDialer(
			ctx,
			activityConn,
			dialAddress,
			tlsProfile,
			randomizedTLSProfileSeed,
			sni,
			fragmentClientHello,
			tlsPadding,
			passthroughMessage,
			client.verifyPin)
		if err != nil {
			return nil, errors.Trace(err)
		}
		TLSDuration = time.Since(start)
		logFields["TLSDuration"] = TLSDuration.String()
	}

	header, err := newLightHeader(
		client.sponsorID,
		client.clientPlatform,
		client.clientBuildRev,
		client.config.DeviceRegion,
		client.sessionID,
		client.config.ProxyEntryTracker,
		encodeNetworkType(networkType),
		connectionNum,
		destinationAddress,
		tunnelDialAuthorization,
		egressProtocol,
		egressTLSProfile,
		egressRandomizedTLSProfileSeed,
		egressQUICVersion,
		egressQUICDialRootObfuscationSeed,
		egressSNI,
		ingressTLSProfile,
		ingressQUICVersion,
		int64(TCPDuration),
		int64(TLSDuration),
		int64(QUICDuration),
		client.proxyEntry.PersonalCompartmentID)
	if err != nil {
		return nil, errors.Trace(err)
	}

	dialMetrics := make(common.LogFields)
	metricsConn := dialConn
	if ingressProtocol == LIGHT_PROTOCOL_TLS {
		metricsConn = ingressConn
		dialMetrics["light_tcp_duration"] = TCPDuration.Milliseconds()
		dialMetrics["light_tls_duration"] = TLSDuration.Milliseconds()
	} else {
		dialMetrics["light_quic_duration"] = QUICDuration.Milliseconds()
	}
	// TODO: include TLS and QUIC session resumption in client connection logs.
	if metricsSource, ok := metricsConn.(common.MetricsSource); ok {
		metrics := metricsSource.GetMetrics()
		for _, name := range []string{
			"tls_sent_ticket",
			"tls_did_resume",
			"quic_sent_ticket",
			"quic_did_resume",
		} {
			if value, ok := metrics[name]; ok {
				dialMetrics["light_"+name] = value
			}
		}
	}

	dialMetrics["light_dial_is_IPv6"] = "0"
	if isIPv6 {
		dialMetrics["light_dial_is_IPv6"] = "1"
	}
	_, port, err := net.SplitHostPort(dialConn.RemoteAddr().String())
	if err == nil {
		dialMetrics["light_dial_port_number"] = port
	}

	lightConn := newLightConn(ingressConn, header)

	clientConn := &ClientConn{
		logFields:     logFields,
		dialMetrics:   dialMetrics,
		lightConn:     lightConn,
		activityConn:  activityConn,
		client:        client,
		connectionNum: connectionNum,
		bytesCounter:  bytesCounter,
	}
	if !client.config.TunnelMode {
		clientConn.quicConn, _ = dialConn.(*quic.Conn)
	}

	client.metricsMutex.Lock()
	if isIPv6 {
		client.dialIPv6Count += 1
	} else {
		client.dialIPv4Count += 1
	}
	client.metricsMutex.Unlock()

	return clientConn, nil
}

func (client *Client) selectDialAddresses(protocol string) (string, string) {
	var addressesIPv4, addressesIPv6 []string
	for _, address := range client.proxyEntry.DialAddresses {
		if address.Protocol != protocol {
			continue
		}
		if net.ParseIP(address.IPAddress).To4() != nil {
			addressesIPv4 = append(addressesIPv4, address.String())
		} else {
			addressesIPv6 = append(addressesIPv6, address.String())
		}
	}

	// Limitation: address selection is not replayed. If a protocol has multiple
	// addresses in one IP address family, each dial selects one at random.
	var addressIPv4, addressIPv6 string
	if len(addressesIPv4) > 0 {
		addressIPv4 = addressesIPv4[prng.Intn(len(addressesIPv4))]
	}
	if len(addressesIPv6) > 0 {
		addressIPv6 = addressesIPv6[prng.Intn(len(addressesIPv6))]
	}
	return addressIPv4, addressIPv6
}

func dialLightProxyAddresses(
	ctx context.Context,
	addressIPv4 string,
	addressIPv6 string,
	dial func(context.Context, string, bool) (net.Conn, error)) (
	net.Conn,
	bool,
	error) {

	if addressIPv4 == "" && addressIPv6 == "" {
		return nil, false, errors.TraceNew("missing dial address")
	}
	if addressIPv4 == "" {
		conn, err := dial(ctx, addressIPv6, true)
		return conn, true, errors.Trace(err)
	}
	if addressIPv6 == "" {
		conn, err := dial(ctx, addressIPv4, false)
		return conn, false, errors.Trace(err)
	}

	// Dial IPv6 first and, after a randomized Happy Eyeballs style stagger or
	// an IPv6 failure, IPv4. Use the first to connect.
	//
	// Currently, there's no check that the client has an IPv6 interface as
	// that case is expected to simply fail fast and not generate log noise.
	// An interface check is possible, similar to
	// resolver.hasRoutableIPv6Interface and/or inproxy.pionNetwork.Interfaces,
	// although that may be more expensive than just dialing.

	dialCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	type result struct {
		conn   net.Conn
		isIPv6 bool
		err    error
	}

	resultChannel := make(chan result, 2)
	runDial := func(address string, isIPv6 bool) {
		conn, err := dial(dialCtx, address, isIPv6)
		resultChannel <- result{conn, isIPv6, errors.Trace(err)}
	}

	// Follow the Happy Eyeballs convention and common pattern by starting IPv6 first.
	go runDial(addressIPv6, true)
	pending := 1

	stagger := time.NewTimer(
		prng.Period(dialStaggerMinDuration, dialStaggerMaxDuration))
	defer stagger.Stop()

	var errIPv4, errIPv6 error
	select {
	case resultIPv6 := <-resultChannel:
		pending--
		if resultIPv6.err == nil {
			return resultIPv6.conn, resultIPv6.isIPv6, nil
		}
		errIPv6 = resultIPv6.err
	case <-stagger.C:
	}

	go runDial(addressIPv4, false)
	pending++

	for pending > 0 {
		next := <-resultChannel
		pending--
		if next.err == nil {
			cancel()
			for pending > 0 {
				second := <-resultChannel
				pending--
				if second.err == nil {
					_ = second.conn.Close()
				}
			}
			return next.conn, next.isIPv6, nil
		}
		if next.isIPv6 {
			errIPv6 = next.err
		} else {
			errIPv4 = next.err
		}
	}

	return nil, false, errors.Tracef("IPv4: %w; IPv6: %v", errIPv4, errIPv6)
}

type ClientConn struct {
	*lightConn
	logFields     common.LogFields
	dialMetrics   common.LogFields
	activityConn  *common.ActivityMonitoredConn
	client        *Client
	connectionNum int64
	bytesCounter  *bytesCounter
	quicConn      *quic.Conn

	closeOnce sync.Once
	closeErr  error
}

func (conn *ClientConn) Read(b []byte) (int, error) {
	n, err := conn.lightConn.Read(b)

	// Preserve io.Reader EOF semantics. Other errors, including EOF wrapped
	// after an incomplete frame, retain the client connection number.
	if err != nil && err != io.EOF {
		return n, errors.Tracef(
			"connectionNum %d: %w", conn.connectionNum, err)
	}
	return n, err
}

func (conn *ClientConn) Write(b []byte) (int, error) {
	n, err := conn.lightConn.Write(b)
	if err != nil {
		return n, errors.Tracef(
			"connectionNum %d: %w", conn.connectionNum, err)
	}
	return n, nil
}

func (conn *ClientConn) Close() error {
	conn.closeOnce.Do(func() {
		if conn.quicConn != nil {
			// See the comment at the proxy's GracefulShutdown call.
			//
			// The proxy closes the connection once it has relayed all
			// written data upstream, so this typically returns early.
			// Limitation: Close blocks for at most gracefulShutdownTimeout,
			// kept short as callers expect a prompt Close, and written data
			// not yet relayed by then may be discarded.
			conn.quicConn.GracefulShutdown(gracefulShutdownTimeout)
		}
		conn.closeErr = errors.Trace(conn.lightConn.Close())

		conn.logFields["bytesRead"] = conn.bytesCounter.bytesRead.Load()
		conn.logFields["bytesWritten"] = conn.bytesCounter.bytesWritten.Load()
		conn.logFields["duration"] = conn.activityConn.GetActiveDuration().String()

		conn.client.config.Logger.WithTraceFields(
			conn.logFields).Info("light proxy connection end")
	})
	return conn.closeErr
}

func (conn *ClientConn) IsClosed() bool {
	return conn.activityConn.IsClosed()
}

// GetMetrics returns a copy of the connection's dial metrics.
func (conn *ClientConn) GetMetrics() common.LogFields {
	logFields := make(common.LogFields)
	logFields.Add(conn.dialMetrics)
	return logFields
}
