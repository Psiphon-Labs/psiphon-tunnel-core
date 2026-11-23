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

package psiphon

import (
	"bytes"
	"context"
	"net"
	"sync"
	"time"

	tls "github.com/Psiphon-Labs/psiphon-tls"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/buildinfo"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/light"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/quic"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/regen"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tlsdialer"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/transforms"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/values"
	utls "github.com/Psiphon-Labs/utls"
)

// Light clients have three modes:
//
// Fallback (EnableLightProxyFallback) relays application TCP traffic when a
// Psiphon tunnel is unavailable or inactive. It uses a configured entry or
// the single stored/push-imported fallback entry, can apply entry-recommended
// dial parameters, and keeps replay parameters in memory. The proxy relays
// directly to the application destination over TCP.
//
// Personal tunnel (EnablePersonalLightProxyTunnels) uses the configured
// PersonalLightProxyEntries and their confidential personal compartment IDs.
// LIGHT protocols participate in the personal-pairing race, alongside INPROXY
// when configured.
//
// Common tunnel selects entries from a separate TTL-limited datastore bucket
// when dialing LIGHT protocols in the regular tunnel race. Fresh dials select
// from a shuffled iterator; replay loads the entry by ProxyEntryHash.
//
// Both tunnel modes use a signed dial authorization, an authenticated proxy
// report, and proxy-to-server TLS/QUIC. Dial parameters are selected by
// MakeDialParameters and persisted for replay, without entry recommendations.

// initLightFallbackProxyClient installs the shared fallback client.
func initLightFallbackProxyClient(
	controller *Controller,
	proxyEntry []byte,
	proxyEntryTracker int64) error {

	if controller.config.DisableTunnels {
		return nil
	}

	p := controller.config.GetParameters().Get()
	defer p.Close()

	// The LightProxyDisableFallback tactics override is checked only when
	// initializing the fallback client.
	if !controller.config.EnableLightProxyFallback ||
		p.Bool(parameters.LightProxyDisableFallback) {

		NoticeInfo("Light proxy disabled: skipping proxy entry")
		return nil
	}

	client, err := makeLightProxyClient(
		controller.config,
		controller.untunneledDialConfig,
		controller.quicTLSClientSessionCache,
		controller.tlsClientSessionCache,
		false,
		proxyEntry,
		proxyEntryTracker)
	if err != nil {
		return errors.Trace(err)
	}

	// Use this tunnel liveness target when deciding whether to fallback to
	// light proxy. This value remains set for the session.
	tunnelInactiveThreshold :=
		p.Duration(parameters.LightProxyTunnelInactiveThreshold)

	lightProxyLimitLookup := common.NewStringLookup(
		p.Strings(parameters.LightProxyLimitDestinationAddresses))

	controller.config.SetLightFallbackProxyClient(
		client,
		&lightFallbackDialParameters{},
		tunnelInactiveThreshold,
		p.Duration(parameters.LightProxyDialTimeout),
		&lightProxyLimitLookup)

	NoticeLightProxyAvailable()

	return nil
}

// makeLightProxyClient creates a Light proxy client for the supplied entry
// and configures its TCP, TLS, and QUIC dialers.
func makeLightProxyClient(
	config *Config,
	dialConfig *DialConfig,
	quicTLSClientSessionCache tls.ClientSessionCache,
	tlsClientSessionCache utls.ClientSessionCache,
	tunnelMode bool,
	proxyEntry []byte,
	proxyEntryTracker int64) (*light.Client, error) {

	tcpDialer := NewTCPDialer(dialConfig)

	client, err := light.NewClient(&light.ClientConfig{
		Logger:                NoticeCommonLogger(false),
		EmitNetworkParameters: GetEmitNetworkParameters,
		TCPDialer: func(ctx context.Context, addr string) (net.Conn, error) {
			return tcpDialer(ctx, "tcp", addr)
		},
		TLSDialer: makeLightClientTLSDialer(
			config,
			tlsClientSessionCache),
		QUICDialer: makeLightClientQUICDialer(
			dialConfig,
			quicTLSClientSessionCache),
		TunnelMode:        tunnelMode,
		SponsorID:         config.SponsorId,
		ClientPlatform:    config.ClientPlatform,
		ClientBuildRev:    buildinfo.GetBuildInfo().BuildRev,
		DeviceRegion:      config.DeviceRegion,
		SessionID:         config.SessionID,
		ProxyEntryTracker: proxyEntryTracker,
		ProxyEntry:        proxyEntry,
	})
	if err != nil {
		return nil, errors.Trace(err)
	}

	return client, nil
}

// lightSessionCacheKeyPrefix keeps Light ingress TLS sessions apart from
// other sessions in the shared session caches. A Light session is verified
// by pin only, and must not be resumed by a dial to the same address that
// verifies its peer in a different way, such as a fronted dial.
const lightSessionCacheKeyPrefix = "light:"

// removeLightTunnelSessionCacheEntries clears Light ingress TLS session
// cache entries after failed dials and before dials that do not use replay.
func removeLightTunnelSessionCacheEntries(dialParams *DialParameters) {

	// Limitation: light.Client selects addresses and may race IPv4 and IPv6
	// dials. DialParameters does not record which addresses were tried, so clear
	// cache entries for every address of the selected ingress protocol. This
	// can affect concurrent dials through the same proxy.
	//
	// TODO: isolate eviction between server candidates so fresh or failed dials
	// do not clear sessions needed by replay dials through the same proxy.

	ingressProtocol := getLightTunnelIngressProtocol(dialParams.TunnelProtocol)
	for _, dialAddress := range dialParams.lightProxyClient.GetDialAddresses() {
		var address light.ProxyAddress = dialAddress
		if address.Protocol != ingressProtocol {
			continue
		}
		if ingressProtocol == light.LIGHT_PROTOCOL_QUIC {
			if dialParams.lightQUICTLSClientSessionCache != nil {
				dialParams.lightQUICTLSClientSessionCache.Put(
					lightSessionCacheKeyPrefix+address.String(), nil)
			}
			continue
		}
		if dialParams.lightTLSClientSessionCache == nil {
			continue
		}

		dialParams.lightTLSClientSessionCache.Put(
			lightSessionCacheKeyPrefix+address.String(), nil)
	}
}

func makeLightClientTLSDialer(
	config *Config,
	tlsClientSessionCache utls.ClientSessionCache) light.ClientTLSDialer {

	return func(
		ctx context.Context,
		underlyingConn net.Conn,
		dialAddress string,
		tlsProfile string,
		randomizedTLSProfileSeed *prng.Seed,
		sni string,
		fragmentClientHello bool,
		tlsPadding int,
		passthroughMessage []byte,
		verifyPin string) (net.Conn, error) {

		return dialLightTLS(
			ctx,
			config,
			tlsClientSessionCache,
			underlyingConn,
			dialAddress,
			tlsProfile,
			randomizedTLSProfileSeed,
			sni,
			fragmentClientHello,
			tlsPadding,
			passthroughMessage,
			verifyPin)
	}
}

func makeLightProxyTLSDialer(
	config *Config,
	dialConfig *DialConfig,
	tlsClientSessionCache utls.ClientSessionCache) light.ProxyTLSDialer {

	tcpDialer := NewTCPDialer(dialConfig)

	return func(
		ctx context.Context,
		address string,
		tlsProfile string,
		randomizedTLSProfileSeed *prng.Seed,
		sni string,
		fragmentClientHello bool,
		tlsPadding int,
		passthroughMessage []byte,
		verifyPin string) (
		conn net.Conn,
		exporter []byte,
		completedTCP time.Time,
		completedTLS time.Time,
		err error) {

		underlyingConn, err := tcpDialer(ctx, "tcp", address)
		if err != nil {
			return nil, nil, completedTCP, completedTLS, errors.Trace(err)
		}
		completedTCP = time.Now().UTC()

		conn, err = dialLightTLS(
			ctx,
			config,
			tlsClientSessionCache,
			underlyingConn,
			address,
			tlsProfile,
			randomizedTLSProfileSeed,
			sni,
			fragmentClientHello,
			tlsPadding,
			passthroughMessage,
			verifyPin)
		if err != nil {
			underlyingConn.Close()
			return nil, nil, completedTCP, completedTLS, errors.Trace(err)
		}

		completedTLS = time.Now().UTC()

		exporter, err = tlsdialer.ExportKeyingMaterial(
			conn,
			light.TunnelProxyReportExporterLabel,
			nil,
			light.TunnelProxyReportExporterSize)
		if err != nil {
			conn.Close()
			return nil, nil, completedTCP, completedTLS, errors.Trace(err)
		}

		return conn, exporter, completedTCP, completedTLS, nil
	}
}

func makeLightClientQUICDialer(
	dialConfig *DialConfig,
	tlsClientSessionCache tls.ClientSessionCache) light.ClientQUICDialer {

	// NewUDPConn does not support upstream proxies. Omit the QUIC dialer
	// so clients select TLS or reject entries with no supported transport.
	if !quic.Enabled() || dialConfig.UpstreamProxyURL != "" {
		return nil
	}

	return func(
		ctx context.Context,
		address string,
		sni string,
		quicVersion string,
		clientHelloSeed *prng.Seed,
		obfuscatedQUICPaddingSeed *prng.Seed,
		obfuscatedQUICNonceTransformerParameters *transforms.ObfuscatorSeedTransformerParameters,
		disablePathMTUDiscovery bool,
		obfuscationKey string,
		verifyPin string) (net.Conn, error) {

		packetConn, remoteAddr, err := NewUDPConn(
			ctx, "udp", false, "", address, dialConfig)
		if err != nil {
			return nil, errors.Trace(err)
		}

		// Light listeners reject 0-RTT. Before enabling early dialing, review
		// whether early data can be safely replayed.
		// Obfuscated PSK sessions lack the peer certificate required for
		// pin verification.
		conn, err := quic.Dial(
			ctx,
			packetConn,
			remoteAddr,
			sni,
			quicVersion,
			clientHelloSeed,
			obfuscationKey,
			obfuscatedQUICPaddingSeed,
			obfuscatedQUICNonceTransformerParameters,
			disablePathMTUDiscovery,
			0,
			false,
			false,
			verifyPin,
			common.WrapClientSessionCache(
				tlsClientSessionCache, lightSessionCacheKeyPrefix+address))
		if err != nil {
			packetConn.Close()
			return nil, errors.Trace(err)
		}
		return conn, nil
	}
}

func makeLightProxyQUICDialer(
	dialConfig *DialConfig,
	tlsClientSessionCache tls.ClientSessionCache) light.ProxyQUICDialer {

	clientDialer := makeLightClientQUICDialer(
		dialConfig, tlsClientSessionCache)
	if clientDialer == nil {
		return nil
	}

	return func(
		ctx context.Context,
		address string,
		sni string,
		quicVersion string,
		clientHelloSeed *prng.Seed,
		obfuscatedQUICPaddingSeed *prng.Seed,
		obfuscationKey string,
		verifyPin string) (
		conn net.Conn,
		exporter []byte,
		completedQUIC time.Time,
		err error) {

		// Future enhancement: client-selected egress QUIC MTU policy and nonce
		// transforms, sent in the light proxy header.
		conn, err = clientDialer(
			ctx,
			address,
			sni,
			quicVersion,
			clientHelloSeed,
			obfuscatedQUICPaddingSeed,
			nil,
			false,
			obfuscationKey,
			verifyPin)
		if err != nil {
			return nil, nil, completedQUIC, errors.Trace(err)
		}
		completedQUIC = time.Now().UTC()

		quicConn, ok := conn.(*quic.Conn)
		if !ok {
			conn.Close()
			return nil, nil, completedQUIC, errors.TraceNew("invalid QUIC connection")
		}
		exporter, err = quicConn.ExportKeyingMaterial(
			light.TunnelProxyReportExporterLabel,
			nil,
			light.TunnelProxyReportExporterSize)
		if err != nil {
			conn.Close()
			return nil, nil, completedQUIC, errors.Trace(err)
		}

		return conn, exporter, completedQUIC, nil
	}
}

func dialLightTLS(
	ctx context.Context,
	config *Config,
	tlsClientSessionCache utls.ClientSessionCache,
	underlyingConn net.Conn,
	dialAddress string,
	tlsProfile string,
	randomizedTLSProfileSeed *prng.Seed,
	sni string,
	fragmentClientHello bool,
	tlsPadding int,
	passthroughMessage []byte,
	verifyPin string) (net.Conn, error) {

	// Derive NoDefaultTLSSessionID from the randomized TLS profile seed, so
	// that a replayed seed reproduces the same ClientHello. Without a seed,
	// the TLS profile is not randomized and, as Light TLS is TLS 1.3,
	// NoDefaultTLSSessionID doesn't apply. For proxy egress dials, the seed
	// is client-selected while the probability is from the proxy's tactics,
	// which are appropriate for the proxy's location.
	//
	// Limitation: unlike other TLS tunnel protocols, the value is not stored
	// in dial parameters or reported in metrics.
	var noDefaultTLSSessionID *bool
	if randomizedTLSProfileSeed != nil {
		PRNG, err := prng.NewPRNGWithSaltedSeed(
			randomizedTLSProfileSeed, "light-no-default-tls-session-id")
		if err != nil {
			return nil, errors.Trace(err)
		}
		p := config.GetParameters().Get()
		value := PRNG.FlipWeightedCoin(
			p.Float(parameters.NoDefaultTLSSessionIDProbability))
		p.Close()
		noDefaultTLSSessionID = &value
	}

	return tlsdialer.Dial(
		ctx,
		"tcp",
		underlyingConn.RemoteAddr().String(),
		&tlsdialer.Config{
			Parameters: config.GetParameters(),
			Dial: func(context.Context, string, string) (net.Conn, error) {
				return underlyingConn, nil
			},
			UseDialAddrSNI:           false,
			SNIServerName:            sni,
			VerifyPins:               []string{verifyPin},
			VerifyPinsOnly:           true,
			TLSProfile:               tlsProfile,
			NoDefaultTLSSessionID:    noDefaultTLSSessionID,
			RandomizedTLSProfileSeed: randomizedTLSProfileSeed,
			FragmentClientHello:      fragmentClientHello,
			TLSPadding:               tlsPadding,
			PassthroughMessage:       passthroughMessage,
			// The session cache key is the dial address, not the connected
			// address, which may be a synthesized NAT64 address.
			ClientSessionCache: common.WrapUtlsClientSessionCache(
				tlsClientSessionCache, lightSessionCacheKeyPrefix+dialAddress),
		})
}

// lightFallbackDialParameters contains in-memory replay parameters for Light
// proxy fallback dials.
type lightFallbackDialParameters struct {
	Protocol                                 string
	TLSProfile                               string
	RandomizedTLSProfileSeed                 *prng.Seed
	FragmentClientHello                      bool
	TLSPadding                               int
	QUICVersion                              string
	QUICDialRootObfuscationSeed              *prng.Seed
	ObfuscatedQUICNonceTransformerParameters *transforms.ObfuscatorSeedTransformerParameters
	QUICDisablePathMTUDiscovery              bool
	SNI                                      string
}

func (r lightFallbackDialParameters) isReplay() bool {
	if r.SNI == "" {
		return false
	}
	switch r.Protocol {
	case light.LIGHT_PROTOCOL_TLS:
		return r.TLSProfile != ""
	case light.LIGHT_PROTOCOL_QUIC:
		return r.QUICVersion != ""
	default:
		return false
	}
}

// makeLightFallbackDialParameters selects parameters for non-tunnel Light
// proxy fallback dials.
func makeLightFallbackDialParameters(
	config *Config,
	lightClient *light.Client) (*lightFallbackDialParameters, error) {

	p := config.GetParameters().Get()
	defer p.Close()

	dialParams := &lightFallbackDialParameters{
		Protocol: lightClient.SelectProtocol(),
		SNI:      selectLightFallbackSNI(lightClient, p),
	}

	switch dialParams.Protocol {
	case light.LIGHT_PROTOCOL_TLS:
		// Limitation: if SelectTLSProfile selects a CustomTLSProfile, the
		// profile reported to the proxy will be "unknown".
		recommendedTLSProfile := lightClient.GetRecommendedTLSProfile()
		if recommendedTLSProfile != "" &&
			!prng.FlipWeightedCoin(
				lightClient.GetRecommendedTLSProfileProbability()) {

			recommendedTLSProfile = ""
		}

		var err error
		dialParams.TLSProfile,
			_,
			dialParams.RandomizedTLSProfileSeed,
			err = tlsdialer.SelectTLSProfile(
			false, true, false, "", recommendedTLSProfile, nil, nil, false, p)
		if err != nil {
			return nil, errors.Trace(err)
		}

		dialParams.FragmentClientHello = prng.FlipWeightedCoin(
			lightClient.GetRecommendedFragmentClientHelloProbability())

		if prng.FlipWeightedCoin(
			lightClient.GetRecommendedTLSPaddingProbability()) {

			dialParams.TLSPadding = prng.Range(
				lightClient.GetRecommendedMinTLSPadding(),
				lightClient.GetRecommendedMaxTLSPadding())
		}

	case light.LIGHT_PROTOCOL_QUIC:
		// Limitation: when tactics LimitQUICVersions leaves no supported
		// Light QUIC version, this dial fails instead of selecting TLS,
		// even when the proxy entry has a TLS address. This case is not
		// expected in practice.
		dialParams.QUICVersion = selectLightQUICVersion(
			nil, p.QUICVersions(parameters.LimitQUICVersions))
		if dialParams.QUICVersion == "" {
			return nil, errors.TraceNew(
				"no supported Light QUIC versions")
		}

		var err error
		dialParams.QUICDialRootObfuscationSeed, err =
			makeLightQUICDialRootObfuscationSeed(
				dialParams.QUICVersion)
		if err != nil {
			return nil, errors.Trace(err)
		}

		dialParams.QUICDisablePathMTUDiscovery =
			protocol.QUICVersionUsesPathMTUDiscovery(dialParams.QUICVersion) &&
				p.WeightedCoinFlip(parameters.QUICDisableClientPathMTUDiscoveryProbability)
		dialParams.ObfuscatedQUICNonceTransformerParameters, err =
			makeLightQUICNonceTransformerParameters(dialParams.QUICVersion, p)
		if err != nil {
			return nil, errors.Trace(err)
		}

	default:
		return nil, errors.TraceNew("unsupported Light proxy protocol")
	}

	return dialParams, nil
}

func makeLightQUICNonceTransformerParameters(
	quicVersion string,
	p parameters.ParametersAccessor) (*transforms.ObfuscatorSeedTransformerParameters, error) {

	if !protocol.QUICVersionIsObfuscated(quicVersion) {
		return nil, nil
	}

	params, err := makeSeedTransformerParameters(
		p,
		parameters.ObfuscatedQUICNonceTransformProbability,
		parameters.ObfuscatedQUICNonceTransformSpecs,
		parameters.ObfuscatedQUICNonceTransformScopedSpecNames)
	if err != nil {
		return nil, errors.Trace(err)
	}
	if params.TransformSpec == nil {
		return nil, nil
	}
	return params, nil
}

func dialLightFallbackProxy(
	ctx context.Context,
	config *Config,
	lightClient *light.Client,
	currentNetworkCtx context.Context,
	inactivityTimeout time.Duration,
	remoteAddr string) (net.Conn, error) {

	// Interrupt the dial if the host's current active network changes.
	// Merging the contexts also ensures ctx.Err() reflects a network change.
	if currentNetworkCtx != nil {
		var cancel context.CancelFunc
		ctx, cancel = common.MergeContextCancel(
			ctx, currentNetworkCtx)
		defer cancel()
	}

	dialParams := config.GetLightFallbackDialParameters()

	isReplay := dialParams.isReplay()
	if !isReplay {

		var err error
		dialParams, err = makeLightFallbackDialParameters(config, lightClient)
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	logFields := common.LogFields{"isReplay": isReplay}

	conn, err := lightClient.Dial(
		ctx,
		logFields,
		inactivityTimeout,
		GetNetworkType(config.GetNetworkID()),
		dialParams.Protocol,
		dialParams.TLSProfile,
		dialParams.RandomizedTLSProfileSeed,
		dialParams.QUICVersion,
		dialParams.QUICDialRootObfuscationSeed,
		dialParams.ObfuscatedQUICNonceTransformerParameters,
		dialParams.QUICDisablePathMTUDiscovery,
		dialParams.SNI,
		dialParams.FragmentClientHello,
		dialParams.TLSPadding,
		remoteAddr,
		nil)
	if err != nil {
		// Retain replay parameters when the dial was canceled, including by a
		// network change. Clear on dial timeout or other failures. A fresh
		// dial doesn't clear replay parameters from a concurrent dial.
		if isReplay && ctx.Err() != context.Canceled {
			config.SetLightFallbackDialParameters(&lightFallbackDialParameters{})
		}
		// Annotate the error with the interrupt cause such as "network changed".
		if ctx.Err() != nil {
			err = errors.TraceMsg(err, context.Cause(ctx).Error())
		}
		return nil, errors.Trace(err)
	}

	// Simple session-only replay: reuse the last transport parameters that
	// successfully dialed. Concurrent successful dials may clobber this
	// value, but every stored value succeeded.
	//
	// Note: a dial that completes after a push import has replaced the
	// fallback Light proxy stores parameters from the previous proxy. The
	// next dial replays them once and, if it fails, clears them.

	config.SetLightFallbackDialParameters(dialParams)

	return conn, nil
}

func dialLightProxyTunnel(
	ctx context.Context,
	config *Config,
	lightClient *light.Client,
	dialParams *DialParameters) (net.Conn, error) {

	ingressProtocol := getLightTunnelIngressProtocol(dialParams.TunnelProtocol)
	if ingressProtocol == "" {
		return nil, errors.TraceNew("invalid Light tunnel protocol")
	}

	egressProtocol := uint8(light.TransportTLS)
	if protocol.TunnelProtocolUsesLightQUICEgress(dialParams.TunnelProtocol) {
		egressProtocol = light.TransportQUIC
	}

	// Disable the Light inactivity timeout so it does not conflict with SSH
	// keepalives.

	var conn net.Conn
	conn, err := lightClient.Dial(
		ctx,
		common.LogFields{"isReplay": dialParams.IsReplay},
		light.NoInactivityTimeout,
		GetNetworkType(config.GetNetworkID()),
		ingressProtocol,
		dialParams.LightTLSProfile,
		dialParams.LightRandomizedTLSProfileSeed,
		dialParams.LightQUICVersion,
		dialParams.LightQUICDialRootObfuscationSeed,
		dialParams.LightObfuscatedQUICNonceTransformerParameters,
		dialParams.LightQUICDisablePathMTUDiscovery,
		dialParams.LightSNI,
		dialParams.LightTLSFragmentClientHello,
		dialParams.LightTLSPadding,
		"",
		&light.TunnelDialParameters{
			TunnelDialAuthorization: dialParams.ServerEntry.LightDialAuthorization,
			EgressProtocol:          egressProtocol,
			EgressTLSProfile:        dialParams.LightEgressTLSProfile,
			EgressRandomizedTLSProfileSeed: dialParams.
				LightEgressRandomizedTLSProfileSeed,
			EgressQUICVersion: dialParams.LightEgressQUICVersion,
			EgressQUICDialRootObfuscationSeed: dialParams.
				LightEgressQUICDialRootObfuscationSeed,
			EgressSNI: dialParams.LightEgressSNI,
		})
	if err != nil {
		return nil, errors.Trace(err)
	}

	return conn, nil
}

func getLightTunnelIngressProtocol(tunnelProtocol string) string {
	switch {
	case protocol.TunnelProtocolUsesLightTLSIngress(tunnelProtocol):
		return light.LIGHT_PROTOCOL_TLS
	case protocol.TunnelProtocolUsesLightQUICIngress(tunnelProtocol):
		return light.LIGHT_PROTOCOL_QUIC
	default:
		return ""
	}
}

func selectLightFallbackSNI(
	lightClient *light.Client, p parameters.ParametersAccessor) string {

	// Prefer light proxy entry recommended regex SNI, then recommended SNI,
	// then light proxy custom hostname tactic.

	recommendedRegexSNI := lightClient.GetRecommendedSNIRegex()
	recommendedSNI := lightClient.GetRecommendedSNI()

	if (recommendedRegexSNI != "" || recommendedSNI != "") &&
		prng.FlipWeightedCoin(lightClient.GetRecommendedSNIProbability()) {

		if recommendedRegexSNI != "" {
			SNI, err := regen.GenerateString(recommendedRegexSNI)
			if err != nil {
				NoticeWarning("selectLightFallbackSNI: regen.Generate failed: %v", errors.Trace(err))
				SNI = values.GetHostName()
			}
			return SNI
		}
		return recommendedSNI
	}

	return selectLightCustomSNI(
		p,
		[]string{parameters.LightProxyCustomHostNameRegexes},
		[]string{parameters.LightProxyCustomHostNameProbability})
}

func selectLightCustomSNI(
	p parameters.ParametersAccessor,
	regexesParameters, probabilityParameters []string) string {

	if p.WeightedCoinFlip(probabilityParameters...) {
		regexStrings := p.RegexStrings(regexesParameters...)
		if len(regexStrings) == 0 {
			return values.GetHostName()
		}
		choice := prng.Intn(len(regexStrings))
		SNI, err := regen.GenerateString(regexStrings[choice])
		if err != nil {
			NoticeWarning("selectLightCustomSNI: regen.Generate failed: %v", errors.Trace(err))
			SNI = values.GetHostName()
		}
		return SNI
	}

	return values.GetHostName()
}

type lightFallbackProxyDialResult struct {
	conn net.Conn
	err  error
}

const lightFallbackTunnelRacePollInterval = 50 * time.Millisecond

func dialLightFallbackProxyRace(
	controller *Controller,
	lightClient *light.Client,
	remoteAddr string,
	downstreamConn net.Conn,
	readInactiveThreshold time.Duration) (net.Conn, *Tunnel, error) {

	// Initiate a light proxy dial and run a race between that dial and any
	// concurrent tunnel dial. This allows for selecting the tunnel if it's
	// just about to connect, or if the read inactive test passes as a
	// connected tunnel was simply idle.

	dialTimeout := controller.config.GetLightFallbackDialTimeout()

	// Associate the dial and established connection with the current network.
	// On NetworkChanged, both dials and connections are interrupted.
	currentNetworkCtx := controller.getCurrentNetworkContext()

	lightDialCtx, cancel := context.WithTimeout(
		controller.runCtx, dialTimeout)
	defer cancel()

	lightResult := make(chan lightFallbackProxyDialResult)
	var lightDialWaitGroup sync.WaitGroup

	lightDialWaitGroup.Add(1)
	go func() {
		defer lightDialWaitGroup.Done()

		p := controller.config.GetParameters().Get()
		inactivityTimeout := p.Duration(
			parameters.LightProxyInactivityTimeout)
		p.Close()

		conn, err := dialLightFallbackProxy(
			lightDialCtx, controller.config, lightClient,
			currentNetworkCtx, inactivityTimeout, remoteAddr)
		lightResult <- lightFallbackProxyDialResult{conn: conn, err: err}
	}()
	defer lightDialWaitGroup.Wait()

	cancelLightDial := func() {
		cancel()
		result := <-lightResult
		if result.conn != nil {
			_ = result.conn.Close()
		}
	}

	// Simply poll for an active tunnel with a recent read. The getNextActiveTunnel
	// call is inexpensive, while a signal on either new tunnel established
	// or existing tunnel reads data is complex.
	ticker := time.NewTicker(lightFallbackTunnelRacePollInterval)
	defer ticker.Stop()

	for {
		select {
		case result := <-lightResult:

			if result.err == nil {
				// Close downstreamConn when the light conn is closed. See
				// Controller.Dial and TunneledConn. A network change also
				// closes the conn, including downstreamConn.
				conn := newLightFallbackProxyConn(
					result.conn, downstreamConn, currentNetworkCtx)

				// Avoid returning a conn for a network that changed while
				// dialing.
				if currentNetworkCtx.Err() != nil {
					_ = conn.Close()
					return nil, nil, errors.Trace(
						context.Cause(currentNetworkCtx))
				}

				return conn, nil, nil
			}

			return nil, nil, errors.Trace(result.err)

		case <-ticker.C:
			tunnel := controller.getNextActiveTunnel(readInactiveThreshold)
			if tunnel != nil {
				cancelLightDial()
				return nil, tunnel, nil
			}

		case <-controller.runCtx.Done():
			cancelLightDial()
			return nil, nil, errors.Trace(controller.runCtx.Err())
		}
	}
}

type lightFallbackProxyConn struct {
	net.Conn
	downstreamConn   net.Conn
	unassociateAfter func() bool
}

func newLightFallbackProxyConn(
	conn net.Conn,
	downstreamConn net.Conn,
	currentNetworkCtx context.Context) *lightFallbackProxyConn {

	lightConn := &lightFallbackProxyConn{
		Conn:           conn,
		downstreamConn: downstreamConn,
	}

	// Close the conns when the network changes. This callback closes the
	// conns directly rather than calling lightFallbackProxyConn.Close, which avoids
	// a race with unassociateAfter assignment.
	if currentNetworkCtx != nil {
		lightConn.unassociateAfter = context.AfterFunc(
			currentNetworkCtx,
			func() {
				if downstreamConn != nil {
					_ = downstreamConn.Close()
				}
				_ = conn.Close()
			})
	}

	return lightConn
}

func (conn *lightFallbackProxyConn) Close() error {

	// The AfterFunc callback may run concurrently with Close; the
	// underlying conns support multiple and concurrent Close calls.
	if conn.unassociateAfter != nil {
		conn.unassociateAfter()
	}

	if conn.downstreamConn != nil {
		_ = conn.downstreamConn.Close()
	}

	return conn.Conn.Close()
}

type lightProxyEventReceiver struct {
	config                     *Config
	started                    chan struct{}
	lastActivityNotice         time.Time
	currentConnectionCount     int64
	totalBytesUp               int64
	totalBytesDown             int64
	lastPersonalRegionActivity map[string]light.RegionActivitySnapshot
	lastCommonRegionActivity   map[string]light.RegionActivitySnapshot
}

func newLightProxyEventReceiver(config *Config) *lightProxyEventReceiver {
	return &lightProxyEventReceiver{
		config:  config,
		started: make(chan struct{}),
	}
}

func (r *lightProxyEventReceiver) Listening(address, ingressProtocol string) {
	NoticeLightProxyListening(address, ingressProtocol)
}

func (r *lightProxyEventReceiver) Started() {
	NoticeLightProxyStarted()
	close(r.started)
}

func (r *lightProxyEventReceiver) Stopped() {
	NoticeLightProxyTotalActivity(
		r.currentConnectionCount, r.totalBytesUp, r.totalBytesDown)
	NoticeLightProxyStopped()
}

func (r *lightProxyEventReceiver) Paused() {
	NoticeInfo("light proxy: paused")
}

func (r *lightProxyEventReceiver) Resumed() {
	NoticeInfo("light proxy: resumed")
}

func (r *lightProxyEventReceiver) Accepted() {
}

func (r *lightProxyEventReceiver) Rejected() {
}

func (r *lightProxyEventReceiver) Connection(stats *light.ConnectionStats) {
	if stats.ProxyCompletedLightHeader.IsZero() {
		// light.Proxy.Run logs pre-header failures through WarningLog.
		return
	}
	NoticeInfo(
		"light proxy: connection: failure=%s "+
			"bytesRead=%d bytesWritten=%d matchedPersonalCompartments=%t",
		stats.Failure,
		stats.BytesRead,
		stats.BytesWritten,
		stats.MatchedPersonalCompartments)
}

func (r *lightProxyEventReceiver) Activity(stats *light.ActivityStats) {
	connectionCountChanged := stats.CurrentConnectionCount != r.currentConnectionCount
	regionActivityChanged :=
		lightProxyRegionActivityChanged(r.lastPersonalRegionActivity, stats.PersonalRegionActivity) ||
			lightProxyRegionActivityChanged(r.lastCommonRegionActivity, stats.CommonRegionActivity)

	if r.config.EmitLightProxyActivity &&
		(stats.BytesUp > 0 || stats.BytesDown > 0 ||
			connectionCountChanged || regionActivityChanged) {

		NoticeLightProxyActivity(
			stats.CurrentConnectionCount,
			stats.BytesUp,
			stats.BytesDown,
			stats.BytesDuration.Milliseconds(),
			stats.PersonalRegionActivity, stats.CommonRegionActivity)
	}

	r.currentConnectionCount = stats.CurrentConnectionCount
	r.totalBytesUp += stats.BytesUp
	r.totalBytesDown += stats.BytesDown
	r.lastPersonalRegionActivity = stats.PersonalRegionActivity
	r.lastCommonRegionActivity = stats.CommonRegionActivity

	p := r.config.GetParameters().Get()
	noticePeriod := p.Duration(parameters.LightTunnelProxyTotalActivityNoticePeriod)
	p.Close()

	now := time.Now()
	if now.Sub(r.lastActivityNotice) >= noticePeriod || connectionCountChanged {
		NoticeLightProxyTotalActivity(
			r.currentConnectionCount, r.totalBytesUp, r.totalBytesDown)
		r.lastActivityNotice = now
	}
}

func lightProxyRegionActivityChanged(
	previous, current map[string]light.RegionActivitySnapshot) bool {

	for region, activity := range current {
		last := previous[region]
		if activity.BytesUp > 0 || activity.BytesDown > 0 ||
			activity.ConnectingClients != last.ConnectingClients ||
			activity.ConnectedClients != last.ConnectedClients {
			return true
		}
	}
	for region, activity := range previous {
		if _, ok := current[region]; !ok &&
			(activity.ConnectingClients != 0 || activity.ConnectedClients != 0) {
			return true
		}
	}
	return false
}

func (r *lightProxyEventReceiver) IrregularConnection(
	_ string,
	_ common.GeoIPData,
	irregularity string) {

	NoticeWarning("light proxy: irregular connection: %s", irregularity)
}

func (r *lightProxyEventReceiver) DebugLog(_ string, _ string) {
}

func (r *lightProxyEventReceiver) InfoLog(_ string, message string) {
	NoticeInfo("light proxy: %s", message)
}

func (r *lightProxyEventReceiver) WarningLog(_ string, message string) {
	NoticeWarning("light proxy: %s", message)
}

func (r *lightProxyEventReceiver) ErrorLog(_ string, message string) {
	NoticeError("light proxy: %s", message)
}

// lightTunnelProxyEntryIterator iterates over Light proxy entries for tunnel
// dials.
type lightTunnelProxyEntryIterator interface {
	HasNext(ingressProtocol string) bool
	Next(ingressProtocol string) ([]byte, *StoredLightProxyEntry, error)
	Load(proxyEntryHash []byte, ingressProtocol string) (*StoredLightProxyEntry, error)
}

// LightProxyEntryTrackerPersonalPairing is the tracker reported for
// PersonalLightProxyEntries, which are not obtained from the Psiphon network.
const LightProxyEntryTrackerPersonalPairing = -1

type personalLightProxyEntry struct {
	proxyEntry     []byte
	proxyEntryHash []byte
	protocols      []string
}

// personalLightProxyEntryIterator cycles through PersonalLightProxyEntries in
// ordered round robin, with one cycle per ingress protocol.
type personalLightProxyEntryIterator struct {
	mutex   sync.Mutex
	entries map[string][]personalLightProxyEntry
	indexes map[string]int
}

func newPersonalLightProxyEntryIterator(config *Config) *personalLightProxyEntryIterator {
	iterator := &personalLightProxyEntryIterator{
		entries: make(map[string][]personalLightProxyEntry),
		indexes: make(map[string]int),
	}
	for _, entry := range config.personalLightProxyEntries {
		for _, ingressProtocol := range entry.protocols {
			iterator.entries[ingressProtocol] = append(iterator.entries[ingressProtocol], entry)
		}
	}
	return iterator
}

func (iterator *personalLightProxyEntryIterator) HasNext(ingressProtocol string) bool {
	return len(iterator.entries[ingressProtocol]) > 0
}

func (iterator *personalLightProxyEntryIterator) Next(
	ingressProtocol string) ([]byte, *StoredLightProxyEntry, error) {

	iterator.mutex.Lock()
	defer iterator.mutex.Unlock()

	entries := iterator.entries[ingressProtocol]
	if len(entries) == 0 {
		return nil, nil, nil
	}
	index := iterator.indexes[ingressProtocol]
	iterator.indexes[ingressProtocol] = (index + 1) % len(entries)
	entry := entries[index]
	return entry.proxyEntryHash, &StoredLightProxyEntry{
		LightProxyEntry:        entry.proxyEntry,
		LightProxyEntryTracker: LightProxyEntryTrackerPersonalPairing,
	}, nil
}

func (iterator *personalLightProxyEntryIterator) Load(
	proxyEntryHash []byte, ingressProtocol string) (*StoredLightProxyEntry, error) {

	for _, entry := range iterator.entries[ingressProtocol] {
		if bytes.Equal(entry.proxyEntryHash, proxyEntryHash) {
			return &StoredLightProxyEntry{
				LightProxyEntry:        entry.proxyEntry,
				LightProxyEntryTracker: LightProxyEntryTrackerPersonalPairing,
			}, nil
		}
	}
	return nil, nil
}
