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
	"context"
	"net"
	"sync"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/buildinfo"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/fragmentor"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/light"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/regen"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tlsdialer"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/values"
)

// storeAndInitLightProxy persists a discovered/imported light proxy entry and,
// when light proxy fallback is enabled, reinitializes the live light proxy with
// it. This is the shared light proxy import path used by both push payload
// imports (Controller.ImportPushPayload) and DSL discovery
// (FetcherConfig.DatastoreStoreLightProxy).
//
// proxyEntry is an opaque encoded light.SignedProxyEntry; StoreLightProxy
// validates it before persisting.
func (controller *Controller) storeAndInitLightProxy(
	proxyEntry []byte,
	proxyEntryTracker int64) error {

	// Light proxies are persisted for potential future use as fallbacks. In
	// EnablePersonalLightProxyTunnels mode, initLightProxy is not called, and
	// the light proxy in use remains config.LightProxyEntry.
	ok := StoreLightProxy(&StoredLightProxy{
		LightProxyEntry:        proxyEntry,
		LightProxyEntryTracker: proxyEntryTracker,
	})
	if !ok {
		return errors.TraceNew("StoreLightProxy failed")
	}

	if controller.config.EnableLightProxyFallback {

		// TODO: skip the reinitialization, or retain the current replay
		// parameters, when the proxy entry is unchanged from the proxy entry
		// currently in use, so that a proven-working replay selection isn't
		// discarded.
		err := controller.initLightProxy(proxyEntry, proxyEntryTracker)
		if err != nil {
			return errors.Trace(err)
		}
	}

	return nil
}

func (controller *Controller) initLightProxy(
	proxyEntry []byte,
	proxyEntryTracker int64) error {

	if controller.config.DisableTunnels {
		return nil
	}

	p := controller.config.GetParameters().Get()
	defer p.Close()

	// Clients must set EnableLightProxyFallback or EnablePersonalLightProxyTunnels
	// in the config. The LightProxyDisableFallback tactics parameter functions
	// as a remote override for fallback mode, and is only checked here, so newly
	// fetched tactics changes won't take effect until the next session. Personal
	// light proxy tunnel mode is enabled only by config, similar to personal
	// pairing.

	enableLightProxy := controller.config.EnablePersonalLightProxyTunnels ||
		(controller.config.EnableLightProxyFallback &&
			!p.Bool(parameters.LightProxyDisableFallback))

	if !enableLightProxy {
		NoticeInfo("Light proxy disabled: skipping proxy entry")
		return nil
	}

	tcpDialer := NewTCPDialer(controller.untunneledDialConfig)

	tlsDialer := func(
		ctx context.Context,
		underlyingConn net.Conn,
		tlsProfile string,
		randomizedTLSProfileSeed *prng.Seed,
		sni string,
		fragmentClientHello bool,
		tlsPadding int,
		passthroughMessage []byte,
		verifyPin string,
		verifyServerName string) (net.Conn, error) {

		return tlsdialer.Dial(
			ctx,
			"tcp",
			underlyingConn.RemoteAddr().String(),
			&tlsdialer.Config{
				Parameters: controller.config.GetParameters(),
				Dial: func(context.Context, string, string) (net.Conn, error) {
					return underlyingConn, nil
				},
				UseDialAddrSNI:           false,
				SNIServerName:            sni,
				VerifyServerName:         verifyServerName,
				VerifyPins:               []string{verifyPin},
				VerifyPinsOnly:           true,
				TLSProfile:               tlsProfile,
				RandomizedTLSProfileSeed: randomizedTLSProfileSeed,
				FragmentClientHello:      fragmentClientHello,
				TLSPadding:               tlsPadding,
				PassthroughMessage:       passthroughMessage,
				ClientSessionCache: common.WrapUtlsClientSessionCache(
					controller.tlsClientSessionCache,
					underlyingConn.RemoteAddr().String()),
			})
	}

	client, err := light.NewClient(&light.ClientConfig{
		Logger: NoticeCommonLogger(false),
		TCPDialer: func(ctx context.Context, addr string) (net.Conn, error) {
			return tcpDialer(ctx, "tcp", addr)
		},
		TLSDialer:         tlsDialer,
		SponsorID:         controller.config.SponsorId,
		ClientPlatform:    controller.config.ClientPlatform,
		ClientBuildRev:    buildinfo.GetBuildInfo().BuildRev,
		DeviceRegion:      controller.config.DeviceRegion,
		SessionID:         controller.config.SessionID,
		ProxyEntryTracker: proxyEntryTracker,
		ProxyEntry:        proxyEntry,
	})
	if err != nil {
		return errors.Trace(err)
	}

	var tunnelInactiveThreshold time.Duration
	lightProxyLimitLookup := common.NewStringLookup(nil)

	if controller.config.EnableLightProxyFallback {
		// Use this tunnel liveness target when deciding whether to fallback to
		// light proxy. This value remains set for the session.
		tunnelInactiveThreshold =
			p.Duration(parameters.LightProxyTunnelInactiveThreshold)

		lightProxyLimitLookup = common.NewStringLookup(
			p.Strings(parameters.LightProxyLimitDestinationAddresses))
	}

	controller.config.SetLightProxy(
		client,
		&lightDialParameters{},
		tunnelInactiveThreshold,
		p.Duration(parameters.LightProxyDialTimeout),
		&lightProxyLimitLookup)

	NoticeLightProxyAvailable()

	return nil
}

type lightDialParameters struct {
	TLSProfile               string
	RandomizedTLSProfileSeed *prng.Seed
	SNI                      string
	FragmentClientHello      bool
	TLSPadding               int
}

func (r lightDialParameters) isReplay() bool {
	return r.TLSProfile != "" && r.SNI != ""
}

func makeLightDialParameters(
	config *Config,
	lightClient *light.Client) (*lightDialParameters, error) {

	// Limitation: if tlsdialer.SelectTLSProfile selects a CustomTLSProfile, the TLS
	// profile reported to the proxy will be "unknown".

	p := config.GetParameters().Get()
	defer p.Close()

	recommendedTLSProfile := lightClient.GetRecommendedTLSProfile()
	if recommendedTLSProfile != "" &&
		!prng.FlipWeightedCoin(lightClient.GetRecommendedTLSProfileProbability()) {
		recommendedTLSProfile = ""
	}

	tlsProfile, _, randomizedTLSProfileSeed, err :=
		tlsdialer.SelectTLSProfile(false, true, false, "", recommendedTLSProfile, p)
	if err != nil {
		return nil, errors.Trace(err)
	}

	SNI := selectLightProxySNI(lightClient, p)

	fragmentClientHello := prng.FlipWeightedCoin(
		lightClient.GetRecommendedFragmentClientHelloProbability())

	tlsPadding := 0
	if prng.FlipWeightedCoin(lightClient.GetRecommendedTLSPaddingProbability()) {
		tlsPadding = prng.Range(
			lightClient.GetRecommendedMinTLSPadding(),
			lightClient.GetRecommendedMaxTLSPadding())
	}

	return &lightDialParameters{
		TLSProfile:               tlsProfile,
		RandomizedTLSProfileSeed: randomizedTLSProfileSeed,
		SNI:                      SNI,
		FragmentClientHello:      fragmentClientHello,
		TLSPadding:               tlsPadding,
	}, nil
}

func dialLightProxy(
	ctx context.Context,
	config *Config,
	lightClient *light.Client,
	remoteAddr string) (net.Conn, error) {

	dialParams := config.GetLightProxyDialParameters()

	isReplay := dialParams.isReplay()
	if !isReplay {

		var err error
		dialParams, err = makeLightDialParameters(config, lightClient)
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	logFields := common.LogFields{"isReplay": isReplay}

	conn, err := lightClient.Dial(
		ctx,
		logFields,
		GetNetworkType(config.GetNetworkID()),
		dialParams.TLSProfile,
		dialParams.RandomizedTLSProfileSeed,
		dialParams.SNI,
		dialParams.FragmentClientHello,
		dialParams.TLSPadding,
		remoteAddr)
	if err != nil {
		if ctx.Err() == nil {
			config.SetLightProxyDialParameters(&lightDialParameters{})
		}
		return nil, errors.Trace(err)
	}

	// Simple session-only replay: reuse the last SNI and TLS
	// profile/randomized seed that successfully dialed. Concurrent
	// successful dials may clobber this value, but every stored value
	// succeeded.

	config.SetLightProxyDialParameters(dialParams)

	return conn, nil
}

func selectLightProxySNI(
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
				NoticeWarning("selectLightProxySNI: regen.Generate failed: %v", errors.Trace(err))
				SNI = values.GetHostName()
			}
			return SNI
		}
		return recommendedSNI
	}

	if p.WeightedCoinFlip(parameters.LightProxyCustomHostNameProbability) {
		regexStrings := p.RegexStrings(parameters.LightProxyCustomHostNameRegexes)
		if len(regexStrings) == 0 {
			return values.GetHostName()
		}
		choice := prng.Intn(len(regexStrings))
		SNI, err := regen.GenerateString(regexStrings[choice])
		if err != nil {
			NoticeWarning("selectLightProxySNI: regen.Generate failed: %v", errors.Trace(err))
			SNI = values.GetHostName()
		}
		return SNI
	}

	return values.GetHostName()
}

type lightProxyDialResult struct {
	conn net.Conn
	err  error
}

const lightProxyTunnelRacePollInterval = 50 * time.Millisecond

func dialLightProxyRace(
	controller *Controller,
	lightClient *light.Client,
	remoteAddr string,
	downstreamConn net.Conn,
	readInactiveThreshold time.Duration) (net.Conn, *Tunnel, error) {

	// Initiate a light proxy dial and run a race between that dial and any
	// concurrent tunnel dial. This allows for selecting the tunnel if it's
	// just about to connect, or if the read inactive test passes as a
	// connected tunnel was simply idle.

	dialTimeout := controller.config.GetLightProxyDialTimeout()

	lightDialCtx, cancel := context.WithTimeout(
		controller.runCtx, dialTimeout)
	defer cancel()

	lightResult := make(chan lightProxyDialResult)
	var lightDialWaitGroup sync.WaitGroup

	lightDialWaitGroup.Add(1)
	go func() {
		defer lightDialWaitGroup.Done()

		conn, err := dialLightProxy(
			lightDialCtx, controller.config, lightClient, remoteAddr)
		lightResult <- lightProxyDialResult{conn: conn, err: err}
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
	ticker := time.NewTicker(lightProxyTunnelRacePollInterval)
	defer ticker.Stop()

	for {
		select {
		case result := <-lightResult:

			if result.err == nil {
				// Close downstreamConn when the light conn is closed. See
				// Controller.Dial and TunneledConn.
				return &lightProxyConn{
					Conn:           result.conn,
					downstreamConn: downstreamConn,
				}, nil, nil
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

type lightProxyConn struct {
	net.Conn
	downstreamConn net.Conn
}

func (conn *lightProxyConn) Close() error {
	if conn.downstreamConn != nil {
		_ = conn.downstreamConn.Close()
	}

	return conn.Conn.Close()
}

func makeLightProxyTunnelTCPDialer(
	config *Config, dialParams *DialParameters) common.Dialer {

	return func(ctx context.Context, network, addr string) (net.Conn, error) {

		if network != "tcp" {
			return nil, errors.Tracef("%s unsupported", network)
		}

		lightProxyClient := config.GetLightProxyClient()
		if lightProxyClient == nil {
			return nil, errors.TraceNew("missing light proxy client")
		}

		conn, err := dialLightProxy(ctx, config, lightProxyClient, addr)
		if err != nil {
			return nil, errors.Trace(err)
		}

		// Here, the fragmentor is layered above the light proxy, so it
		// changes the shape of the traffic within the light proxy
		// transport, but not the network wire shape. This is intended
		// since light proxy has its own shaping.

		if dialParams.dialConfig.FragmentorConfig.MayFragment() {
			conn = fragmentor.NewConn(
				dialParams.dialConfig.FragmentorConfig,
				func(message string) {
					NoticeFragmentor(dialParams.dialConfig.DiagnosticID, message)
				},
				conn)
		}

		return conn, nil
	}
}
