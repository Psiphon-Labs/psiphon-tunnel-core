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

// Command lightproxy is a test harness for fallback light proxies.
// Personal and common tunnel modes are not supported; use
// psiphon.Controller for tunnel proxies.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
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
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tlsdialer"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/transforms"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/internal/testutils"
	utls "github.com/Psiphon-Labs/utls"
	"golang.org/x/sync/errgroup"
)

// This program is intended for testing fallback light proxies and does not
// provide production-grade logging or wire up GeoIP lookup.

func main() {

	var configFilename string
	var entryFilename string
	var providerID string
	var dialAddresses stringListFlag
	var listenAddresses stringListFlag
	var recommendedSNI string
	var recommendedSNIRegex string
	var recommendedSNIProbability float64
	var recommendedTLSProfile string
	var recommendedTLSProfileProbability float64
	var recommendedFragmentClientHelloProbability float64
	var recommendedTLSPaddingProbability float64
	var recommendedMinTLSPadding int
	var recommendedMaxTLSPadding int
	var proxyEntryTTL time.Duration
	var allowedDestinations stringListFlag
	var passthroughAddress string
	var splitUpstreamInterfaceName string
	var splitDownstreamInterfaceName string
	var destination string
	var workerCount int
	var minSleepDuration time.Duration
	var maxSleepDuration time.Duration
	var disableTLSCache bool
	var lightProxyFetchTimeout time.Duration

	flag.StringVar(
		&configFilename,
		"config",
		"lightproxy.config",
		"run/generate config filename")

	flag.StringVar(
		&entryFilename,
		"entry",
		"lightproxy.entry",
		"generate/test proxy entry filename")

	flag.StringVar(
		&providerID,
		"providerID",
		"",
		"generate proxy provider ID; optional")

	flag.Var(
		&dialAddresses,
		"dialAddress",
		"generate proxy dial endpoint: tls://IP:port or quic://IP:port; flag may be repeated")

	flag.Var(
		&listenAddresses,
		"listenAddress",
		"generate proxy listen endpoint; same format and order as dial endpoints; defaults to dial endpoints")

	flag.StringVar(
		&recommendedSNI,
		"recommendedSNI",
		"",
		"generate recommended SNI; optional")

	flag.StringVar(
		&recommendedSNIRegex,
		"recommendedSNIRegex",
		"",
		"generate recommended SNI regex; optional")

	flag.Float64Var(
		&recommendedSNIProbability,
		"recommendedSNIProbability",
		0.0,
		"generate recommended SNI probability; optional")

	flag.StringVar(
		&recommendedTLSProfile,
		"recommendedTLSProfile",
		"",
		"generate recommended TLS profile; optional")

	flag.Float64Var(
		&recommendedTLSProfileProbability,
		"recommendedTLSProfileProbability",
		0.0,
		"generate recommended TLS profile probability; optional")

	flag.Float64Var(
		&recommendedFragmentClientHelloProbability,
		"recommendedFragmentClientHelloProbability",
		0.0,
		"generate recommended FragmentClientHello probability; optional")

	flag.Float64Var(
		&recommendedTLSPaddingProbability,
		"recommendedTLSPaddingProbability",
		0.0,
		"generate recommended TLS padding probability; optional")

	flag.IntVar(
		&recommendedMinTLSPadding,
		"recommendedMinTLSPadding",
		0,
		"generate recommended minimum TLS padding; optional")

	flag.IntVar(
		&recommendedMaxTLSPadding,
		"recommendedMaxTLSPadding",
		0,
		"generate recommended maximum TLS padding; optional")

	flag.DurationVar(
		&proxyEntryTTL,
		"proxyEntryTTL",
		0,
		"generate proxy entry TTL; optional; 0 means no expiry")

	flag.Var(
		&allowedDestinations,
		"allowedDestination",
		"generate allowed destination address; flag may be repeated")

	flag.StringVar(
		&passthroughAddress,
		"passthroughAddress",
		"",
		"generate passthrough address; required when TLS is enabled")

	flag.StringVar(
		&splitUpstreamInterfaceName,
		"splitUpstreamInterface",
		"",
		"generate split upstream interface name; optional")

	flag.StringVar(
		&splitDownstreamInterfaceName,
		"splitDownstreamInterface",
		"",
		"generate split downstream interface name; optional")

	flag.StringVar(
		&destination,
		"destination",
		"",
		"test HTTPS destination address; must include port")

	flag.IntVar(
		&workerCount,
		"workerCount",
		1,
		"test worker count")

	flag.DurationVar(
		&minSleepDuration,
		"minSleepDuration",
		1*time.Second,
		"test minimum sleep duration")

	flag.DurationVar(
		&maxSleepDuration,
		"maxSleepDuration",
		2*time.Second,
		"test maximum sleep duration")

	flag.BoolVar(
		&disableTLSCache,
		"disableTLSCache",
		false,
		"test disable TLS client session cache")

	flag.DurationVar(
		&lightProxyFetchTimeout,
		"fetchTimeout",
		20*time.Second,
		"test fetch timeout")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr,
			"Usage:\n\n"+
				"%s <flags> generate    generates a light proxy config and entry\n"+
				"%s <flags> run         runs a light proxy\n"+
				"%s <flags> test        tests a light proxy\n\n",
			os.Args[0], os.Args[0], os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	args := flag.Args()

	if len(args) < 1 {
		flag.Usage()
		os.Exit(1)
	}

	if args[0] == "generate" {
		err := func() error {

			if len(dialAddresses) == 0 {
				return errors.TraceNew("missing dial address")
			}

			parseAddresses := func(addresses []string) ([]light.ProxyAddress, error) {
				var result []light.ProxyAddress
				for _, address := range addresses {
					proxyProtocol := light.LIGHT_PROTOCOL_TLS
					if scheme, endpoint, ok := strings.Cut(address, "://"); ok {
						switch strings.ToLower(scheme) {
						case "tls":
							proxyProtocol = light.LIGHT_PROTOCOL_TLS
						case "quic":
							proxyProtocol = light.LIGHT_PROTOCOL_QUIC
						default:
							return nil, errors.TraceNew("unsupported proxy protocol")
						}
						address = endpoint
					}

					host, portString, err := net.SplitHostPort(address)
					if err != nil {
						return nil, errors.Trace(err)
					}
					port, err := strconv.Atoi(portString)
					if err != nil {
						return nil, errors.Trace(err)
					}
					result = append(result, light.ProxyAddress{
						IPAddress: host,
						Port:      port,
						Protocol:  proxyProtocol,
					})
				}
				return result, nil
			}

			proxyDialAddresses, err := parseAddresses(dialAddresses)
			if err != nil {
				return errors.Trace(err)
			}
			proxyListenAddresses, err := parseAddresses(listenAddresses)
			if err != nil {
				return errors.Trace(err)
			}

			config, entry, err := light.Generate(
				providerID,
				proxyListenAddresses,
				proxyDialAddresses,
				recommendedSNI,
				recommendedSNIRegex,
				recommendedSNIProbability,
				recommendedTLSProfile,
				recommendedTLSProfileProbability,
				recommendedFragmentClientHelloProbability,
				recommendedTLSPaddingProbability,
				recommendedMinTLSPadding,
				recommendedMaxTLSPadding,
				proxyEntryTTL,
				[]string(allowedDestinations),
				nil,
				nil,
				nil,
				passthroughAddress,
				"",
				"")
			if err != nil {
				return errors.Trace(err)
			}

			config.SplitUpstreamInterfaceName = splitUpstreamInterfaceName
			config.SplitDownstreamInterfaceName = splitDownstreamInterfaceName

			configJSON, err := json.MarshalIndent(config, "", "  ")
			if err != nil {
				return errors.Trace(err)
			}

			err = os.WriteFile(configFilename, append(configJSON, '\n'), 0600)
			if err != nil {
				return errors.Trace(err)
			}

			err = os.WriteFile(entryFilename, entry, 0600)
			if err != nil {
				return errors.Trace(err)
			}

			return nil
		}()
		if err != nil {
			fmt.Printf("generate failed: %s\n", err)
			os.Exit(1)
		}

	} else if args[0] == "run" {
		err := func() error {

			configJSON, err := os.ReadFile(configFilename)
			if err != nil {
				return errors.Trace(err)
			}

			var config light.ProxyConfig
			err = json.Unmarshal(configJSON, &config)
			if err != nil {
				return errors.Trace(err)
			}

			lookupGeoIP := func(string) common.GeoIPData {
				return common.GeoIPData{}
			}

			proxy, err := light.NewProxy(&config, lookupGeoIP, &proxyEventReceiver{})
			if err != nil {
				return errors.Trace(err)
			}

			err = proxy.Run(context.Background())
			if err != nil {
				return errors.Trace(err)
			}

			return nil
		}()
		if err != nil {
			fmt.Printf("run failed: %s\n", err)
			os.Exit(1)
		}

	} else if args[0] == "test" {
		err := runTestLightProxy(
			entryFilename,
			destination,
			workerCount,
			minSleepDuration,
			maxSleepDuration,
			disableTLSCache,
			lightProxyFetchTimeout)
		if err != nil {
			fmt.Printf("test failed: %s\n", err)
			os.Exit(1)
		}

	} else {
		flag.Usage()
		os.Exit(1)
	}
}

func runTestLightProxy(
	entryFilename string,
	destination string,
	workerCount int,
	minSleepDuration time.Duration,
	maxSleepDuration time.Duration,
	disableTLSCache bool,
	lightProxyFetchTimeout time.Duration) error {

	if destination == "" {
		return errors.TraceNew("missing destination")
	}

	_, _, err := net.SplitHostPort(destination)
	if err != nil {
		return errors.Trace(err)
	}

	if workerCount < 1 {
		return errors.TraceNew("invalid workerCount")
	}

	if minSleepDuration < 0 {
		return errors.TraceNew("invalid minSleepDuration")
	}

	if maxSleepDuration < minSleepDuration {
		return errors.TraceNew("invalid maxSleepDuration")
	}

	if lightProxyFetchTimeout <= 0 {
		return errors.TraceNew("invalid fetchTimeout")
	}

	proxyEntry, err := os.ReadFile(entryFilename)
	if err != nil {
		return errors.Trace(err)
	}

	params, err := parameters.NewParameters(nil)
	if err != nil {
		return errors.Trace(err)
	}

	var tlsClientSessionCache utls.ClientSessionCache
	var quicClientSessionCache tls.ClientSessionCache
	if !disableTLSCache {
		tlsClientSessionCache = utls.NewLRUClientSessionCache(0)
		quicClientSessionCache = tls.NewLRUClientSessionCache(0)
	}

	tlsDialer := func(
		ctx context.Context,
		underlyingConn net.Conn,
		_ string,
		tlsProfile string,
		randomizedTLSProfileSeed *prng.Seed,
		sni string,
		fragmentClientHello bool,
		tlsPadding int,
		passthroughMessage []byte,
		verifyPin string) (net.Conn, error) {

		tlsConfig := &tlsdialer.Config{
			Parameters: params,
			Dial: func(context.Context, string, string) (net.Conn, error) {
				return underlyingConn, nil
			},
			UseDialAddrSNI:           false,
			SNIServerName:            sni,
			VerifyPins:               []string{verifyPin},
			VerifyPinsOnly:           true,
			TLSProfile:               tlsProfile,
			RandomizedTLSProfileSeed: randomizedTLSProfileSeed,
			FragmentClientHello:      fragmentClientHello,
			TLSPadding:               tlsPadding,
			PassthroughMessage:       passthroughMessage,
		}

		if tlsClientSessionCache != nil {
			tlsConfig.ClientSessionCache = common.WrapUtlsClientSessionCache(
				tlsClientSessionCache,
				underlyingConn.RemoteAddr().String())
		}

		return tlsdialer.Dial(
			ctx,
			"tcp",
			underlyingConn.RemoteAddr().String(),
			tlsConfig)
	}

	var quicDialer light.ClientQUICDialer
	if quic.Enabled() {
		quicDialer = func(
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

			remoteAddr, err := net.ResolveUDPAddr("udp", address)
			if err != nil {
				return nil, errors.Trace(err)
			}

			network, localAddress := "udp4", "0.0.0.0:0"
			if remoteAddr.IP.To4() == nil {
				network, localAddress = "udp6", "[::]:0"
			}
			listenConfig := net.ListenConfig{}
			packetConn, err := listenConfig.ListenPacket(
				ctx, network, localAddress)
			if err != nil {
				return nil, errors.Trace(err)
			}

			// QUIC requires a cache wrapper; an empty key disables caching.
			sessionCacheKey := address
			if disableTLSCache {
				sessionCacheKey = common.TLS_NULL_SESSION_KEY
			}

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
					quicClientSessionCache, sessionCacheKey))
			if err != nil {
				packetConn.Close()
				return nil, errors.Trace(err)
			}
			return conn, nil
		}
	}

	infoLogSampleRate := float64(10) / float64(workerCount)
	logger := testutils.NewTestLoggerWithInfoSampling(infoLogSampleRate)

	client, err := light.NewClient(&light.ClientConfig{
		Logger: logger,
		TCPDialer: func(ctx context.Context, addr string) (net.Conn, error) {
			d := &net.Dialer{}
			conn, err := d.DialContext(ctx, "tcp", addr)
			return conn, errors.Trace(err)
		},
		TLSDialer:         tlsDialer,
		QUICDialer:        quicDialer,
		SponsorID:         "0000000000000000",
		ClientPlatform:    "lightproxy",
		ClientBuildRev:    buildinfo.GetBuildInfo().BuildRev,
		ProxyEntryTracker: 0,
		ProxyEntry:        proxyEntry,
	})
	if err != nil {
		return errors.Trace(err)
	}

	group, ctx := errgroup.WithContext(context.Background())
	for i := 0; i < workerCount; i++ {
		workerID := i + 1
		group.Go(func() error {
			for {
				time.Sleep(prng.Period(minSleepDuration, maxSleepDuration))
				_ = lightProxyTestFetch(
					ctx,
					params,
					client,
					workerID,
					destination,
					lightProxyFetchTimeout)
			}
		})
	}

	return errors.Trace(group.Wait())
}

func lightProxyTestFetch(
	ctx context.Context,
	params *parameters.Parameters,
	lightClient *light.Client,
	workerID int,
	destination string,
	lightProxyFetchTimeout time.Duration) (retErr error) {

	testURL := url.URL{
		Scheme: "https",
		Host:   destination,
		Path:   "",
	}

	requestCtx, cancel := context.WithTimeout(ctx, lightProxyFetchTimeout)
	defer cancel()

	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(_ context.Context, _, address string) (net.Conn, error) {
			// Use requestCtx, as the QUIC dial requires a context with a
			// deadline.
			conn, err := lightClient.Dial(
				requestCtx,
				nil,
				0,
				"UNKNOWN",
				"",
				protocol.TLS_PROFILE_CHROME_133,
				nil,
				protocol.QUIC_VERSION_V1,
				nil,
				nil,
				false,
				"",
				false,
				0,
				address,
				nil)
			if err != nil {
				return nil, errors.Trace(err)
			}
			return conn, nil
		},
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	request, err := http.NewRequestWithContext(
		requestCtx, http.MethodGet, testURL.String(), nil)
	if err != nil {
		return errors.Trace(err)
	}

	response, err := client.Do(request)
	if err != nil {
		return errors.Trace(err)
	}
	defer response.Body.Close()

	_, err = io.Copy(io.Discard, response.Body)
	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

type proxyEventReceiver struct{}

func (r *proxyEventReceiver) logf(format string, args ...interface{}) {
	fmt.Printf("%s ", time.Now().Format(time.RFC3339))
	fmt.Printf(format, args...)
}

func (r *proxyEventReceiver) Listening(address, ingressProtocol string) {
	r.logf("[Listening] %s %s\n", address, ingressProtocol)
}

func (r *proxyEventReceiver) Started() {
	r.logf("[Started]\n")
}

func (r *proxyEventReceiver) Paused() {
}

func (r *proxyEventReceiver) Resumed() {
}

func (r *proxyEventReceiver) Accepted() {
}

func (r *proxyEventReceiver) Rejected() {
}

func (r *proxyEventReceiver) Activity(stats *light.ActivityStats) {
	const activityFormat = `[Activity] proxyID: %s, providerID: %s, ` +
		`bytesUp: %d, bytesDown: %d, bytesDuration: %s, ` +
		`currentConnectionCount: %d` + "\n"

	r.logf(
		activityFormat,
		stats.ProxyID,
		stats.ProxyProviderID,
		stats.BytesUp,
		stats.BytesDown,
		stats.BytesDuration,
		stats.CurrentConnectionCount)
}

func (r *proxyEventReceiver) Connection(stats *light.ConnectionStats) {
	const connectionFormat = `[Connection] proxyID: %s, ` +
		`proxyConnectionNum: %d, sponsorID: %s, platform: %s, ` +
		`buildRev: %s, deviceRegion: %q, sessionID: %s, ` +
		`tracker: %d, networkType: %s, clientConnectionNum: %d, ` +
		`destination: %q, protocol: %s, tlsProfile: %s, quicVersion: %s, sni: %q, ` +
		`tlsClientHelloFragmented: %t, tlsClientHelloPadding: %d, ` +
		`tlsDidResume: %t, ` +
		`clientTCPDuration: %s, clientTLSDuration: %s, clientQUICDuration: %s, ` +
		`completedTCP: %s, completedTLS: %s, completedQUIC: %s, completedLightHeader: %s, ` +
		`completedUpstreamDNS: %s, completedUpstreamTCP: %s, ` +
		`completedUpstreamTLS: %s, completedUpstreamQUIC: %s, upstreamDNSCached: %v, ` +
		`proxyProtocolHeaderAdded: %t, proxyProtocolHeaderReplaced: %t, ` +
		`bytesRead: %d, bytesWritten: %d, ` +
		`failure: %q, matchedPersonalCompartments: %t` + "\n"

	r.logf(
		connectionFormat,
		stats.ProxyID,
		stats.ProxyConnectionNum,
		stats.SponsorID,
		stats.ClientPlatform,
		stats.ClientBuildRev,
		stats.DeviceRegion,
		stats.SessionID,
		stats.ProxyEntryTracker,
		stats.NetworkType,
		stats.ClientConnectionNum,
		stats.DestinationAddress,
		stats.Protocol,
		stats.TLSProfile,
		stats.QUICVersion,
		stats.SNI,
		stats.TLSClientHelloFragmented,
		stats.TLSClientHelloPadding,
		stats.TLSDidResume,
		stats.ClientTCPDuration,
		stats.ClientTLSDuration,
		stats.ClientQUICDuration,
		stats.ProxyCompletedTCP.Format(time.RFC3339Nano),
		stats.ProxyCompletedTLS.Format(time.RFC3339Nano),
		stats.ProxyCompletedQUIC.Format(time.RFC3339Nano),
		stats.ProxyCompletedLightHeader.Format(time.RFC3339Nano),
		stats.ProxyCompletedUpstreamDNS.Format(time.RFC3339Nano),
		stats.ProxyCompletedUpstreamTCP.Format(time.RFC3339Nano),
		stats.ProxyCompletedUpstreamTLS.Format(time.RFC3339Nano),
		stats.ProxyCompletedUpstreamQUIC.Format(time.RFC3339Nano),
		stats.UpstreamDNSCached,
		stats.ProxyProtocolHeaderAdded,
		stats.ProxyProtocolHeaderReplaced,
		stats.BytesRead,
		stats.BytesWritten,
		stats.Failure,
		stats.MatchedPersonalCompartments)
}

func (r *proxyEventReceiver) IrregularConnection(
	_ string,
	_ common.GeoIPData,
	irregularity string,
) {
	r.logf("[IrregularConnection] %q\n", irregularity)
}

func (r *proxyEventReceiver) DebugLog(_ string, message string) {
	r.logf("[DebugLog] %q\n", message)
}

func (r *proxyEventReceiver) InfoLog(_ string, message string) {
	r.logf("[InfoLog] %q\n", message)
}

func (r *proxyEventReceiver) WarningLog(_ string, message string) {
	// Warning messages include connection failure errors, which may include
	// client-supplied values; escape to prevent forged log lines.
	r.logf("[WarningLog] %q\n", message)
}

func (r *proxyEventReceiver) ErrorLog(_ string, message string) {
	r.logf("[ErrorLog] %q\n", message)
}

type stringListFlag []string

func (list *stringListFlag) String() string {
	return strings.Join(*list, ", ")
}

func (list *stringListFlag) Set(flagValue string) error {
	*list = append(*list, flagValue)
	return nil
}
