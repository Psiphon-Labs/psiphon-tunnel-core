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
	"strings"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/buildinfo"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/light"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tlsdialer"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/internal/testutils"
	utls "github.com/Psiphon-Labs/utls"
	"golang.org/x/sync/errgroup"
)

// This program is primarily intended for testing and does not provide
// production-grade logging or wire up GeoIP lookup.

func main() {

	var configFilename string
	var entryFilename string
	var providerID string
	var listenAddresses stringListFlag
	var dialAddressIPv4 string
	var dialAddressIPv6 string
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
		&listenAddresses,
		"listenAddress",
		"generate proxy listen address; flag may be repeated")

	flag.StringVar(
		&dialAddressIPv4,
		"dialAddressIPv4",
		"",
		"generate proxy IPv4 dial address")

	flag.StringVar(
		&dialAddressIPv6,
		"dialAddressIPv6",
		"",
		"generate proxy IPv6 dial address; optional")

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
		"generate passthrough address")

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

			config, entry, err := light.Generate(
				providerID,
				[]string(listenAddresses),
				dialAddressIPv4,
				dialAddressIPv6,
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
				passthroughAddress)
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
	if !disableTLSCache {
		tlsClientSessionCache = utls.NewLRUClientSessionCache(0)
	}

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

		tlsConfig := &tlsdialer.Config{
			Parameters: params,
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

	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(dialCtx context.Context, _, address string) (net.Conn, error) {
			conn, err := lightClient.Dial(
				dialCtx, nil, "UNKNOWN", protocol.TLS_PROFILE_CHROME_133, nil, "", false, 0, address)
			if err != nil {
				return nil, errors.Trace(err)
			}

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

	requestCtx, cancel := context.WithTimeout(ctx, lightProxyFetchTimeout)
	defer cancel()

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

func (r *proxyEventReceiver) Listening(address string) {
	r.logf("[Listening] %s\n", address)
}

func (r *proxyEventReceiver) Paused() {
}

func (r *proxyEventReceiver) Resumed() {
}

func (r *proxyEventReceiver) Accepted() {
}

func (r *proxyEventReceiver) Rejected() {
}

func (r *proxyEventReceiver) Connection(stats *light.ConnectionStats) {
	const connectionFormat = `[Connection] proxyID: %s, ` +
		`proxyConnectionNum: %d, sponsorID: %s, platform: %s, ` +
		`buildRev: %s, deviceRegion: %s, sessionID: %s, ` +
		`tracker: %d, networkType: %s, clientConnectionNum: %d, ` +
		`destination: %s, tlsProfile: %s, sni: %s, ` +
		`tlsClientHelloFragmented: %t, tlsClientHelloPadding: %d, ` +
		`tlsDidResume: %t, ` +
		`clientTCPDuration: %s, clientTLSDuration: %s, ` +
		`completedTCP: %s, completedTLS: %s, completedLightHeader: %s, ` +
		`completedUpstreamDNS: %s, completedUpstreamTCP: %s, upstreamDNSCached: %v, ` +
		`proxyProtocolHeaderAdded: %t, proxyProtocolHeaderReplaced: %t, ` +
		`bytesRead: %d, bytesWritten: %d, ` +
		`failure: %s` + "\n"

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
		stats.TLSProfile,
		stats.SNI,
		stats.TLSClientHelloFragmented,
		stats.TLSClientHelloPadding,
		stats.TLSDidResume,
		stats.ClientTCPDuration,
		stats.ClientTLSDuration,
		stats.ProxyCompletedTCP.Format(time.RFC3339Nano),
		stats.ProxyCompletedTLS.Format(time.RFC3339Nano),
		stats.ProxyCompletedLightHeader.Format(time.RFC3339Nano),
		stats.ProxyCompletedUpstreamDNS.Format(time.RFC3339Nano),
		stats.ProxyCompletedUpstreamTCP.Format(time.RFC3339Nano),
		stats.UpstreamDNSCached,
		stats.ProxyProtocolHeaderAdded,
		stats.ProxyProtocolHeaderReplaced,
		stats.BytesRead,
		stats.BytesWritten,
		stats.Failure)
}

func (r *proxyEventReceiver) IrregularConnection(
	_ string,
	_ common.GeoIPData,
	irregularity string,
) {
	r.logf("[IrregularConnection] %s\n", irregularity)
}

func (r *proxyEventReceiver) DebugLog(_ string, message string) {
	r.logf("[DebugLog] %s\n", message)
}

func (r *proxyEventReceiver) InfoLog(_ string, message string) {
	r.logf("[InfoLog] %s\n", message)
}

func (r *proxyEventReceiver) WarningLog(_ string, message string) {
	r.logf("[WarningLog] %s\n", message)
}

func (r *proxyEventReceiver) ErrorLog(_ string, message string) {
	r.logf("[ErrorLog] %s\n", message)
}

type stringListFlag []string

func (list *stringListFlag) String() string {
	return strings.Join(*list, ", ")
}

func (list *stringListFlag) Set(flagValue string) error {
	*list = append(*list, flagValue)
	return nil
}
