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
	"os"
	"strings"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/light"
)

// This program is primarily intended for testing and does not provide
// production-grade logging or wire up GeoIP lookup.

func main() {

	var configFilename string
	var entryFilename string
	var listenAddress string
	var dialAddress string
	var recommendedSNI string
	var allowedDestinations stringListFlag
	var passthroughAddress string

	flag.StringVar(
		&configFilename,
		"config",
		"lightproxy.config",
		"run/generate config filename")

	flag.StringVar(
		&entryFilename,
		"entry",
		"lightproxy.entry",
		"generate proxy entry filename")

	flag.StringVar(
		&listenAddress,
		"listenAddress",
		"",
		"generate proxy listen address")

	flag.StringVar(
		&dialAddress,
		"dialAddress",
		"",
		"generate proxy dial address; optional")

	flag.StringVar(
		&recommendedSNI,
		"recommendedSNI",
		"",
		"generate recommended SNI; optional")

	flag.Var(
		&allowedDestinations,
		"allowedDestination",
		"generate allowed destination address; flag may be repeated")

	flag.StringVar(
		&passthroughAddress,
		"passthroughAddress",
		"",
		"generate passthrough address")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr,
			"Usage:\n\n"+
				"%s <flags> generate    generates a light proxy config and entry\n"+
				"%s <flags> run         runs a light proxy\n\n",
			os.Args[0], os.Args[0])
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
				listenAddress,
				dialAddress,
				recommendedSNI,
				[]string(allowedDestinations),
				passthroughAddress)
			if err != nil {
				return errors.Trace(err)
			}

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

	} else {
		flag.Usage()
		os.Exit(1)
	}
}

type proxyEventReceiver struct{}

func (r *proxyEventReceiver) logf(format string, args ...interface{}) {
	fmt.Printf("%s ", time.Now().Format(time.RFC3339))
	fmt.Printf(format, args...)
}

func (r *proxyEventReceiver) Listening(address string) {
	r.logf("[Listening] %s\n", address)
}

func (r *proxyEventReceiver) Connection(stats *light.ConnectionStats) {
	const connectionFormat = `[Connection] proxyID: %s, ` +
		`proxyConnectionNum: %d, sponsorID: %s, platform: %s, ` +
		`buildRev: %s, clientID: %s, deviceRegion: %s, sessionID: %s, ` +
		`tracker: %d, networkType: %s, clientConnectionNum: %d, ` +
		`destination: %s, tlsProfile: %s, sni: %s, ` +
		`clientTCPDuration: %s, clientTLSDuration: %s, ` +
		`completedTCP: %s, completedTLS: %s, completedLightHeader: %s, ` +
		`completedUpstreamDial: %s, bytesRead: %d, bytesWritten: %d, ` +
		`failure: %v` + "\n"

	r.logf(
		connectionFormat,
		stats.ProxyID,
		stats.ProxyConnectionNum,
		stats.SponsorID,
		stats.ClientPlatform,
		stats.ClientBuildRev,
		stats.ClientID,
		stats.DeviceRegion,
		stats.SessionID,
		stats.ProxyEntryTracker,
		stats.NetworkType,
		stats.ClientConnectionNum,
		stats.DestinationAddress,
		stats.TLSProfile,
		stats.SNI,
		stats.ClientTCPDuration,
		stats.ClientTLSDuration,
		stats.ProxyCompletedTCP.Format(time.RFC3339Nano),
		stats.ProxyCompletedTLS.Format(time.RFC3339Nano),
		stats.ProxyCompletedLightHeader.Format(time.RFC3339Nano),
		stats.ProxyCompletedUpstreamDial.Format(time.RFC3339Nano),
		stats.BytesRead,
		stats.BytesWritten,
		stats.ConnectionFailure)
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
