/*
 * Copyright (c) 2016, Psiphon Inc.
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

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	std_errors "errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	socks "github.com/Psiphon-Labs/goptlib"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/accesscontrol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/inproxy"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/quic"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tactics"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/transforms"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/values"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/server/psinet"
	lrucache "github.com/cognusion/go-cache-lru"
	"github.com/miekg/dns"
	"golang.org/x/net/proxy"
)

var testDataDirName string
var mockWebServerURL, mockWebServerPort, mockWebServerExpectedResponse string

func TestMain(m *testing.M) {
	flag.Parse()

	var err error
	testDataDirName, err = ioutil.TempDir("", "psiphon-server-test")
	if err != nil {
		fmt.Printf("TempDir failed: %s\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(testDataDirName)

	psiphon.SetEmitDiagnosticNotices(true, true)

	mockWebServerURL, mockWebServerExpectedResponse = runMockWebServer()

	os.Exit(m.Run())
}

func runMockWebServer() (string, string) {

	responseBody := prng.HexString(100000)

	serveMux := http.NewServeMux()
	serveMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(responseBody))
	})
	server := &http.Server{
		Handler: serveMux,
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Printf("net.Listen failed: %s\n", err)
		os.Exit(1)
	}

	listenAddress := listener.Addr().String()
	_, mockWebServerPort, _ = net.SplitHostPort(listenAddress)

	go func() {
		err := server.Serve(listener)
		if err != nil {
			fmt.Printf("http.Server.Serve failed: %s\n", err)
			os.Exit(1)
		}
	}()

	// TODO: properly synchronize with web server readiness
	time.Sleep(1 * time.Second)

	return fmt.Sprintf("http://%s/", listenAddress), responseBody
}

// Note: not testing fronted meek protocols, which client is
// hard-wired to expect running on privileged ports 80 and 443.

func TestSSH(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "SSH",
			requireAuthorization: true,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			doDanglingTCPConn:    true,
			doLogHostProvider:    true,
		})
}

func TestOSSH(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "OSSH",
			requireAuthorization: true,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			doDanglingTCPConn:    true,
			doLogHostProvider:    true,
		})
}

func TestFragmentedOSSH(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "OSSH",
			requireAuthorization: true,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			forceFragmenting:     true,
			doDanglingTCPConn:    true,
			doLogHostProvider:    true,
		})
}

func TestPrefixedOSSH(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "OSSH",
			requireAuthorization: true,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			applyPrefix:          true,
			doDanglingTCPConn:    true,
			doLogHostProvider:    true,
			inspectFlows:         true,
		})
}

func TestFragmentedPrefixedOSSH(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "OSSH",
			requireAuthorization: true,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			applyPrefix:          true,
			forceFragmenting:     true,
			doDanglingTCPConn:    true,
			doLogHostProvider:    true,
			inspectFlows:         true,
		})
}

// NOTE: breaks the naming convention of dropping the OSSH suffix
// because TestTLS is ambiguous as there are other protocols which
// use TLS, e.g. UNFRONTED-MEEK-HTTPS-OSSH.
func TestTLSOSSH(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "TLS-OSSH",
			passthrough:          true,
			requireAuthorization: true,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			doDanglingTCPConn:    true,
		})
}

func TestUnfrontedMeek(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "UNFRONTED-MEEK-OSSH",
			requireAuthorization: true,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			doDanglingTCPConn:    true,
			doLogHostProvider:    true,
		})
}

func TestFragmentedUnfrontedMeek(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "UNFRONTED-MEEK-OSSH",
			requireAuthorization: true,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			forceFragmenting:     true,
			doDanglingTCPConn:    true,
			doLogHostProvider:    true,
		})
}

func TestUnfrontedMeekHTTPS(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "UNFRONTED-MEEK-HTTPS-OSSH",
			tlsProfile:           protocol.TLS_PROFILE_RANDOMIZED,
			requireAuthorization: true,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			doDanglingTCPConn:    true,
			doLogHostProvider:    true,
		})
}

func TestFragmentedUnfrontedMeekHTTPS(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "UNFRONTED-MEEK-HTTPS-OSSH",
			tlsProfile:           protocol.TLS_PROFILE_RANDOMIZED,
			requireAuthorization: true,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			forceFragmenting:     true,
			doDanglingTCPConn:    true,
			doLogHostProvider:    true,
		})
}

func TestUnfrontedMeekHTTPSTLS13(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "UNFRONTED-MEEK-HTTPS-OSSH",
			tlsProfile:           protocol.TLS_PROFILE_CHROME_70,
			requireAuthorization: true,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			doDanglingTCPConn:    true,
			doLogHostProvider:    true,
		})
}

func TestUnfrontedMeekSessionTicket(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "UNFRONTED-MEEK-SESSION-TICKET-OSSH",
			tlsProfile:           protocol.TLS_PROFILE_CHROME_58,
			requireAuthorization: true,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			doDanglingTCPConn:    true,
			doLogHostProvider:    true,
		})
}

func TestUnfrontedMeekSessionTicketTLS13(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "UNFRONTED-MEEK-SESSION-TICKET-OSSH",
			tlsProfile:           protocol.TLS_PROFILE_CHROME_70,
			requireAuthorization: true,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			doDanglingTCPConn:    true,
			doLogHostProvider:    true,
		})
}

func TestTLSOSSHOverUnfrontedMeekHTTPSDemux(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "UNFRONTED-MEEK-HTTPS-OSSH",
			clientTunnelProtocol: "TLS-OSSH",
			passthrough:          true,
			tlsProfile:           protocol.TLS_PROFILE_CHROME_96, // TLS-OSSH requires TLS 1.3 support
			requireAuthorization: true,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			doDanglingTCPConn:    true,
		})
}

func TestTLSOSSHOverUnfrontedMeekSessionTicketDemux(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "UNFRONTED-MEEK-SESSION-TICKET-OSSH",
			clientTunnelProtocol: "TLS-OSSH",
			passthrough:          true,
			tlsProfile:           protocol.TLS_PROFILE_CHROME_96, // TLS-OSSH requires TLS 1.3 support
			requireAuthorization: true,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			doDanglingTCPConn:    true,
		})
}

func TestQUICOSSH(t *testing.T) {
	if !quic.Enabled() {
		t.Skip("QUIC is not enabled")
	}
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "QUIC-OSSH",
			requireAuthorization: true,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			doLogHostProvider:    true,
		})
}

func TestLimitedQUICOSSH(t *testing.T) {
	if !quic.Enabled() {
		t.Skip("QUIC is not enabled")
	}
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "QUIC-OSSH",
			requireAuthorization: true,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			limitQUICVersions:    true,
			doLogHostProvider:    true,
		})
}

func TestInproxyOSSH(t *testing.T) {
	if !inproxy.Enabled() {
		t.Skip("inproxy is not enabled")
	}
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "INPROXY-WEBRTC-OSSH",
			requireAuthorization: true,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			doDanglingTCPConn:    true,
			doLogHostProvider:    true,
			doTargetBrokerSpecs:  true,
		})
}

func TestInproxyQUICOSSH(t *testing.T) {
	if !quic.Enabled() {
		t.Skip("QUIC is not enabled")
	}
	if !inproxy.Enabled() {
		t.Skip("inproxy is not enabled")
	}
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "INPROXY-WEBRTC-QUIC-OSSH",
			requireAuthorization: true,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			doLogHostProvider:    true,
		})
}

func TestInproxyUnfrontedMeekHTTPS(t *testing.T) {
	if !inproxy.Enabled() {
		t.Skip("inproxy is not enabled")
	}
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "INPROXY-WEBRTC-UNFRONTED-MEEK-HTTPS-OSSH",
			requireAuthorization: true,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			doDanglingTCPConn:    true,
			doLogHostProvider:    true,
		})
}

func TestInproxyTLSOSSH(t *testing.T) {
	if !inproxy.Enabled() {
		t.Skip("inproxy is not enabled")
	}
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "INPROXY-WEBRTC-TLS-OSSH",
			requireAuthorization: true,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			doDanglingTCPConn:    true,
			doLogHostProvider:    true,
		})
}

func TestInproxyPersonalPairing(t *testing.T) {
	if !inproxy.Enabled() {
		t.Skip("inproxy is not enabled")
	}
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "INPROXY-WEBRTC-OSSH",
			requireAuthorization: true,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			doDanglingTCPConn:    true,
			doLogHostProvider:    true,
			doTargetBrokerSpecs:  true,
			doPersonalPairing:    true,
		})
}

func TestHotReload(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "OSSH",
			doHotReload:          true,
			requireAuthorization: true,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			doLogHostProvider:    true,
		})
}

func TestHotReloadWithTactics(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "UNFRONTED-MEEK-OSSH",
			doHotReload:          true,
			requireAuthorization: true,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			doLogHostProvider:    true,
		})
}

func TestDefaultSponsorID(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "OSSH",
			doHotReload:          true,
			doDefaultSponsorID:   true,
			requireAuthorization: true,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			doLogHostProvider:    true,
		})
}

func TestDenyTrafficRules(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "OSSH",
			doHotReload:          true,
			denyTrafficRules:     true,
			requireAuthorization: true,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			doLogHostProvider:    true,
		})
}

func TestOmitAuthorization(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "OSSH",
			doHotReload:          true,
			requireAuthorization: true,
			omitAuthorization:    true,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			doLogHostProvider:    true,
		})
}

func TestNoAuthorization(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "OSSH",
			doHotReload:          true,
			omitAuthorization:    true,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			doLogHostProvider:    true,
		})
}

func TestUnusedAuthorization(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "OSSH",
			doHotReload:          true,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			doLogHostProvider:    true,
		})
}

func TestTCPOnlySLOK(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "OSSH",
			requireAuthorization: true,
			doTunneledWebRequest: true,
			doLogHostProvider:    true,
		})
}

func TestUDPOnlySLOK(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "OSSH",
			requireAuthorization: true,
			doTunneledNTPRequest: true,
			doLogHostProvider:    true,
		})
}

func TestLivenessTest(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "OSSH",
			requireAuthorization: true,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			forceLivenessTest:    true,
			doLogHostProvider:    true,
		})
}

func TestPruneServerEntries(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "OSSH",
			requireAuthorization: true,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			forceLivenessTest:    true,
			doPruneServerEntries: true,
			doLogHostProvider:    true,
		})
}

func TestBurstMonitorAndDestinationBytes(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "OSSH",
			requireAuthorization: true,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			doDanglingTCPConn:    true,
			doBurstMonitor:       true,
			doDestinationBytes:   true,
			doLogHostProvider:    true,
		})
}

func TestChangeBytesConfig(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "OSSH",
			requireAuthorization: true,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			doDanglingTCPConn:    true,
			doDestinationBytes:   true,
			doChangeBytesConfig:  true,
			doLogHostProvider:    true,
		})
}

func TestSplitTunnel(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "OSSH",
			requireAuthorization: true,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			doDanglingTCPConn:    true,
			doSplitTunnel:        true,
			doLogHostProvider:    true,
		})
}

func TestOmitProvider(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "OSSH",
			requireAuthorization: true,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			doDanglingTCPConn:    true,
		})
}

func TestSteeringIP(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "FRONTED-MEEK-OSSH",
			requireAuthorization: true,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			forceFragmenting:     true,
			doDanglingTCPConn:    true,
			doLogHostProvider:    true,
			doSteeringIP:         true,
		})
}

func TestLegacyAPIEncoding(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "OSSH",
			requireAuthorization: true,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			doDanglingTCPConn:    true,
			doLogHostProvider:    true,
			useLegacyAPIEncoding: true,
		})
}

type runServerConfig struct {
	tunnelProtocol       string
	clientTunnelProtocol string
	passthrough          bool
	tlsProfile           string
	doHotReload          bool
	doDefaultSponsorID   bool
	denyTrafficRules     bool
	requireAuthorization bool
	omitAuthorization    bool
	doTunneledWebRequest bool
	doTunneledNTPRequest bool
	applyPrefix          bool
	forceFragmenting     bool
	forceLivenessTest    bool
	doPruneServerEntries bool
	doDanglingTCPConn    bool
	doPacketManipulation bool
	doBurstMonitor       bool
	doSplitTunnel        bool
	limitQUICVersions    bool
	doDestinationBytes   bool
	doChangeBytesConfig  bool
	doLogHostProvider    bool
	inspectFlows         bool
	doSteeringIP         bool
	doTargetBrokerSpecs  bool
	useLegacyAPIEncoding bool
	doPersonalPairing    bool
}

var (
	testSSHClientVersions                = []string{"SSH-2.0-A", "SSH-2.0-B", "SSH-2.0-C"}
	testUserAgents                       = []string{"ua1", "ua2", "ua3"}
	testNetworkType                      = "WIFI"
	testCustomHostNameRegex              = `[a-z0-9]{5,10}\.example\.org`
	testClientFeatures                   = []string{"feature 1", "feature 2"}
	testDisallowedTrafficAlertActionURLs = []string{"https://example.org/disallowed"}

	// A steering IP must not be a bogon; this address is not dialed.
	testSteeringIP = "1.1.1.1"
)

var serverRuns = 0

func runServer(t *testing.T, runConfig *runServerConfig) {

	serverRuns += 1

	psiphonServerIPAddress := "127.0.0.1"
	psiphonServerPort := 4000

	// initialize server entry signing

	serverEntrySignaturePublicKey,
		serverEntrySignaturePrivateKey, err := protocol.NewServerEntrySignatureKeyPair()
	if err != nil {
		t.Fatalf("error generating server entry signature key pair: %s", err)
	}

	// generate inproxy configuration

	doInproxy := protocol.TunnelProtocolUsesInproxy(runConfig.tunnelProtocol)

	var inproxyTestConfig *inproxyTestConfig
	if doInproxy {

		addMeekServerForBroker := true
		brokerIPAddress := "127.0.0.1"
		brokerPort := 4001

		if protocol.TunnelProtocolUsesMeek(runConfig.tunnelProtocol) {
			// Use the existing meek server as the broker server
			addMeekServerForBroker = false
			brokerPort = 4000
		}

		var err error
		inproxyTestConfig, err = generateInproxyTestConfig(
			addMeekServerForBroker,
			runConfig.doTargetBrokerSpecs,
			brokerIPAddress,
			brokerPort,
			serverEntrySignaturePublicKey)
		if err != nil {
			t.Fatalf("error generating inproxy test config: %s", err)
		}
	}

	// configure authorized access

	accessType := "test-access-type"

	accessControlSigningKey, accessControlVerificationKey, err := accesscontrol.NewKeyPair(accessType)
	if err != nil {
		t.Fatalf("error creating access control key pair: %s", err)
	}

	accessControlVerificationKeyRing := accesscontrol.VerificationKeyRing{
		Keys: []*accesscontrol.VerificationKey{accessControlVerificationKey},
	}

	var seedAuthorizationID [32]byte

	clientAuthorization, authorizationID, err := accesscontrol.IssueAuthorization(
		accessControlSigningKey,
		seedAuthorizationID[:],
		time.Now().Add(1*time.Hour))
	if err != nil {
		t.Fatalf("error issuing authorization: %s", err)
	}

	authorizationIDStr := base64.StdEncoding.EncodeToString(authorizationID)

	// Enable tactics when the test protocol is meek or uses inproxy. Both the
	// client and the server will be configured to support tactics. The
	// client config will be set with a nonfunctional config so that the
	// tactics request must succeed, overriding the nonfunctional values, for
	// the tunnel to establish.

	doClientTactics := protocol.TunnelProtocolUsesMeek(runConfig.tunnelProtocol) ||
		doInproxy

	doServerTactics := doClientTactics ||
		runConfig.applyPrefix ||
		runConfig.forceFragmenting ||
		runConfig.doBurstMonitor ||
		runConfig.doDestinationBytes

	// All servers require a tactics config with valid keys.
	tacticsRequestPublicKey, tacticsRequestPrivateKey, tacticsRequestObfuscatedKey, err :=
		tactics.GenerateKeys()
	if err != nil {
		t.Fatalf("error generating tactics keys: %s", err)
	}

	livenessTestSize := 0
	if doClientTactics || runConfig.forceLivenessTest {
		livenessTestSize = 1048576
	}

	// create a server

	var limitQUICVersions protocol.QUICVersions
	if runConfig.limitQUICVersions {

		// Limit the server entry to one specific QUICv1 version, and check
		// that this is used (see expectQUICVersion below). This test case
		// also exercises disabling gQUIC in the server config and
		// using "QUICv1" as the server entry capability.

		selectedQUICVersion := protocol.SupportedQUICv1Versions[prng.Intn(
			len(protocol.SupportedQUICv1Versions))]
		limitQUICVersions = protocol.QUICVersions{selectedQUICVersion}
	}

	var tunnelProtocolPassthroughAddresses map[string]string
	var passthroughAddress *string

	if runConfig.passthrough {
		passthroughAddress = new(string)
		*passthroughAddress = "x.x.x.x:x"

		tunnelProtocolPassthroughAddresses = map[string]string{
			// Tests do not trigger passthrough so set invalid IP and port.
			runConfig.tunnelProtocol: *passthroughAddress,
		}
	}

	tunnelProtocolPorts := map[string]int{runConfig.tunnelProtocol: psiphonServerPort}
	if doInproxy && inproxyTestConfig.addMeekServerForBroker {
		tunnelProtocolPorts["UNFRONTED-MEEK-HTTPS-OSSH"] = inproxyTestConfig.brokerPort
	}

	generateConfigParams := &GenerateConfigParams{
		ServerEntrySignaturePublicKey:      serverEntrySignaturePublicKey,
		ServerEntrySignaturePrivateKey:     serverEntrySignaturePrivateKey,
		ServerIPAddress:                    psiphonServerIPAddress,
		TunnelProtocolPorts:                tunnelProtocolPorts,
		TunnelProtocolPassthroughAddresses: tunnelProtocolPassthroughAddresses,
		Passthrough:                        runConfig.passthrough,
		LimitQUICVersions:                  limitQUICVersions,
		EnableGQUIC:                        !runConfig.limitQUICVersions,
	}

	if doServerTactics {
		generateConfigParams.TacticsRequestPublicKey = tacticsRequestPublicKey
		generateConfigParams.TacticsRequestObfuscatedKey = tacticsRequestObfuscatedKey
	}

	if protocol.TunnelProtocolUsesFrontedMeek(runConfig.tunnelProtocol) {
		generateConfigParams.FrontingProviderID = prng.HexString(8)
	}

	serverConfigJSON, _, _, _, encodedServerEntry, err := GenerateConfig(generateConfigParams)
	if err != nil {
		t.Fatalf("error generating server config: %s", err)
	}

	// customize server config

	discoveryServers, err := newDiscoveryServers([]string{"1.1.1.1", "2.2.2.2"})
	if err != nil {
		t.Fatalf("newDiscoveryServers failed: %s\n", err)
	}

	// Initialize prune server entry test cases and associated data to pave into psinet.
	pruneServerEntryTestCases, psinetValidServerEntryTags, expectedNumPruneNotices :=
		initializePruneServerEntriesTest(t, runConfig)

	// Pave psinet with random values to test handshake homepages.
	psinetFilename := filepath.Join(testDataDirName, "psinet.json")
	sponsorID, expectedHomepageURL := pavePsinetDatabaseFile(
		t, psinetFilename, "", runConfig.doDefaultSponsorID, true, psinetValidServerEntryTags, discoveryServers)

	// Pave OSL config for SLOK testing
	oslConfigFilename := filepath.Join(testDataDirName, "osl_config.json")
	propagationChannelID := paveOSLConfigFile(t, oslConfigFilename)

	// Pave traffic rules file which exercises handshake parameter filtering. Client
	// must handshake with specified sponsor ID in order to allow ports for tunneled
	// requests.
	trafficRulesFilename := filepath.Join(testDataDirName, "traffic_rules.json")
	paveTrafficRulesFile(
		t,
		trafficRulesFilename,
		propagationChannelID,
		accessType,
		authorizationIDStr,
		runConfig.requireAuthorization,
		runConfig.denyTrafficRules,
		livenessTestSize)

	var tacticsConfigFilename string
	var tacticsTunnelProtocol string
	var inproxyTacticsParametersJSON string

	// Only pave the tactics config when tactics are required. This exercises the
	// case where the tactics config is omitted.
	if doServerTactics {
		tacticsConfigFilename = filepath.Join(testDataDirName, "tactics_config.json")

		if runConfig.clientTunnelProtocol != "" {
			tacticsTunnelProtocol = runConfig.clientTunnelProtocol
		} else {
			tacticsTunnelProtocol = runConfig.tunnelProtocol
		}

		if doInproxy {
			inproxyTacticsParametersJSON = inproxyTestConfig.tacticsParametersJSON
		}

		paveTacticsConfigFile(
			t,
			tacticsConfigFilename,
			tacticsRequestPublicKey,
			tacticsRequestPrivateKey,
			tacticsRequestObfuscatedKey,
			tacticsTunnelProtocol,
			propagationChannelID,
			livenessTestSize,
			runConfig.doBurstMonitor,
			runConfig.doDestinationBytes,
			runConfig.applyPrefix,
			runConfig.forceFragmenting,
			"classic",
			inproxyTacticsParametersJSON)
	}

	blocklistFilename := filepath.Join(testDataDirName, "blocklist.csv")
	paveBlocklistFile(t, blocklistFilename)

	var serverConfig map[string]interface{}
	json.Unmarshal(serverConfigJSON, &serverConfig)

	// The test GeoIP databases map all IPs to a single, non-"None" country
	// and ASN.
	//
	// When split tunnel mode is enabled, this should cause port forwards to
	// be untunneled. When split tunnel mode is not enabled, port forwards
	// should be tunneled despite the country match.
	//
	// When destination bytes metrics are enabled, all traffic will map to the
	// single ASN.
	geoIPCityDatabaseFilename := filepath.Join(testDataDirName, "geoip_city_database.mmbd")
	geoIPISPDatabaseFilename := filepath.Join(testDataDirName, "geoip_isp_database.mmbd")
	paveGeoIPDatabaseFiles(t, geoIPCityDatabaseFilename, geoIPISPDatabaseFilename)
	serverConfig["GeoIPDatabaseFilenames"] = []string{geoIPCityDatabaseFilename, geoIPISPDatabaseFilename}

	serverConfig["PsinetDatabaseFilename"] = psinetFilename
	serverConfig["TrafficRulesFilename"] = trafficRulesFilename
	serverConfig["OSLConfigFilename"] = oslConfigFilename
	if doServerTactics {
		serverConfig["TacticsConfigFilename"] = tacticsConfigFilename
	}
	serverConfig["BlocklistFilename"] = blocklistFilename

	serverConfig["LogFilename"] = filepath.Join(testDataDirName, "psiphond.log")
	serverConfig["LogLevel"] = "debug"

	serverConfig["AccessControlVerificationKeyRing"] = accessControlVerificationKeyRing

	// Set this parameter so at least the semaphore functions are called.
	// TODO: test that the concurrency limit is correctly enforced.
	serverConfig["MaxConcurrentSSHHandshakes"] = 1

	// Ensure peak failure rate log fields for a single port forward attempt
	serverConfig["PeakUpstreamFailureRateMinimumSampleSize"] = 1

	// Exercise this option.
	serverConfig["PeriodicGarbageCollectionSeconds"] = 1

	// Allow port forwards to local test web server.
	serverConfig["AllowBogons"] = true

	serverConfig["RunPacketManipulator"] = runConfig.doPacketManipulation

	if protocol.TunnelProtocolUsesQUIC(runConfig.tunnelProtocol) && quic.GQUICEnabled() {
		// Enable legacy QUIC version support.
		serverConfig["EnableGQUIC"] = true
	}

	if runConfig.doLogHostProvider {
		serverConfig["HostProvider"] = "example-host-provider"
	}

	if runConfig.doSteeringIP {
		serverConfig["EnableSteeringIPs"] = true
	}

	// In-proxy setup.

	if doInproxy {

		serverConfig["MeekServerRunInproxyBroker"] = true

		// Limitation: can't exercise MeekServerInproxyBrokerOnly, as the
		// single meek server must also provide a tactics endpoint.

		serverConfig["MeekServerCertificate"] = inproxyTestConfig.brokerServerCertificate
		serverConfig["MeekServerPrivateKey"] = inproxyTestConfig.brokerServerPrivateKey
		serverConfig["MeekRequiredHeaders"] = inproxyTestConfig.brokerMeekRequiredHeaders

		serverConfig["InproxyBrokerSessionPrivateKey"] =
			inproxyTestConfig.brokerSessionPrivateKey

		serverConfig["InproxyBrokerObfuscationRootSecret"] =
			inproxyTestConfig.brokerObfuscationRootSecret

		serverConfig["InproxyBrokerServerEntrySignaturePublicKey"] =
			inproxyTestConfig.brokerServerEntrySignaturePublicKey

		serverConfig["InproxyBrokerAllowCommonASNMatching"] = true
		serverConfig["InproxyBrokerAllowBogonWebRTCConnections"] = true
	}

	// Uncomment to enable SIGUSR2 profile dumps
	//serverConfig["ProcessProfileOutputDirectory"] = "/tmp"

	serverConfigJSON, _ = json.Marshal(serverConfig)

	uniqueUserLog := make(chan map[string]interface{}, 1)
	domainBytesLog := make(chan map[string]interface{}, 1)
	serverTunnelLog := make(chan map[string]interface{}, 1)
	// Max 3 discovery logs:
	// 1. server startup
	// 2. hot reload of psinet db (runConfig.doHotReload)
	// 3. hot reload of server tactics (runConfig.doHotReload && doServerTactics)
	discoveryLog := make(chan map[string]interface{}, 3)

	setLogCallback(func(log []byte) {

		logFields := make(map[string]interface{})

		err := json.Unmarshal(log, &logFields)
		if err != nil {
			return
		}

		if logFields["event_name"] == nil {
			if logFields["discovery_strategy"] != nil {
				select {
				case discoveryLog <- logFields:
				default:
				}
			}
			return
		}

		switch logFields["event_name"].(string) {
		case "unique_user":
			select {
			case uniqueUserLog <- logFields:
			default:
			}
		case "domain_bytes":
			select {
			case domainBytesLog <- logFields:
			default:
			}
		case "server_tunnel":
			select {
			case serverTunnelLog <- logFields:
			default:
			}
		}
	})

	// run flow inspector if requested
	var flowInspectorProxy *flowInspectorProxy
	if runConfig.inspectFlows {
		flowInspectorProxy, err = newFlowInspectorProxy()
		if err != nil {
			t.Fatalf("error starting flow inspector: %s", err)
		}
		flowInspectorProxy.start()
		defer flowInspectorProxy.close()
	}

	// run server

	serverWaitGroup := new(sync.WaitGroup)
	serverWaitGroup.Add(1)
	go func() {
		defer serverWaitGroup.Done()

		// Workaround for one-time logging initialization that persists across
		// test runs. Reset logging to uninitialized. This assumes the
		// previous run has completed and not left any dangling goroutines
		// that may access these variables.
		if log != nil {
			log = nil
			initLogging = sync.Once{}
		}

		err := RunServices(serverConfigJSON)
		if err != nil {
			// TODO: wrong goroutine for t.FatalNow()
			t.Fatalf("error running server: %s", err)
		}
	}()

	stopServer := func() {

		// Test: orderly server shutdown

		p, _ := os.FindProcess(os.Getpid())
		p.Signal(os.Interrupt)

		shutdownTimeout := time.NewTimer(5 * time.Second)

		shutdownOk := make(chan struct{}, 1)
		go func() {
			serverWaitGroup.Wait()
			shutdownOk <- struct{}{}
		}()

		select {
		case <-shutdownOk:
		case <-shutdownTimeout.C:
			t.Fatalf("server shutdown timeout exceeded")
		}
	}

	// Stop server on early exits due to failure.
	defer func() {
		if stopServer != nil {
			stopServer()
		}
	}()

	// TODO: monitor logs for more robust wait-until-loaded. For example,
	// especially with the race detector on, QUIC-OSSH tests can fail as the
	// client sends its initial packet before the server is ready.
	time.Sleep(1 * time.Second)

	// Test: hot reload (of psinet and traffic rules)

	if runConfig.doHotReload {

		// Change discovery servers. Tests that discovery switches over to
		// these new servers.
		discoveryServers, err = newDiscoveryServers([]string{"3.3.3.3"})
		if err != nil {
			t.Fatalf("newDiscoveryServers failed: %s\n", err)
		}

		// Pave new config files with different random values.
		sponsorID, expectedHomepageURL = pavePsinetDatabaseFile(
			t, psinetFilename, "", runConfig.doDefaultSponsorID, true, psinetValidServerEntryTags, discoveryServers)

		propagationChannelID = paveOSLConfigFile(t, oslConfigFilename)

		paveTrafficRulesFile(
			t,
			trafficRulesFilename,
			propagationChannelID,
			accessType,
			authorizationIDStr,
			runConfig.requireAuthorization,
			runConfig.denyTrafficRules,
			livenessTestSize)

		if doServerTactics {
			// Pave new tactics file with different discovery strategy. Tests
			// that discovery switches over to the new strategy.
			paveTacticsConfigFile(
				t,
				tacticsConfigFilename,
				tacticsRequestPublicKey,
				tacticsRequestPrivateKey,
				tacticsRequestObfuscatedKey,
				tacticsTunnelProtocol,
				propagationChannelID,
				livenessTestSize,
				runConfig.doBurstMonitor,
				runConfig.doDestinationBytes,
				runConfig.applyPrefix,
				runConfig.forceFragmenting,
				"consistent",
				inproxyTacticsParametersJSON)
		}

		p, _ := os.FindProcess(os.Getpid())
		p.Signal(syscall.SIGUSR1)

		// TODO: monitor logs for more robust wait-until-reloaded
		time.Sleep(1 * time.Second)

		// After reloading psinet, the new sponsorID/expectedHomepageURL
		// should be active, as tested in the client "Homepage" notice
		// handler below.
	}

	// Exercise server_load logging
	p, _ := os.FindProcess(os.Getpid())
	p.Signal(syscall.SIGUSR2)

	// configure client

	values.SetSSHClientVersionsSpec(values.NewPickOneSpec(testSSHClientVersions))

	values.SetUserAgentsSpec(values.NewPickOneSpec(testUserAgents))

	// TODO: currently, TargetServerEntry only works with one tunnel
	numTunnels := 1
	localSOCKSProxyPort := 1081
	localHTTPProxyPort := 8081

	// Use a distinct suffix for network ID for each test run to ensure tactics
	// from different runs don't apply; this is a workaround for the singleton
	// datastore.
	networkID := fmt.Sprintf("WIFI-%s", time.Now().String())
	jsonNetworkID := fmt.Sprintf(`,"NetworkID" : "%s"`, networkID)

	jsonLimitTLSProfiles := ""
	if runConfig.tlsProfile != "" {
		jsonLimitTLSProfiles = fmt.Sprintf(`,"LimitTLSProfiles" : ["%s"]`, runConfig.tlsProfile)
	}

	testClientFeaturesJSON, _ := json.Marshal(testClientFeatures)

	clientTunnelProtocol := runConfig.tunnelProtocol
	if runConfig.clientTunnelProtocol != "" {
		clientTunnelProtocol = runConfig.clientTunnelProtocol
	}

	clientConfigJSON := fmt.Sprintf(`
    {
        "ClientPlatform" : "Android_10_com.test.app",
        "ClientVersion" : "0",
        "ClientFeatures" : %s,
        "SponsorId" : "0000000000000000",
        "PropagationChannelId" : "0000000000000000",
        "DeviceLocation" : "gzzzz",
        "DeviceRegion" : "US",
        "DisableRemoteServerListFetcher" : true,
        "EstablishTunnelPausePeriodSeconds" : 1,
        "ConnectionWorkerPoolSize" : %d,
        "LimitTunnelProtocols" : ["%s"]
        %s
        %s
    }`,
		string(testClientFeaturesJSON),
		numTunnels,
		clientTunnelProtocol,
		jsonLimitTLSProfiles,
		jsonNetworkID)

	// Don't print initial config setup notices
	psiphon.SetNoticeWriter(io.Discard)

	clientConfig, err := psiphon.LoadConfig([]byte(clientConfigJSON))
	if err != nil {
		t.Fatalf("error processing configuration file: %s", err)
	}

	clientConfig.DataRootDirectory = testDataDirName

	if !runConfig.doDefaultSponsorID {
		clientConfig.SponsorId = sponsorID
	}
	clientConfig.PropagationChannelId = propagationChannelID
	clientConfig.TunnelPoolSize = numTunnels
	clientConfig.TargetServerEntry = string(encodedServerEntry)
	clientConfig.LocalSocksProxyPort = localSOCKSProxyPort
	clientConfig.LocalHttpProxyPort = localHTTPProxyPort
	clientConfig.EmitSLOKs = true
	clientConfig.EmitServerAlerts = true

	// Exercise the WaitForNetworkConnectivity wired-up code path.
	clientConfig.NetworkConnectivityChecker = &networkConnectivityChecker{}

	if runConfig.inspectFlows {
		trueVal := true
		clientConfig.UpstreamProxyURL = fmt.Sprintf("socks5://%s", flowInspectorProxy.listener.Addr())
		clientConfig.UpstreamProxyAllowAllServerEntrySources = &trueVal
	}

	if runConfig.doSplitTunnel {
		clientConfig.SplitTunnelOwnRegion = true
	}

	if !runConfig.omitAuthorization {
		clientConfig.Authorizations = []string{clientAuthorization}
	}

	// When using TLS-OSSH the test expects the server to log the fields
	// tls_ossh_sni_server_name and tls_ossh_transformed_host_name, which are
	// only shipped by the client when the host name is transformed.
	if protocol.TunnelProtocolUsesTLSOSSH(clientTunnelProtocol) {
		transformHostNameProbability := 1.0
		clientConfig.TransformHostNameProbability = &transformHostNameProbability
		clientConfig.CustomHostNameRegexes = []string{testCustomHostNameRegex}
		customHostNameProbability := 1.0
		clientConfig.CustomHostNameProbability = &customHostNameProbability
		clientConfig.CustomHostNameLimitProtocols = []string{clientTunnelProtocol}
	}

	if runConfig.doSteeringIP {

		if runConfig.tunnelProtocol != protocol.TUNNEL_PROTOCOL_FRONTED_MEEK {
			t.Fatalf("steering IP test requires FRONTED-MEEK-OSSH")
		}

		protocol.SetFrontedMeekHTTPDialPortNumber(psiphonServerPort)

		// Note that in an actual fronting deployment, the steering IP header
		// is added to the HTTP request by the CDN and any ingress steering
		// IP header would be stripped to avoid spoofing. To facilitate this
		// test case, we just have the client add the steering IP header as
		// if it were the CDN.

		headers := make(http.Header)
		headers.Set("X-Psiphon-Steering-Ip", testSteeringIP)
		clientConfig.MeekAdditionalHeaders = headers
	}

	if runConfig.useLegacyAPIEncoding {
		clientConfig.TargetAPIEncoding = protocol.PSIPHON_API_ENCODING_JSON
	}

	if doInproxy {

		// Limitation: can't exercise DisableTunnels = true since the client
		// is a singleton and so the single instance must act as both a
		// client and proxy. This self-proxy scheme also requires setting
		// InproxySkipAwaitFullyConnected.

		clientConfig.DisableTunnels = false
		clientConfig.InproxyEnableProxy = true
		clientConfig.InproxySkipAwaitFullyConnected = true

		clientConfig.InproxyProxySessionPrivateKey = inproxyTestConfig.proxySessionPrivateKey
		clientConfig.InproxyMaxClients = 1
		clientConfig.InproxyLimitUpstreamBytesPerSecond = 0
		clientConfig.InproxyLimitDownstreamBytesPerSecond = 0
		clientConfig.ServerEntrySignaturePublicKey = inproxyTestConfig.brokerServerEntrySignaturePublicKey

		if runConfig.doPersonalPairing {

			psiphon.SetAllowOverlappingPersonalCompartmentIDs(true)
			defer psiphon.SetAllowOverlappingPersonalCompartmentIDs(false)

			clientConfig.InproxyClientPersonalCompartmentIDs = []string{inproxyTestConfig.personalCompartmentID}
			clientConfig.InproxyProxyPersonalCompartmentIDs = []string{inproxyTestConfig.personalCompartmentID}
		}

		// Simulate a CDN adding required HTTP headers by injecting them at
		// the client.
		headers := make(http.Header)
		for name, value := range inproxyTestConfig.brokerMeekRequiredHeaders {
			headers.Add(name, value)
		}
		clientConfig.MeekAdditionalHeaders = headers

		// Configure the CAs required to verify the broker TLS certificate.
		clientConfig.TrustedCACertificatesFilename = filepath.Join(testDataDirName, "rootCAs")
		err = ioutil.WriteFile(
			clientConfig.TrustedCACertificatesFilename,
			[]byte(inproxyTestConfig.brokerServerCertificate),
			0600)
		if err != nil {
			t.Fatalf("WriteFile failed: %s", err)
		}
	}

	err = clientConfig.Commit(false)
	if err != nil {
		t.Fatalf("error committing configuration file: %s", err)
	}

	if doClientTactics {
		// Configure nonfunctional values that must be overridden by tactics.

		applyParameters := make(map[string]interface{})

		applyParameters[parameters.TunnelConnectTimeout] = "1s"
		applyParameters[parameters.TunnelRateLimits] = common.RateLimits{WriteBytesPerSecond: 1}

		err = clientConfig.SetParameters("", true, applyParameters)
		if err != nil {
			t.Fatalf("SetParameters failed: %s", err)
		}

	} else {

		// Directly apply same parameters that would've come from tactics.

		applyParameters := make(map[string]interface{})

		if runConfig.applyPrefix {

			applyParameters[parameters.OSSHPrefixSpecs] = transforms.Specs{
				"TEST": {{"", "\x00{200}"}},
			}
			applyParameters[parameters.OSSHPrefixScopedSpecNames] = transforms.ScopedSpecNames{
				"": {"TEST"},
			}
			applyParameters[parameters.OSSHPrefixProbability] = 1.0
			applyParameters[parameters.OSSHPrefixSplitMinDelay] = "10ms"
			applyParameters[parameters.OSSHPrefixSplitMaxDelay] = "20ms"

			applyParameters[parameters.OSSHPrefixEnableFragmentor] = runConfig.forceFragmenting

		}

		if runConfig.forceFragmenting {
			applyParameters[parameters.FragmentorLimitProtocols] = protocol.TunnelProtocols{runConfig.tunnelProtocol}
			applyParameters[parameters.FragmentorProbability] = 1.0
			applyParameters[parameters.FragmentorMinTotalBytes] = 1000
			applyParameters[parameters.FragmentorMaxTotalBytes] = 2000
			applyParameters[parameters.FragmentorMinWriteBytes] = 1
			applyParameters[parameters.FragmentorMaxWriteBytes] = 100
			applyParameters[parameters.FragmentorMinDelay] = 1 * time.Millisecond
			applyParameters[parameters.FragmentorMaxDelay] = 10 * time.Millisecond
		}

		if runConfig.forceLivenessTest {
			applyParameters[parameters.LivenessTestMinUpstreamBytes] = livenessTestSize
			applyParameters[parameters.LivenessTestMaxUpstreamBytes] = livenessTestSize
			applyParameters[parameters.LivenessTestMinDownstreamBytes] = livenessTestSize
			applyParameters[parameters.LivenessTestMaxDownstreamBytes] = livenessTestSize
		}

		if runConfig.doPruneServerEntries {
			applyParameters[parameters.PsiphonAPIStatusRequestShortPeriodMin] = 1 * time.Millisecond
			applyParameters[parameters.PsiphonAPIStatusRequestShortPeriodMax] = 1 * time.Millisecond
		}

		err = clientConfig.SetParameters("", true, applyParameters)
		if err != nil {
			t.Fatalf("SetParameters failed: %s", err)
		}
	}

	// connect to server with client

	err = psiphon.OpenDataStore(clientConfig)
	if err != nil {
		t.Fatalf("error initializing client datastore: %s", err)
	}
	defer psiphon.CloseDataStore()

	// Test unique user counting cases.
	var expectUniqueUser bool
	switch serverRuns % 3 {
	case 0:
		// Mock no last_connected.
		psiphon.SetKeyValue("lastConnected", "")
		expectUniqueUser = true
	case 1:
		// Mock previous day last_connected.
		psiphon.SetKeyValue(
			"lastConnected",
			time.Now().UTC().AddDate(0, 0, -1).Truncate(1*time.Hour).Format(time.RFC3339))
		expectUniqueUser = true
	case 2:
		// Leave previous last_connected.
		expectUniqueUser = false
	}

	// Clear SLOKs from previous test runs.
	psiphon.DeleteSLOKs()

	// Store prune server entry test server entries and failed tunnel records.
	storePruneServerEntriesTest(
		t, runConfig, testDataDirName, pruneServerEntryTestCases)

	controller, err := psiphon.NewController(clientConfig)
	if err != nil {
		t.Fatalf("error creating client controller: %s", err)
	}

	connectedServer := make(chan struct{}, 1)
	inproxyActivity := make(chan struct{}, 1)
	tunnelsEstablished := make(chan struct{}, 1)
	homepageReceived := make(chan struct{}, 1)
	slokSeeded := make(chan struct{}, 1)
	numPruneNotices := 0
	pruneServerEntriesNoticesEmitted := make(chan struct{}, 1)
	serverAlertDisallowedNoticesEmitted := make(chan struct{}, 1)
	untunneledPortForward := make(chan struct{}, 1)

	psiphon.SetNoticeWriter(psiphon.NewNoticeReceiver(
		func(notice []byte) {

			noticeType, payload, err := psiphon.GetNotice(notice)
			if err != nil {
				return
			}

			printNotice := false

			switch noticeType {

			case "ConnectedServer":
				// Check that client connected with the expected protocol.
				protocol := payload["protocol"].(string)
				if protocol != clientTunnelProtocol {
					// TODO: wrong goroutine for t.FatalNow()
					t.Errorf("unexpected protocol: %s", protocol)
				}
				sendNotificationReceived(connectedServer)

			case "Tunnels":
				count := int(payload["count"].(float64))
				if count >= numTunnels {
					sendNotificationReceived(tunnelsEstablished)
				}

			case "Homepage":
				homepageURL := payload["url"].(string)
				if homepageURL != expectedHomepageURL {
					// TODO: wrong goroutine for t.FatalNow()
					t.Errorf("unexpected homepage: %s", homepageURL)
				}
				sendNotificationReceived(homepageReceived)

			case "SLOKSeeded":
				sendNotificationReceived(slokSeeded)

			case "PruneServerEntry":
				numPruneNotices += 1
				if numPruneNotices == expectedNumPruneNotices {
					sendNotificationReceived(pruneServerEntriesNoticesEmitted)
				}

			case "ServerAlert":
				reason := payload["reason"].(string)
				actionURLsPayload := payload["actionURLs"].([]interface{})
				actionURLs := make([]string, len(actionURLsPayload))
				for i, value := range actionURLsPayload {
					actionURLs[i] = value.(string)
				}
				if reason == protocol.PSIPHON_API_ALERT_DISALLOWED_TRAFFIC &&
					reflect.DeepEqual(actionURLs, testDisallowedTrafficAlertActionURLs) {
					sendNotificationReceived(serverAlertDisallowedNoticesEmitted)
				}

			case "Untunneled":
				sendNotificationReceived(untunneledPortForward)

			case "InproxyProxyTotalActivity":

				// This assumes that both non-zero bytes up and down are
				// reported in at least same notice, although there's some
				// unlikely chance it's only one or the other.
				connectedClients := int(payload["connectedClients"].(float64))
				bytesUp := int(payload["totalBytesUp"].(float64))
				bytesDown := int(payload["totalBytesDown"].(float64))
				if connectedClients == 1 && bytesUp > 0 && bytesDown > 0 {
					sendNotificationReceived(inproxyActivity)
				}
			}

			if printNotice {
				fmt.Printf("%s\n", string(notice))
			}
		}))

	ctx, cancelFunc := context.WithCancel(context.Background())

	controllerWaitGroup := new(sync.WaitGroup)

	controllerWaitGroup.Add(1)
	go func() {
		defer controllerWaitGroup.Done()
		controller.Run(ctx)
	}()

	stopClient := func() {
		cancelFunc()

		shutdownTimeout := time.NewTimer(20 * time.Second)

		shutdownOk := make(chan struct{}, 1)
		go func() {
			controllerWaitGroup.Wait()
			shutdownOk <- struct{}{}
		}()

		select {
		case <-shutdownOk:
		case <-shutdownTimeout.C:
			t.Errorf("controller shutdown timeout exceeded")
		}
	}

	// Stop client on early exits due to failure.
	defer func() {
		if stopClient != nil {
			stopClient()
		}
	}()

	// Test: tunnels must be established, and correct homepage
	// must be received, within 30 seconds

	timeoutSignal := make(chan struct{})
	go func() {
		timer := time.NewTimer(30 * time.Second)
		<-timer.C
		close(timeoutSignal)
	}()

	waitOnNotification(t, connectedServer, timeoutSignal, "connected server timeout exceeded")
	if doInproxy {
		waitOnNotification(t, inproxyActivity, timeoutSignal, "inproxy activity timeout exceeded")
	}
	waitOnNotification(t, tunnelsEstablished, timeoutSignal, "tunnel established timeout exceeded")
	waitOnNotification(t, homepageReceived, timeoutSignal, "homepage received timeout exceeded")

	if runConfig.doChangeBytesConfig {

		if !runConfig.doDestinationBytes {
			t.Fatalf("invalid test configuration")
		}

		// Test: now that the client is connected, change the domain bytes and
		// destination bytes configurations. No stats should be logged, even
		// with an already connected client.

		// Pave psinet without domain bytes; retain the same sponsor ID. The
		// random homepage URLs will change, but this has no effect on the
		// already connected client.
		_, _ = pavePsinetDatabaseFile(
			t, psinetFilename, sponsorID, runConfig.doDefaultSponsorID, false, psinetValidServerEntryTags, discoveryServers)

		// Pave tactics without destination bytes.
		paveTacticsConfigFile(
			t,
			tacticsConfigFilename,
			tacticsRequestPublicKey,
			tacticsRequestPrivateKey,
			tacticsRequestObfuscatedKey,
			tacticsTunnelProtocol,
			propagationChannelID,
			livenessTestSize,
			runConfig.doBurstMonitor,
			false,
			runConfig.applyPrefix,
			runConfig.forceFragmenting,
			"consistent",
			inproxyTacticsParametersJSON)

		p, _ := os.FindProcess(os.Getpid())
		p.Signal(syscall.SIGUSR1)

		// TODO: monitor logs for more robust wait-until-reloaded
		time.Sleep(1 * time.Second)
	}

	expectTrafficFailure := runConfig.denyTrafficRules || (runConfig.omitAuthorization && runConfig.requireAuthorization)

	if runConfig.doTunneledWebRequest {

		// Test: tunneled web site fetch

		err = makeTunneledWebRequest(
			t, localHTTPProxyPort, mockWebServerURL, mockWebServerExpectedResponse)

		if err == nil {
			if expectTrafficFailure {
				t.Fatalf("unexpected tunneled web request success")
			}
		} else {
			if !expectTrafficFailure {
				t.Fatalf("tunneled web request failed: %s", err)
			}
		}
	}

	if runConfig.doTunneledNTPRequest {

		// Test: tunneled UDP packets

		udpgwServerAddress := serverConfig["UDPInterceptUdpgwServerAddress"].(string)

		err = makeTunneledNTPRequest(t, localSOCKSProxyPort, udpgwServerAddress)

		if err == nil {
			if expectTrafficFailure {
				t.Fatalf("unexpected tunneled NTP request success")
			}
		} else {
			if !expectTrafficFailure {
				t.Fatalf("tunneled NTP request failed: %s", err)
			}
		}
	}

	// Test: await SLOK payload or server alert notice

	time.Sleep(1 * time.Second)

	if !expectTrafficFailure {

		waitOnNotification(t, slokSeeded, timeoutSignal, "SLOK seeded timeout exceeded")

		numSLOKs := psiphon.CountSLOKs()
		if numSLOKs != expectedNumSLOKs {
			t.Fatalf("unexpected number of SLOKs: %d", numSLOKs)
		}

	} else {

		// Note: in expectTrafficFailure case, timeoutSignal may have already fired.

		waitOnNotification(t, serverAlertDisallowedNoticesEmitted, nil, "")
	}

	// Test: await expected prune server entry notices
	//
	// Note: will take up to PsiphonAPIStatusRequestShortPeriodMax to emit.

	if expectedNumPruneNotices > 0 {
		waitOnNotification(t, pruneServerEntriesNoticesEmitted, nil, "")
	}

	if runConfig.doDanglingTCPConn {

		// Test: client that has established TCP connection but not completed
		// any handshakes must not block/delay server shutdown

		danglingConn, err := net.Dial(
			"tcp", net.JoinHostPort(psiphonServerIPAddress, strconv.Itoa(psiphonServerPort)))
		if err != nil {
			t.Fatalf("TCP dial failed: %s", err)
		}
		defer danglingConn.Close()
	}

	// Test: check for split tunnel notice

	if runConfig.doSplitTunnel {
		if !runConfig.doTunneledWebRequest || expectTrafficFailure {
			t.Fatalf("invalid test run configuration")
		}
		waitOnNotification(t, untunneledPortForward, nil, "")
	} else {
		// There should be no "Untunneled" notice. This check assumes that any
		// unexpected Untunneled notice will have been delivered at this point,
		// after the SLOK notice.
		select {
		case <-untunneledPortForward:
			t.Fatalf("unexpected untunneled port forward")
		default:
		}
	}

	// Trigger server_load logging once more, to exercise
	// sshClient.peakMetrics. As we don't have a reference to the server's
	// Support struct, we can't invoke logServerLoad directly and there's a
	// potential race between asynchronous logServerLoad invocation and
	// client shutdown. For now, we sleep as a workaround.

	p.Signal(syscall.SIGUSR2)
	time.Sleep(1 * time.Second)

	// Shutdown to ensure logs/notices are flushed

	stopClient()
	stopClient = nil
	stopServer()
	stopServer = nil

	// Test: all expected server logs were emitted

	// TODO: stops should be fully synchronous, but, intermittently,
	// server_tunnel fails to appear ("missing server tunnel log")
	// without this delay.
	time.Sleep(100 * time.Millisecond)

	// For in-proxy tunnel protocols, client BPF tactics are currently ignored and not applied by the 2nd hop.
	expectClientBPFField := psiphon.ClientBPFEnabled() && doClientTactics && !protocol.TunnelProtocolUsesInproxy(runConfig.tunnelProtocol)
	expectServerBPFField := ServerBPFEnabled() && protocol.TunnelProtocolIsDirect(runConfig.tunnelProtocol) && doServerTactics
	expectServerPacketManipulationField := runConfig.doPacketManipulation
	expectBurstFields := runConfig.doBurstMonitor
	expectTCPPortForwardDial := runConfig.doTunneledWebRequest
	expectTCPDataTransfer := runConfig.doTunneledWebRequest && !expectTrafficFailure && !runConfig.doSplitTunnel
	// Even with expectTrafficFailure, DNS port forwards will succeed
	expectUDPDataTransfer := runConfig.doTunneledNTPRequest
	expectQUICVersion := ""
	if runConfig.limitQUICVersions {
		expectQUICVersion = limitQUICVersions[0]
	}
	expectDestinationBytesFields := runConfig.doDestinationBytes && !runConfig.doChangeBytesConfig
	expectMeekHTTPVersion := ""
	if protocol.TunnelProtocolUsesMeek(runConfig.tunnelProtocol) {
		if protocol.TunnelProtocolUsesFrontedMeek(runConfig.tunnelProtocol) {
			expectMeekHTTPVersion = "HTTP/2.0"
		} else {
			expectMeekHTTPVersion = "HTTP/1.1"
		}
	}

	// The client still reports zero domain_bytes when no port forwards are
	// allowed (expectTrafficFailure).
	//
	// Limitation: this check is disabled in the in-proxy case since, in the
	// self-proxy scheme, the proxy shuts down before the client can send its
	// final status request.
	expectDomainBytes := !runConfig.doChangeBytesConfig && !doInproxy

	select {
	case logFields := <-serverTunnelLog:
		err := checkExpectedServerTunnelLogFields(
			runConfig,
			doClientTactics,
			expectClientBPFField,
			expectServerBPFField,
			expectServerPacketManipulationField,
			expectBurstFields,
			expectTCPPortForwardDial,
			expectTCPDataTransfer,
			expectUDPDataTransfer,
			expectQUICVersion,
			expectDestinationBytesFields,
			passthroughAddress,
			expectMeekHTTPVersion,
			inproxyTestConfig,
			logFields)
		if err != nil {
			t.Fatalf("invalid server tunnel log fields: %s", err)
		}
	default:
		t.Fatalf("missing server tunnel log")
	}

	if expectUniqueUser {
		select {
		case logFields := <-uniqueUserLog:
			err := checkExpectedUniqueUserLogFields(
				runConfig,
				logFields)
			if err != nil {
				t.Fatalf("invalid unique user log fields: %s", err)
			}
		default:
			t.Fatalf("missing unique user log")
		}
	} else {
		select {
		case <-uniqueUserLog:
			t.Fatalf("unexpected unique user log")
		default:
		}
	}

	if expectDomainBytes {
		select {
		case logFields := <-domainBytesLog:
			err := checkExpectedDomainBytesLogFields(
				runConfig,
				logFields)
			if err != nil {
				t.Fatalf("invalid domain bytes log fields: %s", err)
			}
		default:
			t.Fatalf("missing domain bytes log")
		}
	} else {
		select {
		case <-domainBytesLog:
			t.Fatalf("unexpected domain bytes log")
		default:
		}
	}

	// Check logs emitted by discovery.

	var expectedDiscoveryStrategy []string

	// Discovery emits 1 log on startup.
	if doServerTactics {
		expectedDiscoveryStrategy = append(expectedDiscoveryStrategy, "classic")
	} else {
		expectedDiscoveryStrategy = append(expectedDiscoveryStrategy, "consistent")
	}
	if runConfig.doHotReload {
		if doServerTactics {
			// Discovery emits 1 log when tactics are reloaded, which happens
			// before the psinet database is reloaded.
			expectedDiscoveryStrategy = append(expectedDiscoveryStrategy, "classic")
		}
		// Discovery emits 1 when the psinet database is reloaded.
		expectedDiscoveryStrategy = append(expectedDiscoveryStrategy, "consistent")
	}

	for _, expectedStrategy := range expectedDiscoveryStrategy {
		select {
		case logFields := <-discoveryLog:
			if strategy, ok := logFields["discovery_strategy"].(string); ok {
				if strategy != expectedStrategy {
					t.Fatalf("expected discovery strategy \"%s\"", expectedStrategy)
				}
			} else {
				t.Fatalf("missing discovery_strategy field")
			}
		default:
			t.Fatalf("missing discovery log")
		}
	}

	// Check that datastore had retained/pruned server entries as expected.
	checkPruneServerEntriesTest(t, runConfig, testDataDirName, pruneServerEntryTestCases)

	// Inspect OSSH prefix flows, if applicable.
	if runConfig.inspectFlows && runConfig.applyPrefix {

		flows := <-flowInspectorProxy.ch
		serverFlows := flows[0]
		clientFlows := flows[1]

		expectedClientPrefix := bytes.Repeat([]byte{0x00}, 200)
		expectedServerPrefix := bytes.Repeat([]byte{0x01}, 200)

		if runConfig.forceFragmenting {

			// Fragmentor was applied, so check for prefix in stream dump.
			if !bytes.Equal(clientFlows.streamDump.Bytes()[:200], expectedClientPrefix) {
				t.Fatal("client flow does not have expected prefix")
			}

			if !bytes.Equal(serverFlows.streamDump.Bytes()[:200], expectedServerPrefix) {
				t.Fatal("server flow does not have expected prefix")
			}

			fragmentorMaxWriteBytes := 100
			if len(clientFlows.flows[0].data) > fragmentorMaxWriteBytes {
				t.Fatal("client flow was not fragmented")
			}
			if len(serverFlows.flows[0].data) > fragmentorMaxWriteBytes {
				t.Fatal("server flow was not fragmented")
			}

		} else {
			// Fragmentor was not applied, so check for prefix in first flow.
			if !bytes.Equal(clientFlows.flows[0].data, expectedClientPrefix) {
				t.Fatal("client flow does not have expected prefix")
			}
			if !bytes.Equal(serverFlows.flows[0].data, expectedServerPrefix) {
				t.Fatal("server flow does not have expected prefix")
			}

			// Analyze time between prefix and next packet.
			// client 10-20ms, 30-40ms for server with standard deviation of 2ms.
			clientZtest := testSampleInUniformRange(clientFlows.flows[1].timeDelta.Microseconds(), 10000, 20000, 2000)
			serverZtest := testSampleInUniformRange(serverFlows.flows[1].timeDelta.Microseconds(), 30000, 40000, 2000)

			if !clientZtest {
				t.Fatalf("client write delay after prefix too high: %f ms",
					clientFlows.flows[1].timeDelta.Seconds()*1e3)
			}

			if !serverZtest {
				t.Fatalf("server write delay after prefix too high: %f ms",
					serverFlows.flows[1].timeDelta.Seconds()*1e3)
			}
		}
	}

	if runConfig.doSteeringIP {

		// Access the unexported controller.steeringIPCache
		controllerStruct := reflect.ValueOf(controller).Elem()
		steeringIPCacheField := controllerStruct.Field(40)
		steeringIPCacheField = reflect.NewAt(
			steeringIPCacheField.Type(), unsafe.Pointer(steeringIPCacheField.UnsafeAddr())).Elem()
		steeringIPCache := steeringIPCacheField.Interface().(*lrucache.Cache)

		if steeringIPCache.ItemCount() != 1 {
			t.Fatalf("unexpected steering IP cache size: %d", steeringIPCache.ItemCount())
		}

		key := fmt.Sprintf(
			"%s %s %s",
			networkID,
			generateConfigParams.FrontingProviderID,
			runConfig.tunnelProtocol)

		entry, ok := steeringIPCache.Get(key)
		if !ok {
			t.Fatalf("no entry for steering IP cache key: %s", key)
		}

		if entry.(string) != testSteeringIP {
			t.Fatalf("unexpected cached steering IP: %v", entry)
		}
	}

	// Check that the client discovered one of the discovery servers.

	discoveredServers := make(map[string]*protocol.ServerEntry)

	// Otherwise NewServerEntryIterator only returns TargetServerEntry.
	clientConfig.TargetServerEntry = ""

	_, iterator, err := psiphon.NewServerEntryIterator(clientConfig)
	if err != nil {
		t.Fatalf("NewServerEntryIterator failed: %s", err)
	}
	defer iterator.Close()

	for {
		serverEntry, err := iterator.Next()
		if err != nil {
			t.Fatalf("ServerIterator.Next failed: %s", err)
		}
		if serverEntry == nil {
			break
		}
		discoveredServers[serverEntry.IpAddress] = serverEntry
	}

	foundOne := false
	for _, server := range discoveryServers {

		serverEntry, err := protocol.DecodeServerEntry(server.EncodedServerEntry, "", "")
		if err != nil {
			t.Fatalf("protocol.DecodeServerEntry failed: %s", err)
		}

		if v, ok := discoveredServers[serverEntry.IpAddress]; ok {
			if v.Tag == serverEntry.Tag {
				foundOne = true
				break
			}
		}
	}
	if !foundOne {
		t.Fatalf("expected client to discover at least one server")
	}
}

func sendNotificationReceived(c chan<- struct{}) {
	select {
	case c <- struct{}{}:
	default:
	}
}

func waitOnNotification(t *testing.T, c, timeoutSignal <-chan struct{}, timeoutMessage string) {
	if timeoutSignal == nil {
		<-c
	} else {
		select {
		case <-c:
		case <-timeoutSignal:
			t.Fatalf(timeoutMessage)
		}
	}
}

type networkConnectivityChecker struct {
}

func (c *networkConnectivityChecker) HasNetworkConnectivity() int {
	return 1
}

func checkExpectedServerTunnelLogFields(
	runConfig *runServerConfig,
	expectAppliedTacticsTag bool,
	expectClientBPFField bool,
	expectServerBPFField bool,
	expectServerPacketManipulationField bool,
	expectBurstFields bool,
	expectTCPPortForwardDial bool,
	expectTCPDataTransfer bool,
	expectUDPDataTransfer bool,
	expectQUICVersion string,
	expectDestinationBytesFields bool,
	expectPassthroughAddress *string,
	expectMeekHTTPVersion string,
	inproxyTestConfig *inproxyTestConfig,
	fields map[string]interface{}) error {

	// Limitations:
	//
	// - client_build_rev not set in test build (see common/buildinfo.go)
	// - egress_region, upstream_proxy_type, upstream_proxy_custom_header_names not exercised in test
	// - fronting_provider_id/meek_dial_ip_address/meek_resolved_ip_address only logged for FRONTED meek protocols

	for _, name := range []string{
		"host_id",
		"start_time",
		"duration",
		"session_id",
		"is_first_tunnel_in_session",
		"last_connected",
		"establishment_duration",
		"propagation_channel_id",
		"sponsor_id",
		"client_platform",
		"client_features",
		"relay_protocol",
		"device_region",
		"device_location",
		"ssh_client_version",
		"server_entry_region",
		"server_entry_source",
		"server_entry_timestamp",
		"dial_port_number",
		"is_replay",
		"dial_duration",
		"candidate_number",
		"established_tunnels_count",
		"network_latency_multiplier",
		"network_type",

		// The test run ensures that logServerLoad is invoked while the client
		// is connected, so the following must be logged.
		"peak_concurrent_proximate_accepted_clients",
		"peak_concurrent_proximate_established_clients",
	} {
		if fields[name] == nil || fmt.Sprintf("%s", fields[name]) == "" {
			return fmt.Errorf("missing expected field '%s'", name)
		}
	}

	appliedTacticsTag := len(fields[tactics.APPLIED_TACTICS_TAG_PARAMETER_NAME].(string)) > 0
	if expectAppliedTacticsTag != appliedTacticsTag {
		return fmt.Errorf("unexpected applied_tactics_tag")
	}

	if fields["host_id"].(string) != "example-host-id" {
		return fmt.Errorf("unexpected host_id '%s'", fields["host_id"])
	}

	expectedRelayProtocol := runConfig.tunnelProtocol
	if runConfig.clientTunnelProtocol != "" {
		expectedRelayProtocol = runConfig.clientTunnelProtocol
	}

	if fields["relay_protocol"].(string) != expectedRelayProtocol {
		return fmt.Errorf("unexpected relay_protocol '%s'", fields["relay_protocol"])
	}

	if !common.Contains(testSSHClientVersions, fields["ssh_client_version"].(string)) {
		return fmt.Errorf("unexpected ssh_client_version '%s'", fields["ssh_client_version"])
	}

	clientFeatures := fields["client_features"].([]interface{})
	if len(clientFeatures) != len(testClientFeatures) {
		return fmt.Errorf("unexpected client_features '%s'", fields["client_features"])
	}
	for i, feature := range testClientFeatures {
		if clientFeatures[i].(string) != feature {
			return fmt.Errorf("unexpected client_features '%s'", fields["client_features"])
		}
	}

	if fields["network_type"].(string) != testNetworkType {
		return fmt.Errorf("unexpected network_type '%s'", fields["network_type"])
	}

	// With interruptions, timeouts, and retries in some tests, there may be
	// more than one dangling accepted_client.

	peakConcurrentProximateAcceptedClients :=
		int(fields["peak_concurrent_proximate_accepted_clients"].(float64))
	if peakConcurrentProximateAcceptedClients < 0 ||
		peakConcurrentProximateAcceptedClients > 10 {
		return fmt.Errorf(
			"unexpected peak_concurrent_proximate_accepted_clients '%v'",
			fields["peak_concurrent_proximate_accepted_clients"])
	}

	peakConcurrentProximateEstablishedClients :=
		int(fields["peak_concurrent_proximate_established_clients"].(float64))
	if peakConcurrentProximateEstablishedClients != 0 {
		return fmt.Errorf(
			"unexpected peak_concurrent_proximate_established_clients '%v'",
			fields["peak_concurrent_proximate_established_clients"])
	}

	// In some negative test cases, no port forwards are attempted, in which
	// case these fields are not logged.

	if expectTCPDataTransfer {

		if fields["peak_tcp_port_forward_failure_rate"] == nil {
			return fmt.Errorf("missing expected field 'peak_tcp_port_forward_failure_rate'")
		}
		if fields["peak_tcp_port_forward_failure_rate"].(float64) != 0.0 {
			return fmt.Errorf(
				"unexpected peak_tcp_port_forward_failure_rate '%v'",
				fields["peak_tcp_port_forward_failure_rate"])
		}

		if fields["peak_tcp_port_forward_failure_rate_sample_size"] == nil {
			return fmt.Errorf("missing expected field 'peak_tcp_port_forward_failure_rate_sample_size'")
		}
		if fields["peak_tcp_port_forward_failure_rate_sample_size"].(float64) <= 0.0 {
			return fmt.Errorf(
				"unexpected peak_tcp_port_forward_failure_rate_sample_size '%v'",
				fields["peak_tcp_port_forward_failure_rate_sample_size"])
		}

	} else {

		if fields["peak_tcp_port_forward_failure_rate"] != nil {
			return fmt.Errorf("unexpected field 'peak_tcp_port_forward_failure_rate'")
		}

		if fields["peak_tcp_port_forward_failure_rate_sample_size"] != nil {
			return fmt.Errorf("unexpected field 'peak_tcp_port_forward_failure_rate_sample_size'")
		}
	}

	if expectUDPDataTransfer {

		if fields["peak_dns_failure_rate"] == nil {
			return fmt.Errorf("missing expected field 'peak_dns_failure_rate'")
		}
		if fields["peak_dns_failure_rate"].(float64) != 0.0 {
			return fmt.Errorf(
				"unexpected peak_dns_failure_rate '%v'", fields["peak_dns_failure_rate"])
		}

		if fields["peak_dns_failure_rate_sample_size"] == nil {
			return fmt.Errorf("missing expected field 'peak_dns_failure_rate_sample_size'")
		}
		if fields["peak_dns_failure_rate_sample_size"].(float64) <= 0.0 {
			return fmt.Errorf(
				"unexpected peak_dns_failure_rate_sample_size '%v'",
				fields["peak_dns_failure_rate_sample_size"])
		}

	} else {

		if fields["peak_dns_failure_rate"] != nil {
			return fmt.Errorf("unexpected field 'peak_dns_failure_rate'")
		}

		if fields["peak_dns_failure_rate_sample_size"] != nil {
			return fmt.Errorf("unexpected field 'peak_dns_failure_rate_sample_size'")
		}
	}

	// TODO: the following cases should check that fields are not logged when
	// not expected.

	if runConfig.doSplitTunnel {

		if fields["split_tunnel"] == nil {
			return fmt.Errorf("missing expected field 'split_tunnel'")
		}
		if fields["split_tunnel"].(bool) != true {
			return fmt.Errorf("missing split_tunnel value")
		}
	}

	if protocol.TunnelProtocolUsesObfuscatedSSH(runConfig.tunnelProtocol) {

		for _, name := range []string{
			"padding",
			"pad_response",
		} {
			if fields[name] == nil || fmt.Sprintf("%s", fields[name]) == "" {
				return fmt.Errorf("missing expected field '%s'", name)
			}
		}
	}

	if protocol.TunnelProtocolUsesMeek(runConfig.tunnelProtocol) &&
		(runConfig.clientTunnelProtocol == "" || protocol.TunnelProtocolUsesMeekHTTPS(runConfig.clientTunnelProtocol)) {

		for _, name := range []string{
			"user_agent",
			"meek_transformed_host_name",
			"meek_cookie_size",
			"meek_limit_request",
			"meek_underlying_connection_count",
			"meek_server_http_version",
		} {
			if fields[name] == nil || fmt.Sprintf("%s", fields[name]) == "" {
				return fmt.Errorf("missing expected field '%s'", name)
			}
		}

		if !common.Contains(testUserAgents, fields["user_agent"].(string)) {
			return fmt.Errorf("unexpected user_agent '%s'", fields["user_agent"])
		}

		if fields["meek_server_http_version"].(string) != expectMeekHTTPVersion {
			return fmt.Errorf("unexpected meek_server_http_version '%s'", fields["meek_server_http_version"])
		}
	}

	if protocol.TunnelProtocolUsesMeekHTTP(runConfig.tunnelProtocol) {

		for _, name := range []string{
			"meek_host_header",
		} {
			if fields[name] == nil || fmt.Sprintf("%s", fields[name]) == "" {
				return fmt.Errorf("missing expected field '%s'", name)
			}
		}

		hostName := fields["meek_host_header"].(string)
		dialPortNumber := int(fields["dial_port_number"].(float64))
		if dialPortNumber != 80 {
			hostName, _, _ = net.SplitHostPort(hostName)
		}
		if regexp.MustCompile(testCustomHostNameRegex).FindString(hostName) != hostName {
			return fmt.Errorf("unexpected meek_host_header '%s'", fields["meek_host_header"])
		}

		if !protocol.TunnelProtocolUsesFrontedMeek(runConfig.tunnelProtocol) {
			for _, name := range []string{
				"meek_dial_ip_address",
				"meek_resolved_ip_address",
			} {
				if fields[name] != nil {
					return fmt.Errorf("unexpected field '%s'", name)
				}
			}
		}
	}

	if protocol.TunnelProtocolUsesMeekHTTPS(runConfig.tunnelProtocol) &&
		(runConfig.clientTunnelProtocol == "" || protocol.TunnelProtocolUsesMeekHTTPS(runConfig.clientTunnelProtocol)) {

		for _, name := range []string{
			"tls_profile",
			"tls_version",
			"meek_sni_server_name",
		} {
			if fields[name] == nil || fmt.Sprintf("%s", fields[name]) == "" {
				return fmt.Errorf("missing expected field '%s'", name)
			}
		}

		hostName := fields["meek_sni_server_name"].(string)
		if regexp.MustCompile(testCustomHostNameRegex).FindString(hostName) != hostName {
			return fmt.Errorf("unexpected meek_sni_server_name '%s'", fields["meek_sni_server_name"])
		}

		if !protocol.TunnelProtocolUsesFrontedMeek(runConfig.tunnelProtocol) {
			for _, name := range []string{
				"meek_dial_ip_address",
				"meek_resolved_ip_address",
				"meek_host_header",
			} {
				if fields[name] != nil {
					return fmt.Errorf("unexpected field '%s'", name)
				}
			}
		}

		if !common.Contains(protocol.SupportedTLSProfiles, fields["tls_profile"].(string)) {
			return fmt.Errorf("unexpected tls_profile '%s'", fields["tls_profile"])
		}

		tlsVersion := fields["tls_version"].(string)
		if !strings.HasPrefix(tlsVersion, protocol.TLS_VERSION_12) &&
			!strings.HasPrefix(tlsVersion, protocol.TLS_VERSION_13) {
			return fmt.Errorf("unexpected tls_version '%s'", fields["tls_version"])
		}
	}

	if protocol.TunnelProtocolUsesQUIC(runConfig.tunnelProtocol) {

		for _, name := range []string{
			"quic_version",
			"quic_dial_sni_address",
		} {
			if fields[name] == nil || fmt.Sprintf("%s", fields[name]) == "" {
				return fmt.Errorf("missing expected field '%s'", name)
			}
		}

		quicVersion := fields["quic_version"].(string)
		if !common.Contains(protocol.SupportedQUICVersions, quicVersion) ||
			(runConfig.limitQUICVersions && quicVersion != expectQUICVersion) {

			return fmt.Errorf("unexpected quic_version '%s'", fields["quic_version"])
		}
	}

	if protocol.TunnelProtocolUsesTLSOSSH(expectedRelayProtocol) {
		for _, name := range []string{
			"tls_padding",
			"tls_ossh_sni_server_name",
			"tls_ossh_transformed_host_name",
		} {
			if fields[name] == nil || fmt.Sprintf("%s", fields[name]) == "" {
				return fmt.Errorf("missing expected field '%s'", name)
			}
		}

		hostName := fields["tls_ossh_sni_server_name"].(string)
		if regexp.MustCompile(testCustomHostNameRegex).FindString(hostName) != hostName {
			return fmt.Errorf("unexpected tls_ossh_sni_server_name '%s'", fields["tls_ossh_sni_server_name"])
		}
	}

	if protocol.TunnelProtocolUsesInproxy(runConfig.tunnelProtocol) {

		for _, name := range []string{

			// Fields sent by the broker and populated via
			// inproxy.ServerBrokerSessions.HandlePacket

			"inproxy_broker_id",
			"inproxy_connection_id",
			"inproxy_proxy_id",
			"inproxy_matched_common_compartments",
			"inproxy_proxy_nat_type",
			"inproxy_client_nat_type",

			// Fields sent by the client

			"inproxy_broker_transport",
			"inproxy_broker_fronting_provider_id",
			"inproxy_broker_dial_address",
			"inproxy_broker_resolved_ip_address",
			"inproxy_webrtc_randomize_dtls",
			"inproxy_webrtc_padded_messages_sent",
			"inproxy_webrtc_padded_messages_received",
			"inproxy_webrtc_decoy_messages_sent",
			"inproxy_webrtc_decoy_messages_received",
		} {
			if fields[name] == nil || fmt.Sprintf("%s", fields[name]) == "" {
				return fmt.Errorf("missing expected field '%s'", name)
			}
		}

		if fields["inproxy_broker_id"].(string) != inproxyTestConfig.brokerSessionPublicKeyCurve25519 {
			return fmt.Errorf("unexpected inproxy_broker_id '%s'", fields["inproxy_broker_id"])
		}

		if fields["inproxy_proxy_id"].(string) != inproxyTestConfig.proxySessionPublicKeyCurve25519 {
			return fmt.Errorf("unexpected inproxy_proxy_id '%s'", fields["inproxy_proxy_id"])
		}

		if fields["inproxy_matched_common_compartments"].(bool) != !runConfig.doPersonalPairing {
			return fmt.Errorf("unexpected inproxy_matched_common_compartments '%s'", fields["inproxy_matched_common_compartments"])
		}

		if fields["inproxy_broker_fronting_provider_id"].(string) != inproxyTestConfig.brokerFrontingProviderID {
			return fmt.Errorf("unexpected inproxy_broker_fronting_provider_id '%s'", fields["inproxy_broker_fronting_provider_id"])
		}
	}

	if runConfig.applyPrefix {

		if fields["ossh_prefix"] == nil || fmt.Sprintf("%s", fields["ossh_prefix"]) == "" {
			return fmt.Errorf("missing expected field 'ossh_prefix'")
		}
	}

	if runConfig.forceFragmenting {

		for _, name := range []string{
			"upstream_bytes_fragmented",
			"upstream_min_bytes_written",
			"upstream_max_bytes_written",
			"upstream_min_delayed",
			"upstream_max_delayed",
		} {
			if fields[name] == nil || fmt.Sprintf("%s", fields[name]) == "" {
				return fmt.Errorf("missing expected field '%s'", name)
			}
		}
	}

	if expectClientBPFField {
		name := "client_bpf"
		if fields[name] == nil {
			return fmt.Errorf("missing expected field '%s'", name)
		} else if fmt.Sprintf("%s", fields[name]) != "test-client-bpf" {
			return fmt.Errorf("unexpected field value %s: '%s'", name, fields[name])
		}
	}

	if expectServerBPFField {
		name := "server_bpf"
		if fields[name] == nil {
			return fmt.Errorf("missing expected field '%s'", name)
		} else if fmt.Sprintf("%s", fields[name]) != "test-server-bpf" {
			return fmt.Errorf("unexpected field value %s: '%s'", name, fields[name])
		}
	}

	if expectServerPacketManipulationField {
		name := "server_packet_manipulation"
		if fields[name] == nil {
			return fmt.Errorf("missing expected field '%s'", name)
		} else if fmt.Sprintf("%s", fields[name]) != "test-packetman-spec" {
			return fmt.Errorf("unexpected field value %s: '%s'", name, fields[name])
		}
	}

	if expectBurstFields {

		// common.TestBurstMonitoredConn covers inclusion of additional fields.
		for _, name := range []string{
			"burst_upstream_first_rate",
			"burst_upstream_last_rate",
			"burst_upstream_min_rate",
			"burst_upstream_max_rate",
			"burst_downstream_first_rate",
			"burst_downstream_last_rate",
			"burst_downstream_min_rate",
			"burst_downstream_max_rate",
		} {
			if fields[name] == nil || fmt.Sprintf("%s", fields[name]) == "" {
				return fmt.Errorf("missing expected field '%s'", name)
			}
		}
	}

	var checkTCPMetric func(float64) bool
	if expectTCPPortForwardDial {
		checkTCPMetric = func(f float64) bool { return f > 0 }
	} else {
		checkTCPMetric = func(f float64) bool { return f == 0 }
	}

	for _, name := range []string{
		"peak_concurrent_dialing_port_forward_count_tcp",
	} {
		if fields[name] == nil {
			return fmt.Errorf("missing expected field '%s'", name)
		}
		if !checkTCPMetric(fields[name].(float64)) {
			return fmt.Errorf("unexpected field value %s: '%v'", name, fields[name])
		}
	}

	if expectTCPDataTransfer {
		checkTCPMetric = func(f float64) bool { return f > 0 }
	} else {
		checkTCPMetric = func(f float64) bool { return f == 0 }
	}

	for _, name := range []string{
		"bytes_up_tcp",
		"bytes_down_tcp",
		"peak_concurrent_port_forward_count_tcp",
		"total_port_forward_count_tcp",
	} {
		if fields[name] == nil {
			return fmt.Errorf("missing expected field '%s'", name)
		}
		if !checkTCPMetric(fields[name].(float64)) {
			return fmt.Errorf("unexpected field value %s: '%v'", name, fields[name])
		}
	}

	var checkUDPMetric func(float64) bool
	if expectUDPDataTransfer {
		checkUDPMetric = func(f float64) bool { return f > 0 }
	} else {
		checkUDPMetric = func(f float64) bool { return f == 0 }
	}

	for _, name := range []string{
		"bytes_up_udp",
		"bytes_down_udp",
		"peak_concurrent_port_forward_count_udp",
		"total_port_forward_count_udp",
		"total_udpgw_channel_count",
	} {
		if fields[name] == nil {
			return fmt.Errorf("missing expected field '%s'", name)
		}
		if !checkUDPMetric(fields[name].(float64)) {
			return fmt.Errorf("unexpected field value %s: '%v'", name, fields[name])
		}
	}

	for _, name := range []string{
		"dest_bytes_asn",
		"dest_bytes_up_tcp",
		"dest_bytes_down_tcp",
		"dest_bytes_up_udp",
		"dest_bytes_down_udp",
		"dest_bytes",
	} {
		if expectDestinationBytesFields && fields[name] == nil {
			return fmt.Errorf("missing expected field '%s'", name)

		} else if !expectDestinationBytesFields && fields[name] != nil {
			return fmt.Errorf("unexpected field '%s'", name)
		}
	}

	if expectDestinationBytesFields {
		name := "dest_bytes_asn"
		if fields[name].(string) != testGeoIPASN {
			return fmt.Errorf("unexpected field value %s: '%v'", name, fields[name])
		}
		for _, pair := range [][]string{
			[]string{"dest_bytes_up_tcp", "bytes_up_tcp"},
			[]string{"dest_bytes_down_tcp", "bytes_down_tcp"},
			[]string{"dest_bytes_up_udp", "bytes_up_udp"},
			[]string{"dest_bytes_down_udp", "bytes_down_udp"},
			[]string{"dest_bytes", "bytes"},
		} {
			value0 := int64(fields[pair[0]].(float64))
			value1 := int64(fields[pair[1]].(float64))
			ok := value0 == value1
			if pair[0] == "dest_bytes_up_udp" || pair[0] == "dest_bytes_down_udp" || pair[0] == "dest_bytes" {
				// DNS requests are excluded from destination bytes counting
				ok = value0 > 0 && value0 < value1
			}
			if !ok {
				return fmt.Errorf("unexpected field value %s: %v != %v", pair[0], fields[pair[0]], fields[pair[1]])
			}
		}
	}

	if expectPassthroughAddress != nil {
		name := "passthrough_address"
		if fields[name] == nil {
			return fmt.Errorf("missing expected field '%s'", name)
		}
		if fields[name] != *expectPassthroughAddress {
			return fmt.Errorf("unexpected field value %s: %v != %v", name, fields[name], *expectPassthroughAddress)
		}
	}

	if runConfig.doLogHostProvider {
		name := "provider"
		if fields[name] == nil {
			return fmt.Errorf("missing expected field '%s'", name)
		} else if fmt.Sprintf("%s", fields[name]) != "example-host-provider" {
			return fmt.Errorf("unexpected field value %s: '%s'", name, fields[name])
		}
	} else {
		name := "provider"
		if fields[name] != nil {
			return fmt.Errorf("unexpected field '%s'", name)
		}
	}

	if runConfig.doSteeringIP {
		name := "relayed_steering_ip"
		if fields[name] == nil {
			return fmt.Errorf("missing expected field '%s'", name)
		}
		if fields[name] != testSteeringIP {
			return fmt.Errorf("unexpected field value %s: %v != %v", name, fields[name], testSteeringIP)
		}
		name = "steering_ip"
		if fields[name] != nil {
			return fmt.Errorf("unexpected field '%s'", name)
		}
	}

	return nil
}

func checkExpectedUniqueUserLogFields(
	runConfig *runServerConfig,
	fields map[string]interface{}) error {

	for _, name := range []string{
		"session_id",
		"last_connected",
		"propagation_channel_id",
		"sponsor_id",
		"client_platform",
		"device_region",
		"device_location",
	} {
		if fields[name] == nil || fmt.Sprintf("%s", fields[name]) == "" {
			return fmt.Errorf("missing expected field '%s'", name)
		}
	}

	return nil
}

func checkExpectedDomainBytesLogFields(
	runConfig *runServerConfig,
	fields map[string]interface{}) error {

	for _, name := range []string{
		"session_id",
		"propagation_channel_id",
		"sponsor_id",
		"client_platform",
		"device_region",
		"device_location",
		"domain",
		"bytes",
	} {
		if fields[name] == nil || fmt.Sprintf("%s", fields[name]) == "" {
			return fmt.Errorf("missing expected field '%s'", name)
		}

		if name == "domain" {
			if fields[name].(string) != "ALL" && fields[name].(string) != "(OTHER)" {
				return fmt.Errorf("unexpected field value %s: '%v'", name, fields[name])
			}
		}
	}

	return nil
}

func makeTunneledWebRequest(
	t *testing.T,
	localHTTPProxyPort int,
	requestURL, expectedResponseBody string) error {

	roundTripTimeout := 30 * time.Second

	proxyUrl, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", localHTTPProxyPort))
	if err != nil {
		return fmt.Errorf("error initializing proxied HTTP request: %s", err)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyUrl),
		},
		Timeout: roundTripTimeout,
	}

	response, err := httpClient.Get(requestURL)
	if err != nil {
		return fmt.Errorf("error sending proxied HTTP request: %s", err)
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("error reading proxied HTTP response: %s", err)
	}
	response.Body.Close()

	if string(body) != expectedResponseBody {
		return fmt.Errorf("unexpected proxied HTTP response")
	}

	return nil
}

func makeTunneledNTPRequest(t *testing.T, localSOCKSProxyPort int, udpgwServerAddress string) error {

	timeout := 20 * time.Second
	var err error

	testHostnames := []string{"time.google.com", "time.nist.gov", "pool.ntp.org"}
	indexes := prng.Perm(len(testHostnames))

	for _, index := range indexes {
		testHostname := testHostnames[index]
		err = makeTunneledNTPRequestAttempt(t, testHostname, timeout, localSOCKSProxyPort, udpgwServerAddress)
		if err == nil {
			break
		}
		t.Logf("makeTunneledNTPRequestAttempt failed: %s", err)
	}

	return err
}

var nextUDPProxyPort = 7300

func makeTunneledNTPRequestAttempt(
	t *testing.T, testHostname string, timeout time.Duration, localSOCKSProxyPort int, udpgwServerAddress string) error {

	nextUDPProxyPort++
	localUDPProxyAddress, err := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", nextUDPProxyPort))
	if err != nil {
		return fmt.Errorf("ResolveUDPAddr failed: %s", err)
	}

	// Note: this proxy is intended for this test only -- it only accepts a single connection,
	// handles it, and then terminates.

	localUDPProxy := func(destinationIP net.IP, destinationPort uint16, waitGroup *sync.WaitGroup) {

		if waitGroup != nil {
			defer waitGroup.Done()
		}

		destination := net.JoinHostPort(destinationIP.String(), strconv.Itoa(int(destinationPort)))

		serverUDPConn, err := net.ListenUDP("udp", localUDPProxyAddress)
		if err != nil {
			t.Logf("ListenUDP for %s failed: %s", destination, err)
			return
		}
		defer serverUDPConn.Close()

		udpgwPreambleSize := 11 // see writeUdpgwPreamble
		buffer := make([]byte, udpgwProtocolMaxMessageSize)
		packetSize, clientAddr, err := serverUDPConn.ReadFromUDP(
			buffer[udpgwPreambleSize:])
		if err != nil {
			t.Logf("serverUDPConn.Read for %s failed: %s", destination, err)
			return
		}

		socksProxyAddress := fmt.Sprintf("127.0.0.1:%d", localSOCKSProxyPort)

		dialer, err := proxy.SOCKS5("tcp", socksProxyAddress, nil, proxy.Direct)
		if err != nil {
			t.Logf("proxy.SOCKS5 for %s failed: %s", destination, err)
			return
		}

		socksTCPConn, err := dialer.Dial("tcp", udpgwServerAddress)
		if err != nil {
			t.Logf("dialer.Dial for %s failed: %s", destination, err)
			return
		}
		defer socksTCPConn.Close()

		flags := uint8(0)
		if destinationPort == 53 {
			flags = udpgwProtocolFlagDNS
		}

		err = writeUdpgwPreamble(
			udpgwPreambleSize,
			flags,
			0,
			destinationIP,
			destinationPort,
			uint16(packetSize),
			buffer)
		if err != nil {
			t.Logf("writeUdpgwPreamble for %s failed: %s", destination, err)
			return
		}

		_, err = socksTCPConn.Write(buffer[0 : udpgwPreambleSize+packetSize])
		if err != nil {
			t.Logf("socksTCPConn.Write for %s failed: %s", destination, err)
			return
		}

		udpgwProtocolMessage, err := readUdpgwMessage(socksTCPConn, buffer)
		if err != nil {
			t.Logf("readUdpgwMessage for %s failed: %s", destination, err)
			return
		}

		_, err = serverUDPConn.WriteToUDP(udpgwProtocolMessage.packet, clientAddr)
		if err != nil {
			t.Logf("serverUDPConn.Write for %s failed: %s", destination, err)
			return
		}
	}

	// Tunneled DNS request

	waitGroup := new(sync.WaitGroup)
	waitGroup.Add(1)
	go localUDPProxy(
		net.IP(make([]byte, 4)), // ignored due to transparent DNS forwarding
		53,
		waitGroup)
	// TODO: properly synchronize with local UDP proxy startup
	time.Sleep(1 * time.Second)

	clientUDPConn, err := net.DialUDP("udp", nil, localUDPProxyAddress)
	if err != nil {
		return fmt.Errorf("DialUDP failed: %s", err)
	}

	clientUDPConn.SetReadDeadline(time.Now().Add(timeout))
	clientUDPConn.SetWriteDeadline(time.Now().Add(timeout))

	addrs, err := resolveIP(testHostname, clientUDPConn)

	clientUDPConn.Close()

	if err == nil && (len(addrs) == 0 || len(addrs[0]) < 4) {
		err = std_errors.New("no address")
	}
	if err != nil {
		return fmt.Errorf("resolveIP failed: %s", err)
	}

	waitGroup.Wait()

	// Tunneled NTP request

	waitGroup = new(sync.WaitGroup)
	waitGroup.Add(1)
	go localUDPProxy(
		addrs[0][len(addrs[0])-4:],
		123,
		waitGroup)
	// TODO: properly synchronize with local UDP proxy startup
	time.Sleep(1 * time.Second)

	clientUDPConn, err = net.DialUDP("udp", nil, localUDPProxyAddress)
	if err != nil {
		return fmt.Errorf("DialUDP failed: %s", err)
	}

	clientUDPConn.SetReadDeadline(time.Now().Add(timeout))
	clientUDPConn.SetWriteDeadline(time.Now().Add(timeout))

	// NTP protocol code from: https://groups.google.com/d/msg/golang-nuts/FlcdMU5fkLQ/CAeoD9eqm-IJ

	ntpData := make([]byte, 48)
	ntpData[0] = 3<<3 | 3

	_, err = clientUDPConn.Write(ntpData)
	if err != nil {
		clientUDPConn.Close()
		return fmt.Errorf("NTP Write failed: %s", err)
	}

	_, err = clientUDPConn.Read(ntpData)
	if err != nil {
		clientUDPConn.Close()
		return fmt.Errorf("NTP Read failed: %s", err)
	}

	clientUDPConn.Close()

	var sec, frac uint64
	sec = uint64(ntpData[43]) | uint64(ntpData[42])<<8 | uint64(ntpData[41])<<16 | uint64(ntpData[40])<<24
	frac = uint64(ntpData[47]) | uint64(ntpData[46])<<8 | uint64(ntpData[45])<<16 | uint64(ntpData[44])<<24

	nsec := sec * 1e9
	nsec += (frac * 1e9) >> 32

	ntpNow := time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(nsec)).Local()

	now := time.Now()

	diff := ntpNow.Sub(now)
	if diff < 0 {
		diff = -diff
	}

	if diff > 1*time.Minute {
		return fmt.Errorf("Unexpected NTP time: %s; local time: %s", ntpNow, now)
	}

	waitGroup.Wait()

	return nil
}

func resolveIP(host string, conn net.Conn) (addrs []net.IP, err error) {

	// Send the DNS query (A record only)
	dnsConn := &dns.Conn{Conn: conn}
	defer dnsConn.Close()
	query := new(dns.Msg)
	query.SetQuestion(dns.Fqdn(host), dns.TypeA)
	query.RecursionDesired = true
	dnsConn.WriteMsg(query)

	// Process the response
	response, err := dnsConn.ReadMsg()
	if err == nil && response.MsgHdr.Id != query.MsgHdr.Id {
		err = dns.ErrId
	}
	if err != nil {
		return nil, errors.Trace(err)
	}
	addrs = make([]net.IP, 0)
	for _, answer := range response.Answer {
		if a, ok := answer.(*dns.A); ok {
			addrs = append(addrs, a.A)
		}
	}
	return addrs, nil
}

func pavePsinetDatabaseFile(
	t *testing.T,
	psinetFilename string,
	sponsorID string,
	useDefaultSponsorID bool,
	doDomainBytes bool,
	validServerEntryTags []string,
	discoveryServers []*psinet.DiscoveryServer) (string, string) {

	if sponsorID == "" {
		sponsorID = strings.ToUpper(prng.HexString(8))
	}

	defaultSponsorID := ""
	if useDefaultSponsorID {
		defaultSponsorID = sponsorID
	}

	fakeDomain := prng.HexString(4)
	fakePath := prng.HexString(4)
	expectedHomepageURL := fmt.Sprintf("https://%s.com/%s", fakeDomain, fakePath)

	discoverServersJSON, err := json.Marshal(discoveryServers)
	if err != nil {
		t.Fatalf("json.Marshal failed: %s\n", err)
	}

	psinetJSONFormat := `
    {
        "default_sponsor_id" : "%s",
        "sponsors" : {
            "%s" : {
                %s
                "home_pages" : {
                    "None" : [
                        {
                            "region" : null,
                            "url" : "%s"
                        }
                    ]
                }
            }
        },
        "default_alert_action_urls" : {
            "%s" : %s
        },
        "valid_server_entry_tags" : {
            %s
        },
        "discovery_servers" : %s
    }
	`

	domainBytes := ""
	if doDomainBytes {
		domainBytes = `
                "https_request_regexes" : [
                    {
                        "regex" : ".*",
                        "replace" : "ALL"
                    }
                ],
	`
	}

	actionURLsJSON, _ := json.Marshal(testDisallowedTrafficAlertActionURLs)

	validServerEntryTagsJSON := ""
	for _, serverEntryTag := range validServerEntryTags {
		if len(validServerEntryTagsJSON) > 0 {
			validServerEntryTagsJSON += ", "
		}
		validServerEntryTagsJSON += fmt.Sprintf("\"%s\" : true", serverEntryTag)
	}

	psinetJSON := fmt.Sprintf(
		psinetJSONFormat,
		defaultSponsorID,
		sponsorID,
		domainBytes,
		expectedHomepageURL,
		protocol.PSIPHON_API_ALERT_DISALLOWED_TRAFFIC,
		actionURLsJSON,
		validServerEntryTagsJSON,
		discoverServersJSON)

	err = ioutil.WriteFile(psinetFilename, []byte(psinetJSON), 0600)
	if err != nil {
		t.Fatalf("error paving psinet database file: %s", err)
	}

	return sponsorID, expectedHomepageURL
}

func paveTrafficRulesFile(
	t *testing.T,
	trafficRulesFilename string,
	propagationChannelID string,
	accessType string,
	authorizationID string,
	requireAuthorization bool,
	deny bool,
	livenessTestSize int) {

	// Test both default and fast lookups
	if intLookupThreshold != 10 {
		t.Fatalf("unexpected intLookupThreshold")
	}

	TCPPorts := mockWebServerPort
	UDPPorts := "53, 123, 10001, 10002, 10003, 10004, 10005, 10006, 10007, 10008, 10009, 10010"

	allowTCPPorts := TCPPorts
	allowUDPPorts := UDPPorts
	disallowTCPPorts := "1"
	disallowUDPPorts := "1"

	if deny {
		allowTCPPorts = "1"
		allowUDPPorts = "1"
		disallowTCPPorts = TCPPorts
		disallowUDPPorts = UDPPorts
	}

	authorizationFilterFormat := `,
                    "AuthorizedAccessTypes" : ["%s"],
                    "ActiveAuthorizationIDs" : ["%s"]
	`

	authorizationFilter := ""
	if requireAuthorization {
		authorizationFilter = fmt.Sprintf(
			authorizationFilterFormat, accessType, authorizationID)
	}

	// Supports two traffic rule test cases:
	//
	// 1. no ports are allowed until after the filtered rule is applied
	// 2. no required ports are allowed (deny = true)

	trafficRulesJSONFormat := `
    {
        "DefaultRules" :  {
            "RateLimits" : {
                "ReadBytesPerSecond": 16384,
                "WriteBytesPerSecond": 16384,
                "ReadUnthrottledBytes": %d,
                "WriteUnthrottledBytes": %d
            },
            "AllowTCPPorts" : [1],
            "AllowUDPPorts" : [1],
            "MeekRateLimiterHistorySize" : 10,
            "MeekRateLimiterThresholdSeconds" : 1,
            "MeekRateLimiterGarbageCollectionTriggerCount" : 1,
            "MeekRateLimiterReapHistoryFrequencySeconds" : 1,
            "MeekRateLimiterRegions" : []
        },
        "FilteredRules" : [
            {
                "Filter" : {
                    "HandshakeParameters" : {
                        "propagation_channel_id" : ["%s"]
                    }%s
                },
                "Rules" : {
                    "RateLimits" : {
                        "ReadBytesPerSecond": 2097152,
                        "WriteBytesPerSecond": 2097152
                    },
                    "AllowTCPPorts" : [%s],
                    "AllowUDPPorts" : [%s],
                    "DisallowTCPPorts" : [%s],
                    "DisallowUDPPorts" : [%s]
                }
            }
        ]
    }
    `

	trafficRulesJSON := fmt.Sprintf(
		trafficRulesJSONFormat,
		livenessTestSize, livenessTestSize,
		propagationChannelID, authorizationFilter,
		allowTCPPorts, allowUDPPorts, disallowTCPPorts, disallowUDPPorts)

	err := ioutil.WriteFile(trafficRulesFilename, []byte(trafficRulesJSON), 0600)
	if err != nil {
		t.Fatalf("error paving traffic rules file: %s", err)
	}
}

var expectedNumSLOKs = 3

func paveOSLConfigFile(t *testing.T, oslConfigFilename string) string {

	oslConfigJSONFormat := `
    {
      "Schemes" : [
        {
          "Epoch" : "%s",
          "Regions" : [],
          "PropagationChannelIDs" : ["%s"],
          "MasterKey" : "wFuSbqU/pJ/35vRmoM8T9ys1PgDa8uzJps1Y+FNKa5U=",
          "SeedSpecs" : [
            {
              "ID" : "IXHWfVgWFkEKvgqsjmnJuN3FpaGuCzQMETya+DSQvsk=",
              "UpstreamSubnets" : ["0.0.0.0/0"],
              "Targets" :
              {
                  "BytesRead" : 1,
                  "BytesWritten" : 1,
                  "PortForwardDurationNanoseconds" : 1
              }
            },
            {
              "ID" : "qvpIcORLE2Pi5TZmqRtVkEp+OKov0MhfsYPLNV7FYtI=",
              "UpstreamSubnets" : ["0.0.0.0/0"],
              "Targets" :
              {
                  "BytesRead" : 1,
                  "BytesWritten" : 1,
                  "PortForwardDurationNanoseconds" : 1
              }
            }
          ],
          "SeedSpecThreshold" : 2,
          "SeedPeriodNanoseconds" : 2592000000000000,
          "SeedPeriodKeySplits": [
            {
              "Total": 2,
              "Threshold": 2
            }
          ]
        },
        {
          "Epoch" : "%s",
          "Regions" : [],
          "PropagationChannelIDs" : ["%s"],
          "MasterKey" : "HDc/mvd7e+lKDJD0fMpJW66YJ/VW4iqDRjeclEsMnro=",
          "SeedSpecs" : [
            {
              "ID" : "/M0vsT0IjzmI0MvTI9IYe8OVyeQGeaPZN2xGxfLw/UQ=",
              "UpstreamSubnets" : ["0.0.0.0/0"],
              "Targets" :
              {
                  "BytesRead" : 1,
                  "BytesWritten" : 1,
                  "PortForwardDurationNanoseconds" : 1
              }
            }
          ],
          "SeedSpecThreshold" : 1,
          "SeedPeriodNanoseconds" : 2592000000000000,
          "SeedPeriodKeySplits": [
            {
              "Total": 1,
              "Threshold": 1
            }
          ]
        }
      ]
    }
    `

	propagationChannelID := strings.ToUpper(prng.HexString(8))

	now := time.Now().UTC()
	epoch := now.Truncate(720 * time.Hour)
	epochStr := epoch.Format(time.RFC3339Nano)

	oslConfigJSON := fmt.Sprintf(
		oslConfigJSONFormat,
		epochStr, propagationChannelID,
		epochStr, propagationChannelID)

	err := ioutil.WriteFile(oslConfigFilename, []byte(oslConfigJSON), 0600)
	if err != nil {
		t.Fatalf("error paving osl config file: %s", err)
	}

	return propagationChannelID
}

func paveTacticsConfigFile(
	t *testing.T,
	tacticsConfigFilename string,
	tacticsRequestPublicKey string,
	tacticsRequestPrivateKey string,
	tacticsRequestObfuscatedKey string,
	tunnelProtocol string,
	propagationChannelID string,
	livenessTestSize int,
	doBurstMonitor bool,
	doDestinationBytes bool,
	applyOsshPrefix bool,
	enableOsshPrefixFragmenting bool,
	discoveryStategy string,
	inproxyParametersJSON string) {

	// Setting LimitTunnelProtocols passively exercises the
	// server-side LimitTunnelProtocols enforcement.

	tacticsConfigJSONFormat := `
    {
      "RequestPublicKey" : "%s",
      "RequestPrivateKey" : "%s",
      "RequestObfuscatedKey" : "%s",
      "DefaultTactics" : {
        "TTL" : "60s",
        "Probability" : 1.0,
        "Parameters" : {
          %s
          %s
          %s
          %s
          "LimitTunnelProtocols" : ["%s"],
          "FragmentorLimitProtocols" : ["%s"],
          "FragmentorProbability" : 1.0,
          "FragmentorMinTotalBytes" : 1000,
          "FragmentorMaxTotalBytes" : 2000,
          "FragmentorMinWriteBytes" : 1,
          "FragmentorMaxWriteBytes" : 100,
          "FragmentorMinDelay" : "1ms",
          "FragmentorMaxDelay" : "10ms",
          "FragmentorDownstreamLimitProtocols" : ["%s"],
          "FragmentorDownstreamProbability" : 1.0,
          "FragmentorDownstreamMinTotalBytes" : 1000,
          "FragmentorDownstreamMaxTotalBytes" : 2000,
          "FragmentorDownstreamMinWriteBytes" : 1,
          "FragmentorDownstreamMaxWriteBytes" : 100,
          "FragmentorDownstreamMinDelay" : "1ms",
          "FragmentorDownstreamMaxDelay" : "10ms",
          "LivenessTestMinUpstreamBytes" : %d,
          "LivenessTestMaxUpstreamBytes" : %d,
          "LivenessTestMinDownstreamBytes" : %d,
          "LivenessTestMaxDownstreamBytes" : %d,
          "BPFServerTCPProgram": {
            "Name" : "test-server-bpf",
              "Instructions" : [
                {"Op": "RetConstant", "Args": {"Val": 65535}}]},
          "BPFServerTCPProbability" : 1.0,
          "BPFClientTCPProgram": {
            "Name" : "test-client-bpf",
              "Instructions" : [
                {"Op": "RetConstant", "Args": {"Val": 65535}}]},
          "BPFClientTCPProbability" : 1.0,
          "ServerPacketManipulationSpecs" : [{"Name": "test-packetman-spec", "PacketSpecs": [["TCP-flags S"]]}],
          "ServerPacketManipulationProbability" : 1.0,
          "ServerProtocolPacketManipulations": {"All" : ["test-packetman-spec"]},
          "ServerDiscoveryStrategy": "%s"
        }
      },
      "FilteredTactics" : [
        {
          "Filter" : {
            "APIParameters" : {"propagation_channel_id" : ["%s"]},
            "SpeedTestRTTMilliseconds" : {
              "Aggregation" : "Median",
              "AtLeast" : 1
            }
          },
          "Tactics" : {
            "Parameters" : {
              "TunnelConnectTimeout" : "20s",
              "TunnelRateLimits" : {"WriteBytesPerSecond": 1000000},
              "TransformHostNameProbability" : 1.0,
              "PickUserAgentProbability" : 1.0,
              "ApplicationParameters" : {
                "AppFlag1" : true,
                "AppConfig1" : {"Option1" : "A", "Option2" : "B"},
                "AppSwitches1" : [1, 2, 3, 4]
              },
              "CustomHostNameRegexes": ["%s"],
              "CustomHostNameProbability": 1.0,
              "CustomHostNameLimitProtocols": ["%s"]
            }
          }
        }
      ]
    }
    `

	burstParameters := ""
	if doBurstMonitor {
		burstParameters = `
          "ServerBurstUpstreamDeadline" : "100ms",
          "ServerBurstUpstreamTargetBytes" : 1000,
          "ServerBurstDownstreamDeadline" : "100ms",
          "ServerBurstDownstreamTargetBytes" : 100000,
          "ClientBurstUpstreamDeadline" : "100ms",
          "ClientBurstUpstreamTargetBytes" : 1000,
          "ClientBurstDownstreamDeadline" : "100ms",
          "ClientBurstDownstreamTargetBytes" : 100000,
	`
	}

	destinationBytesParameters := ""
	if doDestinationBytes {
		destinationBytesParameters = fmt.Sprintf(`
          "DestinationBytesMetricsASN" : "%s",
	`, testGeoIPASN)
	}

	osshPrefix := ""
	if applyOsshPrefix {
		osshPrefix = fmt.Sprintf(`
          "ServerOSSHPrefixSpecs": {
              "TEST": [["", "\\x01{200}"]]
          },
          "OSSHPrefixSplitMinDelay": "30ms",
          "OSSHPrefixSplitMaxDelay": "40ms",
          "OSSHPrefixEnableFragmentor": %s,
	`, strconv.FormatBool(enableOsshPrefixFragmenting))
	}

	tacticsConfigJSON := fmt.Sprintf(
		tacticsConfigJSONFormat,
		tacticsRequestPublicKey,
		tacticsRequestPrivateKey,
		tacticsRequestObfuscatedKey,
		burstParameters,
		destinationBytesParameters,
		osshPrefix,
		inproxyParametersJSON,
		tunnelProtocol,
		tunnelProtocol,
		tunnelProtocol,
		livenessTestSize,
		livenessTestSize,
		livenessTestSize,
		livenessTestSize,
		discoveryStategy,
		propagationChannelID,
		strings.ReplaceAll(testCustomHostNameRegex, `\`, `\\`),
		tunnelProtocol)

	err := ioutil.WriteFile(tacticsConfigFilename, []byte(tacticsConfigJSON), 0600)
	if err != nil {
		t.Fatalf("error paving tactics config file: %s", err)
	}
}

func paveBlocklistFile(t *testing.T, blocklistFilename string) {

	blocklistContent :=
		"255.255.255.255,test-source,test-subject\n2001:db8:f75c::0951:58bc:ef22,test-source,test-subject\nexample.org,test-source,test-subject\n"

	err := ioutil.WriteFile(blocklistFilename, []byte(blocklistContent), 0600)
	if err != nil {
		t.Fatalf("error paving blocklist file: %s", err)
	}
}

type inproxyTestConfig struct {
	tacticsParametersJSON string

	addMeekServerForBroker              bool
	brokerIPAddress                     string
	brokerPort                          int
	brokerSessionPublicKey              string
	brokerSessionPublicKeyCurve25519    string
	brokerSessionPrivateKey             string
	brokerObfuscationRootSecret         string
	brokerServerEntrySignaturePublicKey string
	brokerFrontingProviderID            string
	brokerServerCertificate             string
	brokerServerPrivateKey              string
	brokerMeekRequiredHeaders           map[string]string

	proxySessionPublicKey           string
	proxySessionPublicKeyCurve25519 string
	proxySessionPrivateKey          string

	personalCompartmentID string
}

func generateInproxyTestConfig(
	addMeekServerForBroker bool,
	doTargetBrokerSpecs bool,
	brokerIPAddress string,
	brokerPort int,
	serverEntrySignaturePublicKey string) (*inproxyTestConfig, error) {

	// Generate in-proxy configuration.
	//
	// In this test, a single common compartment ID is issued to all clients;
	// the test client will get it via tactics.
	//
	// Because of singletons in the Psiphon client, there can only be a single
	// Psiphon client instance in this test process, and so it must act as
	// it's own in-proxy proxy.
	//
	// To minimize external dependencies, STUN testing is disabled here; it is
	// exercised in the common/inproxy package tests.
	//
	// InproxyBrokerAllowCommonASNMatching and
	// InproxyBrokerAllowBogonWebRTCConnections must be set to true in the
	// server/broker config, to allow matches with the same local network
	// address. InproxyDisableIPv6ICECandidates is turned on, in tactics,
	// since the test GeoIP database is IPv4-only (see paveGeoIPDatabaseFiles).

	commonCompartmentID, err := inproxy.MakeID()
	if err != nil {
		return nil, errors.Trace(err)
	}
	commonCompartmentIDStr := commonCompartmentID.String()

	personalCompartmentID, err := inproxy.MakeID()
	if err != nil {
		return nil, errors.Trace(err)
	}
	personalCompartmentIDStr := personalCompartmentID.String()

	brokerSessionPrivateKey, err := inproxy.GenerateSessionPrivateKey()
	if err != nil {
		return nil, errors.Trace(err)
	}
	brokerSessionPrivateKeyStr := brokerSessionPrivateKey.String()

	brokerSessionPublicKey, err := brokerSessionPrivateKey.GetPublicKey()
	if err != nil {
		return nil, errors.Trace(err)
	}
	brokerSessionPublicKeyStr := brokerSessionPublicKey.String()

	brokerSessionPublicKeyCurve25519, err := brokerSessionPublicKey.ToCurve25519()
	if err != nil {
		return nil, errors.Trace(err)
	}
	brokerSessionPublicKeyCurve25519Str := brokerSessionPublicKeyCurve25519.String()

	brokerRootObfuscationSecret, err := inproxy.GenerateRootObfuscationSecret()
	if err != nil {
		return nil, errors.Trace(err)
	}
	brokerRootObfuscationSecretStr := brokerRootObfuscationSecret.String()

	brokerFrontingProviderID := strings.ToUpper(prng.HexString(8))

	brokerFrontingHostName := values.GetHostName()

	brokerServerCertificate, brokerServerPrivateKey, brokerVerifyPin, err :=
		common.GenerateWebServerCertificate(brokerFrontingHostName)
	if err != nil {
		return nil, errors.Trace(err)
	}

	brokerMeekRequiredHeaders := map[string]string{"X-MeekRequiredHeader": prng.HexString(32)}

	proxySessionPrivateKey, err := inproxy.GenerateSessionPrivateKey()
	if err != nil {
		return nil, errors.Trace(err)
	}
	proxySessionPrivateKeyStr := proxySessionPrivateKey.String()

	proxySessionPublicKey, err := proxySessionPrivateKey.GetPublicKey()
	if err != nil {
		return nil, errors.Trace(err)
	}
	proxySessionPublicKeyStr := proxySessionPublicKey.String()

	proxySessionPublicKeyCurve25519, err := proxySessionPublicKey.ToCurve25519()
	if err != nil {
		return nil, errors.Trace(err)
	}
	proxySessionPublicKeyCurve25519Str := proxySessionPublicKeyCurve25519.String()

	address := net.JoinHostPort(brokerIPAddress, strconv.Itoa(brokerPort))
	addressRegex := strings.ReplaceAll(address, ".", "\\\\.")

	skipVerify := false
	verifyServerName := brokerFrontingHostName
	verifyPins := fmt.Sprintf("[\"%s\"]", brokerVerifyPin)
	if prng.FlipCoin() {
		skipVerify = true
		verifyServerName = ""
		verifyPins = "[]"
	}

	brokerSpecsJSONFormat := `
            [{
                "BrokerPublicKey": "%s",
                "BrokerRootObfuscationSecret": "%s",
                "BrokerFrontingSpecs": [{
                    "FrontingProviderID": "%s",
                    "Addresses": ["%s"],
                    "DisableSNI": true,
                    "SkipVerify": %v,
                    "VerifyServerName": "%s",
                    "VerifyPins": %s,
                    "Host": "%s"
                }]
            }]
    `

	validBrokerSpecsJSON := fmt.Sprintf(
		brokerSpecsJSONFormat,
		brokerSessionPublicKeyStr,
		brokerRootObfuscationSecretStr,
		brokerFrontingProviderID,
		addressRegex,
		skipVerify,
		verifyServerName,
		verifyPins,
		brokerFrontingHostName)

	otherSessionPrivateKey, _ := inproxy.GenerateSessionPrivateKey()
	otherSessionPublicKey, _ := otherSessionPrivateKey.GetPublicKey()
	otherRootObfuscationSecret, _ := inproxy.GenerateRootObfuscationSecret()

	invalidBrokerSpecsJSON := fmt.Sprintf(
		brokerSpecsJSONFormat,
		otherSessionPublicKey.String(),
		otherRootObfuscationSecret.String(),
		prng.HexString(16),
		prng.HexString(16),
		false,
		prng.HexString(16),
		fmt.Sprintf("[\"%s\"]", prng.HexString(16)),
		prng.HexString(16))

	var brokerSpecsJSON, proxyBrokerSpecsJSON, clientBrokerSpecsJSON string
	if doTargetBrokerSpecs {
		// invalidBrokerSpecsJSON should be ignored when specific proxy/client
		// broker specs are set.
		brokerSpecsJSON = invalidBrokerSpecsJSON
		proxyBrokerSpecsJSON = validBrokerSpecsJSON
		clientBrokerSpecsJSON = validBrokerSpecsJSON
	} else {
		brokerSpecsJSON = validBrokerSpecsJSON
		proxyBrokerSpecsJSON = "[]"
		clientBrokerSpecsJSON = "[]"
	}

	tacticsParametersJSONFormat := `
            "InproxyAllowProxy": true,
            "InproxyAllowClient": true,
            "InproxyTunnelProtocolSelectionProbability": 1.0,
            "InproxyAllBrokerPublicKeys": ["%s", "%s"],
            "InproxyBrokerSpecs": %s,
            "InproxyProxyBrokerSpecs": %s,
            "InproxyClientBrokerSpecs": %s,
            "InproxyAllCommonCompartmentIDs": ["%s"],
            "InproxyCommonCompartmentIDs": ["%s"],
            "InproxyClientDiscoverNATProbability": 0.0,
            "InproxyDisableSTUN": true,
            "InproxyDisablePortMapping": true,
            "InproxyDisableIPv6ICECandidates": true,
    `

	tacticsParametersJSON := fmt.Sprintf(
		tacticsParametersJSONFormat,
		brokerSessionPublicKeyStr,
		otherSessionPublicKey.String(),
		brokerSpecsJSON,
		proxyBrokerSpecsJSON,
		clientBrokerSpecsJSON,
		commonCompartmentIDStr,
		commonCompartmentIDStr)

	config := &inproxyTestConfig{
		tacticsParametersJSON:               tacticsParametersJSON,
		addMeekServerForBroker:              addMeekServerForBroker,
		brokerIPAddress:                     brokerIPAddress,
		brokerPort:                          brokerPort,
		brokerSessionPrivateKey:             brokerSessionPrivateKeyStr,
		brokerSessionPublicKey:              brokerSessionPublicKeyStr,
		brokerSessionPublicKeyCurve25519:    brokerSessionPublicKeyCurve25519Str,
		brokerObfuscationRootSecret:         brokerRootObfuscationSecretStr,
		brokerServerEntrySignaturePublicKey: serverEntrySignaturePublicKey,
		brokerFrontingProviderID:            brokerFrontingProviderID,
		brokerServerCertificate:             brokerServerCertificate,
		brokerServerPrivateKey:              brokerServerPrivateKey,
		brokerMeekRequiredHeaders:           brokerMeekRequiredHeaders,
		proxySessionPublicKey:               proxySessionPublicKeyStr,
		proxySessionPublicKeyCurve25519:     proxySessionPublicKeyCurve25519Str,
		proxySessionPrivateKey:              proxySessionPrivateKeyStr,
		personalCompartmentID:               personalCompartmentIDStr,
	}

	return config, nil
}

type pruneServerEntryTestCase struct {
	IPAddress         string
	ExplicitTag       bool
	ExpectedTag       string
	LocalTimestamp    string
	PsinetValid       bool
	ExpectPrune       bool
	IsEmbedded        bool
	DialPort0         bool
	ServerEntryFields protocol.ServerEntryFields
}

func initializePruneServerEntriesTest(
	t *testing.T,
	runConfig *runServerConfig) ([]*pruneServerEntryTestCase, []string, int) {

	if !runConfig.doPruneServerEntries {
		return nil, nil, 0
	}

	newTimeStamp := time.Now().UTC().Format(time.RFC3339)
	oldTimeStamp := time.Now().Add(-30 * 24 * time.Hour).UTC().Format(time.RFC3339)

	// Test Cases:
	// - ExplicitTag: server entry includes a tag; vs. generate a derived tag
	// - LocalTimestamp: server entry is sufficiently old to be pruned; vs. not
	// - PsinetValid: server entry is reported valid by psinet; vs. deleted
	// - ExpectPrune: prune outcome based on flags above
	// - IsEmbedded: pruned embedded server entries leave a tombstone and cannot
	//   be reimported
	// - DialPort0: set dial port to 0, a special prune case (see statusAPIRequestHandler)

	pruneServerEntryTestCases := []*pruneServerEntryTestCase{
		&pruneServerEntryTestCase{IPAddress: "192.0.2.1", ExplicitTag: true, LocalTimestamp: newTimeStamp, PsinetValid: true, ExpectPrune: false},
		&pruneServerEntryTestCase{IPAddress: "192.0.2.2", ExplicitTag: false, LocalTimestamp: newTimeStamp, PsinetValid: true, ExpectPrune: false},
		&pruneServerEntryTestCase{IPAddress: "192.0.2.3", ExplicitTag: true, LocalTimestamp: oldTimeStamp, PsinetValid: true, ExpectPrune: false},
		&pruneServerEntryTestCase{IPAddress: "192.0.2.4", ExplicitTag: false, LocalTimestamp: oldTimeStamp, PsinetValid: true, ExpectPrune: false},
		&pruneServerEntryTestCase{IPAddress: "192.0.2.5", ExplicitTag: true, LocalTimestamp: newTimeStamp, PsinetValid: false, ExpectPrune: false},
		&pruneServerEntryTestCase{IPAddress: "192.0.2.6", ExplicitTag: false, LocalTimestamp: newTimeStamp, PsinetValid: false, ExpectPrune: false},
		&pruneServerEntryTestCase{IPAddress: "192.0.2.7", ExplicitTag: true, LocalTimestamp: oldTimeStamp, PsinetValid: false, ExpectPrune: true, IsEmbedded: false},
		&pruneServerEntryTestCase{IPAddress: "192.0.2.8", ExplicitTag: false, LocalTimestamp: oldTimeStamp, PsinetValid: false, ExpectPrune: true, IsEmbedded: false},
		&pruneServerEntryTestCase{IPAddress: "192.0.2.9", ExplicitTag: true, LocalTimestamp: oldTimeStamp, PsinetValid: false, ExpectPrune: true, IsEmbedded: true},
		&pruneServerEntryTestCase{IPAddress: "192.0.2.10", ExplicitTag: false, LocalTimestamp: oldTimeStamp, PsinetValid: false, ExpectPrune: true, IsEmbedded: true},
		&pruneServerEntryTestCase{IPAddress: "192.0.2.11", ExplicitTag: true, LocalTimestamp: oldTimeStamp, PsinetValid: true, ExpectPrune: true, IsEmbedded: false, DialPort0: true},
		&pruneServerEntryTestCase{IPAddress: "192.0.2.12", ExplicitTag: false, LocalTimestamp: oldTimeStamp, PsinetValid: true, ExpectPrune: true, IsEmbedded: true, DialPort0: true},
		&pruneServerEntryTestCase{IPAddress: "192.0.2.13", ExplicitTag: true, LocalTimestamp: oldTimeStamp, PsinetValid: true, ExpectPrune: true, IsEmbedded: true, DialPort0: true},
	}

	for _, testCase := range pruneServerEntryTestCases {

		dialPort := 4000
		if testCase.DialPort0 {
			dialPort = 0
		}

		_, _, _, _, encodedServerEntry, err := GenerateConfig(
			&GenerateConfigParams{
				ServerIPAddress:     testCase.IPAddress,
				TunnelProtocolPorts: map[string]int{runConfig.tunnelProtocol: dialPort},
			})
		if err != nil {
			t.Fatalf("GenerateConfig failed: %s", err)
		}

		serverEntrySource := protocol.SERVER_ENTRY_SOURCE_REMOTE
		if testCase.IsEmbedded {
			serverEntrySource = protocol.SERVER_ENTRY_SOURCE_EMBEDDED
		}

		serverEntryFields, err := protocol.DecodeServerEntryFields(
			string(encodedServerEntry),
			testCase.LocalTimestamp,
			serverEntrySource)
		if err != nil {
			t.Fatalf("DecodeServerEntryFields failed: %s", err)
		}

		// GenerateConfig now generates an explict tag for each server entry.
		// To test the legacy case with no tag, delete it here.
		delete(serverEntryFields, "tag")

		if testCase.ExplicitTag {
			testCase.ExpectedTag = prng.Base64String(32)
			serverEntryFields.SetTag(testCase.ExpectedTag)
		} else {
			testCase.ExpectedTag = protocol.GenerateServerEntryTag(
				serverEntryFields.GetIPAddress(),
				serverEntryFields.GetWebServerSecret())
		}

		testCase.ServerEntryFields = serverEntryFields
	}

	psinetValidServerEntryTags := make([]string, 0)
	expectedNumPruneNotices := 0

	for _, testCase := range pruneServerEntryTestCases {

		if testCase.PsinetValid {
			psinetValidServerEntryTags = append(
				psinetValidServerEntryTags, testCase.ExpectedTag)
		}

		if testCase.ExpectPrune {
			expectedNumPruneNotices += 1
		}
	}

	return pruneServerEntryTestCases,
		psinetValidServerEntryTags,
		expectedNumPruneNotices
}

func storePruneServerEntriesTest(
	t *testing.T,
	runConfig *runServerConfig,
	testDataDirName string,
	pruneServerEntryTestCases []*pruneServerEntryTestCase) {

	if !runConfig.doPruneServerEntries {
		return
	}

	for _, testCase := range pruneServerEntryTestCases {

		err := psiphon.StoreServerEntry(testCase.ServerEntryFields, true)
		if err != nil {
			t.Fatalf("StoreServerEntry failed: %s", err)
		}
	}

	clientConfig := &psiphon.Config{
		SponsorId:            "0",
		PropagationChannelId: "0",

		// DataRootDirectory must to be set to avoid a migration in the current
		// working directory.
		DataRootDirectory: testDataDirName,
	}
	err := clientConfig.Commit(false)
	if err != nil {
		t.Fatalf("Commit failed: %s", err)
	}

	resolver := psiphon.NewResolver(clientConfig, true)
	defer resolver.Stop()
	clientConfig.SetResolver(resolver)

	applyParameters := make(map[string]interface{})
	applyParameters[parameters.RecordFailedTunnelPersistentStatsProbability] = 1.0

	err = clientConfig.SetParameters("", true, applyParameters)
	if err != nil {
		t.Fatalf("SetParameters failed: %s", err)
	}

	verifyTestCasesStored := make(verifyTestCasesStoredLookup)
	for _, testCase := range pruneServerEntryTestCases {
		verifyTestCasesStored.mustBeStored(testCase.IPAddress)
	}

	scanServerEntries(t, clientConfig, pruneServerEntryTestCases, func(
		t *testing.T,
		testCase *pruneServerEntryTestCase,
		serverEntry *protocol.ServerEntry) {

		verifyTestCasesStored.isStored(testCase.IPAddress)

		// Check that random tag was retained or derived tag was calculated as
		// expected

		if serverEntry.Tag != testCase.ExpectedTag {
			t.Fatalf("unexpected tag for %s got %s expected %s",
				testCase.IPAddress, serverEntry.Tag, testCase.ExpectedTag)
		}

		// Create failed tunnel event records to exercise pruning

		dialParams, err := psiphon.MakeDialParameters(
			clientConfig,
			nil,
			nil,
			func(_ *protocol.ServerEntry, _ string) bool { return true },
			func(serverEntry *protocol.ServerEntry) (string, bool) {
				return runConfig.tunnelProtocol, true
			},
			serverEntry,
			nil,
			nil,
			false,
			0,
			0)
		if err != nil {
			t.Fatalf("MakeDialParameters failed: %s", err)
		}

		err = psiphon.RecordFailedTunnelStat(
			clientConfig, dialParams, nil, 0, 0, std_errors.New("test error"))
		if err != nil {
			t.Fatalf("RecordFailedTunnelStat failed: %s", err)
		}
	})

	verifyTestCasesStored.checkStored(
		t, "missing prune test case server entries")
}

func checkPruneServerEntriesTest(
	t *testing.T,
	runConfig *runServerConfig,
	testDataDirName string,
	pruneServerEntryTestCases []*pruneServerEntryTestCase) {

	if !runConfig.doPruneServerEntries {
		return
	}

	clientConfig := &psiphon.Config{
		SponsorId:            "0",
		PropagationChannelId: "0",

		// DataRootDirectory must to be set to avoid a migration in the current
		// working directory.
		DataRootDirectory: testDataDirName,
	}
	err := clientConfig.Commit(false)
	if err != nil {
		t.Fatalf("Commit failed: %s", err)
	}

	// Check that server entries remain or are pruned as expected

	verifyTestCasesStored := make(verifyTestCasesStoredLookup)
	for _, testCase := range pruneServerEntryTestCases {
		if !testCase.ExpectPrune {
			verifyTestCasesStored.mustBeStored(testCase.IPAddress)
		}
	}

	scanServerEntries(t, clientConfig, pruneServerEntryTestCases, func(
		t *testing.T,
		testCase *pruneServerEntryTestCase,
		serverEntry *protocol.ServerEntry) {

		if testCase.ExpectPrune {
			t.Fatalf("expected prune for %s", testCase.IPAddress)
		} else {
			verifyTestCasesStored.isStored(testCase.IPAddress)
		}
	})

	verifyTestCasesStored.checkStored(
		t, "missing prune test case server entries")

	// Check that pruned server entries reimport or not, as expected

	for _, testCase := range pruneServerEntryTestCases {

		err := psiphon.StoreServerEntry(testCase.ServerEntryFields, true)
		if err != nil {
			t.Fatalf("StoreServerEntry failed: %s", err)
		}
	}

	verifyTestCasesStored = make(verifyTestCasesStoredLookup)
	for _, testCase := range pruneServerEntryTestCases {
		if !testCase.ExpectPrune || !testCase.IsEmbedded {
			verifyTestCasesStored.mustBeStored(testCase.IPAddress)
		}
	}

	scanServerEntries(t, clientConfig, pruneServerEntryTestCases, func(
		t *testing.T,
		testCase *pruneServerEntryTestCase,
		serverEntry *protocol.ServerEntry) {

		if testCase.ExpectPrune && testCase.IsEmbedded {
			t.Fatalf("expected tombstone for %s", testCase.IPAddress)
		} else {
			verifyTestCasesStored.isStored(testCase.IPAddress)
		}
	})

	verifyTestCasesStored.checkStored(
		t, "missing reimported prune test case server entries")

	// Non-embedded server entries with tombstones _can_ be reimported

	for _, testCase := range pruneServerEntryTestCases {

		testCase.ServerEntryFields.SetLocalSource(protocol.SERVER_ENTRY_SOURCE_REMOTE)

		err := psiphon.StoreServerEntry(testCase.ServerEntryFields, true)
		if err != nil {
			t.Fatalf("StoreServerEntry failed: %s", err)
		}
	}

	verifyTestCasesStored = make(verifyTestCasesStoredLookup)
	for _, testCase := range pruneServerEntryTestCases {
		verifyTestCasesStored.mustBeStored(testCase.IPAddress)
	}

	scanServerEntries(t, clientConfig, pruneServerEntryTestCases, func(
		t *testing.T,
		testCase *pruneServerEntryTestCase,
		serverEntry *protocol.ServerEntry) {

		verifyTestCasesStored.isStored(testCase.IPAddress)
	})

	verifyTestCasesStored.checkStored(
		t, "missing non-embedded reimported prune test case server entries")
}

func scanServerEntries(
	t *testing.T,
	clientConfig *psiphon.Config,
	pruneServerEntryTestCases []*pruneServerEntryTestCase,
	scanner func(
		t *testing.T,
		testCase *pruneServerEntryTestCase,
		serverEntry *protocol.ServerEntry)) {

	_, iterator, err := psiphon.NewServerEntryIterator(clientConfig)
	if err != nil {
		t.Fatalf("NewServerEntryIterator failed: %s", err)
	}
	defer iterator.Close()

	for {

		serverEntry, err := iterator.Next()
		if err != nil {
			t.Fatalf("ServerIterator.Next failed: %s", err)
		}
		if serverEntry == nil {
			break
		}

		for _, testCase := range pruneServerEntryTestCases {
			if testCase.IPAddress == serverEntry.IpAddress {
				scanner(t, testCase, serverEntry)
				break
			}
		}
	}
}

type verifyTestCasesStoredLookup map[string]bool

func (v verifyTestCasesStoredLookup) mustBeStored(s string) {
	v[s] = true
}

func (v verifyTestCasesStoredLookup) isStored(s string) {
	delete(v, s)
}

func (v verifyTestCasesStoredLookup) checkStored(t *testing.T, errMessage string) {
	if len(v) != 0 {
		t.Fatalf("%s: %+v", errMessage, v)
	}
}

type Number interface {
	int64 | float64
}

// testSampleInUniformRange returns true if sample is in the range [a, b],
// or within 2 standard deviations of the range.
func testSampleInUniformRange[V Number](sample, a, b, stddev V) bool {
	if sample >= a && sample <= b {
		return true
	}
	lower := math.Abs(float64(sample-a) / float64(stddev))
	higher := math.Abs(float64(sample-b) / float64(stddev))
	return lower <= 2.0 || higher <= 2.0
}

type flowInspectorProxy struct {
	listener *socks.SocksListener
	ch       chan []*flows
}

func newFlowInspectorProxy() (*flowInspectorProxy, error) {
	listener, err := socks.ListenSocks("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Printf("socks.ListenSocks failed: %s\n", err)
		return nil, err
	}
	return &flowInspectorProxy{
		listener: listener,
		ch:       make(chan []*flows, 1),
	}, nil
}

func (f *flowInspectorProxy) start() {

	go func() {
		for {
			localConn, err := f.listener.AcceptSocks()
			if err != nil {
				return
			}
			go func() {
				defer localConn.Close()
				remoteConn, err := net.Dial("tcp", localConn.Req.Target)
				if err != nil {
					fmt.Printf("net.Dial failed: %s\n", err)
					return
				}
				defer remoteConn.Close()
				err = localConn.Grant(&net.TCPAddr{IP: net.ParseIP("0.0.0.0"), Port: 0})
				if err != nil {
					fmt.Printf("localConn.Grant failed: %s\n", err)
					return
				}

				waitGroup := new(sync.WaitGroup)
				waitGroup.Add(1)
				serverFlowWriter := newFlowWriter(true)
				clientFlowWriter := newFlowWriter(false)
				go func() {
					defer waitGroup.Done()

					// Copy from remote to local, and tee to serverFlowWriter.
					io.Copy(localConn, io.TeeReader(remoteConn, serverFlowWriter))

					// fmt.Printf("Server Flows:\n%s\n\n", serverFlowWriter.String())

					localConn.Close()
					remoteConn.Close()
				}()

				// Copy from local to remote, and tee to clientFlowWriter.
				io.Copy(remoteConn, io.TeeReader(localConn, clientFlowWriter))

				// fmt.Printf("Client Flows:\n%s\n\n", clientFlowWriter.String())

				localConn.Close()
				remoteConn.Close()
				waitGroup.Wait()

				// clientFlowWriter and serverFlowWriter are synchronized by waitGroup.
				f.ch <- []*flows{serverFlowWriter, clientFlowWriter}
			}()
		}
	}()
}

func (f *flowInspectorProxy) close() error {
	return f.listener.Close()
}

type flow struct {
	// timeDelta is the time elapsed since the last flow
	timeDelta time.Duration
	data      []byte
}

type flows struct {
	lastTime   time.Time
	server     bool
	streamDump *bytes.Buffer
	flows      []flow
}

func newFlowWriter(server bool) *flows {
	return &flows{
		lastTime:   time.Now(),
		streamDump: new(bytes.Buffer),
		server:     server,
	}
}

// String returns a string representation of the first 10 flows.
func (f *flows) String() string {
	var sb strings.Builder
	for i, flow := range f.flows[:10] {
		sb.WriteString(fmt.Sprintf("Flow %d: %.5f ms: %s\n",
			i, flow.timeDelta.Seconds()*1000, hex.EncodeToString(flow.data)))
	}
	if len(f.flows) > 10 {
		sb.WriteString("...\n")
	}
	return sb.String()
}

func (f *flows) Write(p []byte) (n int, err error) {
	curTime := time.Now()

	_, err = f.streamDump.Write(p)
	if err != nil {
		return 0, err
	}

	data := make([]byte, len(p))
	n = copy(data, p)
	if n < len(p) {
		return n, io.ErrShortWrite
	}

	f.flows = append(f.flows, flow{
		timeDelta: time.Since(f.lastTime),
		data:      data,
	})

	f.lastTime = curTime

	return n, err
}

// newDiscoveryServers returns len(ipAddresses) discovery servers with the
// given IP addresses and randomly generated tags.
func newDiscoveryServers(ipAddresses []string) ([]*psinet.DiscoveryServer, error) {

	servers := make([]*psinet.DiscoveryServer, len(ipAddresses))

	for i, ipAddress := range ipAddresses {

		encodedServer, err := protocol.EncodeServerEntry(&protocol.ServerEntry{
			IpAddress: ipAddress,
			Tag:       prng.HexString(16),
		})
		if err != nil {
			return nil, errors.Trace(err)
		}

		servers[i] = &psinet.DiscoveryServer{
			DiscoveryDateRange: []time.Time{
				time.Now().Add(-time.Hour).UTC(),
				time.Now().Add(time.Hour).UTC(),
			},
			EncodedServerEntry: encodedServer,
		}
	}
	return servers, nil
}
