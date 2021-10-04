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
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
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

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/accesscontrol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/quic"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tactics"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/values"
	"golang.org/x/net/proxy"
)

var serverIPAddress, testDataDirName string
var mockWebServerURL, mockWebServerExpectedResponse string
var mockWebServerPort = 8080

func TestMain(m *testing.M) {
	flag.Parse()

	serverIPv4Address, serverIPv6Address, err := common.GetRoutableInterfaceIPAddresses()
	if err != nil {
		fmt.Printf("error getting server IP address: %s\n", err)
		os.Exit(1)
	}
	if serverIPv4Address != nil {
		serverIPAddress = serverIPv4Address.String()
	} else {
		serverIPAddress = serverIPv6Address.String()
	}

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
	webServerAddress := fmt.Sprintf("%s:%d", serverIPAddress, mockWebServerPort)
	server := &http.Server{
		Addr:    webServerAddress,
		Handler: serveMux,
	}

	go func() {
		err := server.ListenAndServe()
		if err != nil {
			fmt.Printf("error running mock web server: %s\n", err)
			os.Exit(1)
		}
	}()

	// TODO: properly synchronize with web server readiness
	time.Sleep(1 * time.Second)

	return fmt.Sprintf("http://%s/", webServerAddress), responseBody
}

// Note: not testing fronted meek protocols, which client is
// hard-wired to expect running on privileged ports 80 and 443.

func TestSSH(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "SSH",
			enableSSHAPIRequests: true,
			doHotReload:          false,
			doDefaultSponsorID:   false,
			denyTrafficRules:     false,
			requireAuthorization: true,
			omitAuthorization:    false,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			forceFragmenting:     false,
			forceLivenessTest:    false,
			doPruneServerEntries: false,
			doDanglingTCPConn:    true,
			doPacketManipulation: false,
			doBurstMonitor:       false,
			doSplitTunnel:        false,
		})
}

func TestOSSH(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "OSSH",
			enableSSHAPIRequests: true,
			doHotReload:          false,
			doDefaultSponsorID:   false,
			denyTrafficRules:     false,
			requireAuthorization: true,
			omitAuthorization:    false,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			forceFragmenting:     false,
			forceLivenessTest:    false,
			doPruneServerEntries: false,
			doDanglingTCPConn:    true,
			doPacketManipulation: false,
			doBurstMonitor:       false,
			doSplitTunnel:        false,
		})
}

func TestFragmentedOSSH(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "OSSH",
			enableSSHAPIRequests: true,
			doHotReload:          false,
			doDefaultSponsorID:   false,
			denyTrafficRules:     false,
			requireAuthorization: true,
			omitAuthorization:    false,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			forceFragmenting:     true,
			forceLivenessTest:    false,
			doPruneServerEntries: false,
			doDanglingTCPConn:    true,
			doPacketManipulation: false,
			doBurstMonitor:       false,
			doSplitTunnel:        false,
		})
}

func TestUnfrontedMeek(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "UNFRONTED-MEEK-OSSH",
			enableSSHAPIRequests: true,
			doHotReload:          false,
			doDefaultSponsorID:   false,
			denyTrafficRules:     false,
			requireAuthorization: true,
			omitAuthorization:    false,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			forceFragmenting:     false,
			forceLivenessTest:    false,
			doPruneServerEntries: false,
			doDanglingTCPConn:    true,
			doPacketManipulation: false,
			doBurstMonitor:       false,
			doSplitTunnel:        false,
		})
}

func TestUnfrontedMeekHTTPS(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "UNFRONTED-MEEK-HTTPS-OSSH",
			tlsProfile:           protocol.TLS_PROFILE_RANDOMIZED,
			enableSSHAPIRequests: true,
			doHotReload:          false,
			doDefaultSponsorID:   false,
			denyTrafficRules:     false,
			requireAuthorization: true,
			omitAuthorization:    false,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			forceFragmenting:     false,
			forceLivenessTest:    false,
			doPruneServerEntries: false,
			doDanglingTCPConn:    true,
			doPacketManipulation: false,
			doBurstMonitor:       false,
			doSplitTunnel:        false,
		})
}

func TestUnfrontedMeekHTTPSTLS13(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "UNFRONTED-MEEK-HTTPS-OSSH",
			tlsProfile:           protocol.TLS_PROFILE_CHROME_70,
			enableSSHAPIRequests: true,
			doHotReload:          false,
			doDefaultSponsorID:   false,
			denyTrafficRules:     false,
			requireAuthorization: true,
			omitAuthorization:    false,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			forceFragmenting:     false,
			forceLivenessTest:    false,
			doPruneServerEntries: false,
			doDanglingTCPConn:    true,
			doPacketManipulation: false,
			doBurstMonitor:       false,
			doSplitTunnel:        false,
		})
}

func TestUnfrontedMeekSessionTicket(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "UNFRONTED-MEEK-SESSION-TICKET-OSSH",
			tlsProfile:           protocol.TLS_PROFILE_CHROME_58,
			enableSSHAPIRequests: true,
			doHotReload:          false,
			doDefaultSponsorID:   false,
			denyTrafficRules:     false,
			requireAuthorization: true,
			omitAuthorization:    false,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			forceFragmenting:     false,
			forceLivenessTest:    false,
			doPruneServerEntries: false,
			doDanglingTCPConn:    true,
			doPacketManipulation: false,
			doBurstMonitor:       false,
			doSplitTunnel:        false,
		})
}

func TestUnfrontedMeekSessionTicketTLS13(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "UNFRONTED-MEEK-SESSION-TICKET-OSSH",
			tlsProfile:           protocol.TLS_PROFILE_CHROME_70,
			enableSSHAPIRequests: true,
			doHotReload:          false,
			doDefaultSponsorID:   false,
			denyTrafficRules:     false,
			requireAuthorization: true,
			omitAuthorization:    false,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			forceFragmenting:     false,
			forceLivenessTest:    false,
			doPruneServerEntries: false,
			doDanglingTCPConn:    true,
			doPacketManipulation: false,
			doBurstMonitor:       false,
			doSplitTunnel:        false,
		})
}

func TestQUICOSSH(t *testing.T) {
	if !quic.Enabled() {
		t.Skip("QUIC is not enabled")
	}
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "QUIC-OSSH",
			enableSSHAPIRequests: true,
			doHotReload:          false,
			doDefaultSponsorID:   false,
			denyTrafficRules:     false,
			requireAuthorization: true,
			omitAuthorization:    false,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			forceFragmenting:     false,
			forceLivenessTest:    false,
			doPruneServerEntries: false,
			doDanglingTCPConn:    false,
			doPacketManipulation: false,
			doBurstMonitor:       false,
			doSplitTunnel:        false,
		})
}

func TestWebTransportAPIRequests(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "OSSH",
			enableSSHAPIRequests: false,
			doHotReload:          false,
			doDefaultSponsorID:   false,
			denyTrafficRules:     false,
			requireAuthorization: false,
			omitAuthorization:    true,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			forceFragmenting:     false,
			forceLivenessTest:    false,
			doPruneServerEntries: false,
			doDanglingTCPConn:    false,
			doPacketManipulation: false,
			doBurstMonitor:       false,
			doSplitTunnel:        false,
		})
}

func TestHotReload(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "OSSH",
			enableSSHAPIRequests: true,
			doHotReload:          true,
			doDefaultSponsorID:   false,
			denyTrafficRules:     false,
			requireAuthorization: true,
			omitAuthorization:    false,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			forceFragmenting:     false,
			forceLivenessTest:    false,
			doPruneServerEntries: false,
			doDanglingTCPConn:    false,
			doPacketManipulation: false,
			doBurstMonitor:       false,
			doSplitTunnel:        false,
		})
}

func TestDefaultSponsorID(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "OSSH",
			enableSSHAPIRequests: true,
			doHotReload:          true,
			doDefaultSponsorID:   true,
			denyTrafficRules:     false,
			requireAuthorization: true,
			omitAuthorization:    false,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			forceFragmenting:     false,
			forceLivenessTest:    false,
			doPruneServerEntries: false,
			doDanglingTCPConn:    false,
			doPacketManipulation: false,
			doBurstMonitor:       false,
			doSplitTunnel:        false,
		})
}

func TestDenyTrafficRules(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "OSSH",
			enableSSHAPIRequests: true,
			doHotReload:          true,
			doDefaultSponsorID:   false,
			denyTrafficRules:     true,
			requireAuthorization: true,
			omitAuthorization:    false,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			forceFragmenting:     false,
			forceLivenessTest:    false,
			doPruneServerEntries: false,
			doDanglingTCPConn:    false,
			doPacketManipulation: false,
			doBurstMonitor:       false,
			doSplitTunnel:        false,
		})
}

func TestOmitAuthorization(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "OSSH",
			enableSSHAPIRequests: true,
			doHotReload:          true,
			doDefaultSponsorID:   false,
			denyTrafficRules:     false,
			requireAuthorization: true,
			omitAuthorization:    true,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			forceFragmenting:     false,
			forceLivenessTest:    false,
			doPruneServerEntries: false,
			doDanglingTCPConn:    false,
			doPacketManipulation: false,
			doBurstMonitor:       false,
			doSplitTunnel:        false,
		})
}

func TestNoAuthorization(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "OSSH",
			enableSSHAPIRequests: true,
			doHotReload:          true,
			doDefaultSponsorID:   false,
			denyTrafficRules:     false,
			requireAuthorization: false,
			omitAuthorization:    true,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			forceFragmenting:     false,
			forceLivenessTest:    false,
			doPruneServerEntries: false,
			doDanglingTCPConn:    false,
			doPacketManipulation: false,
			doBurstMonitor:       false,
			doSplitTunnel:        false,
		})
}

func TestUnusedAuthorization(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "OSSH",
			enableSSHAPIRequests: true,
			doHotReload:          true,
			doDefaultSponsorID:   false,
			denyTrafficRules:     false,
			requireAuthorization: false,
			omitAuthorization:    false,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			forceFragmenting:     false,
			forceLivenessTest:    false,
			doPruneServerEntries: false,
			doDanglingTCPConn:    false,
			doPacketManipulation: false,
			doBurstMonitor:       false,
			doSplitTunnel:        false,
		})
}

func TestTCPOnlySLOK(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "OSSH",
			enableSSHAPIRequests: true,
			doHotReload:          false,
			doDefaultSponsorID:   false,
			denyTrafficRules:     false,
			requireAuthorization: true,
			omitAuthorization:    false,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: false,
			forceFragmenting:     false,
			forceLivenessTest:    false,
			doPruneServerEntries: false,
			doDanglingTCPConn:    false,
			doPacketManipulation: false,
			doBurstMonitor:       false,
			doSplitTunnel:        false,
		})
}

func TestUDPOnlySLOK(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "OSSH",
			enableSSHAPIRequests: true,
			doHotReload:          false,
			doDefaultSponsorID:   false,
			denyTrafficRules:     false,
			requireAuthorization: true,
			omitAuthorization:    false,
			doTunneledWebRequest: false,
			doTunneledNTPRequest: true,
			forceFragmenting:     false,
			forceLivenessTest:    false,
			doPruneServerEntries: false,
			doDanglingTCPConn:    false,
			doPacketManipulation: false,
			doBurstMonitor:       false,
			doSplitTunnel:        false,
		})
}

func TestLivenessTest(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "OSSH",
			enableSSHAPIRequests: true,
			doHotReload:          false,
			doDefaultSponsorID:   false,
			denyTrafficRules:     false,
			requireAuthorization: true,
			omitAuthorization:    false,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			forceFragmenting:     false,
			forceLivenessTest:    true,
			doPruneServerEntries: false,
			doDanglingTCPConn:    false,
			doPacketManipulation: false,
			doBurstMonitor:       false,
			doSplitTunnel:        false,
		})
}

func TestPruneServerEntries(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "OSSH",
			enableSSHAPIRequests: true,
			doHotReload:          false,
			doDefaultSponsorID:   false,
			denyTrafficRules:     false,
			requireAuthorization: true,
			omitAuthorization:    false,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			forceFragmenting:     false,
			forceLivenessTest:    true,
			doPruneServerEntries: true,
			doDanglingTCPConn:    false,
			doPacketManipulation: false,
			doBurstMonitor:       false,
			doSplitTunnel:        false,
		})
}

func TestBurstMonitor(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "OSSH",
			enableSSHAPIRequests: true,
			doHotReload:          false,
			doDefaultSponsorID:   false,
			denyTrafficRules:     false,
			requireAuthorization: true,
			omitAuthorization:    false,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			forceFragmenting:     false,
			forceLivenessTest:    false,
			doPruneServerEntries: false,
			doDanglingTCPConn:    true,
			doPacketManipulation: false,
			doBurstMonitor:       true,
			doSplitTunnel:        false,
		})
}

func TestSplitTunnel(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "OSSH",
			enableSSHAPIRequests: true,
			doHotReload:          false,
			doDefaultSponsorID:   false,
			denyTrafficRules:     false,
			requireAuthorization: true,
			omitAuthorization:    false,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			forceFragmenting:     false,
			forceLivenessTest:    false,
			doPruneServerEntries: false,
			doDanglingTCPConn:    true,
			doPacketManipulation: false,
			doBurstMonitor:       false,
			doSplitTunnel:        true,
		})
}

type runServerConfig struct {
	tunnelProtocol       string
	tlsProfile           string
	enableSSHAPIRequests bool
	doHotReload          bool
	doDefaultSponsorID   bool
	denyTrafficRules     bool
	requireAuthorization bool
	omitAuthorization    bool
	doTunneledWebRequest bool
	doTunneledNTPRequest bool
	forceFragmenting     bool
	forceLivenessTest    bool
	doPruneServerEntries bool
	doDanglingTCPConn    bool
	doPacketManipulation bool
	doBurstMonitor       bool
	doSplitTunnel        bool
}

var (
	testSSHClientVersions                = []string{"SSH-2.0-A", "SSH-2.0-B", "SSH-2.0-C"}
	testUserAgents                       = []string{"ua1", "ua2", "ua3"}
	testNetworkType                      = "WIFI"
	testCustomHostNameRegex              = `[a-z0-9]{5,10}\.example\.org`
	testClientFeatures                   = []string{"feature 1", "feature 2"}
	testDisallowedTrafficAlertActionURLs = []string{"https://example.org/disallowed"}
)

var serverRuns = 0

func runServer(t *testing.T, runConfig *runServerConfig) {

	serverRuns += 1

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

	// Enable tactics when the test protocol is meek. Both the client and the
	// server will be configured to support tactics. The client config will be
	// set with a nonfunctional config so that the tactics request must
	// succeed, overriding the nonfunctional values, for the tunnel to
	// establish.

	doClientTactics := protocol.TunnelProtocolUsesMeek(runConfig.tunnelProtocol)
	doServerTactics := doClientTactics || runConfig.forceFragmenting || runConfig.doBurstMonitor

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

	psiphonServerIPAddress := serverIPAddress
	if protocol.TunnelProtocolUsesQUIC(runConfig.tunnelProtocol) {
		// Workaround for macOS firewall.
		psiphonServerIPAddress = "127.0.0.1"
	}
	psiphonServerPort := 4000

	generateConfigParams := &GenerateConfigParams{
		ServerIPAddress:      psiphonServerIPAddress,
		EnableSSHAPIRequests: runConfig.enableSSHAPIRequests,
		WebServerPort:        8000,
		TunnelProtocolPorts:  map[string]int{runConfig.tunnelProtocol: psiphonServerPort},
	}

	if doServerTactics {
		generateConfigParams.TacticsRequestPublicKey = tacticsRequestPublicKey
		generateConfigParams.TacticsRequestObfuscatedKey = tacticsRequestObfuscatedKey
	}

	serverConfigJSON, _, _, _, encodedServerEntry, err := GenerateConfig(generateConfigParams)
	if err != nil {
		t.Fatalf("error generating server config: %s", err)
	}

	// customize server config

	// Initialize prune server entry test cases and associated data to pave into psinet.
	pruneServerEntryTestCases, psinetValidServerEntryTags, expectedNumPruneNotices :=
		initializePruneServerEntriesTest(t, runConfig)

	// Pave psinet with random values to test handshake homepages.
	psinetFilename := filepath.Join(testDataDirName, "psinet.json")
	sponsorID, expectedHomepageURL := pavePsinetDatabaseFile(
		t, runConfig.doDefaultSponsorID, psinetFilename, psinetValidServerEntryTags)

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

	// Only pave the tactics config when tactics are required. This exercises the
	// case where the tactics config is omitted.
	if doServerTactics {
		tacticsConfigFilename = filepath.Join(testDataDirName, "tactics_config.json")
		paveTacticsConfigFile(
			t,
			tacticsConfigFilename,
			tacticsRequestPublicKey,
			tacticsRequestPrivateKey,
			tacticsRequestObfuscatedKey,
			runConfig.tunnelProtocol,
			propagationChannelID,
			livenessTestSize,
			runConfig.doBurstMonitor)
	}

	blocklistFilename := filepath.Join(testDataDirName, "blocklist.csv")
	paveBlocklistFile(t, blocklistFilename)

	var serverConfig map[string]interface{}
	json.Unmarshal(serverConfigJSON, &serverConfig)

	// The test GeoIP database maps all IPs to a single, non-"None" country. When
	// split tunnel mode is enabled, this should cause port forwards to be
	// untunneled. When split tunnel mode is not enabled, port forwards should be
	// tunneled despite the country match.
	geoIPDatabaseFilename := filepath.Join(testDataDirName, "geoip_database.mmbd")
	paveGeoIPDatabaseFile(t, geoIPDatabaseFilename)
	serverConfig["GeoIPDatabaseFilenames"] = []string{geoIPDatabaseFilename}

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

	// Exercise this option.
	serverConfig["PeriodicGarbageCollectionSeconds"] = 1

	// Allow port forwards to local test web server.
	serverConfig["AllowBogons"] = true

	serverConfig["RunPacketManipulator"] = runConfig.doPacketManipulation

	serverConfigJSON, _ = json.Marshal(serverConfig)

	serverTunnelLog := make(chan map[string]interface{}, 1)
	uniqueUserLog := make(chan map[string]interface{}, 1)

	setLogCallback(func(log []byte) {

		logFields := make(map[string]interface{})

		err := json.Unmarshal(log, &logFields)
		if err != nil {
			return
		}

		if logFields["event_name"] == nil {
			return
		}

		switch logFields["event_name"].(string) {
		case "unique_user":
			select {
			case uniqueUserLog <- logFields:
			default:
			}
		case "server_tunnel":
			select {
			case serverTunnelLog <- logFields:
			default:
			}
		}
	})

	// run server

	serverWaitGroup := new(sync.WaitGroup)
	serverWaitGroup.Add(1)
	go func() {
		defer serverWaitGroup.Done()
		err := RunServices(serverConfigJSON)
		if err != nil {
			// TODO: wrong goroutine for t.FatalNow()
			t.Errorf("error running server: %s", err)
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
			t.Errorf("server shutdown timeout exceeded")
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

		// Pave new config files with different random values.
		sponsorID, expectedHomepageURL = pavePsinetDatabaseFile(
			t, runConfig.doDefaultSponsorID, psinetFilename, psinetValidServerEntryTags)

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
	jsonNetworkID := fmt.Sprintf(`,"NetworkID" : "WIFI-%s"`, time.Now().String())

	jsonLimitTLSProfiles := ""
	if runConfig.tlsProfile != "" {
		jsonLimitTLSProfiles = fmt.Sprintf(`,"LimitTLSProfiles" : ["%s"]`, runConfig.tlsProfile)
	}

	testClientFeaturesJSON, _ := json.Marshal(testClientFeatures)

	clientConfigJSON := fmt.Sprintf(`
    {
        "ClientPlatform" : "Android_10_com.test.app",
        "ClientVersion" : "0",
        "ClientFeatures" : %s,
        "SponsorId" : "0",
        "PropagationChannelId" : "0",
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
		runConfig.tunnelProtocol,
		jsonLimitTLSProfiles,
		jsonNetworkID)

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

	if runConfig.doSplitTunnel {
		clientConfig.EnableSplitTunnel = true
	}

	if !runConfig.omitAuthorization {
		clientConfig.Authorizations = []string{clientAuthorization}
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
	tunnelsEstablished := make(chan struct{}, 1)
	homepageReceived := make(chan struct{}, 1)
	slokSeeded := make(chan struct{}, 1)
	numPruneNotices := 0
	pruneServerEntriesNoticesEmitted := make(chan struct{}, 1)
	serverAlertDisallowedNoticesEmitted := make(chan struct{}, 1)
	untunneledPortForward := make(chan struct{}, 1)

	psiphon.SetNoticeWriter(psiphon.NewNoticeReceiver(
		func(notice []byte) {

			//fmt.Printf("%s\n", string(notice))

			noticeType, payload, err := psiphon.GetNotice(notice)
			if err != nil {
				return
			}

			switch noticeType {

			case "ConnectedServer":
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
	waitOnNotification(t, tunnelsEstablished, timeoutSignal, "tunnel established timeout exceeded")
	waitOnNotification(t, homepageReceived, timeoutSignal, "homepage received timeout exceeded")

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
			t.Fatalf("unexpected untunnedl port forward")
		default:
		}
	}

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

	expectClientBPFField := psiphon.ClientBPFEnabled() && doClientTactics
	expectServerBPFField := ServerBPFEnabled() && doServerTactics
	expectServerPacketManipulationField := runConfig.doPacketManipulation
	expectBurstFields := runConfig.doBurstMonitor
	expectTCPPortForwardDial := runConfig.doTunneledWebRequest
	expectTCPDataTransfer := runConfig.doTunneledWebRequest && !expectTrafficFailure && !runConfig.doSplitTunnel
	// Even with expectTrafficFailure, DNS port forwards will succeed
	expectUDPDataTransfer := runConfig.doTunneledNTPRequest

	select {
	case logFields := <-serverTunnelLog:
		err := checkExpectedServerTunnelLogFields(
			runConfig,
			expectClientBPFField,
			expectServerBPFField,
			expectServerPacketManipulationField,
			expectBurstFields,
			expectTCPPortForwardDial,
			expectTCPDataTransfer,
			expectUDPDataTransfer,
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

	// Check that datastore had retained/pruned server entries as expected.
	checkPruneServerEntriesTest(t, runConfig, testDataDirName, pruneServerEntryTestCases)
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

func checkExpectedServerTunnelLogFields(
	runConfig *runServerConfig,
	expectClientBPFField bool,
	expectServerBPFField bool,
	expectServerPacketManipulationField bool,
	expectBurstFields bool,
	expectTCPPortForwardDial bool,
	expectTCPDataTransfer bool,
	expectUDPDataTransfer bool,
	fields map[string]interface{}) error {

	// Limitations:
	//
	// - client_build_rev not set in test build (see common/buildinfo.go)
	// - egress_region, upstream_proxy_type, upstream_proxy_custom_header_names not exercised in test
	// - fronting_provider_id/meek_dial_ip_address/meek_resolved_ip_address only logged for FRONTED meek protocols

	for _, name := range []string{
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
	} {
		if fields[name] == nil || fmt.Sprintf("%s", fields[name]) == "" {
			return fmt.Errorf("missing expected field '%s'", name)
		}
	}

	if fields["relay_protocol"].(string) != runConfig.tunnelProtocol {
		return fmt.Errorf("unexpected relay_protocol '%s'", fields["relay_protocol"])
	}

	if !common.Contains(testSSHClientVersions, fields["ssh_client_version"].(string)) {
		return fmt.Errorf("unexpected relay_protocol '%s'", fields["ssh_client_version"])
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

	if protocol.TunnelProtocolUsesMeek(runConfig.tunnelProtocol) {

		for _, name := range []string{
			"user_agent",
			"meek_transformed_host_name",
			"meek_cookie_size",
			"meek_limit_request",
			"meek_underlying_connection_count",
			tactics.APPLIED_TACTICS_TAG_PARAMETER_NAME,
		} {
			if fields[name] == nil || fmt.Sprintf("%s", fields[name]) == "" {
				return fmt.Errorf("missing expected field '%s'", name)
			}
		}

		if !common.Contains(testUserAgents, fields["user_agent"].(string)) {
			return fmt.Errorf("unexpected user_agent '%s'", fields["user_agent"])
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

		for _, name := range []string{
			"meek_dial_ip_address",
			"meek_resolved_ip_address",
		} {
			if fields[name] != nil {
				return fmt.Errorf("unexpected field '%s'", name)
			}
		}
	}

	if protocol.TunnelProtocolUsesMeekHTTPS(runConfig.tunnelProtocol) {

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

		for _, name := range []string{
			"meek_dial_ip_address",
			"meek_resolved_ip_address",
			"meek_host_header",
		} {
			if fields[name] != nil {
				return fmt.Errorf("unexpected field '%s'", name)
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

		if !common.Contains(protocol.SupportedQUICVersions, fields["quic_version"].(string)) {
			return fmt.Errorf("unexpected quic_version '%s'", fields["quic_version"])
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

	if fields["network_type"].(string) != testNetworkType {
		return fmt.Errorf("unexpected network_type '%s'", fields["network_type"])
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
	} {
		if fields[name] == nil || fmt.Sprintf("%s", fields[name]) == "" {
			return fmt.Errorf("missing expected field '%s'", name)
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

	for _, testHostname := range []string{"time.google.com", "time.nist.gov", "pool.ntp.org"} {
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

	addrs, _, err := psiphon.ResolveIP(testHostname, clientUDPConn)

	clientUDPConn.Close()

	if err == nil && (len(addrs) == 0 || len(addrs[0]) < 4) {
		err = errors.New("no address")
	}
	if err != nil {
		return fmt.Errorf("ResolveIP failed: %s", err)
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

func pavePsinetDatabaseFile(
	t *testing.T,
	useDefaultSponsorID bool,
	psinetFilename string,
	validServerEntryTags []string) (string, string) {

	sponsorID := prng.HexString(8)

	defaultSponsorID := ""
	if useDefaultSponsorID {
		defaultSponsorID = sponsorID
	}

	fakeDomain := prng.HexString(4)
	fakePath := prng.HexString(4)
	expectedHomepageURL := fmt.Sprintf("https://%s.com/%s", fakeDomain, fakePath)

	psinetJSONFormat := `
    {
        "default_sponsor_id" : "%s",
        "sponsors": {
            "%s": {
                "home_pages": {
                    "None": [
                        {
                            "region": null,
                            "url": "%s"
                        }
                    ]
                }
            }
        },
        "default_alert_action_urls" : {
            "%s": %s
        },
        "valid_server_entry_tags" : {
            %s
        }
    }
	`

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
		expectedHomepageURL,
		protocol.PSIPHON_API_ALERT_DISALLOWED_TRAFFIC,
		actionURLsJSON,
		validServerEntryTagsJSON)

	err := ioutil.WriteFile(psinetFilename, []byte(psinetJSON), 0600)
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

	TCPPorts := fmt.Sprintf("%d", mockWebServerPort)
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

	propagationChannelID := prng.HexString(8)

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
	t *testing.T, tacticsConfigFilename string,
	tacticsRequestPublicKey, tacticsRequestPrivateKey, tacticsRequestObfuscatedKey string,
	tunnelProtocol string,
	propagationChannelID string,
	livenessTestSize int,
	doBurstMonitor bool) {

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
          "ServerProtocolPacketManipulations": {"All" : ["test-packetman-spec"]}
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

	tacticsConfigJSON := fmt.Sprintf(
		tacticsConfigJSONFormat,
		tacticsRequestPublicKey, tacticsRequestPrivateKey, tacticsRequestObfuscatedKey,
		burstParameters,
		tunnelProtocol,
		tunnelProtocol,
		tunnelProtocol,
		livenessTestSize, livenessTestSize, livenessTestSize, livenessTestSize,
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
				WebServerPort:       8000,
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
			func(_ *protocol.ServerEntry, _ string) bool { return true },
			func(serverEntry *protocol.ServerEntry) (string, bool) {
				return runConfig.tunnelProtocol, true
			},
			serverEntry,
			false,
			0,
			0)
		if err != nil {
			t.Fatalf("MakeDialParameters failed: %s", err)
		}

		err = psiphon.RecordFailedTunnelStat(
			clientConfig, dialParams, nil, 0, 0, errors.New("test error"))
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
