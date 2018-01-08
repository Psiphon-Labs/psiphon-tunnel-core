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
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"golang.org/x/net/proxy"
)

var serverIPAddress, testDataDirName string
var mockWebServerURL, mockWebServerExpectedResponse string
var mockWebServerPort = 8080

func TestMain(m *testing.M) {
	flag.Parse()

	var err error
	for _, interfaceName := range []string{"eth0", "en0"} {
		var serverIPv4Address, serverIPv6Address net.IP
		serverIPv4Address, serverIPv6Address, err = common.GetInterfaceIPAddresses(interfaceName)
		if err == nil {
			if serverIPv4Address != nil {
				serverIPAddress = serverIPv4Address.String()
			} else {
				serverIPAddress = serverIPv6Address.String()
			}
			break
		}
	}
	if err != nil {
		fmt.Printf("error getting server IP address: %s", err)
		os.Exit(1)
	}

	testDataDirName, err = ioutil.TempDir("", "psiphon-server-test")
	if err != nil {
		fmt.Printf("TempDir failed: %s\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(testDataDirName)

	os.Remove(filepath.Join(testDataDirName, psiphon.DATA_STORE_FILENAME))

	psiphon.SetEmitDiagnosticNotices(true)

	CLIENT_VERIFICATION_REQUIRED = true

	mockWebServerURL, mockWebServerExpectedResponse = runMockWebServer()

	os.Exit(m.Run())
}

func runMockWebServer() (string, string) {

	responseBody, _ := common.MakeRandomStringHex(100000)

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

// Note: not testing fronting meek protocols, which client is
// hard-wired to except running on privileged ports 80 and 443.

func TestSSH(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "SSH",
			enableSSHAPIRequests: true,
			doHotReload:          false,
			doDefaultSessionID:   false,
			denyTrafficRules:     false,
			doClientVerification: true,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
		})
}

func TestOSSH(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "OSSH",
			enableSSHAPIRequests: true,
			doHotReload:          false,
			doDefaultSessionID:   false,
			denyTrafficRules:     false,
			doClientVerification: false,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
		})
}

func TestUnfrontedMeek(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "UNFRONTED-MEEK-OSSH",
			enableSSHAPIRequests: true,
			doHotReload:          false,
			doDefaultSessionID:   false,
			denyTrafficRules:     false,
			doClientVerification: false,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
		})
}

func TestUnfrontedMeekHTTPS(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "UNFRONTED-MEEK-HTTPS-OSSH",
			enableSSHAPIRequests: true,
			doHotReload:          false,
			doDefaultSessionID:   false,
			denyTrafficRules:     false,
			doClientVerification: false,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
		})
}

func TestUnfrontedMeekSessionTicket(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "UNFRONTED-MEEK-SESSION-TICKET-OSSH",
			enableSSHAPIRequests: true,
			doHotReload:          false,
			doDefaultSessionID:   false,
			denyTrafficRules:     false,
			doClientVerification: false,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
		})
}

func TestWebTransportAPIRequests(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "OSSH",
			enableSSHAPIRequests: false,
			doHotReload:          false,
			doDefaultSessionID:   false,
			denyTrafficRules:     false,
			doClientVerification: true,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
		})
}

func TestHotReload(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "OSSH",
			enableSSHAPIRequests: true,
			doHotReload:          true,
			doDefaultSessionID:   false,
			denyTrafficRules:     false,
			doClientVerification: false,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
		})
}

func TestDefaultSessionID(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "OSSH",
			enableSSHAPIRequests: true,
			doHotReload:          true,
			doDefaultSessionID:   true,
			denyTrafficRules:     false,
			doClientVerification: false,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
		})
}

func TestDenyTrafficRules(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "OSSH",
			enableSSHAPIRequests: true,
			doHotReload:          true,
			doDefaultSessionID:   false,
			denyTrafficRules:     true,
			doClientVerification: false,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
		})
}

func TestTCPOnlySLOK(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "OSSH",
			enableSSHAPIRequests: true,
			doHotReload:          false,
			doDefaultSessionID:   false,
			denyTrafficRules:     false,
			doClientVerification: false,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: false,
		})
}

func TestUDPOnlySLOK(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "OSSH",
			enableSSHAPIRequests: true,
			doHotReload:          false,
			doDefaultSessionID:   false,
			denyTrafficRules:     false,
			doClientVerification: false,
			doTunneledWebRequest: false,
			doTunneledNTPRequest: true,
		})
}

type runServerConfig struct {
	tunnelProtocol       string
	enableSSHAPIRequests bool
	doHotReload          bool
	doDefaultSessionID   bool
	denyTrafficRules     bool
	doClientVerification bool
	doTunneledWebRequest bool
	doTunneledNTPRequest bool
}

func sendNotificationReceived(c chan<- struct{}) {
	select {
	case c <- *new(struct{}):
	default:
	}
}

func waitOnNotification(t *testing.T, c, timeoutSignal <-chan struct{}, timeoutMessage string) {
	select {
	case <-c:
	case <-timeoutSignal:
		t.Fatalf(timeoutMessage)
	}
}

const dummyClientVerificationPayload = `
{
	"status": 0,
	"payload": ""
}`

func runServer(t *testing.T, runConfig *runServerConfig) {

	// create a server

	serverConfigJSON, _, encodedServerEntry, err := GenerateConfig(
		&GenerateConfigParams{
			ServerIPAddress:      serverIPAddress,
			EnableSSHAPIRequests: runConfig.enableSSHAPIRequests,
			WebServerPort:        8000,
			TunnelProtocolPorts:  map[string]int{runConfig.tunnelProtocol: 4000},
		})
	if err != nil {
		t.Fatalf("error generating server config: %s", err)
	}

	// customize server config

	// Pave psinet with random values to test handshake homepages.
	psinetFilename := filepath.Join(testDataDirName, "psinet.json")
	sponsorID, expectedHomepageURL := pavePsinetDatabaseFile(
		t, runConfig.doDefaultSessionID, psinetFilename)

	// Pave OSL config for SLOK testing
	oslConfigFilename := filepath.Join(testDataDirName, "osl_config.json")
	propagationChannelID := paveOSLConfigFile(t, oslConfigFilename)

	// Pave traffic rules file which exercises handshake parameter filtering. Client
	// must handshake with specified sponsor ID in order to allow ports for tunneled
	// requests.
	trafficRulesFilename := filepath.Join(testDataDirName, "traffic_rules.json")
	paveTrafficRulesFile(t, trafficRulesFilename, propagationChannelID, runConfig.denyTrafficRules)

	var serverConfig map[string]interface{}
	json.Unmarshal(serverConfigJSON, &serverConfig)
	serverConfig["GeoIPDatabaseFilename"] = ""
	serverConfig["PsinetDatabaseFilename"] = psinetFilename
	serverConfig["TrafficRulesFilename"] = trafficRulesFilename
	serverConfig["OSLConfigFilename"] = oslConfigFilename
	serverConfig["LogFilename"] = filepath.Join(testDataDirName, "psiphond.log")
	serverConfig["LogLevel"] = "debug"

	// Set this parameter so at least the semaphore functions are called.
	// TODO: test that the concurrency limit is correctly enforced.
	serverConfig["MaxConcurrentSSHHandshakes"] = 1

	// Exercise this option.
	serverConfig["PeriodicGarbageCollectionSeconds"] = 1

	serverConfigJSON, _ = json.Marshal(serverConfig)

	// run server

	serverWaitGroup := new(sync.WaitGroup)
	serverWaitGroup.Add(1)
	go func() {
		defer serverWaitGroup.Done()
		err := RunServices(serverConfigJSON)
		if err != nil {
			// TODO: wrong goroutine for t.FatalNow()
			t.Fatalf("error running server: %s", err)
		}
	}()
	defer func() {

		// Test: orderly server shutdown

		p, _ := os.FindProcess(os.Getpid())
		p.Signal(os.Interrupt)

		shutdownTimeout := time.NewTimer(5 * time.Second)

		shutdownOk := make(chan struct{}, 1)
		go func() {
			serverWaitGroup.Wait()
			shutdownOk <- *new(struct{})
		}()

		select {
		case <-shutdownOk:
		case <-shutdownTimeout.C:
			t.Fatalf("server shutdown timeout exceeded")
		}
	}()

	// TODO: monitor logs for more robust wait-until-loaded
	time.Sleep(1 * time.Second)

	// Test: hot reload (of psinet and traffic rules)

	if runConfig.doHotReload {

		// Pave new config files with different random values.
		sponsorID, expectedHomepageURL = pavePsinetDatabaseFile(
			t, runConfig.doDefaultSessionID, psinetFilename)

		propagationChannelID = paveOSLConfigFile(t, oslConfigFilename)

		paveTrafficRulesFile(
			t, trafficRulesFilename, propagationChannelID, runConfig.denyTrafficRules)

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

	// connect to server with client

	// TODO: currently, TargetServerEntry only works with one tunnel
	numTunnels := 1
	localSOCKSProxyPort := 1081
	localHTTPProxyPort := 8081
	establishTunnelPausePeriodSeconds := 1

	// Note: calling LoadConfig ensures all *int config fields are initialized
	clientConfigJSON := `
    {
        "ClientPlatform" : "Windows",
        "ClientVersion" : "0",
        "SponsorId" : "0",
        "PropagationChannelId" : "0",
        "DisableRemoteServerListFetcher" : true,
        "UseIndistinguishableTLS" : true
    }`
	clientConfig, _ := psiphon.LoadConfig([]byte(clientConfigJSON))

	if !runConfig.doDefaultSessionID {
		clientConfig.SponsorId = sponsorID
	}
	clientConfig.PropagationChannelId = propagationChannelID
	clientConfig.ConnectionWorkerPoolSize = numTunnels
	clientConfig.TunnelPoolSize = numTunnels
	clientConfig.EstablishTunnelPausePeriodSeconds = &establishTunnelPausePeriodSeconds
	clientConfig.TargetServerEntry = string(encodedServerEntry)
	clientConfig.TunnelProtocol = runConfig.tunnelProtocol
	clientConfig.LocalSocksProxyPort = localSOCKSProxyPort
	clientConfig.LocalHttpProxyPort = localHTTPProxyPort
	clientConfig.EmitSLOKs = true

	if runConfig.doClientVerification {
		clientConfig.ClientPlatform = "Android"
	}

	clientConfig.DataStoreDirectory = testDataDirName
	err = psiphon.InitDataStore(clientConfig)
	if err != nil {
		t.Fatalf("error initializing client datastore: %s", err)
	}
	psiphon.DeleteSLOKs()

	controller, err := psiphon.NewController(clientConfig)
	if err != nil {
		t.Fatalf("error creating client controller: %s", err)
	}

	tunnelsEstablished := make(chan struct{}, 1)
	homepageReceived := make(chan struct{}, 1)
	slokSeeded := make(chan struct{}, 1)
	verificationRequired := make(chan struct{}, 1)
	verificationCompleted := make(chan struct{}, 1)

	psiphon.SetNoticeWriter(psiphon.NewNoticeReceiver(
		func(notice []byte) {

			//fmt.Printf("%s\n", string(notice))

			noticeType, payload, err := psiphon.GetNotice(notice)
			if err != nil {
				return
			}

			switch noticeType {
			case "Tunnels":
				// Do not set verification payload until tunnel is
				// established. Otherwise will silently take no action.
				controller.SetClientVerificationPayloadForActiveTunnels("")
				count := int(payload["count"].(float64))
				if count >= numTunnels {
					sendNotificationReceived(tunnelsEstablished)
				}
			case "Homepage":
				homepageURL := payload["url"].(string)
				if homepageURL != expectedHomepageURL {
					// TODO: wrong goroutine for t.FatalNow()
					t.Fatalf("unexpected homepage: %s", homepageURL)
				}
				sendNotificationReceived(homepageReceived)
			case "SLOKSeeded":
				sendNotificationReceived(slokSeeded)
			case "ClientVerificationRequired":
				sendNotificationReceived(verificationRequired)
				controller.SetClientVerificationPayloadForActiveTunnels(dummyClientVerificationPayload)
			case "NoticeClientVerificationRequestCompleted":
				sendNotificationReceived(verificationCompleted)
			}
		}))

	ctx, cancelFunc := context.WithCancel(context.Background())

	controllerWaitGroup := new(sync.WaitGroup)

	controllerWaitGroup.Add(1)
	go func() {
		defer controllerWaitGroup.Done()
		controller.Run(ctx)
	}()

	defer func() {
		cancelFunc()

		shutdownTimeout := time.NewTimer(20 * time.Second)

		shutdownOk := make(chan struct{}, 1)
		go func() {
			controllerWaitGroup.Wait()
			shutdownOk <- *new(struct{})
		}()

		select {
		case <-shutdownOk:
		case <-shutdownTimeout.C:
			t.Fatalf("controller shutdown timeout exceeded")
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

	waitOnNotification(t, tunnelsEstablished, timeoutSignal, "tunnel establish timeout exceeded")
	waitOnNotification(t, homepageReceived, timeoutSignal, "homepage received timeout exceeded")

	if runConfig.doClientVerification {
		waitOnNotification(t, verificationRequired, timeoutSignal, "verification required timeout exceeded")
		waitOnNotification(t, verificationCompleted, timeoutSignal, "verification completed timeout exceeded")
	}

	if runConfig.doTunneledWebRequest {

		// Test: tunneled web site fetch

		err = makeTunneledWebRequest(
			t, localHTTPProxyPort, mockWebServerURL, mockWebServerExpectedResponse)

		if err == nil {
			if runConfig.denyTrafficRules {
				t.Fatalf("unexpected tunneled web request success")
			}
		} else {
			if !runConfig.denyTrafficRules {
				t.Fatalf("tunneled web request failed: %s", err)
			}
		}
	}

	if runConfig.doTunneledNTPRequest {

		// Test: tunneled UDP packets

		udpgwServerAddress := serverConfig["UDPInterceptUdpgwServerAddress"].(string)

		err = makeTunneledNTPRequest(t, localSOCKSProxyPort, udpgwServerAddress)

		if err == nil {
			if runConfig.denyTrafficRules {
				t.Fatalf("unexpected tunneled NTP request success")
			}
		} else {
			if !runConfig.denyTrafficRules {
				t.Fatalf("tunneled NTP request failed: %s", err)
			}
		}
	}

	// Test: await SLOK payload

	if !runConfig.denyTrafficRules {

		time.Sleep(1 * time.Second)
		waitOnNotification(t, slokSeeded, timeoutSignal, "SLOK seeded timeout exceeded")

		numSLOKs := psiphon.CountSLOKs()
		if numSLOKs != expectedNumSLOKs {
			t.Fatalf("unexpected number of SLOKs: %d", numSLOKs)
		}
	}
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
	t *testing.T, useDefaultSponsorID bool, psinetFilename string) (string, string) {

	sponsorID, _ := common.MakeRandomStringHex(8)

	fakeDomain, _ := common.MakeRandomStringHex(4)
	fakePath, _ := common.MakeRandomStringHex(4)
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
        }
    }
	`

	defaultSponsorID := ""
	if useDefaultSponsorID {
		defaultSponsorID = sponsorID
	}

	psinetJSON := fmt.Sprintf(
		psinetJSONFormat, defaultSponsorID, sponsorID, expectedHomepageURL)

	err := ioutil.WriteFile(psinetFilename, []byte(psinetJSON), 0600)
	if err != nil {
		t.Fatalf("error paving psinet database file: %s", err)
	}

	return sponsorID, expectedHomepageURL
}

func paveTrafficRulesFile(
	t *testing.T, trafficRulesFilename, propagationChannelID string, deny bool) {

	allowTCPPorts := fmt.Sprintf("%d", mockWebServerPort)
	allowUDPPorts := "53, 123"

	if deny {
		allowTCPPorts = "0"
		allowUDPPorts = "0"
	}

	trafficRulesJSONFormat := `
    {
        "DefaultRules" :  {
            "RateLimits" : {
                "ReadBytesPerSecond": 16384,
                "WriteBytesPerSecond": 16384
            },
            "AllowTCPPorts" : [0],
            "AllowUDPPorts" : [0]
        },
        "FilteredRules" : [
            {
                "Filter" : {
                    "HandshakeParameters" : {
                        "propagation_channel_id" : ["%s"]
                    }
                },
                "Rules" : {
                    "RateLimits" : {
                        "ReadUnthrottledBytes": 132352,
                        "WriteUnthrottledBytes": 132352
                    },
                    "AllowTCPPorts" : [%s],
                    "AllowUDPPorts" : [%s]
                }
            }
        ]
    }
    `

	trafficRulesJSON := fmt.Sprintf(
		trafficRulesJSONFormat, propagationChannelID, allowTCPPorts, allowUDPPorts)

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

	propagationChannelID, _ := common.MakeRandomStringHex(8)

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
