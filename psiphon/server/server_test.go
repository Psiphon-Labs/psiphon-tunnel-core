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
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"golang.org/x/net/proxy"
)

func TestMain(m *testing.M) {
	flag.Parse()
	os.Remove(psiphon.DATA_STORE_FILENAME)
	psiphon.SetEmitDiagnosticNotices(true)
	os.Exit(m.Run())
}

// Note: not testing fronting meek protocols, which client is
// hard-wired to except running on privileged ports 80 and 443.

func TestSSH(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "SSH",
			enableSSHAPIRequests: true,
			doHotReload:          false,
			denyTrafficRules:     false,
		})
}

func TestOSSH(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "OSSH",
			enableSSHAPIRequests: true,
			doHotReload:          false,
			denyTrafficRules:     false,
		})
}

func TestUnfrontedMeek(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "UNFRONTED-MEEK-OSSH",
			enableSSHAPIRequests: true,
			doHotReload:          false,
			denyTrafficRules:     false,
		})
}

func TestUnfrontedMeekHTTPS(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "UNFRONTED-MEEK-HTTPS-OSSH",
			enableSSHAPIRequests: true,
			doHotReload:          false,
			denyTrafficRules:     false,
		})
}

func TestWebTransportAPIRequests(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "OSSH",
			enableSSHAPIRequests: false,
			doHotReload:          false,
			denyTrafficRules:     false,
		})
}

func TestHotReload(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "OSSH",
			enableSSHAPIRequests: true,
			doHotReload:          true,
			denyTrafficRules:     false,
		})
}

func TestDenyTrafficRules(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "OSSH",
			enableSSHAPIRequests: true,
			doHotReload:          true,
			denyTrafficRules:     true,
		})
}

type runServerConfig struct {
	tunnelProtocol       string
	enableSSHAPIRequests bool
	doHotReload          bool
	denyTrafficRules     bool
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

	var err error
	serverIPaddress := ""
	for _, interfaceName := range []string{"eth0", "en0"} {
		serverIPaddress, err = psiphon.GetInterfaceIPAddress(interfaceName)
		if err == nil {
			break
		}
	}
	if err != nil {
		t.Fatalf("error getting server IP address: %s", err)
	}

	serverConfigJSON, _, encodedServerEntry, err := GenerateConfig(
		&GenerateConfigParams{
			ServerIPAddress:      serverIPaddress,
			EnableSSHAPIRequests: runConfig.enableSSHAPIRequests,
			WebServerPort:        8000,
			TunnelProtocolPorts:  map[string]int{runConfig.tunnelProtocol: 4000},
		})
	if err != nil {
		t.Fatalf("error generating server config: %s", err)
	}

	// customize server config

	// Pave psinet with random values to test handshake homepages.
	psinetFilename := "psinet.json"
	sponsorID, expectedHomepageURL := pavePsinetDatabaseFile(t, psinetFilename)

	// Pave traffic rules file which exercises handshake parameter filtering. Client
	// must handshake with specified sponsor ID in order to allow ports for tunneled
	// requests.
	trafficRulesFilename := "traffic_rules.json"
	paveTrafficRulesFile(t, trafficRulesFilename, sponsorID, runConfig.denyTrafficRules)

	var serverConfig interface{}
	json.Unmarshal(serverConfigJSON, &serverConfig)
	serverConfig.(map[string]interface{})["GeoIPDatabaseFilename"] = ""
	serverConfig.(map[string]interface{})["PsinetDatabaseFilename"] = psinetFilename
	serverConfig.(map[string]interface{})["TrafficRulesFilename"] = trafficRulesFilename
	serverConfig.(map[string]interface{})["LogLevel"] = "debug"

	// 1 second is the minimum period; should be small enough to emit a log during the
	// test run, but not guaranteed
	serverConfig.(map[string]interface{})["LoadMonitorPeriodSeconds"] = 1

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

	// Test: hot reload (of psinet and traffic rules)

	if runConfig.doHotReload {
		// TODO: monitor logs for more robust wait-until-loaded
		time.Sleep(1 * time.Second)

		// Pave a new psinet and traffic rules with different random values.
		sponsorID, expectedHomepageURL = pavePsinetDatabaseFile(t, psinetFilename)
		paveTrafficRulesFile(t, trafficRulesFilename, sponsorID, runConfig.denyTrafficRules)

		p, _ := os.FindProcess(os.Getpid())
		p.Signal(syscall.SIGUSR1)

		// TODO: monitor logs for more robust wait-until-reloaded
		time.Sleep(1 * time.Second)

		// After reloading psinet, the new sponsorID/expectedHomepageURL
		// should be active, as tested in the client "Homepage" notice
		// handler below.
	}

	// connect to server with client

	// TODO: currently, TargetServerEntry only works with one tunnel
	numTunnels := 1
	localSOCKSProxyPort := 1081
	localHTTPProxyPort := 8081
	establishTunnelPausePeriodSeconds := 1

	// Note: calling LoadConfig ensures all *int config fields are initialized
	clientConfigJSON := `
    {
        "ClientPlatform" : "Android",
        "ClientVersion" : "0",
        "SponsorId" : "0",
        "PropagationChannelId" : "0"
    }`
	clientConfig, _ := psiphon.LoadConfig([]byte(clientConfigJSON))

	clientConfig.SponsorId = sponsorID
	clientConfig.ConnectionWorkerPoolSize = numTunnels
	clientConfig.TunnelPoolSize = numTunnels
	clientConfig.DisableRemoteServerListFetcher = true
	clientConfig.EstablishTunnelPausePeriodSeconds = &establishTunnelPausePeriodSeconds
	clientConfig.TargetServerEntry = string(encodedServerEntry)
	clientConfig.TunnelProtocol = runConfig.tunnelProtocol
	clientConfig.LocalSocksProxyPort = localSOCKSProxyPort
	clientConfig.LocalHttpProxyPort = localHTTPProxyPort

	err = psiphon.InitDataStore(clientConfig)
	if err != nil {
		t.Fatalf("error initializing client datastore: %s", err)
	}

	controller, err := psiphon.NewController(clientConfig)
	if err != nil {
		t.Fatalf("error creating client controller: %s", err)
	}

	tunnelsEstablished := make(chan struct{}, 1)
	homepageReceived := make(chan struct{}, 1)
	verificationRequired := make(chan struct{}, 1)
	verificationCompleted := make(chan struct{}, 1)

	psiphon.SetNoticeOutput(psiphon.NewNoticeReceiver(
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
			case "ClientVerificationRequired":
				sendNotificationReceived(verificationRequired)
				controller.SetClientVerificationPayloadForActiveTunnels(dummyClientVerificationPayload)
			case "NoticeClientVerificationRequestCompleted":
				sendNotificationReceived(verificationCompleted)
			}
		}))

	controllerShutdownBroadcast := make(chan struct{})
	controllerWaitGroup := new(sync.WaitGroup)
	controllerWaitGroup.Add(1)
	go func() {
		defer controllerWaitGroup.Done()
		controller.Run(controllerShutdownBroadcast)
	}()
	defer func() {
		close(controllerShutdownBroadcast)

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
	waitOnNotification(t, verificationRequired, timeoutSignal, "verification required timeout exceeded")
	waitOnNotification(t, verificationCompleted, timeoutSignal, "verification completed timeout exceeded")

	// Test: tunneled web site fetch

	err = makeTunneledWebRequest(t, localHTTPProxyPort)

	if err == nil {
		if runConfig.denyTrafficRules {
			t.Fatalf("unexpected tunneled web request success")
		}
	} else {
		if !runConfig.denyTrafficRules {
			t.Fatalf("tunneled web request failed: %s", err)
		}
	}

	// Test: tunneled UDP packets

	udpgwServerAddress := serverConfig.(map[string]interface{})["UDPInterceptUdpgwServerAddress"].(string)

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

func makeTunneledWebRequest(t *testing.T, localHTTPProxyPort int) error {

	testUrl := "https://psiphon.ca"
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

	response, err := httpClient.Get(testUrl)
	if err != nil {
		return fmt.Errorf("error sending proxied HTTP request: %s", err)
	}

	_, err = ioutil.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("error reading proxied HTTP response: %s", err)
	}
	response.Body.Close()

	return nil
}

func makeTunneledNTPRequest(t *testing.T, localSOCKSProxyPort int, udpgwServerAddress string) error {

	testHostname := "pool.ntp.org"
	timeout := 10 * time.Second

	localUDPProxyAddress, err := net.ResolveUDPAddr("udp", "127.0.0.1:7301")
	if err != nil {
		t.Fatalf("ResolveUDPAddr failed: %s", err)
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
			buffer[udpgwPreambleSize:len(buffer)])
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

		updgwProtocolMessage, err := readUdpgwMessage(socksTCPConn, buffer)
		if err != nil {
			t.Logf("readUdpgwMessage for %s failed: %s", destination, err)
			return
		}

		_, err = serverUDPConn.WriteToUDP(updgwProtocolMessage.packet, clientAddr)
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

	go localUDPProxy(addrs[0][len(addrs[0])-4:], 123, nil)
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

	return nil
}

func pavePsinetDatabaseFile(t *testing.T, psinetFilename string) (string, string) {

	sponsorID, _ := common.MakeRandomStringHex(8)

	fakeDomain, _ := common.MakeRandomStringHex(4)
	fakePath, _ := common.MakeRandomStringHex(4)
	expectedHomepageURL := fmt.Sprintf("https://%s.com/%s", fakeDomain, fakePath)

	psinetJSONFormat := `
    {
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
	psinetJSON := fmt.Sprintf(psinetJSONFormat, sponsorID, expectedHomepageURL)

	err := ioutil.WriteFile(psinetFilename, []byte(psinetJSON), 0600)
	if err != nil {
		t.Fatalf("error paving psinet database file: %s", err)
	}

	return sponsorID, expectedHomepageURL
}

func paveTrafficRulesFile(t *testing.T, trafficRulesFilename, sponsorID string, deny bool) {

	allowTCPPorts := "443"
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
                        "sponsor_id" : ["%s"]
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
		trafficRulesJSONFormat, sponsorID, allowTCPPorts, allowUDPPorts)

	err := ioutil.WriteFile(trafficRulesFilename, []byte(trafficRulesJSON), 0600)
	if err != nil {
		t.Fatalf("error paving traffic rules file: %s", err)
	}
}
