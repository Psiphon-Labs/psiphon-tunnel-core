// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js
// +build !js

package ice

import (
	"net"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/pion/transport/v2/stdnet"
	"github.com/pion/transport/v2/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func getLocalIPAddress(t *testing.T, networkType NetworkType) net.IP {
	net, err := stdnet.NewNet()
	require.NoError(t, err)
	localIPs, err := localInterfaces(net, nil, nil, []NetworkType{networkType}, false)
	require.NoError(t, err)
	require.NotEmpty(t, localIPs)
	return localIPs[0]
}

func ipv6Available(t *testing.T) bool {
	net, err := stdnet.NewNet()
	require.NoError(t, err)
	localIPs, err := localInterfaces(net, nil, nil, []NetworkType{NetworkTypeTCP6}, false)
	require.NoError(t, err)
	return len(localIPs) > 0
}

func TestActiveTCP(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()

	lim := test.TimeOut(time.Second * 5)
	defer lim.Stop()

	const listenPort = 7686
	type testCase struct {
		name                    string
		networkTypes            []NetworkType
		listenIPAddress         net.IP
		selectedPairNetworkType string
	}

	testCases := []testCase{
		{
			name:                    "TCP4 connection",
			networkTypes:            []NetworkType{NetworkTypeTCP4},
			listenIPAddress:         getLocalIPAddress(t, NetworkTypeTCP4),
			selectedPairNetworkType: tcp,
		},
		{
			name:                    "UDP is preferred over TCP4", // This fails some time
			networkTypes:            supportedNetworkTypes(),
			listenIPAddress:         getLocalIPAddress(t, NetworkTypeTCP4),
			selectedPairNetworkType: udp,
		},
	}

	if ipv6Available(t) {
		testCases = append(testCases,
			testCase{
				name:                    "TCP6 connection",
				networkTypes:            []NetworkType{NetworkTypeTCP6},
				listenIPAddress:         getLocalIPAddress(t, NetworkTypeTCP6),
				selectedPairNetworkType: tcp,
			},
			testCase{
				name:                    "UDP is preferred over TCP6", // This fails some time
				networkTypes:            supportedNetworkTypes(),
				listenIPAddress:         getLocalIPAddress(t, NetworkTypeTCP6),
				selectedPairNetworkType: udp,
			},
		)
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			r := require.New(t)

			listener, err := net.ListenTCP("tcp", &net.TCPAddr{
				IP:   testCase.listenIPAddress,
				Port: listenPort,
			})
			r.NoError(err)
			defer func() {
				_ = listener.Close()
			}()

			loggerFactory := logging.NewDefaultLoggerFactory()

			tcpMux := NewTCPMuxDefault(TCPMuxParams{
				Listener:       listener,
				Logger:         loggerFactory.NewLogger("passive-ice-tcp-mux"),
				ReadBufferSize: 20,
			})

			defer func() {
				_ = tcpMux.Close()
			}()

			r.NotNil(tcpMux.LocalAddr(), "tcpMux.LocalAddr() is nil")

			hostAcceptanceMinWait := 100 * time.Millisecond
			passiveAgent, err := NewAgent(&AgentConfig{
				TCPMux:                tcpMux,
				CandidateTypes:        []CandidateType{CandidateTypeHost},
				NetworkTypes:          testCase.networkTypes,
				LoggerFactory:         loggerFactory,
				IncludeLoopback:       true,
				HostAcceptanceMinWait: &hostAcceptanceMinWait,
			})
			r.NoError(err)
			r.NotNil(passiveAgent)

			activeAgent, err := NewAgent(&AgentConfig{
				CandidateTypes:        []CandidateType{CandidateTypeHost},
				NetworkTypes:          testCase.networkTypes,
				LoggerFactory:         loggerFactory,
				HostAcceptanceMinWait: &hostAcceptanceMinWait,
			})
			r.NoError(err)
			r.NotNil(activeAgent)

			passiveAgentConn, activeAgenConn := connect(passiveAgent, activeAgent)
			r.NotNil(passiveAgentConn)
			r.NotNil(activeAgenConn)

			pair := passiveAgent.getSelectedPair()
			r.NotNil(pair)
			r.Equal(testCase.selectedPairNetworkType, pair.Local.NetworkType().NetworkShort())

			foo := []byte("foo")
			_, err = passiveAgentConn.Write(foo)
			r.NoError(err)

			buffer := make([]byte, 1024)
			n, err := activeAgenConn.Read(buffer)
			r.NoError(err)
			r.Equal(foo, buffer[:n])

			bar := []byte("bar")
			_, err = activeAgenConn.Write(bar)
			r.NoError(err)

			n, err = passiveAgentConn.Read(buffer)
			r.NoError(err)
			r.Equal(bar, buffer[:n])

			r.NoError(activeAgenConn.Close())
			r.NoError(passiveAgentConn.Close())
		})
	}
}

// Assert that Active TCP connectivity isn't established inside
// the main thread of the Agent
func TestActiveTCP_NonBlocking(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()

	lim := test.TimeOut(time.Second * 5)
	defer lim.Stop()

	cfg := &AgentConfig{
		NetworkTypes: supportedNetworkTypes(),
	}

	aAgent, err := NewAgent(cfg)
	if err != nil {
		t.Error(err)
	}

	bAgent, err := NewAgent(cfg)
	if err != nil {
		t.Error(err)
	}

	isConnected := make(chan interface{})
	err = aAgent.OnConnectionStateChange(func(c ConnectionState) {
		if c == ConnectionStateConnected {
			close(isConnected)
		}
	})
	if err != nil {
		t.Error(err)
	}

	// Add a invalid ice-tcp candidate to each
	invalidCandidate, err := UnmarshalCandidate("1052353102 1 tcp 1675624447 192.0.2.1 8080 typ host tcptype passive")
	if err != nil {
		t.Fatal(err)
	}
	assert.NoError(t, aAgent.AddRemoteCandidate(invalidCandidate))
	assert.NoError(t, bAgent.AddRemoteCandidate(invalidCandidate))

	connect(aAgent, bAgent)

	<-isConnected
	assert.NoError(t, aAgent.Close())
	assert.NoError(t, bAgent.Close())
}
