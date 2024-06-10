// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js
// +build !js

package ice

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/dtls/v2"
	"github.com/pion/dtls/v2/pkg/crypto/selfsign"
	"github.com/pion/logging"
	"github.com/pion/stun"
	"github.com/pion/transport/v2/test"
	"github.com/pion/turn/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/proxy"
)

func TestListenUDP(t *testing.T) {
	a, err := NewAgent(&AgentConfig{})
	assert.NoError(t, err)

	localIPs, err := localInterfaces(a.net, a.interfaceFilter, a.ipFilter, []NetworkType{NetworkTypeUDP4}, false)
	assert.NotEqual(t, len(localIPs), 0, "localInterfaces found no interfaces, unable to test")
	assert.NoError(t, err)

	ip := localIPs[0]

	conn, err := listenUDPInPortRange(a.net, a.log, 0, 0, udp, &net.UDPAddr{IP: ip, Port: 0})
	assert.NoError(t, err, "listenUDP error with no port restriction")
	assert.NotNil(t, conn, "listenUDP error with no port restriction return a nil conn")

	_, err = listenUDPInPortRange(a.net, a.log, 4999, 5000, udp, &net.UDPAddr{IP: ip, Port: 0})
	assert.Equal(t, err, ErrPort, "listenUDP with invalid port range did not return ErrPort")

	conn, err = listenUDPInPortRange(a.net, a.log, 5000, 5000, udp, &net.UDPAddr{IP: ip, Port: 0})
	assert.NoError(t, err, "listenUDP error with no port restriction")
	assert.NotNil(t, conn, "listenUDP error with no port restriction return a nil conn")

	_, port, err := net.SplitHostPort(conn.LocalAddr().String())
	assert.NoError(t, err)
	assert.Equal(t, port, "5000", "listenUDP with port restriction of 5000 listened on incorrect port")

	portMin := 5100
	portMax := 5109
	total := portMax - portMin + 1
	result := make([]int, 0, total)
	portRange := make([]int, 0, total)
	for i := 0; i < total; i++ {
		conn, err = listenUDPInPortRange(a.net, a.log, portMax, portMin, udp, &net.UDPAddr{IP: ip, Port: 0})
		assert.NoError(t, err, "listenUDP error with no port restriction")
		assert.NotNil(t, conn, "listenUDP error with no port restriction return a nil conn")

		_, port, err = net.SplitHostPort(conn.LocalAddr().String())
		if err != nil {
			t.Fatal(err)
		}
		p, _ := strconv.Atoi(port)
		if p < portMin || p > portMax {
			t.Fatalf("listenUDP with port restriction [%d, %d] listened on incorrect port (%s)", portMin, portMax, port)
		}
		result = append(result, p)
		portRange = append(portRange, portMin+i)
	}
	if sort.IntsAreSorted(result) {
		t.Fatalf("listenUDP with port restriction [%d, %d], ports result should be random", portMin, portMax)
	}
	sort.Ints(result)
	if !reflect.DeepEqual(result, portRange) {
		t.Fatalf("listenUDP with port restriction [%d, %d], got:%v, want:%v", portMin, portMax, result, portRange)
	}
	_, err = listenUDPInPortRange(a.net, a.log, portMax, portMin, udp, &net.UDPAddr{IP: ip, Port: 0})
	assert.Equal(t, err, ErrPort, "listenUDP with port restriction [%d, %d], did not return ErrPort", portMin, portMax)

	assert.NoError(t, a.Close())
}

func TestGatherConcurrency(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()

	lim := test.TimeOut(time.Second * 30)
	defer lim.Stop()

	a, err := NewAgent(&AgentConfig{
		NetworkTypes:    []NetworkType{NetworkTypeUDP4, NetworkTypeUDP6},
		IncludeLoopback: true,
	})
	assert.NoError(t, err)

	candidateGathered, candidateGatheredFunc := context.WithCancel(context.Background())
	assert.NoError(t, a.OnCandidate(func(c Candidate) {
		candidateGatheredFunc()
	}))

	// Testing for panic
	for i := 0; i < 10; i++ {
		_ = a.GatherCandidates()
	}

	<-candidateGathered.Done()

	assert.NoError(t, a.Close())
}

func TestLoopbackCandidate(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()

	lim := test.TimeOut(time.Second * 30)
	defer lim.Stop()
	type testCase struct {
		name        string
		agentConfig *AgentConfig
		loExpected  bool
	}
	mux, err := NewMultiUDPMuxFromPort(12500)
	assert.NoError(t, err)
	muxWithLo, errlo := NewMultiUDPMuxFromPort(12501, UDPMuxFromPortWithLoopback())
	assert.NoError(t, errlo)
	testCases := []testCase{
		{
			name: "mux should not have loopback candidate",
			agentConfig: &AgentConfig{
				NetworkTypes: []NetworkType{NetworkTypeUDP4, NetworkTypeUDP6},
				UDPMux:       mux,
			},
			loExpected: false,
		},
		{
			name: "mux with loopback should not have loopback candidate",
			agentConfig: &AgentConfig{
				NetworkTypes: []NetworkType{NetworkTypeUDP4, NetworkTypeUDP6},
				UDPMux:       muxWithLo,
			},
			loExpected: true,
		},
		{
			name: "includeloopback enabled",
			agentConfig: &AgentConfig{
				NetworkTypes:    []NetworkType{NetworkTypeUDP4, NetworkTypeUDP6},
				IncludeLoopback: true,
			},
			loExpected: true,
		},
		{
			name: "includeloopback disabled",
			agentConfig: &AgentConfig{
				NetworkTypes:    []NetworkType{NetworkTypeUDP4, NetworkTypeUDP6},
				IncludeLoopback: false,
			},
			loExpected: false,
		},
	}

	for _, tc := range testCases {
		tcase := tc
		t.Run(tcase.name, func(t *testing.T) {
			a, err := NewAgent(tc.agentConfig)
			assert.NoError(t, err)

			candidateGathered, candidateGatheredFunc := context.WithCancel(context.Background())
			var loopback int32
			assert.NoError(t, a.OnCandidate(func(c Candidate) {
				if c != nil {
					if net.ParseIP(c.Address()).IsLoopback() {
						atomic.StoreInt32(&loopback, 1)
					}
				} else {
					candidateGatheredFunc()
					return
				}
				t.Log(c.NetworkType(), c.Priority(), c)
			}))
			assert.NoError(t, a.GatherCandidates())

			<-candidateGathered.Done()

			assert.NoError(t, a.Close())
			assert.Equal(t, tcase.loExpected, atomic.LoadInt32(&loopback) == 1)
		})
	}

	assert.NoError(t, mux.Close())
	assert.NoError(t, muxWithLo.Close())
}

// Assert that STUN gathering is done concurrently
func TestSTUNConcurrency(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()

	lim := test.TimeOut(time.Second * 30)
	defer lim.Stop()

	serverPort := randomPort(t)
	serverListener, err := net.ListenPacket("udp4", "127.0.0.1:"+strconv.Itoa(serverPort))
	assert.NoError(t, err)

	server, err := turn.NewServer(turn.ServerConfig{
		Realm:       "pion.ly",
		AuthHandler: optimisticAuthHandler,
		PacketConnConfigs: []turn.PacketConnConfig{
			{
				PacketConn:            serverListener,
				RelayAddressGenerator: &turn.RelayAddressGeneratorNone{Address: "127.0.0.1"},
			},
		},
	})
	assert.NoError(t, err)

	urls := []*stun.URI{}
	for i := 0; i <= 10; i++ {
		urls = append(urls, &stun.URI{
			Scheme: stun.SchemeTypeSTUN,
			Host:   "127.0.0.1",
			Port:   serverPort + 1,
		})
	}
	urls = append(urls, &stun.URI{
		Scheme: stun.SchemeTypeSTUN,
		Host:   "127.0.0.1",
		Port:   serverPort,
	})

	listener, err := net.ListenTCP("tcp", &net.TCPAddr{
		IP: net.IP{127, 0, 0, 1},
	})
	require.NoError(t, err)
	defer func() {
		_ = listener.Close()
	}()

	a, err := NewAgent(&AgentConfig{
		NetworkTypes:   supportedNetworkTypes(),
		Urls:           urls,
		CandidateTypes: []CandidateType{CandidateTypeHost, CandidateTypeServerReflexive},
		TCPMux: NewTCPMuxDefault(
			TCPMuxParams{
				Listener:       listener,
				Logger:         logging.NewDefaultLoggerFactory().NewLogger("ice"),
				ReadBufferSize: 8,
			},
		),
	})
	assert.NoError(t, err)

	candidateGathered, candidateGatheredFunc := context.WithCancel(context.Background())
	assert.NoError(t, a.OnCandidate(func(c Candidate) {
		if c == nil {
			candidateGatheredFunc()
			return
		}
		t.Log(c.NetworkType(), c.Priority(), c)
	}))
	assert.NoError(t, a.GatherCandidates())

	<-candidateGathered.Done()

	assert.NoError(t, a.Close())
	assert.NoError(t, server.Close())
}

// Assert that TURN gathering is done concurrently
func TestTURNConcurrency(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()

	lim := test.TimeOut(time.Second * 30)
	defer lim.Stop()

	runTest := func(protocol stun.ProtoType, scheme stun.SchemeType, packetConn net.PacketConn, listener net.Listener, serverPort int) {
		packetConnConfigs := []turn.PacketConnConfig{}
		if packetConn != nil {
			packetConnConfigs = append(packetConnConfigs, turn.PacketConnConfig{
				PacketConn:            packetConn,
				RelayAddressGenerator: &turn.RelayAddressGeneratorNone{Address: "127.0.0.1"},
			})
		}

		listenerConfigs := []turn.ListenerConfig{}
		if listener != nil {
			listenerConfigs = append(listenerConfigs, turn.ListenerConfig{
				Listener:              listener,
				RelayAddressGenerator: &turn.RelayAddressGeneratorNone{Address: "127.0.0.1"},
			})
		}

		server, err := turn.NewServer(turn.ServerConfig{
			Realm:             "pion.ly",
			AuthHandler:       optimisticAuthHandler,
			PacketConnConfigs: packetConnConfigs,
			ListenerConfigs:   listenerConfigs,
		})
		assert.NoError(t, err)

		urls := []*stun.URI{}
		for i := 0; i <= 10; i++ {
			urls = append(urls, &stun.URI{
				Scheme:   scheme,
				Host:     "127.0.0.1",
				Username: "username",
				Password: "password",
				Proto:    protocol,
				Port:     serverPort + 1 + i,
			})
		}
		urls = append(urls, &stun.URI{
			Scheme:   scheme,
			Host:     "127.0.0.1",
			Username: "username",
			Password: "password",
			Proto:    protocol,
			Port:     serverPort,
		})

		a, err := NewAgent(&AgentConfig{
			CandidateTypes:     []CandidateType{CandidateTypeRelay},
			InsecureSkipVerify: true,
			NetworkTypes:       supportedNetworkTypes(),
			Urls:               urls,
		})
		assert.NoError(t, err)

		candidateGathered, candidateGatheredFunc := context.WithCancel(context.Background())
		assert.NoError(t, a.OnCandidate(func(c Candidate) {
			if c != nil {
				candidateGatheredFunc()
			}
		}))
		assert.NoError(t, a.GatherCandidates())

		<-candidateGathered.Done()

		assert.NoError(t, a.Close())
		assert.NoError(t, server.Close())
	}

	t.Run("UDP Relay", func(t *testing.T) {
		serverPort := randomPort(t)
		serverListener, err := net.ListenPacket("udp", "127.0.0.1:"+strconv.Itoa(serverPort))
		assert.NoError(t, err)

		runTest(stun.ProtoTypeUDP, stun.SchemeTypeTURN, serverListener, nil, serverPort)
	})

	t.Run("TCP Relay", func(t *testing.T) {
		serverPort := randomPort(t)
		serverListener, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(serverPort))
		assert.NoError(t, err)

		runTest(stun.ProtoTypeTCP, stun.SchemeTypeTURN, nil, serverListener, serverPort)
	})

	t.Run("TLS Relay", func(t *testing.T) {
		certificate, genErr := selfsign.GenerateSelfSigned()
		assert.NoError(t, genErr)

		serverPort := randomPort(t)
		serverListener, err := tls.Listen("tcp", "127.0.0.1:"+strconv.Itoa(serverPort), &tls.Config{ //nolint:gosec
			Certificates: []tls.Certificate{certificate},
		})
		assert.NoError(t, err)

		runTest(stun.ProtoTypeTCP, stun.SchemeTypeTURNS, nil, serverListener, serverPort)
	})

	t.Run("DTLS Relay", func(t *testing.T) {
		certificate, genErr := selfsign.GenerateSelfSigned()
		assert.NoError(t, genErr)

		serverPort := randomPort(t)
		serverListener, err := dtls.Listen("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: serverPort}, &dtls.Config{
			Certificates: []tls.Certificate{certificate},
		})
		assert.NoError(t, err)

		runTest(stun.ProtoTypeUDP, stun.SchemeTypeTURNS, nil, serverListener, serverPort)
	})
}

// Assert that STUN and TURN gathering are done concurrently
func TestSTUNTURNConcurrency(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()

	lim := test.TimeOut(time.Second * 8)
	defer lim.Stop()

	serverPort := randomPort(t)
	serverListener, err := net.ListenPacket("udp4", "127.0.0.1:"+strconv.Itoa(serverPort))
	assert.NoError(t, err)

	server, err := turn.NewServer(turn.ServerConfig{
		Realm:       "pion.ly",
		AuthHandler: optimisticAuthHandler,
		PacketConnConfigs: []turn.PacketConnConfig{
			{
				PacketConn:            serverListener,
				RelayAddressGenerator: &turn.RelayAddressGeneratorNone{Address: "127.0.0.1"},
			},
		},
	})
	assert.NoError(t, err)

	urls := []*stun.URI{}
	for i := 0; i <= 10; i++ {
		urls = append(urls, &stun.URI{
			Scheme: stun.SchemeTypeSTUN,
			Host:   "127.0.0.1",
			Port:   serverPort + 1,
		})
	}
	urls = append(urls, &stun.URI{
		Scheme:   stun.SchemeTypeTURN,
		Proto:    stun.ProtoTypeUDP,
		Host:     "127.0.0.1",
		Port:     serverPort,
		Username: "username",
		Password: "password",
	})

	a, err := NewAgent(&AgentConfig{
		NetworkTypes:   supportedNetworkTypes(),
		Urls:           urls,
		CandidateTypes: []CandidateType{CandidateTypeServerReflexive, CandidateTypeRelay},
	})
	assert.NoError(t, err)

	{
		gatherLim := test.TimeOut(time.Second * 3) // As TURN and STUN should be checked in parallel, this should complete before the default STUN timeout (5s)
		candidateGathered, candidateGatheredFunc := context.WithCancel(context.Background())
		assert.NoError(t, a.OnCandidate(func(c Candidate) {
			if c != nil {
				candidateGatheredFunc()
			}
		}))
		assert.NoError(t, a.GatherCandidates())

		<-candidateGathered.Done()

		gatherLim.Stop()
	}

	assert.NoError(t, a.Close())
	assert.NoError(t, server.Close())
}

// Assert that srflx candidates can be gathered from TURN servers
//
// When TURN servers are utilized, both types of candidates
// (i.e. srflx and relay) are obtained from the TURN server.
//
// https://tools.ietf.org/html/rfc5245#section-2.1
func TestTURNSrflx(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()

	lim := test.TimeOut(time.Second * 30)
	defer lim.Stop()

	serverPort := randomPort(t)
	serverListener, err := net.ListenPacket("udp4", "127.0.0.1:"+strconv.Itoa(serverPort))
	assert.NoError(t, err)

	server, err := turn.NewServer(turn.ServerConfig{
		Realm:       "pion.ly",
		AuthHandler: optimisticAuthHandler,
		PacketConnConfigs: []turn.PacketConnConfig{
			{
				PacketConn:            serverListener,
				RelayAddressGenerator: &turn.RelayAddressGeneratorNone{Address: "127.0.0.1"},
			},
		},
	})
	assert.NoError(t, err)

	urls := []*stun.URI{{
		Scheme:   stun.SchemeTypeTURN,
		Proto:    stun.ProtoTypeUDP,
		Host:     "127.0.0.1",
		Port:     serverPort,
		Username: "username",
		Password: "password",
	}}

	a, err := NewAgent(&AgentConfig{
		NetworkTypes:   supportedNetworkTypes(),
		Urls:           urls,
		CandidateTypes: []CandidateType{CandidateTypeServerReflexive, CandidateTypeRelay},
	})
	assert.NoError(t, err)

	candidateGathered, candidateGatheredFunc := context.WithCancel(context.Background())
	assert.NoError(t, a.OnCandidate(func(c Candidate) {
		if c != nil && c.Type() == CandidateTypeServerReflexive {
			candidateGatheredFunc()
		}
	}))

	assert.NoError(t, a.GatherCandidates())

	<-candidateGathered.Done()

	assert.NoError(t, a.Close())
	assert.NoError(t, server.Close())
}

func TestCloseConnLog(t *testing.T) {
	a, err := NewAgent(&AgentConfig{})
	assert.NoError(t, err)

	closeConnAndLog(nil, a.log, "normal nil")

	var nc *net.UDPConn
	closeConnAndLog(nc, a.log, "nil ptr")

	assert.NoError(t, a.Close())
}

type mockProxy struct {
	proxyWasDialed func()
}

type mockConn struct{}

func (m *mockConn) Read([]byte) (n int, err error)   { return 0, io.EOF }
func (m *mockConn) Write([]byte) (int, error)        { return 0, io.EOF }
func (m *mockConn) Close() error                     { return io.EOF }
func (m *mockConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (m *mockConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (m *mockConn) SetDeadline(time.Time) error      { return io.EOF }
func (m *mockConn) SetReadDeadline(time.Time) error  { return io.EOF }
func (m *mockConn) SetWriteDeadline(time.Time) error { return io.EOF }

func (m *mockProxy) Dial(string, string) (net.Conn, error) {
	m.proxyWasDialed()
	return &mockConn{}, nil
}

func TestTURNProxyDialer(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()

	lim := test.TimeOut(time.Second * 30)
	defer lim.Stop()

	proxyWasDialed, proxyWasDialedFunc := context.WithCancel(context.Background())
	proxy.RegisterDialerType("tcp", func(*url.URL, proxy.Dialer) (proxy.Dialer, error) {
		return &mockProxy{proxyWasDialedFunc}, nil
	})

	tcpProxyURI, err := url.Parse("tcp://fakeproxy:3128")
	assert.NoError(t, err)

	proxyDialer, err := proxy.FromURL(tcpProxyURI, proxy.Direct)
	assert.NoError(t, err)

	a, err := NewAgent(&AgentConfig{
		CandidateTypes: []CandidateType{CandidateTypeRelay},
		NetworkTypes:   supportedNetworkTypes(),
		Urls: []*stun.URI{
			{
				Scheme:   stun.SchemeTypeTURN,
				Host:     "127.0.0.1",
				Username: "username",
				Password: "password",
				Proto:    stun.ProtoTypeTCP,
				Port:     5000,
			},
		},
		ProxyDialer: proxyDialer,
	})
	assert.NoError(t, err)

	candidateGatherFinish, candidateGatherFinishFunc := context.WithCancel(context.Background())
	assert.NoError(t, a.OnCandidate(func(c Candidate) {
		if c == nil {
			candidateGatherFinishFunc()
		}
	}))

	assert.NoError(t, a.GatherCandidates())
	<-candidateGatherFinish.Done()
	<-proxyWasDialed.Done()

	assert.NoError(t, a.Close())
}

// TestUDPMuxDefaultWithNAT1To1IPsUsage asserts that candidates
// are given and connections are valid when using UDPMuxDefault and NAT1To1IPs.
func TestUDPMuxDefaultWithNAT1To1IPsUsage(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()

	lim := test.TimeOut(time.Second * 30)
	defer lim.Stop()

	conn, err := net.ListenPacket("udp4", ":0")
	assert.NoError(t, err)
	defer func() {
		_ = conn.Close()
	}()

	mux := NewUDPMuxDefault(UDPMuxParams{
		UDPConn: conn,
	})
	defer func() {
		_ = mux.Close()
	}()

	a, err := NewAgent(&AgentConfig{
		NAT1To1IPs:             []string{"1.2.3.4"},
		NAT1To1IPCandidateType: CandidateTypeHost,
		UDPMux:                 mux,
	})
	assert.NoError(t, err)

	gatherCandidateDone := make(chan struct{})
	assert.NoError(t, a.OnCandidate(func(c Candidate) {
		if c == nil {
			close(gatherCandidateDone)
		} else {
			assert.Equal(t, "1.2.3.4", c.Address())
		}
	}))
	assert.NoError(t, a.GatherCandidates())
	<-gatherCandidateDone

	assert.NotEqual(t, 0, len(mux.connsIPv4))

	assert.NoError(t, a.Close())
}

// Assert that candidates are given for each mux in a MultiUDPMux
func TestMultiUDPMuxUsage(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()

	lim := test.TimeOut(time.Second * 30)
	defer lim.Stop()

	var expectedPorts []int
	var udpMuxInstances []UDPMux
	for i := 0; i < 3; i++ {
		port := randomPort(t)
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IP{127, 0, 0, 1}, Port: port})
		assert.NoError(t, err)
		defer func() {
			_ = conn.Close()
		}()

		expectedPorts = append(expectedPorts, port)
		muxDefault := NewUDPMuxDefault(UDPMuxParams{UDPConn: conn})
		udpMuxInstances = append(udpMuxInstances, muxDefault)
		idx := i
		defer func() {
			_ = udpMuxInstances[idx].Close()
		}()
	}

	a, err := NewAgent(&AgentConfig{
		NetworkTypes:   []NetworkType{NetworkTypeUDP4, NetworkTypeUDP6},
		CandidateTypes: []CandidateType{CandidateTypeHost},
		UDPMux:         NewMultiUDPMuxDefault(udpMuxInstances...),
	})
	assert.NoError(t, err)

	candidateCh := make(chan Candidate)
	assert.NoError(t, a.OnCandidate(func(c Candidate) {
		if c == nil {
			close(candidateCh)
			return
		}
		candidateCh <- c
	}))
	assert.NoError(t, a.GatherCandidates())

	portFound := make(map[int]bool)
	for c := range candidateCh {
		portFound[c.Port()] = true
		assert.True(t, c.NetworkType().IsUDP(), "All candidates should be UDP")
	}
	assert.Len(t, portFound, len(expectedPorts))
	for _, port := range expectedPorts {
		assert.True(t, portFound[port], "There should be a candidate for each UDP mux port")
	}

	assert.NoError(t, a.Close())
}

// Assert that candidates are given for each mux in a MultiTCPMux
func TestMultiTCPMuxUsage(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()

	lim := test.TimeOut(time.Second * 30)
	defer lim.Stop()

	var expectedPorts []int
	var tcpMuxInstances []TCPMux
	for i := 0; i < 3; i++ {
		port := randomPort(t)
		listener, err := net.ListenTCP("tcp", &net.TCPAddr{
			IP:   net.IP{127, 0, 0, 1},
			Port: port,
		})
		assert.NoError(t, err)
		defer func() {
			_ = listener.Close()
		}()

		expectedPorts = append(expectedPorts, port)
		tcpMuxInstances = append(tcpMuxInstances, NewTCPMuxDefault(TCPMuxParams{
			Listener:       listener,
			ReadBufferSize: 8,
		}))
	}

	a, err := NewAgent(&AgentConfig{
		NetworkTypes:   supportedNetworkTypes(),
		CandidateTypes: []CandidateType{CandidateTypeHost},
		TCPMux:         NewMultiTCPMuxDefault(tcpMuxInstances...),
	})
	assert.NoError(t, err)

	candidateCh := make(chan Candidate)
	assert.NoError(t, a.OnCandidate(func(c Candidate) {
		if c == nil {
			close(candidateCh)
			return
		}
		candidateCh <- c
	}))
	assert.NoError(t, a.GatherCandidates())

	portFound := make(map[int]bool)
	for c := range candidateCh {
		activeCandidate := c.Port() == 0
		if c.NetworkType().IsTCP() && !activeCandidate {
			portFound[c.Port()] = true
		}
	}
	assert.Len(t, portFound, len(expectedPorts))
	for _, port := range expectedPorts {
		assert.True(t, portFound[port], "There should be a candidate for each TCP mux port")
	}

	assert.NoError(t, a.Close())
}

// Assert that UniversalUDPMux is used while gathering when configured in the Agent
func TestUniversalUDPMuxUsage(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()

	lim := test.TimeOut(time.Second * 30)
	defer lim.Stop()

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IP{127, 0, 0, 1}, Port: randomPort(t)})
	assert.NoError(t, err)
	defer func() {
		_ = conn.Close()
	}()

	udpMuxSrflx := &universalUDPMuxMock{
		conn: conn,
	}

	numSTUNS := 3
	urls := []*stun.URI{}
	for i := 0; i < numSTUNS; i++ {
		urls = append(urls, &stun.URI{
			Scheme: SchemeTypeSTUN,
			Host:   "127.0.0.1",
			Port:   3478 + i,
		})
	}

	a, err := NewAgent(&AgentConfig{
		NetworkTypes:   supportedNetworkTypes(),
		Urls:           urls,
		CandidateTypes: []CandidateType{CandidateTypeServerReflexive},
		UDPMuxSrflx:    udpMuxSrflx,
	})
	assert.NoError(t, err)

	candidateGathered, candidateGatheredFunc := context.WithCancel(context.Background())
	assert.NoError(t, a.OnCandidate(func(c Candidate) {
		if c == nil {
			candidateGatheredFunc()
			return
		}
		t.Log(c.NetworkType(), c.Priority(), c)
	}))
	assert.NoError(t, a.GatherCandidates())

	<-candidateGathered.Done()

	assert.NoError(t, a.Close())
	// Twice because of 2 STUN servers configured
	assert.Equal(t, numSTUNS, udpMuxSrflx.getXORMappedAddrUsedTimes, "expected times that GetXORMappedAddr should be called")
	// One for Restart() when agent has been initialized and one time when Close() the agent
	assert.Equal(t, 2, udpMuxSrflx.removeConnByUfragTimes, "expected times that RemoveConnByUfrag should be called")
	// Twice because of 2 STUN servers configured
	assert.Equal(t, numSTUNS, udpMuxSrflx.getConnForURLTimes, "expected times that GetConnForURL should be called")
}

type universalUDPMuxMock struct {
	UDPMux
	getXORMappedAddrUsedTimes int
	removeConnByUfragTimes    int
	getConnForURLTimes        int
	mu                        sync.Mutex
	conn                      *net.UDPConn
}

func (m *universalUDPMuxMock) GetRelayedAddr(net.Addr, time.Duration) (*net.Addr, error) {
	return nil, errNotImplemented
}

func (m *universalUDPMuxMock) GetConnForURL(string, string, net.Addr) (net.PacketConn, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getConnForURLTimes++
	return m.conn, nil
}

func (m *universalUDPMuxMock) GetXORMappedAddr(net.Addr, time.Duration) (*stun.XORMappedAddress, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getXORMappedAddrUsedTimes++
	return &stun.XORMappedAddress{IP: net.IP{100, 64, 0, 1}, Port: 77878}, nil
}

func (m *universalUDPMuxMock) RemoveConnByUfrag(string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.removeConnByUfragTimes++
}

func (m *universalUDPMuxMock) GetListenAddresses() []net.Addr {
	return []net.Addr{m.conn.LocalAddr()}
}
