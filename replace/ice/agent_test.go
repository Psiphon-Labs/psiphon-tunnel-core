// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js
// +build !js

package ice

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/pion/ice/v2/internal/fakenet"
	"github.com/pion/logging"
	"github.com/pion/stun"
	"github.com/pion/transport/v2/test"
	"github.com/pion/transport/v2/vnet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type BadAddr struct{}

func (ba *BadAddr) Network() string {
	return "xxx"
}

func (ba *BadAddr) String() string {
	return "yyy"
}

func runAgentTest(t *testing.T, config *AgentConfig, task func(ctx context.Context, a *Agent)) {
	a, err := NewAgent(config)
	if err != nil {
		t.Fatalf("Error constructing ice.Agent")
	}

	if err := a.run(context.Background(), task); err != nil {
		t.Fatalf("Agent run failure: %v", err)
	}

	assert.NoError(t, a.Close())
}

func TestHandlePeerReflexive(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()

	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 2)
	defer lim.Stop()

	t.Run("UDP prflx candidate from handleInbound()", func(t *testing.T) {
		var config AgentConfig
		runAgentTest(t, &config, func(ctx context.Context, a *Agent) {
			a.selector = &controllingSelector{agent: a, log: a.log}

			hostConfig := CandidateHostConfig{
				Network:   "udp",
				Address:   "192.168.0.2",
				Port:      777,
				Component: 1,
			}
			local, err := NewCandidateHost(&hostConfig)
			local.conn = &fakenet.MockPacketConn{}
			if err != nil {
				t.Fatalf("failed to create a new candidate: %v", err)
			}

			remote := &net.UDPAddr{IP: net.ParseIP("172.17.0.3"), Port: 999}

			msg, err := stun.Build(stun.BindingRequest, stun.TransactionID,
				stun.NewUsername(a.localUfrag+":"+a.remoteUfrag),
				UseCandidate(),
				AttrControlling(a.tieBreaker),
				PriorityAttr(local.Priority()),
				stun.NewShortTermIntegrity(a.localPwd),
				stun.Fingerprint,
			)
			if err != nil {
				t.Fatal(err)
			}

			// nolint: contextcheck
			a.handleInbound(msg, local, remote)

			// Length of remote candidate list must be one now
			if len(a.remoteCandidates) != 1 {
				t.Fatal("failed to add a network type to the remote candidate list")
			}

			// Length of remote candidate list for a network type must be 1
			set := a.remoteCandidates[local.NetworkType()]
			if len(set) != 1 {
				t.Fatal("failed to add prflx candidate to remote candidate list")
			}

			c := set[0]

			if c.Type() != CandidateTypePeerReflexive {
				t.Fatal("candidate type must be prflx")
			}

			if c.Address() != "172.17.0.3" {
				t.Fatal("IP address mismatch")
			}

			if c.Port() != 999 {
				t.Fatal("Port number mismatch")
			}
		})
	})

	t.Run("Bad network type with handleInbound()", func(t *testing.T) {
		var config AgentConfig
		runAgentTest(t, &config, func(ctx context.Context, a *Agent) {
			a.selector = &controllingSelector{agent: a, log: a.log}

			hostConfig := CandidateHostConfig{
				Network:   "tcp",
				Address:   "192.168.0.2",
				Port:      777,
				Component: 1,
			}
			local, err := NewCandidateHost(&hostConfig)
			if err != nil {
				t.Fatalf("failed to create a new candidate: %v", err)
			}

			remote := &BadAddr{}

			// nolint: contextcheck
			a.handleInbound(nil, local, remote)

			if len(a.remoteCandidates) != 0 {
				t.Fatal("bad address should not be added to the remote candidate list")
			}
		})
	})

	t.Run("Success from unknown remote, prflx candidate MUST only be created via Binding Request", func(t *testing.T) {
		var config AgentConfig
		runAgentTest(t, &config, func(ctx context.Context, a *Agent) {
			a.selector = &controllingSelector{agent: a, log: a.log}
			tID := [stun.TransactionIDSize]byte{}
			copy(tID[:], "ABC")
			a.pendingBindingRequests = []bindingRequest{
				{time.Now(), tID, &net.UDPAddr{}, false},
			}

			hostConfig := CandidateHostConfig{
				Network:   "udp",
				Address:   "192.168.0.2",
				Port:      777,
				Component: 1,
			}
			local, err := NewCandidateHost(&hostConfig)
			local.conn = &fakenet.MockPacketConn{}
			if err != nil {
				t.Fatalf("failed to create a new candidate: %v", err)
			}

			remote := &net.UDPAddr{IP: net.ParseIP("172.17.0.3"), Port: 999}
			msg, err := stun.Build(stun.BindingSuccess, stun.NewTransactionIDSetter(tID),
				stun.NewShortTermIntegrity(a.remotePwd),
				stun.Fingerprint,
			)
			if err != nil {
				t.Fatal(err)
			}

			// nolint: contextcheck
			a.handleInbound(msg, local, remote)
			if len(a.remoteCandidates) != 0 {
				t.Fatal("unknown remote was able to create a candidate")
			}
		})
	})
}

// Assert that Agent on startup sends message, and doesn't wait for connectivityTicker to fire
// https://github.com/pion/ice/issues/15
func TestConnectivityOnStartup(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()

	lim := test.TimeOut(time.Second * 30)
	defer lim.Stop()

	// Create a network with two interfaces
	wan, err := vnet.NewRouter(&vnet.RouterConfig{
		CIDR:          "0.0.0.0/0",
		LoggerFactory: logging.NewDefaultLoggerFactory(),
	})
	assert.NoError(t, err)

	net0, err := vnet.NewNet(&vnet.NetConfig{
		StaticIPs: []string{"192.168.0.1"},
	})
	assert.NoError(t, err)
	assert.NoError(t, wan.AddNet(net0))

	net1, err := vnet.NewNet(&vnet.NetConfig{
		StaticIPs: []string{"192.168.0.2"},
	})
	assert.NoError(t, err)
	assert.NoError(t, wan.AddNet(net1))

	assert.NoError(t, wan.Start())

	aNotifier, aConnected := onConnected()
	bNotifier, bConnected := onConnected()

	KeepaliveInterval := time.Hour
	cfg0 := &AgentConfig{
		NetworkTypes:      supportedNetworkTypes(),
		MulticastDNSMode:  MulticastDNSModeDisabled,
		Net:               net0,
		KeepaliveInterval: &KeepaliveInterval,
		CheckInterval:     &KeepaliveInterval,
	}

	aAgent, err := NewAgent(cfg0)
	require.NoError(t, err)
	require.NoError(t, aAgent.OnConnectionStateChange(aNotifier))

	cfg1 := &AgentConfig{
		NetworkTypes:      supportedNetworkTypes(),
		MulticastDNSMode:  MulticastDNSModeDisabled,
		Net:               net1,
		KeepaliveInterval: &KeepaliveInterval,
		CheckInterval:     &KeepaliveInterval,
	}

	bAgent, err := NewAgent(cfg1)
	require.NoError(t, err)
	require.NoError(t, bAgent.OnConnectionStateChange(bNotifier))

	aConn, bConn := func(aAgent, bAgent *Agent) (*Conn, *Conn) {
		// Manual signaling
		aUfrag, aPwd, err := aAgent.GetLocalUserCredentials()
		assert.NoError(t, err)

		bUfrag, bPwd, err := bAgent.GetLocalUserCredentials()
		assert.NoError(t, err)

		gatherAndExchangeCandidates(aAgent, bAgent)

		accepted := make(chan struct{})
		accepting := make(chan struct{})
		var aConn *Conn

		origHdlr := aAgent.onConnectionStateChangeHdlr.Load()
		if origHdlr != nil {
			defer check(aAgent.OnConnectionStateChange(origHdlr.(func(ConnectionState)))) //nolint:forcetypeassert
		}
		check(aAgent.OnConnectionStateChange(func(s ConnectionState) {
			if s == ConnectionStateChecking {
				close(accepting)
			}
			if origHdlr != nil {
				origHdlr.(func(ConnectionState))(s) //nolint:forcetypeassert
			}
		}))

		go func() {
			var acceptErr error
			aConn, acceptErr = aAgent.Accept(context.TODO(), bUfrag, bPwd)
			check(acceptErr)
			close(accepted)
		}()

		<-accepting

		bConn, err := bAgent.Dial(context.TODO(), aUfrag, aPwd)
		check(err)

		// Ensure accepted
		<-accepted
		return aConn, bConn
	}(aAgent, bAgent)

	// Ensure pair selected
	// Note: this assumes ConnectionStateConnected is thrown after selecting the final pair
	<-aConnected
	<-bConnected

	assert.NoError(t, wan.Stop())
	if !closePipe(t, aConn, bConn) {
		return
	}
}

func TestConnectivityLite(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()

	lim := test.TimeOut(time.Second * 30)
	defer lim.Stop()

	stunServerURL := &stun.URI{
		Scheme: SchemeTypeSTUN,
		Host:   "1.2.3.4",
		Port:   3478,
		Proto:  stun.ProtoTypeUDP,
	}

	natType := &vnet.NATType{
		MappingBehavior:   vnet.EndpointIndependent,
		FilteringBehavior: vnet.EndpointIndependent,
	}
	v, err := buildVNet(natType, natType)
	require.NoError(t, err, "should succeed")
	defer v.close()

	aNotifier, aConnected := onConnected()
	bNotifier, bConnected := onConnected()

	cfg0 := &AgentConfig{
		Urls:             []*stun.URI{stunServerURL},
		NetworkTypes:     supportedNetworkTypes(),
		MulticastDNSMode: MulticastDNSModeDisabled,
		Net:              v.net0,
	}

	aAgent, err := NewAgent(cfg0)
	require.NoError(t, err)
	require.NoError(t, aAgent.OnConnectionStateChange(aNotifier))

	cfg1 := &AgentConfig{
		Urls:             []*stun.URI{},
		Lite:             true,
		CandidateTypes:   []CandidateType{CandidateTypeHost},
		NetworkTypes:     supportedNetworkTypes(),
		MulticastDNSMode: MulticastDNSModeDisabled,
		Net:              v.net1,
	}

	bAgent, err := NewAgent(cfg1)
	require.NoError(t, err)
	require.NoError(t, bAgent.OnConnectionStateChange(bNotifier))

	aConn, bConn := connectWithVNet(aAgent, bAgent)

	// Ensure pair selected
	// Note: this assumes ConnectionStateConnected is thrown after selecting the final pair
	<-aConnected
	<-bConnected

	if !closePipe(t, aConn, bConn) {
		return
	}
}

func TestInboundValidity(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()

	buildMsg := func(class stun.MessageClass, username, key string) *stun.Message {
		msg, err := stun.Build(stun.NewType(stun.MethodBinding, class), stun.TransactionID,
			stun.NewUsername(username),
			stun.NewShortTermIntegrity(key),
			stun.Fingerprint,
		)
		if err != nil {
			t.Fatal(err)
		}

		return msg
	}

	remote := &net.UDPAddr{IP: net.ParseIP("172.17.0.3"), Port: 999}
	hostConfig := CandidateHostConfig{
		Network:   "udp",
		Address:   "192.168.0.2",
		Port:      777,
		Component: 1,
	}
	local, err := NewCandidateHost(&hostConfig)
	local.conn = &fakenet.MockPacketConn{}
	if err != nil {
		t.Fatalf("failed to create a new candidate: %v", err)
	}

	t.Run("Invalid Binding requests should be discarded", func(t *testing.T) {
		a, err := NewAgent(&AgentConfig{})
		if err != nil {
			t.Fatalf("Error constructing ice.Agent")
		}

		a.handleInbound(buildMsg(stun.ClassRequest, "invalid", a.localPwd), local, remote)
		if len(a.remoteCandidates) == 1 {
			t.Fatal("Binding with invalid Username was able to create prflx candidate")
		}

		a.handleInbound(buildMsg(stun.ClassRequest, a.localUfrag+":"+a.remoteUfrag, "Invalid"), local, remote)
		if len(a.remoteCandidates) == 1 {
			t.Fatal("Binding with invalid MessageIntegrity was able to create prflx candidate")
		}

		assert.NoError(t, a.Close())
	})

	t.Run("Invalid Binding success responses should be discarded", func(t *testing.T) {
		a, err := NewAgent(&AgentConfig{})
		if err != nil {
			t.Fatalf("Error constructing ice.Agent")
		}

		a.handleInbound(buildMsg(stun.ClassSuccessResponse, a.localUfrag+":"+a.remoteUfrag, "Invalid"), local, remote)
		if len(a.remoteCandidates) == 1 {
			t.Fatal("Binding with invalid MessageIntegrity was able to create prflx candidate")
		}

		assert.NoError(t, a.Close())
	})

	t.Run("Discard non-binding messages", func(t *testing.T) {
		a, err := NewAgent(&AgentConfig{})
		if err != nil {
			t.Fatalf("Error constructing ice.Agent")
		}

		a.handleInbound(buildMsg(stun.ClassErrorResponse, a.localUfrag+":"+a.remoteUfrag, "Invalid"), local, remote)
		if len(a.remoteCandidates) == 1 {
			t.Fatal("non-binding message was able to create prflxRemote")
		}

		assert.NoError(t, a.Close())
	})

	t.Run("Valid bind request", func(t *testing.T) {
		a, err := NewAgent(&AgentConfig{})
		if err != nil {
			t.Fatalf("Error constructing ice.Agent")
		}

		err = a.run(context.Background(), func(ctx context.Context, a *Agent) {
			a.selector = &controllingSelector{agent: a, log: a.log}
			// nolint: contextcheck
			a.handleInbound(buildMsg(stun.ClassRequest, a.localUfrag+":"+a.remoteUfrag, a.localPwd), local, remote)
			if len(a.remoteCandidates) != 1 {
				t.Fatal("Binding with valid values was unable to create prflx candidate")
			}
		})

		assert.NoError(t, err)
		assert.NoError(t, a.Close())
	})

	t.Run("Valid bind without fingerprint", func(t *testing.T) {
		var config AgentConfig
		runAgentTest(t, &config, func(ctx context.Context, a *Agent) {
			a.selector = &controllingSelector{agent: a, log: a.log}
			msg, err := stun.Build(stun.BindingRequest, stun.TransactionID,
				stun.NewUsername(a.localUfrag+":"+a.remoteUfrag),
				stun.NewShortTermIntegrity(a.localPwd),
			)
			if err != nil {
				t.Fatal(err)
			}

			// nolint: contextcheck
			a.handleInbound(msg, local, remote)
			if len(a.remoteCandidates) != 1 {
				t.Fatal("Binding with valid values (but no fingerprint) was unable to create prflx candidate")
			}
		})
	})

	t.Run("Success with invalid TransactionID", func(t *testing.T) {
		a, err := NewAgent(&AgentConfig{})
		if err != nil {
			t.Fatalf("Error constructing ice.Agent")
		}

		hostConfig := CandidateHostConfig{
			Network:   "udp",
			Address:   "192.168.0.2",
			Port:      777,
			Component: 1,
		}
		local, err := NewCandidateHost(&hostConfig)
		local.conn = &fakenet.MockPacketConn{}
		if err != nil {
			t.Fatalf("failed to create a new candidate: %v", err)
		}

		remote := &net.UDPAddr{IP: net.ParseIP("172.17.0.3"), Port: 999}
		tID := [stun.TransactionIDSize]byte{}
		copy(tID[:], "ABC")
		msg, err := stun.Build(stun.BindingSuccess, stun.NewTransactionIDSetter(tID),
			stun.NewShortTermIntegrity(a.remotePwd),
			stun.Fingerprint,
		)
		assert.NoError(t, err)

		a.handleInbound(msg, local, remote)
		if len(a.remoteCandidates) != 0 {
			t.Fatal("unknown remote was able to create a candidate")
		}

		assert.NoError(t, a.Close())
	})
}

func TestInvalidAgentStarts(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()

	a, err := NewAgent(&AgentConfig{})
	assert.NoError(t, err)

	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()

	if _, err = a.Dial(ctx, "", "bar"); err != nil && !errors.Is(err, ErrRemoteUfragEmpty) {
		t.Fatal(err)
	}

	if _, err = a.Dial(ctx, "foo", ""); err != nil && !errors.Is(err, ErrRemotePwdEmpty) {
		t.Fatal(err)
	}

	if _, err = a.Dial(ctx, "foo", "bar"); err != nil && !errors.Is(err, ErrCanceledByCaller) {
		t.Fatal(err)
	}

	if _, err = a.Dial(context.TODO(), "foo", "bar"); err != nil && !errors.Is(err, ErrMultipleStart) {
		t.Fatal(err)
	}

	assert.NoError(t, a.Close())
}

// Assert that Agent emits Connecting/Connected/Disconnected/Failed/Closed messages
func TestConnectionStateCallback(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()

	lim := test.TimeOut(time.Second * 5)
	defer lim.Stop()

	disconnectedDuration := time.Second
	failedDuration := time.Second
	KeepaliveInterval := time.Duration(0)

	cfg := &AgentConfig{
		Urls:                []*stun.URI{},
		NetworkTypes:        supportedNetworkTypes(),
		DisconnectedTimeout: &disconnectedDuration,
		FailedTimeout:       &failedDuration,
		KeepaliveInterval:   &KeepaliveInterval,
	}

	aAgent, err := NewAgent(cfg)
	if err != nil {
		t.Error(err)
	}

	bAgent, err := NewAgent(cfg)
	if err != nil {
		t.Error(err)
	}

	isChecking := make(chan interface{})
	isConnected := make(chan interface{})
	isDisconnected := make(chan interface{})
	isFailed := make(chan interface{})
	isClosed := make(chan interface{})
	err = aAgent.OnConnectionStateChange(func(c ConnectionState) {
		switch c {
		case ConnectionStateChecking:
			close(isChecking)
		case ConnectionStateConnected:
			close(isConnected)
		case ConnectionStateDisconnected:
			close(isDisconnected)
		case ConnectionStateFailed:
			close(isFailed)
		case ConnectionStateClosed:
			close(isClosed)
		default:
		}
	})
	if err != nil {
		t.Error(err)
	}

	connect(aAgent, bAgent)

	<-isChecking
	<-isConnected
	<-isDisconnected
	<-isFailed

	assert.NoError(t, aAgent.Close())
	assert.NoError(t, bAgent.Close())

	<-isClosed
}

func TestInvalidGather(t *testing.T) {
	t.Run("Gather with no OnCandidate should error", func(t *testing.T) {
		a, err := NewAgent(&AgentConfig{})
		if err != nil {
			t.Fatalf("Error constructing ice.Agent")
		}

		err = a.GatherCandidates()
		if !errors.Is(err, ErrNoOnCandidateHandler) {
			t.Fatal("trickle GatherCandidates succeeded without OnCandidate")
		}
		assert.NoError(t, a.Close())
	})
}

func TestCandidatePairStats(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()

	// Avoid deadlocks?
	defer test.TimeOut(1 * time.Second).Stop()

	a, err := NewAgent(&AgentConfig{})
	if err != nil {
		t.Fatalf("Failed to create agent: %s", err)
	}

	hostConfig := &CandidateHostConfig{
		Network:   "udp",
		Address:   "192.168.1.1",
		Port:      19216,
		Component: 1,
	}
	hostLocal, err := NewCandidateHost(hostConfig)
	if err != nil {
		t.Fatalf("Failed to construct local host candidate: %s", err)
	}

	relayConfig := &CandidateRelayConfig{
		Network:   "udp",
		Address:   "1.2.3.4",
		Port:      2340,
		Component: 1,
		RelAddr:   "4.3.2.1",
		RelPort:   43210,
	}
	relayRemote, err := NewCandidateRelay(relayConfig)
	if err != nil {
		t.Fatalf("Failed to construct remote relay candidate: %s", err)
	}

	srflxConfig := &CandidateServerReflexiveConfig{
		Network:   "udp",
		Address:   "10.10.10.2",
		Port:      19218,
		Component: 1,
		RelAddr:   "4.3.2.1",
		RelPort:   43212,
	}
	srflxRemote, err := NewCandidateServerReflexive(srflxConfig)
	if err != nil {
		t.Fatalf("Failed to construct remote srflx candidate: %s", err)
	}

	prflxConfig := &CandidatePeerReflexiveConfig{
		Network:   "udp",
		Address:   "10.10.10.2",
		Port:      19217,
		Component: 1,
		RelAddr:   "4.3.2.1",
		RelPort:   43211,
	}
	prflxRemote, err := NewCandidatePeerReflexive(prflxConfig)
	if err != nil {
		t.Fatalf("Failed to construct remote prflx candidate: %s", err)
	}

	hostConfig = &CandidateHostConfig{
		Network:   "udp",
		Address:   "1.2.3.5",
		Port:      12350,
		Component: 1,
	}
	hostRemote, err := NewCandidateHost(hostConfig)
	if err != nil {
		t.Fatalf("Failed to construct remote host candidate: %s", err)
	}

	for _, remote := range []Candidate{relayRemote, srflxRemote, prflxRemote, hostRemote} {
		p := a.findPair(hostLocal, remote)

		if p == nil {
			a.addPair(hostLocal, remote)
		}
	}

	p := a.findPair(hostLocal, prflxRemote)
	p.state = CandidatePairStateFailed

	stats := a.GetCandidatePairsStats()
	if len(stats) != 4 {
		t.Fatal("expected 4 candidate pairs stats")
	}

	var relayPairStat, srflxPairStat, prflxPairStat, hostPairStat CandidatePairStats

	for _, cps := range stats {
		if cps.LocalCandidateID != hostLocal.ID() {
			t.Fatal("invalid local candidate id")
		}
		switch cps.RemoteCandidateID {
		case relayRemote.ID():
			relayPairStat = cps
		case srflxRemote.ID():
			srflxPairStat = cps
		case prflxRemote.ID():
			prflxPairStat = cps
		case hostRemote.ID():
			hostPairStat = cps
		default:
			t.Fatal("invalid remote candidate ID")
		}
	}

	if relayPairStat.RemoteCandidateID != relayRemote.ID() {
		t.Fatal("missing host-relay pair stat")
	}

	if srflxPairStat.RemoteCandidateID != srflxRemote.ID() {
		t.Fatal("missing host-srflx pair stat")
	}

	if prflxPairStat.RemoteCandidateID != prflxRemote.ID() {
		t.Fatal("missing host-prflx pair stat")
	}

	if hostPairStat.RemoteCandidateID != hostRemote.ID() {
		t.Fatal("missing host-host pair stat")
	}

	if prflxPairStat.State != CandidatePairStateFailed {
		t.Fatalf("expected host-prflx pair to have state failed, it has state %s instead",
			prflxPairStat.State.String())
	}

	assert.NoError(t, a.Close())
}

func TestLocalCandidateStats(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()

	// Avoid deadlocks?
	defer test.TimeOut(1 * time.Second).Stop()

	a, err := NewAgent(&AgentConfig{})
	if err != nil {
		t.Fatalf("Failed to create agent: %s", err)
	}

	hostConfig := &CandidateHostConfig{
		Network:   "udp",
		Address:   "192.168.1.1",
		Port:      19216,
		Component: 1,
	}
	hostLocal, err := NewCandidateHost(hostConfig)
	if err != nil {
		t.Fatalf("Failed to construct local host candidate: %s", err)
	}

	srflxConfig := &CandidateServerReflexiveConfig{
		Network:   "udp",
		Address:   "192.168.1.1",
		Port:      19217,
		Component: 1,
		RelAddr:   "4.3.2.1",
		RelPort:   43212,
	}
	srflxLocal, err := NewCandidateServerReflexive(srflxConfig)
	if err != nil {
		t.Fatalf("Failed to construct local srflx candidate: %s", err)
	}

	a.localCandidates[NetworkTypeUDP4] = []Candidate{hostLocal, srflxLocal}

	localStats := a.GetLocalCandidatesStats()
	if len(localStats) != 2 {
		t.Fatalf("expected 2 local candidates stats, got %d instead", len(localStats))
	}

	var hostLocalStat, srflxLocalStat CandidateStats
	for _, stats := range localStats {
		var candidate Candidate
		switch stats.ID {
		case hostLocal.ID():
			hostLocalStat = stats
			candidate = hostLocal
		case srflxLocal.ID():
			srflxLocalStat = stats
			candidate = srflxLocal
		default:
			t.Fatal("invalid local candidate ID")
		}

		if stats.CandidateType != candidate.Type() {
			t.Fatal("invalid stats CandidateType")
		}

		if stats.Priority != candidate.Priority() {
			t.Fatal("invalid stats CandidateType")
		}

		if stats.IP != candidate.Address() {
			t.Fatal("invalid stats IP")
		}
	}

	if hostLocalStat.ID != hostLocal.ID() {
		t.Fatal("missing host local stat")
	}

	if srflxLocalStat.ID != srflxLocal.ID() {
		t.Fatal("missing srflx local stat")
	}

	assert.NoError(t, a.Close())
}

func TestRemoteCandidateStats(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()

	// Avoid deadlocks?
	defer test.TimeOut(1 * time.Second).Stop()

	a, err := NewAgent(&AgentConfig{})
	if err != nil {
		t.Fatalf("Failed to create agent: %s", err)
	}

	relayConfig := &CandidateRelayConfig{
		Network:   "udp",
		Address:   "1.2.3.4",
		Port:      12340,
		Component: 1,
		RelAddr:   "4.3.2.1",
		RelPort:   43210,
	}
	relayRemote, err := NewCandidateRelay(relayConfig)
	if err != nil {
		t.Fatalf("Failed to construct remote relay candidate: %s", err)
	}

	srflxConfig := &CandidateServerReflexiveConfig{
		Network:   "udp",
		Address:   "10.10.10.2",
		Port:      19218,
		Component: 1,
		RelAddr:   "4.3.2.1",
		RelPort:   43212,
	}
	srflxRemote, err := NewCandidateServerReflexive(srflxConfig)
	if err != nil {
		t.Fatalf("Failed to construct remote srflx candidate: %s", err)
	}

	prflxConfig := &CandidatePeerReflexiveConfig{
		Network:   "udp",
		Address:   "10.10.10.2",
		Port:      19217,
		Component: 1,
		RelAddr:   "4.3.2.1",
		RelPort:   43211,
	}
	prflxRemote, err := NewCandidatePeerReflexive(prflxConfig)
	if err != nil {
		t.Fatalf("Failed to construct remote prflx candidate: %s", err)
	}

	hostConfig := &CandidateHostConfig{
		Network:   "udp",
		Address:   "1.2.3.5",
		Port:      12350,
		Component: 1,
	}
	hostRemote, err := NewCandidateHost(hostConfig)
	if err != nil {
		t.Fatalf("Failed to construct remote host candidate: %s", err)
	}

	a.remoteCandidates[NetworkTypeUDP4] = []Candidate{relayRemote, srflxRemote, prflxRemote, hostRemote}

	remoteStats := a.GetRemoteCandidatesStats()
	if len(remoteStats) != 4 {
		t.Fatalf("expected 4 remote candidates stats, got %d instead", len(remoteStats))
	}
	var relayRemoteStat, srflxRemoteStat, prflxRemoteStat, hostRemoteStat CandidateStats
	for _, stats := range remoteStats {
		var candidate Candidate
		switch stats.ID {
		case relayRemote.ID():
			relayRemoteStat = stats
			candidate = relayRemote
		case srflxRemote.ID():
			srflxRemoteStat = stats
			candidate = srflxRemote
		case prflxRemote.ID():
			prflxRemoteStat = stats
			candidate = prflxRemote
		case hostRemote.ID():
			hostRemoteStat = stats
			candidate = hostRemote
		default:
			t.Fatal("invalid remote candidate ID")
		}

		if stats.CandidateType != candidate.Type() {
			t.Fatal("invalid stats CandidateType")
		}

		if stats.Priority != candidate.Priority() {
			t.Fatal("invalid stats CandidateType")
		}

		if stats.IP != candidate.Address() {
			t.Fatal("invalid stats IP")
		}
	}

	if relayRemoteStat.ID != relayRemote.ID() {
		t.Fatal("missing relay remote stat")
	}

	if srflxRemoteStat.ID != srflxRemote.ID() {
		t.Fatal("missing srflx remote stat")
	}

	if prflxRemoteStat.ID != prflxRemote.ID() {
		t.Fatal("missing prflx remote stat")
	}

	if hostRemoteStat.ID != hostRemote.ID() {
		t.Fatal("missing host remote stat")
	}

	assert.NoError(t, a.Close())
}

func TestInitExtIPMapping(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()

	// a.extIPMapper should be nil by default
	a, err := NewAgent(&AgentConfig{})
	if err != nil {
		t.Fatalf("Failed to create agent: %v", err)
	}
	if a.extIPMapper != nil {
		t.Fatal("a.extIPMapper should be nil by default")
	}
	assert.NoError(t, a.Close())

	// a.extIPMapper should be nil when NAT1To1IPs is a non-nil empty array
	a, err = NewAgent(&AgentConfig{
		NAT1To1IPs:             []string{},
		NAT1To1IPCandidateType: CandidateTypeHost,
	})
	if err != nil {
		t.Fatalf("Failed to create agent: %v", err)
	}
	if a.extIPMapper != nil {
		t.Fatal("a.extIPMapper should be nil by default")
	}
	assert.NoError(t, a.Close())

	// NewAgent should return an error when 1:1 NAT for host candidate is enabled
	// but the candidate type does not appear in the CandidateTypes.
	_, err = NewAgent(&AgentConfig{
		NAT1To1IPs:             []string{"1.2.3.4"},
		NAT1To1IPCandidateType: CandidateTypeHost,
		CandidateTypes:         []CandidateType{CandidateTypeRelay},
	})
	if !errors.Is(err, ErrIneffectiveNAT1To1IPMappingHost) {
		t.Fatalf("Unexpected error: %v", err)
	}

	// NewAgent should return an error when 1:1 NAT for srflx candidate is enabled
	// but the candidate type does not appear in the CandidateTypes.
	_, err = NewAgent(&AgentConfig{
		NAT1To1IPs:             []string{"1.2.3.4"},
		NAT1To1IPCandidateType: CandidateTypeServerReflexive,
		CandidateTypes:         []CandidateType{CandidateTypeRelay},
	})
	if !errors.Is(err, ErrIneffectiveNAT1To1IPMappingSrflx) {
		t.Fatalf("Unexpected error: %v", err)
	}

	// NewAgent should return an error when 1:1 NAT for host candidate is enabled
	// along with mDNS with MulticastDNSModeQueryAndGather
	_, err = NewAgent(&AgentConfig{
		NAT1To1IPs:             []string{"1.2.3.4"},
		NAT1To1IPCandidateType: CandidateTypeHost,
		MulticastDNSMode:       MulticastDNSModeQueryAndGather,
	})
	if !errors.Is(err, ErrMulticastDNSWithNAT1To1IPMapping) {
		t.Fatalf("Unexpected error: %v", err)
	}

	// NewAgent should return if newExternalIPMapper() returns an error.
	_, err = NewAgent(&AgentConfig{
		NAT1To1IPs:             []string{"bad.2.3.4"}, // Bad IP
		NAT1To1IPCandidateType: CandidateTypeHost,
	})
	if !errors.Is(err, ErrInvalidNAT1To1IPMapping) {
		t.Fatalf("Unexpected error: %v", err)
	}
}

func TestBindingRequestTimeout(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()

	const expectedRemovalCount = 2

	a, err := NewAgent(&AgentConfig{})
	assert.NoError(t, err)

	now := time.Now()
	a.pendingBindingRequests = append(a.pendingBindingRequests, bindingRequest{
		timestamp: now, // Valid
	})
	a.pendingBindingRequests = append(a.pendingBindingRequests, bindingRequest{
		timestamp: now.Add(-3900 * time.Millisecond), // Valid
	})
	a.pendingBindingRequests = append(a.pendingBindingRequests, bindingRequest{
		timestamp: now.Add(-4100 * time.Millisecond), // Invalid
	})
	a.pendingBindingRequests = append(a.pendingBindingRequests, bindingRequest{
		timestamp: now.Add(-75 * time.Hour), // Invalid
	})

	a.invalidatePendingBindingRequests(now)
	assert.Equal(t, expectedRemovalCount, len(a.pendingBindingRequests), "Binding invalidation due to timeout did not remove the correct number of binding requests")
	assert.NoError(t, a.Close())
}

// TestAgentCredentials checks if local username fragments and passwords (if set) meet RFC standard
// and ensure it's backwards compatible with previous versions of the pion/ice
func TestAgentCredentials(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()

	// Make sure to pass Travis check by disabling the logs
	log := logging.NewDefaultLoggerFactory()
	log.DefaultLogLevel = logging.LogLevelDisabled

	// Agent should not require any of the usernames and password to be set
	// If set, they should follow the default 16/128 bits random number generator strategy

	agent, err := NewAgent(&AgentConfig{LoggerFactory: log})
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, len([]rune(agent.localUfrag))*8, 24)
	assert.GreaterOrEqual(t, len([]rune(agent.localPwd))*8, 128)
	assert.NoError(t, agent.Close())

	// Should honor RFC standards
	// Local values MUST be unguessable, with at least 128 bits of
	// random number generator output used to generate the password, and
	// at least 24 bits of output to generate the username fragment.

	_, err = NewAgent(&AgentConfig{LocalUfrag: "xx", LoggerFactory: log})
	assert.EqualError(t, err, ErrLocalUfragInsufficientBits.Error())

	_, err = NewAgent(&AgentConfig{LocalPwd: "xxxxxx", LoggerFactory: log})
	assert.EqualError(t, err, ErrLocalPwdInsufficientBits.Error())
}

// Assert that Agent on Failure deletes all existing candidates
// User can then do an ICE Restart to bring agent back
func TestConnectionStateFailedDeleteAllCandidates(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()

	lim := test.TimeOut(time.Second * 5)
	defer lim.Stop()

	oneSecond := time.Second
	KeepaliveInterval := time.Duration(0)

	cfg := &AgentConfig{
		NetworkTypes:        supportedNetworkTypes(),
		DisconnectedTimeout: &oneSecond,
		FailedTimeout:       &oneSecond,
		KeepaliveInterval:   &KeepaliveInterval,
	}

	aAgent, err := NewAgent(cfg)
	assert.NoError(t, err)

	bAgent, err := NewAgent(cfg)
	assert.NoError(t, err)

	isFailed := make(chan interface{})
	assert.NoError(t, aAgent.OnConnectionStateChange(func(c ConnectionState) {
		if c == ConnectionStateFailed {
			close(isFailed)
		}
	}))

	connect(aAgent, bAgent)
	<-isFailed

	done := make(chan struct{})
	assert.NoError(t, aAgent.run(context.Background(), func(ctx context.Context, agent *Agent) {
		assert.Equal(t, len(aAgent.remoteCandidates), 0)
		assert.Equal(t, len(aAgent.localCandidates), 0)
		close(done)
	}))
	<-done

	assert.NoError(t, aAgent.Close())
	assert.NoError(t, bAgent.Close())
}

// Assert that the ICE Agent can go directly from Connecting -> Failed on both sides
func TestConnectionStateConnectingToFailed(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()

	lim := test.TimeOut(time.Second * 5)
	defer lim.Stop()

	oneSecond := time.Second
	KeepaliveInterval := time.Duration(0)

	cfg := &AgentConfig{
		DisconnectedTimeout: &oneSecond,
		FailedTimeout:       &oneSecond,
		KeepaliveInterval:   &KeepaliveInterval,
	}

	aAgent, err := NewAgent(cfg)
	assert.NoError(t, err)

	bAgent, err := NewAgent(cfg)
	assert.NoError(t, err)

	var isFailed sync.WaitGroup
	var isChecking sync.WaitGroup

	isFailed.Add(2)
	isChecking.Add(2)

	connectionStateCheck := func(c ConnectionState) {
		switch c {
		case ConnectionStateFailed:
			isFailed.Done()
		case ConnectionStateChecking:
			isChecking.Done()
		case ConnectionStateCompleted:
			t.Errorf("Unexpected ConnectionState: %v", c)
		default:
		}
	}

	assert.NoError(t, aAgent.OnConnectionStateChange(connectionStateCheck))
	assert.NoError(t, bAgent.OnConnectionStateChange(connectionStateCheck))

	go func() {
		_, err := aAgent.Accept(context.TODO(), "InvalidFrag", "InvalidPwd")
		assert.Error(t, err)
	}()

	go func() {
		_, err := bAgent.Dial(context.TODO(), "InvalidFrag", "InvalidPwd")
		assert.Error(t, err)
	}()

	isChecking.Wait()
	isFailed.Wait()

	assert.NoError(t, aAgent.Close())
	assert.NoError(t, bAgent.Close())
}

func TestAgentRestart(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()

	lim := test.TimeOut(time.Second * 30)
	defer lim.Stop()

	oneSecond := time.Second

	t.Run("Restart During Gather", func(t *testing.T) {
		connA, connB := pipe(&AgentConfig{
			DisconnectedTimeout: &oneSecond,
			FailedTimeout:       &oneSecond,
		})

		ctx, cancel := context.WithCancel(context.Background())
		assert.NoError(t, connB.agent.OnConnectionStateChange(func(c ConnectionState) {
			if c == ConnectionStateFailed || c == ConnectionStateDisconnected {
				cancel()
			}
		}))

		connA.agent.gatheringState = GatheringStateGathering
		assert.NoError(t, connA.agent.Restart("", ""))

		<-ctx.Done()
		assert.NoError(t, connA.agent.Close())
		assert.NoError(t, connB.agent.Close())
	})

	t.Run("Restart When Closed", func(t *testing.T) {
		agent, err := NewAgent(&AgentConfig{})
		assert.NoError(t, err)
		assert.NoError(t, agent.Close())

		assert.Equal(t, ErrClosed, agent.Restart("", ""))
	})

	t.Run("Restart One Side", func(t *testing.T) {
		connA, connB := pipe(&AgentConfig{
			DisconnectedTimeout: &oneSecond,
			FailedTimeout:       &oneSecond,
		})

		ctx, cancel := context.WithCancel(context.Background())
		assert.NoError(t, connB.agent.OnConnectionStateChange(func(c ConnectionState) {
			if c == ConnectionStateFailed || c == ConnectionStateDisconnected {
				cancel()
			}
		}))
		assert.NoError(t, connA.agent.Restart("", ""))

		<-ctx.Done()
		assert.NoError(t, connA.agent.Close())
		assert.NoError(t, connB.agent.Close())
	})

	t.Run("Restart Both Sides", func(t *testing.T) {
		// Get all addresses of candidates concatenated
		generateCandidateAddressStrings := func(candidates []Candidate, err error) (out string) {
			assert.NoError(t, err)

			for _, c := range candidates {
				out += c.Address() + ":"
				out += strconv.Itoa(c.Port())
			}
			return
		}

		// Store the original candidates, confirm that after we reconnect we have new pairs
		connA, connB := pipe(&AgentConfig{
			DisconnectedTimeout: &oneSecond,
			FailedTimeout:       &oneSecond,
		})
		connAFirstCandidates := generateCandidateAddressStrings(connA.agent.GetLocalCandidates())
		connBFirstCandidates := generateCandidateAddressStrings(connB.agent.GetLocalCandidates())

		aNotifier, aConnected := onConnected()
		assert.NoError(t, connA.agent.OnConnectionStateChange(aNotifier))

		bNotifier, bConnected := onConnected()
		assert.NoError(t, connB.agent.OnConnectionStateChange(bNotifier))

		// Restart and Re-Signal
		assert.NoError(t, connA.agent.Restart("", ""))
		assert.NoError(t, connB.agent.Restart("", ""))

		// Exchange Candidates and Credentials
		ufrag, pwd, err := connB.agent.GetLocalUserCredentials()
		assert.NoError(t, err)
		assert.NoError(t, connA.agent.SetRemoteCredentials(ufrag, pwd))

		ufrag, pwd, err = connA.agent.GetLocalUserCredentials()
		assert.NoError(t, err)
		assert.NoError(t, connB.agent.SetRemoteCredentials(ufrag, pwd))

		gatherAndExchangeCandidates(connA.agent, connB.agent)

		// Wait until both have gone back to connected
		<-aConnected
		<-bConnected

		// Assert that we have new candidates each time
		assert.NotEqual(t, connAFirstCandidates, generateCandidateAddressStrings(connA.agent.GetLocalCandidates()))
		assert.NotEqual(t, connBFirstCandidates, generateCandidateAddressStrings(connB.agent.GetLocalCandidates()))

		assert.NoError(t, connA.agent.Close())
		assert.NoError(t, connB.agent.Close())
	})
}

func TestGetRemoteCredentials(t *testing.T) {
	var config AgentConfig
	a, err := NewAgent(&config)
	if err != nil {
		t.Fatalf("Error constructing ice.Agent: %v", err)
	}

	a.remoteUfrag = "remoteUfrag"
	a.remotePwd = "remotePwd"

	actualUfrag, actualPwd, err := a.GetRemoteUserCredentials()
	assert.NoError(t, err)

	assert.Equal(t, actualUfrag, a.remoteUfrag)
	assert.Equal(t, actualPwd, a.remotePwd)

	assert.NoError(t, a.Close())
}

func TestGetRemoteCandidates(t *testing.T) {
	var config AgentConfig

	a, err := NewAgent(&config)
	if err != nil {
		t.Fatalf("Error constructing ice.Agent: %v", err)
	}

	expectedCandidates := []Candidate{}

	for i := 0; i < 5; i++ {
		cfg := CandidateHostConfig{
			Network:   "udp",
			Address:   "192.168.0.2",
			Port:      1000 + i,
			Component: 1,
		}

		cand, errCand := NewCandidateHost(&cfg)
		assert.NoError(t, errCand)

		expectedCandidates = append(expectedCandidates, cand)

		a.addRemoteCandidate(cand)
	}

	actualCandidates, err := a.GetRemoteCandidates()
	assert.NoError(t, err)
	assert.ElementsMatch(t, expectedCandidates, actualCandidates)

	assert.NoError(t, a.Close())
}

func TestGetLocalCandidates(t *testing.T) {
	var config AgentConfig

	a, err := NewAgent(&config)
	if err != nil {
		t.Fatalf("Error constructing ice.Agent: %v", err)
	}

	dummyConn := &net.UDPConn{}
	expectedCandidates := []Candidate{}

	for i := 0; i < 5; i++ {
		cfg := CandidateHostConfig{
			Network:   "udp",
			Address:   "192.168.0.2",
			Port:      1000 + i,
			Component: 1,
		}

		cand, errCand := NewCandidateHost(&cfg)
		assert.NoError(t, errCand)

		expectedCandidates = append(expectedCandidates, cand)

		err = a.addCandidate(context.Background(), cand, dummyConn)
		assert.NoError(t, err)
	}

	actualCandidates, err := a.GetLocalCandidates()
	assert.NoError(t, err)
	assert.ElementsMatch(t, expectedCandidates, actualCandidates)

	assert.NoError(t, a.Close())
}

func TestCloseInConnectionStateCallback(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()

	lim := test.TimeOut(time.Second * 5)
	defer lim.Stop()

	disconnectedDuration := time.Second
	failedDuration := time.Second
	KeepaliveInterval := time.Duration(0)
	CheckInterval := 500 * time.Millisecond

	cfg := &AgentConfig{
		Urls:                []*stun.URI{},
		NetworkTypes:        supportedNetworkTypes(),
		DisconnectedTimeout: &disconnectedDuration,
		FailedTimeout:       &failedDuration,
		KeepaliveInterval:   &KeepaliveInterval,
		CheckInterval:       &CheckInterval,
	}

	aAgent, err := NewAgent(cfg)
	if err != nil {
		t.Error(err)
	}

	bAgent, err := NewAgent(cfg)
	if err != nil {
		t.Error(err)
	}

	isClosed := make(chan interface{})
	isConnected := make(chan interface{})
	err = aAgent.OnConnectionStateChange(func(c ConnectionState) {
		switch c {
		case ConnectionStateConnected:
			<-isConnected
			assert.NoError(t, aAgent.Close())
		case ConnectionStateClosed:
			close(isClosed)
		default:
		}
	})
	if err != nil {
		t.Error(err)
	}

	connect(aAgent, bAgent)
	close(isConnected)

	<-isClosed
	assert.NoError(t, bAgent.Close())
}

func TestRunTaskInConnectionStateCallback(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()

	lim := test.TimeOut(time.Second * 5)
	defer lim.Stop()

	oneSecond := time.Second
	KeepaliveInterval := time.Duration(0)
	CheckInterval := 50 * time.Millisecond

	cfg := &AgentConfig{
		Urls:                []*stun.URI{},
		NetworkTypes:        supportedNetworkTypes(),
		DisconnectedTimeout: &oneSecond,
		FailedTimeout:       &oneSecond,
		KeepaliveInterval:   &KeepaliveInterval,
		CheckInterval:       &CheckInterval,
	}

	aAgent, err := NewAgent(cfg)
	check(err)
	bAgent, err := NewAgent(cfg)
	check(err)

	isComplete := make(chan interface{})
	err = aAgent.OnConnectionStateChange(func(c ConnectionState) {
		if c == ConnectionStateConnected {
			_, _, errCred := aAgent.GetLocalUserCredentials()
			assert.NoError(t, errCred)
			assert.NoError(t, aAgent.Restart("", ""))
			close(isComplete)
		}
	})
	if err != nil {
		t.Error(err)
	}

	connect(aAgent, bAgent)

	<-isComplete
	assert.NoError(t, aAgent.Close())
	assert.NoError(t, bAgent.Close())
}

func TestRunTaskInSelectedCandidatePairChangeCallback(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()

	lim := test.TimeOut(time.Second * 5)
	defer lim.Stop()

	oneSecond := time.Second
	KeepaliveInterval := time.Duration(0)
	CheckInterval := 50 * time.Millisecond

	cfg := &AgentConfig{
		Urls:                []*stun.URI{},
		NetworkTypes:        supportedNetworkTypes(),
		DisconnectedTimeout: &oneSecond,
		FailedTimeout:       &oneSecond,
		KeepaliveInterval:   &KeepaliveInterval,
		CheckInterval:       &CheckInterval,
	}

	aAgent, err := NewAgent(cfg)
	check(err)
	bAgent, err := NewAgent(cfg)
	check(err)

	isComplete := make(chan interface{})
	isTested := make(chan interface{})
	if err = aAgent.OnSelectedCandidatePairChange(func(Candidate, Candidate) {
		go func() {
			_, _, errCred := aAgent.GetLocalUserCredentials()
			assert.NoError(t, errCred)
			close(isTested)
		}()
	}); err != nil {
		t.Error(err)
	}
	if err = aAgent.OnConnectionStateChange(func(c ConnectionState) {
		if c == ConnectionStateConnected {
			close(isComplete)
		}
	}); err != nil {
		t.Error(err)
	}

	connect(aAgent, bAgent)

	<-isComplete
	<-isTested
	assert.NoError(t, aAgent.Close())
	assert.NoError(t, bAgent.Close())
}

// Assert that a Lite agent goes to disconnected and failed
func TestLiteLifecycle(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()

	lim := test.TimeOut(time.Second * 30)
	defer lim.Stop()

	aNotifier, aConnected := onConnected()

	aAgent, err := NewAgent(&AgentConfig{
		NetworkTypes:     supportedNetworkTypes(),
		MulticastDNSMode: MulticastDNSModeDisabled,
	})
	require.NoError(t, err)
	require.NoError(t, aAgent.OnConnectionStateChange(aNotifier))

	disconnectedDuration := time.Second
	failedDuration := time.Second
	KeepaliveInterval := time.Duration(0)
	CheckInterval := 500 * time.Millisecond
	bAgent, err := NewAgent(&AgentConfig{
		Lite:                true,
		CandidateTypes:      []CandidateType{CandidateTypeHost},
		NetworkTypes:        supportedNetworkTypes(),
		MulticastDNSMode:    MulticastDNSModeDisabled,
		DisconnectedTimeout: &disconnectedDuration,
		FailedTimeout:       &failedDuration,
		KeepaliveInterval:   &KeepaliveInterval,
		CheckInterval:       &CheckInterval,
	})
	require.NoError(t, err)

	bConnected := make(chan interface{})
	bDisconnected := make(chan interface{})
	bFailed := make(chan interface{})

	require.NoError(t, bAgent.OnConnectionStateChange(func(c ConnectionState) {
		switch c {
		case ConnectionStateConnected:
			close(bConnected)
		case ConnectionStateDisconnected:
			close(bDisconnected)
		case ConnectionStateFailed:
			close(bFailed)
		default:
		}
	}))

	connectWithVNet(bAgent, aAgent)

	<-aConnected
	<-bConnected
	assert.NoError(t, aAgent.Close())

	<-bDisconnected
	<-bFailed
	assert.NoError(t, bAgent.Close())
}

func TestNilCandidate(t *testing.T) {
	a, err := NewAgent(&AgentConfig{})
	assert.NoError(t, err)

	assert.NoError(t, a.AddRemoteCandidate(nil))
	assert.NoError(t, a.Close())
}

func TestNilCandidatePair(t *testing.T) {
	a, err := NewAgent(&AgentConfig{})
	assert.NoError(t, err)

	a.setSelectedPair(nil)
	assert.NoError(t, a.Close())
}

func TestGetSelectedCandidatePair(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()

	lim := test.TimeOut(time.Second * 30)
	defer lim.Stop()

	wan, err := vnet.NewRouter(&vnet.RouterConfig{
		CIDR:          "0.0.0.0/0",
		LoggerFactory: logging.NewDefaultLoggerFactory(),
	})
	assert.NoError(t, err)

	net, err := vnet.NewNet(&vnet.NetConfig{
		StaticIPs: []string{"192.168.0.1"},
	})
	assert.NoError(t, err)
	assert.NoError(t, wan.AddNet(net))

	assert.NoError(t, wan.Start())

	cfg := &AgentConfig{
		NetworkTypes: supportedNetworkTypes(),
		Net:          net,
	}

	aAgent, err := NewAgent(cfg)
	assert.NoError(t, err)

	bAgent, err := NewAgent(cfg)
	assert.NoError(t, err)

	aAgentPair, err := aAgent.GetSelectedCandidatePair()
	assert.NoError(t, err)
	assert.Nil(t, aAgentPair)

	bAgentPair, err := bAgent.GetSelectedCandidatePair()
	assert.NoError(t, err)
	assert.Nil(t, bAgentPair)

	connect(aAgent, bAgent)

	aAgentPair, err = aAgent.GetSelectedCandidatePair()
	assert.NoError(t, err)
	assert.NotNil(t, aAgentPair)

	bAgentPair, err = bAgent.GetSelectedCandidatePair()
	assert.NoError(t, err)
	assert.NotNil(t, bAgentPair)

	assert.True(t, bAgentPair.Local.Equal(aAgentPair.Remote))
	assert.True(t, bAgentPair.Remote.Equal(aAgentPair.Local))

	assert.NoError(t, wan.Stop())
	assert.NoError(t, aAgent.Close())
	assert.NoError(t, bAgent.Close())
}

func TestAcceptAggressiveNomination(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()

	lim := test.TimeOut(time.Second * 30)
	defer lim.Stop()

	// Create a network with two interfaces
	wan, err := vnet.NewRouter(&vnet.RouterConfig{
		CIDR:          "0.0.0.0/0",
		LoggerFactory: logging.NewDefaultLoggerFactory(),
	})
	assert.NoError(t, err)

	net0, err := vnet.NewNet(&vnet.NetConfig{
		StaticIPs: []string{"192.168.0.1"},
	})
	assert.NoError(t, err)
	assert.NoError(t, wan.AddNet(net0))

	net1, err := vnet.NewNet(&vnet.NetConfig{
		StaticIPs: []string{"192.168.0.2", "192.168.0.3", "192.168.0.4"},
	})
	assert.NoError(t, err)
	assert.NoError(t, wan.AddNet(net1))

	assert.NoError(t, wan.Start())

	aNotifier, aConnected := onConnected()
	bNotifier, bConnected := onConnected()

	KeepaliveInterval := time.Hour
	cfg0 := &AgentConfig{
		NetworkTypes:     []NetworkType{NetworkTypeUDP4, NetworkTypeUDP6},
		MulticastDNSMode: MulticastDNSModeDisabled,
		Net:              net0,

		KeepaliveInterval:          &KeepaliveInterval,
		CheckInterval:              &KeepaliveInterval,
		AcceptAggressiveNomination: true,
	}

	var aAgent, bAgent *Agent
	aAgent, err = NewAgent(cfg0)
	require.NoError(t, err)
	require.NoError(t, aAgent.OnConnectionStateChange(aNotifier))

	cfg1 := &AgentConfig{
		NetworkTypes:      []NetworkType{NetworkTypeUDP4, NetworkTypeUDP6},
		MulticastDNSMode:  MulticastDNSModeDisabled,
		Net:               net1,
		KeepaliveInterval: &KeepaliveInterval,
		CheckInterval:     &KeepaliveInterval,
	}

	bAgent, err = NewAgent(cfg1)
	require.NoError(t, err)
	require.NoError(t, bAgent.OnConnectionStateChange(bNotifier))

	aConn, bConn := connect(aAgent, bAgent)

	// Ensure pair selected
	// Note: this assumes ConnectionStateConnected is thrown after selecting the final pair
	<-aConnected
	<-bConnected

	// Send new USE-CANDIDATE message with higher priority to update the selected pair
	buildMsg := func(class stun.MessageClass, username, key string, priority uint32) *stun.Message {
		msg, err1 := stun.Build(stun.NewType(stun.MethodBinding, class), stun.TransactionID,
			stun.NewUsername(username),
			stun.NewShortTermIntegrity(key),
			UseCandidate(),
			PriorityAttr(priority),
			stun.Fingerprint,
		)
		if err1 != nil {
			t.Fatal(err1)
		}

		return msg
	}

	selectedCh := make(chan Candidate, 1)
	var expectNewSelectedCandidate Candidate
	err = aAgent.OnSelectedCandidatePairChange(func(_, remote Candidate) {
		selectedCh <- remote
	})
	require.NoError(t, err)
	var bcandidates []Candidate
	bcandidates, err = bAgent.GetLocalCandidates()
	require.NoError(t, err)

	for _, c := range bcandidates {
		if c != bAgent.getSelectedPair().Local {
			if expectNewSelectedCandidate == nil {
			incr_priority:
				for _, candidates := range aAgent.remoteCandidates {
					for _, candidate := range candidates {
						if candidate.Equal(c) {
							candidate.(*CandidateHost).priorityOverride += 1000 //nolint:forcetypeassert
							break incr_priority
						}
					}
				}
				expectNewSelectedCandidate = c
			}
			_, err = c.writeTo(buildMsg(stun.ClassRequest, aAgent.localUfrag+":"+aAgent.remoteUfrag, aAgent.localPwd, c.Priority()).Raw, bAgent.getSelectedPair().Remote)
			require.NoError(t, err)
		}
	}

	time.Sleep(1 * time.Second)
	select {
	case selected := <-selectedCh:
		assert.True(t, selected.Equal(expectNewSelectedCandidate))
	default:
		t.Fatal("No selected candidate pair")
	}

	assert.NoError(t, wan.Stop())
	if !closePipe(t, aConn, bConn) {
		return
	}
}
