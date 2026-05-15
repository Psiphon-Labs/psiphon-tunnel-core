// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package ice implements the Interactive Connectivity Establishment (ICE)
// protocol defined in rfc5245.
package ice

import (
	"context"
	"fmt"
	"math"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	stunx "github.com/Psiphon-Labs/pion-ice/v4/internal/stun"
	"github.com/Psiphon-Labs/pion-ice/v4/internal/taskloop"
	"github.com/pion/logging"
	"github.com/pion/mdns/v2"
	"github.com/pion/stun/v3"
	"github.com/pion/transport/v4"
	"github.com/pion/transport/v4/packetio"
	"github.com/pion/transport/v4/stdnet"
	"github.com/pion/transport/v4/vnet"
	"github.com/pion/turn/v4"
	"golang.org/x/net/proxy"
)

type bindingRequest struct {
	timestamp       time.Time
	transactionID   [stun.TransactionIDSize]byte
	destination     net.Addr
	isUseCandidate  bool
	nominationValue *uint32 // Tracks nomination value for renomination requests
}

// Agent represents the ICE agent.
type Agent struct {
	loop *taskloop.Loop

	// constructed is set to true after the agent is fully initialized.
	// Options can check this flag to reject updates that are only valid during construction.
	constructed bool

	onConnectionStateChangeHdlr       atomic.Value // func(ConnectionState)
	onSelectedCandidatePairChangeHdlr atomic.Value // func(Candidate, Candidate)
	onCandidateHdlr                   atomic.Value // func(Candidate)

	onConnected     chan struct{}
	onConnectedOnce sync.Once

	// Force candidate to be contacted immediately (instead of waiting for task ticker)
	forceCandidateContact chan bool

	tieBreaker uint64
	lite       bool

	connectionState ConnectionState
	gatheringState  GatheringState

	mDNSMode MulticastDNSMode
	mDNSName string
	mDNSConn *mdns.Conn

	muHaveStarted sync.Mutex
	startedCh     <-chan struct{}
	startedFn     func()
	isControlling atomic.Bool

	maxBindingRequests uint16

	hostAcceptanceMinWait  time.Duration
	srflxAcceptanceMinWait time.Duration
	prflxAcceptanceMinWait time.Duration
	relayAcceptanceMinWait time.Duration
	stunGatherTimeout      time.Duration

	tcpPriorityOffset uint16
	disableActiveTCP  bool

	portMin uint16
	portMax uint16

	candidateTypes []CandidateType

	// How long connectivity checks can fail before the ICE Agent
	// goes to disconnected
	disconnectedTimeout time.Duration

	// How long connectivity checks can fail before the ICE Agent
	// goes to failed
	failedTimeout time.Duration

	// How often should we send keepalive packets?
	// 0 means never
	keepaliveInterval time.Duration

	// How often should we run our internal taskLoop to check for state changes when connecting
	checkInterval time.Duration

	localUfrag      string
	localPwd        string
	localCandidates map[NetworkType][]Candidate

	remoteUfrag      string
	remotePwd        string
	remoteCandidates map[NetworkType][]Candidate

	checklist  []*CandidatePair
	nextPairID uint64
	pairsByID  map[uint64]*CandidatePair

	selectorLock sync.RWMutex
	selector     pairCandidateSelector

	selectedPair atomic.Value // *CandidatePair

	urls                []*stun.URI
	networkTypes        []NetworkType
	addressRewriteRules []AddressRewriteRule

	buf *packetio.Buffer

	// LRU of outbound Binding request Transaction IDs
	pendingBindingRequests []bindingRequest

	// Address rewrite (1:1) IP mapping
	addressRewriteMapper *addressRewriteMapper

	// Callback that allows user to implement custom behavior
	// for STUN Binding Requests
	userBindingRequestHandler func(m *stun.Message, local, remote Candidate, pair *CandidatePair) bool

	gatherCandidateCancel func()
	gatherCandidateDone   chan struct{}

	connectionStateNotifier       *handlerNotifier
	candidateNotifier             *handlerNotifier
	selectedCandidatePairNotifier *handlerNotifier

	loggerFactory logging.LoggerFactory
	log           logging.LeveledLogger

	net         transport.Net
	tcpMux      TCPMux
	udpMux      UDPMux
	udpMuxSrflx UniversalUDPMux

	interfaceFilter func(string) (keep bool)
	ipFilter        func(net.IP) (keep bool)
	includeLoopback bool

	insecureSkipVerify bool

	proxyDialer proxy.Dialer

	enableUseCandidateCheckPriority bool

	// Renomination support
	enableRenomination       bool
	nominationValueGenerator func() uint32
	nominationAttribute      stun.AttrType

	// Continual gathering support
	continualGatheringPolicy ContinualGatheringPolicy
	networkMonitorInterval   time.Duration
	lastKnownInterfaces      map[string]netip.Addr // map[iface+ip] for deduplication

	// Automatic renomination
	automaticRenomination bool
	renominationInterval  time.Duration
	lastRenominationTime  time.Time

	turnClientFactory func(*turn.ClientConfig) (turnClient, error)
}

// NewAgent creates a new Agent.
//
// Deprecated: use NewAgentWithOptions instead.
func NewAgent(config *AgentConfig) (*Agent, error) {
	return newAgentFromConfig(config)
}

// NewAgentWithOptions creates a new Agent with options only.
func NewAgentWithOptions(opts ...AgentOption) (*Agent, error) {
	return newAgentFromConfig(&AgentConfig{}, opts...)
}

func newAgentFromConfig(config *AgentConfig, opts ...AgentOption) (*Agent, error) {
	if config == nil {
		config = &AgentConfig{}
	}

	agent, err := createAgentBase(config)
	if err != nil {
		return nil, err
	}

	agent.localUfrag = config.LocalUfrag
	agent.localPwd = config.LocalPwd
	if config.NAT1To1IPs != nil {
		if err := validateLegacyNAT1To1IPs(config.NAT1To1IPs); err != nil {
			return nil, err
		}

		typ := CandidateTypeHost
		if config.NAT1To1IPCandidateType != CandidateTypeUnspecified {
			typ = config.NAT1To1IPCandidateType
		}

		rules, err := legacyNAT1To1Rules(config.NAT1To1IPs, typ)
		if err != nil {
			return nil, err
		}
		agent.addressRewriteRules = rules
	}

	return newAgentWithConfig(agent, opts...)
}

func validateLegacyNAT1To1IPs(ips []string) error {
	var hasIPv4CatchAll, hasIPv6CatchAll bool

	for _, mapping := range ips {
		trimmed := strings.TrimSpace(mapping)
		var err error
		hasIPv4CatchAll, hasIPv6CatchAll, err = validateLegacyNAT1To1Entry(trimmed, hasIPv4CatchAll, hasIPv6CatchAll)
		if err != nil {
			return err
		}
	}

	return nil
}

func validateLegacyNAT1To1Entry(mapping string, hasIPv4CatchAll, hasIPv6CatchAll bool) (bool, bool, error) {
	if mapping == "" {
		return hasIPv4CatchAll, hasIPv6CatchAll, nil
	}

	parts := strings.Split(mapping, "/")
	if len(parts) == 0 || len(parts) > 2 {
		return hasIPv4CatchAll, hasIPv6CatchAll, ErrInvalidNAT1To1IPMapping
	}

	_, isIPv4, err := validateIPString(parts[0])
	if err != nil {
		return hasIPv4CatchAll, hasIPv6CatchAll, err
	}

	if len(parts) == 2 {
		if _, _, err := validateIPString(strings.TrimSpace(parts[1])); err != nil {
			return hasIPv4CatchAll, hasIPv6CatchAll, err
		}

		return hasIPv4CatchAll, hasIPv6CatchAll, nil
	}

	if isIPv4 {
		if hasIPv4CatchAll {
			return hasIPv4CatchAll, hasIPv6CatchAll, ErrInvalidNAT1To1IPMapping
		}

		return true, hasIPv6CatchAll, nil
	}

	if hasIPv6CatchAll {
		return hasIPv4CatchAll, hasIPv6CatchAll, ErrInvalidNAT1To1IPMapping
	}

	return hasIPv4CatchAll, true, nil
}

func legacyNAT1To1Rules(ips []string, candidateType CandidateType) ([]AddressRewriteRule, error) {
	var rules []AddressRewriteRule

	for _, mapping := range ips {
		trimmed := strings.TrimSpace(mapping)
		if trimmed == "" {
			continue
		}

		parts := strings.Split(trimmed, "/")
		switch len(parts) {
		case 1:
			rules = append(rules, AddressRewriteRule{
				External:        []string{parts[0]},
				AsCandidateType: candidateType,
			})
		case 2:
			ext := strings.TrimSpace(parts[0])
			local := strings.TrimSpace(parts[1])
			if ext == "" || local == "" {
				return nil, ErrInvalidNAT1To1IPMapping
			}

			if _, _, err := validateIPString(ext); err != nil {
				return nil, err
			}
			if _, _, err := validateIPString(local); err != nil {
				return nil, err
			}

			rules = append(rules, AddressRewriteRule{
				External:        []string{ext},
				Local:           local,
				AsCandidateType: candidateType,
			})
		default:
			return nil, ErrInvalidNAT1To1IPMapping
		}
	}

	return rules, nil
}

func createAgentBase(config *AgentConfig) (*Agent, error) {
	if config.PortMax < config.PortMin {
		return nil, ErrPort
	}

	mDNSName, mDNSMode, err := setupMDNSConfig(config)
	if err != nil {
		return nil, err
	}

	loggerFactory := config.LoggerFactory
	if loggerFactory == nil {
		loggerFactory = logging.NewDefaultLoggerFactory()
	}
	log := loggerFactory.NewLogger("ice")

	startedCtx, startedFn := context.WithCancel(context.Background())

	agent := &Agent{
		tieBreaker:                      globalMathRandomGenerator.Uint64(),
		lite:                            config.Lite,
		gatheringState:                  GatheringStateNew,
		connectionState:                 ConnectionStateNew,
		localCandidates:                 make(map[NetworkType][]Candidate),
		remoteCandidates:                make(map[NetworkType][]Candidate),
		pairsByID:                       make(map[uint64]*CandidatePair),
		urls:                            config.Urls,
		networkTypes:                    config.NetworkTypes,
		onConnected:                     make(chan struct{}),
		buf:                             packetio.NewBuffer(),
		startedCh:                       startedCtx.Done(),
		startedFn:                       startedFn,
		portMin:                         config.PortMin,
		portMax:                         config.PortMax,
		loggerFactory:                   loggerFactory,
		log:                             log,
		net:                             config.Net,
		proxyDialer:                     config.ProxyDialer,
		tcpMux:                          config.TCPMux,
		udpMux:                          config.UDPMux,
		udpMuxSrflx:                     config.UDPMuxSrflx,
		mDNSMode:                        mDNSMode,
		mDNSName:                        mDNSName,
		gatherCandidateCancel:           func() {},
		forceCandidateContact:           make(chan bool, 1),
		interfaceFilter:                 config.InterfaceFilter,
		ipFilter:                        config.IPFilter,
		insecureSkipVerify:              config.InsecureSkipVerify,
		includeLoopback:                 config.IncludeLoopback,
		disableActiveTCP:                config.DisableActiveTCP,
		userBindingRequestHandler:       config.BindingRequestHandler,
		enableUseCandidateCheckPriority: config.EnableUseCandidateCheckPriority,
		enableRenomination:              false,
		nominationValueGenerator:        nil,
		nominationAttribute:             stun.AttrType(0x0030), // Default value
		continualGatheringPolicy:        GatherOnce,            // Default to GatherOnce
		networkMonitorInterval:          2 * time.Second,
		lastKnownInterfaces:             make(map[string]netip.Addr),
		automaticRenomination:           false,
		renominationInterval:            3 * time.Second, // Default matching libwebrtc
		turnClientFactory:               defaultTurnClient,
	}

	config.initWithDefaults(agent)

	return agent, nil
}

func applyAddressRewriteMapping(agent *Agent) error {
	mapper, err := newAddressRewriteMapper(agent.addressRewriteRules)
	if err != nil {
		return err
	}

	agent.addressRewriteMapper = mapper
	if agent.addressRewriteMapper == nil {
		return nil
	}

	if agent.addressRewriteMapper.hasCandidateType(CandidateTypeHost) {
		// for mDNS QueryAndGather we never advertise rewritten host IPs to avoid
		// leaking local addresses, this matches the legacy NAT1:1 behavior.
		if agent.mDNSMode == MulticastDNSModeQueryAndGather {
			return ErrMulticastDNSWithNAT1To1IPMapping
		}
		// surface misconfiguration when host candidates are disabled but a host
		// rewrite rule was provided.
		if !containsCandidateType(CandidateTypeHost, agent.candidateTypes) {
			return ErrIneffectiveNAT1To1IPMappingHost
		}
	}

	if agent.addressRewriteMapper.hasCandidateType(CandidateTypeServerReflexive) {
		// surface misconfiguration when srflx candidates are disabled but a srflx
		// rewrite rule was provided.
		if !containsCandidateType(CandidateTypeServerReflexive, agent.candidateTypes) {
			return ErrIneffectiveNAT1To1IPMappingSrflx
		}
	}

	return nil
}

// setupMDNSConfig validates and returns mDNS configuration.
func setupMDNSConfig(config *AgentConfig) (string, MulticastDNSMode, error) {
	mDNSName := config.MulticastDNSHostName
	if mDNSName == "" {
		var err error
		if mDNSName, err = generateMulticastDNSName(); err != nil {
			return "", 0, err
		}
	}

	if !strings.HasSuffix(mDNSName, ".local") || len(strings.Split(mDNSName, ".")) != 2 {
		return "", 0, ErrInvalidMulticastDNSHostName
	}

	mDNSMode := config.MulticastDNSMode
	if mDNSMode == 0 {
		mDNSMode = MulticastDNSModeQueryOnly
	}

	return mDNSName, mDNSMode, nil
}

// newAgentWithConfig finalizes a pre-configured agent with optional overrides.
//
//nolint:gocognit,cyclop
func newAgentWithConfig(agent *Agent, opts ...AgentOption) (*Agent, error) {
	var err error

	for _, opt := range opts {
		if err = opt(agent); err != nil {
			return nil, err
		}
	}

	agent.connectionStateNotifier = &handlerNotifier{
		connectionStateFunc: agent.onConnectionStateChange,
		done:                make(chan struct{}),
	}
	agent.candidateNotifier = &handlerNotifier{candidateFunc: agent.onCandidate, done: make(chan struct{})}
	agent.selectedCandidatePairNotifier = &handlerNotifier{
		candidatePairFunc: agent.onSelectedCandidatePairChange,
		done:              make(chan struct{}),
	}

	if agent.net == nil {
		agent.net, err = stdnet.NewNet()
		if err != nil {
			return nil, fmt.Errorf("failed to create network: %w", err)
		}
	} else if _, isVirtual := agent.net.(*vnet.Net); isVirtual {
		agent.log.Warn("Virtual network is enabled")
		if agent.mDNSMode != MulticastDNSModeDisabled {
			agent.log.Warn("Virtual network does not support mDNS yet")
		}
	}

	localIfcs, _, err := localInterfaces(
		agent.net,
		agent.interfaceFilter,
		agent.ipFilter,
		agent.networkTypes,
		agent.includeLoopback,
	)
	if err != nil {
		return nil, fmt.Errorf("error getting local interfaces: %w", err)
	}

	mDNSLocalAddress := mDNSLocalAddressFromTCPMux(agent.tcpMux, agent.networkTypes)

	// Opportunistic mDNS: If we can't open the connection, that's ok: we
	// can continue without it.
	if agent.mDNSConn, agent.mDNSMode, err = createMulticastDNS(
		agent.net,
		agent.networkTypes,
		localIfcs,
		agent.includeLoopback,
		mDNSLocalAddress,
		agent.mDNSMode,
		agent.mDNSName,
		agent.log,
		agent.loggerFactory,
	); err != nil {
		agent.log.Warnf("Failed to initialize mDNS %s: %v", agent.mDNSName, err)
	}

	// Make sure the buffer doesn't grow indefinitely.
	// NOTE: We actually won't get anywhere close to this limit.
	// SRTP will constantly read from the endpoint and drop packets if it's full.
	agent.buf.SetLimitSize(maxBufferSize)

	if agent.lite && (len(agent.candidateTypes) != 1 || agent.candidateTypes[0] != CandidateTypeHost) {
		agent.closeMulticastConn()

		return nil, ErrLiteUsingNonHostCandidates
	}

	if len(agent.urls) > 0 &&
		!containsCandidateType(CandidateTypeServerReflexive, agent.candidateTypes) &&
		!containsCandidateType(CandidateTypeRelay, agent.candidateTypes) {
		agent.closeMulticastConn()

		return nil, ErrUselessUrlsProvided
	}

	if err = applyAddressRewriteMapping(agent); err != nil {
		agent.closeMulticastConn()

		return nil, err
	}

	agent.loop = taskloop.New(func() {
		agent.gatherCandidateCancel()
		if agent.gatherCandidateDone != nil {
			<-agent.gatherCandidateDone
		}

		agent.removeUfragFromMux()
		agent.deleteAllCandidates()
		agent.startedFn()

		if err := agent.buf.Close(); err != nil {
			agent.log.Warnf("Failed to close buffer: %v", err)
		}

		agent.closeMulticastConn()
		agent.updateConnectionState(ConnectionStateClosed)
	})

	// Restart is also used to initialize the agent for the first time
	if err := agent.Restart(agent.localUfrag, agent.localPwd); err != nil {
		agent.closeMulticastConn()
		_ = agent.Close()

		return nil, err
	}

	agent.constructed = true

	return agent, nil
}

func mDNSLocalAddressFromTCPMux(tcpMux TCPMux, networkTypes []NetworkType) net.IP {
	if tcpMux == nil || !allNetworkTypesTCP(networkTypes) {
		return nil
	}

	tcpAddr, ok := localTCPAddrFromMux(tcpMux)
	if !ok {
		return nil
	}

	localAddr, ok := mDNSLocalAddressFromIP(tcpAddr.IP)
	if !ok {
		return nil
	}

	return localAddr
}

func allNetworkTypesTCP(networkTypes []NetworkType) bool {
	if len(networkTypes) == 0 {
		return false
	}

	for _, networkType := range networkTypes {
		if !networkType.IsTCP() {
			return false
		}
	}

	return true
}

func localTCPAddrFromMux(tcpMux TCPMux) (*net.TCPAddr, bool) {
	addrProvider, ok := tcpMux.(interface{ LocalAddr() net.Addr })
	if !ok {
		return nil, false
	}

	tcpAddr, ok := addrProvider.LocalAddr().(*net.TCPAddr)
	if !ok || tcpAddr.IP == nil || tcpAddr.IP.IsUnspecified() {
		return nil, false
	}

	return tcpAddr, true
}

func mDNSLocalAddressFromIP(ip net.IP) (net.IP, bool) {
	parsed, ok := netip.AddrFromSlice(ip)
	if !ok {
		return nil, false
	}

	parsed = parsed.Unmap()
	if parsed.Is6() && (parsed.IsLinkLocalUnicast() || parsed.IsLinkLocalMulticast()) {
		// mdns.Config.LocalAddress has no zone support for link-local IPv6.
		return nil, false
	}

	return parsed.AsSlice(), true
}

func (a *Agent) startConnectivityChecks(isControlling bool, remoteUfrag, remotePwd string) error {
	a.muHaveStarted.Lock()
	defer a.muHaveStarted.Unlock()
	select {
	case <-a.startedCh:
		return ErrMultipleStart
	default:
	}
	if err := a.SetRemoteCredentials(remoteUfrag, remotePwd); err != nil { //nolint:contextcheck
		return err
	}

	a.log.Debugf("Started agent: isControlling? %t, remoteUfrag: %q, remotePwd: %q", isControlling, remoteUfrag, remotePwd)

	return a.loop.Run(a.loop, func(_ context.Context) {
		a.isControlling.Store(isControlling)
		a.remoteUfrag = remoteUfrag
		a.remotePwd = remotePwd
		a.setSelector()

		a.startedFn()

		a.updateConnectionState(ConnectionStateChecking)

		a.requestConnectivityCheck()
		go a.connectivityChecks() //nolint:contextcheck
	})
}

func (a *Agent) connectivityChecks() { //nolint:cyclop
	lastConnectionState := ConnectionState(0)
	checkingDuration := time.Time{}

	contact := func() {
		if err := a.loop.Run(a.loop, func(_ context.Context) {
			defer func() {
				lastConnectionState = a.connectionState
			}()

			switch a.connectionState {
			case ConnectionStateFailed:
				// The connection is currently failed so don't send any checks
				// In the future it may be restarted though
				return
			case ConnectionStateChecking:
				// We have just entered checking for the first time so update our checking timer
				if lastConnectionState != a.connectionState {
					checkingDuration = time.Now()
				}

				// We have been in checking longer then Disconnect+Failed timeout, set the connection to Failed
				if time.Since(checkingDuration) > a.disconnectedTimeout+a.failedTimeout {
					a.updateConnectionState(ConnectionStateFailed)

					return
				}
			default:
			}

			a.getSelector().ContactCandidates()
		}); err != nil {
			a.log.Warnf("Failed to start connectivity checks: %v", err)
		}
	}

	timer := time.NewTimer(math.MaxInt64)
	timer.Stop()

	for {
		interval := defaultKeepaliveInterval

		updateInterval := func(x time.Duration) {
			if x != 0 && (interval == 0 || interval > x) {
				interval = x
			}
		}

		switch lastConnectionState {
		case ConnectionStateNew, ConnectionStateChecking: // While connecting, check candidates more frequently
			updateInterval(a.checkInterval)
		case ConnectionStateConnected, ConnectionStateDisconnected:
			updateInterval(a.keepaliveInterval)
		default:
		}
		// Ensure we run our task loop as quickly as the minimum of our various configured timeouts
		updateInterval(a.disconnectedTimeout)
		updateInterval(a.failedTimeout)

		timer.Reset(interval)

		select {
		case <-a.forceCandidateContact:
			if !timer.Stop() {
				<-timer.C
			}
			contact()
		case <-timer.C:
			contact()
		case <-a.loop.Done():
			timer.Stop()

			return
		}
	}
}

func (a *Agent) updateConnectionState(newState ConnectionState) {
	if a.connectionState != newState {
		// Connection has gone to failed, release all gathered candidates
		if newState == ConnectionStateFailed {
			a.removeUfragFromMux()
			a.checklist = make([]*CandidatePair, 0)
			a.pairsByID = make(map[uint64]*CandidatePair)
			a.pendingBindingRequests = make([]bindingRequest, 0)
			a.setSelectedPair(nil)
			a.deleteAllCandidates()
		}

		a.log.Infof("Setting new connection state: %s", newState)
		a.connectionState = newState
		a.connectionStateNotifier.EnqueueConnectionState(newState)
	}
}

func (a *Agent) setSelectedPair(pair *CandidatePair) {
	if pair == nil {
		var nilPair *CandidatePair
		a.selectedPair.Store(nilPair)
		a.log.Tracef("Unset selected candidate pair")

		return
	}

	pair.nominated = true
	a.selectedPair.Store(pair)
	a.log.Tracef("Set selected candidate pair: %s", pair)

	// Signal connected: notify any Connect() calls waiting on onConnected
	a.onConnectedOnce.Do(func() { close(a.onConnected) })

	// Update connection state to Connected and notify state change handlers
	a.updateConnectionState(ConnectionStateConnected)

	// Notify when the selected candidate pair changes
	a.selectedCandidatePairNotifier.EnqueueSelectedCandidatePair(pair)
}

func (a *Agent) pingAllCandidates() {
	a.log.Trace("Pinging all candidates")

	if len(a.checklist) == 0 {
		a.log.Warn("Failed to ping without candidate pairs. Connection is not possible yet.")
	}

	for _, p := range a.checklist {
		if p.state == CandidatePairStateWaiting {
			p.state = CandidatePairStateInProgress
		} else if p.state != CandidatePairStateInProgress {
			continue
		}

		if p.bindingRequestCount > a.maxBindingRequests {
			a.log.Tracef("Maximum requests reached for pair %s, marking it as failed", p)
			p.state = CandidatePairStateFailed
		} else {
			a.getSelector().PingCandidate(p.Local, p.Remote)
			p.bindingRequestCount++
		}
	}
}

// keepAliveCandidatesForRenomination pings all candidate pairs to keep them tested
// and ready for automatic renomination. Unlike pingAllCandidates, this:
// - Pings pairs in succeeded state to keep RTT measurements fresh
// - Ignores maxBindingRequests limit (we want to keep testing alternate paths)
// - Only pings pairs that are not failed.
func (a *Agent) keepAliveCandidatesForRenomination() {
	a.log.Trace("Keep alive candidates for automatic renomination")

	if len(a.checklist) == 0 {
		return
	}

	for _, pair := range a.checklist {
		switch pair.state {
		case CandidatePairStateFailed:
			// Skip failed pairs
			continue
		case CandidatePairStateWaiting:
			// Transition waiting pairs to in-progress
			pair.state = CandidatePairStateInProgress
		case CandidatePairStateInProgress, CandidatePairStateSucceeded:
			// Continue pinging in-progress and succeeded pairs
		}

		// Ping all non-failed pairs (including succeeded ones)
		// to keep RTT measurements fresh for renomination decisions
		a.getSelector().PingCandidate(pair.Local, pair.Remote)
	}
}

func (a *Agent) getBestAvailableCandidatePair() *CandidatePair {
	var best *CandidatePair
	for _, p := range a.checklist {
		if p.state == CandidatePairStateFailed {
			continue
		}

		if best == nil {
			best = p
		} else if best.priority() < p.priority() {
			best = p
		}
	}

	return best
}

func (a *Agent) getBestValidCandidatePair() *CandidatePair {
	var best *CandidatePair
	for _, p := range a.checklist {
		if p.state != CandidatePairStateSucceeded {
			continue
		}

		if best == nil {
			best = p
		} else if best.priority() < p.priority() {
			best = p
		}
	}

	return best
}

func (a *Agent) addPair(local, remote Candidate) *CandidatePair {
	a.nextPairID++
	p := newCandidatePair(local, remote, a.isControlling.Load())
	p.id = a.nextPairID
	a.checklist = append(a.checklist, p)
	a.pairsByID[p.id] = p

	return p
}

func (a *Agent) findPair(local, remote Candidate) *CandidatePair {
	for _, p := range a.checklist {
		if p.Local.Equal(local) && p.Remote.Equal(remote) {
			return p
		}
	}

	return nil
}

// validateSelectedPair checks if the selected pair is (still) valid
// Note: the caller should hold the agent lock.
func (a *Agent) validateSelectedPair() bool {
	selectedPair := a.getSelectedPair()
	if selectedPair == nil {
		return false
	}

	disconnectedTime := time.Since(selectedPair.Remote.LastReceived())

	// Only allow transitions to failed if a.failedTimeout is non-zero
	totalTimeToFailure := a.failedTimeout
	if totalTimeToFailure != 0 {
		totalTimeToFailure += a.disconnectedTimeout
	}

	a.updateConnectionState(a.connectionStateForDisconnection(disconnectedTime, totalTimeToFailure))

	return true
}

func (a *Agent) connectionStateForDisconnection(
	disconnectedTime time.Duration,
	totalTimeToFailure time.Duration,
) ConnectionState {
	disconnected := a.disconnectedTimeout != 0 && disconnectedTime > a.disconnectedTimeout
	failed := totalTimeToFailure != 0 && disconnectedTime > totalTimeToFailure

	switch {
	case failed:
		if disconnected && a.connectionState != ConnectionStateDisconnected && a.connectionState != ConnectionStateFailed {
			// If we never reported disconnected but both thresholds are already exceeded,
			// emit disconnected first so callers can observe both transitions.
			return ConnectionStateDisconnected
		}

		return ConnectionStateFailed
	case disconnected:
		return ConnectionStateDisconnected
	default:
		return ConnectionStateConnected
	}
}

// checkKeepalive sends STUN Binding Indications to the selected pair
// if no packet has been sent on that pair in the last keepaliveInterval
// Note: the caller should hold the agent lock.
func (a *Agent) checkKeepalive() {
	selectedPair := a.getSelectedPair()
	if selectedPair == nil {
		return
	}

	if a.keepaliveInterval != 0 {
		// We use binding request instead of indication to support refresh consent schemas
		// see https://tools.ietf.org/html/rfc7675
		a.getSelector().PingCandidate(selectedPair.Local, selectedPair.Remote)
	}
}

// AddRemoteCandidate adds a new remote candidate.
func (a *Agent) AddRemoteCandidate(cand Candidate) error {
	if cand == nil {
		return nil
	}

	// TCP Candidates with TCP type active will probe server passive ones, so
	// no need to do anything with them.
	if cand.TCPType() == TCPTypeActive {
		a.log.Infof("Ignoring remote candidate with tcpType active: %s", cand)

		return nil
	}

	// If we have a mDNS Candidate lets fully resolve it before adding it locally
	if cand.Type() == CandidateTypeHost && strings.HasSuffix(cand.Address(), ".local") {
		if a.mDNSMode == MulticastDNSModeDisabled {
			a.log.Warnf("Remote mDNS candidate added, but mDNS is disabled: (%s)", cand.Address())

			return nil
		}

		hostCandidate, ok := cand.(*CandidateHost)
		if !ok {
			return ErrAddressParseFailed
		}

		go a.resolveAndAddMulticastCandidate(hostCandidate)

		return nil
	}

	go func() {
		if err := a.loop.Run(a.loop, func(_ context.Context) {
			// nolint: contextcheck
			a.addRemoteCandidate(cand)
		}); err != nil {
			a.log.Warnf("Failed to add remote candidate %s: %v", cand.Address(), err)

			return
		}
	}()

	return nil
}

func (a *Agent) resolveAndAddMulticastCandidate(cand *CandidateHost) {
	if a.mDNSConn == nil {
		return
	}

	ctx, cancel := context.WithTimeout(a.loop, a.mDNSQueryTimeout())
	defer cancel()

	_, src, err := a.mDNSConn.QueryAddr(ctx, cand.Address())
	if err != nil {
		a.log.Warnf("Failed to discover mDNS candidate %s: %v", cand.Address(), err)

		return
	}

	if err = cand.setIPAddr(src); err != nil {
		a.log.Warnf("Failed to discover mDNS candidate %s: %v", cand.Address(), err)

		return
	}

	if err = a.loop.Run(a.loop, func(_ context.Context) {
		// nolint: contextcheck
		a.addRemoteCandidate(cand)
	}); err != nil {
		a.log.Warnf("Failed to add mDNS candidate %s: %v", cand.Address(), err)

		return
	}
}

func (a *Agent) mDNSQueryTimeout() time.Duration {
	if a.stunGatherTimeout > 0 {
		return a.stunGatherTimeout
	}

	return defaultSTUNGatherTimeout
}

func (a *Agent) requestConnectivityCheck() {
	select {
	case a.forceCandidateContact <- true:
	default:
	}
}

func (a *Agent) addRemotePassiveTCPCandidate(remoteCandidate Candidate) {
	_, localIPs, err := localInterfaces(
		a.net,
		a.interfaceFilter,
		a.ipFilter,
		[]NetworkType{remoteCandidate.NetworkType()},
		a.includeLoopback,
	)
	if err != nil {
		a.log.Warnf("Failed to iterate local interfaces, host candidates will not be gathered %s", err)

		return
	}

	for i := range localIPs {
		ip, _, _, err := parseAddr(remoteCandidate.addr())
		if err != nil {
			a.log.Warnf("Failed to parse address: %s; error: %s", remoteCandidate.addr(), err)

			continue
		}

		dialIP := remoteDialIPForLocalInterface(ip, localIPs[i].addr)

		conn := newActiveTCPConn(
			a.loop,
			net.JoinHostPort(localIPs[i].addr.String(), "0"),
			netip.AddrPortFrom(dialIP, uint16(remoteCandidate.Port())), //nolint:gosec // G115, no overflow, a port
			a.log,
		)

		tcpAddr, ok := conn.LocalAddr().(*net.TCPAddr)
		if !ok {
			closeConnAndLog(conn, a.log, "Failed to create Active ICE-TCP Candidate: %v", errInvalidAddress)

			continue
		}

		localCandidate, err := NewCandidateHost(&CandidateHostConfig{
			Network:   remoteCandidate.NetworkType().String(),
			Address:   localIPs[i].addr.String(),
			Port:      tcpAddr.Port,
			Component: ComponentRTP,
			TCPType:   TCPTypeActive,
		})
		if err != nil {
			closeConnAndLog(conn, a.log, "Failed to create Active ICE-TCP Candidate: %v", err)

			continue
		}

		localCandidate.start(a, conn, a.startedCh)
		a.localCandidates[localCandidate.NetworkType()] = append(
			a.localCandidates[localCandidate.NetworkType()],
			localCandidate,
		)
		a.candidateNotifier.EnqueueCandidate(localCandidate)

		a.addPair(localCandidate, remoteCandidate)
	}
}

func remoteDialIPForLocalInterface(remoteIP, localIP netip.Addr) netip.Addr {
	if remoteIP.Is6() &&
		remoteIP.Zone() == "" &&
		(remoteIP.IsLinkLocalUnicast() || remoteIP.IsLinkLocalMulticast()) {
		if zone := localIP.Zone(); zone != "" {
			return remoteIP.WithZone(zone)
		}
	}

	return remoteIP
}

// addRemoteCandidate assumes you are holding the lock (must be execute using a.run).
func (a *Agent) addRemoteCandidate(cand Candidate) { //nolint:cyclop
	set := a.remoteCandidates[cand.NetworkType()]

	for _, candidate := range set {
		if candidate.Equal(cand) {
			return
		}
	}

	acceptRemotePassiveTCPCandidate := false
	// Assert that TCP4 or TCP6 is a enabled NetworkType locally
	if !a.disableActiveTCP && cand.TCPType() == TCPTypePassive {
		for _, networkType := range a.networkTypes {
			if cand.NetworkType() == networkType {
				acceptRemotePassiveTCPCandidate = true
			}
		}
	}

	if acceptRemotePassiveTCPCandidate {
		a.addRemotePassiveTCPCandidate(cand)
	}

	set = append(set, cand)
	a.remoteCandidates[cand.NetworkType()] = set

	if cand.TCPType() != TCPTypePassive {
		if localCandidates, ok := a.localCandidates[cand.NetworkType()]; ok {
			for _, localCandidate := range localCandidates {
				a.addPair(localCandidate, cand)
			}
		}
	}

	a.requestConnectivityCheck()
}

func (a *Agent) addCandidate(ctx context.Context, cand Candidate, candidateConn net.PacketConn) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	return a.loop.Run(ctx, func(context.Context) {
		set := a.localCandidates[cand.NetworkType()]
		for _, candidate := range set {
			if candidate.Equal(cand) {
				a.log.Debugf("Ignore duplicate candidate: %s", cand)
				if err := cand.close(); err != nil {
					a.log.Warnf("Failed to close duplicate candidate: %v", err)
				}
				if err := candidateConn.Close(); err != nil {
					a.log.Warnf("Failed to close duplicate candidate connection: %v", err)
				}

				return
			}
		}

		a.setCandidateExtensions(cand)
		cand.start(a, candidateConn, a.startedCh)

		set = append(set, cand)
		a.localCandidates[cand.NetworkType()] = set

		if remoteCandidates, ok := a.remoteCandidates[cand.NetworkType()]; ok {
			for _, remoteCandidate := range remoteCandidates {
				a.addPair(cand, remoteCandidate)
			}
		}

		a.requestConnectivityCheck()

		if !cand.filterForLocationTracking() {
			a.candidateNotifier.EnqueueCandidate(cand)
		}
	})
}

func (a *Agent) setCandidateExtensions(cand Candidate) {
	err := cand.AddExtension(CandidateExtension{
		Key:   "ufrag",
		Value: a.localUfrag,
	})
	if err != nil {
		a.log.Errorf("Failed to add ufrag extension to candidate: %v", err)
	}
}

// GetRemoteCandidates returns the remote candidates.
func (a *Agent) GetRemoteCandidates() ([]Candidate, error) {
	var res []Candidate

	err := a.loop.Run(a.loop, func(_ context.Context) {
		var candidates []Candidate
		for _, set := range a.remoteCandidates {
			candidates = append(candidates, set...)
		}
		res = candidates
	})
	if err != nil {
		return nil, err
	}

	return res, nil
}

// GetLocalCandidates returns the local candidates.
func (a *Agent) GetLocalCandidates() ([]Candidate, error) {
	var res []Candidate

	err := a.loop.Run(a.loop, func(_ context.Context) {
		var candidates []Candidate
		for _, set := range a.localCandidates {
			for _, c := range set {
				if c.filterForLocationTracking() {
					continue
				}
				candidates = append(candidates, c)
			}
		}
		res = candidates
	})
	if err != nil {
		return nil, err
	}

	return res, nil
}

// GetGatheringState returns the current gathering state of the Agent.
func (a *Agent) GetGatheringState() (GatheringState, error) {
	var state GatheringState
	err := a.loop.Run(a.loop, func(_ context.Context) {
		state = a.gatheringState
	})
	if err != nil {
		return GatheringStateUnknown, err
	}

	return state, nil
}

// GetLocalUserCredentials returns the local user credentials.
func (a *Agent) GetLocalUserCredentials() (frag string, pwd string, err error) {
	valSet := make(chan struct{})
	err = a.loop.Run(a.loop, func(_ context.Context) {
		frag = a.localUfrag
		pwd = a.localPwd
		close(valSet)
	})

	if err == nil {
		<-valSet
	}

	return
}

// GetRemoteUserCredentials returns the remote user credentials.
func (a *Agent) GetRemoteUserCredentials() (frag string, pwd string, err error) {
	valSet := make(chan struct{})
	err = a.loop.Run(a.loop, func(_ context.Context) {
		frag = a.remoteUfrag
		pwd = a.remotePwd
		close(valSet)
	})

	if err == nil {
		<-valSet
	}

	return
}

func (a *Agent) removeUfragFromMux() {
	if a.tcpMux != nil {
		a.tcpMux.RemoveConnByUfrag(a.localUfrag)
	}
	if a.udpMux != nil {
		a.udpMux.RemoveConnByUfrag(a.localUfrag)
	}
	if a.udpMuxSrflx != nil {
		a.udpMuxSrflx.RemoveConnByUfrag(a.localUfrag)
	}
}

// Close cleans up the Agent.
func (a *Agent) Close() error {
	return a.close(false)
}

// GracefulClose cleans up the Agent and waits for any goroutines it started
// to complete. This is only safe to call outside of Agent callbacks or if in a callback,
// in its own goroutine.
func (a *Agent) GracefulClose() error {
	return a.close(true)
}

func (a *Agent) close(graceful bool) error {
	// the loop is safe to wait on no matter what
	a.loop.Close()

	// but we are in less control of the notifiers, so we will
	// pass through `graceful`.
	a.connectionStateNotifier.Close(graceful)
	a.candidateNotifier.Close(graceful)
	a.selectedCandidatePairNotifier.Close(graceful)

	return nil
}

// Remove all candidates. This closes any listening sockets
// and removes both the local and remote candidate lists.
//
// This is used for restarts, failures and on close.
func (a *Agent) deleteAllCandidates() {
	for net, cs := range a.localCandidates {
		for _, c := range cs {
			if err := c.close(); err != nil {
				a.log.Warnf("Failed to close candidate %s: %v", c, err)
			}
		}
		delete(a.localCandidates, net)
	}
	for net, cs := range a.remoteCandidates {
		for _, c := range cs {
			if err := c.close(); err != nil {
				a.log.Warnf("Failed to close candidate %s: %v", c, err)
			}
		}
		delete(a.remoteCandidates, net)
	}
}

func (a *Agent) findRemoteCandidate(networkType NetworkType, addr net.Addr) Candidate {
	ip, port, _, err := parseAddr(addr)
	if err != nil {
		a.log.Warnf("Failed to parse address: %s; error: %s", addr, err)

		return nil
	}

	set := a.remoteCandidates[networkType]
	for _, c := range set {
		if c.Address() == ip.String() && c.Port() == port {
			return c
		}
	}

	return nil
}

func (a *Agent) sendBindingRequest(msg *stun.Message, local, remote Candidate) {
	a.log.Tracef("Ping STUN from %s to %s", local, remote)

	// Extract nomination value if present
	var nominationValue *uint32
	var nomination NominationAttribute
	if err := nomination.GetFromWithType(msg, a.nominationAttribute); err == nil {
		nominationValue = &nomination.Value
	}

	a.invalidatePendingBindingRequests(time.Now())
	a.pendingBindingRequests = append(a.pendingBindingRequests, bindingRequest{
		timestamp:       time.Now(),
		transactionID:   msg.TransactionID,
		destination:     remote.addr(),
		isUseCandidate:  msg.Contains(stun.AttrUseCandidate),
		nominationValue: nominationValue,
	})

	if pair := a.findPair(local, remote); pair != nil {
		pair.UpdateRequestSent()
	} else {
		a.log.Warnf("Failed to find pair for add binding request from %s to %s", local, remote)
	}
	a.sendSTUN(msg, local, remote)
}

func (a *Agent) sendBindingSuccess(m *stun.Message, local, remote Candidate) {
	base := remote

	ip, port, _, err := parseAddr(base.addr())
	if err != nil {
		a.log.Warnf("Failed to parse address: %s; error: %s", base.addr(), err)

		return
	}

	if out, err := stun.Build(m, stun.BindingSuccess,
		&stun.XORMappedAddress{
			IP:   ip.AsSlice(),
			Port: port,
		},
		stun.NewShortTermIntegrity(a.localPwd),
		stun.Fingerprint,
	); err != nil {
		a.log.Warnf("Failed to handle inbound ICE from: %s to: %s error: %s", local, remote, err)
	} else {
		if pair := a.findPair(local, remote); pair != nil {
			pair.UpdateResponseSent()
		} else {
			a.log.Warnf("Failed to find pair for add binding response from %s to %s", local, remote)
		}
		a.sendSTUN(out, local, remote)
	}
}

// Removes pending binding requests that are over maxBindingRequestTimeout old
//
// Let HTO be the transaction timeout, which SHOULD be 2*RTT if
// RTT is known or 500 ms otherwise.
// https://tools.ietf.org/html/rfc8445#appendix-B.1
func (a *Agent) invalidatePendingBindingRequests(filterTime time.Time) {
	initialSize := len(a.pendingBindingRequests)

	temp := a.pendingBindingRequests[:0]
	for _, bindingRequest := range a.pendingBindingRequests {
		if filterTime.Sub(bindingRequest.timestamp) < maxBindingRequestTimeout {
			temp = append(temp, bindingRequest)
		}
	}

	a.pendingBindingRequests = temp
	if bindRequestsRemoved := initialSize - len(a.pendingBindingRequests); bindRequestsRemoved > 0 {
		a.log.Tracef("Discarded %d binding requests because they expired", bindRequestsRemoved)
	}
}

// Assert that the passed TransactionID is in our pendingBindingRequests and returns the destination
// If the bindingRequest was valid remove it from our pending cache.
func (a *Agent) handleInboundBindingSuccess(id [stun.TransactionIDSize]byte) (bool, *bindingRequest, time.Duration) {
	a.invalidatePendingBindingRequests(time.Now())
	for i := range a.pendingBindingRequests {
		if a.pendingBindingRequests[i].transactionID == id {
			validBindingRequest := a.pendingBindingRequests[i]
			a.pendingBindingRequests = append(a.pendingBindingRequests[:i], a.pendingBindingRequests[i+1:]...)

			return true, &validBindingRequest, time.Since(validBindingRequest.timestamp)
		}
	}

	return false, nil, 0
}

func (a *Agent) handleRoleConflict(msg *stun.Message, local, remote Candidate, remoteTieBreaker *AttrControl) {
	localIsGreaterOrEqual := a.tieBreaker >= remoteTieBreaker.Tiebreaker
	a.log.Warnf("Role conflict local and remote same role(%s), localIsGreaterOrEqual(%t)", a.role(), localIsGreaterOrEqual)

	// https://datatracker.ietf.org/doc/html/rfc8445#section-7.3.1.1
	//  An agent MUST examine the Binding request for either the ICE-
	//  CONTROLLING or ICE-CONTROLLED attribute.  It MUST follow these
	// procedures:

	// If the agent's tiebreaker value is larger than or equal to the contents of the ICE-CONTROLLING attribute
	// If the agent's tiebreaker value is less than the contents of the ICE-CONTROLLED attribute
	//  the agent generates a Binding error response
	if (a.isControlling.Load() && localIsGreaterOrEqual) || (!a.isControlling.Load() && !localIsGreaterOrEqual) {
		if roleConflictMsg, err := stun.Build(msg, stun.BindingError,
			stun.ErrorCodeAttribute{
				Code:   stun.CodeRoleConflict,
				Reason: []byte("Role Conflict"),
			},
			stun.NewShortTermIntegrity(a.localPwd),
			stun.Fingerprint,
		); err != nil {
			a.log.Warnf("Failed to generate Role Conflict message from: %s to: %s error: %s", local, remote, err)
		} else {
			a.sendSTUN(roleConflictMsg, local, remote)
		}
	} else {
		a.isControlling.Store(!a.isControlling.Load())
		a.setSelector()
	}
}

// handleInbound processes STUN traffic from a remote candidate.
func (a *Agent) handleInbound(msg *stun.Message, local Candidate, remote net.Addr) {
	if msg == nil || local == nil {
		return
	}

	if !canHandleInbound(msg) {
		a.log.Tracef("Unhandled STUN from %s to %s class(%s) method(%s)", remote, local, msg.Type.Class, msg.Type.Method)

		return
	}

	remoteCandidate := a.findRemoteCandidate(local.NetworkType(), remote)

	switch msg.Type.Class {
	case stun.ClassSuccessResponse:
		if !a.handleInboundResponse(remoteCandidate, local, remote, msg) {
			return
		}
	case stun.ClassRequest:
		var ok bool
		if remoteCandidate, ok = a.handleInboundRequest(remoteCandidate, local, remote, msg); !ok {
			return
		}
	default:
	}

	if remoteCandidate != nil {
		remoteCandidate.seen(false)
	}
}

func canHandleInbound(msg *stun.Message) bool {
	return msg.Type.Method == stun.MethodBinding &&
		(msg.Type.Class == stun.ClassSuccessResponse ||
			msg.Type.Class == stun.ClassRequest ||
			msg.Type.Class == stun.ClassIndication)
}

func (a *Agent) handleInboundResponse(
	remoteCandidate, local Candidate, remote net.Addr, msg *stun.Message,
) bool {
	if err := stun.MessageIntegrity([]byte(a.remotePwd)).Check(msg); err != nil {
		a.log.Warnf("Discard success response with broken integrity from (%s), %v", remote, err)

		return false
	}

	if remoteCandidate == nil {
		a.log.Warnf("Discard success message from (%s), no such remote", remote)

		return false
	}

	a.getSelector().HandleSuccessResponse(msg, local, remoteCandidate, remote)

	return true
}

func (a *Agent) handleInboundRequest(
	remoteCandidate, local Candidate, remote net.Addr, msg *stun.Message,
) (remoteCand Candidate, ok bool) {
	a.log.Tracef(
		"Inbound STUN (Request) from %s to %s, useCandidate: %v",
		remote,
		local,
		msg.Contains(stun.AttrUseCandidate),
	)

	if err := stunx.AssertUsername(msg, a.localUfrag+":"+a.remoteUfrag); err != nil {
		a.log.Warnf("Discard request with wrong username from (%s), %v", remote, err)

		return nil, false
	} else if err := stun.MessageIntegrity([]byte(a.localPwd)).Check(msg); err != nil {
		a.log.Warnf("Discard request with broken integrity from (%s), %v", remote, err)

		return nil, false
	}

	if remoteCandidate == nil {
		ip, port, networkType, err := parseAddr(remote)
		if err != nil {
			a.log.Errorf("Failed to create parse remote net.Addr when creating remote prflx candidate: %s", err)

			return nil, false
		}

		prflxCandidateConfig := CandidatePeerReflexiveConfig{
			Network:   networkType.String(),
			Address:   ip.String(),
			Port:      port,
			Component: local.Component(),
			RelAddr:   "",
			RelPort:   0,
		}

		prflxCandidate, err := NewCandidatePeerReflexive(&prflxCandidateConfig)
		if err != nil {
			a.log.Errorf("Failed to create new remote prflx candidate (%s)", err)

			return nil, false
		}
		remoteCandidate = prflxCandidate

		a.log.Debugf("Adding a new peer-reflexive candidate: %s ", remote)
		a.addRemoteCandidate(remoteCandidate)
	}

	// Support Remotes that don't set a TIE-BREAKER. Not standards compliant, but
	// keeping to maintain backwards compat
	remoteTieBreaker := &AttrControl{}
	if err := remoteTieBreaker.GetFrom(msg); err == nil && remoteTieBreaker.Role == a.role() {
		a.handleRoleConflict(msg, local, remoteCandidate, remoteTieBreaker)

		return nil, false
	}

	a.getSelector().HandleBindingRequest(msg, local, remoteCandidate)

	return remoteCandidate, true
}

// validateNonSTUNTraffic processes non STUN traffic from a remote candidate,
// and returns true if it is an actual remote candidate.
func (a *Agent) validateNonSTUNTraffic(local Candidate, remote net.Addr) (Candidate, bool) {
	var remoteCandidate Candidate
	if err := a.loop.Run(local.context(), func(context.Context) {
		remoteCandidate = a.findRemoteCandidate(local.NetworkType(), remote)
		if remoteCandidate != nil {
			remoteCandidate.seen(false)
		}
	}); err != nil {
		a.log.Warnf("Failed to validate remote candidate: %v", err)
	}

	return remoteCandidate, remoteCandidate != nil
}

// GetSelectedCandidatePair returns the selected pair or nil if there is none.
func (a *Agent) GetSelectedCandidatePair() (*CandidatePair, error) {
	selectedPair := a.getSelectedPair()
	if selectedPair == nil {
		return nil, nil //nolint:nilnil
	}

	local, err := selectedPair.Local.copy()
	if err != nil {
		return nil, err
	}

	remote, err := selectedPair.Remote.copy()
	if err != nil {
		return nil, err
	}

	return &CandidatePair{Local: local, Remote: remote}, nil
}

func (a *Agent) getSelectedPair() *CandidatePair {
	if selectedPair, ok := a.selectedPair.Load().(*CandidatePair); ok {
		return selectedPair
	}

	return nil
}

func (a *Agent) closeMulticastConn() {
	if a.mDNSConn != nil {
		if err := a.mDNSConn.Close(); err != nil {
			a.log.Warnf("Failed to close mDNS Conn: %v", err)
		}
	}
}

// SetRemoteCredentials sets the credentials of the remote agent.
func (a *Agent) SetRemoteCredentials(remoteUfrag, remotePwd string) error {
	switch {
	case remoteUfrag == "":
		return ErrRemoteUfragEmpty
	case remotePwd == "":
		return ErrRemotePwdEmpty
	}

	return a.loop.Run(a.loop, func(_ context.Context) {
		a.remoteUfrag = remoteUfrag
		a.remotePwd = remotePwd
	})
}

// UpdateOptions applies the given options to the agent at runtime.
// Only a subset of options can be updated after agent creation:
//   - WithUrls: updates STUN/TURN server URLs (takes effect on next GatherCandidates call)
//
// Returns an error if the agent is closed or if an unsupported option is provided.
func (a *Agent) UpdateOptions(opts ...AgentOption) error {
	var optErr error

	err := a.loop.Run(a.loop, func(_ context.Context) {
		for _, opt := range opts {
			if optErr = opt(a); optErr != nil {
				return
			}
		}
	})
	if err != nil {
		return err
	}

	return optErr
}

// Restart restarts the ICE Agent with the provided ufrag/pwd
// If no ufrag/pwd is provided the Agent will generate one itself
//
// If there is a gatherer routine currently running, Restart will
// cancel it.
// After a Restart, the user must then call GatherCandidates explicitly
// to start generating new ones.
func (a *Agent) Restart(ufrag, pwd string) error { //nolint:cyclop
	if ufrag == "" {
		var err error
		ufrag, err = generateUFrag()
		if err != nil {
			return err
		}
	}
	if pwd == "" {
		var err error
		pwd, err = generatePwd()
		if err != nil {
			return err
		}
	}

	if len([]rune(ufrag))*8 < 24 {
		return ErrLocalUfragInsufficientBits
	}
	if len([]rune(pwd))*8 < 128 {
		return ErrLocalPwdInsufficientBits
	}

	var err error
	if runErr := a.loop.Run(a.loop, func(_ context.Context) {
		if a.gatheringState == GatheringStateGathering {
			a.gatherCandidateCancel()
		}

		// Clear all agent needed to take back to fresh state
		a.removeUfragFromMux()
		a.localUfrag = ufrag
		a.localPwd = pwd
		a.remoteUfrag = ""
		a.remotePwd = ""
		a.gatheringState = GatheringStateNew
		a.checklist = make([]*CandidatePair, 0)
		a.pairsByID = make(map[uint64]*CandidatePair)
		a.pendingBindingRequests = make([]bindingRequest, 0)
		a.setSelectedPair(nil)
		a.deleteAllCandidates()
		a.setSelector()

		// Restart is used by NewAgent. Accept/Connect should be used to move to checking
		// for new Agents
		if a.connectionState != ConnectionStateNew {
			a.updateConnectionState(ConnectionStateChecking)
		}
	}); runErr != nil {
		return runErr
	}

	return err
}

func (a *Agent) setGatheringState(newState GatheringState) error {
	done := make(chan struct{})
	if err := a.loop.Run(a.loop, func(context.Context) {
		if a.gatheringState != newState && newState == GatheringStateComplete {
			a.candidateNotifier.EnqueueCandidate(nil)
		}

		a.gatheringState = newState
		close(done)
	}); err != nil {
		return err
	}

	<-done

	return nil
}

func (a *Agent) needsToCheckPriorityOnNominated() bool {
	return !a.lite || a.enableUseCandidateCheckPriority
}

func (a *Agent) role() Role {
	if a.isControlling.Load() {
		return Controlling
	}

	return Controlled
}

func (a *Agent) setSelector() {
	a.selectorLock.Lock()
	defer a.selectorLock.Unlock()

	var s pairCandidateSelector
	if a.isControlling.Load() {
		s = &controllingSelector{agent: a, log: a.log}
	} else {
		s = &controlledSelector{agent: a, log: a.log}
	}
	if a.lite {
		s = &liteSelector{pairCandidateSelector: s}
	}

	s.Start()
	a.selector = s
}

func (a *Agent) getSelector() pairCandidateSelector {
	a.selectorLock.Lock()
	defer a.selectorLock.Unlock()

	return a.selector
}

// getNominationValue returns a nomination value if generator is available, otherwise 0.
func (a *Agent) getNominationValue() uint32 {
	if a.nominationValueGenerator != nil {
		return a.nominationValueGenerator()
	}

	return 0
}

// RenominateCandidate allows the controlling ICE agent to nominate a new candidate pair.
// This implements the continuous renomination feature from draft-thatcher-ice-renomination-01.
func (a *Agent) RenominateCandidate(local, remote Candidate) error {
	if !a.isControlling.Load() {
		return ErrOnlyControllingAgentCanRenominate
	}

	if !a.enableRenomination {
		return ErrRenominationNotEnabled
	}

	// Find the candidate pair
	pair := a.findPair(local, remote)
	if pair == nil {
		return ErrCandidatePairNotFound
	}

	// Send nomination with custom attribute
	return a.sendNominationRequest(pair, a.getNominationValue())
}

// sendNominationRequest sends a nomination request with custom nomination value.
func (a *Agent) sendNominationRequest(pair *CandidatePair, nominationValue uint32) error {
	attributes := []stun.Setter{
		stun.TransactionID,
		stun.NewUsername(a.remoteUfrag + ":" + a.localUfrag),
		UseCandidate(),
		AttrControlling(a.tieBreaker),
		PriorityAttr(pair.Local.Priority()),
		stun.NewShortTermIntegrity(a.remotePwd),
		stun.Fingerprint,
	}

	// Add nomination attribute if renomination is enabled and value > 0
	if a.enableRenomination && nominationValue > 0 {
		attributes = append(attributes, NominationSetter{
			Value:    nominationValue,
			AttrType: a.nominationAttribute,
		})
		a.log.Tracef("Sending renomination request from %s to %s with nomination value %d",
			pair.Local, pair.Remote, nominationValue)
	}

	msg, err := stun.Build(append([]stun.Setter{stun.BindingRequest}, attributes...)...)
	if err != nil {
		return fmt.Errorf("failed to build nomination request: %w", err)
	}

	a.sendBindingRequest(msg, pair.Local, pair.Remote)

	return nil
}

// evaluateCandidatePairQuality calculates a quality score for a candidate pair.
// Higher scores indicate better quality. The score considers:
// - Candidate types (host > srflx > relay)
// - RTT (lower is better)
// - Connection stability.
func (a *Agent) evaluateCandidatePairQuality(pair *CandidatePair) float64 { //nolint:cyclop
	if pair == nil || pair.state != CandidatePairStateSucceeded {
		return 0
	}

	score := float64(0)

	// Type preference scoring (host=100, srflx=50, prflx=30, relay=10)
	localTypeScore := float64(0)
	switch pair.Local.Type() {
	case CandidateTypeHost:
		localTypeScore = 100
	case CandidateTypeServerReflexive:
		localTypeScore = 50
	case CandidateTypePeerReflexive:
		localTypeScore = 30
	case CandidateTypeRelay:
		localTypeScore = 10
	case CandidateTypeUnspecified:
		localTypeScore = 0
	}

	remoteTypeScore := float64(0)
	switch pair.Remote.Type() {
	case CandidateTypeHost:
		remoteTypeScore = 100
	case CandidateTypeServerReflexive:
		remoteTypeScore = 50
	case CandidateTypePeerReflexive:
		remoteTypeScore = 30
	case CandidateTypeRelay:
		remoteTypeScore = 10
	case CandidateTypeUnspecified:
		remoteTypeScore = 0
	}

	// Combined type score (average of local and remote)
	score += (localTypeScore + remoteTypeScore) / 2

	// RTT scoring (convert to penalty, lower RTT = higher score)
	// Use current RTT if available, otherwise assume high latency
	rtt := pair.CurrentRoundTripTime()
	if rtt > 0 {
		// Convert RTT to Duration for cleaner calculation
		rttDuration := time.Duration(rtt * float64(time.Second))
		rttMs := float64(rttDuration / time.Millisecond)
		if rttMs < 1 {
			rttMs = 1 // Minimum 1ms to avoid log(0)
		}
		// Subtract RTT penalty (logarithmic to reduce impact of very high RTTs)
		score -= math.Log10(rttMs) * 10
	} else {
		// No RTT data available, apply moderate penalty
		score -= 30
	}

	// Boost score if pair has been stable (received responses recently)
	if pair.ResponsesReceived() > 0 {
		lastResponse := pair.LastResponseReceivedAt()
		if !lastResponse.IsZero() && time.Since(lastResponse) < 5*time.Second {
			score += 20 // Stability bonus
		}
	}

	return score
}

// shouldRenominate determines if automatic renomination should occur.
// It compares the current selected pair with a candidate pair and decides
// if switching would provide significant benefit.
func (a *Agent) shouldRenominate(current, candidate *CandidatePair) bool { //nolint:cyclop
	if current == nil || candidate == nil || current.equal(candidate) || candidate.state != CandidatePairStateSucceeded {
		return false
	}

	// Type-based switching (always prefer direct over relay)
	currentIsRelay := current.Local.Type() == CandidateTypeRelay ||
		current.Remote.Type() == CandidateTypeRelay
	candidateIsDirect := candidate.Local.Type() == CandidateTypeHost &&
		candidate.Remote.Type() == CandidateTypeHost

	if currentIsRelay && candidateIsDirect {
		a.log.Debugf("Should renominate: relay -> direct connection available")

		return true
	}

	// RTT-based switching (must improve by at least 10ms)
	currentRTT := current.CurrentRoundTripTime()
	candidateRTT := candidate.CurrentRoundTripTime()

	// Only compare RTT if both values are valid
	if currentRTT > 0 && candidateRTT > 0 {
		currentRTTDuration := time.Duration(currentRTT * float64(time.Second))
		candidateRTTDuration := time.Duration(candidateRTT * float64(time.Second))
		rttImprovement := currentRTTDuration - candidateRTTDuration

		if rttImprovement > 10*time.Millisecond {
			a.log.Debugf("Should renominate: RTT improvement of %v", rttImprovement)

			return true
		}
	}

	// Quality score comparison (must improve by at least 15%)
	currentScore := a.evaluateCandidatePairQuality(current)
	candidateScore := a.evaluateCandidatePairQuality(candidate)

	if candidateScore > currentScore*1.15 {
		a.log.Debugf("Should renominate: quality score improved from %.2f to %.2f",
			currentScore, candidateScore)

		return true
	}

	return false
}

// findBestCandidatePair finds the best available candidate pair based on quality assessment.
func (a *Agent) findBestCandidatePair() *CandidatePair {
	var best *CandidatePair
	bestScore := float64(-math.MaxFloat64)

	for _, pair := range a.checklist {
		if pair.state != CandidatePairStateSucceeded {
			continue
		}

		score := a.evaluateCandidatePairQuality(pair)
		if score > bestScore {
			bestScore = score
			best = pair
		}
	}

	return best
}
