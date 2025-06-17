/*
 * Copyright (c) 2023, Psiphon Inc.
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

package psiphon

import (
	"bytes"
	"context"
	"encoding/binary"
	std_errors "errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/inproxy"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/resolver"
	utls "github.com/Psiphon-Labs/utls"
	"github.com/cespare/xxhash"
)

// InproxyBrokerClientManager manages an InproxyBrokerClientInstance, an
// in-proxy broker client, and its associated broker dial parameters, that
// may be shared by multiple client dials or proxy instances. There is no
// explicit close operation for the managed InproxyBrokerClientInstance.
//
// Once used, the current InproxyBrokerClientInstance and its broker client is
// left actively connected to the broker, to minimize transport round trips
// for additional requests.
//
// The InproxyBrokerClientManager and its components implement a replay system
// for broker client dials. As one broker client is shared access multiple
// client in-proxy dials, the broker dial parameters are replayed
// independently from tunnel dial parameters.
//
// The NewInproxyBrokerClientInstance layer provides a fixed association
// between a broker client and its broker dial parameters, ensuring that
// in-proxy success/failure callbacks reference the correct replay parameters
// when setting or clearing replay.
//
// A new InproxyBrokerClientInstance, including the broker dial parameters and
// broker client, is instantiated when the active network ID changes, using
// tactics for the new network.
type InproxyBrokerClientManager struct {
	config  *Config
	isProxy bool

	tlsCache utls.ClientSessionCache

	mutex                sync.Mutex
	brokerSelectCount    int
	networkID            string
	brokerClientInstance *InproxyBrokerClientInstance
}

// NewInproxyBrokerClientManager creates a new InproxyBrokerClientManager.
// NewInproxyBrokerClientManager does not perform any network operations; the
// managed InproxyBrokerClientInstance is initialized when used for a round
// trip.
func NewInproxyBrokerClientManager(
	config *Config, isProxy bool, tlsCache utls.ClientSessionCache) *InproxyBrokerClientManager {

	b := &InproxyBrokerClientManager{
		config:   config,
		isProxy:  isProxy,
		tlsCache: tlsCache,
	}

	// b.brokerClientInstance is initialized on demand, when getBrokerClient
	// is called.

	return b
}

// TacticsApplied implements the TacticsAppliedReceiver interface, and is
// called when tactics have changed, which triggers a broker client reset in
// order to apply potentially changed parameters.
func (b *InproxyBrokerClientManager) TacticsApplied() error {

	b.mutex.Lock()
	defer b.mutex.Unlock()

	// Don't reset when not yet initialized; b.brokerClientInstance is
	// initialized only on demand.
	if b.brokerClientInstance == nil {
		return nil
	}

	// TODO: as a future future enhancement, don't reset when the tactics
	// brokerSpecs.Hash() is unchanged?

	return errors.Trace(b.reset(resetBrokerClientReasonTacticsApplied))
}

// NetworkChanged is called when the active network changes, to trigger a
// broker client reset.
func (b *InproxyBrokerClientManager) NetworkChanged() error {

	b.mutex.Lock()
	defer b.mutex.Unlock()

	// Don't reset when not yet initialized; b.brokerClientInstance is
	// initialized only on demand.
	if b.brokerClientInstance == nil {
		return nil
	}

	return errors.Trace(b.reset(resetBrokerClientReasonNetworkChanged))
}

// GetBrokerClient returns the current, shared broker client and its
// corresponding dial parametrers (for metrics logging). If there is no
// current broker client, if the network ID differs from the network ID
// associated with the previous broker client, a new broker client is
// initialized.
func (b *InproxyBrokerClientManager) GetBrokerClient(
	networkID string) (*inproxy.BrokerClient, *InproxyBrokerDialParameters, error) {

	b.mutex.Lock()

	if b.brokerClientInstance == nil || b.networkID != networkID {
		err := b.reset(resetBrokerClientReasonInit)
		if err != nil {
			b.mutex.Unlock()
			return nil, nil, errors.Trace(err)
		}
	}

	brokerClientInstance := b.brokerClientInstance

	// Release lock before calling brokerClientInstance.HasSuccess. Otherwise,
	// there's a potential deadlock that would result from this code path
	// locking InproxyBrokerClientManager.mutex then InproxyBrokerClientInstance.mutex,
	// while the BrokerClientRoundTripperFailed code path locks in the reverse order.

	b.mutex.Unlock()

	// Set isReuse, which will record a metric indicating if this broker
	// client has already been used for a successful round trip, a case which
	// should result in faster overall dials.
	//
	// Limitations with HasSuccess, and the resulting isReuse metric: in some
	// cases, it's possible that the underlying TLS connection is still
	// redialed by net/http; or it's possible that the Noise session is
	// invalid/expired and must be reestablished; or it can be the case that
	// a shared broker client is only partially established at this point in
	// time.
	//
	// Return a shallow copy of the broker dial params in order to record the
	// correct isReuse, which varies depending on previous use.

	brokerDialParams := *brokerClientInstance.brokerDialParams
	brokerDialParams.isReuse = brokerClientInstance.HasSuccess()

	// The b.brokerClientInstance.brokerClient is wired up to refer back to
	// b.brokerClientInstance.brokerDialParams/roundTripper, etc.

	return brokerClientInstance.brokerClient,
		&brokerDialParams,
		nil
}

func (b *InproxyBrokerClientManager) resetBrokerClientOnRoundTripperFailed(
	brokerClientInstance *InproxyBrokerClientInstance) error {

	b.mutex.Lock()
	defer b.mutex.Unlock()

	if b.brokerClientInstance != brokerClientInstance {
		// Ignore the reset if the signal comes from the non-current
		// brokerClientInstance, which may occur when multiple in-flight
		// round trips fail in close proximity.
		return nil
	}

	return errors.Trace(b.reset(resetBrokerClientReasonRoundTripperFailed))
}

func (b *InproxyBrokerClientManager) resetBrokerClientOnNoMatch(
	brokerClientInstance *InproxyBrokerClientInstance) error {

	// Ignore the no match callback for proxies. For personal pairing, the
	// broker rotation scheme has clients moving brokers to find relatively
	// static proxies. For common pairing, we want to achieve balanced supply
	// across brokers.
	//
	// Currently, inproxy.BrokerDialCoordinator.BrokerClientNoMatch is only
	// wired up for clients, but this check ensures it'll still be ignored in
	// case that changes.
	if b.isProxy {
		return nil
	}

	if b.brokerClientInstance != brokerClientInstance {
		// See comment for same logic in resetBrokerClientOnRoundTripperFailed.
		return nil
	}

	p := b.config.GetParameters().Get()
	defer p.Close()

	probability := parameters.InproxyClientNoMatchFailoverProbability
	if b.config.IsInproxyClientPersonalPairingMode() {
		probability = parameters.InproxyClientNoMatchFailoverPersonalProbability
	}
	if !p.WeightedCoinFlip(probability) {
		return nil
	}

	return errors.Trace(b.reset(resetBrokerClientReasonRoundNoMatch))
}

type resetBrokerClientReason int

const (
	resetBrokerClientReasonInit resetBrokerClientReason = iota + 1
	resetBrokerClientReasonTacticsApplied
	resetBrokerClientReasonNetworkChanged
	resetBrokerClientReasonRoundTripperFailed
	resetBrokerClientReasonRoundNoMatch
)

func (b *InproxyBrokerClientManager) reset(reason resetBrokerClientReason) error {

	// Assumes b.mutex lock is held.

	if b.brokerClientInstance != nil {

		// Close the existing broker client. This will close all underlying
		// network connections, interrupting any in-flight requests. This
		// close is invoked in the resetBrokerClientOnRoundTripperFailed
		// case, where it's expected that the round tripped has permanently
		// failed.

		b.brokerClientInstance.Close()
	}

	// b.brokerSelectCount tracks the number of broker resets and is used to
	// iterate over the brokers in a deterministic rotation when running in
	// personal pairing mode.

	switch reason {
	case resetBrokerClientReasonInit,
		resetBrokerClientReasonTacticsApplied,
		resetBrokerClientReasonNetworkChanged:
		b.brokerSelectCount = 0

	case resetBrokerClientReasonRoundTripperFailed,
		resetBrokerClientReasonRoundNoMatch:
		b.brokerSelectCount += 1
	}

	// Any existing broker client is removed, even if
	// NewInproxyBrokerClientInstance fails. This ensures, for example, that
	// an existing broker client is removed when its spec is no longer
	// available in tactics.
	b.networkID = ""
	b.brokerClientInstance = nil

	networkID := b.config.GetNetworkID()

	brokerClientInstance, err := NewInproxyBrokerClientInstance(
		b.config,
		b,
		networkID,
		b.isProxy,
		b.brokerSelectCount,
		reason == resetBrokerClientReasonRoundNoMatch)
	if err != nil {
		return errors.Trace(err)
	}

	b.networkID = networkID
	b.brokerClientInstance = brokerClientInstance

	return nil
}

// InproxyBrokerClientInstance pairs an inproxy.BrokerClient instance with an
// implementation of the inproxy.BrokerDialCoordinator interface and the
// associated, underlying broker dial parameters. InproxyBrokerClientInstance
// implements broker client dial replay.
type InproxyBrokerClientInstance struct {
	config                        *Config
	brokerClientManager           *InproxyBrokerClientManager
	networkID                     string
	brokerClientPrivateKey        inproxy.SessionPrivateKey
	brokerClient                  *inproxy.BrokerClient
	brokerPublicKey               inproxy.SessionPublicKey
	brokerRootObfuscationSecret   inproxy.ObfuscationSecret
	brokerDialParams              *InproxyBrokerDialParameters
	replayEnabled                 bool
	roundTripper                  *InproxyBrokerRoundTripper
	personalCompartmentIDs        []inproxy.ID
	commonCompartmentIDs          []inproxy.ID
	disableWaitToShareSession     bool
	sessionHandshakeTimeout       time.Duration
	announceRequestTimeout        time.Duration
	announceDelay                 time.Duration
	announceMaxBackoffDelay       time.Duration
	announceDelayJitter           float64
	answerRequestTimeout          time.Duration
	offerRequestTimeout           time.Duration
	offerRequestPersonalTimeout   time.Duration
	offerRetryDelay               time.Duration
	offerRetryJitter              float64
	relayedPacketRequestTimeout   time.Duration
	replayRetainFailedProbability float64
	replayUpdateFrequency         time.Duration
	retryOnFailedPeriod           time.Duration

	mutex           sync.Mutex
	lastStoreReplay time.Time
	lastSuccess     time.Time
}

// NewInproxyBrokerClientInstance creates a new InproxyBrokerClientInstance.
// NewInproxyBrokerClientManager does not perform any network operations; the
// new InproxyBrokerClientInstance is initialized when used for a round
// trip.
func NewInproxyBrokerClientInstance(
	config *Config,
	brokerClientManager *InproxyBrokerClientManager,
	networkID string,
	isProxy bool,
	brokerSelectCount int,
	resetReasonNoMatch bool) (*InproxyBrokerClientInstance, error) {

	p := config.GetParameters().Get()
	defer p.Close()

	// Select common or personal compartment IDs. Clients must provide at
	// least on compartment ID.

	commonCompartmentIDs, personalCompartmentIDs, err :=
		prepareInproxyCompartmentIDs(config, p, isProxy)
	if err != nil {
		return nil, errors.Trace(err)
	}
	if !isProxy && len(commonCompartmentIDs) == 0 && len(personalCompartmentIDs) == 0 {
		return nil, errors.TraceNew("no compartment IDs")
	}
	if len(personalCompartmentIDs) > 1 {
		return nil, errors.TraceNew("unexpected multiple personal compartment IDs")
	}

	// Select the broker to use, optionally favoring brokers with replay data.
	// In the InproxyBrokerSpecs calls, the first non-empty tactics parameter
	// list is used.
	//
	// Optional broker specs may be used to specify broker(s) dedicated to
	// personal pairing, a configuration which can be used to reserve more
	// capacity for personal pairing, given the simple rendezvous scheme below.

	brokerSpecs := getInproxyBrokerSpecs(config, p, isProxy)
	if len(brokerSpecs) == 0 {
		return nil, errors.TraceNew("no broker specs")
	}

	// Select a broker.

	// In common pairing mode, the available brokers are shuffled before
	// selection, for random load balancing. Brokers with available dial
	// parameter replay data are preferred. When rotating brokers due to a no
	// match, the available replay data is ignored to increase the chance of
	// selecting a different broker.
	//
	// In personal pairing mode, arrange for the proxy and client to
	// rendezvous at the same broker by shuffling based on the shared
	// personal compartment ID. Both the client and proxy will select the
	// same initial broker, and fail over to other brokers in the same order.
	// By design, clients will move between brokers aggressively, rotating on
	// no-match responses and applying a shorter client offer timeout; while
	// proxies will remain in place in order to be found. Since rendezvous
	// depends on the ordering, each broker is selected in shuffle order;
	// dial parameter replay data is used when available but not considered
	// in selection ordering. The brokerSelectCount input is used to
	// progressively index into the list of shuffled brokers.
	//
	// Potential future enhancements:
	//
	// - Use brokerSelectCount in the common pairing case as well, to ensure
	//   that a no-match reset always selects a different broker; but, unlike
	//   the personal pairing logic, still prefer brokers with replay rather
	//   than following a strict shuffle order.
	//
	// - The common pairing no match broker rotation is intended to partially
	//   mitigate poor common proxy load balancing that can leave a broker
	//   with little proxy supply. A more robust mitigation would be to make
	//   proxies distribute announcements across multiple or even all brokers.

	personalPairing := len(personalCompartmentIDs) > 0

	// In the following cases, don't shuffle or otherwise mutate the original
	// broker spec slice, as it is a tactics parameter.

	if personalPairing {

		if len(personalCompartmentIDs[0]) < prng.SEED_LENGTH {
			// Both inproxy.ID and prng.SEED_LENGTH are 32 bytes.
			return nil, errors.TraceNew("unexpected ID length")
		}

		seed := prng.Seed(personalCompartmentIDs[0][0:prng.SEED_LENGTH])
		PRNG := prng.NewPRNGWithSeed(&seed)

		permutedIndexes := PRNG.Perm(len(brokerSpecs))
		selectedIndex := permutedIndexes[brokerSelectCount%len(permutedIndexes)]
		brokerSpecs = brokerSpecs[selectedIndex : selectedIndex+1]

	} else {

		permutedIndexes := prng.Perm(len(brokerSpecs))
		shuffledBrokerSpecs := make(parameters.InproxyBrokerSpecsValue, len(brokerSpecs))
		for i, index := range permutedIndexes {
			shuffledBrokerSpecs[i] = brokerSpecs[index]
		}
		brokerSpecs = shuffledBrokerSpecs
	}

	selectFirstCandidate := resetReasonNoMatch || personalPairing

	// Replay broker dial parameters.

	// In selectFirstCandidate cases, SelectCandidateWithNetworkReplayParameters
	// will always select the first candidate, returning corresponding replay
	// data when available. Otherwise, SelectCandidateWithNetworkReplayParameters
	// iterates over the shuffled candidates and returns the first with replay data.

	var brokerSpec *parameters.InproxyBrokerSpec
	var brokerDialParams *InproxyBrokerDialParameters

	// Replay is disabled when the TTL, InproxyReplayBrokerDialParametersTTL,
	// is 0.
	now := time.Now()
	ttl := p.Duration(parameters.InproxyReplayBrokerDialParametersTTL)

	replayEnabled := ttl > 0 &&
		!config.DisableReplay &&
		prng.FlipWeightedCoin(p.Float(parameters.InproxyReplayBrokerDialParametersProbability))

	if replayEnabled {
		brokerSpec, brokerDialParams, err =
			SelectCandidateWithNetworkReplayParameters[parameters.InproxyBrokerSpec, InproxyBrokerDialParameters](
				networkID,
				selectFirstCandidate,
				brokerSpecs,
				func(spec *parameters.InproxyBrokerSpec) string { return spec.BrokerPublicKey },
				func(spec *parameters.InproxyBrokerSpec, dialParams *InproxyBrokerDialParameters) bool {
					// Replay the successful broker spec, if present, by
					// comparing its hash with that of the candidate.
					return dialParams.LastUsedTimestamp.After(now.Add(-ttl)) &&
						bytes.Equal(dialParams.LastUsedBrokerSpecHash, hashBrokerSpec(spec))
				})
		if err != nil {
			NoticeWarning("SelectCandidateWithNetworkReplayParameters failed: %v", errors.Trace(err))
			// Continue without replay
		}
	}

	// Select the first broker in the shuffle when replay is not enabled or in
	// case SelectCandidateWithNetworkReplayParameters fails.
	if brokerSpec == nil {
		brokerSpec = brokerSpecs[0]
	}

	// Generate new broker dial parameters if not replaying. Later, isReplay
	// is used to report the replay metric.

	isReplay := brokerDialParams != nil

	// Handle legacy replay records by discarding replay when required fields
	// are missing.
	if isReplay && brokerDialParams.FrontedHTTPDialParameters == nil {
		isReplay = false
	}

	if !isReplay {
		brokerDialParams, err = MakeInproxyBrokerDialParameters(config, p, networkID, brokerSpec, brokerClientManager.tlsCache)
		if err != nil {
			return nil, errors.Trace(err)
		}
	} else {
		brokerDialParams.brokerSpec = brokerSpec
		err := brokerDialParams.prepareDialConfigs(config, p, true, brokerClientManager.tlsCache)
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	// Load broker key material.

	brokerPublicKey, err := inproxy.SessionPublicKeyFromString(brokerSpec.BrokerPublicKey)
	if err != nil {
		return nil, errors.Trace(err)
	}
	brokerRootObfuscationSecret, err := inproxy.ObfuscationSecretFromString(brokerSpec.BrokerRootObfuscationSecret)
	if err != nil {
		return nil, errors.Trace(err)
	}

	roundTripper := NewInproxyBrokerRoundTripper(p, brokerDialParams)

	// Clients always generate an ephemeral session key pair. Proxies may opt
	// to use a long-lived key pair for proxied traffic attribution.

	var brokerClientPrivateKey inproxy.SessionPrivateKey
	if isProxy && config.InproxyProxySessionPrivateKey != "" {
		brokerClientPrivateKey, err = inproxy.SessionPrivateKeyFromString(config.InproxyProxySessionPrivateKey)
		if err != nil {
			return nil, errors.Trace(err)
		}
	} else {
		brokerClientPrivateKey, err = inproxy.GenerateSessionPrivateKey()
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	// InproxyBrokerClientInstance implements the
	// inproxy.BrokerDialCoordinator interface and passes itself to
	// inproxy.NewBrokerClient in order to provide the round tripper, key
	// material, compartment IDs, timeouts, and other configuration to the
	// in-proxy broker client.
	//
	// Timeouts are not replayed, but snapshots are stored in the
	// InproxyBrokerClientInstance for efficient lookup.

	b := &InproxyBrokerClientInstance{
		config:                      config,
		brokerClientManager:         brokerClientManager,
		networkID:                   networkID,
		brokerClientPrivateKey:      brokerClientPrivateKey,
		brokerPublicKey:             brokerPublicKey,
		brokerRootObfuscationSecret: brokerRootObfuscationSecret,
		brokerDialParams:            brokerDialParams,
		replayEnabled:               replayEnabled,
		roundTripper:                roundTripper,
		personalCompartmentIDs:      personalCompartmentIDs,
		commonCompartmentIDs:        commonCompartmentIDs,

		sessionHandshakeTimeout:       p.Duration(parameters.InproxySessionHandshakeRoundTripTimeout),
		announceRequestTimeout:        p.Duration(parameters.InproxyProxyAnnounceRequestTimeout),
		announceDelay:                 p.Duration(parameters.InproxyProxyAnnounceDelay),
		announceMaxBackoffDelay:       p.Duration(parameters.InproxyProxyAnnounceMaxBackoffDelay),
		announceDelayJitter:           p.Float(parameters.InproxyProxyAnnounceDelayJitter),
		answerRequestTimeout:          p.Duration(parameters.InproxyProxyAnswerRequestTimeout),
		offerRequestTimeout:           p.Duration(parameters.InproxyClientOfferRequestTimeout),
		offerRequestPersonalTimeout:   p.Duration(parameters.InproxyClientOfferRequestPersonalTimeout),
		offerRetryDelay:               p.Duration(parameters.InproxyClientOfferRetryDelay),
		offerRetryJitter:              p.Float(parameters.InproxyClientOfferRetryJitter),
		relayedPacketRequestTimeout:   p.Duration(parameters.InproxyClientRelayedPacketRequestTimeout),
		replayRetainFailedProbability: p.Float(parameters.InproxyReplayBrokerRetainFailedProbability),
		replayUpdateFrequency:         p.Duration(parameters.InproxyReplayBrokerUpdateFrequency),
	}

	if isProxy && !config.IsInproxyProxyPersonalPairingMode() {
		// This retry is applied only for proxies and only in common pairing
		// mode. See comment in BrokerClientRoundTripperFailed.
		b.retryOnFailedPeriod = p.Duration(parameters.InproxyProxyOnBrokerClientFailedRetryPeriod)
	}

	// Limitation: currently, disableWaitToShareSession is neither replayed
	// nor is the selected value reported in metrics. The default tactics
	// parameters are considered to be optimal: the in-proxy clients
	// disabling wait and proxies using wait. The tactics flag can be used to
	// enable wait for clients in case performance is poor or load on
	// brokers -- due to simultaneous sessions -- is unexpectedly high.
	//
	// Note that, for broker dial parameter replay, the isValidReplay function
	// currently invalidates replay only when broker specs change, and not
	// when tactics in general change; so changes to these
	// disableWaitToShareSession parameters would not properly invalidate
	// replays in any case.
	//
	// Potential future enhancements for in-proxy client broker clients
	// include using a pool of broker clients, with each one potentially
	// using a different broker and/or fronting spec. In this scenario,
	// waitToShareSession would be less impactful.

	if isProxy {
		b.disableWaitToShareSession = p.Bool(parameters.InproxyProxyDisableWaitToShareSession)
	} else {
		b.disableWaitToShareSession = p.Bool(parameters.InproxyClientDisableWaitToShareSession)
	}

	// Adjust long-polling request timeouts to respect any maximum request
	// timeout supported by the provider fronting the request.
	maxRequestTimeout, ok := p.KeyDurations(
		parameters.InproxyFrontingProviderClientMaxRequestTimeouts)[brokerDialParams.FrontedHTTPDialParameters.FrontingProviderID]
	if ok && maxRequestTimeout > 0 {
		if b.announceRequestTimeout > maxRequestTimeout {
			b.announceRequestTimeout = maxRequestTimeout
		}
		if b.offerRequestTimeout > maxRequestTimeout {
			b.offerRequestTimeout = maxRequestTimeout
		}
		if b.offerRequestPersonalTimeout > maxRequestTimeout {
			b.offerRequestPersonalTimeout = maxRequestTimeout
		}
	}

	// Initialize broker client. This will start with a fresh broker session.
	//
	// When resetBrokerClientOnRoundTripperFailed is invoked due to a failure
	// at the transport level -- TLS or domain fronting --
	// NewInproxyBrokerClientInstance is invoked, resetting both the broker
	// client round tripper and the broker session. As a future enhancement,
	// consider distinguishing between transport and session errors and
	// retaining a valid established session when only the transport needs to
	// be reset/retried.

	b.brokerClient, err = inproxy.NewBrokerClient(b)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// The broker ID is the broker's session public key in Curve25519 form.
	brokerID, err := brokerPublicKey.ToCurve25519()
	if err != nil {
		return nil, errors.Trace(err)
	}
	NoticeInfo("inproxy: selected broker %s", inproxy.ID(brokerID))

	return b, nil
}

func haveInproxyProxyBrokerSpecs(config *Config) bool {
	p := config.GetParameters().Get()
	defer p.Close()
	return len(getInproxyBrokerSpecs(config, p, true)) > 0
}

func haveInproxyClientBrokerSpecs(config *Config) bool {
	p := config.GetParameters().Get()
	defer p.Close()
	return len(getInproxyBrokerSpecs(config, p, false)) > 0
}

func getInproxyBrokerSpecs(
	config *Config,
	p parameters.ParametersAccessor,
	isProxy bool) parameters.InproxyBrokerSpecsValue {

	if isProxy {
		if config.IsInproxyProxyPersonalPairingMode() {
			return p.InproxyBrokerSpecs(
				parameters.InproxyProxyPersonalPairingBrokerSpecs,
				parameters.InproxyPersonalPairingBrokerSpecs,
				parameters.InproxyProxyBrokerSpecs,
				parameters.InproxyBrokerSpecs)
		} else {
			return p.InproxyBrokerSpecs(
				parameters.InproxyProxyBrokerSpecs,
				parameters.InproxyBrokerSpecs)
		}
	} else {
		if config.IsInproxyClientPersonalPairingMode() {
			return p.InproxyBrokerSpecs(
				parameters.InproxyClientPersonalPairingBrokerSpecs,
				parameters.InproxyPersonalPairingBrokerSpecs,
				parameters.InproxyClientBrokerSpecs,
				parameters.InproxyBrokerSpecs)
		} else {
			return p.InproxyBrokerSpecs(
				parameters.InproxyClientBrokerSpecs,
				parameters.InproxyBrokerSpecs)
		}
	}
}

func haveInproxyCommonCompartmentIDs(config *Config) bool {
	p := config.GetParameters().Get()
	defer p.Close()
	if len(p.InproxyCompartmentIDs(parameters.InproxyCommonCompartmentIDs)) > 0 {
		return true
	}
	commonCompartmentIDs, _ := LoadInproxyCommonCompartmentIDs()
	return len(commonCompartmentIDs) > 0
}

func prepareInproxyCompartmentIDs(
	config *Config,
	p parameters.ParametersAccessor,
	isProxy bool) ([]inproxy.ID, []inproxy.ID, error) {

	// Personal compartment IDs are loaded from the tunnel-core config; these
	// are set by the external app based on user input/configuration of IDs
	// generated by or obtained from personal proxies. Both clients and
	// proxies send personal compartment IDs to the in-proxy broker. For
	// clients, when personal compartment IDs are configured, no common
	// compartment IDs are prepared, ensuring matches with only proxies that
	// supply the corresponding personal compartment IDs.
	//
	// Common compartment IDs are obtained from tactics and merged with
	// previously learned IDs stored in the local datastore. When new IDs are
	// obtained from tactics, the merged list is written back to the
	// datastore. This allows for schemes where common compartment IDs are
	// distributed to sets of clients, then removed from distibution, and
	// still used to match proxies to those sets of clients. Only clients
	// send common compartment IDs to the in-proxy broker. Proxies are
	// automatically assigned to common compartments by the broker.
	//
	// Maximum compartment ID list lengths are enforced to ensure broker
	// request sizes don't grow unbounded.
	//
	// Limitation: currently, in max length trimming, new common compartment
	// IDs take precedence over older IDs.

	maxCompartmentIDListLength := p.Int(parameters.InproxyMaxCompartmentIDListLength)

	// Personal compartment ID limitations:
	//
	// The broker API messages, ProxyAnnounceRequest and ClientOfferRequest,
	// support lists of personal compartment IDs. However, both the proxy and
	// the client are currently limited to specifying at most one personal
	// compartment ID due to the following limitations:
	//
	// - On the broker side, the matcher queue implementation supports at most
	//   one proxy personal compartment ID. See inproxy/Matcher.Announce. The
	//   broker currently enforces that at most one personal compartment ID
	//   may be specified per ProxyAnnounceRequest.
	//
	// - On the proxy/client side, the personal pairing rendezvous logic --
	//   which aims for proxies and clients to select the same initial broker
	//   and same order of failover to other brokers -- uses a shuffle that
	//   assumes both the proxy and client use the same single, personal
	//   compartment ID

	var configPersonalCompartmentIDs []string
	if isProxy && len(config.InproxyProxyPersonalCompartmentID) > 0 {
		configPersonalCompartmentIDs = []string{config.InproxyProxyPersonalCompartmentID}
	} else if !isProxy && len(config.InproxyClientPersonalCompartmentID) > 0 {
		configPersonalCompartmentIDs = []string{config.InproxyClientPersonalCompartmentID}
	}
	personalCompartmentIDs, err := inproxy.IDsFromStrings(configPersonalCompartmentIDs)
	if err != nil {
		return nil, nil, errors.Trace(err)
	}

	if len(personalCompartmentIDs) > maxCompartmentIDListLength {

		// Trim the list. It's not expected that user-configured personal
		// compartment ID lists will exceed the max length.
		//
		// TODO: shuffle before trimming? Prioritize previous matches?

		personalCompartmentIDs = personalCompartmentIDs[:maxCompartmentIDListLength]
	}

	var commonCompartmentIDs []inproxy.ID
	if !isProxy && len(personalCompartmentIDs) == 0 {

		tacticsCommonCompartmentIDs := p.InproxyCompartmentIDs(parameters.InproxyCommonCompartmentIDs)

		knownCommonCompartmentIDs, err := LoadInproxyCommonCompartmentIDs()
		if err != nil {
			NoticeWarning("LoadInproxyCommonCompartmentIDs failed: %v", errors.Trace(err))
			// Continue with only the tactics common compartment IDs.
		}

		newCompartmentIDs := make([]string, 0, len(tacticsCommonCompartmentIDs))

		for _, compartmentID := range tacticsCommonCompartmentIDs {
			// TODO: faster lookup?
			if !common.Contains(knownCommonCompartmentIDs, compartmentID) {
				newCompartmentIDs = append(newCompartmentIDs, compartmentID)
			}
		}

		if len(newCompartmentIDs) > 0 {
			newCompartmentIDs = append(newCompartmentIDs, knownCommonCompartmentIDs...)

			// Locally store more than InproxyMaxCompartmentIDListLength known
			// common compartment IDs, in case the request limit parameter is
			// increased in the future.
			// maxPersistedCommonCompartmentIDListLength still limits the
			// length of the list to cap local memory and disk impact.

			maxPersistedCommonCompartmentIDListLength := 500 // ~16K
			if maxCompartmentIDListLength > maxPersistedCommonCompartmentIDListLength {
				maxPersistedCommonCompartmentIDListLength = maxCompartmentIDListLength
			}

			if len(newCompartmentIDs) > maxPersistedCommonCompartmentIDListLength {
				newCompartmentIDs = newCompartmentIDs[:maxPersistedCommonCompartmentIDListLength]
			}

			err := StoreInproxyCommonCompartmentIDs(newCompartmentIDs)
			if err != nil {
				NoticeWarning("StoreInproxyCommonCompartmentIDs failed: %v", errors.Trace(err))
				// Continue without persisting new common compartment IDs.
			}

			knownCommonCompartmentIDs = newCompartmentIDs
		}

		commonCompartmentIDs, err = inproxy.IDsFromStrings(knownCommonCompartmentIDs)
		if err != nil {
			return nil, nil, errors.Trace(err)
		}

		if len(commonCompartmentIDs) > maxCompartmentIDListLength {
			// TODO: shuffle before trimming? Prioritize previous matches?
			commonCompartmentIDs = commonCompartmentIDs[:maxCompartmentIDListLength]
		}
	}

	return commonCompartmentIDs, personalCompartmentIDs, nil
}

// HasSuccess indicates whether this broker client instance has completed at
// least one successful round trip.
func (b *InproxyBrokerClientInstance) HasSuccess() bool {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	return !b.lastSuccess.IsZero()
}

// Close closes the broker client round tripper, including closing all
// underlying network connections, which will interrupt any in-flight round
// trips.
func (b *InproxyBrokerClientInstance) Close() error {

	// Concurrency note: Close is called from InproxyBrokerClientManager with
	// its mutex locked. Close must not lock InproxyBrokerClientInstance's
	// mutex, or else there is a risk of deadlock similar to the HasSuccess
	// case documented in InproxyBrokerClientManager.GetBrokerClient.

	err := b.roundTripper.Close()
	return errors.Trace(err)
}

// Implements the inproxy.BrokerDialCoordinator interface.
func (b *InproxyBrokerClientInstance) NetworkID() string {
	return b.networkID
}

// Implements the inproxy.BrokerDialCoordinator interface.
func (b *InproxyBrokerClientInstance) NetworkType() inproxy.NetworkType {
	return getInproxyNetworkType(GetNetworkType(b.networkID))
}

// Implements the inproxy.BrokerDialCoordinator interface.
func (b *InproxyBrokerClientInstance) CommonCompartmentIDs() []inproxy.ID {
	return b.commonCompartmentIDs
}

// Implements the inproxy.BrokerDialCoordinator interface.
func (b *InproxyBrokerClientInstance) PersonalCompartmentIDs() []inproxy.ID {
	return b.personalCompartmentIDs
}

// Implements the inproxy.BrokerDialCoordinator interface.
func (b *InproxyBrokerClientInstance) DisableWaitToShareSession() bool {
	return b.disableWaitToShareSession
}

// Implements the inproxy.BrokerDialCoordinator interface.
func (b *InproxyBrokerClientInstance) BrokerClientPrivateKey() inproxy.SessionPrivateKey {
	return b.brokerClientPrivateKey
}

// Implements the inproxy.BrokerDialCoordinator interface.
func (b *InproxyBrokerClientInstance) BrokerPublicKey() inproxy.SessionPublicKey {
	return b.brokerPublicKey
}

// Implements the inproxy.BrokerDialCoordinator interface.
func (b *InproxyBrokerClientInstance) BrokerRootObfuscationSecret() inproxy.ObfuscationSecret {
	return b.brokerRootObfuscationSecret
}

// Implements the inproxy.BrokerDialCoordinator interface.
func (b *InproxyBrokerClientInstance) BrokerClientRoundTripper() (inproxy.RoundTripper, error) {

	// Returns the same round tripper for the lifetime of the
	// inproxy.BrokerDialCoordinator, ensuring all requests for one in-proxy
	// dial or proxy relay use the same broker, as is necessary due to the
	// broker state for the proxy announce/answer, client broker/server
	// relay, etc.

	return b.roundTripper, nil
}

// Implements the inproxy.BrokerDialCoordinator interface.
func (b *InproxyBrokerClientInstance) BrokerClientRoundTripperSucceeded(roundTripper inproxy.RoundTripper) {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	if rt, ok := roundTripper.(*InproxyBrokerRoundTripper); !ok || rt != b.roundTripper {
		// Passing in the round tripper obtained from BrokerClientRoundTripper
		// is just used for sanity check in this implementation, since each
		// InproxyBrokerClientInstance has exactly one round tripper.
		NoticeError("BrokerClientRoundTripperSucceeded: roundTripper instance mismatch")
		return
	}

	now := time.Now()
	b.lastSuccess = now

	// Set replay or extend the broker dial parameters replay TTL after a
	// success. With tunnel dial parameters, the replay TTL is extended after
	// every successful tunnel connection. Since there are potentially more
	// and more frequent broker round trips compared to tunnel dials, the TTL
	// is only extended after some target duration has elapsed, to avoid
	// excessive datastore writes.

	if b.replayEnabled && now.Sub(b.lastStoreReplay) > b.replayUpdateFrequency {
		b.brokerDialParams.LastUsedTimestamp = time.Now()

		err := SetNetworkReplayParameters[InproxyBrokerDialParameters](
			b.networkID, b.brokerDialParams.brokerSpec.BrokerPublicKey, b.brokerDialParams)
		if err != nil {
			NoticeWarning("StoreBrokerDialParameters failed: %v", errors.Trace(err))
			// Continue without persisting replay changes.
		} else {
			b.lastStoreReplay = now
		}
	}

	// Verify/extend the resolver cache entry for any resolved domain after a
	// success.
	//
	// Limitation: currently this re-extends regardless of how long ago the DNS
	// resolve happened.

	resolver := b.config.GetResolver()
	if resolver != nil {
		resolver.VerifyCacheExtension(b.brokerDialParams.FrontedHTTPDialParameters.FrontingDialAddress)
	}
}

// Implements the inproxy.BrokerDialCoordinator interface.
func (b *InproxyBrokerClientInstance) BrokerClientRoundTripperFailed(roundTripper inproxy.RoundTripper) {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	if rt, ok := roundTripper.(*InproxyBrokerRoundTripper); !ok || rt != b.roundTripper {
		// Passing in the round tripper obtained from BrokerClientRoundTripper
		// is just used for sanity check in this implementation, since each
		// InproxyBrokerClientInstance has exactly one round tripper.
		NoticeError("BrokerClientRoundTripperFailed: roundTripper instance mismatch")
		return
	}

	// For common pairing proxies, skip both the replay deletion and the
	// InproxyBrokerClientInstance reset for a short duration after a recent
	// round trip success. In this case, subsequent broker requests will use
	// the existing round tripper, wired up with the same dial parameters and
	// fronting provider selection. If the failure was due to a transient
	// TLS/TCP network failure, the net/http round tripper should establish a
	// new connection on the next request.
	//
	// This retry is intended to retain proxy affinity with its currently
	// selected broker in cases such as broker service upgrades/restarts or
	// brief network interruptions, mitigating load balancing issues that
	// otherwise occur (e.g., all proxies fail over to other brokers, leaving
	// no supply on a restarted broker).
	//
	// In common pairing mode, clients do not perform this retry and
	// immediately reset, as is appropriate for the tunnel establishment
	// race. In personal pairing mode, neither proxies nor clients retry and
	// instead follow the personal pairing broker selection scheme in an
	// effort to rendezvous at the same broker with minimal delay.
	//
	// A delay before retrying announce requests is appropriate, but there is
	// no delay added here since Proxy.proxyOneClient already schedule delays
	// between announcements.
	//
	// Limitation: BrokerClientRoundTripperSucceeded is not invoked -- and no
	// recent last success time is set -- for proxies which announce, don't
	// match, and then hit the misaligned fronting provider request timeout
	// issue. See the ""unexpected response status code" case and comment in
	// InproxyBrokerRoundTripper.RoundTrip. This case should be mitigated by
	// configuring InproxyFrontingProviderServerMaxRequestTimeouts.
	//
	// TODO: also retry after initial startup, with no previous success? This
	// would further retain random load balancing of proxies newly starting
	// at the same time that their initially selected broker is restarted or
	// briefly unavailable.

	if b.brokerClientManager.isProxy &&
		!b.config.IsInproxyProxyPersonalPairingMode() &&
		b.retryOnFailedPeriod > 0 &&
		!b.lastSuccess.IsZero() &&
		time.Since(b.lastSuccess) <= b.retryOnFailedPeriod {

		NoticeWarning("BrokerClientRoundTripperFailed: retry roundTripper")
		return
	}

	// Delete any persistent replay dial parameters. Unlike with the success
	// case, consecutive, repeated deletes shouldn't write to storage, so
	// they are not avoided.

	if b.replayEnabled &&
		!prng.FlipWeightedCoin(b.replayRetainFailedProbability) {

		// Limitation: there's a race condition with multiple
		// InproxyBrokerClientInstances writing to the replay datastore for
		// the same broker, such as in the case where there's a dual-mode
		// in-proxy client and proxy; this delete could potentially clobber a
		// concurrent fresh replay store after a success.
		//
		// TODO: add an additional storage key distinguisher for each instance?

		err := DeleteNetworkReplayParameters[InproxyBrokerDialParameters](
			b.networkID, b.brokerDialParams.brokerSpec.BrokerPublicKey)
		if err != nil {
			NoticeWarning("DeleteBrokerDialParameters failed: %v", errors.Trace(err))
			// Continue without resetting replay.
		}
	}

	// Remove the TLS session cache entry for the broker's fronting dial address, if present.
	// This ensures that the next round trip establishes a new TLS session, avoiding potential issues
	// caused by session resumption fingerprint that may have contributed to the round tripper failure.
	if hardcodedCache := b.brokerDialParams.FrontedHTTPDialParameters.meekConfig.TLSClientSessionCache; hardcodedCache != nil {
		hardcodedCache.RemoveCacheEntry()
	}

	// Invoke resetBrokerClientOnRoundTripperFailed to signal the
	// InproxyBrokerClientManager to create a new
	// InproxyBrokerClientInstance, with new dial parameters and a new round
	// tripper, after a failure.
	//
	// This InproxyBrokerClientInstance doesn't change its dial parameters or
	// round tripper to ensure that any concurrent usage retains affinity
	// with the same parameters and broker.
	//
	// Limitation: a transport-level failure may unnecessarily reset the
	// broker session state; see comment in NewInproxyBrokerClientInstance.

	err := b.brokerClientManager.resetBrokerClientOnRoundTripperFailed(b)
	if err != nil {
		NoticeWarning("reset broker client failed: %v", errors.Trace(err))
		// Continue with old broker client instance.
	}
}

// Implements the inproxy.BrokerDialCoordinator interface.
func (b *InproxyBrokerClientInstance) BrokerClientNoMatch(roundTripper inproxy.RoundTripper) {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	if rt, ok := roundTripper.(*InproxyBrokerRoundTripper); !ok || rt != b.roundTripper {
		// See roundTripper check comment in BrokerClientRoundTripperFailed.
		NoticeError("BrokerClientNoMatch: roundTripper instance mismatch")
		return
	}

	// Any persistent replay dial parameters are retained and not deleted,
	// since the broker client successfully transacted with the broker.

	err := b.brokerClientManager.resetBrokerClientOnNoMatch(b)
	if err != nil {
		NoticeWarning("reset broker client failed: %v", errors.Trace(err))
		// Continue with old broker client instance.
	}
}

// Implements the inproxy.BrokerDialCoordinator interface.
func (b *InproxyBrokerClientInstance) MetricsForBrokerRequests() common.LogFields {
	return b.brokerDialParams.GetMetricsForBrokerRequests()
}

// Implements the inproxy.BrokerDialCoordinator interface.
func (b *InproxyBrokerClientInstance) AnnounceRequestTimeout() time.Duration {
	return b.announceRequestTimeout
}

// Implements the inproxy.BrokerDialCoordinator interface.
func (b *InproxyBrokerClientInstance) SessionHandshakeRoundTripTimeout() time.Duration {
	return b.sessionHandshakeTimeout
}

// Implements the inproxy.BrokerDialCoordinator interface.
func (b *InproxyBrokerClientInstance) AnnounceDelay() time.Duration {
	return b.announceDelay
}

// Implements the inproxy.BrokerDialCoordinator interface.
func (b *InproxyBrokerClientInstance) AnnounceMaxBackoffDelay() time.Duration {
	return b.announceMaxBackoffDelay
}

// Implements the inproxy.BrokerDialCoordinator interface.
func (b *InproxyBrokerClientInstance) AnnounceDelayJitter() float64 {
	return b.announceDelayJitter
}

// Implements the inproxy.BrokerDialCoordinator interface.
func (b *InproxyBrokerClientInstance) AnswerRequestTimeout() time.Duration {
	return b.answerRequestTimeout
}

// Implements the inproxy.BrokerDialCoordinator interface.
func (b *InproxyBrokerClientInstance) OfferRequestTimeout() time.Duration {
	return b.offerRequestTimeout
}

// Implements the inproxy.BrokerDialCoordinator interface.
func (b *InproxyBrokerClientInstance) OfferRequestPersonalTimeout() time.Duration {
	return b.offerRequestPersonalTimeout
}

// Implements the inproxy.BrokerDialCoordinator interface.
func (b *InproxyBrokerClientInstance) OfferRetryDelay() time.Duration {
	return b.offerRetryDelay
}

// Implements the inproxy.BrokerDialCoordinator interface.
func (b *InproxyBrokerClientInstance) OfferRetryJitter() float64 {
	return b.offerRetryJitter
}

// Implements the inproxy.BrokerDialCoordinator interface.
func (b *InproxyBrokerClientInstance) RelayedPacketRequestTimeout() time.Duration {
	return b.relayedPacketRequestTimeout
}

// InproxyBrokerDialParameters represents a selected broker transport and dial
// paramaters.
//
// InproxyBrokerDialParameters is used to configure dialers; as a persistent
// record to store successful dial parameters for replay; and to report dial
// stats in notices and Psiphon API calls.
//
// InproxyBrokerDialParameters is similar to tunnel DialParameters, but is
// specific to the in-proxy broker dial phase.
type InproxyBrokerDialParameters struct {
	brokerSpec *parameters.InproxyBrokerSpec `json:"-"`
	isReplay   bool                          `json:"-"`
	isReuse    bool                          `json:"-"`

	LastUsedTimestamp      time.Time
	LastUsedBrokerSpecHash []byte

	FrontedHTTPDialParameters *FrontedMeekDialParameters
}

// MakeInproxyBrokerDialParameters creates a new InproxyBrokerDialParameters.
func MakeInproxyBrokerDialParameters(
	config *Config,
	p parameters.ParametersAccessor,
	networkID string,
	brokerSpec *parameters.InproxyBrokerSpec,
	tlsCache utls.ClientSessionCache) (*InproxyBrokerDialParameters, error) {

	if config.UseUpstreamProxy() {
		return nil, errors.TraceNew("upstream proxy unsupported")
	}

	currentTimestamp := time.Now()

	// Select new broker dial parameters

	brokerDialParams := &InproxyBrokerDialParameters{
		brokerSpec:             brokerSpec,
		LastUsedTimestamp:      currentTimestamp,
		LastUsedBrokerSpecHash: hashBrokerSpec(brokerSpec),
	}

	// FrontedMeekDialParameters
	//
	// The broker round trips use MeekModeWrappedPlaintextRoundTrip without
	// meek cookies, so meek obfuscation is not configured. The in-proxy
	// broker session payloads have their own obfuscation layer.

	payloadSecure := true
	skipVerify := false

	var err error
	brokerDialParams.FrontedHTTPDialParameters, err = makeFrontedMeekDialParameters(
		config,
		p,
		nil,
		brokerSpec.BrokerFrontingSpecs,
		nil,
		true,
		skipVerify,
		config.DisableSystemRootCAs,
		payloadSecure,
		tlsCache,
	)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// Initialize Dial/MeekConfigs to be passed to the corresponding dialers.

	err = brokerDialParams.prepareDialConfigs(
		config,
		p,
		false,
		tlsCache)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return brokerDialParams, nil
}

// prepareDialConfigs is called for both new and replayed broker dial parameters.
func (brokerDialParams *InproxyBrokerDialParameters) prepareDialConfigs(
	config *Config,
	p parameters.ParametersAccessor,
	isReplay bool,
	tlsCache utls.ClientSessionCache) error {

	brokerDialParams.isReplay = isReplay

	// brokerDialParams.isReuse is set only later, as this is a new broker
	// client dial.

	if isReplay {
		// FrontedHTTPDialParameters
		//
		// The broker round trips use MeekModeWrappedPlaintextRoundTrip without
		// meek cookies, so meek obfuscation is not configured. The in-proxy
		// broker session payloads have their own obfuscation layer.

		payloadSecure := true
		skipVerify := false

		err := brokerDialParams.FrontedHTTPDialParameters.prepareDialConfigs(
			config, p, nil, nil, true, skipVerify,
			config.DisableSystemRootCAs, payloadSecure, tlsCache)
		if err != nil {
			return errors.Trace(err)
		}
	}

	return nil
}

// GetMetricsForBroker returns broker client dial parameter log fields to be
// reported to a broker.
func (brokerDialParams *InproxyBrokerDialParameters) GetMetricsForBrokerRequests() common.LogFields {

	logFields := common.LogFields{}

	// TODO: add additional broker fronting dial parameters to be logged by
	// the broker -- as successful parameters might not otherwise by logged
	// via server_tunnel if the subsequent WebRTC dials fail.

	logFields["fronting_provider_id"] = brokerDialParams.FrontedHTTPDialParameters.FrontingProviderID

	return logFields
}

// GetMetrics implements the common.MetricsSource interface and returns log
// fields detailing the broker dial parameters.
func (brokerDialParams *InproxyBrokerDialParameters) GetMetrics() common.LogFields {

	logFields := common.LogFields{}

	// Add underlying log fields, which must be renamed to be scoped to the
	// broker.
	logFields.Add(brokerDialParams.FrontedHTTPDialParameters.GetMetrics("inproxy_broker_"))

	logFields["inproxy_broker_transport"] = brokerDialParams.FrontedHTTPDialParameters.FrontingTransport

	isReplay := "0"
	if brokerDialParams.isReplay {
		isReplay = "1"
	}
	logFields["inproxy_broker_is_replay"] = isReplay

	isReuse := "0"
	if brokerDialParams.isReuse {
		isReuse = "1"
	}
	logFields["inproxy_broker_is_reuse"] = isReuse

	return logFields
}

// hashBrokerSpec hashes the broker spec. The hash is used to detect when
// broker spec tactics have changed.
func hashBrokerSpec(spec *parameters.InproxyBrokerSpec) []byte {
	var hash [8]byte
	binary.BigEndian.PutUint64(
		hash[:],
		uint64(xxhash.Sum64String(fmt.Sprintf("%+v", spec))))
	return hash[:]
}

// InproxyBrokerRoundTripper is a broker request round trip transport
// implemented using MeekConn in MeekModePlaintextRoundTrip mode, utilizing
// MeekConn's domain fronting capabilities and using persistent and
// multiplexed connections, via HTTP/2, to support multiple concurrent
// in-flight round trips.
//
// InproxyBrokerRoundTripper implements the inproxy.RoundTripper interface.
type InproxyBrokerRoundTripper struct {
	brokerDialParams *InproxyBrokerDialParameters
	runCtx           context.Context
	stopRunning      context.CancelFunc
	dial             int32
	dialCompleted    chan struct{}
	dialErr          error
	conn             *MeekConn
	failureThreshold time.Duration
}

// NewInproxyBrokerRoundTripper creates a new InproxyBrokerRoundTripper. The
// initial DialMeek is defered until the first call to RoundTrip, so
// NewInproxyBrokerRoundTripper does not perform any network operations.
//
// The input brokerDialParams dial parameter and config fields must not
// modifed after NewInproxyBrokerRoundTripper is called.
func NewInproxyBrokerRoundTripper(
	p parameters.ParametersAccessor,
	brokerDialParams *InproxyBrokerDialParameters) *InproxyBrokerRoundTripper {

	runCtx, stopRunning := context.WithCancel(context.Background())

	return &InproxyBrokerRoundTripper{
		brokerDialParams: brokerDialParams,
		runCtx:           runCtx,
		stopRunning:      stopRunning,
		dialCompleted:    make(chan struct{}),
		failureThreshold: p.Duration(
			parameters.InproxyBrokerRoundTripStatusCodeFailureThreshold),
	}
}

// Close interrupts any in-flight request and closes the underlying
// MeekConn.
func (rt *InproxyBrokerRoundTripper) Close() error {

	// Interrupt any DialMeek or RoundTrip.
	rt.stopRunning()

	if atomic.CompareAndSwapInt32(&rt.dial, 0, 1) {

		// RoundTrip has not yet been called or has not yet kicked off
		// DialMeek, so there is no MeekConn to close. Prevent any future
		// DialMeek by signaling dialCompleted and fail any future round trip
		// attempt by setting dialErr.

		rt.dialErr = errors.TraceNew("closed")
		close(rt.dialCompleted)

	} else {

		// Await any ongoing DialMeek or RoundTrip (stopRunning should
		// interrupt either one quickly).

		<-rt.dialCompleted
		if rt.conn != nil {
			_ = rt.conn.Close()
		}
	}

	// As with MeekConn.Close, any Close errors from underlying conns are not
	// propagated.
	return nil
}

// RoundTrip transports a request to the broker endpoint and returns a
// response.
func (rt *InproxyBrokerRoundTripper) RoundTrip(
	ctx context.Context,
	roundTripDelay time.Duration,
	roundTripTimeout time.Duration,
	requestPayload []byte) (_ []byte, retErr error) {

	defer func() {
		// Log any error which results in invoking BrokerClientRoundTripperFailed.
		var failedError *inproxy.RoundTripperFailedError
		if std_errors.As(retErr, &failedError) {
			NoticeWarning("RoundTripperFailedError: %v", retErr)
		}
	}()

	// Cancel DialMeek or MeekConn.RoundTrip when:
	// - Close is called
	// - the input context is done
	ctx, cancelFunc := common.MergeContextCancel(ctx, rt.runCtx)
	defer cancelFunc()

	// Apply any round trip delay. Currently, this is used to apply an
	// announce request delay post-waitToShareSession, pre-network round
	// trip, and cancelable by the above merged context.
	if roundTripDelay > 0 {
		common.SleepWithContext(ctx, roundTripDelay)
	}

	// Apply the round trip timeout after any delay is complete.
	//
	// This timeout includes any TLS handshake network round trips, as
	// performed by the initial DialMeek and may be performed subsequently by
	// net/http via MeekConn.RoundTrip. These extra round trips should be
	// accounted for in the in the difference between client-side request
	// timeouts, such as InproxyProxyAnswerRequestTimeout, and broker-side
	// handler timeouts, such as InproxyBrokerProxyAnnounceTimeout, with the
	// former allowing more time for network round trips.

	requestCtx := ctx
	if roundTripTimeout > 0 {
		var requestCancelFunc context.CancelFunc
		requestCtx, requestCancelFunc = context.WithTimeout(ctx, roundTripTimeout)
		defer requestCancelFunc()
	}

	// The first RoundTrip caller will perform the DialMeek step, which
	// establishes the TLS trasport connection to the fronted endpoint.
	// Following callers will await that DialMeek or share an established
	// connection.
	//
	// To accomodate using custom utls fingerprints, with varying ALPNs, with
	// net/http, DialMeek completes a full TLS handshake before instantiating
	// the appropriate http.Transport or http2.Transport. Until that first
	// DialMeek completes, and unlike standard net/http round trips,
	// InproxyBrokerRoundTripper won't spawn distinct TLS persistent
	// connections for concurrent round trips. After DialMeek, concurrent
	// round trips over HTTP/2 connections may simply share the one TLS
	// connection, while concurrent round trips over HTTP connections may
	// spawn additional TLS persistent connections.
	//
	// There is no retry here if DialMeek fails, as higher levels will invoke
	// BrokerClientRoundTripperFailed on failure, clear any replay, select
	// new dial parameters, and retry.

	if atomic.CompareAndSwapInt32(&rt.dial, 0, 1) {

		// DialMeek hasn't been called yet.

		conn, err := DialMeek(
			requestCtx,
			rt.brokerDialParams.FrontedHTTPDialParameters.meekConfig,
			rt.brokerDialParams.FrontedHTTPDialParameters.dialConfig)

		if err != nil && ctx.Err() != context.Canceled {

			// DialMeek performs an initial TLS handshake. DialMeek errors,
			// excluding a cancelled context as happens on shutdown, are
			// classified as as RoundTripperFailedErrors, which will invoke
			// BrokerClientRoundTripperFailed, resetting the round tripper
			// and clearing replay parameters.

			err = inproxy.NewRoundTripperFailedError(err)
		}

		rt.conn = conn
		rt.dialErr = err
		close(rt.dialCompleted)

		if err != nil {
			return nil, errors.Trace(rt.dialErr)
		}

	} else {

		// Await any ongoing DialMeek run by a concurrent RoundTrip caller.

		select {
		case <-rt.dialCompleted:
		case <-ctx.Done():
			return nil, errors.Trace(ctx.Err())
		}

		if rt.dialErr != nil {

			// There is no NewRoundTripperFailedError wrapping here, as the
			// DialMeek caller will wrap its error and
			// BrokerClientRoundTripperFailed will be invoked already.

			return nil, errors.Trace(rt.dialErr)
		}
	}

	// At this point, rt.conn is an established MeekConn.

	// Note that the network address portion of the URL will be ignored by
	// MeekConn in favor of the MeekDialConfig, while the path will be used.
	url := fmt.Sprintf(
		"https://%s/%s",
		rt.brokerDialParams.FrontedHTTPDialParameters.DialAddress,
		inproxy.BrokerEndPointName)

	request, err := http.NewRequestWithContext(
		requestCtx, "POST", url, bytes.NewBuffer(requestPayload))
	if err != nil {
		return nil, errors.Trace(err)
	}

	startTime := time.Now()
	response, err := rt.conn.RoundTrip(request)
	roundTripDuration := time.Since(startTime)

	if err == nil {
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {

			err = fmt.Errorf(
				"unexpected response status code %d after %v",
				response.StatusCode,
				roundTripDuration)

			// Depending on the round trip duration, this case is treated as a
			// temporary round tripper failure, since we received a response
			// from the CDN, secured with TLS and VerifyPins, or from broker
			// itself. One common scenario is the CDN returning a temporary
			// timeout error, as can happen when CDN timeouts and broker
			// timeouts are misaligned, especially for long-polling requests.
			//
			// In this scenario, we can reuse the existing round tripper and
			// it may be counterproductive to return a RoundTripperFailedError
			// which will trigger a clearing of any broker dial replay
			// parameters as well as reseting the round tripper.
			//
			// When the round trip duration is sufficiently short, much
			// shorter than expected round trip timeouts, this is still
			// classified as a RoundTripperFailedError error, as it is more
			// likely due to a more serious issue between the CDN and broker.

			if rt.failureThreshold > 0 &&
				roundTripDuration <= rt.failureThreshold {

				err = inproxy.NewRoundTripperFailedError(err)
			}
		}
	} else if ctx.Err() != context.Canceled {

		// Other round trip errors, including TLS failures and client-side
		// timeouts, but excluding a cancelled context as happens on
		// shutdown, are classified as RoundTripperFailedErrors.

		err = inproxy.NewRoundTripperFailedError(err)
	}
	if err != nil {
		return nil, errors.Trace(err)
	}

	responsePayload, err := io.ReadAll(response.Body)
	if err != nil {
		err = inproxy.NewRoundTripperFailedError(err)
		return nil, errors.Trace(err)
	}

	return responsePayload, nil
}

// InproxyWebRTCDialInstance is the network state and dial parameters for a
// single WebRTC client or proxy connection.
//
// InproxyWebRTCDialInstance implements the inproxy.WebRTCDialCoordinator
// interface, which provides the WebRTC dial configuration and support to the
// in-proxy package.
type InproxyWebRTCDialInstance struct {
	config          *Config
	networkID       string
	natStateManager *InproxyNATStateManager

	stunDialParameters   *InproxySTUNDialParameters
	webRTCDialParameters *InproxyWebRTCDialParameters

	discoverNAT                     bool
	disableSTUN                     bool
	disablePortMapping              bool
	disableInboundForMobileNetworks bool
	disableIPv6ICECandidates        bool
	discoverNATTimeout              time.Duration
	webRTCAnswerTimeout             time.Duration
	webRTCAwaitPortMappingTimeout   time.Duration
	awaitReadyToProxyTimeout        time.Duration
	proxyDestinationDialTimeout     time.Duration
	proxyRelayInactivityTimeout     time.Duration
}

// NewInproxyWebRTCDialInstance creates a new InproxyWebRTCDialInstance.
//
// The caller provides STUN and WebRTC dial parameters that are either newly
// generated or replayed. Proxies may optionally pass in nil for either
// stunDialParameters or webRTCDialParameters, and new parameters will be
// generated.
func NewInproxyWebRTCDialInstance(
	config *Config,
	networkID string,
	isProxy bool,
	natStateManager *InproxyNATStateManager,
	stunDialParameters *InproxySTUNDialParameters,
	webRTCDialParameters *InproxyWebRTCDialParameters) (*InproxyWebRTCDialInstance, error) {

	p := config.GetParameters().Get()
	defer p.Close()

	if isProxy && stunDialParameters == nil {
		// Auto-generate STUN dial parameters. There's no replay in this case.
		var err error
		stunDialParameters, err = MakeInproxySTUNDialParameters(config, p, isProxy)
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	if isProxy && webRTCDialParameters == nil {
		// Auto-generate STUN dial parameters. There's no replay in this case.
		var err error
		webRTCDialParameters, err = MakeInproxyWebRTCDialParameters(p)
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	disableSTUN := p.Bool(parameters.InproxyDisableSTUN)
	disablePortMapping := p.Bool(parameters.InproxyDisablePortMapping)
	disableInboundForMobileNetworks := p.Bool(parameters.InproxyDisableInboundForMobileNetworks)
	disableIPv6ICECandidates := p.Bool(parameters.InproxyDisableIPv6ICECandidates)

	var discoverNATTimeout, awaitReadyToProxyTimeout time.Duration

	if isProxy {

		disableSTUN = disableSTUN || p.Bool(parameters.InproxyProxyDisableSTUN)

		disablePortMapping = disablePortMapping || p.Bool(parameters.InproxyProxyDisablePortMapping)

		disableInboundForMobileNetworks = disableInboundForMobileNetworks ||
			p.Bool(parameters.InproxyProxyDisableInboundForMobileNetworks)

		disableIPv6ICECandidates = disableIPv6ICECandidates ||
			p.Bool(parameters.InproxyProxyDisableIPv6ICECandidates)

		discoverNATTimeout = p.Duration(parameters.InproxyProxyDiscoverNATTimeout)

		awaitReadyToProxyTimeout = p.Duration(parameters.InproxyProxyWebRTCAwaitReadyToProxyTimeout)

	} else {

		disableSTUN = disableSTUN || p.Bool(parameters.InproxyClientDisableSTUN)

		disablePortMapping = disablePortMapping || p.Bool(parameters.InproxyClientDisablePortMapping)

		disableInboundForMobileNetworks = disableInboundForMobileNetworks ||
			p.Bool(parameters.InproxyClientDisableInboundForMobileNetworks)

		disableIPv6ICECandidates = disableIPv6ICECandidates ||
			p.Bool(parameters.InproxyClientDisableIPv6ICECandidates)

		discoverNATTimeout = p.Duration(parameters.InproxyClientDiscoverNATTimeout)

		awaitReadyToProxyTimeout = p.Duration(parameters.InproxyClientWebRTCAwaitReadyToProxyTimeout)
	}

	if clientAPILevelDisableInproxyPortMapping.Load() {
		disablePortMapping = true
	}

	// Parameters such as disabling certain operations and operation timeouts
	// are not replayed, but snapshots are stored in the
	// InproxyWebRTCDialInstance for efficient lookup.

	return &InproxyWebRTCDialInstance{
		config:          config,
		networkID:       networkID,
		natStateManager: natStateManager,

		stunDialParameters:   stunDialParameters,
		webRTCDialParameters: webRTCDialParameters,

		// discoverNAT is ignored by proxies, which always attempt discovery.
		// webRTCAnswerTimeout, proxyDestinationDialTimeout, and
		// proxyRelayInactivityTimeout are used only by proxies.

		discoverNAT:                     p.WeightedCoinFlip(parameters.InproxyClientDiscoverNATProbability),
		disableSTUN:                     disableSTUN,
		disablePortMapping:              disablePortMapping,
		disableInboundForMobileNetworks: disableInboundForMobileNetworks,
		disableIPv6ICECandidates:        disableIPv6ICECandidates,
		discoverNATTimeout:              discoverNATTimeout,
		webRTCAnswerTimeout:             p.Duration(parameters.InproxyWebRTCAnswerTimeout),
		webRTCAwaitPortMappingTimeout:   p.Duration(parameters.InproxyWebRTCAwaitPortMappingTimeout),
		awaitReadyToProxyTimeout:        awaitReadyToProxyTimeout,
		proxyDestinationDialTimeout:     p.Duration(parameters.InproxyProxyDestinationDialTimeout),
		proxyRelayInactivityTimeout:     p.Duration(parameters.InproxyProxyRelayInactivityTimeout),
	}, nil
}

// Implements the inproxy.WebRTCDialCoordinator interface.
func (w *InproxyWebRTCDialInstance) NetworkID() string {
	return w.networkID
}

// Implements the inproxy.WebRTCDialCoordinator interface.
func (w *InproxyWebRTCDialInstance) NetworkType() inproxy.NetworkType {
	return getInproxyNetworkType(GetNetworkType(w.networkID))
}

// Implements the inproxy.WebRTCDialCoordinator interface.
func (w *InproxyWebRTCDialInstance) ClientRootObfuscationSecret() inproxy.ObfuscationSecret {
	return w.webRTCDialParameters.RootObfuscationSecret
}

// Implements the inproxy.WebRTCDialCoordinator interface.
func (w *InproxyWebRTCDialInstance) DoDTLSRandomization() bool {
	return w.webRTCDialParameters.DoDTLSRandomization
}

// Implements the inproxy.WebRTCDialCoordinator interface.
func (w *InproxyWebRTCDialInstance) UseMediaStreams() bool {
	return w.webRTCDialParameters.UseMediaStreams
}

// Implements the inproxy.WebRTCDialCoordinator interface.
func (w *InproxyWebRTCDialInstance) TrafficShapingParameters() *inproxy.TrafficShapingParameters {
	return w.webRTCDialParameters.TrafficShapingParameters
}

// Implements the inproxy.WebRTCDialCoordinator interface.
func (w *InproxyWebRTCDialInstance) STUNServerAddress(RFC5780 bool) string {
	if RFC5780 {
		return w.stunDialParameters.STUNServerAddressRFC5780
	} else {
		return w.stunDialParameters.STUNServerAddress
	}
}

// Implements the inproxy.WebRTCDialCoordinator interface.
func (w *InproxyWebRTCDialInstance) STUNServerAddressResolved(RFC5780 bool) string {
	if RFC5780 {
		return w.stunDialParameters.STUNServerAddressRFC5780
	} else {
		return w.stunDialParameters.STUNServerAddress
	}
}

// Implements the inproxy.WebRTCDialCoordinator interface.
func (w *InproxyWebRTCDialInstance) STUNServerAddressSucceeded(RFC5780 bool, address string) {

	// Currently, for client tunnel dials, STUN dial parameter replay is
	// managed by DialParameters and DialParameters.InproxySTUNDialParameters
	// are replayed only when the entire dial succeeds.
	//
	// Note that, for a client tunnel dial, even if the STUN step fails and
	// there are no STUN ICE candidates, the subsequent WebRTC connection may
	// still proceed and be successful. In this case, the failed STUN dial
	// parameters may be replayed.
	//
	// For proxies, there is no STUN dial parameter replay.
	//
	// As a future enhancement, consider independent and shared replay of
	// working STUN servers, similar to how broker client dial parameters are
	// replayed independent of overall dials and proxy relays, and shared
	// between local client and proxy instances.

	// Verify/extend the resolver cache entry for any resolved domain after a
	// success.

	resolver := w.config.GetResolver()
	if resolver != nil {
		resolver.VerifyCacheExtension(address)
	}
}

// Implements the inproxy.WebRTCDialCoordinator interface.
func (w *InproxyWebRTCDialInstance) STUNServerAddressFailed(RFC5780 bool, address string) {
	// Currently there is no independent replay for STUN dial parameters. See
	// comment in STUNServerAddressSucceeded.
}

// Implements the inproxy.WebRTCDialCoordinator interface.
func (w *InproxyWebRTCDialInstance) DiscoverNAT() bool {
	return w.discoverNAT
}

// Implements the inproxy.WebRTCDialCoordinator interface.
func (w *InproxyWebRTCDialInstance) DisableSTUN() bool {
	return w.disableSTUN
}

// Implements the inproxy.WebRTCDialCoordinator interface.
func (w *InproxyWebRTCDialInstance) DisablePortMapping() bool {
	return w.disablePortMapping
}

// Implements the inproxy.WebRTCDialCoordinator interface.
func (w *InproxyWebRTCDialInstance) DisableInboundForMobileNetworks() bool {
	return w.disableInboundForMobileNetworks
}

// Implements the inproxy.WebRTCDialCoordinator interface.
func (w *InproxyWebRTCDialInstance) DisableIPv6ICECandidates() bool {
	return w.disableIPv6ICECandidates
}

// Implements the inproxy.WebRTCDialCoordinator interface.
func (w *InproxyWebRTCDialInstance) NATType() inproxy.NATType {
	return w.natStateManager.getNATType(w.networkID)
}

// Implements the inproxy.WebRTCDialCoordinator interface.
func (w *InproxyWebRTCDialInstance) SetNATType(natType inproxy.NATType) {
	w.natStateManager.setNATType(w.networkID, natType)
}

// Implements the inproxy.WebRTCDialCoordinator interface.
func (w *InproxyWebRTCDialInstance) PortMappingTypes() inproxy.PortMappingTypes {
	return w.natStateManager.getPortMappingTypes(w.networkID)
}

// Implements the inproxy.WebRTCDialCoordinator interface.
func (w *InproxyWebRTCDialInstance) SetPortMappingTypes(
	portMappingTypes inproxy.PortMappingTypes) {
	w.natStateManager.setPortMappingTypes(w.networkID, portMappingTypes)
}

// Implements the inproxy.WebRTCDialCoordinator interface.
func (w *InproxyWebRTCDialInstance) PortMappingProbe() *inproxy.PortMappingProbe {
	return w.natStateManager.getPortMappingProbe(w.networkID)
}

// Implements the inproxy.WebRTCDialCoordinator interface.
func (w *InproxyWebRTCDialInstance) SetPortMappingProbe(
	portMappingProbe *inproxy.PortMappingProbe) {
	w.natStateManager.setPortMappingProbe(w.networkID, portMappingProbe)
}

// Implements the inproxy.WebRTCDialCoordinator interface.
func (w *InproxyWebRTCDialInstance) ResolveAddress(ctx context.Context, network, address string) (string, error) {

	// Use the Psiphon resolver to resolve addresses.

	r := w.config.GetResolver()
	if r == nil {
		return "", errors.TraceNew("missing resolver")
	}

	// Identify when the address to be resolved is one of the configured STUN
	// servers, and, in those cases, use/replay any STUN dial parameters
	// ResolveParameters; and record the resolved IP address for metrics.
	//
	// In the in-proxy proxy case, ResolveAddress is invoked for the upstream,
	// 2nd hop dial as well as for STUN server addresses.
	//
	// Limitation: there's no ResolveParameters, including no preresolved DNS
	// tactics, for 2nd hop dials.

	isSTUNServerAddress := address == w.stunDialParameters.STUNServerAddress
	isSTUNServerAddressRFC5780 := address == w.stunDialParameters.STUNServerAddressRFC5780
	var resolveParams *resolver.ResolveParameters
	if isSTUNServerAddress || isSTUNServerAddressRFC5780 {
		resolveParams = w.stunDialParameters.ResolveParameters
	}

	resolved, err := r.ResolveAddress(
		ctx, w.networkID, resolveParams, network, address)
	if err != nil {
		return "", errors.Trace(err)
	}

	// Invoke the resolved IP callbacks only when the input is not the
	// resolved IP address (this differs from the meek
	// DialConfig.ResolvedIPCallback case).

	if resolved != address {
		if isSTUNServerAddress {
			w.stunDialParameters.STUNServerResolvedIPAddress.Store(resolved)
		} else if isSTUNServerAddressRFC5780 {
			w.stunDialParameters.STUNServerRFC5780ResolvedIPAddress.Store(resolved)
		}
	}

	return resolved, nil
}

// Implements the inproxy.WebRTCDialCoordinator interface.
func (w *InproxyWebRTCDialInstance) UDPListen(ctx context.Context) (net.PacketConn, error) {

	// Create a new inproxyUDPConn for use as the in-proxy STUN and/ord WebRTC
	// UDP socket.

	conn, err := newInproxyUDPConn(ctx, w.config)
	if err != nil {
		return nil, errors.Trace(err)
	}
	return conn, nil
}

// Implements the inproxy.WebRTCDialCoordinator interface.
func (w *InproxyWebRTCDialInstance) UDPConn(
	ctx context.Context, network, remoteAddress string) (net.PacketConn, error) {

	// Create a new UDPConn bound to the specified remote address. This UDP
	// conn is used, by the inproxy package, to determine the local address
	// of the active interface the OS will select for the specified remote
	// destination.
	//
	// Only IP address destinations are supported. ResolveIP is wired up only
	// because NewUDPConn requires a non-nil resolver.

	dialConfig := &DialConfig{
		DeviceBinder:    w.config.deviceBinder,
		IPv6Synthesizer: w.config.IPv6Synthesizer,
		ResolveIP: func(_ context.Context, hostname string) ([]net.IP, error) {
			IP := net.ParseIP(hostname)
			if IP == nil {
				return nil, errors.TraceNew("not supported")
			}
			return []net.IP{IP}, nil
		},
	}

	conn, _, err := NewUDPConn(ctx, network, true, "", remoteAddress, dialConfig)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return conn, nil
}

// Implements the inproxy.WebRTCDialCoordinator interface.
func (w *InproxyWebRTCDialInstance) BindToDevice(fileDescriptor int) error {

	if w.config.deviceBinder == nil {
		return nil
	}

	// Use config.deviceBinder, with wired up logging, not
	// config.DeviceBinder; other tunnel-core dials do this indirectly via
	// psiphon.DialConfig.

	_, err := w.config.deviceBinder.BindToDevice(fileDescriptor)
	return errors.Trace(err)
}

func (w *InproxyWebRTCDialInstance) ProxyUpstreamDial(
	ctx context.Context, network, address string) (net.Conn, error) {

	// This implementation of ProxyUpstreamDial applies additional socket
	// options and BindToDevice as required, but is otherwise a stock dialer.
	//
	// TODO: Use custom UDP and TCP dialers, and wire up TCP/UDP-level
	// tactics, including BPF and the custom resolver, which may be enabled
	// for the proxy's ISP or geolocation. Orchestrating preresolved DNS
	// requires additional information from either from the broker, the
	// FrontingProviderID, to be applied to any
	// DNSResolverPreresolvedIPAddressCIDRs proxy tactics. In addition,
	// replay the selected upstream dial tactics parameters.

	dialer := net.Dialer{
		Control: func(_, _ string, c syscall.RawConn) error {
			var controlErr error
			err := c.Control(func(fd uintptr) {

				socketFD := int(fd)

				setAdditionalSocketOptions(socketFD)

				if w.config.deviceBinder != nil {
					_, err := w.config.deviceBinder.BindToDevice(socketFD)
					if err != nil {
						controlErr = errors.Tracef("BindToDevice failed: %s", err)
						return
					}
				}
			})
			if controlErr != nil {
				return errors.Trace(controlErr)
			}
			return errors.Trace(err)
		},
	}

	conn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, errors.Trace(err)
	}
	return conn, nil
}

// Implements the inproxy.WebRTCDialCoordinator interface.
func (w *InproxyWebRTCDialInstance) DiscoverNATTimeout() time.Duration {
	return w.discoverNATTimeout
}

// Implements the inproxy.WebRTCDialCoordinator interface.
func (w *InproxyWebRTCDialInstance) WebRTCAnswerTimeout() time.Duration {
	return w.webRTCAnswerTimeout
}

// Implements the inproxy.WebRTCDialCoordinator interface.
func (w *InproxyWebRTCDialInstance) WebRTCAwaitPortMappingTimeout() time.Duration {
	return w.webRTCAwaitPortMappingTimeout
}

// Implements the inproxy.WebRTCDialCoordinator interface.
func (w *InproxyWebRTCDialInstance) WebRTCAwaitReadyToProxyTimeout() time.Duration {
	return w.awaitReadyToProxyTimeout
}

// Implements the inproxy.WebRTCDialCoordinator interface.
func (w *InproxyWebRTCDialInstance) ProxyDestinationDialTimeout() time.Duration {
	return w.proxyDestinationDialTimeout
}

// Implements the inproxy.WebRTCDialCoordinator interface.
func (w *InproxyWebRTCDialInstance) ProxyRelayInactivityTimeout() time.Duration {
	return w.proxyRelayInactivityTimeout
}

// InproxySTUNDialParameters is a set of STUN dial parameters.
// InproxySTUNDialParameters is compatible with DialParameters JSON
// marshaling. For client in-proxy tunnel dials, DialParameters will manage
// STUN dial parameter selection and replay.
//
// When an instance of InproxySTUNDialParameters is unmarshaled from JSON,
// Prepare must be called to initialize the instance for use.
type InproxySTUNDialParameters struct {
	ResolveParameters        *resolver.ResolveParameters
	STUNServerAddress        string
	STUNServerAddressRFC5780 string

	STUNServerResolvedIPAddress        atomic.Value `json:"-"`
	STUNServerRFC5780ResolvedIPAddress atomic.Value `json:"-"`
}

// MakeInproxySTUNDialParameters generates new STUN dial parameters from the
// given tactics parameters.
func MakeInproxySTUNDialParameters(
	config *Config,
	p parameters.ParametersAccessor,
	isProxy bool) (*InproxySTUNDialParameters, error) {

	var stunServerAddresses, stunServerAddressesRFC5780 []string
	if isProxy {
		stunServerAddresses = p.Strings(
			parameters.InproxyProxySTUNServerAddresses, parameters.InproxySTUNServerAddresses)
		stunServerAddressesRFC5780 = p.Strings(
			parameters.InproxyProxySTUNServerAddressesRFC5780, parameters.InproxySTUNServerAddressesRFC5780)
	} else {
		stunServerAddresses = p.Strings(
			parameters.InproxyClientSTUNServerAddresses, parameters.InproxySTUNServerAddresses)
		stunServerAddressesRFC5780 = p.Strings(
			parameters.InproxyClientSTUNServerAddressesRFC5780, parameters.InproxySTUNServerAddressesRFC5780)
	}

	// Empty STUN server address lists are not an error condition. When used
	// for WebRTC, the STUN ICE candidate gathering will be skipped but the
	// WebRTC connection may still be established via other candidate types.

	var stunServerAddress, stunServerAddressRFC5780 string

	if len(stunServerAddresses) > 0 {
		stunServerAddress = stunServerAddresses[prng.Range(0, len(stunServerAddresses)-1)]
	}

	if len(stunServerAddressesRFC5780) > 0 {
		stunServerAddressRFC5780 =
			stunServerAddressesRFC5780[prng.Range(0, len(stunServerAddressesRFC5780)-1)]
	}

	// Create DNS resolver dial parameters to use when resolving STUN server
	// domain addresses. Instantiate only when there is a domain to be
	// resolved; when recording DNS fields, GetMetrics will assume that a nil
	// InproxySTUNDialParameters.ResolveParameters implies no resolve was
	// attempted.

	var resolveParameters *resolver.ResolveParameters

	if (stunServerAddress != "" && net.ParseIP(stunServerAddress) == nil) ||
		(stunServerAddressRFC5780 != "" && net.ParseIP(stunServerAddressRFC5780) == nil) {

		// No DNSResolverPreresolvedIPAddressCIDRs will be selected since no
		// fronting provider ID is specified.
		//
		// It would be possible to overload the meaning of the fronting
		// provider ID field by using a string derived from STUN server
		// address as the key.
		//
		// However, preresolved STUN configuration can already be achieved
		// with IP addresses in the STUNServerAddresses tactics parameters.
		// This approach results in slightly different metrics log fields vs.
		// preresolved.

		var err error
		resolveParameters, err = config.GetResolver().MakeResolveParameters(p, "", "")
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	dialParams := &InproxySTUNDialParameters{
		ResolveParameters:        resolveParameters,
		STUNServerAddress:        stunServerAddress,
		STUNServerAddressRFC5780: stunServerAddressRFC5780,
	}

	dialParams.Prepare()

	return dialParams, nil
}

// Prepare initializes an InproxySTUNDialParameters for use. Prepare should be
// called for any InproxySTUNDialParameters instance unmarshaled from JSON.
func (dialParams *InproxySTUNDialParameters) Prepare() {
	dialParams.STUNServerResolvedIPAddress.Store("")
	dialParams.STUNServerRFC5780ResolvedIPAddress.Store("")
}

// IsValidClientReplay checks that the selected STUN servers remain configured
// STUN server candidates for in-proxy clients.
func (dialParams *InproxySTUNDialParameters) IsValidClientReplay(
	p parameters.ParametersAccessor) bool {

	return (dialParams.STUNServerAddress == "" ||
		common.Contains(
			p.Strings(parameters.InproxyClientSTUNServerAddresses),
			dialParams.STUNServerAddress)) &&

		(dialParams.STUNServerAddressRFC5780 == "" ||
			common.Contains(
				p.Strings(parameters.InproxyClientSTUNServerAddressesRFC5780),
				dialParams.STUNServerAddressRFC5780))
}

// GetMetrics implements the common.MetricsSource interface and returns log
// fields detailing the STUN dial parameters.
func (dialParams *InproxySTUNDialParameters) GetMetrics() common.LogFields {

	// There is no is_replay-type field added here; replay is handled at a
	// higher level, and, for client in-proxy tunnel dials, is part of the
	// main tunnel dial parameters.

	logFields := make(common.LogFields)

	logFields["inproxy_webrtc_stun_server"] = dialParams.STUNServerAddress

	resolvedIPAddress := dialParams.STUNServerResolvedIPAddress.Load().(string)
	if resolvedIPAddress != "" {
		logFields["inproxy_webrtc_stun_server_resolved_ip_address"] = resolvedIPAddress
	}

	// TODO: log RFC5780 selection only if used?
	logFields["inproxy_webrtc_stun_server_RFC5780"] = dialParams.STUNServerAddressRFC5780

	resolvedIPAddress = dialParams.STUNServerRFC5780ResolvedIPAddress.Load().(string)
	if resolvedIPAddress != "" {
		logFields["inproxy_webrtc_stun_server_RFC5780_resolved_ip_address"] = resolvedIPAddress
	}

	if dialParams.ResolveParameters != nil {

		// See comment in getBaseAPIParameters regarding
		// dialParams.ResolveParameters handling. As noted in
		// MakeInproxySTUNDialParameters, no preresolved parameters are set,
		// so none are checked for logging.
		//
		// Limitation: the potential use of single ResolveParameters to
		// resolve multiple, different STUN server domains can skew the
		// meaning of GetFirstAttemptWithAnswer.

		if dialParams.ResolveParameters.PreferAlternateDNSServer {
			logFields["inproxy_webrtc_dns_preferred"] = dialParams.ResolveParameters.AlternateDNSServer
		}

		if dialParams.ResolveParameters.ProtocolTransformName != "" {
			logFields["inproxy_webrtc_dns_transform"] = dialParams.ResolveParameters.ProtocolTransformName
		}

		if dialParams.ResolveParameters.RandomQNameCasingSeed != nil {
			logFields["inproxy_webrtc_dns_qname_random_casing"] = "1"
		}

		if dialParams.ResolveParameters.ResponseQNameMustMatch {
			logFields["inproxy_webrtc_dns_qname_must_match"] = "1"
		}

		logFields["inproxy_webrtc_dns_qname_mismatches"] = strconv.Itoa(
			dialParams.ResolveParameters.GetQNameMismatches())

		logFields["inproxy_webrtc_dns_attempt"] = strconv.Itoa(
			dialParams.ResolveParameters.GetFirstAttemptWithAnswer())
	}
	return logFields
}

// InproxyWebRTCDialParameters is a set of WebRTC obfuscation dial parameters.
// InproxyWebRTCDialParameters is compatible with DialParameters JSON
// marshaling. For client in-proxy tunnel dials, DialParameters will manage
// WebRTC dial parameter selection and replay.
type InproxyWebRTCDialParameters struct {
	RootObfuscationSecret    inproxy.ObfuscationSecret
	UseMediaStreams          bool
	TrafficShapingParameters *inproxy.TrafficShapingParameters
	DoDTLSRandomization      bool
}

// MakeInproxyWebRTCDialParameters generates new InproxyWebRTCDialParameters.
func MakeInproxyWebRTCDialParameters(
	p parameters.ParametersAccessor) (*InproxyWebRTCDialParameters, error) {

	rootObfuscationSecret, err := inproxy.GenerateRootObfuscationSecret()
	if err != nil {
		return nil, errors.Trace(err)
	}

	useMediaStreams := p.WeightedCoinFlip(parameters.InproxyWebRTCMediaStreamsProbability)

	var trafficSharingParams *inproxy.TrafficShapingParameters

	if useMediaStreams {

		if p.WeightedCoinFlip(parameters.InproxyWebRTCMediaStreamsTrafficShapingProbability) {
			t := inproxy.TrafficShapingParameters(
				p.InproxyTrafficShapingParameters(
					parameters.InproxyWebRTCMediaStreamsTrafficShapingParameters))
			trafficSharingParams = &t
		}

	} else {

		if p.WeightedCoinFlip(parameters.InproxyWebRTCDataChannelTrafficShapingProbability) {
			t := inproxy.TrafficShapingParameters(
				p.InproxyTrafficShapingParameters(
					parameters.InproxyWebRTCDataChannelTrafficShapingParameters))
			trafficSharingParams = &t
		}
	}

	doDTLSRandomization := p.WeightedCoinFlip(parameters.InproxyDTLSRandomizationProbability)

	return &InproxyWebRTCDialParameters{
		RootObfuscationSecret:    rootObfuscationSecret,
		UseMediaStreams:          useMediaStreams,
		TrafficShapingParameters: trafficSharingParams,
		DoDTLSRandomization:      doDTLSRandomization,
	}, nil
}

// GetMetrics implements the common.MetricsSource interface.
func (dialParams *InproxyWebRTCDialParameters) GetMetrics() common.LogFields {

	// There is no is_replay-type field added here; replay is handled at a
	// higher level, and, for client in-proxy tunnel dials, is part of the
	// main tunnel dial parameters.

	// Currently, all WebRTC metrics are delivered via
	// inproxy.ClientConn/WebRTCConn GetMetrics.
	return common.LogFields{}
}

// InproxyNATStateManager manages the NAT-related network topology state for
// the current network, caching the discovered network NAT type and supported
// port mapping types, if any.
type InproxyNATStateManager struct {
	config *Config

	mutex            sync.Mutex
	networkID        string
	natType          inproxy.NATType
	portMappingTypes inproxy.PortMappingTypes
	portMappingProbe *inproxy.PortMappingProbe
}

// NewInproxyNATStateManager creates a new InproxyNATStateManager.
func NewInproxyNATStateManager(config *Config) *InproxyNATStateManager {

	s := &InproxyNATStateManager{
		config:           config,
		natType:          inproxy.NATTypeUnknown,
		portMappingTypes: inproxy.PortMappingTypes{},
	}

	s.reset()

	return s
}

// TacticsApplied implements the TacticsAppliedReceiver interface, and is
// called when tactics have changed, which triggers a cached NAT state reset
// in order to apply potentially changed parameters.
func (s *InproxyNATStateManager) TacticsApplied() error {
	s.reset()
	return nil
}

func (s *InproxyNATStateManager) reset() {

	s.mutex.Lock()
	defer s.mutex.Unlock()

	networkID := s.config.GetNetworkID()

	s.networkID = networkID
	s.natType = inproxy.NATTypeUnknown
	s.portMappingTypes = inproxy.PortMappingTypes{}
}

func (s *InproxyNATStateManager) getNATType(
	networkID string) inproxy.NATType {

	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.networkID != networkID {
		return inproxy.NATTypeUnknown
	}

	return s.natType
}

func (s *InproxyNATStateManager) setNATType(
	networkID string, natType inproxy.NATType) {

	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.networkID != networkID {
		return
	}

	s.natType = natType
}

func (s *InproxyNATStateManager) getPortMappingTypes(
	networkID string) inproxy.PortMappingTypes {

	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.networkID != networkID {
		return inproxy.PortMappingTypes{}
	}

	return s.portMappingTypes
}

func (s *InproxyNATStateManager) setPortMappingTypes(
	networkID string,
	portMappingTypes inproxy.PortMappingTypes) {

	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.networkID != networkID {
		return
	}

	s.portMappingTypes = portMappingTypes
}

func (s *InproxyNATStateManager) getPortMappingProbe(
	networkID string) *inproxy.PortMappingProbe {

	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.networkID != networkID {
		return nil
	}

	return s.portMappingProbe
}

func (s *InproxyNATStateManager) setPortMappingProbe(
	networkID string,
	portMappingProbe *inproxy.PortMappingProbe) {

	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.networkID != networkID {
		return
	}

	s.portMappingProbe = portMappingProbe
}

// inproxyUDPConn is based on NewUDPConn and includes the write timeout
// workaround from common.WriteTimeoutUDPConn.
//
// inproxyUDPConn expands the NewUDPConn IPv6Synthesizer to support many
// destination addresses, as the inproxyUDPConn will be used to send/receive
// packets between many remote destination addresses.
//
// inproxyUDPConn implements the net.PacketConn interface.
type inproxyUDPConn struct {
	udpConn *net.UDPConn

	ipv6Synthesizer IPv6Synthesizer

	synthesizerMutex sync.Mutex
	ipv4ToIPv6       map[netip.Addr]net.IP
	ipv6ToIPv4       map[netip.Addr]net.IP
}

func newInproxyUDPConn(ctx context.Context, config *Config) (net.PacketConn, error) {

	listen := &net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			var controlErr error
			err := c.Control(func(fd uintptr) {

				socketFD := int(fd)

				setAdditionalSocketOptions(socketFD)

				// Use config.deviceBinder, with wired up logging, not
				// config.DeviceBinder; other tunnel-core dials do this
				// indirectly via psiphon.DialConfig.

				if config.deviceBinder != nil {
					_, err := config.deviceBinder.BindToDevice(socketFD)
					if err != nil {
						controlErr = errors.Tracef("BindToDevice failed: %s", err)
						return
					}
				}
			})
			if controlErr != nil {
				return errors.Trace(controlErr)
			}
			return errors.Trace(err)
		},
	}

	// Create an "unconnected" UDP socket for use with WriteTo and listening
	// on all interfaces. See the limitation comment in NewUDPConn regarding
	// its equivilent mode.

	packetConn, err := listen.ListenPacket(ctx, "udp", "")
	if err != nil {
		return nil, errors.Trace(err)
	}

	var ok bool
	udpConn, ok := packetConn.(*net.UDPConn)
	if !ok {
		return nil, errors.Tracef("unexpected conn type: %T", packetConn)
	}

	conn := &inproxyUDPConn{
		udpConn:         udpConn,
		ipv6Synthesizer: config.IPv6Synthesizer,
	}
	if conn.ipv6Synthesizer != nil {
		conn.ipv4ToIPv6 = make(map[netip.Addr]net.IP)
		conn.ipv6ToIPv4 = make(map[netip.Addr]net.IP)
	}

	return conn, nil
}

func (conn *inproxyUDPConn) ReadFrom(p []byte) (int, net.Addr, error) {

	// net.UDPConn.ReadFrom currently allocates a &UDPAddr{} per call, and so
	// the &net.UDPAddr{} allocations done in the following synthesizer code
	// path are no more than the standard code path.
	//
	// TODO: avoid all address allocations in both ReadFrom and WriteTo by:
	//
	// - changing ipvXToIPvY to map[netip.AddrPort]*net.UDPAddr
	// - using a similar lookup for the non-synthesizer code path
	//
	// Such a scheme would work only if the caller is guaranteed to not mutate
	// the returned net.Addr.

	if conn.ipv6Synthesizer == nil {
		// Do not wrap any I/O err returned by UDPConn
		return conn.udpConn.ReadFrom(p)
	}

	n, addrPort, err := conn.udpConn.ReadFromUDPAddrPort(p)
	// Reverse any synthesized address before returning err.

	// Reverse the IPv6 synthesizer, returning the original IPv4 address
	// as expected by the caller, including pion/webrtc. This logic
	// assumes that no synthesized IPv6 address will conflict with any
	// real IPv6 address.

	var IP net.IP
	ipAddr := addrPort.Addr()
	if ipAddr.Is6() {
		conn.synthesizerMutex.Lock()
		IP, _ = conn.ipv6ToIPv4[ipAddr]
		conn.synthesizerMutex.Unlock()
	}
	if IP == nil {
		IP = ipAddr.AsSlice()
	}

	// Do not wrap any I/O err returned by UDPConn
	return n, &net.UDPAddr{IP: IP, Port: int(addrPort.Port())}, err
}

func (conn *inproxyUDPConn) WriteTo(b []byte, addr net.Addr) (int, error) {

	// See common.WriteTimeoutUDPConn.
	err := conn.udpConn.SetWriteDeadline(
		time.Now().Add(common.UDP_PACKET_WRITE_TIMEOUT))
	if err != nil {
		return 0, errors.Trace(err)
	}

	if conn.ipv6Synthesizer == nil {
		// Do not wrap any I/O err returned by UDPConn
		return conn.udpConn.WriteTo(b, addr)
	}

	// When configured, attempt to synthesize IPv6 addresses from an IPv4
	// addresses for compatibility on DNS64/NAT64 networks.
	//
	// Store any synthesized addresses in a lookup table and reuse for
	// subsequent writes to the same destination as well as reversing the
	// conversion on reads.
	//
	// If synthesize fails, fall back to trying the original address.

	// The netip.Addr type is used as the map key and the input address is
	// assumed to be of the type *net.UDPAddr. This allows for more efficient
	// lookup operations vs. a string key and parsing the input address via
	// addr.String()/net.SplitHostPort().

	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, errors.Tracef("unexpected addr type: %T", addr)
	}

	// Stack allocate to avoid an extra heap allocation per write.
	var synthesizedAddr net.UDPAddr

	if udpAddr.IP.To4() != nil {

		ip4Addr, ok := netip.AddrFromSlice(udpAddr.IP)
		if !ok {
			return 0, errors.Tracef("invalid addr")
		}
		conn.synthesizerMutex.Lock()
		synthesizedIP, ok := conn.ipv4ToIPv6[ip4Addr]
		conn.synthesizerMutex.Unlock()
		if ok {
			synthesizedAddr = net.UDPAddr{IP: synthesizedIP, Port: udpAddr.Port}
		} else {
			synthesized := conn.ipv6Synthesizer.IPv6Synthesize(udpAddr.IP.String())
			if synthesized != "" {
				synthesizedIP := net.ParseIP(synthesized)
				if synthesizedIP != nil {
					conn.synthesizerMutex.Lock()
					conn.ipv4ToIPv6[ip4Addr] = synthesizedIP
					ipv6Addr, _ := netip.AddrFromSlice(synthesizedIP)
					conn.ipv6ToIPv4[ipv6Addr] = udpAddr.IP
					conn.synthesizerMutex.Unlock()
					synthesizedAddr = net.UDPAddr{IP: synthesizedIP, Port: udpAddr.Port}
				}
			}
		}
	}

	if synthesizedAddr.IP == nil {
		// Do not wrap any I/O err returned by UDPConn
		return conn.udpConn.WriteTo(b, addr)
	}

	return conn.udpConn.WriteTo(b, &synthesizedAddr)
}

func (conn *inproxyUDPConn) Close() error {
	// Do not wrap any I/O err returned by UDPConn
	return conn.udpConn.Close()
}

func (conn *inproxyUDPConn) LocalAddr() net.Addr {
	// Do not wrap any I/O err returned by UDPConn
	return conn.udpConn.LocalAddr()
}

func (conn *inproxyUDPConn) SetDeadline(t time.Time) error {
	// Do not wrap any I/O err returned by UDPConn
	return conn.udpConn.SetDeadline(t)
}

func (conn *inproxyUDPConn) SetReadDeadline(t time.Time) error {
	// Do not wrap any I/O err returned by UDPConn
	return conn.udpConn.SetReadDeadline(t)
}

func (conn *inproxyUDPConn) SetWriteDeadline(t time.Time) error {
	// Do not wrap any I/O err returned by UDPConn
	return conn.udpConn.SetWriteDeadline(t)
}

// getInproxyNetworkType converts a legacy string network type to an inproxy
// package type.
func getInproxyNetworkType(networkType string) inproxy.NetworkType {

	// There is no VPN type conversion; clients and proxies will skip/fail
	// in-proxy operations on non-Psiphon VPN networks.

	switch networkType {
	case "WIFI":
		return inproxy.NetworkTypeWiFi
	case "MOBILE":
		return inproxy.NetworkTypeMobile
	case "WIRED":
		return inproxy.NetworkTypeWired
	case "VPN":
		return inproxy.NetworkTypeVPN
	}

	return inproxy.NetworkTypeUnknown
}
