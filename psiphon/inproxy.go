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
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/fragmentor"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/inproxy"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/resolver"
	"github.com/cespare/xxhash"
	"golang.org/x/net/bpf"
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

	mutex                sync.Mutex
	networkID            string
	brokerClientInstance *InproxyBrokerClientInstance
}

// NewInproxyBrokerClientManager creates a new InproxyBrokerClientManager.
// NewInproxyBrokerClientManager does not perform any network operations; the
// managed InproxyBrokerClientInstance is initialized when used for a round
// trip.
func NewInproxyBrokerClientManager(
	config *Config, isProxy bool) *InproxyBrokerClientManager {

	b := &InproxyBrokerClientManager{
		config:  config,
		isProxy: isProxy,
	}

	// b.brokerClientInstance is initialized on demand, when getBrokerClient
	// is called.

	return b
}

// TacticsApplied implements the TacticsAppliedReceiver interface, and is
// called when tactics have changed, which triggers a broker client reset in
// order to apply potentially changed parameters.
func (b *InproxyBrokerClientManager) TacticsApplied() error {

	// TODO: as a future future enhancement, don't reset when the tactics
	// brokerSpecs.Hash() is unchanged?

	return errors.Trace(b.reset())
}

// GetBrokerClient returns the current, shared broker client and its
// corresponding dial parametrers (for metrics logging). If there is no
// current broker client, if the network ID differs from the network ID
// associated with the previous broker client, a new broker client is
// initialized.
func (b *InproxyBrokerClientManager) GetBrokerClient(
	networkID string) (*inproxy.BrokerClient, *InproxyBrokerDialParameters, error) {

	b.mutex.Lock()
	defer b.mutex.Unlock()

	if b.brokerClientInstance == nil || b.networkID != networkID {
		err := b.reset()
		if err != nil {
			return nil, nil, errors.Trace(err)
		}
	}

	// The b.brokerClientInstance.brokerClient is wired up to refer back to
	// b.brokerClientInstance.brokerDialParams/roundTripper, etc.

	return b.brokerClientInstance.brokerClient,
		b.brokerClientInstance.brokerDialParams,
		nil
}

func (b *InproxyBrokerClientManager) resetBrokerClientOnRoundTripFailed() error {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	return errors.Trace(b.reset())
}

func (b *InproxyBrokerClientManager) reset() error {

	// Assumes b.mutex lock is held.

	// Any existing broker client is removed, even if
	// NewInproxyBrokerClientInstance fails. This ensures, for example, that
	// an existing broker client is removed when its spec is no longer
	// available in tactics.
	b.networkID = ""
	b.brokerClientInstance = nil

	networkID := b.config.GetNetworkID()

	brokerClientInstance, err := NewInproxyBrokerClientInstance(
		b.config, b, networkID, b.isProxy)
	if err != nil {
		return errors.Trace(err)
	}

	b.networkID = networkID
	b.brokerClientInstance = brokerClientInstance

	return nil
}

// InproxyBrokerClientInstance pairs an inproxy.BrokerClient instance with an
// implementation of the inproxy.BrokerDialCoordinator interface and the
// associated, underlying broker dial paramaters. InproxyBrokerClientInstance
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
	isReplay                      bool
	roundTripper                  *InproxyBrokerRoundTripper
	personalCompartmentIDs        []inproxy.ID
	commonCompartmentIDs          []inproxy.ID
	announceRequestTimeout        time.Duration
	announceRetryDelay            time.Duration
	announceRetryJitter           float64
	answerRequestTimeout          time.Duration
	offerRequestTimeout           time.Duration
	offerRetryDelay               time.Duration
	offerRetryJitter              float64
	relayedPacketRequestTimeout   time.Duration
	replayRetainFailedProbability float64
	replayUpdateFrequency         time.Duration

	mutex           sync.Mutex
	lastStoreReplay time.Time
}

// NewInproxyBrokerClientInstance creates a new InproxyBrokerClientInstance.
// NewInproxyBrokerClientManager does not perform any network operations; the
// new InproxyBrokerClientInstance is initialized when used for a round
// trip.
func NewInproxyBrokerClientInstance(
	config *Config,
	brokerClientManager *InproxyBrokerClientManager,
	networkID string,
	isProxy bool) (*InproxyBrokerClientInstance, error) {

	p := config.GetParameters().Get()
	defer p.Close()

	// Select common or personal compartment IDs.

	commonCompartmentIDs, personalCompartmentIDs, err := prepareCompartmentIDs(config, p, isProxy)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// Select the broker to use, optionally favoring brokers with replay
	// data.

	brokerSpecs := p.InproxyBrokerSpecs(parameters.InproxyBrokerSpecs)

	if len(brokerSpecs) == 0 {
		return nil, errors.TraceNew("no broker specs")
	}

	// To ensure personal compartment ID client/proxy rendezvous at same
	// broker, simply pick the first configured broker.
	//
	// Limitations: there's no failover or load balancing for the personal
	// compartment ID case; and this logic assumes that the broker spec
	// tactics are the same for the client and proxy.

	if len(personalCompartmentIDs) > 0 {
		brokerSpecs = brokerSpecs[:1]
	}

	now := time.Now()

	// Prefer a broker with replay data.

	// Replay is disabled when the TTL, InproxyReplayBrokerDialParametersTTL,
	// is 0.
	ttl := p.Duration(parameters.InproxyReplayBrokerDialParametersTTL)

	replayEnabled := ttl > 0 &&
		!config.DisableReplay &&
		prng.FlipWeightedCoin(p.Float(parameters.InproxyReplayBrokerDialParametersProbability))

	brokerSpec, brokerDialParams, err :=
		ShuffleAndGetNetworkReplayParameters[parameters.InproxyBrokerSpec, InproxyBrokerDialParameters](
			networkID,
			replayEnabled,
			brokerSpecs,
			func(spec *parameters.InproxyBrokerSpec) string { return spec.BrokerPublicKey },
			func(spec *parameters.InproxyBrokerSpec, dialParams *InproxyBrokerDialParameters) bool {
				return dialParams.LastUsedTimestamp.After(now.Add(-ttl)) &&
					bytes.Equal(dialParams.LastUsedBrokerSpecHash, hashBrokerSpec(spec))
			})
	if err != nil {
		NoticeWarning("ShuffleAndGetNetworkReplayParameters failed: %v", errors.Trace(err))

		// When there's an error, try to continue, using a random broker spec
		// and no replay dial parameters.
		brokerSpec = brokerSpecs[prng.Intn(len(brokerSpecs)-1)]
	}

	// Generate new broker dial parameters if not replaying. Later, isReplay
	// is used to report the replay metric.

	isReplay := brokerDialParams != nil

	if !isReplay {
		brokerDialParams, err = MakeInproxyBrokerDialParameters(config, p, networkID, brokerSpec)
		if err != nil {
			return nil, errors.Trace(err)
		}
	} else {
		brokerDialParams.brokerSpec = brokerSpec
		err := brokerDialParams.prepareDialConfigs(config, p, networkID, true, nil)
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

	roundTripper := NewInproxyBrokerRoundTripper(brokerDialParams)

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
		isReplay:                    isReplay,
		roundTripper:                roundTripper,
		personalCompartmentIDs:      personalCompartmentIDs,
		commonCompartmentIDs:        commonCompartmentIDs,

		announceRequestTimeout:        p.Duration(parameters.InproxyProxyAnnounceRequestTimeout),
		announceRetryDelay:            p.Duration(parameters.InproxyProxyAnnounceRetryDelay),
		announceRetryJitter:           p.Float(parameters.InproxyProxyAnnounceRetryJitter),
		answerRequestTimeout:          p.Duration(parameters.InproxyProxyAnswerRequestTimeout),
		offerRequestTimeout:           p.Duration(parameters.InproxyClientOfferRequestTimeout),
		offerRetryDelay:               p.Duration(parameters.InproxyClientOfferRetryDelay),
		offerRetryJitter:              p.Float(parameters.InproxyClientOfferRetryJitter),
		relayedPacketRequestTimeout:   p.Duration(parameters.InproxyClientRelayedPacketRequestTimeout),
		replayRetainFailedProbability: p.Float(parameters.InproxyReplayBrokerRetainFailedProbability),
		replayUpdateFrequency:         p.Duration(parameters.InproxyReplayBrokerUpdateFrequency),
	}

	// Initialize broker client. This will start with a fresh broker session.
	//
	// When resetBrokerClientOnRoundTripFailed is invoked due to a failure at
	// the transport level -- TLS or domain fronting --
	// NewInproxyBrokerClientInstance is invoked, resetting both the broker
	// client round tripper and the broker session. As a future enhancement,
	// consider distinguishing between transport and session errors and
	// retaining a valid established session when only the transport needs to
	// be reset/retried.

	b.brokerClient, err = inproxy.NewBrokerClient(b)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// Set a finalizer to close any open network resources associated with the
	// round tripper once the InproxyBrokerClientInstance is no longer
	// referenced. Note that there's no explicit call to close in
	// InproxyBrokerClientManager.reset when a new instance is created in
	// case the old insstance is still in use.

	runtime.SetFinalizer(b, func(b *InproxyBrokerClientInstance) {
		_ = b.roundTripper.Close()
	})

	return b, nil
}

func prepareCompartmentIDs(
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

	personalCompartmentIDs, err := inproxy.IDsFromStrings(config.InproxyPersonalCompartmentIDs)
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

	if roundTripper != b.roundTripper {
		// Passing in the round tripper obtained from BrokerClientRoundTripper
		// is just used for sanity check in this implementation, since each
		// InproxyBrokerClientInstance has exactly one round tripper.
		NoticeError("BrokerClientRoundTripperSucceeded: roundTripper instance mismatch")
		return
	}

	// Set replay or extend the broker dial parameters replay TTL after a
	// success. With tunnel dial parameters, the replay TTL is extended after
	// every successful tunnel connection. Since there are potentially more
	// and more frequent broker round trips one tunnel dial, the TTL is only
	// extended after some target duration has elapsed, to avoid excessive
	// datastore writes.

	now := time.Now()
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
		resolver.VerifyCacheExtension(b.brokerDialParams.FrontingDialAddress)
	}
}

// Implements the inproxy.BrokerDialCoordinator interface.
func (b *InproxyBrokerClientInstance) BrokerClientRoundTripperFailed(roundTripper inproxy.RoundTripper) {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	if roundTripper != b.roundTripper {
		// Passing in the round tripper obtained from BrokerClientRoundTripper
		// is just used for sanity check in this implementation, since each
		// InproxyBrokerClientInstance has exactly one round tripper.
		NoticeError("BrokerClientRoundTripperFailed: roundTripper instance mismatch")
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

	// Invoke resetBrokerClientOnRoundTripFailed to signal the
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

	err := b.brokerClientManager.resetBrokerClientOnRoundTripFailed()
	if err != nil {
		NoticeWarning("reset broker client failed: %v", errors.Trace(err))
		// Continue with old broker client instance.
	}
}

// Implements the inproxy.BrokerDialCoordinator interface.
func (b *InproxyBrokerClientInstance) AnnounceRequestTimeout() time.Duration {
	return b.announceRequestTimeout
}

// Implements the inproxy.BrokerDialCoordinator interface.
func (b *InproxyBrokerClientInstance) AnnounceRetryDelay() time.Duration {
	return b.announceRetryDelay
}

// Implements the inproxy.BrokerDialCoordinator interface.
func (b *InproxyBrokerClientInstance) AnnounceRetryJitter() float64 {
	return b.announceRetryJitter
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

	LastUsedTimestamp      time.Time
	LastUsedBrokerSpecHash []byte

	NetworkLatencyMultiplier float64

	BrokerTransport string

	DialAddress string

	FrontingProviderID  string
	FrontingDialAddress string
	SNIServerName       string
	TransformedHostName bool
	VerifyServerName    string
	VerifyPins          []string
	HostHeader          string
	ResolvedIPAddress   atomic.Value `json:"-"`

	TLSProfile               string
	TLSVersion               string
	RandomizedTLSProfileSeed *prng.Seed
	NoDefaultTLSSessionID    bool
	TLSFragmentClientHello   bool

	SelectedUserAgent bool
	UserAgent         string

	BPFProgramName         string
	BPFProgramInstructions []bpf.RawInstruction

	FragmentorSeed *prng.Seed

	ResolveParameters *resolver.ResolveParameters

	dialConfig *DialConfig `json:"-"`
	meekConfig *MeekConfig `json:"-"`
}

// MakeInproxyBrokerDialParameters creates a new InproxyBrokerDialParameters.
func MakeInproxyBrokerDialParameters(
	config *Config,
	p parameters.ParametersAccessor,
	networkID string,
	brokerSpec *parameters.InproxyBrokerSpec) (*InproxyBrokerDialParameters, error) {

	// This function duplicates some code from MakeDialParameters and
	// makeFrontedHTTPClient. To simplify the logic, the Replay<Component>
	// tactic flags for individual dial components are ignored.
	//
	// TODO: merge common functionality?

	if config.UseUpstreamProxy() {
		return nil, errors.TraceNew("upstream proxy unsupported")
	}

	currentTimestamp := time.Now()

	var brokerDialParams *InproxyBrokerDialParameters

	// Select new broker dial parameters

	brokerDialParams = &InproxyBrokerDialParameters{
		brokerSpec:             brokerSpec,
		LastUsedTimestamp:      currentTimestamp,
		LastUsedBrokerSpecHash: hashBrokerSpec(brokerSpec),
	}

	// Network latency multiplier

	brokerDialParams.NetworkLatencyMultiplier = prng.ExpFloat64Range(
		p.Float(parameters.NetworkLatencyMultiplierMin),
		p.Float(parameters.NetworkLatencyMultiplierMax),
		p.Float(parameters.NetworkLatencyMultiplierLambda))

	// Select fronting configuration

	var err error

	brokerDialParams.FrontingProviderID,
		brokerDialParams.BrokerTransport,
		brokerDialParams.FrontingDialAddress,
		brokerDialParams.SNIServerName,
		brokerDialParams.VerifyServerName,
		brokerDialParams.VerifyPins,
		brokerDialParams.HostHeader,
		err = brokerDialParams.brokerSpec.BrokerFrontingSpecs.SelectParameters()
	if err != nil {
		return nil, errors.Trace(err)
	}

	// At this time, the broker client, the transport is limited to fronted
	// HTTPS.
	//
	// MeekModePlaintextRoundTrip currently disallows HTTP, as it must for
	// Conjure's request payloads, but the in-proxy broker session payload is
	// obfuscated. As a future enhancement, allow HTTP for the in-proxy
	// broker case, skip selecting TLS tactics and select HTTP tactics such
	// as HTTPTransformerParameters.

	if brokerDialParams.BrokerTransport == protocol.FRONTING_TRANSPORT_HTTP {
		return nil, errors.TraceNew("unsupported fronting transport")
	}

	// Determine and use the equivilent tunnel protocol for tactics
	// selections. For example, for the broker transport FRONTED-HTTPS, use
	// the tactics for FRONTED-MEEK-OSSH.

	equivilentTunnelProtocol, err := protocol.EquivilentTunnelProtocol(brokerDialParams.BrokerTransport)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// FrontSpec.Addresses may include a port; default to 443 if none.

	if _, _, err := net.SplitHostPort(brokerDialParams.FrontingDialAddress); err == nil {
		brokerDialParams.DialAddress = brokerDialParams.FrontingDialAddress
	} else {
		brokerDialParams.DialAddress = net.JoinHostPort(brokerDialParams.FrontingDialAddress, "443")
	}

	// SNI configuration
	//
	// For a FrontingSpec, an SNI value of "" indicates to disable/omit SNI, so
	// never transform in that case.

	if brokerDialParams.SNIServerName != "" {
		if p.WeightedCoinFlip(parameters.TransformHostNameProbability) {
			brokerDialParams.SNIServerName = selectHostName(equivilentTunnelProtocol, p)
			brokerDialParams.TransformedHostName = true
		}
	}

	// TLS configuration
	//
	// The requireTLS13 flag is set to true in order to use only modern TLS
	// fingerprints which should support HTTP/2 in the ALPN.
	//
	// TODO: TLS padding, NoDefaultTLSSessionID

	brokerDialParams.TLSProfile,
		brokerDialParams.TLSVersion,
		brokerDialParams.RandomizedTLSProfileSeed,
		err = SelectTLSProfile(false, true, true, brokerDialParams.FrontingProviderID, p)

	brokerDialParams.NoDefaultTLSSessionID = p.WeightedCoinFlip(
		parameters.NoDefaultTLSSessionIDProbability)

	if brokerDialParams.SNIServerName != "" && net.ParseIP(brokerDialParams.SNIServerName) == nil {
		tlsFragmentorLimitProtocols := p.TunnelProtocols(parameters.TLSFragmentClientHelloLimitProtocols)
		if len(tlsFragmentorLimitProtocols) == 0 || common.Contains(tlsFragmentorLimitProtocols, equivilentTunnelProtocol) {
			brokerDialParams.TLSFragmentClientHello = p.WeightedCoinFlip(parameters.TLSFragmentClientHelloProbability)
		}
	}

	// User Agent configuration

	dialCustomHeaders := makeDialCustomHeaders(config, p)
	brokerDialParams.SelectedUserAgent, brokerDialParams.UserAgent = selectUserAgentIfUnset(p, dialCustomHeaders)

	// BPF configuration

	if ClientBPFEnabled() &&
		protocol.TunnelProtocolMayUseClientBPF(equivilentTunnelProtocol) {

		if p.WeightedCoinFlip(parameters.BPFClientTCPProbability) {
			brokerDialParams.BPFProgramName = ""
			brokerDialParams.BPFProgramInstructions = nil
			ok, name, rawInstructions := p.BPFProgram(parameters.BPFClientTCPProgram)
			if ok {
				brokerDialParams.BPFProgramName = name
				brokerDialParams.BPFProgramInstructions = rawInstructions
			}
		}
	}

	// Fragmentor configuration

	brokerDialParams.FragmentorSeed, err = prng.NewSeed()
	if err != nil {
		return nil, errors.Trace(err)
	}

	// Resolver configuration
	//
	// The custom resolcer is wired up only when there is a domain to be
	// resolved; GetMetrics will log resolver metrics when the resolver is set.

	if net.ParseIP(brokerDialParams.FrontingDialAddress) == nil {

		resolver := config.GetResolver()
		if resolver == nil {
			return nil, errors.TraceNew("missing resolver")
		}

		brokerDialParams.ResolveParameters, err = resolver.MakeResolveParameters(
			p, brokerDialParams.FrontingProviderID, brokerDialParams.FrontingDialAddress)
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	// Initialize Dial/MeekConfigs to be passed to the corresponding dialers.

	err = brokerDialParams.prepareDialConfigs(config, p, networkID, false, dialCustomHeaders)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return brokerDialParams, nil
}

// prepareDialConfigs is called for both new and replayed broker dial parameters.
func (brokerDialParams *InproxyBrokerDialParameters) prepareDialConfigs(
	config *Config,
	p parameters.ParametersAccessor,
	networkID string,
	isReplay bool,
	dialCustomHeaders http.Header) error {

	brokerDialParams.isReplay = isReplay

	equivilentTunnelProtocol, err := protocol.EquivilentTunnelProtocol(brokerDialParams.BrokerTransport)
	if err != nil {
		return errors.Trace(err)
	}

	// Custom headers and User Agent

	if dialCustomHeaders == nil {
		dialCustomHeaders = makeDialCustomHeaders(config, p)
	}
	if brokerDialParams.SelectedUserAgent {

		// Limitation: if config.CustomHeaders adds a User-Agent between
		// replays, it may be ignored due to replaying a selected User-Agent.
		dialCustomHeaders.Set("User-Agent", brokerDialParams.UserAgent)
	}

	// Fragmentor

	fragmentorConfig := fragmentor.NewUpstreamConfig(
		p, equivilentTunnelProtocol, brokerDialParams.FragmentorSeed)

	// Resolver

	var resolveIP func(ctx context.Context, hostname string) ([]net.IP, error)

	if net.ParseIP(brokerDialParams.FrontingDialAddress) == nil {

		resolver := config.GetResolver()
		if resolver == nil {
			return errors.TraceNew("missing resolver")
		}

		resolveIP = func(ctx context.Context, hostname string) ([]net.IP, error) {
			IPs, err := resolver.ResolveIP(
				ctx, networkID, brokerDialParams.ResolveParameters, hostname)
			return IPs, errors.Trace(err)
		}

	} else {
		resolveIP = func(ctx context.Context, hostname string) ([]net.IP, error) {
			return nil, errors.TraceNew("unexpected resolve")
		}
	}

	// DialConfig

	brokerDialParams.ResolvedIPAddress.Store("")

	brokerDialParams.dialConfig = &DialConfig{
		DiagnosticID:                  brokerDialParams.brokerSpec.BrokerPublicKey,
		CustomHeaders:                 dialCustomHeaders,
		BPFProgramInstructions:        brokerDialParams.BPFProgramInstructions,
		DeviceBinder:                  config.deviceBinder,
		IPv6Synthesizer:               config.IPv6Synthesizer,
		ResolveIP:                     resolveIP,
		TrustedCACertificatesFilename: config.TrustedCACertificatesFilename,
		FragmentorConfig:              fragmentorConfig,
		ResolvedIPCallback: func(IPAddress string) {
			brokerDialParams.ResolvedIPAddress.Store(IPAddress)
		},
	}

	// MeekDialConfig
	//
	// The broker round trips use MeekModePlaintextRoundTrip without meek
	// cookies, so meek obfuscation is not configured. The in-proxy broker
	// session payloads have their own obfuscation layer.

	addPsiphonFrontingHeader := false
	if brokerDialParams.FrontingProviderID != "" {
		addPsiphonFrontingHeader = common.Contains(
			p.LabeledTunnelProtocols(
				parameters.AddFrontingProviderPsiphonFrontingHeader,
				brokerDialParams.FrontingProviderID),
			equivilentTunnelProtocol)
	}

	brokerDialParams.meekConfig = &MeekConfig{
		Mode:                     MeekModePlaintextRoundTrip,
		DiagnosticID:             brokerDialParams.FrontingProviderID,
		Parameters:               config.GetParameters(),
		DialAddress:              brokerDialParams.DialAddress,
		TLSProfile:               brokerDialParams.TLSProfile,
		NoDefaultTLSSessionID:    brokerDialParams.NoDefaultTLSSessionID,
		RandomizedTLSProfileSeed: brokerDialParams.RandomizedTLSProfileSeed,
		SNIServerName:            brokerDialParams.SNIServerName,
		AddPsiphonFrontingHeader: addPsiphonFrontingHeader,
		VerifyServerName:         brokerDialParams.VerifyServerName,
		VerifyPins:               brokerDialParams.VerifyPins,
		HostHeader:               brokerDialParams.HostHeader,
		TransformedHostName:      brokerDialParams.TransformedHostName,
		NetworkLatencyMultiplier: brokerDialParams.NetworkLatencyMultiplier,
		AdditionalHeaders:        config.MeekAdditionalHeaders,
	}

	switch brokerDialParams.BrokerTransport {
	case protocol.FRONTING_TRANSPORT_HTTPS:
		brokerDialParams.meekConfig.UseHTTPS = true
	case protocol.FRONTING_TRANSPORT_QUIC:
		brokerDialParams.meekConfig.UseQUIC = true
	}

	return nil
}

// GetMetrics implements the common.MetricsSource interface and returns log
// fields detailing the broker dial parameters.
func (brokerDialParams *InproxyBrokerDialParameters) GetMetrics() common.LogFields {

	logFields := make(common.LogFields)

	logFields["inproxy_broker_transport"] = brokerDialParams.BrokerTransport

	isReplay := "0"
	if brokerDialParams.isReplay {
		isReplay = "1"
	}
	logFields["inproxy_broker_is_replay"] = isReplay

	// Note: as At the broker client transport is currently limited to domain
	// fronted HTTPS, the following related parameters are included
	// unconditionally.

	logFields["inproxy_broker_fronting_provider_id"] = brokerDialParams.FrontingProviderID

	logFields["inproxy_broker_dial_address"] = brokerDialParams.FrontingDialAddress

	resolvedIPAddress := brokerDialParams.ResolvedIPAddress.Load().(string)
	if resolvedIPAddress != "" {
		logFields["inproxy_broker_resolved_ip_address"] = resolvedIPAddress
	}

	if brokerDialParams.SNIServerName != "" {
		logFields["inproxy_broker_sni_server_name"] = brokerDialParams.SNIServerName
	}

	logFields["inproxy_broker_host_header"] = brokerDialParams.HostHeader

	transformedHostName := "0"
	if brokerDialParams.TransformedHostName {
		transformedHostName = "1"
	}
	logFields["inproxy_broker_transformed_host_name"] = transformedHostName

	if brokerDialParams.UserAgent != "" {
		logFields["inproxy_broker_user_agent"] = brokerDialParams.UserAgent
	}

	if brokerDialParams.BrokerTransport == protocol.FRONTING_TRANSPORT_HTTPS {

		if brokerDialParams.TLSProfile != "" {
			logFields["inproxy_broker_tls_profile"] = brokerDialParams.TLSProfile
		}

		logFields["inproxy_broker_tls_version"] = brokerDialParams.TLSVersion

		tlsFragmented := "0"
		if brokerDialParams.TLSFragmentClientHello {
			tlsFragmented = "1"
		}
		logFields["inproxy_broker_tls_fragmented"] = tlsFragmented
	}

	if brokerDialParams.BPFProgramName != "" {
		logFields["inproxy_broker_client_bpf"] = brokerDialParams.BPFProgramName
	}

	if brokerDialParams.ResolveParameters != nil {

		// See comment for dialParams.ResolveParameters handling in
		// getBaseAPIParameters.

		if brokerDialParams.ResolveParameters.PreresolvedIPAddress != "" {
			dialDomain, _, _ := net.SplitHostPort(brokerDialParams.DialAddress)
			if brokerDialParams.ResolveParameters.PreresolvedDomain == dialDomain {
				logFields["inproxy_broker_dns_preresolved"] = brokerDialParams.ResolveParameters.PreresolvedIPAddress
			}
		}

		if brokerDialParams.ResolveParameters.PreferAlternateDNSServer {
			logFields["inproxy_broker_dns_preferred"] = brokerDialParams.ResolveParameters.AlternateDNSServer
		}

		if brokerDialParams.ResolveParameters.ProtocolTransformName != "" {
			logFields["inproxy_broker_dns_transform"] = brokerDialParams.ResolveParameters.ProtocolTransformName
		}

		logFields["inproxy_broker_dns_attempt"] = strconv.Itoa(
			brokerDialParams.ResolveParameters.GetFirstAttemptWithAnswer())
	}

	// TODO: get fragmentor metrics, if any, from MeekConn.

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
}

// NewInproxyBrokerRoundTripper creates a new InproxyBrokerRoundTripper. The
// initial DialMeek is defered until the first call to RoundTrip, so
// NewInproxyBrokerRoundTripper does not perform any network operations.
//
// The input brokerDialParams dial parameter and config fields must not
// modifed after NewInproxyBrokerRoundTripper is called.
func NewInproxyBrokerRoundTripper(
	brokerDialParams *InproxyBrokerDialParameters) *InproxyBrokerRoundTripper {

	runCtx, stopRunning := context.WithCancel(context.Background())

	return &InproxyBrokerRoundTripper{
		brokerDialParams: brokerDialParams,
		runCtx:           runCtx,
		stopRunning:      stopRunning,
		dialCompleted:    make(chan struct{}),
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
	ctx context.Context, requestPayload []byte) ([]byte, error) {

	// Cancel DialMeek or MeekConn.RoundTrip when:
	// - Close is called
	// - the input context is done
	ctx, cancelFunc := common.MergeContextCancel(ctx, rt.runCtx)
	defer cancelFunc()

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
	// There is no retry here is DialMeek fails, as higher levels will invoke
	// BrokerClientRoundTripperFailed on failure, clear any replay, select
	// new dial parameters, and retry.

	if atomic.CompareAndSwapInt32(&rt.dial, 0, 1) {

		// DialMeek hasn't been called yet.

		conn, err := DialMeek(
			ctx,
			rt.brokerDialParams.meekConfig,
			rt.brokerDialParams.dialConfig)

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
			return nil, errors.Trace(rt.dialErr)
		}
	}

	// At this point, rt.conn is an established MeekConn.

	// Note that the network address portion of the URL will be ignored by
	// MeekConn in favor of the MeekDialConfig, while the path will be used.
	url := fmt.Sprintf(
		"https://%s/%s",
		rt.brokerDialParams.DialAddress,
		inproxy.BrokerEndPointName)

	request, err := http.NewRequestWithContext(
		ctx, "POST", url, bytes.NewBuffer(requestPayload))
	if err != nil {
		return nil, errors.Trace(err)
	}

	response, err := rt.conn.RoundTrip(request)
	if err == nil {
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			err = fmt.Errorf("unexpected response status code: %d", response.StatusCode)
		}
	}
	if err != nil {
		return nil, errors.Trace(err)
	}

	responsePayload, err := io.ReadAll(response.Body)
	if err != nil {
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

	discoverNAT                    bool
	disableSTUN                    bool
	disablePortMapping             bool
	disableInboundForMobleNetworks bool
	disableIPv6ICECandidates       bool
	discoverNATTimeout             time.Duration
	webRTCAnswerTimeout            time.Duration
	awaitDataChannelTimeout        time.Duration
	proxyDestinationDialTimeout    time.Duration
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

	var awaitDataChannelTimeout time.Duration
	if isProxy {
		awaitDataChannelTimeout = p.Duration(parameters.InproxyProxyWebRTCAwaitDataChannelTimeout)
	} else {
		awaitDataChannelTimeout = p.Duration(parameters.InproxyClientWebRTCAwaitDataChannelTimeout)
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

		discoverNAT:                    p.WeightedCoinFlip(parameters.InproxyClientDiscoverNATProbability),
		disableSTUN:                    p.Bool(parameters.InproxyDisableSTUN),
		disablePortMapping:             p.Bool(parameters.InproxyDisablePortMapping),
		disableInboundForMobleNetworks: p.Bool(parameters.InproxyDisableInboundForMobleNetworks),
		disableIPv6ICECandidates:       p.Bool(parameters.InproxyDisableIPv6ICECandidates),
		discoverNATTimeout:             p.Duration(parameters.InproxyDiscoverNATTimeout),
		webRTCAnswerTimeout:            p.Duration(parameters.InproxyWebRTCAnswerTimeout),
		awaitDataChannelTimeout:        awaitDataChannelTimeout,
		proxyDestinationDialTimeout:    p.Duration(parameters.InproxyProxyDestinationDialTimeout),
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
func (w *InproxyWebRTCDialInstance) DataChannelTrafficShapingParameters() *inproxy.DataChannelTrafficShapingParameters {
	return &w.webRTCDialParameters.DataChannelTrafficShapingParameters
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
func (w *InproxyWebRTCDialInstance) DisableInboundForMobleNetworks() bool {
	return w.disableInboundForMobleNetworks
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
func (w *InproxyWebRTCDialInstance) SetPortMappingTypes(portMappingTypes inproxy.PortMappingTypes) {
	w.natStateManager.setPortMappingTypes(w.networkID, portMappingTypes)
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
	// Limitation: there's ResolveParameters, including no preresolved DNS
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
func (w *InproxyWebRTCDialInstance) BindToDevice(fileDescriptor int) error {

	// Use config.deviceBinder, with wired up logging, not
	// config.DeviceBinder; other tunnel-core dials do this indirectly via
	// psiphon.DialConfig.

	_, err := w.config.deviceBinder.BindToDevice(fileDescriptor)
	return errors.Trace(err)
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
func (w *InproxyWebRTCDialInstance) WebRTCAwaitDataChannelTimeout() time.Duration {
	return w.awaitDataChannelTimeout
}

// Implements the inproxy.WebRTCDialCoordinator interface.
func (w *InproxyWebRTCDialInstance) ProxyDestinationDialTimeout() time.Duration {
	return w.proxyDestinationDialTimeout
}

// InproxySTUNDialParameters is a set of STUN dial parameters.
// InproxySTUNDialParameters is compatible with DialParameters JSON
// marshaling. For client in-proxy tunnel dials, DialParameters will manage
// STUN dial parameter selection and replay.
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

	stunServerAddressesParam := parameters.InproxyClientSTUNServerAddresses
	stunServerAddressesRFC5780Param := parameters.InproxyClientSTUNServerAddressesRFC5780
	if isProxy {
		stunServerAddressesParam = parameters.InproxyProxySTUNServerAddresses
		stunServerAddressesRFC5780Param = parameters.InproxyProxySTUNServerAddressesRFC5780
	}

	// Empty STUN server address lists are not an error condition. When used
	// for WebRTC, the STUN ICE candidate gathering will be skipped but the
	// WebRTC connection may still be established via other candidate types.

	stunServerAddresses := p.Strings(stunServerAddressesParam)
	stunServerAddressesRFC5780 := p.Strings(stunServerAddressesRFC5780Param)

	var stunServerAddress, stunServerAddressRFC5780 string

	if len(stunServerAddresses) > 0 {
		prng.Shuffle(
			len(stunServerAddresses),
			func(i, j int) {
				stunServerAddresses[i], stunServerAddresses[j] =
					stunServerAddresses[j], stunServerAddresses[i]
			})
		stunServerAddress = stunServerAddresses[0]
	}

	if len(stunServerAddressesRFC5780) > 0 {
		prng.Shuffle(
			len(stunServerAddressesRFC5780),
			func(i, j int) {
				stunServerAddressesRFC5780[i], stunServerAddressesRFC5780[j] =
					stunServerAddressesRFC5780[j], stunServerAddressesRFC5780[i]
			})
		stunServerAddressRFC5780 = stunServerAddressesRFC5780[0]
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

	dialParams.STUNServerResolvedIPAddress.Store("")
	dialParams.STUNServerRFC5780ResolvedIPAddress.Store("")

	return dialParams, nil
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
	RootObfuscationSecret               inproxy.ObfuscationSecret
	DataChannelTrafficShapingParameters inproxy.DataChannelTrafficShapingParameters
	DoDTLSRandomization                 bool
}

// MakeInproxyWebRTCDialParameters generates new InproxyWebRTCDialParameters.
func MakeInproxyWebRTCDialParameters(
	p parameters.ParametersAccessor) (*InproxyWebRTCDialParameters, error) {

	rootObfuscationSecret, err := inproxy.GenerateRootObfuscationSecret()
	if err != nil {
		return nil, errors.Trace(err)
	}

	trafficShapingParameters := p.InproxyDataChannelTrafficShapingParameters(
		parameters.InproxyDataChannelTrafficShapingParameters)

	doDTLSRandomization := p.WeightedCoinFlip(parameters.InproxyDTLSRandomizationProbability)

	return &InproxyWebRTCDialParameters{
		RootObfuscationSecret:               rootObfuscationSecret,
		DataChannelTrafficShapingParameters: inproxy.DataChannelTrafficShapingParameters(trafficShapingParameters),
		DoDTLSRandomization:                 doDTLSRandomization,
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

	// Assumes s.mutex lock is held.

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
	networkID string, portMappingTypes inproxy.PortMappingTypes) {

	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.networkID != networkID {
		return
	}

	s.portMappingTypes = portMappingTypes
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

func inproxyUDPAddrFromAddrPort(addrPort netip.AddrPort) *net.UDPAddr {
	return &net.UDPAddr{
		IP:   addrPort.Addr().AsSlice(),
		Port: int(addrPort.Port()),
	}
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
	}

	return inproxy.NetworkTypeUnknown
}
