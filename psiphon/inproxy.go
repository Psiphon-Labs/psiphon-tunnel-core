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
	"crypto/sha256"
	"encoding/json"
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
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/resolver"
	utls "github.com/Psiphon-Labs/utls"
)

// InproxyBrokerClientManager manages a bounded set of
// InproxyBrokerClientInstance values, each an in-proxy broker client with
// its own broker dial parameters, for use by client dials or proxy
// announcements. At most InproxyClientMaxBrokerClients or
// InproxyProxyMaxBrokerClients are managed at once for clients and proxies
// respectively.
//
// One broker client at a time may be shared: the first to receive a valid
// broker response is returned by subsequent GetBrokerClient calls and
// remains connected to the broker, to minimize transport round trips for
// subsequent requests. Other broker clients are not closed until released
// by all callers. For in-proxy clients, a shared broker client with no
// callers is closed after InproxyClientBrokerClientIdleTimeout.
// GetBrokerClient documents acquisition, sharing, and closure.
//
// Each InproxyBrokerClientInstance binds one broker client to one broker,
// round tripper, and set of dial parameters for all of its requests, so that
// round tripper success/failure callbacks set or clear replay for the
// correct dial parameters while several broker clients are live. Broker
// dial parameters are replayed independently of tunnel dial parameters,
// as one broker client serves many in-proxy dials.
//
// Network changes, tactics updates and controller shutdown close all broker
// clients.
type InproxyBrokerClientManager struct {
	config  *Config
	isProxy bool

	tlsCache utls.ClientSessionCache

	mutex        sync.Mutex
	networkID    string
	sharedClient *InproxyBrokerClientInstance

	// clients tracks broker client instances until the broker client manager
	// closes them, including those that have not dialed yet or have no
	// requests in progress.
	clients map[*InproxyBrokerClientInstance]*inproxyBrokerClientEntry
	// sharedIdleTimer closes the shared client when it has no callers for
	// InproxyClientBrokerClientIdleTimeout.
	sharedIdleTimer             *time.Timer
	changed                     chan struct{}
	selector                    inproxyBrokerSelector
	createdBrokerClients        int
	peakConcurrentBrokerClients int
	proxyKeyOnce                sync.Once
	proxyKey                    inproxy.SessionPrivateKey
	proxyKeyErr                 error
}

// NewInproxyBrokerClientManager creates a new InproxyBrokerClientManager.
// NewInproxyBrokerClientManager does not perform any network operations; the
// managed InproxyBrokerClientInstance values are initialized when used for a
// round trip.
func NewInproxyBrokerClientManager(
	config *Config, isProxy bool, tlsCache utls.ClientSessionCache) *InproxyBrokerClientManager {

	b := &InproxyBrokerClientManager{
		config:   config,
		isProxy:  isProxy,
		tlsCache: tlsCache,
	}

	// b.clients is initialized on demand, when GetBrokerClient is called.
	// b.sharedClient is set when a client is selected for sharing; see
	// clientResponseReceived.

	return b
}

// TacticsApplied implements the TacticsAppliedReceiver interface, and is
// called when tactics have changed, which closes existing broker clients in
// order to apply potentially changed parameters.
func (b *InproxyBrokerClientManager) TacticsApplied() error {

	b.mutex.Lock()
	defer b.mutex.Unlock()
	if len(b.clients) == 0 {
		// No clients to close; invalidate the cached broker selection so
		// the next GetBrokerClient reinitializes it from current tactics.
		b.selector.brokers = nil
		return nil
	}
	b.resetClientBrokerClientsLocked("tactics applied")
	return nil
}

// NetworkChanged is called when the active network changes, to trigger a
// broker client reset.
func (b *InproxyBrokerClientManager) NetworkChanged() error {

	b.mutex.Lock()
	defer b.mutex.Unlock()
	b.resetClientBrokerClientsLocked("network changed")
	return nil
}

// GetBrokerClient returns the current, shared broker client and its
// corresponding dial parameters (for metrics logging), along with a release
// function. If there is no shared broker client, a new broker client instance
// is initialized. networkID must be the current network ID, or GetBrokerClient
// returns an error; when it differs from the network ID of the tracked broker
// clients, those are first closed.
//
// GetBrokerClient waits when InproxyClientMaxBrokerClients or
// InproxyProxyMaxBrokerClients is reached, for clients and proxies
// respectively, or, for personal pairing clients and proxies, when all
// fronting providers at the current broker selection have been tried and
// InproxyBrokerClientManager still manages broker clients from that
// selection. The wait ends and acquisition is retried when a broker client
// becomes shared or unshared or is closed. When tactics provides no broker
// specs, GetBrokerClient returns an error immediately.
//
// ctx applies only while GetBrokerClient waits for a broker client. After
// GetBrokerClient returns, canceling ctx does not close the broker client or
// interrupt its requests, which use their own contexts. The caller must invoke
// release when done with the broker client; subsequent invocations of release
// have no effect.
//
// A broker client that is not shared closes when all callers have released it.
// A shared broker client remains available for reuse; for in-proxy clients, it
// closes after InproxyClientBrokerClientIdleTimeout with no callers, while
// proxies retain it. A broker client that fails is no longer shared, and closes
// when all callers have released it. NoMatch failover, network changes, tactics
// updates and shutdown may close broker clients while they are in use.
func (b *InproxyBrokerClientManager) GetBrokerClient(
	ctx context.Context, networkID string) (*inproxy.BrokerClient, *InproxyBrokerDialParameters, func(), error) {
	start := time.Now()
	for {
		if err := ctx.Err(); err != nil {
			return nil, nil, nil, errors.Trace(err)
		}
		if b.config.GetNetworkID() != networkID {
			return nil, nil, nil, errors.TraceNew("network changed")
		}

		instance, reused, changed, err := b.tryGetClientBrokerClient(networkID)
		if err != nil {
			return nil, nil, nil, errors.Trace(err)
		}
		if instance == nil {
			select {
			case <-ctx.Done():
				return nil, nil, nil, errors.Trace(ctx.Err())
			case <-changed:
				continue
			}
		}

		// Copy dial parameters with b.mutex released: failure callbacks
		// take instance.mutex before b.mutex, so the reverse order could
		// deadlock.
		instance.mutex.Lock()
		dialParams := *instance.brokerDialParams
		instance.mutex.Unlock()
		dialParams.isReuse = reused
		dialParams.candidateNumber = instance.candidateNumber
		dialParams.acquireDuration = time.Since(start)
		release := sync.OnceFunc(func() {
			b.mutex.Lock()
			defer b.mutex.Unlock()
			if entry := b.clients[instance]; entry != nil {
				entry.refs--
				if entry.refs == 0 && b.sharedClient != instance {
					b.closeClientLocked(instance, "last caller released")
				} else if entry.refs == 0 {
					b.startSharedIdleTimerLocked(instance)
				}
			}
		})
		if err := ctx.Err(); err != nil {
			release()
			return nil, nil, nil, errors.Trace(err)
		}
		return instance.brokerClient, &dialParams, release, nil
	}
}

// brokerClientFailed stops sharing a failed broker client and prevents later
// responses from making it shared again; see clientResponseReceived. Existing
// callers may continue using it until they release it. It closes when all
// callers have released it. Replay deletion and TLS session cache removal are
// handled by the caller.
func (b *InproxyBrokerClientManager) brokerClientFailed(
	instance *InproxyBrokerClientInstance, err error) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	entry := b.clients[instance]
	// Concurrent requests may report failures after this client was closed or
	// marked failed; failure handling has already been completed.
	if entry == nil || entry.failed {
		return
	}
	entry.failed = true
	// A failed client held by callers stays tracked until released, so it
	// still counts toward the client limit and toward the fronting providers
	// tried at the current broker selection. Unsharing it or closing it
	// closes b.changed, waking GetBrokerClient calls blocked on either.
	wasShared := b.sharedClient == instance
	if wasShared {
		b.stopSharedIdleTimerLocked()
		b.sharedClient = nil
		b.selector.sharedLost()
		if entry.refs > 0 {
			b.signalClientChangedLocked()
		}
	}
	failure := fmt.Sprintf("transport failure (%v)", err)
	// With no callers holding the broker client, no release will close it.
	if entry.refs == 0 {
		b.closeClientLocked(instance, failure)
		return
	}
	NoticeWarning(
		"inproxy: broker client %s failed: %s, shared %t, callers %d",
		instance.brokerClientID, failure, wasShared, entry.refs)
}

// tryGetClientBrokerClient reuses the shared client or creates a new client.
// When neither is possible, it returns a channel to wait on before retrying.
func (b *InproxyBrokerClientManager) tryGetClientBrokerClient(
	networkID string) (
	instance *InproxyBrokerClientInstance, reused bool, changed <-chan struct{}, err error) {

	b.mutex.Lock()
	defer b.mutex.Unlock()

	if b.networkID != networkID || b.selector.brokers == nil {
		b.resetClientBrokerClientsLocked("network ID or broker specs changed")
		b.networkID = networkID
	}

	// A personal pairing proxy away from its first rendezvous broker
	// returns to it on a schedule, checked here since proxy workers
	// acquire at least once per announce cycle.
	if b.selector.returnHomeDue() {
		b.returnHomeLocked()
	}

	// Reusing the shared client ends its idle period.
	if b.sharedClient != nil {
		b.stopSharedIdleTimerLocked()
		b.clients[b.sharedClient].refs++
		return b.sharedClient, true, nil, nil
	}

	p := b.config.GetParameters().Get()
	defer p.Close()

	if len(getInproxyBrokerSpecs(b.config, p, b.isProxy)) == 0 {
		return nil, false, nil, errors.TraceNew("no broker specs")
	}

	// The client limit includes clients still in use after a failure.
	limit := p.Int(parameters.InproxyClientMaxBrokerClients)
	if b.isProxy {
		limit = p.Int(parameters.InproxyProxyMaxBrokerClients)
	}
	if len(b.clients) >= limit {
		return nil, false, b.waitLocked(
			"%d of %d broker clients tracked", len(b.clients), limit), nil
	}

	liveClients := make([]*InproxyBrokerClientInstance, 0, len(b.clients))
	for client := range b.clients {
		liveClients = append(liveClients, client)
	}
	selection, err := b.selector.selectClient(b.config, p, networkID, b.isProxy, liveClients)
	if err != nil {
		return nil, false, nil, errors.Trace(err)
	}
	if selection == nil {
		return nil, false, b.waitLocked(
			"all fronting providers tried at the current broker"), nil
	}
	instance, err = newInproxyBrokerClientInstance(b.config, p, b, networkID, b.isProxy, selection)
	if err != nil {
		return nil, false, nil, errors.Trace(err)
	}
	if b.clients == nil {
		b.clients = make(map[*InproxyBrokerClientInstance]*inproxyBrokerClientEntry)
	}
	b.clients[instance] = &inproxyBrokerClientEntry{refs: 1}
	b.createdBrokerClients++
	instance.candidateNumber = b.createdBrokerClients
	if len(b.clients) > b.peakConcurrentBrokerClients {
		b.peakConcurrentBrokerClients = len(b.clients)
	}
	return instance, false, nil, nil
}

// takeBrokerClientCounts returns the number of broker clients created and
// the peak number tracked concurrently since the previous call, then resets
// both so they accumulate again afterwards. The peak restarts at the number of
// clients still tracked, so clients that outlive the interval are not
// forgotten. It is safe to call on a nil receiver, returning zeros.
func (b *InproxyBrokerClientManager) takeBrokerClientCounts() (created, peakConcurrent int) {
	if b == nil {
		return 0, 0
	}
	b.mutex.Lock()
	defer b.mutex.Unlock()
	created, peakConcurrent = b.createdBrokerClients, b.peakConcurrentBrokerClients
	b.createdBrokerClients, b.peakConcurrentBrokerClients = 0, len(b.clients)
	return created, peakConcurrent
}

// brokerClientPrivateKey returns the configured proxy key, or generates an
// ephemeral proxy key on first use and retains it for future calls.
// Clients get a new ephemeral key on each call.
func (b *InproxyBrokerClientManager) brokerClientPrivateKey() (inproxy.SessionPrivateKey, error) {
	if !b.isProxy {
		return inproxy.GenerateSessionPrivateKey()
	}
	b.proxyKeyOnce.Do(func() {
		if b.config.InproxyProxySessionPrivateKey != "" {
			b.proxyKey, b.proxyKeyErr = inproxy.SessionPrivateKeyFromString(b.config.InproxyProxySessionPrivateKey)
		} else {
			b.proxyKey, b.proxyKeyErr = inproxy.GenerateSessionPrivateKey()
		}
	})
	return b.proxyKey, b.proxyKeyErr
}

// waitLocked returns the channel broker client acquisition waits on in the
// event the max number of broker clients has been reached with no shared
// client or the search space of the current selection is exhausted. The
// caller must hold b.mutex.
func (b *InproxyBrokerClientManager) waitLocked(reasonFormat string, args ...any) <-chan struct{} {
	// Log once per stall rather than once per waiter.
	if b.changed == nil {
		b.changed = make(chan struct{})
		NoticeInfo(
			"inproxy: broker client acquisition waiting: "+reasonFormat, args...)
	}
	return b.changed
}

// signalClientChangedLocked wakes waiting GetBrokerClient calls. The caller
// must hold b.mutex.
func (b *InproxyBrokerClientManager) signalClientChangedLocked() {
	if b.changed != nil {
		close(b.changed)
	}
	b.changed = nil
}

type inproxyBrokerClientEntry struct {
	// GetBrokerClient calls not yet released.
	refs int
	// Set by brokerClientFailed. clientResponseReceived cannot make this client
	// shared again, even after a successful response.
	failed bool
}

func (b *InproxyBrokerClientManager) stopSharedIdleTimerLocked() {
	// b.sharedIdleTimer is the current idle timer; only its callback may
	// close the shared client. Stop does not cancel a callback that has
	// already fired and is waiting for b.mutex, so also set
	// b.sharedIdleTimer to nil so the callback's timer is not current,
	// and expireSharedClientLocked returns without closing anything.
	if b.sharedIdleTimer != nil {
		b.sharedIdleTimer.Stop()
		b.sharedIdleTimer = nil
	}
}

// startSharedIdleTimerLocked starts the idle timeout for the shared client
// instance when its last caller releases it and
// InproxyClientBrokerClientIdleTimeout is nonzero. Any previous timer is
// stopped first. The caller must hold b.mutex.
func (b *InproxyBrokerClientManager) startSharedIdleTimerLocked(instance *InproxyBrokerClientInstance) {
	b.stopSharedIdleTimerLocked()
	if b.isProxy {
		return
	}
	p := b.config.GetParameters().Get()
	timeout := p.Duration(parameters.InproxyClientBrokerClientIdleTimeout)
	p.Close()
	if timeout <= 0 {
		return
	}
	var timer *time.Timer
	timer = time.AfterFunc(timeout, func() {
		b.mutex.Lock()
		defer b.mutex.Unlock()
		b.expireSharedClientLocked(instance, timer)
	})
	b.sharedIdleTimer = timer
	NoticeInfo(
		"inproxy: broker client %s idle timer armed: %s",
		instance.brokerClientID, timeout)
}

// expireSharedClientLocked is the idle timer callback. It closes instance
// only if timer is still the current b.sharedIdleTimer and instance is
// still the shared client with no callers holding it. The caller must hold
// b.mutex.
func (b *InproxyBrokerClientManager) expireSharedClientLocked(instance *InproxyBrokerClientInstance, timer *time.Timer) {
	entry := b.clients[instance]
	// A different timer means this callback's timer was stopped or replaced.
	// The same client may have been reused and released since then; this
	// callback must not end its new idle period. Also require that it is
	// still shared and has no callers holding it.
	if timer == nil || timer != b.sharedIdleTimer || b.sharedClient != instance || entry == nil || entry.refs != 0 {
		return
	}
	// Unlike a failure, idle expiry does not delete the stored replay dial
	// parameters, and sharedLost allows the provider to be replayed again.
	b.closeClientLocked(instance, "idle timeout")
	b.selector.sharedLost()
}

// closeClientLocked removes and closes a client, even if it is still in use.
// reason is included in the diagnostic notice. The caller must hold b.mutex.
func (b *InproxyBrokerClientManager) closeClientLocked(
	instance *InproxyBrokerClientInstance, reason string) {
	entry, ok := b.clients[instance]
	if !ok {
		return
	}
	delete(b.clients, instance)
	wasShared := b.sharedClient == instance
	if wasShared {
		b.sharedClient = nil
		b.stopSharedIdleTimerLocked()
	}
	_ = instance.Close()
	b.signalClientChangedLocked()
	NoticeInfo(
		"inproxy: broker client %s closed: %s, shared %t, callers %d",
		instance.brokerClientID, reason, wasShared, entry.refs)
}

// clientResponseReceived is called when instance receives a valid broker
// response, and decides whether instance becomes the shared client.
// retryableNoMatch indicates a client offer with no match that may be
// retried on another broker; see
// inproxy.BrokerDialCoordinator.BrokerClientResponseReceived.
func (b *InproxyBrokerClientManager) clientResponseReceived(
	instance *InproxyBrokerClientInstance, retryableNoMatch bool) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	if entry := b.clients[instance]; entry == nil || entry.failed {
		return
	}
	if !b.selector.matchesCurrentBrokerSelection(instance) {
		// A response from an earlier broker selection cannot change the shared
		// client, even if the same broker has since been selected again.
		if retryableNoMatch && !b.isProxy {
			b.closeClientLocked(instance, "no match at stale broker selection")
		}
		return
	}
	if retryableNoMatch && !b.isProxy {
		if b.sharedClient != nil && b.sharedClient != instance {
			b.closeClientLocked(instance, "no match, another client is shared")
			return
		}
		p := b.config.GetParameters().Get()
		probability := parameters.InproxyClientNoMatchFailoverProbability
		if b.selector.personal {
			probability = parameters.InproxyClientNoMatchFailoverPersonalProbability
		}
		failover := p.WeightedCoinFlip(probability)
		p.Close()
		if failover {
			// Retain replay dial parameters and other clients. Close this
			// client immediately, including any concurrent requests using it.
			NoticeInfo(
				"inproxy: broker client %s no match: failover",
				instance.brokerClientID)
			b.selector.noMatch(instance.brokerDialParams.brokerSpec)
			b.closeClientLocked(instance, "no match failover")
			return
		}
		NoticeInfo(
			"inproxy: broker client %s no match: retained",
			instance.brokerClientID)
	}
	if b.sharedClient != nil {
		// Keep the existing shared client. Both clients may still be in use.
		return
	}
	b.sharedClient = instance
	if b.clients[instance].refs == 0 {
		b.startSharedIdleTimerLocked(instance)
	}
	b.signalClientChangedLocked()
	NoticeInfo("inproxy: broker client %s shared", instance.brokerClientID)
}

// clientTransportEstablished is called when instance's TLS transport is
// established and transport sharing is enabled. It shares instance when no
// client is shared and instance belongs to the current broker selection,
// so other callers reuse the transport before the first broker response.
// Failed clients and clients from earlier selections are not shared, as in
// clientResponseReceived. A later ordinary decoded response on a client
// shared here finds it already shared and changes nothing; a retryable
// NoMatch still applies the failover policy and may close it.
func (b *InproxyBrokerClientManager) clientTransportEstablished(
	instance *InproxyBrokerClientInstance) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	entry := b.clients[instance]
	if entry == nil || entry.failed || b.sharedClient != nil ||
		!b.selector.matchesCurrentBrokerSelection(instance) {
		return
	}
	b.sharedClient = instance
	if entry.refs == 0 {
		b.startSharedIdleTimerLocked(instance)
	}
	b.signalClientChangedLocked()
	NoticeInfo("inproxy: broker client %s shared transport", instance.brokerClientID)
}

// closeAllClientsLocked closes every tracked client, even those still held
// by callers, clears the registry, shared pointer and idle timer, and wakes
// waiting GetBrokerClient calls, as closeClientLocked does for one client.
// reason is included in the per-client diagnostic notice. Selection state
// is left to the caller; woken waiters re-check it only after the caller
// releases b.mutex. The caller must hold b.mutex.
func (b *InproxyBrokerClientManager) closeAllClientsLocked(reason string) {
	for instance, entry := range b.clients {
		_ = instance.Close()
		NoticeInfo(
			"inproxy: broker client %s closed: %s, shared %t, callers %d",
			instance.brokerClientID, reason, b.sharedClient == instance, entry.refs)
	}
	clear(b.clients)
	b.sharedClient = nil
	b.stopSharedIdleTimerLocked()
	b.signalClientChangedLocked()
}

// resetClientBrokerClientsLocked closes all clients and clears network and
// broker selection state. reason is included in the per-client diagnostic
// notice. The caller must hold b.mutex.
func (b *InproxyBrokerClientManager) resetClientBrokerClientsLocked(reason string) {
	b.closeAllClientsLocked(reason)
	b.networkID = ""
	b.selector.reset()
}

// returnHomeLocked closes all clients and selects the first rendezvous
// broker again for a personal pairing proxy that has been away for the
// return-to-home interval. Unlike resetClientBrokerClientsLocked, the
// network ID, broker order and compartment IDs are retained. The caller
// must hold b.mutex.
func (b *InproxyBrokerClientManager) returnHomeLocked() {
	b.closeAllClientsLocked("return home")
	away := b.selector.returnHome()
	NoticeInfo(
		"inproxy: returning to first rendezvous broker after %s away", away)
}

// closeClientBrokerClients closes all clients and resets broker selection.
// It is safe to call on a nil receiver. The caller must not hold b.mutex.
func (b *InproxyBrokerClientManager) closeClientBrokerClients() {
	if b == nil {
		return
	}
	b.mutex.Lock()
	defer b.mutex.Unlock()
	b.resetClientBrokerClientsLocked("shutdown")
}

// inproxyBrokerFrontingSpecs returns all fronting specs in broker for the
// given provider.
func inproxyBrokerFrontingSpecs(broker *parameters.InproxyBrokerSpec, provider string) parameters.FrontingSpecs {
	var specs parameters.FrontingSpecs
	for _, spec := range broker.BrokerFrontingSpecs {
		if spec.FrontingProviderID == provider {
			specs = append(specs, spec)
		}
	}
	return specs
}

// inproxyBrokerSupportsProvider reports whether the broker has at least one
// fronting spec for the given provider.
func inproxyBrokerSupportsProvider(broker *parameters.InproxyBrokerSpec, provider string) bool {
	for _, spec := range broker.BrokerFrontingSpecs {
		if spec.FrontingProviderID == provider {
			return true
		}
	}
	return false
}

// inproxyBrokerSelector selects the broker, fronting provider and any dial
// parameters for a new broker client. Its goal is to reach a working broker
// when some fronting providers or brokers are blocked, trying providers in
// an order that spreads load and favors proven dial parameters, while keeping
// clients and proxies at brokers where they can be matched: common pairing
// clients may explore across brokers, personal pairing clients and proxies
// follow a derived broker order, and proxies stay at one broker to remain
// findable. The fields below describe the state each strategy keeps.
//
// Common pairing clients explore across brokers (selectAcrossBrokers):
//   - Each provider progresses independently through the stable broker order
//     (illustrated below), skipping brokers that do not support it and
//     wrapping at the end. A provider being tried for the first time starts
//     after the most recently selected broker.
//   - When replay is enabled, prefer valid stored dial parameters for a
//     provider with no tracked broker clients that has not already been
//     replayed during this search, considering providers in rotating order
//     and brokers from each provider's saved position.
//   - Otherwise, choose the provider with the fewest tracked broker clients,
//     breaking ties by rotating provider order, and take its next supporting
//     broker. Use eligible replay there if available.
//   - After a selection, that provider's position advances past the selected
//     broker and preference rotates to the next provider. A failed or
//     canceled attempt does not undo this progress or restore a consumed
//     replay attempt.
//   - NoMatch failover makes the next selection order-first; see noMatch.
//
// Example search positions for common pairing clients:
//
//	Brokers:       [1, 2, 3, 4, ...]
//	Provider A:              ^
//	Provider B:        ^
//
// Here A's next search starts at broker 4 and B's starts at broker 2. When
// replay is preferred, the search may skip earlier brokers to select one with
// valid replay parameters for this provider. The provider's saved position
// then advances past the selected broker. Searches wrap from the end of the
// broker list to the beginning.
//
// Personal pairing clients and all proxies try each provider at one broker
// before advancing (selectAtCurrentBroker):
//   - Each provider at the current broker is tried once per search. After all
//     have been tried, selection waits for clients from the current selection
//     to close, then advances to the next broker in order.
//   - Personal pairing clients and proxies follow the rendezvous order derived
//     from the personal compartment ID, so a client and proxy with the same ID
//     and broker list walk the same brokers from the same first rendezvous
//     broker and meet at one of them. Replay is considered only at the
//     selected broker.
//   - Common pairing proxies follow the selector's own stable order, but may
//     start a visit at a broker with eligible replay.
//   - A personal pairing client advances immediately on NoMatch failover, even
//     while other broker clients are still held by callers. Proxies never fail
//     over on NoMatch: they keep announcing at the same broker so that a
//     client can find them.
//   - A personal pairing proxy that has advanced away from the first
//     rendezvous broker returns to it after
//     InproxyProxyPersonalReturnHomePeriod; see returnHome.
//
// Losing the shared client refreshes the provider search in every mode without
// changing broker positions or the current broker selection; see sharedLost. A
// reset clears all selection state except the random seed.
//
// inproxyBrokerSelector is not safe for concurrent use.
type inproxyBrokerSelector struct {
	// Prepared during initialization and retained until reset. All broker
	// clients created by this selector use the same compartment ID lists.
	commonCompartmentIDs   []inproxy.ID
	personalCompartmentIDs []inproxy.ID

	// Whether a personal compartment ID is configured.
	personal bool

	// Whether this selector is used by a proxy rather than a client.
	proxy bool

	// Random seed for common pairing broker order, retained across resets.
	// Personal pairing derives its seed from the compartment ID instead.
	seed *prng.Seed

	// Shuffled broker specs used when choosing the next broker to try.
	// In personal pairing mode, the list is limited to
	// InproxyPersonalPairingMaxBrokerSpecCount brokers.
	brokers parameters.InproxyBrokerSpecsValue

	// Current broker and provider attempts for personal pairing clients and
	// proxies. Replaced when advancing or resetting selection, even when
	// selecting the same broker again. Retained on shared client loss.
	currentBrokerSelection *inproxyBrokerSelectionState

	// Starting position in brokers for a provider not yet in
	// nextBrokerByProvider.
	// Updated to the position after each selected broker. For example, if the
	// last selection used the second broker in the list, a provider with no
	// saved position starts searching at the third broker. Positions wrap at
	// the end of the list. Providers with saved positions are unaffected.
	// Used only by common pairing clients.
	nextBroker int

	// Next position in brokers for each previously selected provider.
	// Used only by common pairing clients.
	nextBrokerByProvider map[string]int

	// Try each fronting provider at the current broker before advancing,
	// waiting for existing attempts to finish. NoMatch failover may advance
	// earlier. Set for personal pairing clients and proxies.
	exhaustBrokerProviders bool

	// Distinct fronting provider IDs in shuffled order. Includes providers
	// from all brokers for common pairing clients, or the current broker
	// for personal pairing clients and proxies.
	providers []string

	// Starting position in providers for the next selection. Advances after
	// each selection to rotate preference among equally eligible providers.
	nextProvider int

	// Providers whose replay dial parameters have already been selected.
	// Cleared on reset or shared client loss, not when advancing brokers.
	replayedByProvider map[string]bool

	// Prefer broker order over replay when choosing the next broker after
	// NoMatch failover. Replay at the selected broker is still allowed.
	// Cleared after the next selection.
	preferBrokerOrder bool

	// The broker whose NoMatch response caused the common pairing
	// failover.
	noMatchBroker *parameters.InproxyBrokerSpec

	// Interval after which a personal pairing proxy away from the first
	// rendezvous broker returns to it; see returnHome. Zero disables
	// returns.
	returnHomePeriod time.Duration

	// When a personal pairing proxy last advanced from the first
	// rendezvous broker. Zero while it is there or when the selector is
	// not a personal pairing proxy's.
	awayFromHomeSince time.Time
}

// inproxyBrokerSelectionState tracks attempts at one broker. Each selection
// gets distinct selection state, even when selecting the same broker again.
// Broker clients retain its pointer; matchesCurrentBrokerSelection compares
// it with the selector's current state before sharing or counting clients at
// the current broker. InproxyBrokerClientManager.mutex protects these fields
// and pointer comparisons.
type inproxyBrokerSelectionState struct {
	// Selected broker spec. Nil until broker selection is complete; common
	// pairing proxies may first advance index to a broker with replay.
	spec *parameters.InproxyBrokerSpec

	// Position in the selector's brokers list, before or after selection.
	// May exceed the list length; lookup uses index modulo len(brokers).
	index int

	// Fronting provider IDs already attempted for this broker selection.
	// Recorded before client creation, so construction failures count as
	// attempts. Providers used by broker clients still tracked for this
	// selection are also marked as tried.
	tried map[string]bool

	// Why selection moved to this broker. Empty for the initial selection.
	reason string
}

// reset clears broker selection while retaining the random seed. It creates
// new selection state, so broker clients created earlier no longer belong to
// the current selection. For personal pairing clients and proxies,
// matchesCurrentBrokerSelection rejects those clients: they cannot become
// shared or count toward providers tried at the current broker, even if the
// same broker is selected again.
func (s *inproxyBrokerSelector) reset() {
	s.commonCompartmentIDs, s.personalCompartmentIDs = nil, nil
	s.brokers = nil
	s.exhaustBrokerProviders, s.personal, s.proxy = false, false, false
	s.providers = nil
	s.nextProvider, s.nextBroker = 0, 0
	s.nextBrokerByProvider, s.replayedByProvider = nil, nil
	s.preferBrokerOrder, s.noMatchBroker = false, nil
	s.currentBrokerSelection = &inproxyBrokerSelectionState{}
	s.returnHomePeriod, s.awayFromHomeSince = 0, time.Time{}
}

// sharedLost refreshes the search after the shared client fails or idle
// expires: provider order is rebuilt and replayedByProvider is cleared, so
// the lost client's provider may be replayed again, while broker cursors
// and the session seed are kept. Personal pairing clients and proxies keep
// their current broker and selection state pointer, with its tried
// providers cleared so the next selection rebuilds them from the clients
// still tracked: the lost client was proven at that broker, surviving
// candidates there can still become shared, and a personal pairing client
// that left would have to re-walk every broker between the first in
// rendezvous order and the one where its proxy is.
func (s *inproxyBrokerSelector) sharedLost() {
	s.providers, s.replayedByProvider = nil, nil
	s.nextProvider = 0
	s.preferBrokerOrder, s.noMatchBroker = false, nil
	if s.exhaustBrokerProviders {
		s.currentBrokerSelection.tried = nil
	}
}

// advanceBroker records the next broker index and clears the tried providers.
// New state distinguishes this selection even if the broker order wraps
// around to a previously selected broker. reason captures why selection moved
// to this broker; newInproxyBrokerClientInstance appends it to the
// "selected broker" notice of the first broker client created at the new
// selection and then clears it.
func (s *inproxyBrokerSelector) advanceBroker(index int, reason string) {
	s.currentBrokerSelection = &inproxyBrokerSelectionState{index: index, reason: reason}
	s.providers = nil
	s.nextProvider = 0
}

// noMatch applies client NoMatch failover after broker returned no match.
// Personal pairing clients advance to the next rendezvous broker; common
// pairing clients keep their broker positions but make the next selection
// order-first, so replay cannot jump ahead of it, and skip broker, which has
// just reported no supply, when the selected provider has another broker.
// replayedByProvider is kept, so a provider already replayed in this search is
// not replayed again. Only clients call noMatch: proxies never fail over on
// NoMatch, and InproxyBrokerClientManager calls it only after verifying that
// the responding client belongs to the current selection.
func (s *inproxyBrokerSelector) noMatch(broker *parameters.InproxyBrokerSpec) {
	if s.exhaustBrokerProviders {
		s.advanceBroker(s.currentBrokerSelection.index+1, "no match failover")
	}
	s.preferBrokerOrder, s.noMatchBroker = true, broker
}

// matchesCurrentBrokerSelection reports whether the instance holds the
// selector's current broker selection state. Selecting the same broker again
// creates new state, so matching broker specs alone is insufficient. Common
// pairing clients always return true because they select brokers independently
// for each fronting provider.
func (s *inproxyBrokerSelector) matchesCurrentBrokerSelection(instance *InproxyBrokerClientInstance) bool {
	return !s.exhaustBrokerProviders || (s.currentBrokerSelection != nil && instance.brokerSelection == s.currentBrokerSelection)
}

// initialize builds the broker order and caches compartment IDs. It runs
// at the start of every selectClient call and returns immediately while
// s.brokers is populated, so the order is built once per configuration
// snapshot rather than per candidate. s.brokers is cleared by reset and
// by a tactics callback; the next selectClient call then rebuilds it from
// current tactics.
//
// Common pairing order is a permutation seeded by s.seed, allocated once
// per selector and retained across resets. Personal pairing order is
// seeded by the personal compartment ID and bounded by
// InproxyPersonalPairingMaxBrokerSpecCount.
func (s *inproxyBrokerSelector) initialize(config *Config, p parameters.ParametersAccessor, isProxy bool) error {
	if s.currentBrokerSelection == nil {
		s.currentBrokerSelection = &inproxyBrokerSelectionState{}
	}
	if len(s.brokers) > 0 {
		return nil
	}
	commonIDs, personalIDs, err := prepareInproxyCompartmentIDs(config, p, isProxy)
	if err != nil {
		return errors.Trace(err)
	}
	specs := getInproxyBrokerSpecs(config, p, isProxy)
	if len(specs) == 0 {
		return errors.TraceNew("no broker specs")
	}
	s.personal, s.proxy = len(personalIDs) > 0, isProxy
	s.exhaustBrokerProviders = s.personal || isProxy
	seed := s.seed
	if s.personal {
		value := prng.Seed(personalIDs[0])
		seed = &value
	} else if seed == nil {
		var err error
		seed, err = prng.NewSeed()
		if err != nil {
			return errors.Trace(err)
		}
		s.seed = seed
	}
	for _, i := range prng.NewPRNGWithSeed(seed).Perm(len(specs)) {
		s.brokers = append(s.brokers, specs[i])
	}
	if s.personal {
		if max := p.Int(parameters.InproxyPersonalPairingMaxBrokerSpecCount); max > 0 && max < len(s.brokers) {
			s.brokers = s.brokers[:max]
		}
	}
	if s.personal && s.proxy {
		s.returnHomePeriod = p.Duration(parameters.InproxyProxyPersonalReturnHomePeriod)
	}
	s.commonCompartmentIDs, s.personalCompartmentIDs = commonIDs, personalIDs
	return nil
}

// returnHomeDue reports whether a personal pairing proxy away from the first
// rendezvous broker should return to it now: returnHomePeriod has elapsed
// since it left, and the period is not zero, which disables returns.
// Elapsed time is measured with the monotonic clock, so sleep on mobile
// delays a return rather than forcing one.
func (s *inproxyBrokerSelector) returnHomeDue() bool {
	return s.personal && s.proxy && !s.awayFromHomeSince.IsZero() &&
		s.returnHomePeriod > 0 && time.Since(s.awayFromHomeSince) >= s.returnHomePeriod
}

// returnHome selects the first rendezvous broker again with a new selection
// state and returns the time spent away. If the first broker is exhausted
// again, selection advances in rendezvous order as usual and the interval
// restarts. The caller closes the tracked broker clients; see
// InproxyBrokerClientManager.returnHomeLocked.
func (s *inproxyBrokerSelector) returnHome() time.Duration {
	away := time.Since(s.awayFromHomeSince)
	s.advanceBroker(0, "returned home")
	s.awayFromHomeSince = time.Time{}
	return away
}

// initializeProviders builds s.providers, the cyclic order of distinct
// fronting provider IDs across specs, in random order. A populated provider
// list is left unchanged; sharedLost and advanceBroker clear it so the next
// selection rebuilds it.
func (s *inproxyBrokerSelector) initializeProviders(specs parameters.InproxyBrokerSpecsValue) {
	if len(s.providers) > 0 {
		return
	}
	seen := make(map[string]bool)
	var ids []string
	for _, broker := range specs {
		for _, spec := range broker.BrokerFrontingSpecs {
			if !seen[spec.FrontingProviderID] {
				seen[spec.FrontingProviderID] = true
				ids = append(ids, spec.FrontingProviderID)
			}
		}
	}
	for _, i := range prng.Perm(len(ids)) {
		s.providers = append(s.providers, ids[i])
	}
}

// selectClient selects a broker, fronting provider and optional replay dial
// parameters for a new broker client, applying the strategies described on
// inproxyBrokerSelector. It returns the selection without creating the
// client or performing network operations.
//
// InproxyBrokerClientManager passes every broker client it still tracks,
// including failed clients and clients from earlier broker selections that
// callers still hold. All supplied clients count toward provider usage; for
// personal pairing clients and proxies, only clients holding the current
// broker selection state count toward providers tried at that broker and the
// decision to wait before advancing.
//
// selectClient returns nil, nil when every provider at the current broker has
// been tried and clients from that selection are still tracked; the caller
// waits for a change and retries. Selection state, including positions,
// tried providers and consumed replay, is updated before the client is
// created, so a construction failure or cancellation does not undo it.
func (s *inproxyBrokerSelector) selectClient(config *Config, p parameters.ParametersAccessor,
	networkID string, proxy bool, live []*InproxyBrokerClientInstance) (*inproxyBrokerClientSelection, error) {
	if err := s.initialize(config, p, proxy); err != nil {
		return nil, errors.Trace(err)
	}
	if s.exhaustBrokerProviders {
		visit := s.currentBrokerSelection

		// Shared client loss clears the provider order and tried
		// providers but retains the selection, so both are rebuilt from
		// the clients that remain tracked. Clients from earlier
		// selections occupy capacity but cannot delay this one.
		if visit.spec != nil {
			s.initializeProviders(parameters.InproxyBrokerSpecsValue{visit.spec})
		}
		currentLive := 0
		for _, c := range live {
			if c.brokerSelection != visit {
				continue
			}
			currentLive++
			if visit.tried == nil {
				visit.tried = make(map[string]bool)
			}
			visit.tried[c.frontingProviderID] = true
		}

		// Once every provider at the current broker has been tried,
		// wait while clients from that selection remain tracked, since
		// one may still become shared; advance only after none remain.
		// A broker not yet selected has no providers and is not
		// exhausted.
		if len(s.providers) > 0 && len(visit.tried) == len(s.providers) {
			if currentLive > 0 {
				return nil, nil
			}
			if s.personal && s.proxy {
				// Track a personal pairing proxy's time away
				// from the first rendezvous broker: advancing
				// onto it, by wrapping around the order, ends
				// the interval without a return; advancing off
				// it starts the interval. Arrival is checked
				// first so that a single-broker order, where
				// every advance both leaves and arrives, never
				// marks the proxy as away.
				switch {
				case (visit.index+1)%len(s.brokers) == 0:
					s.awayFromHomeSince = time.Time{}
				case visit.index%len(s.brokers) == 0:
					s.awayFromHomeSince = time.Now()
				}
			}
			s.advanceBroker(visit.index+1, fmt.Sprintf(
				"advanced after %d providers tried", len(visit.tried)))
		}
	}
	counts := make(map[string]int)
	for _, c := range live {
		counts[c.frontingProviderID]++
	}
	ttl := p.Duration(parameters.InproxyReplayBrokerDialParametersTTL)
	replayEnabled := ttl > 0 && !config.DisableReplay && p.WeightedCoinFlip(parameters.InproxyReplayBrokerDialParametersProbability)
	loaded := make(map[*parameters.InproxyBrokerSpec]*InproxyBrokerDialParameters)
	load := func(spec *parameters.InproxyBrokerSpec) *InproxyBrokerDialParameters {
		if params, ok := loaded[spec]; ok {
			return params
		}
		params, err := loadInproxyBrokerReplayParameters(networkID, spec, ttl)
		if err != nil {
			NoticeWarning("loadInproxyBrokerReplayParameters failed: %v", errors.Trace(err))
		}
		loaded[spec] = params
		return params
	}
	canReplay := func(provider string) bool {
		return replayEnabled && counts[provider] == 0 && !s.replayedByProvider[provider] && (!s.exhaustBrokerProviders || !s.currentBrokerSelection.tried[provider])
	}
	var spec *parameters.InproxyBrokerSpec
	var provider string
	var replay *InproxyBrokerDialParameters
	var err error
	if s.exhaustBrokerProviders {
		spec, provider, replay, err = s.selectAtCurrentBroker(counts, load, canReplay, replayEnabled)
	} else {
		spec, provider, replay, err = s.selectAcrossBrokers(counts, load, canReplay)
	}
	if err != nil {
		return nil, errors.Trace(err)
	}
	if replay != nil {
		if s.replayedByProvider == nil {
			s.replayedByProvider = make(map[string]bool)
		}
		s.replayedByProvider[provider] = true
	}
	for i, id := range s.providers {
		if id == provider {
			s.nextProvider = (i + 1) % len(s.providers)
			break
		}
	}
	s.preferBrokerOrder, s.noMatchBroker = false, nil
	return &inproxyBrokerClientSelection{
		brokerSelection:        s.currentBrokerSelection,
		brokerSpec:             spec,
		frontingSpecs:          inproxyBrokerFrontingSpecs(spec, provider),
		replayDialParams:       replay,
		replayEnabled:          replayEnabled,
		commonCompartmentIDs:   s.commonCompartmentIDs,
		personalCompartmentIDs: s.personalCompartmentIDs,
	}, nil
}

// selectAcrossBrokers selects a broker and fronting provider for common
// pairing clients by traversing each provider's broker order independently.
// Replay may jump ahead; otherwise the least occupied provider is selected
// next. It returns the selected broker spec, the provider ID and, when
// eligible, the replay dial parameters loaded for that broker and provider,
// or nil for a fresh dial. It advances the provider's broker cursor before
// returning.
func (s *inproxyBrokerSelector) selectAcrossBrokers(
	counts map[string]int,
	load func(*parameters.InproxyBrokerSpec) *InproxyBrokerDialParameters,
	canReplay func(string) bool) (*parameters.InproxyBrokerSpec, string, *InproxyBrokerDialParameters, error) {

	specs := s.brokers
	s.initializeProviders(specs)
	if len(s.providers) == 0 {
		return nil, "", nil, errors.TraceNew("no broker fronting providers")
	}
	cursor := func(provider string) int {
		if next, ok := s.nextBrokerByProvider[provider]; ok {
			return next
		}
		return s.nextBroker
	}
	provider, index := "", -1
	var replay *InproxyBrokerDialParameters
	if !s.preferBrokerOrder {
		for i := 0; i < len(s.providers) && index < 0; i++ {
			id := s.providers[(s.nextProvider+i)%len(s.providers)]
			if !canReplay(id) {
				continue
			}
			for j := range specs {
				k := (cursor(id) + j) % len(specs)
				if !inproxyBrokerSupportsProvider(specs[k], id) {
					continue
				}
				if params := load(specs[k]); params != nil && params.FrontedHTTPDialParameters.FrontingProviderID == id {
					provider, index, replay = id, k, params
					break
				}
			}
		}
	}
	if index < 0 {
		minCount := 0
		for i := range s.providers {
			id := s.providers[(s.nextProvider+i)%len(s.providers)]
			if i == 0 || counts[id] < minCount {
				provider, minCount = id, counts[id]
			}
		}
		// Take the provider's next broker in order, passing over the
		// broker that just returned NoMatch unless it is the only one
		// that supports the provider.
		fallback := -1
		for i := range specs {
			k := (cursor(provider) + i) % len(specs)
			if !inproxyBrokerSupportsProvider(specs[k], provider) {
				continue
			}
			if specs[k] == s.noMatchBroker {
				if fallback < 0 {
					fallback = k
				}
				continue
			}
			index = k
			break
		}
		if index < 0 {
			index = fallback
		}
		if index < 0 {
			return nil, "", nil, errors.TraceNew("no broker for selected fronting provider")
		}
		if canReplay(provider) {
			if params := load(specs[index]); params != nil && params.FrontedHTTPDialParameters.FrontingProviderID == provider {
				replay = params
			}
		}
	}
	if s.nextBrokerByProvider == nil {
		s.nextBrokerByProvider = make(map[string]int)
	}
	s.nextBroker = (index + 1) % len(specs)
	s.nextBrokerByProvider[provider] = s.nextBroker
	return specs[index], provider, replay, nil
}

// selectAtCurrentBroker selects a broker and fronting provider for personal
// pairing clients and all proxies: the current broker, chosen here if not
// yet chosen, and an untried provider at it. It returns the broker spec, the
// provider ID and, when eligible, the replay dial parameters loaded for that
// broker and provider, or nil for a fresh dial. It marks the provider as
// tried before returning.
func (s *inproxyBrokerSelector) selectAtCurrentBroker(
	counts map[string]int,
	load func(*parameters.InproxyBrokerSpec) *InproxyBrokerDialParameters,
	canReplay func(string) bool,
	replayEnabled bool) (*parameters.InproxyBrokerSpec, string, *InproxyBrokerDialParameters, error) {

	visit := s.currentBrokerSelection
	if visit.spec == nil {
		// Common proxies may start at a broker with replay. Personal
		// pairing must retain its rendezvous order. A visit that follows
		// an exhaustion advance (index > 0, since common proxies start at
		// 0 and never return there) does not scan back to the broker it
		// just left, whose providers all failed; a replay record there
		// would otherwise pull the proxy straight back when that
		// provider was not yet marked in replayedByProvider, because
		// the coin flip chose fresh parameters or another live client
		// occupied it.
		if !s.personal && replayEnabled {
			scan := len(s.brokers)
			if visit.index > 0 && scan > 1 {
				scan--
			}
			for i := 0; i < scan; i++ {
				brokerIndex := (visit.index + i) % len(s.brokers)
				if params := load(s.brokers[brokerIndex]); params != nil && canReplay(params.FrontedHTTPDialParameters.FrontingProviderID) {
					visit.index += i
					break
				}
			}
		}
		visit.spec = s.brokers[visit.index%len(s.brokers)]
	}
	s.initializeProviders(parameters.InproxyBrokerSpecsValue{visit.spec})
	if len(s.providers) == 0 {
		return nil, "", nil, errors.TraceNew("no broker fronting providers")
	}
	providerIndex := -1
	var replay *InproxyBrokerDialParameters
	if !s.preferBrokerOrder {
		for i := range s.providers {
			candidate := (s.nextProvider + i) % len(s.providers)
			id := s.providers[candidate]
			if !canReplay(id) {
				continue
			}
			if params := load(visit.spec); params != nil && params.FrontedHTTPDialParameters.FrontingProviderID == id {
				providerIndex, replay = candidate, params
				break
			}
		}
	}
	if providerIndex < 0 {
		for i := range s.providers {
			candidate := (s.nextProvider + i) % len(s.providers)
			id := s.providers[candidate]
			if visit.tried[id] {
				continue
			}
			if providerIndex < 0 || counts[id] < counts[s.providers[providerIndex]] {
				providerIndex = candidate
			}
		}
		if providerIndex < 0 {
			return nil, "", nil, errors.TraceNew("no untried broker fronting provider")
		}
		id := s.providers[providerIndex]
		if canReplay(id) {
			if params := load(visit.spec); params != nil && params.FrontedHTTPDialParameters.FrontingProviderID == id {
				replay = params
			}
		}
	}
	provider := s.providers[providerIndex]
	if visit.tried == nil {
		visit.tried = make(map[string]bool)
	}
	visit.tried[provider] = true
	return visit.spec, provider, replay, nil
}

// InproxyBrokerClientInstance pairs an inproxy.BrokerClient instance with an
// implementation of the inproxy.BrokerDialCoordinator interface and the
// associated, underlying broker dial parameters. InproxyBrokerClientInstance
// implements broker client dial replay.
type InproxyBrokerClientInstance struct {
	// The fields above mutex are set before the broker client is returned by
	// GetBrokerClient and are read without InproxyBrokerClientInstance.mutex.
	// candidateNumber is assigned by InproxyBrokerClientManager, under its
	// mutex, when it registers the broker client; the rest are set at
	// construction.
	frontingProviderID string
	// brokerClientID is a random identifier for diagnostics.
	brokerClientID string
	// candidateNumber is the creation ordinal within the
	// InproxyBrokerClientManager counting window; see
	// InproxyBrokerDialParameters.candidateNumber.
	candidateNumber               int
	brokerSelection               *inproxyBrokerSelectionState
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
	answerRequestTimeout          time.Duration
	offerRequestTimeout           time.Duration
	offerRequestPersonalTimeout   time.Duration
	offerRetryDelay               time.Duration
	offerRetryJitter              float64
	relayedPacketRequestTimeout   time.Duration
	dslRequestTimeout             time.Duration
	replayRetainFailedProbability float64
	replayUpdateFrequency         time.Duration
	retryOnFailedPeriod           time.Duration

	mutex           sync.Mutex
	lastStoreReplay time.Time
	lastSuccess     time.Time
	failed          bool
	loggedRetry     bool
}

// inproxyBrokerClientSelection contains the broker and dial parameters for a
// broker client.
type inproxyBrokerClientSelection struct {
	brokerSelection *inproxyBrokerSelectionState

	// brokerSpec retains all providers for replay hash validation.
	brokerSpec *parameters.InproxyBrokerSpec
	// frontingSpecs contains only the selected provider's specs.
	frontingSpecs parameters.FrontingSpecs

	// replayDialParams is the validated replay record selected for this
	// broker and provider, or nil when fresh dial parameters are generated.
	replayDialParams *InproxyBrokerDialParameters

	// replayEnabled reports whether replay is in effect for the broker
	// client's lifetime: its first success stores dial parameters as the
	// broker's replay record and a transport failure may delete it. It is
	// false when InproxyReplayBrokerDialParametersTTL is zero, when
	// Config.DisableReplay is set, or when the per-selection coin flip
	// against InproxyReplayBrokerDialParametersProbability fails; such a
	// broker client neither reads nor changes the record. It is
	// independent of whether this dial is itself a replay: a fresh dial
	// with replay enabled is what creates the record.
	replayEnabled bool

	commonCompartmentIDs   []inproxy.ID
	personalCompartmentIDs []inproxy.ID
}

// newInproxyBrokerClientInstance creates a client for the selected broker and
// fronting provider. It generates fresh dial parameters or prepares the
// selected replay parameters in place for use by the new instance. No network
// operations occur until the client's first request.
func newInproxyBrokerClientInstance(
	config *Config,
	p parameters.ParametersAccessor,
	brokerClientManager *InproxyBrokerClientManager,
	networkID string,
	isProxy bool,
	selection *inproxyBrokerClientSelection) (*InproxyBrokerClientInstance, error) {

	brokerSpec := selection.brokerSpec
	brokerDialParams := selection.replayDialParams
	var err error

	// Generate new broker dial parameters if not replaying. isReplay also
	// determines the replay metric when preparing the dial configurations.
	// The selector has already validated any replay parameters.

	isReplay := brokerDialParams != nil

	if !isReplay {
		brokerDialParams, err = MakeInproxyBrokerDialParameters(
			config, p, brokerSpec, selection.frontingSpecs, brokerClientManager.tlsCache)
	} else {
		err = brokerDialParams.prepareDialConfigs(config, p, isReplay, brokerClientManager.tlsCache)
	}
	if err != nil {
		return nil, errors.Trace(err)
	}

	brokerClientPrivateKey, err := brokerClientManager.brokerClientPrivateKey()
	if err != nil {
		return nil, errors.Trace(err)
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

	// The ID is set on brokerDialParams before the round tripper is created
	// so that round trip failure notices can report it.
	brokerDialParams.brokerClientID = prng.HexString(4)

	// The broker ID is the broker's session public key in Curve25519 form.
	brokerID, err := brokerPublicKey.ToCurve25519()
	if err != nil {
		return nil, errors.Trace(err)
	}

	roundTripper := NewInproxyBrokerRoundTripper(p, brokerDialParams)

	// With transport sharing, the broker client becomes shared as soon as its
	// TLS transport is established, before the first broker response. Other
	// callers then reuse the MeekConn, and
	// InproxyClientDisableWaitToShareSession or
	// InproxyProxyDisableWaitToShareSession governs whether they wait for the
	// first Noise handshake or run their own. By default, the
	// broker client is shared only after a decoded response; see
	// InproxyBrokerClientManager.sharedClient. The choice is made once per
	// broker client, here, so that a given client is consistently shared at
	// one point or the other.
	shareOnTransportProbability := parameters.InproxyClientShareBrokerClientTransportProbability
	if isProxy {
		shareOnTransportProbability = parameters.InproxyProxyShareBrokerClientTransportProbability
	}
	shareOnTransport := p.WeightedCoinFlip(shareOnTransportProbability)

	// InproxyBrokerClientInstance implements the
	// inproxy.BrokerDialCoordinator interface and passes itself to
	// inproxy.NewBrokerClient in order to provide the round tripper, key
	// material, compartment IDs, timeouts, and other configuration to the
	// in-proxy broker client.
	//
	// Timeouts are not replayed, but snapshots are stored in the
	// InproxyBrokerClientInstance for efficient lookup.

	b := &InproxyBrokerClientInstance{
		brokerSelection:             selection.brokerSelection,
		frontingProviderID:          brokerDialParams.FrontedHTTPDialParameters.FrontingProviderID,
		brokerClientID:              brokerDialParams.brokerClientID,
		config:                      config,
		brokerClientManager:         brokerClientManager,
		networkID:                   networkID,
		brokerClientPrivateKey:      brokerClientPrivateKey,
		brokerPublicKey:             brokerPublicKey,
		brokerRootObfuscationSecret: brokerRootObfuscationSecret,
		brokerDialParams:            brokerDialParams,
		replayEnabled:               selection.replayEnabled,
		roundTripper:                roundTripper,
		personalCompartmentIDs:      selection.personalCompartmentIDs,
		commonCompartmentIDs:        selection.commonCompartmentIDs,

		sessionHandshakeTimeout:       p.Duration(parameters.InproxySessionHandshakeRoundTripTimeout),
		announceRequestTimeout:        p.Duration(parameters.InproxyProxyAnnounceRequestTimeout),
		answerRequestTimeout:          p.Duration(parameters.InproxyProxyAnswerRequestTimeout),
		offerRequestTimeout:           p.Duration(parameters.InproxyClientOfferRequestTimeout),
		offerRequestPersonalTimeout:   p.Duration(parameters.InproxyClientOfferRequestPersonalTimeout),
		offerRetryDelay:               p.Duration(parameters.InproxyClientOfferRetryDelay),
		offerRetryJitter:              p.Float(parameters.InproxyClientOfferRetryJitter),
		relayedPacketRequestTimeout:   p.Duration(parameters.InproxyClientRelayedPacketRequestTimeout),
		dslRequestTimeout:             p.Duration(parameters.InproxyClientDSLRequestTimeout),
		replayRetainFailedProbability: p.Float(parameters.InproxyReplayBrokerRetainFailedProbability),
		replayUpdateFrequency:         p.Duration(parameters.InproxyReplayBrokerUpdateFrequency),
	}

	if isProxy && !config.IsInproxyProxyPersonalPairingMode() {
		// This retry is applied only for proxies and only in common pairing
		// mode. See comment in BrokerClientRoundTripperFailed.
		b.retryOnFailedPeriod = p.Duration(parameters.InproxyProxyOnBrokerClientFailedRetryPeriod)
	}

	// Limitation: currently, disableWaitToShareSession is neither replayed
	// nor is the selected value reported in metrics. The tactics flag can be
	// used to enable wait for clients in case load on brokers -- due to
	// simultaneous sessions -- is unexpectedly high.
	//
	// Broker dial replay validation checks for changes to broker specs, not
	// tactics in general. Changes to disableWaitToShareSession do not
	// invalidate stored replay dial parameters.

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
	// A transport-level failure -- TLS or domain fronting -- stops sharing
	// the broker client, and the next acquisition constructs a new
	// InproxyBrokerClientInstance, which resets both the round tripper and
	// the broker session. As a future enhancement, consider distinguishing
	// transport errors from session errors and retaining a valid
	// established session when only the transport needs to be replaced.

	b.brokerClient, err = inproxy.NewBrokerClient(b)
	if err != nil {
		_ = roundTripper.Close()
		return nil, errors.Trace(err)
	}

	if shareOnTransport {
		roundTripper.transportEstablished = func() {
			brokerClientManager.clientTransportEstablished(b)
		}
	}

	// Include the client ID, fronting provider and replay state, as
	// concurrent broker clients may select the same broker via different
	// providers; the client ID also appears in close notices and in
	// ConnectedServer as inproxy_broker_client_id. The first client at a
	// new broker selection also reports why selection moved there.
	reason := ""
	if selection.brokerSelection != nil && selection.brokerSelection.reason != "" {
		reason = ": " + selection.brokerSelection.reason
		selection.brokerSelection.reason = ""
	}
	NoticeInfo(
		"inproxy: broker client %s selected broker %s fronting provider %s replay %t%s",
		b.brokerClientID, inproxy.ID(brokerID), b.frontingProviderID, brokerDialParams.isReplay, reason)

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

	// Concurrency note: InproxyBrokerClientManager calls Close with its
	// mutex locked. Close must not lock InproxyBrokerClientInstance's
	// mutex since failure callbacks hold InproxyBrokerClientInstance.mutex
	// while calling InproxyBrokerClientManager. Reversing that lock order
	// could deadlock.

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
func (b *InproxyBrokerClientInstance) BrokerClientID() string {
	return b.brokerClientID
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
	b.loggedRetry = false

	// Set replay or extend the broker dial parameters replay TTL after a
	// success. With tunnel dial parameters, the replay TTL is extended after
	// every successful tunnel connection. Since there are potentially more
	// and more frequent broker round trips compared to tunnel dials, the TTL
	// is only extended after some target duration has elapsed, to avoid
	// excessive datastore writes.
	//
	// That duration is replayUpdateFrequency, measured from lastStoreReplay,
	// which each broker client tracks separately. A newly constructed broker
	// client therefore writes on its first success, persisting a proven
	// configuration; with several broker clients racing, that is at most one
	// write per broker client, after which each is limited by its own
	// lastStoreReplay. The replay record is per broker, not per fronting
	// provider, so any broker client's success may replace it; see
	// InproxyBrokerDialParameters.

	if b.replayEnabled && now.Sub(b.lastStoreReplay) > b.replayUpdateFrequency {
		b.brokerDialParams.LastUsedTimestamp = now

		err := storeInproxyBrokerReplayParameters(b.networkID, b.brokerDialParams)
		if err != nil {
			NoticeWarning("StoreBrokerDialParameters failed: %v", errors.Trace(err))
			// Continue without persisting replay changes.
		} else {
			b.lastStoreReplay = now
			NoticeInfo(
				"inproxy: broker client %s stored replay for provider %s",
				b.brokerClientID, b.frontingProviderID)
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
func (b *InproxyBrokerClientInstance) BrokerClientRoundTripperFailed(
	roundTripper inproxy.RoundTripper, err error) {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	if rt, ok := roundTripper.(*InproxyBrokerRoundTripper); !ok || rt != b.roundTripper {
		// Passing in the round tripper obtained from BrokerClientRoundTripper
		// is just used for sanity check in this implementation, since each
		// InproxyBrokerClientInstance has exactly one round tripper.
		NoticeError("BrokerClientRoundTripperFailed: roundTripper instance mismatch")
		return
	}

	// An already failed broker client is draining; later failures on it,
	// including from requests that outlive a retry window, change nothing
	// and are not logged.
	if b.failed {
		return
	}

	// For common pairing proxies, skip both the replay deletion and demotion
	// of a shared client for a short duration after a recent round trip
	// success. In this case, subsequent broker requests will use the existing
	// round tripper, wired up with the same dial parameters and fronting
	// provider selection. If the failure was due to a transient TLS/TCP network
	// failure, the net/http round tripper should establish a new connection on
	// the next request.
	//
	// This retry is intended to retain proxy affinity with its currently
	// selected broker in cases such as broker service upgrades/restarts or
	// brief network interruptions, mitigating load balancing issues that
	// otherwise occur (e.g., all proxies fail over to other brokers, leaving
	// no supply on a restarted broker).
	//
	// In common pairing mode, clients do not perform this retry and
	// immediately stop sharing the failed broker client, as is appropriate
	// for the tunnel establishment race. In personal pairing mode, neither
	// proxies nor clients retry and instead follow the personal pairing
	// broker selection scheme in an effort to rendezvous at the same broker
	// with minimal delay.
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

		if !b.loggedRetry {
			b.loggedRetry = true
			NoticeWarning(
				"inproxy: broker client %s round trip failed (%v), retrying within %s of last success",
				b.brokerClientID, err, b.retryOnFailedPeriod)
		}
		return
	}

	// Concurrent requests on a failed shared transport each report the
	// failure. Decide replay retention, evict the TLS session and notify the
	// broker client manager once per failure event.
	b.failed = true

	// Delete stored replay dial parameters unless selected for retention.

	if b.replayEnabled {
		if prng.FlipWeightedCoin(b.replayRetainFailedProbability) {
			NoticeInfo(
				"inproxy: broker client %s retained replay for provider %s",
				b.brokerClientID, b.frontingProviderID)
		} else {
			// Delete only the record this broker client loaded or
			// stored; another may have stored different parameters
			// under the same key.
			deleted, err := deleteInproxyBrokerReplayParameters(b.networkID, b.brokerDialParams)
			if err != nil {
				NoticeWarning("DeleteBrokerDialParameters failed: %v", errors.Trace(err))
				// Continue without resetting replay.
			} else {
				NoticeInfo(
					"inproxy: broker client %s deleted replay for provider %s: %t",
					b.brokerClientID, b.frontingProviderID, deleted)
			}
		}
	}

	// Remove the TLS session cache entry for the broker's fronting dial address, if present.
	// This ensures that the next round trip establishes a new TLS session, avoiding potential issues
	// caused by session resumption fingerprint that may have contributed to the round tripper failure.
	if hardcodedCache := b.brokerDialParams.FrontedHTTPDialParameters.meekConfig.TLSClientSessionCache; hardcodedCache != nil {
		hardcodedCache.RemoveCacheEntry()
	}

	// Mark this broker client as failed so it cannot be shared again. Existing
	// callers retain the same broker, dial parameters and round tripper until
	// they release it; see brokerClientFailed. brokerClientManager records
	// its own failed flag, which stops a later decoded response from
	// re-sharing the client.
	//
	// Limitation: a transport-level failure may unnecessarily reset the
	// broker session state; see comment in newInproxyBrokerClientInstance.

	b.brokerClientManager.brokerClientFailed(b, err)
}

// Implements the inproxy.BrokerDialCoordinator interface.
func (b *InproxyBrokerClientInstance) BrokerClientResponseReceived(
	roundTripper inproxy.RoundTripper, retryableNoMatch bool) {
	// roundTripper does not change after construction, so this check does not
	// require InproxyBrokerClientInstance.mutex.
	if rt, ok := roundTripper.(*InproxyBrokerRoundTripper); !ok || rt != b.roundTripper {
		// See roundTripper check comment in BrokerClientRoundTripperFailed.
		NoticeError("BrokerClientResponseReceived: roundTripper instance mismatch")
		return
	}

	// Any persistent replay dial parameters are retained and not deleted,
	// since the broker client successfully transacted with the broker.

	b.brokerClientManager.clientResponseReceived(b, retryableNoMatch)
}

// Implements the inproxy.BrokerDialCoordinator interface.
func (b *InproxyBrokerClientInstance) MetricsForBrokerRequests() common.LogFields {
	// b.candidateNumber is assigned at registration and immutable after,
	// so no lock is required; b.brokerDialParams is never replaced.
	return b.brokerDialParams.GetMetricsForBrokerRequests(b.candidateNumber)
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

// Implements the inproxy.BrokerDialCoordinator interface.
func (b *InproxyBrokerClientInstance) DSLRequestTimeout() time.Duration {
	return b.dslRequestTimeout
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
//
// The replay record is keyed by network ID and broker public key: one
// record per broker, holding the last successful fronting provider and dial
// parameters. The client and proxy broker client managers share it but
// validate it against their own broker spec, so when their specs for a
// broker differ, each lookup discards the other's record and the next
// success replaces it. Concurrent broker clients for the same broker may
// also overwrite each other. Overwrites are accepted: a record is written
// only after a successful round trip, so whichever record remains holds
// parameters that worked. A failure deletes the record only if it is still
// the one this broker client loaded or stored; see replayRecordHash.
type InproxyBrokerDialParameters struct {
	brokerSpec *parameters.InproxyBrokerSpec `json:"-"`
	isReplay   bool                          `json:"-"`
	isReuse    bool                          `json:"-"`
	// brokerClientID identifies the InproxyBrokerClientInstance that
	// supplied this copy; see GetBrokerClient. Only used for diagnostics.
	brokerClientID string `json:"-"`
	// candidateNumber and acquireDuration are set on the copy returned by
	// GetBrokerClient and reported as metrics; see GetMetrics.
	// candidateNumber is the creation ordinal of the broker client within
	// its InproxyBrokerClientManager's count, which restarts at each
	// takeBrokerClientCounts call. A shared client reused after a restart
	// keeps the ordinal it was created with. acquireDuration is the time
	// the caller waited in GetBrokerClient.
	candidateNumber int           `json:"-"`
	acquireDuration time.Duration `json:"-"`
	// replayRecordHash is the SHA-256 of the stored record bytes this
	// broker client loaded or stored, used to check for changes before
	// deleting replay parameters.
	replayRecordHash []byte

	LastUsedTimestamp      time.Time
	LastUsedBrokerSpecHash []byte

	FrontedHTTPDialParameters *FrontedMeekDialParameters
}

// loadInproxyBrokerReplayParameters loads valid replay dial parameters or
// deletes an invalid record. The hash is checked against the full broker
// spec, including all fronting providers.
//
// Absent and valid records are read in a read-only transaction, which avoids
// a writable commit for the common cases. Only an invalid record enters a
// writable transaction, which re-reads and revalidates the current bytes so
// that a valid record stored concurrently by another broker client between
// the two transactions is returned rather than deleted.
func loadInproxyBrokerReplayParameters(
	networkID string, brokerSpec *parameters.InproxyBrokerSpec,
	ttl time.Duration) (*InproxyBrokerDialParameters, error) {

	hash, err := brokerSpec.Hash()
	if err != nil {
		return nil, errors.Trace(err)
	}
	key := makeNetworkReplayParametersKey[InproxyBrokerDialParameters](networkID, brokerSpec.BrokerPublicKey)

	// decode returns the record when value holds valid replay parameters for
	// brokerSpec, or nil when value is absent or invalid. The returned record
	// copies value, as bucket values live only for their transaction.
	decode := func(value []byte) *InproxyBrokerDialParameters {
		if value == nil {
			return nil
		}
		var params *InproxyBrokerDialParameters
		if err := json.Unmarshal(value, &params); err != nil || params == nil ||
			params.FrontedHTTPDialParameters == nil ||
			!params.LastUsedTimestamp.After(time.Now().Add(-ttl)) ||
			!bytes.Equal(params.LastUsedBrokerSpecHash, hash) ||
			!inproxyBrokerSupportsProvider(brokerSpec, params.FrontedHTTPDialParameters.FrontingProviderID) {
			return nil
		}
		// Hash the original bytes rather than the decoded record:
		// re-marshalling could drop unknown fields and no longer match the
		// stored record during deletion.
		params.replayRecordHash = hashInproxyBrokerReplayRecord(value)
		params.brokerSpec = brokerSpec
		return params
	}

	var params *InproxyBrokerDialParameters
	invalid := false
	err = datastoreView(func(tx *datastoreTx) error {
		value := tx.bucket(datastoreNetworkReplayParametersBucket).get(key)
		params = decode(value)
		invalid = value != nil && params == nil
		return nil
	})
	if err != nil {
		return nil, errors.Trace(err)
	}
	if !invalid {
		return params, nil
	}

	err = datastoreUpdate(func(tx *datastoreTx) error {
		bucket := tx.bucket(datastoreNetworkReplayParametersBucket)
		value := bucket.get(key)
		params = decode(value)
		if value != nil && params == nil {
			return errors.Trace(bucket.delete(key))
		}
		return nil
	})
	if err != nil {
		return nil, errors.Trace(err)
	}
	return params, nil
}

// hashInproxyBrokerReplayRecord returns the hash retained in
// InproxyBrokerDialParameters.replayRecordHash for stored record bytes.
func hashInproxyBrokerReplayRecord(value []byte) []byte {
	sum := sha256.Sum256(value)
	return sum[:]
}

// storeInproxyBrokerReplayParameters stores successful broker dial parameters
// and saves a hash of the stored bytes for comparison before deletion on
// failure.
//
// Unlike SetNetworkReplayParameters, this function retains the record hash.
// It updates replayRecordHash only after a successful write. When params
// belongs to an InproxyBrokerClientInstance, the caller must hold its mutex.
func storeInproxyBrokerReplayParameters(networkID string, params *InproxyBrokerDialParameters) error {
	value, err := json.Marshal(params)
	if err != nil {
		return errors.Trace(err)
	}
	key := makeNetworkReplayParametersKey[InproxyBrokerDialParameters](networkID, params.brokerSpec.BrokerPublicKey)
	if err := setBucketValue(datastoreNetworkReplayParametersBucket, key, value); err != nil {
		return errors.Trace(err)
	}
	params.replayRecordHash = hashInproxyBrokerReplayRecord(value)
	return nil
}

// deleteInproxyBrokerReplayParameters deletes the record only if its bytes
// hash to the value previously loaded or stored. The comparison and deletion
// use one transaction to preserve changes made by another client. The caller
// must hold InproxyBrokerClientInstance.mutex when params belongs to a broker
// client instance.
func deleteInproxyBrokerReplayParameters(networkID string, params *InproxyBrokerDialParameters) (deleted bool, err error) {
	if len(params.replayRecordHash) == 0 {
		// This broker client has neither loaded nor stored replay dial
		// parameters.
		return false, nil
	}
	key := makeNetworkReplayParametersKey[InproxyBrokerDialParameters](networkID, params.brokerSpec.BrokerPublicKey)
	err = datastoreUpdate(func(tx *datastoreTx) error {
		bucket := tx.bucket(datastoreNetworkReplayParametersBucket)
		value := bucket.get(key)
		if value == nil ||
			!bytes.Equal(hashInproxyBrokerReplayRecord(value), params.replayRecordHash) {
			return nil
		}
		deleted = true
		return errors.Trace(bucket.delete(key))
	})
	if err != nil {
		return false, errors.Trace(err)
	}
	params.replayRecordHash = nil
	return deleted, nil
}

// MakeInproxyBrokerDialParameters creates a new InproxyBrokerDialParameters.
func MakeInproxyBrokerDialParameters(
	config *Config,
	p parameters.ParametersAccessor,
	brokerSpec *parameters.InproxyBrokerSpec,
	frontingSpecs parameters.FrontingSpecs,
	tlsCache utls.ClientSessionCache) (*InproxyBrokerDialParameters, error) {

	currentTimestamp := time.Now()

	// Select new broker dial parameters

	brokerSpecHash, err := brokerSpec.Hash()
	if err != nil {
		return nil, errors.Trace(err)
	}

	brokerDialParams := &InproxyBrokerDialParameters{
		brokerSpec:             brokerSpec,
		LastUsedTimestamp:      currentTimestamp,
		LastUsedBrokerSpecHash: brokerSpecHash,
	}

	// FrontedMeekDialParameters
	//
	// The broker round trips use MeekModeWrappedPlaintextRoundTrip without
	// meek cookies, so meek obfuscation is not configured. The in-proxy
	// broker session payloads have their own obfuscation layer.
	//
	// makeFrontedMeekDialParameters may wire up upstream proxy support, which
	// is compatible with the current broker transports. While in-proxy
	// tunnel protocols are incompatible with UpstreamProxyURL, other broker
	// use cases, such as relayed DSL requests, will still work.

	payloadSecure := true
	skipVerify := false

	brokerDialParams.FrontedHTTPDialParameters, err = makeFrontedMeekDialParameters(
		config,
		p,
		nil,
		frontingSpecs,
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

// GetMetricsForBrokerRequests returns broker client dial parameter log
// fields to be reported to a broker. candidateNumber is the broker client's
// creation ordinal, held by InproxyBrokerClientInstance rather than by the
// dial parameters it was constructed with.
func (brokerDialParams *InproxyBrokerDialParameters) GetMetricsForBrokerRequests(
	candidateNumber int) common.LogFields {

	logFields := common.LogFields{}

	// TODO: add additional broker fronting dial parameters to be logged by
	// the broker -- as successful parameters might not otherwise by logged
	// via server_tunnel if the subsequent WebRTC dials fail.

	logFields["fronting_provider_id"] = brokerDialParams.FrontedHTTPDialParameters.FrontingProviderID

	// The broker sees every candidate's requests, including candidates
	// whose tunnels never reach a server, so it also receives the replay
	// flag and candidate ordinal otherwise reported only in the winning
	// tunnel's handshake; see GetMetrics.
	isReplay := "0"
	if brokerDialParams.isReplay {
		isReplay = "1"
	}
	logFields["inproxy_broker_is_replay"] = isReplay
	logFields["inproxy_broker_candidate_number"] = strconv.Itoa(candidateNumber)

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

	// Broker client selection diagnostics. Handshake metrics reach the
	// server only for the winning tunnel; these fields identify which
	// of the concurrent broker clients it won on and what acquiring it
	// cost. candidate_number is an ordinal, not bounded by
	// InproxyClientMaxBrokerClients or InproxyProxyMaxBrokerClients, since
	// broker clients close and new ones are created within an establishment;
	// see InproxyBrokerDialParameters for when the count restarts.
	logFields["inproxy_broker_candidate_number"] = strconv.Itoa(brokerDialParams.candidateNumber)
	logFields["inproxy_broker_acquire_wait_ms"] = strconv.FormatInt(
		brokerDialParams.acquireDuration.Milliseconds(), 10)

	// TODO: include tlsConn.GetMetrics tls_did_resume/tls_sent_ticket.
	// Requires a reference to the InproxyBrokerRoundTripper.

	return logFields
}

// inproxyBrokerClientClosedError wraps a broker request error caused by
// InproxyBrokerRoundTripper.Close while the caller's context was still
// live: the broker client was closed under the request by NoMatch
// failover, a tactics or network reset, or shutdown. Like
// inproxyBrokerAcquireFailedError, it is excluded from server entry
// failure attribution by isServerEntryFailure.
type inproxyBrokerClientClosedError struct {
	err error
}

func (e inproxyBrokerClientClosedError) Error() string {
	return e.err.Error()
}

func (e inproxyBrokerClientClosedError) Unwrap() error {
	return e.err
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

	// transportEstablished, when set, is invoked once after the initial
	// DialMeek succeeds, before any request is sent.
	transportEstablished func()
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

	callerCtx := ctx
	defer func() {
		// A request failing because Close cancelled rt.runCtx while
		// the caller's own context was live, for example a sibling
		// offer interrupted by NoMatch failover, reset or shutdown, is
		// marked so dialTunnel does not attribute the dial to the
		// server entry; see isServerEntryFailure. callerCtx is checked,
		// not the merged ctx below, which Close also cancels.
		if retErr != nil && rt.runCtx.Err() != nil && callerCtx.Err() == nil {
			retErr = &inproxyBrokerClientClosedError{err: retErr}
		}
	}()

	// Cancel DialMeek or MeekConn.RoundTrip when:
	// - Close is called
	// - the input context is done
	ctx, cancelFunc := common.MergeContextCancel(ctx, rt.runCtx)
	defer cancelFunc()

	// isTransportFailure reports whether an error should be classified as
	// a RoundTripperFailedError. An error is a transport failure unless
	// the caller cancelled the request or Close was called.
	//
	// A caller deadline does count as a transport failure. The caller's
	// deadline may expire before the request's own timeout, in which case
	// it is the only thing that ends a request hung on a shared client.
	// If it were not a failure, the client would stay shared, every later
	// acquisition would reuse it before broker selection ran, and the
	// client would never try another provider or broker; treating it as
	// a failure is what unshares the client and lets selection move on.
	//
	// Close cancels rt.runCtx synchronously and then closes the MeekConn,
	// but the merged ctx is cancelled from rt.runCtx asynchronously, so a
	// request failing on the closed connection may observe ctx.Err() ==
	// nil; check rt.runCtx directly as well.
	isTransportFailure := func() bool {
		ctxErr := ctx.Err()
		return (ctxErr == nil || ctxErr == context.DeadlineExceeded) &&
			rt.runCtx.Err() == nil
	}

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
	// DialMeek is attempted once for this round tripper. Transport failures
	// invoke BrokerClientRoundTripperFailed; subsequent attempts obtain a
	// client from InproxyBrokerClientManager. Caller cancellation does not
	// invalidate replay.
	//
	// If the caller cancels or reaches its deadline during the initial dial,
	// the error remains cached and this round tripper cannot be used again.
	// InproxyBrokerClientManager does not share a client before its dial
	// succeeds: by default it waits for a decoded broker response, and with
	// transport sharing it waits for this dial to complete. So a client
	// with a cached dial error has a single caller, whose release closes it.

	if atomic.CompareAndSwapInt32(&rt.dial, 0, 1) {

		// DialMeek hasn't been called yet.

		conn, err := DialMeek(
			requestCtx,
			rt.brokerDialParams.FrontedHTTPDialParameters.meekConfig,
			rt.brokerDialParams.FrontedHTTPDialParameters.dialConfig)

		if err != nil && isTransportFailure() {

			// DialMeek performs an initial TLS handshake. DialMeek errors,
			// excluding caller cancellation, are classified as
			// RoundTripperFailedErrors. These invoke
			// BrokerClientRoundTripperFailed to handle sharing and replay.

			err = inproxy.NewRoundTripperFailedError(errors.Trace(err))
		}

		rt.conn = conn
		rt.dialErr = err
		close(rt.dialCompleted)

		if err != nil {
			return nil, errors.Trace(rt.dialErr)
		}

		if rt.transportEstablished != nil {
			rt.transportEstablished()
		}

	} else {

		// Await any ongoing DialMeek run by a concurrent RoundTrip caller.

		select {
		case <-rt.dialCompleted:
		case <-ctx.Done():
			return nil, errors.Trace(ctx.Err())
		}

		if rt.dialErr != nil {

			// Return the error as classified by the DialMeek caller, including
			// caller cancellation errors that do not invalidate replay.

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
			// which may delete replay dial parameters and stop sharing this
			// broker client, depending on the failure-retention policy.
			//
			// When the round trip duration is sufficiently short, much
			// shorter than expected round trip timeouts, this is still
			// classified as a RoundTripperFailedError error, as it is more
			// likely due to a more serious issue between the CDN and broker.

			if isTransportFailure() && rt.failureThreshold > 0 &&
				roundTripDuration <= rt.failureThreshold {

				err = inproxy.NewRoundTripperFailedError(errors.Trace(err))
			}
		}
	} else if isTransportFailure() {

		// Request timeouts and other transport errors count as
		// failures unless the caller cancelled or the round tripper
		// was closed; see isTransportFailure.

		err = inproxy.NewRoundTripperFailedError(errors.Trace(err))
	}
	if err != nil {
		return nil, errors.Trace(err)
	}

	responsePayload, err := io.ReadAll(response.Body)
	if err != nil {
		if isTransportFailure() {
			err = inproxy.NewRoundTripperFailedError(errors.Trace(err))
		}
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
	disableSTUNCandidateGathering   bool
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
		// Auto-generate WebRTC dial parameters. There's no replay in this
		// case. The proxy DTLS fingerprint is selected later, after the
		// client root obfuscation secret is received from the broker.
		var err error
		webRTCDialParameters, err = MakeInproxyWebRTCDialParameters(p, true)
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	disableSTUN := p.Bool(parameters.InproxyDisableSTUN)
	disableSTUNCandidateGathering := p.Bool(parameters.InproxyDisableSTUNCandidateGathering)
	disablePortMapping := p.Bool(parameters.InproxyDisablePortMapping)
	disableInboundForMobileNetworks := p.Bool(parameters.InproxyDisableInboundForMobileNetworks)
	disableIPv6ICECandidates := p.Bool(parameters.InproxyDisableIPv6ICECandidates)

	var discoverNATTimeout, awaitReadyToProxyTimeout time.Duration

	if isProxy {

		disableSTUN = disableSTUN || p.Bool(parameters.InproxyProxyDisableSTUN)

		disableSTUNCandidateGathering = disableSTUNCandidateGathering ||
			p.Bool(parameters.InproxyProxyDisableSTUNCandidateGathering)

		disablePortMapping = disablePortMapping || p.Bool(parameters.InproxyProxyDisablePortMapping)

		disableInboundForMobileNetworks = disableInboundForMobileNetworks ||
			p.Bool(parameters.InproxyProxyDisableInboundForMobileNetworks)

		disableIPv6ICECandidates = disableIPv6ICECandidates ||
			p.Bool(parameters.InproxyProxyDisableIPv6ICECandidates)

		discoverNATTimeout = p.Duration(parameters.InproxyProxyDiscoverNATTimeout)

		awaitReadyToProxyTimeout = p.Duration(parameters.InproxyProxyWebRTCAwaitReadyToProxyTimeout)

	} else {

		disableSTUN = disableSTUN || p.Bool(parameters.InproxyClientDisableSTUN)

		disableSTUNCandidateGathering = disableSTUNCandidateGathering ||
			p.Bool(parameters.InproxyClientDisableSTUNCandidateGathering)

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
		disableSTUNCandidateGathering:   disableSTUNCandidateGathering,
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
func (w *InproxyWebRTCDialInstance) ClientDTLSFingerprint() string {
	return w.webRTCDialParameters.DTLSFingerprint
}

// Implements the inproxy.WebRTCDialCoordinator interface.
func (w *InproxyWebRTCDialInstance) ProxyDTLSFingerprint(
	clientRootObfuscationSecret inproxy.ObfuscationSecret) (string, error) {

	p := w.config.GetParameters().Get()
	defer p.Close()

	isOffer := false
	dtlsFingerprint, err := selectDTLSFingerprint(
		p, clientRootObfuscationSecret, isOffer)
	if err != nil {
		return "", errors.Trace(err)
	}
	return dtlsFingerprint, nil
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
	// success. Use the split resolver, since STUN address resolution goes
	// via the same in ResolveAddress (and thus its cache holds the entry).

	resolver := w.config.GetSplitResolver()
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
func (w *InproxyWebRTCDialInstance) DisableSTUNCandidateGathering() bool {
	return w.disableSTUNCandidateGathering
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

	// Use the split resolver for STUN server resolves so that, in
	// split-interface mode, the lookup goes via the downstream (ICE)
	// interface; the upstream 2nd-hop dial uses the main resolver.
	//
	// Limitation: this assumes the only ICE-side resolves routed through
	// ResolveAddress are the STUN server addresses. Any future ICE-side
	// resolve (e.g. a TURN server) would silently route through the
	// upstream resolver instead.
	var r *resolver.Resolver
	if isSTUNServerAddress || isSTUNServerAddressRFC5780 {
		r = w.config.GetSplitResolver()
	} else {
		r = w.config.GetResolver()
	}
	if r == nil {
		return "", errors.TraceNew("missing resolver")
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

	// Create a new inproxyUDPConn for use as the in-proxy STUN and/or WebRTC
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

	// In a split-interface in-proxy proxy configuration, the probe socket
	// must be bound to the downstream (non-upstream) interface so that the
	// active local address discovered here is the one used for ICE.
	dialConfig := &DialConfig{
		DeviceBinder:    w.config.splitDeviceBinder(),
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

	// Use Config.splitDeviceBinder, with wired up logging, not the public
	// config.DeviceBinder; other tunnel-core dials do this indirectly via
	// psiphon.DialConfig.
	//
	// In a split-interface in-proxy proxy configuration, WebRTC port
	// mapping and other auxiliary sockets bind to the downstream
	// (non-upstream) interface; splitDeviceBinder carries that.
	deviceBinder := w.config.splitDeviceBinder()
	if deviceBinder == nil {
		return nil
	}

	_, err := deviceBinder.BindToDevice(fileDescriptor)
	return errors.Trace(err)
}

// Implements the inproxy.WebRTCDialCoordinator interface.
func (w *InproxyWebRTCDialInstance) BindToDeviceInterfaceName() string {

	// In a split-interface in-proxy proxy, BindToDevice (via
	// splitDeviceBinder) binds port mapping sockets to the downstream
	// (non-upstream) interface; return that interface's name so port mapping
	// gateway discovery targets the downstream gateway rather than the system
	// default route. Returns "" outside split-interface mode, selecting
	// default-route gateway discovery.
	return w.config.splitInterfaceDownstreamInterfaceName()
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

	deviceBinder := w.config.deviceBinder()

	dialer := net.Dialer{
		Control: func(_, _ string, c syscall.RawConn) error {
			var controlErr error
			err := c.Control(func(fd uintptr) {

				socketFD := int(fd)

				setAdditionalSocketOptions(socketFD)

				if deviceBinder != nil {
					_, err := deviceBinder.BindToDevice(socketFD)
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
			p.Strings(
				parameters.InproxyClientSTUNServerAddresses,
				parameters.InproxySTUNServerAddresses),
			dialParams.STUNServerAddress)) &&

		(dialParams.STUNServerAddressRFC5780 == "" ||
			common.Contains(
				p.Strings(
					parameters.InproxyClientSTUNServerAddressesRFC5780,
					parameters.InproxySTUNServerAddressesRFC5780),
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
	DTLSFingerprint          string
}

// MakeInproxyWebRTCDialParameters generates new InproxyWebRTCDialParameters.
func MakeInproxyWebRTCDialParameters(
	p parameters.ParametersAccessor,
	isProxy bool) (*InproxyWebRTCDialParameters, error) {

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

	// Clients select a DTLS fingerprint now. Proxies select later, once they
	// receive the ClientRootObfuscationSecret.

	var dtlsFingerprint string
	if !isProxy {
		isOffer := true
		dtlsFingerprint, err = selectDTLSFingerprint(
			p, rootObfuscationSecret, isOffer)
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	return &InproxyWebRTCDialParameters{
		RootObfuscationSecret:    rootObfuscationSecret,
		UseMediaStreams:          useMediaStreams,
		TrafficShapingParameters: trafficSharingParams,
		DTLSFingerprint:          dtlsFingerprint,
	}, nil
}

// selectDTLSFingerprint selects a DTLS fingerprint following the same
// two-tier pattern as selectTLSProfile: randomized fingerprints are selected
// with probability InproxyDTLSFingerprintSelectRandomizedProbability, and
// parrot (mimicry) fingerprints are selected otherwise.
//
// Clients and proxies select their replayable DTLS fingerprints
// deterministically from the same client root obfuscation secret, using
// distinct offer and answer contexts.
//
// Limitation: the proxy selects its DTLS fingerprint using its local
// protocol.SupportedDTLSFingerprints and tactics parameters. If a client
// replays the same ClientRootObfuscationSecret against a different proxy
// whose SupportedDTLSFingerprints list has been upgraded, downgraded, or
// reordered, the proxy's fingerprint choice will not be the same as on the
// original dial, even though the PRNG seed is identical. Similarly, for
// randomized fingerprints, the randomized ClientHello content is derived from
// pion/dtls' default cipher suite and signature algorithm sets, so upgrading
// pion/dtls also changes that content for a given seed.
func selectDTLSFingerprint(
	p parameters.ParametersAccessor,
	clientRootObfuscationSecret inproxy.ObfuscationSecret,
	isOffer bool) (string, error) {

	PRNG, err := inproxy.DeriveDTLSFingerprintPRNG(
		clientRootObfuscationSecret, isOffer)
	if err != nil {
		return "", errors.Trace(err)
	}

	limitFingerprints := p.DTLSFingerprintsWithPRNG(
		parameters.InproxyLimitDTLSFingerprints,
		PRNG)

	randomizedFingerprints := make([]string, 0)
	parrotFingerprints := make([]string, 0)

	for _, fp := range protocol.SupportedDTLSFingerprints {
		if len(limitFingerprints) > 0 && !common.Contains(limitFingerprints, fp) {
			continue
		}
		if protocol.DTLSFingerprintIsRandomized(fp) {
			randomizedFingerprints = append(randomizedFingerprints, fp)
		} else {
			parrotFingerprints = append(parrotFingerprints, fp)
		}
	}

	if len(randomizedFingerprints) > 0 &&
		(len(parrotFingerprints) == 0 ||
			PRNG.FlipWeightedCoin(
				p.Float(parameters.InproxyDTLSFingerprintSelectRandomizedProbability))) {
		return randomizedFingerprints[PRNG.Intn(len(randomizedFingerprints))], nil
	}

	if len(parrotFingerprints) == 0 {
		return "", nil
	}

	return parrotFingerprints[PRNG.Intn(len(parrotFingerprints))], nil
}

// GetMetrics implements the common.MetricsSource interface.
func (dialParams *InproxyWebRTCDialParameters) GetMetrics() common.LogFields {

	// There is no is_replay-type field added here; replay is handled at a
	// higher level, and, for client in-proxy tunnel dials, is part of the
	// main tunnel dial parameters.

	// All WebRTC metrics except inproxy_webrtc_dtls_fingerprint are
	// delivered via inproxy.ClientConn/WebRTCConn GetMetrics.
	logFields := common.LogFields{}

	if dialParams.DTLSFingerprint != "" {
		logFields["inproxy_webrtc_dtls_fingerprint"] = dialParams.DTLSFingerprint
	}

	return logFields
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
	s.portMappingProbe = nil
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

// inproxyProxyAnnouncementLimits relays tactics proxy limits overrides to the
// specified inproxy proxy.
type inproxyProxyAnnouncementLimits struct {
	mutex  sync.Mutex
	config *Config
	proxy  *inproxy.Proxy
}

func newInproxyProxyAnnouncementLimits(
	config *Config) *inproxyProxyAnnouncementLimits {

	return &inproxyProxyAnnouncementLimits{
		config: config,
	}
}

func (limits *inproxyProxyAnnouncementLimits) SetProxy(proxy *inproxy.Proxy) error {

	limits.mutex.Lock()
	defer limits.mutex.Unlock()

	limits.proxy = proxy

	return errors.Trace(limits.setLimitsLocked())
}

// TacticsApplied implements the TacticsAppliedReceiver interface.
func (limits *inproxyProxyAnnouncementLimits) TacticsApplied() error {

	limits.mutex.Lock()
	defer limits.mutex.Unlock()

	return errors.Trace(limits.setLimitsLocked())
}

func (limits *inproxyProxyAnnouncementLimits) setLimitsLocked() error {

	if limits.proxy == nil {
		return nil
	}

	p := limits.config.GetParameters().Get()

	commonOverride := p.Int(parameters.InproxyProxyAnnounceCommonOverride)
	personalOverride := p.Int(parameters.InproxyProxyAnnouncePersonalOverride)

	return errors.Trace(limits.proxy.OverrideAnnouncementLimits(
		commonOverride,
		personalOverride))
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

	// Use Config.splitDeviceBinder, with wired up logging, not the public
	// config.DeviceBinder; other tunnel-core dials do this indirectly via
	// psiphon.DialConfig.
	//
	// In a split-interface in-proxy proxy configuration, this WebRTC/STUN
	// mux socket must be bound to the downstream (non-upstream) interface
	// so that STUN, ICE, and data channel traffic flow through it.
	deviceBinder := config.splitDeviceBinder()

	listen := &net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			var controlErr error
			err := c.Control(func(fd uintptr) {

				socketFD := int(fd)

				setAdditionalSocketOptions(socketFD)

				if deviceBinder != nil {
					_, err := deviceBinder.BindToDevice(socketFD)
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
