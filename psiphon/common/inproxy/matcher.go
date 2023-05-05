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
package inproxy

import (
	"context"
	"sync"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	lrucache "github.com/cognusion/go-cache-lru"
	"github.com/gammazero/deque"
	"github.com/pion/webrtc/v3"
)

// TTLs should be aligned with STUN hole punch lifetimes.

const (
	matcherAnnouncementQueueMaxSize = 100000
	matcherOfferQueueMaxSize        = 100000
	matcherPendingAnswersTTL        = 30 * time.Second
	matcherPendingAnswersMaxSize    = 100000
)

// Matcher matches proxy announcements with client offers. Matcher also
// coordinates pending proxy answers and routes answers to the awaiting
// client offer handler.
//
// Matching prioritizes selecting the oldest announcments and client offers,
// as they are closest to timing out.
//
// The client and proxy must supply matching personal or common compartment
// IDs. Personal compartment matching is preferred. Common compartments are
// managed by Psiphon and can be obtained via a tactics parameter or via an
// OSL embedding.
//
// Matching prefers to pair proxies and clients in a way that maximizes total
// possible matches. For a client or proxy with less-limited NAT traversal, a
// pairing with more-limited NAT traversal is preferred; and vice versa.
// Candidates with unknown NAT types and mobile network types are assumed to
// have the most limited NAT traversal capability.
//
// Preferred matchings take priority over announcment age.
//
// The client and proxy will not match if they are in the same country and
// ASN, as it's assumed that doesn't provide any blocking circumvention
// benefit. Disallowing proxies in certain blocked countries is handled at a
// higher level; any such proxies should not be enqueued for matching.
type Matcher struct {
	config *MatcherConfig

	runMutex    sync.Mutex
	runContext  context.Context
	stopRunning context.CancelFunc
	waitGroup   *sync.WaitGroup

	// The announcement queue is implicitly sorted by announcement age. The
	// count fields are used to skip searching deeper into the queue for
	// preferred matches.

	// TODO: replace queue and counts with an indexed, in-memory database?

	announcementQueueMutex                      sync.Mutex
	announcementQueue                           *deque.Deque[*announcementEntry]
	announcementsPersonalCompartmentalizedCount int
	announcementsUnlimitedNATCount              int
	announcementsPartiallyLimitedNATCount       int
	announcementsStrictlyLimitedNATCount        int

	// The offer queue is also implicitly sorted by offer age. Both an offer
	// and announcement queue are required since either announcements or
	// offers can arrive while there are no available pairings.

	offerQueueMutex sync.Mutex
	offerQueue      *deque.Deque[*offerEntry]

	matchSignal chan struct{}

	pendingAnswers *lrucache.Cache
}

// MatchProperties specifies the compartment, GeoIP, and network topology
// matching roperties of clients and proxies.
type MatchProperties struct {
	CommonCompartmentIDs   []ID
	PersonalCompartmentIDs []ID
	GeoIPData              common.GeoIPData
	NetworkType            NetworkType
	NATType                NATType
	PortMappingTypes       PortMappingTypes
}

// EffectiveNATType combines the set of network properties into an effective
// NAT type. When a port mapping is offered, a NAT type with unlimiter NAT
// traversal is assumed. When NAT type is unknown and the network type is
// mobile, CGNAT with limited NAT traversal is assumed.
func (p *MatchProperties) EffectiveNATType() NATType {

	if p.PortMappingTypes.Available() {
		return NATTypePortMapping
	}

	// TODO: can a peer have limited NAT travseral for IPv4 and also have a
	// publicly reachable IPv6 ICE host candidate? If so, change the
	// effective NAT type? Depends on whether the matched peer can use IPv6.

	if p.NATType == NATTypeUnknown && p.NetworkType == NetworkTypeMobile {
		return NATTypeMobileNetwork
	}

	return p.NATType
}

// ExistsPreferredNATMatch indicates whether there exists a preferred NAT
// matching given the types of pairing candidates available.
func (p *MatchProperties) ExistsPreferredNATMatch(
	unlimitedNAT, partiallyLimitedNAT, limitedNAT bool) bool {

	return p.EffectiveNATType().ExistsPreferredMatch(
		unlimitedNAT, partiallyLimitedNAT, limitedNAT)
}

// IsPreferredNATMatch indicates whether the peer candidate is a preferred
// NAT matching.
func (p *MatchProperties) IsPreferredNATMatch(
	peerMatchProperties *MatchProperties) bool {

	return p.EffectiveNATType().IsPreferredMatch(
		peerMatchProperties.EffectiveNATType())
}

// IsPersonalCompartmentalized indicates whether the candidate has personal
// compartment IDs.
func (p *MatchProperties) IsPersonalCompartmentalized() bool {
	return len(p.PersonalCompartmentIDs) > 0
}

// MatchAnnouncement is a proxy announcement to be queued for matching.
type MatchAnnouncement struct {
	Properties           MatchProperties
	ProxyID              ID
	ConnectionID         ID
	ProxyProtocolVersion int32
}

// MatchOffer is a client offer to be queued for matching.
type MatchOffer struct {
	Properties                  MatchProperties
	ClientProxyProtocolVersion  int32
	ClientOfferSDP              webrtc.SessionDescription
	ClientRootObfuscationSecret ObfuscationSecret
	NetworkProtocol             NetworkProtocol
	DestinationAddress          string
	DestinationServerID         string
}

// MatchAnswer is a proxy answer, the proxy's follow up to a matched
// announcement, to be routed to the awaiting client offer.
type MatchAnswer struct {
	ProxyIP                      string
	ProxyID                      ID
	ConnectionID                 ID
	SelectedProxyProtocolVersion int32
	ProxyAnswerSDP               webrtc.SessionDescription
}

// announcementEntry is an announcement queue entry, an announcement with its
// associated lifetime context and signaling channel.
type announcementEntry struct {
	ctx          context.Context
	announcement *MatchAnnouncement
	offerChan    chan *MatchOffer
}

// offerEntry is an offer queue entry, an offer with its associated lifetime
// context and signaling channel.
type offerEntry struct {
	ctx        context.Context
	offer      *MatchOffer
	answerChan chan *answerInfo
}

// answerInfo is an answer and its associated announcement.
type answerInfo struct {
	announcement *MatchAnnouncement
	answer       *MatchAnswer
}

// pendingAnswer represents an answer that is expected to arrive from a
// proxy.
type pendingAnswer struct {
	announcement *MatchAnnouncement
	answerChan   chan *answerInfo
}

// MatcherConfig specifies the configuration for a matcher.
type MatcherConfig struct {

	// Logger is used to log events.
	Logger common.Logger
}

// NewMatcher creates a new Matcher.
func NewMatcher(config *MatcherConfig) *Matcher {

	return &Matcher{
		config: config,

		waitGroup: new(sync.WaitGroup),

		announcementQueue: deque.New[*announcementEntry](),
		offerQueue:        deque.New[*offerEntry](),

		matchSignal: make(chan struct{}, 1),

		// matcherPendingAnswersTTL is not configurable; it supplies a default
		// that is expected to be ignored when each entry's TTL is set to the
		// Offer ctx timeout.

		pendingAnswers: lrucache.NewWithLRU(
			matcherPendingAnswersTTL,
			1*time.Minute,
			matcherPendingAnswersMaxSize),
	}
}

// Start starts running the Matcher. The Matcher runs a goroutine which
// matches announcements and offers.
func (m *Matcher) Start() error {

	m.runMutex.Lock()
	defer m.runMutex.Unlock()

	if m.runContext != nil {
		return errors.TraceNew("already running")
	}

	m.runContext, m.stopRunning = context.WithCancel(context.Background())

	m.waitGroup.Add(1)
	go func() {
		defer m.waitGroup.Done()
		m.matchWorker(m.runContext)
	}()

	return nil
}

// Stop stops running the Matcher and its worker goroutine.
//
// Limitation: Stop is not synchronized with Announce/Offer/Answer, so items
// can get enqueued during and after a Stop call. Stop is intended more for a
// full broker shutdown, where this won't be a concern.
func (m *Matcher) Stop() {

	m.runMutex.Lock()
	defer m.runMutex.Unlock()

	m.stopRunning()
	m.waitGroup.Wait()
	m.runContext, m.stopRunning = nil, nil
}

// Announce enqueues the proxy announcement and blocks until it is matched
// with a returned offer or ctx is done. The caller must not mutate the
// announcement or its properties after calling Announce.
//
// The offer is sent to the proxy by the broker, and then the proxy sends its
// answer back to the broker, which calls Answer with that value.
func (m *Matcher) Announce(
	ctx context.Context,
	proxyAnnouncement *MatchAnnouncement) (*MatchOffer, error) {

	announcementEntry := &announcementEntry{
		ctx:          ctx,
		announcement: proxyAnnouncement,
		offerChan:    make(chan *MatchOffer, 1),
	}

	m.addAnnouncementEntry(announcementEntry)

	// Await client offer.

	var clientOffer *MatchOffer

	select {
	case <-ctx.Done():
		m.removeAnnouncementEntry(announcementEntry)
		return nil, errors.Trace(ctx.Err())

	case clientOffer = <-announcementEntry.offerChan:
	}

	return clientOffer, nil
}

// Offer enqueues the client offer and blocks until it is matched with a
// returned announcement or ctx is done. The caller must not mutate the offer
// or its properties after calling Announce.
//
// The answer is returned to the client by the broker, and the WebRTC
// connection is dialed. The original announcement is also returned, so its
// match properties can be logged.
func (m *Matcher) Offer(
	ctx context.Context,
	clientOffer *MatchOffer) (*MatchAnswer, *MatchAnnouncement, error) {

	offerEntry := &offerEntry{
		ctx:        ctx,
		offer:      clientOffer,
		answerChan: make(chan *answerInfo, 1),
	}

	m.addOfferEntry(offerEntry)

	// Await proxy answer.

	var proxyAnswerInfo *answerInfo

	select {
	case <-ctx.Done():
		m.removeOfferEntry(offerEntry)

		// TODO: also remove any pendingAnswers entry? The entry TTL is set to
		// the Offer ctx, the client request, timeout, so it will eventually
		// get removed. But a client may abort its request earlier than the
		// timeout.

		return nil, nil, errors.Trace(ctx.Err())
	case proxyAnswerInfo = <-offerEntry.answerChan:
	}

	if proxyAnswerInfo == nil {

		// nil will be delivered to the channel when either the proxy
		// announcment request concurrently timed out, or the answer
		// indicated a proxy error, or the answer did not arrive in time.
		return nil, nil, errors.TraceNew("no answer")
	}

	// This is a sanity check and not expected to fail.
	if !proxyAnswerInfo.answer.ConnectionID.Equal(
		proxyAnswerInfo.announcement.ConnectionID) {
		return nil, nil, errors.TraceNew("unexpected connection ID")
	}

	return proxyAnswerInfo.answer, proxyAnswerInfo.announcement, nil
}

// Answer delivers an answer from the proxy for a previously matched offer.
// The ProxyID and ConnectionID must correspond to the original announcement.
// The caller must not mutate the answer after calling Answer. Answer does
// not block.
//
// The answer is returned to the awaiting Offer call and sent to the matched
// client.
func (m *Matcher) Answer(
	proxyAnswer *MatchAnswer) error {

	key := m.pendingAnswerKey(proxyAnswer.ProxyID, proxyAnswer.ConnectionID)
	pendingAnswerValue, ok := m.pendingAnswers.Get(key)
	if !ok {
		// The client is no longer awaiting the response.
		return errors.TraceNew("no client")
	}

	m.pendingAnswers.Delete(key)

	pendingAnswer := pendingAnswerValue.(*pendingAnswer)

	pendingAnswer.answerChan <- &answerInfo{
		announcement: pendingAnswer.announcement,
		answer:       proxyAnswer,
	}

	return nil
}

// AnswerError delivers a failed answer indication from the proxy to an
// awaiting offer. The ProxyID and ConnectionID must correspond to the
// original announcement.
//
// The failure indication is returned to the awaiting Offer call and sent to
// the matched client.
func (m *Matcher) AnswerError(proxyID ID, connectionID ID) {

	key := m.pendingAnswerKey(proxyID, connectionID)
	pendingAnswerValue, ok := m.pendingAnswers.Get(key)
	if !ok {
		// The client is no longer awaiting the response.
		return
	}

	m.pendingAnswers.Delete(key)

	// Closing the channel delivers nil, a failed indicator, to any receiver.
	close(pendingAnswerValue.(*pendingAnswer).answerChan)
}

// matchWorker is the matching worker goroutine. It idles until signaled that
// a queue item has been added, and then runs a full matching pass.
func (m *Matcher) matchWorker(ctx context.Context) {
	for {
		select {
		case <-m.matchSignal:
		case <-ctx.Done():
			return
		}
		m.matchAllOffers()
	}
}

// matchAllOffers iterates over the queues, making all possible matches.
func (m *Matcher) matchAllOffers() {

	m.announcementQueueMutex.Lock()
	defer m.announcementQueueMutex.Unlock()
	m.offerQueueMutex.Lock()
	defer m.offerQueueMutex.Unlock()

	// Take each offer in turn, and select an announcement match. There is an
	// implicit preference for older client offers, sooner to timeout, at the
	// front of the queue.

	// TODO: consider matching one offer, then releasing the locks to allow
	// more announcements to be enqueued, then continuing to match.

	i := 0
	end := m.offerQueue.Len()

	for i < end && m.announcementQueue.Len() > 0 {

		offerEntry := m.offerQueue.At(i)

		// Skip and remove this offer if its deadline has already passed.
		// There is no signal to the awaiting Offer function, as it will exit
		// based on the same ctx.

		if offerEntry.ctx.Err() != nil {
			m.offerQueue.Remove(i)
			end -= 1
			continue
		}

		j, ok := m.matchOffer(offerEntry)
		if !ok {

			// No match, so leave this offer in place in the queue and move to
			// the next.

			i++
			continue
		}

		if m.config.Logger.IsLogLevelDebug() {
			m.config.Logger.WithTraceFields(common.LogFields{
				"match_index":             j,
				"offer_queue_size":        m.offerQueue.Len(),
				"announcement_queue_size": m.announcementQueue.Len(),
			}).Debug("match metrics")
		}

		// Remove the matched announcement from the queue. Send the offer to
		// the announcment entry's offerChan, which will deliver it to the
		// blocked Announce call. Add a pending answers entry to await the
		// proxy's follow up Answer call. The TTL for the pending answer
		// entry is set to the matched Offer call's ctx, as the answer is
		// only useful as long as the client is still waiting.

		announcementEntry := m.announcementQueue.At(j)

		expiry := lrucache.DefaultExpiration
		deadline, ok := offerEntry.ctx.Deadline()
		if ok {
			expiry = time.Until(deadline)
		}

		key := m.pendingAnswerKey(
			announcementEntry.announcement.ProxyID,
			announcementEntry.announcement.ConnectionID)

		m.pendingAnswers.Set(
			key,
			&pendingAnswer{
				announcement: announcementEntry.announcement,
				answerChan:   offerEntry.answerChan,
			},
			expiry)

		announcementEntry.offerChan <- offerEntry.offer

		m.announcementQueue.Remove(j)
		m.adjustAnnouncementCounts(announcementEntry, -1)

		// Remove the matched offer from the queue and match the next offer,
		// now first in the queue.

		m.offerQueue.Remove(i)
		end -= 1
	}
}

func (m *Matcher) matchOffer(offerEntry *offerEntry) (int, bool) {

	// Assumes the caller has the queue mutexed locked.

	// Check each announcement in turn, and select a match. There is an
	// implicit preference for older proxy announcments, sooner to timeout, at the
	// front of the queue.

	// Future matching enhancements could include more sophisticated GeoIP
	// rules, such as a configuration encoding knowledge of an ASN's NAT
	// type, or preferred client/proxy country/ASN matches.

	offerProperties := &offerEntry.offer.Properties

	// Use the NAT traversal type counters to check if there's any preferred
	// NAT match for this offer in the announcement queue. When there is, we
	// will search beyond the first announcement.

	existsPreferredNATMatch := offerProperties.ExistsPreferredNATMatch(
		m.announcementsUnlimitedNATCount > 0,
		m.announcementsPartiallyLimitedNATCount > 0,
		m.announcementsStrictlyLimitedNATCount > 0)

	bestMatch := -1
	bestMatchNAT := false
	bestMatchCompartment := false

	end := m.announcementQueue.Len()

	for i := 0; i < end; i++ {

		announcementEntry := m.announcementQueue.At(i)

		// Skip and remove this announcement if its deadline has already
		// passed. There is no signal to the awaiting Announce function, as
		// it will exit based on the same ctx.

		if announcementEntry.ctx.Err() != nil {
			m.announcementQueue.Remove(i)
			end -= 1
			continue
		}

		announcementProperties := &announcementEntry.announcement.Properties

		// Disallow matching the same country and ASN

		if offerProperties.GeoIPData.Country ==
			announcementProperties.GeoIPData.Country &&
			offerProperties.GeoIPData.ASN ==
				announcementProperties.GeoIPData.ASN {
			continue
		}

		// There must be a compartment match. If there is a personal
		// compartment match, this match will be preferred.

		matchCommonCompartment := HaveCommonIDs(
			announcementProperties.CommonCompartmentIDs, offerProperties.CommonCompartmentIDs)
		matchPersonalCompartment := HaveCommonIDs(
			announcementProperties.PersonalCompartmentIDs, offerProperties.PersonalCompartmentIDs)
		if !matchCommonCompartment && !matchPersonalCompartment {
			continue
		}

		// Check if this is a preferred NAT match. Ultimately, a match may be
		// made with potentially incompatible NATs, but the client/proxy
		// reported NAT types may be incorrect or unknown; the client will
		// oftern skip NAT discovery.

		matchNAT := offerProperties.IsPreferredNATMatch(announcementProperties)

		// At this point, the candidate is a match. Determine if this is a new
		// best match.

		if bestMatch == -1 {

			// This is a match, and there was no previous match, so it becomes
			// the provisional best match.

			bestMatch = i
			bestMatchNAT = matchNAT
			bestMatchCompartment = matchPersonalCompartment

		} else if !bestMatchNAT && matchNAT {

			// If there was a previous best match which was not a preferred
			// NAT match, this becomes the new best match. The preferred NAT
			// match is prioritized over personal compartment matching.

			bestMatch = i
			bestMatchNAT = true
			bestMatchCompartment = matchPersonalCompartment

		} else if !bestMatchCompartment && matchPersonalCompartment && (!bestMatchNAT || matchNAT) {

			// If there was a previous best match which was not a personal
			// compartment match, and as long as this match doesn't undo a
			// better NAT match, this becomes the new best match.

			bestMatch = i
			bestMatchNAT = matchNAT
			bestMatchCompartment = true
		}

		// Stop as soon as we have the best possible match.

		if (bestMatchNAT || !existsPreferredNATMatch) &&
			(matchPersonalCompartment || m.announcementsPersonalCompartmentalizedCount == 0) {
			break
		}
	}

	return bestMatch, bestMatch != -1
}

func (m *Matcher) addAnnouncementEntry(announcementEntry *announcementEntry) bool {

	m.announcementQueueMutex.Lock()
	defer m.announcementQueueMutex.Unlock()

	if m.announcementQueue.Len() >= matcherAnnouncementQueueMaxSize {
		return false
	}
	m.announcementQueue.PushBack(announcementEntry)
	m.adjustAnnouncementCounts(announcementEntry, 1)

	select {
	case m.matchSignal <- struct{}{}:
	default:
	}

	return true
}

func (m *Matcher) removeAnnouncementEntry(announcementEntry *announcementEntry) {

	m.announcementQueueMutex.Lock()
	defer m.announcementQueueMutex.Unlock()

	found := false
	for i := 0; i < m.announcementQueue.Len(); i++ {
		if m.announcementQueue.At(i) == announcementEntry {
			m.announcementQueue.Remove(i)
			m.adjustAnnouncementCounts(announcementEntry, -1)
			found = true
			break
		}
	}
	if !found {

		// The Announce call is aborting and taking its entry back out of the
		// queue. If the entry is not found in the queue, then a concurrent
		// Offer has matched the announcement. So check for the pending
		// answer corresponding to the announcement and remove it and deliver
		// a failure signal to the waiting Offer, so the client doesn't wait
		// longer than necessary.

		key := m.pendingAnswerKey(
			announcementEntry.announcement.ProxyID,
			announcementEntry.announcement.ConnectionID)

		pendingAnswerValue, ok := m.pendingAnswers.Get(key)
		if ok {
			close(pendingAnswerValue.(*pendingAnswer).answerChan)
			m.pendingAnswers.Delete(key)
		}
	}
}

func (m *Matcher) adjustAnnouncementCounts(
	announcementEntry *announcementEntry, delta int) {

	// Assumes s.announcementQueueMutex lock is held.

	if announcementEntry.announcement.Properties.IsPersonalCompartmentalized() {
		m.announcementsPersonalCompartmentalizedCount += delta
	}

	switch announcementEntry.announcement.Properties.EffectiveNATType().Traversal() {
	case NATTraversalUnlimited:
		m.announcementsUnlimitedNATCount += delta
	case NATTraversalPartiallyLimited:
		m.announcementsPartiallyLimitedNATCount += delta
	case NATTraversalStrictlyLimited:
		m.announcementsStrictlyLimitedNATCount += delta
	}
}

func (m *Matcher) addOfferEntry(offerEntry *offerEntry) bool {

	m.offerQueueMutex.Lock()
	defer m.offerQueueMutex.Unlock()

	if m.offerQueue.Len() >= matcherOfferQueueMaxSize {
		return false
	}
	m.offerQueue.PushBack(offerEntry)

	select {
	case m.matchSignal <- struct{}{}:
	default:
	}

	return true
}

func (m *Matcher) removeOfferEntry(offerEntry *offerEntry) {

	m.offerQueueMutex.Lock()
	defer m.offerQueueMutex.Unlock()

	for i := 0; i < m.offerQueue.Len(); i++ {
		if m.offerQueue.At(i) == offerEntry {
			m.offerQueue.Remove(i)
			break
		}
	}
}

func (m *Matcher) pendingAnswerKey(proxyID ID, connectionID ID) string {

	// The pending answer lookup key is used to associate announcements and
	// subsequent answers. While the client learns the ConnectionID, only the
	// proxy knows the ProxyID component, so only the correct proxy can match
	// an answer to an announcement. The ConnectionID component is necessary
	// as a proxy may have multiple, concurrent pending answers.

	return string(proxyID[:]) + string(connectionID[:])
}
