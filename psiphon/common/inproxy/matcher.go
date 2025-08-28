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
	"container/list"
	"context"
	std_errors "errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	lrucache "github.com/cognusion/go-cache-lru"
	"golang.org/x/time/rate"
)

// TTLs should be aligned with STUN hole punch lifetimes.

const (
	matcherAnnouncementQueueMaxSize = 5000000
	matcherOfferQueueMaxSize        = 5000000
	matcherPendingAnswersTTL        = 30 * time.Second
	matcherPendingAnswersMaxSize    = 100000
	matcherMaxPreferredNATProbe     = 100
	matcherMaxProbe                 = 1000

	matcherRateLimiterReapHistoryFrequencySeconds = 300
	matcherRateLimiterMaxCacheEntries             = 1000000
)

// Matcher matches proxy announcements with client offers. Matcher also
// coordinates pending proxy answers and routes answers to the awaiting
// client offer handler.
//
// Matching prioritizes selecting the oldest announcements and client offers,
// as they are closest to timing out.
//
// The client and proxy must supply matching personal or common compartment
// IDs. Common compartments are managed by Psiphon and can be obtained via a
// tactics parameter or via an OSL embedding. Each proxy announcement or
// client offer may specify only one compartment ID type, either common or
// personal.
//
// Matching prefers to pair proxies and clients in a way that maximizes total
// possible matches. For a client or proxy with less-limited NAT traversal, a
// pairing with more-limited NAT traversal is preferred; and vice versa.
// Candidates with unknown NAT types and mobile network types are assumed to
// have the most limited NAT traversal capability.
//
// Preferred matchings take priority over announcement age.
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

	announcementQueueMutex          sync.Mutex
	announcementQueue               *announcementMultiQueue
	announcementQueueEntryCountByIP map[string]int
	announcementQueueRateLimiters   *lrucache.Cache
	announcementLimitEntryCount     int
	announcementRateLimitQuantity   int
	announcementRateLimitInterval   time.Duration
	announcementNonlimitedProxyIDs  map[ID]struct{}

	// The offer queue is also implicitly sorted by offer age. Both an offer
	// and announcement queue are required since either announcements or
	// offers can arrive while there are no available pairings.

	offerQueueMutex          sync.Mutex
	offerQueue               *list.List
	offerQueueEntryCountByIP map[string]int
	offerQueueRateLimiters   *lrucache.Cache
	offerLimitEntryCount     int
	offerRateLimitQuantity   int
	offerRateLimitInterval   time.Duration

	matchSignal chan struct{}

	pendingAnswers *lrucache.Cache
}

// MatcherConfig specifies the configuration for a matcher.
type MatcherConfig struct {

	// Logger is used to log events.
	Logger common.Logger

	// Announcement queue limits.
	AnnouncementLimitEntryCount    int
	AnnouncementRateLimitQuantity  int
	AnnouncementRateLimitInterval  time.Duration
	AnnouncementNonlimitedProxyIDs []ID

	// Offer queue limits.
	OfferLimitEntryCount   int
	OfferRateLimitQuantity int
	OfferRateLimitInterval time.Duration

	// Proxy quality state.
	ProxyQualityState *ProxyQualityState

	// Broker process load limit state callback. See BrokerConfig.
	IsLoadLimiting func() bool

	// Proxy/client allow match callback. See BrokerConfig.
	AllowMatch func(common.GeoIPData, common.GeoIPData) bool
}

// MatchProperties specifies the compartment, GeoIP, and network topology
// matching properties of clients and proxies.
type MatchProperties struct {
	IsPriority             bool
	ProtocolVersion        int32
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

// MatchAnnouncement is a proxy announcement to be queued for matching.
type MatchAnnouncement struct {
	Properties   MatchProperties
	ProxyID      ID
	ProxyMetrics *ProxyMetrics
	ConnectionID ID
}

// MatchOffer is a client offer to be queued for matching.
type MatchOffer struct {
	Properties                  MatchProperties
	ClientOfferSDP              WebRTCSessionDescription
	ClientRootObfuscationSecret ObfuscationSecret
	DoDTLSRandomization         bool
	UseMediaStreams             bool
	TrafficShapingParameters    *TrafficShapingParameters
	NetworkProtocol             NetworkProtocol
	DestinationAddress          string
	DestinationServerID         string
}

// MatchAnswer is a proxy answer, the proxy's follow up to a matched
// announcement, to be routed to the awaiting client offer.
type MatchAnswer struct {
	ProxyIP        string
	ProxyID        ID
	ConnectionID   ID
	ProxyAnswerSDP WebRTCSessionDescription
}

// MatchMetrics records statistics about the match queue state at the time a
// match is made.
type MatchMetrics struct {
	OfferMatchIndex        int
	OfferQueueSize         int
	AnnouncementMatchIndex int
	AnnouncementQueueSize  int
}

// GetMetrics converts MatchMetrics to loggable fields.
func (metrics *MatchMetrics) GetMetrics() common.LogFields {
	if metrics == nil {
		return nil
	}
	return common.LogFields{
		"offer_match_index":        metrics.OfferMatchIndex,
		"offer_queue_size":         metrics.OfferQueueSize,
		"announcement_match_index": metrics.AnnouncementMatchIndex,
		"announcement_queue_size":  metrics.AnnouncementQueueSize,
	}
}

// announcementEntry is an announcement queue entry, an announcement with its
// associated lifetime context and signaling channel.
type announcementEntry struct {
	ctx          context.Context
	limitIP      string
	announcement *MatchAnnouncement
	offerChan    chan *MatchOffer
	matchMetrics atomic.Value

	// queueReference is initialized by addAnnouncementEntry, and used to
	// efficiently dequeue the entry.
	queueReference announcementQueueReference
}

func (announcementEntry *announcementEntry) getMatchMetrics() *MatchMetrics {
	matchMetrics, _ := announcementEntry.matchMetrics.Load().(*MatchMetrics)
	return matchMetrics
}

// offerEntry is an offer queue entry, an offer with its associated lifetime
// context and signaling channel.
type offerEntry struct {
	ctx          context.Context
	limitIP      string
	offer        *MatchOffer
	answerChan   chan *answerInfo
	matchMetrics atomic.Value

	// queueReference is initialized by addOfferEntry, and used to efficiently
	// dequeue the entry.
	queueReference *list.Element
}

func (offerEntry *offerEntry) getMatchMetrics() *MatchMetrics {
	matchMetrics, _ := offerEntry.matchMetrics.Load().(*MatchMetrics)
	return matchMetrics
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

// NewMatcher creates a new Matcher.
func NewMatcher(config *MatcherConfig) *Matcher {

	m := &Matcher{
		config: config,

		waitGroup: new(sync.WaitGroup),

		announcementQueue:               newAnnouncementMultiQueue(),
		announcementQueueEntryCountByIP: make(map[string]int),
		announcementQueueRateLimiters: lrucache.NewWithLRU(
			0,
			time.Duration(matcherRateLimiterReapHistoryFrequencySeconds)*time.Second,
			matcherRateLimiterMaxCacheEntries),

		offerQueue:               list.New(),
		offerQueueEntryCountByIP: make(map[string]int),
		offerQueueRateLimiters: lrucache.NewWithLRU(
			0,
			time.Duration(matcherRateLimiterReapHistoryFrequencySeconds)*time.Second,
			matcherRateLimiterMaxCacheEntries),

		matchSignal: make(chan struct{}, 1),

		// matcherPendingAnswersTTL is not configurable; it supplies a default
		// that is expected to be ignored when each entry's TTL is set to the
		// Offer ctx timeout.

		pendingAnswers: lrucache.NewWithLRU(
			matcherPendingAnswersTTL,
			1*time.Minute,
			matcherPendingAnswersMaxSize),
	}

	m.SetLimits(
		config.AnnouncementLimitEntryCount,
		config.AnnouncementRateLimitQuantity,
		config.AnnouncementRateLimitInterval,
		config.AnnouncementNonlimitedProxyIDs,
		config.OfferLimitEntryCount,
		config.OfferRateLimitQuantity,
		config.OfferRateLimitInterval)

	return m
}

// SetLimits sets new queue limits, replacing the previous configuration.
// Existing, cached rate limiters retain their existing rate limit state. New
// entries will use the new quantity/interval configuration. In addition,
// currently enqueued items may exceed any new, lower maximum entry count
// until naturally dequeued.
func (m *Matcher) SetLimits(
	announcementLimitEntryCount int,
	announcementRateLimitQuantity int,
	announcementRateLimitInterval time.Duration,
	announcementNonlimitedProxyIDs []ID,
	offerLimitEntryCount int,
	offerRateLimitQuantity int,
	offerRateLimitInterval time.Duration) {

	nonlimitedProxyIDs := make(map[ID]struct{})
	for _, proxyID := range announcementNonlimitedProxyIDs {
		nonlimitedProxyIDs[proxyID] = struct{}{}
	}

	m.announcementQueueMutex.Lock()
	m.announcementLimitEntryCount = announcementLimitEntryCount
	m.announcementRateLimitQuantity = announcementRateLimitQuantity
	m.announcementRateLimitInterval = announcementRateLimitInterval
	m.announcementNonlimitedProxyIDs = nonlimitedProxyIDs
	m.announcementQueueMutex.Unlock()

	m.offerQueueMutex.Lock()
	m.offerLimitEntryCount = offerLimitEntryCount
	m.offerRateLimitQuantity = offerRateLimitQuantity
	m.offerRateLimitInterval = offerRateLimitInterval
	m.offerQueueMutex.Unlock()
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
// Announce assumes that the ctx.Deadline for each call is monotonically
// increasing and that the deadline can be used as part of selecting the next
// nearest-to-expire announcement.
//
// The offer is sent to the proxy by the broker, and then the proxy sends its
// answer back to the broker, which calls Answer with that value.
//
// The returned MatchMetrics is nil unless a match is made; and non-nil if a
// match is made, even if there is a later error.
func (m *Matcher) Announce(
	ctx context.Context,
	proxyIP string,
	proxyAnnouncement *MatchAnnouncement) (*MatchOffer, *MatchMetrics, error) {

	// An announcement must specify exactly one compartment ID, of one type,
	// common or personal. The limit of one is currently a limitation of the
	// multi-queue implementation; see comment in
	// announcementMultiQueue.enqueue.
	compartmentIDs := proxyAnnouncement.Properties.CommonCompartmentIDs
	if len(compartmentIDs) == 0 {
		compartmentIDs = proxyAnnouncement.Properties.PersonalCompartmentIDs
	} else if len(proxyAnnouncement.Properties.PersonalCompartmentIDs) > 0 {
		return nil, nil, errors.TraceNew("unexpected multiple compartment ID types")
	}
	if len(compartmentIDs) != 1 {
		return nil, nil, errors.TraceNew("unexpected compartment ID count")
	}

	isAnnouncement := true
	err := m.applyLoadLimit(isAnnouncement)
	if err != nil {
		return nil, nil, errors.Trace(err)
	}

	announcementEntry := &announcementEntry{
		ctx:          ctx,
		limitIP:      getRateLimitIP(proxyIP),
		announcement: proxyAnnouncement,
		offerChan:    make(chan *MatchOffer, 1),
	}

	err = m.addAnnouncementEntry(announcementEntry)
	if err != nil {
		return nil, nil, errors.Trace(err)
	}

	// Await client offer.

	var clientOffer *MatchOffer

	select {
	case <-ctx.Done():
		m.removeAnnouncementEntry(true, announcementEntry)
		return nil, announcementEntry.getMatchMetrics(), errors.Trace(ctx.Err())

	case clientOffer = <-announcementEntry.offerChan:
	}

	return clientOffer, announcementEntry.getMatchMetrics(), nil
}

// Offer enqueues the client offer and blocks until it is matched with a
// returned announcement or ctx is done. The caller must not mutate the offer
// or its properties after calling Announce.
//
// The answer is returned to the client by the broker, and the WebRTC
// connection is dialed. The original announcement is also returned, so its
// match properties can be logged.
//
// The returned MatchMetrics is nil unless a match is made; and non-nil if a
// match is made, even if there is a later error.
func (m *Matcher) Offer(
	ctx context.Context,
	clientIP string,
	clientOffer *MatchOffer) (*MatchAnswer, *MatchAnnouncement, *MatchMetrics, error) {

	// An offer must specify at least one compartment ID, and may only specify
	// one type, common or personal, of compartment IDs.
	compartmentIDs := clientOffer.Properties.CommonCompartmentIDs
	if len(compartmentIDs) == 0 {
		compartmentIDs = clientOffer.Properties.PersonalCompartmentIDs
	} else if len(clientOffer.Properties.PersonalCompartmentIDs) > 0 {
		return nil, nil, nil, errors.TraceNew("unexpected multiple compartment ID types")
	}
	if len(compartmentIDs) < 1 {
		return nil, nil, nil, errors.TraceNew("unexpected missing compartment IDs")
	}

	isAnnouncement := false
	err := m.applyLoadLimit(isAnnouncement)
	if err != nil {
		return nil, nil, nil, errors.Trace(err)
	}

	offerEntry := &offerEntry{
		ctx:        ctx,
		limitIP:    getRateLimitIP(clientIP),
		offer:      clientOffer,
		answerChan: make(chan *answerInfo, 1),
	}

	err = m.addOfferEntry(offerEntry)
	if err != nil {
		return nil, nil, nil, errors.Trace(err)
	}

	// Await proxy answer.

	var proxyAnswerInfo *answerInfo

	select {
	case <-ctx.Done():
		m.removeOfferEntry(true, offerEntry)

		// TODO: also remove any pendingAnswers entry? The entry TTL is set to
		// the Offer ctx, the client request, timeout, so it will eventually
		// get removed. But a client may abort its request earlier than the
		// timeout.

		return nil, nil,
			offerEntry.getMatchMetrics(), errors.Trace(ctx.Err())

	case proxyAnswerInfo = <-offerEntry.answerChan:
	}

	if proxyAnswerInfo == nil {

		// nil will be delivered to the channel when either the proxy
		// announcement request concurrently timed out, or the answer
		// indicated a proxy error, or the answer did not arrive in time.
		return nil, nil,
			offerEntry.getMatchMetrics(), errors.TraceNew("no answer")
	}

	// This is a sanity check and not expected to fail.
	if !proxyAnswerInfo.answer.ConnectionID.Equal(
		proxyAnswerInfo.announcement.ConnectionID) {
		return nil, nil,
			offerEntry.getMatchMetrics(), errors.TraceNew("unexpected connection ID")
	}

	return proxyAnswerInfo.answer,
		proxyAnswerInfo.announcement,
		offerEntry.getMatchMetrics(),
		nil
}

// AnnouncementHasPersonalCompartmentIDs looks for a pending answer for an
// announcement identified by the specified proxy ID and connection ID and
// returns whether the announcement has personal compartment IDs, indicating
// personal pairing mode.
//
// If no pending answer is found, an error is returned.
func (m *Matcher) AnnouncementHasPersonalCompartmentIDs(
	proxyID ID, connectionID ID) (bool, error) {

	key := m.pendingAnswerKey(proxyID, connectionID)
	pendingAnswerValue, ok := m.pendingAnswers.Get(key)
	if !ok {
		// The input IDs don't correspond to a pending answer, or the client
		// is no longer awaiting the response.
		return false, errors.TraceNew("no pending answer")
	}

	pendingAnswer := pendingAnswerValue.(*pendingAnswer)

	hasPersonalCompartmentIDs := len(
		pendingAnswer.announcement.Properties.PersonalCompartmentIDs) > 0

	return hasPersonalCompartmentIDs, nil
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
		// The input IDs don't correspond to a pending answer, or the client
		// is no longer awaiting the response.
		return errors.TraceNew("no pending answer")
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
			m.matchAllOffers()
		case <-ctx.Done():
			return
		}
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

	nextOffer := m.offerQueue.Front()
	offerIndex := -1

	for nextOffer != nil && m.announcementQueue.getLen() > 0 {

		offerIndex += 1

		// nextOffer.Next must be invoked before any removeOfferEntry since
		// container/list.remove clears list.Element.next.
		offer := nextOffer
		nextOffer = nextOffer.Next()

		offerEntry := offer.Value.(*offerEntry)

		// Skip and remove this offer if its deadline has already passed.
		// There is no signal to the awaiting Offer function, as it will exit
		// based on the same ctx.

		if offerEntry.ctx.Err() != nil {
			m.removeOfferEntry(false, offerEntry)
			continue
		}

		announcementEntry, announcementMatchIndex := m.matchOffer(offerEntry)
		if announcementEntry == nil {
			continue
		}

		// Record match metrics.

		// The index metrics predate the announcement multi-queue; now, with
		// the multi-queue, announcement_index is how many announce entries
		// were inspected before matching.

		matchMetrics := &MatchMetrics{
			OfferMatchIndex:        offerIndex,
			OfferQueueSize:         m.offerQueue.Len(),
			AnnouncementMatchIndex: announcementMatchIndex,
			AnnouncementQueueSize:  m.announcementQueue.getLen(),
		}

		offerEntry.matchMetrics.Store(matchMetrics)
		announcementEntry.matchMetrics.Store(matchMetrics)

		// Remove the matched announcement from the queue. Send the offer to
		// the announcement entry's offerChan, which will deliver it to the
		// blocked Announce call. Add a pending answers entry to await the
		// proxy's follow up Answer call. The TTL for the pending answer
		// entry is set to the matched Offer call's ctx, as the answer is
		// only useful as long as the client is still waiting.

		m.removeAnnouncementEntry(false, announcementEntry)

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

		// Remove the matched offer from the queue and match the next offer,
		// now first in the queue.

		m.removeOfferEntry(false, offerEntry)
	}
}

func (m *Matcher) matchOffer(offerEntry *offerEntry) (*announcementEntry, int) {

	// Assumes the caller has the queue mutexes locked.

	// Check each candidate announcement in turn, and select a match. There is
	// an implicit preference for older proxy announcements, sooner to
	// timeout, at the front of the enqueued announcements.
	// announcementMultiQueue.startMatching skips to the first matching
	// compartment ID(s).
	//
	// Limitation: since this logic matches each enqueued client in turn, it will
	// only make the optimal NAT match for the oldest enqueued client vs. all
	// proxies, and not do optimal N x M matching for all clients and all proxies.
	//
	// Future matching enhancements could include more sophisticated GeoIP
	// rules, such as a configuration encoding knowledge of an ASN's NAT
	// type, or preferred client/proxy country/ASN matches.

	offerProperties := &offerEntry.offer.Properties

	// Assumes the caller checks that offer specifies either personal
	// compartment IDs or common compartment IDs, but not both.
	isCommonCompartments := false
	compartmentIDs := offerProperties.PersonalCompartmentIDs
	if len(compartmentIDs) == 0 {
		isCommonCompartments = true
		compartmentIDs = offerProperties.CommonCompartmentIDs
	}
	if len(compartmentIDs) == 0 {
		return nil, -1
	}

	matchIterator := m.announcementQueue.startMatching(
		isCommonCompartments, compartmentIDs)

	// Use the NAT traversal type counters to check if there's any preferred
	// NAT match for this offer in the announcement queue. When there is, we
	// will search beyond the first announcement.

	unlimitedNATCount, partiallyLimitedNATCount, strictlyLimitedNATCount :=
		matchIterator.getNATCounts()

	existsPreferredNATMatch := offerProperties.ExistsPreferredNATMatch(
		unlimitedNATCount > 0,
		partiallyLimitedNATCount > 0,
		strictlyLimitedNATCount > 0)

	// TODO: add an ExistsCompatibleProtocolVersionMatch check?
	//
	// Currently, searching for protocol version support that doesn't exist
	// may be mitigated by limiting, through tactics, client protocol options
	// selection; using the proxy protocol version in PrioritizeProxy; and,
	// ultimately, increasing MinimumProxyProtocolVersion.

	var bestMatch *announcementEntry
	bestMatchIndex := -1
	bestMatchIsPriority := false
	bestMatchNAT := false

	// matcherMaxProbe limits the linear search through the announcement queue
	// to find a match. Currently, the queue implementation provides
	// constant-time lookup for matching compartment IDs. Other matching
	// aspects may require iterating over the queue items, including the
	// strict same-country and ASN constraint and protocol version
	// compatibility constraint. Best NAT match is not a strict constraint
	// and uses a shorter search limit, matcherMaxPreferredNATProbe.

	candidateIndex := -1
	for candidateIndex <= matcherMaxProbe {

		announcementEntry, isPriority := matchIterator.getNext()
		if announcementEntry == nil {
			break
		}

		if !isPriority && bestMatchIsPriority {

			// There is a priority match, but it wasn't bestMatchNAT and we
			// continued to iterate. Now that isPriority is false, we're past the
			// end of the priority items, so stop looking for any best NAT match
			// and return the previous priority match. When there are zero
			// priority items to begin with, this case should not be hit.
			break
		}

		candidateIndex += 1

		// Skip and remove this announcement if its deadline has already
		// passed. There is no signal to the awaiting Announce function, as
		// it will exit based on the same ctx.

		if announcementEntry.ctx.Err() != nil {
			m.removeAnnouncementEntry(false, announcementEntry)
			continue
		}

		announcementProperties := &announcementEntry.announcement.Properties

		// Don't match unless the proxy announcement, client offer, and the
		// client's selected protocol options are compatible. UseMediaStreams
		// requires at least ProtocolVersion2.

		_, ok := negotiateProtocolVersion(
			announcementProperties.ProtocolVersion,
			offerProperties.ProtocolVersion,
			offerEntry.offer.UseMediaStreams)
		if !ok {
			continue
		}

		// Disallow matching the same country and ASN, or GeoIP combinations
		// prohibited by the AllowMatch callback, except for personal
		// compartment ID matches.
		//
		// For common matching, hopping through the same ISP is assumed to
		// have no circumvention benefit. For personal matching, the user may
		// wish to hop their their own or their friend's proxy regardless.

		if isCommonCompartments {
			if !GetAllowCommonASNMatching() &&
				(offerProperties.GeoIPData.Country ==
					announcementProperties.GeoIPData.Country &&
					offerProperties.GeoIPData.ASN ==
						announcementProperties.GeoIPData.ASN) {
				continue
			}
			if !m.config.AllowMatch(
				announcementProperties.GeoIPData,
				offerProperties.GeoIPData) {
				continue
			}
		}

		// Check if this is a preferred NAT match. Ultimately, a match may be
		// made with potentially incompatible NATs, but the client/proxy
		// reported NAT types may be incorrect or unknown; the client will
		// often skip NAT discovery.

		matchNAT := offerProperties.IsPreferredNATMatch(announcementProperties)

		// Use proxy ASN quality as an alternative to preferred NAT matches.
		//
		// The NAT matching logic depends on RFC5780 NAT discovery test
		// results, which may not be entirely accurate, and may not be
		// available in the first place, especially if skipped for clients,
		// which is the default.
		//
		// Proxy ASN quality leverages the quality data, provided by servers,
		// indicating that the particular proxy recently relayed a successful
		// tunnel for some client in the given ASN. When this quality data is
		// present, NAT compatibility is assumed, with the caveat that the
		// client device and immediate router may not be the same.
		//
		// Limitations:
		// - existsPreferredNATMatch doesn't reflect existence of matching
		//   proxy ASN quality, so the NAT match probe can end prematurely.
		// - IsPreferredNATMatch currently takes precedence over proxy ASN
		//   quality.

		if !matchNAT && isPriority {
			matchNAT = m.config.ProxyQualityState.HasQuality(
				announcementEntry.announcement.ProxyID,
				announcementEntry.announcement.Properties.GeoIPData.ASN,
				offerProperties.GeoIPData.ASN)
		}

		// At this point, the candidate is a match. Determine if this is a new
		// best match, either if there was no previous match, or this is a
		// better NAT match.

		if bestMatch == nil || (!bestMatchNAT && matchNAT) {

			bestMatch = announcementEntry
			bestMatchIndex = candidateIndex
			bestMatchIsPriority = isPriority
			bestMatchNAT = matchNAT
		}

		// Stop as soon as we have the best possible match, or have reached
		// the probe limit for preferred NAT matches.

		if bestMatch != nil && (bestMatchNAT ||
			!existsPreferredNATMatch ||
			candidateIndex-bestMatchIndex >= matcherMaxPreferredNATProbe) {

			break
		}
	}

	return bestMatch, bestMatchIndex
}

// applyLoadLimit checks if the broker process is in the load limiting state
// and, in order to reduce load, determines if new proxy announces or client
// offers should be rejected immediately instead of enqueued.
func (m *Matcher) applyLoadLimit(isAnnouncement bool) error {

	if m.config.IsLoadLimiting == nil || !m.config.IsLoadLimiting() {
		return nil
	}

	// Acquire the queue locks only when in the load limit state, and in the
	// same order as matchAllOffers.

	m.announcementQueueMutex.Lock()
	defer m.announcementQueueMutex.Unlock()
	m.offerQueueMutex.Lock()
	defer m.offerQueueMutex.Unlock()

	announcementLen := m.announcementQueue.getLen()
	offerLen := m.offerQueue.Len()

	// When the load limit had been reached, and assuming the broker process
	// is running only an in-proxy broker, it's likely, in practise, that
	// only one of the two queues has hundreds of thousands of entries while
	// the other has few, and there are no matches clearing the queue.
	//
	// Instead of simply rejecting all enqueue requests, allow the request
	// type, announce or offer, that is in shorter supply as these are likely
	// to match and draw down the larger queue. This attempts to make
	// productive use of enqueued items, and also attempts to avoid simply
	// emptying both queues -- as will happen in any case due to timeouts --
	// and then have the same larger queue refill again after the load limit
	// state exits.
	//
	// This approach assumes some degree of slack in available system memory
	// and CPU in the load limiting state, similar to how the tunnel server
	// continues to operate existing tunnels in the same state.
	//
	// The heuristic below of allowing when less than half the size of the
	// larger queue puts a cap on the amount the shorter queue can continue
	// to grow in the load limiting state, in the worst case.
	//
	// Limitation: in some scenarios that are expected to be rare, it can
	// happen that allowed requests don't result in a match and memory
	// consumption continues to grow, leading to a broker process OOM kill.

	var allow bool
	if isAnnouncement {
		allow = announcementLen < offerLen/2
	} else {
		allow = offerLen < announcementLen/2
	}
	if allow {
		return nil
	}

	// Do not return a MatcherLimitError, as is done in applyIPLimits. A
	// MatcherLimitError results in a Response.Limited error response, which
	// causes a proxy to back off and a client to abort its dial; but in
	// neither case is the broker client reset. The error returned here will
	// result in a fast 404 response to the proxy or client, which will
	// instead trigger a broker client reset, and a chance of moving to a
	// different broker that is not overloaded.
	//
	// Limitation: the 404 response won't be distinguishable, in client or
	// proxy diagnostics, from other error conditions.
	//
	// TODO: add a new Response.LoadLimited flag which the proxy/client can
	// use use log a distinct error and also ensure that it doesn't reselect
	// the same broker again in the broker client reset random selection.

	return errors.TraceNew("load limited")
}

// MatcherLimitError is the error type returned by Announce or Offer when the
// caller has exceeded configured queue entry or rate limits.
type MatcherLimitError struct {
	err error
}

func NewMatcherLimitError(err error) *MatcherLimitError {
	return &MatcherLimitError{err: err}
}

func (e MatcherLimitError) Error() string {
	return e.err.Error()
}

// applyIPLimits checks per-proxy or per-client -- as determined by peer IP
// address -- rate limits and queue entry limits.
func (m *Matcher) applyIPLimits(isAnnouncement bool, limitIP string, proxyID ID) error {

	// Assumes m.announcementQueueMutex or m.offerQueueMutex is locked.

	var entryCountByIP map[string]int
	var queueRateLimiters *lrucache.Cache
	var limitEntryCount int
	var quantity int
	var interval time.Duration

	if isAnnouncement {

		// Skip limit checks for non-limited proxies.
		if _, ok := m.announcementNonlimitedProxyIDs[proxyID]; ok {
			return nil
		}

		entryCountByIP = m.announcementQueueEntryCountByIP
		queueRateLimiters = m.announcementQueueRateLimiters
		limitEntryCount = m.announcementLimitEntryCount
		quantity = m.announcementRateLimitQuantity
		interval = m.announcementRateLimitInterval

	} else {
		entryCountByIP = m.offerQueueEntryCountByIP
		queueRateLimiters = m.offerQueueRateLimiters
		limitEntryCount = m.offerLimitEntryCount
		quantity = m.offerRateLimitQuantity
		interval = m.offerRateLimitInterval
	}

	// The rate limit is checked first, before the max count check, to ensure
	// that the rate limit state is updated regardless of the max count check
	// outcome.

	if quantity > 0 && interval > 0 {

		var rateLimiter *rate.Limiter

		entry, ok := queueRateLimiters.Get(limitIP)
		if ok {
			rateLimiter = entry.(*rate.Limiter)
		} else {
			limit := float64(quantity) / interval.Seconds()
			rateLimiter = rate.NewLimiter(rate.Limit(limit), quantity)
			queueRateLimiters.Set(
				limitIP, rateLimiter, interval)
		}

		if !rateLimiter.Allow() {
			return errors.Trace(
				NewMatcherLimitError(std_errors.New("rate exceeded for IP")))
		}
	}

	if limitEntryCount > 0 {

		// Limitation: non-limited proxy ID entries are counted in
		// entryCountByIP. If both a limited and non-limited proxy ingress
		// from the same limitIP, then the non-limited entries will count
		// against the limited proxy's limitEntryCount.

		entryCount, ok := entryCountByIP[limitIP]
		if ok && entryCount >= limitEntryCount {
			return errors.Trace(
				NewMatcherLimitError(std_errors.New("max entries for IP")))
		}
	}

	return nil
}

func (m *Matcher) addAnnouncementEntry(announcementEntry *announcementEntry) error {

	m.announcementQueueMutex.Lock()
	defer m.announcementQueueMutex.Unlock()

	// Ensure the queue doesn't grow larger than the max size.
	if m.announcementQueue.getLen() >= matcherAnnouncementQueueMaxSize {
		return errors.TraceNew("queue full")
	}

	// Ensure no single peer IP can enqueue a large number of entries or
	// rapidly enqueue beyond the configured rate.
	isAnnouncement := true
	err := m.applyIPLimits(
		isAnnouncement, announcementEntry.limitIP, announcementEntry.announcement.ProxyID)
	if err != nil {
		return errors.Trace(err)
	}

	// announcementEntry.queueReference should be uninitialized.
	// announcementMultiQueue.enqueue sets queueReference to be used for
	// efficient dequeuing.

	if announcementEntry.queueReference.entry != nil {
		return errors.TraceNew("unexpected queue reference")
	}

	err = m.announcementQueue.enqueue(announcementEntry)
	if err != nil {
		return errors.Trace(err)
	}

	m.announcementQueueEntryCountByIP[announcementEntry.limitIP] += 1

	select {
	case m.matchSignal <- struct{}{}:
	default:
	}

	return nil
}

func (m *Matcher) removeAnnouncementEntry(aborting bool, announcementEntry *announcementEntry) {

	// In the aborting case, the queue isn't already locked. Otherwise, assume
	// it is locked.
	if aborting {
		m.announcementQueueMutex.Lock()
		defer m.announcementQueueMutex.Unlock()
	}

	found := announcementEntry.queueReference.dequeue()

	if found {
		// Adjust entry counts by peer IP, used to enforce
		// matcherAnnouncementQueueMaxEntriesPerIP.
		m.announcementQueueEntryCountByIP[announcementEntry.limitIP] -= 1
		if m.announcementQueueEntryCountByIP[announcementEntry.limitIP] == 0 {
			delete(m.announcementQueueEntryCountByIP, announcementEntry.limitIP)
		}
	}

	if aborting && !found {

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

func (m *Matcher) addOfferEntry(offerEntry *offerEntry) error {

	m.offerQueueMutex.Lock()
	defer m.offerQueueMutex.Unlock()

	// Ensure the queue doesn't grow larger than the max size.
	if m.offerQueue.Len() >= matcherOfferQueueMaxSize {
		return errors.TraceNew("queue full")
	}

	// Ensure no single peer IP can enqueue a large number of entries or
	// rapidly enqueue beyond the configured rate.
	isAnnouncement := false
	err := m.applyIPLimits(
		isAnnouncement, offerEntry.limitIP, ID{})
	if err != nil {
		return errors.Trace(err)
	}

	// offerEntry.queueReference should be uninitialized and is set here to be
	// used for efficient dequeuing.

	if offerEntry.queueReference != nil {
		return errors.TraceNew("unexpected queue reference")
	}

	offerEntry.queueReference = m.offerQueue.PushBack(offerEntry)

	m.offerQueueEntryCountByIP[offerEntry.limitIP] += 1

	select {
	case m.matchSignal <- struct{}{}:
	default:
	}

	return nil
}

func (m *Matcher) removeOfferEntry(aborting bool, offerEntry *offerEntry) {

	// In the aborting case, the queue isn't already locked. Otherise, assume
	// it is locked.
	if aborting {
		m.offerQueueMutex.Lock()
		defer m.offerQueueMutex.Unlock()
	}

	if offerEntry.queueReference == nil {
		return
	}

	m.offerQueue.Remove(offerEntry.queueReference)

	offerEntry.queueReference = nil

	// Adjust entry counts by peer IP, used to enforce
	// matcherOfferQueueMaxEntriesPerIP.
	m.offerQueueEntryCountByIP[offerEntry.limitIP] -= 1
	if m.offerQueueEntryCountByIP[offerEntry.limitIP] == 0 {
		delete(m.offerQueueEntryCountByIP, offerEntry.limitIP)
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

func getRateLimitIP(strIP string) string {

	IP := net.ParseIP(strIP)
	if IP == nil || IP.To4() != nil {
		return strIP
	}

	// With IPv6, individual users or sites are users commonly allocated a /64
	// or /56, so rate limit by /56.
	return IP.Mask(net.CIDRMask(56, 128)).String()
}

// announcementMultiQueue is a set of announcement queues, one per common or
// personal compartment ID, providing efficient iteration over announcements
// matching a specified list of compartment IDs. announcementMultiQueue and
// its underlying data structures are not safe for concurrent access.
type announcementMultiQueue struct {
	priorityCommonCompartmentQueues map[ID]*announcementCompartmentQueue
	commonCompartmentQueues         map[ID]*announcementCompartmentQueue
	personalCompartmentQueues       map[ID]*announcementCompartmentQueue
	totalEntries                    int
}

// announcementCompartmentQueue is a single compartment queue within an
// announcementMultiQueue. The queue is implemented using a doubly-linked
// list, which provides efficient insert and mid-queue dequeue operations.
// The announcementCompartmentQueue also records NAT type stats for enqueued
// announcements, which are used, when matching, to determine when better NAT
// matches may be possible.
type announcementCompartmentQueue struct {
	isCommonCompartment      bool
	isPriority               bool
	compartmentID            ID
	entries                  *list.List
	unlimitedNATCount        int
	partiallyLimitedNATCount int
	strictlyLimitedNATCount  int
}

// announcementMatchIterator represents the state of an iteration over a
// subset of announcementMultiQueue compartment queues. Concurrent
// announcementMatchIterators are not supported.
type announcementMatchIterator struct {
	multiQueue        *announcementMultiQueue
	compartmentQueues []*announcementCompartmentQueue
	compartmentIDs    []ID
	nextEntries       []*list.Element
}

// announcementQueueReference represents the queue position for a given
// announcement entry, and provides an efficient dequeue operation.
type announcementQueueReference struct {
	multiQueue       *announcementMultiQueue
	compartmentQueue *announcementCompartmentQueue
	entry            *list.Element
}

func newAnnouncementMultiQueue() *announcementMultiQueue {
	return &announcementMultiQueue{
		priorityCommonCompartmentQueues: make(map[ID]*announcementCompartmentQueue),
		commonCompartmentQueues:         make(map[ID]*announcementCompartmentQueue),
		personalCompartmentQueues:       make(map[ID]*announcementCompartmentQueue),
	}
}

func (q *announcementMultiQueue) getLen() int {
	return q.totalEntries
}

func (q *announcementMultiQueue) enqueue(announcementEntry *announcementEntry) error {

	// Assumes announcementEntry not already enueued.

	// Limitation: only one compartment ID, either common or personal, is
	// supported per announcement entry. In the common compartment case, the
	// broker currently assigns only one common compartment ID per proxy
	// announcement. In the personal compartment case, there is currently no
	// use case for allowing a proxy to announce under multiple personal
	// compartment IDs.
	//
	// To overcome this limitation, the dequeue operation would need to be
	// able to remove an announcement entry from multiple
	// announcementCompartmentQueues.

	commonCompartmentIDs := announcementEntry.announcement.Properties.CommonCompartmentIDs
	personalCompartmentIDs := announcementEntry.announcement.Properties.PersonalCompartmentIDs

	if len(commonCompartmentIDs)+len(personalCompartmentIDs) != 1 {
		return errors.TraceNew("announcement must specify exactly one compartment ID")
	}

	isPriority := announcementEntry.announcement.Properties.IsPriority

	isCommonCompartment := true
	var compartmentID ID
	var compartmentQueues map[ID]*announcementCompartmentQueue
	if len(commonCompartmentIDs) > 0 {
		compartmentID = commonCompartmentIDs[0]
		compartmentQueues = q.commonCompartmentQueues
		if isPriority {
			compartmentQueues = q.priorityCommonCompartmentQueues
		}
	} else {
		isCommonCompartment = false
		compartmentID = personalCompartmentIDs[0]
		compartmentQueues = q.personalCompartmentQueues
		if isPriority {
			return errors.TraceNew("priority not supported for personal compartments")
		}
	}

	compartmentQueue, ok := compartmentQueues[compartmentID]
	if !ok {
		compartmentQueue = &announcementCompartmentQueue{
			isCommonCompartment: isCommonCompartment,
			isPriority:          isPriority,
			compartmentID:       compartmentID,
			entries:             list.New(),
		}
		compartmentQueues[compartmentID] = compartmentQueue
	}

	entry := compartmentQueue.entries.PushBack(announcementEntry)

	// Update the NAT type counts which are used to determine if a better NAT
	// match may be made by inspecting more announcement queue entries.

	switch announcementEntry.announcement.Properties.EffectiveNATType().Traversal() {
	case NATTraversalUnlimited:
		compartmentQueue.unlimitedNATCount += 1
	case NATTraversalPartiallyLimited:
		compartmentQueue.partiallyLimitedNATCount += 1
	case NATTraversalStrictlyLimited:
		compartmentQueue.strictlyLimitedNATCount += 1
	}

	q.totalEntries += 1

	announcementEntry.queueReference = announcementQueueReference{
		multiQueue:       q,
		compartmentQueue: compartmentQueue,
		entry:            entry,
	}

	return nil
}

// announcementQueueReference returns false if the item is already dequeued.
func (r *announcementQueueReference) dequeue() bool {

	if r.entry == nil {
		// Already dequeued.
		return false
	}

	announcementEntry := r.entry.Value.(*announcementEntry)

	// Reverse the NAT type counts.
	switch announcementEntry.announcement.Properties.EffectiveNATType().Traversal() {
	case NATTraversalUnlimited:
		r.compartmentQueue.unlimitedNATCount -= 1
	case NATTraversalPartiallyLimited:
		r.compartmentQueue.partiallyLimitedNATCount -= 1
	case NATTraversalStrictlyLimited:
		r.compartmentQueue.strictlyLimitedNATCount -= 1
	}

	r.compartmentQueue.entries.Remove(r.entry)

	if r.compartmentQueue.entries.Len() == 0 {
		// Remove empty compartment queue.
		queues := r.multiQueue.personalCompartmentQueues
		if r.compartmentQueue.isCommonCompartment {
			if r.compartmentQueue.isPriority {
				queues = r.multiQueue.priorityCommonCompartmentQueues

			} else {
				queues = r.multiQueue.commonCompartmentQueues
			}
		}
		delete(queues, r.compartmentQueue.compartmentID)
	}

	r.multiQueue.totalEntries -= 1

	// Mark as dequeued.
	r.entry = nil

	return true
}

func (q *announcementMultiQueue) startMatching(
	isCommonCompartments bool,
	compartmentIDs []ID) *announcementMatchIterator {

	iter := &announcementMatchIterator{
		multiQueue: q,
	}

	// Find the matching compartment queues and initialize iteration over
	// those queues. Building the set of matching queues is a linear time
	// operation, bounded by the length of compartmentIDs (no more than
	// maxCompartmentIDs, as enforced in
	// ClientOfferRequest.ValidateAndGetLogFields).

	// Priority queues, when in use, must all be added to the beginning of
	// iter.compartmentQueues in order to ensure that the iteration logic in
	// getNext visits all priority items first.

	var compartmentQueuesList []map[ID]*announcementCompartmentQueue
	if isCommonCompartments {
		compartmentQueuesList = append(
			compartmentQueuesList,
			q.priorityCommonCompartmentQueues,
			q.commonCompartmentQueues)
	} else {
		compartmentQueuesList = append(
			compartmentQueuesList,
			q.personalCompartmentQueues)
	}

	for _, compartmentQueues := range compartmentQueuesList {
		for _, ID := range compartmentIDs {
			if compartmentQueue, ok := compartmentQueues[ID]; ok {
				iter.compartmentQueues = append(iter.compartmentQueues, compartmentQueue)
				iter.compartmentIDs = append(iter.compartmentIDs, ID)
				iter.nextEntries = append(iter.nextEntries, compartmentQueue.entries.Front())
			}
		}
	}

	return iter
}

func (iter *announcementMatchIterator) getNATCounts() (int, int, int) {

	// Return the count of NAT types across all matchable compartment queues.
	//
	// A potential future enhancement would be to provide per-queue NAT counts
	// or NAT type indexing in order to quickly find preferred NAT matches.

	unlimitedNATCount := 0
	partiallyLimitedNATCount := 0
	strictlyLimitedNATCount := 0

	for _, compartmentQueue := range iter.compartmentQueues {
		unlimitedNATCount += compartmentQueue.unlimitedNATCount
		partiallyLimitedNATCount += compartmentQueue.partiallyLimitedNATCount
		strictlyLimitedNATCount += compartmentQueue.strictlyLimitedNATCount
	}

	return unlimitedNATCount, partiallyLimitedNATCount, strictlyLimitedNATCount
}

// announcementMatchIterator returns the next announcement entry candidate in
// compartment queue FIFO order, selecting the queue with the oldest head
// item.
//
// The caller should invoke announcementEntry.queueReference.dequeue when the
// candidate is selected. dequeue may be called on any getNext return value
// without disrupting the iteration state; however,
// announcementEntry.queueReference.dequeue calls for arbitrary queue entries
// are not supported during iteration. Iteration and dequeue should all be
// performed with a lock over the entire announcementMultiQueue, and with
// only one concurrent announcementMatchIterator.
//
// getNext returns a nil *announcementEntry when there are no more items.
// getNext also returns an isPriority flag, indicating the announcement is a
// priority candidate. All priority candidates are guaranteed to be returned
// before any non-priority candidates.
func (iter *announcementMatchIterator) getNext() (*announcementEntry, bool) {

	// Assumes announcements are enqueued in announcementEntry.ctx.Deadline
	// order. Also assumes that any priority queues are all at the front of
	// iter.compartmentQueues.

	// Select the oldest item, by deadline, from all the candidate queue head
	// items. This operation is linear in the number of matching compartment
	// ID queues, which is currently bounded by the length of matching
	// compartment IDs (no more than maxCompartmentIDs, as enforced in
	// ClientOfferRequest.ValidateAndGetLogFields).
	//
	// When there are priority candidates, they are selected first, regardless
	// of the deadlines of non-priority candidates. Multiple priority
	// candidates are processed in FIFO deadline order.
	//
	// A potential future enhancement is to add more iterator state to track
	// which queue has the next oldest time to select on the following
	// getNext call. Another potential enhancement is to remove fully
	// consumed queues from compartmentQueues/compartmentIDs/nextEntries.

	var selectedCandidate *announcementEntry
	selectedIndex := -1
	selectedPriority := false

	for i := 0; i < len(iter.compartmentQueues); i++ {
		if iter.nextEntries[i] == nil {
			continue
		}
		isPriority := iter.compartmentQueues[i].isPriority
		if selectedPriority && !isPriority {
			// Ignore older of non-priority entries when there are priority
			// candidates.
			break
		}
		if selectedCandidate == nil {
			selectedCandidate = iter.nextEntries[i].Value.(*announcementEntry)
			selectedIndex = i
			selectedPriority = isPriority
		} else {
			candidate := iter.nextEntries[i].Value.(*announcementEntry)
			deadline, deadlineOk := candidate.ctx.Deadline()
			selectedDeadline, selectedDeadlineOk := selectedCandidate.ctx.Deadline()
			if deadlineOk && selectedDeadlineOk && deadline.Before(selectedDeadline) {
				selectedCandidate = candidate
				selectedIndex = i
				selectedPriority = isPriority
			}
		}
	}

	// Advance the selected queue to the next element. This must be done
	// before any dequeue call, since container/list.remove clears
	// list.Element.next.
	if selectedIndex != -1 {
		iter.nextEntries[selectedIndex] = iter.nextEntries[selectedIndex].Next()
	}

	return selectedCandidate, selectedPriority
}
