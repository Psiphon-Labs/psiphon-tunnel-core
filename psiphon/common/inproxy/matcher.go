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
	std_errors "errors"
	"net"
	"sync"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	lrucache "github.com/cognusion/go-cache-lru"
	"github.com/gammazero/deque"
	"github.com/juju/ratelimit"
	"github.com/pion/webrtc/v3"
)

// TTLs should be aligned with STUN hole punch lifetimes.

const (
	matcherAnnouncementQueueMaxSize = 5000000
	matcherOfferQueueMaxSize        = 5000000
	matcherPendingAnswersTTL        = 30 * time.Second
	matcherPendingAnswersMaxSize    = 100000

	matcherRateLimiterReapHistoryFrequencySeconds = 300
	matcherRateLimiterMaxCacheEntries             = 1000000
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
// A client may opt form personal-only matching by not supplying any common
// compartment IDs.
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
	announcementQueueEntryCountByIP             map[string]int
	announcementQueueRateLimiters               *lrucache.Cache
	announcementLimitEntryCount                 int
	announcementRateLimitQuantity               int
	announcementRateLimitInterval               time.Duration
	announcementNonlimitedProxyIDs              map[ID]struct{}
	announcementsPersonalCompartmentalizedCount int
	announcementsUnlimitedNATCount              int
	announcementsPartiallyLimitedNATCount       int
	announcementsStrictlyLimitedNATCount        int

	// The offer queue is also implicitly sorted by offer age. Both an offer
	// and announcement queue are required since either announcements or
	// offers can arrive while there are no available pairings.

	offerQueueMutex          sync.Mutex
	offerQueue               *deque.Deque[*offerEntry]
	offerQueueEntryCountByIP map[string]int
	offerQueueRateLimiters   *lrucache.Cache
	offerLimitEntryCount     int
	offerRateLimitQuantity   int
	offerRateLimitInterval   time.Duration

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
	DoDTLSRandomization         bool
	TrafficShapingParameters    *DataChannelTrafficShapingParameters
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
	limitIP      string
	announcement *MatchAnnouncement
	offerChan    chan *MatchOffer
}

// offerEntry is an offer queue entry, an offer with its associated lifetime
// context and signaling channel.
type offerEntry struct {
	ctx        context.Context
	limitIP    string
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

	// Accouncement queue limits.
	AnnouncementLimitEntryCount    int
	AnnouncementRateLimitQuantity  int
	AnnouncementRateLimitInterval  time.Duration
	AnnouncementNonlimitedProxyIDs []ID

	// Offer queue limits.
	OfferLimitEntryCount   int
	OfferRateLimitQuantity int
	OfferRateLimitInterval time.Duration
}

// NewMatcher creates a new Matcher.
func NewMatcher(config *MatcherConfig) *Matcher {

	m := &Matcher{
		config: config,

		waitGroup: new(sync.WaitGroup),

		announcementQueue:               deque.New[*announcementEntry](),
		announcementQueueEntryCountByIP: make(map[string]int),
		announcementQueueRateLimiters: lrucache.NewWithLRU(
			0,
			time.Duration(matcherRateLimiterReapHistoryFrequencySeconds)*time.Second,
			matcherRateLimiterMaxCacheEntries),

		offerQueue:               deque.New[*offerEntry](),
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
// The offer is sent to the proxy by the broker, and then the proxy sends its
// answer back to the broker, which calls Answer with that value.
func (m *Matcher) Announce(
	ctx context.Context,
	proxyIP string,
	proxyAnnouncement *MatchAnnouncement) (*MatchOffer, error) {

	announcementEntry := &announcementEntry{
		ctx:          ctx,
		limitIP:      getRateLimitIP(proxyIP),
		announcement: proxyAnnouncement,
		offerChan:    make(chan *MatchOffer, 1),
	}

	err := m.addAnnouncementEntry(announcementEntry)
	if err != nil {
		return nil, errors.Trace(err)
	}

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
	clientIP string,
	clientOffer *MatchOffer) (*MatchAnswer, *MatchAnnouncement, error) {

	offerEntry := &offerEntry{
		ctx:        ctx,
		limitIP:    getRateLimitIP(clientIP),
		offer:      clientOffer,
		answerChan: make(chan *answerInfo, 1),
	}

	err := m.addOfferEntry(offerEntry)
	if err != nil {
		return nil, nil, errors.Trace(err)
	}

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

	i := 0
	end := m.offerQueue.Len()

	for i < end && m.announcementQueue.Len() > 0 {

		offerEntry := m.offerQueue.At(i)

		// Skip and remove this offer if its deadline has already passed.
		// There is no signal to the awaiting Offer function, as it will exit
		// based on the same ctx.

		if offerEntry.ctx.Err() != nil {
			m.removeOfferEntryByIndex(i)
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

		// Remove the matched announcement from the queue. Send the offer to
		// the announcement entry's offerChan, which will deliver it to the
		// blocked Announce call. Add a pending answers entry to await the
		// proxy's follow up Answer call. The TTL for the pending answer
		// entry is set to the matched Offer call's ctx, as the answer is
		// only useful as long as the client is still waiting.

		announcementEntry := m.announcementQueue.At(j)

		if m.config.Logger.IsLogLevelDebug() {

			announcementProxyID :=
				announcementEntry.announcement.ProxyID
			announcementConnectionID :=
				announcementEntry.announcement.ConnectionID
			announcementCommonCompartmentIDs :=
				announcementEntry.announcement.Properties.CommonCompartmentIDs
			offerCommonCompartmentIDs :=
				offerEntry.offer.Properties.CommonCompartmentIDs

			m.config.Logger.WithTraceFields(common.LogFields{
				"announcement_proxy_id":               announcementProxyID,
				"announcement_connection_id":          announcementConnectionID,
				"announcement_common_compartment_ids": announcementCommonCompartmentIDs,
				"offer_common_compartment_ids":        offerCommonCompartmentIDs,
				"match_index":                         j,
				"announcement_queue_size":             m.announcementQueue.Len(),
				"offer_queue_size":                    m.offerQueue.Len(),
			}).Debug("match metrics")
		}

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

		m.removeAnnouncementEntryByIndex(j)

		// Remove the matched offer from the queue and match the next offer,
		// now first in the queue.

		m.removeOfferEntryByIndex(i)

		end -= 1
	}
}

func (m *Matcher) matchOffer(offerEntry *offerEntry) (int, bool) {

	// Assumes the caller has the queue mutexed locked.

	// Check each announcement in turn, and select a match. There is an
	// implicit preference for older proxy announcments, sooner to timeout, at the
	// front of the queue.
	//
	// Limitation: since this logic matches each enqueued client in turn, it will
	// only make the optimal NAT match for the oldest enqueued client vs. all
	// proxies, and not do optimal N x M matching for all clients and all proxies.
	//
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
			m.removeAnnouncementEntryByIndex(i)
			end -= 1
			continue
		}

		announcementProperties := &announcementEntry.announcement.Properties

		// There must be a compartment match. If there is a personal
		// compartment match, this match will be preferred.

		matchCommonCompartment := HaveCommonIDs(
			announcementProperties.CommonCompartmentIDs, offerProperties.CommonCompartmentIDs)
		matchPersonalCompartment := HaveCommonIDs(
			announcementProperties.PersonalCompartmentIDs, offerProperties.PersonalCompartmentIDs)
		if !matchCommonCompartment && !matchPersonalCompartment {
			continue
		}

		// Disallow matching the same country and ASN, except for personal
		// compartment ID matches.
		//
		// For common matching, hopping through the same ISP is assumed to
		// have no circumvention benefit. For personal matching, the user may
		// wish to hop their their own or their friend's proxy regardless.

		if !matchPersonalCompartment &&
			!GetAllowCommonASNMatching() &&
			(offerProperties.GeoIPData.Country ==
				announcementProperties.GeoIPData.Country &&
				offerProperties.GeoIPData.ASN ==
					announcementProperties.GeoIPData.ASN) {
			continue
		}

		// Check if this is a preferred NAT match. Ultimately, a match may be
		// made with potentially incompatible NATs, but the client/proxy
		// reported NAT types may be incorrect or unknown; the client will
		// often skip NAT discovery.

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
			(matchPersonalCompartment ||
				m.announcementsPersonalCompartmentalizedCount == 0 ||
				len(offerProperties.PersonalCompartmentIDs) == 0) {
			break
		}
	}

	return bestMatch, bestMatch != -1
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

func (m *Matcher) applyLimits(isAnnouncement bool, limitIP string, proxyID ID) error {

	// Assumes the m.announcementQueueMutex or m.offerQueue mutex is locked.

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

		var rateLimiter *ratelimit.Bucket

		entry, ok := queueRateLimiters.Get(limitIP)
		if ok {
			rateLimiter = entry.(*ratelimit.Bucket)
		} else {
			rateLimiter = ratelimit.NewBucketWithQuantum(
				interval, int64(quantity), int64(quantity))
			queueRateLimiters.Set(
				limitIP, rateLimiter, interval)
		}

		if rateLimiter.TakeAvailable(1) < 1 {
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
	if m.announcementQueue.Len() >= matcherAnnouncementQueueMaxSize {
		return errors.TraceNew("queue full")
	}

	// Ensure no single peer IP can enqueue a large number of entries or
	// rapidly enqueue beyond the configured rate.
	isAnnouncement := true
	err := m.applyLimits(
		isAnnouncement, announcementEntry.limitIP, announcementEntry.announcement.ProxyID)
	if err != nil {
		return errors.Trace(err)
	}

	m.announcementQueue.PushBack(announcementEntry)

	m.announcementQueueEntryCountByIP[announcementEntry.limitIP] += 1

	m.adjustAnnouncementCounts(announcementEntry, 1)

	select {
	case m.matchSignal <- struct{}{}:
	default:
	}

	return nil
}

func (m *Matcher) removeAnnouncementEntry(announcementEntry *announcementEntry) {

	m.announcementQueueMutex.Lock()
	defer m.announcementQueueMutex.Unlock()

	found := false
	for i := 0; i < m.announcementQueue.Len(); i++ {
		if m.announcementQueue.At(i) == announcementEntry {
			m.removeAnnouncementEntryByIndex(i)
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

func (m *Matcher) removeAnnouncementEntryByIndex(i int) {

	// Assumes s.announcementQueueMutex lock is held.

	announcementEntry := m.announcementQueue.At(i)

	// This should be only direct call to Remove, as following adjustments
	// must always be made when removing.
	m.announcementQueue.Remove(i)

	// Adjust entry counts by peer IP, used to enforce
	// matcherAnnouncementQueueMaxEntriesPerIP.
	m.announcementQueueEntryCountByIP[announcementEntry.limitIP] -= 1
	if m.announcementQueueEntryCountByIP[announcementEntry.limitIP] == 0 {
		delete(m.announcementQueueEntryCountByIP, announcementEntry.limitIP)
	}

	m.adjustAnnouncementCounts(announcementEntry, -1)
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
	err := m.applyLimits(
		isAnnouncement, offerEntry.limitIP, ID{})
	if err != nil {
		return errors.Trace(err)
	}

	m.offerQueue.PushBack(offerEntry)

	m.offerQueueEntryCountByIP[offerEntry.limitIP] += 1

	select {
	case m.matchSignal <- struct{}{}:
	default:
	}

	return nil
}

func (m *Matcher) removeOfferEntry(offerEntry *offerEntry) {

	m.offerQueueMutex.Lock()
	defer m.offerQueueMutex.Unlock()

	for i := 0; i < m.offerQueue.Len(); i++ {
		if m.offerQueue.At(i) == offerEntry {
			m.removeOfferEntryByIndex(i)
			break
		}
	}
}

func (m *Matcher) removeOfferEntryByIndex(i int) {

	// Assumes s.offerQueueMutex lock is held.

	offerEntry := m.offerQueue.At(i)

	// This should be only direct call to Remove, as following adjustments
	// must always be made when removing.
	m.offerQueue.Remove(i)

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
