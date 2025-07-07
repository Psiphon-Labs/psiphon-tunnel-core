/*
 * Copyright (c) 2025, Psiphon Inc.
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
	"sync"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	lrucache "github.com/cognusion/go-cache-lru"
)

const (
	proxyQualityMaxEntries                 = 10000000
	proxyQualityTTL                        = 24 * time.Hour
	proxyQualityMaxPendingFailedMatches    = 1000000
	proxyQualityPendingFailedMatchDeadline = 5 * time.Minute
	proxyQualityFailedMatchThreshold       = 10
	proxyQualityReporterMaxQueueEntries    = 5000000
	proxyQualityReporterMaxRequestEntries  = 1000
	proxyQualityReporterRequestDelay       = 10 * time.Second
	proxyQualityReporterRequestTimeout     = 10 * time.Second
	proxyQualityReporterRequestRetries     = 1
)

// ProxyQualityState records and manages proxy tunnel quality data reported by
// servers and used to prioritize proxies in the broker matching process.
type ProxyQualityState struct {
	mutex                      sync.Mutex
	qualityTTL                 time.Duration
	pendingFailedMatchDeadline time.Duration
	failedMatchThreshold       int
	entries                    *lrucache.Cache
	pendingFailedMatches       *lrucache.Cache
}

type proxyQualityEntry struct {
	clientASNCounts  ProxyQualityASNCounts
	failedMatchCount int
}

// NewProxyQuality creates a new ProxyQualityState.
func NewProxyQuality() *ProxyQualityState {

	// Limitation: max cache sizes are not dynamically configurable and are
	// set to fixed values that are in line with other, indirectly related
	// limits, such as matcherAnnouncementQueueMaxSize.

	// TODO: lrucache.Cache.DeleteExpired is a linear scan; review the
	// performance of scanning up to 10,000,000 entries every 1 minute.

	q := &ProxyQualityState{
		qualityTTL:                 proxyQualityTTL,
		pendingFailedMatchDeadline: proxyQualityPendingFailedMatchDeadline,
		failedMatchThreshold:       proxyQualityFailedMatchThreshold,

		entries: lrucache.NewWithLRU(
			0, 1*time.Minute, proxyQualityMaxEntries),
		pendingFailedMatches: lrucache.NewWithLRU(
			0, 1*time.Minute, proxyQualityMaxPendingFailedMatches),
	}

	q.pendingFailedMatches.OnEvicted(q.addFailedMatch)

	return q
}

// SetProxyQualityRequestParameters overrides default values for proxy quality
// state management parameters.
//
// qualityTTL is the TTL for a proxy's quality entry. Each AddQuality call
// extends an entry's TTL.
//
// pendingFailedMatchDeadline is the elapsed time between calling Match for a
// given proxy, and subsequently incrementing that proxy's failed match
// count, unless an AddQuality call is made in the meantime.
//
// failedMatchThreshold is the threshold failed match count after which a
// proxy's quality entry is deleted.
func (q *ProxyQualityState) SetParameters(
	qualityTTL time.Duration,
	pendingFailedMatchDeadline time.Duration,
	failedMatchThreshold int) {

	q.mutex.Lock()
	defer q.mutex.Unlock()

	q.qualityTTL = qualityTTL
	q.pendingFailedMatchDeadline = pendingFailedMatchDeadline
	q.failedMatchThreshold = failedMatchThreshold
}

// HasQuality indicates if the specified proxy, defined by its ID and ASN, has
// a quality entry. If the input client ASN is blank, any entry suffices. If
// a client ASN is given the proxy must have a quality tunnel for a client in
// that ASN.
func (q *ProxyQualityState) HasQuality(
	proxyID ID, proxyASN string, clientASN string) bool {

	q.mutex.Lock()
	defer q.mutex.Unlock()

	proxyKey := MakeProxyQualityKey(proxyID, proxyASN)

	strProxyKey := string(proxyKey[:])

	entryValue, ok := q.entries.Get(strProxyKey)

	if !ok {
		return false
	}

	entry := entryValue.(*proxyQualityEntry)

	// Currently, the actual count value is not used; any count > 0
	// is "quality".

	if clientASN == "" {
		// No specific ASN.
		return len(entry.clientASNCounts) > 0
	}

	return entry.clientASNCounts[clientASN] > 0
}

// AddQuality adds a new quality entry or adds counts to an existing quality
// entry for the specified proxy, defined by its ID and ASN. For an existing
// entry, its TTL is extended, and any failed match count is reset to zero.
// AddQuality deletes any pending failed match, set by Matched, for the
// proxy.
func (q *ProxyQualityState) AddQuality(
	proxyKey ProxyQualityKey, counts ProxyQualityASNCounts) {

	q.mutex.Lock()
	defer q.mutex.Unlock()

	strProxyKey := string(proxyKey[:])

	entryValue, ok := q.entries.Get(strProxyKey)

	var entry *proxyQualityEntry
	if ok {
		entry = entryValue.(*proxyQualityEntry)
	} else {
		entry = &proxyQualityEntry{
			clientASNCounts: make(ProxyQualityASNCounts),
		}
	}

	// Reset the consecutive failed match count for existing entry.
	entry.failedMatchCount = 0

	// Add in counts.
	for ASN, count := range counts {
		entry.clientASNCounts[ASN] += count
	}

	// Set both updates the value and extends the TTL for any existing entry.
	q.entries.Set(strProxyKey, entry, q.qualityTTL)

	// Delete any pending failed match. The actual pending match may still be
	// in progress and may even fail, but the new quality event is considered
	// sufficient to ignore that outcome.
	//
	// lrucache.Cache.Delete invokes OnEvicted, so OnEvicted is temporarily
	// cleared to avoid incrementing the failed match count. In addition,
	// avoiding OnEvicted here ensures that addFailedMatch can assume that
	// the mutex lock is not held.

	q.pendingFailedMatches.OnEvicted(nil)
	q.pendingFailedMatches.Delete(strProxyKey)
	q.pendingFailedMatches.OnEvicted(q.addFailedMatch)
}

// Matched reports that, for the specified proxy, defined by its ID and ASN, a
// proxy announcement was just matched with a client offer, and an announcement
// response returned to the proxy. Matched begins a "countdown" until a
// subsequent, expected AddQuality call for the same proxy: if too much time
// elapses with no AddQuality, the match is considered to have failed to
// produce a successful tunnel. After exceeding a threshold count of
// consecutive failed matches, a proxy's quality entry is deleted.
//
// Matched/AddQuality do not track the outcome of specific matches -- for a
// given proxy, any successful, quality tunnel will cancel any pending failed
// match.

func (q *ProxyQualityState) Matched(proxyID ID, proxyASN string) {
	q.mutex.Lock()
	defer q.mutex.Unlock()

	// This uses a lrucache.Cache and OnEvicted events as an implementation of
	// the failed match deadline without requiring a timer or goroutine per
	// pending match. When the cache entry expires due to TTL, the failed
	// match deadline is met.

	proxyKey := MakeProxyQualityKey(proxyID, proxyASN)

	strProxyKey := string(proxyKey[:])

	_, ok := q.pendingFailedMatches.Get(strProxyKey)
	if ok {
		// When there's already a pending failed match, leave the existing
		// deadline in place and don't extend it.
		return
	}

	q.pendingFailedMatches.Add(
		strProxyKey, struct{}{}, q.pendingFailedMatchDeadline)
}

// Flush clears all quality state.
func (q *ProxyQualityState) Flush() {

	q.mutex.Lock()
	defer q.mutex.Unlock()

	q.entries.Flush()

	q.pendingFailedMatches.OnEvicted(nil)
	q.pendingFailedMatches.Flush()
	q.pendingFailedMatches.OnEvicted(q.addFailedMatch)
}

// addFailedMatch is invoked when a pendingFailedMatches expires, increments
// the failed match count, and removes a quality entry when the failed match
// threshold count is exceeded.
func (q *ProxyQualityState) addFailedMatch(strProxyKey string, _ interface{}) {

	// Assumes pendingFailedMatches.OnEvicted is not invoked while already
	// holding the mutex lock.

	q.mutex.Lock()
	defer q.mutex.Unlock()

	entryValue, ok := q.entries.Get(strProxyKey)
	if !ok {
		// No quality to remove.
		return
	}

	entry := entryValue.(*proxyQualityEntry)

	entry.failedMatchCount += 1

	if entry.failedMatchCount >= q.failedMatchThreshold {
		// Remove quality.
		q.entries.Delete(strProxyKey)
	}
}

// ProxyQualityReporter manages sending proxy quality requests to brokers.
type ProxyQualityReporter struct {
	logger                  common.Logger
	serverBrokerSessions    *ServerBrokerSessions
	serverSessionPrivateKey SessionPrivateKey
	roundTripperMaker       ProxyQualityBrokerRoundTripperMaker

	runMutex    sync.Mutex
	runContext  context.Context
	stopRunning context.CancelFunc
	waitGroup   *sync.WaitGroup

	queueMutex        sync.Mutex
	reportQueue       *list.List
	proxyIDQueueEntry map[ProxyQualityKey]*list.Element

	brokerPublicKeys             atomic.Value
	brokerRootObfuscationSecrets atomic.Value
	requestDelay                 int64
	maxRequestEntries            int64
	requestTimeout               int64
	requestRetries               int64

	signalReport chan struct{}
}

// ProxyQualityBrokerRoundTripperMaker is a callback which creates a new
// RoundTripper for sending requests to the broker specified by the given
// session public key.
//
// The optional common.APIParameters are broker dial parameter metrics to be
// reported to the broker.
type ProxyQualityBrokerRoundTripperMaker func(SessionPublicKey) (
	RoundTripper, common.APIParameters, error)

type proxyQualityReportQueueEntry struct {
	proxyKey ProxyQualityKey
	counts   ProxyQualityASNCounts
}

type serverBrokerClient struct {
	publicKey             SessionPublicKey
	rootObfuscationSecret ObfuscationSecret
	brokerInitiatorID     ID
	sessions              *InitiatorSessions
	roundTripper          RoundTripper
	dialParams            common.APIParameters
}

// NewProxyQualityReporter creates a new ProxyQualityReporter.
//
// serverBrokerSessions is the server's ServerBrokerSessions instance which
// manages inbound reports from the broker; the ServerBrokerSessions is
// consulted to determine which brokers have recently communicated with the
// server, and are therefore expected to trust the server's public key.
//
// serverSessionPrivateKey is the server's session private key to be used in
// the quality reporting Noise sessions established with the brokers.
// brokerPublicKeys specify the brokers to send to.
//
// roundTripperMaker is a callback which creates RoundTrippers for these
// brokers. The ProxyQualityReporter will invoke roundTripperMaker when
// attempting to send requests to a given broker; each RoundTripper will be
// retained and reused as long as it continues to work successfully.
func NewProxyQualityReporter(
	logger common.Logger,
	serverBrokerSessions *ServerBrokerSessions,
	serverSessionPrivateKey SessionPrivateKey,
	brokerPublicKeys []SessionPublicKey,
	brokerRootObfuscationSecrets []ObfuscationSecret,
	roundTripperMaker ProxyQualityBrokerRoundTripperMaker) (
	*ProxyQualityReporter, error) {

	r := &ProxyQualityReporter{
		logger:                  logger,
		serverBrokerSessions:    serverBrokerSessions,
		serverSessionPrivateKey: serverSessionPrivateKey,
		roundTripperMaker:       roundTripperMaker,

		waitGroup: new(sync.WaitGroup),

		requestDelay:      int64(proxyQualityReporterRequestDelay),
		maxRequestEntries: proxyQualityReporterMaxRequestEntries,
		requestTimeout:    int64(proxyQualityReporterRequestTimeout),
		requestRetries:    proxyQualityReporterRequestRetries,

		reportQueue:       list.New(),
		proxyIDQueueEntry: make(map[ProxyQualityKey]*list.Element),

		signalReport: make(chan struct{}, 1),
	}

	err := r.SetKnownBrokers(brokerPublicKeys, brokerRootObfuscationSecrets)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return r, nil
}

// SetKnownBrokers updates the set of brokers to send to.
func (r *ProxyQualityReporter) SetKnownBrokers(
	brokerPublicKeys []SessionPublicKey,
	brokerRootObfuscationSecrets []ObfuscationSecret) error {

	if len(brokerPublicKeys) != len(brokerRootObfuscationSecrets) {
		return errors.TraceNew("invalid broker specs")
	}

	r.brokerPublicKeys.Store(brokerPublicKeys)
	r.brokerRootObfuscationSecrets.Store(brokerRootObfuscationSecrets)

	return nil
}

// SetRequestParameters overrides default values for request parameters.
func (r *ProxyQualityReporter) SetRequestParameters(
	maxRequestEntries int,
	requestDelay time.Duration,
	requestTimeout time.Duration,
	requestRetries int) {

	atomic.StoreInt64(&r.requestDelay, int64(requestDelay))
	atomic.StoreInt64(&r.maxRequestEntries, int64(maxRequestEntries))
	atomic.StoreInt64(&r.requestTimeout, int64(requestTimeout))
	atomic.StoreInt64(&r.requestRetries, int64(requestRetries))
}

// Start launches the request workers.
func (r *ProxyQualityReporter) Start() error {

	r.runMutex.Lock()
	defer r.runMutex.Unlock()

	if r.runContext != nil {
		return errors.TraceNew("already running")
	}

	r.runContext, r.stopRunning = context.WithCancel(context.Background())

	r.waitGroup.Add(1)
	go func() {
		defer r.waitGroup.Done()
		r.requestScheduler(r.runContext)
	}()

	return nil
}

// Stop terminates the request workers.
func (r *ProxyQualityReporter) Stop() {

	r.runMutex.Lock()
	defer r.runMutex.Unlock()

	r.stopRunning()
	r.waitGroup.Wait()
	r.runContext, r.stopRunning = nil, nil
}

// ReportQuality registers a quality tunnel for the specified proxy, defined
// by its ID and ASN, and client ASN. Broker requests are scheduled to be
// sent after a short delay -- intended to batch up additional data -- or
// once sufficient request data is accumulated.
func (r *ProxyQualityReporter) ReportQuality(
	proxyID ID, proxyASN string, clientASN string) {

	r.queueMutex.Lock()
	defer r.queueMutex.Unlock()

	proxyKey := MakeProxyQualityKey(proxyID, proxyASN)

	// Proxy quality data is stored in a FIFO queue. New reports are merged
	// into existing entries for that same proxy ID when possible.

	entry, ok := r.proxyIDQueueEntry[proxyKey]
	if ok {
		entry.Value.(proxyQualityReportQueueEntry).counts[clientASN] += 1
		return
	}

	// Sanity check against an unbounded queue. When the queue is full, new
	// reports are simply dropped. There is no back pressure to slow down the
	// rate of quality tunnels, since the overall goal is to establish
	// quality tunnels.
	if r.reportQueue.Len() >= proxyQualityReporterMaxQueueEntries {
		r.logger.WithTrace().Warning("proxyQualityReporterMaxQueueEntries exceeded")
		return
	}

	counts := make(ProxyQualityASNCounts)
	counts[clientASN] += 1

	entry = r.reportQueue.PushBack(
		proxyQualityReportQueueEntry{
			proxyKey: proxyKey,
			counts:   counts,
		})
	r.proxyIDQueueEntry[proxyKey] = entry

	// signalReport has a buffer size of 1, so when a signal can't be sent to
	// the channel, it's already signalled.
	select {
	case r.signalReport <- struct{}{}:
	default:
	}
}

func (r *ProxyQualityReporter) requestScheduler(ctx context.Context) {

	// Retain a set of serverBrokerClients, with established round trip
	// transports and Noise sessions, for reuse across many requests.
	// sendToBrokers will add to and trim this set.

	brokerClients := make(map[SessionPublicKey]*serverBrokerClient)

	for {

		// Await the signal that there is quality data to report.

		select {
		case <-r.signalReport:
		case <-ctx.Done():
			return
		}

		// Delay, for a brief moment, sending requests in an effort to batch
		// up more data for the requests.

		requestDelay := time.Duration(atomic.LoadInt64(&r.requestDelay))
		if requestDelay > 0 {

			// TODO: SleepWithContext creates and discards a timer per call;
			// instead reuse an inline timer?
			common.SleepWithContext(ctx, requestDelay)
		}

		// Loop and drain the quality data queue, sending the same payload to
		// each broker in each iteration. sendToBrokers performs the broker
		// requests in parallel, but sendToBrokers doesn't return until all
		// requests are complete, meaning no broker will get far ahead of any
		// other.
		//
		// If a certain broker request fails, including retries, that may
		// delay the overall schedule, up to requestTimeout * requestRetries.
		// Furthermore, after all retries fail, the failing broker simply does
		// never receives the payload.

		// Future enhancements:
		//
		// - Use a dynamic request timeout for failing brokers, to avoid
		//   repeatedly delaying every round when one broker persistently fails?
		//
		// - Consider skipping sending a quality payload if contains only the
		//   exact same proxy ID(s) and client ASNs reported in a very recent
		//   request? Currently, the quality _count_ values aren't used as
		//   distinguisher, so the primary benefit for sending additional
		//   counts for the same proxy ID and client ASN are TTL extensions
		//   in the ProxyQualityState.

		for {
			requestCounts := r.prepareNextRequest()

			if len(requestCounts) == 0 {
				break
			}

			r.sendToBrokers(ctx, brokerClients, requestCounts)
		}
	}
}

func (r *ProxyQualityReporter) prepareNextRequest() ProxyQualityRequestCounts {

	r.queueMutex.Lock()
	defer r.queueMutex.Unlock()

	// prepareNextRequest should not hold the mutex for a long period, as this
	// blocks ReportQuality, which in turn could block tunnel I/O operations.

	if r.reportQueue.Len() == 0 {
		return nil
	}

	counts := make(ProxyQualityRequestCounts)

	queueEntry := r.reportQueue.Front()

	// Limit the size of each request, capping both the memory overhead and
	// the amount of data lost in a temporary network disruption.
	//
	// Limitation: maxRequestEntries doesn't take into account the number of
	// different client ASN counts per entry. In practice, there shouldn't be
	// an excessive number of client ASNs.

	for queueEntry != nil && int64(len(counts)) < atomic.LoadInt64(&r.maxRequestEntries) {

		entry := queueEntry.Value.(proxyQualityReportQueueEntry)

		// Reuse queueEntry.counts rather than make a copy. As queueEntry is
		// removed from the queue here, this should be safe as no subsequent
		// ReportQuality will add to the same entry.

		counts[entry.proxyKey] = entry.counts

		removeEntry := queueEntry
		queueEntry = queueEntry.Next()

		r.reportQueue.Remove(removeEntry)
		delete(r.proxyIDQueueEntry, entry.proxyKey)
	}

	return counts
}

func (r *ProxyQualityReporter) sendToBrokers(
	ctx context.Context,
	brokerClients map[SessionPublicKey]*serverBrokerClient,
	requestCounts ProxyQualityRequestCounts) {

	// Iterate over the current list of brokers, as identified by the public
	// keys in brokerPublicKeys. For each broker, reuse any existing broker
	// client or create a new one. Spawns short term goroutine workers to
	// send requests to each broker in parallel, and await all worker
	// completion. Leave all working broker clients in place for future use,
	// but prune failed or unused broker clients from brokerClients. Assumes
	// only a handful of brokers.

	// This implementation is not using BrokerClient, the type used as the
	// proxy/client broker client, as BrokerClient uses a BrokerDialCoordinator
	// and is oriented to proxy/client functionality.

	var sendWaitGroup sync.WaitGroup

	var retainBrokerClientsMutex sync.Mutex
	retainBrokerClients := make(map[SessionPublicKey]struct{})

	brokerPublicKeys := r.brokerPublicKeys.Load().([]SessionPublicKey)
	brokerRootObfuscationSecrets := r.brokerRootObfuscationSecrets.Load().([]ObfuscationSecret)

	establishedBrokerIDs := r.serverBrokerSessions.sessions.GetEstablishedKnownInitiatorIDs()

	for i, brokerPublicKey := range brokerPublicKeys {

		// Get or create the brokerClient for brokerPublicKey.

		brokerClient, ok := brokerClients[brokerPublicKey]
		if !ok {

			initiatorID, err := brokerPublicKey.ToCurve25519()
			if err != nil {
				r.logger.WithTraceFields(
					common.LogFields{
						"brokerID": brokerPublicKey.String(),
						"error":    err.Error()},
				).Warning("ToCurve25519 failed")
				continue
			}

			brokerClient = &serverBrokerClient{
				publicKey:             brokerPublicKey,
				rootObfuscationSecret: brokerRootObfuscationSecrets[i],
				brokerInitiatorID:     ID(initiatorID),
			}

			// This partially initialized brokerClient will be retained even
			// if the following establishedBrokerIDs check fails, as this
			// caches the result of the ToCurve25519. The next sendToBrokers
			// call will check the same brokerPublicKey again -- unless
			// brokerPublicKeys changes.

			brokerClients[brokerPublicKey] = brokerClient
		}

		// Currently, brokers will only trust and allow proxy quality requests
		// from servers for which the broker has seen the corresponding
		// signed server entries as client proxy destinations. As such, the
		// following request is expected to fail unless the broker has
		// established a session with this server as indicated in
		// establishedBrokerIDs. Skip any broker that's not in
		// establishedBrokerIDs; those brokers will not receive this proxy
		// quality request payload.
		//
		// Mitigating factor: due to proxy affinity to a single broker, it's
		// likely that the proxy in any local ReportQuality call used and is
		// using a broker that has relayed a BrokerServerReport to this server.
		//
		// Future enhancement: the server could send its own signed server
		// entry to a broker, instead of relying on the broker to receive
		// that signed server entry in a client offer.

		if _, ok := establishedBrokerIDs[brokerClient.brokerInitiatorID]; !ok {

			// If there is a brokerClient for brokerPublicKey but the
			// establishedBrokerIDs check _no longer_ passes, remove and
			// garbage collect any round tripper and Noise session. The
			// remaining brokerClient is still retained, for the cached
			// ToCurve25519 conversion.

			brokerClient.sessions = nil
			if brokerClient.roundTripper != nil {
				// Close all network connections.
				brokerClient.roundTripper.Close()
			}
			brokerClient.roundTripper = nil

			retainBrokerClientsMutex.Lock()
			retainBrokerClients[brokerPublicKey] = struct{}{}
			retainBrokerClientsMutex.Unlock()

			continue
		}

		if brokerClient.sessions == nil {

			// Initialize the rest of the brokerClient: the round tripper and
			// the Noise session.
			//
			// Once initialized, these are retained after a successful round
			// trip, so that subsequent sendToBrokers calls can reuse the
			// existing, established network transport and Noise session.
			//
			// This implementation uses one Noise InitiatorSessions per
			// broker, instead of sharing a single instance, since
			// InitiatorSessions currently lacks an API to discard a
			// particular session.

			roundTripper, dialParams, err := r.roundTripperMaker(brokerPublicKey)
			if err != nil {
				r.logger.WithTraceFields(
					common.LogFields{
						"brokerID": brokerPublicKey.String(),
						"error":    err.Error()},
				).Warning("roundTripperMaker failed")
				continue
			}

			brokerClient.sessions = NewInitiatorSessions(r.serverSessionPrivateKey)
			brokerClient.roundTripper = roundTripper
			brokerClient.dialParams = dialParams
		}

		// Spawn a goroutine to send the request to this brokerClient.
		// Spawning goroutines for every request round should be efficient
		// enough, and avoids additional complexity in alternatives such as
		// maintaining long-running goroutine workers per broker.

		sendWaitGroup.Add(1)
		go func(brokerClient *serverBrokerClient) {
			defer sendWaitGroup.Done()

			retries := int(atomic.LoadInt64(&r.requestRetries))
			for i := 0; i <= retries; i++ {
				err := r.sendBrokerRequest(ctx, brokerClient, requestCounts)
				if err != nil {
					r.logger.WithTraceFields(
						common.LogFields{
							"brokerID": brokerClient.publicKey.String(),
							"error":    err.Error()},
					).Warning("sendBrokerRequest failed")
					if i < retries {
						// Try again.
						continue
					}
					// No more retries, and don't retain the brokerClient.
					return
				}
				// Exit the retry loop, and retain the successful brokerClient.
				break
			}

			// Retain the successful brokerClient.
			retainBrokerClientsMutex.Lock()
			retainBrokerClients[brokerClient.publicKey] = struct{}{}
			retainBrokerClientsMutex.Unlock()
		}(brokerClient)

	}

	// Await all request worker completion.
	//
	// Currently there is no backoff for brokers whose requests fail Unlike
	// proxies (and to some degree clients), there is only one concurrent
	// request, from this server, per broker, so there is less expectation of
	// hitting rate limiting by some intermediary, such as a CDN. The
	// requestDelay, primarily intended for batching data payloads, should
	// also provide a short cool-down period after failures.

	sendWaitGroup.Wait()

	// Trim the set of broker clients. Broker clients in brokerClients but not
	// in retainBrokerClients include cases where the request failed and
	// where the broker is no longer in brokerPublicKeys.

	for brokerPublicKey, brokerClient := range brokerClients {
		if _, ok := retainBrokerClients[brokerPublicKey]; !ok {
			// Close all network connections.
			brokerClient.roundTripper.Close()
			delete(brokerClients, brokerPublicKey)
		}
	}
}

func (r *ProxyQualityReporter) sendBrokerRequest(
	ctx context.Context,
	brokerClient *serverBrokerClient,
	requestCounts ProxyQualityRequestCounts) error {

	requestTimeout := time.Duration(atomic.LoadInt64(&r.requestTimeout))

	// While the request payload, requestCounts, is the same for every broker,
	// each broker round tripper may have different dial parameters, so each
	// request worker encodes and marshals its own request. requestCounts is
	// shared across multiple concurrent workers and must not be mutated.

	dialParams, err := protocol.EncodePackedAPIParameters(brokerClient.dialParams)
	if err != nil {
		return errors.Trace(err)
	}

	request := &ServerProxyQualityRequest{
		QualityCounts:  requestCounts,
		DialParameters: dialParams,
	}

	requestPayload, err := MarshalServerProxyQualityRequest(request)
	if err != nil {
		return errors.Trace(err)
	}

	// Unlike clients and proxies, there is no Noise session sharing, as
	// there's only one, sequentially invoked sendBrokerRequest worker per
	// broker. The ServerProxyQualityRequest is not a long polling request,
	// so there's no special case, shorter Noise handshake timeout. There's
	// no request delay at this level.

	waitToShareSession := false
	sessionHandshakeTimeout := requestTimeout
	requestDelay := time.Duration(0)

	responsePayload, err := brokerClient.sessions.RoundTrip(
		ctx,
		brokerClient.roundTripper,
		brokerClient.publicKey,
		brokerClient.rootObfuscationSecret,
		waitToShareSession,
		sessionHandshakeTimeout,
		requestDelay,
		requestTimeout,
		requestPayload)
	if err != nil {

		// TODO: check if the error is a RoundTripperFailedError and,
		// if not, potentially retain the RoundTripper? At this time,
		// the server.InproxyProxyQualityBrokerRoundTripper.RoundTrip
		// implementation always returns RoundTripperFailedError.

		return errors.Trace(err)
	}

	// The response is simply an acknowledgement of the request.

	_, err = UnmarshalServerProxyQualityResponse(responsePayload)
	if err != nil {
		return errors.Trace(err)
	}

	return nil
}
