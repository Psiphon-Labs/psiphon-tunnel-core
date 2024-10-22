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
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
)

const (
	proxyAnnounceDelay           = 1 * time.Second
	proxyAnnounceDelayJitter     = 0.5
	proxyAnnounceMaxBackoffDelay = 1 * time.Hour
	proxyAnnounceLogSampleSize   = 2
	proxyAnnounceLogSamplePeriod = 30 * time.Minute
	proxyWebRTCAnswerTimeout     = 20 * time.Second
	proxyDestinationDialTimeout  = 20 * time.Second
	proxyRelayInactivityTimeout  = 5 * time.Minute
)

// Proxy is the in-proxy proxying component, which relays traffic from a
// client to a Psiphon server.
type Proxy struct {
	// Note: 64-bit ints used with atomic operations are placed
	// at the start of struct to ensure 64-bit alignment.
	// (https://golang.org/pkg/sync/atomic/#pkg-note-BUG)
	bytesUp           int64
	bytesDown         int64
	peakBytesUp       int64
	peakBytesDown     int64
	connectingClients int32
	connectedClients  int32

	config                *ProxyConfig
	activityUpdateWrapper *activityUpdateWrapper

	networkDiscoveryMutex     sync.Mutex
	networkDiscoveryRunOnce   bool
	networkDiscoveryNetworkID string

	nextAnnounceMutex        sync.Mutex
	nextAnnounceBrokerClient *BrokerClient
	nextAnnounceNotBefore    time.Time
}

// TODO: add PublicNetworkAddress/ListenNetworkAddress to facilitate manually
// configured, permanent port mappings.

// ProxyConfig specifies the configuration for a Proxy run.
type ProxyConfig struct {

	// Logger is used to log events.
	Logger common.Logger

	// EnableWebRTCDebugLogging indicates whether to emit WebRTC debug logs.
	EnableWebRTCDebugLogging bool

	// WaitForNetworkConnectivity is a callback that should block until there
	// is network connectivity or shutdown. The return value is true when
	// there is network connectivity, and false for shutdown.
	WaitForNetworkConnectivity func() bool

	// GetBrokerClient provides a BrokerClient which the proxy will use for
	// making broker requests. If GetBrokerClient returns a shared
	// BrokerClient instance, the BrokerClient must support multiple,
	// concurrent round trips, as the proxy will use it to concurrently
	// announce many proxy instances. The BrokerClient should be implemented
	// using multiplexing over a shared network connection -- for example,
	// HTTP/2 --  and a shared broker session for optimal performance.
	GetBrokerClient func() (*BrokerClient, error)

	// GetBaseAPIParameters returns Psiphon API parameters to be sent to and
	// logged by the broker. Expected parameters include client/proxy
	// application and build version information. GetBaseAPIParameters also
	// returns the network ID, corresponding to the parameters, to be used in
	// tactics logic; the network ID is not sent to the broker.
	GetBaseAPIParameters func() (common.APIParameters, string, error)

	// MakeWebRTCDialCoordinator provides a WebRTCDialCoordinator which
	// specifies WebRTC-related dial parameters, including selected STUN
	// server addresses; network topology information for the current netork;
	// NAT logic settings; and other settings.
	//
	// MakeWebRTCDialCoordinator is invoked for each proxy/client connection,
	// and the provider can select new parameters per connection as reqired.
	MakeWebRTCDialCoordinator func() (WebRTCDialCoordinator, error)

	// HandleTacticsPayload is a callback that receives any tactics payload,
	// provided by the broker in proxy announcement request responses.
	// HandleTacticsPayload must return true when the tacticsPayload includes
	// new tactics, indicating that the proxy should reinitialize components
	// controlled by tactics parameters.
	HandleTacticsPayload func(networkID string, tacticsPayload []byte) bool

	// MustUpgrade is a callback that is invoked when a MustUpgrade flag is
	// received from the broker. When MustUpgrade is received, the proxy
	// should be stopped and the user should be prompted to upgrade before
	// restarting the proxy.
	MustUpgrade func()

	// MaxClients is the maximum number of clients that are allowed to connect
	// to the proxy. Must be > 0.
	MaxClients int

	// LimitUpstreamBytesPerSecond limits the upstream data transfer rate for
	// a single client. When 0, there is no limit.
	LimitUpstreamBytesPerSecond int

	// LimitDownstreamBytesPerSecond limits the downstream data transfer rate
	// for a single client. When 0, there is no limit.
	LimitDownstreamBytesPerSecond int

	// ActivityUpdater specifies an ActivityUpdater for activity associated
	// with this proxy.
	ActivityUpdater ActivityUpdater
}

// ActivityUpdater is a callback that is invoked when clients connect and
// disconnect and periodically with data transfer updates (unless idle). This
// callback may be used to update an activity UI. This callback should post
// this data to another thread or handler and return immediately and not
// block on UI updates.
type ActivityUpdater func(
	connectingClients int32,
	connectedClients int32,
	bytesUp int64,
	bytesDown int64,
	bytesDuration time.Duration)

// NewProxy initializes a new Proxy with the specified configuration.
func NewProxy(config *ProxyConfig) (*Proxy, error) {

	if config.MaxClients <= 0 {
		return nil, errors.TraceNew("invalid MaxClients")
	}

	p := &Proxy{
		config: config,
	}

	p.activityUpdateWrapper = &activityUpdateWrapper{p: p}

	return p, nil
}

// activityUpdateWrapper implements the psiphon/common.ActivityUpdater
// interface and is used to receive bytes transferred updates from the
// ActivityConns wrapping proxied traffic. A wrapper is used so that
// UpdateProgress is not exported from Proxy.
type activityUpdateWrapper struct {
	p *Proxy
}

func (w *activityUpdateWrapper) UpdateProgress(bytesRead, bytesWritten int64, _ int64) {
	atomic.AddInt64(&w.p.bytesUp, bytesWritten)
	atomic.AddInt64(&w.p.bytesDown, bytesRead)
}

// Run runs the proxy. The proxy sends requests to the Broker announcing its
// availability; the Broker matches the proxy with clients, and facilitates
// an exchange of WebRTC connection information; the proxy and each client
// attempt to establish a connection; and the client's traffic is relayed to
// Psiphon server.
//
// Run ends when ctx is Done. A proxy run may continue across underlying
// network changes assuming that the ProxyConfig GetBrokerClient and
// MakeWebRTCDialCoordinator callbacks react to network changes and provide
// instances that are reflect network changes.
func (p *Proxy) Run(ctx context.Context) {

	// Run MaxClient proxying workers. Each worker handles one client at a time.

	proxyWaitGroup := new(sync.WaitGroup)

	// Launch the first proxy worker, passing a signal to be triggered once
	// the very first announcement round trip is complete. The first round
	// trip is awaited so that:
	//
	// - The first announce response will arrive with any new tactics,
	//   which may be applied before launching additions workers.
	//
	// - The first worker gets no announcement delay and is also guaranteed to
	//   be the shared session establisher. Since the announcement delays are
	//   applied _after_ waitToShareSession, it would otherwise be possible,
	//   with a race of MaxClient initial, concurrent announces, for the
	//   session establisher to be a different worker than the no-delay worker.
	//
	// The first worker is the only proxy worker which sets
	// ProxyAnnounceRequest.CheckTactics.

	signalFirstAnnounceCtx, signalFirstAnnounceDone :=
		context.WithCancel(context.Background())

	proxyWaitGroup.Add(1)
	go func() {
		defer proxyWaitGroup.Done()
		p.proxyClients(ctx, signalFirstAnnounceDone)
	}()

	select {
	case <-signalFirstAnnounceCtx.Done():
	case <-ctx.Done():
		return
	}

	// Launch the remaining workers.

	for i := 0; i < p.config.MaxClients-1; i++ {
		proxyWaitGroup.Add(1)
		go func() {
			defer proxyWaitGroup.Done()
			p.proxyClients(ctx, nil)
		}()
	}

	// Capture activity updates every second, which is the required frequency
	// for PeakUp/DownstreamBytesPerSecond. This is also a reasonable
	// frequency for invoking the ActivityUpdater and updating UI widgets.

	activityUpdatePeriod := 1 * time.Second
	ticker := time.NewTicker(activityUpdatePeriod)
	defer ticker.Stop()

loop:
	for {
		select {
		case <-ticker.C:
			p.activityUpdate(activityUpdatePeriod)
		case <-ctx.Done():
			break loop
		}
	}

	proxyWaitGroup.Wait()
}

// getAnnounceDelayParameters is a helper that fetches the proxy announcement
// delay parameters from the current broker client.
//
// getAnnounceDelayParameters is used to configure a delay when
// proxyOneClient fails. As having no broker clients is a possible
// proxyOneClient failure case, GetBrokerClient errors are ignored here and
// defaults used in that case.
func (p *Proxy) getAnnounceDelayParameters() (time.Duration, float64) {
	brokerClient, err := p.config.GetBrokerClient()
	if err != nil {
		return proxyAnnounceDelay, proxyAnnounceDelayJitter
	}
	brokerCoordinator := brokerClient.GetBrokerDialCoordinator()
	return common.ValueOrDefault(brokerCoordinator.AnnounceDelay(), proxyAnnounceDelay),
		common.ValueOrDefault(brokerCoordinator.AnnounceDelayJitter(), proxyAnnounceDelayJitter)

}

func (p *Proxy) activityUpdate(period time.Duration) {

	connectingClients := atomic.LoadInt32(&p.connectingClients)
	connectedClients := atomic.LoadInt32(&p.connectedClients)
	bytesUp := atomic.SwapInt64(&p.bytesUp, 0)
	bytesDown := atomic.SwapInt64(&p.bytesDown, 0)

	greaterThanSwapInt64(&p.peakBytesUp, bytesUp)
	greaterThanSwapInt64(&p.peakBytesDown, bytesDown)

	if connectingClients == 0 &&
		connectedClients == 0 &&
		bytesUp == 0 &&
		bytesDown == 0 {
		// Skip the activity callback on idle.
		return
	}

	p.config.ActivityUpdater(
		connectingClients,
		connectedClients,
		bytesUp,
		bytesDown,
		period)
}

func greaterThanSwapInt64(addr *int64, new int64) bool {

	// Limitation: if there are two concurrent calls, the greater value could
	// get overwritten.

	old := atomic.LoadInt64(addr)
	if new > old {
		return atomic.CompareAndSwapInt64(addr, old, new)
	}
	return false
}

func (p *Proxy) proxyClients(
	ctx context.Context, signalAnnounceDone func()) {

	// Proxy one client, repeating until ctx is done.
	//
	// This worker starts with posting a long-polling announcement request.
	// The broker response with a matched client, and the proxy and client
	// attempt to establish a WebRTC connection for relaying traffic.
	//
	// Limitation: this design may not maximize the utility of the proxy,
	// since some proxy/client connections will fail at the WebRTC stage due
	// to NAT traversal failure, and at most MaxClient concurrent
	// establishments are attempted. Another scenario comes from the Psiphon
	// client horse race, which may start in-proxy dials but then abort them
	// when some other tunnel protocol succeeds.
	//
	// As a future enhancement, consider using M announcement goroutines and N
	// WebRTC dial goroutines. When an announcement gets a response,
	// immediately announce again unless there are already MaxClient active
	// connections established. This approach may require the proxy to
	// backpedal and reject connections when establishment is too successful.
	//
	// Another enhancement could be a signal from the client, to the broker,
	// relayed to the proxy, when a dial is aborted.

	failureDelayFactor := time.Duration(1)

	// To reduce diagnostic log noise, only log an initial sample of
	// announcement request timings (delays/elapsed time) and a periodic
	// sample of repeating errors such as "no match".
	logAnnounceCount := proxyAnnounceLogSampleSize
	logErrorsCount := proxyAnnounceLogSampleSize
	lastErrMsg := ""
	startLogSampleTime := time.Now()
	logAnnounce := func() bool {
		if logAnnounceCount > 0 {
			logAnnounceCount -= 1
			return true
		}
		return false
	}

	for ctx.Err() == nil {

		if !p.config.WaitForNetworkConnectivity() {
			break
		}

		if time.Since(startLogSampleTime) >= proxyAnnounceLogSamplePeriod {
			logAnnounceCount = proxyAnnounceLogSampleSize
			logErrorsCount = proxyAnnounceLogSampleSize
			lastErrMsg = ""
			startLogSampleTime = time.Now()
		}

		backOff, err := p.proxyOneClient(
			ctx, logAnnounce, signalAnnounceDone)

		if err != nil && ctx.Err() == nil {

			// Limitation: the lastErrMsg string comparison isn't compatible
			// with errors with minor variations, such as "unexpected
			// response status code %d after %v" from
			// InproxyBrokerRoundTripper.RoundTrip, with a time duration in
			// the second parameter.
			errMsg := err.Error()
			if lastErrMsg != errMsg {
				logErrorsCount = proxyAnnounceLogSampleSize
				lastErrMsg = errMsg
			}
			if logErrorsCount > 0 {
				p.config.Logger.WithTraceFields(
					common.LogFields{
						"error": errMsg,
					}).Error("proxy client failed")
				logErrorsCount -= 1
			}

			// Apply a simple exponential backoff based on whether
			// proxyOneClient either relayed client traffic or got no match,
			// or encountered a failure.
			//
			// The proxyOneClient failure could range from local
			// configuration (no broker clients) to network issues(failure to
			// completely establish WebRTC connection) and this backoff
			// prevents both excess local logging and churning in the former
			// case and excessive bad service to clients or unintentionally
			// overloading the broker in the latter case.
			//
			// TODO: specific tactics parameters to control this logic.

			delay, jitter := p.getAnnounceDelayParameters()

			if !backOff {
				failureDelayFactor = 1
			}
			delay = delay * failureDelayFactor
			if delay > proxyAnnounceMaxBackoffDelay {
				delay = proxyAnnounceMaxBackoffDelay
			}
			if failureDelayFactor < 1<<20 {
				failureDelayFactor *= 2
			}

			common.SleepWithJitter(ctx, delay, jitter)
		}
	}
}

// resetNetworkDiscovery resets the network discovery state, which will force
// another network discovery when doNetworkDiscovery is invoked.
// resetNetworkDiscovery is called when new tactics have been received from
// the broker, as new tactics may change parameters that control network
// discovery.
func (p *Proxy) resetNetworkDiscovery() {
	p.networkDiscoveryMutex.Lock()
	defer p.networkDiscoveryMutex.Unlock()

	p.networkDiscoveryRunOnce = false
	p.networkDiscoveryNetworkID = ""
}

func (p *Proxy) doNetworkDiscovery(
	ctx context.Context,
	webRTCCoordinator WebRTCDialCoordinator) {

	// Allow only one concurrent network discovery. In practise, this may
	// block all other proxyOneClient goroutines while one single goroutine
	// runs doNetworkDiscovery. Subsequently, all other goroutines will find
	// networkDiscoveryRunOnce is true and use the cached results.
	p.networkDiscoveryMutex.Lock()
	defer p.networkDiscoveryMutex.Unlock()

	networkID := webRTCCoordinator.NetworkID()

	if p.networkDiscoveryRunOnce &&
		p.networkDiscoveryNetworkID == networkID {
		// Already ran discovery for this network.
		//
		// TODO: periodically re-probe for port mapping services?
		return
	}

	// Reset and configure port mapper component, as required. See
	// initPortMapper comment.
	initPortMapper(webRTCCoordinator)

	// Gather local network NAT/port mapping metrics and configuration before
	// sending any announce requests. NAT topology metrics are used by the
	// Broker to optimize client and in-proxy matching. Unlike the client, we
	// always perform this synchronous step here, since waiting doesn't
	// necessarily block a client tunnel dial.

	waitGroup := new(sync.WaitGroup)
	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()

		// NATDiscover may use cached NAT type/port mapping values from
		// DialParameters, based on the network ID. If discovery is not
		// successful, the proxy still proceeds to announce.
		NATDiscover(
			ctx,
			&NATDiscoverConfig{
				Logger:                p.config.Logger,
				WebRTCDialCoordinator: webRTCCoordinator,
			})

	}()
	waitGroup.Wait()

	p.networkDiscoveryRunOnce = true
	p.networkDiscoveryNetworkID = networkID
}

func (p *Proxy) proxyOneClient(
	ctx context.Context,
	logAnnounce func() bool,
	signalAnnounceDone func()) (bool, error) {

	// Do not trigger back-off unless the proxy successfully announces and
	// only then performs poorly.
	//
	// A no-match response should not trigger back-off, nor should broker
	// request transport errors which may include non-200 responses due to
	// CDN timeout mismatches or TLS errors due to CDN TLS fingerprint
	// incompatibility.

	backOff := false

	// Get a new WebRTCDialCoordinator, which should be configured with the
	// latest network tactics.
	webRTCCoordinator, err := p.config.MakeWebRTCDialCoordinator()
	if err != nil {
		return backOff, errors.Trace(err)
	}

	// Perform network discovery, to determine NAT type and other network
	// topology information that is reported to the broker in the proxy
	// announcement and used to optimize proxy/client matching. Unlike
	// clients, which can't easily delay dials in the tunnel establishment
	// horse race, proxies will always perform network discovery.
	// doNetworkDiscovery allows only one concurrent discovery and caches
	// results for the current network (as determined by
	// WebRTCCoordinator.GetNetworkID), so when multiple proxyOneClient
	// goroutines call doNetworkDiscovery, at most one discovery is performed
	// per network.
	p.doNetworkDiscovery(ctx, webRTCCoordinator)

	// Send the announce request

	// At this point, no NAT traversal operations have been performed by the
	// proxy, since its announcement may sit idle for the long-polling period
	// and NAT hole punches or port mappings could expire before the
	// long-polling period.
	//
	// As a future enhancement, the proxy could begin gathering WebRTC ICE
	// candidates while awaiting a client match, reducing the turn around
	// time after a match. This would make sense if there's high demand for
	// proxies, and so hole punches unlikely to expire while awaiting a client match.
	//
	// Another possibility may be to prepare and send a full offer SDP in the
	// announcment; and have the broker modify either the proxy or client
	// offer SDP to produce an answer SDP. In this case, the entire
	// ProxyAnswerRequest could be skipped as the WebRTC dial can begin after
	// the ProxyAnnounceRequest response (and ClientOfferRequest response).
	//
	// Furthermore, if a port mapping can be established, instead of using
	// WebRTC the proxy could run a Psiphon tunnel protocol listener at the
	// mapped port and send the dial information -- including some secret to
	// authenticate the client -- in its announcement. The client would then
	// receive this direct dial information from the broker and connect. The
	// proxy should be able to send keep alives to extend the port mapping
	// lifetime.

	brokerClient, err := p.config.GetBrokerClient()
	if err != nil {
		return backOff, errors.Trace(err)
	}

	brokerCoordinator := brokerClient.GetBrokerDialCoordinator()

	// Get the base Psiphon API parameters and additional proxy metrics,
	// including performance information, which is sent to the broker in the
	// proxy announcment.
	//
	// tacticsNetworkID is the exact network ID that corresponds to the
	// tactics tag sent in the base parameters; this is passed to
	// HandleTacticsPayload in order to double check that any tactics
	// returned in the proxy announcment response are associated and stored
	// with the original network ID.

	metrics, tacticsNetworkID, err := p.getMetrics(
		brokerCoordinator, webRTCCoordinator)
	if err != nil {
		return backOff, errors.Trace(err)
	}

	// Set a delay before announcing, to stagger the announce request times.
	// The delay helps to avoid triggering rate limits or similar errors from
	// any intermediate CDN between the proxy and the broker; and provides a
	// nudge towards better load balancing across multiple large MaxClients
	// proxies, as the broker primarily matches enqueued announces in FIFO
	// order, since older announces expire earlier.
	//
	// The delay is intended to be applied after doNetworkDiscovery, which has
	// no reason to be delayed; and also after any waitToShareSession delay,
	// as delaying before waitToShareSession can result in the announce
	// request times collapsing back together. Delaying after
	// waitToShareSession is handled by brokerClient.ProxyAnnounce, which
	// will also extend the base request timeout, as required, to account for
	// any deliberate delay.

	requestDelay := time.Duration(0)
	announceDelay, announceDelayJitter := p.getAnnounceDelayParameters()
	p.nextAnnounceMutex.Lock()
	nextDelay := prng.JitterDuration(announceDelay, announceDelayJitter)
	if p.nextAnnounceBrokerClient != brokerClient {
		// Reset the delay when the broker client changes.
		p.nextAnnounceNotBefore = time.Time{}
		p.nextAnnounceBrokerClient = brokerClient
	}
	if p.nextAnnounceNotBefore.IsZero() {
		p.nextAnnounceNotBefore = time.Now().Add(nextDelay)
		// No delay for the very first announce request, so leave
		// announceRequestDelay set to 0.
	} else {
		requestDelay = time.Until(p.nextAnnounceNotBefore)
		if requestDelay < 0 {
			// This announce did not arrive until after the next delay already
			// passed, so proceed with no delay.
			p.nextAnnounceNotBefore = time.Now().Add(nextDelay)
			requestDelay = 0
		} else {
			p.nextAnnounceNotBefore = p.nextAnnounceNotBefore.Add(nextDelay)
		}
	}
	p.nextAnnounceMutex.Unlock()

	// Only the first worker, which has signalAnnounceDone configured, checks
	// for tactics.
	checkTactics := signalAnnounceDone != nil

	// A proxy ID is implicitly sent with requests; it's the proxy's session
	// public key.
	//
	// ProxyAnnounce applies an additional request timeout to facilitate
	// long-polling.
	announceStartTime := time.Now()
	personalCompartmentIDs := brokerCoordinator.PersonalCompartmentIDs()
	announceResponse, err := brokerClient.ProxyAnnounce(
		ctx,
		requestDelay,
		&ProxyAnnounceRequest{
			PersonalCompartmentIDs: personalCompartmentIDs,
			Metrics:                metrics,
			CheckTactics:           checkTactics,
		})
	if logAnnounce() {
		p.config.Logger.WithTraceFields(common.LogFields{
			"delay":       requestDelay.String(),
			"elapsedTime": time.Since(announceStartTime).String(),
		}).Info("announcement request")
	}
	if err != nil {
		return backOff, errors.Trace(err)
	}

	if len(announceResponse.TacticsPayload) > 0 {

		// The TacticsPayload may include new tactics, or may simply signal,
		// to the Psiphon client, that its tactics tag remains up-to-date and
		// to extend cached tactics TTL. HandleTacticsPayload returns true
		// when tactics haved changed; in this case we clear cached network
		// discovery but proceed with handling the proxy announcement
		// response as there may still be a match.

		if p.config.HandleTacticsPayload(
			tacticsNetworkID, announceResponse.TacticsPayload) {

			p.resetNetworkDiscovery()
		}
	}

	// Signal that the announce round trip is complete. At this point, the
	// broker Noise session should be established and any fresh tactics
	// applied.
	if signalAnnounceDone != nil {
		signalAnnounceDone()
	}

	// MustUpgrade has precedence over other cases, to ensure the callback is
	// invoked. Trigger back-off back off when rate/entry limited or must
	// upgrade; no back-off for no-match.

	if announceResponse.MustUpgrade {

		if p.config.MustUpgrade != nil {
			p.config.MustUpgrade()
		}
		backOff = true
		return backOff, errors.TraceNew("must upgrade")

	} else if announceResponse.Limited {

		backOff = true
		return backOff, errors.TraceNew("limited")

	} else if announceResponse.NoMatch {

		return backOff, errors.TraceNew("no match")

	}

	if announceResponse.ClientProxyProtocolVersion != ProxyProtocolVersion1 {
		// This case is currently unexpected, as all clients and proxies use
		// ProxyProtocolVersion1.
		backOff = true
		return backOff, errors.Tracef(
			"Unsupported proxy protocol version: %d",
			announceResponse.ClientProxyProtocolVersion)
	}

	// Trigger back-off if the following WebRTC operations fail to establish a
	// connections.
	//
	// Limitation: the proxy answer request to the broker may fail due to the
	// non-back-off reasons documented above for the proxy announcment request;
	// however, these should be unlikely assuming that the broker client is
	// using a persistent transport connection.

	backOff = true

	// For activity updates, indicate that a client connection is now underway.

	atomic.AddInt32(&p.connectingClients, 1)
	connected := false
	defer func() {
		if !connected {
			atomic.AddInt32(&p.connectingClients, -1)
		}
	}()

	// Initialize WebRTC using the client's offer SDP

	webRTCAnswerCtx, webRTCAnswerCancelFunc := context.WithTimeout(
		ctx, common.ValueOrDefault(webRTCCoordinator.WebRTCAnswerTimeout(), proxyWebRTCAnswerTimeout))
	defer webRTCAnswerCancelFunc()

	// In personal pairing mode, RFC 1918/4193 private IP addresses are
	// included in SDPs.
	hasPersonalCompartmentIDs := len(personalCompartmentIDs) > 0

	webRTCConn, SDP, sdpMetrics, webRTCErr := newWebRTCConnForAnswer(
		webRTCAnswerCtx,
		&webRTCConfig{
			Logger:                      p.config.Logger,
			EnableDebugLogging:          p.config.EnableWebRTCDebugLogging,
			WebRTCDialCoordinator:       webRTCCoordinator,
			ClientRootObfuscationSecret: announceResponse.ClientRootObfuscationSecret,
			DoDTLSRandomization:         announceResponse.DoDTLSRandomization,
			TrafficShapingParameters:    announceResponse.TrafficShapingParameters,
		},
		announceResponse.ClientOfferSDP,
		hasPersonalCompartmentIDs)
	var webRTCRequestErr string
	if webRTCErr != nil {
		webRTCErr = errors.Trace(webRTCErr)
		webRTCRequestErr = webRTCErr.Error()
		SDP = WebRTCSessionDescription{}
		sdpMetrics = &webRTCSDPMetrics{}
		// Continue to report the error to the broker. The broker will respond
		// with failure to the client's offer request.
	} else {
		defer webRTCConn.Close()
	}

	// Send answer request with SDP or error.

	_, err = brokerClient.ProxyAnswer(
		ctx,
		&ProxyAnswerRequest{
			ConnectionID:                 announceResponse.ConnectionID,
			SelectedProxyProtocolVersion: announceResponse.ClientProxyProtocolVersion,
			ProxyAnswerSDP:               SDP,
			ICECandidateTypes:            sdpMetrics.iceCandidateTypes,
			AnswerError:                  webRTCRequestErr,
		})
	if err != nil {
		if webRTCErr != nil {
			// Prioritize returning any WebRTC error for logging.
			return backOff, webRTCErr
		}
		return backOff, errors.Trace(err)
	}

	// Now that an answer is sent, stop if WebRTC initialization failed.

	if webRTCErr != nil {
		return backOff, webRTCErr
	}

	// Await the WebRTC connection.

	// We could concurrently dial the destination, to have that network
	// connection available immediately once the WebRTC channel is
	// established. This would work only for TCP, not UDP, network protocols
	// and could only include the TCP connection, as client traffic is
	// required for all higher layers such as TLS, SSH, etc. This could also
	// create wasted load on destination Psiphon servers, particularly when
	// WebRTC connections fail.

	awaitDataChannelCtx, awaitDataChannelCancelFunc := context.WithTimeout(
		ctx,
		common.ValueOrDefault(
			webRTCCoordinator.WebRTCAwaitDataChannelTimeout(), dataChannelAwaitTimeout))
	defer awaitDataChannelCancelFunc()

	err = webRTCConn.AwaitInitialDataChannel(awaitDataChannelCtx)
	if err != nil {
		return backOff, errors.Trace(err)
	}

	p.config.Logger.WithTraceFields(common.LogFields{
		"connectionID": announceResponse.ConnectionID,
	}).Info("WebRTC data channel established")

	// Dial the destination, a Psiphon server. The broker validates that the
	// dial destination is a Psiphon server.

	destinationDialContext, destinationDialCancelFunc := context.WithTimeout(
		ctx,
		common.ValueOrDefault(
			webRTCCoordinator.ProxyDestinationDialTimeout(), proxyDestinationDialTimeout))
	defer destinationDialCancelFunc()

	// Use the custom resolver when resolving destination hostnames, such as
	// those used in domain fronted protocols.
	//
	// - Resolving at the in-proxy should yield a more optimal CDN edge, vs.
	//   resolving at the client.
	//
	// - Sending unresolved hostnames to in-proxies can expose some domain
	//   fronting configuration. This can be mitigated by enabling domain
	//   fronting on this 2nd hop only when the in-proxy is located in a
	//   region that may be censored or blocked; this is to be enforced by
	//   the broker.
	//
	// - Any DNSResolverPreresolved tactics applied will be relative to the
	//   in-proxy location.

	destinationAddress, err := webRTCCoordinator.ResolveAddress(
		ctx, "ip", announceResponse.DestinationAddress)
	if err != nil {
		return backOff, errors.Trace(err)
	}

	destinationConn, err := webRTCCoordinator.ProxyUpstreamDial(
		destinationDialContext,
		announceResponse.NetworkProtocol.String(),
		destinationAddress)
	if err != nil {
		return backOff, errors.Trace(err)
	}
	defer destinationConn.Close()

	// For activity updates, indicate that a client connection is established.

	connected = true
	atomic.AddInt32(&p.connectingClients, -1)
	atomic.AddInt32(&p.connectedClients, 1)
	defer func() {
		atomic.AddInt32(&p.connectedClients, -1)
	}()

	// Throttle the relay connection.
	//
	// Here, each client gets LimitUp/DownstreamBytesPerSecond. Proxy
	// operators may to want to limit their bandwidth usage with a single
	// up/down value, an overall limit. The ProxyConfig can simply be
	// generated by dividing the limit by MaxClients. This approach favors
	// performance stability: each client gets the same throttling limits
	// regardless of how many other clients are connected.

	destinationConn = common.NewThrottledConn(
		destinationConn,
		announceResponse.NetworkProtocol.IsStream(),
		common.RateLimits{
			ReadBytesPerSecond:  int64(p.config.LimitUpstreamBytesPerSecond),
			WriteBytesPerSecond: int64(p.config.LimitDownstreamBytesPerSecond),
		})

	// Hook up bytes transferred counting for activity updates.

	// The ActivityMonitoredConn inactivity timeout is configured. For
	// upstream TCP connections, the destinationConn will close when the TCP
	// connection to the Psiphon server closes. But for upstream UDP flows,
	// the relay does not know when the upstream "connection" has closed.
	// Well-behaved clients will close the WebRTC half of the relay when
	// those clients know the UDP-based tunnel protocol connection is closed;
	// the inactivity timeout handles the remaining cases.

	inactivityTimeout :=
		common.ValueOrDefault(
			webRTCCoordinator.ProxyRelayInactivityTimeout(),
			proxyRelayInactivityTimeout)

	destinationConn, err = common.NewActivityMonitoredConn(
		destinationConn, inactivityTimeout, false, nil, p.activityUpdateWrapper)
	if err != nil {
		return backOff, errors.Trace(err)
	}

	// Relay the client traffic to the destination. The client traffic is a
	// standard Psiphon tunnel protocol destinated to a Psiphon server. Any
	// blocking/censorship at the 2nd hop will be mitigated by the use of
	// Psiphon circumvention protocols and techniques.

	// Limitation: clients may apply fragmentation to traffic relayed over the
	// data channel, and there's no guarantee that the fragmentation write
	// sizes or delays will carry over to the egress side.

	// The proxy operator's ISP may be able to observe that the operator's
	// host has nearly matching ingress and egress traffic. The traffic
	// content won't be the same: the ingress traffic is wrapped in a WebRTC
	// data channel, and the egress traffic is a Psiphon tunnel protocol.
	// With padding and decoy packets, the ingress and egress traffic shape
	// will differ beyond the basic WebRTC overheader. Even with this
	// measure, over time the number of bytes in and out of the proxy may
	// still indicate proxying.

	waitGroup := new(sync.WaitGroup)
	relayErrors := make(chan error, 2)
	var relayedUp, relayedDown int32

	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()

		// WebRTC data channels are based on SCTP, which is actually
		// message-based, not a stream. The (default) max message size for
		// pion/sctp is 65536:
		// https://github.com/pion/sctp/blob/44ed465396c880e379aae9c1bf81809a9e06b580/association.go#L52.
		//
		// As io.Copy uses a buffer size of 32K, each relayed message will be
		// less than the maximum. Calls to ClientConn.Write are also expected
		// to use io.Copy, keeping messages at most 32K in size.

		// io.Copy doesn't return an error on EOF, but we still want to signal
		// that relaying is done, so in this case a nil error is sent to the
		// channel.
		//
		// Limitation: if one io.Copy goproutine sends nil and the other
		// io.Copy goroutine sends a non-nil error concurrently, the non-nil
		// error isn't prioritized.

		n, err := io.Copy(webRTCConn, destinationConn)
		if n > 0 {
			atomic.StoreInt32(&relayedDown, 1)
		}
		relayErrors <- errors.Trace(err)
	}()

	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		n, err := io.Copy(destinationConn, webRTCConn)
		if n > 0 {
			atomic.StoreInt32(&relayedUp, 1)
		}
		relayErrors <- errors.Trace(err)
	}()

	select {
	case err = <-relayErrors:
	case <-ctx.Done():
	}

	// Interrupt the relay goroutines by closing the connections.
	webRTCConn.Close()
	destinationConn.Close()

	waitGroup.Wait()

	p.config.Logger.WithTraceFields(common.LogFields{
		"connectionID": announceResponse.ConnectionID,
	}).Info("connection closed")

	// Don't apply a back-off delay to the next announcement since this
	// iteration successfully relayed bytes.
	if atomic.LoadInt32(&relayedUp) == 1 || atomic.LoadInt32(&relayedDown) == 1 {
		backOff = false
	}

	return backOff, err
}

func (p *Proxy) getMetrics(
	brokerCoordinator BrokerDialCoordinator,
	webRTCCoordinator WebRTCDialCoordinator) (*ProxyMetrics, string, error) {

	// tacticsNetworkID records the exact network ID that corresponds to the
	// tactics tag sent in the base parameters, and is used when applying any
	// new tactics returned by the broker.
	baseParams, tacticsNetworkID, err := p.config.GetBaseAPIParameters()
	if err != nil {
		return nil, "", errors.Trace(err)
	}

	apiParams := common.APIParameters{}
	apiParams.Add(baseParams)
	apiParams.Add(common.APIParameters(brokerCoordinator.MetricsForBrokerRequests()))

	packedParams, err := protocol.EncodePackedAPIParameters(apiParams)
	if err != nil {
		return nil, "", errors.Trace(err)
	}

	return &ProxyMetrics{
		BaseAPIParameters:             packedParams,
		ProxyProtocolVersion:          proxyProtocolVersion,
		NATType:                       webRTCCoordinator.NATType(),
		PortMappingTypes:              webRTCCoordinator.PortMappingTypes(),
		MaxClients:                    int32(p.config.MaxClients),
		ConnectingClients:             atomic.LoadInt32(&p.connectingClients),
		ConnectedClients:              atomic.LoadInt32(&p.connectedClients),
		LimitUpstreamBytesPerSecond:   int64(p.config.LimitUpstreamBytesPerSecond),
		LimitDownstreamBytesPerSecond: int64(p.config.LimitDownstreamBytesPerSecond),
		PeakUpstreamBytesPerSecond:    atomic.LoadInt64(&p.peakBytesUp),
		PeakDownstreamBytesPerSecond:  atomic.LoadInt64(&p.peakBytesDown),
	}, tacticsNetworkID, nil
}
