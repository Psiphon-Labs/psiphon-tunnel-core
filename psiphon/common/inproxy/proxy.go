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
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/pion/webrtc/v3"
)

// Timeouts should be aligned with Broker timeouts.

const (
	proxyAnnounceRequestTimeout = 2 * time.Minute
	proxyAnnounceRetryDelay     = 1 * time.Second
	proxyAnnounceRetryJitter    = 0.3
	proxyWebRTCAnswerTimeout    = 20 * time.Second
	proxyAnswerRequestTimeout   = 10 * time.Second
	proxyClientConnectTimeout   = 30 * time.Second
	proxyDestinationDialTimeout = 30 * time.Second
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
	brokerClient          *BrokerClient
	activityUpdateWrapper *activityUpdateWrapper
}

// TODO: add PublicNetworkAddress/ListenNetworkAddress to facilitate manually
// configured, permanent port mappings.

// ProxyConfig specifies the configuration for a Proxy run.
type ProxyConfig struct {

	// Logger is used to log events.
	Logger common.Logger

	// BaseMetrics should be populated with Psiphon handshake metrics
	// parameters. These will be sent to and logger by the Broker.
	BaseMetrics common.APIParameters

	// OperatorMessageHandler is a callback that is invoked with any user
	// message JSON object that is sent to the Proxy from the Broker. This
	// facility may be used to alert proxy operators when required. The JSON
	// object schema is arbitrary and not defined here.
	OperatorMessageHandler func(messageJSON string)

	// DialParameters specifies specific broker and WebRTC dial configuration
	// and strategies and settings; DialParameters also facilities dial
	// replay by receiving callbacks when individual dial steps succeed or
	// fail.
	//
	// As a DialParameters is associated with one network ID, it is expected
	// that the proxy will be stopped and restarted when a network change is
	// detected.
	DialParameters DialParameters

	// MaxClients is the maximum number of clients that are allowed to connect
	// to the proxy.
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

	// Create one BrokerClient which will be shared for all requests. When the
	// round tripper supports multiplexing -- for example HTTP/2 -- many
	// concurrent requests can share the same TLS network connection and
	// established session.

	brokerClient, err := NewBrokerClient(config.DialParameters)
	if err != nil {
		return nil, errors.Trace(err)
	}

	p := &Proxy{
		config:       config,
		brokerClient: brokerClient,
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

// Run runs the Proxy. The proxy sends requests to the Broker announcing its
// availability; the Broker matches the proxy with clients, and facilitates
// an exchange of WebRTC connection information; the proxy and each client
// attempt to establish a connection; and the client's traffic is relayed to
// Psiphon server.
//
// Run ends when ctx is Done. When a network change is detected, Run should be
// stopped and a new Proxy configured and started. This minimizes dangling
// client connections running over the previous network; provides an
// opportunity to gather fresh NAT/port mapping metrics for the new network;
// and allows for a new DialParameters, associated with the new network, to
// be configured.
func (p *Proxy) Run(ctx context.Context) {

	// Reset and configure port mapper component, as required. See
	// initPortMapper comment.
	initPortMapper(p.config.DialParameters)

	// Gather local network NAT/port mapping metrics before sending any
	// announce requests. NAT topology metrics are used by the Broker to
	// optimize client and in-proxy matching. Unlike the client, we always
	// perform this synchronous step here, since waiting doesn't necessarily
	// block a client tunnel dial.

	initWaitGroup := new(sync.WaitGroup)
	initWaitGroup.Add(1)
	go func() {
		defer initWaitGroup.Done()

		// NATDiscover may use cached NAT type/port mapping values from
		// DialParameters, based on the network ID. If discovery is not
		// successful, the proxy still proceeds to announce.

		NATDiscover(
			ctx,
			&NATDiscoverConfig{
				Logger:         p.config.Logger,
				DialParameters: p.config.DialParameters,
			})

	}()
	initWaitGroup.Wait()

	// Run MaxClient proxying workers. Each worker handles one client at a time.

	proxyWaitGroup := new(sync.WaitGroup)

	for i := 0; i < p.config.MaxClients; i++ {
		proxyWaitGroup.Add(1)
		go func() {
			defer proxyWaitGroup.Done()
			p.proxyClients(ctx)
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

func (p *Proxy) proxyClients(ctx context.Context) {

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

	for ctx.Err() == nil {
		err := p.proxyOneClient(ctx)
		if err != nil && ctx.Err() == nil {
			p.config.Logger.WithTraceFields(
				common.LogFields{
					"error": err.Error(),
				}).Error("proxy client failed")

			// Delay briefly, to avoid unintentionally overloading the broker
			// in some recurring failure case. Use a jitter to avoid a
			// regular traffic period.

			common.SleepWithJitter(
				ctx,
				common.ValueOrDefault(p.config.DialParameters.AnnounceRetryDelay(), proxyAnnounceRetryDelay),
				common.ValueOrDefault(p.config.DialParameters.AnnounceRetryJitter(), proxyAnnounceRetryJitter))
		}
	}
}

func (p *Proxy) proxyOneClient(ctx context.Context) error {

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

	announceRequestCtx, announceRequestCancelFunc := context.WithTimeout(
		ctx, common.ValueOrDefault(p.config.DialParameters.AnnounceRequestTimeout(), proxyAnnounceRequestTimeout))
	defer announceRequestCancelFunc()

	metrics, err := p.getMetrics()
	if err != nil {
		return errors.Trace(err)
	}

	// A proxy ID is implicitly sent with requests; it's the proxy's session
	// public key.

	announceResponse, err := p.brokerClient.ProxyAnnounce(
		announceRequestCtx,
		&ProxyAnnounceRequest{
			PersonalCompartmentIDs: p.config.DialParameters.PersonalCompartmentIDs(),
			Metrics:                metrics,
		})
	if err != nil {
		return errors.Trace(err)
	}

	if announceResponse.ClientProxyProtocolVersion != ProxyProtocolVersion1 {
		return errors.Tracef(
			"Unsupported proxy protocol version: %d",
			announceResponse.ClientProxyProtocolVersion)
	}

	if announceResponse.OperatorMessageJSON != "" {
		p.config.OperatorMessageHandler(announceResponse.OperatorMessageJSON)
	}

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
		ctx, common.ValueOrDefault(p.config.DialParameters.WebRTCAnswerTimeout(), proxyWebRTCAnswerTimeout))
	defer webRTCAnswerCancelFunc()

	webRTCConn, SDP, SDPMetrics, webRTCErr := NewWebRTCConnWithAnswer(
		webRTCAnswerCtx,
		&WebRTCConfig{
			Logger:                      p.config.Logger,
			DialParameters:              p.config.DialParameters,
			ClientRootObfuscationSecret: announceResponse.ClientRootObfuscationSecret,
		},
		announceResponse.ClientOfferSDP)
	var webRTCRequestErr string
	if webRTCErr != nil {
		webRTCErr = errors.Trace(webRTCErr)
		webRTCRequestErr = webRTCErr.Error()
		SDP = webrtc.SessionDescription{}
		// Continue to report the error to the broker. The broker will respond
		// with failure to the client's offer request.
	}
	defer webRTCConn.Close()

	// Send answer request with SDP or error.

	answerRequestCtx, answerRequestCancelFunc := context.WithTimeout(
		ctx, common.ValueOrDefault(p.config.DialParameters.AnswerRequestTimeout(), proxyAnswerRequestTimeout))
	defer answerRequestCancelFunc()

	_, err = p.brokerClient.ProxyAnswer(
		answerRequestCtx,
		&ProxyAnswerRequest{
			ConnectionID:                 announceResponse.ConnectionID,
			SelectedProxyProtocolVersion: announceResponse.ClientProxyProtocolVersion,
			ProxyAnswerSDP:               SDP,
			ICECandidateTypes:            SDPMetrics.ICECandidateTypes,
			AnswerError:                  webRTCRequestErr,
		})
	if err != nil {
		if webRTCErr != nil {
			// Prioritize returning any WebRTC error for logging.
			return webRTCErr
		}
		return errors.Trace(err)
	}

	// Now that an answer is sent, stop if WebRTC initialization failed.

	if webRTCErr != nil {
		return webRTCErr
	}

	// Await the WebRTC connection.

	// We could concurrently dial the destination, to have that network
	// connection available immediately once the WebRTC channel is
	// established. This would work only for TCP, not UDP, network protocols
	// and could only include the TCP connection, as client traffic is
	// required for all higher layers such as TLS, SSH, etc. This could also
	// create wasted load on destination Psiphon servers, particularly when
	// WebRTC connections fail.

	clientConnectCtx, clientConnectCancelFunc := context.WithTimeout(
		ctx, common.ValueOrDefault(p.config.DialParameters.ProxyClientConnectTimeout(), proxyClientConnectTimeout))
	defer clientConnectCancelFunc()

	err = webRTCConn.AwaitInitialDataChannel(clientConnectCtx)
	if err != nil {
		return errors.Trace(err)
	}

	p.config.Logger.WithTraceFields(common.LogFields{
		"connectionID": announceResponse.ConnectionID,
	}).Info("WebRTC data channel established")

	// Dial the destination, a Psiphon server. The broker validates that the
	// dial destination is a Psiphon server.

	destinationDialContext, destinationDialCancelFunc := context.WithTimeout(
		ctx, common.ValueOrDefault(p.config.DialParameters.ProxyDestinationDialTimeout(), proxyDestinationDialTimeout))
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

	destinationAddress, err := p.config.DialParameters.ResolveAddress(ctx, announceResponse.DestinationAddress)
	if err != nil {
		return errors.Trace(err)
	}

	var dialer net.Dialer
	destinationConn, err := dialer.DialContext(
		destinationDialContext,
		announceResponse.NetworkProtocol.String(),
		destinationAddress)
	if err != nil {
		return errors.Trace(err)
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
		common.RateLimits{
			ReadBytesPerSecond:  int64(p.config.LimitUpstreamBytesPerSecond),
			WriteBytesPerSecond: int64(p.config.LimitDownstreamBytesPerSecond),
		})

	// Hook up bytes transferred counting for activity updates.

	// The ActivityMonitoredConn inactivity timeout is not configured, since
	// the Psiphon server will close its connection to inactive clients on
	// its own schedule.

	destinationConn, err = common.NewActivityMonitoredConn(
		destinationConn, 0, false, nil, p.activityUpdateWrapper)
	if err != nil {
		return errors.Trace(err)
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
	// data channel, and the egress traffic is a Psiphon tunnel protocol. But
	// the traffic shape will be close to the same. As a future enhancement,
	// consider adding data channel padding and decoy traffic, which is
	// dropped on egress. For performance, traffic shaping could be ceased
	// after some time. Even with this measure, over time the number of bytes
	// in and out of the proxy may still indicate proxying.

	waitGroup := new(sync.WaitGroup)
	relayErrors := make(chan error, 2)

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
		// to use io.Copy, keeping messages at most 32K in size. Note that
		// testing with io.CopyBuffer and a buffer of size 65536 actually
		// yielded the pion error io.ErrShortBuffer, "short buffer", while a
		// buffer of size 65535 worked.

		_, err := io.Copy(webRTCConn, destinationConn)
		if err != nil {
			relayErrors <- errors.Trace(err)
			return
		}
	}()

	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		_, err := io.Copy(destinationConn, webRTCConn)
		if err != nil {
			relayErrors <- errors.Trace(err)
			return
		}
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

	return err
}

func (p *Proxy) getMetrics() (*ProxyMetrics, error) {

	baseMetrics, err := EncodeBaseMetrics(p.config.BaseMetrics)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return &ProxyMetrics{
		BaseMetrics:                   baseMetrics,
		ProxyProtocolVersion:          ProxyProtocolVersion1,
		NATType:                       p.config.DialParameters.NATType(),
		PortMappingTypes:              p.config.DialParameters.PortMappingTypes(),
		MaxClients:                    int32(p.config.MaxClients),
		ConnectingClients:             atomic.LoadInt32(&p.connectingClients),
		ConnectedClients:              atomic.LoadInt32(&p.connectedClients),
		LimitUpstreamBytesPerSecond:   int64(p.config.LimitUpstreamBytesPerSecond),
		LimitDownstreamBytesPerSecond: int64(p.config.LimitDownstreamBytesPerSecond),
		PeakUpstreamBytesPerSecond:    atomic.LoadInt64(&p.peakBytesUp),
		PeakDownstreamBytesPerSecond:  atomic.LoadInt64(&p.peakBytesDown),
	}, nil
}
