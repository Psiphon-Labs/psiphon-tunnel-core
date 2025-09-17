/*
 * Copyright (c) 2015, Psiphon Inc.
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
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	std_errors "errors"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"net"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/crypto/ssh"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/fragmentor"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/inproxy"
	inproxy_dtls "github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/inproxy/dtls"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/obfuscator"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/quic"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/refraction"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tactics"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/wildcard"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/transferstats"
	"github.com/fxamacker/cbor/v2"
)

// Tunneler specifies the interface required by components that use tunnels.
type Tunneler interface {

	// Dial creates a tunneled connection.
	//
	// When split tunnel mode is enabled, the connection may be untunneled,
	// depending on GeoIP classification of the destination.
	//
	// downstreamConn is an optional parameter which specifies a connection to be
	// explicitly closed when the Dialed connection is closed. For instance, this
	// is used to close downstreamConn App<->LocalProxy connections when the related
	// LocalProxy<->SshPortForward connections close.
	Dial(remoteAddr string, downstreamConn net.Conn) (conn net.Conn, err error)

	DirectDial(remoteAddr string) (conn net.Conn, err error)

	SignalComponentFailure()
}

// TunnelOwner specifies the interface required by Tunnel to notify its
// owner when it has failed. The owner may, as in the case of the Controller,
// remove the tunnel from its list of active tunnels.
type TunnelOwner interface {
	SignalSeededNewSLOK()
	SignalTunnelFailure(tunnel *Tunnel)
}

// Tunnel is a connection to a Psiphon server. An established
// tunnel includes a network connection to the specified server
// and an SSH session built on top of that transport.
type Tunnel struct {
	mutex                          *sync.Mutex
	config                         *Config
	isActivated                    bool
	isStatusReporter               bool
	isDiscarded                    bool
	isClosed                       bool
	dialParams                     *DialParameters
	livenessTestMetrics            *livenessTestMetrics
	extraFailureAction             func()
	serverContext                  *ServerContext
	monitoringStartTime            time.Time
	conn                           *common.BurstMonitoredConn
	sshClient                      *ssh.Client
	sshServerRequests              <-chan *ssh.Request
	operateWaitGroup               *sync.WaitGroup
	operateCtx                     context.Context
	stopOperate                    context.CancelFunc
	signalPortForwardFailure       chan struct{}
	totalPortForwardFailures       int
	adjustedEstablishStartTime     time.Time
	establishDuration              time.Duration
	establishedTime                time.Time
	handledSSHKeepAliveFailure     int32
	inFlightConnectedRequestSignal chan struct{}
}

// getCustomParameters helpers wrap the verbose function call chain required
// to get a current snapshot of the parameters.Parameters customized with the
// dial parameters associated with a tunnel.

func (tunnel *Tunnel) getCustomParameters() parameters.ParametersAccessor {
	return getCustomParameters(tunnel.config, tunnel.dialParams)
}

func getCustomParameters(
	config *Config, dialParams *DialParameters) parameters.ParametersAccessor {
	return config.GetParameters().GetCustom(dialParams.NetworkLatencyMultiplier)
}

// ConnectTunnel first makes a network transport connection to the
// Psiphon server and then establishes an SSH client session on top of
// that transport. The SSH server is authenticated using the public
// key in the server entry.
// Depending on the server's capabilities, the connection may use
// plain SSH over TCP, obfuscated SSH over TCP, or obfuscated SSH over
// HTTP (meek protocol).
// When requiredProtocol is not blank, that protocol is used. Otherwise,
// the a random supported protocol is used.
//
// Call Activate on a connected tunnel to complete its establishment
// before using.
//
// Tunnel establishment is split into two phases: connection, and
// activation. The Controller will run many ConnectTunnel calls
// concurrently and then, to avoid unnecessary overhead from making
// handshake requests and starting operateTunnel from tunnels which
// may be discarded, call Activate on connected tunnels sequentially
// as necessary.
func ConnectTunnel(
	ctx context.Context,
	config *Config,
	adjustedEstablishStartTime time.Time,
	dialParams *DialParameters) (*Tunnel, error) {

	// Build transport layers and establish SSH connection. Note that
	// dialConn and monitoredConn are the same network connection.
	dialResult, err := dialTunnel(ctx, config, dialParams)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// The tunnel is now connected
	return &Tunnel{
		mutex:               new(sync.Mutex),
		config:              config,
		dialParams:          dialParams,
		livenessTestMetrics: dialResult.livenessTestMetrics,
		extraFailureAction:  dialResult.extraFailureAction,
		monitoringStartTime: dialResult.monitoringStartTime,
		conn:                dialResult.monitoredConn,
		sshClient:           dialResult.sshClient,
		sshServerRequests:   dialResult.sshRequests,
		// A buffer allows at least one signal to be sent even when the receiver is
		// not listening. Senders should not block.
		signalPortForwardFailure:   make(chan struct{}, 1),
		adjustedEstablishStartTime: adjustedEstablishStartTime,
	}, nil
}

// Activate completes the tunnel establishment, performing the handshake
// request and starting operateTunnel, the worker that monitors the tunnel
// and handles periodic management.
func (tunnel *Tunnel) Activate(
	ctx context.Context,
	tunnelOwner TunnelOwner,
	isStatusReporter bool) (retErr error) {

	// Ensure that, unless the base context is cancelled, any replayed dial
	// parameters are cleared, no longer to be retried, if the tunnel fails to
	// activate.
	activationSucceeded := false
	baseCtx := ctx
	defer func() {
		if !activationSucceeded && baseCtx.Err() != context.Canceled {
			tunnel.dialParams.Failed(tunnel.config, retErr)
			if tunnel.extraFailureAction != nil {
				tunnel.extraFailureAction()
			}
			if retErr != nil {
				_ = RecordFailedTunnelStat(
					tunnel.config,
					tunnel.dialParams,
					tunnel.livenessTestMetrics,
					-1,
					-1,
					retErr)
			}
		}
	}()

	// Create a new Psiphon API server context for this tunnel. This includes
	// performing a handshake request. If the handshake fails, this activation
	// fails.
	var serverContext *ServerContext
	if !tunnel.config.DisableApi {
		NoticeInfo(
			"starting server context for %s",
			tunnel.dialParams.ServerEntry.GetDiagnosticID())

		// Call NewServerContext in a goroutine, as it blocks on a network operation,
		// the handshake request, and would block shutdown. If the shutdown signal is
		// received, close the tunnel, which will interrupt the handshake request
		// that may be blocking NewServerContext.
		//
		// Timeout after PsiphonApiServerTimeoutSeconds. NewServerContext may not
		// return if the tunnel network connection is unstable during the handshake
		// request. At this point, there is no operateTunnel monitor that will detect
		// this condition with SSH keep alives.

		doInproxy := protocol.TunnelProtocolUsesInproxy(tunnel.dialParams.TunnelProtocol)

		var timeoutParameter string
		if doInproxy {
			// Optionally allow more time in case the broker/server relay
			// requires additional round trips to establish a new session.
			timeoutParameter = parameters.InproxyPsiphonAPIRequestTimeout
		} else {
			timeoutParameter = parameters.PsiphonAPIRequestTimeout
		}
		timeout := tunnel.getCustomParameters().Duration(timeoutParameter)

		var handshakeCtx context.Context
		var cancelFunc context.CancelFunc
		if timeout > 0 {
			handshakeCtx, cancelFunc = context.WithTimeout(ctx, timeout)
		} else {
			handshakeCtx, cancelFunc = context.WithCancel(ctx)
		}

		type newServerContextResult struct {
			serverContext *ServerContext
			err           error
		}

		resultChannel := make(chan newServerContextResult)

		wg := new(sync.WaitGroup)

		if doInproxy {

			// Launch a handler to handle broker/server relay SSH requests,
			// which will occur when the broker needs to establish a new
			// session with the server.
			wg.Add(1)
			go func() {
				defer wg.Done()
				notice := true
				for {
					select {
					case serverRequest := <-tunnel.sshServerRequests:
						if serverRequest != nil {
							if serverRequest.Type == protocol.PSIPHON_API_INPROXY_RELAY_REQUEST_NAME {

								if notice {
									NoticeInfo(
										"relaying inproxy broker packets for %s",
										tunnel.dialParams.ServerEntry.GetDiagnosticID())
									notice = false
								}
								err := tunnel.relayInproxyPacketRoundTrip(handshakeCtx, serverRequest)
								if err != nil {
									NoticeWarning(
										"relay inproxy broker packets failed: %v",
										errors.Trace(err))
									// Continue
								}

							} else {

								// There's a potential race condition in which
								// post-handshake SSH requests, such as OSL or
								// alert requests, arrive to this handler instead
								// of operateTunnel, so invoke HandleServerRequest here.
								HandleServerRequest(tunnelOwner, tunnel, serverRequest)
							}
						}
					case <-handshakeCtx.Done():
						return
					}
				}
			}()
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			serverContext, err := NewServerContext(tunnel)
			resultChannel <- newServerContextResult{
				serverContext: serverContext,
				err:           err,
			}
		}()

		var result newServerContextResult

		select {
		case result = <-resultChannel:
		case <-handshakeCtx.Done():
			result.err = handshakeCtx.Err()
			// Interrupt the goroutine
			tunnel.Close(true)
			<-resultChannel
		}

		cancelFunc()
		wg.Wait()

		if result.err != nil {
			return errors.Trace(result.err)
		}

		serverContext = result.serverContext
	}

	// The activation succeeded.
	activationSucceeded = true

	tunnel.mutex.Lock()

	// It may happen that the tunnel gets closed while Activate is running.
	// In this case, abort here, to ensure that the operateTunnel goroutine
	// will not be launched after Close is called.
	if tunnel.isClosed {
		return errors.TraceNew("tunnel is closed")
	}

	tunnel.isActivated = true
	tunnel.isStatusReporter = isStatusReporter
	tunnel.serverContext = serverContext

	// establishDuration is the elapsed time between the controller starting tunnel
	// establishment and this tunnel being established. The reported value represents
	// how long the user waited between starting the client and having a usable tunnel;
	// or how long between the client detecting an unexpected tunnel disconnect and
	// completing automatic reestablishment.
	//
	// This time period may include time spent unsuccessfully connecting to other
	// servers. Time spent waiting for network connectivity is excluded.
	tunnel.establishDuration = time.Since(tunnel.adjustedEstablishStartTime)
	tunnel.establishedTime = time.Now()

	// Use the Background context instead of the controller run context, as tunnels
	// are terminated when the controller calls tunnel.Close.
	tunnel.operateCtx, tunnel.stopOperate = context.WithCancel(context.Background())
	tunnel.operateWaitGroup = new(sync.WaitGroup)

	// Spawn the operateTunnel goroutine, which monitors the tunnel and handles periodic
	// stats updates.
	tunnel.operateWaitGroup.Add(1)
	go tunnel.operateTunnel(tunnelOwner)

	tunnel.mutex.Unlock()

	return nil
}

func (tunnel *Tunnel) relayInproxyPacketRoundTrip(
	ctx context.Context, request *ssh.Request) (retErr error) {

	defer func() {
		if retErr != nil {
			_ = request.Reply(false, nil)
		}
	}()

	// Continue the broker/server relay started in handshake round trip.

	// server -> broker

	var relayRequest protocol.InproxyRelayRequest
	err := cbor.Unmarshal(request.Payload, &relayRequest)
	if err != nil {
		return errors.Trace(err)
	}

	inproxyConn := tunnel.dialParams.inproxyConn.Load().(*inproxy.ClientConn)
	if inproxyConn == nil {
		return errors.TraceNew("missing inproxyConn")
	}

	responsePacket, err := inproxyConn.RelayPacket(ctx, relayRequest.Packet)
	if err != nil {
		return errors.Trace(err)
	}

	// RelayPacket may return a nil packet when the relay is complete.
	if responsePacket == nil {
		return nil
	}

	// broker -> server

	relayResponse := &protocol.InproxyRelayResponse{
		Packet: responsePacket,
	}
	responsePayload, err := protocol.CBOREncoding.Marshal(relayResponse)
	if err != nil {
		return errors.Trace(err)
	}

	err = request.Reply(true, responsePayload)
	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

// Close stops operating the tunnel and closes the underlying connection.
// Supports multiple and/or concurrent calls to Close().
// When isDiscarded is set, operateTunnel will not attempt to send final
// status requests.
func (tunnel *Tunnel) Close(isDiscarded bool) {

	tunnel.mutex.Lock()
	tunnel.isDiscarded = isDiscarded
	isActivated := tunnel.isActivated
	isClosed := tunnel.isClosed
	tunnel.isClosed = true
	tunnel.mutex.Unlock()

	if !isClosed {

		// Signal operateTunnel to stop before closing the tunnel -- this
		// allows a final status request to be made in the case of an orderly
		// shutdown.
		// A timer is set, so if operateTunnel takes too long to stop, the
		// tunnel is closed, which will interrupt any slow final status request.

		if isActivated {
			timeout := tunnel.getCustomParameters().Duration(
				parameters.TunnelOperateShutdownTimeout)
			afterFunc := time.AfterFunc(
				timeout,
				func() { tunnel.conn.Close() })
			tunnel.stopOperate()
			tunnel.operateWaitGroup.Wait()
			afterFunc.Stop()
		}

		tunnel.sshClient.Close()
		// tunnel.conn.Close() may get called multiple times, which is allowed.
		tunnel.conn.Close()

		err := tunnel.sshClient.Wait()
		if err != nil {
			NoticeWarning("close tunnel ssh error: %s", err)
		}
	}

	// Log burst metrics now that the BurstMonitoredConn is closed.
	// Metrics will be empty when burst monitoring is disabled.
	if !isDiscarded && isActivated {
		burstMetrics := tunnel.conn.GetMetrics(tunnel.monitoringStartTime)
		if len(burstMetrics) > 0 {
			NoticeBursts(
				tunnel.dialParams.ServerEntry.GetDiagnosticID(),
				burstMetrics)
		}
	}
}

// SetInFlightConnectedRequest checks if a connected request can begin and
// sets the channel used to signal that the request is complete.
//
// The caller must not initiate a connected request when
// SetInFlightConnectedRequest returns false. When SetInFlightConnectedRequest
// returns true, the caller must call SetInFlightConnectedRequest(nil) when
// the connected request completes.
func (tunnel *Tunnel) SetInFlightConnectedRequest(requestSignal chan struct{}) bool {
	tunnel.mutex.Lock()
	defer tunnel.mutex.Unlock()

	// If already closing, don't start a connected request: the
	// TunnelOperateShutdownTimeout period may be nearly expired.
	if tunnel.isClosed {
		return false
	}

	if requestSignal == nil {
		// Not already in-flight (not expected)
		if tunnel.inFlightConnectedRequestSignal == nil {
			return false
		}
	} else {
		// Already in-flight (not expected)
		if tunnel.inFlightConnectedRequestSignal != nil {
			return false
		}
	}

	tunnel.inFlightConnectedRequestSignal = requestSignal

	return true
}

// AwaitInFlightConnectedRequest waits for the signal that any in-flight
// connected request is complete.
//
// AwaitInFlightConnectedRequest may block until the connected request is
// aborted by terminating the tunnel.
func (tunnel *Tunnel) AwaitInFlightConnectedRequest() {
	tunnel.mutex.Lock()
	requestSignal := tunnel.inFlightConnectedRequestSignal
	tunnel.mutex.Unlock()

	if requestSignal != nil {
		<-requestSignal
	}
}

// IsActivated returns the tunnel's activated flag.
func (tunnel *Tunnel) IsActivated() bool {
	tunnel.mutex.Lock()
	defer tunnel.mutex.Unlock()
	return tunnel.isActivated
}

// IsDiscarded returns the tunnel's discarded flag.
func (tunnel *Tunnel) IsDiscarded() bool {
	tunnel.mutex.Lock()
	defer tunnel.mutex.Unlock()
	return tunnel.isDiscarded
}

// SendAPIRequest sends an API request as an SSH request through the tunnel.
// This function blocks awaiting a response. Only one request may be in-flight
// at once; a concurrent SendAPIRequest will block until an active request
// receives its response (or the SSH connection is terminated).
func (tunnel *Tunnel) SendAPIRequest(
	name string, requestPayload []byte) ([]byte, error) {

	ok, responsePayload, err := tunnel.sshClient.Conn.SendRequest(
		name, true, requestPayload)

	if err != nil {
		return nil, errors.Trace(err)
	}

	if !ok {
		return nil, errors.TraceNew("API request rejected")
	}

	return responsePayload, nil
}

// DialTCPChannel establishes a TCP port forward connection through the
// tunnel.
//
// When split tunnel mode is enabled, and unless alwaysTunneled is set, the
// server may reject the port forward and indicate that the client is to make
// direct, untunneled connection. In this case, the bool return value is true
// and net.Conn and error are nil.
//
// downstreamConn is an optional parameter which specifies a connection to be
// explicitly closed when the dialed connection is closed.
func (tunnel *Tunnel) DialTCPChannel(
	remoteAddr string,
	alwaysTunneled bool,
	downstreamConn net.Conn) (net.Conn, bool, error) {

	channelType := "direct-tcpip"
	if alwaysTunneled && tunnel.config.IsSplitTunnelEnabled() {
		// This channel type is only necessary in split tunnel mode.
		channelType = protocol.TCP_PORT_FORWARD_NO_SPLIT_TUNNEL_TYPE
	}

	channel, err := tunnel.dialChannel(channelType, remoteAddr)
	if err != nil {
		if isSplitTunnelRejectReason(err) {
			return nil, true, nil
		}
		return nil, false, errors.Trace(err)
	}

	netConn, ok := channel.(net.Conn)
	if !ok {
		return nil, false, errors.Tracef("unexpected channel type: %T", channel)
	}

	conn := &TunneledConn{
		Conn:           netConn,
		tunnel:         tunnel,
		downstreamConn: downstreamConn}

	return tunnel.wrapWithTransferStats(conn), false, nil
}

func (tunnel *Tunnel) DialPacketTunnelChannel() (net.Conn, error) {

	channel, err := tunnel.dialChannel(protocol.PACKET_TUNNEL_CHANNEL_TYPE, "")
	if err != nil {
		return nil, errors.Trace(err)
	}

	sshChannel, ok := channel.(ssh.Channel)
	if !ok {
		return nil, errors.Tracef("unexpected channel type: %T", channel)
	}

	NoticeInfo("DialPacketTunnelChannel: established channel")

	conn := newChannelConn(sshChannel)

	// wrapWithTransferStats will track bytes transferred for the
	// packet tunnel. It will count packet overhead (TCP/UDP/IP headers).
	//
	// Since the data in the channel is not HTTP or TLS, no domain bytes
	// counting is expected.
	//
	// transferstats are also used to determine that there's been recent
	// activity and skip periodic SSH keep alives; see Tunnel.operateTunnel.

	return tunnel.wrapWithTransferStats(conn), nil
}

func (tunnel *Tunnel) dialChannel(channelType, remoteAddr string) (interface{}, error) {

	if !tunnel.IsActivated() {
		return nil, errors.TraceNew("tunnel is not activated")
	}

	// Note: there is no dial context since SSH port forward dials cannot
	// be interrupted directly. Closing the tunnel will interrupt the dials.
	// A timeout is set to unblock this function, but the goroutine may
	// not exit until the tunnel is closed.

	type channelDialResult struct {
		channel interface{}
		err     error
	}

	// Use a buffer of 1 as there are two senders and only one guaranteed receive.

	results := make(chan *channelDialResult, 1)

	afterFunc := time.AfterFunc(
		tunnel.getCustomParameters().Duration(
			parameters.TunnelPortForwardDialTimeout),
		func() {
			results <- &channelDialResult{
				nil, errors.Tracef("channel dial timeout: %s", channelType)}
		})
	defer afterFunc.Stop()

	go func() {
		result := new(channelDialResult)
		switch channelType {

		case "direct-tcpip", protocol.TCP_PORT_FORWARD_NO_SPLIT_TUNNEL_TYPE:
			// The protocol.TCP_PORT_FORWARD_NO_SPLIT_TUNNEL_TYPE is the same as
			// "direct-tcpip", except split tunnel channel rejections are disallowed
			// even when split tunnel mode is enabled.
			result.channel, result.err =
				tunnel.sshClient.Dial(channelType, remoteAddr)

		default:
			var sshRequests <-chan *ssh.Request
			result.channel, sshRequests, result.err =
				tunnel.sshClient.OpenChannel(channelType, nil)
			if result.err == nil {
				go ssh.DiscardRequests(sshRequests)
			}
		}
		if result.err != nil {
			result.err = errors.Trace(result.err)
		}
		results <- result
	}()

	result := <-results

	if result.err != nil {
		if !isSplitTunnelRejectReason(result.err) {
			select {
			case tunnel.signalPortForwardFailure <- struct{}{}:
			default:
			}
		}
		return nil, errors.Trace(result.err)
	}

	return result.channel, nil
}

func isSplitTunnelRejectReason(err error) bool {

	var openChannelErr *ssh.OpenChannelError
	if std_errors.As(err, &openChannelErr) {
		return openChannelErr.Reason ==
			ssh.RejectionReason(protocol.CHANNEL_REJECT_REASON_SPLIT_TUNNEL)
	}

	return false
}

func (tunnel *Tunnel) wrapWithTransferStats(conn net.Conn) net.Conn {

	// Tunnel does not have a serverContext when DisableApi is set. We still use
	// transferstats.Conn to count bytes transferred for monitoring tunnel
	// quality.
	var regexps *transferstats.Regexps
	if tunnel.serverContext != nil {
		regexps = tunnel.serverContext.StatsRegexps()
	}

	return transferstats.NewConn(
		conn, tunnel.dialParams.ServerEntry.IpAddress, regexps)
}

// SignalComponentFailure notifies the tunnel that an associated component has failed.
// This will terminate the tunnel.
func (tunnel *Tunnel) SignalComponentFailure() {
	NoticeWarning("tunnel received component failure signal")
	tunnel.Close(false)
}

// TunneledConn implements net.Conn and wraps a port forward connection.
// It is used to hook into Read and Write to observe I/O errors and
// report these errors back to the tunnel monitor as port forward failures.
// TunneledConn optionally tracks a peer connection to be explicitly closed
// when the TunneledConn is closed.
type TunneledConn struct {
	net.Conn
	tunnel         *Tunnel
	downstreamConn net.Conn
}

func (conn *TunneledConn) Read(buffer []byte) (n int, err error) {
	n, err = conn.Conn.Read(buffer)
	if err != nil && err != io.EOF {
		// Report new failure. Won't block; assumes the receiver
		// has a sufficient buffer for the threshold number of reports.
		// TODO: conditional on type of error or error message?
		select {
		case conn.tunnel.signalPortForwardFailure <- struct{}{}:
		default:
		}
	}
	return
}

func (conn *TunneledConn) Write(buffer []byte) (n int, err error) {
	n, err = conn.Conn.Write(buffer)
	if err != nil && err != io.EOF {
		// Same as TunneledConn.Read()
		select {
		case conn.tunnel.signalPortForwardFailure <- struct{}{}:
		default:
		}
	}
	return
}

func (conn *TunneledConn) Close() error {
	if conn.downstreamConn != nil {
		conn.downstreamConn.Close()
	}
	return conn.Conn.Close()
}

type dialResult struct {
	dialConn            net.Conn
	monitoringStartTime time.Time
	monitoredConn       *common.BurstMonitoredConn
	sshClient           *ssh.Client
	sshRequests         <-chan *ssh.Request
	livenessTestMetrics *livenessTestMetrics
	extraFailureAction  func()
}

// dialTunnel is a helper that builds the transport layers and establishes the
// SSH connection. When additional dial configuration is used, dial metrics
// are recorded and returned.
func dialTunnel(
	ctx context.Context,
	config *Config,
	dialParams *DialParameters) (_ *dialResult, retErr error) {

	// Return immediately when overall context is canceled or timed-out. This
	// avoids notice noise.
	err := ctx.Err()
	if err != nil {
		return nil, errors.Trace(err)
	}

	p := getCustomParameters(config, dialParams)
	timeout := p.Duration(parameters.TunnelConnectTimeout)
	rateLimits := p.RateLimits(parameters.TunnelRateLimits)
	obfuscatedSSHMinPadding := p.Int(parameters.ObfuscatedSSHMinPadding)
	obfuscatedSSHMaxPadding := p.Int(parameters.ObfuscatedSSHMaxPadding)
	livenessTestSpec := getLivenessTestSpec(p, dialParams.TunnelProtocol, dialParams.EstablishedTunnelsCount)
	burstUpstreamTargetBytes := int64(p.Int(parameters.ClientBurstUpstreamTargetBytes))
	burstUpstreamDeadline := p.Duration(parameters.ClientBurstUpstreamDeadline)
	burstDownstreamTargetBytes := int64(p.Int(parameters.ClientBurstDownstreamTargetBytes))
	burstDownstreamDeadline := p.Duration(parameters.ClientBurstDownstreamDeadline)
	tlsOSSHApplyTrafficShaping := p.WeightedCoinFlip(parameters.TLSTunnelTrafficShapingProbability)
	tlsOSSHMinTLSPadding := p.Int(parameters.TLSTunnelMinTLSPadding)
	tlsOSSHMaxTLSPadding := p.Int(parameters.TLSTunnelMaxTLSPadding)
	conjureEnableIPv6Dials := p.Bool(parameters.ConjureEnableIPv6Dials)
	conjureEnablePortRandomization := p.Bool(parameters.ConjureEnablePortRandomization)
	conjureEnableRegistrationOverrides := p.Bool(parameters.ConjureEnableRegistrationOverrides)
	p.Close()

	// Ensure that, unless the base context is cancelled, any replayed dial
	// parameters are cleared, no longer to be retried, if the tunnel fails to
	// connect.
	//
	// Limitation: dials that fail to connect due to the server being in a
	// load-limiting state are not distinguished and excepted from this
	// logic.
	dialSucceeded := false
	baseCtx := ctx
	var failedTunnelLivenessTestMetrics *livenessTestMetrics
	var extraFailureAction func()
	defer func() {
		if !dialSucceeded && baseCtx.Err() != context.Canceled {
			dialParams.Failed(config, retErr)
			if extraFailureAction != nil {
				extraFailureAction()
			}
			if retErr != nil {
				_ = RecordFailedTunnelStat(
					config,
					dialParams,
					failedTunnelLivenessTestMetrics,
					-1,
					-1,
					retErr)
			}
		}
	}()

	var cancelFunc context.CancelFunc
	ctx, cancelFunc = context.WithTimeout(ctx, timeout)
	defer cancelFunc()

	// DialDuration is the elapsed time for both successful and failed tunnel
	// dials. For successful tunnels, it includes any the network protocol
	// handshake(s), obfuscation protocol handshake(s), SSH handshake, and
	// liveness test, when performed.
	//
	// Note: ensure DialDuration is set before calling any function which logs
	// dial_duration.

	startDialTime := time.Now()
	defer func() {
		dialParams.DialDuration = time.Since(startDialTime)
	}()

	// Note: dialParams.MeekResolvedIPAddress isn't set until the dial begins,
	// so it will always be blank in NoticeConnectingServer.

	NoticeConnectingServer(dialParams)

	// Create the base transport: meek or direct connection

	var dialConn net.Conn

	if protocol.TunnelProtocolUsesMeek(dialParams.TunnelProtocol) {

		dialConn, err = DialMeek(
			ctx,
			dialParams.GetMeekConfig(),
			dialParams.GetDialConfig())
		if err != nil {
			return nil, errors.Trace(err)
		}

	} else if protocol.TunnelProtocolUsesQUIC(dialParams.TunnelProtocol) {

		var packetConn net.PacketConn
		var remoteAddr *net.UDPAddr

		// Special case: explict in-proxy dial. TCP dials wire up in-proxy
		// dials via DialConfig and its CustomDialer using
		// makeInproxyTCPDialer. common/quic doesn't have an equivilent to
		// CustomDialer.

		if protocol.TunnelProtocolUsesInproxy(dialParams.TunnelProtocol) {

			packetConn, err = dialInproxy(ctx, config, dialParams)
			if err != nil {
				return nil, errors.Trace(err)
			}

			// Use the actual 2nd hop destination address as the remote
			// address for correct behavior in
			// common/quic.getMaxPreDiscoveryPacketSize, which differs for
			// IPv4 vs. IPv6 destination addresses; and
			// ObfuscatedPacketConn.RemoteAddr. The 2nd hop destination
			// address is not actually dialed.
			//
			// Limitation: for domain destinations, the in-proxy proxy
			// resolves the domain, so just assume IPv6, which has lower max
			// padding(see quic.getMaxPreDiscoveryPacketSize), and use a stub
			// address.

			host, portStr, err := net.SplitHostPort(dialParams.DirectDialAddress)
			if err != nil {
				return nil, errors.Trace(err)
			}
			port, err := strconv.Atoi(portStr)
			if err != nil {
				return nil, errors.Trace(err)
			}
			IP := net.ParseIP(host)
			if IP == nil {
				IP = net.ParseIP("fd00::")
			}
			remoteAddr = &net.UDPAddr{IP: IP, Port: port}

		} else {

			packetConn, remoteAddr, err = NewUDPConn(
				ctx, "udp", false, "", dialParams.DirectDialAddress, dialParams.GetDialConfig())
			if err != nil {
				return nil, errors.Trace(err)
			}
		}

		dialConn, err = quic.Dial(
			ctx,
			packetConn,
			remoteAddr,
			dialParams.QUICDialSNIAddress,
			dialParams.QUICVersion,
			dialParams.QUICClientHelloSeed,
			dialParams.ServerEntry.SshObfuscatedKey,
			dialParams.ObfuscatedQUICPaddingSeed,
			dialParams.ObfuscatedQUICNonceTransformerParameters,
			dialParams.QUICDisablePathMTUDiscovery,
			dialParams.QUICMaxPacketSizeAdjustment,
			dialParams.QUICDialEarly,
			dialParams.QUICUseObfuscatedPSK,
			dialParams.quicTLSClientSessionCache)
		if err != nil {
			return nil, errors.Trace(err)
		}

	} else if protocol.TunnelProtocolUsesTapDance(dialParams.TunnelProtocol) {

		dialConn, err = refraction.DialTapDance(
			ctx,
			config.EmitRefractionNetworkingLogs,
			config.GetPsiphonDataDirectory(),
			NewRefractionNetworkingDialer(dialParams.GetDialConfig()).DialContext,
			dialParams.DirectDialAddress)
		if err != nil {
			return nil, errors.Trace(err)
		}

	} else if protocol.TunnelProtocolUsesConjure(dialParams.TunnelProtocol) {

		dialConn, extraFailureAction, err = dialConjure(
			ctx,
			config,
			dialParams,
			conjureEnableIPv6Dials,
			conjureEnablePortRandomization,
			conjureEnableRegistrationOverrides)
		if err != nil {
			return nil, errors.Trace(err)
		}

	} else if protocol.TunnelProtocolUsesTLSOSSH(dialParams.TunnelProtocol) {

		dialConn, err = DialTLSTunnel(
			ctx,
			dialParams.GetTLSOSSHConfig(config),
			dialParams.GetDialConfig(),
			tlsOSSHApplyTrafficShaping,
			tlsOSSHMinTLSPadding,
			tlsOSSHMaxTLSPadding)
		if err != nil {
			return nil, errors.Trace(err)
		}

	} else if protocol.TunnelProtocolUsesShadowsocks(dialParams.TunnelProtocol) {

		dialConn, err = DialShadowsocksTunnel(
			ctx,
			dialParams.GetShadowsocksConfig(),
			dialParams.GetDialConfig(),
		)
		if err != nil {
			return nil, errors.Trace(err)
		}

	} else {

		// Use NewTCPDialer and don't use DialTCP directly, to ensure that
		// dialParams.GetDialConfig()CustomDialer is applied.
		tcpDialer := NewTCPDialer(dialParams.GetDialConfig())
		dialConn, err = tcpDialer(ctx, "tcp", dialParams.DirectDialAddress)
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	// Some conns report additional metrics. fragmentor.Conns report
	// fragmentor configs.
	if metricsSource, ok := dialConn.(common.MetricsSource); ok {
		dialParams.DialConnMetrics = metricsSource
	}

	if noticeMetricsSource, ok := dialConn.(common.NoticeMetricsSource); ok {
		dialParams.DialConnNoticeMetrics = noticeMetricsSource
	}

	// If dialConn is not a Closer, tunnel failure detection may be slower
	if _, ok := dialConn.(common.Closer); !ok {
		NoticeWarning("tunnel.dialTunnel: dialConn is not a Closer")
	}

	cleanupConn := dialConn
	defer func() {
		// Cleanup on error
		if cleanupConn != nil {
			cleanupConn.Close()
		}
	}()

	monitoringStartTime := time.Now()
	monitoredConn := common.NewBurstMonitoredConn(
		dialConn,
		false,
		burstUpstreamTargetBytes, burstUpstreamDeadline,
		burstDownstreamTargetBytes, burstDownstreamDeadline)

	// Apply throttling (if configured). The underlying dialConn is always a
	// stream, even when the network conn uses UDP.
	throttledConn := common.NewThrottledConn(
		monitoredConn,
		true,
		rateLimits)

	// Add obfuscated SSH layer
	var sshConn net.Conn = throttledConn
	if protocol.TunnelProtocolUsesObfuscatedSSH(dialParams.TunnelProtocol) {
		obfuscatedSSHConn, err := obfuscator.NewClientObfuscatedSSHConn(
			throttledConn,
			dialParams.ServerEntry.SshObfuscatedKey,
			dialParams.ObfuscatorPaddingSeed,
			dialParams.OSSHObfuscatorSeedTransformerParameters,
			dialParams.OSSHPrefixSpec,
			dialParams.OSSHPrefixSplitConfig,
			&obfuscatedSSHMinPadding,
			&obfuscatedSSHMaxPadding)
		if err != nil {
			return nil, errors.Trace(err)
		}
		sshConn = obfuscatedSSHConn
		dialParams.ObfuscatedSSHConnMetrics = obfuscatedSSHConn
	}

	// Now establish the SSH session over the conn transport
	expectedPublicKey, err := base64.StdEncoding.DecodeString(
		dialParams.ServerEntry.SshHostKey)
	if err != nil {
		return nil, errors.Trace(err)
	}
	sshCertChecker := &ssh.CertChecker{
		IsHostAuthority: func(auth ssh.PublicKey, address string) bool {
			// Psiphon servers do not currently use SSH certificates. This CertChecker
			// code path may still be hit if a client attempts to connect using an
			// obsolete server entry.
			return false
		},
		HostKeyFallback: func(addr string, remote net.Addr, publicKey ssh.PublicKey) error {

			// The remote address input isn't checked. In the case of fronted
			// protocols, the immediate remote peer won't be the Psiphon
			// server. In direct cases, the client has just dialed the IP
			// address and expected public key both taken from the same
			// trusted, signed server entry.

			if !bytes.Equal(expectedPublicKey, publicKey.Marshal()) {
				return errors.TraceNew("unexpected host public key")
			}
			return nil
		},
	}

	sshPasswordPayload := &protocol.SSHPasswordPayload{
		SessionId:          config.SessionID,
		SshPassword:        dialParams.ServerEntry.SshPassword,
		ClientCapabilities: []string{protocol.CLIENT_CAPABILITY_SERVER_REQUESTS},
		SponsorID:          config.GetSponsorID(),
	}

	payload, err := json.Marshal(sshPasswordPayload)
	if err != nil {
		return nil, errors.Trace(err)
	}

	sshClientConfig := &ssh.ClientConfig{
		User: dialParams.ServerEntry.SshUsername,
		Auth: []ssh.AuthMethod{
			ssh.Password(string(payload)),
		},
		HostKeyCallback: sshCertChecker.CheckHostKey,
		ClientVersion:   dialParams.SSHClientVersion,
	}

	sshClientConfig.KEXPRNGSeed = dialParams.SSHKEXSeed

	if protocol.TunnelProtocolUsesObfuscatedSSH(dialParams.TunnelProtocol) {
		if config.ObfuscatedSSHAlgorithms != nil {
			sshClientConfig.KeyExchanges = []string{config.ObfuscatedSSHAlgorithms[0]}
			sshClientConfig.Ciphers = []string{config.ObfuscatedSSHAlgorithms[1]}
			sshClientConfig.MACs = []string{config.ObfuscatedSSHAlgorithms[2]}
			sshClientConfig.HostKeyAlgorithms = []string{config.ObfuscatedSSHAlgorithms[3]}

		} else {
			// With Encrypt-then-MAC hash algorithms, packet length is
			// transmitted in plaintext, which aids in traffic analysis.
			//
			// TUNNEL_PROTOCOL_SSH is excepted since its KEX appears in plaintext,
			// and the protocol is intended to look like SSH on the wire.
			sshClientConfig.NoEncryptThenMACHash = true
		}
	} else {
		// For TUNNEL_PROTOCOL_SSH only, the server is expected to randomize
		// its KEX; setting PeerKEXPRNGSeed will ensure successful negotiation
		// between two randomized KEXes.
		if dialParams.ServerEntry.SshObfuscatedKey != "" {
			sshClientConfig.PeerKEXPRNGSeed, err = protocol.DeriveSSHServerKEXPRNGSeed(
				dialParams.ServerEntry.SshObfuscatedKey)
			if err != nil {
				return nil, errors.Trace(err)
			}
		}
	}

	// The ssh session establishment (via ssh.NewClientConn) is wrapped
	// in a timeout to ensure it won't hang. We've encountered firewalls
	// that allow the TCP handshake to complete but then send a RST to the
	// server-side and nothing to the client-side, and if that happens
	// while ssh.NewClientConn is reading, it may wait forever. The timeout
	// closes the conn, which interrupts it.
	// Note: TCP handshake timeouts are provided by TCPConn, and session
	// timeouts *after* ssh establishment are provided by the ssh keep alive
	// in operate tunnel.

	type sshNewClientResult struct {
		sshClient           *ssh.Client
		sshRequests         <-chan *ssh.Request
		livenessTestMetrics *livenessTestMetrics
		err                 error
	}

	resultChannel := make(chan sshNewClientResult)

	// Call NewClientConn in a goroutine, as it blocks on SSH handshake network
	// operations, and would block canceling or shutdown. If the parent context
	// is canceled, close the net.Conn underlying SSH, which will interrupt the
	// SSH handshake that may be blocking NewClientConn.

	go func() {
		// The following is adapted from ssh.Dial(), here using a custom conn
		// The sshAddress is passed through to host key verification callbacks; we don't use it.
		sshAddress := ""
		sshClientConn, sshChannels, sshRequests, err := ssh.NewClientConn(
			sshConn, sshAddress, sshClientConfig)

		var sshClient *ssh.Client
		var metrics *livenessTestMetrics

		if err == nil {

			// sshRequests is handled by operateTunnel.
			// ssh.NewClient also expects to handle the sshRequests
			// value from ssh.NewClientConn and will spawn a goroutine
			// to handle the  <-chan *ssh.Request, so we must provide
			// a closed channel to ensure that goroutine halts instead
			// of hanging on a nil channel.
			noRequests := make(chan *ssh.Request)
			close(noRequests)

			sshClient = ssh.NewClient(sshClientConn, sshChannels, noRequests)

			if livenessTestSpec.MaxUpstreamBytes > 0 || livenessTestSpec.MaxDownstreamBytes > 0 {

				// When configured, perform a liveness test which sends and
				// receives bytes through the tunnel to ensure the tunnel had
				// not been blocked upon or shortly after connecting. This
				// test is performed concurrently for each establishment
				// candidate before selecting a successful tunnel.
				//
				// Note that the liveness test is subject to the
				// TunnelConnectTimeout, which should be adjusted
				// accordinging.

				metrics, err = performLivenessTest(
					sshClient,
					livenessTestSpec,
					dialParams.LivenessTestSeed)

				// Skip notice when cancelling.
				if baseCtx.Err() == nil {
					NoticeLivenessTest(
						dialParams.ServerEntry.GetDiagnosticID(), metrics, err == nil)
				}
			}
		}

		resultChannel <- sshNewClientResult{sshClient, sshRequests, metrics, err}
	}()

	var result sshNewClientResult

	select {
	case result = <-resultChannel:
	case <-ctx.Done():

		// Interrupt the goroutine and capture its error context to
		// distinguish point of failure.
		err := ctx.Err()
		sshConn.Close()
		result = <-resultChannel
		if result.err != nil {
			result.err = fmt.Errorf("%s: %s", err, result.err)
		} else {
			result.err = err
		}
	}

	if result.err != nil {
		failedTunnelLivenessTestMetrics = result.livenessTestMetrics
		return nil, errors.Trace(result.err)
	}

	dialSucceeded = true

	NoticeConnectedServer(dialParams)

	cleanupConn = nil

	// Invoke DNS cache extension (if enabled in the resolver) now that the
	// tunnel is connected and the Psiphon server is authenticated. This
	// demonstrates that any domain name resolved to an endpoint that is or
	// is forwarded to the expected Psiphon server.
	//
	// Limitation: DNS cache extension is not implemented for Refraction
	// Networking protocols. iOS VPN, the primary use case for DNS cache
	// extension, does not enable Refraction Networking.
	if protocol.TunnelProtocolUsesFrontedMeek(dialParams.TunnelProtocol) {
		resolver := config.GetResolver()
		if resolver != nil {
			resolver.VerifyCacheExtension(dialParams.MeekFrontingDialAddress)
		}
	}

	// When configured to do so, hold-off on activating this tunnel. This allows
	// some extra time for slower but less resource intensive protocols to
	// establish tunnels. By holding off post-connect, the client has this
	// established tunnel ready to activate in case other protocols fail to
	// establish. This hold-off phase continues to consume one connection worker.
	//
	// The network latency multiplier is not applied to HoldOffTunnelDuration,
	// as the goal is to apply a consistent hold-off range across all tunnel
	// candidates; and this avoids scaling up any delay users experience.
	//
	// The hold-off is applied regardless of whether this is the first tunnel
	// in a session or a reconnection, even to a server affinity candidate,
	// so that the advantage for other protocols persists.

	if dialParams.HoldOffTunnelDuration > 0 {
		NoticeHoldOffTunnel(dialParams.ServerEntry.GetDiagnosticID(), dialParams.HoldOffTunnelDuration)
		common.SleepWithContext(ctx, dialParams.HoldOffTunnelDuration)
	}

	// Note: dialConn may be used to close the underlying network connection
	// but should not be used to perform I/O as that would interfere with SSH
	// (and also bypasses throttling).

	return &dialResult{
			dialConn:            dialConn,
			monitoringStartTime: monitoringStartTime,
			monitoredConn:       monitoredConn,
			sshClient:           result.sshClient,
			sshRequests:         result.sshRequests,
			livenessTestMetrics: result.livenessTestMetrics,
			extraFailureAction:  extraFailureAction,
		},
		nil
}

func dialConjure(
	ctx context.Context,
	config *Config,
	dialParams *DialParameters,
	enableIPv6Dials bool,
	enablePortRandomization bool,
	enableRegistrationOverrides bool) (net.Conn, func(), error) {

	// Specify a cache key with a scope that ensures that:
	//
	// (a) cached registrations aren't used across different networks, as a
	// registration requires the client's public IP to match the value at time
	// of registration;
	//
	// (b) cached registrations are associated with specific Psiphon server
	// candidates, to ensure that replay will use the same phantom IP(s).
	//
	// This scheme allows for reuse of cached registrations on network A when a
	// client roams from network A to network B and back to network A.
	//
	// Using the network ID as a proxy for client public IP address is a
	// heurisitic: it's possible that a clients public IP address changes
	// without the network ID changing, and it's not guaranteed that the client
	// will be assigned the original public IP on network A; so there's some
	// chance the registration cannot be reused.

	diagnosticID := dialParams.ServerEntry.GetDiagnosticID()

	cacheKey := dialParams.NetworkID + "-" + diagnosticID

	conjureConfig := &refraction.ConjureConfig{
		RegistrationCacheTTL:        dialParams.ConjureCachedRegistrationTTL,
		RegistrationCacheKey:        cacheKey,
		EnableIPv6Dials:             enableIPv6Dials,
		EnablePortRandomization:     enablePortRandomization,
		EnableRegistrationOverrides: enableRegistrationOverrides,
		Transport:                   dialParams.ConjureTransport,
		STUNServerAddress:           dialParams.ConjureSTUNServerAddress,
		DTLSEmptyInitialPacket:      dialParams.ConjureDTLSEmptyInitialPacket,
		DiagnosticID:                diagnosticID,
		Logger:                      NoticeCommonLogger(false),
	}

	if dialParams.ConjureAPIRegistration {

		// Use MeekConn to domain front Conjure API registration.
		//
		// ConjureAPIRegistrarFrontingSpecs are applied via
		// dialParams.GetMeekConfig, and will be subject to replay.
		//
		// Since DialMeek will create a TLS connection immediately, and a cached
		// registration may be used, we will delay initializing the MeekConn-based
		// RoundTripper until we know it's needed. This is implemented by passing
		// in a RoundTripper that establishes a MeekConn when RoundTrip is called.
		//
		// In refraction.dial we configure 0 retries for API registration requests,
		// assuming it's better to let another Psiphon candidate retry, with new
		// domaing fronting parameters. As such, we expect only one round trip call
		// per NewHTTPRoundTripper, so, in practise, there's no performance penalty
		// from establishing a new MeekConn per round trip.
		//
		// Performing the full DialMeek/RoundTrip operation here allows us to call
		// MeekConn.Close and ensure all resources are immediately cleaned up.
		roundTrip := func(request *http.Request) (*http.Response, error) {

			conn, err := DialMeek(
				ctx, dialParams.GetMeekConfig(), dialParams.GetDialConfig())
			if err != nil {
				return nil, errors.Trace(err)
			}
			defer conn.Close()

			response, err := conn.RoundTrip(request)
			if err != nil {
				return nil, errors.Trace(err)
			}

			// Read the response into a buffer and close the response
			// body, ensuring that MeekConn.Close closes all idle connections.
			//
			// Alternatively, we could Clone the request to set
			// http.Request.Close and avoid keeping any idle connection
			// open after the response body is read by gotapdance. Since
			// the response body is small and since gotapdance does not
			// stream the response body, we're taking this approach which
			// ensures cleanup.

			body, err := ioutil.ReadAll(response.Body)
			_ = response.Body.Close()
			if err != nil {
				return nil, errors.Trace(err)
			}
			response.Body = io.NopCloser(bytes.NewReader(body))

			return response, nil
		}

		conjureConfig.APIRegistrarHTTPClient = &http.Client{
			Transport: common.NewHTTPRoundTripper(roundTrip),
		}

		conjureConfig.APIRegistrarBidirectionalURL =
			dialParams.ConjureAPIRegistrarBidirectionalURL
		conjureConfig.APIRegistrarDelay = dialParams.ConjureAPIRegistrarDelay

	} else if dialParams.ConjureDecoyRegistration {

		// The Conjure "phantom" connection is compatible with fragmentation, but
		// the decoy registrar connection, like Tapdance, is not, so force it off.
		// Any tunnel fragmentation metrics will refer to the "phantom" connection
		// only.
		conjureConfig.DoDecoyRegistration = true
		conjureConfig.DecoyRegistrarWidth = dialParams.ConjureDecoyRegistrarWidth
		conjureConfig.DecoyRegistrarDelay = dialParams.ConjureDecoyRegistrarDelay
	}

	// Set extraFailureAction, which is invoked whenever the tunnel fails (i.e.,
	// where RecordFailedTunnelStat is invoked). The action will remove any
	// cached registration. When refraction.DialConjure succeeds, the underlying
	// registration is cached. After refraction.DialConjure returns, it no
	// longer modifies the cached state of that registration, assuming that it
	// remains valid and effective. However adversarial impact on a given
	// phantom IP may not become evident until after the initial TCP connection
	// establishment and handshake performed by refraction.DialConjure. For
	// example, it may be that the phantom dial is targeted for severe
	// throttling which begins or is only evident later in the flow. Scheduling
	// a call to DeleteCachedConjureRegistration allows us to invalidate the
	// cached registration for a tunnel that fails later in its lifecycle.
	//
	// Note that extraFailureAction will retain a reference to conjureConfig for
	// the lifetime of the tunnel.
	extraFailureAction := func() {
		refraction.DeleteCachedConjureRegistration(conjureConfig)
	}

	dialCtx := ctx
	if protocol.ConjureTransportUsesDTLS(dialParams.ConjureTransport) {
		// Conjure doesn't use the DTLS seed scheme, which supports in-proxy
		// DTLS randomization. But every DTLS dial expects to find a seed
		// state, so set the no-seed state.
		dialCtx = inproxy_dtls.SetNoDTLSSeed(ctx)
	}

	dialConn, err := refraction.DialConjure(
		dialCtx,
		config.EmitRefractionNetworkingLogs,
		config.GetPsiphonDataDirectory(),
		NewRefractionNetworkingDialer(dialParams.GetDialConfig()).DialContext,
		dialParams.DirectDialAddress,
		conjureConfig)
	if err != nil {

		// When this function fails, invoke extraFailureAction directly; when it
		// succeeds, return extraFailureAction to be called later.
		extraFailureAction()

		return nil, nil, errors.Trace(err)
	}

	return dialConn, extraFailureAction, nil
}

// makeInproxyTCPDialer returns a dialer which proxies TCP dials via an
// in-proxy proxy, as configured in dialParams.
//
// Limitation: MeekConn may redial TCP for a single tunnel connection, but
// that case is not supported by the in-proxy protocol, as the in-proxy proxy
// closes both its WebRTC DataChannel and the overall client connection when
// the upstream TCP connection closes. Any new connection from the client to
// the proxy must be a new tunnel connection with and accompanying
// broker/server relay. As a future enhancement, consider extending the
// in-proxy protocol to enable the client and proxy to establish additional
// WebRTC DataChannels and new upstream TCP connections within the scope of a
// single proxy/client connection.
func makeInproxyTCPDialer(
	config *Config, dialParams *DialParameters) common.Dialer {

	return func(ctx context.Context, _, _ string) (net.Conn, error) {

		if dialParams.inproxyConn.Load() != nil {
			return nil, errors.TraceNew("redial not supported")
		}

		var conn net.Conn
		var err error

		conn, err = dialInproxy(ctx, config, dialParams)
		if err != nil {
			return nil, errors.Trace(err)
		}

		// When the TCP fragmentor is configured for the 2nd hop protocol,
		// approximate the behavior by applying the fragmentor to the WebRTC
		// DataChannel writes, which will result in delays and DataChannel
		// message sizes which will be reflected in the proxy's relay to its
		// upstream TCP connection.
		//
		// This code is copied from DialTCP.
		//
		// Limitation: TCP BPF settings are not supported and currently
		// disabled for all 2nd hop cases in
		// protocol.TunnelProtocolMayUseClientBPF.

		if dialParams.dialConfig.FragmentorConfig.MayFragment() {
			conn = fragmentor.NewConn(
				dialParams.dialConfig.FragmentorConfig,
				func(message string) {
					NoticeFragmentor(dialParams.dialConfig.DiagnosticID, message)
				},
				conn)
		}

		return conn, nil
	}
}

type inproxyDialFailedError struct {
	err error
}

func (e inproxyDialFailedError) Error() string {
	return e.err.Error()
}

// dialInproxy performs the in-proxy dial and returns the resulting conn for
// use as an underlying conn for the 2nd hop protocol. The in-proxy dial
// first connects to the broker (or reuses an existing connection) to match
// with a proxy; and then establishes connection to the proxy.
func dialInproxy(
	ctx context.Context,
	config *Config,
	dialParams *DialParameters) (retConn *inproxy.ClientConn, retErr error) {

	defer func() {
		// Wrap all returned errors with inproxyDialFailedError so callers can
		// check for dialInproxy failures within nested errors.
		if retErr != nil {
			retErr = &inproxyDialFailedError{err: retErr}
		}
	}()

	isProxy := false
	webRTCDialInstance, err := NewInproxyWebRTCDialInstance(
		config,
		dialParams.NetworkID,
		isProxy,
		dialParams.inproxyNATStateManager,
		dialParams.InproxySTUNDialParameters,
		dialParams.InproxyWebRTCDialParameters)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// dialAddress indicates to the broker and proxy how to dial the upstream
	// Psiphon server, based on the 2nd hop tunnel protocol.

	networkProtocol := inproxy.NetworkProtocolUDP
	reliableTransport := false
	if protocol.TunnelProtocolUsesTCP(dialParams.TunnelProtocol) {
		networkProtocol = inproxy.NetworkProtocolTCP
		reliableTransport = true
	}

	dialAddress := dialParams.DirectDialAddress
	if protocol.TunnelProtocolUsesMeek(dialParams.TunnelProtocol) {
		dialAddress = dialParams.MeekDialAddress
	}

	// Specify the value to be returned by inproxy.ClientConn.RemoteAddr.
	// Currently, the one caller of RemoteAddr is utls, which uses the
	// RemoteAddr as a TLS session cache key when there is no SNI.
	// GetTLSSessionCacheKeyAddress returns a cache key value that is a valid
	// address and that is also a more appropriate TLS session cache key than
	// the proxy address.

	remoteAddrOverride, err := dialParams.ServerEntry.GetTLSSessionCacheKeyAddress(
		dialParams.TunnelProtocol)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// Unlike the proxy broker case, clients already actively fetch tactics
	// during tunnel estalishment, so tactics.SetTacticsAPIParameters are not
	// sent to the broker and no tactics are returned by the broker.
	params := getBaseAPIParameters(
		baseParametersNoDialParameters, true, config, nil)

	// The debugLogging flag is passed to both NoticeCommonLogger and to the
	// inproxy package as well; skipping debug logs in the inproxy package,
	// before calling into the notice logger, avoids unnecessary allocations
	// and formatting when debug logging is off.
	debugLogging := config.InproxyEnableWebRTCDebugLogging

	clientConfig := &inproxy.ClientConfig{
		Logger:                       NoticeCommonLogger(debugLogging),
		EnableWebRTCDebugLogging:     debugLogging,
		BaseAPIParameters:            params,
		BrokerClient:                 dialParams.inproxyBrokerClient,
		WebRTCDialCoordinator:        webRTCDialInstance,
		ReliableTransport:            reliableTransport,
		DialNetworkProtocol:          networkProtocol,
		DialAddress:                  dialAddress,
		RemoteAddrOverride:           remoteAddrOverride,
		PackedDestinationServerEntry: dialParams.inproxyPackedSignedServerEntry,
		MustUpgrade:                  config.OnInproxyMustUpgrade,
	}

	conn, err := inproxy.DialClient(ctx, clientConfig)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// The inproxy.ClientConn is stored in dialParams.inproxyConn in order to
	// later fetch its connection ID and to facilitate broker/client replay.
	dialParams.inproxyConn.Store(conn)

	return conn, nil
}

// Fields are exported for JSON encoding in NoticeLivenessTest.
type livenessTestMetrics struct {
	Duration                string
	UpstreamBytes           int
	SentUpstreamBytes       int
	DownstreamBytes         int
	ReceivedDownstreamBytes int
}

func performLivenessTest(
	sshClient *ssh.Client,
	spec *parameters.LivenessTestSpec,
	livenessTestPRNGSeed *prng.Seed) (*livenessTestMetrics, error) {

	metrics := new(livenessTestMetrics)

	defer func(startTime time.Time) {
		metrics.Duration = time.Since(startTime).String()
	}(time.Now())

	PRNG := prng.NewPRNGWithSeed(livenessTestPRNGSeed)

	metrics.UpstreamBytes = PRNG.Range(spec.MinUpstreamBytes, spec.MaxUpstreamBytes)
	metrics.DownstreamBytes = PRNG.Range(spec.MinDownstreamBytes, spec.MaxDownstreamBytes)

	request := &protocol.RandomStreamRequest{
		UpstreamBytes:   metrics.UpstreamBytes,
		DownstreamBytes: metrics.DownstreamBytes,
	}

	extraData, err := json.Marshal(request)
	if err != nil {
		return metrics, errors.Trace(err)
	}

	channel, requests, err := sshClient.OpenChannel(
		protocol.RANDOM_STREAM_CHANNEL_TYPE, extraData)
	if err != nil {
		return metrics, errors.Trace(err)
	}
	defer channel.Close()

	go ssh.DiscardRequests(requests)

	sent := 0
	received := 0
	upstream := new(sync.WaitGroup)
	var errUpstream, errDownstream error

	if metrics.UpstreamBytes > 0 {

		// Process streams concurrently to minimize elapsed time. This also
		// avoids a unidirectional flow burst early in the tunnel lifecycle.

		upstream.Add(1)
		go func() {
			defer upstream.Done()

			// In consideration of memory-constrained environments, use modest-sized copy
			// buffers since many tunnel establishment workers may run the liveness test
			// concurrently.
			var buffer [4096]byte

			n, err := common.CopyNBuffer(channel, rand.Reader, int64(metrics.UpstreamBytes), buffer[:])
			sent = int(n)
			if err != nil {
				errUpstream = errors.Trace(err)
			}
		}()
	}

	if metrics.DownstreamBytes > 0 {
		var buffer [4096]byte
		n, err := common.CopyNBuffer(ioutil.Discard, channel, int64(metrics.DownstreamBytes), buffer[:])
		received = int(n)
		if err != nil {
			errDownstream = errors.Trace(err)
		}
	}

	upstream.Wait()
	metrics.SentUpstreamBytes = sent
	metrics.ReceivedDownstreamBytes = received

	if errUpstream != nil {
		return metrics, errUpstream
	} else if errDownstream != nil {
		return metrics, errDownstream
	}

	return metrics, nil
}

// operateTunnel monitors the health of the tunnel and performs
// periodic work.
//
// BytesTransferred and TotalBytesTransferred notices are emitted
// for live reporting and diagnostics reporting, respectively.
//
// Status requests are sent to the Psiphon API to report bytes
// transferred.
//
// Periodic SSH keep alive packets are sent to ensure the underlying
// TCP connection isn't terminated by NAT, or other network
// interference -- or test if it has been terminated while the device
// has been asleep. When a keep alive times out, the tunnel is
// considered failed.
//
// An immediate SSH keep alive "probe" is sent to test the tunnel and
// server responsiveness when a port forward failure is detected: a
// failed dial or failed read/write. This keep alive has a shorter
// timeout.
//
// Note that port forward failures may be due to non-failure conditions.
// For example, when the user inputs an invalid domain name and
// resolution is done by the ssh server; or trying to connect to a
// non-white-listed port; and the error message in these cases is not
// distinguishable from a a true server error (a common error message,
// "ssh: rejected: administratively prohibited (open failed)", may be
// returned for these cases but also if the server has run out of
// ephemeral ports, for example).
//
// SSH keep alives are not sent when the tunnel has been recently
// active (not only does tunnel activity obviate the necessity of a keep
// alive, testing has shown that keep alives may time out for "busy"
// tunnels, especially over meek protocol and other high latency
// conditions).
//
// "Recently active" is defined has having received payload bytes. Sent
// bytes are not considered as testing has shown bytes may appear to
// send when certain NAT devices have interfered with the tunnel, while
// no bytes are received. In a pathological case, with DNS implemented
// as tunneled UDP, a browser may wait excessively for a domain name to
// resolve, while no new port forward is attempted which would otherwise
// result in a tunnel failure detection.
//
// TODO: change "recently active" to include having received any
// SSH protocol messages from the server, not just user payload?
func (tunnel *Tunnel) operateTunnel(tunnelOwner TunnelOwner) {
	defer tunnel.operateWaitGroup.Done()

	now := time.Now()
	lastBytesReceivedTime := now
	lastTotalBytesTransferedTime := now
	totalSent := int64(0)
	totalReceived := int64(0)
	setDialParamsSucceeded := false

	noticeBytesTransferredTicker := time.NewTicker(1 * time.Second)
	defer noticeBytesTransferredTicker.Stop()

	// The next status request and ssh keep alive times are picked at random,
	// from a range, to make the resulting traffic less fingerprintable,
	// Note: not using Tickers since these are not fixed time periods.
	nextStatusRequestPeriod := func() time.Duration {
		p := tunnel.getCustomParameters()
		return prng.Period(
			p.Duration(parameters.PsiphonAPIStatusRequestPeriodMin),
			p.Duration(parameters.PsiphonAPIStatusRequestPeriodMax))
	}

	statsTimer := time.NewTimer(nextStatusRequestPeriod())
	defer statsTimer.Stop()

	// Only one active tunnel should be designated as the status reporter for
	// sending stats and prune checks. While the stats provide a "take out"
	// scheme that would allow for multiple, concurrent requesters, the prune
	// check does not.
	//
	// The statsTimer is retained, but set to practically never trigger, in
	// the !isStatusReporter case to simplify following select statements.
	if tunnel.isStatusReporter {

		// Schedule an almost-immediate status request to deliver any unreported
		// persistent stats or perform a server entry prune check.
		unreported := CountUnreportedPersistentStats()
		isCheckDue := IsCheckServerEntryTagsDue(tunnel.config)
		if unreported > 0 || isCheckDue {
			NoticeInfo(
				"Unreported persistent stats: %d; server entry check due: %v",
				unreported, isCheckDue)
			p := tunnel.getCustomParameters()
			statsTimer.Reset(
				prng.Period(
					p.Duration(parameters.PsiphonAPIStatusRequestShortPeriodMin),
					p.Duration(parameters.PsiphonAPIStatusRequestShortPeriodMax)))
		}
	} else {
		statsTimer = time.NewTimer(time.Duration(math.MaxInt64))
	}

	nextSshKeepAlivePeriod := func() time.Duration {
		p := tunnel.getCustomParameters()
		return prng.Period(
			p.Duration(parameters.SSHKeepAlivePeriodMin),
			p.Duration(parameters.SSHKeepAlivePeriodMax))
	}

	// TODO: don't initialize timer when config.DisablePeriodicSshKeepAlive is set
	sshKeepAliveTimer := time.NewTimer(nextSshKeepAlivePeriod())
	if tunnel.config.DisablePeriodicSshKeepAlive {
		sshKeepAliveTimer.Stop()
	} else {
		defer sshKeepAliveTimer.Stop()
	}

	// Perform network requests in separate goroutines so as not to block
	// other operations.
	requestsWaitGroup := new(sync.WaitGroup)

	requestsWaitGroup.Add(1)
	signalStatusRequest := make(chan struct{})
	go func() {
		defer requestsWaitGroup.Done()
		for range signalStatusRequest {
			sendStats(tunnel)
		}
	}()

	requestsWaitGroup.Add(1)
	signalPeriodicSshKeepAlive := make(chan time.Duration)
	sshKeepAliveError := make(chan error, 1)
	go func() {
		defer requestsWaitGroup.Done()
		isFirstPeriodicKeepAlive := true
		for timeout := range signalPeriodicSshKeepAlive {
			bytesUp := atomic.LoadInt64(&totalSent)
			bytesDown := atomic.LoadInt64(&totalReceived)
			err := tunnel.sendSshKeepAlive(
				isFirstPeriodicKeepAlive, false, timeout, bytesUp, bytesDown)
			if err != nil {
				select {
				case sshKeepAliveError <- err:
				default:
				}
			}
			isFirstPeriodicKeepAlive = false
		}
	}()

	// Probe-type SSH keep alives have a distinct send worker and may be sent
	// concurrently, to ensure a long period keep alive timeout doesn't delay
	// failed tunnel detection.

	requestsWaitGroup.Add(1)
	signalProbeSshKeepAlive := make(chan time.Duration)
	go func() {
		defer requestsWaitGroup.Done()
		for timeout := range signalProbeSshKeepAlive {
			bytesUp := atomic.LoadInt64(&totalSent)
			bytesDown := atomic.LoadInt64(&totalReceived)
			err := tunnel.sendSshKeepAlive(
				false, true, timeout, bytesUp, bytesDown)
			if err != nil {
				select {
				case sshKeepAliveError <- err:
				default:
				}
			}
		}
	}()

	shutdown := false
	var err error
	for !shutdown && err == nil {
		select {
		case <-noticeBytesTransferredTicker.C:
			sent, received := transferstats.ReportRecentBytesTransferredForServer(
				tunnel.dialParams.ServerEntry.IpAddress)

			if received > 0 {
				lastBytesReceivedTime = time.Now()
			}

			bytesUp := atomic.AddInt64(&totalSent, sent)
			bytesDown := atomic.AddInt64(&totalReceived, received)

			p := tunnel.getCustomParameters()
			noticePeriod := p.Duration(parameters.TotalBytesTransferredNoticePeriod)
			doEmitMemoryMetrics := p.Bool(parameters.TotalBytesTransferredEmitMemoryMetrics)
			replayTargetUpstreamBytes := p.Int(parameters.ReplayTargetUpstreamBytes)
			replayTargetDownstreamBytes := p.Int(parameters.ReplayTargetDownstreamBytes)
			replayTargetTunnelDuration := p.Duration(parameters.ReplayTargetTunnelDuration)

			if lastTotalBytesTransferedTime.Add(noticePeriod).Before(time.Now()) {
				NoticeTotalBytesTransferred(
					tunnel.dialParams.ServerEntry.GetDiagnosticID(), bytesUp, bytesDown)
				if doEmitMemoryMetrics {
					emitMemoryMetrics()
				}
				lastTotalBytesTransferedTime = time.Now()
			}

			// Only emit the frequent BytesTransferred notice when tunnel is not idle.
			if tunnel.config.EmitBytesTransferred && (sent > 0 || received > 0) {
				NoticeBytesTransferred(
					tunnel.dialParams.ServerEntry.GetDiagnosticID(), sent, received)
			}

			// Once the tunnel has connected, activated, successfully transmitted the
			// targeted number of bytes, and been up for the targeted duration
			// (measured from the end of establishment), store its dial parameters for
			// subsequent replay.
			//
			// Even when target bytes and duration are all 0, the tunnel must remain up
			// for at least 1 second due to use of noticeBytesTransferredTicker; for
			// the same reason the granularity of ReplayTargetTunnelDuration is
			// seconds.
			if !setDialParamsSucceeded &&
				bytesUp >= int64(replayTargetUpstreamBytes) &&
				bytesDown >= int64(replayTargetDownstreamBytes) &&
				time.Since(tunnel.establishedTime) >= replayTargetTunnelDuration {

				tunnel.dialParams.Succeeded()
				setDialParamsSucceeded = true
			}

		case <-statsTimer.C:
			if tunnel.isStatusReporter {
				select {
				case signalStatusRequest <- struct{}{}:
				default:
				}
				statsTimer.Reset(nextStatusRequestPeriod())
			}

		case <-sshKeepAliveTimer.C:
			p := tunnel.getCustomParameters()
			inactivePeriod := p.Duration(parameters.SSHKeepAlivePeriodicInactivePeriod)
			if lastBytesReceivedTime.Add(inactivePeriod).Before(time.Now()) {
				timeout := p.Duration(parameters.SSHKeepAlivePeriodicTimeout)
				select {
				case signalPeriodicSshKeepAlive <- timeout:
				default:
				}
			}
			sshKeepAliveTimer.Reset(nextSshKeepAlivePeriod())

		case <-tunnel.signalPortForwardFailure:
			// Note: no mutex on portForwardFailureTotal; only referenced here
			tunnel.totalPortForwardFailures++
			NoticeInfo("port forward failures for %s: %d",
				tunnel.dialParams.ServerEntry.GetDiagnosticID(),
				tunnel.totalPortForwardFailures)

			// If the underlying Conn has closed (meek and other plugin protocols may
			// close themselves in certain error conditions), the tunnel has certainly
			// failed. Otherwise, probe with an SSH keep alive.
			//
			// TODO: the IsClosed case omits the failed tunnel logging and reset
			// actions performed by sendSshKeepAlive. Should self-closing protocols
			// perform these actions themselves?

			if tunnel.conn.IsClosed() {
				err = errors.TraceNew("underlying conn is closed")
			} else {
				p := tunnel.getCustomParameters()
				inactivePeriod := p.Duration(parameters.SSHKeepAliveProbeInactivePeriod)
				if lastBytesReceivedTime.Add(inactivePeriod).Before(time.Now()) {
					timeout := p.Duration(parameters.SSHKeepAliveProbeTimeout)
					select {
					case signalProbeSshKeepAlive <- timeout:
					default:
					}
				}
				if !tunnel.config.DisablePeriodicSshKeepAlive {
					sshKeepAliveTimer.Reset(nextSshKeepAlivePeriod())
				}

			}

		case err = <-sshKeepAliveError:

		case serverRequest := <-tunnel.sshServerRequests:
			if serverRequest != nil {
				HandleServerRequest(tunnelOwner, tunnel, serverRequest)
			}

		case <-tunnel.operateCtx.Done():
			shutdown = true
		}
	}

	close(signalPeriodicSshKeepAlive)
	close(signalProbeSshKeepAlive)
	close(signalStatusRequest)
	requestsWaitGroup.Wait()

	// Capture bytes transferred since the last noticeBytesTransferredTicker tick
	sent, received := transferstats.ReportRecentBytesTransferredForServer(
		tunnel.dialParams.ServerEntry.IpAddress)
	bytesUp := atomic.AddInt64(&totalSent, sent)
	bytesDown := atomic.AddInt64(&totalReceived, received)

	// Always emit a final NoticeTotalBytesTransferred
	NoticeTotalBytesTransferred(
		tunnel.dialParams.ServerEntry.GetDiagnosticID(), bytesUp, bytesDown)

	if err == nil {

		NoticeInfo("shutdown operate tunnel")

		// This commanded shutdown case is initiated by Tunnel.Close, which will
		// wait up to parameters.TunnelOperateShutdownTimeout to allow the following
		// requests to complete.

		// Send a final status request in order to report any outstanding persistent
		// stats and domain bytes transferred as soon as possible.

		sendStats(tunnel)

		// The controller connectedReporter may have initiated a connected request
		// concurrent to this commanded shutdown. SetInFlightConnectedRequest
		// ensures that a connected request doesn't start after the commanded
		// shutdown. AwaitInFlightConnectedRequest blocks until any in flight
		// request completes or is aborted after TunnelOperateShutdownTimeout.
		//
		// As any connected request is performed by a concurrent goroutine,
		// sendStats is called first and AwaitInFlightConnectedRequest second.

		tunnel.AwaitInFlightConnectedRequest()

	} else {

		NoticeWarning("operate tunnel error for %s: %s",
			tunnel.dialParams.ServerEntry.GetDiagnosticID(), err)

		tunnelOwner.SignalTunnelFailure(tunnel)
	}
}

// sendSshKeepAlive is a helper which sends a keepalive@openssh.com request
// on the specified SSH connections and returns true of the request succeeds
// within a specified timeout. If the request fails, the associated conn is
// closed, which will terminate the associated tunnel.
func (tunnel *Tunnel) sendSshKeepAlive(
	isFirstPeriodicKeepAlive bool,
	isProbeKeepAlive bool,
	timeout time.Duration,
	bytesUp int64,
	bytesDown int64) error {

	p := tunnel.getCustomParameters()

	// Random padding to frustrate fingerprinting.
	request := prng.Padding(
		p.Int(parameters.SSHKeepAlivePaddingMinBytes),
		p.Int(parameters.SSHKeepAlivePaddingMaxBytes))

	speedTestSample := isFirstPeriodicKeepAlive
	if !speedTestSample {
		speedTestSample = p.WeightedCoinFlip(
			parameters.SSHKeepAliveSpeedTestSampleProbability)
	}

	networkConnectivityPollPeriod := p.Duration(
		parameters.SSHKeepAliveNetworkConnectivityPollingPeriod)

	resetOnFailure := p.WeightedCoinFlip(
		parameters.SSHKeepAliveResetOnFailureProbability)

	p.Close()

	// Note: there is no request context since SSH requests cannot be interrupted
	// directly. Closing the tunnel will interrupt the request. A timeout is set
	// to unblock this function, but the goroutine may not exit until the tunnel
	// is closed.

	// Use a buffer of 1 as there are two senders and only one guaranteed receive.
	errChannel := make(chan error, 1)

	afterFunc := time.AfterFunc(timeout, func() {
		errChannel <- errors.TraceNew("timed out")
	})
	defer afterFunc.Stop()

	go func() {

		startTime := time.Now()

		// Note: reading a reply is important for last-received-time tunnel
		// duration calculation.
		requestOk, response, err := tunnel.sshClient.SendRequest(
			"keepalive@openssh.com", true, request)

		elapsedTime := time.Since(startTime)

		errChannel <- err

		success := (err == nil && requestOk)

		if success && isProbeKeepAlive {
			NoticeInfo("Probe SSH keep-alive RTT: %s", elapsedTime)
		}

		// Record the keep alive round trip as a speed test sample. The first
		// periodic keep alive is always recorded, as many tunnels are short-lived
		// and we want to ensure that some data is gathered. Subsequent keep alives
		// are recorded with some configurable probability, which, considering that
		// only the last SpeedTestMaxSampleCount samples are retained, enables
		// tuning the sampling frequency.

		if success && speedTestSample {

			err = tactics.AddSpeedTestSample(
				tunnel.config.GetParameters(),
				GetTacticsStorer(tunnel.config),
				tunnel.config.GetNetworkID(),
				tunnel.dialParams.ServerEntry.Region,
				tunnel.dialParams.TunnelProtocol,
				elapsedTime,
				request,
				response)
			if err != nil {
				NoticeWarning("AddSpeedTestSample failed: %s", errors.Trace(err))
			}
		}
	}()

	// While awaiting the response, poll the network connectivity state. If there
	// is network connectivity, on the same network, for the entire duration of
	// the keep alive request and the request fails, record a failed tunnel
	// event.
	//
	// The network connectivity heuristic is intended to reduce the number of
	// failed tunnels reported due to routine situations such as varying mobile
	// network conditions. The polling may produce false positives if the network
	// goes down and up between polling periods, or changes to a new network and
	// back to the previous network between polling periods.
	//
	// For platforms that don't provide a NetworkConnectivityChecker, it is
	// assumed that there is network connectivity.
	//
	// The approximate number of tunneled bytes successfully sent and received is
	// recorded in the failed tunnel event as a quality indicator.

	ticker := time.NewTicker(networkConnectivityPollPeriod)
	defer ticker.Stop()
	continuousNetworkConnectivity := true
	networkID := tunnel.config.GetNetworkID()

	var err error
loop:
	for {
		select {
		case err = <-errChannel:
			break loop
		case <-ticker.C:
			connectivityChecker := tunnel.config.NetworkConnectivityChecker
			if (connectivityChecker != nil &&
				connectivityChecker.HasNetworkConnectivity() != 1) ||
				(networkID != tunnel.config.GetNetworkID()) {

				continuousNetworkConnectivity = false
			}
		}
	}

	err = errors.Trace(err)

	if err != nil {
		tunnel.sshClient.Close()
		tunnel.conn.Close()

		// Don't perform log or reset actions when the keep alive may have been
		// interrupted due to shutdown.

		isShutdown := false
		select {
		case <-tunnel.operateCtx.Done():
			isShutdown = true
		default:
		}

		// Ensure that at most one of the two SSH keep alive workers (periodic and
		// probe) perform the log and reset actions.

		wasHandled := atomic.CompareAndSwapInt32(&tunnel.handledSSHKeepAliveFailure, 0, 1)

		if continuousNetworkConnectivity &&
			!isShutdown &&
			!wasHandled {

			// Note that tunnel.dialParams.Failed is not called in this failed
			// tunnel case, and any replay parameters are retained.
			//
			// The continuousNetworkConnectivity mechanism is an imperfect
			// best-effort to filter out bad network conditions, and isn't
			// enabled on platforms without NetworkConnectivityChecker. There
			// remains a possibility of failure due to innocuous bad network
			// conditions and perhaps device sleep cycles.
			//
			// Furthermore, at this point the tunnel has already passed any
			// pre-handshake liveness test, which is intended to catch cases
			// of late-life cycle blocking.

			_ = RecordFailedTunnelStat(
				tunnel.config,
				tunnel.dialParams,
				tunnel.livenessTestMetrics,
				bytesUp,
				bytesDown,
				err)
			if tunnel.extraFailureAction != nil {
				tunnel.extraFailureAction()
			}

			// SSHKeepAliveResetOnFailureProbability is set when a late-lifecycle
			// impaired protocol attack is suspected. With the given probability, reset
			// server affinity and replay parameters for this server to avoid
			// continuously reconnecting to the server and/or using the same protocol
			// and dial parameters.

			if resetOnFailure {
				NoticeInfo("Delete dial parameters for %s", tunnel.dialParams.ServerEntry.GetDiagnosticID())
				err := DeleteDialParameters(tunnel.dialParams.ServerEntry.IpAddress, tunnel.dialParams.NetworkID)
				if err != nil {
					NoticeWarning("DeleteDialParameters failed: %s", err)
				}
				NoticeInfo("Delete server affinity for %s", tunnel.dialParams.ServerEntry.GetDiagnosticID())
				err = DeleteServerEntryAffinity(tunnel.dialParams.ServerEntry.IpAddress)
				if err != nil {
					NoticeWarning("DeleteServerEntryAffinity failed: %s", err)
				}
			}
		}
	}

	return err
}

// sendStats is a helper for sending session stats to the server.
func sendStats(tunnel *Tunnel) bool {

	// Tunnel does not have a serverContext when DisableApi is set
	if tunnel.serverContext == nil {
		return true
	}

	// Skip when tunnel is discarded
	if tunnel.IsDiscarded() {
		return true
	}

	err := tunnel.serverContext.DoStatusRequest()
	if err != nil {
		NoticeWarning("DoStatusRequest failed for %s: %s",
			tunnel.dialParams.ServerEntry.GetDiagnosticID(), err)
	}

	return err == nil
}

// getLivenessTestSpec returns the LivenessTestSpec for the given tunnel protocol.
func getLivenessTestSpec(
	p parameters.ParametersAccessor,
	tunnelProtocol string,
	establishedTunnelsCount int) *parameters.LivenessTestSpec {

	// matchingSpec returns the first matching LivenessTestSpec for the given
	// tunnelProtocol.
	matchingSpec := func(
		spec parameters.LivenessTestSpecs,
		tunnelProtocol string) *parameters.LivenessTestSpec {
		if len(spec) != 0 {
			// Sort the patterns by length, longest first, so that the most specific
			// match is found first.
			patterns := make([]string, 0, len(spec))
			for p := range spec {
				patterns = append(patterns, p)
			}
			slices.SortFunc(patterns, func(i, j string) int {
				return len(j) - len(i)
			})
			// Find the first and longest pattern that matches the tunnel protocol.
			for _, p := range patterns {
				if wildcard.Match(p, tunnelProtocol) {
					return spec[p]
				}
			}
			// Default to LIVENESS_ANY if no pattern matches.
			if v, ok := spec[parameters.LIVENESS_ANY]; ok {
				return v
			}
		}
		return nil
	}

	// If EstablishedTunnelsCount is 0, attempt the InitialLivenessTest specification.
	// If no match is found, or if this is a subsequent connection, proceed to LivenessTest.

	if establishedTunnelsCount == 0 {
		spec := matchingSpec(p.LivenessTest(parameters.InitialLivenessTest), tunnelProtocol)
		if spec != nil {
			return spec
		}
	}

	spec := matchingSpec(p.LivenessTest(parameters.LivenessTest), tunnelProtocol)
	if spec != nil {
		return spec
	}

	// Return legacy values as a last resort.
	return &parameters.LivenessTestSpec{
		MinUpstreamBytes:   p.Int(parameters.LivenessTestMinUpstreamBytes),
		MaxUpstreamBytes:   p.Int(parameters.LivenessTestMaxUpstreamBytes),
		MinDownstreamBytes: p.Int(parameters.LivenessTestMinDownstreamBytes),
		MaxDownstreamBytes: p.Int(parameters.LivenessTestMaxDownstreamBytes),
	}
}
