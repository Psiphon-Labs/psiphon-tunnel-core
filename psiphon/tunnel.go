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
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"sync"
	"time"

	"github.com/Psiphon-Labs/goarista/monotime"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/crypto/ssh"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/marionette"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/obfuscator"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/quic"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tactics"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tapdance"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/transferstats"
)

// Tunneler specifies the interface required by components that use a tunnel.
// Components which use this interface may be serviced by a single Tunnel instance,
// or a Controller which manages a pool of tunnels, or any other object which
// implements Tunneler.
type Tunneler interface {

	// Dial creates a tunneled connection.
	//
	// alwaysTunnel indicates that the connection should always be tunneled. If this
	// is not set, the connection may be made directly, depending on split tunnel
	// classification, when that feature is supported and active.
	//
	// downstreamConn is an optional parameter which specifies a connection to be
	// explicitly closed when the Dialed connection is closed. For instance, this
	// is used to close downstreamConn App<->LocalProxy connections when the related
	// LocalProxy<->SshPortForward connections close.
	Dial(remoteAddr string, alwaysTunnel bool, downstreamConn net.Conn) (conn net.Conn, err error)

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
	mutex                      *sync.Mutex
	config                     *Config
	isActivated                bool
	isDiscarded                bool
	isClosed                   bool
	sessionId                  string
	dialParams                 *DialParameters
	serverContext              *ServerContext
	conn                       *common.ActivityMonitoredConn
	sshClient                  *ssh.Client
	sshServerRequests          <-chan *ssh.Request
	operateWaitGroup           *sync.WaitGroup
	operateCtx                 context.Context
	stopOperate                context.CancelFunc
	signalPortForwardFailure   chan struct{}
	totalPortForwardFailures   int
	adjustedEstablishStartTime monotime.Time
	establishDuration          time.Duration
	establishedTime            monotime.Time
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
//
func ConnectTunnel(
	ctx context.Context,
	config *Config,
	sessionId string,
	adjustedEstablishStartTime monotime.Time,
	dialParams *DialParameters) (*Tunnel, error) {

	// Build transport layers and establish SSH connection. Note that
	// dialConn and monitoredConn are the same network connection.
	dialResult, err := dialTunnel(
		ctx, config, sessionId, dialParams)
	if err != nil {
		return nil, common.ContextError(err)
	}

	// The tunnel is now connected
	return &Tunnel{
		mutex:             new(sync.Mutex),
		config:            config,
		sessionId:         sessionId,
		dialParams:        dialParams,
		conn:              dialResult.monitoredConn,
		sshClient:         dialResult.sshClient,
		sshServerRequests: dialResult.sshRequests,
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
	tunnelOwner TunnelOwner) error {

	// Ensure that, unless the context is cancelled, any replayed dial
	// parameters are cleared, no longer to be retried, if the tunnel fails to
	// activate.
	activationSucceeded := false
	defer func() {
		if !activationSucceeded && ctx.Err() == nil {
			tunnel.dialParams.Failed()
		}
	}()

	// Create a new Psiphon API server context for this tunnel. This includes
	// performing a handshake request. If the handshake fails, this activation
	// fails.
	var serverContext *ServerContext
	if !tunnel.config.DisableApi {
		NoticeInfo(
			"starting server context for %s",
			tunnel.dialParams.ServerEntry.IpAddress)

		// Call NewServerContext in a goroutine, as it blocks on a network operation,
		// the handshake request, and would block shutdown. If the shutdown signal is
		// received, close the tunnel, which will interrupt the handshake request
		// that may be blocking NewServerContext.
		//
		// Timeout after PsiphonApiServerTimeoutSeconds. NewServerContext may not
		// return if the tunnel network connection is unstable during the handshake
		// request. At this point, there is no operateTunnel monitor that will detect
		// this condition with SSH keep alives.

		timeout := tunnel.config.clientParameters.Get().Duration(
			parameters.PsiphonAPIRequestTimeout)

		if timeout > 0 {
			var cancelFunc context.CancelFunc
			ctx, cancelFunc = context.WithTimeout(ctx, timeout)
			defer cancelFunc()
		}

		type newServerContextResult struct {
			serverContext *ServerContext
			err           error
		}

		resultChannel := make(chan newServerContextResult)

		go func() {
			serverContext, err := NewServerContext(tunnel)
			resultChannel <- newServerContextResult{
				serverContext: serverContext,
				err:           err,
			}
		}()

		var result newServerContextResult

		select {
		case result = <-resultChannel:
		case <-ctx.Done():
			result.err = ctx.Err()
			// Interrupt the goroutine
			tunnel.Close(true)
			<-resultChannel
		}

		if result.err != nil {
			return common.ContextError(
				fmt.Errorf("error starting server context for %s: %s",
					tunnel.dialParams.ServerEntry.IpAddress, result.err))
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
		return common.ContextError(errors.New("tunnel is closed"))
	}

	tunnel.isActivated = true
	tunnel.serverContext = serverContext

	// establishDuration is the elapsed time between the controller starting tunnel
	// establishment and this tunnel being established. The reported value represents
	// how long the user waited between starting the client and having a usable tunnel;
	// or how long between the client detecting an unexpected tunnel disconnect and
	// completing automatic reestablishment.
	//
	// This time period may include time spent unsuccessfully connecting to other
	// servers. Time spent waiting for network connectivity is excluded.
	tunnel.establishDuration = monotime.Since(tunnel.adjustedEstablishStartTime)
	tunnel.establishedTime = monotime.Now()

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
			timeout := tunnel.config.clientParameters.Get().Duration(
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
			NoticeAlert("close tunnel ssh error: %s", err)
		}
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
		return nil, common.ContextError(err)
	}

	if !ok {
		return nil, common.ContextError(errors.New("API request rejected"))
	}

	return responsePayload, nil
}

// Dial establishes a port forward connection through the tunnel
// This Dial doesn't support split tunnel, so alwaysTunnel is not referenced
func (tunnel *Tunnel) Dial(
	remoteAddr string, alwaysTunnel bool, downstreamConn net.Conn) (conn net.Conn, err error) {

	if !tunnel.IsActivated() {
		return nil, common.ContextError(errors.New("tunnel is not activated"))
	}

	type tunnelDialResult struct {
		sshPortForwardConn net.Conn
		err                error
	}

	// Note: there is no dial context since SSH port forward dials cannot
	// be interrupted directly. Closing the tunnel will interrupt the dials.
	// A timeout is set to unblock this function, but the goroutine may
	// not exit until the tunnel is closed.

	// Use a buffer of 1 as there are two senders and only one guaranteed receive.

	resultChannel := make(chan *tunnelDialResult, 1)

	timeout := tunnel.config.clientParameters.Get().Duration(
		parameters.TunnelPortForwardDialTimeout)

	afterFunc := time.AfterFunc(
		timeout,
		func() {
			resultChannel <- &tunnelDialResult{nil, errors.New("tunnel dial timeout")}
		})
	defer afterFunc.Stop()

	go func() {
		sshPortForwardConn, err := tunnel.sshClient.Dial("tcp", remoteAddr)
		resultChannel <- &tunnelDialResult{sshPortForwardConn, err}
	}()

	result := <-resultChannel

	if result.err != nil {
		// TODO: conditional on type of error or error message?
		select {
		case tunnel.signalPortForwardFailure <- *new(struct{}):
		default:
		}
		return nil, common.ContextError(result.err)
	}

	conn = &TunneledConn{
		Conn:           result.sshPortForwardConn,
		tunnel:         tunnel,
		downstreamConn: downstreamConn}

	return tunnel.wrapWithTransferStats(conn), nil
}

func (tunnel *Tunnel) DialPacketTunnelChannel() (net.Conn, error) {

	if !tunnel.IsActivated() {
		return nil, common.ContextError(errors.New("tunnel is not activated"))
	}
	channel, requests, err := tunnel.sshClient.OpenChannel(
		protocol.PACKET_TUNNEL_CHANNEL_TYPE, nil)
	if err != nil {
		// TODO: conditional on type of error or error message?
		select {
		case tunnel.signalPortForwardFailure <- *new(struct{}):
		default:
		}

		return nil, common.ContextError(err)
	}
	go ssh.DiscardRequests(requests)

	conn := newChannelConn(channel)

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
	NoticeAlert("tunnel received component failure signal")
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
		case conn.tunnel.signalPortForwardFailure <- *new(struct{}):
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
		case conn.tunnel.signalPortForwardFailure <- *new(struct{}):
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
	dialConn      net.Conn
	monitoredConn *common.ActivityMonitoredConn
	sshClient     *ssh.Client
	sshRequests   <-chan *ssh.Request
}

// dialTunnel is a helper that builds the transport layers and establishes the
// SSH connection. When additional dial configuration is used, dial metrics
// are recorded and returned.
//
// The net.Conn return value is the value to be removed from pendingConns;
// additional layering (ThrottledConn, ActivityMonitoredConn) is applied, but
// this return value is the base dial conn. The *ActivityMonitoredConn return
// value is the layered conn passed into the ssh.Client.
func dialTunnel(
	ctx context.Context,
	config *Config,
	sessionId string,
	dialParams *DialParameters) (*dialResult, error) {

	// Return immediately when overall context is canceled or timed-out. This
	// avoids notice noise.
	err := ctx.Err()
	if err != nil {
		return nil, common.ContextError(err)
	}

	p := config.clientParameters.Get()
	timeout := p.Duration(parameters.TunnelConnectTimeout)
	rateLimits := p.RateLimits(parameters.TunnelRateLimits)
	obfuscatedSSHMinPadding := p.Int(parameters.ObfuscatedSSHMinPadding)
	obfuscatedSSHMaxPadding := p.Int(parameters.ObfuscatedSSHMaxPadding)
	livenessTestMinUpstreamBytes := p.Int(parameters.LivenessTestMinUpstreamBytes)
	livenessTestMaxUpstreamBytes := p.Int(parameters.LivenessTestMaxUpstreamBytes)
	livenessTestMinDownstreamBytes := p.Int(parameters.LivenessTestMinDownstreamBytes)
	livenessTestMaxDownstreamBytes := p.Int(parameters.LivenessTestMaxDownstreamBytes)
	p = nil

	// Ensure that, unless the base context is cancelled, any replayed dial
	// parameters are cleared, no longer to be retried, if the tunnel fails to
	// connect.
	//
	// Limitation: dials that fail to connect due to the server being in a
	// load-limiting state are not distinguished and excepted from this
	// logic.
	dialSucceeded := false
	baseCtx := ctx
	defer func() {
		if !dialSucceeded && baseCtx.Err() == nil {
			dialParams.Failed()
		}
	}()

	var cancelFunc context.CancelFunc
	ctx, cancelFunc = context.WithTimeout(ctx, timeout)
	defer cancelFunc()

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
			return nil, common.ContextError(err)
		}

	} else if protocol.TunnelProtocolUsesQUIC(dialParams.TunnelProtocol) {

		packetConn, remoteAddr, err := NewUDPConn(
			ctx,
			dialParams.DirectDialAddress,
			dialParams.GetDialConfig())
		if err != nil {
			return nil, common.ContextError(err)
		}

		dialConn, err = quic.Dial(
			ctx,
			packetConn,
			remoteAddr,
			dialParams.QUICDialSNIAddress,
			dialParams.QUICVersion,
			dialParams.ServerEntry.SshObfuscatedKey,
			dialParams.ObfuscatedQUICPaddingSeed)
		if err != nil {
			return nil, common.ContextError(err)
		}

	} else if protocol.TunnelProtocolUsesMarionette(dialParams.TunnelProtocol) {

		dialConn, err = marionette.Dial(
			ctx,
			NewNetDialer(dialParams.GetDialConfig()),
			dialParams.ServerEntry.MarionetteFormat,
			dialParams.DirectDialAddress)
		if err != nil {
			return nil, common.ContextError(err)
		}

	} else if protocol.TunnelProtocolUsesTapdance(dialParams.TunnelProtocol) {

		dialConn, err = tapdance.Dial(
			ctx,
			config.DataStoreDirectory,
			NewNetDialer(dialParams.GetDialConfig()),
			dialParams.DirectDialAddress)
		if err != nil {
			return nil, common.ContextError(err)
		}

	} else {

		dialConn, err = DialTCP(
			ctx,
			dialParams.DirectDialAddress,
			dialParams.GetDialConfig())
		if err != nil {
			return nil, common.ContextError(err)
		}
	}

	// Some conns report additional metrics. fragmentor.Conns report
	// fragmentor configs.
	//
	// Limitation: for meek, GetMetrics from underlying fragmentor.Conn(s)
	// should be called in order to log fragmentor metrics for meek sessions.
	if metricsSource, ok := dialConn.(common.MetricsSource); ok {
		dialParams.DialConnMetrics = metricsSource
	}

	// If dialConn is not a Closer, tunnel failure detection may be slower
	if _, ok := dialConn.(common.Closer); !ok {
		NoticeAlert("tunnel.dialTunnel: dialConn is not a Closer")
	}

	cleanupConn := dialConn
	defer func() {
		// Cleanup on error
		if cleanupConn != nil {
			cleanupConn.Close()
		}
	}()

	// Activity monitoring is used to measure tunnel duration
	monitoredConn, err := common.NewActivityMonitoredConn(dialConn, 0, false, nil, nil)
	if err != nil {
		return nil, common.ContextError(err)
	}

	// Apply throttling (if configured)
	throttledConn := common.NewThrottledConn(
		monitoredConn,
		rateLimits)

	// Add obfuscated SSH layer
	var sshConn net.Conn = throttledConn
	if protocol.TunnelProtocolUsesObfuscatedSSH(dialParams.TunnelProtocol) {
		obfuscatedSSHConn, err := obfuscator.NewObfuscatedSSHConn(
			obfuscator.OBFUSCATION_CONN_MODE_CLIENT,
			throttledConn,
			dialParams.ServerEntry.SshObfuscatedKey,
			dialParams.ObfuscatorPaddingSeed,
			&obfuscatedSSHMinPadding,
			&obfuscatedSSHMaxPadding)
		if err != nil {
			return nil, common.ContextError(err)
		}
		sshConn = obfuscatedSSHConn
		dialParams.ObfuscatedSSHConnMetrics = obfuscatedSSHConn
	}

	// Now establish the SSH session over the conn transport
	expectedPublicKey, err := base64.StdEncoding.DecodeString(
		dialParams.ServerEntry.SshHostKey)
	if err != nil {
		return nil, common.ContextError(err)
	}
	sshCertChecker := &ssh.CertChecker{
		HostKeyFallback: func(addr string, remote net.Addr, publicKey ssh.PublicKey) error {
			if !bytes.Equal(expectedPublicKey, publicKey.Marshal()) {
				return common.ContextError(errors.New("unexpected host public key"))
			}
			return nil
		},
	}

	sshPasswordPayload := &protocol.SSHPasswordPayload{
		SessionId:          sessionId,
		SshPassword:        dialParams.ServerEntry.SshPassword,
		ClientCapabilities: []string{protocol.CLIENT_CAPABILITY_SERVER_REQUESTS},
	}

	payload, err := json.Marshal(sshPasswordPayload)
	if err != nil {
		return nil, common.ContextError(err)
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
			// This is the list of supported non-Encrypt-then-MAC algorithms from
			// https://github.com/Psiphon-Labs/psiphon-tunnel-core/blob/3ef11effe6acd92c3aefd140ee09c42a1f15630b/psiphon/common/crypto/ssh/common.go#L60
			//
			// With Encrypt-then-MAC algorithms, packet length is transmitted in
			// plaintext, which aids in traffic analysis.
			//
			// TUNNEL_PROTOCOL_SSH is excepted since its KEX appears in plaintext,
			// and the protocol is intended to look like SSH on the wire.
			sshClientConfig.MACs = []string{"hmac-sha2-256", "hmac-sha1", "hmac-sha1-96"}
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
		sshClient   *ssh.Client
		sshRequests <-chan *ssh.Request
		err         error
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

			if livenessTestMaxUpstreamBytes > 0 || livenessTestMaxDownstreamBytes > 0 {

				// When configured, perform a liveness test which sends and
				// receives bytes through the tunnel to ensure the tunnel had
				// not been blocked upon or shortly after connecting. This
				// test is performed concurrently for each establishment
				// candidate before selecting a successful tunnel.
				//
				// Note that the liveness test is subject to the
				// TunnelConnectTimeout, which should be adjusted
				// accordinging.

				var metrics *livenessTestMetrics
				metrics, err = performLivenessTest(
					sshClient,
					livenessTestMinUpstreamBytes, livenessTestMaxUpstreamBytes,
					livenessTestMinDownstreamBytes, livenessTestMaxDownstreamBytes,
					dialParams.LivenessTestSeed)

				// Skip notice when cancelling.
				if baseCtx.Err() == nil {
					NoticeLivenessTest(
						dialParams.ServerEntry.IpAddress, metrics, err == nil)
				}
			}
		}

		resultChannel <- sshNewClientResult{sshClient, sshRequests, err}
	}()

	var result sshNewClientResult

	select {
	case result = <-resultChannel:
	case <-ctx.Done():
		result.err = ctx.Err()
		// Interrupt the goroutine
		sshConn.Close()
		<-resultChannel
	}

	if result.err != nil {
		return nil, common.ContextError(result.err)
	}

	dialSucceeded = true

	NoticeConnectedServer(dialParams)

	cleanupConn = nil

	// Note: dialConn may be used to close the underlying network connection
	// but should not be used to perform I/O as that would interfere with SSH
	// (and also bypasses throttling).

	return &dialResult{
			dialConn:      dialConn,
			monitoredConn: monitoredConn,
			sshClient:     result.sshClient,
			sshRequests:   result.sshRequests},
		nil
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
	minUpstreamBytes, maxUpstreamBytes int,
	minDownstreamBytes, maxDownstreamBytes int,
	livenessTestPRNGSeed *prng.Seed) (*livenessTestMetrics, error) {

	metrics := new(livenessTestMetrics)

	defer func(startTime monotime.Time) {
		metrics.Duration = fmt.Sprintf("%s", monotime.Since(startTime))
	}(monotime.Now())

	PRNG := prng.NewPRNGWithSeed(livenessTestPRNGSeed)

	metrics.UpstreamBytes = PRNG.Range(minUpstreamBytes, maxUpstreamBytes)
	metrics.DownstreamBytes = PRNG.Range(minDownstreamBytes, maxDownstreamBytes)

	request := &protocol.RandomStreamRequest{
		UpstreamBytes:   metrics.UpstreamBytes,
		DownstreamBytes: metrics.DownstreamBytes,
	}

	extraData, err := json.Marshal(request)
	if err != nil {
		return metrics, common.ContextError(err)
	}

	channel, requests, err := sshClient.OpenChannel(
		protocol.RANDOM_STREAM_CHANNEL_TYPE, extraData)
	if err != nil {
		return metrics, common.ContextError(err)
	}
	defer channel.Close()

	go ssh.DiscardRequests(requests)

	// In consideration of memory-constrained environments, use a modest-sized
	// copy buffer since many tunnel establishment workers may run the
	// liveness test concurrently.

	var buffer [8192]byte

	if metrics.UpstreamBytes > 0 {
		n, err := common.CopyNBuffer(channel, rand.Reader, int64(metrics.UpstreamBytes), buffer[:])
		metrics.SentUpstreamBytes = int(n)
		if err != nil {
			return metrics, common.ContextError(err)
		}
	}

	if metrics.DownstreamBytes > 0 {
		n, err := common.CopyNBuffer(ioutil.Discard, channel, int64(metrics.DownstreamBytes), buffer[:])
		metrics.ReceivedDownstreamBytes = int(n)
		if err != nil {
			return metrics, common.ContextError(err)
		}
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
//
func (tunnel *Tunnel) operateTunnel(tunnelOwner TunnelOwner) {
	defer tunnel.operateWaitGroup.Done()

	clientParameters := tunnel.config.clientParameters

	lastBytesReceivedTime := monotime.Now()

	lastTotalBytesTransferedTime := monotime.Now()
	totalSent := int64(0)
	totalReceived := int64(0)
	dialParamsSucceeded := false

	noticeBytesTransferredTicker := time.NewTicker(1 * time.Second)
	defer noticeBytesTransferredTicker.Stop()

	// The next status request and ssh keep alive times are picked at random,
	// from a range, to make the resulting traffic less fingerprintable,
	// Note: not using Tickers since these are not fixed time periods.
	nextStatusRequestPeriod := func() time.Duration {
		p := clientParameters.Get()
		return prng.Period(
			p.Duration(parameters.PsiphonAPIStatusRequestPeriodMin),
			p.Duration(parameters.PsiphonAPIStatusRequestPeriodMax))
	}

	statsTimer := time.NewTimer(nextStatusRequestPeriod())
	defer statsTimer.Stop()

	// Schedule an almost-immediate status request to deliver any unreported
	// persistent stats.
	unreported := CountUnreportedPersistentStats()
	if unreported > 0 {
		NoticeInfo("Unreported persistent stats: %d", unreported)
		p := clientParameters.Get()
		statsTimer.Reset(
			prng.Period(
				p.Duration(parameters.PsiphonAPIStatusRequestShortPeriodMin),
				p.Duration(parameters.PsiphonAPIStatusRequestShortPeriodMax)))
	}

	nextSshKeepAlivePeriod := func() time.Duration {
		p := clientParameters.Get()
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
	signalSshKeepAlive := make(chan time.Duration)
	sshKeepAliveError := make(chan error, 1)
	go func() {
		defer requestsWaitGroup.Done()
		isFirstKeepAlive := true
		for timeout := range signalSshKeepAlive {
			err := tunnel.sendSshKeepAlive(isFirstKeepAlive, timeout)
			if err != nil {
				select {
				case sshKeepAliveError <- err:
				default:
				}
			}
			isFirstKeepAlive = false
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
				lastBytesReceivedTime = monotime.Now()
			}

			totalSent += sent
			totalReceived += received

			p := clientParameters.Get()
			noticePeriod := p.Duration(parameters.TotalBytesTransferredNoticePeriod)
			replayTargetUpstreamBytes := p.Int(parameters.ReplayTargetUpstreamBytes)
			replayTargetDownstreamBytes := p.Int(parameters.ReplayTargetDownstreamBytes)

			if lastTotalBytesTransferedTime.Add(noticePeriod).Before(monotime.Now()) {
				NoticeTotalBytesTransferred(
					tunnel.dialParams.ServerEntry.IpAddress, totalSent, totalReceived)
				lastTotalBytesTransferedTime = monotime.Now()
			}

			// Only emit the frequent BytesTransferred notice when tunnel is not idle.
			if tunnel.config.EmitBytesTransferred && (sent > 0 || received > 0) {
				NoticeBytesTransferred(
					tunnel.dialParams.ServerEntry.IpAddress, sent, received)
			}

			// Once the tunnel has connected, activated, and successfully
			// transmitted the targetted number of bytes, store its dial
			// parameters for subsequent replay.
			//
			// Even when target bytes are both 0, tunnel must remain up for at
			// least 1 second due to use of noticeBytesTransferredTicker.
			if totalSent >= int64(replayTargetUpstreamBytes) &&
				totalReceived >= int64(replayTargetDownstreamBytes) &&
				!dialParamsSucceeded {

				tunnel.dialParams.Succeeded()
				dialParamsSucceeded = true
			}

		case <-statsTimer.C:
			select {
			case signalStatusRequest <- *new(struct{}):
			default:
			}
			statsTimer.Reset(nextStatusRequestPeriod())

		case <-sshKeepAliveTimer.C:
			inactivePeriod := clientParameters.Get().Duration(parameters.SSHKeepAlivePeriodicInactivePeriod)
			if lastBytesReceivedTime.Add(inactivePeriod).Before(monotime.Now()) {
				timeout := clientParameters.Get().Duration(parameters.SSHKeepAlivePeriodicTimeout)
				select {
				case signalSshKeepAlive <- timeout:
				default:
				}
			}
			sshKeepAliveTimer.Reset(nextSshKeepAlivePeriod())

		case <-tunnel.signalPortForwardFailure:
			// Note: no mutex on portForwardFailureTotal; only referenced here
			tunnel.totalPortForwardFailures++
			NoticeInfo("port forward failures for %s: %d",
				tunnel.dialParams.ServerEntry.IpAddress,
				tunnel.totalPortForwardFailures)

			// If the underlying Conn has closed (meek and other plugin protocols may close
			// themselves in certain error conditions), the tunnel has certainly failed.
			// Otherwise, probe with an SSH keep alive.

			if tunnel.conn.IsClosed() {
				err = errors.New("underlying conn is closed")
			} else {
				inactivePeriod := clientParameters.Get().Duration(parameters.SSHKeepAliveProbeInactivePeriod)
				if lastBytesReceivedTime.Add(inactivePeriod).Before(monotime.Now()) {
					timeout := clientParameters.Get().Duration(parameters.SSHKeepAliveProbeTimeout)
					select {
					case signalSshKeepAlive <- timeout:
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
				err := HandleServerRequest(tunnelOwner, tunnel, serverRequest.Type, serverRequest.Payload)
				if err == nil {
					serverRequest.Reply(true, nil)
				} else {
					NoticeAlert("HandleServerRequest for %s failed: %s", serverRequest.Type, err)
					serverRequest.Reply(false, nil)

				}
			}

		case <-tunnel.operateCtx.Done():
			shutdown = true
		}
	}

	close(signalSshKeepAlive)
	close(signalStatusRequest)
	requestsWaitGroup.Wait()

	// Capture bytes transferred since the last noticeBytesTransferredTicker tick
	sent, received := transferstats.ReportRecentBytesTransferredForServer(
		tunnel.dialParams.ServerEntry.IpAddress)
	totalSent += sent
	totalReceived += received

	// Always emit a final NoticeTotalBytesTransferred
	NoticeTotalBytesTransferred(
		tunnel.dialParams.ServerEntry.IpAddress, totalSent, totalReceived)

	if err == nil {
		NoticeInfo("shutdown operate tunnel")

		// Send a final status request in order to report any outstanding
		// domain bytes transferred stats as well as to report session stats
		// as soon as possible.
		// This request will be interrupted when the tunnel is closed after
		// an operate shutdown timeout.
		sendStats(tunnel)

	} else {
		NoticeAlert("operate tunnel error for %s: %s",
			tunnel.dialParams.ServerEntry.IpAddress, err)
		tunnelOwner.SignalTunnelFailure(tunnel)
	}
}

// sendSshKeepAlive is a helper which sends a keepalive@openssh.com request
// on the specified SSH connections and returns true of the request succeeds
// within a specified timeout. If the request fails, the associated conn is
// closed, which will terminate the associated tunnel.
func (tunnel *Tunnel) sendSshKeepAlive(isFirstKeepAlive bool, timeout time.Duration) error {

	// Note: there is no request context since SSH requests cannot be
	// interrupted directly. Closing the tunnel will interrupt the request.
	// A timeout is set to unblock this function, but the goroutine may
	// not exit until the tunnel is closed.

	// Use a buffer of 1 as there are two senders and only one guaranteed receive.

	errChannel := make(chan error, 1)

	afterFunc := time.AfterFunc(timeout, func() {
		errChannel <- errors.New("timed out")
	})
	defer afterFunc.Stop()

	go func() {
		// Random padding to frustrate fingerprinting.
		p := tunnel.config.clientParameters.Get()
		request := prng.Padding(
			p.Int(parameters.SSHKeepAlivePaddingMinBytes),
			p.Int(parameters.SSHKeepAlivePaddingMaxBytes))
		p = nil

		startTime := monotime.Now()

		// Note: reading a reply is important for last-received-time tunnel
		// duration calculation.
		requestOk, response, err := tunnel.sshClient.SendRequest(
			"keepalive@openssh.com", true, request)

		elapsedTime := monotime.Since(startTime)

		errChannel <- err

		// Record the keep alive round trip as a speed test sample. The first
		// keep alive is always recorded, as many tunnels are short-lived and
		// we want to ensure that some data is gathered. Subsequent keep
		// alives are recorded with some configurable probability, which,
		// considering that only the last SpeedTestMaxSampleCount samples are
		// retained, enables tuning the sampling frequency.

		if err == nil && requestOk &&
			(isFirstKeepAlive ||
				tunnel.config.clientParameters.Get().WeightedCoinFlip(
					parameters.SSHKeepAliveSpeedTestSampleProbability)) {

			err = tactics.AddSpeedTestSample(
				tunnel.config.clientParameters,
				GetTacticsStorer(),
				tunnel.config.GetNetworkID(),
				tunnel.dialParams.ServerEntry.Region,
				tunnel.dialParams.TunnelProtocol,
				elapsedTime,
				request,
				response)
			if err != nil {
				NoticeAlert("AddSpeedTestSample failed: %s", common.ContextError(err))
			}
		}
	}()

	err := <-errChannel
	if err != nil {
		tunnel.sshClient.Close()
		tunnel.conn.Close()
	}

	return common.ContextError(err)
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

	err := tunnel.serverContext.DoStatusRequest(tunnel)
	if err != nil {
		NoticeAlert("DoStatusRequest failed for %s: %s",
			tunnel.dialParams.ServerEntry.IpAddress, err)
	}

	return err == nil
}
