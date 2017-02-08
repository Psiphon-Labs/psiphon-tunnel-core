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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Inc/crypto/ssh"
	"github.com/Psiphon-Inc/goarista/monotime"
	regen "github.com/Psiphon-Inc/goregen"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/transferstats"
)

// Tunneler specifies the interface required by components that use a tunnel.
// Components which use this interface may be serviced by a single Tunnel instance,
// or a Controller which manages a pool of tunnels, or any other object which
// implements Tunneler.
// alwaysTunnel indicates that the connection should always be tunneled. If this
// is not set, the connection may be made directly, depending on split tunnel
// classification, when that feature is supported and active.
// downstreamConn is an optional parameter which specifies a connection to be
// explictly closed when the Dialed connection is closed. For instance, this
// is used to close downstreamConn App<->LocalProxy connections when the related
// LocalProxy<->SshPortForward connections close.
type Tunneler interface {
	Dial(remoteAddr string, alwaysTunnel bool, downstreamConn net.Conn) (conn net.Conn, err error)
	SignalComponentFailure()
}

// TunnerOwner specifies the interface required by Tunnel to notify its
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
	mutex                        *sync.Mutex
	config                       *Config
	untunneledDialConfig         *DialConfig
	isDiscarded                  bool
	isClosed                     bool
	serverEntry                  *protocol.ServerEntry
	serverContext                *ServerContext
	protocol                     string
	conn                         *common.ActivityMonitoredConn
	sshClient                    *ssh.Client
	sshServerRequests            <-chan *ssh.Request
	operateWaitGroup             *sync.WaitGroup
	shutdownOperateBroadcast     chan struct{}
	signalPortForwardFailure     chan struct{}
	totalPortForwardFailures     int
	establishDuration            time.Duration
	establishedTime              monotime.Time
	dialStats                    *TunnelDialStats
	newClientVerificationPayload chan string
}

// TunnelDialStats records additional dial config that is sent to the server for stats
// recording. This data is used to analyze which configuration settings are successful
// in various circumvention contexts, and includes meek dial params and upstream proxy
// params.
// For upstream proxy, only proxy type and custom header names are recorded; proxy
// address and custom header values are considered PII.
type TunnelDialStats struct {
	UpstreamProxyType              string
	UpstreamProxyCustomHeaderNames []string
	MeekDialAddress                string
	MeekResolvedIPAddress          string
	MeekSNIServerName              string
	MeekHostHeader                 string
	MeekTransformedHostName        bool
	SelectedUserAgent              bool
	UserAgent                      string
}

// EstablishTunnel first makes a network transport connection to the
// Psiphon server and then establishes an SSH client session on top of
// that transport. The SSH server is authenticated using the public
// key in the server entry.
// Depending on the server's capabilities, the connection may use
// plain SSH over TCP, obfuscated SSH over TCP, or obfuscated SSH over
// HTTP (meek protocol).
// When requiredProtocol is not blank, that protocol is used. Otherwise,
// the a random supported protocol is used.
// untunneledDialConfig is used for untunneled final status requests.
func EstablishTunnel(
	config *Config,
	untunneledDialConfig *DialConfig,
	sessionId string,
	pendingConns *common.Conns,
	serverEntry *protocol.ServerEntry,
	adjustedEstablishStartTime monotime.Time,
	tunnelOwner TunnelOwner) (tunnel *Tunnel, err error) {

	selectedProtocol, err := selectProtocol(config, serverEntry)
	if err != nil {
		return nil, common.ContextError(err)
	}

	// Build transport layers and establish SSH connection. Note that
	// dialConn and monitoredConn are the same network connection.
	dialResult, err := dialSsh(
		config, pendingConns, serverEntry, selectedProtocol, sessionId)
	if err != nil {
		return nil, common.ContextError(err)
	}

	// Cleanup on error
	defer func() {
		if err != nil {
			dialResult.sshClient.Close()
			dialResult.monitoredConn.Close()
			pendingConns.Remove(dialResult.dialConn)
		}
	}()

	// The tunnel is now connected
	tunnel = &Tunnel{
		mutex:                    new(sync.Mutex),
		config:                   config,
		untunneledDialConfig:     untunneledDialConfig,
		isClosed:                 false,
		serverEntry:              serverEntry,
		protocol:                 selectedProtocol,
		conn:                     dialResult.monitoredConn,
		sshClient:                dialResult.sshClient,
		sshServerRequests:        dialResult.sshRequests,
		operateWaitGroup:         new(sync.WaitGroup),
		shutdownOperateBroadcast: make(chan struct{}),
		// A buffer allows at least one signal to be sent even when the receiver is
		// not listening. Senders should not block.
		signalPortForwardFailure: make(chan struct{}, 1),
		dialStats:                dialResult.dialStats,
		// Buffer allows SetClientVerificationPayload to submit one new payload
		// without blocking or dropping it.
		newClientVerificationPayload: make(chan string, 1),
	}

	// Create a new Psiphon API server context for this tunnel. This includes
	// performing a handshake request. If the handshake fails, this establishment
	// fails.
	if !config.DisableApi {
		NoticeInfo("starting server context for %s", tunnel.serverEntry.IpAddress)
		tunnel.serverContext, err = NewServerContext(tunnel, sessionId)
		if err != nil {
			return nil, common.ContextError(
				fmt.Errorf("error starting server context for %s: %s",
					tunnel.serverEntry.IpAddress, err))
		}
	}

	// establishDuration is the elapsed time between the controller starting tunnel
	// establishment and this tunnel being established. The reported value represents
	// how long the user waited between starting the client and having a usable tunnel;
	// or how long between the client detecting an unexpected tunnel disconnect and
	// completing automatic reestablishment.
	//
	// This time period may include time spent unsuccessfully connecting to other
	// servers. Time spent waiting for network connectivity is excluded.
	tunnel.establishDuration = monotime.Since(adjustedEstablishStartTime)

	tunnel.establishedTime = monotime.Now()

	// Now that network operations are complete, cancel interruptibility
	pendingConns.Remove(dialResult.dialConn)

	// Spawn the operateTunnel goroutine, which monitors the tunnel and handles periodic stats updates.
	tunnel.operateWaitGroup.Add(1)
	go tunnel.operateTunnel(tunnelOwner)

	return tunnel, nil
}

// Close stops operating the tunnel and closes the underlying connection.
// Supports multiple and/or concurrent calls to Close().
// When isDiscarded is set, operateTunnel will not attempt to send final
// status requests.
func (tunnel *Tunnel) Close(isDiscarded bool) {

	tunnel.mutex.Lock()
	tunnel.isDiscarded = isDiscarded
	isClosed := tunnel.isClosed
	tunnel.isClosed = true
	tunnel.mutex.Unlock()

	if !isClosed {
		// Signal operateTunnel to stop before closing the tunnel -- this
		// allows a final status request to be made in the case of an orderly
		// shutdown.
		// A timer is set, so if operateTunnel takes too long to stop, the
		// tunnel is closed, which will interrupt any slow final status request.
		// In effect, the TUNNEL_OPERATE_SHUTDOWN_TIMEOUT value will take
		// precedence over the PSIPHON_API_SERVER_TIMEOUT http.Client.Timeout
		// value set in makePsiphonHttpsClient.
		timer := time.AfterFunc(TUNNEL_OPERATE_SHUTDOWN_TIMEOUT, func() { tunnel.conn.Close() })
		close(tunnel.shutdownOperateBroadcast)
		tunnel.operateWaitGroup.Wait()
		timer.Stop()
		tunnel.sshClient.Close()
		// tunnel.conn.Close() may get called multiple times, which is allowed.
		tunnel.conn.Close()
	}
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

	type tunnelDialResult struct {
		sshPortForwardConn net.Conn
		err                error
	}
	resultChannel := make(chan *tunnelDialResult, 2)
	if *tunnel.config.TunnelPortForwardDialTimeoutSeconds > 0 {
		time.AfterFunc(time.Duration(*tunnel.config.TunnelPortForwardDialTimeoutSeconds)*time.Second, func() {
			resultChannel <- &tunnelDialResult{nil, errors.New("tunnel dial timeout")}
		})
	}
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

	// Tunnel does not have a serverContext when DisableApi is set. We still use
	// transferstats.Conn to count bytes transferred for monitoring tunnel
	// quality.
	var regexps *transferstats.Regexps
	if tunnel.serverContext != nil {
		regexps = tunnel.serverContext.StatsRegexps()
	}
	conn = transferstats.NewConn(conn, tunnel.serverEntry.IpAddress, regexps)

	return conn, nil
}

// SignalComponentFailure notifies the tunnel that an associated component has failed.
// This will terminate the tunnel.
func (tunnel *Tunnel) SignalComponentFailure() {
	NoticeAlert("tunnel received component failure signal")
	tunnel.Close(false)
}

// SetClientVerificationPayload triggers a client verification request, for this
// tunnel, with the specified verifiction payload. If the tunnel is not yet established,
// the payload/request is enqueued. If a payload/request is already eneueued, the
// new payload is dropped.
func (tunnel *Tunnel) SetClientVerificationPayload(clientVerificationPayload string) {
	select {
	case tunnel.newClientVerificationPayload <- clientVerificationPayload:
	default:
	}
}

// TunneledConn implements net.Conn and wraps a port foward connection.
// It is used to hook into Read and Write to observe I/O errors and
// report these errors back to the tunnel monitor as port forward failures.
// TunneledConn optionally tracks a peer connection to be explictly closed
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

// selectProtocol is a helper that picks the tunnel protocol
func selectProtocol(
	config *Config, serverEntry *protocol.ServerEntry) (selectedProtocol string, err error) {

	// TODO: properly handle protocols (e.g. FRONTED-MEEK-OSSH) vs. capabilities (e.g., {FRONTED-MEEK, OSSH})
	// for now, the code is simply assuming that MEEK capabilities imply OSSH capability.
	if config.TunnelProtocol != "" {
		if !serverEntry.SupportsProtocol(config.TunnelProtocol) {
			return "", common.ContextError(fmt.Errorf("server does not have required capability"))
		}
		selectedProtocol = config.TunnelProtocol
	} else {
		// Pick at random from the supported protocols. This ensures that we'll eventually
		// try all possible protocols. Depending on network configuration, it may be the
		// case that some protocol is only available through multi-capability servers,
		// and a simpler ranked preference of protocols could lead to that protocol never
		// being selected.

		candidateProtocols := serverEntry.GetSupportedProtocols()
		if len(candidateProtocols) == 0 {
			return "", common.ContextError(fmt.Errorf("server does not have any supported capabilities"))
		}

		index, err := common.MakeSecureRandomInt(len(candidateProtocols))
		if err != nil {
			return "", common.ContextError(err)
		}
		selectedProtocol = candidateProtocols[index]
	}
	return selectedProtocol, nil
}

// selectFrontingParameters is a helper which selects/generates meek fronting
// parameters where the server entry provides multiple options or patterns.
func selectFrontingParameters(
	serverEntry *protocol.ServerEntry) (frontingAddress, frontingHost string, err error) {

	if len(serverEntry.MeekFrontingAddressesRegex) > 0 {

		// Generate a front address based on the regex.

		frontingAddress, err = regen.Generate(serverEntry.MeekFrontingAddressesRegex)
		if err != nil {
			return "", "", common.ContextError(err)
		}
	} else {

		// Randomly select, for this connection attempt, one front address for
		// fronting-capable servers.

		if len(serverEntry.MeekFrontingAddresses) == 0 {
			return "", "", common.ContextError(errors.New("MeekFrontingAddresses is empty"))
		}
		index, err := common.MakeSecureRandomInt(len(serverEntry.MeekFrontingAddresses))
		if err != nil {
			return "", "", common.ContextError(err)
		}
		frontingAddress = serverEntry.MeekFrontingAddresses[index]
	}

	if len(serverEntry.MeekFrontingHosts) > 0 {
		index, err := common.MakeSecureRandomInt(len(serverEntry.MeekFrontingHosts))
		if err != nil {
			return "", "", common.ContextError(err)
		}
		frontingHost = serverEntry.MeekFrontingHosts[index]
	} else {
		// Backwards compatibility case
		frontingHost = serverEntry.MeekFrontingHost
	}

	return
}

func doMeekTransformHostName(config *Config) bool {
	switch config.TransformHostNames {
	case TRANSFORM_HOST_NAMES_ALWAYS:
		return true
	case TRANSFORM_HOST_NAMES_NEVER:
		return false
	}
	return common.FlipCoin()
}

// initMeekConfig is a helper that creates a MeekConfig suitable for the
// selected meek tunnel protocol.
func initMeekConfig(
	config *Config,
	serverEntry *protocol.ServerEntry,
	selectedProtocol,
	sessionId string) (*MeekConfig, error) {

	// The meek protocol always uses OSSH
	psiphonServerAddress := fmt.Sprintf("%s:%d", serverEntry.IpAddress, serverEntry.SshObfuscatedPort)

	var dialAddress string
	useHTTPS := false
	useObfuscatedSessionTickets := false
	var SNIServerName, hostHeader string
	transformedHostName := false

	switch selectedProtocol {
	case protocol.TUNNEL_PROTOCOL_FRONTED_MEEK:

		frontingAddress, frontingHost, err := selectFrontingParameters(serverEntry)
		if err != nil {
			return nil, common.ContextError(err)
		}
		dialAddress = fmt.Sprintf("%s:443", frontingAddress)
		useHTTPS = true
		if !serverEntry.MeekFrontingDisableSNI {
			SNIServerName = frontingAddress
			if doMeekTransformHostName(config) {
				SNIServerName = common.GenerateHostName()
				transformedHostName = true
			}
		}
		hostHeader = frontingHost

	case protocol.TUNNEL_PROTOCOL_FRONTED_MEEK_HTTP:

		frontingAddress, frontingHost, err := selectFrontingParameters(serverEntry)
		if err != nil {
			return nil, common.ContextError(err)
		}
		dialAddress = fmt.Sprintf("%s:80", frontingAddress)
		hostHeader = frontingHost

	case protocol.TUNNEL_PROTOCOL_UNFRONTED_MEEK:

		dialAddress = fmt.Sprintf("%s:%d", serverEntry.IpAddress, serverEntry.MeekServerPort)
		hostname := serverEntry.IpAddress
		if doMeekTransformHostName(config) {
			hostname = common.GenerateHostName()
			transformedHostName = true
		}
		if serverEntry.MeekServerPort == 80 {
			hostHeader = hostname
		} else {
			hostHeader = fmt.Sprintf("%s:%d", hostname, serverEntry.MeekServerPort)
		}

	case protocol.TUNNEL_PROTOCOL_UNFRONTED_MEEK_HTTPS,
		protocol.TUNNEL_PROTOCOL_UNFRONTED_MEEK_SESSION_TICKET:

		dialAddress = fmt.Sprintf("%s:%d", serverEntry.IpAddress, serverEntry.MeekServerPort)
		useHTTPS = true
		if selectedProtocol == protocol.TUNNEL_PROTOCOL_UNFRONTED_MEEK_SESSION_TICKET {
			useObfuscatedSessionTickets = true
		}
		SNIServerName = serverEntry.IpAddress
		if doMeekTransformHostName(config) {
			SNIServerName = common.GenerateHostName()
			transformedHostName = true
		}
		if serverEntry.MeekServerPort == 443 {
			hostHeader = serverEntry.IpAddress
		} else {
			hostHeader = fmt.Sprintf("%s:%d", serverEntry.IpAddress, serverEntry.MeekServerPort)
		}

	default:
		return nil, common.ContextError(errors.New("unexpected selectedProtocol"))
	}

	// The unnderlying TLS will automatically disable SNI for IP address server name
	// values; we have this explicit check here so we record the correct value for stats.
	if net.ParseIP(SNIServerName) != nil {
		SNIServerName = ""
	}

	return &MeekConfig{
		DialAddress:                   dialAddress,
		UseHTTPS:                      useHTTPS,
		UseObfuscatedSessionTickets:   useObfuscatedSessionTickets,
		SNIServerName:                 SNIServerName,
		HostHeader:                    hostHeader,
		TransformedHostName:           transformedHostName,
		PsiphonServerAddress:          psiphonServerAddress,
		SessionID:                     sessionId,
		MeekCookieEncryptionPublicKey: serverEntry.MeekCookieEncryptionPublicKey,
		MeekObfuscatedKey:             serverEntry.MeekObfuscatedKey,
	}, nil
}

type dialResult struct {
	dialConn      net.Conn
	monitoredConn *common.ActivityMonitoredConn
	sshClient     *ssh.Client
	sshRequests   <-chan *ssh.Request
	dialStats     *TunnelDialStats
}

// dialSsh is a helper that builds the transport layers and establishes the SSH connection.
// When additional dial configuration is used, DialStats are recorded and returned.
//
// The net.Conn return value is the value to be removed from pendingConns; additional
// layering (ThrottledConn, ActivityMonitoredConn) is applied, but this return value is the
// base dial conn. The *ActivityMonitoredConn return value is the layered conn passed into
// the ssh.Client.
func dialSsh(
	config *Config,
	pendingConns *common.Conns,
	serverEntry *protocol.ServerEntry,
	selectedProtocol,
	sessionId string) (*dialResult, error) {

	// The meek protocols tunnel obfuscated SSH. Obfuscated SSH is layered on top of SSH.
	// So depending on which protocol is used, multiple layers are initialized.

	useObfuscatedSsh := false
	dialCustomHeaders := config.CustomHeaders
	var directTCPDialAddress string
	var meekConfig *MeekConfig
	var selectedUserAgent bool
	var err error

	switch selectedProtocol {
	case protocol.TUNNEL_PROTOCOL_OBFUSCATED_SSH:
		useObfuscatedSsh = true
		directTCPDialAddress = fmt.Sprintf("%s:%d", serverEntry.IpAddress, serverEntry.SshObfuscatedPort)

	case protocol.TUNNEL_PROTOCOL_SSH:
		directTCPDialAddress = fmt.Sprintf("%s:%d", serverEntry.IpAddress, serverEntry.SshPort)

	default:
		useObfuscatedSsh = true
		meekConfig, err = initMeekConfig(config, serverEntry, selectedProtocol, sessionId)
		if err != nil {
			return nil, common.ContextError(err)
		}
	}

	NoticeConnectingServer(
		serverEntry.IpAddress,
		serverEntry.Region,
		selectedProtocol,
		directTCPDialAddress,
		meekConfig)

	// Use an asynchronous callback to record the resolved IP address when
	// dialing a domain name. Note that DialMeek doesn't immediately
	// establish any HTTPS connections, so the resolved IP address won't be
	// reported until during/after ssh session establishment (the ssh traffic
	// is meek payload). So don't Load() the IP address value until after that
	// has completed to ensure a result.
	var resolvedIPAddress atomic.Value
	resolvedIPAddress.Store("")
	setResolvedIPAddress := func(IPAddress string) {
		resolvedIPAddress.Store(IPAddress)
	}

	dialCustomHeaders, selectedUserAgent = common.UserAgentIfUnset(config.CustomHeaders)

	// Create the base transport: meek or direct connection
	dialConfig := &DialConfig{
		UpstreamProxyUrl:              config.UpstreamProxyUrl,
		CustomHeaders:                 dialCustomHeaders,
		ConnectTimeout:                time.Duration(*config.TunnelConnectTimeoutSeconds) * time.Second,
		PendingConns:                  pendingConns,
		DeviceBinder:                  config.DeviceBinder,
		DnsServerGetter:               config.DnsServerGetter,
		IPv6Synthesizer:               config.IPv6Synthesizer,
		UseIndistinguishableTLS:       config.UseIndistinguishableTLS,
		TrustedCACertificatesFilename: config.TrustedCACertificatesFilename,
		DeviceRegion:                  config.DeviceRegion,
		ResolvedIPCallback:            setResolvedIPAddress,
	}
	var dialConn net.Conn
	if meekConfig != nil {
		dialConn, err = DialMeek(meekConfig, dialConfig)
		if err != nil {
			return nil, common.ContextError(err)
		}
	} else {
		dialConn, err = DialTCP(directTCPDialAddress, dialConfig)
		if err != nil {
			return nil, common.ContextError(err)
		}
	}

	cleanupConn := dialConn
	defer func() {
		// Cleanup on error
		if cleanupConn != nil {
			cleanupConn.Close()
			pendingConns.Remove(cleanupConn)
		}
	}()

	// Activity monitoring is used to measure tunnel duration
	monitoredConn, err := common.NewActivityMonitoredConn(dialConn, 0, false, nil, nil)
	if err != nil {
		return nil, common.ContextError(err)
	}

	// Apply throttling (if configured)
	throttledConn := common.NewThrottledConn(monitoredConn, config.RateLimits)

	// Add obfuscated SSH layer
	var sshConn net.Conn = throttledConn
	if useObfuscatedSsh {
		sshConn, err = common.NewObfuscatedSshConn(
			common.OBFUSCATION_CONN_MODE_CLIENT, throttledConn, serverEntry.SshObfuscatedKey)
		if err != nil {
			return nil, common.ContextError(err)
		}
	}

	// Now establish the SSH session over the conn transport
	expectedPublicKey, err := base64.StdEncoding.DecodeString(serverEntry.SshHostKey)
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
		SshPassword:        serverEntry.SshPassword,
		ClientCapabilities: []string{protocol.CLIENT_CAPABILITY_SERVER_REQUESTS},
	}

	payload, err := json.Marshal(sshPasswordPayload)
	if err != nil {
		return nil, common.ContextError(err)
	}
	sshClientConfig := &ssh.ClientConfig{
		User: serverEntry.SshUsername,
		Auth: []ssh.AuthMethod{
			ssh.Password(string(payload)),
		},
		HostKeyCallback: sshCertChecker.CheckHostKey,
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
	// TODO: adjust the timeout to account for time-elapsed-from-start

	type sshNewClientResult struct {
		sshClient   *ssh.Client
		sshRequests <-chan *ssh.Request
		err         error
	}
	resultChannel := make(chan *sshNewClientResult, 2)
	if *config.TunnelConnectTimeoutSeconds > 0 {
		time.AfterFunc(time.Duration(*config.TunnelConnectTimeoutSeconds)*time.Second, func() {
			resultChannel <- &sshNewClientResult{nil, nil, errors.New("ssh dial timeout")}
		})
	}

	go func() {
		// The following is adapted from ssh.Dial(), here using a custom conn
		// The sshAddress is passed through to host key verification callbacks; we don't use it.
		sshAddress := ""
		sshClientConn, sshChannels, sshRequests, err := ssh.NewClientConn(
			sshConn, sshAddress, sshClientConfig)
		var sshClient *ssh.Client
		if err == nil {
			sshClient = ssh.NewClient(sshClientConn, sshChannels, nil)
		}
		resultChannel <- &sshNewClientResult{sshClient, sshRequests, err}
	}()

	result := <-resultChannel
	if result.err != nil {
		return nil, common.ContextError(result.err)
	}

	var dialStats *TunnelDialStats

	if dialConfig.UpstreamProxyUrl != "" || meekConfig != nil {
		dialStats = &TunnelDialStats{}

		if selectedUserAgent {
			dialStats.SelectedUserAgent = true
			dialStats.UserAgent = dialConfig.CustomHeaders.Get("User-Agent")
		}

		if dialConfig.UpstreamProxyUrl != "" {

			// Note: UpstreamProxyUrl should have parsed correctly in the dial
			proxyURL, err := url.Parse(dialConfig.UpstreamProxyUrl)
			if err == nil {
				dialStats.UpstreamProxyType = proxyURL.Scheme
			}

			dialStats.UpstreamProxyCustomHeaderNames = make([]string, 0)
			for name, _ := range dialConfig.CustomHeaders {
				if selectedUserAgent && name == "User-Agent" {
					continue
				}
				dialStats.UpstreamProxyCustomHeaderNames = append(dialStats.UpstreamProxyCustomHeaderNames, name)
			}
		}

		if meekConfig != nil {
			dialStats.MeekDialAddress = meekConfig.DialAddress
			dialStats.MeekResolvedIPAddress = resolvedIPAddress.Load().(string)
			dialStats.MeekSNIServerName = meekConfig.SNIServerName
			dialStats.MeekHostHeader = meekConfig.HostHeader
			dialStats.MeekTransformedHostName = meekConfig.TransformedHostName
		}

		NoticeConnectedTunnelDialStats(serverEntry.IpAddress, dialStats)
	}

	cleanupConn = nil

	// Note: dialConn may be used to close the underlying network connection
	// but should not be used to perform I/O as that would interfere with SSH
	// (and also bypasses throttling).

	return &dialResult{
			dialConn:      dialConn,
			monitoredConn: monitoredConn,
			sshClient:     result.sshClient,
			sshRequests:   result.sshRequests,
			dialStats:     dialStats},
		nil
}

func makeRandomPeriod(min, max time.Duration) time.Duration {
	period, err := common.MakeRandomPeriod(min, max)
	if err != nil {
		NoticeAlert("MakeRandomPeriod failed: %s", err)
		// Proceed without random period
		period = max
	}
	return period
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
// Note that port foward failures may be due to non-failure conditions.
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

	lastBytesReceivedTime := monotime.Now()

	lastTotalBytesTransferedTime := monotime.Now()
	totalSent := int64(0)
	totalReceived := int64(0)

	noticeBytesTransferredTicker := time.NewTicker(1 * time.Second)
	defer noticeBytesTransferredTicker.Stop()

	// The next status request and ssh keep alive times are picked at random,
	// from a range, to make the resulting traffic less fingerprintable,
	// Note: not using Tickers since these are not fixed time periods.
	nextStatusRequestPeriod := func() time.Duration {
		return makeRandomPeriod(
			PSIPHON_API_STATUS_REQUEST_PERIOD_MIN,
			PSIPHON_API_STATUS_REQUEST_PERIOD_MAX)
	}

	statsTimer := time.NewTimer(nextStatusRequestPeriod())
	defer statsTimer.Stop()

	// Schedule an immediate status request to deliver any unreported
	// persistent stats.
	// Note: this may not be effective when there's an outstanding
	// asynchronous untunneled final status request is holding the
	// persistent stats records. It may also conflict with other
	// tunnel candidates which attempt to send an immediate request
	// before being discarded. For now, we mitigate this with a short,
	// random delay.
	unreported := CountUnreportedPersistentStats()
	if unreported > 0 {
		NoticeInfo("Unreported persistent stats: %d", unreported)
		statsTimer.Reset(makeRandomPeriod(
			PSIPHON_API_STATUS_REQUEST_SHORT_PERIOD_MIN,
			PSIPHON_API_STATUS_REQUEST_SHORT_PERIOD_MAX))
	}

	nextSshKeepAlivePeriod := func() time.Duration {
		return makeRandomPeriod(
			TUNNEL_SSH_KEEP_ALIVE_PERIOD_MIN,
			TUNNEL_SSH_KEEP_ALIVE_PERIOD_MAX)
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
		for _ = range signalStatusRequest {
			sendStats(tunnel)
		}
	}()

	requestsWaitGroup.Add(1)
	signalSshKeepAlive := make(chan time.Duration)
	sshKeepAliveError := make(chan error, 1)
	go func() {
		defer requestsWaitGroup.Done()
		for timeout := range signalSshKeepAlive {
			err := sendSshKeepAlive(tunnel.sshClient, tunnel.conn, timeout)
			if err != nil {
				select {
				case sshKeepAliveError <- err:
				default:
				}
			}
		}
	}()

	requestsWaitGroup.Add(1)
	signalStopClientVerificationRequests := make(chan struct{})
	go func() {
		defer requestsWaitGroup.Done()

		clientVerificationRequestSuccess := true
		clientVerificationPayload := ""
		failCount := 0
		for {
			// TODO: use reflect.SelectCase?
			if clientVerificationRequestSuccess == true {
				failCount = 0
				select {
				case clientVerificationPayload = <-tunnel.newClientVerificationPayload:
				case <-signalStopClientVerificationRequests:
					return
				}
			} else {
				// If sendClientVerification failed to send the payload we
				// will retry after a delay. Will use a new payload instead
				// if that arrives in the meantime.
				// If failures count is more than PSIPHON_API_CLIENT_VERIFICATION_REQUEST_MAX_RETRIES
				// stop retrying for this tunnel.
				failCount += 1
				if failCount > PSIPHON_API_CLIENT_VERIFICATION_REQUEST_MAX_RETRIES {
					return
				}
				timeout := time.After(PSIPHON_API_CLIENT_VERIFICATION_REQUEST_RETRY_PERIOD)
				select {
				case <-timeout:
				case clientVerificationPayload = <-tunnel.newClientVerificationPayload:
				case <-signalStopClientVerificationRequests:
					return
				}
			}

			clientVerificationRequestSuccess = sendClientVerification(tunnel, clientVerificationPayload)
		}
	}()

	shutdown := false
	var err error
	for !shutdown && err == nil {
		select {
		case <-noticeBytesTransferredTicker.C:
			sent, received := transferstats.ReportRecentBytesTransferredForServer(
				tunnel.serverEntry.IpAddress)

			if received > 0 {
				lastBytesReceivedTime = monotime.Now()
			}

			totalSent += sent
			totalReceived += received

			if lastTotalBytesTransferedTime.Add(TOTAL_BYTES_TRANSFERRED_NOTICE_PERIOD).Before(monotime.Now()) {
				NoticeTotalBytesTransferred(tunnel.serverEntry.IpAddress, totalSent, totalReceived)
				lastTotalBytesTransferedTime = monotime.Now()
			}

			// Only emit the frequent BytesTransferred notice when tunnel is not idle.
			if tunnel.config.EmitBytesTransferred && (sent > 0 || received > 0) {
				NoticeBytesTransferred(tunnel.serverEntry.IpAddress, sent, received)
			}

		case <-statsTimer.C:
			select {
			case signalStatusRequest <- *new(struct{}):
			default:
			}
			statsTimer.Reset(nextStatusRequestPeriod())

		case <-sshKeepAliveTimer.C:
			if lastBytesReceivedTime.Add(TUNNEL_SSH_KEEP_ALIVE_PERIODIC_INACTIVE_PERIOD).Before(monotime.Now()) {
				select {
				case signalSshKeepAlive <- time.Duration(*tunnel.config.TunnelSshKeepAlivePeriodicTimeoutSeconds) * time.Second:
				default:
				}
			}
			sshKeepAliveTimer.Reset(nextSshKeepAlivePeriod())

		case <-tunnel.signalPortForwardFailure:
			// Note: no mutex on portForwardFailureTotal; only referenced here
			tunnel.totalPortForwardFailures++
			NoticeInfo("port forward failures for %s: %d",
				tunnel.serverEntry.IpAddress, tunnel.totalPortForwardFailures)

			if lastBytesReceivedTime.Add(TUNNEL_SSH_KEEP_ALIVE_PROBE_INACTIVE_PERIOD).Before(monotime.Now()) {
				select {
				case signalSshKeepAlive <- time.Duration(*tunnel.config.TunnelSshKeepAliveProbeTimeoutSeconds) * time.Second:
				default:
				}
			}
			if !tunnel.config.DisablePeriodicSshKeepAlive {
				sshKeepAliveTimer.Reset(nextSshKeepAlivePeriod())
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

		case <-tunnel.shutdownOperateBroadcast:
			shutdown = true
		}
	}

	close(signalSshKeepAlive)
	close(signalStatusRequest)
	close(signalStopClientVerificationRequests)
	requestsWaitGroup.Wait()

	// Capture bytes transferred since the last noticeBytesTransferredTicker tick
	sent, received := transferstats.ReportRecentBytesTransferredForServer(tunnel.serverEntry.IpAddress)
	totalSent += sent
	totalReceived += received

	// Always emit a final NoticeTotalBytesTransferred
	NoticeTotalBytesTransferred(tunnel.serverEntry.IpAddress, totalSent, totalReceived)

	// Tunnel does not have a serverContext when DisableApi is set.
	if tunnel.serverContext != nil && !tunnel.IsDiscarded() {

		// The stats for this tunnel will be reported via the next successful
		// status request.

		// Since client clocks are unreliable, we report the server's timestamp from
		// the handshake response as the absolute tunnel start time. This time
		// will be slightly earlier than the actual tunnel activation time, as the
		// client has to receive and parse the response and activate the tunnel.

		tunnelStartTime := tunnel.serverContext.serverHandshakeTimestamp

		// For the tunnel duration calculation, we use the local clock. The start time
		// is tunnel.establishedTime as recorded when the tunnel was established. For the
		// end time, we do not use the current time as we may now be long past the
		// actual termination time of the tunnel. For example, the host or device may
		// have resumed after a long sleep (it's not clear that the monotonic clock service
		// used to measure elapsed time will or will not stop during device sleep). Instead,
		// we use the last data received time as the estimated tunnel end time.
		//
		// One potential issue with using the last received time is receiving data
		// after an extended sleep because the device sleep occured with data still in
		// the OS socket read buffer. This is not expected to happen on Android, as the
		// OS will wake a process when it has TCP data available to read. (For this reason,
		// the actual long sleep issue is only with an idle tunnel; in this case the client
		// is responsible for sending SSH keep alives but a device sleep will delay the
		// golang SSH keep alive timer.)
		//
		// Idle tunnels will only read data when a SSH keep alive is sent. As a result,
		// the last-received-time scheme can undercount tunnel durations by up to
		// TUNNEL_SSH_KEEP_ALIVE_PERIOD_MAX for idle tunnels.

		tunnelDuration := tunnel.conn.GetLastActivityMonotime().Sub(tunnel.establishedTime)

		err := RecordTunnelStat(
			tunnel.serverContext.sessionId,
			tunnel.serverContext.tunnelNumber,
			tunnel.serverEntry.IpAddress,
			fmt.Sprintf("%d", tunnel.establishDuration),
			tunnelStartTime,
			fmt.Sprintf("%d", tunnelDuration),
			totalSent,
			totalReceived)
		if err != nil {
			NoticeAlert("RecordTunnelStats failed: %s", common.ContextError(err))
		}
	}

	// Final status request notes:
	//
	// It's highly desirable to send a final status request in order to report
	// domain bytes transferred stats as well as to report tunnel stats as
	// soon as possible. For this reason, we attempt untunneled requests when
	// the tunneled request isn't possible or has failed.
	//
	// In an orderly shutdown (err == nil), the Controller is stopping and
	// everything must be wrapped up quickly. Also, we still have a working
	// tunnel. So we first attempt a tunneled status request (with a short
	// timeout) and then attempt, synchronously -- otherwise the Contoller's
	// runWaitGroup.Wait() will return while a request is still in progress
	// -- untunneled requests (also with short timeouts). Note that in this
	// case the untunneled request will opt out of untunneledPendingConns so
	// that it's not inadvertently canceled by the Controller shutdown
	// sequence (see doUntunneledStatusRequest).
	//
	// If the tunnel has failed, the Controller may continue working. We want
	// to re-establish as soon as possible (so don't want to block on status
	// requests, even for a second). We may have a long time to attempt
	// untunneled requests in the background. And there is no tunnel through
	// which to attempt tunneled requests. So we spawn a goroutine to run the
	// untunneled requests, which are allowed a longer timeout. These requests
	// will be interrupted by the Controller's untunneledPendingConns.CloseAll()
	// in the case of a shutdown.

	if err == nil {
		NoticeInfo("shutdown operate tunnel")
		if !sendStats(tunnel) {
			sendUntunneledStats(tunnel, true)
		}
	} else {
		NoticeAlert("operate tunnel error for %s: %s", tunnel.serverEntry.IpAddress, err)
		go sendUntunneledStats(tunnel, false)
		tunnelOwner.SignalTunnelFailure(tunnel)
	}
}

// sendSshKeepAlive is a helper which sends a keepalive@openssh.com request
// on the specified SSH connections and returns true of the request succeeds
// within a specified timeout. If the request fails, the associated conn is
// closed, which will terminate the associated tunnel.
func sendSshKeepAlive(
	sshClient *ssh.Client, conn net.Conn, timeout time.Duration) error {

	errChannel := make(chan error, 2)
	if timeout > 0 {
		time.AfterFunc(timeout, func() {
			errChannel <- TimeoutError{}
		})
	}

	go func() {
		// Random padding to frustrate fingerprinting
		randomPadding, err := common.MakeSecureRandomPadding(0, TUNNEL_SSH_KEEP_ALIVE_PAYLOAD_MAX_BYTES)
		if err != nil {
			NoticeAlert("MakeSecureRandomPadding failed: %s", err)
			// Proceed without random padding
			randomPadding = make([]byte, 0)
		}
		// Note: reading a reply is important for last-received-time tunnel
		// duration calculation.
		_, _, err = sshClient.SendRequest("keepalive@openssh.com", true, randomPadding)
		errChannel <- err
	}()

	err := <-errChannel
	if err != nil {
		sshClient.Close()
		conn.Close()
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
		NoticeAlert("DoStatusRequest failed for %s: %s", tunnel.serverEntry.IpAddress, err)
	}

	return err == nil
}

// sendUntunnelStats sends final status requests directly to Psiphon
// servers after the tunnel has already failed. This is an attempt
// to retain useful bytes transferred stats.
func sendUntunneledStats(tunnel *Tunnel, isShutdown bool) {

	// Tunnel does not have a serverContext when DisableApi is set
	if tunnel.serverContext == nil {
		return
	}

	// Skip when tunnel is discarded
	if tunnel.IsDiscarded() {
		return
	}

	err := tunnel.serverContext.TryUntunneledStatusRequest(isShutdown)
	if err != nil {
		NoticeAlert("TryUntunneledStatusRequest failed for %s: %s", tunnel.serverEntry.IpAddress, err)
	}
}

// sendClientVerification is a helper for sending a client verification request
// to the server.
func sendClientVerification(tunnel *Tunnel, clientVerificationPayload string) bool {

	// Tunnel does not have a serverContext when DisableApi is set
	if tunnel.serverContext == nil {
		return true
	}

	// Skip when tunnel is discarded
	if tunnel.IsDiscarded() {
		return true
	}

	err := tunnel.serverContext.DoClientVerificationRequest(clientVerificationPayload, tunnel.serverEntry.IpAddress)
	if err != nil {
		NoticeAlert("DoClientVerificationRequest failed for %s: %s", tunnel.serverEntry.IpAddress, err)
	}

	return err == nil
}
