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
	"sync"
	"time"

	regen "github.com/Psiphon-Inc/goregen"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/transferstats"
	"golang.org/x/crypto/ssh"
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
	SignalTunnelFailure(tunnel *Tunnel)
}

// Tunnel is a connection to a Psiphon server. An established
// tunnel includes a network connection to the specified server
// and an SSH session built on top of that transport.
type Tunnel struct {
	mutex                    *sync.Mutex
	isClosed                 bool
	serverEntry              *ServerEntry
	session                  *Session
	protocol                 string
	conn                     net.Conn
	sshClient                *ssh.Client
	operateWaitGroup         *sync.WaitGroup
	shutdownOperateBroadcast chan struct{}
	signalPortForwardFailure chan struct{}
	totalPortForwardFailures int
	sessionStartTime         time.Time
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
func EstablishTunnel(
	config *Config,
	sessionId string,
	pendingConns *Conns,
	serverEntry *ServerEntry,
	tunnelOwner TunnelOwner) (tunnel *Tunnel, err error) {

	selectedProtocol, err := selectProtocol(config, serverEntry)
	if err != nil {
		return nil, ContextError(err)
	}

	// Build transport layers and establish SSH connection
	conn, sshClient, err := dialSsh(
		config, pendingConns, serverEntry, selectedProtocol, sessionId)
	if err != nil {
		return nil, ContextError(err)
	}

	// Cleanup on error
	defer func() {
		if err != nil {
			sshClient.Close()
			conn.Close()
		}
	}()

	// The tunnel is now connected
	tunnel = &Tunnel{
		mutex:                    new(sync.Mutex),
		isClosed:                 false,
		serverEntry:              serverEntry,
		protocol:                 selectedProtocol,
		conn:                     conn,
		sshClient:                sshClient,
		operateWaitGroup:         new(sync.WaitGroup),
		shutdownOperateBroadcast: make(chan struct{}),
		// A buffer allows at least one signal to be sent even when the receiver is
		// not listening. Senders should not block.
		signalPortForwardFailure: make(chan struct{}, 1),
	}

	// Create a new Psiphon API session for this tunnel. This includes performing
	// a handshake request. If the handshake fails, this establishment fails.
	//
	// TODO: as long as the servers are not enforcing that a client perform a handshake,
	// proceed with this tunnel as long as at least one previous handhake succeeded?
	//
	if !config.DisableApi {
		NoticeInfo("starting session for %s", tunnel.serverEntry.IpAddress)
		tunnel.session, err = NewSession(config, tunnel, sessionId)
		if err != nil {
			return nil, ContextError(fmt.Errorf("error starting session for %s: %s", tunnel.serverEntry.IpAddress, err))
		}
	}

	tunnel.sessionStartTime = time.Now()

	// Now that network operations are complete, cancel interruptibility
	pendingConns.Remove(conn)

	// Promote this successful tunnel to first rank so it's one
	// of the first candidates next time establish runs.
	PromoteServerEntry(tunnel.serverEntry.IpAddress)

	// Spawn the operateTunnel goroutine, which monitors the tunnel and handles periodic stats updates.
	tunnel.operateWaitGroup.Add(1)
	go tunnel.operateTunnel(config, tunnelOwner)

	return tunnel, nil
}

// Close stops operating the tunnel and closes the underlying connection.
// Supports multiple and/or concurrent calls to Close().
func (tunnel *Tunnel) Close() {

	tunnel.mutex.Lock()
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
		// tunnel.conn.Close() may get called twice, which is allowed.
		tunnel.conn.Close()
	}
}

// Dial establishes a port forward connection through the tunnel
// This Dial doesn't support split tunnel, so alwaysTunnel is not referenced
func (tunnel *Tunnel) Dial(
	remoteAddr string, alwaysTunnel bool, downstreamConn net.Conn) (conn net.Conn, err error) {

	tunnel.mutex.Lock()
	isClosed := tunnel.isClosed
	tunnel.mutex.Unlock()

	if isClosed {
		return nil, errors.New("tunnel is closed")
	}

	type tunnelDialResult struct {
		sshPortForwardConn net.Conn
		err                error
	}
	resultChannel := make(chan *tunnelDialResult, 2)
	time.AfterFunc(TUNNEL_PORT_FORWARD_DIAL_TIMEOUT, func() {
		resultChannel <- &tunnelDialResult{nil, errors.New("tunnel dial timeout")}
	})
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
		return nil, ContextError(result.err)
	}

	conn = &TunneledConn{
		Conn:           result.sshPortForwardConn,
		tunnel:         tunnel,
		downstreamConn: downstreamConn}

	// Tunnel does not have a session when DisableApi is set. We still use
	// transferstats.Conn to count bytes transferred for monitoring tunnel
	// quality.
	var regexps *transferstats.Regexps
	if tunnel.session != nil {
		regexps = tunnel.session.StatsRegexps()
	}
	conn = transferstats.NewConn(conn, tunnel.serverEntry.IpAddress, regexps)

	return conn, nil
}

// SignalComponentFailure notifies the tunnel that an associated component has failed.
// This will terminate the tunnel.
func (tunnel *Tunnel) SignalComponentFailure() {
	NoticeAlert("tunnel received component failure signal")
	tunnel.Close()
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
func selectProtocol(config *Config, serverEntry *ServerEntry) (selectedProtocol string, err error) {
	// TODO: properly handle protocols (e.g. FRONTED-MEEK-OSSH) vs. capabilities (e.g., {FRONTED-MEEK, OSSH})
	// for now, the code is simply assuming that MEEK capabilities imply OSSH capability.
	if config.TunnelProtocol != "" {
		if !serverEntry.SupportsProtocol(config.TunnelProtocol) {
			return "", ContextError(fmt.Errorf("server does not have required capability"))
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
			return "", ContextError(fmt.Errorf("server does not have any supported capabilities"))
		}

		index, err := MakeSecureRandomInt(len(candidateProtocols))
		if err != nil {
			return "", ContextError(err)
		}
		selectedProtocol = candidateProtocols[index]
	}
	return selectedProtocol, nil
}

// dialSsh is a helper that builds the transport layers and establishes the SSH connection
func dialSsh(
	config *Config,
	pendingConns *Conns,
	serverEntry *ServerEntry,
	selectedProtocol,
	sessionId string) (conn net.Conn, sshClient *ssh.Client, err error) {

	// The meek protocols tunnel obfuscated SSH. Obfuscated SSH is layered on top of SSH.
	// So depending on which protocol is used, multiple layers are initialized.
	port := 0
	useMeek := false
	useFronting := false
	useObfuscatedSsh := false
	switch selectedProtocol {
	case TUNNEL_PROTOCOL_FRONTED_MEEK:
		useMeek = true
		useFronting = true
		useObfuscatedSsh = true
	case TUNNEL_PROTOCOL_UNFRONTED_MEEK:
		useMeek = true
		useObfuscatedSsh = true
		port = serverEntry.SshObfuscatedPort
	case TUNNEL_PROTOCOL_OBFUSCATED_SSH:
		useObfuscatedSsh = true
		port = serverEntry.SshObfuscatedPort
	case TUNNEL_PROTOCOL_SSH:
		port = serverEntry.SshPort
	}

	frontingAddress := ""
	if useFronting {
		if len(serverEntry.MeekFrontingAddressesRegex) > 0 {

			// Generate a front address based on the regex.

			frontingAddress, err = regen.Generate(serverEntry.MeekFrontingAddressesRegex)
			if err != nil {
				return nil, nil, ContextError(err)
			}
		} else {

			// Randomly select, for this connection attempt, one front address for
			// fronting-capable servers.

			if len(serverEntry.MeekFrontingAddresses) == 0 {
				return nil, nil, ContextError(errors.New("MeekFrontingAddresses is empty"))
			}
			index, err := MakeSecureRandomInt(len(serverEntry.MeekFrontingAddresses))
			if err != nil {
				return nil, nil, ContextError(err)
			}
			frontingAddress = serverEntry.MeekFrontingAddresses[index]
		}
	}
	NoticeConnectingServer(
		serverEntry.IpAddress,
		serverEntry.Region,
		selectedProtocol,
		frontingAddress)

	// Create the base transport: meek or direct connection
	dialConfig := &DialConfig{
		UpstreamProxyUrl:              config.UpstreamProxyUrl,
		ConnectTimeout:                TUNNEL_CONNECT_TIMEOUT,
		PendingConns:                  pendingConns,
		DeviceBinder:                  config.DeviceBinder,
		DnsServerGetter:               config.DnsServerGetter,
		UseIndistinguishableTLS:       config.UseIndistinguishableTLS,
		TrustedCACertificatesFilename: config.TrustedCACertificatesFilename,
	}
	if useMeek {
		conn, err = DialMeek(serverEntry, sessionId, frontingAddress, dialConfig)
		if err != nil {
			return nil, nil, ContextError(err)
		}
	} else {
		conn, err = DialTCP(fmt.Sprintf("%s:%d", serverEntry.IpAddress, port), dialConfig)
		if err != nil {
			return nil, nil, ContextError(err)
		}
	}

	cleanupConn := conn
	defer func() {
		// Cleanup on error
		if err != nil {
			cleanupConn.Close()
		}
	}()

	// Add obfuscated SSH layer
	var sshConn net.Conn
	sshConn = conn
	if useObfuscatedSsh {
		sshConn, err = NewObfuscatedSshConn(conn, serverEntry.SshObfuscatedKey)
		if err != nil {
			return nil, nil, ContextError(err)
		}
	}

	// Now establish the SSH session over the sshConn transport
	expectedPublicKey, err := base64.StdEncoding.DecodeString(serverEntry.SshHostKey)
	if err != nil {
		return nil, nil, ContextError(err)
	}
	sshCertChecker := &ssh.CertChecker{
		HostKeyFallback: func(addr string, remote net.Addr, publicKey ssh.PublicKey) error {
			if !bytes.Equal(expectedPublicKey, publicKey.Marshal()) {
				return ContextError(errors.New("unexpected host public key"))
			}
			return nil
		},
	}
	sshPasswordPayload, err := json.Marshal(
		struct {
			SessionId   string `json:"SessionId"`
			SshPassword string `json:"SshPassword"`
		}{sessionId, serverEntry.SshPassword})
	if err != nil {
		return nil, nil, ContextError(err)
	}
	sshClientConfig := &ssh.ClientConfig{
		User: serverEntry.SshUsername,
		Auth: []ssh.AuthMethod{
			ssh.Password(string(sshPasswordPayload)),
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
		sshClient *ssh.Client
		err       error
	}
	resultChannel := make(chan *sshNewClientResult, 2)
	time.AfterFunc(TUNNEL_CONNECT_TIMEOUT, func() {
		resultChannel <- &sshNewClientResult{nil, errors.New("ssh dial timeout")}
	})

	go func() {
		// The folowing is adapted from ssh.Dial(), here using a custom conn
		// The sshAddress is passed through to host key verification callbacks; we don't use it.
		sshAddress := ""
		sshClientConn, sshChans, sshReqs, err := ssh.NewClientConn(sshConn, sshAddress, sshClientConfig)
		var sshClient *ssh.Client
		if err == nil {
			sshClient = ssh.NewClient(sshClientConn, sshChans, sshReqs)
		}
		resultChannel <- &sshNewClientResult{sshClient, err}
	}()

	result := <-resultChannel
	if result.err != nil {
		return nil, nil, ContextError(result.err)
	}

	return conn, result.sshClient, nil
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
func (tunnel *Tunnel) operateTunnel(config *Config, tunnelOwner TunnelOwner) {
	defer tunnel.operateWaitGroup.Done()

	lastBytesReceivedTime := time.Now()

	lastTotalBytesTransferedTime := time.Now()
	totalSent := int64(0)
	totalReceived := int64(0)

	noticeBytesTransferredTicker := time.NewTicker(1 * time.Second)
	defer noticeBytesTransferredTicker.Stop()

	// The next status request and ssh keep alive times are picked at random,
	// from a range, to make the resulting traffic less fingerprintable,
	// Note: not using Tickers since these are not fixed time periods.
	nextStatusRequestPeriod := func() time.Duration {
		return MakeRandomPeriod(
			PSIPHON_API_STATUS_REQUEST_PERIOD_MIN,
			PSIPHON_API_STATUS_REQUEST_PERIOD_MAX)
	}

	statsTimer := time.NewTimer(nextStatusRequestPeriod())
	defer statsTimer.Stop()

	nextSshKeepAlivePeriod := func() time.Duration {
		return MakeRandomPeriod(
			TUNNEL_SSH_KEEP_ALIVE_PERIOD_MIN,
			TUNNEL_SSH_KEEP_ALIVE_PERIOD_MAX)
	}

	// TODO: don't initialize timer when config.DisablePeriodicSshKeepAlive is set
	sshKeepAliveTimer := time.NewTimer(nextSshKeepAlivePeriod())
	if config.DisablePeriodicSshKeepAlive {
		sshKeepAliveTimer.Stop()
	} else {
		defer sshKeepAliveTimer.Stop()
	}

	var err error
	for err == nil {
		select {
		case <-noticeBytesTransferredTicker.C:
			sent, received := transferstats.GetBytesTransferredForServer(
				tunnel.serverEntry.IpAddress)

			if received > 0 {
				lastBytesReceivedTime = time.Now()
			}

			totalSent += sent
			totalReceived += received

			if lastTotalBytesTransferedTime.Add(TOTAL_BYTES_TRANSFERRED_NOTICE_PERIOD).Before(time.Now()) {
				NoticeTotalBytesTransferred(tunnel.serverEntry.IpAddress, totalSent, totalReceived)
				lastTotalBytesTransferedTime = time.Now()
			}

			// Only emit the frequent BytesTransferred notice when tunnel is not idle.
			if config.EmitBytesTransferred && (sent > 0 || received > 0) {
				NoticeBytesTransferred(tunnel.serverEntry.IpAddress, sent, received)
			}

		case <-statsTimer.C:
			// TODO: perform this request asynchronously; don't block other operations
			sendStats(tunnel)
			statsTimer.Reset(nextStatusRequestPeriod())

		case <-sshKeepAliveTimer.C:
			if lastBytesReceivedTime.Add(TUNNEL_SSH_KEEP_ALIVE_PERIODIC_INACTIVE_PERIOD).Before(time.Now()) {
				err = sendSshKeepAlive(
					tunnel.sshClient, tunnel.conn, TUNNEL_SSH_KEEP_ALIVE_PERIODIC_TIMEOUT)
			}
			sshKeepAliveTimer.Reset(nextSshKeepAlivePeriod())

		case <-tunnel.signalPortForwardFailure:
			// Note: no mutex on portForwardFailureTotal; only referenced here
			tunnel.totalPortForwardFailures++
			NoticeInfo("port forward failures for %s: %d",
				tunnel.serverEntry.IpAddress, tunnel.totalPortForwardFailures)

			if lastBytesReceivedTime.Add(TUNNEL_SSH_KEEP_ALIVE_PROBE_INACTIVE_PERIOD).Before(time.Now()) {
				err = sendSshKeepAlive(
					tunnel.sshClient, tunnel.conn, TUNNEL_SSH_KEEP_ALIVE_PROBE_TIMEOUT)
			}
			if !config.DisablePeriodicSshKeepAlive {
				sshKeepAliveTimer.Reset(nextSshKeepAlivePeriod())
			}

		case <-tunnel.shutdownOperateBroadcast:
			// Attempt to send any remaining stats
			sendStats(tunnel)
			NoticeInfo("shutdown operate tunnel")
			return
		}
	}

	NoticeTotalBytesTransferred(tunnel.serverEntry.IpAddress, totalSent, totalReceived)

	if err != nil {
		NoticeAlert("operate tunnel error for %s: %s", tunnel.serverEntry.IpAddress, err)
		tunnelOwner.SignalTunnelFailure(tunnel)
	}
}

// sendSshKeepAlive is a helper which sends a keepalive@openssh.com request
// on the specified SSH connections and returns true of the request succeeds
// within a specified timeout.
func sendSshKeepAlive(
	sshClient *ssh.Client, conn net.Conn, timeout time.Duration) error {

	errChannel := make(chan error, 2)
	time.AfterFunc(timeout, func() {
		errChannel <- TimeoutError{}
	})

	go func() {
		// Random padding to frustrate fingerprinting
		_, _, err := sshClient.SendRequest(
			"keepalive@openssh.com", true,
			MakeSecureRandomPadding(0, TUNNEL_SSH_KEEP_ALIVE_PAYLOAD_MAX_BYTES))
		errChannel <- err
	}()

	err := <-errChannel
	if err != nil {
		sshClient.Close()
		conn.Close()
	}

	return ContextError(err)
}

// sendStats is a helper for sending session stats to the server.
func sendStats(tunnel *Tunnel) {

	// Tunnel does not have a session when DisableApi is set
	if tunnel.session == nil {
		return
	}

	payload := transferstats.GetForServer(tunnel.serverEntry.IpAddress)
	if payload != nil {
		err := tunnel.session.DoStatusRequest(payload)
		if err != nil {
			NoticeAlert("DoStatusRequest failed for %s: %s", tunnel.serverEntry.IpAddress, err)
			transferstats.PutBack(tunnel.serverEntry.IpAddress, payload)
		}
	}
}
