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
	"fmt"
	"math"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/pion/datachannel"
	"github.com/pion/ice/v2"
	"github.com/pion/sdp/v3"
	"github.com/pion/webrtc/v3"
	"github.com/wader/filtertransport"
)

const (
	dataChannelBufferedAmountLowThreshold uint64 = 512 * 1024
	dataChannelMaxBufferedAmount          uint64 = 1024 * 1024
)

// WebRTCConn is a WebRTC connection between two peers, with a data channel
// used to relay streams or packets between them. WebRTCConn implements the
// net.Conn interface.
type WebRTCConn struct {
	config                       *WebRTCConfig
	mutex                        sync.Mutex
	udpConn                      net.PacketConn
	portMapper                   *portMapper
	isClosed                     bool
	closedSignal                 chan struct{}
	peerConnection               *webrtc.PeerConnection
	dataChannel                  *webrtc.DataChannel
	dataChannelConn              datachannel.ReadWriteCloser
	dataChannelOpenedSignal      chan struct{}
	dataChannelOpenedOnce        sync.Once
	dataChannelWriteBufferSignal chan struct{}
	messageMutex                 sync.Mutex
	messageBuffer                []byte
	messageOffset                int
	messageLength                int
	messageError                 error
}

// WebRTCConfig specifies the configuration for a WebRTC dial.
type WebRTCConfig struct {

	// Logger is used to log events.
	Logger common.Logger

	// DialParameters specifies specific WebRTC dial strategies and
	// settings; DialParameters also facilities dial replay by receiving
	// callbacks when individual dial steps succeed or fail.
	DialParameters DialParameters

	// ClientRootObfuscationSecret is generated (or replayed) by the client
	// and sent to the proxy and used to drive obfuscation operations.
	ClientRootObfuscationSecret ObfuscationSecret

	// DoDTLSRandomization indicates whether to perform DTLS randomization.
	DoDTLSRandomization bool

	// ReliableTransport indicates whether to configure the WebRTC data
	// channel to use reliable transport. Set ReliableTransport when proxying
	// a TCP stream, and unset it when proxying a UDP packets flow with its
	// own reliability later, such as QUIC.
	ReliableTransport bool
}

// NewWebRTCConnWithOffer initiates a new WebRTC connection. An offer SDP is
// returned, to be sent to the peer. After the offer SDP is forwarded and an
// answer SDP received in response, call SetRemoteSDP with the answer SDP and
// then call AwaitInitialDataChannel to await the eventual WebRTC connection
// establishment.
func NewWebRTCConnWithOffer(
	ctx context.Context,
	config *WebRTCConfig) (
	*WebRTCConn, webrtc.SessionDescription, *SDPMetrics, error) {

	conn, SDP, metrics, err := newWebRTCConn(ctx, config, nil)
	if err != nil {
		return nil, webrtc.SessionDescription{}, nil, errors.Trace(err)
	}
	return conn, *SDP, metrics, nil
}

// NewWebRTCConnWithAnswer creates a new WebRTC connection initiated by a peer
// that provided an offer SDP. An answer SDP is returned to be sent to the
// peer. After the answer SDP is forwarded, call AwaitInitialDataChannel to
// await the eventual WebRTC connection establishment.
func NewWebRTCConnWithAnswer(
	ctx context.Context,
	config *WebRTCConfig,
	peerSDP webrtc.SessionDescription) (
	*WebRTCConn, webrtc.SessionDescription, *SDPMetrics, error) {

	conn, SDP, metrics, err := newWebRTCConn(ctx, config, &peerSDP)
	if err != nil {
		return nil, webrtc.SessionDescription{}, nil, errors.Trace(err)
	}
	return conn, *SDP, metrics, nil
}

func newWebRTCConn(
	ctx context.Context,
	config *WebRTCConfig,
	peerSDP *webrtc.SessionDescription) (
	retConn *WebRTCConn,
	retSDP *webrtc.SessionDescription,
	retMetrics *SDPMetrics,
	retErr error) {

	isOffer := peerSDP == nil

	udpConn, err := config.DialParameters.UDPListen()
	if err != nil {
		return nil, nil, nil, errors.Trace(err)
	}

	// Facilitate DTLS Client/ServerHello randomization. The client decides
	// whether to do DTLS randomization and generates and the proxy receives
	// ClientRootObfuscationSecret, so the client can orchestrate replay on
	// both ends of the connection by reusing an obfuscation secret. Derive a
	// secret specific to DTLS. SetDTLSSeed will futher derive a secure PRNG
	// seed specific to either the client or proxy end of the connection
	// (so each peer's randomization will be distinct).
	//
	// To avoid forking many pion repos in order to pass the seed through to
	// the DTLS implementation, SetDTLSSeed populates a cache that's keyed by
	// the UDP conn.
	//
	// TODO: pion/dtls is not forked yet, so this is a no-op at this time.

	if config.DoDTLSRandomization {

		dtlsObfuscationSecret, err := deriveObfuscationSecret(
			config.ClientRootObfuscationSecret, false, "in-proxy-DTLS-seed")
		if err != nil {
			return nil, nil, nil, errors.Trace(err)
		}

		deadline, _ := ctx.Deadline()
		err = SetDTLSSeed(udpConn, dtlsObfuscationSecret, isOffer, time.Until(deadline))
		if err != nil {
			return nil, nil, nil, errors.Trace(err)
		}
	}

	// Initialize WebRTC

	// There is no explicit anti-probing measures for the proxy side of the
	// WebRTC connection, since each proxy "listener" is ephemeral, and since
	// the WebRTC data channel protocol authenticates peers with
	// certificates, so even if a probe were to find an ephemeral proxy
	// listener, the listener can respond the same as a normal WebRTC end
	// point would respond to a peer that doesn't have the correct credentials.
	//
	// pion's Mux API is used, as it enables providing a pre-created UDP
	// socket which is configured with necessary BindToDevice settings. We do
	// not actually multiplex multiple client connections on a single proxy
	// connection. As a proxy creates a new UDP socket and Mux for each
	// client, this currently open issue should not impact our
	// implementation: "Listener doesn't process parallel handshakes",
	// https://github.com/pion/dtls/issues/279.
	//
	// We detach data channels in order to use the standard Read/Write APIs.
	// As detaching avoids using the pion DataChannel read loop, this
	// currently open issue should not impact our
	// implementation: "DataChannel.readLoop goroutine leak",
	// https://github.com/pion/webrtc/issues/2098.

	settingEngine := webrtc.SettingEngine{}
	settingEngine.DetachDataChannels()
	settingEngine.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)
	settingEngine.SetICEUDPMux(webrtc.NewICEUDPMux(&webrtcLogger{logger: config.Logger}, udpConn))

	// Set this behavior to like common web browser WebRTC stacks.
	settingEngine.SetDTLSInsecureSkipHelloVerify(true)

	webRTCAPI := webrtc.NewAPI(webrtc.WithSettingEngine(settingEngine))

	dataChannelLabel := "in-proxy-data-channel"

	// NAT traversal setup

	// When DisableInboundForMobleNetworks is set, skip both STUN and port
	// mapping for mobile networks. Most mobile networks use CGNAT and
	// neither STUN nor port mapping will be effective. It's faster to not
	// wait for something that ultimately won't work.

	disableInbound := config.DialParameters.DisableInboundForMobleNetworks() &&
		config.DialParameters.NetworkType() == NetworkTypeMobile

	// Try to establish a port mapping (UPnP-IGD, PCP, or NAT-PMP). The port
	// mapper will attempt to identify the local gateway and query various
	// port mapping protocols. portMapper.start launches this process and
	// does not block. Port mappings are not part of the WebRTC standard, or
	// supported by pion/webrtc. Instead, if a port mapping is established,
	// it's edited into the SDP as a new host-type ICE candidate.

	localPort := udpConn.LocalAddr().(*net.UDPAddr).Port
	portMapper := newPortMapper(config.Logger, localPort)

	doPortMapping := !disableInbound && !config.DialParameters.DisablePortMapping()

	if doPortMapping {
		portMapper.start()
	}

	// Select a STUN server for ICE hole punching. The STUN server to be used
	// needs only support bind and not full RFC5780 NAT discovery.
	//
	// Each dial trys only one STUN server; in Psiphon tunnel establishment,
	// other, concurrent in-proxy dials may select alternative STUN servers
	// via DialParameters. When the STUN server operation is successful,
	// DialParameters will be signaled so that it may configure the STUN
	// server selection for replay.
	//
	// The STUN server will observe proxy IP addresses. Enumeration is
	// mitigated by using various public STUN servers, including Psiphon STUN
	// servers for proxies in non-censored regions. Proxies are also more
	// ephemeral than Psiphon servers.

	RFC5780 := false
	stunServerAddress := config.DialParameters.STUNServerAddress(RFC5780)

	// Proceed even when stunServerAddress is "" and !DisableSTUN, as ICE may
	// find other host candidates.

	doSTUN := stunServerAddress != "" && !disableInbound && !config.DialParameters.DisableSTUN()

	var ICEServers []webrtc.ICEServer

	if doSTUN {

		// Use the Psiphon custom resolver to resolve any STUN server domains.
		serverAddress, err := config.DialParameters.ResolveAddress(
			ctx, stunServerAddress)
		if err != nil {
			return nil, nil, nil, errors.Trace(err)
		}

		ICEServers = []webrtc.ICEServer{
			webrtc.ICEServer{
				URLs: []string{"stun:" + serverAddress},
			},
		}
	}

	peerConnection, err := webRTCAPI.NewPeerConnection(
		webrtc.Configuration{
			ICEServers: ICEServers,
		})
	if err != nil {
		return nil, nil, nil, errors.Trace(err)
	}

	conn := &WebRTCConn{
		config:                       config,
		udpConn:                      udpConn,
		portMapper:                   portMapper,
		closedSignal:                 make(chan struct{}),
		peerConnection:               peerConnection,
		dataChannelOpenedSignal:      make(chan struct{}),
		dataChannelWriteBufferSignal: make(chan struct{}, 1),

		// A data channel uses SCTP and is message oriented. The maximum
		// message size supported by pion/webrtc is 65536:
		// https://github.com/pion/webrtc/blob/dce970438344727af9c9965f88d958c55d32e64d/datachannel.go#L19.
		// This read buffer must be as large as the maximum message size or
		// else a read may fail with io.ErrShortBuffer.
		messageBuffer: make([]byte, math.MaxUint16),
	}
	defer func() {
		if retErr != nil {
			// Cleanup on early return
			conn.Close()

			// Notify the DialParameters that the operation failed so that it
			// can clear replay for that STUN server selection.
			//
			// Limitation: the error here may be due to failures unrelated to
			// the STUN server.

			if ctx.Err() == nil && doSTUN {
				config.DialParameters.STUNServerAddressFailed(RFC5780, stunServerAddress)
			}
		}
	}()

	conn.peerConnection.OnConnectionStateChange(conn.onConnectionStateChange)
	conn.peerConnection.OnICECandidate(conn.onICECandidate)
	conn.peerConnection.OnICEConnectionStateChange(conn.onICEConnectionStateChange)
	conn.peerConnection.OnICEGatheringStateChange(conn.onICEGatheringStateChange)
	conn.peerConnection.OnNegotiationNeeded(conn.onNegotiationNeeded)
	conn.peerConnection.OnSignalingStateChange(conn.onSignalingStateChange)
	conn.peerConnection.OnDataChannel(conn.onDataChannel)

	// As a future enhancement, consider using media channels instead of data
	// channels, as media channels may be more common. Proxied QUIC would
	// work over an unreliable media channel. Note that a media channel is
	// still prefixed with STUN and DTLS exchanges before SRTP begins, so the
	// first few packets are the same as a data channel.

	// The offer sets the data channel configuration.
	if isOffer {

		dataChannelInit := &webrtc.DataChannelInit{}
		if !config.ReliableTransport {
			ordered := false
			dataChannelInit.Ordered = &ordered
			maxRetransmits := uint16(0)
			dataChannelInit.MaxRetransmits = &maxRetransmits
		}

		dataChannel, err := peerConnection.CreateDataChannel(
			dataChannelLabel, dataChannelInit)
		if err != nil {
			return nil, nil, nil, errors.Trace(err)
		}

		conn.setDataChannel(dataChannel)
	}

	// Prepare to await full ICE completion, including STUN candidates.
	// Trickle ICE is not used, simplifying the broker API. It's expected
	// that most clients and proxies will be behind a NAT, and not have
	// publicly addressable host candidates. TURN is not used. So most
	// candidates will be STUN, or server-reflexive, candidates.
	//
	// Later, the first to complete out of ICE or port mapping is used.
	//
	// TODO: stop waiting if an IPv6 host candidate is found?

	iceComplete := webrtc.GatheringCompletePromise(conn.peerConnection)

	// Create an offer, or input a peer's offer to create an answer.

	if isOffer {

		offer, err := conn.peerConnection.CreateOffer(nil)
		if err != nil {
			return nil, nil, nil, errors.Trace(err)
		}

		err = conn.peerConnection.SetLocalDescription(offer)
		if err != nil {
			return nil, nil, nil, errors.Trace(err)
		}

	} else {

		err = conn.peerConnection.SetRemoteDescription(*peerSDP)
		if err != nil {
			return nil, nil, nil, errors.Trace(err)
		}

		answer, err := conn.peerConnection.CreateAnswer(nil)
		if err != nil {
			return nil, nil, nil, errors.Trace(err)
		}

		err = conn.peerConnection.SetLocalDescription(answer)
		if err != nil {
			return nil, nil, nil, errors.Trace(err)
		}

	}

	// Await either ICE or port mapping completion.

	// As a future enhancement, track which of ICE or port mapping succeeds
	// and is then followed by a failed WebRTC dial; stop trying the method
	// that often fails.

	iceCompleted := false
	portMappingExternalAddr := ""

	select {
	case <-iceComplete:
		iceCompleted = true

	case portMappingExternalAddr = <-portMapper.portMappingExternalAddress():

		// Set responding port mapping types for metrics.
		//
		// Limitation: if there are multiple responding protocol types, it's
		// not known here which was used for this dial.
		config.DialParameters.SetPortMappingTypes(
			getRespondingPortMappingTypes(config.DialParameters.NetworkID()))

	case <-ctx.Done():
		return nil, nil, nil, errors.Trace(ctx.Err())
	}

	// Release any port mapping resources when not using it.
	if portMapper != nil && portMappingExternalAddr == "" {
		portMapper.close()
		conn.portMapper = nil
	}

	// Get the offer or answer, now populated with any ICE candidates.

	localDescription := conn.peerConnection.LocalDescription()

	// Adjust the SDP, removing local network addresses and adding any
	// port mapping candidate.

	adjustedSDP, metrics, err := PrepareSDPAddresses([]byte(
		localDescription.SDP), portMappingExternalAddr)
	if err != nil {
		return nil, nil, nil, errors.Trace(err)
	}

	// When STUN was attempted, ICE completed, and a STUN server-reflexive
	// candidate is present, notify the DialParameters so that it can set
	// replay for that STUN server selection.

	if iceCompleted && doSTUN {
		hasServerReflexive := false
		for _, candidateType := range metrics.ICECandidateTypes {
			if candidateType == ICECandidateServerReflexive {
				hasServerReflexive = true
			}
		}
		if hasServerReflexive {
			config.DialParameters.STUNServerAddressSucceeded(RFC5780, stunServerAddress)
		} else {
			config.DialParameters.STUNServerAddressFailed(RFC5780, stunServerAddress)
		}
	}

	// The WebRTCConn is prepared, but the data channel is not yet connected.
	// On the offer end, the peer's following answer must be input to
	// SetRemoteSDP. And both ends must call AwaitInitialDataChannel to await
	// the data channel establishment.

	return conn,
		&webrtc.SessionDescription{
			Type: localDescription.Type,
			SDP:  string(adjustedSDP),
		},
		metrics,
		nil
}

func (conn *WebRTCConn) setDataChannel(dataChannel *webrtc.DataChannel) {

	// Assumes the caller holds conn.mutex, or is newWebRTCConn, creating the
	// conn.

	conn.dataChannel = dataChannel
	conn.dataChannel.OnOpen(conn.onDataChannelOpen)
	conn.dataChannel.OnClose(conn.onDataChannelClose)

	conn.dataChannel.OnOpen(conn.onDataChannelOpen)
	conn.dataChannel.OnClose(conn.onDataChannelClose)

	// Set up flow control (see comment in conn.Write)
	conn.dataChannel.SetBufferedAmountLowThreshold(dataChannelBufferedAmountLowThreshold)
	conn.dataChannel.OnBufferedAmountLow(func() {
		select {
		case conn.dataChannelWriteBufferSignal <- struct{}{}:
		default:
		}
	})
}

// SetRemoteSDP takes the answer SDP that is received in response to an offer
// SDP. SetRemoteSDP initiates the WebRTC connection establishment on the
// offer end.
func (conn *WebRTCConn) SetRemoteSDP(peerSDP webrtc.SessionDescription) error {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	err := conn.peerConnection.SetRemoteDescription(peerSDP)
	if err != nil {
		return errors.Trace(err)
	}
	return nil
}

// AwaitInitialDataChannel returns when the data channel is established, or
// when an error has occured.
func (conn *WebRTCConn) AwaitInitialDataChannel(ctx context.Context) error {

	// Don't lock the mutex, or else necessary operations will deadlock.

	select {
	case <-conn.dataChannelOpenedSignal:

		// The data channel is connected.
		//
		// TODO: for metrics, determine which end was the network connection
		// initiator; and determine which type of ICE candidate was
		// successful (note that peer-reflexive candidates aren't in either
		// SDP and emerge only during ICE negotiation).

	case <-ctx.Done():
		return errors.Trace(ctx.Err())
	case <-conn.closedSignal:
		return errors.TraceNew("connection has closed")
	}
	return nil
}

func (conn *WebRTCConn) Close() error {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	if conn.isClosed {
		return nil
	}

	// Close the udpConn to interrupt any blocking DTLS handshake:
	// https://github.com/pion/webrtc/blob/c1467e4871c78ee3f463b50d858d13dc6f2874a4/dtlstransport.go#L334-L340

	if conn.udpConn != nil {
		conn.udpConn.Close()
	}

	if conn.portMapper != nil {
		conn.portMapper.close()
	}

	if conn.dataChannelConn != nil {
		conn.dataChannelConn.Close()
	}
	if conn.dataChannel != nil {
		conn.dataChannel.Close()
	}
	if conn.peerConnection != nil {
		conn.peerConnection.Close()
	}

	close(conn.closedSignal)

	conn.isClosed = true

	return nil
}

func (conn *WebRTCConn) Read(p []byte) (int, error) {

	// Don't hold this lock, or else concurrent Writes will be blocked.
	conn.mutex.Lock()
	dataChannelConn := conn.dataChannelConn
	conn.mutex.Unlock()

	if dataChannelConn == nil {
		return 0, errors.TraceNew("not connected")
	}

	// The input read buffer, p, may not be the same length as the message
	// read from the data channel. Buffer the read message if another Read
	// call is necessary to consume it. As per https://pkg.go.dev/io#Reader,
	// dataChannelConn bytes read are processed even when
	// dataChannelConn.Read returns an error; the error value is stored and
	// returned with the Read call that consumes the end of the message buffer.

	conn.messageMutex.Lock()
	defer conn.messageMutex.Unlock()

	if conn.messageOffset == conn.messageLength {
		n, err := dataChannelConn.Read(conn.messageBuffer)
		conn.messageOffset = 0
		conn.messageLength = n
		conn.messageError = err
	}

	n := copy(p, conn.messageBuffer[conn.messageOffset:conn.messageLength])
	conn.messageOffset += n

	var err error
	if conn.messageOffset == conn.messageLength {
		err = conn.messageError
	}

	return n, errors.Trace(err)
}

func (conn *WebRTCConn) Write(p []byte) (int, error) {

	// Don't hold this lock, or else concurrent Reads will be blocked.
	conn.mutex.Lock()
	isClosed := conn.isClosed
	bufferedAmount := conn.dataChannel.BufferedAmount()
	dataChannelConn := conn.dataChannelConn
	conn.mutex.Unlock()

	if dataChannelConn == nil {
		return 0, errors.TraceNew("not connected")
	}

	// Flow control is required to ensure that Write calls don't result in
	// unbounded buffering in pion/webrtc. Use similar logic and the same
	// buffer size thresholds as the pion sample code.
	//
	// https://github.com/pion/webrtc/tree/master/examples/data-channels-flow-control#when-do-we-need-it:
	// > Send or SendText methods are called on DataChannel to send data to
	// > the connected peer. The methods return immediately, but it does not
	// > mean the data was actually sent onto the wire. Instead, it is
	// > queued in a buffer until it actually gets sent out to the wire.
	// >
	// > When you have a large amount of data to send, it is an application's
	// > responsibility to control the buffered amount in order not to
	// > indefinitely grow the buffer size to eventually exhaust the memory.

	// If the pion write buffer is too full, wait for a signal that sufficient
	// write data has been consumed before writing more.
	if !isClosed && bufferedAmount+uint64(len(p)) > dataChannelMaxBufferedAmount {
		select {
		case <-conn.dataChannelWriteBufferSignal:
		case <-conn.closedSignal:
			return 0, errors.TraceNew("connection has closed")
		}
	}

	// Limitation: if len(p) > 65536, the dataChannelConn.Write wil fail. In
	// practise, this is not expected to happen with typical use cases such
	// as io.Copy, which uses a 32K buffer.

	n, err := dataChannelConn.Write(p)
	return n, errors.Trace(err)
}

func (conn *WebRTCConn) LocalAddr() net.Addr {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	// This is the local UDP socket address, not the external, public address.
	return conn.udpConn.LocalAddr()
}

func (conn *WebRTCConn) RemoteAddr() net.Addr {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	// Not supported.
	return nil
}

func (conn *WebRTCConn) SetDeadline(t time.Time) error {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	return errors.TraceNew("not supported")
}

func (conn *WebRTCConn) SetReadDeadline(t time.Time) error {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	return errors.TraceNew("not supported")
}

func (conn *WebRTCConn) SetWriteDeadline(t time.Time) error {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	return errors.TraceNew("not supported")
}

func (conn *WebRTCConn) onConnectionStateChange(state webrtc.PeerConnectionState) {

	if state == webrtc.PeerConnectionStateFailed {
		conn.Close()
	}

	conn.config.Logger.WithTraceFields(common.LogFields{
		"state": state.String(),
	}).Info("peer connection state changed")
}

func (conn *WebRTCConn) onICECandidate(candidate *webrtc.ICECandidate) {

	conn.config.Logger.WithTraceFields(common.LogFields{
		"candidate": candidate,
	}).Info("new ICE candidate")
}

func (conn *WebRTCConn) onICEConnectionStateChange(state webrtc.ICEConnectionState) {

	conn.config.Logger.WithTraceFields(common.LogFields{
		"state": state.String(),
	}).Info("ICE connection state changed")
}

func (conn *WebRTCConn) onICEGatheringStateChange(state webrtc.ICEGathererState) {

	conn.config.Logger.WithTraceFields(common.LogFields{
		"state": state.String(),
	}).Info("ICE gathering state changed")
}

func (conn *WebRTCConn) onNegotiationNeeded() {

	conn.config.Logger.WithTrace().Info("negotiation needed")
}

func (conn *WebRTCConn) onSignalingStateChange(state webrtc.SignalingState) {

	conn.config.Logger.WithTraceFields(common.LogFields{
		"state": state.String(),
	}).Info("signaling state changed")
}

func (conn *WebRTCConn) onDataChannel(dataChannel *webrtc.DataChannel) {

	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	conn.setDataChannel(dataChannel)

	conn.config.Logger.WithTraceFields(common.LogFields{
		"label": dataChannel.Label(),
		"ID":    dataChannel.ID(),
	}).Info("new data channel")
}

func (conn *WebRTCConn) onDataChannelOpen() {

	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	dataChannelConn, err := conn.dataChannel.Detach()
	if err == nil {
		conn.dataChannelConn = dataChannelConn

		// TODO: can a data channel be connected, disconnected, and then
		// reestablished in one session?

		conn.dataChannelOpenedOnce.Do(func() { close(conn.dataChannelOpenedSignal) })
	}

	conn.config.Logger.WithTraceFields(common.LogFields{
		"detachError": err,
	}).Info("data channel open")
}

func (conn *WebRTCConn) onDataChannelClose() {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	conn.config.Logger.WithTrace().Info("data channel closed")
}

// PrepareSDPAddresses adjusts the SDP, pruning local network addresses and
// adding any port mapping as a host candidate.
func PrepareSDPAddresses(
	encodedSDP []byte,
	portMappingExternalAddr string) ([]byte, *SDPMetrics, error) {

	modifiedSDP, metrics, err := processSDPAddresses(
		encodedSDP, portMappingExternalAddr, false, nil, common.GeoIPData{})
	return modifiedSDP, metrics, errors.Trace(err)
}

// ValidateSDPAddresses checks that the SDP does not contain an empty list of
// candidates, bogon candidates, or candidates outside of the country and ASN
// for the specified expectedGeoIPData.
func ValidateSDPAddresses(
	encodedSDP []byte,
	lookupGeoIP LookupGeoIP,
	expectedGeoIPData common.GeoIPData) (*SDPMetrics, error) {

	_, metrics, err := processSDPAddresses(encodedSDP, "", true, lookupGeoIP, expectedGeoIPData)
	return metrics, errors.Trace(err)
}

// SDPMetrics are network capability metrics values for an SDP.
type SDPMetrics struct {
	ICECandidateTypes []ICECandidateType
	HasIPv6           bool
}

// processSDPAddresses is based on snowflake/common/util.StripLocalAddresses
// https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/-/blob/v2.5.1/common/util/util.go#L70-99
/*
              This file contains the license for "Snowflake"
     a free software project which provides a WebRTC pluggable transport.

================================================================================
Copyright (c) 2016, Serene Han, Arlo Breault
Copyright (c) 2019-2020, The Tor Project, Inc

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

  * Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

  * Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.

  * Neither the names of the copyright owners nor the names of its
contributors may be used to endorse or promote products derived from this
software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
================================================================================

*/

func processSDPAddresses(
	encodedSDP []byte,
	portMappingExternalAddr string,
	errorOnBogon bool,
	lookupGeoIP LookupGeoIP,
	expectedGeoIPData common.GeoIPData) ([]byte, *SDPMetrics, error) {

	var sessionDescription sdp.SessionDescription
	err := sessionDescription.Unmarshal(encodedSDP)
	if err != nil {
		return nil, nil, errors.Trace(err)
	}

	candidateTypes := map[ICECandidateType]bool{}
	hasIPv6 := false

	var portMappingICECandidates []sdp.Attribute
	if portMappingExternalAddr != "" {

		// Prepare ICE candidate attibute pair for the port mapping, modeled after the definition of host candidates.

		host, portStr, err := net.SplitHostPort(portMappingExternalAddr)
		if err != nil {
			return nil, nil, errors.Trace(err)
		}
		port, _ := strconv.Atoi(portStr)

		// Only IPv4 port mapping addresses are supported due to the
		// NewCandidateHost limitation noted below. It is expected that port
		// mappings will be IPv4, as NAT and IPv6 is not a typical combination.

		hostIP := net.ParseIP(host)
		if hostIP != nil && hostIP.To4() != nil {

			for _, component := range []webrtc.ICEComponent{webrtc.ICEComponentRTP, webrtc.ICEComponentRTCP} {

				// The candidate ID is generated and the priorty and foundation
				// use the default for hosts.
				//
				// Limitation: NewCandidateHost initializes the networkType to
				// NetworkTypeUDP4, and this field is not-exported.
				// https://github.com/pion/ice/blob/6d301287654b05a36248842c278d58d501454bff/candidate_host.go#L27-L64

				iceCandidate, err := ice.NewCandidateHost(&ice.CandidateHostConfig{
					Network:   "udp",
					Address:   host,
					Port:      port,
					Component: uint16(component),
				})
				if err != nil {
					return nil, nil, errors.Trace(err)
				}

				portMappingICECandidates = append(
					portMappingICECandidates,
					sdp.Attribute{Key: "candidate", Value: iceCandidate.Marshal()})
			}

			candidateTypes[ICECandidatePortMapping] = true
		}
	}

	candidateCount := len(portMappingICECandidates)

	for _, mediaDescription := range sessionDescription.MediaDescriptions {

		addPortMappingCandidates := len(portMappingICECandidates) > 0
		var attributes []sdp.Attribute
		for _, attribute := range mediaDescription.Attributes {

			// Insert the port mapping candidate either before the
			// first "a=candidate", or before "a=end-of-candidates"(there may
			// be no "a=candidate" attributes).

			if addPortMappingCandidates &&
				(attribute.IsICECandidate() || attribute.Key == sdp.AttrKeyEndOfCandidates) {

				attributes = append(attributes, portMappingICECandidates...)
				addPortMappingCandidates = false
			}

			if attribute.IsICECandidate() {

				candidate, err := ice.UnmarshalCandidate(attribute.Value)
				if err != nil {
					return nil, nil, errors.Trace(err)
				}

				candidateIP := net.ParseIP(candidate.Address())

				if candidateIP == nil {
					return nil, nil, errors.TraceNew("unexpected non-IP")
				}

				if candidateIP.To4() == nil {
					hasIPv6 = true
				}

				// Strip non-routable bogons, including LAN addresses.
				// Same-LAN client/proxy hops are not expected to be useful,
				// and this also avoids unnecessary local network traffic.
				//
				// Well-behaved clients and proxies will strip these values;
				// the broker enforces this and uses errorOnBogon.

				if !getAllowLoopbackWebRTCConnections() &&
					isBogon(candidateIP) {

					if errorOnBogon {
						return nil, nil, errors.TraceNew("unexpected bogon")
					}
					continue
				}

				// The broker will check that clients and proxies specify only
				// candidates that map to the same GeoIP country and ASN as
				// the client/proxy connection to the broker. This limits
				// misuse of candidate to connect to other locations.
				// Legitimate candidates will not all have the exact same IP
				// address, as there could be a mix of IPv4 and IPv6, as well
				// as potentially different NAT paths.

				if lookupGeoIP != nil {
					candidateGeoIPData := lookupGeoIP(candidate.Address())
					if candidateGeoIPData.Country != expectedGeoIPData.Country {
						return nil, nil, errors.TraceNew("unexpected GeoIP country")
					}
					if candidateGeoIPData.ASN != expectedGeoIPData.ASN {
						return nil, nil, errors.TraceNew("unexpected GeoIP ASN")
					}
				}

				// These types are not reported:
				// - CandidateTypeRelay: TURN servers are not used.
				// - CandidateTypePeerReflexive: this candidate type only
				//   emerges later in the connection process.

				switch candidate.Type() {
				case ice.CandidateTypeHost:
					candidateTypes[ICECandidateHost] = true
				case ice.CandidateTypeServerReflexive:
					candidateTypes[ICECandidateServerReflexive] = true
				}

				candidateCount += 1
			}

			attributes = append(attributes, attribute)
		}

		mediaDescription.Attributes = attributes
	}

	if candidateCount == 0 {
		return nil, nil, errors.TraceNew("no candidates")
	}

	encodedSDP, err = sessionDescription.Marshal()
	if err != nil {
		return nil, nil, errors.Trace(err)
	}

	metrics := &SDPMetrics{
		HasIPv6: hasIPv6,
	}
	for candidateType := range candidateTypes {
		metrics.ICECandidateTypes = append(metrics.ICECandidateTypes, candidateType)
	}

	return encodedSDP, metrics, nil
}

var allowLoopbackWebRTCConnections int32

func getAllowLoopbackWebRTCConnections() bool {
	return atomic.LoadInt32(&allowLoopbackWebRTCConnections) == 1
}

// setAllowLoopbackWebRTCConnections is for testing only, to allow the
// end-to-end inproxy_test to run with a restrictive OS firewall in place. Do
// not export.
func setAllowLoopbackWebRTCConnections(allow bool) {
	value := int32(0)
	if allow {
		value = 1
	}
	atomic.StoreInt32(&allowLoopbackWebRTCConnections, value)
}

func isBogon(IP net.IP) bool {
	if IP == nil {
		return false
	}
	return filtertransport.FindIPNet(
		filtertransport.DefaultFilteredNetworks, IP)
}

// webrtcLogger wraps common.Logger and implements
// https://pkg.go.dev/github.com/pion/logging#LeveledLogger for passing into
// pion.
type webrtcLogger struct {
	logger common.Logger
}

func (l *webrtcLogger) Trace(msg string) {
	// Ignored.
}

func (l *webrtcLogger) Tracef(format string, args ...interface{}) {
	// Ignored.
}

func (l *webrtcLogger) Debug(msg string) {
	l.logger.WithTrace().Debug("webRTC: " + msg)
}

func (l *webrtcLogger) Debugf(format string, args ...interface{}) {
	l.logger.WithTrace().Debug("webRTC: " + fmt.Sprintf(format, args...))
}

func (l *webrtcLogger) Info(msg string) {
	l.logger.WithTrace().Info("webRTC: " + msg)
}

func (l *webrtcLogger) Infof(format string, args ...interface{}) {
	l.logger.WithTrace().Info("webRTC: " + fmt.Sprintf(format, args...))
}

func (l *webrtcLogger) Warn(msg string) {
	l.logger.WithTrace().Warning("webRTC: " + msg)
}

func (l *webrtcLogger) Warnf(format string, args ...interface{}) {
	l.logger.WithTrace().Warning("webRTC: " + fmt.Sprintf(format, args...))
}

func (l *webrtcLogger) Error(msg string) {
	l.logger.WithTrace().Error("webRTC: " + msg)
}

func (l *webrtcLogger) Errorf(format string, args ...interface{}) {
	l.logger.WithTrace().Error("webRTC: " + fmt.Sprintf(format, args...))
}
