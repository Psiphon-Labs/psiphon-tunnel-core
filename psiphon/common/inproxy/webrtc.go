//go:build PSIPHON_ENABLE_INPROXY

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
	"bytes"
	"context"
	"encoding/binary"
	std_errors "errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	inproxy_dtls "github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/inproxy/dtls"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/stacktrace"
	"github.com/pion/datachannel"
	"github.com/pion/dtls/v2"
	"github.com/pion/ice/v2"
	pion_logging "github.com/pion/logging"
	"github.com/pion/sdp/v3"
	"github.com/pion/stun"
	"github.com/pion/transport/v2"
	"github.com/pion/webrtc/v3"
	"github.com/wlynxg/anet"
)

const (
	dataChannelAwaitTimeout                      = 20 * time.Second
	dataChannelBufferedAmountLowThreshold uint64 = 512 * 1024
	dataChannelMaxBufferedAmount          uint64 = 1024 * 1024
	dataChannelMaxMessageSize                    = 65536
	dataChannelMaxLabelLength                    = 512

	// Psiphon uses a fork of github.com/pion/dtls/v2, selected with go mod
	// replace, which has an idential API apart from dtls.IsPsiphon. If
	// dtls.IsPsiphon is undefined, the build is not using the fork.
	//
	// Limitation: this doesn't check that the vendored code is exactly the
	// same code as the fork.
	assertDTLSFork = dtls.IsPsiphon

	// Similarly, check for the fork of github.com/pion/ice/v2.
	assertICEFork = ice.IsPsiphon

	// Note that Psiphon also uses a fork of github.com/pion/webrtc/v3, but it
	// has an API change which will cause builds to fail when not present.
)

// webRTCConn is a WebRTC connection between two peers, with a data channel
// used to relay streams or packets between them. WebRTCConn implements the
// net.Conn interface.
type webRTCConn struct {
	config                   *webRTCConfig
	trafficShapingParameters *DataChannelTrafficShapingParameters

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
	decoyDone                    bool
	iceCandidatePairMetrics      common.LogFields

	readMutex       sync.Mutex
	readBuffer      []byte
	readOffset      int
	readLength      int
	readError       error
	peerPaddingDone bool

	writeMutex           sync.Mutex
	trafficShapingPRNG   *prng.PRNG
	trafficShapingBuffer *bytes.Buffer
	paddedMessageCount   int
	decoyMessageCount    int
	trafficShapingDone   bool

	paddedMessagesSent     int32
	paddedMessagesReceived int32
	decoyMessagesSent      int32
	decoyMessagesReceived  int32
}

// webRTCConfig specifies the configuration for a WebRTC dial.
type webRTCConfig struct {

	// Logger is used to log events.
	Logger common.Logger

	// EnableDebugLogging indicates whether to log pion/webrtc debug and trace
	// events. When enabled, these events will be logged to the specified
	// Logger at a Debug log level.
	EnableDebugLogging bool

	// WebRTCDialCoordinator specifies specific WebRTC dial strategies and
	// settings; WebRTCDialCoordinator also facilities dial replay by
	// receiving callbacks when individual dial steps succeed or fail.
	WebRTCDialCoordinator WebRTCDialCoordinator

	// ClientRootObfuscationSecret is generated (or replayed) by the client
	// and sent to the proxy and used to drive obfuscation operations.
	ClientRootObfuscationSecret ObfuscationSecret

	// DoDTLSRandomization indicates whether to perform DTLS randomization.
	DoDTLSRandomization bool

	// TrafficShapingParameters indicates whether and how to perform data channel traffic shaping.
	TrafficShapingParameters *DataChannelTrafficShapingParameters

	// ReliableTransport indicates whether to configure the WebRTC data
	// channel to use reliable transport. Set ReliableTransport when proxying
	// a TCP stream, and unset it when proxying a UDP packets flow with its
	// own reliability later, such as QUIC.
	ReliableTransport bool
}

// newWebRTCConnWithOffer initiates a new WebRTC connection. An offer SDP is
// returned, to be sent to the peer. After the offer SDP is forwarded and an
// answer SDP received in response, call SetRemoteSDP with the answer SDP and
// then call AwaitInitialDataChannel to await the eventual WebRTC connection
// establishment.
func newWebRTCConnWithOffer(
	ctx context.Context,
	config *webRTCConfig,
	hasPersonalCompartmentIDs bool) (
	*webRTCConn, WebRTCSessionDescription, *webRTCSDPMetrics, error) {

	conn, SDP, metrics, err := newWebRTCConn(
		ctx, config, nil, hasPersonalCompartmentIDs)
	if err != nil {
		return nil, WebRTCSessionDescription{}, nil, errors.Trace(err)
	}
	return conn, *SDP, metrics, nil
}

// newWebRTCConnWithAnswer creates a new WebRTC connection initiated by a peer
// that provided an offer SDP. An answer SDP is returned to be sent to the
// peer. After the answer SDP is forwarded, call AwaitInitialDataChannel to
// await the eventual WebRTC connection establishment.
func newWebRTCConnWithAnswer(
	ctx context.Context,
	config *webRTCConfig,
	peerSDP WebRTCSessionDescription,
	hasPersonalCompartmentIDs bool) (
	*webRTCConn, WebRTCSessionDescription, *webRTCSDPMetrics, error) {

	conn, SDP, metrics, err := newWebRTCConn(
		ctx, config, &peerSDP, hasPersonalCompartmentIDs)
	if err != nil {
		return nil, WebRTCSessionDescription{}, nil, errors.Trace(err)
	}
	return conn, *SDP, metrics, nil
}

func newWebRTCConn(
	ctx context.Context,
	config *webRTCConfig,
	peerSDP *WebRTCSessionDescription,
	hasPersonalCompartmentIDs bool) (
	retconn *webRTCConn,
	retSDP *WebRTCSessionDescription,
	retMetrics *webRTCSDPMetrics,
	retErr error) {

	isOffer := peerSDP == nil

	udpConn, err := config.WebRTCDialCoordinator.UDPListen(ctx)
	if err != nil {
		return nil, nil, nil, errors.Trace(err)
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

	// UDPMux Limitations:
	//
	// For Psiphon, WebRTCDialCoordinator.UDPListen will call
	// https://pkg.go.dev/net#ListenUDP with an unspecified IP address, in
	// order to listen on all available interfaces, both IPv4 and IPv6.
	// However, using webrtc.NewICEUDPMux and a UDP conn with an unspecified
	// IP address results in this log warning: "UDPMuxDefault should not
	// listening on unspecified address, use NewMultiUDPMuxFromPort instead".
	//
	// With NewICEUDPMux and an unspecified IP address, pion currently
	// enumerates local, active interfaces and derives a list of listening
	// addresses, combining each interface's IP addresses with the assigned
	// port:
	// https://github.com/pion/ice/blob/8c5b0991ef3bb070e47afda96faf090e8bf94be6/net.go#L35.
	// While this works ok in many cases, this PR,
	// https://github.com/pion/ice/pull/475, indicates the nature of the
	// issue with UDPMuxDefault:
	//
	// > When we have multiple host candidates and been mux to a single port,
	// > if these candidates share a same conn (either tcp or udp), they
	// > might read other's [messages causing failure].
	//
	// This PR, https://github.com/pion/ice/pull/473, also describes the issue:
	//
	// > When using UDPMux and UniversalUDPMux, it is possible that a
	// > registerConnForAddress() could be called twice or more for the same
	// > remote candidate (endpoint) by different candidates. E.g., when
	// > different HOST candidates ping the same remote candidate, the
	// > udpMuxedConn gets stored once. The second candidate will never
	// > receive a response. This is also the case when a single socket is
	// > used for gathering SRFLX and HOST candidates.
	//
	// PR 475 introduced MultiUDPMuxDefault to address the issue. However, at
	// this time, https://github.com/pion/ice/releases/tag/v2.3.6, there's an
	// open bug with MultiUDPMuxDefault
	// https://github.com/pion/ice/issues/507: "Multi UDP Mux can't works
	// when remote also enables Multi UDP Mux". Running the test program
	// attached to the bug confirms that no data channel is established;
	// while switching the test code to use NewICEUDPMux results in a
	// successful data channel connection. Since we need to use a Mux API on
	// both clients and proxies, we can't yet use MultiUDPMux.
	//
	// We patch pion/webrtc to add the SetICEUDPMuxSrflx functionality from
	// the currently unmerged https://github.com/pion/webrtc/pull/2298.
	// Without SetICEUDPMuxSrflx, STUN operations don't use the mux.
	//
	// We patch pion/ice gatherCandidatesSrflxUDPMux vendor patch to include
	// only the correct network type (IPv4 or IPv6) address candidates.
	// Without this patch, we observed up to 2x duplicate/redundant STUN
	// candidates.
	//
	// TODO: implement and try using transport.Net UDP dial functions in place
	// of NewICEUDPMux and pre-dialed UDP conn; track all dialed UDP
	// connections to close on WebRTCConn.Close; this approach would require
	// an alternative approach to injecting port mapping candidates, which
	// currently depends on the mux UDP socket being available outside of pion.

	// Another limitation and issue with NewICEUDPMux is that its enumeration
	// of all local interfaces and IPs includes many IPv6 addresses for
	// certain interfaces. For example, on macOS,
	// https://apple.stackexchange.com/a/371661, there are "secured" IPv6
	// addresses and many "temporary" IPv6 addresses, with all but one
	// temporary address being "deprecated". Instead of a full enumeration,
	// we should select only the non-deprecated temporary IPv6 address --
	// both for performance (avoid excess STUN requests) and privacy.
	//
	// Go has a proposal to expose the necessary IPv6 address information:
	// https://github.com/golang/go/issues/42694. However, as of Android SDK
	// 30, Go's net.InterfaceAddrs doesn't work at all:
	// https://github.com/pion/transport/issues/228,
	// https://github.com/golang/go/issues/40569.
	//
	// Note that it's not currently possible to
	// webrtc.SettingEngine.SetIPFilter to limit IPv6 selection to a single
	// candidate; that IP filter is not passed through to localInterfaces in
	// the NewUDPMuxDefault case. And even if it were, there's no guarantee
	// that the the first IPv6 address passed to the filter would be the
	// non-deprecated temporary address.
	//
	// To workaround net.Interface issues, we use SettingEngine.SetNet to plug
	// in an alternative implementation of net.Interface which selects only
	// one IPv4 and one IPv6 active interface and IP address and uses the
	// anet package for Android. See pionNetwork for more details.

	deadline, _ := ctx.Deadline()
	TTL := time.Until(deadline)

	pionLoggerFactory := newPionLoggerFactory(
		config.Logger,
		config.EnableDebugLogging)

	pionNetwork := newPionNetwork(
		ctx, pionLoggerFactory.NewLogger("net"), config.WebRTCDialCoordinator)

	udpMux := webrtc.NewICEUniversalUDPMux(
		pionLoggerFactory.NewLogger("mux"), udpConn, TTL, pionNetwork)

	settingEngine := webrtc.SettingEngine{
		LoggerFactory: pionLoggerFactory,
	}
	settingEngine.SetNet(pionNetwork)
	settingEngine.DetachDataChannels()
	settingEngine.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)
	settingEngine.SetICEUDPMux(udpMux)
	settingEngine.SetICEUDPMuxSrflx(udpMux)

	// Set this behavior to look like common web browser WebRTC stacks.
	settingEngine.SetDTLSInsecureSkipHelloVerify(true)

	settingEngine.EnableSCTPZeroChecksum(true)

	// Timeout, retry, and delay adjustments
	//
	// - Add some jitter to timed operations to avoid a trivial pion timing
	//   fingerprint.
	//
	// - Reduce the wait time for STUN and peer reflexive candidates from the
	//   default 500ms and 1s.
	//
	// - Reduce keepalives from the default 2s to +/-15s and increase
	//   disconnect timeout from the default 5s to 3x15s.
	//
	// TODO:
	//
	// - Configuration via tactics.
	//
	// - While the RFC,
	//   https://datatracker.ietf.org/doc/html/rfc5245#section-10, calls for
	//   keep alives no less than 15s, implementations such as Chrome send
	//   keep alives much more frequently,
	//   https://issues.webrtc.org/issues/42221718.
	//
	// - Varying the period bewteen each keepalive, as is done with SSH via
	//   SSHKeepAlivePeriodMin/Max, requires changes to pion/dtls.
	//
	// - Some traffic-related timeouts are not yet exposed via settingEngine,
	//   including ice.defaultSTUNGatherTimeout, ice.maxBindingRequestTimeout.

	settingEngine.SetDTLSRetransmissionInterval(prng.JitterDuration(100*time.Millisecond, 0.1))
	settingEngine.SetHostAcceptanceMinWait(0)
	settingEngine.SetSrflxAcceptanceMinWait(prng.JitterDuration(100*time.Millisecond, 0.1))
	settingEngine.SetPrflxAcceptanceMinWait(prng.JitterDuration(200*time.Millisecond, 0.1))
	settingEngine.SetICETimeouts(45*time.Second, 0, prng.JitterDuration(15*time.Second, 0.2))
	settingEngine.SetICEMaxBindingRequests(10)

	// Initialize data channel obfuscation

	config.Logger.WithTraceFields(common.LogFields{
		"dtls_randomization":           config.DoDTLSRandomization,
		"data_channel_traffic_shaping": config.TrafficShapingParameters != nil,
	}).Info("webrtc_data_channel_obfuscation")

	// Facilitate DTLS Client/ServerHello randomization. The client decides
	// whether to do DTLS randomization and generates and the proxy receives
	// ClientRootObfuscationSecret, so the client can orchestrate replay on
	// both ends of the connection by reusing an obfuscation secret. Derive a
	// secret specific to DTLS. SetDTLSSeed will futher derive a secure PRNG
	// seed specific to either the client or proxy end of the connection
	// (so each peer's randomization will be distinct).
	//
	// To avoid forking many pion repos in order to pass the seed through to
	// the DTLS implementation, SetDTLSSeed attaches the seed to the DTLS
	// dial context.
	//
	// Either SetDTLSSeed or SetNoDTLSSeed should be set for each conn, as the
	// pion/dtl fork treats no-seed as an error, as a check against the
	// context value mechanism.

	var dtlsCtx context.Context
	if config.DoDTLSRandomization {

		dtlsObfuscationSecret, err := deriveObfuscationSecret(
			config.ClientRootObfuscationSecret, "in-proxy-DTLS-seed")
		if err != nil {
			return nil, nil, nil, errors.Trace(err)
		}

		baseSeed := prng.Seed(dtlsObfuscationSecret)

		dtlsCtx, err = inproxy_dtls.SetDTLSSeed(ctx, &baseSeed, isOffer)
		if err != nil {
			return nil, nil, nil, errors.Trace(err)
		}

	} else {

		dtlsCtx = inproxy_dtls.SetNoDTLSSeed(ctx)
	}
	settingEngine.SetDTLSConnectContextMaker(func() (context.Context, func()) {
		return context.WithCancel(dtlsCtx)
	})

	// Configure traffic shaping, which adds random padding and decoy messages
	// to data channel message flows.

	var trafficShapingPRNG *prng.PRNG
	trafficShapingBuffer := new(bytes.Buffer)
	paddedMessageCount := 0
	decoyMessageCount := 0

	if config.TrafficShapingParameters != nil {

		// TODO: also use pion/dtls.Config.PaddingLengthGenerator?

		trafficShapingContext := "in-proxy-data-channel-traffic-shaping-offer"
		if !isOffer {
			trafficShapingContext = "in-proxy-data-channel-traffic-shaping-answer"
		}

		trafficShapingObfuscationSecret, err := deriveObfuscationSecret(
			config.ClientRootObfuscationSecret, trafficShapingContext)
		if err != nil {
			return nil, nil, nil, errors.Trace(err)
		}

		seed := prng.Seed(trafficShapingObfuscationSecret)
		trafficShapingPRNG = prng.NewPRNGWithSeed(&seed)

		paddedMessageCount = trafficShapingPRNG.Range(
			config.TrafficShapingParameters.MinPaddedMessages,
			config.TrafficShapingParameters.MaxPaddedMessages)

		decoyMessageCount = trafficShapingPRNG.Range(
			config.TrafficShapingParameters.MinDecoyMessages,
			config.TrafficShapingParameters.MaxDecoyMessages)
	}

	// NAT traversal setup

	// When DisableInboundForMobileNetworks is set, skip both STUN and port
	// mapping for mobile networks. Most mobile networks use CGNAT and
	// neither STUN nor port mapping will be effective. It's faster to not
	// wait for something that ultimately won't work.

	disableInbound := config.WebRTCDialCoordinator.DisableInboundForMobileNetworks() &&
		config.WebRTCDialCoordinator.NetworkType() == NetworkTypeMobile

	// Try to establish a port mapping (UPnP-IGD, PCP, or NAT-PMP). The port
	// mapper will attempt to identify the local gateway and query various
	// port mapping protocols. portMapper.start launches this process and
	// does not block. Port mappings are not part of the WebRTC standard, or
	// supported by pion/webrtc. Instead, if a port mapping is established,
	// it's edited into the SDP as a new host-type ICE candidate.

	localPort := udpConn.LocalAddr().(*net.UDPAddr).Port
	portMapper := newPortMapper(config.Logger, localPort)

	doPortMapping := !disableInbound && !config.WebRTCDialCoordinator.DisablePortMapping()

	if doPortMapping {
		portMapper.start()
	}

	// Select a STUN server for ICE hole punching. The STUN server to be used
	// needs only support bind and not full RFC5780 NAT discovery.
	//
	// Each dial trys only one STUN server; in Psiphon tunnel establishment,
	// other, concurrent in-proxy dials may select alternative STUN servers
	// via WebRTCDialCoordinator. When the STUN server operation is successful,
	// WebRTCDialCoordinator will be signaled so that it may configure the STUN
	// server selection for replay.
	//
	// The STUN server will observe proxy IP addresses. Enumeration is
	// mitigated by using various public STUN servers, including Psiphon STUN
	// servers for proxies in non-censored regions. Proxies are also more
	// ephemeral than Psiphon servers.

	RFC5780 := false
	stunServerAddress := config.WebRTCDialCoordinator.STUNServerAddress(RFC5780)

	// Proceed even when stunServerAddress is "" and !DisableSTUN, as ICE may
	// find other host candidates.

	doSTUN := stunServerAddress != "" && !disableInbound && !config.WebRTCDialCoordinator.DisableSTUN()

	var ICEServers []webrtc.ICEServer

	if doSTUN {
		// stunServerAddress domain names are resolved with the Psiphon custom
		// resolver via pionNetwork.ResolveUDPAddr
		ICEServers = []webrtc.ICEServer{{URLs: []string{"stun:" + stunServerAddress}}}
	}

	conn := &webRTCConn{
		config: config,

		udpConn:                      udpConn,
		portMapper:                   portMapper,
		closedSignal:                 make(chan struct{}),
		dataChannelOpenedSignal:      make(chan struct{}),
		dataChannelWriteBufferSignal: make(chan struct{}, 1),

		// A data channel uses SCTP and is message oriented. The maximum
		// message size supported by pion/webrtc is 65536:
		// https://github.com/pion/webrtc/blob/dce970438344727af9c9965f88d958c55d32e64d/datachannel.go#L19.
		// This read buffer must be as large as the maximum message size or
		// else a read may fail with io.ErrShortBuffer.
		readBuffer: make([]byte, dataChannelMaxMessageSize),

		trafficShapingPRNG:   trafficShapingPRNG,
		trafficShapingBuffer: trafficShapingBuffer,
		paddedMessageCount:   paddedMessageCount,
		decoyMessageCount:    decoyMessageCount,
	}
	defer func() {
		if retErr != nil {
			// Cleanup on early return
			conn.Close()

			// Notify the WebRTCDialCoordinator that the operation failed so
			// that it can clear replay for that STUN server selection.
			//
			// Limitation: the error here may be due to failures unrelated to
			// the STUN server.

			if ctx.Err() == nil && doSTUN {
				config.WebRTCDialCoordinator.STUNServerAddressFailed(RFC5780, stunServerAddress)
			}
		}
	}()

	settingEngine.SetICEBindingRequestHandler(conn.onICEBindingRequest)

	// All settingEngine configuration must be done before calling NewAPI.
	webRTCAPI := webrtc.NewAPI(webrtc.WithSettingEngine(settingEngine))

	conn.peerConnection, err = webRTCAPI.NewPeerConnection(
		webrtc.Configuration{
			ICEServers: ICEServers,
		})
	if err != nil {
		return nil, nil, nil, errors.Trace(err)
	}

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

		// Generate a random length label, to vary the DATA_CHANNEL_OPEN
		// message length. The label is derived from and replayed via
		// ClientRootObfuscationSecret.
		labelObfuscationSecret, err := deriveObfuscationSecret(
			config.ClientRootObfuscationSecret, "in-proxy-data-channel-label")
		if err != nil {
			return nil, nil, nil, errors.Trace(err)
		}
		seed := prng.Seed(labelObfuscationSecret)
		labelPRNG := prng.NewPRNGWithSeed(&seed)
		dataChannelLabel := labelPRNG.HexString(
			labelPRNG.Range(1, dataChannelMaxLabelLength/2))

		dataChannel, err := conn.peerConnection.CreateDataChannel(
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

		SDP := peerSDP.SDP
		if hasPersonalCompartmentIDs {

			// In personal pairing mode, the peer SDP may include private IP
			// addresses. To avoid unnecessary network traffic, filter out
			// any peer private IP addresses for which there is no
			// corresponding local, active interface.

			errorOnNoCandidates := false
			allowPrivateIPAddressCandidates := true
			filterPrivateIPAddressCandidates := true
			adjustedSDP, _, err := filterSDPAddresses(
				[]byte(peerSDP.SDP),
				errorOnNoCandidates,
				nil,
				common.GeoIPData{},
				allowPrivateIPAddressCandidates,
				filterPrivateIPAddressCandidates)
			if err != nil {
				return nil, nil, nil, errors.Trace(err)
			}
			SDP = string(adjustedSDP)
		}

		pionSessionDescription := webrtc.SessionDescription{
			Type: webrtc.SDPType(peerSDP.Type),
			SDP:  SDP,
		}

		err = conn.peerConnection.SetRemoteDescription(pionSessionDescription)
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
		config.WebRTCDialCoordinator.SetPortMappingTypes(
			getRespondingPortMappingTypes(config.WebRTCDialCoordinator.NetworkID()))

	case <-ctx.Done():
		return nil, nil, nil, errors.Trace(ctx.Err())
	}

	// Release any port mapping resources when not using it.
	if portMapper != nil && portMappingExternalAddr == "" {
		portMapper.close()
		conn.portMapper = nil
	}

	config.Logger.WithTraceFields(common.LogFields{
		"ice_completed": iceCompleted,
		"port_mapping":  portMappingExternalAddr != "",
	}).Info("webrtc_candidates_gathered")

	// Get the offer or answer, now populated with any ICE candidates.

	localDescription := conn.peerConnection.LocalDescription()

	// Adjust the SDP, removing local network addresses and adding any
	// port mapping candidate. Clients (offer) are permitted to have
	// no ICE candidates but proxies (answer) must have at least one
	//candidate.
	errorOnNoCandidates := !isOffer

	adjustedSDP, metrics, err := prepareSDPAddresses(
		[]byte(localDescription.SDP),
		errorOnNoCandidates,
		portMappingExternalAddr,
		config.WebRTCDialCoordinator.DisableIPv6ICECandidates(),
		hasPersonalCompartmentIDs)
	if err != nil {
		return nil, nil, nil, errors.Trace(err)
	}

	// When STUN was attempted, ICE completed, and a STUN server-reflexive
	// candidate is present, notify the WebRTCDialCoordinator so that it can
	// set replay for that STUN server selection.

	if iceCompleted && doSTUN {
		hasServerReflexive := false
		for _, candidateType := range metrics.iceCandidateTypes {
			if candidateType == ICECandidateServerReflexive {
				hasServerReflexive = true
			}
		}
		if hasServerReflexive {
			config.WebRTCDialCoordinator.STUNServerAddressSucceeded(RFC5780, stunServerAddress)
		} else {
			config.WebRTCDialCoordinator.STUNServerAddressFailed(RFC5780, stunServerAddress)
		}
	}

	// The WebRTCConn is prepared, but the data channel is not yet connected.
	// On the offer end, the peer's following answer must be input to
	// SetRemoteSDP. And both ends must call AwaitInitialDataChannel to await
	// the data channel establishment.

	return conn,
		&WebRTCSessionDescription{
			Type: int(localDescription.Type),
			SDP:  string(adjustedSDP),
		},
		metrics,
		nil
}

func (conn *webRTCConn) setDataChannel(dataChannel *webrtc.DataChannel) {

	// Assumes the caller holds conn.mutex, or is newWebRTCConn, creating the
	// conn.

	conn.dataChannel = dataChannel
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
func (conn *webRTCConn) SetRemoteSDP(
	peerSDP WebRTCSessionDescription,
	hasPersonalCompartmentIDs bool) error {

	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	SDP := peerSDP.SDP
	if hasPersonalCompartmentIDs {

		// In personal pairing mode, the peer SDP may include private IP
		// addresses. To avoid unnecessary network traffic, filter out any
		// peer private IP addresses for which there is no corresponding
		// local, active interface.

		errorOnNoCandidates := false
		allowPrivateIPAddressCandidates := true
		filterPrivateIPAddressCandidates := true
		adjustedSDP, _, err := filterSDPAddresses(
			[]byte(peerSDP.SDP),
			errorOnNoCandidates,
			nil,
			common.GeoIPData{},
			allowPrivateIPAddressCandidates,
			filterPrivateIPAddressCandidates)
		if err != nil {
			return errors.Trace(err)
		}
		SDP = string(adjustedSDP)
	}

	pionSessionDescription := webrtc.SessionDescription{
		Type: webrtc.SDPType(peerSDP.Type),
		SDP:  SDP,
	}

	err := conn.peerConnection.SetRemoteDescription(pionSessionDescription)
	if err != nil {
		return errors.Trace(err)
	}
	return nil
}

// AwaitInitialDataChannel returns when the data channel is established, or
// when an error has occured.
func (conn *webRTCConn) AwaitInitialDataChannel(ctx context.Context) error {

	// Don't lock the mutex, or else necessary operations will deadlock.

	select {
	case <-conn.dataChannelOpenedSignal:

		// The data channel is connected.

		err := conn.recordSelectedICECandidateStats()
		if err != nil {
			conn.config.Logger.WithTraceFields(common.LogFields{
				"error": err.Error()}).Warning("recordCandidateStats failed")
			// Continue without log
		}

	case <-ctx.Done():
		return errors.Tracef("with ICE candidate pairs %s: %w",
			conn.getICECandidatePairsSummary(),
			ctx.Err())

	case <-conn.closedSignal:
		return errors.TraceNew("connection has closed")
	}

	return nil
}

func (conn *webRTCConn) getICECandidatePairsSummary() string {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	stateCounts := map[webrtc.StatsICECandidatePairState]int{}

	statsReport := conn.peerConnection.GetStats()
	for key, stats := range statsReport {

		// Uses the pion StatsReport key formats "candidate:<ID>"
		// and "candidate:<ID>-candidate:<ID>"

		key, found := strings.CutPrefix(key, "candidate:")
		if !found {
			continue
		}
		candidateIDs := strings.Split(key, "-candidate:")
		if len(candidateIDs) != 2 {
			continue
		}

		candidatePairStats, ok := stats.(webrtc.ICECandidatePairStats)
		if !ok {
			continue
		}

		stateCounts[candidatePairStats.State] += 1
	}

	if len(stateCounts) == 0 {
		return "(none)"
	}

	var strs []string
	for state, count := range stateCounts {
		strs = append(strs, fmt.Sprintf("%s(%d)", state, count))
	}
	return strings.Join(strs, ", ")
}

func (conn *webRTCConn) recordSelectedICECandidateStats() error {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	statsReport := conn.peerConnection.GetStats()
	foundNominatedPair := false
	for key, stats := range statsReport {

		// Uses the pion StatsReport key formats "candidate:<ID>"
		// and "candidate:<ID>-candidate:<ID>"

		key, found := strings.CutPrefix(key, "candidate:")
		if !found {
			continue
		}
		candidateIDs := strings.Split(key, "-candidate:")
		if len(candidateIDs) != 2 {
			continue
		}

		candidatePairStats, ok := stats.(webrtc.ICECandidatePairStats)
		if !ok ||
			candidatePairStats.State != webrtc.StatsICECandidatePairStateSucceeded ||
			!candidatePairStats.Nominated {
			continue
		}

		localKey := fmt.Sprintf("candidate:%s", candidateIDs[0])
		stats, ok := statsReport[localKey]
		if !ok {
			return errors.TraceNew("missing local ICECandidateStats")
		}
		localCandidateStats, ok := stats.(webrtc.ICECandidateStats)
		if !ok {
			return errors.TraceNew("unexpected local ICECandidateStats")
		}

		remoteKey := fmt.Sprintf("candidate:%s", candidateIDs[1])
		stats, ok = statsReport[remoteKey]
		if !ok {
			return errors.TraceNew("missing remote ICECandidateStats")
		}
		remoteCandidateStats, ok := stats.(webrtc.ICECandidateStats)
		if !ok {
			return errors.TraceNew("unexpected remote ICECandidateStats")
		}

		// Use the same ICE candidate type names as logged in broker logs.
		logCandidateType := func(
			iceCandidateType webrtc.ICECandidateType) string {
			logType := ICECandidateUnknown
			switch iceCandidateType {
			case webrtc.ICECandidateTypeHost:
				logType = ICECandidateHost
			case webrtc.ICECandidateTypeSrflx:
				logType = ICECandidateServerReflexive
			case webrtc.ICECandidateTypePrflx:
				logType = ICECandidatePeerReflexive
			}
			return logType.String()
		}

		conn.iceCandidatePairMetrics = common.LogFields{}

		// TODO: log which of local/remote candidate is initiator

		conn.iceCandidatePairMetrics["inproxy_webrtc_local_ice_candidate_type"] =
			logCandidateType(localCandidateStats.CandidateType)
		localIP := net.ParseIP(localCandidateStats.IP)
		isIPv6 := "0"
		if localIP != nil && localIP.To4() == nil {
			isIPv6 = "1"
		}
		isPrivate := "0"
		if localIP != nil && localIP.IsPrivate() {
			isPrivate = "1"
		}
		conn.iceCandidatePairMetrics["inproxy_webrtc_local_ice_candidate_is_IPv6"] =
			isIPv6
		conn.iceCandidatePairMetrics["inproxy_webrtc_local_ice_candidate_is_private_IP"] =
			isPrivate
		conn.iceCandidatePairMetrics["inproxy_webrtc_local_ice_candidate_port"] =
			localCandidateStats.Port

		conn.iceCandidatePairMetrics["inproxy_webrtc_remote_ice_candidate_type"] =
			logCandidateType(remoteCandidateStats.CandidateType)
		remoteIP := net.ParseIP(remoteCandidateStats.IP)
		isIPv6 = "0"
		if remoteIP != nil && remoteIP.To4() == nil {
			isIPv6 = "1"
		}
		isPrivate = "0"
		if remoteIP != nil && remoteIP.IsPrivate() {
			isPrivate = "1"
		}
		conn.iceCandidatePairMetrics["inproxy_webrtc_remote_ice_candidate_is_IPv6"] =
			isIPv6
		conn.iceCandidatePairMetrics["inproxy_webrtc_remote_ice_candidate_is_private_IP"] =
			isPrivate
		conn.iceCandidatePairMetrics["inproxy_webrtc_remote_ice_candidate_port"] =
			remoteCandidateStats.Port

		foundNominatedPair = true
		break
	}
	if !foundNominatedPair {
		return errors.TraceNew("missing nominated ICECandidateStatsPair")
	}

	return nil
}

func (conn *webRTCConn) Close() error {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	if conn.isClosed {
		return nil
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

	// Close the udpConn to interrupt any blocking DTLS handshake:
	// https://github.com/pion/webrtc/blob/c1467e4871c78ee3f463b50d858d13dc6f2874a4/dtlstransport.go#L334-L340
	//
	// Limitation: there is no guarantee that pion sends any closing packets
	// before the UDP socket is closed here.

	if conn.udpConn != nil {
		conn.udpConn.Close()
	}

	close(conn.closedSignal)

	conn.isClosed = true

	return nil
}

func (conn *webRTCConn) IsClosed() bool {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	return conn.isClosed
}

func (conn *webRTCConn) Read(p []byte) (int, error) {

	for {

		n, err := conn.readMessage(p)
		if err != nil || n > 0 {
			return n, err
		}

		// A decoy message was read; discard and read again.
	}
}

func (conn *webRTCConn) readMessage(p []byte) (int, error) {

	// Don't hold this lock, or else concurrent Writes will be blocked.
	conn.mutex.Lock()
	isClosed := conn.isClosed
	dataChannelConn := conn.dataChannelConn
	decoyDone := conn.decoyDone
	conn.mutex.Unlock()

	if isClosed {
		return 0, errors.TraceNew("closed")
	}

	if dataChannelConn == nil {
		return 0, errors.TraceNew("no data channel")
	}

	// The input read buffer, p, may not be the same length as the message
	// read from the data channel. Buffer the read message if another Read
	// call is necessary to consume it. As per https://pkg.go.dev/io#Reader,
	// dataChannelConn bytes read are processed even when
	// dataChannelConn.Read returns an error; the error value is stored and
	// returned with the Read call that consumes the end of the message buffer.

	conn.readMutex.Lock()
	defer conn.readMutex.Unlock()

	if conn.readOffset == conn.readLength {
		n, err := dataChannelConn.Read(conn.readBuffer)
		conn.readOffset = 0
		conn.readLength = n
		conn.readError = err

		// Skip over padding.

		if n > 0 && !conn.peerPaddingDone {

			paddingSize, n := binary.Varint(conn.readBuffer[0:conn.readLength])
			if (paddingSize == 0 && n <= 0) || paddingSize >= int64(conn.readLength) {
				return 0, errors.TraceNew("invalid padding")
			}

			if paddingSize < 0 {

				// When the padding header indicates a padding size of -1, the
				// peer is indicating that padding is done. Subsequent
				// messages will have no padding header or padding bytes.

				conn.peerPaddingDone = true
				conn.readOffset += n

			} else {

				conn.readOffset += n + int(paddingSize)

				atomic.AddInt32(&conn.paddedMessagesReceived, 1)
				if conn.readOffset == conn.readLength {
					atomic.AddInt32(&conn.decoyMessagesReceived, 1)
				}
			}
		}
	}

	n := copy(p, conn.readBuffer[conn.readOffset:conn.readLength])
	conn.readOffset += n

	var err error
	if conn.readOffset == conn.readLength {
		err = conn.readError
	}

	// When decoy messages are enabled, periodically response to an incoming
	// messages with an immediate outbound decoy message. This is similar to
	// the design here:
	// https://github.com/Psiphon-Labs/psiphon-tunnel-core/blob/c4f6a593a645db4479a7032a9e97d3c0b905cdfc/psiphon/common/quic/obfuscator.go#L361-L409
	//
	// writeMessage handles conn.decoyMessageCount, which is syncronized with
	// conn.WriteMutex, as well as other specific logic. Here we just signal
	// writeMessage based on the read event.
	//
	// When the data channel already has buffered writes in excess of a decoy
	// message size, the writeMessage skips the decoy message and returns
	// without blocking, so Read calls will not block.

	if !decoyDone {
		_, _ = conn.writeMessage(nil, true)
	}

	return n, errors.Trace(err)
}

func (conn *webRTCConn) Write(p []byte) (int, error) {
	return conn.writeMessage(p, false)
}

func (conn *webRTCConn) writeMessage(p []byte, decoy bool) (int, error) {

	if p != nil && decoy {
		return 0, errors.TraceNew("invalid write parameters")
	}

	// pion/sctp doesn't handle 0-byte writes correctly, so drop/skip at this level.
	//
	// Testing shows that the SCTP connection stalls after a 0-byte write. In
	// the pion/sctp implementation,
	// https://github.com/pion/sctp/blob/v1.8.8/stream.go#L254-L278 and
	// https://github.com/pion/sctp/blob/v1.8.8/stream.go#L280-L336, it
	// appears that a zero-byte write won't send an SCTP messages but does
	// increment a sequence number.

	if len(p) == 0 && !decoy {
		return 0, nil
	}

	// Don't hold this lock, or else concurrent Reads will be blocked.
	conn.mutex.Lock()
	isClosed := conn.isClosed
	bufferedAmount := conn.dataChannel.BufferedAmount()
	dataChannelConn := conn.dataChannelConn
	conn.mutex.Unlock()

	if isClosed {
		return 0, errors.TraceNew("closed")
	}

	if dataChannelConn == nil {
		return 0, errors.TraceNew("no data channel")
	}

	// Only proceed with a decoy message when no pending writes are buffered.
	//
	// This check is made before acquiring conn.writeMutex so that, in most
	// cases, writeMessage won't block Read calls when a concurrent Write is
	// holding conn.writeMutex and potentially blocking on flow control.
	// There's still a chance that this test passes, and a concurrent Write
	// arrives at the same time.

	if decoy && bufferedAmount > 0 {
		return 0, nil
	}

	conn.writeMutex.Lock()
	defer conn.writeMutex.Unlock()

	writeSize := len(p)

	// Determine padding size and padding header size.

	doPadding := false
	paddingSize := 0
	var paddingHeader [binary.MaxVarintLen32]byte
	paddingHeaderSize := 0

	if decoy {

		if conn.decoyMessageCount < 1 {
			return 0, nil
		}

		if !conn.trafficShapingPRNG.FlipWeightedCoin(
			conn.config.TrafficShapingParameters.DecoyMessageProbability) {
			return 0, nil
		}

		conn.decoyMessageCount -= 1

		decoySize := conn.trafficShapingPRNG.Range(
			conn.config.TrafficShapingParameters.MinDecoySize,
			conn.config.TrafficShapingParameters.MaxDecoySize)

		// When sending a decoy message, the entire message is padding.

		doPadding = true
		paddingSize = decoySize

		if conn.decoyMessageCount == 0 {

			// Set the shared flag that readMessage uses to stop invoking
			// writeMessage for decoy events.

			conn.mutex.Lock()
			conn.decoyDone = true
			conn.mutex.Unlock()
		}

	} else if conn.paddedMessageCount > 0 {

		// Add padding to a normal write.

		conn.paddedMessageCount -= 1

		doPadding = true
		paddingSize = prng.Range(
			conn.config.TrafficShapingParameters.MinPaddingSize,
			conn.config.TrafficShapingParameters.MaxPaddingSize)

	} else if conn.decoyMessageCount > 0 {

		// Padding normal messages is done, but there are still outstanding
		// decoy messages, so add a padding header indicating padding size 0
		// to this normal message.

		doPadding = true
		paddingSize = 0

	} else if !conn.trafficShapingDone {

		// Padding normal messages is done and all decoy messages are sent, so
		// send a special padding header with padding size -1, signaling the
		// peer that no additional padding will be performed and no
		// subsequent messages will contain a padding header.

		doPadding = true
		paddingSize = -1

	}

	if doPadding {

		if paddingSize > 0 {

			// Reduce, if necessary, to stay within the maximum data channel
			// message size. This is not expected to happen for the io.Copy use
			// case, with 32K message size, plus reasonable padding sizes.

			if writeSize+binary.MaxVarintLen32+paddingSize > dataChannelMaxMessageSize {
				paddingSize -= (writeSize + binary.MaxVarintLen32 + paddingSize) - dataChannelMaxMessageSize
				if paddingSize < 0 {
					paddingSize = 0
				}
			}

			// Add padding overhead to total writeSize before the flow control check.

			writeSize += paddingSize
		}

		paddingHeaderSize = binary.PutVarint(paddingHeader[:], int64(paddingSize))
		writeSize += paddingHeaderSize
	}

	if writeSize > dataChannelMaxMessageSize {
		return 0, errors.TraceNew("write too large")
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
	if !isClosed && bufferedAmount+uint64(writeSize) > dataChannelMaxBufferedAmount {
		select {
		case <-conn.dataChannelWriteBufferSignal:
		case <-conn.closedSignal:
			return 0, errors.TraceNew("connection has closed")
		}
	}

	if conn.trafficShapingDone {

		// When traffic shaping is done, p is written directly without the
		// additional trafficShapingBuffer copy.

		// Limitation: if len(p) > 65536, the dataChannelConn.Write will fail. In
		// practise, this is not expected to happen with typical use cases such
		// as io.Copy, which uses a 32K buffer.
		n, err := dataChannelConn.Write(p)

		return n, errors.Trace(err)
	}

	conn.trafficShapingBuffer.Reset()
	conn.trafficShapingBuffer.Write(paddingHeader[:paddingHeaderSize])
	if paddingSize > 0 {
		conn.trafficShapingBuffer.Write(prng.Bytes(paddingSize))
	}
	conn.trafficShapingBuffer.Write(p)

	// Limitation: see above; len(p) + padding must be <= 65536.
	_, err := dataChannelConn.Write(conn.trafficShapingBuffer.Bytes())

	if decoy {
		atomic.AddInt32(&conn.decoyMessagesSent, 1)
	} else if doPadding && paddingSize > 0 {
		atomic.AddInt32(&conn.paddedMessagesSent, 1)
	}

	if conn.paddedMessageCount == 0 && conn.decoyMessageCount == 0 && paddingSize == -1 {

		// Set flag indicating -1 padding size was sent and release traffic
		// shaping resources.

		conn.trafficShapingDone = true
		conn.trafficShapingPRNG = nil
		conn.trafficShapingBuffer = nil
	}

	return len(p), errors.Trace(err)
}

func (conn *webRTCConn) LocalAddr() net.Addr {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	// This is the local UDP socket address, not the external, public address.
	return conn.udpConn.LocalAddr()
}

func (conn *webRTCConn) RemoteAddr() net.Addr {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	// Not supported.
	return nil
}

func (conn *webRTCConn) SetDeadline(t time.Time) error {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	return errors.TraceNew("not supported")
}

func (conn *webRTCConn) SetReadDeadline(t time.Time) error {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	if conn.isClosed {
		return errors.TraceNew("closed")
	}

	readDeadliner, ok := conn.dataChannelConn.(datachannel.ReadDeadliner)
	if !ok {
		return errors.TraceNew("no data channel")
	}

	return readDeadliner.SetReadDeadline(t)
}

func (conn *webRTCConn) SetWriteDeadline(t time.Time) error {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	return errors.TraceNew("not supported")
}

// GetMetrics implements the common.MetricsSource interface and returns log
// fields detailing the WebRTC dial parameters.
func (conn *webRTCConn) GetMetrics() common.LogFields {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	logFields := make(common.LogFields)

	logFields.Add(conn.iceCandidatePairMetrics)

	randomizeDTLS := "0"
	if conn.config.DoDTLSRandomization {
		randomizeDTLS = "1"
	}
	logFields["inproxy_webrtc_randomize_dtls"] = randomizeDTLS

	logFields["inproxy_webrtc_padded_messages_sent"] = atomic.LoadInt32(&conn.paddedMessagesSent)
	logFields["inproxy_webrtc_padded_messages_received"] = atomic.LoadInt32(&conn.paddedMessagesReceived)
	logFields["inproxy_webrtc_decoy_messages_sent"] = atomic.LoadInt32(&conn.decoyMessagesSent)
	logFields["inproxy_webrtc_decoy_messages_received"] = atomic.LoadInt32(&conn.decoyMessagesReceived)

	return logFields
}

func (conn *webRTCConn) onConnectionStateChange(state webrtc.PeerConnectionState) {

	// Close the WebRTCConn when the connection is no longer connected. Close
	// will lock conn.mutex, so do lot aquire the lock here.
	//
	// Currently, ICE Restart is not used, and there is no transition from
	// Disconnected back to Connected.

	switch state {
	case webrtc.PeerConnectionStateDisconnected,
		webrtc.PeerConnectionStateFailed,
		webrtc.PeerConnectionStateClosed:
		conn.Close()
	}

	conn.config.Logger.WithTraceFields(common.LogFields{
		"state": state.String(),
	}).Info("peer connection state changed")
}

func (conn *webRTCConn) onICECandidate(candidate *webrtc.ICECandidate) {
	if candidate == nil {
		return
	}

	conn.config.Logger.WithTraceFields(common.LogFields{
		"candidate": candidate.String(),
	}).Info("new ICE candidate")
}

func (conn *webRTCConn) onICEBindingRequest(m *stun.Message, local, remote ice.Candidate, pair *ice.CandidatePair) bool {

	// SetICEBindingRequestHandler is used to hook onICEBindingRequest into
	// STUN bind events for logging. The return values is always false as
	// this callback makes no adjustments to ICE candidate selection. When
	// the data channel has already opened, skip logging events, as this
	// callback appears to be invoked for keepalive pings.

	if local == nil || remote == nil {
		return false
	}

	select {
	case <-conn.dataChannelOpenedSignal:
		return false
	default:
	}

	conn.config.Logger.WithTraceFields(common.LogFields{
		"local_candidate":  local.String(),
		"remote_candidate": remote.String(),
	}).Info("new ICE STUN binding request")

	return false
}

func (conn *webRTCConn) onICEConnectionStateChange(state webrtc.ICEConnectionState) {

	conn.config.Logger.WithTraceFields(common.LogFields{
		"state": state.String(),
	}).Info("ICE connection state changed")
}

func (conn *webRTCConn) onICEGatheringStateChange(state webrtc.ICEGathererState) {

	conn.config.Logger.WithTraceFields(common.LogFields{
		"state": state.String(),
	}).Info("ICE gathering state changed")
}

func (conn *webRTCConn) onNegotiationNeeded() {

	conn.config.Logger.WithTrace().Info("negotiation needed")
}

func (conn *webRTCConn) onSignalingStateChange(state webrtc.SignalingState) {

	conn.config.Logger.WithTraceFields(common.LogFields{
		"state": state.String(),
	}).Info("signaling state changed")
}

func (conn *webRTCConn) onDataChannel(dataChannel *webrtc.DataChannel) {

	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	conn.setDataChannel(dataChannel)

	conn.config.Logger.WithTraceFields(common.LogFields{
		"label": dataChannel.Label(),
		"ID":    dataChannel.ID(),
	}).Info("new data channel")
}

func (conn *webRTCConn) onDataChannelOpen() {

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

func (conn *webRTCConn) onDataChannelClose() {

	// Close the WebRTCConn when the data channel is closed. Close will lock
	// conn.mutex, so do lot aquire the lock here.
	conn.Close()

	conn.config.Logger.WithTrace().Info("data channel closed")
}

// prepareSDPAddresses adjusts the SDP, pruning local network addresses and
// adding any port mapping as a host candidate.
func prepareSDPAddresses(
	encodedSDP []byte,
	errorOnNoCandidates bool,
	portMappingExternalAddr string,
	disableIPv6Candidates bool,
	allowPrivateIPAddressCandidates bool) ([]byte, *webRTCSDPMetrics, error) {

	modifiedSDP, metrics, err := processSDPAddresses(
		encodedSDP,
		errorOnNoCandidates,
		portMappingExternalAddr,
		disableIPv6Candidates,
		allowPrivateIPAddressCandidates,
		false,
		nil,
		common.GeoIPData{})
	return modifiedSDP, metrics, errors.Trace(err)
}

// filterSDPAddresses checks that the SDP does not contain an empty list of
// candidates, bogon candidates, or candidates outside of the country and ASN
// for the specified expectedGeoIPData. Invalid candidates are stripped and a
// filtered SDP is returned.
func filterSDPAddresses(
	encodedSDP []byte,
	errorOnNoCandidates bool,
	lookupGeoIP LookupGeoIP,
	expectedGeoIPData common.GeoIPData,
	allowPrivateIPAddressCandidates bool,
	filterPrivateIPAddressCandidates bool) ([]byte, *webRTCSDPMetrics, error) {

	filteredSDP, metrics, err := processSDPAddresses(
		encodedSDP,
		errorOnNoCandidates,
		"",
		false,
		allowPrivateIPAddressCandidates,
		filterPrivateIPAddressCandidates,
		lookupGeoIP,
		expectedGeoIPData)
	return filteredSDP, metrics, errors.Trace(err)
}

// webRTCSDPMetrics are network capability metrics values for an SDP.
type webRTCSDPMetrics struct {
	iceCandidateTypes     []ICECandidateType
	hasIPv6               bool
	hasPrivateIP          bool
	filteredICECandidates []string
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
	errorOnNoCandidates bool,
	portMappingExternalAddr string,
	disableIPv6Candidates bool,
	allowPrivateIPAddressCandidates bool,
	filterPrivateIPAddressCandidates bool,
	lookupGeoIP LookupGeoIP,
	expectedGeoIPData common.GeoIPData) ([]byte, *webRTCSDPMetrics, error) {

	var sessionDescription sdp.SessionDescription
	err := sessionDescription.Unmarshal(encodedSDP)
	if err != nil {
		return nil, nil, errors.Trace(err)
	}

	candidateTypes := map[ICECandidateType]bool{}
	hasIPv6 := false
	hasPrivateIP := true
	filteredCandidateReasons := make(map[string]int)

	var portMappingICECandidates []sdp.Attribute
	if portMappingExternalAddr != "" {

		// Prepare ICE candidate attibute pair for the port mapping, modeled
		// after the definition of host candidates.

		host, portStr, err := net.SplitHostPort(portMappingExternalAddr)
		if err != nil {
			return nil, nil, errors.Trace(err)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, nil, errors.Trace(err)
		}

		// Only IPv4 port mapping addresses are supported due to the
		// NewCandidateHost limitation noted below. It is expected that port
		// mappings will be IPv4, as NAT and IPv6 is not a typical combination.

		hostIP := net.ParseIP(host)
		if hostIP != nil && hostIP.To4() != nil {

			for _, component := range []webrtc.ICEComponent{webrtc.ICEComponentRTP, webrtc.ICEComponentRTCP} {

				// The candidate ID is generated and the priority and foundation
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

				candidateIsIPv6 := false
				if candidateIP.To4() == nil {
					if disableIPv6Candidates {
						reason := fmt.Sprintf("disabled %s IPv6",
							candidate.Type().String())
						filteredCandidateReasons[reason] += 1
						continue
					}
					candidateIsIPv6 = true
				}

				// Strip non-routable bogons, including RFC 1918/4193 private
				// IP addresses. Same-LAN client/proxy hops are not expected
				// to be useful, and this also avoids unnecessary network traffic.
				//
				// Well-behaved clients and proxies should strip these values;
				// the broker enforces this with filtering.
				//
				// In personal pairing mode, private IP addresses are allowed,
				// as connection may be made between devices the same LAN and
				// not all routers support NAT hairpinning.

				candidateIsPrivateIP := candidateIP.IsPrivate()

				if !GetAllowBogonWebRTCConnections() &&
					!(candidateIsPrivateIP && allowPrivateIPAddressCandidates) &&
					common.IsBogon(candidateIP) {

					version := "IPv4"
					if candidateIsIPv6 {
						version = "IPv6"
					}
					reason := fmt.Sprintf("bogon %s %s",
						candidate.Type().String(), version)
					filteredCandidateReasons[reason] += 1
					continue
				}

				// In personal pairing mode, filter out any private IP
				// addresses for which there is no corresponding local,
				// active interface. This avoids unnecessary network traffic.
				// This filtering option is applied post-broker exchange,
				// with the SDP received, via the broker, from the peer.

				if candidateIsPrivateIP && filterPrivateIPAddressCandidates {
					if !hasInterfaceForPrivateIPAddress(candidateIP) {
						continue
					}
				}

				// The broker will check that clients and proxies specify only
				// candidates that map to the same GeoIP country and ASN as
				// the client/proxy connection to the broker. This limits
				// misuse of candidates to connect to other locations.
				// Legitimate candidates will not all have the exact same IP
				// address, as there could be a mix of IPv4 and IPv6, as well
				// as potentially different NAT paths.
				//
				// In some cases, legitimate clients and proxies may
				// unintentionally submit candidates with mismatching GeoIP.
				// This can occur, for example, when a STUN candidate is only
				// a partial hole punch through double NAT, and when internal
				// network addresses misuse non-private IP ranges (so are
				// technically not bogons). Instead of outright rejecting
				// SDPs containing unexpected GeoIP candidates, they are
				// instead stripped out and the resulting filtered SDP is
				// used.

				if lookupGeoIP != nil {
					candidateGeoIPData := lookupGeoIP(candidate.Address())

					if candidateGeoIPData.Country != expectedGeoIPData.Country ||
						candidateGeoIPData.ASN != expectedGeoIPData.ASN {

						version := "IPv4"
						if candidateIsIPv6 {
							version = "IPv6"
						}
						reason := fmt.Sprintf(
							"unexpected GeoIP %s %s: %s/%s",
							candidate.Type().String(),
							version,
							candidateGeoIPData.Country,
							candidateGeoIPData.ASN)
						filteredCandidateReasons[reason] += 1
						continue
					}
				}

				if candidateIsIPv6 {
					hasIPv6 = true
				}
				if candidateIsPrivateIP {
					hasPrivateIP = true
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

	if errorOnNoCandidates && candidateCount == 0 {
		return nil, nil, errors.TraceNew("no candidates")
	}

	encodedSDP, err = sessionDescription.Marshal()
	if err != nil {
		return nil, nil, errors.Trace(err)
	}

	metrics := &webRTCSDPMetrics{
		hasIPv6:      hasIPv6,
		hasPrivateIP: hasPrivateIP,
	}
	for candidateType := range candidateTypes {
		metrics.iceCandidateTypes = append(metrics.iceCandidateTypes, candidateType)
	}
	for reason, count := range filteredCandidateReasons {
		metrics.filteredICECandidates = append(metrics.filteredICECandidates,
			fmt.Sprintf("%s: %d", reason, count))
	}

	return encodedSDP, metrics, nil
}

type pionLoggerFactory struct {
	logger       common.Logger
	debugLogging bool
}

func newPionLoggerFactory(logger common.Logger, debugLogging bool) *pionLoggerFactory {
	return &pionLoggerFactory{
		logger:       logger,
		debugLogging: debugLogging,
	}
}

func (f *pionLoggerFactory) NewLogger(scope string) pion_logging.LeveledLogger {
	return newPionLogger(scope, f.logger, f.debugLogging)
}

// pionLogger wraps common.Logger and implements
// https://pkg.go.dev/github.com/pion/logging#LeveledLogger for passing into
// pion.
type pionLogger struct {
	scope        string
	logger       common.Logger
	debugLogging bool
	warnNoPairs  int32
}

func newPionLogger(scope string, logger common.Logger, debugLogging bool) *pionLogger {
	return &pionLogger{
		scope:        scope,
		logger:       logger,
		debugLogging: debugLogging,
	}
}

func (l *pionLogger) Trace(msg string) {
	if !l.debugLogging {
		return
	}
	l.logger.WithTrace().Debug(fmt.Sprintf("webRTC: %s: %s", l.scope, msg))
}

func (l *pionLogger) Tracef(format string, args ...interface{}) {
	if !l.debugLogging {
		return
	}
	l.logger.WithTrace().Debug(fmt.Sprintf("webRTC: %s: %s", l.scope, fmt.Sprintf(format, args...)))
}

func (l *pionLogger) Debug(msg string) {
	if !l.debugLogging {
		return
	}
	l.logger.WithTrace().Debug(fmt.Sprintf("[webRTC: %s: %s", l.scope, msg))
}

func (l *pionLogger) Debugf(format string, args ...interface{}) {
	if !l.debugLogging {
		return
	}
	l.logger.WithTrace().Debug(fmt.Sprintf("webRTC: %s: %s", l.scope, fmt.Sprintf(format, args...)))
}

func (l *pionLogger) Info(msg string) {
	l.logger.WithTrace().Info(fmt.Sprintf("webRTC: %s: %s", l.scope, msg))
}

func (l *pionLogger) Infof(format string, args ...interface{}) {
	l.logger.WithTrace().Info(fmt.Sprintf("webRTC: %s: %s", l.scope, fmt.Sprintf(format, args...)))
}

func (l *pionLogger) Warn(msg string) {

	// To reduce diagnostic log noise, only log this message once per dial attempt.
	if msg == "Failed to ping without candidate pairs. Connection is not possible yet." &&
		!atomic.CompareAndSwapInt32(&l.warnNoPairs, 0, 1) {
		return
	}

	l.logger.WithTrace().Warning(fmt.Sprintf("webRTC: %s: %s", l.scope, msg))
}

func (l *pionLogger) Warnf(format string, args ...interface{}) {
	l.logger.WithTrace().Warning(fmt.Sprintf("webRTC: %s: %s", l.scope, fmt.Sprintf(format, args...)))
}

func (l *pionLogger) Error(msg string) {
	l.logger.WithTrace().Error(fmt.Sprintf("webRTC: %s: %s", l.scope, msg))
}

func (l *pionLogger) Errorf(format string, args ...interface{}) {
	l.logger.WithTrace().Error(fmt.Sprintf("webRTC: %s: %s", l.scope, fmt.Sprintf(format, args...)))
}

func hasInterfaceForPrivateIPAddress(IP net.IP) bool {

	if !IP.IsPrivate() {
		return false
	}

	// The anet package is used to work around net.Interfaces not working on
	// Android at this time: https://github.com/golang/go/issues/40569.
	//
	// Any errors are silently dropped; the caller will proceed without using
	// the input private IP; and equivilent anet calls are made in
	// pionNetwork.Interfaces, with errors logged.

	netInterfaces, err := anet.Interfaces()
	if err != nil {
		return false
	}

	for _, netInterface := range netInterfaces {
		// Note: don't exclude interfaces with the net.FlagPointToPoint flag,
		// which is set for certain mobile networks
		if netInterface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := anet.InterfaceAddrsByInterface(&netInterface)
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			_, IPNet, err := net.ParseCIDR(addr.String())
			if err != nil {
				continue
			}
			if IPNet.Contains(IP) {
				return true
			}
		}
	}

	return false
}

// pionNetwork implements pion/transport.Net.
//
// Via the SettingsEngine, pion is configured to use a pionNetwork instance,
// which providing alternative implementations for various network functions.
// The Interfaces implementation provides a workaround for Android
// net.Interfaces issues and reduces the number of IPv6 candidates to avoid
// excess STUN requests; and the ResolveUDPAddr implementation hooks into the
// Psiphon custom resolver.
type pionNetwork struct {
	dialCtx               context.Context
	logger                pion_logging.LeveledLogger
	webRTCDialCoordinator WebRTCDialCoordinator
}

func newPionNetwork(
	dialCtx context.Context,
	logger pion_logging.LeveledLogger,
	webRTCDialCoordinator WebRTCDialCoordinator) *pionNetwork {

	return &pionNetwork{
		dialCtx:               dialCtx,
		logger:                logger,
		webRTCDialCoordinator: webRTCDialCoordinator,
	}
}

func (p *pionNetwork) Interfaces() ([]*transport.Interface, error) {

	// To determine the active IPv4 and IPv6 interfaces, let the OS bind IPv4
	// and IPv6 UDP sockets with a specified external destination address.
	// Then iterate over all interfaces, but return interface info for only
	// the interfaces those sockets were bound to.
	//
	// The destination IPs are the IPs that currently resolve for example.com.
	// No actual traffic to these IPs or example.com is sent, as the UDP
	// sockets are not used to send any packets.
	//
	// This scheme should select just one IPv4 and one IPv6 address, which
	// should be the active, externally routable addresses, and the IPv6
	// address should be the preferred, non-deprecated temporary IPv6 address.
	//
	// In post-ICE gathering processing, processSDPAddresses will also strip
	// all bogon addresses, so there is no explicit bogon check here.
	//
	// Limitations:
	//
	// - The active interface could change between the socket operation and
	//   iterating over all interfaces. Higher-level code is expected to
	//   react to active network changes.
	//
	// - The public IPs for example.com may not be robust in all routing
	//   situations. Alternatively, we could use the configured STUN server
	//   as the test destination, but the STUN server domain is not resolved
	//   at this point and STUN is not always configured and used.
	//
	// - The results could be cached and reused.

	var defaultIPv4, defaultIPv6 net.IP

	udpConnIPv4, err := p.webRTCDialCoordinator.UDPConn(
		context.Background(), "udp4", "93.184.216.34:3478")
	if err == nil {
		defaultIPv4 = udpConnIPv4.LocalAddr().(*net.UDPAddr).IP
		udpConnIPv4.Close()
	}

	udpConnIPv6, err := p.webRTCDialCoordinator.UDPConn(
		context.Background(), "udp6", "[2606:2800:220:1:248:1893:25c8:1946]:3478")
	if err == nil {
		defaultIPv6 = udpConnIPv6.LocalAddr().(*net.UDPAddr).IP
		udpConnIPv6.Close()
	}

	// The anet package is used to work around net.Interfaces not working on
	// Android at this time: https://github.com/golang/go/issues/40569.

	transportInterfaces := []*transport.Interface{}

	netInterfaces, err := anet.Interfaces()
	if err != nil {
		return nil, errors.Trace(err)
	}

	for _, netInterface := range netInterfaces {
		// Note: don't exclude interfaces with the net.FlagPointToPoint flag,
		// which is set for certain mobile networks
		if (netInterface.Flags&net.FlagUp == 0) ||
			(!GetAllowBogonWebRTCConnections() && (netInterface.Flags&net.FlagLoopback != 0)) {
			continue
		}
		addrs, err := anet.InterfaceAddrsByInterface(&netInterface)
		if err != nil {
			return nil, errors.Trace(err)
		}
		var transportInterface *transport.Interface
		for _, addr := range addrs {
			IP, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				return nil, errors.Trace(err)
			}
			if IP.Equal(defaultIPv4) || IP.Equal(defaultIPv6) ||
				(GetAllowBogonWebRTCConnections() && (netInterface.Flags&net.FlagLoopback != 0)) {
				if transportInterface == nil {
					transportInterface = transport.NewInterface(netInterface)
				}
				transportInterface.AddAddress(addr)
			}
		}
		if transportInterface != nil {
			transportInterfaces = append(transportInterfaces, transportInterface)
		}
	}

	return transportInterfaces, nil
}

func (p *pionNetwork) ResolveUDPAddr(network, address string) (retAddr *net.UDPAddr, retErr error) {

	defer func() {
		if retErr != nil {
			// Explicitly log an error since certain pion operations -- e.g.,
			// ICE gathering -- don't propagate all pion/transport.Net errors.
			p.logger.Errorf("pionNetwork.ResolveUDPAddr failed: %v", retErr)
		}
	}()

	// Currently, pion appears to call ResolveUDPAddr with "udp4"/udp6"
	// instead of "ip4"/"ip6", as expected by, e.g., net.Resolver.LookupIP.
	// Convert to "ip4"/"ip6".

	// Specifying v4/v6 ensures that the resolved IP address is the correct
	// type. In the case of STUN servers, the correct type is required in
	// order to create the correct IPv4 or IPv6 whole punch address.

	switch network {
	case "udp4", "tcp4":
		network = "ip4"
	case "udp6", "tcp6":
		network = "ip6"
	default:
		network = "ip"
	}

	// Currently, pion appears to call ResolveUDPAddr with an improperly
	// formatted address, <IPv6>:443 not [<IPv6>]:443; handle this case.
	index := strings.LastIndex(address, ":")
	if index != -1 {
		address = net.JoinHostPort(address[:index], address[index+1:])
	}

	// Use the Psiphon custom resolver to resolve any STUN server domains.
	resolvedAddress, err := p.webRTCDialCoordinator.ResolveAddress(
		p.dialCtx, network, address)
	if err != nil {
		return nil, errors.Trace(err)
	}

	IPStr, portStr, err := net.SplitHostPort(resolvedAddress)
	if err != nil {
		return nil, errors.Trace(err)
	}
	IP := net.ParseIP(IPStr)
	if IP == nil {
		return nil, errors.TraceNew("invalid IP address")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, errors.Trace(err)
	}
	return &net.UDPAddr{IP: IP, Port: port}, nil
}

var errNotSupported = std_errors.New("not supported")

func (p *pionNetwork) ListenPacket(network string, address string) (net.PacketConn, error) {
	// Explicitly log an error since certain pion operations -- e.g., ICE
	// gathering -- don't propagate all pion/transport.Net errors.
	p.logger.Errorf("unexpected pionNetwork.ListenPacket call from %s", stacktrace.GetParentFunctionName())
	return nil, errors.Trace(errNotSupported)
}

func (p *pionNetwork) ListenUDP(network string, locAddr *net.UDPAddr) (transport.UDPConn, error) {
	p.logger.Errorf("unexpected pionNetwork.ListenUDP call from %s", stacktrace.GetParentFunctionName())
	return nil, errors.Trace(errNotSupported)
}

func (p *pionNetwork) ListenTCP(network string, laddr *net.TCPAddr) (transport.TCPListener, error) {
	p.logger.Errorf("unexpected pionNetwork.ListenTCP call from %s", stacktrace.GetParentFunctionName())
	return nil, errors.Trace(errNotSupported)
}

func (p *pionNetwork) Dial(network, address string) (net.Conn, error) {
	p.logger.Errorf("unexpected pionNetwork.Dial call from %s", stacktrace.GetParentFunctionName())
	return nil, errors.Trace(errNotSupported)
}

func (p *pionNetwork) DialUDP(network string, laddr, raddr *net.UDPAddr) (transport.UDPConn, error) {
	p.logger.Errorf("unexpected pionNetwork.DialUDP call from %s", stacktrace.GetParentFunctionName())
	return nil, errors.Trace(errNotSupported)
}

func (p *pionNetwork) DialTCP(network string, laddr, raddr *net.TCPAddr) (transport.TCPConn, error) {
	p.logger.Errorf("unexpected pionNetwork.DialTCP call from %s", stacktrace.GetParentFunctionName())
	return nil, errors.Trace(errNotSupported)
}

func (p *pionNetwork) ResolveIPAddr(network, address string) (*net.IPAddr, error) {
	p.logger.Errorf("unexpected pionNetwork.ResolveIPAddr call from %s", stacktrace.GetParentFunctionName())
	return nil, errors.Trace(errNotSupported)
}

func (p *pionNetwork) ResolveTCPAddr(network, address string) (*net.TCPAddr, error) {
	p.logger.Errorf("unexpected pionNetwork.ResolveTCPAddr call from %s", stacktrace.GetParentFunctionName())
	return nil, errors.Trace(errNotSupported)
}

func (p *pionNetwork) InterfaceByIndex(index int) (*transport.Interface, error) {
	p.logger.Errorf("unexpected pionNetwork.InterfaceByIndex call from %s", stacktrace.GetParentFunctionName())
	return nil, errors.Trace(errNotSupported)
}

func (p *pionNetwork) InterfaceByName(name string) (*transport.Interface, error) {
	p.logger.Errorf("unexpected pionNetwork.InterfaceByName call from %s", stacktrace.GetParentFunctionName())
	return nil, errors.Trace(errNotSupported)
}

func (p *pionNetwork) CreateDialer(dialer *net.Dialer) transport.Dialer {
	return &pionNetworkDialer{pionNetwork: p}
}

type pionNetworkDialer struct {
	pionNetwork *pionNetwork
}

func (d pionNetworkDialer) Dial(network, address string) (net.Conn, error) {
	d.pionNetwork.logger.Errorf("unexpected pionNetworkDialer.Dial call from %s", stacktrace.GetParentFunctionName())
	return nil, errors.Trace(errNotSupported)
}
