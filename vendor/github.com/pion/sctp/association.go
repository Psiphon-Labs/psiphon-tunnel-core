// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/logging"
	"github.com/pion/randutil"
	"github.com/pion/transport/v4/deadline"
)

// Port 5000 shows up in examples for SDPs used by WebRTC. Since this implementation
// assumes it will be used by DTLS over UDP, the port is only meaningful for de-multiplexing
// but more-so verification.
// Example usage: https://www.rfc-editor.org/rfc/rfc8841.html#section-13.1-2
const defaultSCTPSrcDstPort = 5000

// Use global random generator to properly seed by crypto grade random.
var globalMathRandomGenerator = randutil.NewMathRandomGenerator() // nolint:gochecknoglobals

// Association errors.
var (
	ErrChunk                         = errors.New("abort chunk, with following errors")
	ErrShutdownNonEstablished        = errors.New("shutdown called in non-established state")
	ErrAssociationClosedBeforeConn   = errors.New("association closed before connecting")
	ErrAssociationClosed             = errors.New("association closed")
	ErrSilentlyDiscard               = errors.New("silently discard")
	ErrInitNotStoredToSend           = errors.New("the init not stored to send")
	ErrCookieEchoNotStoredToSend     = errors.New("cookieEcho not stored to send")
	ErrSCTPPacketSourcePortZero      = errors.New("sctp packet must not have a source port of 0")
	ErrSCTPPacketDestinationPortZero = errors.New("sctp packet must not have a destination port of 0")
	ErrInitChunkBundled              = errors.New("init chunk must not be bundled with any other chunk")
	ErrInitChunkVerifyTagNotZero     = errors.New(
		"init chunk expects a verification tag of 0 on the packet when out-of-the-blue",
	)
	ErrHandleInitState            = errors.New("todo: handle Init when in state")
	ErrInitAckNoCookie            = errors.New("no cookie in InitAck")
	ErrInflightQueueTSNPop        = errors.New("unable to be popped from inflight queue TSN")
	ErrTSNRequestNotExist         = errors.New("requested non-existent TSN")
	ErrResetPacketInStateNotExist = errors.New("sending reset packet in non-established state")
	ErrParamterType               = errors.New("unexpected parameter type")
	ErrPayloadDataStateNotExist   = errors.New("sending payload data in non-established state")
	ErrChunkTypeUnhandled         = errors.New("unhandled chunk type")
	ErrHandshakeInitAck           = errors.New("handshake failed (INIT ACK)")
	ErrHandshakeCookieEcho        = errors.New("handshake failed (COOKIE ECHO)")
	ErrTooManyReconfigRequests    = errors.New("too many outstanding reconfig requests")
)

const (
	receiveMTU            uint32 = 8192 // MTU for inbound packet (from DTLS)
	initialMTU            uint32 = 1228 // initial MTU for outgoing packets (to DTLS)
	initialRecvBufSize    uint32 = 1024 * 1024
	commonHeaderSize      uint32 = 12
	dataChunkHeaderSize   uint32 = 16
	defaultMaxMessageSize uint32 = 65536
)

// association state enums.
const (
	closed uint32 = iota
	cookieWait
	cookieEchoed
	established
	shutdownAckSent
	shutdownPending
	shutdownReceived
	shutdownSent
)

// retransmission timer IDs.
const (
	timerT1Init int = iota
	timerT1Cookie
	timerT2Shutdown
	timerT3RTX
	timerReconfig
)

// ack mode (for testing).
const (
	ackModeNormal int = iota
	ackModeNoDelay
	ackModeAlwaysDelay
)

// ack transmission state.
const (
	ackStateIdle      int = iota // ack timer is off
	ackStateImmediate            // will send ack immediately
	ackStateDelay                // ack timer is on (ack is being delayed)
)

// other constants.
const (
	acceptChSize = 16
	// avgChunkSize is an estimate of the average chunk size. There is no theory behind
	// this estimate.
	avgChunkSize = 500
	// minTSNOffset is the minimum offset over the cummulative TSN that we will enqueue
	// irrespective of the receive buffer size
	// see getMaxTSNOffset.
	minTSNOffset = 2000
	// maxTSNOffset is the maximum offset over the cummulative TSN that we will enqueue
	// irrespective of the receive buffer size
	// see getMaxTSNOffset.
	maxTSNOffset = 40000
	// maxReconfigRequests is the maximum number of reconfig requests we will keep outstanding.
	maxReconfigRequests = 1000

	// TLR Adaptive burst mitigation uses quarter-MTU units.
	// 1 MTU == 4 units, 0.25 MTU == 1 unit.
	tlrUnitsPerMTU = 4

	// Default burst limits.
	tlrBurstDefaultFirstRTT = 16 // 4.0 MTU
	tlrBurstDefaultLaterRTT = 8  // 2.0 MTU

	// Minimum burst limits.
	tlrBurstMinFirstRTT = 8 // 2.0 MTU
	tlrBurstMinLaterRTT = 5 // 1.25 MTU

	// Adaptation steps.
	tlrBurstStepDownFirstRTT = 4 // reduce by 1.0 MTU
	tlrBurstStepDownLaterRTT = 1 // reduce by 0.25 MTU

	tlrGoodOpsResetThreshold = 16
)

func getAssociationStateString(assoc uint32) string {
	switch assoc {
	case closed:
		return "Closed"
	case cookieWait:
		return "CookieWait"
	case cookieEchoed:
		return "CookieEchoed"
	case established:
		return "Established"
	case shutdownPending:
		return "ShutdownPending"
	case shutdownSent:
		return "ShutdownSent"
	case shutdownReceived:
		return "ShutdownReceived"
	case shutdownAckSent:
		return "ShutdownAckSent"
	default:
		return fmt.Sprintf("Invalid association state %d", assoc)
	}
}

// Association represents an SCTP association
// 13.2.  Parameters Necessary per Association (i.e., the TCB)
//
//	Peer        : Tag value to be sent in every packet and is received
//	Verification: in the INIT or INIT ACK chunk.
//	Tag         :
//	State       : A state variable indicating what state the association
//	            : is in, i.e., COOKIE-WAIT, COOKIE-ECHOED, ESTABLISHED,
//	            : SHUTDOWN-PENDING, SHUTDOWN-SENT, SHUTDOWN-RECEIVED,
//	            : SHUTDOWN-ACK-SENT.
//
// Note: No "CLOSED" state is illustrated since if a
// association is "CLOSED" its TCB SHOULD be removed.
// Note: By nature of an Association being constructed with one net.Conn,
// it is not a multi-home supporting implementation of SCTP.
type Association struct {
	bytesReceived uint64
	bytesSent     uint64

	lock sync.RWMutex

	netConn net.Conn

	peerVerificationTag    uint32
	myVerificationTag      uint32
	state                  uint32
	initialTSN             uint32
	myNextTSN              uint32 // nextTSN
	minTSN2MeasureRTT      uint32 // for RTT measurement
	willSendForwardTSN     bool
	willRetransmitFast     bool
	willRetransmitReconfig bool

	willSendShutdown         bool
	willSendShutdownAck      bool
	willSendShutdownComplete bool

	willSendAbort      bool
	willSendAbortCause errorCause

	// Reconfig
	myNextRSN        uint32
	reconfigs        map[uint32]*chunkReconfig
	reconfigRequests map[uint32]*paramOutgoingResetRequest

	// Non-RFC internal data
	sourcePort              uint16
	destinationPort         uint16
	myMaxNumInboundStreams  uint16
	myMaxNumOutboundStreams uint16
	myCookie                *paramStateCookie
	payloadQueue            *receivePayloadQueue
	inflightQueue           *payloadQueue
	pendingQueue            *pendingQueue
	controlQueue            *controlQueue
	mtu                     uint32
	maxPayloadSize          uint32       // max DATA chunk payload size
	srtt                    atomic.Value // type float64
	cumulativeTSNAckPoint   uint32
	advancedPeerTSNAckPoint uint32
	useForwardTSN           bool
	sendZeroChecksum        bool
	recvZeroChecksum        bool

	// Congestion control parameters
	maxReceiveBufferSize uint32
	maxMessageSize       uint32
	cwnd                 uint32 // my congestion window size
	rwnd                 uint32 // calculated peer's receiver windows size
	ssthresh             uint32 // slow start threshold
	partialBytesAcked    uint32
	inFastRecovery       bool
	fastRecoverExitPoint uint32
	minCwnd              uint32 // Minimum congestion window
	fastRtxWnd           uint32 // Send window for fast retransmit
	cwndCAStep           uint32 // Step of congestion window increase at Congestion Avoidance

	// RTX & Ack timer
	rtoMgr     *rtoManager
	t1Init     *rtxTimer
	t1Cookie   *rtxTimer
	t2Shutdown *rtxTimer
	t3RTX      *rtxTimer
	tReconfig  *rtxTimer
	ackTimer   *ackTimer

	// RACK / TLP state
	rackReoWnd                  time.Duration // dynamic reordering window
	rackMinRTT                  time.Duration // min observed RTT
	rackMinRTTWnd               *windowedMin  // the window used to determine minRTT, defaults to 30s
	rackDeliveredTime           time.Time     // send time of most recently delivered original chunk
	rackHighestDeliveredOrigTSN uint32
	rackReorderingSeen          bool // ever observed reordering for this association
	rackKeepInflatedRecoveries  int  // keep inflated reoWnd for 16 loss recoveries
	// RACK xmit-time ordered list
	rackHead *chunkPayloadData
	rackTail *chunkPayloadData

	// Unified timer for RACK and PTO driven by a single goroutine.
	// Deadlines are protected with timerMu.
	timerMu       sync.Mutex
	timerUpdateCh chan struct{}
	rackDeadline  time.Time
	ptoDeadline   time.Time

	rackWCDelAck    time.Duration // 200ms default
	rackReoWndFloor time.Duration

	// Chunks stored for retransmission
	storedInit       *chunkInit
	storedCookieEcho *chunkCookieEcho

	streams              map[uint16]*Stream
	acceptCh             chan *Stream
	readLoopCloseCh      chan struct{}
	awakeWriteLoopCh     chan struct{}
	closeWriteLoopCh     chan struct{}
	handshakeCompletedCh chan error

	closeWriteLoopOnce sync.Once

	// local error
	silentError error

	ackState int
	ackMode  int // for testing

	// stats
	stats *associationStats

	// per inbound packet context
	delayedAckTriggered   bool
	immediateAckTriggered bool

	blockWrite   bool
	writePending bool
	writeNotify  chan struct{}

	name string
	log  logging.LeveledLogger

	// Adaptive burst mitigation variables
	tlrActive            bool
	tlrFirstRTT          bool // first RTT of this TLR operation
	tlrHadAdditionalLoss bool
	tlrEndTSN            uint32 // recovery is done when cumAck >= tlrEndTSN

	tlrBurstFirstRTTUnits int64 // quarter-MTU units
	tlrBurstLaterRTTUnits int64 // quarter-MTU units

	tlrGoodOps   uint32    // count of TLR ops completed w/o additional loss
	tlrStartTime time.Time // time of first recovery RTT
}

// Config collects the arguments to createAssociation construction into
// a single structure.
type Config struct {
	Name                 string
	NetConn              net.Conn
	MaxReceiveBufferSize uint32
	MaxMessageSize       uint32
	EnableZeroChecksum   bool
	LoggerFactory        logging.LoggerFactory
	BlockWrite           bool
	MTU                  uint32

	// congestion control configuration
	// RTOMax is the maximum retransmission timeout in milliseconds
	RTOMax float64
	// Minimum congestion window
	MinCwnd uint32
	// Send window for fast retransmit
	FastRtxWnd uint32
	// Step of congestion window increase at Congestion Avoidance
	CwndCAStep uint32

	// The RACK configs are currently private as SCTP will be reworked to use the
	// modern options pattern in a future release.
	// Optional: size of window used to determine minimum RTT for RACK (defaults to 30s)
	rackMinRTTWnd time.Duration
	// Optional: cap the minimum reordering window: 0 = use quarter-RTT
	rackReoWndFloor time.Duration
	// Optional: receiver worst-case delayed-ACK for PTO when only one packet is in flight
	rackWCDelAck time.Duration
}

// Server accepts a SCTP stream over a conn.
func Server(config Config) (*Association, error) {
	a := createAssociation(config)
	a.init(false)

	select {
	case err := <-a.handshakeCompletedCh:
		if err != nil {
			return nil, err
		}

		return a, nil
	case <-a.readLoopCloseCh:
		return nil, ErrAssociationClosedBeforeConn
	}
}

// Client opens a SCTP stream over a conn.
func Client(config Config) (*Association, error) {
	return createClientWithContext(context.Background(), config)
}

func createClientWithContext(ctx context.Context, config Config) (*Association, error) {
	assoc := createAssociation(config)
	assoc.init(true)

	select {
	case <-ctx.Done():
		assoc.log.Errorf("[%s] client handshake canceled: state=%s", assoc.name, getAssociationStateString(assoc.getState()))
		assoc.Close() // nolint:errcheck,gosec

		return nil, ctx.Err()
	case err := <-assoc.handshakeCompletedCh:
		if err != nil {
			return nil, err
		}

		return assoc, nil
	case <-assoc.readLoopCloseCh:
		return nil, ErrAssociationClosedBeforeConn
	}
}

func createAssociation(config Config) *Association {
	maxReceiveBufferSize := config.MaxReceiveBufferSize
	if maxReceiveBufferSize == 0 {
		maxReceiveBufferSize = initialRecvBufSize
	}

	maxMessageSize := config.MaxMessageSize
	if maxMessageSize == 0 {
		maxMessageSize = defaultMaxMessageSize
	}

	mtu := config.MTU
	if mtu == 0 {
		mtu = initialMTU
	}

	tsn := globalMathRandomGenerator.Uint32()
	assoc := &Association{
		netConn:              config.NetConn,
		maxReceiveBufferSize: maxReceiveBufferSize,
		maxMessageSize:       maxMessageSize,
		minCwnd:              config.MinCwnd,
		fastRtxWnd:           config.FastRtxWnd,
		cwndCAStep:           config.CwndCAStep,

		// These two max values have us not need to follow
		// 5.1.1 where this peer may be incapable of supporting
		// the requested amount of outbound streams from the other
		// peer.
		myMaxNumOutboundStreams: math.MaxUint16,
		myMaxNumInboundStreams:  math.MaxUint16,

		payloadQueue:            newReceivePayloadQueue(getMaxTSNOffset(maxReceiveBufferSize)),
		inflightQueue:           newPayloadQueue(),
		pendingQueue:            newPendingQueue(),
		controlQueue:            newControlQueue(),
		mtu:                     mtu,
		maxPayloadSize:          mtu - (commonHeaderSize + dataChunkHeaderSize),
		myVerificationTag:       globalMathRandomGenerator.Uint32(),
		initialTSN:              tsn,
		myNextTSN:               tsn,
		myNextRSN:               tsn,
		minTSN2MeasureRTT:       tsn,
		state:                   closed,
		rtoMgr:                  newRTOManager(config.RTOMax),
		streams:                 map[uint16]*Stream{},
		reconfigs:               map[uint32]*chunkReconfig{},
		reconfigRequests:        map[uint32]*paramOutgoingResetRequest{},
		acceptCh:                make(chan *Stream, acceptChSize),
		readLoopCloseCh:         make(chan struct{}),
		awakeWriteLoopCh:        make(chan struct{}, 1),
		closeWriteLoopCh:        make(chan struct{}),
		handshakeCompletedCh:    make(chan error),
		cumulativeTSNAckPoint:   tsn - 1,
		advancedPeerTSNAckPoint: tsn - 1,
		recvZeroChecksum:        config.EnableZeroChecksum,
		silentError:             ErrSilentlyDiscard,
		stats:                   &associationStats{},
		log:                     config.LoggerFactory.NewLogger("sctp"),
		name:                    config.Name,
		blockWrite:              config.BlockWrite,
		writeNotify:             make(chan struct{}, 1),
	}

	// adaptive burst mitigation defaults
	assoc.tlrBurstFirstRTTUnits = tlrBurstDefaultFirstRTT
	assoc.tlrBurstLaterRTTUnits = tlrBurstDefaultLaterRTT

	// RACK defaults
	assoc.rackWCDelAck = config.rackWCDelAck
	if assoc.rackWCDelAck == 0 {
		assoc.rackWCDelAck = 200 * time.Millisecond // WCDelAckT, RACK for SCTP section 2C
	}

	// defaults to 30s window to determine minRTT
	assoc.rackMinRTTWnd = newWindowedMin(config.rackMinRTTWnd)

	assoc.timerUpdateCh = make(chan struct{}, 1)
	go assoc.timerLoop()

	assoc.rackReoWndFloor = config.rackReoWndFloor // optional floor; usually 0
	assoc.rackKeepInflatedRecoveries = 0

	if assoc.name == "" {
		assoc.name = fmt.Sprintf("%p", assoc)
	}

	// RFC 4690 Sec 7.2.1
	//  o  The initial cwnd before DATA transmission or after a sufficiently
	//     long idle period MUST be set to min(4*MTU, max (2*MTU, 4380
	//     bytes)).
	assoc.setCWND(min32(4*assoc.MTU(), max32(2*assoc.MTU(), 4380)))
	assoc.log.Tracef("[%s] updated cwnd=%d ssthresh=%d inflight=%d (INI)",
		assoc.name, assoc.CWND(), assoc.ssthresh, assoc.inflightQueue.getNumBytes())

	assoc.srtt.Store(float64(0))
	assoc.t1Init = newRTXTimer(timerT1Init, assoc, maxInitRetrans, config.RTOMax)
	assoc.t1Cookie = newRTXTimer(timerT1Cookie, assoc, maxInitRetrans, config.RTOMax)
	assoc.t2Shutdown = newRTXTimer(timerT2Shutdown, assoc, noMaxRetrans, config.RTOMax)
	assoc.t3RTX = newRTXTimer(timerT3RTX, assoc, noMaxRetrans, config.RTOMax)
	assoc.tReconfig = newRTXTimer(timerReconfig, assoc, noMaxRetrans, config.RTOMax)
	assoc.ackTimer = newAckTimer(assoc)

	return assoc
}

func (a *Association) init(isClient bool) {
	a.lock.Lock()
	defer a.lock.Unlock()

	go a.readLoop()
	go a.writeLoop()

	if isClient {
		init := &chunkInit{}
		init.initialTSN = a.myNextTSN
		init.numOutboundStreams = a.myMaxNumOutboundStreams
		init.numInboundStreams = a.myMaxNumInboundStreams
		init.initiateTag = a.myVerificationTag
		init.advertisedReceiverWindowCredit = a.maxReceiveBufferSize
		setSupportedExtensions(&init.chunkInitCommon)

		if a.recvZeroChecksum {
			init.params = append(init.params, &paramZeroChecksumAcceptable{edmid: dtlsErrorDetectionMethod})
		}

		a.storedInit = init

		err := a.sendInit()
		if err != nil {
			a.log.Errorf("[%s] failed to send init: %s", a.name, err.Error())
		}

		// After sending the INIT chunk, "A" starts the T1-init timer and enters the COOKIE-WAIT state.
		// Note: ideally we would set state after the timer starts but since we don't do this in an atomic
		// set + timer-start, it's safer to just set the state first so that we don't have a timer expiration
		// race.
		a.setState(cookieWait)
		a.t1Init.start(a.rtoMgr.getRTO())
	}
}

// caller must hold a.lock.
func (a *Association) sendInit() error {
	a.log.Debugf("[%s] sending INIT", a.name)
	if a.storedInit == nil {
		return ErrInitNotStoredToSend
	}

	outbound := &packet{}
	outbound.verificationTag = 0
	a.sourcePort = defaultSCTPSrcDstPort
	a.destinationPort = defaultSCTPSrcDstPort
	outbound.sourcePort = a.sourcePort
	outbound.destinationPort = a.destinationPort

	outbound.chunks = []chunk{a.storedInit}

	a.controlQueue.push(outbound)
	a.awakeWriteLoop()

	return nil
}

// caller must hold a.lock.
func (a *Association) sendCookieEcho() error {
	if a.storedCookieEcho == nil {
		return ErrCookieEchoNotStoredToSend
	}

	a.log.Debugf("[%s] sending COOKIE-ECHO", a.name)

	outbound := &packet{}
	outbound.verificationTag = a.peerVerificationTag
	outbound.sourcePort = a.sourcePort
	outbound.destinationPort = a.destinationPort
	outbound.chunks = []chunk{a.storedCookieEcho}

	a.controlQueue.push(outbound)
	a.awakeWriteLoop()

	return nil
}

// Shutdown initiates the shutdown sequence. The method blocks until the
// shutdown sequence is completed and the connection is closed, or until the
// passed context is done, in which case the context's error is returned.
func (a *Association) Shutdown(ctx context.Context) error {
	a.log.Debugf("[%s] closing association..", a.name)

	state := a.getState()

	if state != established {
		return fmt.Errorf("%w: shutdown %s", ErrShutdownNonEstablished, a.name)
	}

	// Attempt a graceful shutdown.
	a.setState(shutdownPending)

	a.lock.Lock()

	if a.inflightQueue.size() == 0 {
		// No more outstanding, send shutdown.
		a.willSendShutdown = true
		a.awakeWriteLoop()
		a.setState(shutdownSent)
	}

	a.lock.Unlock()

	select {
	case <-a.closeWriteLoopCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close ends the SCTP Association and cleans up any state.
func (a *Association) Close() error {
	a.log.Debugf("[%s] closing association..", a.name)

	err := a.close()

	// Wait for readLoop to end
	<-a.readLoopCloseCh

	a.log.Debugf("[%s] association closed", a.name)
	a.log.Debugf("[%s] stats nPackets (in) : %d", a.name, a.stats.getNumPacketsReceived())
	a.log.Debugf("[%s] stats nPackets (out) : %d", a.name, a.stats.getNumPacketsSent())
	a.log.Debugf("[%s] stats nDATAs (in) : %d", a.name, a.stats.getNumDATAs())
	a.log.Debugf("[%s] stats nSACKs (in) : %d", a.name, a.stats.getNumSACKsReceived())
	a.log.Debugf("[%s] stats nSACKs (out) : %d", a.name, a.stats.getNumSACKsSent())
	a.log.Debugf("[%s] stats nT3Timeouts : %d", a.name, a.stats.getNumT3Timeouts())
	a.log.Debugf("[%s] stats nAckTimeouts: %d", a.name, a.stats.getNumAckTimeouts())
	a.log.Debugf("[%s] stats nFastRetrans: %d", a.name, a.stats.getNumFastRetrans())

	return err
}

func (a *Association) close() error {
	a.log.Debugf("[%s] closing association..", a.name)

	a.setState(closed)

	err := a.netConn.Close()

	a.closeAllTimers()

	// awake writeLoop to exit
	a.closeWriteLoopOnce.Do(func() { close(a.closeWriteLoopCh) })

	return err
}

// Abort sends the abort packet with user initiated abort and immediately
// closes the connection.
func (a *Association) Abort(reason string) {
	a.log.Debugf("[%s] aborting association: %s", a.name, reason)

	a.lock.Lock()

	a.willSendAbort = true
	a.willSendAbortCause = &errorCauseUserInitiatedAbort{
		upperLayerAbortReason: []byte(reason),
	}

	a.lock.Unlock()

	// short bound for abort flush.
	_ = a.netConn.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
	a.awakeWriteLoop()

	// unblock readLoop even if the underlying TCP connection is half-open.
	// We want Abort to return promptly during shutdown.
	_ = a.netConn.SetReadDeadline(time.Now())

	// Wait for readLoop to end
	<-a.readLoopCloseCh
}

func (a *Association) closeAllTimers() {
	// Close all retransmission & ack timers
	a.t1Init.close()
	a.t1Cookie.close()
	a.t2Shutdown.close()
	a.t3RTX.close()
	a.tReconfig.close()
	a.ackTimer.close()
	a.stopRackTimer()
	a.stopPTOTimer()
}

func (a *Association) readLoop() {
	var closeErr error
	defer func() {
		// also stop writeLoop, otherwise writeLoop can be leaked
		// if connection is lost when there is no writing packet.
		a.closeWriteLoopOnce.Do(func() { close(a.closeWriteLoopCh) })

		a.lock.Lock()
		a.setState(closed)
		for _, s := range a.streams {
			a.unregisterStream(s, closeErr)
		}
		a.lock.Unlock()
		close(a.acceptCh)
		close(a.readLoopCloseCh)

		a.log.Debugf("[%s] association closed", a.name)
		a.log.Debugf("[%s] stats nDATAs (in) : %d", a.name, a.stats.getNumDATAs())
		a.log.Debugf("[%s] stats nSACKs (in) : %d", a.name, a.stats.getNumSACKsReceived())
		a.log.Debugf("[%s] stats nT3Timeouts : %d", a.name, a.stats.getNumT3Timeouts())
		a.log.Debugf("[%s] stats nAckTimeouts: %d", a.name, a.stats.getNumAckTimeouts())
		a.log.Debugf("[%s] stats nFastRetrans: %d", a.name, a.stats.getNumFastRetrans())
	}()

	a.log.Debugf("[%s] readLoop entered", a.name)
	buffer := make([]byte, receiveMTU)

	for {
		n, err := a.netConn.Read(buffer)
		if err != nil {
			closeErr = err

			break
		}
		// Make a buffer sized to what we read, then copy the data we
		// read from the underlying transport. We do this because the
		// user data is passed to the reassembly queue without
		// copying.
		inbound := make([]byte, n)
		copy(inbound, buffer[:n])
		atomic.AddUint64(&a.bytesReceived, uint64(n)) //nolint:gosec // G115
		if err = a.handleInbound(inbound); err != nil {
			closeErr = err

			break
		}
	}

	a.log.Debugf("[%s] readLoop exited %s", a.name, closeErr)
}

func (a *Association) writeLoop() {
	a.log.Debugf("[%s] writeLoop entered", a.name)
	defer a.log.Debugf("[%s] writeLoop exited", a.name)

loop:
	for {
		rawPackets, ok := a.gatherOutbound()

		for _, raw := range rawPackets {
			_, err := a.netConn.Write(raw)
			if err != nil {
				if !errors.Is(err, io.EOF) {
					a.log.Warnf("[%s] failed to write packets on netConn: %v", a.name, err)
				}
				a.log.Debugf("[%s] writeLoop ended", a.name)

				break loop
			}
			atomic.AddUint64(&a.bytesSent, uint64(len(raw)))
			a.stats.incPacketsSent()
		}

		if !ok {
			if err := a.close(); err != nil {
				a.log.Warnf("[%s] failed to close association: %v", a.name, err)
			}

			return
		}

		select {
		case <-a.awakeWriteLoopCh:
		case <-a.closeWriteLoopCh:
			break loop
		}
	}

	a.setState(closed)
	a.closeAllTimers()
}

func (a *Association) awakeWriteLoop() {
	select {
	case a.awakeWriteLoopCh <- struct{}{}:
	default:
	}
}

func (a *Association) isBlockWrite() bool {
	return a.blockWrite
}

// Mark the association is writable and unblock the waiting write,
// the caller should hold the association write lock.
func (a *Association) notifyBlockWritable() {
	a.writePending = false
	select {
	case a.writeNotify <- struct{}{}:
	default:
	}
}

// unregisterStream un-registers a stream from the association
// The caller should hold the association write lock.
func (a *Association) unregisterStream(s *Stream, err error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	delete(a.streams, s.streamIdentifier)
	s.readErr = err
	s.readNotifier.Broadcast()
}

func chunkMandatoryChecksum(cc []chunk) bool {
	for _, c := range cc {
		switch c.(type) {
		case *chunkInit, *chunkCookieEcho:
			return true
		}
	}

	return false
}

func (a *Association) marshalPacket(p *packet) ([]byte, error) {
	return p.marshal(!a.sendZeroChecksum || chunkMandatoryChecksum(p.chunks))
}

func (a *Association) unmarshalPacket(raw []byte) (*packet, error) {
	p := &packet{}
	if err := p.unmarshal(!a.recvZeroChecksum, raw); err != nil {
		return nil, err
	}

	return p, nil
}

// handleInbound parses incoming raw packets.
func (a *Association) handleInbound(raw []byte) error {
	pkt, err := a.unmarshalPacket(raw)
	if err != nil {
		a.log.Warnf("[%s] unable to parse SCTP packet %s", a.name, err)

		return nil
	}

	if err := checkPacket(pkt); err != nil {
		a.log.Warnf("[%s] failed validating packet %s", a.name, err)

		return nil
	}

	a.handleChunksStart()

	for _, c := range pkt.chunks {
		if err := a.handleChunk(pkt, c); err != nil {
			return err
		}
	}

	a.handleChunksEnd()

	return nil
}

// The caller should hold the lock.
func (a *Association) gatherDataPacketsToRetransmit(rawPackets [][]byte, budgetUnits *int64, consumed *bool) [][]byte {
	for _, p := range a.getDataPacketsToRetransmit(budgetUnits, consumed) {
		raw, err := a.marshalPacket(p)
		if err != nil {
			a.log.Warnf("[%s] failed to serialize a DATA packet to be retransmitted", a.name)

			continue
		}
		rawPackets = append(rawPackets, raw)
	}

	return rawPackets
}

// The caller should hold the lock.
//
//nolint:cyclop
func (a *Association) gatherOutboundDataAndReconfigPackets(
	rawPackets [][]byte,
	budgetUnits *int64,
	consumed *bool,
) [][]byte {
	// Pop unsent data chunks from the pending queue to send as much as
	// cwnd and rwnd allow.
	chunks, sisToReset := a.popPendingDataChunksToSend(budgetUnits, consumed)

	if len(chunks) > 0 {
		// Start timer. (noop if already started)
		a.log.Tracef("[%s] T3-rtx timer start (pt1)", a.name)
		a.t3RTX.start(a.rtoMgr.getRTO())
		for _, p := range a.bundleDataChunksIntoPackets(chunks) {
			raw, err := a.marshalPacket(p)
			if err != nil {
				a.log.Warnf("[%s] failed to serialize a DATA packet", a.name)

				continue
			}
			rawPackets = append(rawPackets, raw)
		}
		// RFC 8985 (RACK) schedule PTO on new data transmission
		a.schedulePTOAfterSendLocked()
	}

	if len(sisToReset) > 0 || a.willRetransmitReconfig { //nolint:nestif
		if a.willRetransmitReconfig {
			a.willRetransmitReconfig = false
			a.log.Debugf("[%s] retransmit %d RECONFIG chunk(s)", a.name, len(a.reconfigs))
			for _, c := range a.reconfigs {
				p := a.createPacket([]chunk{c})
				raw, err := a.marshalPacket(p)
				if err != nil {
					a.log.Warnf("[%s] failed to serialize a RECONFIG packet to be retransmitted", a.name)
				} else {
					rawPackets = append(rawPackets, raw)
				}
			}
		}

		if len(sisToReset) > 0 {
			rsn := a.generateNextRSN()
			tsn := a.myNextTSN - 1
			c := &chunkReconfig{
				paramA: &paramOutgoingResetRequest{
					reconfigRequestSequenceNumber: rsn,
					senderLastTSN:                 tsn,
					streamIdentifiers:             sisToReset,
				},
			}
			a.reconfigs[rsn] = c // store in the map for retransmission
			a.log.Debugf("[%s] sending RECONFIG: rsn=%d tsn=%d streams=%v",
				a.name, rsn, a.myNextTSN-1, sisToReset)
			p := a.createPacket([]chunk{c})
			raw, err := a.marshalPacket(p)
			if err != nil {
				a.log.Warnf("[%s] failed to serialize a RECONFIG packet to be transmitted", a.name)
			} else {
				rawPackets = append(rawPackets, raw)
			}
		}

		if len(a.reconfigs) > 0 {
			a.tReconfig.start(a.rtoMgr.getRTO())
		}
	}

	return rawPackets
}

// The caller should hold the lock.
//
//nolint:cyclop
func (a *Association) gatherOutboundFastRetransmissionPackets( //nolint:gocognit
	rawPackets [][]byte,
	budgetScaled *int64,
	consumed *bool,
) [][]byte {
	if !a.willRetransmitFast {
		return rawPackets
	}
	a.willRetransmitFast = false

	toFastRetrans := []*chunkPayloadData{}
	fastRetransSize := int(commonHeaderSize)
	fastRetransWnd := int(max(a.MTU(), a.fastRtxWnd))
	now := time.Now()

	// MTU bundling + burst budgeting tracker
	bytesInPacket := 0
	stopBundling := false

	for i := 0; ; i++ {
		chunkPayload, ok := a.inflightQueue.get(a.cumulativeTSNAckPoint + uint32(i) + 1) //nolint:gosec // G115
		if !ok {
			break // end of pending data
		}

		if chunkPayload.acked || chunkPayload.abandoned() {
			continue
		}

		if chunkPayload.nSent > 1 || chunkPayload.missIndicator < 3 {
			continue
		}

		// include padding for sizing.
		chunkBytes := int(dataChunkHeaderSize) + len(chunkPayload.userData)
		chunkBytes += getPadding(chunkBytes)

		// fast retransmit window cap
		if fastRetransWnd < fastRetransSize+chunkBytes {
			break
		}

		// MTU bundling + burst budget before mutating
		for {
			addBytes := chunkBytes

			if bytesInPacket == 0 {
				addBytes += int(commonHeaderSize)
				if addBytes > int(a.MTU()) {
					stopBundling = true

					break
				}
			} else if bytesInPacket+chunkBytes > int(a.MTU()) {
				// start a new packet and retry this same chunk as first in packet
				bytesInPacket = 0

				continue
			}

			if !a.tlrAllowSendLocked(budgetScaled, consumed, addBytes) {
				// budget exhausted, stop selecting any more fast-rtx chunks
				stopBundling = true

				break
			}

			if bytesInPacket == 0 {
				bytesInPacket = int(commonHeaderSize)
			}
			bytesInPacket += chunkBytes

			break
		}

		if stopBundling {
			break
		}

		fastRetransSize += chunkBytes
		a.stats.incFastRetrans()

		// Update for retransmission
		chunkPayload.nSent++
		chunkPayload.since = now
		a.rackRemove(chunkPayload)
		a.rackInsert(chunkPayload)

		a.checkPartialReliabilityStatus(chunkPayload)
		toFastRetrans = append(toFastRetrans, chunkPayload)
		a.log.Tracef("[%s] fast-retransmit: tsn=%d sent=%d htna=%d",
			a.name, chunkPayload.tsn, chunkPayload.nSent, a.fastRecoverExitPoint)
	}

	if len(toFastRetrans) == 0 {
		return rawPackets
	}

	for _, p := range a.bundleDataChunksIntoPackets(toFastRetrans) {
		raw, err := a.marshalPacket(p)
		if err != nil {
			a.log.Warnf("[%s] failed to serialize a DATA packet to be fast-retransmitted", a.name)

			continue
		}
		rawPackets = append(rawPackets, raw)
	}

	return rawPackets
}

// The caller should hold the lock.
func (a *Association) gatherOutboundSackPackets(rawPackets [][]byte) [][]byte {
	if a.ackState == ackStateImmediate {
		a.ackState = ackStateIdle
		sack := a.createSelectiveAckChunk()
		a.stats.incSACKsSent()
		a.log.Debugf("[%s] sending SACK: %s", a.name, sack)
		raw, err := a.marshalPacket(a.createPacket([]chunk{sack}))
		if err != nil {
			a.log.Warnf("[%s] failed to serialize a SACK packet", a.name)
		} else {
			rawPackets = append(rawPackets, raw)
		}
	}

	return rawPackets
}

// The caller should hold the lock.
func (a *Association) gatherOutboundForwardTSNPackets(rawPackets [][]byte) [][]byte {
	if a.willSendForwardTSN {
		a.willSendForwardTSN = false
		if sna32GT(a.advancedPeerTSNAckPoint, a.cumulativeTSNAckPoint) {
			fwdtsn := a.createForwardTSN()
			raw, err := a.marshalPacket(a.createPacket([]chunk{fwdtsn}))
			if err != nil {
				a.log.Warnf("[%s] failed to serialize a Forward TSN packet", a.name)
			} else {
				rawPackets = append(rawPackets, raw)
			}
		}
	}

	return rawPackets
}

func (a *Association) gatherOutboundShutdownPackets(rawPackets [][]byte) ([][]byte, bool) {
	ok := true

	switch {
	case a.willSendShutdown:
		a.willSendShutdown = false

		shutdown := &chunkShutdown{
			cumulativeTSNAck: a.cumulativeTSNAckPoint,
		}

		raw, err := a.marshalPacket(a.createPacket([]chunk{shutdown}))
		if err != nil {
			a.log.Warnf("[%s] failed to serialize a Shutdown packet", a.name)
		} else {
			a.t2Shutdown.start(a.rtoMgr.getRTO())
			rawPackets = append(rawPackets, raw)
		}
	case a.willSendShutdownAck:
		a.willSendShutdownAck = false

		shutdownAck := &chunkShutdownAck{}

		raw, err := a.marshalPacket(a.createPacket([]chunk{shutdownAck}))
		if err != nil {
			a.log.Warnf("[%s] failed to serialize a ShutdownAck packet", a.name)
		} else {
			a.t2Shutdown.start(a.rtoMgr.getRTO())
			rawPackets = append(rawPackets, raw)
		}
	case a.willSendShutdownComplete:
		a.willSendShutdownComplete = false

		shutdownComplete := &chunkShutdownComplete{}

		raw, err := a.marshalPacket(a.createPacket([]chunk{shutdownComplete}))
		if err != nil {
			a.log.Warnf("[%s] failed to serialize a ShutdownComplete packet", a.name)
		} else {
			rawPackets = append(rawPackets, raw)
			ok = false
		}
	}

	return rawPackets, ok
}

func (a *Association) gatherAbortPacket() ([]byte, error) {
	cause := a.willSendAbortCause

	a.willSendAbort = false
	a.willSendAbortCause = nil

	abort := &chunkAbort{}

	if cause != nil {
		abort.errorCauses = []errorCause{cause}
	}

	raw, err := a.marshalPacket(a.createPacket([]chunk{abort}))

	return raw, err
}

// gatherOutbound gathers outgoing packets. The returned bool value set to
// false means the association should be closed down after the final send.
func (a *Association) gatherOutbound() ([][]byte, bool) {
	a.lock.Lock()
	defer a.lock.Unlock()

	if a.willSendAbort {
		pkt, err := a.gatherAbortPacket()
		if err != nil {
			a.log.Warnf("[%s] failed to serialize an abort packet", a.name)

			return nil, false
		}

		return [][]byte{pkt}, false
	}

	rawPackets := [][]byte{}

	if a.controlQueue.size() > 0 {
		for _, p := range a.controlQueue.popAll() {
			raw, err := a.marshalPacket(p)
			if err != nil {
				a.log.Warnf("[%s] failed to serialize a control packet", a.name)

				continue
			}
			rawPackets = append(rawPackets, raw)
		}
	}

	state := a.getState()

	ok := true

	switch state {
	case established:
		budgetUnits := a.tlrCurrentBurstBudgetScaledLocked()
		consumed := false

		rawPackets = a.gatherDataPacketsToRetransmit(rawPackets, &budgetUnits, &consumed)
		rawPackets = a.gatherOutboundDataAndReconfigPackets(rawPackets, &budgetUnits, &consumed)
		rawPackets = a.gatherOutboundFastRetransmissionPackets(rawPackets, &budgetUnits, &consumed)

		// control traffic shouldn't be limited.
		rawPackets = a.gatherOutboundSackPackets(rawPackets)
		rawPackets = a.gatherOutboundForwardTSNPackets(rawPackets)
	case shutdownPending, shutdownSent, shutdownReceived:
		budgetUnits := a.tlrCurrentBurstBudgetScaledLocked()
		consumed := false

		rawPackets = a.gatherDataPacketsToRetransmit(rawPackets, &budgetUnits, &consumed)
		rawPackets = a.gatherOutboundFastRetransmissionPackets(rawPackets, &budgetUnits, &consumed)

		rawPackets = a.gatherOutboundSackPackets(rawPackets)
		rawPackets, ok = a.gatherOutboundShutdownPackets(rawPackets)
	case shutdownAckSent:
		rawPackets, ok = a.gatherOutboundShutdownPackets(rawPackets)
	}

	return rawPackets, ok
}

func checkPacket(pkt *packet) error {
	// All packets must adhere to these rules

	// This is the SCTP sender's port number.  It can be used by the
	// receiver in combination with the source IP address, the SCTP
	// destination port, and possibly the destination IP address to
	// identify the association to which this packet belongs.  The port
	// number 0 MUST NOT be used.
	if pkt.sourcePort == 0 {
		return ErrSCTPPacketSourcePortZero
	}

	// This is the SCTP port number to which this packet is destined.
	// The receiving host will use this port number to de-multiplex the
	// SCTP packet to the correct receiving endpoint/application.  The
	// port number 0 MUST NOT be used.
	if pkt.destinationPort == 0 {
		return ErrSCTPPacketDestinationPortZero
	}

	// Check values on the packet that are specific to a particular chunk type
	for _, c := range pkt.chunks {
		switch c.(type) { // nolint:gocritic
		case *chunkInit:
			// An INIT or INIT ACK chunk MUST NOT be bundled with any other chunk.
			// They MUST be the only chunks present in the SCTP packets that carry
			// them.
			if len(pkt.chunks) != 1 {
				return ErrInitChunkBundled
			}

			// A packet containing an INIT chunk MUST have a zero Verification
			// Tag.
			if pkt.verificationTag != 0 {
				return ErrInitChunkVerifyTagNotZero
			}
		}
	}

	return nil
}

func min16(a, b uint16) uint16 {
	if a < b {
		return a
	}

	return b
}

func max32(a, b uint32) uint32 {
	if a > b {
		return a
	}

	return b
}

func min32(a, b uint32) uint32 {
	if a < b {
		return a
	}

	return b
}

// peerLastTSN return last received cumulative TSN.
func (a *Association) peerLastTSN() uint32 {
	return a.payloadQueue.getcumulativeTSN()
}

// setState atomically sets the state of the Association.
// The caller should hold the lock.
func (a *Association) setState(newState uint32) {
	oldState := atomic.SwapUint32(&a.state, newState)
	if newState != oldState {
		a.log.Debugf("[%s] state change: '%s' => '%s'",
			a.name,
			getAssociationStateString(oldState),
			getAssociationStateString(newState))
	}
}

// getState atomically returns the state of the Association.
func (a *Association) getState() uint32 {
	return atomic.LoadUint32(&a.state)
}

// BytesSent returns the number of bytes sent.
func (a *Association) BytesSent() uint64 {
	return atomic.LoadUint64(&a.bytesSent)
}

// BytesReceived returns the number of bytes received.
func (a *Association) BytesReceived() uint64 {
	return atomic.LoadUint64(&a.bytesReceived)
}

// MTU returns the association's current MTU.
func (a *Association) MTU() uint32 {
	return atomic.LoadUint32(&a.mtu)
}

// CWND returns the association's current congestion window (cwnd).
func (a *Association) CWND() uint32 {
	return atomic.LoadUint32(&a.cwnd)
}

func (a *Association) setCWND(cwnd uint32) {
	if cwnd < a.minCwnd {
		cwnd = a.minCwnd
	}
	atomic.StoreUint32(&a.cwnd, cwnd)
}

// RWND returns the association's current receiver window (rwnd).
func (a *Association) RWND() uint32 {
	return atomic.LoadUint32(&a.rwnd)
}

func (a *Association) setRWND(rwnd uint32) {
	atomic.StoreUint32(&a.rwnd, rwnd)
}

// SRTT returns the latest smoothed round-trip time (srrt).
func (a *Association) SRTT() float64 {
	return a.srtt.Load().(float64) //nolint:forcetypeassert
}

// getMaxTSNOffset returns the maximum offset over the current cummulative TSN that
// we are willing to enqueue. This ensures that we keep the bytes utilized in the receive
// buffer within a small multiple of the user provided max receive buffer size.
func getMaxTSNOffset(maxReceiveBufferSize uint32) uint32 {
	// 4 is a magic number here. There is no theory behind this.
	offset := max((maxReceiveBufferSize*4)/avgChunkSize, minTSNOffset)
	if offset > maxTSNOffset {
		offset = maxTSNOffset
	}

	return offset
}

func setSupportedExtensions(init *chunkInitCommon) {
	// nolint:godox
	// TODO RFC5061 https://tools.ietf.org/html/rfc6525#section-5.2
	// An implementation supporting this (Supported Extensions Parameter)
	// extension MUST list the ASCONF, the ASCONF-ACK, and the AUTH chunks
	// in its INIT and INIT-ACK parameters.
	init.params = append(init.params, &paramSupportedExtensions{
		ChunkTypes: []chunkType{ctReconfig, ctForwardTSN},
	})
}

// The caller should hold the lock.
//
//nolint:cyclop
func (a *Association) handleInit(pkt *packet, initChunk *chunkInit) ([]*packet, error) {
	state := a.getState()
	a.log.Debugf("[%s] chunkInit received in state '%s'", a.name, getAssociationStateString(state))

	// https://tools.ietf.org/html/rfc4960#section-5.2.1
	// Upon receipt of an INIT in the COOKIE-WAIT state, an endpoint MUST
	// respond with an INIT ACK using the same parameters it sent in its
	// original INIT chunk (including its Initiate Tag, unchanged).  When
	// responding, the endpoint MUST send the INIT ACK back to the same
	// address that the original INIT (sent by this endpoint) was sent.

	if state != closed && state != cookieWait && state != cookieEchoed {
		// 5.2.2.  Unexpected INIT in States Other than CLOSED, COOKIE-ECHOED,
		//        COOKIE-WAIT, and SHUTDOWN-ACK-SENT
		return nil, fmt.Errorf("%w: %s", ErrHandleInitState, getAssociationStateString(state))
	}

	// NOTE: Setting these prior to a reception of a COOKIE ECHO chunk containing
	// our cookie is not compliant with https://www.rfc-editor.org/rfc/rfc9260#section-5.1-2.2.3.
	// It makes us more vulnerable to resource attacks, albeit minimally so.
	//  https://www.rfc-editor.org/rfc/rfc9260#sec_handle_stream_parameters
	a.myMaxNumInboundStreams = min16(initChunk.numInboundStreams, a.myMaxNumInboundStreams)
	a.myMaxNumOutboundStreams = min16(initChunk.numOutboundStreams, a.myMaxNumOutboundStreams)
	a.peerVerificationTag = initChunk.initiateTag
	a.sourcePort = pkt.destinationPort
	a.destinationPort = pkt.sourcePort

	// 13.2 This is the last TSN received in sequence.  This value
	// is set initially by taking the peer's initial TSN,
	// received in the INIT or INIT ACK chunk, and
	// subtracting one from it.
	a.payloadQueue.init(initChunk.initialTSN - 1)

	a.setRWND(initChunk.advertisedReceiverWindowCredit)
	a.log.Debugf("[%s] initial rwnd=%d", a.name, a.RWND())

	for _, param := range initChunk.params {
		switch v := param.(type) { // nolint:gocritic
		case *paramSupportedExtensions:
			for _, t := range v.ChunkTypes {
				if t == ctForwardTSN {
					a.log.Debugf("[%s] use ForwardTSN (on init)", a.name)
					a.useForwardTSN = true
				}
			}
		case *paramZeroChecksumAcceptable:
			a.sendZeroChecksum = v.edmid == dtlsErrorDetectionMethod
		}
	}

	if !a.useForwardTSN {
		a.log.Warnf("[%s] not using ForwardTSN (on init)", a.name)
	}

	outbound := &packet{}
	outbound.verificationTag = a.peerVerificationTag
	outbound.sourcePort = a.sourcePort
	outbound.destinationPort = a.destinationPort

	initAck := &chunkInitAck{}
	a.log.Debug("sending INIT ACK")

	initAck.initialTSN = a.myNextTSN
	initAck.numOutboundStreams = a.myMaxNumOutboundStreams
	initAck.numInboundStreams = a.myMaxNumInboundStreams
	initAck.initiateTag = a.myVerificationTag
	initAck.advertisedReceiverWindowCredit = a.maxReceiveBufferSize

	if a.myCookie == nil {
		var err error
		// NOTE: This generation process is not compliant with
		// 5.1.3.  Generating State Cookie (https://www.rfc-editor.org/rfc/rfc4960#section-5.1.3)
		if a.myCookie, err = newRandomStateCookie(); err != nil {
			return nil, err
		}
	}

	initAck.params = []param{a.myCookie}

	if a.recvZeroChecksum {
		initAck.params = append(initAck.params, &paramZeroChecksumAcceptable{edmid: dtlsErrorDetectionMethod})
	}
	a.log.Debugf("[%s] sendZeroChecksum=%t (on init)", a.name, a.sendZeroChecksum)

	setSupportedExtensions(&initAck.chunkInitCommon)

	outbound.chunks = []chunk{initAck}

	return pack(outbound), nil
}

// The caller should hold the lock.
func (a *Association) handleInitAck(pkt *packet, initChunkAck *chunkInitAck) error { //nolint:cyclop
	state := a.getState()
	a.log.Debugf("[%s] chunkInitAck received in state '%s'", a.name, getAssociationStateString(state))
	if state != cookieWait {
		// RFC 4960
		// 5.2.3.  Unexpected INIT ACK
		//   If an INIT ACK is received by an endpoint in any state other than the
		//   COOKIE-WAIT state, the endpoint should discard the INIT ACK chunk.
		//   An unexpected INIT ACK usually indicates the processing of an old or
		//   duplicated INIT chunk.
		return nil
	}

	a.myMaxNumInboundStreams = min16(initChunkAck.numInboundStreams, a.myMaxNumInboundStreams)
	a.myMaxNumOutboundStreams = min16(initChunkAck.numOutboundStreams, a.myMaxNumOutboundStreams)
	a.peerVerificationTag = initChunkAck.initiateTag
	a.payloadQueue.init(initChunkAck.initialTSN - 1)
	if a.sourcePort != pkt.destinationPort ||
		a.destinationPort != pkt.sourcePort {
		a.log.Warnf("[%s] handleInitAck: port mismatch", a.name)

		return nil
	}

	a.setRWND(initChunkAck.advertisedReceiverWindowCredit)
	a.log.Debugf("[%s] initial rwnd=%d", a.name, a.RWND())

	// RFC 4690 Sec 7.2.1
	//  o  The initial value of ssthresh MAY be arbitrarily high (for
	//     example, implementations MAY use the size of the receiver
	//     advertised window).
	a.ssthresh = a.RWND()
	a.log.Tracef("[%s] updated cwnd=%d ssthresh=%d inflight=%d (INI)",
		a.name, a.CWND(), a.ssthresh, a.inflightQueue.getNumBytes())

	a.t1Init.stop()
	a.storedInit = nil

	var cookieParam *paramStateCookie
	for _, param := range initChunkAck.params {
		switch v := param.(type) {
		case *paramStateCookie:
			cookieParam = v
		case *paramSupportedExtensions:
			for _, t := range v.ChunkTypes {
				if t == ctForwardTSN {
					a.log.Debugf("[%s] use ForwardTSN (on initAck)", a.name)
					a.useForwardTSN = true
				}
			}
		case *paramZeroChecksumAcceptable:
			a.sendZeroChecksum = v.edmid == dtlsErrorDetectionMethod
		}
	}

	a.log.Debugf("[%s] sendZeroChecksum=%t (on initAck)", a.name, a.sendZeroChecksum)

	if !a.useForwardTSN {
		a.log.Warnf("[%s] not using ForwardTSN (on initAck)", a.name)
	}
	if cookieParam == nil {
		return ErrInitAckNoCookie
	}

	a.storedCookieEcho = &chunkCookieEcho{}
	a.storedCookieEcho.cookie = cookieParam.cookie

	err := a.sendCookieEcho()
	if err != nil {
		a.log.Errorf("[%s] failed to send init: %s", a.name, err.Error())
	}

	a.t1Cookie.start(a.rtoMgr.getRTO())
	a.setState(cookieEchoed)

	return nil
}

// The caller should hold the lock.
func (a *Association) handleHeartbeat(c *chunkHeartbeat) []*packet {
	a.log.Tracef("[%s] chunkHeartbeat", a.name)

	if len(c.params) == 0 {
		a.log.Warnf("[%s] Heartbeat without ParamHeartbeatInfo (no params)", a.name)

		return nil
	}

	info, ok := c.params[0].(*paramHeartbeatInfo)
	if !ok {
		a.log.Warnf("[%s] Heartbeat without ParamHeartbeatInfo (got %T)", a.name, c.params[0])

		return nil
	}

	return pack(&packet{
		verificationTag: a.peerVerificationTag,
		sourcePort:      a.sourcePort,
		destinationPort: a.destinationPort,
		chunks: []chunk{&chunkHeartbeatAck{
			params: []param{
				&paramHeartbeatInfo{
					heartbeatInformation: info.heartbeatInformation,
				},
			},
		}},
	})
}

// The caller should hold the lock.
func (a *Association) handleHeartbeatAck(c *chunkHeartbeatAck) {
	a.log.Tracef("[%s] chunkHeartbeatAck", a.name)

	if len(c.params) == 0 {
		return
	}

	info, ok := c.params[0].(*paramHeartbeatInfo)
	if !ok {
		a.log.Warnf("[%s] HeartbeatAck without ParamHeartbeatInfo", a.name)

		return
	}

	// active RTT probe: if heartbeatInformation is exactly 8 bytes, treat it
	// as a big-endian unix nano timestamp.
	if len(info.heartbeatInformation) == 8 {
		ns := binary.BigEndian.Uint64(info.heartbeatInformation)
		if ns > math.MaxInt64 {
			// Malformed or future-unsafe value; ignore this heartbeat-ack.
			a.log.Warnf("[%s] HB RTT: timestamp overflows int64, ignoring", a.name)

			return
		}

		sentNanos := int64(ns)
		sent := time.Unix(0, sentNanos)
		now := time.Now()

		if !sent.IsZero() && !now.Before(sent) {
			rttMs := now.Sub(sent).Seconds() * 1000.0
			srtt := a.rtoMgr.setNewRTT(rttMs)
			a.srtt.Store(srtt)

			a.rackMinRTTWnd.Push(now, now.Sub(sent))

			a.log.Tracef("[%s] HB RTT: measured=%.3fms srtt=%.3fms rto=%.3fms",
				a.name, rttMs, srtt, a.rtoMgr.getRTO())
		}
	}
}

// The caller should hold the lock.
func (a *Association) handleCookieEcho(cookieEcho *chunkCookieEcho) []*packet {
	state := a.getState()
	a.log.Debugf("[%s] COOKIE-ECHO received in state '%s'", a.name, getAssociationStateString(state))

	if a.myCookie == nil {
		a.log.Debugf("[%s] COOKIE-ECHO received before initialization", a.name)

		return nil
	}
	switch state {
	default:
		return nil
	case established:
		if !bytes.Equal(a.myCookie.cookie, cookieEcho.cookie) {
			return nil
		}
	case closed, cookieWait, cookieEchoed:
		if !bytes.Equal(a.myCookie.cookie, cookieEcho.cookie) {
			return nil
		}

		// RFC wise, these do not seem to belong here, but removing them
		// causes TestCookieEchoRetransmission to break
		a.t1Init.stop()
		a.storedInit = nil

		a.t1Cookie.stop()
		a.storedCookieEcho = nil

		a.setState(established)
		if !a.completeHandshake(nil) {
			return nil
		}
	}

	p := &packet{
		verificationTag: a.peerVerificationTag,
		sourcePort:      a.sourcePort,
		destinationPort: a.destinationPort,
		chunks:          []chunk{&chunkCookieAck{}},
	}

	return pack(p)
}

// The caller should hold the lock.
func (a *Association) handleCookieAck() {
	state := a.getState()
	a.log.Debugf("[%s] COOKIE-ACK received in state '%s'", a.name, getAssociationStateString(state))
	if state != cookieEchoed {
		// RFC 4960
		// 5.2.5.  Handle Duplicate COOKIE-ACK.
		//   At any state other than COOKIE-ECHOED, an endpoint should silently
		//   discard a received COOKIE ACK chunk.
		return
	}

	a.t1Cookie.stop()
	a.storedCookieEcho = nil

	a.setState(established)
	a.completeHandshake(nil)
}

// The caller should hold the lock.
func (a *Association) handleData(chunkPayload *chunkPayloadData) []*packet {
	a.log.Tracef("[%s] DATA: tsn=%d immediateSack=%v len=%d",
		a.name, chunkPayload.tsn, chunkPayload.immediateSack, len(chunkPayload.userData))
	a.stats.incDATAs()

	canPush := a.payloadQueue.canPush(chunkPayload.tsn)
	if canPush { //nolint:nestif
		stream := a.getOrCreateStream(chunkPayload.streamIdentifier, true, PayloadTypeUnknown)
		if stream == nil {
			// silently discard the data. (sender will retry on T3-rtx timeout)
			// see pion/sctp#30
			a.log.Debugf("[%s] discard %d", a.name, chunkPayload.streamSequenceNumber)

			return nil
		}

		if a.getMyReceiverWindowCredit() > 0 {
			// Pass the new chunk to stream level as soon as it arrives
			a.payloadQueue.push(chunkPayload.tsn)
			stream.handleData(chunkPayload)
		} else {
			// Receive buffer is full
			lastTSN, ok := a.payloadQueue.getLastTSNReceived()
			if ok && sna32LT(chunkPayload.tsn, lastTSN) {
				a.log.Debugf(
					"[%s] receive buffer full, but accepted as this is a missing chunk with tsn=%d ssn=%d",
					a.name, chunkPayload.tsn, chunkPayload.streamSequenceNumber,
				)
				a.payloadQueue.push(chunkPayload.tsn)
				stream.handleData(chunkPayload)
			} else {
				a.log.Debugf(
					"[%s] receive buffer full. dropping DATA with tsn=%d ssn=%d",
					a.name, chunkPayload.tsn, chunkPayload.streamSequenceNumber,
				)
			}
		}
	}

	// Upon the reception of a new DATA chunk, an endpoint shall examine the
	// continuity of the TSNs received.  If the endpoint detects a gap in
	// the received DATA chunk sequence, it SHOULD send a SACK with Gap Ack
	// Blocks immediately.  The data receiver continues sending a SACK after
	// receipt of each SCTP packet that doesn't fill the gap.
	//  https://datatracker.ietf.org/doc/html/rfc4960#section-6.7
	expectedTSN := a.peerLastTSN() + 1
	gapDetected := sna32GT(chunkPayload.tsn, expectedTSN)

	sackNow := chunkPayload.immediateSack || gapDetected

	return a.handlePeerLastTSNAndAcknowledgement(sackNow)
}

// A common routine for handleData and handleForwardTSN routines
// The caller should hold the lock.
func (a *Association) handlePeerLastTSNAndAcknowledgement(sackImmediately bool) []*packet { //nolint:cyclop
	var reply []*packet

	// Try to advance peerLastTSN

	// From RFC 3758 Sec 3.6:
	//   .. and then MUST further advance its cumulative TSN point locally
	//   if possible
	// Meaning, if peerLastTSN+1 points to a chunk that is received,
	// advance peerLastTSN until peerLastTSN+1 points to unreceived chunk.
	for {
		if popOk := a.payloadQueue.pop(false); !popOk {
			break
		}

		for _, rstReq := range a.reconfigRequests {
			resp := a.resetStreamsIfAny(rstReq)
			if resp != nil {
				a.log.Debugf("[%s] RESET RESPONSE: %+v", a.name, resp)
				reply = append(reply, resp)
			}
		}
	}

	hasPacketLoss := (a.payloadQueue.size() > 0)
	if hasPacketLoss {
		a.log.Tracef("[%s] packetloss: %s", a.name, a.payloadQueue.getGapAckBlocksString())
	}

	// RFC 4960 $6.7: SHOULD ack immediately when detecting a gap.
	if sackImmediately || hasPacketLoss || a.ackMode == ackModeNoDelay {
		a.immediateAckTriggered = true

		return reply
	}

	if a.ackMode == ackModeAlwaysDelay || (a.ackMode == ackModeNormal && a.ackState != ackStateImmediate) {
		if a.ackState == ackStateIdle {
			a.delayedAckTriggered = true
		} else {
			a.immediateAckTriggered = true
		}

		return reply
	}

	a.immediateAckTriggered = true

	return reply
}

// The caller should hold the lock.
func (a *Association) getMyReceiverWindowCredit() uint32 {
	var bytesQueued uint32
	for _, s := range a.streams {
		bytesQueued += uint32(s.getNumBytesInReassemblyQueue()) //nolint:gosec // G115
	}

	if bytesQueued >= a.maxReceiveBufferSize {
		return 0
	}

	return a.maxReceiveBufferSize - bytesQueued
}

// OpenStream opens a stream.
func (a *Association) OpenStream(
	streamIdentifier uint16,
	defaultPayloadType PayloadProtocolIdentifier,
) (*Stream, error) {
	a.lock.Lock()
	defer a.lock.Unlock()

	switch a.getState() {
	case shutdownAckSent, shutdownPending, shutdownReceived, shutdownSent, closed:
		return nil, ErrAssociationClosed
	}

	return a.getOrCreateStream(streamIdentifier, false, defaultPayloadType), nil
}

// AcceptStream accepts a stream.
func (a *Association) AcceptStream() (*Stream, error) {
	s, ok := <-a.acceptCh
	if !ok {
		return nil, io.EOF // no more incoming streams
	}

	return s, nil
}

// createStream creates a stream. The caller should hold the lock and check no stream exists for this id.
func (a *Association) createStream(streamIdentifier uint16, accept bool) *Stream {
	stream := &Stream{
		association:      a,
		streamIdentifier: streamIdentifier,
		reassemblyQueue:  newReassemblyQueue(streamIdentifier),
		log:              a.log,
		name:             fmt.Sprintf("%d:%s", streamIdentifier, a.name),
		writeDeadline:    deadline.New(),
	}

	stream.readNotifier = sync.NewCond(&stream.lock)

	if accept {
		select {
		case a.acceptCh <- stream:
			a.streams[streamIdentifier] = stream
			a.log.Debugf("[%s] accepted a new stream (streamIdentifier: %d)",
				a.name, streamIdentifier)
		default:
			a.log.Debugf("[%s] dropped a new stream (acceptCh size: %d)",
				a.name, len(a.acceptCh))

			return nil
		}
	} else {
		a.streams[streamIdentifier] = stream
	}

	return stream
}

// getOrCreateStream gets or creates a stream. The caller should hold the lock.
func (a *Association) getOrCreateStream(
	streamIdentifier uint16,
	accept bool,
	defaultPayloadType PayloadProtocolIdentifier,
) *Stream {
	if s, ok := a.streams[streamIdentifier]; ok {
		s.SetDefaultPayloadType(defaultPayloadType)

		return s
	}

	s := a.createStream(streamIdentifier, accept)
	if s != nil {
		s.SetDefaultPayloadType(defaultPayloadType)
	}

	return s
}

// The caller should hold the lock.
//
//nolint:gocognit,cyclop
func (a *Association) processSelectiveAck(selectiveAckChunk *chunkSelectiveAck) (
	bytesAckedPerStream map[uint16]int,
	htna uint32,
	newestDeliveredSendTime time.Time,
	newestDeliveredOrigTSN uint32,
	deliveredFound bool,
	err error,
) {
	bytesAckedPerStream = map[uint16]int{}
	now := time.Now() // capture the time for this SACK

	// New ack point, so pop all ACKed packets from inflightQueue
	// We add 1 because the "currentAckPoint" has already been popped from the inflight queue
	// For the first SACK we take care of this by setting the ackpoint to cumAck - 1
	for idx := a.cumulativeTSNAckPoint + 1; sna32LTE(idx, selectiveAckChunk.cumulativeTSNAck); idx++ {
		chunkPayload, ok := a.inflightQueue.pop(idx)
		if !ok {
			return nil, 0, time.Time{}, 0, false, fmt.Errorf("%w: %v", ErrInflightQueueTSNPop, idx)
		}

		// RACK: remove from xmit-time list since it's delivered
		a.rackRemove(chunkPayload)

		if !chunkPayload.acked { //nolint:nestif
			// RFC 4960 sec 6.3.2.  Retransmission Timer Rules
			//   R3)  Whenever a SACK is received that acknowledges the DATA chunk
			//        with the earliest outstanding TSN for that address, restart the
			//        T3-rtx timer for that address with its current RTO (if there is
			//        still outstanding data on that address).
			if idx == a.cumulativeTSNAckPoint+1 {
				// T3 timer needs to be reset. Stop it for now.
				a.t3RTX.stop()
			}

			nBytesAcked := len(chunkPayload.userData)

			// Sum the number of bytes acknowledged per stream
			if amount, ok := bytesAckedPerStream[chunkPayload.streamIdentifier]; ok {
				bytesAckedPerStream[chunkPayload.streamIdentifier] = amount + nBytesAcked
			} else {
				bytesAckedPerStream[chunkPayload.streamIdentifier] = nBytesAcked
			}

			// RFC 4960 sec 6.3.1.  RTO Calculation
			//   C4)  When data is in flight and when allowed by rule C5 below, a new
			//        RTT measurement MUST be made each round trip.  Furthermore, new
			//        RTT measurements SHOULD be made no more than once per round trip
			//        for a given destination transport address.
			//   C5)  Karn's algorithm: RTT measurements MUST NOT be made using
			//        packets that were retransmitted (and thus for which it is
			//        ambiguous whether the reply was for the first instance of the
			//        chunk or for a later instance)
			if sna32GTE(chunkPayload.tsn, a.minTSN2MeasureRTT) {
				// Only original transmissions for classic RTT measurement (Karn's rule)
				if chunkPayload.nSent == 1 {
					a.minTSN2MeasureRTT = a.myNextTSN
					rtt := now.Sub(chunkPayload.since).Seconds() * 1000.0
					srtt := a.rtoMgr.setNewRTT(rtt)
					a.srtt.Store(srtt)

					// use a window to determine minRtt instead of a global min
					// as the RTT can fluctuate, which can cause problems if going from a
					// high RTT to a low RTT.
					a.rackMinRTTWnd.Push(now, now.Sub(chunkPayload.since))

					a.log.Tracef("[%s] SACK: measured-rtt=%f srtt=%f new-rto=%f",
						a.name, rtt, srtt, a.rtoMgr.getRTO())
				}
			}

			// RFC 8985 (RACK) sec 5.2: RACK.segment is the most recently sent
			// segment that has been delivered, including retransmissions.
			if chunkPayload.since.After(newestDeliveredSendTime) {
				newestDeliveredSendTime = chunkPayload.since
				newestDeliveredOrigTSN = chunkPayload.tsn
				deliveredFound = true
			}
		}

		if a.inFastRecovery && chunkPayload.tsn == a.fastRecoverExitPoint {
			a.log.Debugf("[%s] exit fast-recovery", a.name)
			a.inFastRecovery = false
		}
	}

	htna = selectiveAckChunk.cumulativeTSNAck

	// Mark selectively acknowledged chunks as "acked"
	for _, g := range selectiveAckChunk.gapAckBlocks {
		for i := g.start; i <= g.end; i++ {
			tsn := selectiveAckChunk.cumulativeTSNAck + uint32(i)
			chunkPayload, ok := a.inflightQueue.get(tsn)
			if !ok {
				return nil, 0, time.Time{}, 0, false, fmt.Errorf("%w: %v", ErrTSNRequestNotExist, tsn)
			}

			// RACK: remove from xmit-time list since it's delivered
			a.rackRemove(chunkPayload)

			if !chunkPayload.acked { //nolint:nestif
				nBytesAcked := a.inflightQueue.markAsAcked(tsn)

				// Sum the number of bytes acknowledged per stream
				if amount, ok := bytesAckedPerStream[chunkPayload.streamIdentifier]; ok {
					bytesAckedPerStream[chunkPayload.streamIdentifier] = amount + nBytesAcked
				} else {
					bytesAckedPerStream[chunkPayload.streamIdentifier] = nBytesAcked
				}

				a.log.Tracef("[%s] tsn=%d has been sacked", a.name, chunkPayload.tsn)

				// RTT / RTO and RACK updates
				if sna32GTE(chunkPayload.tsn, a.minTSN2MeasureRTT) {
					// Only original transmissions for classic RTT measurement
					if chunkPayload.nSent == 1 {
						a.minTSN2MeasureRTT = a.myNextTSN
						rtt := now.Sub(chunkPayload.since).Seconds() * 1000.0
						srtt := a.rtoMgr.setNewRTT(rtt)
						a.srtt.Store(srtt)

						a.rackMinRTTWnd.Push(now, now.Sub(chunkPayload.since))

						a.log.Tracef("[%s] SACK: measured-rtt=%f srtt=%f new-rto=%f",
							a.name, rtt, srtt, a.rtoMgr.getRTO())
					}
				}

				if chunkPayload.since.After(newestDeliveredSendTime) {
					newestDeliveredSendTime = chunkPayload.since
					newestDeliveredOrigTSN = chunkPayload.tsn
					deliveredFound = true
				}
			}

			if sna32LT(htna, tsn) {
				htna = tsn
			}
		}
	}

	return bytesAckedPerStream, htna, newestDeliveredSendTime, newestDeliveredOrigTSN, deliveredFound, nil
}

// The caller should hold the lock.
func (a *Association) onCumulativeTSNAckPointAdvanced(totalBytesAcked int) {
	// RFC 4960, sec 6.3.2.  Retransmission Timer Rules
	//   R2)  Whenever all outstanding data sent to an address have been
	//        acknowledged, turn off the T3-rtx timer of that address.
	if a.inflightQueue.size() == 0 {
		a.log.Tracef("[%s] SACK: no more packet in-flight (pending=%d)", a.name, a.pendingQueue.size())
		a.t3RTX.stop()
		a.stopPTOTimer()
		a.stopRackTimer()
	} else {
		a.log.Tracef("[%s] T3-rtx timer start (pt2)", a.name)
		a.t3RTX.start(a.rtoMgr.getRTO())
	}

	// Update congestion control parameters
	if a.CWND() <= a.ssthresh { //nolint:nestif
		// RFC 4960, sec 7.2.1.  Slow-Start
		//   o  When cwnd is less than or equal to ssthresh, an SCTP endpoint MUST
		//		use the slow-start algorithm to increase cwnd only if the current
		//      congestion window is being fully utilized, an incoming SACK
		//      advances the Cumulative TSN Ack Point, and the data sender is not
		//      in Fast Recovery.  Only when these three conditions are met can
		//      the cwnd be increased; otherwise, the cwnd MUST not be increased.
		//		If these conditions are met, then cwnd MUST be increased by, at
		//      most, the lesser of 1) the total size of the previously
		//      outstanding DATA chunk(s) acknowledged, and 2) the destination's
		//      path MTU.
		if !a.inFastRecovery &&
			a.pendingQueue.size() > 0 {
			a.setCWND(a.CWND() + min32(uint32(totalBytesAcked), a.CWND())) //nolint:gosec // G115
			// a.cwnd += min32(uint32(totalBytesAcked), a.MTU()) // SCTP way (slow)
			a.log.Tracef("[%s] updated cwnd=%d ssthresh=%d acked=%d (SS)",
				a.name, a.CWND(), a.ssthresh, totalBytesAcked)
		} else {
			a.log.Tracef("[%s] cwnd did not grow: cwnd=%d ssthresh=%d acked=%d FR=%v pending=%d",
				a.name, a.CWND(), a.ssthresh, totalBytesAcked, a.inFastRecovery, a.pendingQueue.size())
		}
	} else {
		// RFC 4960, sec 7.2.2.  Congestion Avoidance
		//   o  Whenever cwnd is greater than ssthresh, upon each SACK arrival
		//      that advances the Cumulative TSN Ack Point, increase
		//      partial_bytes_acked by the total number of bytes of all new chunks
		//      acknowledged in that SACK including chunks acknowledged by the new
		//      Cumulative TSN Ack and by Gap Ack Blocks.
		a.partialBytesAcked += uint32(totalBytesAcked) //nolint:gosec // G115

		//   o  When partial_bytes_acked is equal to or greater than cwnd and
		//      before the arrival of the SACK the sender had cwnd or more bytes
		//      of data outstanding (i.e., before arrival of the SACK, flight size
		//      was greater than or equal to cwnd), increase cwnd by MTU, and
		//      reset partial_bytes_acked to (partial_bytes_acked - cwnd).
		if a.partialBytesAcked >= a.CWND() && a.pendingQueue.size() > 0 {
			a.partialBytesAcked -= a.CWND()
			step := max(a.MTU(), a.cwndCAStep)
			a.setCWND(a.CWND() + step)
			a.log.Tracef("[%s] updated cwnd=%d ssthresh=%d acked=%d (CA)",
				a.name, a.CWND(), a.ssthresh, totalBytesAcked)
		}
	}
}

// The caller should hold the lock.
//
//nolint:cyclop
func (a *Association) processFastRetransmission( //nolint:gocognit
	cumTSNAckPoint uint32,
	gapAckBlocks []gapAckBlock,
	htna uint32,
	cumTSNAckPointAdvanced bool,
) error {
	// HTNA algorithm - RFC 4960 Sec 7.2.4
	// Increment missIndicator of each chunks that the SACK reported missing
	// when either of the following is met:
	// a)  Not in fast-recovery
	//     miss indications are incremented only for missing TSNs prior to the
	//     highest TSN newly acknowledged in the SACK.
	// b)  In fast-recovery AND the Cumulative TSN Ack Point advanced
	//     the miss indications are incremented for all TSNs reported missing
	//     in the SACK.
	//nolint:nestif
	if !a.inFastRecovery ||
		(a.inFastRecovery && cumTSNAckPointAdvanced) {
		var maxTSN uint32
		if !a.inFastRecovery {
			// a) increment only for missing TSNs prior to the HTNA
			maxTSN = htna
		} else {
			// b) increment for all TSNs reported missing
			maxTSN = cumTSNAckPoint
			if len(gapAckBlocks) > 0 {
				maxTSN += uint32(gapAckBlocks[len(gapAckBlocks)-1].end)
			}
		}

		for tsn := cumTSNAckPoint + 1; sna32LT(tsn, maxTSN); tsn++ {
			c, ok := a.inflightQueue.get(tsn)
			if !ok {
				return fmt.Errorf("%w: %v", ErrTSNRequestNotExist, tsn)
			}
			if !c.acked && !c.abandoned() && c.missIndicator < 3 {
				c.missIndicator++
				if c.missIndicator == 3 {
					if a.tlrActive {
						a.tlrApplyAdditionalLossLocked(time.Now())
					}

					if !a.inFastRecovery {
						// 2)  If not in Fast Recovery, adjust the ssthresh and cwnd of the
						//     destination address(es) to which the missing DATA chunks were
						//     last sent, according to the formula described in Section 7.2.3.
						a.inFastRecovery = true
						a.fastRecoverExitPoint = htna
						a.ssthresh = max32(a.CWND()/2, 4*a.MTU())
						a.setCWND(a.ssthresh)
						a.partialBytesAcked = 0
						a.willRetransmitFast = true

						a.log.Tracef("[%s] updated cwnd=%d ssthresh=%d inflight=%d (FR)",
							a.name, a.CWND(), a.ssthresh, a.inflightQueue.getNumBytes())
					}
				}
			}
		}
	}

	if a.inFastRecovery && cumTSNAckPointAdvanced {
		a.willRetransmitFast = true
	}

	return nil
}

// The caller should hold the lock.
//
//nolint:cyclop
func (a *Association) handleSack(selectiveAckChunk *chunkSelectiveAck) error {
	a.log.Tracef(
		"[%s] SACK: cumTSN=%d a_rwnd=%d",
		a.name, selectiveAckChunk.cumulativeTSNAck, selectiveAckChunk.advertisedReceiverWindowCredit,
	)
	state := a.getState()
	if state != established && state != shutdownPending && state != shutdownReceived {
		return nil
	}

	a.stats.incSACKsReceived()

	if sna32GT(a.cumulativeTSNAckPoint, selectiveAckChunk.cumulativeTSNAck) {
		// RFC 4960 sec 6.2.1.  Processing a Received SACK
		// D)
		//   i) If Cumulative TSN Ack is less than the Cumulative TSN Ack
		//      Point, then drop the SACK.  Since Cumulative TSN Ack is
		//      monotonically increasing, a SACK whose Cumulative TSN Ack is
		//      less than the Cumulative TSN Ack Point indicates an out-of-
		//      order SACK.

		a.log.Debugf("[%s] SACK Cumulative ACK %v is older than ACK point %v",
			a.name,
			selectiveAckChunk.cumulativeTSNAck,
			a.cumulativeTSNAckPoint)

		return nil
	}

	// Process selective ack
	bytesAckedPerStream, htna,
		newestDeliveredSendTime, newestDeliveredOrigTSN,
		deliveredFound, err := a.processSelectiveAck(selectiveAckChunk)
	if err != nil {
		return err
	}

	var totalBytesAcked int
	for _, nBytesAcked := range bytesAckedPerStream {
		totalBytesAcked += nBytesAcked
	}

	cumTSNAckPointAdvanced := false
	if sna32LT(a.cumulativeTSNAckPoint, selectiveAckChunk.cumulativeTSNAck) {
		a.log.Tracef("[%s] SACK: cumTSN advanced: %d -> %d",
			a.name,
			a.cumulativeTSNAckPoint,
			selectiveAckChunk.cumulativeTSNAck)

		a.cumulativeTSNAckPoint = selectiveAckChunk.cumulativeTSNAck
		cumTSNAckPointAdvanced = true
		a.onCumulativeTSNAckPointAdvanced(totalBytesAcked)
	}

	for si, nBytesAcked := range bytesAckedPerStream {
		if s, ok := a.streams[si]; ok {
			a.lock.Unlock()
			s.onBufferReleased(nBytesAcked)
			a.lock.Lock()
		}
	}

	// New rwnd value
	// RFC 4960 sec 6.2.1.  Processing a Received SACK
	// D)
	//   ii) Set rwnd equal to the newly received a_rwnd minus the number
	//       of bytes still outstanding after processing the Cumulative
	//       TSN Ack and the Gap Ack Blocks.

	// bytes acked were already subtracted by markAsAcked() method
	bytesOutstanding := uint32(a.inflightQueue.getNumBytes()) //nolint:gosec // G115
	if bytesOutstanding >= selectiveAckChunk.advertisedReceiverWindowCredit {
		a.setRWND(0)
	} else {
		a.setRWND(selectiveAckChunk.advertisedReceiverWindowCredit - bytesOutstanding)
	}

	err = a.processFastRetransmission(
		selectiveAckChunk.cumulativeTSNAck, selectiveAckChunk.gapAckBlocks, htna, cumTSNAckPointAdvanced,
	)
	if err != nil {
		return err
	}

	if a.useForwardTSN {
		// RFC 3758 Sec 3.5 C1
		if sna32LT(a.advancedPeerTSNAckPoint, a.cumulativeTSNAckPoint) {
			a.advancedPeerTSNAckPoint = a.cumulativeTSNAckPoint
		}

		// RFC 3758 Sec 3.5 C2
		for i := a.advancedPeerTSNAckPoint + 1; ; i++ {
			c, ok := a.inflightQueue.get(i)
			if !ok {
				break
			}
			if !c.abandoned() {
				break
			}
			a.advancedPeerTSNAckPoint = i
		}

		// RFC 3758 Sec 3.5 C3
		if sna32GT(a.advancedPeerTSNAckPoint, a.cumulativeTSNAckPoint) {
			a.willSendForwardTSN = true
		}
		a.awakeWriteLoop()
	}

	a.postprocessSack(state, cumTSNAckPointAdvanced)

	// RACK
	a.onRackAfterSACK(deliveredFound, newestDeliveredSendTime, newestDeliveredOrigTSN, selectiveAckChunk)

	// adaptive burst mitigation
	ackProgress := cumTSNAckPointAdvanced || deliveredFound
	a.tlrMaybeFinishLocked(ackProgress)

	return nil
}

// The caller must hold the lock. This method was only added because the
// linter was complaining about the "cognitive complexity" of handleSack.
func (a *Association) postprocessSack(state uint32, shouldAwakeWriteLoop bool) {
	switch {
	case a.inflightQueue.size() > 0:
		// Start timer. (noop if already started)
		a.log.Tracef("[%s] T3-rtx timer start (pt3)", a.name)
		a.t3RTX.start(a.rtoMgr.getRTO())
	case state == shutdownPending:
		// No more outstanding, send shutdown.
		shouldAwakeWriteLoop = true
		a.willSendShutdown = true
		a.setState(shutdownSent)
	case state == shutdownReceived:
		// No more outstanding, send shutdown ack.
		shouldAwakeWriteLoop = true
		a.willSendShutdownAck = true
		a.setState(shutdownAckSent)
	}

	if shouldAwakeWriteLoop {
		a.awakeWriteLoop()
	}
}

// The caller should hold the lock.
func (a *Association) handleShutdown(_ *chunkShutdown) {
	state := a.getState()

	switch state {
	case established:
		if a.inflightQueue.size() > 0 {
			a.setState(shutdownReceived)
		} else {
			// No more outstanding, send shutdown ack.
			a.willSendShutdownAck = true
			a.setState(shutdownAckSent)

			a.awakeWriteLoop()
		}

		// a.cumulativeTSNAckPoint = c.cumulativeTSNAck
	case shutdownSent:
		a.willSendShutdownAck = true
		a.setState(shutdownAckSent)

		a.awakeWriteLoop()
	}
}

// The caller should hold the lock.
func (a *Association) handleShutdownAck(_ *chunkShutdownAck) {
	state := a.getState()
	if state == shutdownSent || state == shutdownAckSent {
		a.t2Shutdown.stop()
		a.willSendShutdownComplete = true

		a.awakeWriteLoop()
	}
}

func (a *Association) handleShutdownComplete(_ *chunkShutdownComplete) error {
	state := a.getState()
	if state == shutdownAckSent {
		a.t2Shutdown.stop()

		return a.close()
	}

	return nil
}

func (a *Association) handleAbort(c *chunkAbort) error {
	var errStr string
	for _, e := range c.errorCauses {
		errStr += fmt.Sprintf("(%s)", e)
	}

	_ = a.close()

	return fmt.Errorf("[%s] %w: %s", a.name, ErrChunk, errStr)
}

// createForwardTSN generates ForwardTSN chunk.
// This method will be be called if useForwardTSN is set to false.
// The caller should hold the lock.
func (a *Association) createForwardTSN() *chunkForwardTSN {
	// RFC 3758 Sec 3.5 C4
	streamMap := map[uint16]uint16{} // to report only once per SI
	for i := a.cumulativeTSNAckPoint + 1; sna32LTE(i, a.advancedPeerTSNAckPoint); i++ {
		c, ok := a.inflightQueue.get(i)
		if !ok {
			break
		}

		ssn, ok := streamMap[c.streamIdentifier]
		if !ok {
			streamMap[c.streamIdentifier] = c.streamSequenceNumber
		} else if sna16LT(ssn, c.streamSequenceNumber) {
			// to report only once with greatest SSN
			streamMap[c.streamIdentifier] = c.streamSequenceNumber
		}
	}

	fwdtsn := &chunkForwardTSN{
		newCumulativeTSN: a.advancedPeerTSNAckPoint,
		streams:          []chunkForwardTSNStream{},
	}

	var streamStr string
	for si, ssn := range streamMap {
		streamStr += fmt.Sprintf("(si=%d ssn=%d)", si, ssn)
		fwdtsn.streams = append(fwdtsn.streams, chunkForwardTSNStream{
			identifier: si,
			sequence:   ssn,
		})
	}
	a.log.Tracef(
		"[%s] building fwdtsn: newCumulativeTSN=%d cumTSN=%d - %s",
		a.name, fwdtsn.newCumulativeTSN, a.cumulativeTSNAckPoint, streamStr,
	)

	return fwdtsn
}

// createPacket wraps chunks in a packet.
// The caller should hold the read lock.
func (a *Association) createPacket(cs []chunk) *packet {
	return &packet{
		verificationTag: a.peerVerificationTag,
		sourcePort:      a.sourcePort,
		destinationPort: a.destinationPort,
		chunks:          cs,
	}
}

// The caller should hold the lock.
func (a *Association) handleReconfig(reconfigChunk *chunkReconfig) ([]*packet, error) {
	a.log.Tracef("[%s] handleReconfig", a.name)

	pp := make([]*packet, 0)

	pkt, err := a.handleReconfigParam(reconfigChunk.paramA)
	if err != nil {
		return nil, err
	}
	if pkt != nil {
		pp = append(pp, pkt)
	}

	if reconfigChunk.paramB != nil {
		pkt, err = a.handleReconfigParam(reconfigChunk.paramB)
		if err != nil {
			return nil, err
		}
		if pkt != nil {
			pp = append(pp, pkt)
		}
	}

	return pp, nil
}

// The caller should hold the lock.
func (a *Association) handleForwardTSN(chunkTSN *chunkForwardTSN) []*packet {
	a.log.Tracef("[%s] FwdTSN: %s", a.name, chunkTSN.String())

	if !a.useForwardTSN {
		a.log.Warn("[%s] received FwdTSN but not enabled")
		// Return an error chunk
		cerr := &chunkError{
			errorCauses: []errorCause{&errorCauseUnrecognizedChunkType{}},
		}
		outbound := &packet{}
		outbound.verificationTag = a.peerVerificationTag
		outbound.sourcePort = a.sourcePort
		outbound.destinationPort = a.destinationPort
		outbound.chunks = []chunk{cerr}

		return []*packet{outbound}
	}

	// From RFC 3758 Sec 3.6:
	//   Note, if the "New Cumulative TSN" value carried in the arrived
	//   FORWARD TSN chunk is found to be behind or at the current cumulative
	//   TSN point, the data receiver MUST treat this FORWARD TSN as out-of-
	//   date and MUST NOT update its Cumulative TSN.  The receiver SHOULD
	//   send a SACK to its peer (the sender of the FORWARD TSN) since such a
	//   duplicate may indicate the previous SACK was lost in the network.

	a.log.Tracef("[%s] should send ack? newCumTSN=%d peerLastTSN=%d",
		a.name, chunkTSN.newCumulativeTSN, a.peerLastTSN())
	if sna32LTE(chunkTSN.newCumulativeTSN, a.peerLastTSN()) {
		a.log.Tracef("[%s] sending ack on Forward TSN", a.name)
		a.ackState = ackStateImmediate
		a.ackTimer.stop()
		a.awakeWriteLoop()

		return nil
	}

	// From RFC 3758 Sec 3.6:
	//   the receiver MUST perform the same TSN handling, including duplicate
	//   detection, gap detection, SACK generation, cumulative TSN
	//   advancement, etc. as defined in RFC 2960 [2]---with the following
	//   exceptions and additions.

	//   When a FORWARD TSN chunk arrives, the data receiver MUST first update
	//   its cumulative TSN point to the value carried in the FORWARD TSN
	//   chunk,

	// Advance peerLastTSN
	for sna32LT(a.peerLastTSN(), chunkTSN.newCumulativeTSN) {
		a.payloadQueue.pop(true) // may not exist
	}

	// Report new peerLastTSN value and abandoned largest SSN value to
	// corresponding streams so that the abandoned chunks can be removed
	// from the reassemblyQueue.
	for _, forwarded := range chunkTSN.streams {
		if s, ok := a.streams[forwarded.identifier]; ok {
			s.handleForwardTSNForOrdered(forwarded.sequence)
		}
	}

	// TSN may be forewared for unordered chunks. ForwardTSN chunk does not
	// report which stream identifier it skipped for unordered chunks.
	// Therefore, we need to broadcast this event to all existing streams for
	// unordered chunks.
	// See https://github.com/pion/sctp/issues/106
	for _, s := range a.streams {
		s.handleForwardTSNForUnordered(chunkTSN.newCumulativeTSN)
	}

	return a.handlePeerLastTSNAndAcknowledgement(false)
}

func (a *Association) sendResetRequest(streamIdentifier uint16) error {
	a.lock.Lock()
	defer a.lock.Unlock()

	state := a.getState()
	if state != established {
		return fmt.Errorf("%w: state=%s", ErrResetPacketInStateNotExist,
			getAssociationStateString(state))
	}

	// Create DATA chunk which only contains valid stream identifier with
	// nil userData and use it as a EOS from the stream.
	c := &chunkPayloadData{
		streamIdentifier:  streamIdentifier,
		beginningFragment: true,
		endingFragment:    true,
		userData:          nil,
	}

	a.pendingQueue.push(c)
	a.awakeWriteLoop()

	return nil
}

// The caller should hold the lock.
func (a *Association) handleReconfigParam(raw param) (*packet, error) {
	switch par := raw.(type) {
	case *paramOutgoingResetRequest:
		a.log.Tracef("[%s] handleReconfigParam (OutgoingResetRequest)", a.name)
		if a.peerLastTSN() < par.senderLastTSN && len(a.reconfigRequests) >= maxReconfigRequests {
			// We have too many reconfig requests outstanding. Drop the request and let
			// the peer retransmit. A well behaved peer should only have 1 outstanding
			// reconfig request.
			//
			// RFC 6525: https://www.rfc-editor.org/rfc/rfc6525.html#section-5.1.1
			//    At any given time, there MUST NOT be more than one request in flight.
			//    So, if the Re-configuration Timer is running and the RE-CONFIG chunk
			//    contains at least one request parameter, the chunk MUST be buffered.
			// chrome:
			// https://chromium.googlesource.com/external/webrtc/+/refs/heads/main/net/dcsctp/socket/stream_reset_handler.cc#271
			return nil, fmt.Errorf("%w: %d", ErrTooManyReconfigRequests, len(a.reconfigRequests))
		}
		a.reconfigRequests[par.reconfigRequestSequenceNumber] = par
		resp := a.resetStreamsIfAny(par)
		if resp != nil {
			return resp, nil
		}

		return nil, nil //nolint:nilnil
	case *paramReconfigResponse:
		a.log.Tracef("[%s] handleReconfigParam (ReconfigResponse)", a.name)
		if par.result == reconfigResultInProgress {
			// RFC 6525: https://www.rfc-editor.org/rfc/rfc6525.html#section-5.2.7
			//
			//   If the Result field indicates "In progress", the timer for the
			//   Re-configuration Request Sequence Number is started again.  If
			//   the timer runs out, the RE-CONFIG chunk MUST be retransmitted
			//   but the corresponding error counters MUST NOT be incremented.
			if _, ok := a.reconfigs[par.reconfigResponseSequenceNumber]; ok {
				a.tReconfig.stop()
				a.tReconfig.start(a.rtoMgr.getRTO())
			}

			return nil, nil //nolint:nilnil
		}
		delete(a.reconfigs, par.reconfigResponseSequenceNumber)
		if len(a.reconfigs) == 0 {
			a.tReconfig.stop()
		}

		return nil, nil //nolint:nilnil
	default:
		return nil, fmt.Errorf("%w: %t", ErrParamterType, par)
	}
}

// The caller should hold the lock.
func (a *Association) resetStreamsIfAny(resetRequest *paramOutgoingResetRequest) *packet {
	result := reconfigResultSuccessPerformed
	if sna32LTE(resetRequest.senderLastTSN, a.peerLastTSN()) {
		a.log.Debugf("[%s] resetStream(): senderLastTSN=%d <= peerLastTSN=%d",
			a.name, resetRequest.senderLastTSN, a.peerLastTSN())
		for _, id := range resetRequest.streamIdentifiers {
			s, ok := a.streams[id]
			if !ok {
				continue
			}
			a.lock.Unlock()
			s.onInboundStreamReset()
			a.lock.Lock()
			a.log.Debugf("[%s] deleting stream %d", a.name, id)
			delete(a.streams, s.streamIdentifier)
		}
		delete(a.reconfigRequests, resetRequest.reconfigRequestSequenceNumber)
	} else {
		a.log.Debugf("[%s] resetStream(): senderLastTSN=%d > peerLastTSN=%d",
			a.name, resetRequest.senderLastTSN, a.peerLastTSN())
		result = reconfigResultInProgress
	}

	return a.createPacket([]chunk{&chunkReconfig{
		paramA: &paramReconfigResponse{
			reconfigResponseSequenceNumber: resetRequest.reconfigRequestSequenceNumber,
			result:                         result,
		},
	}})
}

// Move the chunk peeked with a.pendingQueue.peek() to the inflightQueue.
// The caller should hold the lock.
func (a *Association) movePendingDataChunkToInflightQueue(chunkPayload *chunkPayloadData) {
	if err := a.pendingQueue.pop(chunkPayload); err != nil {
		a.log.Errorf("[%s] failed to pop from pending queue: %s", a.name, err.Error())
	}

	if chunkPayload.endingFragment {
		chunkPayload.setAllInflight()
	}

	// Assign TSN and original send time
	chunkPayload.tsn = a.generateNextTSN()
	chunkPayload.since = time.Now()
	chunkPayload.nSent = 1

	a.checkPartialReliabilityStatus(chunkPayload)

	a.log.Tracef(
		"[%s] sending ppi=%d tsn=%d ssn=%d sent=%d len=%d (%v,%v)",
		a.name,
		chunkPayload.payloadType,
		chunkPayload.tsn,
		chunkPayload.streamSequenceNumber,
		chunkPayload.nSent,
		len(chunkPayload.userData),
		chunkPayload.beginningFragment,
		chunkPayload.endingFragment,
	)

	a.inflightQueue.pushNoCheck(chunkPayload)

	// RACK: track outstanding original transmissions by send time.
	a.rackInsert(chunkPayload)
}

// popPendingDataChunksToSend pops chunks from the pending queues as many as
// the cwnd and rwnd allows to send.
// The caller should hold the lock.
//
//nolint:cyclop
func (a *Association) popPendingDataChunksToSend( //nolint:cyclop,gocognit
	budgetScaled *int64,
	consumed *bool,
) ([]*chunkPayloadData, []uint16) {
	chunks := []*chunkPayloadData{}
	var sisToReset []uint16 // stream indentifiers to reset

	// track current packet size for MTU bundling so budgeting is accurate.
	bytesInPacket := 0

	if a.pendingQueue.size() > 0 { //nolint:nestif
		// RFC 4960 sec 6.1.  Transmission of DATA Chunks
		//   A) At any given time, the data sender MUST NOT transmit new data to
		//      any destination transport address if its peer's rwnd indicates
		//      that the peer has no buffer space (i.e., rwnd is 0; see Section
		//      6.2.1).  However, regardless of the value of rwnd (including if it
		//      is 0), the data sender can always have one DATA chunk in flight to
		//      the receiver if allowed by cwnd (see rule B, below).

		for {
			chunkPayload := a.pendingQueue.peek()
			if chunkPayload == nil {
				break // no more pending data
			}

			dataLen := uint32(len(chunkPayload.userData)) //nolint:gosec // G115
			if dataLen == 0 {
				sisToReset = append(sisToReset, chunkPayload.streamIdentifier)
				err := a.pendingQueue.pop(chunkPayload)
				if err != nil {
					a.log.Errorf("failed to pop from pending queue: %s", err.Error())
				}

				continue
			}

			if uint32(a.inflightQueue.getNumBytes())+dataLen > a.CWND() { //nolint:gosec // G115
				break // would exceeds cwnd
			}

			if dataLen > a.RWND() {
				break // no more rwnd
			}

			// compute current DATA chunk size including padding.
			chunkBytes := int(dataChunkHeaderSize) + len(chunkPayload.userData)
			chunkBytes += getPadding(chunkBytes)

			// ensure MTU bundling matches bundleDataChunksIntoPackets().
			addBytes := chunkBytes
			if bytesInPacket == 0 {
				addBytes += int(commonHeaderSize)
				if addBytes > int(a.MTU()) {
					break
				}

				// reserve budget for common header + first chunk.
				if !a.tlrAllowSendLocked(budgetScaled, consumed, addBytes) {
					break
				}

				bytesInPacket = int(commonHeaderSize)
			} else {
				// if it doesn't fit, start a new packet and retry same chunk.
				if bytesInPacket+chunkBytes > int(a.MTU()) {
					bytesInPacket = 0

					continue
				}

				// reserve budget for the additional chunk bytes.
				if !a.tlrAllowSendLocked(budgetScaled, consumed, chunkBytes) {
					break
				}
			}

			a.setRWND(a.RWND() - dataLen)

			a.movePendingDataChunkToInflightQueue(chunkPayload)
			chunks = append(chunks, chunkPayload)
			bytesInPacket += chunkBytes
		}

		// allow one DATA chunk if nothing is inflight to the receiver.
		if len(chunks) == 0 && a.inflightQueue.size() == 0 {
			// Send zero window probe
			c := a.pendingQueue.peek()
			if c != nil && len(c.userData) > 0 {
				// probe is a new packet: common header + chunk bytes.
				chunkBytes := int(dataChunkHeaderSize) + len(c.userData)
				chunkBytes += getPadding(chunkBytes)
				addBytes := int(commonHeaderSize) + chunkBytes

				if addBytes <= int(a.MTU()) && a.tlrAllowSendLocked(budgetScaled, consumed, addBytes) {
					a.movePendingDataChunkToInflightQueue(c)
					chunks = append(chunks, c)
				}
			}
		}
	}

	if a.blockWrite && len(chunks) > 0 && a.pendingQueue.size() == 0 {
		a.log.Tracef("[%s] all pending data have been sent, notify writable", a.name)
		a.notifyBlockWritable()
	}

	return chunks, sisToReset
}

// bundleDataChunksIntoPackets packs DATA chunks into packets. It tries to bundle
// DATA chunks into a packet so long as the resulting packet size does not exceed
// the path MTU.
// The caller should hold the lock.
func (a *Association) bundleDataChunksIntoPackets(chunks []*chunkPayloadData) []*packet {
	packets := []*packet{}
	chunksToSend := []chunk{}
	bytesInPacket := int(commonHeaderSize)

	for _, chunkPayload := range chunks {
		// RFC 4960 sec 6.1.  Transmission of DATA Chunks
		//   Multiple DATA chunks committed for transmission MAY be bundled in a
		//   single packet.  Furthermore, DATA chunks being retransmitted MAY be
		//   bundled with new DATA chunks, as long as the resulting packet size
		//   does not exceed the path MTU.
		chunkSizeInPacket := int(dataChunkHeaderSize) + len(chunkPayload.userData)
		chunkSizeInPacket += getPadding(chunkSizeInPacket)
		if bytesInPacket+chunkSizeInPacket > int(a.MTU()) {
			packets = append(packets, a.createPacket(chunksToSend))
			chunksToSend = []chunk{}
			bytesInPacket = int(commonHeaderSize)
		}
		chunksToSend = append(chunksToSend, chunkPayload)
		bytesInPacket += chunkSizeInPacket
	}

	if len(chunksToSend) > 0 {
		packets = append(packets, a.createPacket(chunksToSend))
	}

	return packets
}

// sendPayloadData sends the data chunks.
func (a *Association) sendPayloadData(ctx context.Context, chunks []*chunkPayloadData) error {
	a.lock.Lock()

	state := a.getState()
	if state != established {
		a.lock.Unlock()

		return fmt.Errorf("%w: state=%s", ErrPayloadDataStateNotExist,
			getAssociationStateString(state))
	}

	if a.blockWrite {
		for a.writePending {
			a.lock.Unlock()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-a.writeNotify:
				a.lock.Lock()
			}
		}
		a.writePending = true
	}

	// Push the chunks into the pending queue first.
	for _, c := range chunks {
		a.pendingQueue.push(c)
	}

	a.lock.Unlock()
	a.awakeWriteLoop()

	return nil
}

// The caller should hold the lock.
func (a *Association) checkPartialReliabilityStatus(chunkPayload *chunkPayloadData) {
	if !a.useForwardTSN {
		return
	}

	// draft-ietf-rtcweb-data-protocol-09.txt section 6
	//	6.  Procedures
	//		All Data Channel Establishment Protocol messages MUST be sent using
	//		ordered delivery and reliable transmission.
	//
	if chunkPayload.payloadType == PayloadTypeWebRTCDCEP {
		return
	}

	// PR-SCTP
	if stream, ok := a.streams[chunkPayload.streamIdentifier]; ok { //nolint:nestif
		stream.lock.RLock()
		if stream.reliabilityType == ReliabilityTypeRexmit {
			if chunkPayload.nSent >= stream.reliabilityValue {
				chunkPayload.setAbandoned(true)
				a.rackRemove(chunkPayload)
				a.log.Tracef(
					"[%s] marked as abandoned: tsn=%d ppi=%d (remix: %d)",
					a.name, chunkPayload.tsn, chunkPayload.payloadType, chunkPayload.nSent,
				)
			}
		} else if stream.reliabilityType == ReliabilityTypeTimed {
			elapsed := int64(time.Since(chunkPayload.since).Seconds() * 1000)
			if elapsed >= int64(stream.reliabilityValue) {
				chunkPayload.setAbandoned(true)
				a.rackRemove(chunkPayload)
				a.log.Tracef(
					"[%s] marked as abandoned: tsn=%d ppi=%d (timed: %d)",
					a.name, chunkPayload.tsn, chunkPayload.payloadType, elapsed,
				)
			}
		}
		stream.lock.RUnlock()
	} else {
		// Remote has reset its send side of the stream, we can still send data.
		a.log.Tracef("[%s] stream %d not found, remote reset", a.name, chunkPayload.streamIdentifier)
	}
}

// getDataPacketsToRetransmit is called when T3-rtx is timed out and retransmit outstanding data chunks
// that are not acked or abandoned yet.
// The caller should hold the lock.
func (a *Association) getDataPacketsToRetransmit(budgetScaled *int64, consumed *bool) []*packet { //nolint:cyclop
	awnd := min32(a.CWND(), a.RWND())
	chunks := []*chunkPayloadData{}
	var bytesToSend int
	currRtxTimestamp := time.Now()

	bytesInPacket := 0

	for i := 0; ; i++ {
		chunkPayload, ok := a.inflightQueue.get(a.cumulativeTSNAckPoint + uint32(i) + 1) //nolint:gosec // G115
		if !ok {
			break // end of pending data
		}

		if !chunkPayload.retransmit {
			continue
		}

		if i == 0 && int(a.RWND()) < len(chunkPayload.userData) {
			// allow as zero window probe
		} else if bytesToSend+len(chunkPayload.userData) > int(awnd) {
			break
		}

		chunkBytes := int(dataChunkHeaderSize) + len(chunkPayload.userData)
		chunkBytes += getPadding(chunkBytes)

		// retry as first chunk in a new packet if needed.
		for {
			addBytes := chunkBytes
			if bytesInPacket == 0 {
				addBytes += int(commonHeaderSize)
				if addBytes > int(a.MTU()) {
					return a.bundleDataChunksIntoPackets(chunks)
				}
			} else if bytesInPacket+chunkBytes > int(a.MTU()) {
				bytesInPacket = 0

				continue
			}

			// burst budget gate before mutating the chunk.
			if !a.tlrAllowSendLocked(budgetScaled, consumed, addBytes) {
				return a.bundleDataChunksIntoPackets(chunks)
			}

			if bytesInPacket == 0 {
				bytesInPacket = int(commonHeaderSize)
			}
			bytesInPacket += chunkBytes

			break
		}

		chunkPayload.retransmit = false
		bytesToSend += len(chunkPayload.userData)

		// Update for retransmission
		chunkPayload.nSent++
		chunkPayload.since = currRtxTimestamp
		a.rackRemove(chunkPayload)
		a.rackInsert(chunkPayload)

		a.checkPartialReliabilityStatus(chunkPayload)

		a.log.Tracef(
			"[%s] retransmitting tsn=%d ssn=%d sent=%d",
			a.name, chunkPayload.tsn, chunkPayload.streamSequenceNumber, chunkPayload.nSent,
		)

		chunks = append(chunks, chunkPayload)
	}

	return a.bundleDataChunksIntoPackets(chunks)
}

// generateNextTSN returns the myNextTSN and increases it. The caller should hold the lock.
// The caller should hold the lock.
func (a *Association) generateNextTSN() uint32 {
	tsn := a.myNextTSN
	a.myNextTSN++

	return tsn
}

// generateNextRSN returns the myNextRSN and increases it. The caller should hold the lock.
// The caller should hold the lock.
func (a *Association) generateNextRSN() uint32 {
	rsn := a.myNextRSN
	a.myNextRSN++

	return rsn
}

func (a *Association) createSelectiveAckChunk() *chunkSelectiveAck {
	sack := &chunkSelectiveAck{}
	sack.cumulativeTSNAck = a.peerLastTSN()
	sack.advertisedReceiverWindowCredit = a.getMyReceiverWindowCredit()
	sack.duplicateTSN = a.payloadQueue.popDuplicates()
	sack.gapAckBlocks = a.payloadQueue.getGapAckBlocks()

	return sack
}

func pack(p *packet) []*packet {
	return []*packet{p}
}

func (a *Association) handleChunksStart() {
	a.lock.Lock()
	defer a.lock.Unlock()

	a.stats.incPacketsReceived()

	a.delayedAckTriggered = false
	a.immediateAckTriggered = false
}

func (a *Association) handleChunksEnd() {
	a.lock.Lock()
	defer a.lock.Unlock()

	if a.immediateAckTriggered {
		a.ackState = ackStateImmediate
		a.ackTimer.stop()
		a.awakeWriteLoop()
	} else if a.delayedAckTriggered {
		// Will send delayed ack in the next ack timeout
		a.ackState = ackStateDelay
		a.ackTimer.start()
	}
}

func (a *Association) handleChunk(receivedPacket *packet, receivedChunk chunk) error { //nolint:cyclop
	a.lock.Lock()
	defer a.lock.Unlock()

	var packets []*packet
	var err error

	if _, err = receivedChunk.check(); err != nil {
		a.log.Errorf("[%s] failed validating chunk: %s ", a.name, err)

		return nil
	}

	isAbort := false

	switch receivedChunk := receivedChunk.(type) {
	// Note: We do not do the following for chunkInit, chunkInitAck, and chunkCookieEcho:
	// If an endpoint receives an INIT, INIT ACK, or COOKIE ECHO chunk but decides not to establish the
	// new association due to missing mandatory parameters in the received INIT or INIT ACK chunk, invalid
	// parameter values, or lack of local resources, it SHOULD respond with an ABORT chunk.

	case *chunkInit:
		packets, err = a.handleInit(receivedPacket, receivedChunk)

	case *chunkInitAck:
		err = a.handleInitAck(receivedPacket, receivedChunk)

	case *chunkAbort:
		isAbort = true
		err = a.handleAbort(receivedChunk)

	case *chunkError:
		var errStr string
		for _, e := range receivedChunk.errorCauses {
			errStr += fmt.Sprintf("(%s)", e)
		}
		a.log.Debugf("[%s] Error chunk, with following errors: %s", a.name, errStr)

	case *chunkHeartbeat:
		packets = a.handleHeartbeat(receivedChunk)

	case *chunkHeartbeatAck:
		a.handleHeartbeatAck(receivedChunk)

	case *chunkCookieEcho:
		packets = a.handleCookieEcho(receivedChunk)

	case *chunkCookieAck:
		a.handleCookieAck()

	case *chunkPayloadData:
		packets = a.handleData(receivedChunk)

	case *chunkSelectiveAck:
		err = a.handleSack(receivedChunk)

	case *chunkReconfig:
		packets, err = a.handleReconfig(receivedChunk)

	case *chunkForwardTSN:
		packets = a.handleForwardTSN(receivedChunk)

	case *chunkShutdown:
		a.handleShutdown(receivedChunk)
	case *chunkShutdownAck:
		a.handleShutdownAck(receivedChunk)
	case *chunkShutdownComplete:
		err = a.handleShutdownComplete(receivedChunk)

	default:
		err = ErrChunkTypeUnhandled
	}

	// Log and return, the only condition that is fatal is a ABORT chunk
	if err != nil {
		if isAbort {
			return err
		}

		a.log.Errorf("Failed to handle chunk: %v", err)

		return nil
	}

	if len(packets) > 0 {
		a.controlQueue.pushAll(packets)
		a.awakeWriteLoop()
	}

	return nil
}

func (a *Association) onRetransmissionTimeout(id int, nRtos uint) { //nolint:cyclop
	a.lock.Lock()
	defer a.lock.Unlock()

	if id == timerT1Init {
		err := a.sendInit()
		if err != nil {
			a.log.Debugf("[%s] failed to retransmit init (nRtos=%d): %v", a.name, nRtos, err)
		}

		return
	}

	if id == timerT1Cookie {
		err := a.sendCookieEcho()
		if err != nil {
			a.log.Debugf("[%s] failed to retransmit cookie-echo (nRtos=%d): %v", a.name, nRtos, err)
		}

		return
	}

	if id == timerT2Shutdown {
		a.log.Debugf("[%s] retransmission of shutdown timeout (nRtos=%d): %v", a.name, nRtos)
		state := a.getState()

		switch state {
		case shutdownSent:
			a.willSendShutdown = true
			a.awakeWriteLoop()
		case shutdownAckSent:
			a.willSendShutdownAck = true
			a.awakeWriteLoop()
		}
	}

	if id == timerT3RTX { //nolint:nestif
		a.stats.incT3Timeouts()

		// RFC 4960 sec 6.3.3
		//  E1)  For the destination address for which the timer expires, adjust
		//       its ssthresh with rules defined in Section 7.2.3 and set the
		//       cwnd <- MTU.
		// RFC 4960 sec 7.2.3
		//   When the T3-rtx timer expires on an address, SCTP should perform slow
		//   start by:
		//      ssthresh = max(cwnd/2, 4*MTU)
		//      cwnd = 1*MTU

		a.ssthresh = max32(a.CWND()/2, 4*a.MTU())
		a.setCWND(a.MTU())
		a.log.Tracef("[%s] updated cwnd=%d ssthresh=%d inflight=%d (RTO)",
			a.name, a.CWND(), a.ssthresh, a.inflightQueue.getNumBytes())
		// If not in Fast Recovery, enter Fast Recovery and mark the highest outstanding TSN as the Fast Recovery exit point.
		// When a SACK acknowledges all TSNs up to and including this exit point, Fast Recovery is exited.
		// https://www.rfc-editor.org/rfc/rfc4960#section-7.2.4
		// https://www.rfc-editor.org/rfc/rfc9260.html#section-7.2.4
		if a.inFastRecovery {
			a.inFastRecovery = false
			a.willRetransmitFast = false
			a.fastRecoverExitPoint = 0
			a.partialBytesAcked = 0
			a.log.Debugf("[%s] exit fast-recovery (RTO)", a.name)
		}

		// RFC 3758 sec 3.5
		//  A5) Any time the T3-rtx timer expires, on any destination, the sender
		//  SHOULD try to advance the "Advanced.Peer.Ack.Point" by following
		//  the procedures outlined in C2 - C5.
		if a.useForwardTSN {
			// RFC 3758 Sec 3.5 C2
			for i := a.advancedPeerTSNAckPoint + 1; ; i++ {
				c, ok := a.inflightQueue.get(i)
				if !ok {
					break
				}
				if !c.abandoned() {
					break
				}
				a.advancedPeerTSNAckPoint = i
			}

			// RFC 3758 Sec 3.5 C3
			if sna32GT(a.advancedPeerTSNAckPoint, a.cumulativeTSNAckPoint) {
				a.willSendForwardTSN = true
			}
		}

		a.log.Debugf("[%s] T3-rtx timed out: nRtos=%d cwnd=%d ssthresh=%d", a.name, nRtos, a.CWND(), a.ssthresh)

		/*
			a.log.Debugf("   - advancedPeerTSNAckPoint=%d", a.advancedPeerTSNAckPoint)
			a.log.Debugf("   - cumulativeTSNAckPoint=%d", a.cumulativeTSNAckPoint)
			a.inflightQueue.updateSortedKeys()
			for i, tsn := range a.inflightQueue.sorted {
				if c, ok := a.inflightQueue.get(tsn); ok {
					a.log.Debugf("   - [%d] tsn=%d acked=%v abandoned=%v (%v,%v) len=%d",
						i, c.tsn, c.acked, c.abandoned(), c.beginningFragment, c.endingFragment, len(c.userData))
				}
			}
		*/

		a.inflightQueue.markAllToRetrasmit()
		a.awakeWriteLoop()

		return
	}

	if id == timerReconfig {
		a.willRetransmitReconfig = true
		a.awakeWriteLoop()
	}
}

func (a *Association) onRetransmissionFailure(id int) {
	a.lock.Lock()
	defer a.lock.Unlock()

	if id == timerT1Init {
		a.log.Errorf("[%s] retransmission failure: T1-init", a.name)
		a.completeHandshake(ErrHandshakeInitAck)

		return
	}

	if id == timerT1Cookie {
		a.log.Errorf("[%s] retransmission failure: T1-cookie", a.name)
		a.completeHandshake(ErrHandshakeCookieEcho)

		return
	}

	if id == timerT2Shutdown {
		a.log.Errorf("[%s] retransmission failure: T2-shutdown", a.name)

		return
	}

	if id == timerT3RTX {
		// T3-rtx timer will not fail by design
		// Justifications:
		//  * ICE would fail if the connectivity is lost
		//  * WebRTC spec is not clear how this incident should be reported to ULP
		a.log.Errorf("[%s] retransmission failure: T3-rtx (DATA)", a.name)

		return
	}
}

func (a *Association) onAckTimeout() {
	a.lock.Lock()
	defer a.lock.Unlock()

	a.log.Tracef("[%s] ack timed out (ackState: %d)", a.name, a.ackState)
	a.stats.incAckTimeouts()

	a.ackState = ackStateImmediate
	a.awakeWriteLoop()
}

// BufferedAmount returns total amount (in bytes) of currently buffered user data.
func (a *Association) BufferedAmount() int {
	a.lock.RLock()
	defer a.lock.RUnlock()

	return a.pendingQueue.getNumBytes() + a.inflightQueue.getNumBytes()
}

// MaxMessageSize returns the maximum message size you can send.
func (a *Association) MaxMessageSize() uint32 {
	return atomic.LoadUint32(&a.maxMessageSize)
}

// SetMaxMessageSize sets the maximum message size you can send.
func (a *Association) SetMaxMessageSize(maxMsgSize uint32) {
	atomic.StoreUint32(&a.maxMessageSize, maxMsgSize)
}

// completeHandshake sends the given error to  handshakeCompletedCh unless the read/write
// side of the association closes before that can happen. It returns whether it was able
// to send on the channel or not.
func (a *Association) completeHandshake(handshakeErr error) bool {
	select {
	// Note: This is a future place where the user could be notified (COMMUNICATION UP)
	case a.handshakeCompletedCh <- handshakeErr:
		return true
	case <-a.closeWriteLoopCh: // check the read/write sides for closure
	case <-a.readLoopCloseCh:
	}

	return false
}

func (a *Association) pokeTimerLoop() {
	// enqueue a single wake-up without blocking.
	select {
	case a.timerUpdateCh <- struct{}{}:
	default:
	}
}

func (a *Association) startRackTimer(dur time.Duration) {
	a.timerMu.Lock()

	if dur <= 0 {
		a.rackDeadline = time.Time{}
	} else {
		a.rackDeadline = time.Now().Add(dur)
	}

	a.timerMu.Unlock()

	a.pokeTimerLoop()
}

func (a *Association) stopRackTimer() {
	a.timerMu.Lock()
	a.rackDeadline = time.Time{}
	a.timerMu.Unlock()

	a.pokeTimerLoop()
}

func (a *Association) startPTOTimer(dur time.Duration) {
	a.timerMu.Lock()

	if dur <= 0 {
		a.ptoDeadline = time.Time{}
	} else {
		a.ptoDeadline = time.Now().Add(dur)
	}

	a.timerMu.Unlock()

	a.pokeTimerLoop()
}

func (a *Association) stopPTOTimer() {
	a.timerMu.Lock()
	a.ptoDeadline = time.Time{}
	a.timerMu.Unlock()

	a.pokeTimerLoop()
}

// drainTimer safely stops a timer and drains its channel if needed.
func drainTimer(t *time.Timer) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
}

// timerLoop runs one goroutine per association for RACK and PTO deadlines.
// this only runs if RACK is enabled.
func (a *Association) timerLoop() { //nolint:gocognit,cyclop
	// begin with a disarmed timer.
	timer := time.NewTimer(time.Hour)
	drainTimer(timer)
	armed := false

	for {
		// compute the earliest non-zero deadline.
		a.timerMu.Lock()
		rackDeadline := a.rackDeadline
		ptoDeadline := a.ptoDeadline
		a.timerMu.Unlock()

		var next time.Time
		switch {
		case rackDeadline.IsZero():
			next = ptoDeadline
		case ptoDeadline.IsZero():
			next = rackDeadline
		default:
			if rackDeadline.Before(ptoDeadline) {
				next = rackDeadline
			} else {
				next = ptoDeadline
			}
		}

		if next.IsZero() {
			if armed {
				drainTimer(timer)
				armed = false
			}
		} else {
			d := time.Until(next)

			if d <= 0 {
				d = time.Nanosecond
			}

			if armed {
				drainTimer(timer)
			}

			timer.Reset(d)
			armed = true
		}

		select {
		case <-a.closeWriteLoopCh:
			if armed {
				drainTimer(timer)
			}

			return

		case <-a.timerUpdateCh:
			// re-compute deadlines and (re)arm in next loop iteration.

		case <-timer.C:
			armed = false

			// snapshot & clear due deadlines before firing to avoid races with re-arms.
			currTime := time.Now()
			var fireRack, firePTO bool

			a.timerMu.Lock()

			if !a.rackDeadline.IsZero() && !currTime.Before(a.rackDeadline) {
				fireRack = true
				a.rackDeadline = time.Time{}
			}

			if !a.ptoDeadline.IsZero() && !currTime.Before(a.ptoDeadline) {
				firePTO = true
				a.ptoDeadline = time.Time{}
			}

			a.timerMu.Unlock()

			// fire callbacks without holding timerMu.
			if fireRack {
				a.onRackTimeout()
			}

			if firePTO {
				a.onPTOTimer()
			}
		}
	}
}

// onRackAfterSACK implements the RACK logic (RACK for SCTP section 2A/B, section 3) and TLP scheduling (section 2C).
func (a *Association) onRackAfterSACK( // nolint:gocognit,cyclop,gocyclo
	deliveredFound bool,
	newestDeliveredSendTime time.Time,
	newestDeliveredOrigTSN uint32,
	sack *chunkSelectiveAck,
) {
	// store the current time for when we check if it's needed in step 2 (whether we should maintain ReoWND)
	currTime := time.Now()

	// 1) Update highest delivered original TSN for reordering detection (section 2B)
	if deliveredFound {
		if sna32LT(a.rackHighestDeliveredOrigTSN, newestDeliveredOrigTSN) {
			a.rackHighestDeliveredOrigTSN = newestDeliveredOrigTSN
		} else {
			// ACK of an original TSN below the high-watermark -> reordering observed
			a.rackReorderingSeen = true
		}
		if newestDeliveredSendTime.After(a.rackDeliveredTime) {
			a.rackDeliveredTime = newestDeliveredSendTime
		}
	}

	// 2) Maintain ReoWND (RACK for SCTP section 2B)
	if minRTT := a.rackMinRTTWnd.Min(currTime); minRTT > 0 {
		a.rackMinRTT = minRTT
	}

	var base time.Duration
	if a.rackMinRTT > 0 {
		base = max(a.rackMinRTT/4, a.rackReoWndFloor)
	}

	// Suppress during recovery if no reordering ever seen; else (re)initialize from base if zero.
	if !a.rackReorderingSeen && (a.inFastRecovery || a.t3RTX.isRunning()) {
		a.rackReoWnd = 0
	} else if a.rackReoWnd == 0 && base > 0 {
		a.rackReoWnd = base
	}

	// DSACK-style inflation using SCTP duplicate TSNs (RACK for SCTP section 3 noting SCTP
	// natively reports duplicates + RACK for SCTP section 2B policy)
	if len(sack.duplicateTSN) > 0 && a.rackMinRTT > 0 {
		a.rackReoWnd += max(a.rackMinRTT/4, a.rackReoWndFloor)
		// keep inflated for 16 loss recoveries before reset
		a.rackKeepInflatedRecoveries = 16
		a.log.Tracef("[%s] RACK: DSACK/dupTSN seen, inflate reoWnd to %v", a.name, a.rackReoWnd)
	}

	// decrement the keep inflated counter when we leave recovery
	if !a.inFastRecovery && a.rackKeepInflatedRecoveries > 0 {
		a.rackKeepInflatedRecoveries--
		if a.rackKeepInflatedRecoveries == 0 && a.rackMinRTT > 0 {
			a.rackReoWnd = a.rackMinRTT / 4
		}
	}

	// RFC 8985: the reordering window MUST be bounded by SRTT.
	if srttMs := a.SRTT(); srttMs > 0 {
		if srttDur := time.Duration(srttMs * 1e6); a.rackReoWnd > srttDur {
			a.rackReoWnd = srttDur
		}
	}

	// 3) Loss marking on ACK: any outstanding chunk whose (send_time + reoWnd) < newestDeliveredSendTime
	// is lost (RACK for SCTP section 2A)
	if !a.rackDeliveredTime.IsZero() { //nolint:nestif
		marked := false

		for chunk := a.rackHead; chunk != nil; {
			next := chunk.rackNext // save in case we remove c

			// but clean up if they exist.
			if chunk.acked || chunk.abandoned() {
				a.rackRemove(chunk)
				chunk = next

				continue
			}

			if chunk.retransmit || chunk.nSent > 1 {
				// Either already scheduled for retransmit or not an original send:
				// skip but keep in list in case it's still outstanding.
				chunk = next

				continue
			}

			// Ordered by original send time. If this one is too new,
			// all later ones are even newer -> short-circuit.
			if !chunk.since.Add(a.rackReoWnd).Before(a.rackDeliveredTime) {
				break
			}

			// Mark as lost by RACK.
			chunk.retransmit = true
			marked = true

			// Remove from xmit-time list: we no longer need RACK for this TSN.
			a.rackRemove(chunk)

			a.log.Tracef("[%s] RACK: mark lost tsn=%d (sent=%v, delivered=%v, reoWnd=%v)",
				a.name, chunk.tsn, chunk.since, a.rackDeliveredTime, a.rackReoWnd)

			chunk = next
		}

		if marked {
			// loss detected during active TLR so we must reduce burst
			if a.tlrActive {
				a.tlrApplyAdditionalLossLocked(currTime)
			}

			a.awakeWriteLoop()
		}
	}

	// 4) Arm the RACK timer if there are still outstanding but not-yet-overdue chunks (RACK for SCTP section 2A)
	if a.rackHead != nil && !a.rackDeliveredTime.IsZero() {
		// RackRTT = RTT of the most recently delivered packet
		rackRTT := max(time.Since(a.rackDeliveredTime), time.Duration(0))
		a.startRackTimer(rackRTT + a.rackReoWnd) // RACK for SCTP section 2A
	} else {
		a.stopRackTimer()
	}

	// 5) Re/schedule Tail Loss Probe (PTO) (RACK for SCTP section 2C)
	// Triggered when new data is sent or cum-ack advances; we approximate by scheduling on every SACK that advanced
	if a.inflightQueue.size() == 0 {
		a.stopPTOTimer()

		return
	}

	var pto time.Duration
	srttMs := a.SRTT()
	if srttMs > 0 {
		srtt := time.Duration(srttMs * 1e6)
		extra := 2 * time.Millisecond

		if a.inflightQueue.size() == 1 {
			extra = a.rackWCDelAck // 200ms for single outstanding, else 2ms
		}

		pto = 2*srtt + extra
	} else {
		pto = time.Second // no RTT yet
	}

	a.startPTOTimer(pto)
}

// schedulePTOAfterSendLocked starts/restarts the PTO timer when new data is transmitted.
// Caller must hold a.lock.
func (a *Association) schedulePTOAfterSendLocked() {
	if a.inflightQueue.size() == 0 {
		a.stopPTOTimer()

		return
	}

	var pto time.Duration
	if srttMs := a.SRTT(); srttMs > 0 {
		srtt := time.Duration(srttMs * 1e6)
		extra := 2 * time.Millisecond

		if a.inflightQueue.size() == 1 {
			extra = a.rackWCDelAck
		}

		pto = 2*srtt + extra
	} else {
		pto = time.Second
	}

	a.startPTOTimer(pto)
}

// onRackTimeout is fired to avoid waiting for the next ACK.
func (a *Association) onRackTimeout() {
	a.lock.Lock()
	defer a.lock.Unlock()
	a.onRackTimeoutLocked()
}

func (a *Association) onRackTimeoutLocked() { //nolint:cyclop
	if a.rackDeliveredTime.IsZero() {
		return
	}

	marked := false

	for chunk := a.rackHead; chunk != nil; {
		next := chunk.rackNext

		if chunk.acked || chunk.abandoned() {
			a.rackRemove(chunk)
			chunk = next

			continue
		}
		if chunk.retransmit || chunk.nSent > 1 {
			chunk = next

			continue
		}

		if !chunk.since.Add(a.rackReoWnd).Before(a.rackDeliveredTime) {
			// too new, later ones are newer so we can skip.
			break
		}

		chunk.retransmit = true
		marked = true
		a.rackRemove(chunk)

		a.log.Tracef("[%s] RACK timer: mark lost tsn=%d", a.name, chunk.tsn)

		chunk = next
	}

	if marked {
		// loss detected during active TLR so we must reduce burst
		if a.tlrActive {
			a.tlrApplyAdditionalLossLocked(time.Now())
		}

		a.awakeWriteLoop()
	}
}

func (a *Association) onPTOTimer() {
	a.lock.Lock()
	defer a.lock.Unlock()
	a.onPTOTimerLocked()
}

func (a *Association) onPTOTimerLocked() {
	// if nothing is inflight, PTO should not drive TLR.
	// use PTO as a chance to probe RTT via HEARTBEAT instead of retransmitting DATA.
	if a.inflightQueue.size() == 0 {
		a.stopPTOTimer()
		a.log.Tracef("[%s] PTO idle: sending active HEARTBEAT for RTT probe", a.name)
		a.sendActiveHeartbeatLocked()

		return
	}

	currTime := time.Now()

	if !a.tlrActive {
		a.tlrBeginLocked()
	} else {
		a.tlrApplyAdditionalLossLocked(currTime)
	}

	// If we have unsent data, PTO should just wake the writer.
	if a.pendingQueue.size() > 0 {
		a.awakeWriteLoop()

		return
	}

	// otherwise retransmit most recently sent in-flight DATA.
	var latest *chunkPayloadData
	for i := uint32(0); ; i++ {
		c, ok := a.inflightQueue.get(a.cumulativeTSNAckPoint + i + 1)
		if !ok {
			break
		}

		if c.acked || c.abandoned() {
			continue
		}

		latest = c
	}

	if latest != nil && !latest.retransmit {
		latest.retransmit = true
		a.log.Tracef("[%s] PTO fired: probe tsn=%d", a.name, latest.tsn)
		a.awakeWriteLoop()
	}
}

func (a *Association) rackInsert(c *chunkPayloadData) {
	if c == nil || c.rackInList {
		return
	}

	if a.rackTail != nil {
		a.rackTail.rackNext = c
		c.rackPrev = a.rackTail
	} else {
		a.rackHead = c
	}
	a.rackTail = c
	c.rackInList = true
}

func (a *Association) rackRemove(chunk *chunkPayloadData) {
	if chunk == nil || !chunk.rackInList {
		return
	}

	if prev := chunk.rackPrev; prev != nil {
		prev.rackNext = chunk.rackNext
	} else {
		a.rackHead = chunk.rackNext
	}

	if next := chunk.rackNext; next != nil {
		next.rackPrev = chunk.rackPrev
	} else {
		a.rackTail = chunk.rackPrev
	}

	chunk.rackPrev = nil
	chunk.rackNext = nil
	chunk.rackInList = false
}

// caller must hold a.lock.
func (a *Association) tlrFirstRTTDurationLocked() time.Duration {
	// Use SRTT when available; fall back to a safe default.
	if srttMs := a.SRTT(); srttMs > 0 {
		return time.Duration(srttMs * 1e6)
	}

	return time.Second
}

// caller must hold a.lock.
func (a *Association) tlrUpdatePhaseLocked(currTime time.Time) {
	if !a.tlrActive || !a.tlrFirstRTT {
		return
	}
	if a.tlrStartTime.IsZero() {
		return
	}

	if currTime.Sub(a.tlrStartTime) >= a.tlrFirstRTTDurationLocked() {
		a.tlrFirstRTT = false
	}
}

// caller must hold a.lock.
func (a *Association) tlrCurrentBurstUnitsLocked() int64 {
	if !a.tlrActive {
		return 0
	}

	a.tlrUpdatePhaseLocked(time.Now())

	if a.tlrFirstRTT {
		return a.tlrBurstFirstRTTUnits
	}

	return a.tlrBurstLaterRTTUnits
}

// caller must hold a.lock.
// Returns remaining burst budget in "scaled bytes": bytes * 4 (quarter-MTU precision).
func (a *Association) tlrCurrentBurstBudgetScaledLocked() int64 {
	if !a.tlrActive {
		return 0
	}

	units := a.tlrCurrentBurstUnitsLocked()

	return units * int64(a.MTU())
}

// caller must hold a.lock.
func (a *Association) tlrHighestOutstandingTSNLocked() (uint32, bool) {
	var last uint32
	found := false

	for i := uint32(0); ; i++ {
		tsn := a.cumulativeTSNAckPoint + i + 1
		_, ok := a.inflightQueue.get(tsn)
		if !ok {
			break
		}
		last = tsn
		found = true
	}

	return last, found
}

// caller must hold a.lock.
func (a *Association) tlrBeginLocked() {
	currTime := time.Now()

	a.tlrActive = true
	a.tlrFirstRTT = true
	a.tlrHadAdditionalLoss = false
	a.tlrStartTime = currTime

	if endTSN, ok := a.tlrHighestOutstandingTSNLocked(); ok {
		a.tlrEndTSN = endTSN
	} else {
		a.tlrEndTSN = a.cumulativeTSNAckPoint
	}
}

// caller must hold a.lock.
func (a *Association) tlrApplyAdditionalLossLocked(currTime time.Time) {
	if !a.tlrActive {
		return
	}

	// Decide whether we're still within the first recovery RTT window.
	a.tlrUpdatePhaseLocked(currTime)

	a.tlrHadAdditionalLoss = true
	a.tlrGoodOps = 0

	if a.tlrFirstRTT {
		// Loss during first recovery RTT => initial burst too high.
		a.tlrBurstFirstRTTUnits -= tlrBurstStepDownFirstRTT
		if a.tlrBurstFirstRTTUnits < tlrBurstMinFirstRTT {
			a.tlrBurstFirstRTTUnits = tlrBurstMinFirstRTT
		}
	} else {
		// Loss during later RTTs => increasing rate too high.
		a.tlrBurstLaterRTTUnits -= tlrBurstStepDownLaterRTT
		if a.tlrBurstLaterRTTUnits < tlrBurstMinLaterRTT {
			a.tlrBurstLaterRTTUnits = tlrBurstMinLaterRTT
		}
	}
}

// caller must hold a.lock.
func (a *Association) tlrMaybeFinishLocked(ackProgress bool) {
	if !a.tlrActive {
		return
	}

	// determine if we should move from the first RTT burst to later RTT burst.
	if a.tlrFirstRTT && ackProgress {
		a.tlrFirstRTT = false
	}

	// finish once cumulatively ACKed through the tail we were recovering.
	if sna32GTE(a.cumulativeTSNAckPoint, a.tlrEndTSN) {
		if !a.tlrHadAdditionalLoss {
			a.tlrGoodOps++
			if a.tlrGoodOps >= tlrGoodOpsResetThreshold {
				a.tlrBurstFirstRTTUnits = tlrBurstDefaultFirstRTT
				a.tlrBurstLaterRTTUnits = tlrBurstDefaultLaterRTT
				a.tlrGoodOps = 0
			}
		} else {
			a.tlrGoodOps = 0
		}

		a.tlrActive = false
		a.tlrFirstRTT = false
		a.tlrHadAdditionalLoss = false
		a.tlrEndTSN = 0
	}
}

// caller must hold a.lock.
// "budgetScaled" is remaining burst budget in (bytes*4) scale.
// "consumed" allows the first send in a burst.
func (a *Association) tlrAllowSendLocked(budgetScaled *int64, consumed *bool, estBytes int) bool {
	if !a.tlrActive || budgetScaled == nil || consumed == nil {
		return true
	}
	if estBytes <= 0 {
		return true
	}

	needScaled := int64(estBytes) * tlrUnitsPerMTU // bytes*4
	if *consumed && *budgetScaled < needScaled {
		return false
	}

	*budgetScaled -= needScaled
	if *budgetScaled < 0 {
		*budgetScaled = 0
	}
	*consumed = true

	return true
}

// ActiveHeartbeat sends a HEARTBEAT chunk on the association to perform an
// on-demand RTT measurement without application payload.
//
// It is safe to call from outside; it will take the association lock and
// be a no-op if the association is not established.
func (a *Association) ActiveHeartbeat() {
	a.lock.Lock()
	defer a.lock.Unlock()

	if a.getState() != established {
		return
	}

	a.sendActiveHeartbeatLocked()
}

// caller must hold a.lock.
func (a *Association) sendActiveHeartbeatLocked() {
	now := time.Now().UnixNano()
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(now)) //nolint:gosec // time.now() will never be negative

	info := &paramHeartbeatInfo{heartbeatInformation: buf}

	hb := &chunkHeartbeat{
		chunkHeader: chunkHeader{
			typ:   ctHeartbeat,
			flags: 0,
		},
		params: []param{info},
	}

	a.controlQueue.push(&packet{
		verificationTag: a.peerVerificationTag,
		sourcePort:      a.sourcePort,
		destinationPort: a.destinationPort,
		chunks:          []chunk{hb},
	})
	a.awakeWriteLoop()
}
