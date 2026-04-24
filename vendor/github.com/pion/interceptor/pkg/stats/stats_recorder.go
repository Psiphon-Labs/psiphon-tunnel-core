// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package stats

import (
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/interceptor"
	"github.com/pion/interceptor/internal/ntp"
	"github.com/pion/interceptor/internal/sequencenumber"
	"github.com/pion/logging"
	"github.com/pion/rtcp"
	"github.com/pion/rtp"
)

// Stats contains all the available statistics of RTP streams.
type Stats struct {
	InboundRTPStreamStats
	OutboundRTPStreamStats
	RemoteInboundRTPStreamStats
	RemoteOutboundRTPStreamStats
}

type internalStats struct {
	inboundSequencerNumber           sequencenumber.Unwrapper
	inboundSequenceNumberInitialized bool
	inboundFirstSequenceNumber       int64
	inboundHighestSequenceNumber     int64

	inboundLastArrivalInitialized bool
	inboundLastArrival            time.Time
	inboundLastArrivalRTP         uint32
	inboundLastTransit            int

	remoteInboundFirstSequenceNumberInitialized bool
	remoteInboundFirstSequenceNumber            int64

	lastSenderReports []uint64

	lastReceiverReferenceTimes []uint64

	InboundRTPStreamStats
	OutboundRTPStreamStats

	RemoteInboundRTPStreamStats
	RemoteOutboundRTPStreamStats
}

type incomingRTP struct {
	ts         time.Time
	header     rtp.Header
	payloadLen int
	attr       interceptor.Attributes
}

type incomingRTCP struct {
	ts   time.Time
	pkts []rtcp.Packet
	attr interceptor.Attributes
}

type outgoingRTP struct {
	ts         time.Time
	header     rtp.Header
	payloadLen int
	attr       interceptor.Attributes
}

type outgoingRTCP struct {
	ts   time.Time
	pkts []rtcp.Packet
	attr interceptor.Attributes
}

type recorder struct {
	logger logging.LeveledLogger

	ssrc      uint32
	clockRate float64

	maxLastSenderReports          int
	maxLastReceiverReferenceTimes int

	latestStats *internalStats
	ms          *sync.Mutex // Locks latestStats
	running     uint32
}

func newRecorder(ssrc uint32, clockRate float64, loggerFactory logging.LoggerFactory) *recorder {
	return &recorder{
		logger:                        loggerFactory.NewLogger("stats_recorder"),
		ssrc:                          ssrc,
		clockRate:                     clockRate,
		maxLastSenderReports:          5,
		maxLastReceiverReferenceTimes: 5,
		latestStats:                   &internalStats{},
		ms:                            &sync.Mutex{},
	}
}

func (r *recorder) Stop() {
	atomic.StoreUint32(&r.running, 0)
}

func (r *recorder) GetStats() Stats {
	r.ms.Lock()
	defer r.ms.Unlock()

	return Stats{
		InboundRTPStreamStats:        r.latestStats.InboundRTPStreamStats,
		OutboundRTPStreamStats:       r.latestStats.OutboundRTPStreamStats,
		RemoteInboundRTPStreamStats:  r.latestStats.RemoteInboundRTPStreamStats,
		RemoteOutboundRTPStreamStats: r.latestStats.RemoteOutboundRTPStreamStats,
	}
}

func (r *recorder) recordIncomingRTP(latestStats internalStats, incoming *incomingRTP) internalStats {
	if incoming.header.SSRC != r.ssrc {
		return latestStats
	}
	sequenceNumber := latestStats.inboundSequencerNumber.Unwrap(incoming.header.SequenceNumber)
	if !latestStats.inboundSequenceNumberInitialized {
		latestStats.inboundFirstSequenceNumber = sequenceNumber
		latestStats.inboundSequenceNumberInitialized = true
	}
	if sequenceNumber > latestStats.inboundHighestSequenceNumber {
		latestStats.inboundHighestSequenceNumber = sequenceNumber
	}

	latestStats.InboundRTPStreamStats.PacketsReceived++
	expectedPackets := latestStats.inboundHighestSequenceNumber - latestStats.inboundFirstSequenceNumber + 1
	//nolint:gosec // G115
	latestStats.InboundRTPStreamStats.PacketsLost = expectedPackets -
		int64(latestStats.InboundRTPStreamStats.PacketsReceived)

	if !latestStats.inboundLastArrivalInitialized {
		latestStats.inboundLastArrival = incoming.ts
		latestStats.inboundLastArrivalRTP = incoming.header.Timestamp
		latestStats.inboundLastArrivalInitialized = true
	} else {
		rtpUnitsSinceLastArrival := incoming.ts.Sub(latestStats.inboundLastArrival).Seconds() * r.clockRate
		arrival := latestStats.inboundLastArrivalRTP + uint32(rtpUnitsSinceLastArrival)
		transit := int(arrival) - int(incoming.header.Timestamp)
		d := transit - latestStats.inboundLastTransit
		if d < 0 {
			d = -d
		}
		dSec := float64(d) / r.clockRate
		latestStats.inboundLastTransit = transit
		latestStats.InboundRTPStreamStats.Jitter += (1.0 / 16.0) * (dSec - latestStats.InboundRTPStreamStats.Jitter)
		latestStats.inboundLastArrival = incoming.ts
		latestStats.inboundLastArrivalRTP = incoming.header.Timestamp
	}

	latestStats.LastPacketReceivedTimestamp = incoming.ts
	latestStats.HeaderBytesReceived += uint64(incoming.header.MarshalSize())                 //nolint:gosec // G115
	latestStats.BytesReceived += uint64(incoming.header.MarshalSize() + incoming.payloadLen) //nolint:gosec // G115

	return latestStats
}

//nolint:cyclop
func (r *recorder) recordOutgoingRTCP(latestStats internalStats, v *outgoingRTCP) internalStats {
	for _, pkt := range v.pkts {
		// The SSRC check is performed for most of the cases but not all. The
		// reason is that ReceiverReferenceTimeReportBlocks don't have
		// destination SSRCs but must still be recorded.
		switch rtcpPkt := pkt.(type) {
		case *rtcp.FullIntraRequest:
			if !contains(pkt.DestinationSSRC(), r.ssrc) {
				r.logger.Debugf("skipping outgoing RTCP pkt: %v", pkt)

				continue
			}
			latestStats.InboundRTPStreamStats.FIRCount++
		case *rtcp.PictureLossIndication:
			if !contains(pkt.DestinationSSRC(), r.ssrc) {
				r.logger.Debugf("skipping outgoing RTCP pkt: %v", pkt)

				continue
			}
			latestStats.InboundRTPStreamStats.PLICount++
		case *rtcp.TransportLayerNack:
			if !contains(pkt.DestinationSSRC(), r.ssrc) {
				r.logger.Debugf("skipping outgoing RTCP pkt: %v", pkt)

				continue
			}
			latestStats.InboundRTPStreamStats.NACKCount++
		case *rtcp.SenderReport:
			if !contains(pkt.DestinationSSRC(), r.ssrc) {
				r.logger.Debugf("skipping outgoing RTCP pkt: %v", pkt)

				continue
			}
			latestStats.lastSenderReports = append(latestStats.lastSenderReports, rtcpPkt.NTPTime)
			if len(latestStats.lastSenderReports) > r.maxLastSenderReports {
				latestStats.lastSenderReports = latestStats.lastSenderReports[len(
					latestStats.lastSenderReports,
				)-r.maxLastSenderReports:]
			}
		case *rtcp.ExtendedReport:
			for _, block := range rtcpPkt.Reports {
				if xr, ok := block.(*rtcp.ReceiverReferenceTimeReportBlock); ok {
					latestStats.lastReceiverReferenceTimes = append(latestStats.lastReceiverReferenceTimes, xr.NTPTimestamp)
					if len(latestStats.lastReceiverReferenceTimes) > r.maxLastReceiverReferenceTimes {
						latestStats.lastReceiverReferenceTimes = latestStats.lastReceiverReferenceTimes[len(
							latestStats.lastReceiverReferenceTimes,
						)-r.maxLastReceiverReferenceTimes:]
					}
				}
			}
		}
	}

	return latestStats
}

func (r *recorder) recordOutgoingRTP(latestStats internalStats, v *outgoingRTP) internalStats {
	if v.header.SSRC != r.ssrc {
		return latestStats
	}
	headerSize := v.header.MarshalSize()
	latestStats.OutboundRTPStreamStats.PacketsSent++
	latestStats.OutboundRTPStreamStats.BytesSent += uint64(headerSize + v.payloadLen) //nolint:gosec // G115
	latestStats.HeaderBytesSent += uint64(headerSize)                                 //nolint:gosec // G115
	if !latestStats.remoteInboundFirstSequenceNumberInitialized {
		latestStats.remoteInboundFirstSequenceNumber = int64(v.header.SequenceNumber)
		latestStats.remoteInboundFirstSequenceNumberInitialized = true
	}

	return latestStats
}

func (r *recorder) recordIncomingRR(latestStats internalStats, pkt *rtcp.ReceiverReport, ts time.Time) internalStats {
	for _, report := range pkt.Reports {
		if latestStats.remoteInboundFirstSequenceNumberInitialized {
			cycles := uint64(report.LastSequenceNumber&0xFFFF0000) >> 16
			nr := uint64(report.LastSequenceNumber & 0x0000FFFF)
			highest := cycles*(0xFFFF+1) + nr
			//nolint:gosec // G115
			expected := int64(highest) - latestStats.remoteInboundFirstSequenceNumber + 1
			received := max(expected-int64(report.TotalLost), 0)
			//nolint:gosec // G115
			latestStats.RemoteInboundRTPStreamStats.PacketsReceived = uint64(received)
		}
		latestStats.RemoteInboundRTPStreamStats.PacketsLost = int64(report.TotalLost)
		latestStats.RemoteInboundRTPStreamStats.Jitter = float64(report.Jitter) / r.clockRate

		if report.Delay != 0 && report.LastSenderReport != 0 {
			for i := min(r.maxLastSenderReports, len(latestStats.lastSenderReports)) - 1; i >= 0; i-- {
				lastReport := latestStats.lastSenderReports[i]
				if (lastReport&0x0000FFFFFFFF0000)>>16 == uint64(report.LastSenderReport) {
					dlsr := time.Duration(float64(report.Delay) / 65536.0 * float64(time.Second))
					latestStats.RemoteInboundRTPStreamStats.RoundTripTime = (ts.Add(-dlsr)).Sub(ntp.ToTime(lastReport))
					latestStats.RemoteInboundRTPStreamStats.TotalRoundTripTime += latestStats.RemoteInboundRTPStreamStats.RoundTripTime
					latestStats.RemoteInboundRTPStreamStats.RoundTripTimeMeasurements++

					break
				}
			}
		}
		latestStats.FractionLost = float64(report.FractionLost) / 256.0
	}

	return latestStats
}

func (r *recorder) recordIncomingXR(latestStats internalStats, pkt *rtcp.ExtendedReport, ts time.Time) internalStats {
	for _, report := range pkt.Reports {
		if xr, ok := report.(*rtcp.DLRRReportBlock); ok {
			for _, xrReport := range xr.Reports {
				if xrReport.LastRR != 0 && xrReport.DLRR != 0 {
					for i := min(r.maxLastReceiverReferenceTimes, len(latestStats.lastReceiverReferenceTimes)) - 1; i >= 0; i-- {
						lastRR := latestStats.lastReceiverReferenceTimes[i]
						if (lastRR&0x0000FFFFFFFF0000)>>16 == uint64(xrReport.LastRR) {
							dlrr := time.Duration(float64(xrReport.DLRR) / 65536.0 * float64(time.Second))
							latestStats.RemoteOutboundRTPStreamStats.RoundTripTime = (ts.Add(-dlrr)).Sub(ntp.ToTime(lastRR))
							//nolint:lll
							latestStats.RemoteOutboundRTPStreamStats.TotalRoundTripTime += latestStats.RemoteOutboundRTPStreamStats.RoundTripTime
							latestStats.RemoteOutboundRTPStreamStats.RoundTripTimeMeasurements++
						}
					}
				}
			}
		}
	}

	return latestStats
}

func contains(ls []uint32, e uint32) bool {
	return slices.Contains(ls, e)
}

func (r *recorder) recordIncomingRTCP(latestStats internalStats, incoming *incomingRTCP) internalStats {
	for _, pkt := range incoming.pkts {
		if !contains(pkt.DestinationSSRC(), r.ssrc) {
			r.logger.Debugf("skipping incoming RTCP pkt: %v", pkt)

			continue
		}
		switch pkt := pkt.(type) {
		case *rtcp.TransportLayerNack:
			latestStats.OutboundRTPStreamStats.NACKCount++
		case *rtcp.FullIntraRequest:
			latestStats.OutboundRTPStreamStats.FIRCount++
		case *rtcp.PictureLossIndication:
			latestStats.OutboundRTPStreamStats.PLICount++
		case *rtcp.ReceiverReport:
			latestStats = r.recordIncomingRR(latestStats, pkt, incoming.ts)
		case *rtcp.SenderReport:
			latestStats.RemoteOutboundRTPStreamStats.PacketsSent = uint64(pkt.PacketCount)
			latestStats.RemoteOutboundRTPStreamStats.BytesSent = uint64(pkt.OctetCount)
			latestStats.RemoteTimeStamp = ntp.ToTime(pkt.NTPTime)
			latestStats.ReportsSent++

		case *rtcp.ExtendedReport:
			return r.recordIncomingXR(latestStats, pkt, incoming.ts)
		}
	}

	return latestStats
}

func (r *recorder) Start() {
	atomic.StoreUint32(&r.running, 1)
}

func (r *recorder) QueueIncomingRTP(ts time.Time, buf []byte, attr interceptor.Attributes) {
	if atomic.LoadUint32(&r.running) == 0 {
		return
	}
	if attr == nil {
		attr = make(interceptor.Attributes)
	}
	header, err := attr.GetRTPHeader(buf)
	if err != nil {
		r.logger.Warnf("failed to get RTP Header, skipping incoming RTP packet in stats calculation: %v", err)

		return
	}
	hdr := header.Clone()
	r.ms.Lock()
	*r.latestStats = r.recordIncomingRTP(*r.latestStats, &incomingRTP{
		ts:         ts,
		header:     hdr,
		payloadLen: len(buf) - hdr.MarshalSize(),
		attr:       attr,
	})
	r.ms.Unlock()
}

func (r *recorder) QueueIncomingRTCP(ts time.Time, buf []byte, attr interceptor.Attributes) {
	if atomic.LoadUint32(&r.running) == 0 {
		return
	}
	if attr == nil {
		attr = make(interceptor.Attributes)
	}
	pkts, err := attr.GetRTCPPackets(buf)
	if err != nil {
		r.logger.Warnf("failed to get RTCP packets, skipping incoming RTCP packet in stats calculation: %v", err)

		return
	}
	r.ms.Lock()
	*r.latestStats = r.recordIncomingRTCP(*r.latestStats, &incomingRTCP{
		ts:   ts,
		pkts: pkts,
		attr: attr,
	})
	r.ms.Unlock()
}

func (r *recorder) QueueOutgoingRTP(ts time.Time, header *rtp.Header, payload []byte, attr interceptor.Attributes) {
	if atomic.LoadUint32(&r.running) == 0 {
		return
	}
	hdr := header.Clone()
	r.ms.Lock()
	*r.latestStats = r.recordOutgoingRTP(*r.latestStats, &outgoingRTP{
		ts:         ts,
		header:     hdr,
		payloadLen: len(payload),
		attr:       attr,
	})
	r.ms.Unlock()
}

func (r *recorder) QueueOutgoingRTCP(ts time.Time, pkts []rtcp.Packet, attr interceptor.Attributes) {
	if atomic.LoadUint32(&r.running) == 0 {
		return
	}
	r.ms.Lock()
	*r.latestStats = r.recordOutgoingRTCP(*r.latestStats, &outgoingRTCP{
		ts:   ts,
		pkts: pkts,
		attr: attr,
	})
	r.ms.Unlock()
}
