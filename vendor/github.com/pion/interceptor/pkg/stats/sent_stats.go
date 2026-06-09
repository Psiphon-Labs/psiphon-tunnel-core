// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package stats

import (
	"fmt"
	"time"
)

// SentRTPStreamStats contains common sender stats of RTP streams.
type SentRTPStreamStats struct {
	PacketsSent uint64
	BytesSent   uint64
}

// String returns a string representation of SentRTPStreamStats.
func (s SentRTPStreamStats) String() string {
	out := fmt.Sprintf("\tPacketsSent: %v\n", s.PacketsSent)
	out += fmt.Sprintf("\tBytesSent: %v\n", s.BytesSent)

	return out
}

// OutboundRTPStreamStats contains stats of outbound RTP streams.
type OutboundRTPStreamStats struct {
	SentRTPStreamStats

	HeaderBytesSent uint64
	NACKCount       uint32
	FIRCount        uint32
	PLICount        uint32
}

// String returns a string representation of OutboundRTPStreamStats.
func (s OutboundRTPStreamStats) String() string {
	out := "OutboundRTPStreamStats\n"
	out += s.SentRTPStreamStats.String()
	out += fmt.Sprintf("\tHeaderBytesSent: %v\n", s.HeaderBytesSent)
	out += fmt.Sprintf("\tNACKCount: %v\n", s.NACKCount)
	out += fmt.Sprintf("\tFIRCount: %v\n", s.FIRCount)
	out += fmt.Sprintf("\tPLICount: %v\n", s.PLICount)

	return out
}

// RemoteOutboundRTPStreamStats contains stats of outbound RTP streams of the
// remote peer.
type RemoteOutboundRTPStreamStats struct {
	SentRTPStreamStats

	RemoteTimeStamp           time.Time
	ReportsSent               uint64
	RoundTripTime             time.Duration
	TotalRoundTripTime        time.Duration
	RoundTripTimeMeasurements uint64
}

// String returns a string representation of RemoteOutboundRTPStreamStats.
func (s RemoteOutboundRTPStreamStats) String() string {
	out := "RemoteOutboundRTPStreamStats:\n"
	out += s.SentRTPStreamStats.String()
	out += fmt.Sprintf("\tRemoteTimeStamp: %v\n", s.RemoteTimeStamp)
	out += fmt.Sprintf("\tReportsSent: %v\n", s.ReportsSent)
	out += fmt.Sprintf("\tRoundTripTime: %v\n", s.RoundTripTime)
	out += fmt.Sprintf("\tTotalRoundTripTime: %v\n", s.TotalRoundTripTime)
	out += fmt.Sprintf("\tRoundTripTimeMeasurements: %v\n", s.RoundTripTimeMeasurements)

	return out
}
