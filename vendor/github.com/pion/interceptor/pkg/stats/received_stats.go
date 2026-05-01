// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package stats

import (
	"fmt"
	"time"
)

// ReceivedRTPStreamStats contains common receiver stats of RTP streams.
type ReceivedRTPStreamStats struct {
	PacketsReceived uint64
	PacketsLost     int64
	Jitter          float64
}

// String returns a string representation of ReceivedRTPStreamStats.
func (s ReceivedRTPStreamStats) String() string {
	out := fmt.Sprintf("\tPacketsReceived: %v\n", s.PacketsReceived)
	out += fmt.Sprintf("\tPacketsLost: %v\n", s.PacketsLost)
	out += fmt.Sprintf("\tJitter: %v\n", s.Jitter)

	return out
}

// InboundRTPStreamStats contains stats of inbound RTP streams.
type InboundRTPStreamStats struct {
	ReceivedRTPStreamStats

	LastPacketReceivedTimestamp time.Time
	HeaderBytesReceived         uint64
	BytesReceived               uint64
	FIRCount                    uint32
	PLICount                    uint32
	NACKCount                   uint32
}

// String returns a string representation of InboundRTPStreamStats.
func (s InboundRTPStreamStats) String() string {
	out := "InboundRTPStreamStats:\n"
	out += s.ReceivedRTPStreamStats.String()
	out += fmt.Sprintf("\tLastPacketReceivedTimestamp: %v\n", s.LastPacketReceivedTimestamp)
	out += fmt.Sprintf("\tHeaderBytesReceived: %v\n", s.HeaderBytesReceived)
	out += fmt.Sprintf("\tBytesReceived: %v\n", s.BytesReceived)
	out += fmt.Sprintf("\tFIRCount: %v\n", s.FIRCount)
	out += fmt.Sprintf("\tPLICount: %v\n", s.PLICount)
	out += fmt.Sprintf("\tNACKCount: %v\n", s.NACKCount)

	return out
}

// RemoteInboundRTPStreamStats contains stats of inbound RTP streams of the
// remote peer.
type RemoteInboundRTPStreamStats struct {
	ReceivedRTPStreamStats

	RoundTripTime             time.Duration
	TotalRoundTripTime        time.Duration
	FractionLost              float64
	RoundTripTimeMeasurements uint64
}

// String returns a string representation of RemoteInboundRTPStreamStats.
func (s RemoteInboundRTPStreamStats) String() string {
	out := "RemoteInboundRTPStreamStats:\n"
	out += s.ReceivedRTPStreamStats.String()
	out += fmt.Sprintf("\tRoundTripTime: %v\n", s.RoundTripTime)
	out += fmt.Sprintf("\tTotalRoundTripTime: %v\n", s.TotalRoundTripTime)
	out += fmt.Sprintf("\tFractionLost: %v\n", s.FractionLost)
	out += fmt.Sprintf("\tRoundTripTimeMeasurements: %v\n", s.RoundTripTimeMeasurements)

	return out
}
