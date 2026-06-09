// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package rtp

import (
	"sync/atomic"
)

// Sequencer generates sequential sequence numbers for building RTP packets.
type Sequencer interface {
	NextSequenceNumber() uint16
	RollOverCount() uint64
}

// maxInitialRandomSequenceNumber is the maximum value used for the initial sequence
// number when using NewRandomSequencer().
// This uses only half the potential sequence number space to avoid issues decrypting
// SRTP when the sequence number starts near the rollover and there is packet loss.
// See https://webrtc-review.googlesource.com/c/src/+/358360
const maxInitialRandomSequenceNumber = 1<<15 - 1

// NewRandomSequencer returns a new sequencer starting from a random sequence
// number.
func NewRandomSequencer() Sequencer {
	s := &sequencer{}
	s.state.Store(uint64(globalMathRandomGenerator.Intn(maxInitialRandomSequenceNumber))) // nolint: gosec // G115

	return s
}

// NewFixedSequencer returns a new sequencer starting from a specific
// sequence number.
func NewFixedSequencer(s uint16) Sequencer {
	seq := &sequencer{}
	seq.state.Store(uint64(s - 1)) // -1 because the first sequence number prepends 1

	return seq
}

type sequencer struct {
	// state packs both sequenceNumber (lower 16 bits) and rollOverCount (upper 48 bits)
	// into a single atomic uint64
	state atomic.Uint64
}

// NextSequenceNumber increment and returns a new sequence number for
// building RTP packets.
func (s *sequencer) NextSequenceNumber() uint16 {
	return uint16(s.state.Add(1)) // nolint: gosec // G115
}

// RollOverCount returns the amount of times the 16bit sequence number
// has wrapped.
func (s *sequencer) RollOverCount() uint64 {
	return s.state.Load() >> 16
}
