// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package flexfec implements FlexFEC to recover missing RTP packets due to packet loss.
// https://datatracker.ietf.org/doc/html/rfc8627
package flexfec

import (
	"encoding/binary"
	"sync"

	"github.com/pion/rtp"
)

const (
	// BaseFec03HeaderSize represents the minium FEC payload's header size including the
	// required first mask.
	BaseFec03HeaderSize = 20
	// maxRTPPacketSize represents the maximum size of an RTP packet buffer.
	// This is a reasonable upper bound for typical RTP packets.
	maxRTPPacketSize = 1500
)

var bufferPool = sync.Pool{ //nolint:gochecknoglobals
	New: func() any {
		b := make([]byte, maxRTPPacketSize)

		return &b
	},
}

// FlexEncoder03 implements the Fec encoding mechanism for the "Flex" variant of FlexFec.
type FlexEncoder03 struct {
	fecBaseSn   uint16
	payloadType uint8
	ssrc        uint32
	coverage    *ProtectionCoverage
}

// FlexEncoder03Factory is a factory for FlexFEC-03 encoders.
type FlexEncoder03Factory struct{}

// NewEncoder creates new FlexFEC-03 encoder.
func (f FlexEncoder03Factory) NewEncoder(payloadType uint8, ssrc uint32) FlexEncoder {
	return NewFlexEncoder03(payloadType, ssrc)
}

// NewFlexEncoder03 creates new FlexFEC-03 encoder.
func NewFlexEncoder03(payloadType uint8, ssrc uint32) *FlexEncoder03 {
	return &FlexEncoder03{
		payloadType: payloadType,
		ssrc:        ssrc,
		fecBaseSn:   uint16(1000),
	}
}

// EncodeFec returns a list of generated RTP packets with FEC payloads that protect the specified mediaPackets.
// This method returns nil in case of missing RTP packets in the mediaPackets array or packets passed out of order.
func (flex *FlexEncoder03) EncodeFec(mediaPackets []rtp.Packet, numFecPackets uint32) []rtp.Packet {
	// Check if mediaPackets is empty
	if len(mediaPackets) == 0 {
		return nil
	}

	// Check if RTP packets are in order by comparing sequence numbers
	for i := 1; i < len(mediaPackets); i++ {
		if mediaPackets[i].SequenceNumber != mediaPackets[i-1].SequenceNumber+1 {
			// Packets are not in order or there are missing packets
			return nil
		}
	}

	// Start by defining which FEC packets cover which media packets
	if flex.coverage == nil {
		flex.coverage = NewCoverage(mediaPackets, numFecPackets)
	} else {
		flex.coverage.UpdateCoverage(mediaPackets, numFecPackets)
	}

	if flex.coverage == nil {
		return nil
	}

	// Generate FEC payloads
	fecPackets := make([]rtp.Packet, 0, numFecPackets)
	for fecPacketIndex := uint32(0); fecPacketIndex < numFecPackets; fecPacketIndex++ {
		fecPacket, ok := flex.encodeFlexFecPacket(fecPacketIndex, mediaPackets[0].SequenceNumber)
		if ok {
			fecPackets = append(fecPackets, fecPacket)
		}
	}

	return fecPackets
}

//nolint:cyclop
func (flex *FlexEncoder03) encodeFlexFecPacket(fecPacketIndex uint32, mediaBaseSn uint16) (rtp.Packet, bool) {
	mediaPackets := flex.coverage.GetCoveredBy(fecPacketIndex)
	mask1 := flex.coverage.ExtractMask1(fecPacketIndex)
	optionalMask2 := flex.coverage.ExtractMask2(fecPacketIndex)
	optionalMask3 := flex.coverage.ExtractMask3_03(fecPacketIndex)

	/*
	    FlexFEC Header Format:
	    0                   1                   2                   3
	    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |0|0| P|X|  CC  |M| PT recovery |         length recovery       |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                          TS recovery                          |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |   SSRCCount   |                    reserved                   |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                             SSRC_i                            |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |           SN base_i           |k|          Mask [0-14]        |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |k|                   Mask [15-45] (optional)                   |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |k|                                                             |
	   +-+                   Mask [46-108] (optional)                  |
	   |                                                               |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                     ... next in SSRC_i ...                    |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	*/

	if !mediaPackets.HasNext() {
		return rtp.Packet{}, false
	}

	// Get header size - This depends on the size of the bitmask.
	headerSize := BaseFec03HeaderSize
	if optionalMask2 > 0 || optionalMask3 > 0 {
		headerSize += 4
	}
	if optionalMask3 > 0 {
		headerSize += 8
	}

	// Find the maximum payload size among all media packets
	maxPayloadSize := 0
	for mediaPackets.HasNext() {
		maxPayloadSize = max(maxPayloadSize, mediaPackets.Next().MarshalSize()-BaseRTPHeaderSize)
	}
	mediaPackets.Reset()

	flexFecPayload := make([]byte, headerSize+maxPayloadSize)

	flexFecHeader := flexFecPayload[:headerSize]
	flexFecRepairPayload := flexFecPayload[headerSize : headerSize+maxPayloadSize]

	bufferFromPool := bufferPool.Get().(*[]byte) //nolint:forcetypeassert
	defer bufferPool.Put(bufferFromPool)
	tmpMediaPacketBuf := *bufferFromPool

	for mediaPackets.HasNext() {
		mediaPacket := mediaPackets.Next()
		packetSize := mediaPacket.MarshalSize()
		if packetSize > len(tmpMediaPacketBuf) {
			// Packet is too large for our fixed buffer, fallback to dynamic allocation
			tmpMediaPacketBuf = make([]byte, packetSize)
		}

		n, err := mediaPacket.MarshalTo(tmpMediaPacketBuf[:packetSize])
		if n == 0 || err != nil {
			return rtp.Packet{}, false
		}

		// XOR the first 2 bytes of the header: V, P, X, CC, M, PT fields
		flexFecHeader[0] ^= tmpMediaPacketBuf[0]
		flexFecHeader[1] ^= tmpMediaPacketBuf[1]

		// Clear the first 2 bits
		flexFecHeader[0] &= 0b00111111

		// XOR the length recovery field
		lengthRecoveryVal := uint16(mediaPacket.MarshalSize() - BaseRTPHeaderSize) //nolint:gosec // G115
		flexFecHeader[2] ^= uint8(lengthRecoveryVal >> 8)                          //nolint:gosec // G115
		flexFecHeader[3] ^= uint8(lengthRecoveryVal)                               //nolint:gosec // G115

		// XOR the 5th to 8th bytes of the header: the timestamp field
		flexFecHeader[4] ^= tmpMediaPacketBuf[4]
		flexFecHeader[5] ^= tmpMediaPacketBuf[5]
		flexFecHeader[6] ^= tmpMediaPacketBuf[6]
		flexFecHeader[7] ^= tmpMediaPacketBuf[7]

		// Process FlexFEC Repair Payload (bytes after RTP header)
		for byteIndex := 0; byteIndex < packetSize-BaseRTPHeaderSize; byteIndex++ {
			flexFecRepairPayload[byteIndex] ^= tmpMediaPacketBuf[byteIndex+BaseRTPHeaderSize]
		}
	}

	// Write the SSRC count
	flexFecHeader[8] = 1

	// Write 0s in reserved
	flexFecHeader[9] = 0
	flexFecHeader[10] = 0
	flexFecHeader[11] = 0

	// Write the SSRC of media packets protected by this FEC packet
	binary.BigEndian.PutUint32(flexFecHeader[12:16], mediaPackets.First().SSRC)

	// Write the base SN for the batch of media packets
	binary.BigEndian.PutUint16(flexFecHeader[16:18], mediaBaseSn)

	// Write the bitmasks to the header
	binary.BigEndian.PutUint16(flexFecHeader[18:20], mask1)

	if optionalMask2 == 0 && optionalMask3 == 0 {
		flexFecHeader[18] |= 0b10000000
	} else {
		binary.BigEndian.PutUint32(flexFecHeader[20:24], optionalMask2)

		if optionalMask3 == 0 {
			flexFecHeader[20] |= 0b10000000
		} else {
			binary.BigEndian.PutUint64(flexFecHeader[24:32], optionalMask3)
			flexFecHeader[24] |= 0b10000000
		}
	}

	packet := rtp.Packet{
		Header: rtp.Header{
			Version:        2,
			Padding:        false,
			Extension:      false,
			Marker:         false,
			PayloadType:    flex.payloadType,
			SequenceNumber: flex.fecBaseSn,
			Timestamp:      54243243,
			SSRC:           flex.ssrc,
			CSRC:           []uint32{},
		},
		Payload: flexFecPayload,
	}
	flex.fecBaseSn++

	return packet, true
}
