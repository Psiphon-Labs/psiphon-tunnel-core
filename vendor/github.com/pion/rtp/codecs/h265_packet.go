// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package codecs

import (
	"encoding/binary"
	"errors"
	"fmt"
)

//
// Errors
//

var (
	errH265CorruptedPacket          = errors.New("corrupted h265 packet")
	errInvalidH265PacketType        = errors.New("invalid h265 packet type")
	errMissingDonl                  = errors.New("expecting all aggregated packets to have DONL values")
	errDonlOutOfOrder               = errors.New("expecting aggregation packets to have increasing DONL values")
	errDondTooLarge                 = errors.New("expecint DONL difference between packets to be no more than 256")
	errExpectFragmentationStartUnit = errors.New("expecting a fragmentation start unit")
	errH265PACIPHESTooLong          = errors.New("expecting a PHES field shorter than 32 bytes")
)

//
// Network Abstraction Unit Header implementation
//

const (
	// sizeof(uint16).
	h265NaluHeaderSize = 2
	// sizeof(uint16).
	h265NaluDonlSize = 2
	// https://datatracker.ietf.org/doc/html/rfc7798#section-4.4.2
	h265NaluAggregationPacketType = 48
	// https://datatracker.ietf.org/doc/html/rfc7798#section-4.4.3
	h265NaluFragmentationUnitType = 49
	// https://datatracker.ietf.org/doc/html/rfc7798#section-4.4.4
	h265NaluPACIPacketType         = 50
	h265AggregatedPacketMaxSize    = ^uint16(0)
	h265AggregatedPacketLengthSize = 2
)

// H265NALUHeader is a H265 NAL Unit Header.
// https://datatracker.ietf.org/doc/html/rfc7798#section-1.1.4
//
//	+---------------+---------------+
//	|0|1|2|3|4|5|6|7|0|1|2|3|4|5|6|7|
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|F|   Type    |  LayerID  | TID |
//	+-------------+-----------------+
//
// .
type H265NALUHeader uint16

func newH265NALUHeader(highByte, lowByte uint8) H265NALUHeader {
	return H265NALUHeader((uint16(highByte) << 8) | uint16(lowByte))
}

// F is the forbidden bit, should always be 0.
func (h H265NALUHeader) F() bool {
	return (uint16(h) >> 15) != 0
}

// Type of NAL Unit.
func (h H265NALUHeader) Type() uint8 {
	// 01111110 00000000
	const mask = 0b01111110 << 8

	return uint8((uint16(h) & mask) >> (8 + 1)) // nolint: gosec // G115 false positive
}

// IsTypeVCLUnit returns whether or not the NAL Unit type is a VCL NAL unit.
func (h H265NALUHeader) IsTypeVCLUnit() bool {
	// Type is coded on 6 bits
	const msbMask = 0b00100000

	return (h.Type() & msbMask) == 0
}

// LayerID should always be 0 in non-3D HEVC context.
func (h H265NALUHeader) LayerID() uint8 {
	// 00000001 11111000
	const mask = (0b00000001 << 8) | 0b11111000

	return uint8((uint16(h) & mask) >> 3) // nolint: gosec // G115 false positive
}

// TID is the temporal identifier of the NAL unit +1.
func (h H265NALUHeader) TID() uint8 {
	const mask = 0b00000111

	return uint8(uint16(h) & mask) // nolint: gosec // G115 false positive
}

// IsAggregationPacket returns whether or not the packet is an Aggregation packet.
func (h H265NALUHeader) IsAggregationPacket() bool {
	return h.Type() == h265NaluAggregationPacketType
}

// IsFragmentationUnit returns whether or not the packet is a Fragmentation Unit packet.
func (h H265NALUHeader) IsFragmentationUnit() bool {
	return h.Type() == h265NaluFragmentationUnitType
}

// IsPACIPacket returns whether or not the packet is a PACI packet.
func (h H265NALUHeader) IsPACIPacket() bool {
	return h.Type() == h265NaluPACIPacketType
}

//
// Single NAL Unit Packet implementation
//

// H265SingleNALUnitPacket represents a NALU packet, containing exactly one NAL unit.
//
//	 0                   1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|           PayloadHdr          |      DONL (conditional)       |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                                                               |
//	|                  NAL unit payload data                        |
//	|                                                               |
//	|                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                               :...OPTIONAL RTP padding        |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Reference: https://datatracker.ietf.org/doc/html/rfc7798#section-4.4.1
type h265SingleNALUnitPacket struct {
	// payloadHeader is the header of the H265 packet.
	payloadHeader H265NALUHeader
	// donl is a 16-bit field, that may or may not be present.
	donl *uint16
	// payload of the fragmentation unit.
	payload []byte
}

// PayloadHeader returns the NALU header of the packet.
func (p *h265SingleNALUnitPacket) PayloadHeader() H265NALUHeader {
	return p.payloadHeader
}

// DONL returns the DONL of the packet.
func (p *h265SingleNALUnitPacket) DONL() *uint16 {
	return p.donl
}

// Payload returns the Fragmentation Unit packet payload.
func (p *h265SingleNALUnitPacket) Payload() []byte {
	return p.payload
}

func (p *h265SingleNALUnitPacket) wireSize() int {
	size := h265NaluHeaderSize
	if p.donl != nil {
		size += h265NaluDonlSize
	}
	size += len(p.payload)

	return size
}

func parseH265SingleNalUnitPacket(buf []byte, withDONL bool) (*h265SingleNALUnitPacket, error) {
	if buf == nil {
		return nil, errNilPacket
	}

	minSize := h265NaluHeaderSize

	if withDONL {
		minSize += h265NaluDonlSize
	}

	if len(buf) <= minSize {
		return nil, fmt.Errorf("%w: %d <= %v", errShortPacket, len(buf), minSize)
	}

	payloadHeader := newH265NALUHeader(buf[0], buf[1])

	if payloadHeader.F() {
		return nil, errH265CorruptedPacket
	}

	if payloadHeader.IsFragmentationUnit() || payloadHeader.IsPACIPacket() || payloadHeader.IsAggregationPacket() {
		return nil, errInvalidH265PacketType
	}

	var donl *uint16

	buf = buf[2:]

	if withDONL {
		donlValue := binary.BigEndian.Uint16(buf[:2])
		donl = &donlValue
		buf = buf[2:]
	}

	packet := h265SingleNALUnitPacket{
		payloadHeader,
		donl,
		buf,
	}

	return &packet, nil
}

func (p *h265SingleNALUnitPacket) isH265Packet() {}

func (p *h265SingleNALUnitPacket) header() H265NALUHeader {
	return p.payloadHeader
}

func (p *h265SingleNALUnitPacket) toAnnexB(buf []byte) []byte {
	buf = append(buf, annexbNALUStartCode...)

	donl := p.donl
	p.donl = nil
	buf = p.serialize(buf)
	p.donl = donl

	return buf
}

func (p *h265SingleNALUnitPacket) serialize(buf []byte) []byte {
	buf = binary.BigEndian.AppendUint16(buf, uint16(p.payloadHeader))

	if p.donl != nil {
		buf = binary.BigEndian.AppendUint16(buf, *p.donl)
	}

	buf = append(buf, p.payload...)

	return buf
}

// H265SingleNALUnitPacket represents a NALU packet, containing exactly one NAL unit.
//
//	 0                   1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|           PayloadHdr          |      DONL (conditional)       |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                                                               |
//	|                  NAL unit payload data                        |
//	|                                                               |
//	|                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                               :...OPTIONAL RTP padding        |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Reference: https://datatracker.ietf.org/doc/html/rfc7798#section-4.4.1
//
// Deprecated: replaced with a private type instead, will be removed in a future release.
type H265SingleNALUnitPacket struct {
	// payloadHeader is the header of the H265 packet.
	payloadHeader H265NALUHeader
	// donl is a 16-bit field, that may or may not be present.
	donl *uint16
	// payload of the fragmentation unit.
	payload []byte

	mightNeedDONL bool
}

// WithDONL can be called to specify whether or not DONL might be parsed.
// DONL may need to be parsed if `sprop-max-don-diff` is greater than 0 on the RTP stream.
func (p *H265SingleNALUnitPacket) WithDONL(value bool) {
	p.mightNeedDONL = value
}

// Unmarshal parses the passed byte slice and stores the result in the H265SingleNALUnitPacket
// this method is called upon.
func (p *H265SingleNALUnitPacket) Unmarshal(payload []byte) ([]byte, error) {
	parsed, err := parseH265SingleNalUnitPacket(payload, p.mightNeedDONL)
	if err != nil {
		return nil, err
	}
	p.payloadHeader = parsed.payloadHeader
	p.donl = parsed.donl
	p.payload = parsed.payload

	return nil, nil
}

// PayloadHeader returns the NALU header of the packet.
func (p *H265SingleNALUnitPacket) PayloadHeader() H265NALUHeader {
	return p.payloadHeader
}

// DONL returns the DONL of the packet.
func (p *H265SingleNALUnitPacket) DONL() *uint16 {
	return p.donl
}

// Payload returns the Fragmentation Unit packet payload.
func (p *H265SingleNALUnitPacket) Payload() []byte {
	return p.payload
}

//
// Aggregation Packets implementation
//

// h265AggregationPacket represents an Aggregation packet.
//
//	 0                   1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|    PayloadHdr (Type=48)       |                               |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
//	|                                                               |
//	|             two or more aggregation units                     |
//	|                                                               |
//	|                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                               :...OPTIONAL RTP padding        |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Reference: https://datatracker.ietf.org/doc/html/rfc7798#section-4.4.2
type h265AggregationPacket struct {
	payloadHeader H265NALUHeader
	donl          *uint16
	payload       []byte
}

// PayloadHeader returns the NALU header of the packet.
func (p *h265AggregationPacket) PayloadHeader() H265NALUHeader {
	return p.payloadHeader
}

// DONL returns the DONL of the packet.
func (p *h265AggregationPacket) DONL() *uint16 {
	return p.donl
}

// Payload returns the Fragmentation Unit packet payload.
func (p *h265AggregationPacket) Payload() []byte {
	return p.payload
}

func (p *h265AggregationPacket) isH265Packet() {}

func (p *h265AggregationPacket) header() H265NALUHeader {
	return p.payloadHeader
}

func (p *h265AggregationPacket) serialize(buf []byte) []byte {
	buf = binary.BigEndian.AppendUint16(buf, uint16(p.payloadHeader))

	if p.donl != nil {
		buf = binary.BigEndian.AppendUint16(buf, *p.donl)
	}

	buf = append(buf, p.payload...)

	return buf
}

func parseH265AggregationPacket(buf []byte, withDONL bool) (*h265AggregationPacket, error) {
	// header + 2 length fields
	minSize := h265NaluHeaderSize + (h265AggregatedPacketLengthSize * 2)
	payloadStart := h265NaluHeaderSize

	if withDONL {
		payloadStart += h265NaluDonlSize
		minSize += h265NaluDonlSize
	}

	if len(buf) < minSize {
		return nil, errShortPacket
	}

	header := H265NALUHeader(binary.BigEndian.Uint16(buf[0:2]))

	if !header.IsAggregationPacket() {
		return nil, errInvalidH265PacketType
	}

	var donl *uint16

	if withDONL {
		donlValue := binary.BigEndian.Uint16(buf[2:4])
		donl = &donlValue
	}

	payload := buf[payloadStart:]

	packet := h265AggregationPacket{
		header,
		donl,
		payload,
	}

	return &packet, nil
}

// returns whether this NALU can even fit inside an AP with another NALU.
func canAggregateH265(mtu uint16, packet *h265SingleNALUnitPacket) bool {
	// must leave enough space for the AP header, optionally its DONL field, 2 length headers, a 2nd AU's header
	// and a second packet's DOND field
	return packet.wireSize()+(h265AggregatedPacketLengthSize*2)+h265NaluHeaderSize+1 <= int(mtu)
}

// returns whether inserting a new packet will make this list of packets too big to aggregate within the MTU.
func shouldAggregateH265Now(mtu uint16, packets []h265SingleNALUnitPacket, newPacket h265SingleNALUnitPacket) bool {
	if len(packets) < 1 {
		return false
	}
	// AP header + each AU's size field
	totalSize := h265NaluHeaderSize + ((len(packets) + 1) * h265AggregatedPacketLengthSize)
	hasDonl := packets[0].donl != nil
	// first AU's DONL field
	if hasDonl {
		totalSize += 2
	}

	if hasDonl && newPacket.donl == nil {
		return true
	}

	for _, p := range packets {
		totalSize += p.wireSize()
		// individual AUs have their DONL fields replaced with DOND (1 byte)
		if hasDonl {
			totalSize -= 1
		}
	}

	totalSize += newPacket.wireSize()
	if hasDonl {
		totalSize -= 1
	}

	return totalSize > int(mtu)
}

// Reference: https://datatracker.ietf.org/doc/html/rfc7798#section-4.4.2
// nolint: cyclop // hot path
func newH265AggregationPacket(packets []h265SingleNALUnitPacket) (*h265AggregationPacket, error) {
	if packets == nil {
		return nil, errNilPacket
	}
	if len(packets) < 2 {
		return nil, errNotEnoughPackets
	}

	donlExpected := packets[0].donl != nil
	var aggrDonl *uint16
	if donlExpected {
		aggrDonlVal := *packets[0].donl
		aggrDonl = &aggrDonlVal
	}

	header := uint16(0)
	header |= h265NaluAggregationPacketType << 9

	firstPacket := packets[0]
	if firstPacket.wireSize() > int(h265AggregatedPacketMaxSize) {
		return nil, errPacketTooLarge
	}

	fBit := firstPacket.payloadHeader.F()
	layerID := firstPacket.payloadHeader.LayerID()
	tid := firstPacket.payloadHeader.TID()

	payload := make([]byte, 0)

	lastDonl := packets[0].donl
	for i, packet := range packets {
		if donlExpected && packet.donl == nil {
			return nil, errMissingDonl
		}
		if i > 0 && packet.donl != nil {
			// the DOND field plus 1 specifies the difference between
			// the decoding order number values of the current aggregated NAL unit
			// and the preceding aggregated NAL unit in the same AP.
			dond := int(*packet.donl) - int(*lastDonl) - 1
			if dond < 0 {
				return nil, errDonlOutOfOrder
			}
			if dond > int(^uint8(0)) {
				return nil, errDondTooLarge
			}
			payload = append(payload, uint8(dond))
			lastDonl = packet.donl
		}
		// following AUs' DONs are derived from the DOND field
		packet.donl = nil

		if packet.wireSize() > int(h265AggregatedPacketMaxSize) {
			return nil, errPacketTooLarge
		}

		if packet.payloadHeader.F() {
			fBit = true
		}
		pLayerID := packet.payloadHeader.LayerID()
		if pLayerID < layerID {
			layerID = pLayerID
		}
		pTid := packet.payloadHeader.TID()
		if pTid < tid {
			tid = pTid
		}

		// nolint: gosec // Already checked for max size
		payload = binary.BigEndian.AppendUint16(payload, uint16(packet.wireSize()))

		payload = packet.serialize(payload)
	}

	header |= uint16(tid)
	header |= uint16(layerID) << 3

	if fBit {
		header |= uint16(0b1) << 15
	}

	packet := h265AggregationPacket{
		H265NALUHeader(header),
		aggrDonl,
		payload,
	}

	return &packet, nil
}

func splitH265AggregationPacket(packet h265AggregationPacket) ([]h265SingleNALUnitPacket, error) { // nolint:cyclop
	curDonl := packet.donl
	packets := make([]h265SingleNALUnitPacket, 0)
	payload := packet.payload

	i := 0
	for len(payload) > 0 {
		minSize := h265AggregatedPacketLengthSize

		// DOND is present starting on 2nd AU
		if curDonl != nil && i > 0 {
			minSize += 1
		}

		if len(payload) < minSize {
			return nil, errShortPacket
		}

		var donl *uint16
		if curDonl != nil {
			if i == 0 {
				donl = curDonl
			} else {
				donlValue := *curDonl + uint16(payload[0]) + 1
				donl = &donlValue
				curDonl = &donlValue
				payload = payload[1:]
			}
		}

		curLen := binary.BigEndian.Uint16(payload[0:2])
		if len(payload[2:]) < int(curLen) {
			return nil, errShortPacket
		}

		parsed, err := parseH265SingleNalUnitPacket(payload[2:2+curLen], false)
		if err != nil {
			return nil, err
		}

		if curDonl != nil {
			parsed.donl = donl
		}
		packets = append(packets, *parsed)
		payload = payload[2+curLen:]

		i++
	}
	if len(packets) < 2 {
		return nil, errNotEnoughPackets
	}

	return packets, nil
}

// H265AggregationUnitFirst represent the First Aggregation Unit in an AP.
//
//	 0                   1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	:       DONL (conditional)      |   NALU size   |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|   NALU size   |                                               |
//	+-+-+-+-+-+-+-+-+         NAL unit                              |
//	|                                                               |
//	|                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                               :
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Reference: https://datatracker.ietf.org/doc/html/rfc7798#section-4.4.2
//
// Deprecated: replaced with a private type instead, will be removed in a future release.
type H265AggregationUnitFirst struct {
	donl        *uint16
	nalUnitSize uint16
	nalUnit     []byte
}

// DONL field, when present, specifies the value of the 16 least
// significant bits of the decoding order number of the aggregated NAL
// unit.
func (u H265AggregationUnitFirst) DONL() *uint16 {
	return u.donl
}

// NALUSize represents the size, in bytes, of the NalUnit.
func (u H265AggregationUnitFirst) NALUSize() uint16 {
	return u.nalUnitSize
}

// NalUnit payload.
func (u H265AggregationUnitFirst) NalUnit() []byte {
	return u.nalUnit
}

// H265AggregationUnit represent the an Aggregation Unit in an AP, which is not the first one.
//
//	 0                   1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	: DOND (cond)   |          NALU size            |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                                                               |
//	|                       NAL unit                                |
//	|                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                               :
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Reference: https://datatracker.ietf.org/doc/html/rfc7798#section-4.4.2
//
// Deprecated: replaced with a private type instead, will be removed in a future release.
type H265AggregationUnit struct {
	dond        *uint8
	nalUnitSize uint16
	nalUnit     []byte
}

// DOND field plus 1 specifies the difference between
// the decoding order number values of the current aggregated NAL unit
// and the preceding aggregated NAL unit in the same AP.
func (u H265AggregationUnit) DOND() *uint8 {
	return u.dond
}

// NALUSize represents the size, in bytes, of the NalUnit.
func (u H265AggregationUnit) NALUSize() uint16 {
	return u.nalUnitSize
}

// NalUnit payload.
func (u H265AggregationUnit) NalUnit() []byte {
	return u.nalUnit
}

// H265AggregationPacket represents an Aggregation packet.
//
//	 0                   1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|    PayloadHdr (Type=48)       |                               |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
//	|                                                               |
//	|             two or more aggregation units                     |
//	|                                                               |
//	|                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                               :...OPTIONAL RTP padding        |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Reference: https://datatracker.ietf.org/doc/html/rfc7798#section-4.4.2
//
// Deprecated: replaced with a private type instead, will be removed in a future release.
type H265AggregationPacket struct {
	payloadHeader H265NALUHeader
	firstUnit     *H265AggregationUnitFirst
	otherUnits    []H265AggregationUnit

	mightNeedDONL bool
}

// WithDONL can be called to specify whether or not DONL might be parsed.
// DONL may need to be parsed if `sprop-max-don-diff` is greater than 0 on the RTP stream.
func (p *H265AggregationPacket) WithDONL(value bool) {
	p.mightNeedDONL = value
}

// Unmarshal parses the passed byte slice and stores the result in the H265AggregationPacket this method is called upon.
func (p *H265AggregationPacket) Unmarshal(payload []byte) ([]byte, error) { //nolint:cyclop
	// sizeof(headers)
	minSize := h265NaluHeaderSize + (h265AggregatedPacketLengthSize * 2)

	if p.mightNeedDONL {
		minSize += h265NaluDonlSize
	}

	if payload == nil {
		return nil, errNilPacket
	} else if len(payload) <= minSize {
		return nil, fmt.Errorf("%w: %d <= %v", errShortPacket, len(payload), minSize)
	}

	payloadHeader := newH265NALUHeader(payload[0], payload[1])
	if payloadHeader.F() {
		return nil, errH265CorruptedPacket
	}
	if !payloadHeader.IsAggregationPacket() {
		return nil, errInvalidH265PacketType
	}
	p.payloadHeader = payloadHeader

	// First parse the first aggregation unit
	payload = payload[2:]
	firstUnit := &H265AggregationUnitFirst{}

	if p.mightNeedDONL {
		if len(payload) < 2 {
			return nil, errShortPacket
		}

		donl := binary.BigEndian.Uint16(payload[0:2])
		firstUnit.donl = &donl

		payload = payload[2:]
	}
	if len(payload) < 2 {
		return nil, errShortPacket
	}
	firstUnit.nalUnitSize = binary.BigEndian.Uint16(payload[0:2])
	payload = payload[2:]

	if len(payload) < int(firstUnit.nalUnitSize) {
		return nil, errShortPacket
	}

	firstUnit.nalUnit = payload[:firstUnit.nalUnitSize]
	payload = payload[firstUnit.nalUnitSize:]

	// Parse remaining Aggregation Units
	var units []H265AggregationUnit
	for {
		unit := H265AggregationUnit{}

		if p.mightNeedDONL {
			if len(payload) < 1 {
				break
			}

			dond := payload[0]
			unit.dond = &dond

			payload = payload[1:]
		}

		if len(payload) < 2 {
			break
		}
		unit.nalUnitSize = binary.BigEndian.Uint16(payload[0:2])
		payload = payload[2:]

		if len(payload) < int(unit.nalUnitSize) {
			return nil, errShortPacket
		}

		unit.nalUnit = payload[:unit.nalUnitSize]
		payload = payload[unit.nalUnitSize:]

		units = append(units, unit)
	}

	// There need to be **at least** two Aggregation Units (first + another one)
	if len(units) < 1 {
		return nil, errShortPacket
	}

	p.firstUnit = firstUnit
	p.otherUnits = units

	return nil, nil
}

// FirstUnit returns the first Aggregated Unit of the packet.
func (p *H265AggregationPacket) FirstUnit() *H265AggregationUnitFirst {
	return p.firstUnit
}

// OtherUnits returns the all the other Aggregated Unit of the packet (excluding the first one).
func (p *H265AggregationPacket) OtherUnits() []H265AggregationUnit {
	return p.otherUnits
}

//
// Fragmentation Unit implementation
//

const (
	// sizeof(uint8).
	h265FragmentationUnitHeaderSize = 1
)

// H265FragmentationUnitHeader is a H265 FU Header.
//
//	+---------------+
//	|0|1|2|3|4|5|6|7|
//	+-+-+-+-+-+-+-+-+
//	|S|E|  FuType   |
//	+---------------+
//
// .
type H265FragmentationUnitHeader uint8

func newH265FragmentationUnitHeader(
	payloadHeader H265NALUHeader,
	s, e bool, //nolint:unparam
) H265FragmentationUnitHeader {
	header := payloadHeader.Type()
	if s {
		header |= 0b1 << 7
	}
	if e {
		header |= 0b1 << 6
	}

	return H265FragmentationUnitHeader(header)
}

// S represents the start of a fragmented NAL unit.
func (h H265FragmentationUnitHeader) S() bool {
	const mask = 0b10000000

	return ((h & mask) >> 7) != 0
}

// E represents the end of a fragmented NAL unit.
func (h H265FragmentationUnitHeader) E() bool {
	const mask = 0b01000000

	return ((h & mask) >> 6) != 0
}

// FuType MUST be equal to the field Type of the fragmented NAL unit.
func (h H265FragmentationUnitHeader) FuType() uint8 {
	const mask = 0b00111111

	return uint8(h) & mask
}

type h265FragmentationPacket struct {
	payloadHeader H265NALUHeader
	fuHeader      H265FragmentationUnitHeader
	donl          *uint16
	payload       []byte
}

func (p *h265FragmentationPacket) isH265Packet() {}

func (p *h265FragmentationPacket) header() H265NALUHeader {
	return p.payloadHeader
}

func (p *h265FragmentationPacket) serialize(buf []byte) []byte {
	buf = binary.BigEndian.AppendUint16(buf, uint16(p.payloadHeader))
	buf = append(buf, byte(p.fuHeader))

	if p.donl != nil {
		buf = binary.BigEndian.AppendUint16(buf, *p.donl)
	}

	buf = append(buf, p.payload...)

	return buf
}

func parseH265FragmentationPacket(payload []byte, withDONL bool) (*h265FragmentationPacket, error) {
	minSize := h265NaluHeaderSize + h265FragmentationUnitHeaderSize
	payloadStart := h265NaluHeaderSize + h265FragmentationUnitHeaderSize

	if withDONL {
		minSize += h265NaluDonlSize
		payloadStart += h265NaluDonlSize
	}

	if len(payload) < minSize {
		return nil, errShortPacket
	}

	header := H265NALUHeader(binary.BigEndian.Uint16(payload[0:2]))

	if !header.IsFragmentationUnit() {
		return nil, errInvalidH265PacketType
	}

	var donl *uint16
	if withDONL {
		donlVal := binary.BigEndian.Uint16(payload[3:5])
		donl = &donlVal
	}

	packet := h265FragmentationPacket{
		header,
		H265FragmentationUnitHeader(payload[2]),
		donl,
		payload[payloadStart:],
	}

	return &packet, nil
}

// Replaces the original header's type with 49, while keeping other fields.
func newH265FragmentationPacketHeader(payloadHeader H265NALUHeader) H265NALUHeader {
	typeMask := ^uint16(0b01111110_00000000)

	return H265NALUHeader((uint16(payloadHeader) & typeMask) | (h265NaluFragmentationUnitType << 9))
}

// Replaces the FU's payload header's type with the FU Header's type, while keeping other fields.
func rebuildH265FragmentationPacketHeader(
	payloadHeader H265NALUHeader,
	fuHeader H265FragmentationUnitHeader,
) H265NALUHeader {
	typeMask := ^uint16(0b01111110_00000000)
	origType := uint8(fuHeader) & 0b00111111

	return H265NALUHeader((uint16(payloadHeader) & typeMask) | (uint16(origType) << 9))
}

// Splits a H265SingleNALUnitPacket into many FU packets.
//
// Errors if the packet would result in a single FU packet.
//
// The P bit is not set in any case.
func newH265FragmentationPackets(mtu uint16, packet *h265SingleNALUnitPacket) ([]h265FragmentationPacket, error) {
	if packet == nil {
		return nil, errNilPacket
	}

	// size of Header, FU header and (optionally) the DONL
	overheadSize := 3
	if packet.donl != nil {
		overheadSize += 2
	}

	sliceSize := int(mtu) - overheadSize

	if len(packet.payload) <= sliceSize {
		return nil, errShortPacket
	}

	packets := make([]h265FragmentationPacket, 0)
	header := newH265FragmentationPacketHeader(packet.payloadHeader)

	fuPayload := packet.payload

	firstPacket := h265FragmentationPacket{
		payloadHeader: header,
		fuHeader:      newH265FragmentationUnitHeader(packet.payloadHeader, true, false),
		donl:          packet.donl,
		payload:       fuPayload[:sliceSize],
	}
	packets = append(packets, firstPacket)
	fuPayload = fuPayload[sliceSize:]

	for len(fuPayload) > sliceSize {
		p := h265FragmentationPacket{
			payloadHeader: header,
			fuHeader:      newH265FragmentationUnitHeader(packet.payloadHeader, false, false),
			donl:          nil,
			payload:       fuPayload[:sliceSize],
		}
		packets = append(packets, p)

		fuPayload = fuPayload[sliceSize:]
	}

	lastPacket := h265FragmentationPacket{
		payloadHeader: header,
		fuHeader:      newH265FragmentationUnitHeader(packet.payloadHeader, false, true),
		donl:          nil,
		payload:       fuPayload,
	}
	packets = append(packets, lastPacket)

	return packets, nil
}

func rebuildH265FragmentationPackets(packets []h265FragmentationPacket) (*h265SingleNALUnitPacket, error) {
	if len(packets) < 2 {
		return nil, errNotEnoughPackets
	}

	if !packets[0].fuHeader.S() {
		return nil, errFirstFragmentationUnitMissing
	}
	if !packets[len(packets)-1].fuHeader.E() {
		return nil, errLastFragmentationUnitMissing
	}

	payload := make([]byte, 0)
	for _, fu := range packets {
		payload = append(payload, fu.payload...)
	}

	rebuilt := h265SingleNALUnitPacket{
		payloadHeader: rebuildH265FragmentationPacketHeader(packets[0].payloadHeader, packets[0].fuHeader),
		donl:          packets[0].donl,
		payload:       payload,
	}

	return &rebuilt, nil
}

// H265FragmentationUnitPacket represents a single Fragmentation Unit packet.
//
//	 0                   1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|    PayloadHdr (Type=49)       |   FU header   | DONL (cond)   |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
//	| DONL (cond)   |                                               |
//	|-+-+-+-+-+-+-+-+                                               |
//	|                         FU payload                            |
//	|                                                               |
//	|                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                               :...OPTIONAL RTP padding        |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Reference: https://datatracker.ietf.org/doc/html/rfc7798#section-4.4.3
//
// Deprecated: replaced with a private type instead, will be removed in a future release.
type H265FragmentationUnitPacket struct {
	// payloadHeader is the header of the H265 packet.
	payloadHeader H265NALUHeader
	// fuHeader is the header of the fragmentation unit
	fuHeader H265FragmentationUnitHeader
	// donl is a 16-bit field, that may or may not be present.
	donl *uint16
	// payload of the fragmentation unit.
	payload []byte

	mightNeedDONL bool
}

// WithDONL can be called to specify whether or not DONL might be parsed.
// DONL may need to be parsed if `sprop-max-don-diff` is greater than 0 on the RTP stream.
func (p *H265FragmentationUnitPacket) WithDONL(value bool) {
	p.mightNeedDONL = value
}

// Unmarshal parses the passed byte slice and stores the result in the H265FragmentationUnitPacket
// this method is called upon.
func (p *H265FragmentationUnitPacket) Unmarshal(payload []byte) ([]byte, error) {
	parsed, err := parseH265FragmentationPacket(payload, p.mightNeedDONL)
	if err != nil {
		return nil, err
	}

	p.payloadHeader = parsed.payloadHeader
	p.fuHeader = parsed.fuHeader
	p.donl = parsed.donl
	p.payload = parsed.payload

	return nil, nil
}

// PayloadHeader returns the NALU header of the packet.
func (p *H265FragmentationUnitPacket) PayloadHeader() H265NALUHeader {
	return p.payloadHeader
}

// FuHeader returns the Fragmentation Unit Header of the packet.
func (p *H265FragmentationUnitPacket) FuHeader() H265FragmentationUnitHeader {
	return p.fuHeader
}

// DONL returns the DONL of the packet.
func (p *H265FragmentationUnitPacket) DONL() *uint16 {
	return p.donl
}

// Payload returns the Fragmentation Unit packet payload.
func (p *H265FragmentationUnitPacket) Payload() []byte {
	return p.payload
}

// H265FragmentationPacket represents a Fragmentation packet, which contains one or more Fragmentation Units.
//
// Deprecated: replaced with a private type instead, will be removed in a future release.
type H265FragmentationPacket struct {
	payloadHeader H265NALUHeader
	donl          *uint16
	units         []*H265FragmentationUnitPacket
	payload       []byte
}

// NewH265FragmentationPacket creates a H265FragmentationPacket.
func NewH265FragmentationPacket(startUnit *H265FragmentationUnitPacket) *H265FragmentationPacket {
	return &H265FragmentationPacket{
		payloadHeader: (startUnit.payloadHeader & 0x81FF) | (H265NALUHeader(startUnit.FuHeader().FuType()) << 9),
		donl:          startUnit.donl,
		units:         []*H265FragmentationUnitPacket{startUnit},
	}
}

// PayloadHeader returns the NALU header of the packet.
func (p *H265FragmentationPacket) PayloadHeader() H265NALUHeader {
	return p.payloadHeader
}

// DONL returns the DONL of the packet.
func (p *H265FragmentationPacket) DONL() *uint16 {
	return p.donl
}

// Payload returns the Fragmentation packet payload.
func (p *H265FragmentationPacket) Payload() []byte {
	return p.payload
}

//
// PACI implementation
//

// paciHeaderFields is the few fields after the payload header of a PACI packet
//
//	 0                   1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|    PayloadHdr (Type=50)       |A|   cType   | PHSsize |F0..2|Y|
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|        Payload Header Extension Structure (PHES)              |
//	|=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=|
//	|                                                               |
//	|                  PACI payload: NAL unit                       |
//	|                   . . .                                       |
//	|                                                               |
//	|                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                               :...OPTIONAL RTP padding        |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type paciHeaderFields uint16

func (h *paciHeaderFields) A() bool {
	return (uint16(*h) & 0b1 << 15) != 0
}

func (h *paciHeaderFields) CType() uint8 {
	mask := uint16(0b111111) << 9

	return uint8((uint16(*h) & mask) >> 9) // nolint:gosec // G115 false positive
}

func (h *paciHeaderFields) PHSize() uint8 {
	mask := uint16(0b11111) << 4

	return uint8((uint16(*h) & mask) >> 4) // nolint:gosec // G115 false positive
}

func (h *paciHeaderFields) F0() bool {
	return (uint16(*h) & 0b1 << 3) != 0
}

func (h *paciHeaderFields) F1() bool {
	return (uint16(*h) & 0b1 << 2) != 0
}

func (h *paciHeaderFields) F2() bool {
	return (uint16(*h) & 0b1 << 1) != 0
}

func (h *paciHeaderFields) Y() bool {
	return (uint16(*h) & 0b1) != 0
}

// H265PACIPacket represents a single H265 PACI packet.
//
//	 0                   1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|    PayloadHdr (Type=50)       |A|   cType   | PHSsize |F0..2|Y|
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|        Payload Header Extension Structure (PHES)              |
//	|=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=|
//	|                                                               |
//	|                  PACI payload: NAL unit                       |
//	|                   . . .                                       |
//	|                                                               |
//	|                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                               :...OPTIONAL RTP padding        |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Reference: https://datatracker.ietf.org/doc/html/rfc7798#section-4.4.4
type H265PACIPacket struct {
	// payloadHeader is the header of the H265 packet.
	payloadHeader H265NALUHeader

	// Field which holds value for `A`, `cType`, `PHSsize`, `F0`, `F1`, `F2` and `Y` fields.
	paciHeaderFields

	// phes is a header extension, of byte length `PHSsize`
	phes []byte

	// Payload contains NAL units & optional padding
	payload isH265Packet
}

// PayloadHeader returns the NAL Unit Header.
func (p *H265PACIPacket) PayloadHeader() H265NALUHeader {
	return p.payloadHeader
}

func (p *H265PACIPacket) PHSsize() uint8 {
	return p.paciHeaderFields.PHSize()
}

// PHES contains header extensions. Its size is indicated by PHSsize.
func (p *H265PACIPacket) PHES() []byte {
	return p.phes
}

// Payload is a single NALU or NALU-like struct, without its header.
func (p *H265PACIPacket) Payload() []byte {
	return p.payload.serialize(make([]byte, 0))[2:]
}

// TSCI returns the Temporal Scalability Control Information extension, if present.
func (p *H265PACIPacket) TSCI() *H265TSCI {
	if !p.F0() || p.PHSsize() < 3 || len(p.phes) < 3 {
		return nil
	}

	tsci := H265TSCI((uint32(p.phes[0]) << 16) | (uint32(p.phes[1]) << 8) | uint32(p.phes[2]))

	return &tsci
}

func rebuildPACIHeader(header H265NALUHeader, paciFields paciHeaderFields) H265NALUHeader {
	f := uint16(0)
	if paciFields.A() {
		f = 1
	}
	pType := paciFields.CType()
	layerID := header.LayerID()
	tid := header.TID()

	return H265NALUHeader(
		(f << 15) |
			(uint16(pType) << 9) |
			(uint16(layerID) << 3) |
			(uint16(tid)),
	)
}

func parseH265PACIPacket(buf []byte, withDONL bool) (*H265PACIPacket, error) { // nolint: cyclop
	minSize := h265NaluHeaderSize + 2
	if buf == nil {
		return nil, errNilPacket
	}
	if len(buf) < minSize {
		return nil, errShortPacket
	}
	header := H265NALUHeader(binary.BigEndian.Uint16(buf[0:2]))

	if header.Type() != h265NaluPACIPacketType {
		return nil, errInvalidH265PacketType
	}

	paciFields := paciHeaderFields(binary.BigEndian.Uint16(buf[2:4]))

	// a PACI packet cannot be inside another PACI packet
	if paciFields.CType() == h265NaluPACIPacketType {
		return nil, errInvalidH265PacketType
	}

	if len(buf) < minSize+int(paciFields.PHSize()) {
		return nil, errShortPacket
	}

	payloadStart := 4 + paciFields.PHSize()

	phes := buf[4:payloadStart]

	innerNalu := buf[payloadStart:]

	var innerPacket isH265Packet

	switch paciFields.CType() {
	case h265NaluAggregationPacketType:
		minLength := h265NaluHeaderSize + h265AggregatedPacketLengthSize*2
		// DONL field + 1 DOND field
		if withDONL {
			minLength += h265NaluDonlSize + 1
		}
		if len(innerNalu) < minLength {
			return nil, errShortPacket
		}
		var donl *uint16
		innerPayloadStart := 0
		if withDONL {
			donlVal := binary.BigEndian.Uint16(innerNalu[0:2])
			donl = &donlVal
			innerPayloadStart += h265NaluDonlSize
		}

		innerPacket = &h265AggregationPacket{
			payloadHeader: rebuildPACIHeader(header, paciFields),
			donl:          donl,
			payload:       innerNalu[innerPayloadStart:],
		}
	case h265NaluFragmentationUnitType:
		// header + fuHeader
		minLength := h265NaluHeaderSize + 1
		if withDONL {
			minLength += h265NaluDonlSize
		}
		if len(innerNalu) < minLength {
			return nil, errShortPacket
		}
		var donl *uint16
		innerPayloadStart := 1
		if withDONL {
			donlVal := binary.BigEndian.Uint16(innerNalu[1:3])
			donl = &donlVal
			innerPayloadStart += h265NaluDonlSize
		}
		innerPacket = &h265FragmentationPacket{
			payloadHeader: rebuildPACIHeader(header, paciFields),
			fuHeader:      H265FragmentationUnitHeader(innerNalu[0]),
			donl:          donl,
			payload:       innerNalu[innerPayloadStart:],
		}
	default:
		// header + fuHeader
		minLength := h265NaluHeaderSize
		if withDONL {
			minLength += h265NaluDonlSize
		}
		if len(innerNalu) < minLength {
			return nil, errShortPacket
		}
		var donl *uint16
		innerPayloadStart := 0
		if withDONL {
			donlVal := binary.BigEndian.Uint16(innerNalu[0:2])
			donl = &donlVal
			innerPayloadStart += h265NaluDonlSize
		}
		innerPacket = &h265SingleNALUnitPacket{
			payloadHeader: rebuildPACIHeader(header, paciFields),
			donl:          donl,
			payload:       innerNalu[innerPayloadStart:],
		}
	}

	packet := H265PACIPacket{
		header,
		paciFields,
		phes,
		innerPacket,
	}

	return &packet, nil
}

func newH265PACIPacketHeaders(originalHeader H265NALUHeader, phes []byte) (*H265NALUHeader, *paciHeaderFields, error) {
	if len(phes) >= 32 {
		return nil, nil, errH265PACIPHESTooLong
	}
	newHeader := H265NALUHeader(
		uint16(h265NaluPACIPacketType)<<9 |
			uint16(originalHeader.LayerID())<<3 |
			uint16(originalHeader.TID()),
	)
	a := uint16(0)
	if originalHeader.F() {
		a = 1
	}
	f0 := uint16(0)
	if len(phes) > 0 {
		f0 = 1
	}
	headerFields := paciHeaderFields(
		(a << 15) |
			(uint16(originalHeader.Type()) << 9) |
			(uint16(len(phes)) << 4) | // nolint: gosec // G115 false positive
			(f0 << 3),
	)

	return &newHeader, &headerFields, nil
}

func newH265PACIPacket(inner isH265Packet) (*H265PACIPacket, error) {
	_, ok := inner.(*H265PACIPacket)
	if ok {
		return nil, errInvalidH265PacketType
	}

	header, headerFields, err := newH265PACIPacketHeaders(inner.header(), nil)
	if err != nil {
		return nil, err
	}

	packet := H265PACIPacket{
		payloadHeader:    *header,
		paciHeaderFields: *headerFields,
		phes:             nil,
		payload:          inner,
	}

	return &packet, nil
}

// Unmarshal parses the passed byte slice and stores the result in the H265PACIPacket this method is called upon.
func (p *H265PACIPacket) Unmarshal(payload []byte) ([]byte, error) {
	// Bad behavior, no DONL parsing
	packet, err := parseH265PACIPacket(payload, false)
	if err != nil {
		return nil, err
	}

	p.payloadHeader = packet.payloadHeader
	p.paciHeaderFields = packet.paciHeaderFields
	p.phes = packet.phes
	p.payload = packet.payload

	return nil, nil
}

func (p *H265PACIPacket) isH265Packet() {}

func (p *H265PACIPacket) header() H265NALUHeader {
	return p.payloadHeader
}

func (p *H265PACIPacket) serialize(buf []byte) []byte {
	buf = binary.BigEndian.AppendUint16(buf, uint16(p.payloadHeader))

	buf = binary.BigEndian.AppendUint16(buf, uint16(p.paciHeaderFields))

	if len(p.phes) > 0 {
		buf = append(buf, p.phes...)
	}

	fragment, ok := p.payload.(*h265FragmentationPacket)
	if ok {
		buf = append(buf, byte(fragment.fuHeader))
		if fragment.donl != nil {
			buf = binary.BigEndian.AppendUint16(buf, *fragment.donl)
		}
		buf = append(buf, fragment.payload...)
	}

	aggregation, ok := p.payload.(*h265AggregationPacket)
	if ok {
		if aggregation.donl != nil {
			buf = binary.BigEndian.AppendUint16(buf, *aggregation.donl)
		}
		buf = append(buf, aggregation.payload...)
	}

	single, ok := p.payload.(*h265SingleNALUnitPacket)
	if ok {
		if single.donl != nil {
			buf = binary.BigEndian.AppendUint16(buf, *single.donl)
		}
		buf = append(buf, single.payload...)
	}

	return buf
}

//
// Temporal Scalability Control Information
//

// H265TSCI is a Temporal Scalability Control Information header extension.
// Reference: https://datatracker.ietf.org/doc/html/rfc7798#section-4.5
type H265TSCI uint32

// TL0PICIDX see RFC7798 for more details.
func (h H265TSCI) TL0PICIDX() uint8 {
	const m1 = 0xFFFF0000
	const m2 = 0xFF00

	return uint8((((h & m1) >> 16) & m2) >> 8) // nolint: gosec // G115 false positive
}

// IrapPicID see RFC7798 for more details.
func (h H265TSCI) IrapPicID() uint8 {
	const m1 = 0xFFFF0000
	const m2 = 0x00FF

	return uint8(((h & m1) >> 16) & m2) // nolint: gosec // G115 false positive
}

// S see RFC7798 for more details.
func (h H265TSCI) S() bool {
	const m1 = 0xFF00
	const m2 = 0b10000000

	return (uint8((h&m1)>>8) & m2) != 0 // nolint: gosec // G115 false positive
}

// E see RFC7798 for more details.
func (h H265TSCI) E() bool {
	const m1 = 0xFF00
	const m2 = 0b01000000

	return (uint8((h&m1)>>8) & m2) != 0 // nolint: gosec // G115 false positive
}

// RES see RFC7798 for more details.
func (h H265TSCI) RES() uint8 {
	const m1 = 0xFF00
	const m2 = 0b00111111

	return uint8((h&m1)>>8) & m2 // nolint: gosec // G115 false positive
}

//
// H265 Packet interface
//

type isH265Packet interface {
	isH265Packet()
	header() H265NALUHeader
	serialize([]byte) []byte
}

var (
	_ isH265Packet = (*h265FragmentationPacket)(nil)
	_ isH265Packet = (*H265PACIPacket)(nil)
	_ isH265Packet = (*h265SingleNALUnitPacket)(nil)
	_ isH265Packet = (*h265AggregationPacket)(nil)
)

//
// Packet implementation
//

// H265Depacketizer unmarshals an H265 RTP stream into an Annex-B one.
type H265Depacketizer struct {
	hasDonl  bool
	partials []h265FragmentationPacket

	videoDepacketizer
}

func (d *H265Depacketizer) handleSingleUnit(output []byte, single h265SingleNALUnitPacket) []byte {
	d.partials = d.partials[:0]
	output = single.toAnnexB(output)

	return output
}

func (d *H265Depacketizer) handleAggregationUnit(output []byte, aggregation h265AggregationPacket) ([]byte, error) {
	d.partials = d.partials[:0]
	aggregated, err := splitH265AggregationPacket(aggregation)
	if err != nil {
		return nil, err
	}

	for _, p := range aggregated {
		output = p.toAnnexB(output)
	}

	return output, nil
}

func (d *H265Depacketizer) handleFragmentationUnit(output []byte, fragment h265FragmentationPacket) ([]byte, error) {
	if fragment.fuHeader.E() { // nolint: nestif
		if len(d.partials) == 0 {
			return output, nil
		}

		d.partials = append(d.partials, fragment)

		rebuilt, err := rebuildH265FragmentationPackets(d.partials)
		if err != nil {
			return nil, err
		}
		output = d.handleSingleUnit(output, *rebuilt)
		d.partials = d.partials[:0]

		return output, nil
	} else {
		// discard lost partial fragments
		if fragment.fuHeader.S() {
			d.partials = d.partials[:0]
		} else if len(d.partials) == 0 {
			return nil, errExpectFragmentationStartUnit
		}

		d.partials = append(d.partials, fragment)

		return nil, nil
	}
}

func (d *H265Depacketizer) Unmarshal(payload []byte) ([]byte, error) { // nolint:cyclop, gocognit
	if len(payload) < h265NaluHeaderSize {
		return nil, errShortPacket
	}

	header := H265NALUHeader(binary.BigEndian.Uint16(payload[0:2]))

	output := make([]byte, 0)

	switch {
	case header.IsFragmentationUnit():
		parseDonl := len(d.partials) == 0 && d.hasDonl
		fragment, err := parseH265FragmentationPacket(payload, parseDonl)
		if err != nil {
			return nil, err
		}
		output, err = d.handleFragmentationUnit(output, *fragment)
		if err != nil {
			return nil, err
		}
	case header.IsAggregationPacket():
		aggregation, err := parseH265AggregationPacket(payload, d.hasDonl)
		if err != nil {
			return nil, err
		}
		output, err = d.handleAggregationUnit(output, *aggregation)
		if err != nil {
			return nil, err
		}
	case header.IsPACIPacket():
		paci, err := parseH265PACIPacket(payload, d.hasDonl)
		if err != nil {
			return nil, err
		}
		fragment, ok := paci.payload.(*h265FragmentationPacket)
		if ok {
			output, err = d.handleFragmentationUnit(output, *fragment)
			if err != nil {
				return nil, err
			}
		}
		aggregation, ok := paci.payload.(*h265AggregationPacket)
		if ok {
			output, err = d.handleAggregationUnit(output, *aggregation)
			if err != nil {
				return nil, err
			}
		}
		single, ok := paci.payload.(*h265SingleNALUnitPacket)
		if ok {
			output = d.handleSingleUnit(output, *single)
		}
	default:
		single, err := parseH265SingleNalUnitPacket(payload, d.hasDonl)
		if err != nil {
			return nil, err
		}
		output = d.handleSingleUnit(output, *single)
	}

	return output, nil
}

func (d *H265Depacketizer) IsPartitionHead(payload []byte) bool {
	if len(payload) < 2 {
		return false
	}
	header := H265NALUHeader(binary.BigEndian.Uint16(payload[0:2]))
	if header.IsFragmentationUnit() {
		if len(payload) < 3 {
			return false
		}
		fuHeader := H265FragmentationUnitHeader(payload[2])

		return fuHeader.S()
	}

	return true
}

func (d *H265Depacketizer) IsPartitionTail(marker bool, payload []byte) bool {
	if len(payload) < 3 {
		return marker
	}
	header := H265NALUHeader(binary.BigEndian.Uint16(payload[0:2]))
	if !header.IsFragmentationUnit() {
		return marker
	}
	fuHeader := H265FragmentationUnitHeader(payload[2])

	return fuHeader.E()
}

// H265Packet represents a H265 packet, stored in the payload of an RTP packet.
//
// Deprecated: Use H265Depacketizer instead.
type H265Packet struct {
	packet isH265Packet

	H265Depacketizer
}

// WithDONL can be called to specify whether or not DONL might be parsed.
// DONL may need to be parsed if `sprop-max-don-diff` is greater than 0 on the RTP stream.
func (p *H265Packet) WithDONL(value bool) {
	p.H265Depacketizer.hasDonl = value
}

// Packet returns the populated packet.
// Must be casted to one of:
// - *H265SingleNALUnitPacket
// - *H265FragmentationUnitPacket
// - *H265AggregationPacket
// - *H265PACIPacket.
//
// Deprecated: will always return nil.
func (p *H265Packet) Packet() isH265Packet {
	return p.packet
}

// H265Payloader payloads H265 packets.
type H265Payloader struct {
	// Deprecated: Has no effect.
	AddDONL         bool
	SkipAggregation bool
}

// Payload fragments a H265 packet across one or more byte arrays.
func (p *H265Payloader) Payload(mtu uint16, payload []byte) [][]byte { // nolint:cyclop
	// SampleBuilder reuses the payload buffer so this is required
	tmp := make([]byte, len(payload))
	copy(tmp, payload)
	payload = tmp

	var payloads [][]byte
	naluBuffer := make([]h265SingleNALUnitPacket, 0)

	flushBuffer := func() {
		switch len(naluBuffer) {
		case 0:
			return
		case 1:
			packetized := naluBuffer[0].serialize(make([]byte, 0, naluBuffer[0].wireSize()))
			naluBuffer = naluBuffer[:0]
			payloads = append(payloads, packetized)
		default:
			aggrPacket, err := newH265AggregationPacket(naluBuffer)
			naluBuffer = naluBuffer[:0]
			if err != nil {
				return
			}
			packetized := aggrPacket.serialize(make([]byte, 0))
			payloads = append(payloads, packetized)
		}
	}

	emitNalus(payload, func(nalu []byte) {
		if len(nalu) < h265NaluHeaderSize {
			return
		}

		header := H265NALUHeader(binary.BigEndian.Uint16(nalu[0:2]))

		if header.IsAggregationPacket() ||
			header.IsFragmentationUnit() ||
			header.IsPACIPacket() {
			return
		}

		packet := h265SingleNALUnitPacket{
			header,
			nil,
			nalu[2:],
		}

		if len(nalu) > int(mtu) { // nolint: nestif
			flushBuffer()
			fragments, err := newH265FragmentationPackets(mtu, &packet)
			if err != nil {
				return
			}
			for _, fragment := range fragments {
				payloads = append(payloads, fragment.serialize(make([]byte, 0)))
			}
		} else {
			if p.SkipAggregation {
				payloads = append(payloads, nalu)

				return
			}
			if len(naluBuffer) == 0 {
				if canAggregateH265(mtu, &packet) {
					naluBuffer = append(naluBuffer, packet)
				} else {
					payloads = append(payloads, nalu)
				}
			} else {
				// can't fit any more packets, just send what we have and make current first in buffer
				if shouldAggregateH265Now(mtu, naluBuffer, packet) {
					flushBuffer()
				}
				naluBuffer = append(naluBuffer, packet)
			}
		}
	})

	flushBuffer()

	return payloads
}
