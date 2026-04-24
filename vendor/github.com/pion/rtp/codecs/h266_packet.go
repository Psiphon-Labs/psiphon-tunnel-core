// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package codecs

import (
	"bytes"
	"encoding/binary"
	"errors"
)

var (
	errNalCorrupted                  = errors.New("NAL could not be parsed to one of known types")
	errInvalidNalType                = errors.New("NAL types 28 and 29 are reserved for RTP streams")
	errPacketTooLarge                = errors.New("packet passed in is larger than 65535 bytes")
	errNotEnoughPackets              = errors.New("aggregation and fragmentation packets requires at least 2 packets")
	errFirstFragmentationUnitMissing = errors.New("expecting the first fragmentation packet")
	errLastFragmentationUnitMissing  = errors.New("expecting the last fragmentation packet")
)

const (
	// sizeof(uint16).
	h266NaluHeaderSize = 2
	// sizeof(uint16).
	h266NaluDonlSize = 2
	// https://datatracker.ietf.org/doc/html/rfc9328#section-4.3.2
	h266NaluAggregationPacketType = 28
	// https://datatracker.ietf.org/doc/html/rfc9328#section-4.3.3
	h266NaluFragmentationUnitType  = 29
	h266AggregatedPacketMaxSize    = ^uint16(0)
	h266AggregatedPacketLengthSize = 2
)

func emitH266Nalus(nals []byte, emit func([]byte)) {
	// look for 3-byte NALU start code
	start := bytes.Index(nals, naluStartCode)
	offset := 3

	if start == -1 {
		// no start code, emit the whole buffer
		emit(nals)

		return
	}

	length := len(nals)

	for start < length {
		// look for the next NALU start (end of this NALU)
		end := bytes.Index(nals[start+offset:], naluStartCode)
		if end == -1 {
			// no more NALUs, emit the rest of the buffer
			emit(nals[start+offset:])

			break
		}

		// next NALU start
		nextStart := start + offset + end

		// check if the next NALU is actually a 4-byte start code
		endIs4Byte := nals[nextStart-1] == 0
		if endIs4Byte {
			nextStart--
		}

		emit(nals[start+offset : nextStart])

		start = nextStart

		if endIs4Byte {
			offset = 4
		} else {
			offset = 3
		}
	}
}

type isH266Packet interface {
	isH266Packet()
	// write the packet in its wire format
	packetize([]byte) []byte
}

// h266NALUHeader is an H266 NAL Unit Header.
// https://datatracker.ietf.org/doc/html/rfc9328#section-1.1.4
//
//	+---------------+---------------+
//	|0|1|2|3|4|5|6|7|0|1|2|3|4|5|6|7|
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|F|Z| LayerID   |  Type   | TID |
//	+---------------+---------------+
type h266NALUHeader uint16

func newH266NALUHeader(highByte, lowByte uint8) h266NALUHeader {
	return h266NALUHeader((uint16(highByte) << 8) | uint16(lowByte))
}

// F is the forbidden bit, should always be 0.
func (h h266NALUHeader) F() bool {
	return (uint16(h) >> 15) != 0
}

// Z is a reserved bit, should always be 0.
func (h h266NALUHeader) Z() bool {
	const mask = 0b01000000 << 8

	return (uint16(h) & mask) != 0
}

// Type of NAL Unit.
func (h h266NALUHeader) Type() uint8 {
	const mask = 0b11111000

	return uint8((h & mask) >> 3) // nolint: gosec // G115 false positive
}

// IsTypeVCLUnit returns whether or not the NAL Unit type is a VCL NAL unit.
func (h h266NALUHeader) IsTypeVCLUnit() bool {
	// Section 7.4.2.2 http://www.itu.int/rec/T-REC-H.266
	return (h.Type() <= 11)
}

func (h h266NALUHeader) LayerID() uint8 {
	// 00111111 00000000
	const mask = 0b00111111 << 8

	return uint8((uint16(h) & mask) >> 8) // nolint: gosec // G115 false positive
}

func (h h266NALUHeader) TID() uint8 {
	const mask = 0b00000111

	return uint8(uint16(h) & mask) // nolint: gosec // G115 false positive
}

// IsAggregationPacket returns whether or not the packet is an Aggregation packet.
func (h h266NALUHeader) IsAggregationPacket() bool {
	return h.Type() == h266NaluAggregationPacketType
}

// IsFragmentationUnit returns whether or not the packet is a Fragmentation Unit packet.
func (h h266NALUHeader) IsFragmentationUnit() bool {
	return h.Type() == h266NaluFragmentationUnitType
}

// h266SingleNALUnitPacket represents a NALU packet, containing exactly one NAL unit.
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
type h266SingleNALUnitPacket struct {
	// payloadHeader is the header of the H266 packet.
	payloadHeader h266NALUHeader
	// donl is a 16-bit field, that may or may not be present.
	donl *uint16
	// payload of the NAL unit.
	payload []byte
}

func (p *h266SingleNALUnitPacket) wireSize() int {
	donlSize := 0
	if p.donl != nil {
		donlSize = 2
	}

	return h266NaluHeaderSize + donlSize + len(p.payload)
}

func (p h266SingleNALUnitPacket) isH266Packet() {}

func (p *h266SingleNALUnitPacket) packetize(buf []byte) []byte {
	buf = binary.BigEndian.AppendUint16(buf, uint16(p.payloadHeader))

	if p.donl != nil {
		buf = binary.BigEndian.AppendUint16(buf, *p.donl)
	}

	buf = append(buf, p.payload...)

	return buf
}

// Aggregation Packet implementation

// h266AggregationPacket is a single H266 aggregation packet.
//
//	 0                   1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|    PayloadHdr (Type=28)       |                               |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
//	|                                                               |
//	|             two or more aggregation units                     |
//	|                                                               |
//	|                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                               :...OPTIONAL RTP padding        |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Reference: https://datatracker.ietf.org/doc/html/rfc9328#section-4.3.2
type h266AggregationPacket struct {
	payloadHeader h266NALUHeader
	donl          *uint16
	payload       []byte
}

// returns whether this NALU can even fit inside an AP with another NALU.
func canAggregate(mtu uint16, packet *h266SingleNALUnitPacket) bool {
	// must leave enough space for the AP header, optionally its DONL field, 2 length headers and a 2nd AU's header
	return packet.wireSize()+(h266AggregatedPacketLengthSize*2)+h266NaluHeaderSize <= int(mtu)
}

// returns whether inserting a new packet will make this list of packets too big to aggregate within the MTU.
func shouldAggregateNow(mtu uint16, packets []h266SingleNALUnitPacket, newPacket h266SingleNALUnitPacket) bool {
	if len(packets) < 1 {
		return false
	}
	// AP header + each AU's size field
	totalSize := h266NaluHeaderSize + ((len(packets) + 1) * h266AggregatedPacketLengthSize)
	hasDonl := packets[0].donl != nil
	// first AU's DONL field
	if hasDonl {
		totalSize += 2
	}
	for _, p := range packets {
		totalSize += p.wireSize()
		// individual AUs have their DONL fields removed
		if hasDonl {
			totalSize -= 2
		}
	}
	totalSize += newPacket.wireSize()
	if hasDonl {
		totalSize -= 2
	}

	return totalSize > int(mtu)
}

// Reference: https://datatracker.ietf.org/doc/html/rfc9328#section-4.3.2
func newH266AggregationPacket(packets []h266SingleNALUnitPacket) (*h266AggregationPacket, error) {
	if packets == nil {
		return nil, errNilPacket
	}
	if len(packets) < 2 {
		return nil, errNotEnoughPackets
	}

	header := uint16(0)
	// type 28
	header |= 28 << 3

	firstPacket := packets[0]
	if firstPacket.wireSize() > int(h266AggregatedPacketMaxSize) {
		return nil, errPacketTooLarge
	}

	fBit := firstPacket.payloadHeader.F()
	layerID := firstPacket.payloadHeader.LayerID()
	tid := firstPacket.payloadHeader.TID()

	payload := make([]byte, 0)

	for _, packet := range packets {
		// following AUs' DONs are derived as the previous AU's DON + 1
		packet.donl = nil

		if packet.wireSize() > int(h266AggregatedPacketMaxSize) {
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

		payload = packet.packetize(payload)
	}

	header |= uint16(tid)
	header |= uint16(layerID) << 8

	if fBit {
		header |= uint16(0b1) << 15
	}

	packet := h266AggregationPacket{
		h266NALUHeader(header),
		firstPacket.donl,
		payload,
	}

	return &packet, nil
}

func splitH266AggregationPacket(packet h266AggregationPacket) ([]h266SingleNALUnitPacket, error) {
	curDonl := packet.donl
	packets := make([]h266SingleNALUnitPacket, 0)
	payload := packet.payload
	for len(payload) > 0 {
		if len(payload) < 2 {
			return nil, errShortPacket
		}
		curLen := binary.BigEndian.Uint16(payload)
		if len(payload[2:]) < int(curLen) {
			return nil, errShortPacket
		}

		parsed, err := parseH266Packet(payload[2:2+curLen], false)
		if err != nil {
			return nil, err
		}
		p, ok := parsed.(*h266SingleNALUnitPacket)
		if !ok {
			return nil, errInvalidNalType
		}
		if curDonl != nil {
			nextDonl := *curDonl + 1
			p.donl = curDonl
			curDonl = &nextDonl
		}
		packets = append(packets, *p)
		payload = payload[2+curLen:]
	}
	if len(packets) < 2 {
		return nil, errNotEnoughPackets
	}

	return packets, nil
}

func (p *h266AggregationPacket) isH266Packet() {}

func (p *h266AggregationPacket) packetize(buf []byte) []byte {
	buf = binary.BigEndian.AppendUint16(buf, uint16(p.payloadHeader))

	if p.donl != nil {
		buf = binary.BigEndian.AppendUint16(buf, *p.donl)
	}

	buf = append(buf, p.payload...)

	return buf
}

// Fragmentation Unit implementation

// h266FragmentationUnitHeader is the header for each H266FragmentationPacket.
//
//	+---------------+
//	|0|1|2|3|4|5|6|7|
//	+-+-+-+-+-+-+-+-+
//	|S|E|P|  FuType |
//	+---------------+
type h266FragmentationUnitHeader uint8

func newH266FragmentationUnitHeader(
	payloadHeader h266NALUHeader,
	s, e, p bool, //nolint:unparam
) h266FragmentationUnitHeader {
	header := payloadHeader.Type()
	if s {
		header |= 0b1 << 7
	}
	if e {
		header |= 0b1 << 6
	}
	if p {
		header |= 0b1 << 5
	}

	return h266FragmentationUnitHeader(header)
}

// S represents the start of a fragmented NAL unit.
func (h h266FragmentationUnitHeader) S() bool {
	const mask = 0b10000000

	return (h & mask) != 0
}

// E represents the end of a fragmented NAL unit.
func (h h266FragmentationUnitHeader) E() bool {
	const mask = 0b01000000

	return (h & mask) != 0
}

// P indicates the last FU of the last VCL NAL unit of a coded picture.
func (h h266FragmentationUnitHeader) P() bool {
	const mask = 0b00100000

	return (h & mask) != 0
}

// FuType MUST be equal to the field Type of the fragmented NAL unit.
func (h h266FragmentationUnitHeader) FuType() uint8 {
	const mask = 0b00011111

	return uint8(h) & mask
}

// h266FragmentationPacket is a single H266 Fragmentation Unit.
//
//	 0                   1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|   PayloadHdr (Type=29)        |   FU header   | DONL (cond)   |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
//	|   DONL (cond) |                                               |
//	|-+-+-+-+-+-+-+-+                                               |
//	|                         FU payload                            |
//	|                                                               |
//	|                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                               :...OPTIONAL RTP padding        |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Reference: https://datatracker.ietf.org/doc/html/rfc9328#section-4.3.3
type h266FragmentationPacket struct {
	payloadHeader h266NALUHeader
	fuHeader      h266FragmentationUnitHeader
	donl          *uint16
	payload       []byte
}

// Replaces the original header's type with 29, while keeping other fields.
func newH266FragmentationPacketHeader(payloadHeader h266NALUHeader) h266NALUHeader {
	typeMask := ^uint16(0b11111000)

	return h266NALUHeader((uint16(payloadHeader) & typeMask) | (h266NaluFragmentationUnitType << 3))
}

// Replaces the FU's payload header's type with the FU Header's type, while keeping other fields.
func rebuildH266FragmentationPacketHeader(
	payloadHeader h266NALUHeader,
	fuHeader h266FragmentationUnitHeader,
) h266NALUHeader {
	typeMask := ^uint16(0b11111000)
	origType := uint8(fuHeader) & 0b00011111

	return h266NALUHeader((uint16(payloadHeader) & typeMask) | (uint16(origType) << 3))
}

// Splits a H266SingleNALUnitPacket into many FU packets.
//
// Errors if the packet would result in a single FU packet.
//
// The P bit is not set in any case.
func newH266FragmentationPackets(mtu uint16, packet *h266SingleNALUnitPacket) ([]h266FragmentationPacket, error) {
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

	packets := make([]h266FragmentationPacket, 0)
	header := newH266FragmentationPacketHeader(packet.payloadHeader)

	fuPayload := packet.payload

	firstPacket := h266FragmentationPacket{
		payloadHeader: header,
		fuHeader:      newH266FragmentationUnitHeader(packet.payloadHeader, true, false, false),
		donl:          packet.donl,
		payload:       fuPayload[:sliceSize],
	}
	packets = append(packets, firstPacket)
	fuPayload = fuPayload[sliceSize:]

	for len(fuPayload) > sliceSize {
		p := h266FragmentationPacket{
			payloadHeader: header,
			fuHeader:      newH266FragmentationUnitHeader(packet.payloadHeader, false, false, false),
			donl:          nil,
			payload:       fuPayload[:sliceSize],
		}
		packets = append(packets, p)

		fuPayload = fuPayload[sliceSize:]
	}

	lastPacket := h266FragmentationPacket{
		payloadHeader: header,
		fuHeader:      newH266FragmentationUnitHeader(packet.payloadHeader, false, true, false),
		donl:          nil,
		payload:       fuPayload,
	}
	packets = append(packets, lastPacket)

	return packets, nil
}

func rebuildH266FragmentationPackets(packets []h266FragmentationPacket) (*h266SingleNALUnitPacket, error) {
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

	rebuilt := h266SingleNALUnitPacket{
		payloadHeader: rebuildH266FragmentationPacketHeader(packets[0].payloadHeader, packets[0].fuHeader),
		donl:          packets[0].donl,
		payload:       payload,
	}

	return &rebuilt, nil
}

func (p *h266FragmentationPacket) isH266Packet() {}

func (p *h266FragmentationPacket) packetize(buf []byte) []byte {
	buf = binary.BigEndian.AppendUint16(buf, uint16(p.payloadHeader))
	buf = append(buf, uint8(p.fuHeader))

	if p.donl != nil {
		buf = binary.BigEndian.AppendUint16(buf, *p.donl)
	}

	buf = append(buf, p.payload...)

	return buf
}

func parseH266Packet(buf []byte, hasDonl bool) (isH266Packet, error) { // nolint:cyclop
	if buf == nil {
		return nil, errNilPacket
	}
	minLength := h266NaluHeaderSize
	payloadStart := h265NaluHeaderSize
	donlStart := h266NaluHeaderSize

	if hasDonl {
		payloadStart += h266NaluDonlSize
		minLength += h266NaluDonlSize
	}

	if len(buf) < minLength {
		return nil, errShortPacket
	}

	header := newH266NALUHeader(buf[0], buf[1])

	// take into account FuPacket
	if header.IsFragmentationUnit() {
		payloadStart += 1
		donlStart += 1
		minLength += 1
	}

	if len(buf) < minLength {
		return nil, errShortPacket
	}

	var donl *uint16
	if hasDonl {
		donlVal := binary.BigEndian.Uint16(buf[donlStart : donlStart+2])
		donl = &donlVal
	}

	switch {
	case header.IsAggregationPacket():
		packet := &h266AggregationPacket{
			payloadHeader: header,
			donl:          donl,
			payload:       buf[payloadStart:],
		}

		return packet, nil
	case header.IsFragmentationUnit():
		packet := &h266FragmentationPacket{
			payloadHeader: header,
			fuHeader:      h266FragmentationUnitHeader(buf[2]),
			donl:          donl,
			payload:       buf[payloadStart:],
		}

		return packet, nil
	default:
		packet := &h266SingleNALUnitPacket{
			payloadHeader: header,
			donl:          donl,
			payload:       buf[payloadStart:],
		}

		return packet, nil
	}
}

type H266Depacketizer struct {
	hasDonl  bool
	partials []h266FragmentationPacket
}

func (d *H266Depacketizer) Unmarshal(packet []byte) ([]byte, error) { //nolint: cyclop
	if packet == nil {
		return nil, errNilPacket
	}
	if len(packet) < 2 {
		return nil, errShortPacket
	}

	parsedHeader := newH266NALUHeader(packet[0], packet[1])

	// we are expecting another FU but only the first FU of a series has the DONL field present
	isFrag := parsedHeader.IsFragmentationUnit()
	parseDonl := d.hasDonl && ((len(d.partials) == 0 && isFrag) || !isFrag)

	parsed, err := parseH266Packet(packet, parseDonl)
	if err != nil {
		return nil, err
	}
	output := make([]byte, 0)

	fragment, ok := parsed.(*h266FragmentationPacket)

	if ok { // nolint:nestif
		if fragment.fuHeader.E() {
			d.partials = append(d.partials, *fragment)
			output = append(output, annexbNALUStartCode...)

			rebuilt, err := rebuildH266FragmentationPackets(d.partials)
			if err != nil {
				return nil, err
			}
			rebuilt.donl = nil
			output = append(output, rebuilt.packetize(make([]byte, 0))...)
			d.partials = d.partials[:0]

			return output, nil
		} else {
			// discard lost partial fragments
			if fragment.fuHeader.S() {
				d.partials = d.partials[:0]
			} else if len(d.partials) == 0 {
				return nil, errExpectFragmentationStartUnit
			}

			d.partials = append(d.partials, *fragment)

			return nil, nil
		}
	}

	d.partials = d.partials[:0]

	aggregation, ok := parsed.(*h266AggregationPacket)
	if ok {
		aggregated, err := splitH266AggregationPacket(*aggregation)
		if err != nil {
			return nil, err
		}
		for _, p := range aggregated {
			output = append(output, annexbNALUStartCode...)
			p.donl = nil
			output = p.packetize(output)
		}

		return output, nil
	}

	output = append(output, annexbNALUStartCode...)
	single, ok := parsed.(*h266SingleNALUnitPacket)
	if !ok {
		return nil, errNalCorrupted
	}

	single.donl = nil
	output = single.packetize(output)

	return output, nil
}

type H266Packetizer struct {
	naluBuffer []h266SingleNALUnitPacket
}

func (p *H266Packetizer) Payload(mtu uint16, payload []byte) [][]byte { //nolint: cyclop
	var payloads [][]byte

	flushBuffer := func() {
		switch len(p.naluBuffer) {
		case 0:
			return
		case 1:
			packetized := p.naluBuffer[0].packetize(make([]byte, 0))
			p.naluBuffer = p.naluBuffer[:0]
			payloads = append(payloads, packetized)
		default:
			aggrPacket, err := newH266AggregationPacket(p.naluBuffer)
			p.naluBuffer = p.naluBuffer[:0]
			if err != nil {
				return
			}
			packetized := aggrPacket.packetize(make([]byte, 0))
			payloads = append(payloads, packetized)
		}
	}

	emitH266Nalus(payload, func(nalu []byte) {
		if len(nalu) < h266NaluHeaderSize {
			return
		}

		parsedPacket, err := parseH266Packet(nalu, false)
		if err != nil {
			return
		}

		// ignores RFC9328 packets
		packet, ok := parsedPacket.(*h266SingleNALUnitPacket)
		if !ok {
			return
		}

		if len(nalu) > int(mtu) { //nolint:nestif
			flushBuffer()
			fragments, err := newH266FragmentationPackets(mtu, packet)
			if err != nil {
				return
			}
			for _, f := range fragments {
				packetized := f.packetize(make([]byte, 0))
				payloads = append(payloads, packetized)
			}
		} else {
			if len(p.naluBuffer) == 0 {
				if canAggregate(mtu, packet) {
					p.naluBuffer = append(p.naluBuffer, *packet)
				} else {
					payloads = append(payloads, nalu)
				}
			} else {
				// can't fit any more packets, just send what we have and make current first in buffer
				if shouldAggregateNow(mtu, p.naluBuffer, *packet) {
					flushBuffer()
				}
				p.naluBuffer = append(p.naluBuffer, *packet)
			}
		}
	})

	flushBuffer()

	return payloads
}
