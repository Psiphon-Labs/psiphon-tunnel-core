/*
 * Copyright (c) 2020, Psiphon Inc.
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

/*
Package packetman implements low-level manipulation of TCP packets, enabling a
variety of strategies to evade network censorship.

This implementation is entirely based on and is a subset of Geneva:

  Come as You Are: Helping Unmodified Clients Bypass Censorship with
  Server-side Evasion
  Kevin Bock, George Hughey, Louis-Henri Merino, Tania Arya, Daniel Liscinsky,
  Regina Pogosian, Dave Levin
  ACM SIGCOMM 2020

  Geneva: Evolving Censorship Evasion Strategies
  Kevin Bock, George Hughey, Xiao Qiang, Dave Levin
  ACM CCS 2019 (Conference on Computer and Communications Security)

  https://github.com/Kkevsterrr/geneva

This package implements the equivilent of the Geneva "engine", which can
execute packet manipulation strategies. It does not implement the genetic
algorithm component.

Other notable differences:

- We intercept, parse, and transform only server-side outbound SYN-ACK
packets. Geneva supports client-side packet manipulation with a more diverse
set of trigger packets, but in practise we cannot execute most low-level
packet operations on client platforms such as Android and iOS.

- For expediancy, we use a simplified strategy syntax (called transformation
specs, to avoid confusion with the more general original). As we do not
evolve strategies, we do not use a tree representation and some
randomization tranformations are simplified.

At this time, full functionality is limited to the Linux platform.

Security: external parties can induce the server to emit a SYN-ACK, invoking
the packet manipulation logic. External parties cannot set the transformation
specs, and, as the input is the server-side generated SYN-ACK packet, cannot
influence the packet manipulation with any external input parameters.

*/
package packetman

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Config specifies a packet manipulation configuration.
type Config struct {

	// Logger is used for logging events and metrics.
	Logger common.Logger

	// ProtocolPorts specifies the set of TCP ports to which SYN-ACK packet
	// interception and manipulation is to be applied. To accommodate hosts with
	// multiple IP addresses, packet interception is applied to all interfaces.
	ProtocolPorts []int

	// On Linux, which uses NFQUEUE and raw sockets, QueueNumber is the NFQUEUE
	// queue-num parameter to be used.
	QueueNumber int

	// On Linux, which uses NFQUEUE and raw sockets, SocketMark is the SO_MARK
	// value to be used. When 0, a default value is used.
	SocketMark int

	// Specs is the list of packet transformation Spec value that are to be
	// available for packet manipulation. Spec names must be unique.
	Specs []*Spec

	// SelectSpecName is a callback invoked for each intercepted SYN-ACK packet.
	// SelectSpecName must return a name of a Spec, in Specs, to apply that
	// transformation spec, or "" to send the SYN-ACK packet unmodified.
	// The second return value is arbitrary extra data that is associated
	// with the packet's connection; see GetAppliedSpecName.
	//
	// The inputs protocolPort and clientIP allow the callback to select a Spec
	// based on the protocol running at the intercepted packet's port and/or
	// client GeoIP.
	SelectSpecName func(protocolPort int, clientIP net.IP) (string, interface{})

	// SudoNetworkConfigCommands specifies whether to use "sudo" when executing
	// network configuration commands. See comment for same parameter in
	// psiphon/common/tun.
	SudoNetworkConfigCommands bool

	// AllowNoIPv6NetworkConfiguration indicates that failures while configuring
	// tun interfaces and routing for IPv6 are to be logged as warnings only. See
	// comment for same parameter in psiphon/common/tun.
	AllowNoIPv6NetworkConfiguration bool
}

// Spec specifies a set of transformations to be applied to an intercepted
// SYN-ACK packet to produce zero or more replacement packets to be sent in
// its place.
//
// Each element in PacketSpecs specifies a new outgoing packet. Each element
// in a packet specification specifies an individual transformation to be
// applied, in turn, to a copy of the intercepted SYN-ACK packet, producing
// the outgoing packet.
//
// Syntax of individual tranformations:
//
// "TCP-flags random|<flags>"
// flags: FSRPAUECN
//
// "TCP-<field> random|<base64>"
// field: srcport, dstport, seq, ack, dataoffset, window, checksum, urgent
//
// "TCP-option-<option> random|omit|<base64>"
// option: eol, nop, mss, windowscale, sackpermitted, sack, timestamps,
// altchecksum, altchecksumdata, md5header, usertimeout
//
// "TCP-payload random|<base64>"
//
// For example, this Geneva strategy:
//   [TCP:flags:SA]-duplicate(tamper{TCP:flags:replace:R},tamper{TCP:flags:replace:S})-| \/
//
// is represented as follows (in JSON encoding):
//   [["TCP-flags R"], ["TCP-flags S"]]
//
//
// Field and option values must be the expected length (see implementation).
//
// A Spec may produce invalid packets. For example, the total options length
// can exceed 40 bytes and the DataOffset field may overflow.
type Spec struct {
	Name        string
	PacketSpecs [][]string
}

// Validate checks that the transformation spec is syntactically correct.
func (s *Spec) Validate() error {
	_, err := compileSpec(s)
	return errors.Trace(err)
}

type compiledSpec struct {
	name                string
	compiledPacketSpecs [][]transformation
}

func compileSpec(spec *Spec) (*compiledSpec, error) {

	compiledPacketSpecs := make([][]transformation, len(spec.PacketSpecs))
	for i, _ := range spec.PacketSpecs {
		compiledPacketSpecs[i] = make([]transformation, len(spec.PacketSpecs[i]))
		for j, transformationSpec := range spec.PacketSpecs[i] {
			transform, err := compileTransformation(transformationSpec)
			if err != nil {
				return nil, errors.Trace(err)
			}
			compiledPacketSpecs[i][j] = transform
		}
	}
	return &compiledSpec{
		name:                spec.Name,
		compiledPacketSpecs: compiledPacketSpecs}, nil
}

func (spec *compiledSpec) apply(interceptedPacket gopacket.Packet) ([][]byte, error) {

	packets := make([][]byte, len(spec.compiledPacketSpecs))

	for i, packetTransformations := range spec.compiledPacketSpecs {

		var networkLayer gopacket.NetworkLayer
		var serializableNetworkLayer gopacket.SerializableLayer

		// Copy the network layer (IPv4 or IPv6) as modifications may be made to
		// checksums or lengths in that layer. Note this is not a deep copy of
		// fields such as the Options slice, as these are not modified.

		interceptedIPv4Layer := interceptedPacket.Layer(layers.LayerTypeIPv4)
		if interceptedIPv4Layer != nil {
			transformedIPv4 := *interceptedIPv4Layer.(*layers.IPv4)
			networkLayer = &transformedIPv4
			serializableNetworkLayer = &transformedIPv4
		} else {
			interceptedIPv6Layer := interceptedPacket.Layer(layers.LayerTypeIPv6)
			transformedIPv6 := *interceptedIPv6Layer.(*layers.IPv6)
			networkLayer = &transformedIPv6
			serializableNetworkLayer = &transformedIPv6
		}

		interceptedTCP := interceptedPacket.Layer(layers.LayerTypeTCP).(*layers.TCP)

		// Copy the TCP layer before transforming it. Again this is not a deep copy.
		// If a transformation modifies the Options slice, it will be copied at that
		// time.

		transformedTCP := *interceptedTCP
		var payload gopacket.Payload
		setCalculatedField := false

		for _, transform := range packetTransformations {
			transform.apply(&transformedTCP, &payload)
			if transform.setsCalculatedField() {
				setCalculatedField = true
			}
		}

		err := transformedTCP.SetNetworkLayerForChecksum(networkLayer)
		if err != nil {
			return nil, errors.Trace(err)
		}

		buffer := gopacket.NewSerializeBuffer()
		options := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

		gopacket.SerializeLayers(
			buffer,
			options,
			serializableNetworkLayer,
			&transformedTCP,
			payload)

		// In the first SerializeLayers call, all IP and TCP length and checksums
		// are recalculated and set to the correct values with transformations
		// applied.
		//
		// If the spec calls for setting the TCP DataOffset or Checksum, a second
		// SerializeLayers call is performed, which will repave these values without
		// recalculation; all other calculated lengths and checksums are retained
		// from the first round.

		if setCalculatedField {
			buffer.Clear()
			gopacket.SerializeLayers(
				buffer,
				gopacket.SerializeOptions{},
				serializableNetworkLayer,
				&transformedTCP,
				payload)
		}

		packets[i] = buffer.Bytes()
	}

	return packets, nil
}

type transformation interface {
	apply(tcp *layers.TCP, payload *gopacket.Payload)
	setsCalculatedField() bool
}

const (
	transformationTypeUnknown = iota
	transformationTypeOmit
	transformationTypeRandom
	transformationTypeValue
)

func compileTransformation(spec string) (transformation, error) {

	parts := strings.Split(spec, " ")
	if len(parts) != 2 {
		return nil, errors.Tracef("invalid spec: %s", spec)
	}
	fieldSpec := parts[0]
	valueSpec := parts[1]

	parts = strings.Split(fieldSpec, "-")
	if (len(parts) != 2 && len(parts) != 3) || parts[0] != "TCP" {
		return nil, errors.Tracef("invalid field spec: %s", fieldSpec)
	}

	var transformationType int

	if valueSpec == "omit" {
		transformationType = transformationTypeOmit
	} else if valueSpec == "random" {
		transformationType = transformationTypeRandom
	} else {
		transformationType = transformationTypeValue
	}

	var t transformation
	var err error

	if len(parts) == 3 {
		if parts[1] != "option" {
			return nil, errors.Tracef("invalid field spec: %s", fieldSpec)
		}
		t, err = newTransformationTCPOption(parts[2], transformationType, valueSpec)
	} else if parts[1] == "flags" {
		t, err = newTransformationTCPFlags(transformationType, valueSpec)
	} else if parts[1] == "payload" {
		t, err = newTransformationTCPPayload(transformationType, valueSpec)
	} else {
		t, err = newTransformationTCPField(parts[1], transformationType, valueSpec)
	}
	if err != nil {
		return nil, errors.Tracef("invalid field spec: %s: %v", fieldSpec, err)
	}
	return t, nil
}

type transformationTCPFlags struct {
	transformationType int
	flags              string
}

func newTransformationTCPFlags(
	transformationType int, valueSpec string) (*transformationTCPFlags, error) {

	var flags string

	switch transformationType {
	case transformationTypeRandom:
	case transformationTypeValue:
		checkFlags := valueSpec
		for _, f := range "FSRPAUECN" {
			checkFlags = strings.ReplaceAll(checkFlags, string(f), "")
		}
		if checkFlags != "" {
			return nil, errors.Tracef("invalid value spec: %s", valueSpec)
		}
		flags = valueSpec
	default:
		return nil, errors.Tracef("invalid transformation type")
	}

	return &transformationTCPFlags{
		transformationType: transformationType,
		flags:              flags,
	}, nil
}

func (t *transformationTCPFlags) apply(tcp *layers.TCP, _ *gopacket.Payload) {

	var flags string

	if t.transformationType == transformationTypeRandom {

		// Differs from Geneva, which often selects real flag combinations,
		// presumably to focus its search space:
		// https://github.com/Kkevsterrr/geneva/blob/de6823ba7723582054d2047083262cabffa85f36/layers/tcp_layer.py#L117-L121.

		for _, f := range "FSRPAUECN" {
			if prng.FlipCoin() {
				flags += string(f)
			}
		}
	} else {
		flags = t.flags
	}

	tcp.FIN = strings.Index(t.flags, "F") != -1
	tcp.SYN = strings.Index(t.flags, "S") != -1
	tcp.RST = strings.Index(t.flags, "R") != -1
	tcp.PSH = strings.Index(t.flags, "P") != -1
	tcp.ACK = strings.Index(t.flags, "A") != -1
	tcp.URG = strings.Index(t.flags, "U") != -1
	tcp.ECE = strings.Index(t.flags, "E") != -1
	tcp.CWR = strings.Index(t.flags, "C") != -1
	tcp.NS = strings.Index(t.flags, "N") != -1
}

func (t *transformationTCPFlags) setsCalculatedField() bool {
	return false
}

type transformationTCPField struct {
	fieldName          string
	transformationType int
	value              []byte
}

const (
	tcpFieldSrcPort    = "srcport"
	tcpFieldDstPort    = "dstport"
	tcpFieldSeq        = "seq"
	tcpFieldAck        = "ack"
	tcpFieldDataOffset = "dataoffset"
	tcpFieldWindow     = "window"
	tcpFieldChecksum   = "checksum"
	tcpFieldUrgent     = "urgent"
)

func newTransformationTCPField(
	fieldName string, transformationType int, valueSpec string) (*transformationTCPField, error) {

	length := 0

	switch fieldName {
	case tcpFieldSrcPort:
		length = 2
	case tcpFieldDstPort:
		length = 2
	case tcpFieldSeq:
		length = 4
	case tcpFieldAck:
		length = 4
	case tcpFieldDataOffset:
		length = 1
	case tcpFieldWindow:
		length = 2
	case tcpFieldChecksum:
		length = 2
	case tcpFieldUrgent:
		length = 2
	default:
		return nil, errors.Tracef("invalid field name: %s", fieldName)
	}

	var decodedValue []byte

	switch transformationType {
	case transformationTypeRandom:
	case transformationTypeValue:
		var err error
		decodedValue, err = hex.DecodeString(valueSpec)
		if err == nil && len(decodedValue) != length {
			err = fmt.Errorf("invalid value length: %d", len(decodedValue))
		}
		if err != nil {
			return nil, errors.Tracef("invalid value spec: %s: %v", valueSpec, err)
		}
	default:
		return nil, errors.Tracef("invalid transformation type")
	}

	return &transformationTCPField{
		fieldName:          fieldName,
		transformationType: transformationType,
		value:              decodedValue,
	}, nil
}

func (t *transformationTCPField) apply(tcp *layers.TCP, _ *gopacket.Payload) {

	var value [4]byte

	if t.transformationType == transformationTypeRandom {
		_, _ = prng.Read(value[:])
	} else {
		copy(value[:], t.value)
	}

	switch t.fieldName {
	case tcpFieldSrcPort:
		tcp.SrcPort = layers.TCPPort(binary.BigEndian.Uint16(value[:]))
	case tcpFieldDstPort:
		tcp.DstPort = layers.TCPPort(binary.BigEndian.Uint16(value[:]))
	case tcpFieldSeq:
		tcp.Seq = binary.BigEndian.Uint32(value[:])
	case tcpFieldAck:
		tcp.Ack = binary.BigEndian.Uint32(value[:])
	case tcpFieldDataOffset:
		tcp.DataOffset = value[0]
		// DataOffset is a 4-bit field; the most significant 4 bits are ignored
		tcp.DataOffset &= 0x0f
	case tcpFieldWindow:
		// Differs from Geneva: https://github.com/Kkevsterrr/geneva/blob/de6823ba7723582054d2047083262cabffa85f36/layers/tcp_layer.py#L117-L121
		tcp.Window = binary.BigEndian.Uint16(value[:])
	case tcpFieldChecksum:
		tcp.Checksum = binary.BigEndian.Uint16(value[:])
	case tcpFieldUrgent:
		tcp.Urgent = binary.BigEndian.Uint16(value[:])
	}
}

func (t *transformationTCPField) setsCalculatedField() bool {
	return t.fieldName == tcpFieldDataOffset || t.fieldName == tcpFieldChecksum
}

type transformationTCPOption struct {
	optionName         string
	transformationType int
	value              []byte
}

const (
	tcpOptionEOL             = "eol"
	tcpOptionNOP             = "nop"
	tcpOptionMSS             = "mss"
	tcpOptionWindowScale     = "windowscale"
	tcpOptionSACKPermitted   = "sackpermitted"
	tcpOptionSACK            = "sack"
	tcpOptionTimestamps      = "timestamps"
	tcpOptionAltChecksum     = "altchecksum"
	tcpOptionAltChecksumData = "altchecksumdata"
	tcpOptionMD5Header       = "md5header"
	tcpOptionUserTimeout     = "usertimeout"
)

func tcpOptionInfo(optionName string) (layers.TCPOptionKind, []int, bool) {

	var kind layers.TCPOptionKind
	var validLengths []int
	switch optionName {
	case tcpOptionEOL:
		kind = layers.TCPOptionKindEndList
		validLengths = nil // no option length field
	case tcpOptionNOP:
		kind = layers.TCPOptionKindNop
		validLengths = nil
	case tcpOptionMSS:
		kind = layers.TCPOptionKindMSS
		validLengths = []int{2}
	case tcpOptionWindowScale:
		kind = layers.TCPOptionKindWindowScale
		validLengths = []int{1}
	case tcpOptionSACKPermitted:
		kind = layers.TCPOptionKindSACKPermitted
		validLengths = []int{0}
	case tcpOptionSACK:
		// https://tools.ietf.org/html/rfc2018
		kind = layers.TCPOptionKindSACK
		validLengths = []int{8, 16, 24, 32}
	case tcpOptionTimestamps:
		kind = layers.TCPOptionKindTimestamps
		validLengths = []int{8}
	case tcpOptionAltChecksum:
		kind = layers.TCPOptionKindAltChecksum
		validLengths = []int{1}
	case tcpOptionAltChecksumData:
		// https://tools.ietf.org/html/rfc1145:
		// "this field is used only when the alternate checksum that is negotiated is longer than 16 bits"
		//
		// Geneva allows setting length 0.
		kind = layers.TCPOptionKindAltChecksumData
		validLengths = []int{0, 4}
	case tcpOptionMD5Header:
		// https://tools.ietf.org/html/rfc2385
		kind = layers.TCPOptionKind(19)
		validLengths = []int{16}
	case tcpOptionUserTimeout:
		// https://tools.ietf.org/html/rfc5482
		kind = layers.TCPOptionKind(28)
		validLengths = []int{2}
	default:
		return kind, nil, false
	}
	return kind, validLengths, true
}

func newTransformationTCPOption(
	optionName string, transformationType int, valueSpec string) (*transformationTCPOption, error) {

	_, validLengths, ok := tcpOptionInfo(optionName)
	if !ok {
		return nil, errors.Tracef("invalid option name: %s", optionName)
	}

	var decodedValue []byte

	switch transformationType {
	case transformationTypeOmit:
	case transformationTypeRandom:
	case transformationTypeValue:
		var err error
		decodedValue, err = hex.DecodeString(valueSpec)
		if err == nil {
			if validLengths == nil {
				validLengths = []int{0}
			}
			if !common.ContainsInt(validLengths, len(decodedValue)) {
				err = fmt.Errorf("invalid value length: %d", len(decodedValue))
			}
		}
		if err != nil {
			return nil, errors.Tracef("invalid value spec: %s: %v", valueSpec, err)
		}
	default:
		return nil, errors.Tracef("invalid transformation type")
	}

	return &transformationTCPOption{
		optionName:         optionName,
		transformationType: transformationType,
		value:              decodedValue,
	}, nil
}

func (t *transformationTCPOption) apply(tcp *layers.TCP, _ *gopacket.Payload) {

	// This transformation makes a copy of all existing TCPOption structs, so
	// transformed option slices are not shared between multiple packets.
	//
	// All existing options are retained in the existing order. Modified options
	// are overwritten in place. New options are appended to the end of the
	// option list.
	//
	// Total option set size is not tracked or validated and the DataOffset TCP
	// field can overflow.
	//
	// Limitations:
	// - Inserting an option at a specific position is not supported.
	// - OptionLengths cannot be set to arbitrary values.
	// - Each option transformation executes a full copy of the existing option
	//   list, which is not efficient for a long list of option transformations.

	kind, validLengths, _ := tcpOptionInfo(t.optionName)

	var options []layers.TCPOption

	// The for loop iterates over all existing options plus one additional
	// iteration, copying or modifying existing options and then appending a new
	// option if required. This flag ensures that we don't both modify and append
	// a new option.
	applied := false

	for i := 0; i <= len(tcp.Options); i++ {

		if i < len(tcp.Options) {
			option := tcp.Options[i]
			if option.OptionType != kind {
				options = append(options, layers.TCPOption{
					OptionType:   option.OptionType,
					OptionLength: option.OptionLength,
					OptionData:   append([]byte(nil), option.OptionData...),
				})
				continue
			}
		} else if applied {
			// Skip the append iteration if we already applied the transformation to an
			// existing option.
			continue
		}

		// TCP options with validLengths == nil have only the "kind" byte and total
		// length 1. Options with validLengths have the "kind" byte, the "length"
		// byte, and 0 or more data bytes; in this case, "length" is 2 + the length
		// of the data.

		switch t.transformationType {

		case transformationTypeOmit:
			continue

		case transformationTypeRandom:
			if validLengths == nil {
				options = append(options, layers.TCPOption{
					OptionType:   kind,
					OptionLength: 1,
				})
			} else {
				length := validLengths[prng.Range(0, len(validLengths)-1)]
				var data []byte
				if length > 0 {
					data = prng.Bytes(length)
				}
				options = append(options, layers.TCPOption{
					OptionType:   kind,
					OptionLength: 2 + uint8(length),
					OptionData:   data,
				})
			}
			applied = true

		case transformationTypeValue:
			if validLengths == nil {
				options = append(options, layers.TCPOption{
					OptionType:   kind,
					OptionLength: 1,
				})
			} else {
				length := len(t.value)
				var data []byte
				if length > 0 {
					data = append([]byte(nil), t.value...)
				}
				options = append(options, layers.TCPOption{
					OptionType:   kind,
					OptionLength: 2 + uint8(length),
					OptionData:   data,
				})
			}
			applied = true
		}
	}

	tcp.Options = options
}

func (t *transformationTCPOption) setsCalculatedField() bool {
	return false
}

type transformationTCPPayload struct {
	transformationType int
	value              []byte
}

func newTransformationTCPPayload(
	transformationType int, valueSpec string) (*transformationTCPPayload, error) {

	var decodedValue []byte

	switch transformationType {
	case transformationTypeOmit:
	case transformationTypeRandom:
	case transformationTypeValue:
		var err error
		decodedValue, err = hex.DecodeString(valueSpec)
		if err != nil {
			return nil, errors.Tracef("invalid value spec: %s: %v", valueSpec, err)
		}
	default:
		return nil, errors.Tracef("invalid transformation type")
	}

	return &transformationTCPPayload{
		transformationType: transformationType,
		value:              decodedValue,
	}, nil
}

func (t *transformationTCPPayload) apply(tcp *layers.TCP, payload *gopacket.Payload) {

	var value []byte

	switch t.transformationType {
	case transformationTypeOmit:

	case transformationTypeRandom:
		// Differs from Geneva: https://github.com/Kkevsterrr/geneva/blob/de6823ba7723582054d2047083262cabffa85f36/layers/layer.py#L191-L197
		value = prng.Bytes(prng.Range(1, 200))

	case transformationTypeValue:
		value = t.value
	}

	if value == nil {
		// Omit the payload.
		*payload = nil
	} else {
		// Change the payload.
		*payload = append([]byte(nil), value...)
	}
}

func (t *transformationTCPPayload) setsCalculatedField() bool {
	return false
}

func stripEOLOption(packet gopacket.Packet) {

	// gopacket.NewPacket appears to decode padding (0s) as an explicit EOL
	// option (value 0) at the end of the option list. This helper strips that
	// option, allowing append-option transformations to work as expected.
	// gopacket TCP serialization will re-add padding as required.

	tcpLayer := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if len(tcpLayer.Options) > 0 &&
		tcpLayer.Options[len(tcpLayer.Options)-1].OptionType == layers.TCPOptionKindEndList {
		tcpLayer.Options = tcpLayer.Options[:len(tcpLayer.Options)-1]
	}
}
