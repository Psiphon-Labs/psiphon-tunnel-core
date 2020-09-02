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

package packetman

import (
	"bytes"
	"encoding/json"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestTransformations(t *testing.T) {

	// Test: apply various transformations to an original packet, then parse the
	// resulting packets and check that flags/fields/options are as expected.

	// Limitation: gopacket, used here in the test to verify transformations,
	// will fail to parse some or all of certain packets that can be created by
	// certain transformations. gopacket will fail to parse packets with too many
	// option bytes or invalid DataOffset values. gopacket will stop
	// deserializing TCP options as soon as it encounters the EOL option, even if
	// the packet actually contains more options. Etc.

	specJSON := []byte(`
    {
        "Name": "test-spec",
        "PacketSpecs": [
            ["TCP-flags SA",
             "TCP-flags S",
             "TCP-srcport ffff",
             "TCP-dstport ffff",
             "TCP-seq ffffffff",
             "TCP-ack ffffffff",
             "TCP-dataoffset 0f",
             "TCP-window ffff",
             "TCP-checksum ffff",
             "TCP-urgent ffff",
             "TCP-option-nop omit",
             "TCP-option-mss ffff",
             "TCP-option-windowscale ff",
             "TCP-option-sackpermitted ",
	         "TCP-option-sack ffffffffffffffff",
	         "TCP-option-timestamps ffffffffffffffff",
             "TCP-payload eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
             "TCP-payload ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"],

            ["TCP-flags random",
             "TCP-srcport random",
             "TCP-dstport random",
             "TCP-seq random",
             "TCP-ack random",
             "TCP-dataoffset random",
             "TCP-window random",
             "TCP-checksum random",
             "TCP-urgent random",
             "TCP-option-mss random",
             "TCP-option-windowscale random",
             "TCP-option-sackpermitted random",
             "TCP-option-timestamps random",
             "TCP-payload random"]
        ]
    }
	`)

	var spec *Spec
	err := json.Unmarshal(specJSON, &spec)
	if err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	c, err := compileSpec(spec)
	if err != nil {
		t.Fatalf("compileSpec failed: %v", err)
	}

	if c.name != spec.Name {
		t.Fatalf("unexpected compiled spec name: %s", c.name)
	}

	originalIPv4 := &layers.IPv4{
		Version:  0x04,
		IHL:      0x05,
		Protocol: 0x06,
		SrcIP:    net.IPv4(192, 168, 0, 1),
		DstIP:    net.IPv4(192, 168, 0, 2),
	}

	originalTCP := &layers.TCP{
		SYN: true,
		ACK: true,
		Options: []layers.TCPOption{
			layers.TCPOption{OptionType: layers.TCPOptionKindNop, OptionLength: 1},
			layers.TCPOption{OptionType: layers.TCPOptionKindSACKPermitted, OptionLength: 2},
			layers.TCPOption{OptionType: layers.TCPOptionKindSACK, OptionLength: 10, OptionData: bytes.Repeat([]byte{0}, 8)},
			layers.TCPOption{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: bytes.Repeat([]byte{0}, 8)},
		},
	}

	originalTCP.SetNetworkLayerForChecksum(originalIPv4)

	originalPayload := gopacket.Payload([]byte{0, 0, 0, 0})

	buffer := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(
		buffer,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		originalIPv4,
		originalTCP,
		originalPayload)
	originalPacketData := buffer.Bytes()

	originalPacket := gopacket.NewPacket(originalPacketData, layers.LayerTypeIPv4, gopacket.Default)
	errLayer := originalPacket.ErrorLayer()
	if errLayer != nil {
		t.Fatalf("gopacket.NewPacket failed: %v", errLayer.Error())
	}

	stripEOLOption(originalPacket)

	repeats := 1000
repeatLoop:
	for i := 0; i < repeats; i++ {

		lastRepeat := i == repeats-1

		injectPackets, err := c.apply(originalPacket)
		if err != nil {
			t.Fatalf("apply failed: %v", err)
		}

		if len(injectPackets) != 2 {
			t.Fatalf("unexpected injectPackets count: %d", len(injectPackets))
		}

		for packetNum, packetData := range injectPackets {

			packet := gopacket.NewPacket(packetData, layers.LayerTypeIPv4, gopacket.Default)

			errLayer := packet.ErrorLayer()
			if errLayer != nil {
				t.Fatalf("gopacket.NewPacket failed: %v", errLayer.Error())
			}

			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			if tcpLayer == nil {
				t.Fatalf("missing TCP layer")
			}

			tcp := tcpLayer.(*layers.TCP)

			payloadLayer := packet.Layer(gopacket.LayerTypePayload)
			if payloadLayer == nil {
				t.Fatalf("missing payload layer")
			}

			payload := payloadLayer.(*gopacket.Payload)

			optionsEqual := func(a, b layers.TCPOption) bool {
				if a.OptionType != b.OptionType ||
					a.OptionLength != b.OptionLength ||
					!bytes.Equal(a.OptionData, b.OptionData) {
					return false
				}
				return true
			}

			optionsListEqual := func(a, b []layers.TCPOption) bool {
				if len(a) != len(b) {
					return false
				}
				for i, o := range a {
					if !optionsEqual(o, b[i]) {
						return false
					}
				}
				return true
			}

			if packetNum == 0 {

				// With multiple, redundant value specs (TCP-flags in the test case) the
				// _last_ value spec should be applied. Values should be truncated to
				// protocol lengths. The NOP option in the original packet should be
				// omitted.

				expectedOptions := []layers.TCPOption{
					layers.TCPOption{OptionType: layers.TCPOptionKindSACKPermitted, OptionLength: 2},
					layers.TCPOption{OptionType: layers.TCPOptionKindSACK, OptionLength: 10, OptionData: bytes.Repeat([]byte{0xff}, 8)},
					layers.TCPOption{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: bytes.Repeat([]byte{0xff}, 8)},
					layers.TCPOption{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: bytes.Repeat([]byte{0xff}, 2)},
					layers.TCPOption{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: bytes.Repeat([]byte{0xff}, 1)},
					layers.TCPOption{OptionType: layers.TCPOptionKindEndList, OptionLength: 1},
				}

				if tcp.SrcPort != 0xffff ||
					tcp.DstPort != 0xffff ||
					tcp.Seq != 0xffffffff ||
					tcp.Ack != 0xffffffff ||
					tcp.FIN || !tcp.SYN || tcp.RST || tcp.PSH || tcp.ACK ||
					tcp.URG || tcp.ECE || tcp.CWR || tcp.NS ||
					tcp.Window != 0xffff ||
					tcp.Urgent != 0xffff ||
					!optionsListEqual(tcp.Options, expectedOptions) {
					t.Fatalf("unexpected TCP layer: %+v", tcp)
				}

				expectedPayload := bytes.Repeat([]byte{0xff}, 32)
				if !bytes.Equal(expectedPayload, *payload) {
					t.Fatalf("unexpected payload: %x", *payload)
				}

			} else {

				// In at least one repeat, randomized fields fully differ from original,
				// including zero-values; original NOP and SACK options retained; random
				// options have correct protocol lengths.

				if tcp.SrcPort == originalTCP.SrcPort ||
					tcp.DstPort == originalTCP.DstPort ||
					tcp.Seq == originalTCP.Seq ||
					tcp.Ack == originalTCP.Ack ||
					(tcp.FIN == originalTCP.FIN &&
						tcp.SYN == originalTCP.SYN &&
						tcp.RST == originalTCP.RST &&
						tcp.PSH == originalTCP.PSH &&
						tcp.ACK == originalTCP.ACK &&
						tcp.URG == originalTCP.URG &&
						tcp.ECE == originalTCP.ECE &&
						tcp.CWR == originalTCP.CWR &&
						tcp.NS == originalTCP.NS) ||
					tcp.Window == originalTCP.Window ||
					tcp.Checksum == originalTCP.Checksum ||
					tcp.Urgent == originalTCP.Urgent ||
					len(tcp.Options) != 7 ||
					!optionsEqual(tcp.Options[0], originalTCP.Options[0]) ||
					!optionsEqual(tcp.Options[1], originalTCP.Options[1]) ||
					!optionsEqual(tcp.Options[2], originalTCP.Options[2]) ||
					tcp.Options[3].OptionType != layers.TCPOptionKindTimestamps ||
					tcp.Options[3].OptionLength != 10 ||
					optionsEqual(tcp.Options[3], originalTCP.Options[3]) ||
					tcp.Options[4].OptionType != layers.TCPOptionKindMSS ||
					tcp.Options[4].OptionLength != 4 ||
					tcp.Options[5].OptionType != layers.TCPOptionKindWindowScale ||
					tcp.Options[5].OptionLength != 3 ||
					tcp.Options[6].OptionType != layers.TCPOptionKindEndList ||
					bytes.Equal(originalPayload, *payload) {

					if lastRepeat {
						t.Fatalf("unexpected TCP layer: %+v", tcp)
					}
				} else {
					break repeatLoop
				}
			}
		}
	}
}
