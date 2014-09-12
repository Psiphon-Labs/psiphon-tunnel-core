/*
 * Copyright (c) 2014, Psiphon Inc.
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

package psiphon

import (
	"bytes"
	"encoding/binary"
	"net"
)

type ObfuscatedSshState int

const (
	OBFUSCATION_STATE_SEND_SEED_MESSAGE = iota
	OBFUSCATION_STATE_IDENTITY_LINE
	OBFUSCATION_STATE_PACKETS
	OBFUSCATION_STATE_FINISHED
)

// ObfuscatedSshConn wraps a Conn and applies the obfuscated SSH protocol
// to the traffic on the connection:
// https://github.com/brl/obfuscated-openssh/blob/master/README.obfuscation
// ObfuscatedSshConn is used to add obfuscation to go's stock ssh client
// without modification to that standard library code.
// The underlying connection must be used for SSH client traffic. This code
// injects the obfuscated seed message, applies obfuscated stream cipher
// transformations, and performs minimal parsing of the SSH protocol to
// determine when to stop obfuscation (after the first SSH_MSG_NEWKEYS is
// sent by the client).
type ObfuscatedSshConn struct {
	net.Conn
	obfuscator    *Obfuscator
	state         ObfuscatedSshState
	messageBuffer []byte
}

// NewObfuscatedSshConn creates a new ObfuscatedSshConn. The underlying
// conn must be used for SSH client traffic and must have transferred
// no traffic.
func NewObfuscatedSshConn(conn net.Conn, obfuscationKeyword string) (*ObfuscatedSshConn, error) {
	obfuscator, err := NewObfuscator(obfuscationKeyword)
	if err != nil {
		return nil, err
	}
	return &ObfuscatedSshConn{
		Conn:       conn,
		obfuscator: obfuscator,
		state:      OBFUSCATION_STATE_SEND_SEED_MESSAGE}, nil
}

// Read wraps standard Read, deobfuscating read bytes while in the
// obfuscating state.
func (conn *ObfuscatedSshConn) Read(buffer []byte) (n int, err error) {
	n, err = conn.Conn.Read(buffer)
	if conn.state != OBFUSCATION_STATE_FINISHED {
		conn.obfuscator.ObfuscateServerToClient(buffer)
	}
	return
}

// Write wraps standard Write, obfuscating bytes to be written while in the
// obfuscating state. The plain SSH protocol bytes are parsed to observe
// the protocol state and set obfuscation state accordingly.
func (conn *ObfuscatedSshConn) Write(buffer []byte) (n int, err error) {
	err = conn.updateState(buffer)
	if err != nil {
		return
	}
	conn.obfuscator.ObfuscateClientToServer(buffer)
	return conn.Conn.Write(buffer)
}

// updateState transforms the obfucation state. It parses the stream of bytes
// written by the client, looking for the first SSH_MSG_NEWKEYS packet sent,
// after which obfuscation is turned off.
//
// State OBFUSCATION_STATE_SEND_SEED_MESSAGE: the initial state, when the client
// has not sent any data. In this state, the seed message is injected into the
// client output stream.
//
// State OBFUSCATION_STATE_IDENTITY_LINE: before packets are sent, the client
// send a line terminated by CRLF: http://www.ietf.org/rfc/rfc4253.txt sec 4.2.
// In this state, the CRLF terminator is used to parse message boundaries.
//
// State OBFUSCATION_STATE_PACKETS: follows the binary packet protocol, parsing
// each packet until the first SSH_MSG_NEWKEYS.
// http://www.ietf.org/rfc/rfc4253.txt sec 6:
//     uint32    packet_length
//     byte      padding_length
//     byte[n1]  payload; n1 = packet_length - padding_length - 1
//     byte[n2]  random padding; n2 = padding_length
//     byte[m]   mac (Message Authentication Code - MAC); m = mac_length
// m is 0 as no MAC ha yet been negotiated.
// http://www.ietf.org/rfc/rfc4253.txt sec 7.3, 12:
// The payload for SSH_MSG_NEWKEYS is one byte, the packet type, value 21.
func (conn *ObfuscatedSshConn) updateState(buffer []byte) (err error) {
	// Use of conn.messageBuffer allows protocol message boundaries to cross Write() calls
	switch conn.state {
	case OBFUSCATION_STATE_SEND_SEED_MESSAGE:
		_, err = conn.Conn.Write(conn.obfuscator.ConsumeSeedMessage())
		if err != nil {
			return err
		}
		conn.state = OBFUSCATION_STATE_IDENTITY_LINE
	case OBFUSCATION_STATE_IDENTITY_LINE:
		conn.messageBuffer = append(conn.messageBuffer, buffer...)
		line := bytes.SplitN(conn.messageBuffer, []byte("\r\n"), 1)
		if len(line) > 1 {
			// TODO: efficiency...?
			conn.messageBuffer = conn.messageBuffer[len(line[0]):]
			conn.state = OBFUSCATION_STATE_PACKETS
		}
	case OBFUSCATION_STATE_PACKETS:
		const SSH_MSG_NEWKEYS = 21
		conn.messageBuffer = append(conn.messageBuffer, buffer...)
		const PREFIX_LENGTH = 5 // uint32 + byte
		for len(conn.messageBuffer) >= PREFIX_LENGTH {
			// This parsing repeats for a single packet sent over multiple Write() calls
			var packetLength uint32
			reader := bytes.NewReader(conn.messageBuffer)
			err = binary.Read(reader, binary.BigEndian, &packetLength)
			if err != nil {
				return err
			}
			// TODO: handle malformed packet [lengths]
			paddingLength := conn.messageBuffer[PREFIX_LENGTH-1]
			payloadLength := packetLength - uint32(paddingLength) - 1
			messageLength := PREFIX_LENGTH + packetLength - 1
			if uint32(len(conn.messageBuffer)) < messageLength {
				break
			}
			if payloadLength > 1 {
				packetType := conn.messageBuffer[PREFIX_LENGTH]
				if packetType == SSH_MSG_NEWKEYS {
					conn.state = OBFUSCATION_STATE_FINISHED
					conn.messageBuffer = nil
					break
				}
			}
			// TODO: efficiency...?
			conn.messageBuffer = conn.messageBuffer[messageLength:]
		}
	}
	return nil
}
