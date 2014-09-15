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
	"errors"
	"io"
	"log"
	"net"
)

type ObfuscatedSshState int

const (
	OBFUSCATION_STATE_SEND_CLIENT_SEED_MESSAGE = iota
	OBFUSCATION_STATE_CLIENT_IDENTIFICATION_LINE
	OBFUSCATION_STATE_CLIENT_KEX_PACKETS
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
	obfuscator                   *Obfuscator
	state                        ObfuscatedSshState
	finishedServerIdentification bool
	clientMessageBuffer          []byte
	serverIdentificationBuffer   []byte
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
		state:      OBFUSCATION_STATE_SEND_CLIENT_SEED_MESSAGE,
		finishedServerIdentification: false}, nil
}

// Read wraps standard Read, deobfuscating read bytes while in the
// obfuscating state.
func (conn *ObfuscatedSshConn) Read(buffer []byte) (n int, err error) {
	if !conn.finishedServerIdentification {
		n, err = conn.readServerIdentification(buffer)
	} else {
		n, err = conn.Conn.Read(buffer)
		if conn.state != OBFUSCATION_STATE_FINISHED {
			conn.obfuscator.ObfuscateServerToClient(buffer[:n])
		}
	}
	return
}

// Write wraps standard Write, obfuscating bytes to be written while in the
// obfuscating state. The plain SSH protocol bytes are parsed to observe
// the protocol state and set obfuscation state accordingly.
func (conn *ObfuscatedSshConn) Write(buffer []byte) (n int, err error) {
	if conn.state != OBFUSCATION_STATE_FINISHED {
		err = conn.updateState(buffer)
		if err != nil {
			return
		}
		// Don't overwrite original buffer
		obfuscatedBuffer := make([]byte, len(buffer))
		copy(obfuscatedBuffer, buffer)
		conn.obfuscator.ObfuscateClientToServer(obfuscatedBuffer)
		return conn.Conn.Write(obfuscatedBuffer)
	}
	return conn.Conn.Write(buffer)
}

// readServerIdentification implements a workaround for issues with
// ssh/transport.go exchangeVersions/readVersion and Psiphon's openssh
// server.
//
// Psiphon's server sends extra lines before the version line, as
// permitted by http://www.ietf.org/rfc/rfc4253.txt sec 4.2:
//   The server MAY send other lines of data before sending the
//   version string. [...] Clients MUST be able to process such lines.
//
// A comment in exchangeVersions explains that the go code doesn't
// support this:
//   Contrary to the RFC, we do not ignore lines that don't
//   start with "SSH-2.0-" to make the library usable with
//   nonconforming servers.
//
// In addition, Psiphon's server sends up to 512 characters per extra
// line. It's not clear that the 255 max string size in sec 4.2 refers
// to the extra lines as well, but in any case go's code only supports
// a 255 character lines.
//
// When first called, this function reads all the extra lines, discarding
// them, and then the version string line, retaining it in a buffer so
// that it can be consumed by subsequent calls (depending on the input
// buffer size).
func (conn *ObfuscatedSshConn) readServerIdentification(buffer []byte) (n int, err error) {
	if conn.serverIdentificationBuffer == nil {
		for {
			conn.serverIdentificationBuffer = make([]byte, 0, 512)
			// TODO: use bufio.Reader?
			var readBuffer [1]byte
			var validLine = false
			for len(conn.serverIdentificationBuffer) < cap(conn.serverIdentificationBuffer) {
				_, err := io.ReadFull(conn.Conn, readBuffer[:])
				if err != nil {
					return 0, err
				}
				conn.obfuscator.ObfuscateServerToClient(readBuffer[:])
				conn.serverIdentificationBuffer = append(conn.serverIdentificationBuffer, readBuffer[0])
				if bytes.HasSuffix(conn.serverIdentificationBuffer, []byte("\r\n")) {
					validLine = true
					break
				}
			}
			if !validLine {
				return 0, errors.New("invalid server identity line")
			}
			if bytes.HasPrefix(conn.serverIdentificationBuffer, []byte("SSH-")) {
				log.Printf("DEBUG server version string %s", string(conn.serverIdentificationBuffer))
				break
			}
		}
	}
	n = copy(buffer, conn.serverIdentificationBuffer)
	conn.serverIdentificationBuffer = conn.serverIdentificationBuffer[n:]
	if len(conn.serverIdentificationBuffer) == 0 {
		conn.serverIdentificationBuffer = nil
		conn.finishedServerIdentification = true
	}
	return n, nil
}

// updateState transforms the obfucation state. It parses the stream of bytes
// written by the client, looking for the first SSH_MSG_NEWKEYS packet sent,
// after which obfuscation is turned off.
//
// State OBFUSCATION_STATE_SEND_CLIENT_SEED_MESSAGE: the initial state, when
// the client has not sent any data. In this state, the seed message is
// injected into the client output stream.
//
// State OBFUSCATION_STATE_CLIENT_IDENTIFICATION_LINE: before packets are sent,
// the client sends an identification line terminated by CRLF:
// http://www.ietf.org/rfc/rfc4253.txt sec 4.2.
// In this state, the CRLF terminator is used to parse message boundaries.
//
// State OBFUSCATION_STATE_CLIENT_KEX_PACKETS: follows the binary packet protocol,
// parsing each packet until the first SSH_MSG_NEWKEYS.
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
	// Use of conn.clientMessageBuffer allows protocol message boundaries to cross Write() calls
	if conn.state == OBFUSCATION_STATE_SEND_CLIENT_SEED_MESSAGE {
		_, err = conn.Conn.Write(conn.obfuscator.ConsumeSeedMessage())
		if err != nil {
			return err
		}
		conn.state = OBFUSCATION_STATE_CLIENT_IDENTIFICATION_LINE
	}
	conn.clientMessageBuffer = append(conn.clientMessageBuffer, buffer...)
	switch conn.state {
	case OBFUSCATION_STATE_CLIENT_IDENTIFICATION_LINE:
		lines := bytes.SplitN(conn.clientMessageBuffer, []byte("\r\n"), 2)
		if len(lines) > 1 {
			// TODO: efficiency...?
			conn.clientMessageBuffer = conn.clientMessageBuffer[len(lines[0])+2:]
			conn.state = OBFUSCATION_STATE_CLIENT_KEX_PACKETS
		}
	case OBFUSCATION_STATE_CLIENT_KEX_PACKETS:
		const SSH_MSG_NEWKEYS = 21
		const PREFIX_LENGTH = 5 // uint32 + byte
		for len(conn.clientMessageBuffer) >= PREFIX_LENGTH {
			// This parsing repeats for a single packet sent over multiple Write() calls
			// TODO: handle malformed packet [lengths]
			packetLength := binary.BigEndian.Uint32(conn.clientMessageBuffer[0:4])
			paddingLength := uint32(conn.clientMessageBuffer[PREFIX_LENGTH-1])
			payloadLength := packetLength - uint32(paddingLength) - 1
			messageLength := PREFIX_LENGTH + packetLength - 1
			if uint32(len(conn.clientMessageBuffer)) < messageLength {
				break
			}
			if payloadLength > 1 {
				packetType := uint32(conn.clientMessageBuffer[PREFIX_LENGTH])
				log.Printf("DEBUG packetType %d", packetType)
				if packetType == SSH_MSG_NEWKEYS {
					conn.state = OBFUSCATION_STATE_FINISHED
					conn.clientMessageBuffer = nil
					break
				}
			}
			// TODO: efficiency...?
			conn.clientMessageBuffer = conn.clientMessageBuffer[messageLength:]
		}
	}
	return nil
}
