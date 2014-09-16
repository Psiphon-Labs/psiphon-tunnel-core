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
	"net"
)

type ObfuscatedSshReadState int

const (
	OBFUSCATION_READ_STATE_SERVER_IDENTIFICATION_LINE = iota
	OBFUSCATION_READ_STATE_SERVER_KEX_PACKETS
	OBFUSCATION_READ_STATE_FLUSH
	OBFUSCATION_READ_STATE_FINISHED
)

type ObfuscatedSshWriteState int

const (
	OBFUSCATION_WRITE_STATE_SEND_CLIENT_SEED_MESSAGE = iota
	OBFUSCATION_WRITE_STATE_CLIENT_IDENTIFICATION_LINE
	OBFUSCATION_WRITE_STATE_CLIENT_KEX_PACKETS
	OBFUSCATION_WRITE_STATE_FINISHED
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
// sent by the client and received from the server).
type ObfuscatedSshConn struct {
	net.Conn
	obfuscator  *Obfuscator
	readState   ObfuscatedSshReadState
	writeState  ObfuscatedSshWriteState
	readBuffer  []byte
	writeBuffer []byte
}

const (
	MAX_SERVER_LINE_LENGTH   = 1024
	SSH_PACKET_PREFIX_LENGTH = 5          // uint32 + byte
	SSH_MAX_PACKET_LENGTH    = 256 * 1024 // OpenSSH max packet length
	SSH_MSG_NEWKEYS          = 21
)

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
		readState:  OBFUSCATION_READ_STATE_SERVER_IDENTIFICATION_LINE,
		writeState: OBFUSCATION_WRITE_STATE_SEND_CLIENT_SEED_MESSAGE,
	}, nil
}

// Read wraps standard Read, transparently applying the obfusation
// transformations.
func (conn *ObfuscatedSshConn) Read(buffer []byte) (n int, err error) {
	if conn.readState == OBFUSCATION_READ_STATE_FINISHED {
		return conn.Conn.Read(buffer)
	}
	return conn.readAndTransform(buffer)
}

// Write wraps standard Write, transparently applying the obfuscation
// transformations.
func (conn *ObfuscatedSshConn) Write(buffer []byte) (n int, err error) {
	if conn.writeState == OBFUSCATION_WRITE_STATE_FINISHED {
		return conn.Conn.Write(buffer)
	}
	err = conn.transformAndWrite(buffer)
	if err != nil {
		return 0, err
	}
	// Reports that we wrote all the bytes
	// (althogh we may have buffered some or all)
	return len(buffer), nil
}

// readAndTransform reads and transforms the server->client bytes stream
// while in an obfucation state. It parses the stream of bytes read
// looking for the first SSH_MSG_NEWKEYS packet sent from the server,
// after which obfuscation is turned off.
//
// readAndTransform also implements a workaround for issues with
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
// State OBFUSCATION_READ_STATE_SERVER_IDENTIFICATION_LINE: in this
// state, extra lines are read and discarded. Once the server
// identification string line is read, it is buffered and returned
// as per the requested read buffer size.
//
// State OBFUSCATION_READ_STATE_SERVER_KEX_PACKETS: reads, deobfuscates,
// and buffers full SSH packets, checking for SSH_MSG_NEWKEYS. Packet
// data is returned as per the requested read buffer size.
//
// State OBFUSCATION_READ_STATE_FLUSH: after SSH_MSG_NEWKEYS, no more
// packets are read by this function, but bytes from the SSH_MSG_NEWKEYS
// packet may need to be buffered due to partial reading.
func (conn *ObfuscatedSshConn) readAndTransform(buffer []byte) (n int, err error) {
	nextState := conn.readState
	switch conn.readState {
	case OBFUSCATION_READ_STATE_SERVER_IDENTIFICATION_LINE:
		if len(conn.readBuffer) == 0 {
			for {
				// TODO: use bufio.BufferedReader? less redundant string searching?
				var oneByte [1]byte
				var validLine = false
				for len(conn.readBuffer) < MAX_SERVER_LINE_LENGTH {
					_, err := io.ReadFull(conn.Conn, oneByte[:])
					if err != nil {
						return 0, err
					}
					conn.obfuscator.ObfuscateServerToClient(oneByte[:])
					conn.readBuffer = append(conn.readBuffer, oneByte[0])
					if bytes.HasSuffix(conn.readBuffer, []byte("\r\n")) {
						validLine = true
						break
					}
				}
				if !validLine {
					return 0, errors.New("ObfuscatedSshConn: invalid server line")
				}
				if bytes.HasPrefix(conn.readBuffer, []byte("SSH-")) {
					break
				}
				// Discard extra line
				conn.readBuffer = nil
			}
		}
		nextState = OBFUSCATION_READ_STATE_SERVER_KEX_PACKETS
	case OBFUSCATION_READ_STATE_SERVER_KEX_PACKETS:
		if len(conn.readBuffer) == 0 {
			prefix := make([]byte, SSH_PACKET_PREFIX_LENGTH)
			_, err := io.ReadFull(conn.Conn, prefix)
			if err != nil {
				return 0, err
			}
			conn.obfuscator.ObfuscateServerToClient(prefix)
			packetLength, _, payloadLength, messageLength := getSshPacketPrefix(prefix)
			if packetLength > SSH_MAX_PACKET_LENGTH {
				return 0, errors.New("ObfuscatedSshConn: ssh packet length too large")
			}
			conn.readBuffer = make([]byte, messageLength)
			copy(conn.readBuffer, prefix)
			_, err = io.ReadFull(conn.Conn, conn.readBuffer[len(prefix):])
			if err != nil {
				return 0, err
			}
			conn.obfuscator.ObfuscateServerToClient(conn.readBuffer[len(prefix):])
			if payloadLength > 0 {
				packetType := int(conn.readBuffer[SSH_PACKET_PREFIX_LENGTH])
				if packetType == SSH_MSG_NEWKEYS {
					nextState = OBFUSCATION_READ_STATE_FLUSH
				}
			}
		}
	case OBFUSCATION_READ_STATE_FLUSH:
		nextState = OBFUSCATION_READ_STATE_FINISHED
	case OBFUSCATION_READ_STATE_FINISHED:
		panic("ObfuscatedSshConn: invalid read state")
	}
	n = copy(buffer, conn.readBuffer)
	conn.readBuffer = conn.readBuffer[n:]
	if len(conn.readBuffer) == 0 {
		conn.readState = nextState
		conn.readBuffer = nil
	}
	return n, nil
}

// transformAndWrite transforms the client->server bytes stream while in an
// obfucation state, buffers bytes as necessary for parsing, and writes
// transformed bytes to the network connection. Bytes are obfuscated until
// the first client SSH_MSG_NEWKEYS packet is sent.
//
// State OBFUSCATION_WRITE_STATE_SEND_CLIENT_SEED_MESSAGE: the initial state,
// when the client has not sent any data. In this state, the seed message is
// injected into the client output stream.
//
// State OBFUSCATION_WRITE_STATE_CLIENT_IDENTIFICATION_LINE: before packets are
// sent, the client sends an identification line terminated by CRLF:
// http://www.ietf.org/rfc/rfc4253.txt sec 4.2.
// In this state, the CRLF terminator is used to parse message boundaries.
//
// State OBFUSCATION_WRITE_STATE_CLIENT_KEX_PACKETS: follows the binary packet
// protocol, parsing each packet until the first SSH_MSG_NEWKEYS.
// http://www.ietf.org/rfc/rfc4253.txt sec 6:
//     uint32    packet_length
//     byte      padding_length
//     byte[n1]  payload; n1 = packet_length - padding_length - 1
//     byte[n2]  random padding; n2 = padding_length
//     byte[m]   mac (Message Authentication Code - MAC); m = mac_length
// m is 0 as no MAC ha yet been negotiated.
// http://www.ietf.org/rfc/rfc4253.txt sec 7.3, 12:
// The payload for SSH_MSG_NEWKEYS is one byte, the packet type, value 21.
func (conn *ObfuscatedSshConn) transformAndWrite(buffer []byte) (err error) {
	if conn.writeState == OBFUSCATION_WRITE_STATE_SEND_CLIENT_SEED_MESSAGE {
		_, err = conn.Conn.Write(conn.obfuscator.ConsumeSeedMessage())
		if err != nil {
			return err
		}
		conn.writeState = OBFUSCATION_WRITE_STATE_CLIENT_IDENTIFICATION_LINE
	}
	conn.writeBuffer = append(conn.writeBuffer, buffer...)
	var messageBuffer []byte
	switch conn.writeState {
	case OBFUSCATION_WRITE_STATE_CLIENT_IDENTIFICATION_LINE:
		index := bytes.Index(conn.writeBuffer, []byte("\r\n"))
		if index != -1 {
			messageLength := index + 2 // + 2 for \r\n
			messageBuffer = append([]byte(nil), conn.writeBuffer[:messageLength]...)
			conn.writeBuffer = conn.writeBuffer[messageLength:]
			conn.writeState = OBFUSCATION_WRITE_STATE_CLIENT_KEX_PACKETS
		}
	case OBFUSCATION_WRITE_STATE_CLIENT_KEX_PACKETS:
		for len(conn.writeBuffer) >= SSH_PACKET_PREFIX_LENGTH {
			_, _, payloadLength, messageLength := getSshPacketPrefix(conn.writeBuffer)
			if len(conn.writeBuffer) < messageLength {
				// We don't have the complete packet yet
				break
			}
			// TODO: transform padding to implement random, variable length padding in KEX phase
			messageBuffer = append([]byte(nil), conn.writeBuffer[:messageLength]...)
			conn.writeBuffer = conn.writeBuffer[messageLength:]
			if payloadLength > 0 {
				packetType := int(messageBuffer[SSH_PACKET_PREFIX_LENGTH])
				if packetType == SSH_MSG_NEWKEYS {
					conn.writeState = OBFUSCATION_WRITE_STATE_FINISHED
				}
			}
		}
	case OBFUSCATION_WRITE_STATE_FINISHED:
		panic("ObfuscatedSshConn: invalid write state")
	}
	if messageBuffer != nil {
		conn.obfuscator.ObfuscateClientToServer(messageBuffer)
		_, err := conn.Conn.Write(messageBuffer)
		if err != nil {
			return err
		}
	}
	if conn.writeState == OBFUSCATION_WRITE_STATE_FINISHED {
		// After SSH_MSG_NEWKEYS, any remaining bytes are un-obfuscated
		_, err := conn.Conn.Write(conn.writeBuffer)
		if err != nil {
			return err
		}
		// The buffer memory is no longer used
		conn.writeBuffer = nil
	}
	return nil
}

func getSshPacketPrefix(buffer []byte) (packetLength, paddingLength, payloadLength, messageLength int) {
	// TODO: handle malformed packet [lengths]
	packetLength = int(binary.BigEndian.Uint32(buffer[0 : SSH_PACKET_PREFIX_LENGTH-1]))
	paddingLength = int(buffer[SSH_PACKET_PREFIX_LENGTH-1])
	payloadLength = packetLength - paddingLength - 1
	messageLength = SSH_PACKET_PREFIX_LENGTH + packetLength - 1
	return
}
