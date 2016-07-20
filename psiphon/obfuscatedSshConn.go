/*
 * Copyright (c) 2015, Psiphon Inc.
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

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
)

const (
	SSH_MAX_SERVER_LINE_LENGTH = 1024
	SSH_PACKET_PREFIX_LENGTH   = 5          // uint32 + byte
	SSH_MAX_PACKET_LENGTH      = 256 * 1024 // OpenSSH max packet length
	SSH_MSG_NEWKEYS            = 21
	SSH_MAX_PADDING_LENGTH     = 255 // RFC 4253 sec. 6
	SSH_PADDING_MULTIPLE       = 16  // Default cipher block size
)

// ObfuscatedSshConn wraps a Conn and applies the obfuscated SSH protocol
// to the traffic on the connection:
// https://github.com/brl/obfuscated-openssh/blob/master/README.obfuscation
//
// ObfuscatedSshConn is used to add obfuscation to golang's stock ssh
// client and server without modification to that standard library code.
// The underlying connection must be used for SSH traffic. This code
// injects the obfuscated seed message, applies obfuscated stream cipher
// transformations, and performs minimal parsing of the SSH protocol to
// determine when to stop obfuscation (after the first SSH_MSG_NEWKEYS is
// sent and received).
//
// WARNING: doesn't fully conform to net.Conn concurrency semantics: there's
// no synchronization of access to the read/writeBuffers, so concurrent
// calls to one of Read or Write will result in undefined behavior.
//
type ObfuscatedSshConn struct {
	net.Conn
	mode            ObfuscatedSshConnMode
	obfuscator      *Obfuscator
	readDeobfuscate func([]byte)
	writeObfuscate  func([]byte)
	readState       ObfuscatedSshReadState
	writeState      ObfuscatedSshWriteState
	readBuffer      []byte
	writeBuffer     []byte
}

type ObfuscatedSshConnMode int

const (
	OBFUSCATION_CONN_MODE_CLIENT = iota
	OBFUSCATION_CONN_MODE_SERVER
)

type ObfuscatedSshReadState int

const (
	OBFUSCATION_READ_STATE_IDENTIFICATION_LINES = iota
	OBFUSCATION_READ_STATE_KEX_PACKETS
	OBFUSCATION_READ_STATE_FLUSH
	OBFUSCATION_READ_STATE_FINISHED
)

type ObfuscatedSshWriteState int

const (
	OBFUSCATION_WRITE_STATE_CLIENT_SEND_SEED_MESSAGE = iota
	OBFUSCATION_WRITE_STATE_SERVER_SEND_IDENTIFICATION_LINE_PADDING
	OBFUSCATION_WRITE_STATE_IDENTIFICATION_LINE
	OBFUSCATION_WRITE_STATE_KEX_PACKETS
	OBFUSCATION_WRITE_STATE_FINISHED
)

// NewObfuscatedSshConn creates a new ObfuscatedSshConn.
// The underlying conn must be used for SSH traffic and must have
// transferred no traffic.
//
// In client mode, NewObfuscatedSshConn does not block or initiate network
// I/O. The obfuscation seed message is sent when Write() is first called.
//
// In server mode, NewObfuscatedSshConn cannot completely initialize itself
// without the seed message from the client to derive obfuscation keys. So
// NewObfuscatedSshConn blocks on reading the client seed message from the
// underlying conn.
//
func NewObfuscatedSshConn(
	mode ObfuscatedSshConnMode,
	conn net.Conn,
	obfuscationKeyword string) (*ObfuscatedSshConn, error) {

	var err error
	var obfuscator *Obfuscator
	var readDeobfuscate, writeObfuscate func([]byte)
	var writeState ObfuscatedSshWriteState

	if mode == OBFUSCATION_CONN_MODE_CLIENT {
		obfuscator, err = NewClientObfuscator(&ObfuscatorConfig{Keyword: obfuscationKeyword})
		if err != nil {
			return nil, common.ContextError(err)
		}
		readDeobfuscate = obfuscator.ObfuscateServerToClient
		writeObfuscate = obfuscator.ObfuscateClientToServer
		writeState = OBFUSCATION_WRITE_STATE_CLIENT_SEND_SEED_MESSAGE
	} else {
		// NewServerObfuscator reads a seed message from conn
		obfuscator, err = NewServerObfuscator(
			conn, &ObfuscatorConfig{Keyword: obfuscationKeyword})
		if err != nil {
			// TODO: readForver() equivilent
			return nil, common.ContextError(err)
		}
		readDeobfuscate = obfuscator.ObfuscateClientToServer
		writeObfuscate = obfuscator.ObfuscateServerToClient
		writeState = OBFUSCATION_WRITE_STATE_SERVER_SEND_IDENTIFICATION_LINE_PADDING
	}

	return &ObfuscatedSshConn{
		Conn:            conn,
		mode:            mode,
		obfuscator:      obfuscator,
		readDeobfuscate: readDeobfuscate,
		writeObfuscate:  writeObfuscate,
		readState:       OBFUSCATION_READ_STATE_IDENTIFICATION_LINES,
		writeState:      writeState,
	}, nil
}

// Read wraps standard Read, transparently applying the obfuscation
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
		return 0, common.ContextError(err)
	}
	// Reports that we wrote all the bytes
	// (althogh we may have buffered some or all)
	return len(buffer), nil
}

// readAndTransform reads and transforms the downstream bytes stream
// while in an obfucation state. It parses the stream of bytes read
// looking for the first SSH_MSG_NEWKEYS packet sent from the peer,
// after which obfuscation is turned off. Since readAndTransform may
// read in more bytes that the higher-level conn.Read() can consume,
// read bytes are buffered and may be returned in subsequent calls.
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
// A comment in exchangeVersions explains that the golang code doesn't
// support this:
//   Contrary to the RFC, we do not ignore lines that don't
//   start with "SSH-2.0-" to make the library usable with
//   nonconforming servers.
//
// In addition, Psiphon's server sends up to 512 characters per extra
// line. It's not clear that the 255 max string size in sec 4.2 refers
// to the extra lines as well, but in any case golang's code only
// supports 255 character lines.
//
// State OBFUSCATION_READ_STATE_IDENTIFICATION_LINES: in this
// state, extra lines are read and discarded. Once the peer's
// identification string line is read, it is buffered and returned
// as per the requested read buffer size.
//
// State OBFUSCATION_READ_STATE_KEX_PACKETS: reads, deobfuscates,
// and buffers full SSH packets, checking for SSH_MSG_NEWKEYS. Packet
// data is returned as per the requested read buffer size.
//
// State OBFUSCATION_READ_STATE_FLUSH: after SSH_MSG_NEWKEYS, no more
// packets are read by this function, but bytes from the SSH_MSG_NEWKEYS
// packet may need to be buffered due to partial reading.
func (conn *ObfuscatedSshConn) readAndTransform(buffer []byte) (n int, err error) {
	nextState := conn.readState

	switch conn.readState {
	case OBFUSCATION_READ_STATE_IDENTIFICATION_LINES:
		// TODO: only client should accept multiple lines?
		if len(conn.readBuffer) == 0 {
			for {
				conn.readBuffer, err = readSshIdentificationLine(
					conn.Conn, conn.readDeobfuscate)
				if err != nil {
					return 0, common.ContextError(err)
				}
				if bytes.HasPrefix(conn.readBuffer, []byte("SSH-")) {
					break
				}
				// Discard extra line
				conn.readBuffer = nil
			}
		}
		nextState = OBFUSCATION_READ_STATE_KEX_PACKETS

	case OBFUSCATION_READ_STATE_KEX_PACKETS:
		if len(conn.readBuffer) == 0 {
			var isMsgNewKeys bool
			conn.readBuffer, isMsgNewKeys, err = readSshPacket(
				conn.Conn, conn.readDeobfuscate)
			if err != nil {
				return 0, common.ContextError(err)
			}

			if isMsgNewKeys {
				nextState = OBFUSCATION_READ_STATE_FLUSH
			}
		}

	case OBFUSCATION_READ_STATE_FLUSH:
		nextState = OBFUSCATION_READ_STATE_FINISHED

	case OBFUSCATION_READ_STATE_FINISHED:
		return 0, common.ContextError(errors.New("invalid read state"))
	}

	n = copy(buffer, conn.readBuffer)
	conn.readBuffer = conn.readBuffer[n:]
	if len(conn.readBuffer) == 0 {
		conn.readState = nextState
		conn.readBuffer = nil
	}
	return n, nil
}

// transformAndWrite transforms the upstream bytes stream while in an
// obfucation state, buffers bytes as necessary for parsing, and writes
// transformed bytes to the network connection. Bytes are obfuscated until
// after the first SSH_MSG_NEWKEYS packet is sent.
//
// There are two mode-specific states:
//
// State OBFUSCATION_WRITE_STATE_CLIENT_SEND_SEED_MESSAGE: the initial
// state, when the client has not sent any data. In this state, the seed message
// is injected into the client output stream.
//
// State OBFUSCATION_WRITE_STATE_SERVER_SEND_IDENTIFICATION_LINE_PADDING: the
// initial state, when the server has not sent any data. In this state, the
// additional lines of padding are injected into the server output stream.
// This padding is a partial defense against traffic analysis against the
// otherwise-fixed size server version line. This makes use of the
// "other lines of data" allowance, before the version line, which clients
// will ignore (http://tools.ietf.org/html/rfc4253#section-4.2).
//
// State OBFUSCATION_WRITE_STATE_IDENTIFICATION_LINE: before
// packets are sent, the ssh peer sends an identification line terminated by CRLF:
// http://www.ietf.org/rfc/rfc4253.txt sec 4.2.
// In this state, the CRLF terminator is used to parse message boundaries.
//
// State OBFUSCATION_WRITE_STATE_KEX_PACKETS: follows the binary
// packet protocol, parsing each packet until the first SSH_MSG_NEWKEYS.
// http://www.ietf.org/rfc/rfc4253.txt sec 6:
//     uint32    packet_length
//     byte      padding_length
//     byte[n1]  payload; n1 = packet_length - padding_length - 1
//     byte[n2]  random padding; n2 = padding_length
//     byte[m]   mac (Message Authentication Code - MAC); m = mac_length
// m is 0 as no MAC ha yet been negotiated.
// http://www.ietf.org/rfc/rfc4253.txt sec 7.3, 12:
// The payload for SSH_MSG_NEWKEYS is one byte, the packet type, value 21.
//
// SSH packet padding values are transformed to achive random, variable length
// padding during the KEX phase as a partial defense against traffic analysis.
// (The transformer can do this since only the payload and not the padding of
// these packets is authenticated in the "exchange hash").
func (conn *ObfuscatedSshConn) transformAndWrite(buffer []byte) (err error) {

	// The seed message (client) and identification line padding (server)
	// are injected before any standard SSH traffic.
	if conn.writeState == OBFUSCATION_WRITE_STATE_CLIENT_SEND_SEED_MESSAGE {
		_, err = conn.Conn.Write(conn.obfuscator.SendSeedMessage())
		if err != nil {
			return common.ContextError(err)
		}
		conn.writeState = OBFUSCATION_WRITE_STATE_IDENTIFICATION_LINE
	} else if conn.writeState == OBFUSCATION_WRITE_STATE_SERVER_SEND_IDENTIFICATION_LINE_PADDING {
		padding, err := makeServerIdentificationLinePadding()
		if err != nil {
			return common.ContextError(err)
		}
		conn.writeObfuscate(padding)
		_, err = conn.Conn.Write(padding)
		if err != nil {
			return common.ContextError(err)
		}
		conn.writeState = OBFUSCATION_WRITE_STATE_IDENTIFICATION_LINE
	}

	conn.writeBuffer = append(conn.writeBuffer, buffer...)
	var sendBuffer []byte

	switch conn.writeState {
	case OBFUSCATION_WRITE_STATE_IDENTIFICATION_LINE:
		conn.writeBuffer, sendBuffer = extractSshIdentificationLine(conn.writeBuffer)
		if sendBuffer != nil {
			conn.writeState = OBFUSCATION_WRITE_STATE_KEX_PACKETS
		}

	case OBFUSCATION_WRITE_STATE_KEX_PACKETS:
		var hasMsgNewKeys bool
		conn.writeBuffer, sendBuffer, hasMsgNewKeys, err = extractSshPackets(conn.writeBuffer)
		if err != nil {
			return common.ContextError(err)
		}
		if hasMsgNewKeys {
			conn.writeState = OBFUSCATION_WRITE_STATE_FINISHED
		}

	case OBFUSCATION_WRITE_STATE_FINISHED:
		return common.ContextError(errors.New("invalid write state"))
	}

	if sendBuffer != nil {
		conn.writeObfuscate(sendBuffer)
		_, err := conn.Conn.Write(sendBuffer)
		if err != nil {
			return common.ContextError(err)
		}
	}

	if conn.writeState == OBFUSCATION_WRITE_STATE_FINISHED {
		// After SSH_MSG_NEWKEYS, any remaining bytes are un-obfuscated
		_, err := conn.Conn.Write(conn.writeBuffer)
		if err != nil {
			return common.ContextError(err)
		}
		// The buffer memory is no longer used
		conn.writeBuffer = nil
	}
	return nil
}

func readSshIdentificationLine(
	conn net.Conn, deobfuscate func([]byte)) ([]byte, error) {

	// TODO: use bufio.BufferedReader? less redundant string searching?
	var oneByte [1]byte
	var validLine = false
	readBuffer := make([]byte, 0)
	for len(readBuffer) < SSH_MAX_SERVER_LINE_LENGTH {
		_, err := io.ReadFull(conn, oneByte[:])
		if err != nil {
			return nil, common.ContextError(err)
		}
		deobfuscate(oneByte[:])
		readBuffer = append(readBuffer, oneByte[0])
		if bytes.HasSuffix(readBuffer, []byte("\r\n")) {
			validLine = true
			break
		}
	}
	if !validLine {
		return nil, common.ContextError(errors.New("invalid identification line"))
	}
	return readBuffer, nil
}

func readSshPacket(
	conn net.Conn, deobfuscate func([]byte)) ([]byte, bool, error) {

	prefix := make([]byte, SSH_PACKET_PREFIX_LENGTH)
	_, err := io.ReadFull(conn, prefix)
	if err != nil {
		return nil, false, common.ContextError(err)
	}
	deobfuscate(prefix)
	packetLength, _, payloadLength, messageLength := getSshPacketPrefix(prefix)
	if packetLength > SSH_MAX_PACKET_LENGTH {
		return nil, false, common.ContextError(errors.New("ssh packet length too large"))
	}
	readBuffer := make([]byte, messageLength)
	copy(readBuffer, prefix)
	_, err = io.ReadFull(conn, readBuffer[len(prefix):])
	if err != nil {
		return nil, false, common.ContextError(err)
	}
	deobfuscate(readBuffer[len(prefix):])
	isMsgNewKeys := false
	if payloadLength > 0 {
		packetType := int(readBuffer[SSH_PACKET_PREFIX_LENGTH])
		if packetType == SSH_MSG_NEWKEYS {
			isMsgNewKeys = true
		}
	}
	return readBuffer, isMsgNewKeys, nil
}

// From the original patch to sshd.c:
// https://bitbucket.org/psiphon/psiphon-circumvention-system/commits/f40865ce624b680be840dc2432283c8137bd896d
func makeServerIdentificationLinePadding() ([]byte, error) {
	paddingLength, err := common.MakeSecureRandomInt(OBFUSCATE_MAX_PADDING - 2) // 2 = CRLF
	if err != nil {
		return nil, common.ContextError(err)
	}
	paddingLength += 2
	padding := make([]byte, paddingLength)

	// For backwards compatibility with some clients, send no more than 512 characters
	// per line (including CRLF). To keep the padding distribution between 0 and OBFUSCATE_MAX_PADDING
	// characters, we send lines that add up to padding_length characters including all CRLFs.

	minLineLength := 2
	maxLineLength := 512
	lineStartIndex := 0
	for paddingLength > 0 {
		lineLength := paddingLength
		if lineLength > maxLineLength {
			lineLength = maxLineLength
		}
		// Leave enough padding allowance to send a full CRLF on the last line
		if paddingLength-lineLength > 0 &&
			paddingLength-lineLength < minLineLength {
			lineLength -= minLineLength - (paddingLength - lineLength)
		}
		padding[lineStartIndex+lineLength-2] = '\r'
		padding[lineStartIndex+lineLength-1] = '\n'
		lineStartIndex += lineLength
		paddingLength -= lineLength
	}

	return padding, nil
}

func extractSshIdentificationLine(writeBuffer []byte) ([]byte, []byte) {
	var lineBuffer []byte
	index := bytes.Index(writeBuffer, []byte("\r\n"))
	if index != -1 {
		messageLength := index + 2 // + 2 for \r\n
		lineBuffer = append([]byte(nil), writeBuffer[:messageLength]...)
		writeBuffer = writeBuffer[messageLength:]
	}
	return writeBuffer, lineBuffer
}

func extractSshPackets(writeBuffer []byte) ([]byte, []byte, bool, error) {
	var packetBuffer, packetsBuffer []byte
	hasMsgNewKeys := false
	for len(writeBuffer) >= SSH_PACKET_PREFIX_LENGTH {
		packetLength, paddingLength, payloadLength, messageLength := getSshPacketPrefix(writeBuffer)
		if len(writeBuffer) < messageLength {
			// We don't have the complete packet yet
			break
		}
		packetBuffer = append([]byte(nil), writeBuffer[:messageLength]...)
		writeBuffer = writeBuffer[messageLength:]
		if payloadLength > 0 {
			packetType := int(packetBuffer[SSH_PACKET_PREFIX_LENGTH])
			if packetType == SSH_MSG_NEWKEYS {
				hasMsgNewKeys = true
			}
		}
		// Padding transformation
		// See RFC 4253 sec. 6 for constraints
		possiblePaddings := (SSH_MAX_PADDING_LENGTH - paddingLength) / SSH_PADDING_MULTIPLE
		if possiblePaddings > 0 {
			// selectedPadding is integer in range [0, possiblePaddings)
			selectedPadding, err := common.MakeSecureRandomInt(possiblePaddings)
			if err != nil {
				return nil, nil, false, common.ContextError(err)
			}
			extraPaddingLength := selectedPadding * SSH_PADDING_MULTIPLE
			extraPadding, err := common.MakeSecureRandomBytes(extraPaddingLength)
			if err != nil {
				return nil, nil, false, common.ContextError(err)
			}
			setSshPacketPrefix(
				packetBuffer, packetLength+extraPaddingLength, paddingLength+extraPaddingLength)
			packetBuffer = append(packetBuffer, extraPadding...)
		}
		packetsBuffer = append(packetsBuffer, packetBuffer...)
	}
	return writeBuffer, packetsBuffer, hasMsgNewKeys, nil
}

func getSshPacketPrefix(buffer []byte) (packetLength, paddingLength, payloadLength, messageLength int) {
	// TODO: handle malformed packet [lengths]
	packetLength = int(binary.BigEndian.Uint32(buffer[0 : SSH_PACKET_PREFIX_LENGTH-1]))
	paddingLength = int(buffer[SSH_PACKET_PREFIX_LENGTH-1])
	payloadLength = packetLength - paddingLength - 1
	messageLength = SSH_PACKET_PREFIX_LENGTH + packetLength - 1
	return
}

func setSshPacketPrefix(buffer []byte, packetLength, paddingLength int) {
	binary.BigEndian.PutUint32(buffer, uint32(packetLength))
	buffer[SSH_PACKET_PREFIX_LENGTH-1] = byte(paddingLength)
}
