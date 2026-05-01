// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"errors"
	"fmt"
)

/*
chunkHeartbeatAck represents an SCTP Chunk of type HEARTBEAT ACK

An endpoint should send this chunk to its peer endpoint as a response
to a HEARTBEAT chunk (see Section 8.3).  A HEARTBEAT ACK is always
sent to the source IP address of the IP datagram containing the
HEARTBEAT chunk to which this ack is responding.

The parameter field contains a variable-length opaque data structure.

	 0                   1                   2                   3
	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|   Type = 5    | Chunk  Flags  |    Heartbeat Ack Length       |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                                                               |
	|            Heartbeat Information TLV (Variable-Length)        |
	|                                                               |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Defined as a variable-length parameter using the format described
in Section 3.2.1, i.e.:

Variable Parameters                  Status     Type Value
-------------------------------------------------------------
Heartbeat Info                       Mandatory   1
.
*/
type chunkHeartbeatAck struct {
	chunkHeader
	params []param
}

// Heartbeat ack chunk errors.
var (
	// Deprecated: this error is no longer used but is kept for compatibility.
	ErrUnimplemented                = errors.New("unimplemented")
	ErrChunkTypeNotHeartbeatAck     = errors.New("chunk type is not of type HEARTBEAT ACK")
	ErrHeartbeatAckParams           = errors.New("heartbeat Ack must have one param")
	ErrHeartbeatAckNotHeartbeatInfo = errors.New("heartbeat Ack must have one param, and it should be a HeartbeatInfo")
	ErrHeartbeatAckMarshalParam     = errors.New("unable to marshal parameter for Heartbeat Ack")
)

func (h *chunkHeartbeatAck) unmarshal(raw []byte) error { //nolint:cyclop
	if err := h.chunkHeader.unmarshal(raw); err != nil {
		return err
	}

	if h.typ != ctHeartbeatAck {
		return fmt.Errorf("%w %s", ErrChunkTypeNotHeartbeatAck, h.typ.String())
	}

	// allow for an empty heartbeat: no RTT info -> ActiveHeartbeat just won't update SRTT.
	if len(h.raw) == 0 {
		h.params = nil

		return nil
	}

	if len(h.raw) < initOptionalVarHeaderLength {
		return fmt.Errorf("%w: %d", ErrHeartbeatAckParams, len(h.raw))
	}

	pType, err := parseParamType(h.raw)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrHeartbeatAckParams, err) //nolint:errorlint
	}
	if pType != heartbeatInfo {
		return fmt.Errorf("%w: instead have %s", ErrHeartbeatAckNotHeartbeatInfo, pType.String())
	}

	var pHeader paramHeader
	if e := pHeader.unmarshal(h.raw); e != nil {
		return fmt.Errorf("%w: %v", ErrHeartbeatAckParams, e) //nolint:errorlint
	}
	plen := pHeader.length()
	if plen < initOptionalVarHeaderLength || plen > len(h.raw) {
		return fmt.Errorf("%w: %d", ErrHeartbeatAckParams, plen)
	}

	p, err := buildParam(pType, h.raw[:plen])
	if err != nil {
		return fmt.Errorf("%w: %v", ErrHeartbeatAckMarshalParam, err) //nolint:errorlint
	}
	h.params = []param{p}

	// Any trailing bytes beyond the single param must be zero.
	if rem := h.raw[plen:]; len(rem) > 0 && !allZero(rem) {
		return ErrHeartbeatExtraNonZero
	}

	return nil
}

func (h *chunkHeartbeatAck) marshal() ([]byte, error) {
	if len(h.params) != 1 {
		return nil, ErrHeartbeatAckParams
	}

	switch h.params[0].(type) {
	case *paramHeartbeatInfo:
		// ParamHeartbeatInfo is valid
	default:
		return nil, ErrHeartbeatAckNotHeartbeatInfo
	}

	out := make([]byte, 0)
	for idx, p := range h.params {
		pp, err := p.marshal()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrHeartbeatAckMarshalParam, err) //nolint:errorlint
		}

		out = append(out, pp...)

		// Chunks (including Type, Length, and Value fields) are padded out
		// by the sender with all zero bytes to be a multiple of 4 bytes
		// long.  This padding MUST NOT be more than 3 bytes in total.  The
		// Chunk Length value does not include terminating padding of the
		// chunk.  *However, it does include padding of any variable-length
		// parameter except the last parameter in the chunk.*  The receiver
		// MUST ignore the padding.
		if idx != len(h.params)-1 {
			out = padByte(out, getPadding(len(pp)))
		}
	}

	h.chunkHeader.typ = ctHeartbeatAck
	h.chunkHeader.raw = out

	return h.chunkHeader.marshal()
}

func (h *chunkHeartbeatAck) check() (abort bool, err error) {
	return false, nil
}
