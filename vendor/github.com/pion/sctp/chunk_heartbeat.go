// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"errors"
	"fmt"
)

/*
chunkHeartbeat represents an SCTP Chunk of type HEARTBEAT (RFC 9260 section 3.3.6)

An endpoint sends this chunk to probe reachability of a destination address.
The chunk MUST contain exactly one variable-length parameter:

Variable Parameters                 Status     Type Value
-------------------------------------------------------------
Heartbeat Info                      Mandatory  1

nolint:godot
*/
type chunkHeartbeat struct {
	chunkHeader
	params []param
}

// Heartbeat chunk errors.
var (
	ErrChunkTypeNotHeartbeat      = errors.New("ChunkType is not of type HEARTBEAT")
	ErrHeartbeatNotLongEnoughInfo = errors.New("heartbeat is not long enough to contain Heartbeat Info")
	ErrParseParamTypeFailed       = errors.New("failed to parse param type")
	ErrHeartbeatParam             = errors.New("heartbeat should only have HEARTBEAT param")
	ErrHeartbeatChunkUnmarshal    = errors.New("failed unmarshalling param in Heartbeat Chunk")
	ErrHeartbeatExtraNonZero      = errors.New("heartbeat has non-zero trailing bytes after last parameter")
	ErrHeartbeatMarshalNoInfo     = errors.New("heartbeat marshal requires exactly one Heartbeat Info parameter")
)

func (h *chunkHeartbeat) unmarshal(raw []byte) error { //nolint:cyclop
	if err := h.chunkHeader.unmarshal(raw); err != nil {
		return err
	}

	if h.typ != ctHeartbeat {
		return fmt.Errorf("%w: actually is %s", ErrChunkTypeNotHeartbeat, h.typ.String())
	}

	// if the body is completely empty, accept it but don't populate params.
	if len(h.raw) == 0 {
		return nil
	}

	// need at least a parameter header present (TLV: 4 bytes minimum).
	if len(h.raw) < initOptionalVarHeaderLength {
		return fmt.Errorf("%w: %d", ErrHeartbeatNotLongEnoughInfo, len(h.raw))
	}

	pType, err := parseParamType(h.raw)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrParseParamTypeFailed, err) //nolint:errorlint
	}
	if pType != heartbeatInfo {
		return fmt.Errorf("%w: instead have %s", ErrHeartbeatParam, pType.String())
	}

	var pHeader paramHeader
	if e := pHeader.unmarshal(h.raw); e != nil {
		return fmt.Errorf("%w: %v", ErrParseParamTypeFailed, e) //nolint:errorlint
	}

	plen := pHeader.length()
	if plen < initOptionalVarHeaderLength || plen > len(h.raw) {
		return ErrHeartbeatNotLongEnoughInfo
	}

	p, err := buildParam(pType, h.raw[:plen])
	if err != nil {
		return fmt.Errorf("%w: %v", ErrHeartbeatChunkUnmarshal, err) //nolint:errorlint
	}
	h.params = append(h.params, p)

	// any trailing bytes beyond the single param must be all zeros.
	if rem := h.raw[plen:]; len(rem) > 0 && !allZero(rem) {
		return ErrHeartbeatExtraNonZero
	}

	return nil
}

func (h *chunkHeartbeat) Marshal() ([]byte, error) {
	// exactly one Heartbeat Info param is required.
	if len(h.params) != 1 {
		return nil, ErrHeartbeatMarshalNoInfo
	}

	// enforce correct concrete type via type assertion (param interface has no type getter).
	if _, ok := h.params[0].(*paramHeartbeatInfo); !ok {
		return nil, ErrHeartbeatParam
	}

	pp, err := h.params[0].marshal()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHeartbeatChunkUnmarshal, err) //nolint:errorlint
	}

	// single TLV, no inter-parameter padding within the chunk body.
	h.chunkHeader.typ = ctHeartbeat
	h.chunkHeader.flags = 0 // sender MUST set to 0
	h.chunkHeader.raw = append([]byte(nil), pp...)

	return h.chunkHeader.marshal()
}

func (h *chunkHeartbeat) check() (abort bool, err error) {
	return false, nil
}
