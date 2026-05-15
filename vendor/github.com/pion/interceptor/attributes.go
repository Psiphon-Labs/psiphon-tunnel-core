// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package interceptor

import (
	"errors"

	"github.com/pion/rtcp"
	"github.com/pion/rtp"
)

type unmarshaledDataKeyType int

const (
	rtpHeaderKey unmarshaledDataKeyType = iota
	rtcpPacketsKey
)

var errInvalidType = errors.New("found value of invalid type in attributes map")

// Attributes are a generic key/value store used by interceptors.
type Attributes map[any]any

// Get returns the attribute associated with key.
func (a Attributes) Get(key any) any {
	return a[key]
}

// Set sets the attribute associated with key to the given value.
func (a Attributes) Set(key any, val any) {
	a[key] = val
}

// GetRTPHeader gets the RTP header if present. If it is not present, it will be
// unmarshalled from the raw byte slice and stored in the attributes.
func (a Attributes) GetRTPHeader(raw []byte) (*rtp.Header, error) {
	if val, ok := a[rtpHeaderKey]; ok {
		if header, ok := val.(*rtp.Header); ok {
			return header, nil
		}

		return nil, errInvalidType
	}
	header := &rtp.Header{}
	if _, err := header.Unmarshal(raw); err != nil {
		return nil, err
	}
	a[rtpHeaderKey] = header

	return header, nil
}

// GetRTCPPackets gets the RTCP packets if present. If the packet slice is not
// present, it will be unmarshalled from the raw byte slice and stored in the
// attributes.
func (a Attributes) GetRTCPPackets(raw []byte) ([]rtcp.Packet, error) {
	if val, ok := a[rtcpPacketsKey]; ok {
		if packets, ok := val.([]rtcp.Packet); ok {
			return packets, nil
		}

		return nil, errInvalidType
	}
	pkts, err := rtcp.Unmarshal(raw)
	if err != nil {
		return nil, err
	}
	a[rtcpPacketsKey] = pkts

	return pkts, nil
}
