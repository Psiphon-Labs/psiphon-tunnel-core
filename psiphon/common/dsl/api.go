/*
 * Copyright (c) 2025, Psiphon Inc.
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

// Package dsl implements the Dynamic Server List (DSL) mechanism.
//
// Unlike Remote Server Lists (RSLs) and Obfuscated Server Lists (OSLs), which
// are based on static file downloads, with DSLs the client requests
// discovery and download of server entries from a DSL backend that actively
// selects from compartmentalized servers based on the client's inputs and
// other properties.
//
// Clients use relays with obfuscation and blocking resistence properties to
// transport requests to a DSL backend.
//
// The discovery concepts of OSLs are retained with the client reporting its
// known OSL keys to the DSL backend, as a proof-of-knowledge used to access
// certain compartments of servers.
package dsl

import (
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
)

type OSLID []byte
type OSLKey []byte
type OSLFileSpec []byte

// DiscoverServerEntriesRequest is a request from a client to potentially
// discover new server entries. The DSL backend serving the request selects
// discoverable server entries using a combination of inputs in
// BaseAPIParameters; active OSL keys known to the client; and client GeoIP
// data.
//
// The response contains a list of server entry tags and versions, and
// the client will then proceed to request full server entries for unknown or
// stale server entries, based on the tags and versions. DiscoverCount
// specifies a maximum number of server entry tags/versions to return; the
// DSL backend may return less, but not more.
type DiscoverServerEntriesRequest struct {
	BaseAPIParameters protocol.PackedAPIParameters `cbor:"1,keyasint,omitempty"`
	OSLKeys           []OSLKey                     `cbor:"2,keyasint,omitempty"`
	DiscoverCount     int32                        `cbor:"3,keyasint,omitempty"`
}

// ServerEntryTag is a binary representation of a protocol.ServerEntry.Tag
// value. Hex- or base64-encoded tag strings should be converted to binary
// for compactness.
type ServerEntryTag []byte

// VersionedServerEntryTag is a server entry tag and version pair.
type VersionedServerEntryTag struct {
	Tag     ServerEntryTag `cbor:"1,keyasint,omitempty"`
	Version int32          `cbor:"2,keyasint,omitempty"`
}

// DiscoverServerEntriesResponse is the set of server entries revealed to the
// client, specified as server entry tag and version pairs, which enable the
// client to determine if it already has the server entry, and has the latest
// version. For new or updated server entries, the client will proceed to
// send a GetServerEntriesRequest to fetch the server entries.
type DiscoverServerEntriesResponse struct {
	VersionedServerEntryTags []*VersionedServerEntryTag `cbor:"1,keyasint,omitempty"`
}

// GetServerEntriesRequest is a request from a client to download the
// specified server entries.
type GetServerEntriesRequest struct {
	BaseAPIParameters protocol.PackedAPIParameters `cbor:"1,keyasint,omitempty"`
	ServerEntryTags   []ServerEntryTag             `cbor:"2,keyasint,omitempty"`
}

// SourcedServerEntry is a server entry and server entry source pair. The
// client stores the server entry source as protocol.ServerEntry.LocalSource,
// which is used for server_entry_source stats reporting.
type SourcedServerEntry struct {
	ServerEntryFields protocol.PackedServerEntryFields `cbor:"1,keyasint,omitempty"`
	Source            string                           `cbor:"2,keyasint,omitempty"`
}

// GetServerEntriesResponse includes the list of server entries requested by
// the client. Each requested tag has a corresponding entry in
// SourcedServerEntries. When a requested tag is no longer available for
// distribution, there is a nil/empty entry.
type GetServerEntriesResponse struct {
	SourcedServerEntries []*SourcedServerEntry `cbor:"1,keyasint,omitempty"`
}

// GetActiveOSLsRequest is a request from a client to get the list of
// currently active OSL IDs.
//
// Clients maintain local copies of the OSL FileSpec for each active OSL,
// using SLOKs to reassemble the keys for the OSLs using the key split
// definitions in each OSL FileSpec. These current OSL keys, reassembled by
// the client, are then included in DiscoverServerEntriesRequest requests,
// demonstrating that the client can decrypt the OSL in the classic scheme;
// the DSL backend uses the keys as proof-of-knowledge to grant access to
// compartmentalized server entries.
//
// For new and unknown OSL IDs, clients will use GetOSLFileSpecsRequest to
// download the corresponding OSL FileSpecs.
//
// It is assumed that the number of OSL schemes and scheme pave counts
// (see common/osl.Config) produces an OSL ID list size that is appropriate
// to return in full in a single response.
type GetActiveOSLsRequest struct {
	BaseAPIParameters protocol.PackedAPIParameters `cbor:"1,keyasint,omitempty"`
}

// GetActiveOSLsResponse is a list of the currently active OSL IDs.
type GetActiveOSLsResponse struct {
	ActiveOSLIDs []OSLID `cbor:"1,keyasint,omitempty"`
}

// GetOSLFileSpecsRequest is a request from a client to download the
// OSL FileSpecs for the OSLs specified by ID.
type GetOSLFileSpecsRequest struct {
	BaseAPIParameters protocol.PackedAPIParameters `cbor:"1,keyasint,omitempty"`
	OSLIDs            []OSLID                      `cbor:"2,keyasint,omitempty"`
}

// GetOSLFileSpecsResponse includes the list of OSL FileSpecs requested by the
// client. Each requested OSL ID has a corresponding entry in OSLFileSpecs.
// When a requsted OSL is no longer active or available for distribution,
// there is a nil/empty entry.
//
// Here, OSLFileSpec is a []byte, not an osl.FileSpec, as this value doesn't
// need to be unmarshaled immediately in the fetcher processing.
type GetOSLFileSpecsResponse struct {
	OSLFileSpecs []OSLFileSpec `cbor:"1,keyasint,omitempty"`
}

// Relay API layer
//
// DSL clients send requests to the DSL backend via a relay, which provides
// circumvention and blocking resistance. Relays include in-proxy brokers,
// with untunneled domain fronting over a secure Noise session; and Psiphon
// servers, via SSH requests within an established tunnel. The relays remove
// the RelayedRequest layer and forward requests to the DSL backend over
// HTTPS with mutually authenticated TLS; and wrap responses with
// RelayedResponse.
//
// The trusted relays will attach the original client IP and GeoIP data to
// relayed requests; these inputs may be used by the DSL backend when
// selecting server entries that the client may discover.
//
// 1. client -> broker/psiphond relay
//    CBOR[RelayedRequest(requestTypeDiscoverServerEntries, v1, CBOR[DiscoverServerEntriesRequest])]
//
// 2. broker/psiphond -> DSL
//    POST /DiscoverServerEntries/v1 HTTP/1.1
//    X-Psiphon-Client-IP: x.x.x.x
//    CBOR[DiscoverServerEntriesRequest]
//
// 3. DSL -> broker/psiphond
//    HTTP/1.1 200 OK
//    CBOR[DiscoverServerEntriesResponse]
//
// 4. broker/psiphond -> client
//    CBOR[RelayedResponse(ErrorCode, CBOR[DiscoverServerEntriesResponse])]
//

// MaxRelayPayloadSize is bounded by inproxy.BrokerMaxRequestBodySize,
// 64K, and the common/crypto/ssh maxPacket, 256K.
const MaxRelayPayloadSize = 65536

const (
	PsiphonClientIPHeader        = "X-Psiphon-Client-Ip"
	PsiphonClientGeoIPDataHeader = "X-Psiphon-Client-Geoipdata"
	PsiphonClientTunneledHeader  = "X-Psiphon-Client-Tunneled"
	PsiphonHostIDHeader          = "X-Psiphon-Host-Id"

	RequestPathDiscoverServerEntries = "/v1/DiscoverServerEntries"
	RequestPathGetServerEntries      = "/v1/GetServerEntries"
	RequestPathGetActiveOSLs         = "/v1/GetActiveOSLs"
	RequestPathGetOSLFileSpecs       = "/v1/GetOSLFileSpecs"

	requestVersion                   = 0
	requestTypeDiscoverServerEntries = 1
	requestTypeGetServerEntries      = 2
	requestTypeGetActiveOSLs         = 3
	requestTypeGetOSLFileSpecs       = 4
)

var requestTypeToHTTPPath = map[int32]string{
	requestTypeDiscoverServerEntries: RequestPathDiscoverServerEntries,
	requestTypeGetServerEntries:      RequestPathGetServerEntries,
	requestTypeGetActiveOSLs:         RequestPathGetActiveOSLs,
	requestTypeGetOSLFileSpecs:       RequestPathGetOSLFileSpecs,
}

// RelayedRequest wraps a DSL request to be relayed. RequestType indicates the
// type of the wrapped request. Version must be 0.
type RelayedRequest struct {
	RequestType int32  `cbor:"1,keyasint,omitempty"`
	Version     int32  `cbor:"2,keyasint,omitempty"`
	Request     []byte `cbor:"3,keyasint,omitempty"`
}

// RelayedResponse wraps a DSL response value or error.
type RelayedResponse struct {
	Error       int32  `cbor:"1,keyasint,omitempty"`
	Compression int32  `cbor:"2,keyasint,omitempty"`
	Response    []byte `cbor:"3,keyasint,omitempty"`
}
