/*
 * Copyright (c) 2023, Psiphon Inc.
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

package protocol

import (
	"encoding"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/accesscontrol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/fxamacker/cbor/v2"
)

// PackedAPIParameters is a compacted representation of common.APIParameters
// using integer keys in place of string keys, and with some values
// represented in compacted form, such as byte slices in place of hex or
// base64 strings.
//
// The PackedAPIParameters representation is intended to be used to create
// compacted, CBOR encodings of API parameters.
type PackedAPIParameters map[int]interface{}

// EncodePackedAPIParameters converts common.APIParameters to
// PackedAPIParameters.
func EncodePackedAPIParameters(params common.APIParameters) (PackedAPIParameters, error) {
	packedParams := PackedAPIParameters{}
	for name, value := range params {
		spec, ok := packedAPIParametersNameToSpec[name]
		if !ok {
			// The API parameter to be packed is not in
			// packedAPIParametersNameToSpec. This will occur if
			// packedAPIParametersNameToSpec is not updated when new API
			// parameters are added. Fail the operation and, ultimately, the
			// dial rather than proceeding without the parameter.
			return nil, errors.Tracef("unknown parameter name: %s", name)

		}
		if spec.converter != nil {
			var err error
			value, err = spec.converter.pack(value)
			if err != nil {
				return nil, errors.Tracef(
					"pack %s (%T) failed: %v", name, params[name], err)
			}
		}
		if _, ok := packedParams[spec.key]; ok {
			// This is a sanity check and shouldn't happen unless
			// packedAPIParametersNameToSpec is misconfigured.
			return nil, errors.TraceNew("duplicate parameter")
		}
		packedParams[spec.key] = value
	}
	return packedParams, nil
}

// DecodePackedAPIParameters converts PackedAPIParameters to
// common.APIParameters
func DecodePackedAPIParameters(packedParams PackedAPIParameters) (common.APIParameters, error) {
	params := common.APIParameters{}
	for key, value := range packedParams {
		spec, ok := packedAPIParametersKeyToSpec[key]
		if !ok {
			// The API parameter received is not in
			// packedAPIParametersNameToInt. Skip logging it and proceed.
			// This allows for production psiphond/broker instances to handle
			// experimental clients which ship new parameters, and matches
			// the legacy JSON-encoded API parameters behavior.
			continue
		}
		if spec.converter != nil {
			var err error
			value, err = spec.converter.unpack(value)
			if err != nil {
				return nil, errors.Tracef(
					"unpack %s (%T) failed: %v", spec.name, packedParams[key], err)
			}
		}
		if _, ok := params[spec.name]; ok {
			// This is a sanity check and shouldn't happen unless
			// packedAPIParametersKeyToSpec is misconfigured.
			return nil, errors.TraceNew("duplicate parameter")
		}
		params[spec.name] = value
	}
	return params, nil
}

// GetNetworkType returns the "network_type" API parameter value, if present.
func (p PackedAPIParameters) GetNetworkType() (string, bool) {
	spec, ok := packedAPIParametersNameToSpec["network_type"]
	if !ok {
		return "", false
	}
	value, ok := p[spec.key]
	if !ok {
		return "", false
	}
	networkType, ok := value.(string)
	if !ok {
		return "", false
	}
	return networkType, true
}

// MakePackedAPIParametersRequestPayload converts common.APIParameters to
// PackedAPIParameters and encodes the packed parameters as CBOR data.
func MakePackedAPIParametersRequestPayload(
	params common.APIParameters) ([]byte, error) {

	packedParams, err := EncodePackedAPIParameters(params)
	if err != nil {
		return nil, errors.Trace(err)
	}

	payload, err := CBOREncoding.Marshal(packedParams)
	if err != nil {
		return nil, errors.Trace(err)
	}

	payload = addPackedAPIParametersPreamble(payload)

	return payload, nil
}

// GetPackedAPIParametersRequestPayload decodes the CBOR payload and converts
// the PackedAPIParameters to common.APIParameters.
//
// GetPackedAPIParametersRequestPayload returns false and a nil error if the
// input payload is not CBOR data, which is the case for legacy JSON
// payloads.
func GetPackedAPIParametersRequestPayload(
	payload []byte) (common.APIParameters, bool, error) {

	payload, ok := isPackedAPIParameters(payload)
	if !ok {
		return nil, false, nil
	}

	var packedParams PackedAPIParameters
	err := cbor.Unmarshal(payload, &packedParams)
	if err != nil {
		return nil, false, errors.Trace(err)
	}

	params, err := DecodePackedAPIParameters(packedParams)
	if err != nil {
		return nil, false, errors.Trace(err)
	}

	return params, true, nil
}

const (
	packedAPIParametersDistinguisher = byte(0)
	packedAPIParametersVersion       = byte(1)
)

func addPackedAPIParametersPreamble(payload []byte) []byte {

	var preamble [2]byte

	// Use a simple 0 byte to distinguish payloads from JSON.
	preamble[0] = packedAPIParametersDistinguisher

	// Add a version tag, for future protocol changes.
	preamble[1] = packedAPIParametersVersion

	// Attempt to use the input buffer, which will avoid an allocation if it
	// has sufficient capacity.
	payload = append(payload, preamble[:]...)
	copy(payload[2:], payload[:len(payload)-2])
	copy(payload[0:2], preamble[:])

	return payload
}

func isPackedAPIParameters(payload []byte) ([]byte, bool) {
	if len(payload) < 2 {
		return nil, false
	}
	if payload[0] != packedAPIParametersDistinguisher {
		return nil, false
	}
	if payload[1] != packedAPIParametersVersion {
		return nil, false
	}

	return payload[2:], true
}

// PackedServerEntryFields is a compacted representation of ServerEntryFields
// using integer keys in place of string keys, and with some values
// represented in compacted form, such as byte slices in place of hex or
// base64 strings.
//
// The PackedServerEntryFields representation is intended to be used in
// CBOR-encoded messages, including in-proxy broker requests.
//
// To support older clients encoding signed server entries with new,
// unrecognized fields, the encoded structure includes a list of packed
// fields, Fields, and a list of raw, unpacked fields, UnrecognizedFields.
type PackedServerEntryFields struct {
	Fields             map[int]interface{}    `cbor:"1,keyasint,omitempty"`
	UnrecognizedFields map[string]interface{} `cbor:"2,keyasint,omitempty"`
}

// EncodePackedServerEntryFields converts serverEntryFields to
// PackedServerEntryFields.
func EncodePackedServerEntryFields(
	serverEntryFields ServerEntryFields) (PackedServerEntryFields, error) {

	// An allocated but empty UnrecognizedFields should be omitted from any
	// CBOR encoding, taking no space.
	packedServerEntry := PackedServerEntryFields{
		Fields:             make(map[int]interface{}),
		UnrecognizedFields: make(map[string]interface{}),
	}
	for name, value := range serverEntryFields {
		spec, ok := packedServerEntryFieldsNameToSpec[name]
		if !ok {
			// Add unrecognized fields to the unpacked UnrecognizedFields set.
			if _, ok := packedServerEntry.UnrecognizedFields[name]; ok {
				// This is a sanity check and shouldn't happen.
				return PackedServerEntryFields{}, errors.TraceNew("duplicate field")
			}
			packedServerEntry.UnrecognizedFields[name] = value
			continue
		}
		if spec.converter != nil {
			var err error
			value, err = spec.converter.pack(value)
			if err != nil {
				return PackedServerEntryFields{}, errors.Tracef(
					"pack %s (%T) failed: %v", name, serverEntryFields[name], err)
			}
		}
		if _, ok := packedServerEntry.Fields[spec.key]; ok {
			// This is a sanity check and shouldn't happen unless
			// packedServerEntryFieldsNameToSpec is misconfigured.
			return PackedServerEntryFields{}, errors.TraceNew("duplicate field")
		}
		packedServerEntry.Fields[spec.key] = value
	}
	return packedServerEntry, nil
}

// DecodePackedServerEntryFields converts PackedServerEntryFields to
// ServerEntryFields.
func DecodePackedServerEntryFields(
	packedServerEntryFields PackedServerEntryFields) (ServerEntryFields, error) {

	serverEntryFields := ServerEntryFields{}
	for key, value := range packedServerEntryFields.Fields {
		spec, ok := packedServerEntryFieldsKeyToSpec[key]
		if !ok {
			// Unlike DecodePackedAPIParameters, unknown fields cannot be
			// ignored as they may be part of the server entry digital
			// signature. Production psiphond/broker instances must be
			// updated to handle new server entry fields.
			return nil, errors.Tracef("unknown field key: %d", key)
		}
		if spec.converter != nil {
			var err error
			value, err = spec.converter.unpack(value)
			if err != nil {
				return nil, errors.Tracef(
					"unpack %s (%T) failed: %v",
					spec.name, packedServerEntryFields.Fields[key], err)
			}
		}
		if _, ok := serverEntryFields[spec.name]; ok {
			// This is a sanity check and shouldn't happen unless
			// packedServerEntryFieldsKeyToSpec is misconfigured.
			return nil, errors.TraceNew("duplicate field")
		}
		serverEntryFields[spec.name] = value
	}
	for name, value := range packedServerEntryFields.UnrecognizedFields {
		if _, ok := serverEntryFields[name]; ok {
			// This is a sanity check and shouldn't happen.
			return nil, errors.TraceNew("duplicate field")
		}
		serverEntryFields[name] = value
	}
	return serverEntryFields, nil
}

type packSpec struct {
	key       int
	name      string
	converter *packConverter
}

// packConverter defines an optional pack/unpack transformation to further
// reduce encoding overhead. For example, fields that are expected to be hex
// strings may be converted to byte slices, and then back again; integer
// strings are converted to actual integers; etc..
type packConverter struct {
	pack   func(interface{}) (interface{}, error)
	unpack func(interface{}) (interface{}, error)
}

func packInt(v interface{}) (interface{}, error) {
	switch value := v.(type) {
	case string:
		i, err := strconv.Atoi(value)
		if err != nil {
			return nil, errors.Trace(err)
		}
		return i, nil
	case float64:
		// Decoding server entry JSON from the local datastore may produce
		// float64 field types.
		return int(value), nil
	default:
		return nil, errors.TraceNew(
			"expected string or float type")
	}
}

func unpackInt(v interface{}) (interface{}, error) {
	switch i := v.(type) {
	case int:
		return strconv.FormatInt(int64(i), 10), nil
	case int64:
		return strconv.FormatInt(i, 10), nil
	case uint64:
		return strconv.FormatUint(i, 10), nil
	default:
		return nil, errors.TraceNew(
			"expected int, int64, or uint64 type")
	}
}

func packFloat(v interface{}) (interface{}, error) {
	switch value := v.(type) {
	case string:
		i, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return nil, errors.Trace(err)
		}
		return i, nil
	case float64:
		return value, nil
	default:
		return nil, errors.TraceNew(
			"expected string or float type")
	}
}

func unpackFloat(v interface{}) (interface{}, error) {
	f, ok := v.(float64)
	if !ok {
		return nil, errors.TraceNew("expected int type")
	}
	return fmt.Sprintf("%f", f), nil
}

func packHex(v interface{}) (interface{}, error) {
	// Accept a type that is either a string, or implements MarshalText
	// returning a string. The resulting string must be hex encoded.
	s, err := stringOrTextMarshal(v)
	if err != nil {
		return nil, errors.Trace(err)
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, errors.Trace(err)
	}
	return b, nil
}

func unpackHexLower(v interface{}) (interface{}, error) {
	b, ok := v.([]byte)
	if !ok {
		return nil, errors.TraceNew("expected []byte type")
	}
	return hex.EncodeToString(b), nil
}

func unpackHexUpper(v interface{}) (interface{}, error) {
	s, err := unpackHexLower(v)
	if err != nil {
		return nil, errors.Trace(err)
	}
	return strings.ToUpper(s.(string)), nil
}

func packBase64(v interface{}) (interface{}, error) {
	// Accept a type that is either a string, or implements MarshalText
	// returning a string. The resulting string must be base64 encoded.
	s, err := stringOrTextMarshal(v)
	if err != nil {
		return nil, errors.Trace(err)
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, errors.Trace(err)
	}
	return b, nil
}

func unpackBase64(v interface{}) (interface{}, error) {
	b, ok := v.([]byte)
	if !ok {
		return nil, errors.TraceNew("expected []byte type")
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func packUnpaddedBase64(v interface{}) (interface{}, error) {
	// Accept a type that is either a string, or implements MarshalText
	// returning a string. The resulting string must be base64 encoded
	// (unpadded).
	s, err := stringOrTextMarshal(v)
	if err != nil {
		return nil, errors.Trace(err)
	}
	b, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil {
		return nil, errors.Trace(err)
	}
	return b, nil
}

func unpackUnpaddedBase64(v interface{}) (interface{}, error) {
	b, ok := v.([]byte)
	if !ok {
		return nil, errors.TraceNew("expected []byte type")
	}
	return base64.RawStdEncoding.EncodeToString(b), nil
}

func packAuthorizations(v interface{}) (interface{}, error) {
	auths, ok := v.([]string)
	if !ok {
		return nil, errors.TraceNew("expected []string type")
	}
	packedAuths, err := accesscontrol.PackAuthorizations(auths, CBOREncoding)
	if err != nil {
		return nil, errors.Trace(err)
	}
	return packedAuths, nil
}

func unpackAuthorizations(v interface{}) (interface{}, error) {
	packedAuths, ok := v.([]byte)
	if !ok {
		return nil, errors.TraceNew("expected []byte type")
	}
	auths, err := accesscontrol.UnpackAuthorizations(packedAuths)
	if err != nil {
		return nil, errors.Trace(err)
	}
	return auths, nil
}

func packNoop(v interface{}) (interface{}, error) {
	return v, nil
}

func unpackRawJSON(v interface{}) (interface{}, error) {

	// For compatibility with the legacy JSON encoding as used in the status
	// API request payload, where the input is pre-JSON-marshaling
	// json.RawMessage (so use packNoop) and the output is expected to be an
	// unmarshaled JSON decoded object; e.g., map[string]interface{}.

	packedRawJSON, ok := v.([]byte)
	if !ok {
		return nil, errors.TraceNew("expected []byte type")
	}
	var unmarshaledJSON map[string]interface{}
	err := json.Unmarshal(packedRawJSON, &unmarshaledJSON)
	if err != nil {
		return nil, errors.Trace(err)
	}
	return unmarshaledJSON, nil
}

func unpackSliceOfJSONCompatibleMaps(v interface{}) (interface{}, error) {

	// For compatibility with the legacy JSON encoding as used for tactics
	// speed test sample parameters. This converts CBOR maps of type map
	// [interface{}]interface{} to JSON-compatible maps of type map
	// [string]interface{}.

	if v == nil {
		return nil, nil
	}

	packedEntries, ok := v.([]interface{})
	if !ok {
		return nil, errors.TraceNew("expected []interface{} type")
	}

	entries := make([]map[string]interface{}, len(packedEntries))

	for i, packedEntry := range packedEntries {
		entry, ok := packedEntry.(map[interface{}]interface{})
		if !ok {
			return nil, errors.TraceNew("expected map[interface{}]interface{} type")
		}
		entries[i] = make(map[string]interface{})
		for key, value := range entry {
			strKey, ok := key.(string)
			if !ok {
				return nil, errors.TraceNew("expected string type")
			}
			entries[i][strKey] = value
		}
	}

	return entries, nil
}

func stringOrTextMarshal(v interface{}) (string, error) {
	switch value := v.(type) {
	case string:
		return value, nil
	case encoding.TextMarshaler:
		bytes, err := value.MarshalText()
		if err != nil {
			return "", errors.Trace(err)
		}
		return string(bytes), nil
	default:
		return "", errors.TraceNew(
			"expected string or TextMarshaler type")
	}
}

var (

	// All of the following variables should be read-only after
	// initialization, due to concurrent access.

	packedAPIParametersNameToSpec = make(map[string]packSpec)
	packedAPIParametersKeyToSpec  = make(map[int]packSpec)

	packedServerEntryFieldsNameToSpec = make(map[string]packSpec)
	packedServerEntryFieldsKeyToSpec  = make(map[int]packSpec)

	intConverter               = &packConverter{packInt, unpackInt}
	floatConverter             = &packConverter{packFloat, unpackFloat}
	lowerHexConverter          = &packConverter{packHex, unpackHexLower}
	upperHexConverter          = &packConverter{packHex, unpackHexUpper}
	base64Converter            = &packConverter{packBase64, unpackBase64}
	unpaddedBase64Converter    = &packConverter{packUnpaddedBase64, unpackUnpaddedBase64}
	authorizationsConverter    = &packConverter{packAuthorizations, unpackAuthorizations}
	rawJSONConverter           = &packConverter{packNoop, unpackRawJSON}
	compatibleJSONMapConverter = &packConverter{packNoop, unpackSliceOfJSONCompatibleMaps}
)

func init() {

	// Packed API parameters
	//
	// - must be appended to when server entry fields are added; existing key
	//   values cannot be reordered or reused.
	//
	// - limitation: use of converters means secrets/passwords/IDs are locked
	//   in as upper or lower hex with even digits, etc.
	//
	// - while not currently the case, if different API requests have the same
	//   input field name with different types, the nil converter must be used.

	packedAPIParameterSpecs := []packSpec{

		// Specs: protocol.PSIPHON_API_HANDSHAKE_AUTHORIZATIONS

		{1, "authorizations", authorizationsConverter},

		// Specs:
		// tactics.SPEED_TEST_SAMPLES_PARAMETER_NAME
		// tactics.APPLIED_TACTICS_TAG_PARAMETER_NAME
		// tactics.STORED_TACTICS_TAG_PARAMETER_NAME

		{2, "stored_tactics_tag", lowerHexConverter},
		{3, "speed_test_samples", compatibleJSONMapConverter},
		{4, "applied_tactics_tag", lowerHexConverter},

		// Specs: server.baseParams
		//
		// - client_build_rev does not use a hex converter since some values
		//   are a non-even length prefix of a commit hash hex.

		{5, "client_session_id", lowerHexConverter},
		{6, "propagation_channel_id", upperHexConverter},
		{7, "sponsor_id", upperHexConverter},
		{8, "client_version", intConverter},
		{9, "client_platform", nil},
		{10, "client_features", nil},
		{11, "client_build_rev", nil},
		{12, "device_region", nil},
		{13, "device_location", nil},

		// Specs: server.baseSessionParams

		{14, "session_id", lowerHexConverter},

		// Specs: server.baseDialParams
		//
		// - intConverter is used for boolean fields as those are "0"/"1"
		//   string values by legacy convention.
		//
		// - the `padding` field is not packed since it is intended to pad the
		//   encoded message to its existing size.
		//
		// - egress_region is now in server.baseParams, but its encoding
		//   remains the same.

		{15, "relay_protocol", nil},
		{16, "ssh_client_version", nil},
		{17, "upstream_proxy_type", nil},
		{18, "upstream_proxy_custom_header_names", nil},
		{19, "fronting_provider_id", upperHexConverter},
		{20, "meek_dial_address", nil},
		{21, "meek_resolved_ip_address", nil},
		{22, "meek_sni_server_name", nil},
		{23, "meek_host_header", nil},
		{24, "meek_transformed_host_name", intConverter},
		{25, "user_agent", nil},
		{26, "tls_profile", nil},
		{27, "tls_version", nil},
		{28, "server_entry_region", nil},
		{29, "server_entry_source", nil},
		{30, "server_entry_timestamp", nil},
		{31, "dial_port_number", intConverter},
		{32, "quic_version", nil},
		{33, "quic_dial_sni_address", nil},
		{34, "quic_disable_client_path_mtu_discovery", intConverter},
		{35, "upstream_bytes_fragmented", intConverter},
		{36, "upstream_min_bytes_written", intConverter},
		{37, "upstream_max_bytes_written", intConverter},
		{38, "upstream_min_delayed", intConverter},
		{39, "upstream_max_delayed", intConverter},
		{40, "padding", nil},
		{41, "pad_response", intConverter},
		{42, "is_replay", intConverter},
		{43, "egress_region", nil},
		{44, "dial_duration", intConverter},
		{45, "candidate_number", intConverter},
		{46, "established_tunnels_count", intConverter},
		{47, "upstream_ossh_padding", intConverter},
		{48, "meek_cookie_size", intConverter},
		{49, "meek_limit_request", intConverter},
		{50, "meek_redial_probability", floatConverter},
		{51, "meek_tls_padding", intConverter},
		{52, "network_latency_multiplier", floatConverter},
		{53, "client_bpf", nil},
		{54, "network_type", nil},
		{55, "conjure_cached", nil},
		{56, "conjure_delay", nil},
		{57, "conjure_transport", nil},
		{58, "conjure_prefix", nil},
		{59, "conjure_stun", nil},
		{60, "conjure_empty_packet", intConverter},
		{61, "conjure_network", nil},
		{62, "conjure_port_number", intConverter},
		{63, "split_tunnel", nil},
		{64, "split_tunnel_regions", nil},
		{65, "dns_preresolved", nil},
		{66, "dns_preferred", nil},
		{67, "dns_transform", nil},
		{68, "dns_attempt", intConverter},
		{69, "http_transform", nil},
		{70, "seed_transform", nil},
		{71, "ossh_prefix", nil},
		{72, "tls_fragmented", intConverter},
		{73, "tls_padding", intConverter},
		{74, "tls_ossh_sni_server_name", nil},
		{75, "tls_ossh_transformed_host_name", intConverter},

		// Specs: server.inproxyDialParams

		{76, "inproxy_connection_id", unpaddedBase64Converter},
		{77, "inproxy_relay_packet", unpaddedBase64Converter},
		{78, "inproxy_broker_is_replay", intConverter},
		{79, "inproxy_broker_transport", nil},
		{80, "inproxy_broker_fronting_provider_id", upperHexConverter},
		{81, "inproxy_broker_dial_address", nil},
		{82, "inproxy_broker_resolved_ip_address", nil},
		{83, "inproxy_broker_sni_server_name", nil},
		{84, "inproxy_broker_host_header", nil},
		{85, "inproxy_broker_transformed_host_name", intConverter},
		{86, "inproxy_broker_user_agent", nil},
		{87, "inproxy_broker_tls_profile", nil},
		{88, "inproxy_broker_tls_version", nil},
		{89, "inproxy_broker_tls_fragmented", intConverter},
		{90, "inproxy_broker_tls_padding", intConverter},
		{91, "inproxy_broker_client_bpf", nil},
		{92, "inproxy_broker_upstream_bytes_fragmented", intConverter},
		{93, "inproxy_broker_upstream_min_bytes_written", intConverter},
		{94, "inproxy_broker_upstream_max_bytes_written", intConverter},
		{95, "inproxy_broker_upstream_min_delayed", intConverter},
		{96, "inproxy_broker_upstream_max_delayed", intConverter},
		{97, "inproxy_broker_http_transform", nil},
		{98, "inproxy_broker_dns_preresolved", nil},
		{99, "inproxy_broker_dns_preferred", nil},
		{100, "inproxy_broker_dns_transform", nil},
		{101, "inproxy_broker_dns_attempt", intConverter},
		{102, "inproxy_webrtc_dns_preresolved", nil},
		{103, "inproxy_webrtc_dns_preferred", nil},
		{104, "inproxy_webrtc_dns_transform", nil},
		{105, "inproxy_webrtc_dns_attempt", intConverter},
		{106, "inproxy_webrtc_stun_server", nil},
		{107, "inproxy_webrtc_stun_server_resolved_ip_address", nil},
		{108, "inproxy_webrtc_stun_server_RFC5780", nil},
		{109, "inproxy_webrtc_stun_server_RFC5780_resolved_ip_address", nil},
		{110, "inproxy_webrtc_randomize_dtls", intConverter},
		{111, "inproxy_webrtc_padded_messages_sent", intConverter},
		{112, "inproxy_webrtc_padded_messages_received", intConverter},
		{113, "inproxy_webrtc_decoy_messages_sent", intConverter},
		{114, "inproxy_webrtc_decoy_messages_received", intConverter},
		{115, "inproxy_webrtc_local_ice_candidate_type", nil},
		{116, "inproxy_webrtc_local_ice_candidate_is_initiator", intConverter},
		{117, "inproxy_webrtc_local_ice_candidate_is_IPv6", intConverter},
		{118, "inproxy_webrtc_local_ice_candidate_port", intConverter},
		{119, "inproxy_webrtc_remote_ice_candidate_type", nil},
		{120, "inproxy_webrtc_remote_ice_candidate_is_IPv6", intConverter},
		{121, "inproxy_webrtc_remote_ice_candidate_port", intConverter},

		// Specs: server.handshakeRequestParams

		{122, "missing_server_entry_signature", base64Converter},
		{123, "missing_server_entry_provider_id", base64Converter},

		// Specs: server.uniqueUserParams
		//
		// - future enhancement: add a timestamp converter from RFC3339 to and
		//   from 64-bit Unix time?

		{124, "last_connected", nil},

		// Specs: server.connectedRequestParams

		{125, "establishment_duration", intConverter},

		// Specs: server.remoteServerListStatParams

		{126, "client_download_timestamp", nil},
		{127, "tunneled", intConverter},
		{128, "url", nil},
		{129, "etag", nil},
		{130, "bytes", intConverter},
		{131, "duration", intConverter},

		// Specs: server.failedTunnelStatParams
		//
		// - given CBOR integer encoding, int key values greater than 128 may
		//   be a byte longer; this means some failed_tunnel required field
		//   key encodings may be longer than some optional handshake field
		//   key encodings; however, we prioritize reducing the handshake
		//   size, since it comes earlier in the tunnel flow.

		{132, "server_entry_tag", base64Converter},
		{133, "client_failed_timestamp", nil},
		{134, "record_probability", floatConverter},
		{135, "liveness_test_upstream_bytes", intConverter},
		{136, "liveness_test_sent_upstream_bytes", intConverter},
		{137, "liveness_test_downstream_bytes", intConverter},
		{138, "liveness_test_received_downstream_bytes", intConverter},
		{139, "bytes_up", intConverter},
		{140, "bytes_down", intConverter},
		{141, "tunnel_error", nil},

		// Specs: status request payload
		//
		// - future enhancement: pack the statusData payload, which is
		//   currently sent as unpacked JSON.

		{142, "statusData", rawJSONConverter},

		// Specs: server.inproxyDialParams

		{143, "inproxy_webrtc_local_ice_candidate_is_private_IP", intConverter},
		{144, "inproxy_webrtc_remote_ice_candidate_is_private_IP", intConverter},

		// Specs: server.baseDialParams

		{145, "tls_sent_ticket", intConverter},
		{146, "tls_did_resume", intConverter},
		{147, "quic_sent_ticket", intConverter},
		{148, "quic_did_resume", intConverter},
		{149, "quic_dial_early", intConverter},
		{150, "quic_obfuscated_psk", intConverter},

		{151, "dns_qname_random_casing", intConverter},
		{152, "dns_qname_must_match", intConverter},
		{153, "dns_qname_mismatches", intConverter},

		// Specs: server.inproxyDialParams

		{154, "inproxy_broker_dns_qname_random_casing", intConverter},
		{155, "inproxy_broker_dns_qname_must_match", intConverter},
		{156, "inproxy_broker_dns_qname_mismatches", intConverter},
		{157, "inproxy_webrtc_dns_qname_random_casing", intConverter},
		{158, "inproxy_webrtc_dns_qname_must_match", intConverter},
		{159, "inproxy_webrtc_dns_qname_mismatches", intConverter},

		{160, "inproxy_dial_nat_discovery_duration", intConverter},
		{161, "inproxy_dial_failed_attempts_duration", intConverter},
		{162, "inproxy_dial_webrtc_ice_gathering_duration", intConverter},
		{163, "inproxy_dial_broker_offer_duration", intConverter},
		{164, "inproxy_dial_webrtc_connection_duration", intConverter},
		{165, "inproxy_broker_is_reuse", intConverter},
		{166, "inproxy_webrtc_use_media_streams", intConverter},

		// Specs: server.baseDialParams

		{167, "shadowsocks_prefix", nil},

		// Specs: protocol.PSIPHON_API_RESPONSE_VERSION_FIELD_NAME

		{168, "psiphon_api_response_version", intConverter},

		// Specs: server.baseDialParams

		{169, "server_entry_count", intConverter},
		{170, "replay_ignored_change", intConverter},
		{171, "dsl_prioritized", intConverter},

		// Next key value = 172
	}

	for _, spec := range packedAPIParameterSpecs {

		if _, ok := packedAPIParametersNameToSpec[spec.name]; ok {
			panic("duplicate parameter name")
		}
		packedAPIParametersNameToSpec[spec.name] = spec

		if _, ok := packedAPIParametersKeyToSpec[spec.key]; ok {
			panic("duplicate parameter key")
		}
		packedAPIParametersKeyToSpec[spec.key] = spec
	}

	// Packed server entry fields
	//
	// - must be appended to when server entry fields are added; existing key
	//   values cannot be reordered or reused.
	//
	// - limitation: use of converters means secrets/passwords/IDs are locked
	//   in as upper or lower hex with even digits, etc.
	//
	// - since webServerCertificate is omitted in non-legacy server entries,
	//   no PEM-encoding packer is implemented.
	//
	// - unlike API integer parameters and certain server entry fields, most
	//   port values are already int types and so not converted.
	//
	// - local-only fields are also packed, to allow for future use of packed
	//   encodings in the local datastore.

	packedServerEntryFieldSpecs := []packSpec{
		{1, "tag", base64Converter},
		{2, "ipAddress", nil},
		{3, "webServerPort", intConverter},
		{4, "webServerSecret", lowerHexConverter},
		{5, "webServerCertificate", nil},
		{6, "sshPort", nil},
		{7, "sshUsername", nil},
		{8, "sshPassword", lowerHexConverter},
		{9, "sshHostKey", base64Converter},
		{10, "sshObfuscatedPort", nil},
		{11, "sshObfuscatedQUICPort", nil},
		{12, "limitQUICVersions", nil},
		{13, "sshObfuscatedTapdancePort", nil},
		{14, "sshObfuscatedConjurePort", nil},
		{15, "sshObfuscatedKey", lowerHexConverter},
		{16, "capabilities", nil},
		{17, "region", nil},
		{18, "providerID", upperHexConverter},
		{19, "frontingProviderID", upperHexConverter},
		{20, "tlsOSSHPort", nil},
		{21, "meekServerPort", nil},
		{22, "meekCookieEncryptionPublicKey", base64Converter},
		{23, "meekObfuscatedKey", lowerHexConverter},
		{24, "meekFrontingHost", nil},
		{25, "meekFrontingHosts", nil},
		{26, "meekFrontingDomain", nil},
		{27, "meekFrontingAddresses", nil},
		{28, "meekFrontingAddressesRegex", nil},
		{29, "meekFrontingDisableSNI", nil},
		{30, "tacticsRequestPublicKey", base64Converter},
		{31, "tacticsRequestObfuscatedKey", base64Converter},
		{32, "configurationVersion", nil},
		{33, "signature", base64Converter},
		{34, "disableHTTPTransforms", nil},
		{35, "disableObfuscatedQUICTransforms", nil},
		{36, "disableOSSHTransforms", nil},
		{37, "disableOSSHPrefix", nil},
		{38, "inproxySessionPublicKey", unpaddedBase64Converter},
		{39, "inproxySessionRootObfuscationSecret", unpaddedBase64Converter},
		{40, "inproxySSHPort", nil},
		{41, "inproxyOSSHPort", nil},
		{42, "inproxyQUICPort", nil},
		{43, "inproxyMeekPort", nil},
		{44, "inproxyTlsOSSHPort", nil},
		{45, "localSource", nil},
		{46, "localTimestamp", nil},
		{47, "isLocalDerivedTag", nil},
	}

	for _, spec := range packedServerEntryFieldSpecs {

		if _, ok := packedServerEntryFieldsNameToSpec[spec.name]; ok {
			panic("duplicate field name")
		}
		packedServerEntryFieldsNameToSpec[spec.name] = spec

		if _, ok := packedServerEntryFieldsKeyToSpec[spec.key]; ok {
			panic("duplicate field key")
		}
		packedServerEntryFieldsKeyToSpec[spec.key] = spec
	}

}
