/*
 * Copyright (c) 2016, Psiphon Inc.
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

package server

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/fragmentor"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/inproxy"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tactics"
	"github.com/fxamacker/cbor/v2"
)

const (
	MAX_API_PARAMS_SIZE = 256 * 1024 // 256KB
	PADDING_MAX_BYTES   = 16 * 1024

	CLIENT_PLATFORM_ANDROID = "Android"
	CLIENT_PLATFORM_WINDOWS = "Windows"
	CLIENT_PLATFORM_IOS     = "iOS"
)

// sshAPIRequestHandler routes Psiphon API requests transported as
// JSON objects via the SSH request mechanism.
//
// The API request parameters and event log values follow the legacy
// psi_web protocol and naming conventions. The API is compatible with
// all tunnel-core clients but are not backwards compatible with all
// legacy clients.
func sshAPIRequestHandler(
	support *SupportServices,
	sshClient *sshClient,
	name string,
	requestPayload []byte) ([]byte, error) {

	// Notes:
	//
	// - For SSH requests, MAX_API_PARAMS_SIZE is implicitly enforced
	//   by max SSH request packet size.
	//
	// - The param protocol.PSIPHON_API_HANDSHAKE_AUTHORIZATIONS is an
	//   array of base64-encoded strings; the base64 representation should
	//   not be decoded to []byte values. The default behavior of
	//   https://golang.org/pkg/encoding/json/#Unmarshal for a target of
	//   type map[string]interface{} will unmarshal a base64-encoded string
	//   to a string, not a decoded []byte, as required.

	var params common.APIParameters

	// The request payload is either packed CBOR or legacy JSON.

	params, isPacked, err := protocol.GetPackedAPIParametersRequestPayload(requestPayload)
	if err != nil {
		return nil, errors.Tracef(
			"invalid packed payload for request name: %s: %s", name, err)
	}

	if !isPacked {
		err := json.Unmarshal(requestPayload, &params)
		if err != nil {
			return nil, errors.Tracef(
				"invalid payload for request name: %s: %s", name, err)
		}
	}

	// Before invoking the handlers, enforce some preconditions:
	//
	// - A handshake request must precede any other requests.
	// - When the handshake results in a traffic rules state where
	//   the client is immediately exhausted, no requests
	//   may succeed. This case ensures that blocked clients do
	//   not log "connected", etc.
	//
	// Only one handshake request may be made. There is no check here
	// to enforce that handshakeAPIRequestHandler will be called at
	// most once. The SetHandshakeState call in handshakeAPIRequestHandler
	// enforces that only a single handshake is made; enforcing that there
	// ensures no race condition even if concurrent requests are
	// in flight.

	if name != protocol.PSIPHON_API_HANDSHAKE_REQUEST_NAME {

		completed, exhausted := sshClient.getHandshaked()
		if !completed {
			return nil, errors.TraceNew("handshake not completed")
		}
		if exhausted {
			return nil, errors.TraceNew("exhausted after handshake")
		}
	}

	switch name {

	case protocol.PSIPHON_API_HANDSHAKE_REQUEST_NAME:
		responsePayload, err := handshakeAPIRequestHandler(
			support, protocol.PSIPHON_API_PROTOCOL_SSH, sshClient, params)
		if err != nil {
			// Handshake failed, disconnect the client.
			sshClient.stop()
			return nil, errors.Trace(err)
		}
		return responsePayload, nil

	case protocol.PSIPHON_API_CONNECTED_REQUEST_NAME:
		return connectedAPIRequestHandler(
			support, sshClient, params)

	case protocol.PSIPHON_API_STATUS_REQUEST_NAME:
		return statusAPIRequestHandler(
			support, sshClient, params)

	case protocol.PSIPHON_API_CLIENT_VERIFICATION_REQUEST_NAME:
		return clientVerificationAPIRequestHandler(
			support, sshClient, params)
	}

	return nil, errors.Tracef("invalid request name: %s", name)
}

var handshakeRequestParams = append(
	append(
		[]requestParamSpec{
			{"missing_server_entry_signature", isBase64String, requestParamOptional},
			{"missing_server_entry_provider_id", isBase64String, requestParamOptional},
		},
		baseAndDialParams...),
	tacticsParams...)

// handshakeAPIRequestHandler implements the "handshake" API request.
// Clients make the handshake immediately after establishing a tunnel
// connection; the response tells the client what homepage to open, what
// stats to record, etc.
func handshakeAPIRequestHandler(
	support *SupportServices,
	apiProtocol string,
	sshClient *sshClient,
	params common.APIParameters) ([]byte, error) {

	var clientGeoIPData GeoIPData

	var inproxyClientIP string
	var inproxyProxyID inproxy.ID
	var inproxyMatchedPersonalCompartments bool
	var inproxyClientGeoIPData GeoIPData
	var inproxyRelayLogFields common.LogFields

	if sshClient.isInproxyTunnelProtocol {

		inproxyConnectionID, err := getStringRequestParam(params, "inproxy_connection_id")

		if err != nil {
			return nil, errors.Trace(err)
		}

		// Complete the in-proxy broker/server relay before the rest of
		// handshake in order to obtain the original client IP and other
		// inputs sent from the broker.
		//
		// In the best and typical case, the broker has already established a
		// secure session with this server and the inproxy_relay_packet is
		// the broker report application-level payload. Otherwise, if there
		// is no session or the session has expired, session handshake
		// messages will be relayed to the broker via the client, using SSH
		// requests to the client. These requests/responses happen while the
		// handshake response remains outstanding, as this handler needs the
		// original client IP and its geolocation data in order to determine
		// the correct landing pages, traffic rules, tactics, etc.
		//
		// The client should extends its handshake timeout to accommodate
		// potential relay round trips.

		inproxyRelayPacketStr, err := getStringRequestParam(params, "inproxy_relay_packet")
		if err != nil {
			return nil, errors.Trace(err)
		}

		inproxyRelayPacket, err := base64.RawStdEncoding.DecodeString(inproxyRelayPacketStr)
		if err != nil {
			return nil, errors.Trace(err)
		}

		inproxyClientIP,
			inproxyProxyID,
			inproxyMatchedPersonalCompartments,
			inproxyRelayLogFields,
			err =
			doHandshakeInproxyBrokerRelay(
				sshClient,
				inproxyConnectionID,
				inproxyRelayPacket)
		if err != nil {
			return nil, errors.Trace(err)
		}

		inproxyClientGeoIPData = support.GeoIPService.Lookup(inproxyClientIP)
		clientGeoIPData = inproxyClientGeoIPData

	} else {

		clientGeoIPData = sshClient.getClientGeoIPData()
	}

	// Check input parameters

	// Note: ignoring legacy "known_servers" params

	err := validateRequestParams(support.Config, params, handshakeRequestParams)
	if err != nil {
		return nil, errors.Trace(err)
	}

	sponsorID, _ := getStringRequestParam(params, "sponsor_id")
	clientVersion, _ := getStringRequestParam(params, "client_version")
	clientPlatform, _ := getStringRequestParam(params, "client_platform")
	isMobile := isMobileClientPlatform(clientPlatform)
	normalizedPlatform := normalizeClientPlatform(clientPlatform)

	// establishedTunnelsCount is used in traffic rule selection. When omitted by
	// the client, a value of 0 will be used.
	establishedTunnelsCount, _ := getIntStringRequestParam(params, "established_tunnels_count")

	var authorizations []string
	if params[protocol.PSIPHON_API_HANDSHAKE_AUTHORIZATIONS] != nil {
		authorizations, err = getStringArrayRequestParam(params, protocol.PSIPHON_API_HANDSHAKE_AUTHORIZATIONS)
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	deviceRegion, ok := getOptionalStringRequestParam(params, "device_region")
	if !ok {
		deviceRegion = GEOIP_UNKNOWN_VALUE
	}

	// splitTunnelOwnRegion indicates if the client is requesting split tunnel
	// mode to be applied to the client's own country. When omitted by the
	// client, the value will be false.
	//
	// When split_tunnel_regions is non-empty, split tunnel mode will be
	// applied for the specified country codes. When omitted by the client,
	// the value will be an empty slice.
	splitTunnelOwnRegion, _ := getBoolStringRequestParam(params, "split_tunnel")
	splitTunnelOtherRegions, _ := getStringArrayRequestParam(params, "split_tunnel_regions")

	ownRegion := ""
	if splitTunnelOwnRegion {
		ownRegion = clientGeoIPData.Country
	}
	var splitTunnelLookup *splitTunnelLookup
	if ownRegion != "" || len(splitTunnelOtherRegions) > 0 {
		splitTunnelLookup, err = newSplitTunnelLookup(ownRegion, splitTunnelOtherRegions)
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	// Note: no guarantee that PsinetDatabase won't reload between database calls
	db := support.PsinetDatabase

	httpsRequestRegexes, domainBytesChecksum := db.GetHttpsRequestRegexes(sponsorID)

	tacticsPayload, err := support.TacticsServer.GetTacticsPayload(
		common.GeoIPData(clientGeoIPData), params)
	if err != nil {
		return nil, errors.Trace(err)
	}

	var newTacticsTag string
	if tacticsPayload != nil && len(tacticsPayload.Tactics) > 0 {
		newTacticsTag = tacticsPayload.Tag
	}

	// Flag the SSH client as having completed its handshake. This
	// may reselect traffic rules and starts allowing port forwards.

	apiParams := copyBaseAndDialParams(params)

	handshakeStateInfo, err := sshClient.setHandshakeState(
		handshakeState{
			completed:               true,
			apiProtocol:             apiProtocol,
			apiParams:               apiParams,
			domainBytesChecksum:     domainBytesChecksum,
			establishedTunnelsCount: establishedTunnelsCount,
			splitTunnelLookup:       splitTunnelLookup,
			deviceRegion:            deviceRegion,
			newTacticsTag:           newTacticsTag,
			inproxyClientIP:         inproxyClientIP,
			inproxyClientGeoIPData:  inproxyClientGeoIPData,
			inproxyProxyID:          inproxyProxyID,
			inproxyMatchedPersonal:  inproxyMatchedPersonalCompartments,
			inproxyRelayLogFields:   inproxyRelayLogFields,
		},
		authorizations)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// The log comes _after_ SetClientHandshakeState, in case that call rejects
	// the state change (for example, if a second handshake is performed)
	//
	// The handshake event is no longer shipped to log consumers, so this is
	// simply a diagnostic log. Since the "server_tunnel" event includes all
	// common API parameters and "handshake_completed" flag, this handshake
	// log is mostly redundant and set to debug level.

	if IsLogLevelDebug() {
		logFields := getRequestLogFields(
			"",
			"",
			sshClient.sessionID,
			clientGeoIPData,
			handshakeStateInfo.authorizedAccessTypes,
			params,
			handshakeRequestParams)
		log.WithTraceFields(logFields).Debug("handshake")
	}

	pad_response, _ := getPaddingSizeRequestParam(params, "pad_response")

	// Discover new servers

	var encodedServerList []string
	if !sshClient.getDisableDiscovery() {

		clientIP := ""
		if sshClient.isInproxyTunnelProtocol {
			clientIP = inproxyClientIP
		} else if sshClient.peerAddr != nil {
			clientIP, _, _ = net.SplitHostPort(sshClient.peerAddr.String())

		}

		IP := net.ParseIP(clientIP)
		if IP == nil {
			return nil, errors.TraceNew("invalid client IP")
		}

		encodedServerList = support.discovery.DiscoverServers(IP)
	}

	// When the client indicates that it used an out-of-date server entry for
	// this connection, return a signed copy of the server entry for the client
	// to upgrade to. Out-of-date server entries are either unsigned or missing
	// a provider ID. See also: comment in psiphon.doHandshakeRequest.
	//
	// The missing_server_entry_signature parameter value is a server entry tag,
	// which is used to select the correct server entry for servers with multiple
	// entries. Identifying the server entries tags instead of server IPs prevents
	// an enumeration attack, where a malicious client can abuse this facilty to
	// check if an arbitrary IP address is a Psiphon server.
	//
	// The missing_server_entry_provider_id parameter value is a server entry
	// tag.
	serverEntryTag, ok := getOptionalStringRequestParam(
		params, "missing_server_entry_signature")
	if !ok {
		// Do not need to check this case if we'll already return the server
		// entry due to a missing signature.
		serverEntryTag, ok = getOptionalStringRequestParam(
			params, "missing_server_entry_provider_id")
	}
	if ok {
		ownServerEntry, ok := support.Config.GetOwnEncodedServerEntry(serverEntryTag)
		if ok {
			encodedServerList = append(encodedServerList, ownServerEntry)
		}
	}

	// PageViewRegexes is obsolete and not used by any tunnel-core clients. In
	// the JSON response, return an empty array instead of null for legacy
	// clients.

	homepages := db.GetRandomizedHomepages(
		sponsorID,
		clientGeoIPData.Country,
		clientGeoIPData.ASN,
		deviceRegion,
		isMobile)

	clientAddress := ""
	if sshClient.isInproxyTunnelProtocol {

		// ClientAddress not supported for in-proxy tunnel protocols:
		//
		// - We don't want to return the address of the direct peer, the
		//   in-proxy proxy;
		// - The known  port number will correspond to the in-proxy proxy
		//   source address, not the client;
		// - While we assume that the the original client IP from the broker
		//   is representative for geolocation, an actual direct connection
		//   to the Psiphon server from the client may route differently and
		//   use a different IP address.

		clientAddress = ""
	} else if sshClient.peerAddr != nil {
		clientAddress = sshClient.peerAddr.String()
	}

	var marshaledTacticsPayload []byte
	if tacticsPayload != nil {
		marshaledTacticsPayload, err = json.Marshal(tacticsPayload)
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	handshakeResponse := protocol.HandshakeResponse{
		Homepages:                homepages,
		UpgradeClientVersion:     db.GetUpgradeClientVersion(clientVersion, normalizedPlatform),
		PageViewRegexes:          make([]map[string]string, 0),
		HttpsRequestRegexes:      httpsRequestRegexes,
		EncodedServerList:        encodedServerList,
		ClientRegion:             clientGeoIPData.Country,
		ClientAddress:            clientAddress,
		ServerTimestamp:          common.GetCurrentTimestamp(),
		ActiveAuthorizationIDs:   handshakeStateInfo.activeAuthorizationIDs,
		TacticsPayload:           marshaledTacticsPayload,
		UpstreamBytesPerSecond:   handshakeStateInfo.upstreamBytesPerSecond,
		DownstreamBytesPerSecond: handshakeStateInfo.downstreamBytesPerSecond,
		SteeringIP:               handshakeStateInfo.steeringIP,
		Padding:                  strings.Repeat(" ", pad_response),
	}

	// TODO: as a future enhancement, pack and CBOR encode this and other API
	// responses

	responsePayload, err := json.Marshal(handshakeResponse)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return responsePayload, nil
}

func doHandshakeInproxyBrokerRelay(
	sshClient *sshClient,
	clientConnectionID string,
	initialRelayPacket []byte) (string, inproxy.ID, bool, common.LogFields, error) {

	connectionID, err := inproxy.IDFromString(clientConnectionID)
	if err != nil {
		return "", inproxy.ID{}, false, nil, errors.Trace(err)
	}

	clientIP := ""
	var proxyID inproxy.ID
	var matchedPersonalCompartments bool
	var logFields common.LogFields

	// This first packet from broker arrives via the client handshake. If
	// there is an established, non-expired session, this packet will contain
	// the application-level broker report and the relay will complete
	// immediately.

	relayPacket := initialRelayPacket

	for i := 0; i < inproxy.MaxRelayRoundTrips; i++ {

		// broker -> server

		relayPacket, err = sshClient.sshServer.inproxyBrokerSessions.HandlePacket(
			CommonLogger(log),
			relayPacket,
			connectionID,
			func(
				brokerVerifiedOriginalClientIP string,
				brokerReportedProxyID inproxy.ID,
				brokerMatchedPersonalCompartments bool,
				fields common.LogFields) {

				// Once the broker report is received, this callback is invoked.
				clientIP = brokerVerifiedOriginalClientIP
				proxyID = brokerReportedProxyID
				matchedPersonalCompartments = brokerMatchedPersonalCompartments
				logFields = fields
			})
		if err != nil {
			if relayPacket == nil {

				// If there is an error and no relay packet, the packet is
				// invalid. Drop the packet and return an error. Do _not_
				// reset the session, otherwise a malicious client could
				// interrupt a valid broker/server session with a malformed packet.
				return "", inproxy.ID{}, false, nil, errors.Trace(err)
			}

			// In the case of expired sessions, a reset session token is sent
			// to the broker, so this is not a failure condition; the error
			// is for logging only. Continue to ship relayPacket.

			log.WithTraceFields(LogFields{"error": err}).Warning(
				"HandlePacket returned packet and error")
		}

		if relayPacket == nil {

			// The relay is complete; the handler recording the clientIP and
			// logFields was invoked.
			return clientIP, proxyID, matchedPersonalCompartments, logFields, nil
		}

		// server -> broker

		// Send an SSH request back to client with next packet for broker;
		// then the client relays that to the broker and returns the broker's
		// next response in the SSH response.

		request := protocol.InproxyRelayRequest{
			Packet: relayPacket,
		}
		requestPayload, err := protocol.CBOREncoding.Marshal(request)
		if err != nil {
			return "", inproxy.ID{}, false, nil, errors.Trace(err)
		}

		ok, responsePayload, err := sshClient.sshConn.SendRequest(
			protocol.PSIPHON_API_INPROXY_RELAY_REQUEST_NAME,
			true,
			requestPayload)
		if err != nil {
			return "", inproxy.ID{}, false, nil, errors.Trace(err)
		}
		if !ok {
			return "", inproxy.ID{}, false, nil, errors.TraceNew("client rejected request")
		}

		var response protocol.InproxyRelayResponse
		err = cbor.Unmarshal(responsePayload, &response)
		if err != nil {
			return "", inproxy.ID{}, false, nil, errors.Trace(err)
		}

		relayPacket = response.Packet
	}

	return "", inproxy.ID{}, false, nil, errors.Tracef(
		"exceeded %d relay round trips", inproxy.MaxRelayRoundTrips)
}

// uniqueUserParams are the connected request parameters which are logged for
// unique_user events.
var uniqueUserParams = append(
	[]requestParamSpec{
		{"last_connected", isLastConnected, 0}},
	baseParams...)

var connectedRequestParams = append(
	[]requestParamSpec{
		{"establishment_duration", isIntString, requestParamOptional | requestParamLogStringAsInt}},
	uniqueUserParams...)

// updateOnConnectedParamNames are connected request parameters which are
// copied to update data logged with server_tunnel: these fields either only
// ship with or ship newer data with connected requests.
var updateOnConnectedParamNames = append(
	[]string{
		"last_connected",
		"establishment_duration",
	},
	fragmentor.GetUpstreamMetricsNames()...)

// connectedAPIRequestHandler implements the "connected" API request. Clients
// make the connected request once a tunnel connection has been established
// and at least once per 24h for long-running tunnels. The last_connected
// input value, which should be a connected_timestamp output from a previous
// connected response, is used to calculate unique user stats.
// connected_timestamp is truncated as a privacy measure.
func connectedAPIRequestHandler(
	support *SupportServices,
	sshClient *sshClient,
	params common.APIParameters) ([]byte, error) {

	err := validateRequestParams(support.Config, params, connectedRequestParams)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// Note: unlock before use is only safe as long as referenced sshClient data,
	// such as slices in handshakeState, is read-only after initially set.

	sshClient.Lock()
	authorizedAccessTypes := sshClient.handshakeState.authorizedAccessTypes
	sshClient.Unlock()

	lastConnected, _ := getStringRequestParam(params, "last_connected")

	// Update, for server_tunnel logging, upstream fragmentor metrics, as the
	// client may have performed more upstream fragmentation since the previous
	// metrics reported by the handshake request. Also, additional fields that
	// are reported only in the connected request are added to server_tunnel
	// here.

	sshClient.updateAPIParameters(copyUpdateOnConnectedParams(params))

	connectedTimestamp := common.TruncateTimestampToHour(common.GetCurrentTimestamp())

	// The finest required granularity for unique users is daily. To save space,
	// only record a "unique_user" log event when the client's last_connected is
	// in the previous day relative to the new connected_timestamp.

	logUniqueUser := false
	if lastConnected == "None" {
		logUniqueUser = true
	} else {

		t1, _ := time.Parse(time.RFC3339, lastConnected)
		year, month, day := t1.Date()
		d1 := time.Date(year, month, day, 0, 0, 0, 0, time.UTC)

		t2, _ := time.Parse(time.RFC3339, connectedTimestamp)
		year, month, day = t2.Date()
		d2 := time.Date(year, month, day, 0, 0, 0, 0, time.UTC)

		if t1.Before(t2) && d1 != d2 {
			logUniqueUser = true
		}
	}

	if logUniqueUser {
		log.LogRawFieldsWithTimestamp(
			getRequestLogFields(
				"unique_user",
				"",
				sshClient.sessionID,
				sshClient.getClientGeoIPData(),
				authorizedAccessTypes,
				params,
				uniqueUserParams))
	}

	pad_response, _ := getPaddingSizeRequestParam(params, "pad_response")

	connectedResponse := protocol.ConnectedResponse{
		ConnectedTimestamp: connectedTimestamp,
		Padding:            strings.Repeat(" ", pad_response),
	}

	responsePayload, err := json.Marshal(connectedResponse)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return responsePayload, nil
}

var statusRequestParams = baseParams

var remoteServerListStatParams = append(
	[]requestParamSpec{
		// Legacy clients don't record the session_id with remote_server_list_stats entries.
		{"session_id", isHexDigits, requestParamOptional},
		{"client_download_timestamp", isISO8601Date, 0},
		{"tunneled", isBooleanFlag, requestParamOptional | requestParamLogFlagAsBool},
		{"url", isAnyString, 0},
		{"etag", isAnyString, 0},
		{"bytes", isIntString, requestParamOptional | requestParamLogStringAsInt},
		{"duration", isIntString, requestParamOptional | requestParamLogStringAsInt},
		{"authenticated", isBooleanFlag, requestParamOptional | requestParamLogFlagAsBool},
		{"fronting_provider_id", isAnyString, requestParamOptional},
		{"meek_dial_address", isDialAddress, requestParamOptional},
		{"meek_resolved_ip_address", isIPAddress, requestParamOptional},
		{"meek_sni_server_name", isDomain, requestParamOptional},
		{"meek_host_header", isHostHeader, requestParamOptional},
		{"meek_transformed_host_name", isBooleanFlag, requestParamOptional | requestParamLogFlagAsBool},
		{"user_agent", isAnyString, requestParamOptional},
		{"tls_profile", isAnyString, requestParamOptional},
		{"tls_version", isAnyString, requestParamOptional},
		{"tls_fragmented", isBooleanFlag, requestParamOptional | requestParamLogFlagAsBool},
	},

	baseParams...)

// Backwards compatibility case: legacy clients do not include these fields in
// the remote_server_list_stats entries. Use the values from the outer status
// request as an approximation (these values reflect the client at persistent
// stat shipping time, which may differ from the client at persistent stat
// recording time). Note that all but client_build_rev, device_region, and
// device_location are required fields.
var remoteServerListStatBackwardsCompatibilityParamNames = []string{
	"propagation_channel_id",
	"sponsor_id",
	"client_version",
	"client_platform",
	"client_build_rev",
	"device_region",
	"device_location",
}

var failedTunnelStatParams = append(
	[]requestParamSpec{
		{"server_entry_tag", isAnyString, requestParamOptional},
		{"session_id", isHexDigits, 0},
		{"last_connected", isLastConnected, 0},
		{"client_failed_timestamp", isISO8601Date, 0},
		{"record_probability", isFloatString, requestParamOptional | requestParamLogStringAsFloat},
		{"liveness_test_upstream_bytes", isIntString, requestParamOptional | requestParamLogStringAsInt},
		{"liveness_test_sent_upstream_bytes", isIntString, requestParamOptional | requestParamLogStringAsInt},
		{"liveness_test_downstream_bytes", isIntString, requestParamOptional | requestParamLogStringAsInt},
		{"liveness_test_received_downstream_bytes", isIntString, requestParamOptional | requestParamLogStringAsInt},
		{"bytes_up", isIntString, requestParamOptional | requestParamLogStringAsInt},
		{"bytes_down", isIntString, requestParamOptional | requestParamLogStringAsInt},
		{"tunnel_error", isAnyString, 0}},
	baseAndDialParams...)

// statusAPIRequestHandler implements the "status" API request.
// Clients make periodic status requests which deliver client-side
// recorded data transfer and tunnel duration stats.
// Note from psi_web implementation: no input validation on domains;
// any string is accepted (regex transform may result in arbitrary
// string). Stats processor must handle this input with care.
func statusAPIRequestHandler(
	support *SupportServices,
	sshClient *sshClient,
	params common.APIParameters) ([]byte, error) {

	err := validateRequestParams(support.Config, params, statusRequestParams)
	if err != nil {
		return nil, errors.Trace(err)
	}

	sshClient.Lock()
	authorizedAccessTypes := sshClient.handshakeState.authorizedAccessTypes
	sshClient.Unlock()

	statusData, err := getJSONObjectRequestParam(params, "statusData")
	if err != nil {
		return nil, errors.Trace(err)
	}

	// Logs are queued until the input is fully validated. Otherwise, stats
	// could be double counted if the client has a bug in its request
	// formatting: partial stats would be logged (counted), the request would
	// fail, and clients would then resend all the same stats again.

	logQueue := make([]LogFields, 0)

	// Domain bytes transferred stats
	// Older clients may not submit this data

	// Clients are expected to send host_bytes/domain_bytes stats only when
	// configured to do so in the handshake reponse. Legacy clients may still
	// report "(OTHER)" host_bytes when no regexes are set. Drop those stats.

	if sshClient.acceptDomainBytes() && statusData["host_bytes"] != nil {

		hostBytes, err := getMapStringInt64RequestParam(statusData, "host_bytes")
		if err != nil {
			return nil, errors.Trace(err)
		}
		for domain, bytes := range hostBytes {

			domainBytesFields := getRequestLogFields(
				"domain_bytes",
				"",
				sshClient.sessionID,
				sshClient.getClientGeoIPData(),
				authorizedAccessTypes,
				params,
				statusRequestParams)

			domainBytesFields["domain"] = domain
			domainBytesFields["bytes"] = bytes

			logQueue = append(logQueue, domainBytesFields)
		}
	}

	// Limitation: for "persistent" stats, host_id and geolocation is time-of-sending
	// not time-of-recording.

	// Remote server list download persistent stats.
	// Older clients may not submit this data.

	if statusData["remote_server_list_stats"] != nil {

		remoteServerListStats, err := getJSONObjectArrayRequestParam(statusData, "remote_server_list_stats")
		if err != nil {
			return nil, errors.Trace(err)
		}

		for _, remoteServerListStat := range remoteServerListStats {

			for _, name := range remoteServerListStatBackwardsCompatibilityParamNames {
				if _, ok := remoteServerListStat[name]; !ok {
					if field, ok := params[name]; ok {
						remoteServerListStat[name] = field
					}
				}
			}

			err := validateRequestParams(support.Config, remoteServerListStat, remoteServerListStatParams)
			if err != nil {
				// Occasionally, clients may send corrupt persistent stat data. Do not
				// fail the status request, as this will lead to endless retries.
				log.WithTraceFields(LogFields{"error": err}).Warning("remote_server_list_stats entry dropped")
				continue
			}

			remoteServerListFields := getRequestLogFields(
				"remote_server_list",
				"",
				"", // Use the session_id the client recorded with the event
				sshClient.getClientGeoIPData(),
				authorizedAccessTypes,
				remoteServerListStat,
				remoteServerListStatParams)

			logQueue = append(logQueue, remoteServerListFields)
		}
	}

	// Failed tunnel persistent stats.
	// Older clients may not submit this data.

	// Note: no guarantee that PsinetDatabase won't reload between database calls
	db := support.PsinetDatabase

	invalidServerEntryTags := make(map[string]bool)

	if statusData["failed_tunnel_stats"] != nil {

		failedTunnelStats, err := getJSONObjectArrayRequestParam(statusData, "failed_tunnel_stats")
		if err != nil {
			return nil, errors.Trace(err)
		}

		for _, failedTunnelStat := range failedTunnelStats {

			err := validateRequestParams(support.Config, failedTunnelStat, failedTunnelStatParams)
			if err != nil {
				// Occasionally, clients may send corrupt persistent stat data. Do not
				// fail the status request, as this will lead to endless retries.
				//
				// TODO: trigger pruning if the data corruption indicates corrupt server
				// entry storage?
				log.WithTraceFields(LogFields{"error": err}).Warning("failed_tunnel_stats entry dropped")
				continue
			}

			failedTunnelFields := getRequestLogFields(
				"failed_tunnel",
				"",
				"", // Use the session_id the client recorded with the event
				sshClient.getClientGeoIPData(),
				authorizedAccessTypes,
				failedTunnelStat,
				failedTunnelStatParams)

			// Return a list of servers, identified by server entry tag, that are
			// invalid and presumed to be deleted. This information is used by clients
			// to prune deleted servers from their local datastores and stop attempting
			// connections to servers that no longer exist.
			//
			// This mechanism uses tags instead of server IPs: (a) to prevent an
			// enumeration attack, where a malicious client can query the entire IPv4
			// range and build a map of the Psiphon network; (b) to deal with recyling
			// cases where a server deleted and its IP is reused for a new server with
			// a distinct server entry.
			//
			// IsValidServerEntryTag ensures that the local copy of psinet is not stale
			// before returning a negative result, to mitigate accidental pruning.
			//
			// In addition, when the reported dial port number is 0, flag the server
			// entry as invalid to trigger client pruning. This covers a class of
			// invalid/semi-functional server entries, found in practice to be stored
			// by clients, where some protocol port number has been omitted -- due to
			// historical bugs in various server entry handling implementations. When
			// missing from a server entry loaded by a client, the port number
			// evaluates to 0, the zero value, which is not a valid port number even if
			// it were not missing.

			serverEntryTag, ok := getOptionalStringRequestParam(failedTunnelStat, "server_entry_tag")

			if ok {
				serverEntryValid := db.IsValidServerEntryTag(serverEntryTag)

				if serverEntryValid {
					dialPortNumber, err := getIntStringRequestParam(failedTunnelStat, "dial_port_number")
					if err == nil && dialPortNumber == 0 {
						serverEntryValid = false
					}
				}

				if !serverEntryValid {
					invalidServerEntryTags[serverEntryTag] = true
				}

				// Add a field to the failed_tunnel log indicating if the server entry is
				// valid.
				failedTunnelFields["server_entry_valid"] = serverEntryValid
			}

			// Log failed_tunnel.

			logQueue = append(logQueue, failedTunnelFields)
		}
	}

	// Handle the prune check, which is an aggressive server entry prune
	// operation on top of the opportunistic pruning that is triggered by
	// failed_tunnel reports.

	if statusData["check_server_entry_tags"] != nil {

		checkServerEntryTags, err := getStringArrayRequestParam(statusData, "check_server_entry_tags")
		if err != nil {
			return nil, errors.Trace(err)
		}

		invalidCount := 0

		for _, serverEntryTag := range checkServerEntryTags {

			serverEntryValid := db.IsValidServerEntryTag(serverEntryTag)
			if !serverEntryValid {
				invalidServerEntryTags[serverEntryTag] = true
				invalidCount += 1
			}

		}

		// Prune metrics will be logged in server_tunnel.

		sshClient.Lock()
		sshClient.requestCheckServerEntryTags += 1
		sshClient.checkedServerEntryTags += len(checkServerEntryTags)
		sshClient.invalidServerEntryTags += invalidCount
		sshClient.Unlock()
	}

	for _, logItem := range logQueue {
		log.LogRawFieldsWithTimestamp(logItem)
	}

	pad_response, _ := getPaddingSizeRequestParam(params, "pad_response")

	statusResponse := protocol.StatusResponse{
		Padding: strings.Repeat(" ", pad_response),
	}

	if len(invalidServerEntryTags) > 0 {
		statusResponse.InvalidServerEntryTags = make([]string, len(invalidServerEntryTags))
		i := 0
		for tag := range invalidServerEntryTags {
			statusResponse.InvalidServerEntryTags[i] = tag
			i++
		}
	}

	responsePayload, err := json.Marshal(statusResponse)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return responsePayload, nil
}

// clientVerificationAPIRequestHandler is just a compliance stub
// for older Android clients that still send verification requests
func clientVerificationAPIRequestHandler(
	_ *SupportServices,
	_ *sshClient,
	_ common.APIParameters) ([]byte, error) {
	return make([]byte, 0), nil
}

var tacticsParams = []requestParamSpec{
	{tactics.STORED_TACTICS_TAG_PARAMETER_NAME, isAnyString, requestParamOptional},
	{tactics.SPEED_TEST_SAMPLES_PARAMETER_NAME, nil, requestParamOptional | requestParamJSON},
}

var tacticsRequestParams = append(
	append(
		[]requestParamSpec{
			{"session_id", isHexDigits, 0}},
		tacticsParams...),
	baseAndDialParams...)

func getTacticsAPIParameterValidator(config *Config) common.APIParameterValidator {
	return func(params common.APIParameters) error {
		return validateRequestParams(config, params, tacticsRequestParams)
	}
}

func getTacticsAPIParameterLogFieldFormatter() common.APIParameterLogFieldFormatter {

	return func(prefix string, geoIPData common.GeoIPData, params common.APIParameters) common.LogFields {

		logFields := getRequestLogFields(
			tactics.TACTICS_METRIC_EVENT_NAME,
			prefix,
			"", // Use the session_id the client reported
			GeoIPData(geoIPData),
			nil, // authorizedAccessTypes are not known yet
			params,
			tacticsRequestParams)

		return common.LogFields(logFields)
	}
}

var inproxyBrokerRequestParams = append(
	append(
		[]requestParamSpec{
			{"session_id", isHexDigits, 0},
			{"fronting_provider_id", isAnyString, requestParamOptional}},
		tacticsParams...),
	baseParams...)

func getInproxyBrokerAPIParameterValidator(config *Config) common.APIParameterValidator {
	return func(params common.APIParameters) error {
		return validateRequestParams(config, params, inproxyBrokerRequestParams)
	}
}

func getInproxyBrokerAPIParameterLogFieldFormatter() common.APIParameterLogFieldFormatter {

	return func(prefix string, geoIPData common.GeoIPData, params common.APIParameters) common.LogFields {

		logFields := getRequestLogFields(
			"inproxy_broker",
			prefix,
			"", // Use the session_id the client reported
			GeoIPData(geoIPData),
			nil,
			params,
			inproxyBrokerRequestParams)

		return common.LogFields(logFields)
	}
}

func getInproxyBrokerServerReportParameterLogFieldFormatter() common.APIParameterLogFieldFormatter {

	return func(prefix string, _ common.GeoIPData, params common.APIParameters) common.LogFields {

		logFields := getRequestLogFields(
			"",
			prefix,
			"",          // Use the session_id in ProxyMetrics
			GeoIPData{}, // Proxy GeoIP data is added in sshClient.logTunnel
			nil,
			params,
			inproxyBrokerRequestParams)

		return common.LogFields(logFields)
	}
}

// requestParamSpec defines a request parameter. Each param is expected to be
// a string, unless requestParamArray is specified, in which case an array of
// strings is expected.
type requestParamSpec struct {
	name      string
	validator func(*Config, string) bool
	flags     uint32
}

const (
	requestParamOptional                                      = 1
	requestParamNotLogged                                     = 1 << 1
	requestParamArray                                         = 1 << 2
	requestParamJSON                                          = 1 << 3
	requestParamLogStringAsInt                                = 1 << 4
	requestParamLogStringAsFloat                              = 1 << 5
	requestParamLogStringLengthAsInt                          = 1 << 6
	requestParamLogFlagAsBool                                 = 1 << 7
	requestParamLogOnlyForFrontedMeekOrConjure                = 1 << 8
	requestParamNotLoggedForUnfrontedMeekNonTransformedHeader = 1 << 9
)

// baseParams are the basic request parameters that are expected for all API
// requests and log events.
var baseParams = []requestParamSpec{
	{"propagation_channel_id", isHexDigits, 0},
	{"sponsor_id", isHexDigits, 0},
	{"client_version", isIntString, requestParamLogStringAsInt},
	{"client_platform", isClientPlatform, 0},
	{"client_features", isAnyString, requestParamOptional | requestParamArray},
	{"client_build_rev", isHexDigits, requestParamOptional},
	{"device_region", isAnyString, requestParamOptional},
	{"device_location", isGeoHashString, requestParamOptional},
	{"network_type", isAnyString, requestParamOptional},
	{tactics.APPLIED_TACTICS_TAG_PARAMETER_NAME, isAnyString, requestParamOptional},
}

// baseDialParams are the dial parameters, per-tunnel network protocol and
// obfuscation metrics which are logged with server_tunnel, failed_tunnel, and
// tactics.
var baseDialParams = []requestParamSpec{
	{"relay_protocol", isRelayProtocol, 0},
	{"ssh_client_version", isAnyString, requestParamOptional},
	{"upstream_proxy_type", isUpstreamProxyType, requestParamOptional},
	{"upstream_proxy_custom_header_names", isAnyString, requestParamOptional | requestParamArray},
	{"fronting_provider_id", isAnyString, requestParamOptional},
	{"meek_dial_address", isDialAddress, requestParamOptional | requestParamLogOnlyForFrontedMeekOrConjure},
	{"meek_resolved_ip_address", isIPAddress, requestParamOptional | requestParamLogOnlyForFrontedMeekOrConjure},
	{"meek_sni_server_name", isDomain, requestParamOptional},
	{"meek_host_header", isHostHeader, requestParamOptional | requestParamNotLoggedForUnfrontedMeekNonTransformedHeader},
	{"meek_transformed_host_name", isBooleanFlag, requestParamOptional | requestParamLogFlagAsBool},
	{"user_agent", isAnyString, requestParamOptional},
	{"tls_profile", isAnyString, requestParamOptional},
	{"tls_version", isAnyString, requestParamOptional},
	{"server_entry_region", isRegionCode, requestParamOptional},
	{"server_entry_source", isServerEntrySource, requestParamOptional},
	{"server_entry_timestamp", isISO8601Date, requestParamOptional},
	{"dial_port_number", isIntString, requestParamOptional | requestParamLogStringAsInt},
	{"quic_version", isAnyString, requestParamOptional},
	{"quic_dial_sni_address", isAnyString, requestParamOptional},
	{"quic_disable_client_path_mtu_discovery", isBooleanFlag, requestParamOptional | requestParamLogFlagAsBool},
	{"upstream_bytes_fragmented", isIntString, requestParamOptional | requestParamLogStringAsInt},
	{"upstream_min_bytes_written", isIntString, requestParamOptional | requestParamLogStringAsInt},
	{"upstream_max_bytes_written", isIntString, requestParamOptional | requestParamLogStringAsInt},
	{"upstream_min_delayed", isIntString, requestParamOptional | requestParamLogStringAsInt},
	{"upstream_max_delayed", isIntString, requestParamOptional | requestParamLogStringAsInt},
	{"padding", isAnyString, requestParamOptional | requestParamLogStringLengthAsInt},
	{"pad_response", isIntString, requestParamOptional | requestParamLogStringAsInt},
	{"is_replay", isBooleanFlag, requestParamOptional | requestParamLogFlagAsBool},
	{"egress_region", isRegionCode, requestParamOptional},
	{"dial_duration", isIntString, requestParamOptional | requestParamLogStringAsInt},
	{"candidate_number", isIntString, requestParamOptional | requestParamLogStringAsInt},
	{"established_tunnels_count", isIntString, requestParamOptional | requestParamLogStringAsInt},
	{"upstream_ossh_padding", isIntString, requestParamOptional | requestParamLogStringAsInt},
	{"meek_cookie_size", isIntString, requestParamOptional | requestParamLogStringAsInt},
	{"meek_limit_request", isIntString, requestParamOptional | requestParamLogStringAsInt},
	{"meek_redial_probability", isFloatString, requestParamOptional | requestParamLogStringAsFloat},
	{"meek_tls_padding", isIntString, requestParamOptional | requestParamLogStringAsInt},
	{"network_latency_multiplier", isFloatString, requestParamOptional | requestParamLogStringAsFloat},
	{"client_bpf", isAnyString, requestParamOptional},
	{"conjure_cached", isBooleanFlag, requestParamOptional | requestParamLogFlagAsBool},
	{"conjure_delay", isIntString, requestParamOptional | requestParamLogStringAsInt},
	{"conjure_transport", isAnyString, requestParamOptional},
	{"conjure_prefix", isAnyString, requestParamOptional},
	{"conjure_stun", isAnyString, requestParamOptional},
	{"conjure_empty_packet", isBooleanFlag, requestParamOptional | requestParamLogFlagAsBool},
	{"conjure_network", isAnyString, requestParamOptional},
	{"conjure_port_number", isAnyString, requestParamOptional},
	{"split_tunnel", isBooleanFlag, requestParamOptional | requestParamLogFlagAsBool},
	{"split_tunnel_regions", isRegionCode, requestParamOptional | requestParamArray},
	{"dns_preresolved", isAnyString, requestParamOptional},
	{"dns_preferred", isAnyString, requestParamOptional},
	{"dns_transform", isAnyString, requestParamOptional},
	{"dns_qname_random_casing", isBooleanFlag, requestParamOptional | requestParamLogFlagAsBool},
	{"dns_qname_must_match", isBooleanFlag, requestParamOptional | requestParamLogFlagAsBool},
	{"dns_qname_mismatches", isIntString, requestParamOptional | requestParamLogStringAsInt},
	{"dns_attempt", isIntString, requestParamOptional | requestParamLogStringAsInt},
	{"http_transform", isAnyString, requestParamOptional},
	{"seed_transform", isAnyString, requestParamOptional},
	{"ossh_prefix", isAnyString, requestParamOptional},
	{"shadowsocks_prefix", isAnyString, requestParamOptional},
	{"tls_fragmented", isBooleanFlag, requestParamOptional | requestParamLogFlagAsBool},
	{"tls_padding", isIntString, requestParamOptional | requestParamLogStringAsInt},
	{"tls_ossh_sni_server_name", isDomain, requestParamOptional},
	{"tls_ossh_transformed_host_name", isBooleanFlag, requestParamOptional | requestParamLogFlagAsBool},
	{"steering_ip", isIPAddress, requestParamOptional | requestParamLogOnlyForFrontedMeekOrConjure},
	{"tls_sent_ticket", isBooleanFlag, requestParamOptional | requestParamLogFlagAsBool},
	{"tls_did_resume", isBooleanFlag, requestParamOptional | requestParamLogFlagAsBool},
	{"quic_sent_ticket", isBooleanFlag, requestParamOptional | requestParamLogFlagAsBool},
	{"quic_did_resume", isBooleanFlag, requestParamOptional | requestParamLogFlagAsBool},
	{"quic_dial_early", isBooleanFlag, requestParamOptional | requestParamLogFlagAsBool},
	{"quic_obfuscated_psk", isBooleanFlag, requestParamOptional | requestParamLogFlagAsBool},
}

var inproxyDialParams = []requestParamSpec{

	// Both the client and broker send inproxy_connection_id, and the values
	// must be the same. The broker's value is logged, so the client's value
	// is configured here as requestParamNotLogged.
	{"inproxy_connection_id", isUnpaddedBase64String, requestParamOptional | requestParamNotLogged},
	{"inproxy_relay_packet", isUnpaddedBase64String, requestParamOptional | requestParamNotLogged},
	{"inproxy_broker_is_replay", isBooleanFlag, requestParamOptional | requestParamLogFlagAsBool},
	{"inproxy_broker_transport", isAnyString, requestParamOptional},
	{"inproxy_broker_fronting_provider_id", isAnyString, requestParamOptional},
	{"inproxy_broker_dial_address", isAnyString, requestParamOptional},
	{"inproxy_broker_resolved_ip_address", isAnyString, requestParamOptional},
	{"inproxy_broker_sni_server_name", isAnyString, requestParamOptional},
	{"inproxy_broker_host_header", isAnyString, requestParamOptional},
	{"inproxy_broker_transformed_host_name", isBooleanFlag, requestParamOptional | requestParamLogFlagAsBool},
	{"inproxy_broker_user_agent", isAnyString, requestParamOptional},
	{"inproxy_broker_tls_profile", isAnyString, requestParamOptional},
	{"inproxy_broker_tls_version", isAnyString, requestParamOptional},
	{"inproxy_broker_tls_fragmented", isBooleanFlag, requestParamOptional | requestParamLogFlagAsBool},
	{"inproxy_broker_client_bpf", isAnyString, requestParamOptional},
	{"inproxy_broker_upstream_bytes_fragmented", isIntString, requestParamOptional | requestParamLogStringAsInt},
	{"inproxy_broker_http_transform", isAnyString, requestParamOptional},
	{"inproxy_broker_dns_preresolved", isAnyString, requestParamOptional},
	{"inproxy_broker_dns_preferred", isAnyString, requestParamOptional},
	{"inproxy_broker_dns_transform", isAnyString, requestParamOptional},
	{"inproxy_broker_dns_qname_random_casing", isBooleanFlag, requestParamOptional | requestParamLogFlagAsBool},
	{"inproxy_broker_dns_qname_must_match", isBooleanFlag, requestParamOptional | requestParamLogFlagAsBool},
	{"inproxy_broker_dns_qname_mismatches", isIntString, requestParamOptional | requestParamLogStringAsInt},
	{"inproxy_broker_dns_attempt", isIntString, requestParamOptional | requestParamLogStringAsInt},
	{"inproxy_webrtc_dns_preresolved", isAnyString, requestParamOptional},
	{"inproxy_webrtc_dns_preferred", isAnyString, requestParamOptional},
	{"inproxy_webrtc_dns_transform", isAnyString, requestParamOptional},
	{"inproxy_broker_dns_qname_random_casing", isBooleanFlag, requestParamOptional | requestParamLogFlagAsBool},
	{"inproxy_webrtc_dns_qname_must_match", isBooleanFlag, requestParamOptional | requestParamLogFlagAsBool},
	{"inproxy_webrtc_dns_qname_mismatches", isIntString, requestParamOptional | requestParamLogStringAsInt},
	{"inproxy_webrtc_dns_attempt", isIntString, requestParamOptional | requestParamLogStringAsInt},
	{"inproxy_webrtc_stun_server", isAnyString, requestParamOptional},
	{"inproxy_webrtc_stun_server_resolved_ip_address", isAnyString, requestParamOptional},
	{"inproxy_webrtc_stun_server_RFC5780", isAnyString, requestParamOptional},
	{"inproxy_webrtc_stun_server_RFC5780_resolved_ip_address", isAnyString, requestParamOptional},
	{"inproxy_webrtc_randomize_dtls", isBooleanFlag, requestParamOptional | requestParamLogFlagAsBool},
	{"inproxy_webrtc_padded_messages_sent", isIntString, requestParamOptional | requestParamLogStringAsInt},
	{"inproxy_webrtc_padded_messages_received", isIntString, requestParamOptional | requestParamLogStringAsInt},
	{"inproxy_webrtc_decoy_messages_sent", isIntString, requestParamOptional | requestParamLogStringAsInt},
	{"inproxy_webrtc_decoy_messages_received", isIntString, requestParamOptional | requestParamLogStringAsInt},
	{"inproxy_webrtc_local_ice_candidate_type", isAnyString, requestParamOptional},
	{"inproxy_webrtc_local_ice_candidate_is_initiator", isBooleanFlag, requestParamOptional | requestParamLogFlagAsBool},
	{"inproxy_webrtc_local_ice_candidate_is_IPv6", isBooleanFlag, requestParamOptional | requestParamLogFlagAsBool},
	{"inproxy_webrtc_local_ice_candidate_port", isIntString, requestParamOptional | requestParamLogStringAsInt},
	{"inproxy_webrtc_remote_ice_candidate_type", isAnyString, requestParamOptional},
	{"inproxy_webrtc_remote_ice_candidate_is_IPv6", isBooleanFlag, requestParamOptional | requestParamLogFlagAsBool},
	{"inproxy_webrtc_remote_ice_candidate_port", isIntString, requestParamOptional | requestParamLogStringAsInt},
	{"inproxy_dial_nat_discovery_duration", isIntString, requestParamOptional | requestParamLogStringAsInt},
	{"inproxy_dial_failed_attempts_duration", isIntString, requestParamOptional | requestParamLogStringAsInt},
	{"inproxy_dial_webrtc_ice_gathering_duration", isIntString, requestParamOptional | requestParamLogStringAsInt},
	{"inproxy_dial_broker_offer_duration", isIntString, requestParamOptional | requestParamLogStringAsInt},
	{"inproxy_dial_webrtc_connection_duration", isIntString, requestParamOptional | requestParamLogStringAsInt},
	{"inproxy_broker_is_reuse", isBooleanFlag, requestParamOptional | requestParamLogFlagAsBool},
	{"inproxy_webrtc_use_media_streams", isBooleanFlag, requestParamOptional | requestParamLogFlagAsBool},
}

// baseAndDialParams adds baseDialParams and inproxyDialParams to baseParams.
var baseAndDialParams = append(
	append(
		append(
			[]requestParamSpec{},
			baseParams...),
		baseDialParams...),
	inproxyDialParams...)

func validateRequestParams(
	config *Config,
	params common.APIParameters,
	expectedParams []requestParamSpec) error {

	for _, expectedParam := range expectedParams {
		value := params[expectedParam.name]
		if value == nil {
			if expectedParam.flags&requestParamOptional != 0 {
				continue
			}
			return errors.Tracef("missing param: %s", expectedParam.name)
		}
		var err error
		switch {
		case expectedParam.flags&requestParamArray != 0:
			err = validateStringArrayRequestParam(config, expectedParam, value)
		case expectedParam.flags&requestParamJSON != 0:
			// No validation: the JSON already unmarshalled; the parameter
			// user will validate that the JSON contains the expected
			// objects/data.

			// TODO: without validation, any valid JSON will be logged
			// by getRequestLogFields, even if the parameter user validates
			// and rejects the parameter.

		default:
			err = validateStringRequestParam(config, expectedParam, value)
		}
		if err != nil {
			return errors.Trace(err)
		}
	}

	return nil
}

// copyBaseAndDialParams makes a copy of the params which includes only
// the baseAndDialParams.
func copyBaseAndDialParams(params common.APIParameters) common.APIParameters {

	// Note: not a deep copy; assumes baseSessionAndDialParams values are all
	// scalar types (int, string, etc.)
	paramsCopy := make(common.APIParameters)
	for _, baseParam := range baseAndDialParams {
		value := params[baseParam.name]
		if value == nil {
			continue
		}
		paramsCopy[baseParam.name] = value
	}
	return paramsCopy
}

func copyUpdateOnConnectedParams(params common.APIParameters) common.APIParameters {

	// Note: not a deep copy
	paramsCopy := make(common.APIParameters)
	for _, name := range updateOnConnectedParamNames {
		value := params[name]
		if value == nil {
			continue
		}
		paramsCopy[name] = value
	}
	return paramsCopy
}

func validateStringRequestParam(
	config *Config,
	expectedParam requestParamSpec,
	value interface{}) error {

	strValue, ok := value.(string)
	if !ok {
		return errors.Tracef("unexpected string param type: %s", expectedParam.name)
	}
	if !expectedParam.validator(config, strValue) {
		return errors.Tracef("invalid param: %s: %s", expectedParam.name, strValue)
	}
	return nil
}

func validateStringArrayRequestParam(
	config *Config,
	expectedParam requestParamSpec,
	value interface{}) error {

	arrayValue, ok := value.([]interface{})
	if !ok {
		return errors.Tracef("unexpected array param type: %s", expectedParam.name)
	}
	for _, value := range arrayValue {
		err := validateStringRequestParam(config, expectedParam, value)
		if err != nil {
			return errors.Trace(err)
		}
	}
	return nil
}

// getRequestLogFields makes LogFields to log the API event following
// the legacy psi_web and current ELK naming conventions.
// When GeoIPData is the zero value, it is omitted.
func getRequestLogFields(
	eventName string,
	logFieldPrefix string,
	sessionID string,
	geoIPData GeoIPData,
	authorizedAccessTypes []string,
	params common.APIParameters,
	expectedParams []requestParamSpec) LogFields {

	logFields := make(LogFields)

	// A sessionID is specified for SSH API requests, where the Psiphon server
	// has already received a session ID in the SSH auth payload. In this
	// case, use that session ID.
	//
	// sessionID is "" for other, non-SSH server cases including tactics,
	// in-proxy broker, and client-side store and forward events including
	// remote server list and failed tunnel.

	if sessionID != "" {
		logFields["session_id"] = sessionID
	}

	if eventName != "" {
		logFields["event_name"] = eventName
	}

	zeroGeoIPData := GeoIPData{}
	if geoIPData != zeroGeoIPData {
		geoIPData.SetClientLogFields(logFields)
	}

	if len(authorizedAccessTypes) > 0 {
		logFields["authorized_access_types"] = authorizedAccessTypes
	}

	if params == nil {
		return logFields
	}

	for _, expectedParam := range expectedParams {

		if expectedParam.flags&requestParamNotLogged != 0 {
			continue
		}

		var tunnelProtocol string
		if value, ok := params["relay_protocol"]; ok {
			tunnelProtocol, _ = value.(string)
		}

		if expectedParam.flags&requestParamLogOnlyForFrontedMeekOrConjure != 0 &&
			!protocol.TunnelProtocolUsesFrontedMeek(tunnelProtocol) &&
			!protocol.TunnelProtocolUsesConjure(tunnelProtocol) {
			continue
		}

		if expectedParam.flags&requestParamNotLoggedForUnfrontedMeekNonTransformedHeader != 0 &&
			protocol.TunnelProtocolUsesMeek(tunnelProtocol) &&
			!protocol.TunnelProtocolUsesFrontedMeek(tunnelProtocol) {

			// Non-HTTP unfronted meek protocols never tranform the host header.
			if protocol.TunnelProtocolUsesMeekHTTPS(tunnelProtocol) {
				continue
			}

			var transformedHostName string
			if value, ok := params["meek_transformed_host_name"]; ok {
				transformedHostName, _ = value.(string)
			}
			if transformedHostName != "1" {
				continue
			}
		}

		value := params[expectedParam.name]
		if value == nil {

			// Special case: older clients don't send this value,
			// so log a default.
			if expectedParam.name == "tunnel_whole_device" {
				value = "0"
			} else {
				// Skip omitted, optional params
				continue
			}
		}

		name := expectedParam.name
		if logFieldPrefix != "" {
			name = logFieldPrefix + name
		}

		switch v := value.(type) {
		case string:
			strValue := v

			// Special cases:
			// - Number fields are encoded as integer types.
			// - For ELK performance we record certain domain-or-IP
			//   fields as one of two different values based on type;
			//   we also omit port from these host:port fields for now.
			// - Boolean fields that come into the api as "1"/"0"
			//   must be logged as actual boolean values
			switch expectedParam.name {

			case "meek_dial_address":
				host, _, _ := net.SplitHostPort(strValue)
				if isIPAddress(nil, host) {
					name = "meek_dial_ip_address"
				} else {
					name = "meek_dial_domain"
				}
				if logFieldPrefix != "" {
					name = logFieldPrefix + name
				}
				logFields[name] = host

			case "upstream_proxy_type":
				// Submitted value could be e.g., "SOCKS5" or "socks5"; log lowercase
				logFields[name] = strings.ToLower(strValue)

			case tactics.SPEED_TEST_SAMPLES_PARAMETER_NAME:
				// Due to a client bug, clients may deliever an incorrect ""
				// value for speed_test_samples via the web API protocol. Omit
				// the field in this case.

			case "tunnel_error":
				// net/url.Error, returned from net/url.Parse, contains the original input
				// URL, which may contain PII. New clients strip this out by using
				// common.SafeParseURL. Legacy clients will still send the full error
				// message, so strip it out here. The target substring should be unique to
				// legacy clients.
				target := "upstreamproxy error: proxyURI url.Parse: parse "
				index := strings.Index(strValue, target)
				if index != -1 {
					strValue = strValue[:index+len(target)] + "<redacted>"
				}
				logFields[name] = strValue

			default:
				if expectedParam.flags&requestParamLogStringAsInt != 0 {
					intValue, _ := strconv.Atoi(strValue)
					logFields[name] = intValue

				} else if expectedParam.flags&requestParamLogStringAsFloat != 0 {
					floatValue, _ := strconv.ParseFloat(strValue, 64)
					logFields[name] = floatValue

				} else if expectedParam.flags&requestParamLogStringLengthAsInt != 0 {
					logFields[name] = len(strValue)

				} else if expectedParam.flags&requestParamLogFlagAsBool != 0 {
					// Submitted value could be "0" or "1"
					// "0" and non "0"/"1" values should be transformed to false
					// "1" should be transformed to true
					if strValue == "1" {
						logFields[name] = true
					} else {
						logFields[name] = false
					}

				} else {
					logFields[name] = strValue
				}
			}

		case []interface{}:
			if expectedParam.name == tactics.SPEED_TEST_SAMPLES_PARAMETER_NAME {
				logFields[name] = makeSpeedTestSamplesLogField(v)
			} else {
				logFields[name] = v
			}

		default:
			logFields[name] = v
		}
	}

	return logFields
}

// makeSpeedTestSamplesLogField renames the tactics.SpeedTestSample json tag
// fields to more verbose names for metrics.
func makeSpeedTestSamplesLogField(samples []interface{}) []interface{} {
	// TODO: use reflection and add additional tags, e.g.,
	// `json:"s" log:"timestamp"` to remove hard-coded
	// tag value dependency?
	logSamples := make([]interface{}, len(samples))
	for i, sample := range samples {
		logSample := make(map[string]interface{})
		if m, ok := sample.(map[string]interface{}); ok {
			for k, v := range m {
				logK := k
				switch k {
				case "s":
					logK = "timestamp"
				case "r":
					logK = "server_region"
				case "p":
					logK = "relay_protocol"
				case "t":
					logK = "round_trip_time_ms"
				case "u":
					logK = "bytes_up"
				case "d":
					logK = "bytes_down"
				}
				logSample[logK] = v
			}
		}
		logSamples[i] = logSample
	}
	return logSamples
}

func getOptionalStringRequestParam(params common.APIParameters, name string) (string, bool) {
	if params[name] == nil {
		return "", false
	}
	value, ok := params[name].(string)
	if !ok {
		return "", false
	}
	return value, true
}

func getStringRequestParam(params common.APIParameters, name string) (string, error) {
	if params[name] == nil {
		return "", errors.Tracef("missing param: %s", name)
	}
	value, ok := params[name].(string)
	if !ok {
		return "", errors.Tracef("invalid param: %s", name)
	}
	return value, nil
}

func getIntStringRequestParam(params common.APIParameters, name string) (int, error) {
	if params[name] == nil {
		return 0, errors.Tracef("missing param: %s", name)
	}
	valueStr, ok := params[name].(string)
	if !ok {
		return 0, errors.Tracef("invalid param: %s", name)
	}
	value, err := strconv.Atoi(valueStr)
	if !ok {
		return 0, errors.Trace(err)
	}
	return value, nil
}

func getBoolStringRequestParam(params common.APIParameters, name string) (bool, error) {
	if params[name] == nil {
		return false, errors.Tracef("missing param: %s", name)
	}
	valueStr, ok := params[name].(string)
	if !ok {
		return false, errors.Tracef("invalid param: %s", name)
	}
	if valueStr == "1" {
		return true, nil
	}
	return false, nil
}

func getPaddingSizeRequestParam(params common.APIParameters, name string) (int, error) {
	value, err := getIntStringRequestParam(params, name)
	if err != nil {
		return 0, errors.Trace(err)
	}
	if value < 0 {
		value = 0
	}
	if value > PADDING_MAX_BYTES {
		value = PADDING_MAX_BYTES
	}
	return int(value), nil
}

func getJSONObjectRequestParam(params common.APIParameters, name string) (common.APIParameters, error) {
	if params[name] == nil {
		return nil, errors.Tracef("missing param: %s", name)
	}
	// Note: generic unmarshal of JSON produces map[string]interface{}, not common.APIParameters
	value, ok := params[name].(map[string]interface{})
	if !ok {
		return nil, errors.Tracef("invalid param: %s", name)
	}
	return common.APIParameters(value), nil
}

func getJSONObjectArrayRequestParam(params common.APIParameters, name string) ([]common.APIParameters, error) {
	if params[name] == nil {
		return nil, errors.Tracef("missing param: %s", name)
	}
	value, ok := params[name].([]interface{})
	if !ok {
		return nil, errors.Tracef("invalid param: %s", name)
	}

	result := make([]common.APIParameters, len(value))
	for i, item := range value {
		// Note: generic unmarshal of JSON produces map[string]interface{}, not common.APIParameters
		resultItem, ok := item.(map[string]interface{})
		if !ok {
			return nil, errors.Tracef("invalid param: %s", name)
		}
		result[i] = common.APIParameters(resultItem)
	}

	return result, nil
}

func getMapStringInt64RequestParam(params common.APIParameters, name string) (map[string]int64, error) {
	if params[name] == nil {
		return nil, errors.Tracef("missing param: %s", name)
	}
	// TODO: can't use common.APIParameters type?
	value, ok := params[name].(map[string]interface{})
	if !ok {
		return nil, errors.Tracef("invalid param: %s", name)
	}

	result := make(map[string]int64)
	for k, v := range value {
		numValue, ok := v.(float64)
		if !ok {
			return nil, errors.Tracef("invalid param: %s", name)
		}
		result[k] = int64(numValue)
	}

	return result, nil
}

func getStringArrayRequestParam(params common.APIParameters, name string) ([]string, error) {
	if params[name] == nil {
		return nil, errors.Tracef("missing param: %s", name)
	}

	switch value := params[name].(type) {
	case []string:
		return value, nil
	case []interface{}:
		// JSON unmarshaling may decode the parameter as []interface{}.
		result := make([]string, len(value))
		for i, v := range value {
			strValue, ok := v.(string)
			if !ok {
				return nil, errors.Tracef("invalid param: %s", name)
			}
			result[i] = strValue
		}
		return result, nil
	default:
		return nil, errors.Tracef("invalid param: %s", name)
	}
}

// Normalize reported client platform. Android clients, for example, report
// OS version, rooted status, and Google Play build status in the clientPlatform
// string along with "Android".
func normalizeClientPlatform(clientPlatform string) string {

	if strings.Contains(strings.ToLower(clientPlatform), strings.ToLower(CLIENT_PLATFORM_ANDROID)) {
		return CLIENT_PLATFORM_ANDROID
	} else if strings.HasPrefix(clientPlatform, CLIENT_PLATFORM_IOS) {
		return CLIENT_PLATFORM_IOS
	}

	return CLIENT_PLATFORM_WINDOWS
}

func isAnyString(config *Config, value string) bool {
	return true
}

func isMobileClientPlatform(clientPlatform string) bool {
	normalizedClientPlatform := normalizeClientPlatform(clientPlatform)
	return normalizedClientPlatform == CLIENT_PLATFORM_ANDROID ||
		normalizedClientPlatform == CLIENT_PLATFORM_IOS
}

// Input validators follow the legacy validations rules in psi_web.

func isHexDigits(_ *Config, value string) bool {
	// Allows both uppercase in addition to lowercase, for legacy support.
	return -1 == strings.IndexFunc(value, func(c rune) bool {
		return !unicode.Is(unicode.ASCII_Hex_Digit, c)
	})
}

func isBase64String(_ *Config, value string) bool {
	_, err := base64.StdEncoding.DecodeString(value)
	return err == nil
}

func isUnpaddedBase64String(_ *Config, value string) bool {
	_, err := base64.RawStdEncoding.DecodeString(value)
	return err == nil
}

func isDigits(_ *Config, value string) bool {
	return -1 == strings.IndexFunc(value, func(c rune) bool {
		return c < '0' || c > '9'
	})
}

func isIntString(_ *Config, value string) bool {
	_, err := strconv.Atoi(value)
	return err == nil
}

func isFloatString(_ *Config, value string) bool {
	_, err := strconv.ParseFloat(value, 64)
	return err == nil
}

func isClientPlatform(_ *Config, value string) bool {
	return -1 == strings.IndexFunc(value, func(c rune) bool {
		// Note: stricter than psi_web's Python string.whitespace
		return unicode.Is(unicode.White_Space, c)
	})
}

func isRelayProtocol(_ *Config, value string) bool {
	return common.Contains(protocol.SupportedTunnelProtocols, value)
}

func isBooleanFlag(_ *Config, value string) bool {
	return value == "0" || value == "1"
}

func isUpstreamProxyType(_ *Config, value string) bool {
	value = strings.ToLower(value)
	return value == "http" || value == "socks5" || value == "socks4a"
}

func isRegionCode(_ *Config, value string) bool {
	if len(value) != 2 {
		return false
	}
	return -1 == strings.IndexFunc(value, func(c rune) bool {
		return c < 'A' || c > 'Z'
	})
}

func isDialAddress(_ *Config, value string) bool {
	// "<host>:<port>", where <host> is a domain or IP address
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return false
	}
	if !isIPAddress(nil, parts[0]) && !isDomain(nil, parts[0]) {
		return false
	}
	if !isDigits(nil, parts[1]) {
		return false
	}
	_, err := strconv.Atoi(parts[1])
	if err != nil {
		return false
	}
	// Allow port numbers outside [0,65535] to accommodate failed_tunnel cases.
	return true
}

func isIPAddress(_ *Config, value string) bool {
	return net.ParseIP(value) != nil
}

var isDomainRegex = regexp.MustCompile(`[a-zA-Z\d-]{1,63}$`)

func isDomain(_ *Config, value string) bool {

	// From: http://stackoverflow.com/questions/2532053/validate-a-hostname-string
	//
	// "ensures that each segment
	//    * contains at least one character and a maximum of 63 characters
	//    * consists only of allowed characters
	//    * doesn't begin or end with a hyphen"
	//

	if len(value) > 255 {
		return false
	}
	value = strings.TrimSuffix(value, ".")
	for _, part := range strings.Split(value, ".") {
		// Note: regexp doesn't support the following Perl expression which
		// would check for '-' prefix/suffix: "(?!-)[a-zA-Z\\d-]{1,63}(?<!-)$"
		if strings.HasPrefix(part, "-") || strings.HasSuffix(part, "-") {
			return false
		}
		if !isDomainRegex.Match([]byte(part)) {
			return false
		}
	}
	return true
}

func isHostHeader(_ *Config, value string) bool {
	// "<host>:<port>", where <host> is a domain or IP address and ":<port>" is optional
	if strings.Contains(value, ":") {
		return isDialAddress(nil, value)
	}
	return isIPAddress(nil, value) || isDomain(nil, value)
}

func isServerEntrySource(_ *Config, value string) bool {
	return common.Contains(protocol.SupportedServerEntrySources, value)
}

var isISO8601DateRegex = regexp.MustCompile(
	`(?P<year>[0-9]{4})-(?P<month>[0-9]{1,2})-(?P<day>[0-9]{1,2})T(?P<hour>[0-9]{2}):(?P<minute>[0-9]{2}):(?P<second>[0-9]{2})(\.(?P<fraction>[0-9]+))?(?P<timezone>Z|(([-+])([0-9]{2}):([0-9]{2})))`)

func isISO8601Date(_ *Config, value string) bool {
	return isISO8601DateRegex.Match([]byte(value))
}

func isLastConnected(_ *Config, value string) bool {
	return value == "None" || isISO8601Date(nil, value)
}

const geohashAlphabet = "0123456789bcdefghjkmnpqrstuvwxyz"

func isGeoHashString(_ *Config, value string) bool {
	// Verify that the string is between 1 and 12 characters long
	// and contains only characters from the geohash alphabet.
	if len(value) < 1 || len(value) > 12 {
		return false
	}
	for _, c := range value {
		if !strings.Contains(geohashAlphabet, string(c)) {
			return false
		}
	}
	return true
}
