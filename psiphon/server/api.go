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
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	std_errors "errors"
	"net"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/fragmentor"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tactics"
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
// The API request handlers, handshakeAPIRequestHandler, etc., are
// reused by webServer which offers the Psiphon API via web transport.
//
// The API request parameters and event log values follow the legacy
// psi_web protocol and naming conventions. The API is compatible with
// all tunnel-core clients but are not backwards compatible with all
// legacy clients.
//
func sshAPIRequestHandler(
	support *SupportServices,
	geoIPData GeoIPData,
	authorizedAccessTypes []string,
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
	err := json.Unmarshal(requestPayload, &params)
	if err != nil {
		return nil, errors.Tracef(
			"invalid payload for request name: %s: %s", name, err)
	}

	return dispatchAPIRequestHandler(
		support,
		protocol.PSIPHON_SSH_API_PROTOCOL,
		geoIPData,
		authorizedAccessTypes,
		name,
		params)
}

// dispatchAPIRequestHandler is the common dispatch point for both
// web and SSH API requests.
func dispatchAPIRequestHandler(
	support *SupportServices,
	apiProtocol string,
	geoIPData GeoIPData,
	authorizedAccessTypes []string,
	name string,
	params common.APIParameters) (response []byte, reterr error) {

	// Recover from and log any unexpected panics caused by user input
	// handling bugs. User inputs should be properly validated; this
	// mechanism is only a last resort to prevent the process from
	// terminating in the case of a bug.
	defer func() {
		if e := recover(); e != nil {
			if intentionalPanic, ok := e.(IntentionalPanicError); ok {
				panic(intentionalPanic)
			} else {
				log.LogPanicRecover(e, debug.Stack())
				reterr = errors.TraceNew("request handler panic")
			}
		}
	}()

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

		// TODO: same session-ID-lookup TODO in handshakeAPIRequestHandler
		// applies here.
		sessionID, err := getStringRequestParam(params, "client_session_id")
		if err == nil {
			// Note: follows/duplicates baseParams validation
			if !isHexDigits(support.Config, sessionID) {
				err = std_errors.New("invalid param: client_session_id")
			}
		}
		if err != nil {
			return nil, errors.Trace(err)
		}

		completed, exhausted, err := support.TunnelServer.GetClientHandshaked(sessionID)
		if err != nil {
			return nil, errors.Trace(err)
		}
		if !completed {
			return nil, errors.TraceNew("handshake not completed")
		}
		if exhausted {
			return nil, errors.TraceNew("exhausted after handshake")
		}
	}

	switch name {
	case protocol.PSIPHON_API_HANDSHAKE_REQUEST_NAME:
		return handshakeAPIRequestHandler(support, apiProtocol, geoIPData, params)
	case protocol.PSIPHON_API_CONNECTED_REQUEST_NAME:
		return connectedAPIRequestHandler(support, geoIPData, authorizedAccessTypes, params)
	case protocol.PSIPHON_API_STATUS_REQUEST_NAME:
		return statusAPIRequestHandler(support, geoIPData, authorizedAccessTypes, params)
	case protocol.PSIPHON_API_CLIENT_VERIFICATION_REQUEST_NAME:
		return clientVerificationAPIRequestHandler(support, geoIPData, authorizedAccessTypes, params)
	}

	return nil, errors.Tracef("invalid request name: %s", name)
}

var handshakeRequestParams = append(
	append(
		append(
			[]requestParamSpec{
				// Legacy clients may not send "session_id" in handshake
				{"session_id", isHexDigits, requestParamOptional},
				{"missing_server_entry_signature", isBase64String, requestParamOptional}},
			baseParams...),
		baseDialParams...),
	tacticsParams...)

// handshakeAPIRequestHandler implements the "handshake" API request.
// Clients make the handshake immediately after establishing a tunnel
// connection; the response tells the client what homepage to open, what
// stats to record, etc.
func handshakeAPIRequestHandler(
	support *SupportServices,
	apiProtocol string,
	geoIPData GeoIPData,
	params common.APIParameters) ([]byte, error) {

	// Note: ignoring legacy "known_servers" params

	err := validateRequestParams(support.Config, params, handshakeRequestParams)
	if err != nil {
		return nil, errors.Trace(err)
	}

	sessionID, _ := getStringRequestParam(params, "client_session_id")
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

	// Note: no guarantee that PsinetDatabase won't reload between database calls
	db := support.PsinetDatabase

	httpsRequestRegexes := db.GetHttpsRequestRegexes(sponsorID)

	// Flag the SSH client as having completed its handshake. This
	// may reselect traffic rules and starts allowing port forwards.

	// TODO: in the case of SSH API requests, the actual sshClient could
	// be passed in and used here. The session ID lookup is only strictly
	// necessary to support web API requests.
	handshakeStateInfo, err := support.TunnelServer.SetClientHandshakeState(
		sessionID,
		handshakeState{
			completed:               true,
			apiProtocol:             apiProtocol,
			apiParams:               copyBaseSessionAndDialParams(params),
			expectDomainBytes:       len(httpsRequestRegexes) > 0,
			establishedTunnelsCount: establishedTunnelsCount,
		},
		authorizations)
	if err != nil {
		return nil, errors.Trace(err)
	}

	tacticsPayload, err := support.TacticsServer.GetTacticsPayload(
		common.GeoIPData(geoIPData), params)
	if err != nil {
		return nil, errors.Trace(err)
	}

	var marshaledTacticsPayload []byte

	if tacticsPayload != nil {

		marshaledTacticsPayload, err = json.Marshal(tacticsPayload)
		if err != nil {
			return nil, errors.Trace(err)
		}

		// Log a metric when new tactics are issued. Logging here indicates that
		// the handshake tactics mechanism is active; but logging for every
		// handshake creates unneccesary log data.

		if len(tacticsPayload.Tactics) > 0 {

			logFields := getRequestLogFields(
				tactics.TACTICS_METRIC_EVENT_NAME,
				geoIPData,
				handshakeStateInfo.authorizedAccessTypes,
				params,
				handshakeRequestParams)

			logFields[tactics.NEW_TACTICS_TAG_LOG_FIELD_NAME] = tacticsPayload.Tag
			logFields[tactics.IS_TACTICS_REQUEST_LOG_FIELD_NAME] = false

			log.LogRawFieldsWithTimestamp(logFields)
		}
	}

	// The log comes _after_ SetClientHandshakeState, in case that call rejects
	// the state change (for example, if a second handshake is performed)
	//
	// The handshake event is no longer shipped to log consumers, so this is
	// simply a diagnostic log. Since the "server_tunnel" event includes all
	// common API parameters and "handshake_completed" flag, this handshake
	// log is mostly redundant and set to debug level.

	log.WithTraceFields(
		getRequestLogFields(
			"",
			geoIPData,
			handshakeStateInfo.authorizedAccessTypes,
			params,
			handshakeRequestParams)).Debug("handshake")

	pad_response, _ := getPaddingSizeRequestParam(params, "pad_response")

	encodedServerList := db.DiscoverServers(geoIPData.DiscoveryValue)

	// When the client indicates that it used an unsigned server entry for this
	// connection, return a signed copy of the server entry for the client to
	// upgrade to. See also: comment in psiphon.doHandshakeRequest.
	//
	// The missing_server_entry_signature parameter value is a server entry tag,
	// which is used to select the correct server entry for servers with multiple
	// entries. Identifying the server entries tags instead of server IPs prevents
	// an enumeration attack, where a malicious client can abuse this facilty to
	// check if an arbitrary IP address is a Psiphon server.
	serverEntryTag, ok := getOptionalStringRequestParam(
		params, "missing_server_entry_signature")
	if ok {
		ownServerEntry, ok := support.Config.GetOwnEncodedServerEntry(serverEntryTag)
		if ok {
			encodedServerList = append(encodedServerList, ownServerEntry)
		}
	}

	handshakeResponse := protocol.HandshakeResponse{
		SSHSessionID:             sessionID,
		Homepages:                db.GetRandomizedHomepages(sponsorID, geoIPData.Country, geoIPData.ASN, isMobile),
		UpgradeClientVersion:     db.GetUpgradeClientVersion(clientVersion, normalizedPlatform),
		PageViewRegexes:          make([]map[string]string, 0),
		HttpsRequestRegexes:      httpsRequestRegexes,
		EncodedServerList:        encodedServerList,
		ClientRegion:             geoIPData.Country,
		ServerTimestamp:          common.GetCurrentTimestamp(),
		ActiveAuthorizationIDs:   handshakeStateInfo.activeAuthorizationIDs,
		TacticsPayload:           marshaledTacticsPayload,
		UpstreamBytesPerSecond:   handshakeStateInfo.upstreamBytesPerSecond,
		DownstreamBytesPerSecond: handshakeStateInfo.downstreamBytesPerSecond,
		Padding:                  strings.Repeat(" ", pad_response),
	}

	responsePayload, err := json.Marshal(handshakeResponse)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return responsePayload, nil
}

// uniqueUserParams are the connected request parameters which are logged for
// unique_user events.
var uniqueUserParams = append(
	[]requestParamSpec{
		{"last_connected", isLastConnected, 0}},
	baseSessionParams...)

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
	geoIPData GeoIPData,
	authorizedAccessTypes []string,
	params common.APIParameters) ([]byte, error) {

	err := validateRequestParams(support.Config, params, connectedRequestParams)
	if err != nil {
		return nil, errors.Trace(err)
	}

	sessionID, _ := getStringRequestParam(params, "client_session_id")
	lastConnected, _ := getStringRequestParam(params, "last_connected")

	// Update, for server_tunnel logging, upstream fragmentor metrics, as the
	// client may have performed more upstream fragmentation since the previous
	// metrics reported by the handshake request. Also, additional fields that
	// are reported only in the connected request are added to server_tunnel
	// here.

	// TODO: same session-ID-lookup TODO in handshakeAPIRequestHandler
	// applies here.
	err = support.TunnelServer.UpdateClientAPIParameters(
		sessionID, copyUpdateOnConnectedParams(params))
	if err != nil {
		return nil, errors.Trace(err)
	}

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
				geoIPData,
				authorizedAccessTypes,
				params,
				uniqueUserParams))
	}

	// TODO: retire the legacy "connected" log event
	log.LogRawFieldsWithTimestamp(
		getRequestLogFields(
			"connected",
			geoIPData,
			authorizedAccessTypes,
			params,
			connectedRequestParams))

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

var statusRequestParams = baseSessionParams

var remoteServerListStatParams = append(
	[]requestParamSpec{
		{"client_download_timestamp", isISO8601Date, 0},
		{"tunneled", isBooleanFlag, requestParamOptional | requestParamLogFlagAsBool},
		{"url", isAnyString, 0},
		{"etag", isAnyString, 0},
		{"authenticated", isBooleanFlag, requestParamOptional | requestParamLogFlagAsBool}},
	baseSessionParams...)

// Backwards compatibility case: legacy clients do not include these fields in
// the remote_server_list_stats entries. Use the values from the outer status
// request as an approximation (these values reflect the client at persistent
// stat shipping time, which may differ from the client at persistent stat
// recording time). Note that all but client_build_rev and device_region are
// required fields.
var remoteServerListStatBackwardsCompatibilityParamNames = []string{
	"session_id",
	"propagation_channel_id",
	"sponsor_id",
	"client_version",
	"client_platform",
	"client_build_rev",
	"device_region",
}

var failedTunnelStatParams = append(
	[]requestParamSpec{
		{"server_entry_tag", isAnyString, requestParamOptional},
		{"session_id", isHexDigits, 0},
		{"last_connected", isLastConnected, 0},
		{"client_failed_timestamp", isISO8601Date, 0},
		{"liveness_test_upstream_bytes", isIntString, requestParamOptional},
		{"liveness_test_sent_upstream_bytes", isIntString, requestParamOptional},
		{"liveness_test_downstream_bytes", isIntString, requestParamOptional},
		{"liveness_test_received_downstream_bytes", isIntString, requestParamOptional},
		{"bytes_up", isIntString, requestParamOptional},
		{"bytes_down", isIntString, requestParamOptional},
		{"tunnel_error", isAnyString, 0}},
	baseSessionAndDialParams...)

// statusAPIRequestHandler implements the "status" API request.
// Clients make periodic status requests which deliver client-side
// recorded data transfer and tunnel duration stats.
// Note from psi_web implementation: no input validation on domains;
// any string is accepted (regex transform may result in arbitrary
// string). Stats processor must handle this input with care.
func statusAPIRequestHandler(
	support *SupportServices,
	geoIPData GeoIPData,
	authorizedAccessTypes []string,
	params common.APIParameters) ([]byte, error) {

	err := validateRequestParams(support.Config, params, statusRequestParams)
	if err != nil {
		return nil, errors.Trace(err)
	}

	sessionID, _ := getStringRequestParam(params, "client_session_id")

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
	domainBytesExpected, err := support.TunnelServer.ExpectClientDomainBytes(sessionID)
	if err != nil {
		return nil, errors.Trace(err)
	}

	if domainBytesExpected && statusData["host_bytes"] != nil {

		hostBytes, err := getMapStringInt64RequestParam(statusData, "host_bytes")
		if err != nil {
			return nil, errors.Trace(err)
		}
		for domain, bytes := range hostBytes {

			domainBytesFields := getRequestLogFields(
				"domain_bytes",
				geoIPData,
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

			// For validation, copy expected fields from the outer
			// statusRequestParams.
			remoteServerListStat["server_secret"] = params["server_secret"]
			remoteServerListStat["client_session_id"] = params["client_session_id"]

			err := validateRequestParams(support.Config, remoteServerListStat, remoteServerListStatParams)
			if err != nil {
				// Occasionally, clients may send corrupt persistent stat data. Do not
				// fail the status request, as this will lead to endless retries.
				log.WithTraceFields(LogFields{"error": err}).Warning("remote_server_list_stats entry dropped")
				continue
			}

			remoteServerListFields := getRequestLogFields(
				"remote_server_list",
				geoIPData,
				authorizedAccessTypes,
				remoteServerListStat,
				remoteServerListStatParams)

			logQueue = append(logQueue, remoteServerListFields)
		}
	}

	// Failed tunnel persistent stats.
	// Older clients may not submit this data.

	var invalidServerEntryTags map[string]bool

	if statusData["failed_tunnel_stats"] != nil {

		// Note: no guarantee that PsinetDatabase won't reload between database calls
		db := support.PsinetDatabase

		invalidServerEntryTags = make(map[string]bool)

		failedTunnelStats, err := getJSONObjectArrayRequestParam(statusData, "failed_tunnel_stats")
		if err != nil {
			return nil, errors.Trace(err)
		}
		for _, failedTunnelStat := range failedTunnelStats {

			// failed_tunnel supplies a full set of base params, but the server secret
			// must use the correct value from the outer statusRequestParams.
			failedTunnelStat["server_secret"] = params["server_secret"]

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
				geoIPData,
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

			var serverEntryTagStr string

			serverEntryTag, ok := failedTunnelStat["server_entry_tag"]
			if ok {
				serverEntryTagStr, ok = serverEntryTag.(string)
			}

			if ok {
				serverEntryValid := db.IsValidServerEntryTag(serverEntryTagStr)
				if !serverEntryValid {
					invalidServerEntryTags[serverEntryTagStr] = true
				}

				// Add a field to the failed_tunnel log indicating if the server entry is
				// valid.
				failedTunnelFields["server_entry_valid"] = serverEntryValid
			}

			// Log failed_tunnel.

			logQueue = append(logQueue, failedTunnelFields)
		}
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
	support *SupportServices,
	geoIPData GeoIPData,
	authorizedAccessTypes []string,
	params common.APIParameters) ([]byte, error) {
	return make([]byte, 0), nil
}

var tacticsParams = []requestParamSpec{
	{tactics.STORED_TACTICS_TAG_PARAMETER_NAME, isAnyString, requestParamOptional},
	{tactics.SPEED_TEST_SAMPLES_PARAMETER_NAME, nil, requestParamOptional | requestParamJSON},
}

var tacticsRequestParams = append(
	append([]requestParamSpec(nil), tacticsParams...),
	baseSessionAndDialParams...)

func getTacticsAPIParameterValidator(config *Config) common.APIParameterValidator {
	return func(params common.APIParameters) error {
		return validateRequestParams(config, params, tacticsRequestParams)
	}
}

func getTacticsAPIParameterLogFieldFormatter() common.APIParameterLogFieldFormatter {

	return func(geoIPData common.GeoIPData, params common.APIParameters) common.LogFields {

		logFields := getRequestLogFields(
			tactics.TACTICS_METRIC_EVENT_NAME,
			GeoIPData(geoIPData),
			nil, // authorizedAccessTypes are not known yet
			params,
			tacticsRequestParams)

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
	requestParamLogOnlyForFrontedMeek                         = 1 << 8
	requestParamNotLoggedForUnfrontedMeekNonTransformedHeader = 1 << 9
)

// baseParams are the basic request parameters that are expected for all API
// requests and log events.
var baseParams = []requestParamSpec{
	{"server_secret", isServerSecret, requestParamNotLogged},
	{"client_session_id", isHexDigits, requestParamNotLogged},
	{"propagation_channel_id", isHexDigits, 0},
	{"sponsor_id", isHexDigits, 0},
	{"client_version", isIntString, requestParamLogStringAsInt},
	{"client_platform", isClientPlatform, 0},
	{"client_build_rev", isHexDigits, requestParamOptional},
	{"tunnel_whole_device", isBooleanFlag, requestParamOptional | requestParamLogFlagAsBool},
	{"device_region", isAnyString, requestParamOptional},
}

// baseSessionParams adds to baseParams the required session_id parameter. For
// all requests except handshake, all existing clients are expected to send
// session_id. Legacy clients may not send "session_id" in handshake.
var baseSessionParams = append(
	[]requestParamSpec{
		{"session_id", isHexDigits, 0}},
	baseParams...)

// baseDialParams are the dial parameters, per-tunnel network protocol and
// obfuscation metrics which are logged with server_tunnel, failed_tunnel, and
// tactics.
var baseDialParams = []requestParamSpec{
	{"relay_protocol", isRelayProtocol, 0},
	{"ssh_client_version", isAnyString, requestParamOptional},
	{"upstream_proxy_type", isUpstreamProxyType, requestParamOptional},
	{"upstream_proxy_custom_header_names", isAnyString, requestParamOptional | requestParamArray},
	{"fronting_provider_id", isAnyString, requestParamOptional},
	{"meek_dial_address", isDialAddress, requestParamOptional | requestParamLogOnlyForFrontedMeek},
	{"meek_resolved_ip_address", isIPAddress, requestParamOptional | requestParamLogOnlyForFrontedMeek},
	{"meek_sni_server_name", isDomain, requestParamOptional},
	{"meek_host_header", isHostHeader, requestParamOptional | requestParamNotLoggedForUnfrontedMeekNonTransformedHeader},
	{"meek_transformed_host_name", isBooleanFlag, requestParamOptional | requestParamLogFlagAsBool},
	{"user_agent", isAnyString, requestParamOptional},
	{"tls_profile", isAnyString, requestParamOptional},
	{"tls_version", isAnyString, requestParamOptional},
	{"server_entry_region", isRegionCode, requestParamOptional},
	{"server_entry_source", isServerEntrySource, requestParamOptional},
	{"server_entry_timestamp", isISO8601Date, requestParamOptional},
	{tactics.APPLIED_TACTICS_TAG_PARAMETER_NAME, isAnyString, requestParamOptional},
	{"dial_port_number", isIntString, requestParamOptional | requestParamLogStringAsInt},
	{"quic_version", isAnyString, requestParamOptional},
	{"quic_dial_sni_address", isAnyString, requestParamOptional},
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
	{"meek_tls_padding", isIntString, requestParamOptional | requestParamLogStringAsInt},
	{"network_latency_multiplier", isFloatString, requestParamOptional | requestParamLogStringAsFloat},
	{"client_bpf", isAnyString, requestParamOptional},
	{"network_type", isAnyString, requestParamOptional},
}

// baseSessionAndDialParams adds baseDialParams to baseSessionParams.
var baseSessionAndDialParams = append(
	append(
		[]requestParamSpec{},
		baseSessionParams...),
	baseDialParams...)

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

// copyBaseSessionAndDialParams makes a copy of the params which includes only
// the baseSessionAndDialParams.
func copyBaseSessionAndDialParams(params common.APIParameters) common.APIParameters {

	// Note: not a deep copy; assumes baseSessionAndDialParams values are all
	// scalar types (int, string, etc.)
	paramsCopy := make(common.APIParameters)
	for _, baseParam := range baseSessionAndDialParams {
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
		return errors.Tracef("unexpected string param type: %s", expectedParam.name)
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
func getRequestLogFields(
	eventName string,
	geoIPData GeoIPData,
	authorizedAccessTypes []string,
	params common.APIParameters,
	expectedParams []requestParamSpec) LogFields {

	logFields := make(LogFields)

	if eventName != "" {
		logFields["event_name"] = eventName
	}

	geoIPData.SetLogFields(logFields)

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

		if expectedParam.flags&requestParamLogOnlyForFrontedMeek != 0 &&
			!protocol.TunnelProtocolUsesFrontedMeek(tunnelProtocol) {
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
					logFields["meek_dial_ip_address"] = host
				} else {
					logFields["meek_dial_domain"] = host
				}

			case "upstream_proxy_type":
				// Submitted value could be e.g., "SOCKS5" or "socks5"; log lowercase
				logFields[expectedParam.name] = strings.ToLower(strValue)

			case tactics.SPEED_TEST_SAMPLES_PARAMETER_NAME:
				// Due to a client bug, clients may deliever an incorrect ""
				// value for speed_test_samples via the web API protocol. Omit
				// the field in this case.

			default:
				if expectedParam.flags&requestParamLogStringAsInt != 0 {
					intValue, _ := strconv.Atoi(strValue)
					logFields[expectedParam.name] = intValue

				} else if expectedParam.flags&requestParamLogStringAsFloat != 0 {
					floatValue, _ := strconv.ParseFloat(strValue, 64)
					logFields[expectedParam.name] = floatValue

				} else if expectedParam.flags&requestParamLogStringLengthAsInt != 0 {
					logFields[expectedParam.name] = len(strValue)

				} else if expectedParam.flags&requestParamLogFlagAsBool != 0 {
					// Submitted value could be "0" or "1"
					// "0" and non "0"/"1" values should be transformed to false
					// "1" should be transformed to true
					if strValue == "1" {
						logFields[expectedParam.name] = true
					} else {
						logFields[expectedParam.name] = false
					}

				} else {
					logFields[expectedParam.name] = strValue
				}
			}

		case []interface{}:
			if expectedParam.name == tactics.SPEED_TEST_SAMPLES_PARAMETER_NAME {
				logFields[expectedParam.name] = makeSpeedTestSamplesLogField(v)
			} else {
				logFields[expectedParam.name] = v
			}

		default:
			logFields[expectedParam.name] = v
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
	value, ok := params[name].([]interface{})
	if !ok {
		return nil, errors.Tracef("invalid param: %s", name)
	}

	result := make([]string, len(value))
	for i, v := range value {
		strValue, ok := v.(string)
		if !ok {
			return nil, errors.Tracef("invalid param: %s", name)
		}
		result[i] = strValue
	}

	return result, nil
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

func isServerSecret(config *Config, value string) bool {
	return subtle.ConstantTimeCompare(
		[]byte(value),
		[]byte(config.WebServerSecret)) == 1
}

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
