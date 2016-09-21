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
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"unicode"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
)

const (
	MAX_API_PARAMS_SIZE = 256 * 1024 // 256KB

	CLIENT_VERIFICATION_REQUIRED    = true
	CLIENT_VERIFICATION_TTL_SECONDS = 60 * 60 * 24 * 7 // 7 days

	CLIENT_PLATFORM_ANDROID = "Android"
	CLIENT_PLATFORM_WINDOWS = "Windows"
)

type requestJSONObject map[string]interface{}

// sshAPIRequestHandler routes Psiphon API requests transported as
// JSON objects via the SSH request mechanism.
//
// The API request handlers, handshakeAPIRequestHandler, etc., are
// reused by webServer which offers the Psiphon API via web transport.
//
// The API request parameters and event log values follow the legacy
// psi_web protocol and naming conventions. The API is compatible all
// tunnel-core clients but are not backwards compatible with older
// clients.
//
func sshAPIRequestHandler(
	support *SupportServices,
	geoIPData GeoIPData,
	name string,
	requestPayload []byte) ([]byte, error) {

	// Note: for SSH requests, MAX_API_PARAMS_SIZE is implicitly enforced
	// by max SSH reqest packet size.

	var params requestJSONObject
	err := json.Unmarshal(requestPayload, &params)
	if err != nil {
		return nil, common.ContextError(
			fmt.Errorf("invalid payload for request name: %s: %s", name, err))
	}

	return dispatchAPIRequestHandler(
		support,
		common.PSIPHON_SSH_API_PROTOCOL,
		geoIPData,
		name,
		params)
}

// dispatchAPIRequestHandler is the common dispatch point for both
// web and SSH API requests.
func dispatchAPIRequestHandler(
	support *SupportServices,
	apiProtocol string,
	geoIPData GeoIPData,
	name string,
	params requestJSONObject) (response []byte, reterr error) {

	// Recover from and log any unexpected panics caused by user input
	// handling bugs. User inputs should be properly validated; this
	// mechanism is only a last resort to prevent the process from
	// terminating in the case of a bug.
	defer func() {
		if e := recover(); e != nil {
			reterr = common.ContextError(
				fmt.Errorf(
					"request handler panic: %s: %s", e, debug.Stack()))
		}
	}()

	switch name {
	case common.PSIPHON_API_HANDSHAKE_REQUEST_NAME:
		return handshakeAPIRequestHandler(support, apiProtocol, geoIPData, params)
	case common.PSIPHON_API_CONNECTED_REQUEST_NAME:
		return connectedAPIRequestHandler(support, geoIPData, params)
	case common.PSIPHON_API_STATUS_REQUEST_NAME:
		return statusAPIRequestHandler(support, geoIPData, params)
	case common.PSIPHON_API_CLIENT_VERIFICATION_REQUEST_NAME:
		return clientVerificationAPIRequestHandler(support, geoIPData, params)
	}

	return nil, common.ContextError(fmt.Errorf("invalid request name: %s", name))
}

// handshakeAPIRequestHandler implements the "handshake" API request.
// Clients make the handshake immediately after establishing a tunnel
// connection; the response tells the client what homepage to open, what
// stats to record, etc.
func handshakeAPIRequestHandler(
	support *SupportServices,
	apiProtocol string,
	geoIPData GeoIPData,
	params requestJSONObject) ([]byte, error) {

	// Note: ignoring "known_servers" params

	err := validateRequestParams(support, params, baseRequestParams)
	if err != nil {
		return nil, common.ContextError(err)
	}

	log.LogRawFieldsWithTimestamp(
		getRequestLogFields(
			support,
			"handshake",
			geoIPData,
			params,
			baseRequestParams))

	// Note: ignoring param format errors as params have been validated

	sessionID, _ := getStringRequestParam(params, "client_session_id")
	sponsorID, _ := getStringRequestParam(params, "sponsor_id")
	clientVersion, _ := getStringRequestParam(params, "client_version")
	clientPlatform, _ := getStringRequestParam(params, "client_platform")
	isMobile := isMobileClientPlatform(clientPlatform)
	normalizedPlatform := normalizeClientPlatform(clientPlatform)

	// Flag the SSH client as having completed its handshake. This
	// may reselect traffic rules and starts allowing port forwards.

	// TODO: in the case of SSH API requests, the actual sshClient could
	// be passed in and used here. The session ID lookup is only strictly
	// necessary to support web API requests.
	err = support.TunnelServer.SetClientHandshakeState(
		sessionID,
		handshakeState{
			completed:   true,
			apiProtocol: apiProtocol,
			apiParams:   copyBaseRequestParams(params),
		})
	if err != nil {
		return nil, common.ContextError(err)
	}

	// Note: no guarantee that PsinetDatabase won't reload between database calls
	db := support.PsinetDatabase
	handshakeResponse := common.HandshakeResponse{
		Homepages:            db.GetHomepages(sponsorID, geoIPData.Country, isMobile),
		UpgradeClientVersion: db.GetUpgradeClientVersion(clientVersion, normalizedPlatform),
		HttpsRequestRegexes:  db.GetHttpsRequestRegexes(sponsorID),
		EncodedServerList:    db.DiscoverServers(geoIPData.DiscoveryValue),
		ClientRegion:         geoIPData.Country,
		ServerTimestamp:      common.GetCurrentTimestamp(),
	}

	responsePayload, err := json.Marshal(handshakeResponse)
	if err != nil {
		return nil, common.ContextError(err)
	}

	return responsePayload, nil
}

var connectedRequestParams = append(
	[]requestParamSpec{
		requestParamSpec{"session_id", isHexDigits, 0},
		requestParamSpec{"last_connected", isLastConnected, 0}},
	baseRequestParams...)

// connectedAPIRequestHandler implements the "connected" API request.
// Clients make the connected request once a tunnel connection has been
// established and at least once per day. The last_connected input value,
// which should be a connected_timestamp output from a previous connected
// response, is used to calculate unique user stats.
func connectedAPIRequestHandler(
	support *SupportServices,
	geoIPData GeoIPData,
	params requestJSONObject) ([]byte, error) {

	err := validateRequestParams(support, params, connectedRequestParams)
	if err != nil {
		return nil, common.ContextError(err)
	}

	log.LogRawFieldsWithTimestamp(
		getRequestLogFields(
			support,
			"connected",
			geoIPData,
			params,
			connectedRequestParams))

	connectedResponse := common.ConnectedResponse{
		ConnectedTimestamp: common.TruncateTimestampToHour(common.GetCurrentTimestamp()),
	}

	responsePayload, err := json.Marshal(connectedResponse)
	if err != nil {
		return nil, common.ContextError(err)
	}

	return responsePayload, nil
}

var statusRequestParams = append(
	[]requestParamSpec{
		requestParamSpec{"session_id", isHexDigits, 0},
		requestParamSpec{"connected", isBooleanFlag, 0}},
	baseRequestParams...)

// statusAPIRequestHandler implements the "status" API request.
// Clients make periodic status requests which deliver client-side
// recorded data transfer and tunnel duration stats.
// Note from psi_web implementation: no input validation on domains;
// any string is accepted (regex transform may result in arbitrary
// string). Stats processor must handle this input with care.
func statusAPIRequestHandler(
	support *SupportServices,
	geoIPData GeoIPData,
	params requestJSONObject) ([]byte, error) {

	err := validateRequestParams(support, params, statusRequestParams)
	if err != nil {
		return nil, common.ContextError(err)
	}

	statusData, err := getJSONObjectRequestParam(params, "statusData")
	if err != nil {
		return nil, common.ContextError(err)
	}

	// Overall bytes transferred stats

	bytesTransferred, err := getInt64RequestParam(statusData, "bytes_transferred")
	if err != nil {
		return nil, common.ContextError(err)
	}
	bytesTransferredFields := getRequestLogFields(
		support, "bytes_transferred", geoIPData, params, statusRequestParams)
	bytesTransferredFields["bytes"] = bytesTransferred
	log.LogRawFieldsWithTimestamp(bytesTransferredFields)

	// Domain bytes transferred stats
	// Older clients may not submit this data

	if statusData["host_bytes"] != nil {

		hostBytes, err := getMapStringInt64RequestParam(statusData, "host_bytes")
		if err != nil {
			return nil, common.ContextError(err)
		}
		domainBytesFields := getRequestLogFields(
			support, "domain_bytes", geoIPData, params, statusRequestParams)
		for domain, bytes := range hostBytes {
			domainBytesFields["domain"] = domain
			domainBytesFields["bytes"] = bytes
			log.LogRawFieldsWithTimestamp(domainBytesFields)
		}
	}

	// Tunnel duration and bytes transferred stats
	// Older clients may not submit this data

	if statusData["tunnel_stats"] != nil {

		tunnelStats, err := getJSONObjectArrayRequestParam(statusData, "tunnel_stats")
		if err != nil {
			return nil, common.ContextError(err)
		}
		sessionFields := getRequestLogFields(
			support, "session", geoIPData, params, statusRequestParams)
		for _, tunnelStat := range tunnelStats {

			sessionID, err := getStringRequestParam(tunnelStat, "session_id")
			if err != nil {
				return nil, common.ContextError(err)
			}
			sessionFields["session_id"] = sessionID

			tunnelNumber, err := getInt64RequestParam(tunnelStat, "tunnel_number")
			if err != nil {
				return nil, common.ContextError(err)
			}
			sessionFields["tunnel_number"] = tunnelNumber

			tunnelServerIPAddress, err := getStringRequestParam(tunnelStat, "tunnel_server_ip_address")
			if err != nil {
				return nil, common.ContextError(err)
			}
			sessionFields["tunnel_server_ip_address"] = tunnelServerIPAddress

			// Note: older clients won't send establishment_duration
			if _, ok := tunnelStat["establishment_duration"]; ok {

				strEstablishmentDuration, err := getStringRequestParam(tunnelStat, "establishment_duration")
				if err != nil {
					return nil, common.ContextError(err)
				}
				establishmentDuration, err := strconv.ParseInt(strEstablishmentDuration, 10, 64)
				if err != nil {
					return nil, common.ContextError(err)
				}
				// Client reports establishment_duration in nanoseconds; divide to get to milliseconds
				sessionFields["establishment_duration"] = establishmentDuration / 1000000
			}

			serverHandshakeTimestamp, err := getStringRequestParam(tunnelStat, "server_handshake_timestamp")
			if err != nil {
				return nil, common.ContextError(err)
			}
			sessionFields["server_handshake_timestamp"] = serverHandshakeTimestamp

			strDuration, err := getStringRequestParam(tunnelStat, "duration")
			if err != nil {
				return nil, common.ContextError(err)
			}
			duration, err := strconv.ParseInt(strDuration, 10, 64)
			if err != nil {
				return nil, common.ContextError(err)
			}
			// Client reports duration in nanoseconds; divide to get to milliseconds
			sessionFields["duration"] = duration / 1000000

			totalBytesSent, err := getInt64RequestParam(tunnelStat, "total_bytes_sent")
			if err != nil {
				return nil, common.ContextError(err)
			}
			sessionFields["total_bytes_sent"] = totalBytesSent

			totalBytesReceived, err := getInt64RequestParam(tunnelStat, "total_bytes_received")
			if err != nil {
				return nil, common.ContextError(err)
			}
			sessionFields["total_bytes_received"] = totalBytesReceived

			log.LogRawFieldsWithTimestamp(sessionFields)
		}
	}

	return make([]byte, 0), nil
}

// clientVerificationAPIRequestHandler implements the
// "client verification" API request. Clients make the client
// verification request once per tunnel connection. The payload
// attests that client is a legitimate Psiphon client.
func clientVerificationAPIRequestHandler(
	support *SupportServices,
	geoIPData GeoIPData,
	params requestJSONObject) ([]byte, error) {

	err := validateRequestParams(support, params, baseRequestParams)
	if err != nil {
		return nil, common.ContextError(err)
	}

	// Ignoring error as params are validated
	clientPlatform, _ := getStringRequestParam(params, "client_platform")

	// Client sends empty payload to receive TTL
	// NOTE: these events are not currently logged
	if params["verificationData"] == nil {
		if CLIENT_VERIFICATION_REQUIRED {

			var clientVerificationResponse struct {
				ClientVerificationTTLSeconds int `json:"client_verification_ttl_seconds"`
			}
			clientVerificationResponse.ClientVerificationTTLSeconds = CLIENT_VERIFICATION_TTL_SECONDS

			responsePayload, err := json.Marshal(clientVerificationResponse)
			if err != nil {
				return nil, common.ContextError(err)
			}

			return responsePayload, nil
		} else {
			return make([]byte, 0), nil
		}
	} else {
		verificationData, err := getJSONObjectRequestParam(params, "verificationData")
		if err != nil {
			return nil, common.ContextError(err)
		}

		logFields := getRequestLogFields(
			support,
			"client_verification",
			geoIPData,
			params,
			baseRequestParams)

		var verified bool
		var safetyNetCheckLogs LogFields
		switch normalizeClientPlatform(clientPlatform) {
		case CLIENT_PLATFORM_ANDROID:
			verified, safetyNetCheckLogs = verifySafetyNetPayload(verificationData)
			logFields["safetynet_check"] = safetyNetCheckLogs
		}

		log.LogRawFieldsWithTimestamp(logFields)

		if verified {
			// TODO: change throttling treatment
		}
		return make([]byte, 0), nil
	}
}

type requestParamSpec struct {
	name      string
	validator func(*SupportServices, string) bool
	flags     uint32
}

const (
	requestParamOptional  = 1
	requestParamNotLogged = 2
	requestParamArray     = 4
)

// baseRequestParams is the list of required and optional
// request parameters; derived from COMMON_INPUTS and
// OPTIONAL_COMMON_INPUTS in psi_web.
// Each param is expected to be a string, unless requestParamArray
// is specified, in which case an array of string is expected.
var baseRequestParams = []requestParamSpec{
	requestParamSpec{"server_secret", isServerSecret, requestParamNotLogged},
	requestParamSpec{"client_session_id", isHexDigits, requestParamOptional | requestParamNotLogged},
	requestParamSpec{"propagation_channel_id", isHexDigits, 0},
	requestParamSpec{"sponsor_id", isHexDigits, 0},
	requestParamSpec{"client_version", isIntString, 0},
	requestParamSpec{"client_platform", isClientPlatform, 0},
	requestParamSpec{"relay_protocol", isRelayProtocol, 0},
	requestParamSpec{"tunnel_whole_device", isBooleanFlag, requestParamOptional},
	requestParamSpec{"device_region", isRegionCode, requestParamOptional},
	requestParamSpec{"upstream_proxy_type", isUpstreamProxyType, requestParamOptional},
	requestParamSpec{"upstream_proxy_custom_header_names", isAnyString, requestParamOptional | requestParamArray},
	requestParamSpec{"meek_dial_address", isDialAddress, requestParamOptional},
	requestParamSpec{"meek_resolved_ip_address", isIPAddress, requestParamOptional},
	requestParamSpec{"meek_sni_server_name", isDomain, requestParamOptional},
	requestParamSpec{"meek_host_header", isHostHeader, requestParamOptional},
	requestParamSpec{"meek_transformed_host_name", isBooleanFlag, requestParamOptional},
	requestParamSpec{"server_entry_region", isRegionCode, requestParamOptional},
	requestParamSpec{"server_entry_source", isServerEntrySource, requestParamOptional},
	requestParamSpec{"server_entry_timestamp", isISO8601Date, requestParamOptional},
}

func validateRequestParams(
	support *SupportServices,
	params requestJSONObject,
	expectedParams []requestParamSpec) error {

	for _, expectedParam := range expectedParams {
		value := params[expectedParam.name]
		if value == nil {
			if expectedParam.flags&requestParamOptional != 0 {
				continue
			}
			return common.ContextError(
				fmt.Errorf("missing param: %s", expectedParam.name))
		}
		var err error
		if expectedParam.flags&requestParamArray != 0 {
			err = validateStringArrayRequestParam(support, expectedParam, value)
		} else {
			err = validateStringRequestParam(support, expectedParam, value)
		}
		if err != nil {
			return common.ContextError(err)
		}
	}

	return nil
}

// copyBaseRequestParams makes a copy of the params which
// includes only the baseRequestParams.
func copyBaseRequestParams(params requestJSONObject) requestJSONObject {

	// Note: not a deep copy; assumes baseRequestParams values
	// are all scalar types (int, string, etc.)

	paramsCopy := make(requestJSONObject)
	for _, baseParam := range baseRequestParams {
		value := params[baseParam.name]
		if value == nil {
			continue
		}

		paramsCopy[baseParam.name] = value
	}

	return paramsCopy
}

func validateStringRequestParam(
	support *SupportServices,
	expectedParam requestParamSpec,
	value interface{}) error {

	strValue, ok := value.(string)
	if !ok {
		return common.ContextError(
			fmt.Errorf("unexpected string param type: %s", expectedParam.name))
	}
	if !expectedParam.validator(support, strValue) {
		return common.ContextError(
			fmt.Errorf("invalid param: %s", expectedParam.name))
	}
	return nil
}

func validateStringArrayRequestParam(
	support *SupportServices,
	expectedParam requestParamSpec,
	value interface{}) error {

	arrayValue, ok := value.([]interface{})
	if !ok {
		return common.ContextError(
			fmt.Errorf("unexpected string param type: %s", expectedParam.name))
	}
	for _, value := range arrayValue {
		err := validateStringRequestParam(support, expectedParam, value)
		if err != nil {
			return common.ContextError(err)
		}
	}
	return nil
}

// getRequestLogFields makes LogFields to log the API event following
// the legacy psi_web and current ELK naming conventions.
func getRequestLogFields(
	support *SupportServices,
	eventName string,
	geoIPData GeoIPData,
	params requestJSONObject,
	expectedParams []requestParamSpec) LogFields {

	logFields := make(LogFields)

	logFields["event_name"] = eventName
	logFields["host_id"] = support.Config.HostID
	logFields["build_rev"] = common.GetBuildInfo().BuildRev

	// In psi_web, the space replacement was done to accommodate space
	// delimited logging, which is no longer required; we retain the
	// transformation so that stats aggregation isn't impacted.
	logFields["client_region"] = strings.Replace(geoIPData.Country, " ", "_", -1)
	logFields["client_city"] = strings.Replace(geoIPData.City, " ", "_", -1)
	logFields["client_isp"] = strings.Replace(geoIPData.ISP, " ", "_", -1)

	if params == nil {
		return logFields
	}

	for _, expectedParam := range expectedParams {

		if expectedParam.flags&requestParamNotLogged != 0 {
			continue
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
			// - For ELK performance we record these domain-or-IP
			//   fields as one of two different values based on type;
			//   we also omit port from host:port fields for now.
			switch expectedParam.name {
			case "client_version":
				intValue, _ := strconv.Atoi(strValue)
				logFields[expectedParam.name] = intValue
			case "meek_dial_address":
				host, _, _ := net.SplitHostPort(strValue)
				if isIPAddress(support, host) {
					logFields["meek_dial_ip_address"] = host
				} else {
					logFields["meek_dial_domain"] = host
				}
			case "meek_host_header":
				host, _, _ := net.SplitHostPort(strValue)
				logFields[expectedParam.name] = host
			case "upstream_proxy_type":
				// Submitted value could be e.g., "SOCKS5" or "socks5"; log lowercase
				logFields[expectedParam.name] = strings.ToLower(strValue)
			default:
				logFields[expectedParam.name] = strValue
			}

		case []interface{}:
			// Note: actually validated as an array of strings
			logFields[expectedParam.name] = v

		default:
			// This type assertion should be checked already in
			// validateRequestParams, so failure is unexpected.
			continue
		}
	}

	return logFields
}

func getStringRequestParam(params requestJSONObject, name string) (string, error) {
	if params[name] == nil {
		return "", common.ContextError(fmt.Errorf("missing param: %s", name))
	}
	value, ok := params[name].(string)
	if !ok {
		return "", common.ContextError(fmt.Errorf("invalid param: %s", name))
	}
	return value, nil
}

func getInt64RequestParam(params requestJSONObject, name string) (int64, error) {
	if params[name] == nil {
		return 0, common.ContextError(fmt.Errorf("missing param: %s", name))
	}
	value, ok := params[name].(float64)
	if !ok {
		return 0, common.ContextError(fmt.Errorf("invalid param: %s", name))
	}
	return int64(value), nil
}

func getJSONObjectRequestParam(params requestJSONObject, name string) (requestJSONObject, error) {
	if params[name] == nil {
		return nil, common.ContextError(fmt.Errorf("missing param: %s", name))
	}
	// Note: generic unmarshal of JSON produces map[string]interface{}, not requestJSONObject
	value, ok := params[name].(map[string]interface{})
	if !ok {
		return nil, common.ContextError(fmt.Errorf("invalid param: %s", name))
	}
	return requestJSONObject(value), nil
}

func getJSONObjectArrayRequestParam(params requestJSONObject, name string) ([]requestJSONObject, error) {
	if params[name] == nil {
		return nil, common.ContextError(fmt.Errorf("missing param: %s", name))
	}
	value, ok := params[name].([]interface{})
	if !ok {
		return nil, common.ContextError(fmt.Errorf("invalid param: %s", name))
	}

	result := make([]requestJSONObject, len(value))
	for i, item := range value {
		// Note: generic unmarshal of JSON produces map[string]interface{}, not requestJSONObject
		resultItem, ok := item.(map[string]interface{})
		if !ok {
			return nil, common.ContextError(fmt.Errorf("invalid param: %s", name))
		}
		result[i] = requestJSONObject(resultItem)
	}

	return result, nil
}

func getMapStringInt64RequestParam(params requestJSONObject, name string) (map[string]int64, error) {
	if params[name] == nil {
		return nil, common.ContextError(fmt.Errorf("missing param: %s", name))
	}
	// TODO: can't use requestJSONObject type?
	value, ok := params[name].(map[string]interface{})
	if !ok {
		return nil, common.ContextError(fmt.Errorf("invalid param: %s", name))
	}

	result := make(map[string]int64)
	for k, v := range value {
		numValue, ok := v.(float64)
		if !ok {
			return nil, common.ContextError(fmt.Errorf("invalid param: %s", name))
		}
		result[k] = int64(numValue)
	}

	return result, nil
}

// Normalize reported client platform. Android clients, for example, report
// OS version, rooted status, and Google Play build status in the clientPlatform
// string along with "Android".
func normalizeClientPlatform(clientPlatform string) string {

	if strings.Contains(strings.ToLower(clientPlatform), strings.ToLower(CLIENT_PLATFORM_ANDROID)) {
		return CLIENT_PLATFORM_ANDROID
	}

	return CLIENT_PLATFORM_WINDOWS
}

func isAnyString(support *SupportServices, value string) bool {
	return true
}

func isMobileClientPlatform(clientPlatform string) bool {
	return normalizeClientPlatform(clientPlatform) == CLIENT_PLATFORM_ANDROID
}

// Input validators follow the legacy validations rules in psi_web.

func isServerSecret(support *SupportServices, value string) bool {
	return subtle.ConstantTimeCompare(
		[]byte(value),
		[]byte(support.Config.WebServerSecret)) == 1
}

func isHexDigits(_ *SupportServices, value string) bool {
	return -1 == strings.IndexFunc(value, func(c rune) bool {
		return !unicode.Is(unicode.ASCII_Hex_Digit, c)
	})
}

func isDigits(_ *SupportServices, value string) bool {
	return -1 == strings.IndexFunc(value, func(c rune) bool {
		return c < '0' || c > '9'
	})
}

func isIntString(_ *SupportServices, value string) bool {
	_, err := strconv.Atoi(value)
	return err == nil
}

func isClientPlatform(_ *SupportServices, value string) bool {
	return -1 == strings.IndexFunc(value, func(c rune) bool {
		// Note: stricter than psi_web's Python string.whitespace
		return unicode.Is(unicode.White_Space, c)
	})
}

func isRelayProtocol(_ *SupportServices, value string) bool {
	return common.Contains(common.SupportedTunnelProtocols, value)
}

func isBooleanFlag(_ *SupportServices, value string) bool {
	return value == "0" || value == "1"
}

func isUpstreamProxyType(_ *SupportServices, value string) bool {
	value = strings.ToLower(value)
	return value == "http" || value == "socks5" || value == "socks4a"
}

func isRegionCode(_ *SupportServices, value string) bool {
	if len(value) != 2 {
		return false
	}
	return -1 == strings.IndexFunc(value, func(c rune) bool {
		return c < 'A' || c > 'Z'
	})
}

func isDialAddress(support *SupportServices, value string) bool {
	// "<host>:<port>", where <host> is a domain or IP address
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return false
	}
	if !isIPAddress(support, parts[0]) && !isDomain(support, parts[0]) {
		return false
	}
	if !isDigits(support, parts[1]) {
		return false
	}
	port, err := strconv.Atoi(parts[1])
	if err != nil {
		return false
	}
	return port > 0 && port < 65536
}

func isIPAddress(_ *SupportServices, value string) bool {
	return net.ParseIP(value) != nil
}

var isDomainRegex = regexp.MustCompile("[a-zA-Z\\d-]{1,63}$")

func isDomain(_ *SupportServices, value string) bool {

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

func isHostHeader(support *SupportServices, value string) bool {
	// "<host>:<port>", where <host> is a domain or IP address and ":<port>" is optional
	if strings.Contains(value, ":") {
		return isDialAddress(support, value)
	}
	return isIPAddress(support, value) || isDomain(support, value)
}

func isServerEntrySource(_ *SupportServices, value string) bool {
	return common.Contains(common.SupportedServerEntrySources, value)
}

var isISO8601DateRegex = regexp.MustCompile(
	"(?P<year>[0-9]{4})-(?P<month>[0-9]{1,2})-(?P<day>[0-9]{1,2})T(?P<hour>[0-9]{2}):(?P<minute>[0-9]{2}):(?P<second>[0-9]{2})(\\.(?P<fraction>[0-9]+))?(?P<timezone>Z|(([-+])([0-9]{2}):([0-9]{2})))")

func isISO8601Date(_ *SupportServices, value string) bool {
	return isISO8601DateRegex.Match([]byte(value))
}

func isLastConnected(support *SupportServices, value string) bool {
	return value == "None" || value == "Unknown" || isISO8601Date(support, value)
}
