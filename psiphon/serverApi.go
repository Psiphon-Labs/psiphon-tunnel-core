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
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/buildinfo"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tactics"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/transferstats"
)

// ServerContext is a utility struct which holds all of the data associated
// with a Psiphon server connection. In addition to the established tunnel, this
// includes data and transport mechanisms for Psiphon API requests. Legacy servers
// offer the Psiphon API through a web service; newer servers offer the Psiphon
// API through SSH requests made directly through the tunnel's SSH client.
type ServerContext struct {
	tunnel                   *Tunnel
	psiphonHttpsClient       *http.Client
	statsRegexps             *transferstats.Regexps
	clientRegion             string
	clientUpgradeVersion     string
	serverHandshakeTimestamp string
	paddingPRNG              *prng.PRNG
}

// MakeSessionId creates a new session ID. The same session ID is used across
// multi-tunnel controller runs, where each tunnel has its own ServerContext
// instance.
// In server-side stats, we now consider a "session" to be the lifetime of the
// Controller (e.g., the user's commanded start and stop) and we measure this
// duration as well as the duration of each tunnel within the session.
func MakeSessionId() (string, error) {
	randomId, err := common.MakeSecureRandomBytes(protocol.PSIPHON_API_CLIENT_SESSION_ID_LENGTH)
	if err != nil {
		return "", errors.Trace(err)
	}
	return hex.EncodeToString(randomId), nil
}

// NewServerContext makes the tunneled handshake request to the Psiphon server
// and returns a ServerContext struct for use with subsequent Psiphon server API
// requests (e.g., periodic connected and status requests).
func NewServerContext(tunnel *Tunnel) (*ServerContext, error) {

	// For legacy servers, set up psiphonHttpsClient for
	// accessing the Psiphon API via the web service.
	var psiphonHttpsClient *http.Client
	if !tunnel.dialParams.ServerEntry.SupportsSSHAPIRequests() ||
		tunnel.config.TargetApiProtocol == protocol.PSIPHON_WEB_API_PROTOCOL {

		var err error
		psiphonHttpsClient, err = makePsiphonHttpsClient(tunnel)
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	serverContext := &ServerContext{
		tunnel:             tunnel,
		psiphonHttpsClient: psiphonHttpsClient,
		paddingPRNG:        prng.NewPRNGWithSeed(tunnel.dialParams.APIRequestPaddingSeed),
	}

	ignoreRegexps := tunnel.config.GetClientParameters().Get().Bool(
		parameters.IgnoreHandshakeStatsRegexps)

	err := serverContext.doHandshakeRequest(ignoreRegexps)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return serverContext, nil
}

// doHandshakeRequest performs the "handshake" API request. The handshake
// returns upgrade info, newly discovered server entries -- which are
// stored -- and sponsor info (home pages, stat regexes).
func (serverContext *ServerContext) doHandshakeRequest(
	ignoreStatsRegexps bool) error {

	params := serverContext.getBaseAPIParameters()

	// The server will return a signed copy of its own server entry when the
	// client specifies this 'missing_server_entry_signature' parameter.
	//
	// The purpose of this mechanism is to rapidly upgrade client local storage
	// from unsigned to signed server entries, and to ensure that the client has
	// a signed server entry for its currently connected server as required for
	// the client-to-client exchange feature.
	//
	// The server entry will be included in handshakeResponse.EncodedServerList,
	// along side discovery servers.
	requestedMissingSignature := false
	if !serverContext.tunnel.dialParams.ServerEntry.HasSignature() {
		requestedMissingSignature = true
		params["missing_server_entry_signature"] =
			serverContext.tunnel.dialParams.ServerEntry.Tag
	}

	doTactics := !serverContext.tunnel.config.DisableTactics

	networkID := ""
	if doTactics {

		// Limitation: it is assumed that the network ID obtained here is the
		// one that is active when the handshake request is received by the
		// server. However, it is remotely possible to switch networks
		// immediately after invoking the GetNetworkID callback and initiating
		// the handshake, if the tunnel protocol is meek.
		//
		// The response handling code below calls GetNetworkID again and ignores
		// any tactics payload if the network ID is not the same. While this
		// doesn't detect all cases of changing networks, it reduces the already
		// narrow window.

		networkID = serverContext.tunnel.config.GetNetworkID()

		err := tactics.SetTacticsAPIParameters(
			serverContext.tunnel.config.clientParameters, GetTacticsStorer(), networkID, params)
		if err != nil {
			return errors.Trace(err)
		}
	}

	var response []byte
	if serverContext.psiphonHttpsClient == nil {

		params[protocol.PSIPHON_API_HANDSHAKE_AUTHORIZATIONS] =
			serverContext.tunnel.config.GetAuthorizations()

		request, err := serverContext.makeSSHAPIRequestPayload(params)
		if err != nil {
			return errors.Trace(err)
		}

		response, err = serverContext.tunnel.SendAPIRequest(
			protocol.PSIPHON_API_HANDSHAKE_REQUEST_NAME, request)
		if err != nil {
			return errors.Trace(err)
		}

	} else {

		// Legacy web service API request

		responseBody, err := serverContext.doGetRequest(
			makeRequestUrl(serverContext.tunnel, "", "handshake", params))
		if err != nil {
			return errors.Trace(err)
		}
		// Skip legacy format lines and just parse the JSON config line
		configLinePrefix := []byte("Config: ")
		for _, line := range bytes.Split(responseBody, []byte("\n")) {
			if bytes.HasPrefix(line, configLinePrefix) {
				response = line[len(configLinePrefix):]
				break
			}
		}
		if len(response) == 0 {
			return errors.TraceNew("no config line found")
		}
	}

	// Legacy fields:
	// - 'preemptive_reconnect_lifetime_milliseconds' is unused and ignored
	// - 'ssh_session_id' is ignored; client session ID is used instead

	var handshakeResponse protocol.HandshakeResponse

	// Initialize these fields to distinguish between psiphond omitting values in
	// the response and the zero value, which means unlimited rate.
	handshakeResponse.UpstreamBytesPerSecond = -1
	handshakeResponse.DownstreamBytesPerSecond = -1

	err := json.Unmarshal(response, &handshakeResponse)
	if err != nil {
		return errors.Trace(err)
	}

	serverContext.clientRegion = handshakeResponse.ClientRegion
	NoticeClientRegion(serverContext.clientRegion)

	var serverEntries []protocol.ServerEntryFields

	// Store discovered server entries
	// We use the server's time, as it's available here, for the server entry
	// timestamp since this is more reliable than the client time.
	for _, encodedServerEntry := range handshakeResponse.EncodedServerList {

		serverEntryFields, err := protocol.DecodeServerEntryFields(
			encodedServerEntry,
			common.TruncateTimestampToHour(handshakeResponse.ServerTimestamp),
			protocol.SERVER_ENTRY_SOURCE_DISCOVERY)
		if err != nil {
			return errors.Trace(err)
		}

		// Retain the original timestamp and source in the requestedMissingSignature
		// case, as this server entry was not discovered here.
		//
		// Limitation: there is a transient edge case where
		// requestedMissingSignature will be set for a discovery server entry that
		// _is_ also discovered here.
		if requestedMissingSignature &&
			serverEntryFields.GetIPAddress() == serverContext.tunnel.dialParams.ServerEntry.IpAddress {

			serverEntryFields.SetLocalTimestamp(serverContext.tunnel.dialParams.ServerEntry.LocalTimestamp)
			serverEntryFields.SetLocalSource(serverContext.tunnel.dialParams.ServerEntry.LocalSource)
		}

		err = protocol.ValidateServerEntryFields(serverEntryFields)
		if err != nil {
			// Skip this entry and continue with the next one
			NoticeWarning("invalid handshake server entry: %s", err)
			continue
		}

		serverEntries = append(serverEntries, serverEntryFields)
	}

	err = StoreServerEntries(
		serverContext.tunnel.config,
		serverEntries,
		true)
	if err != nil {
		return errors.Trace(err)
	}

	NoticeHomepages(handshakeResponse.Homepages)

	serverContext.clientUpgradeVersion = handshakeResponse.UpgradeClientVersion
	if handshakeResponse.UpgradeClientVersion != "" {
		NoticeClientUpgradeAvailable(handshakeResponse.UpgradeClientVersion)
	} else {
		NoticeClientIsLatestVersion("")
	}

	if !ignoreStatsRegexps {

		var regexpsNotices []string
		serverContext.statsRegexps, regexpsNotices = transferstats.MakeRegexps(
			handshakeResponse.PageViewRegexes,
			handshakeResponse.HttpsRequestRegexes)

		for _, notice := range regexpsNotices {
			NoticeWarning(notice)
		}
	}

	serverContext.serverHandshakeTimestamp = handshakeResponse.ServerTimestamp
	NoticeServerTimestamp(serverContext.serverHandshakeTimestamp)

	NoticeActiveAuthorizationIDs(handshakeResponse.ActiveAuthorizationIDs)

	NoticeTrafficRateLimits(
		handshakeResponse.UpstreamBytesPerSecond, handshakeResponse.DownstreamBytesPerSecond)

	if doTactics && handshakeResponse.TacticsPayload != nil &&
		networkID == serverContext.tunnel.config.GetNetworkID() {

		var payload *tactics.Payload
		err := json.Unmarshal(handshakeResponse.TacticsPayload, &payload)
		if err != nil {
			return errors.Trace(err)
		}

		// handshakeResponse.TacticsPayload may be "null", and payload
		// will successfully unmarshal as nil. As a result, the previous
		// handshakeResponse.TacticsPayload != nil test is insufficient.
		if payload != nil {

			tacticsRecord, err := tactics.HandleTacticsPayload(
				GetTacticsStorer(),
				networkID,
				payload)
			if err != nil {
				return errors.Trace(err)
			}

			if tacticsRecord != nil &&
				prng.FlipWeightedCoin(tacticsRecord.Tactics.Probability) {

				err := serverContext.tunnel.config.SetClientParameters(
					tacticsRecord.Tag, true, tacticsRecord.Tactics.Parameters)
				if err != nil {
					NoticeInfo("apply handshake tactics failed: %s", err)
				}
				// The error will be due to invalid tactics values from
				// the server. When ApplyClientParameters fails, all
				// previous tactics values are left in place.
			}
		}
	}

	return nil
}

// DoConnectedRequest performs the "connected" API request. This request is
// used for statistics. The server returns a last_connected token for
// the client to store and send next time it connects. This token is
// a timestamp (using the server clock, and should be rounded to the
// nearest hour) which is used to determine when a connection represents
// a unique user for a time period.
func (serverContext *ServerContext) DoConnectedRequest() error {

	params := serverContext.getBaseAPIParameters()

	lastConnected, err := getLastConnected()
	if err != nil {
		return errors.Trace(err)
	}

	params["last_connected"] = lastConnected

	// serverContext.tunnel.establishDuration is nanoseconds; divide to get to milliseconds
	params["establishment_duration"] =
		fmt.Sprintf("%d", serverContext.tunnel.establishDuration/1000000)

	var response []byte
	if serverContext.psiphonHttpsClient == nil {

		request, err := serverContext.makeSSHAPIRequestPayload(params)
		if err != nil {
			return errors.Trace(err)
		}

		response, err = serverContext.tunnel.SendAPIRequest(
			protocol.PSIPHON_API_CONNECTED_REQUEST_NAME, request)
		if err != nil {
			return errors.Trace(err)
		}

	} else {

		// Legacy web service API request

		response, err = serverContext.doGetRequest(
			makeRequestUrl(serverContext.tunnel, "", "connected", params))
		if err != nil {
			return errors.Trace(err)
		}
	}

	var connectedResponse protocol.ConnectedResponse
	err = json.Unmarshal(response, &connectedResponse)
	if err != nil {
		return errors.Trace(err)
	}

	err = SetKeyValue(
		datastoreLastConnectedKey, connectedResponse.ConnectedTimestamp)
	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

func getLastConnected() (string, error) {
	lastConnected, err := GetKeyValue(datastoreLastConnectedKey)
	if err != nil {
		return "", errors.Trace(err)
	}
	if lastConnected == "" {
		lastConnected = "None"
	}
	return lastConnected, nil
}

// StatsRegexps gets the Regexps used for the statistics for this tunnel.
func (serverContext *ServerContext) StatsRegexps() *transferstats.Regexps {
	return serverContext.statsRegexps
}

// DoStatusRequest makes a "status" API request to the server, sending session stats.
func (serverContext *ServerContext) DoStatusRequest(tunnel *Tunnel) error {

	params := serverContext.getStatusParams(true)

	// Note: ensure putBackStatusRequestPayload is called, to replace
	// payload for future attempt, in all failure cases.

	statusPayload, statusPayloadInfo, err := makeStatusRequestPayload(
		serverContext.tunnel.config,
		tunnel.dialParams.ServerEntry.IpAddress)
	if err != nil {
		return errors.Trace(err)
	}

	// Skip the request when there's no payload to send.

	if len(statusPayload) == 0 {
		return nil
	}

	var response []byte

	if serverContext.psiphonHttpsClient == nil {

		rawMessage := json.RawMessage(statusPayload)
		params["statusData"] = &rawMessage

		var request []byte
		request, err = serverContext.makeSSHAPIRequestPayload(params)

		if err == nil {
			response, err = serverContext.tunnel.SendAPIRequest(
				protocol.PSIPHON_API_STATUS_REQUEST_NAME, request)
		}

	} else {

		// Legacy web service API request
		response, err = serverContext.doPostRequest(
			makeRequestUrl(serverContext.tunnel, "", "status", params),
			"application/json",
			bytes.NewReader(statusPayload))
	}

	if err != nil {

		// Resend the transfer stats and tunnel stats later
		// Note: potential duplicate reports if the server received and processed
		// the request but the client failed to receive the response.
		putBackStatusRequestPayload(statusPayloadInfo)

		return errors.Trace(err)
	}

	confirmStatusRequestPayload(statusPayloadInfo)

	var statusResponse protocol.StatusResponse
	err = json.Unmarshal(response, &statusResponse)
	if err != nil {
		return errors.Trace(err)
	}

	for _, serverEntryTag := range statusResponse.InvalidServerEntryTags {
		PruneServerEntry(serverContext.tunnel.config, serverEntryTag)
	}

	return nil
}

func (serverContext *ServerContext) getStatusParams(
	isTunneled bool) common.APIParameters {

	params := serverContext.getBaseAPIParameters()

	// Legacy clients set "connected" to "0" when disconnecting, and this value
	// is used to calculate session duration estimates. This is now superseded
	// by explicit tunnel stats duration reporting.
	// The legacy method of reconstructing session durations is not compatible
	// with this client's connected request retries and asynchronous final
	// status request attempts. So we simply set this "connected" flag to reflect
	// whether the request is sent tunneled or not.

	connected := "1"
	if !isTunneled {
		connected = "0"
	}
	params["connected"] = connected

	return params
}

// statusRequestPayloadInfo is a temporary structure for data used to
// either "clear" or "put back" status request payload data depending
// on whether or not the request succeeded.
type statusRequestPayloadInfo struct {
	serverId        string
	transferStats   *transferstats.AccumulatedStats
	persistentStats map[string][][]byte
}

func makeStatusRequestPayload(
	config *Config,
	serverId string) ([]byte, *statusRequestPayloadInfo, error) {

	transferStats := transferstats.TakeOutStatsForServer(serverId)
	hostBytes := transferStats.GetStatsForStatusRequest()

	persistentStats, err := TakeOutUnreportedPersistentStats(config)
	if err != nil {
		NoticeWarning(
			"TakeOutUnreportedPersistentStats failed: %s", errors.Trace(err))
		persistentStats = nil
		// Proceed with transferStats only
	}

	if len(hostBytes) == 0 && len(persistentStats) == 0 {
		// There is no payload to send.
		return nil, nil, nil
	}

	payloadInfo := &statusRequestPayloadInfo{
		serverId, transferStats, persistentStats}

	payload := make(map[string]interface{})

	payload["host_bytes"] = hostBytes

	// We're not recording these fields, but legacy servers require them.
	payload["bytes_transferred"] = 0
	payload["page_views"] = make([]string, 0)
	payload["https_requests"] = make([]string, 0)

	persistentStatPayloadNames := make(map[string]string)
	persistentStatPayloadNames[datastorePersistentStatTypeRemoteServerList] = "remote_server_list_stats"
	persistentStatPayloadNames[datastorePersistentStatTypeFailedTunnel] = "failed_tunnel_stats"

	for statType, stats := range persistentStats {

		// Persistent stats records are already in JSON format
		jsonStats := make([]json.RawMessage, len(stats))
		for i, stat := range stats {
			jsonStats[i] = json.RawMessage(stat)
		}
		payload[persistentStatPayloadNames[statType]] = jsonStats
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {

		// Send the transfer stats and tunnel stats later
		putBackStatusRequestPayload(payloadInfo)

		return nil, nil, errors.Trace(err)
	}

	return jsonPayload, payloadInfo, nil
}

func putBackStatusRequestPayload(payloadInfo *statusRequestPayloadInfo) {
	transferstats.PutBackStatsForServer(
		payloadInfo.serverId, payloadInfo.transferStats)
	err := PutBackUnreportedPersistentStats(payloadInfo.persistentStats)
	if err != nil {
		// These persistent stats records won't be resent until after a
		// datastore re-initialization.
		NoticeWarning(
			"PutBackUnreportedPersistentStats failed: %s", errors.Trace(err))
	}
}

func confirmStatusRequestPayload(payloadInfo *statusRequestPayloadInfo) {
	err := ClearReportedPersistentStats(payloadInfo.persistentStats)
	if err != nil {
		// These persistent stats records may be resent.
		NoticeWarning(
			"ClearReportedPersistentStats failed: %s", errors.Trace(err))
	}
}

// RecordRemoteServerListStat records a completed common or OSL
// remote server list resource download.
//
// The RSL download event could occur when the client is unable
// to immediately send a status request to a server, so these
// records are stored in the persistent datastore and reported
// via subsequent status requests sent to any Psiphon server.
//
// Note that some common event field values may change between the
// stat recording and reporting, including client geolocation and
// host_id.
//
// Multiple "status" requests may be in flight at once (due
// to multi-tunnel, asynchronous final status retry, and
// aggressive status requests for pre-registered tunnels),
// To avoid duplicate reporting, persistent stats records are
// "taken-out" by a status request and then "put back" in
// case the request fails.
//
// Duplicate reporting may also occur when a server receives and
// processes a status request but the client fails to receive
// the response.
func RecordRemoteServerListStat(
	config *Config,
	tunneled bool,
	url string,
	etag string,
	authenticated bool) error {

	if !config.GetClientParameters().Get().WeightedCoinFlip(
		parameters.RecordRemoteServerListPersistentStatsProbability) {
		return nil
	}

	params := make(common.APIParameters)

	params["session_id"] = config.SessionID
	params["propagation_channel_id"] = config.PropagationChannelId
	params["sponsor_id"] = config.GetSponsorID()
	params["client_version"] = config.ClientVersion
	params["client_platform"] = config.ClientPlatform
	params["client_build_rev"] = buildinfo.GetBuildInfo().BuildRev
	if config.DeviceRegion != "" {
		params["device_region"] = config.DeviceRegion
	}

	params["client_download_timestamp"] = common.TruncateTimestampToHour(common.GetCurrentTimestamp())
	tunneledStr := "0"
	if tunneled {
		tunneledStr = "1"
	}
	params["tunneled"] = tunneledStr
	params["url"] = url
	params["etag"] = etag
	authenticatedStr := "0"
	if authenticated {
		authenticatedStr = "1"
	}
	params["authenticated"] = authenticatedStr

	remoteServerListStatJson, err := json.Marshal(params)
	if err != nil {
		return errors.Trace(err)
	}

	return StorePersistentStat(
		config, datastorePersistentStatTypeRemoteServerList, remoteServerListStatJson)
}

// RecordFailedTunnelStat records metrics for a failed tunnel dial, including
// dial parameters and error condition (tunnelErr).
//
// This uses the same reporting facility, with the same caveats, as
// RecordRemoteServerListStat.
func RecordFailedTunnelStat(
	config *Config,
	dialParams *DialParameters,
	livenessTestMetrics *livenessTestMetrics,
	bytesUp int64,
	bytesDown int64,
	tunnelErr error) error {

	if !config.GetClientParameters().Get().WeightedCoinFlip(
		parameters.RecordFailedTunnelPersistentStatsProbability) {
		return nil
	}

	lastConnected, err := getLastConnected()
	if err != nil {
		return errors.Trace(err)
	}

	params := getBaseAPIParameters(config, dialParams)

	delete(params, "server_secret")
	params["server_entry_tag"] = dialParams.ServerEntry.Tag
	params["last_connected"] = lastConnected
	params["client_failed_timestamp"] = common.TruncateTimestampToHour(common.GetCurrentTimestamp())
	if livenessTestMetrics != nil {
		params["liveness_test_upstream_bytes"] = strconv.Itoa(livenessTestMetrics.UpstreamBytes)
		params["liveness_test_sent_upstream_bytes"] = strconv.Itoa(livenessTestMetrics.SentUpstreamBytes)
		params["liveness_test_downstream_bytes"] = strconv.Itoa(livenessTestMetrics.DownstreamBytes)
		params["liveness_test_received_downstream_bytes"] = strconv.Itoa(livenessTestMetrics.ReceivedDownstreamBytes)
	}
	if bytesUp >= 0 {
		params["bytes_up"] = fmt.Sprintf("%d", bytesUp)
	}
	if bytesDown >= 0 {
		params["bytes_down"] = fmt.Sprintf("%d", bytesDown)
	}

	// Ensure direct server IPs are not exposed in logs. The "net" package, and
	// possibly other 3rd party packages, will include destination addresses in
	// I/O error messages.
	tunnelError := StripIPAddressesString(tunnelErr.Error())

	params["tunnel_error"] = tunnelError

	failedTunnelStatJson, err := json.Marshal(params)
	if err != nil {
		return errors.Trace(err)
	}

	return StorePersistentStat(
		config, datastorePersistentStatTypeFailedTunnel, failedTunnelStatJson)
}

// doGetRequest makes a tunneled HTTPS request and returns the response body.
func (serverContext *ServerContext) doGetRequest(
	requestUrl string) (responseBody []byte, err error) {

	request, err := http.NewRequest("GET", requestUrl, nil)
	if err != nil {
		return nil, errors.Trace(err)
	}

	request.Header.Set("User-Agent", MakePsiphonUserAgent(serverContext.tunnel.config))

	response, err := serverContext.psiphonHttpsClient.Do(request)
	if err == nil && response.StatusCode != http.StatusOK {
		response.Body.Close()
		err = fmt.Errorf("HTTP GET request failed with response code: %d", response.StatusCode)
	}
	if err != nil {
		// Trim this error since it may include long URLs
		return nil, errors.Trace(TrimError(err))
	}
	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, errors.Trace(err)
	}
	return body, nil
}

// doPostRequest makes a tunneled HTTPS POST request.
func (serverContext *ServerContext) doPostRequest(
	requestUrl string, bodyType string, body io.Reader) (responseBody []byte, err error) {

	request, err := http.NewRequest("POST", requestUrl, body)
	if err != nil {
		return nil, errors.Trace(err)
	}

	request.Header.Set("User-Agent", MakePsiphonUserAgent(serverContext.tunnel.config))
	request.Header.Set("Content-Type", bodyType)

	response, err := serverContext.psiphonHttpsClient.Do(request)
	if err == nil && response.StatusCode != http.StatusOK {
		response.Body.Close()
		err = fmt.Errorf("HTTP POST request failed with response code: %d", response.StatusCode)
	}
	if err != nil {
		// Trim this error since it may include long URLs
		return nil, errors.Trace(TrimError(err))
	}
	defer response.Body.Close()
	responseBody, err = ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, errors.Trace(err)
	}
	return responseBody, nil
}

// makeSSHAPIRequestPayload makes a JSON payload for an SSH API request.
func (serverContext *ServerContext) makeSSHAPIRequestPayload(
	params common.APIParameters) ([]byte, error) {
	jsonPayload, err := json.Marshal(params)
	if err != nil {
		return nil, errors.Trace(err)
	}
	return jsonPayload, nil
}

func (serverContext *ServerContext) getBaseAPIParameters() common.APIParameters {

	params := getBaseAPIParameters(
		serverContext.tunnel.config,
		serverContext.tunnel.dialParams)

	// Add a random amount of padding to defend against API call traffic size
	// fingerprints. The "pad_response" field instructs the server to pad its
	// response accordingly.

	p := serverContext.tunnel.config.GetClientParameters().Get()
	minUpstreamPadding := p.Int(parameters.APIRequestUpstreamPaddingMinBytes)
	maxUpstreamPadding := p.Int(parameters.APIRequestUpstreamPaddingMaxBytes)
	minDownstreamPadding := p.Int(parameters.APIRequestDownstreamPaddingMinBytes)
	maxDownstreamPadding := p.Int(parameters.APIRequestDownstreamPaddingMaxBytes)

	if maxUpstreamPadding > 0 {
		size := serverContext.paddingPRNG.Range(minUpstreamPadding, maxUpstreamPadding)
		params["padding"] = strings.Repeat(" ", size)
	}

	if maxDownstreamPadding > 0 {
		size := serverContext.paddingPRNG.Range(minDownstreamPadding, maxDownstreamPadding)
		params["pad_response"] = strconv.Itoa(size)
	}

	return params
}

// getBaseAPIParameters returns all the common API parameters that are
// included with each Psiphon API request. These common parameters are used
// for metrics.
func getBaseAPIParameters(
	config *Config,
	dialParams *DialParameters) common.APIParameters {

	params := make(common.APIParameters)

	params["session_id"] = config.SessionID
	params["client_session_id"] = config.SessionID
	params["server_secret"] = dialParams.ServerEntry.WebServerSecret
	params["propagation_channel_id"] = config.PropagationChannelId
	params["sponsor_id"] = config.GetSponsorID()
	params["client_version"] = config.ClientVersion
	params["relay_protocol"] = dialParams.TunnelProtocol
	params["client_platform"] = config.ClientPlatform
	params["client_build_rev"] = buildinfo.GetBuildInfo().BuildRev
	params["tunnel_whole_device"] = strconv.Itoa(config.TunnelWholeDevice)
	params["network_type"] = dialParams.GetNetworkType()

	// The following parameters may be blank and must
	// not be sent to the server if blank.

	if config.DeviceRegion != "" {
		params["device_region"] = config.DeviceRegion
	}

	if dialParams.BPFProgramName != "" {
		params["client_bpf"] = dialParams.BPFProgramName
	}

	if dialParams.SelectedSSHClientVersion {
		params["ssh_client_version"] = dialParams.SSHClientVersion
	}

	if dialParams.UpstreamProxyType != "" {
		params["upstream_proxy_type"] = dialParams.UpstreamProxyType
	}

	if dialParams.UpstreamProxyCustomHeaderNames != nil {
		params["upstream_proxy_custom_header_names"] = dialParams.UpstreamProxyCustomHeaderNames
	}

	if dialParams.FrontingProviderID != "" {
		params["fronting_provider_id"] = dialParams.FrontingProviderID
	}

	if dialParams.MeekDialAddress != "" {
		params["meek_dial_address"] = dialParams.MeekDialAddress
	}

	meekResolvedIPAddress := dialParams.MeekResolvedIPAddress.Load().(string)
	if meekResolvedIPAddress != "" {
		params["meek_resolved_ip_address"] = meekResolvedIPAddress
	}

	if dialParams.MeekSNIServerName != "" {
		params["meek_sni_server_name"] = dialParams.MeekSNIServerName
	}

	if dialParams.MeekHostHeader != "" {
		params["meek_host_header"] = dialParams.MeekHostHeader
	}

	// MeekTransformedHostName is meaningful when meek is used, which is when MeekDialAddress != ""
	if dialParams.MeekDialAddress != "" {
		transformedHostName := "0"
		if dialParams.MeekTransformedHostName {
			transformedHostName = "1"
		}
		params["meek_transformed_host_name"] = transformedHostName
	}

	if dialParams.SelectedUserAgent {
		params["user_agent"] = dialParams.UserAgent
	}

	if dialParams.SelectedTLSProfile {
		params["tls_profile"] = dialParams.TLSProfile
		params["tls_version"] = dialParams.GetTLSVersionForMetrics()
	}

	if dialParams.ServerEntry.Region != "" {
		params["server_entry_region"] = dialParams.ServerEntry.Region
	}

	if dialParams.ServerEntry.LocalSource != "" {
		params["server_entry_source"] = dialParams.ServerEntry.LocalSource
	}

	// As with last_connected, this timestamp stat, which may be
	// a precise handshake request server timestamp, is truncated
	// to hour granularity to avoid introducing a reconstructable
	// cross-session user trace into server logs.
	localServerEntryTimestamp := common.TruncateTimestampToHour(
		dialParams.ServerEntry.LocalTimestamp)
	if localServerEntryTimestamp != "" {
		params["server_entry_timestamp"] = localServerEntryTimestamp
	}

	params[tactics.APPLIED_TACTICS_TAG_PARAMETER_NAME] =
		config.GetClientParameters().Get().Tag()

	if dialParams.DialPortNumber != "" {
		params["dial_port_number"] = dialParams.DialPortNumber
	}

	if dialParams.QUICVersion != "" {
		params["quic_version"] = dialParams.QUICVersion
	}

	if dialParams.QUICDialSNIAddress != "" {
		params["quic_dial_sni_address"] = dialParams.QUICDialSNIAddress
	}

	isReplay := "0"
	if dialParams.IsReplay {
		isReplay = "1"
	}
	params["is_replay"] = isReplay

	if config.EgressRegion != "" {
		params["egress_region"] = config.EgressRegion
	}

	// dialParams.DialDuration is nanoseconds; divide to get to milliseconds
	params["dial_duration"] = fmt.Sprintf("%d", dialParams.DialDuration/1000000)

	params["candidate_number"] = strconv.Itoa(dialParams.CandidateNumber)

	params["established_tunnels_count"] = strconv.Itoa(dialParams.EstablishedTunnelsCount)

	if dialParams.NetworkLatencyMultiplier != 0.0 {
		params["network_latency_multiplier"] =
			fmt.Sprintf("%f", dialParams.NetworkLatencyMultiplier)
	}

	if dialParams.DialConnMetrics != nil {
		metrics := dialParams.DialConnMetrics.GetMetrics()
		for name, value := range metrics {
			params[name] = fmt.Sprintf("%v", value)
		}
	}

	if dialParams.ObfuscatedSSHConnMetrics != nil {
		metrics := dialParams.ObfuscatedSSHConnMetrics.GetMetrics()
		for name, value := range metrics {
			params[name] = fmt.Sprintf("%v", value)
		}
	}

	return params
}

// makeRequestUrl makes a URL for a web service API request.
func makeRequestUrl(tunnel *Tunnel, port, path string, params common.APIParameters) string {
	var requestUrl bytes.Buffer

	if port == "" {
		port = tunnel.dialParams.ServerEntry.WebServerPort
	}

	requestUrl.WriteString("https://")
	requestUrl.WriteString(tunnel.dialParams.ServerEntry.IpAddress)
	requestUrl.WriteString(":")
	requestUrl.WriteString(port)
	requestUrl.WriteString("/")
	requestUrl.WriteString(path)

	if len(params) > 0 {

		queryParams := url.Values{}

		for name, value := range params {

			// Note: this logic skips the tactics.SPEED_TEST_SAMPLES_PARAMETER_NAME
			// parameter, which has a different type. This parameter is not recognized
			// by legacy servers.

			switch v := value.(type) {
			case string:
				queryParams.Set(name, v)
			case []string:
				// String array param encoded as JSON
				jsonValue, err := json.Marshal(v)
				if err != nil {
					break
				}
				queryParams.Set(name, string(jsonValue))
			}
		}

		requestUrl.WriteString("?")
		requestUrl.WriteString(queryParams.Encode())
	}

	return requestUrl.String()
}

// makePsiphonHttpsClient creates a Psiphon HTTPS client that tunnels web service API
// requests and which validates the web server using the Psiphon server entry web server
// certificate.
func makePsiphonHttpsClient(tunnel *Tunnel) (httpsClient *http.Client, err error) {

	certificate, err := DecodeCertificate(
		tunnel.dialParams.ServerEntry.WebServerCertificate)
	if err != nil {
		return nil, errors.Trace(err)
	}

	tunneledDialer := func(_ context.Context, _, addr string) (conn net.Conn, err error) {
		return tunnel.sshClient.Dial("tcp", addr)
	}

	// Note: as with SSH API requests, there no dial context here. SSH port forward dials
	// cannot be interrupted directly. Closing the tunnel will interrupt both the dial and
	// the request. While it's possible to add a timeout here, we leave it with no explicit
	// timeout which is the same as SSH API requests: if the tunnel has stalled then SSH keep
	// alives will cause the tunnel to close.

	dialer := NewCustomTLSDialer(
		&CustomTLSConfig{
			ClientParameters:        tunnel.config.clientParameters,
			Dial:                    tunneledDialer,
			VerifyLegacyCertificate: certificate,
		})

	transport := &http.Transport{
		DialTLS: func(network, addr string) (net.Conn, error) {
			return dialer(context.Background(), network, addr)
		},
		Dial: func(network, addr string) (net.Conn, error) {
			return nil, errors.TraceNew("HTTP not supported")
		},
	}

	return &http.Client{
		Transport: transport,
	}, nil
}

func HandleServerRequest(
	tunnelOwner TunnelOwner, tunnel *Tunnel, name string, payload []byte) error {

	switch name {
	case protocol.PSIPHON_API_OSL_REQUEST_NAME:
		return HandleOSLRequest(tunnelOwner, tunnel, payload)
	case protocol.PSIPHON_API_ALERT_REQUEST_NAME:
		return HandleAlertRequest(tunnelOwner, tunnel, payload)
	}

	return errors.Tracef("invalid request name: %s", name)
}

func HandleOSLRequest(
	tunnelOwner TunnelOwner, tunnel *Tunnel, payload []byte) error {

	var oslRequest protocol.OSLRequest
	err := json.Unmarshal(payload, &oslRequest)
	if err != nil {
		return errors.Trace(err)
	}

	if oslRequest.ClearLocalSLOKs {
		DeleteSLOKs()
	}

	seededNewSLOK := false

	for _, slok := range oslRequest.SeedPayload.SLOKs {
		duplicate, err := SetSLOK(slok.ID, slok.Key)
		if err != nil {
			// TODO: return error to trigger retry?
			NoticeWarning("SetSLOK failed: %s", errors.Trace(err))
		} else if !duplicate {
			seededNewSLOK = true
		}

		if tunnel.config.EmitSLOKs {
			NoticeSLOKSeeded(base64.StdEncoding.EncodeToString(slok.ID), duplicate)
		}
	}

	if seededNewSLOK {
		tunnelOwner.SignalSeededNewSLOK()
	}

	return nil
}

func HandleAlertRequest(
	tunnelOwner TunnelOwner, tunnel *Tunnel, payload []byte) error {

	var alertRequest protocol.AlertRequest
	err := json.Unmarshal(payload, &alertRequest)
	if err != nil {
		return errors.Trace(err)
	}

	if tunnel.config.EmitServerAlerts {
		NoticeServerAlert(alertRequest)
	}

	return nil
}
