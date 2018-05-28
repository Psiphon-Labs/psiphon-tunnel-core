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
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync/atomic"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
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
	// Note: 64-bit ints used with atomic operations are placed
	// at the start of struct to ensure 64-bit alignment.
	// (https://golang.org/pkg/sync/atomic/#pkg-note-BUG)
	tunnelNumber             int64
	sessionId                string
	tunnel                   *Tunnel
	psiphonHttpsClient       *http.Client
	statsRegexps             *transferstats.Regexps
	clientRegion             string
	clientUpgradeVersion     string
	serverHandshakeTimestamp string
}

// nextTunnelNumber is a monotonically increasing number assigned to each
// successive tunnel connection. The sessionId and tunnelNumber together
// form a globally unique identifier for tunnels, which is used for
// stats. Note that the number is increasing but not necessarily
// consecutive for each active tunnel in session.
var nextTunnelNumber int64

// MakeSessionId creates a new session ID. The same session ID is used across
// multi-tunnel controller runs, where each tunnel has its own ServerContext
// instance.
// In server-side stats, we now consider a "session" to be the lifetime of the
// Controller (e.g., the user's commanded start and stop) and we measure this
// duration as well as the duration of each tunnel within the session.
func MakeSessionId() (sessionId string, err error) {
	randomId, err := common.MakeSecureRandomBytes(protocol.PSIPHON_API_CLIENT_SESSION_ID_LENGTH)
	if err != nil {
		return "", common.ContextError(err)
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
	if !tunnel.serverEntry.SupportsSSHAPIRequests() ||
		tunnel.config.TargetApiProtocol == protocol.PSIPHON_WEB_API_PROTOCOL {

		var err error
		psiphonHttpsClient, err = makePsiphonHttpsClient(tunnel)
		if err != nil {
			return nil, common.ContextError(err)
		}
	}

	serverContext := &ServerContext{
		sessionId:          tunnel.sessionId,
		tunnelNumber:       atomic.AddInt64(&nextTunnelNumber, 1),
		tunnel:             tunnel,
		psiphonHttpsClient: psiphonHttpsClient,
	}

	ignoreRegexps := tunnel.config.clientParameters.Get().Bool(parameters.IgnoreHandshakeStatsRegexps)

	err := serverContext.doHandshakeRequest(ignoreRegexps)
	if err != nil {
		return nil, common.ContextError(err)
	}

	return serverContext, nil
}

// doHandshakeRequest performs the "handshake" API request. The handshake
// returns upgrade info, newly discovered server entries -- which are
// stored -- and sponsor info (home pages, stat regexes).
func (serverContext *ServerContext) doHandshakeRequest(
	ignoreStatsRegexps bool) error {

	params := serverContext.getBaseAPIParameters()

	doTactics := !serverContext.tunnel.config.DisableTactics &&
		serverContext.tunnel.config.networkIDGetter != nil

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

		networkID = serverContext.tunnel.config.networkIDGetter.GetNetworkID()

		err := tactics.SetTacticsAPIParameters(
			serverContext.tunnel.config.clientParameters, GetTacticsStorer(), networkID, params)
		if err != nil {
			return common.ContextError(err)
		}
	}

	var response []byte
	if serverContext.psiphonHttpsClient == nil {

		params[protocol.PSIPHON_API_HANDSHAKE_AUTHORIZATIONS] = serverContext.tunnel.config.Authorizations

		request, err := makeSSHAPIRequestPayload(params)
		if err != nil {
			return common.ContextError(err)
		}

		response, err = serverContext.tunnel.SendAPIRequest(
			protocol.PSIPHON_API_HANDSHAKE_REQUEST_NAME, request)
		if err != nil {
			return common.ContextError(err)
		}

	} else {

		// Legacy web service API request

		responseBody, err := serverContext.doGetRequest(
			makeRequestUrl(serverContext.tunnel, "", "handshake", params))
		if err != nil {
			return common.ContextError(err)
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
			return common.ContextError(errors.New("no config line found"))
		}
	}

	// Legacy fields:
	// - 'preemptive_reconnect_lifetime_milliseconds' is unused and ignored
	// - 'ssh_session_id' is ignored; client session ID is used instead

	var handshakeResponse protocol.HandshakeResponse
	err := json.Unmarshal(response, &handshakeResponse)
	if err != nil {
		return common.ContextError(err)
	}

	serverContext.clientRegion = handshakeResponse.ClientRegion
	NoticeClientRegion(serverContext.clientRegion)

	var decodedServerEntries []*protocol.ServerEntry

	// Store discovered server entries
	// We use the server's time, as it's available here, for the server entry
	// timestamp since this is more reliable than the client time.
	for _, encodedServerEntry := range handshakeResponse.EncodedServerList {

		serverEntry, err := protocol.DecodeServerEntry(
			encodedServerEntry,
			common.TruncateTimestampToHour(handshakeResponse.ServerTimestamp),
			protocol.SERVER_ENTRY_SOURCE_DISCOVERY)
		if err != nil {
			return common.ContextError(err)
		}

		err = protocol.ValidateServerEntry(serverEntry)
		if err != nil {
			// Skip this entry and continue with the next one
			NoticeAlert("invalid handshake server entry: %s", err)
			continue
		}

		decodedServerEntries = append(decodedServerEntries, serverEntry)
	}

	// The reason we are storing the entire array of server entries at once rather
	// than one at a time is that some desirable side-effects get triggered by
	// StoreServerEntries that don't get triggered by StoreServerEntry.
	err = StoreServerEntries(
		serverContext.tunnel.config,
		decodedServerEntries,
		true)
	if err != nil {
		return common.ContextError(err)
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
			NoticeAlert(notice)
		}
	}

	serverContext.serverHandshakeTimestamp = handshakeResponse.ServerTimestamp
	NoticeServerTimestamp(serverContext.serverHandshakeTimestamp)

	NoticeActiveAuthorizationIDs(handshakeResponse.ActiveAuthorizationIDs)

	if doTactics && handshakeResponse.TacticsPayload != nil &&
		networkID == serverContext.tunnel.config.networkIDGetter.GetNetworkID() {

		var payload *tactics.Payload
		err := json.Unmarshal(handshakeResponse.TacticsPayload, &payload)
		if err != nil {
			return common.ContextError(err)
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
				return common.ContextError(err)
			}

			if tacticsRecord != nil &&
				common.FlipWeightedCoin(tacticsRecord.Tactics.Probability) {

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

	lastConnected, err := GetKeyValue(DATA_STORE_LAST_CONNECTED_KEY)
	if err != nil {
		return common.ContextError(err)
	}
	if lastConnected == "" {
		lastConnected = "None"
	}

	params["last_connected"] = lastConnected

	// serverContext.tunnel.establishDuration is nanoseconds; divide to get to milliseconds
	params["establishment_duration"] =
		fmt.Sprintf("%d", serverContext.tunnel.establishDuration/1000000)

	var response []byte
	if serverContext.psiphonHttpsClient == nil {

		request, err := makeSSHAPIRequestPayload(params)
		if err != nil {
			return common.ContextError(err)
		}

		response, err = serverContext.tunnel.SendAPIRequest(
			protocol.PSIPHON_API_CONNECTED_REQUEST_NAME, request)
		if err != nil {
			return common.ContextError(err)
		}

	} else {

		// Legacy web service API request

		response, err = serverContext.doGetRequest(
			makeRequestUrl(serverContext.tunnel, "", "connected", params))
		if err != nil {
			return common.ContextError(err)
		}
	}

	var connectedResponse protocol.ConnectedResponse
	err = json.Unmarshal(response, &connectedResponse)
	if err != nil {
		return common.ContextError(err)
	}

	err = SetKeyValue(
		DATA_STORE_LAST_CONNECTED_KEY, connectedResponse.ConnectedTimestamp)
	if err != nil {
		return common.ContextError(err)
	}

	return nil
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
		serverContext.tunnel.config.clientParameters,
		tunnel.serverEntry.IpAddress)
	if err != nil {
		return common.ContextError(err)
	}

	// Skip the request when there's no payload to send.

	if len(statusPayload) == 0 {
		return nil
	}

	if serverContext.psiphonHttpsClient == nil {

		rawMessage := json.RawMessage(statusPayload)
		params["statusData"] = &rawMessage

		var request []byte
		request, err = makeSSHAPIRequestPayload(params)

		if err == nil {
			_, err = serverContext.tunnel.SendAPIRequest(
				protocol.PSIPHON_API_STATUS_REQUEST_NAME, request)
		}

	} else {

		// Legacy web service API request
		_, err = serverContext.doPostRequest(
			makeRequestUrl(serverContext.tunnel, "", "status", params),
			"application/json",
			bytes.NewReader(statusPayload))
	}

	if err != nil {

		// Resend the transfer stats and tunnel stats later
		// Note: potential duplicate reports if the server received and processed
		// the request but the client failed to receive the response.
		putBackStatusRequestPayload(statusPayloadInfo)

		return common.ContextError(err)
	}

	confirmStatusRequestPayload(statusPayloadInfo)

	return nil
}

func (serverContext *ServerContext) getStatusParams(
	isTunneled bool) common.APIParameters {

	params := serverContext.getBaseAPIParameters()

	// Add a random amount of padding to help prevent stats updates from being
	// a predictable size (which often happens when the connection is quiet).
	// TODO: base64 encoding of padding means the padding size is not exactly
	// [PADDING_MIN_BYTES, PADDING_MAX_BYTES].

	p := serverContext.tunnel.config.clientParameters.Get()
	randomPadding, err := common.MakeSecureRandomPadding(
		p.Int(parameters.PsiphonAPIStatusRequestPaddingMinBytes),
		p.Int(parameters.PsiphonAPIStatusRequestPaddingMaxBytes))
	p = nil
	if err != nil {
		NoticeAlert("MakeSecureRandomPadding failed: %s", common.ContextError(err))
		// Proceed without random padding
		randomPadding = make([]byte, 0)
	}
	params["padding"] = base64.StdEncoding.EncodeToString(randomPadding)

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
	clientParameters *parameters.ClientParameters,
	serverId string) ([]byte, *statusRequestPayloadInfo, error) {

	transferStats := transferstats.TakeOutStatsForServer(serverId)
	hostBytes := transferStats.GetStatsForStatusRequest()

	maxCount := clientParameters.Get().Int(parameters.PsiphonAPIPersistentStatsMaxCount)

	persistentStats, err := TakeOutUnreportedPersistentStats(maxCount)
	if err != nil {
		NoticeAlert(
			"TakeOutUnreportedPersistentStats failed: %s", common.ContextError(err))
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
	persistentStatPayloadNames[PERSISTENT_STAT_TYPE_REMOTE_SERVER_LIST] = "remote_server_list_stats"

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

		return nil, nil, common.ContextError(err)
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
		NoticeAlert(
			"PutBackUnreportedPersistentStats failed: %s", common.ContextError(err))
	}
}

func confirmStatusRequestPayload(payloadInfo *statusRequestPayloadInfo) {
	err := ClearReportedPersistentStats(payloadInfo.persistentStats)
	if err != nil {
		// These persistent stats records may be resent.
		NoticeAlert(
			"ClearReportedPersistentStats failed: %s", common.ContextError(err))
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
// Note that common event field values may change between the
// stat recording and reporting include client geo data,
// propagation channel, sponsor ID, client version. These are not
// stored in the datastore (client region, in particular, since
// that would create an on-disk record of user location).
// TODO: the server could encrypt, with a nonce and key unknown to
// the client, a blob containing this data; return it in the
// handshake response; and the client could store and later report
// this blob with its tunnel stats records.
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
	url, etag string) error {

	remoteServerListStat := struct {
		ClientDownloadTimestamp string `json:"client_download_timestamp"`
		URL                     string `json:"url"`
		ETag                    string `json:"etag"`
	}{
		common.TruncateTimestampToHour(common.GetCurrentTimestamp()),
		url,
		etag,
	}

	remoteServerListStatJson, err := json.Marshal(remoteServerListStat)
	if err != nil {
		return common.ContextError(err)
	}

	return StorePersistentStat(
		PERSISTENT_STAT_TYPE_REMOTE_SERVER_LIST, remoteServerListStatJson)
}

// doGetRequest makes a tunneled HTTPS request and returns the response body.
func (serverContext *ServerContext) doGetRequest(
	requestUrl string) (responseBody []byte, err error) {

	request, err := http.NewRequest("GET", requestUrl, nil)
	if err != nil {
		return nil, common.ContextError(err)
	}

	request.Header.Set("User-Agent", MakePsiphonUserAgent(serverContext.tunnel.config))

	response, err := serverContext.psiphonHttpsClient.Do(request)
	if err == nil && response.StatusCode != http.StatusOK {
		response.Body.Close()
		err = fmt.Errorf("HTTP GET request failed with response code: %d", response.StatusCode)
	}
	if err != nil {
		// Trim this error since it may include long URLs
		return nil, common.ContextError(TrimError(err))
	}
	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, common.ContextError(err)
	}
	return body, nil
}

// doPostRequest makes a tunneled HTTPS POST request.
func (serverContext *ServerContext) doPostRequest(
	requestUrl string, bodyType string, body io.Reader) (responseBody []byte, err error) {

	request, err := http.NewRequest("POST", requestUrl, body)
	if err != nil {
		return nil, common.ContextError(err)
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
		return nil, common.ContextError(TrimError(err))
	}
	defer response.Body.Close()
	responseBody, err = ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, common.ContextError(err)
	}
	return responseBody, nil
}

func (serverContext *ServerContext) getBaseAPIParameters() common.APIParameters {
	return getBaseAPIParameters(
		serverContext.tunnel.config,
		serverContext.sessionId,
		serverContext.tunnel.serverEntry,
		serverContext.tunnel.protocol,
		serverContext.tunnel.dialStats)
}

// getBaseAPIParameters returns all the common API parameters that are
// included with each Psiphon API request. These common parameters are used
// for metrics.
func getBaseAPIParameters(
	config *Config,
	sessionID string,
	serverEntry *protocol.ServerEntry,
	protocol string,
	dialStats *DialStats) common.APIParameters {

	params := make(common.APIParameters)

	params["session_id"] = sessionID
	params["client_session_id"] = sessionID
	params["server_secret"] = serverEntry.WebServerSecret
	params["propagation_channel_id"] = config.PropagationChannelId
	params["sponsor_id"] = config.SponsorId
	params["client_version"] = config.ClientVersion
	params["relay_protocol"] = protocol
	params["client_platform"] = config.ClientPlatform
	params["client_build_rev"] = common.GetBuildInfo().BuildRev
	params["tunnel_whole_device"] = strconv.Itoa(config.TunnelWholeDevice)

	// The following parameters may be blank and must
	// not be sent to the server if blank.

	if config.DeviceRegion != "" {
		params["device_region"] = config.DeviceRegion
	}

	if dialStats.SelectedSSHClientVersion {
		params["ssh_client_version"] = dialStats.SSHClientVersion
	}

	if dialStats.UpstreamProxyType != "" {
		params["upstream_proxy_type"] = dialStats.UpstreamProxyType
	}

	if dialStats.UpstreamProxyCustomHeaderNames != nil {
		params["upstream_proxy_custom_header_names"] = dialStats.UpstreamProxyCustomHeaderNames
	}

	if dialStats.MeekDialAddress != "" {
		params["meek_dial_address"] = dialStats.MeekDialAddress
	}

	meekResolvedIPAddress := dialStats.MeekResolvedIPAddress.Load().(string)
	if meekResolvedIPAddress != "" {
		params["meek_resolved_ip_address"] = meekResolvedIPAddress
	}

	if dialStats.MeekSNIServerName != "" {
		params["meek_sni_server_name"] = dialStats.MeekSNIServerName
	}

	if dialStats.MeekHostHeader != "" {
		params["meek_host_header"] = dialStats.MeekHostHeader
	}

	// MeekTransformedHostName is meaningful when meek is used, which is when MeekDialAddress != ""
	if dialStats.MeekDialAddress != "" {
		transformedHostName := "0"
		if dialStats.MeekTransformedHostName {
			transformedHostName = "1"
		}
		params["meek_transformed_host_name"] = transformedHostName
	}

	if dialStats.SelectedUserAgent {
		params["user_agent"] = dialStats.UserAgent
	}

	if dialStats.SelectedTLSProfile {
		params["tls_profile"] = dialStats.TLSProfile
	}

	if serverEntry.Region != "" {
		params["server_entry_region"] = serverEntry.Region
	}

	if serverEntry.LocalSource != "" {
		params["server_entry_source"] = serverEntry.LocalSource
	}

	// As with last_connected, this timestamp stat, which may be
	// a precise handshake request server timestamp, is truncated
	// to hour granularity to avoid introducing a reconstructable
	// cross-session user trace into server logs.
	localServerEntryTimestamp := common.TruncateTimestampToHour(serverEntry.LocalTimestamp)
	if localServerEntryTimestamp != "" {
		params["server_entry_timestamp"] = localServerEntryTimestamp
	}

	params[tactics.APPLIED_TACTICS_TAG_PARAMETER_NAME] = config.clientParameters.Get().Tag()

	return params
}

// makeSSHAPIRequestPayload makes a JSON payload for an SSH API request.
func makeSSHAPIRequestPayload(params common.APIParameters) ([]byte, error) {
	jsonPayload, err := json.Marshal(params)
	if err != nil {
		return nil, common.ContextError(err)
	}
	return jsonPayload, nil
}

// makeRequestUrl makes a URL for a web service API request.
func makeRequestUrl(tunnel *Tunnel, port, path string, params common.APIParameters) string {
	var requestUrl bytes.Buffer

	if port == "" {
		port = tunnel.serverEntry.WebServerPort
	}

	requestUrl.WriteString("https://")
	requestUrl.WriteString(tunnel.serverEntry.IpAddress)
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

	certificate, err := DecodeCertificate(tunnel.serverEntry.WebServerCertificate)
	if err != nil {
		return nil, common.ContextError(err)
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
			ClientParameters: tunnel.config.clientParameters,
			Dial:             tunneledDialer,
			VerifyLegacyCertificate: certificate,
		})

	transport := &http.Transport{
		DialTLS: func(network, addr string) (net.Conn, error) {
			return dialer(context.Background(), network, addr)
		},
		Dial: func(network, addr string) (net.Conn, error) {
			return nil, errors.New("HTTP not supported")
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
	}

	return common.ContextError(fmt.Errorf("invalid request name: %s", name))
}

func HandleOSLRequest(
	tunnelOwner TunnelOwner, tunnel *Tunnel, payload []byte) error {

	var oslRequest protocol.OSLRequest
	err := json.Unmarshal(payload, &oslRequest)
	if err != nil {
		return common.ContextError(err)
	}

	if oslRequest.ClearLocalSLOKs {
		DeleteSLOKs()
	}

	seededNewSLOK := false

	for _, slok := range oslRequest.SeedPayload.SLOKs {
		duplicate, err := SetSLOK(slok.ID, slok.Key)
		if err != nil {
			// TODO: return error to trigger retry?
			NoticeAlert("SetSLOK failed: %s", common.ContextError(err))
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
