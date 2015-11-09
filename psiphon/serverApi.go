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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/transferstats"
)

// ServerContext is a utility struct which holds all of the data associated
// with a Psiphon server connection. In addition to the established tunnel, this
// includes data associated with Psiphon API requests and a persistent http
// client configured to make tunneled Psiphon API requests.
type ServerContext struct {
	sessionId                string
	tunnelNumber             int64
	baseRequestUrl           string
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
	randomId, err := MakeSecureRandomBytes(PSIPHON_API_CLIENT_SESSION_ID_LENGTH)
	if err != nil {
		return "", ContextError(err)
	}
	return hex.EncodeToString(randomId), nil
}

// NewServerContext makes the tunnelled handshake request to the Psiphon server
// and returns a ServerContext struct for use with subsequent Psiphon server API
// requests (e.g., periodic connected and status requests).
func NewServerContext(tunnel *Tunnel, sessionId string) (*ServerContext, error) {

	psiphonHttpsClient, err := makePsiphonHttpsClient(tunnel)
	if err != nil {
		return nil, ContextError(err)
	}

	serverContext := &ServerContext{
		sessionId:          sessionId,
		tunnelNumber:       atomic.AddInt64(&nextTunnelNumber, 1),
		baseRequestUrl:     makeBaseRequestUrl(tunnel, "", sessionId),
		psiphonHttpsClient: psiphonHttpsClient,
	}

	err = serverContext.doHandshakeRequest()
	if err != nil {
		return nil, ContextError(err)
	}

	return serverContext, nil
}

// doHandshakeRequest performs the handshake API request. The handshake
// returns upgrade info, newly discovered server entries -- which are
// stored -- and sponsor info (home pages, stat regexes).
func (serverContext *ServerContext) doHandshakeRequest() error {
	extraParams := make([]*ExtraParam, 0)
	serverEntryIpAddresses, err := GetServerEntryIpAddresses()
	if err != nil {
		return ContextError(err)
	}
	// Submit a list of known servers -- this will be used for
	// discovery statistics.
	for _, ipAddress := range serverEntryIpAddresses {
		extraParams = append(extraParams, &ExtraParam{"known_server", ipAddress})
	}
	url := buildRequestUrl(serverContext.baseRequestUrl, "handshake", extraParams...)
	responseBody, err := serverContext.doGetRequest(url)
	if err != nil {
		return ContextError(err)
	}
	// Skip legacy format lines and just parse the JSON config line
	configLinePrefix := []byte("Config: ")
	var configLine []byte
	for _, line := range bytes.Split(responseBody, []byte("\n")) {
		if bytes.HasPrefix(line, configLinePrefix) {
			configLine = line[len(configLinePrefix):]
			break
		}
	}
	if len(configLine) == 0 {
		return ContextError(errors.New("no config line found"))
	}

	// Note:
	// - 'preemptive_reconnect_lifetime_milliseconds' is currently unused
	// - 'ssh_session_id' is ignored; client session ID is used instead
	var handshakeConfig struct {
		Homepages            []string            `json:"homepages"`
		UpgradeClientVersion string              `json:"upgrade_client_version"`
		PageViewRegexes      []map[string]string `json:"page_view_regexes"`
		HttpsRequestRegexes  []map[string]string `json:"https_request_regexes"`
		EncodedServerList    []string            `json:"encoded_server_list"`
		ClientRegion         string              `json:"client_region"`
		ServerTimestamp      string              `json:"server_timestamp"`
	}
	err = json.Unmarshal(configLine, &handshakeConfig)
	if err != nil {
		return ContextError(err)
	}

	serverContext.clientRegion = handshakeConfig.ClientRegion
	NoticeClientRegion(serverContext.clientRegion)

	var decodedServerEntries []*ServerEntry

	// Store discovered server entries
	for _, encodedServerEntry := range handshakeConfig.EncodedServerList {
		serverEntry, err := DecodeServerEntry(encodedServerEntry)
		if err != nil {
			return ContextError(err)
		}
		err = ValidateServerEntry(serverEntry)
		if err != nil {
			// Skip this entry and continue with the next one
			continue
		}

		decodedServerEntries = append(decodedServerEntries, serverEntry)
	}

	// The reason we are storing the entire array of server entries at once rather
	// than one at a time is that some desirable side-effects get triggered by
	// StoreServerEntries that don't get triggered by StoreServerEntry.
	err = StoreServerEntries(decodedServerEntries, true)
	if err != nil {
		return ContextError(err)
	}

	// TODO: formally communicate the sponsor and upgrade info to an
	// outer client via some control interface.
	for _, homepage := range handshakeConfig.Homepages {
		NoticeHomepage(homepage)
	}

	serverContext.clientUpgradeVersion = handshakeConfig.UpgradeClientVersion
	if handshakeConfig.UpgradeClientVersion != "" {
		NoticeClientUpgradeAvailable(handshakeConfig.UpgradeClientVersion)
	}

	var regexpsNotices []string
	serverContext.statsRegexps, regexpsNotices = transferstats.MakeRegexps(
		handshakeConfig.PageViewRegexes,
		handshakeConfig.HttpsRequestRegexes)

	for _, notice := range regexpsNotices {
		NoticeAlert(notice)
	}

	serverContext.serverHandshakeTimestamp = handshakeConfig.ServerTimestamp

	return nil
}

// DoConnectedRequest performs the connected API request. This request is
// used for statistics. The server returns a last_connected token for
// the client to store and send next time it connects. This token is
// a timestamp (using the server clock, and should be rounded to the
// nearest hour) which is used to determine when a connection represents
// a unique user for a time period.
func (serverContext *ServerContext) DoConnectedRequest() error {
	const DATA_STORE_LAST_CONNECTED_KEY = "lastConnected"
	lastConnected, err := GetKeyValue(DATA_STORE_LAST_CONNECTED_KEY)
	if err != nil {
		return ContextError(err)
	}
	if lastConnected == "" {
		lastConnected = "None"
	}
	url := buildRequestUrl(
		serverContext.baseRequestUrl,
		"connected",
		&ExtraParam{"session_id", serverContext.sessionId},
		&ExtraParam{"last_connected", lastConnected})
	responseBody, err := serverContext.doGetRequest(url)
	if err != nil {
		return ContextError(err)
	}

	var response struct {
		ConnectedTimestamp string `json:"connected_timestamp"`
	}
	err = json.Unmarshal(responseBody, &response)
	if err != nil {
		return ContextError(err)
	}

	err = SetKeyValue(DATA_STORE_LAST_CONNECTED_KEY, response.ConnectedTimestamp)
	if err != nil {
		return ContextError(err)
	}
	return nil
}

// StatsRegexps gets the Regexps used for the statistics for this tunnel.
func (serverContext *ServerContext) StatsRegexps() *transferstats.Regexps {
	return serverContext.statsRegexps
}

// DoStatusRequest makes a /status request to the server, sending session stats.
func (serverContext *ServerContext) DoStatusRequest(tunnel *Tunnel) error {

	url := makeStatusRequestUrl(serverContext.sessionId, serverContext.baseRequestUrl, true)

	payload, payloadInfo, err := makeStatusRequestPayload(tunnel.serverEntry.IpAddress)
	if err != nil {
		return ContextError(err)
	}

	err = serverContext.doPostRequest(url, "application/json", bytes.NewReader(payload))
	if err != nil {

		// Resend the transfer stats and tunnel durations later
		// Note: potential duplicate reports if the server received and processed
		// the request but the client failed to receive the response.
		putBackStatusRequestPayload(payloadInfo)

		return ContextError(err)
	}
	confirmStatusRequestPayload(payloadInfo)

	return nil
}

func makeStatusRequestUrl(sessionId, baseRequestUrl string, isTunneled bool) string {

	// Add a random amount of padding to help prevent stats updates from being
	// a predictable size (which often happens when the connection is quiet).
	padding := MakeSecureRandomPadding(0, PSIPHON_API_STATUS_REQUEST_PADDING_MAX_BYTES)

	// Legacy clients set "connected" to "0" when disconnecting, and this value
	// is used to calculate session duration estimates. This is now superseded
	// by explicit tunnel duration reporting.
	// The legacy method of reconstructing session durations is not compatible
	// with this client's connected request retries and asynchronous final
	// status request attempts. So we simply set this "connected" flag to reflect
	// whether the request is sent tunneled or not.

	connected := "1"
	if !isTunneled {
		connected = "0"
	}

	return buildRequestUrl(
		baseRequestUrl,
		"status",
		&ExtraParam{"session_id", sessionId},
		&ExtraParam{"connected", connected},
		// TODO: base64 encoding of padding means the padding
		// size is not exactly [0, PADDING_MAX_BYTES]
		&ExtraParam{"padding", base64.StdEncoding.EncodeToString(padding)})
}

// statusRequestPayloadInfo is a temporary structure for data used to
// either "clear" or "put back" status request payload data depending
// on whether or not the request succeeded.
type statusRequestPayloadInfo struct {
	serverId        string
	transferStats   *transferstats.ServerStats
	tunnelDurations [][]byte
}

func makeStatusRequestPayload(
	serverId string) ([]byte, *statusRequestPayloadInfo, error) {

	transferStats := transferstats.GetForServer(serverId)
	tunnelDurations, err := TakeOutUnreportedTunnelDurations(
		PSIPHON_API_TUNNEL_DURATIONS_MAX_COUNT)
	if err != nil {
		NoticeAlert(
			"TakeOutUnreportedTunnelDurations failed: %s", ContextError(err))
		tunnelDurations = nil
		// Proceed with transferStats only
	}
	payloadInfo := &statusRequestPayloadInfo{
		serverId, transferStats, tunnelDurations}

	payload := make(map[string]interface{})

	hostBytes, bytesTransferred := transferStats.GetStatsForReporting()
	payload["host_bytes"] = hostBytes
	payload["bytes_transferred"] = bytesTransferred

	// We're not recording these fields, but the server requires them.
	payload["page_views"] = make([]string, 0)
	payload["https_requests"] = make([]string, 0)

	payload["tunnel_durations"] = tunnelDurations

	jsonPayload, err := json.Marshal(payload)
	if err != nil {

		// Send the transfer stats and tunnel durations later
		putBackStatusRequestPayload(payloadInfo)

		return nil, nil, ContextError(err)
	}

	return jsonPayload, payloadInfo, nil
}

func putBackStatusRequestPayload(payloadInfo *statusRequestPayloadInfo) {
	transferstats.PutBack(payloadInfo.serverId, payloadInfo.transferStats)
	err := PutBackUnreportedTunnelDurations(payloadInfo.tunnelDurations)
	if err != nil {
		// These tunnel duration records won't be resent under after a
		// datastore re-initialization.
		NoticeAlert(
			"PutBackUnreportedTunnelDurations failed: %s", ContextError(err))
	}
}

func confirmStatusRequestPayload(payloadInfo *statusRequestPayloadInfo) {
	err := ClearReportedTunnelDurations(payloadInfo.tunnelDurations)
	if err != nil {
		// These tunnel duration records may be resent.
		NoticeAlert(
			"ClearReportedTunnelDurations failed: %s", ContextError(err))
	}
}

// TryUntunneledStatusRequest makes direct connections to the specified
// server (if supported) in an attempt to send useful bytes transferred
// and tunnel duration stats after a tunnel has alreay failed.
// The tunnel is assumed to be closed, but its config, protocol, and
// context values must still be valid.
// TryUntunneledStatusRequest emits notices detailing failed attempts.
func TryUntunneledStatusRequest(tunnel *Tunnel, isShutdown bool) error {

	for _, port := range tunnel.serverEntry.GetDirectWebRequestPorts() {
		err := doUntunneledStatusRequest(tunnel, port, isShutdown)
		if err == nil {
			return nil
		}
		NoticeAlert("doUntunneledStatusRequest failed for %s:%s: %s",
			tunnel.serverEntry.IpAddress, port, err)
	}

	return errors.New("all attempts failed")
}

// doUntunneledStatusRequest attempts an untunneled stratus request.
func doUntunneledStatusRequest(
	tunnel *Tunnel, port string, isShutdown bool) error {

	url := makeStatusRequestUrl(
		tunnel.serverContext.sessionId,
		makeBaseRequestUrl(tunnel, port, tunnel.serverContext.sessionId),
		false)

	certificate, err := DecodeCertificate(tunnel.serverEntry.WebServerCertificate)
	if err != nil {
		return ContextError(err)
	}

	timeout := PSIPHON_API_SERVER_TIMEOUT
	if isShutdown {
		timeout = PSIPHON_API_SHUTDOWN_SERVER_TIMEOUT
	}

	httpClient, requestUrl, err := MakeUntunneledHttpsClient(
		tunnel.untunneledDialConfig,
		certificate,
		url,
		timeout)
	if err != nil {
		return ContextError(err)
	}

	payload, payloadInfo, err := makeStatusRequestPayload(tunnel.serverEntry.IpAddress)
	if err != nil {
		return ContextError(err)
	}

	bodyType := "application/json"
	body := bytes.NewReader(payload)

	response, err := httpClient.Post(requestUrl, bodyType, body)
	if err == nil && response.StatusCode != http.StatusOK {
		response.Body.Close()
		err = fmt.Errorf("HTTP POST request failed with response code: %d", response.StatusCode)
	}
	if err != nil {

		// Resend the transfer stats and tunnel durations later
		// Note: potential duplicate reports if the server received and processed
		// the request but the client failed to receive the response.
		putBackStatusRequestPayload(payloadInfo)

		// Trim this error since it may include long URLs
		return ContextError(TrimError(err))
	}
	confirmStatusRequestPayload(payloadInfo)
	response.Body.Close()

	return nil
}

// RecordTunnelDuration records a tunnel duration for
// subsequent reporting.
//
// Tunnel durations are precisely measured client-side
// and reported in status requests. As the duration is
// not determined until the tunnel is closed, tunnel
// duration records are stored in the persistent datastore
// and reported via subsequent status requests sent to any
// Psiphon server.
//
// Since the status request that reports a tunnel duration
// is not necessarily handled by the same server, the
// tunnel duration records include the original server ID.
//
// Other fields that may change between duration recording and
// duration reporting include client geo data, propagation channel,
// sponsor ID, client version. These are not stored in the
// datastore (client region, in particular, since that would
// create an on-disk record of user location).
// TODO: the server could encrypt, with a nonce and key unknown to
// the client, a blob containing this data; return it in the
// handshake response; and the client could store and later report
// this blob with its tunnel duration records.
//
// Multiple "status" requests may be in flight at once (due
// to multi-tunnel, asynchronous final status retry, and
// aggressive status requests for pre-registered tunnels),
// To avoid duplicate reporting, tunnel duration records are
// "taken-out" by a status request and then "put back" in
// case the request fails.
//
// Note: since tunnel duration records have a globally unique
// identifier (sessionId + tunnelNumber), we could permit
// duplicate reporting and filter our duplicates on the
// server-side. Permitting duplicate reporting could increase
// the velocity of reporting (for example, both the asynchronous
// untunneled final status requests and the post-connected
// immediate startus requests could try to report the same tunnel
// durations).
// Duplicate reporting may also occur when a server receives and
// processes a status request but the client fails to receive
// the response.
func RecordTunnelDuration(
	sessionId string,
	tunnelNumber int64,
	serverId string,
	serverHandshakeTimestamp, duration string,
	totalBytesSent, totalBytesReceived int64) error {

	tunnelDuration := struct {
		sessionId                string `json:"sessionId"`
		tunnelNumber             int64  `json:"tunnelNumber"`
		serverId                 string `json:"serverId"`
		serverHandshakeTimestamp string `json:"serverHandshakeTimestamp"`
		duration                 string `json:"duration"`
		totalBytesSent           int64  `json:"totalBytesSent"`
		totalBytesReceived       int64  `json:"totalBytesReceived"`
	}{
		sessionId,
		tunnelNumber,
		serverId,
		serverHandshakeTimestamp,
		duration,
		totalBytesSent,
		totalBytesReceived,
	}

	tunnelDurationJson, err := json.Marshal(tunnelDuration)
	if err != nil {
		return ContextError(err)
	}

	return StoreTunnelDuration(tunnelDurationJson)
}

// doGetRequest makes a tunneled HTTPS request and returns the response body.
func (serverContext *ServerContext) doGetRequest(
	requestUrl string) (responseBody []byte, err error) {

	response, err := serverContext.psiphonHttpsClient.Get(requestUrl)
	if err == nil && response.StatusCode != http.StatusOK {
		response.Body.Close()
		err = fmt.Errorf("HTTP GET request failed with response code: %d", response.StatusCode)
	}
	if err != nil {
		// Trim this error since it may include long URLs
		return nil, ContextError(TrimError(err))
	}
	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, ContextError(err)
	}
	return body, nil
}

// doPostRequest makes a tunneled HTTPS POST request.
func (serverContext *ServerContext) doPostRequest(
	requestUrl string, bodyType string, body io.Reader) (err error) {

	response, err := serverContext.psiphonHttpsClient.Post(requestUrl, bodyType, body)
	if err == nil && response.StatusCode != http.StatusOK {
		response.Body.Close()
		err = fmt.Errorf("HTTP POST request failed with response code: %d", response.StatusCode)
	}
	if err != nil {
		// Trim this error since it may include long URLs
		return ContextError(TrimError(err))
	}
	response.Body.Close()
	return nil
}

// makeBaseRequestUrl makes a URL containing all the common parameters
// that are included with Psiphon API requests. These common parameters
// are used for statistics.
func makeBaseRequestUrl(tunnel *Tunnel, port, sessionId string) string {
	var requestUrl bytes.Buffer

	if port == "" {
		port = tunnel.serverEntry.WebServerPort
	}

	// Note: don't prefix with HTTPS scheme, see comment in doGetRequest.
	// e.g., don't do this: requestUrl.WriteString("https://")
	requestUrl.WriteString("http://")
	requestUrl.WriteString(tunnel.serverEntry.IpAddress)
	requestUrl.WriteString(":")
	requestUrl.WriteString(port)
	requestUrl.WriteString("/")
	// Placeholder for the path component of a request
	requestUrl.WriteString("%s")
	requestUrl.WriteString("?client_session_id=")
	requestUrl.WriteString(sessionId)
	requestUrl.WriteString("&server_secret=")
	requestUrl.WriteString(tunnel.serverEntry.WebServerSecret)
	requestUrl.WriteString("&propagation_channel_id=")
	requestUrl.WriteString(tunnel.config.PropagationChannelId)
	requestUrl.WriteString("&sponsor_id=")
	requestUrl.WriteString(tunnel.config.SponsorId)
	requestUrl.WriteString("&client_version=")
	requestUrl.WriteString(tunnel.config.ClientVersion)
	// TODO: client_tunnel_core_version
	requestUrl.WriteString("&relay_protocol=")
	requestUrl.WriteString(tunnel.protocol)
	requestUrl.WriteString("&client_platform=")
	requestUrl.WriteString(tunnel.config.ClientPlatform)
	requestUrl.WriteString("&tunnel_whole_device=")
	requestUrl.WriteString(strconv.Itoa(tunnel.config.TunnelWholeDevice))
	return requestUrl.String()
}

type ExtraParam struct{ name, value string }

// buildRequestUrl makes a URL for an API request. The URL includes the
// base request URL and any extra parameters for the specific request.
func buildRequestUrl(baseRequestUrl, path string, extraParams ...*ExtraParam) string {
	var requestUrl bytes.Buffer
	requestUrl.WriteString(fmt.Sprintf(baseRequestUrl, path))
	for _, extraParam := range extraParams {
		requestUrl.WriteString("&")
		requestUrl.WriteString(extraParam.name)
		requestUrl.WriteString("=")
		requestUrl.WriteString(extraParam.value)
	}
	return requestUrl.String()
}

// makeHttpsClient creates a Psiphon HTTPS client that tunnels requests and which validates
// the web server using the Psiphon server entry web server certificate.
// This is not a general purpose HTTPS client.
// As the custom dialer makes an explicit TLS connection, URLs submitted to the returned
// http.Client should use the "http://" scheme. Otherwise http.Transport will try to do another TLS
// handshake inside the explicit TLS session.
func makePsiphonHttpsClient(tunnel *Tunnel) (httpsClient *http.Client, err error) {
	certificate, err := DecodeCertificate(tunnel.serverEntry.WebServerCertificate)
	if err != nil {
		return nil, ContextError(err)
	}
	tunneledDialer := func(_, addr string) (conn net.Conn, err error) {
		return tunnel.sshClient.Dial("tcp", addr)
	}
	dialer := NewCustomTLSDialer(
		&CustomTLSConfig{
			Dial:                    tunneledDialer,
			Timeout:                 PSIPHON_API_SERVER_TIMEOUT,
			VerifyLegacyCertificate: certificate,
		})
	transport := &http.Transport{
		Dial: dialer,
		ResponseHeaderTimeout: PSIPHON_API_SERVER_TIMEOUT,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   PSIPHON_API_SERVER_TIMEOUT,
	}, nil
}
