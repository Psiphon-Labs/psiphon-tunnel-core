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
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/buildinfo"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/crypto/ssh"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/fragmentor"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/inproxy"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tactics"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/transferstats"
	lrucache "github.com/cognusion/go-cache-lru"
	"github.com/fxamacker/cbor/v2"
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
		tunnel.config.TargetAPIProtocol == protocol.PSIPHON_API_PROTOCOL_WEB {

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

	ignoreRegexps := tunnel.config.GetParameters().Get().Bool(
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
func (serverContext *ServerContext) doHandshakeRequest(ignoreStatsRegexps bool) error {

	params := serverContext.getBaseAPIParameters(baseParametersAll)

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

	// The server will return a signed copy of its own server entry when the
	// client specifies this 'missing_server_entry_provider_id' parameter.
	//
	// The purpose of this mechanism is to rapidly add provider IDs to the
	// server entries in client local storage, and to ensure that the client has
	// a provider ID for its currently connected server as required for the
	// RestrictDirectProviderRegions, HoldOffDirectTunnelProviderRegions,
	// RestrictInproxyProviderRegions, and HoldOffInproxyTunnelProviderRegions
	// tactics.
	//
	// The server entry will be included in handshakeResponse.EncodedServerList,
	// along side discovery servers.
	requestedMissingProviderID := false
	if !serverContext.tunnel.dialParams.ServerEntry.HasProviderID() {
		requestedMissingProviderID = true
		params["missing_server_entry_provider_id"] =
			serverContext.tunnel.dialParams.ServerEntry.Tag
	}

	doTactics := !serverContext.tunnel.config.DisableTactics

	compressTactics := false

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
			GetTacticsStorer(serverContext.tunnel.config),
			networkID,
			params)
		if err != nil {
			return errors.Trace(err)
		}

		p := serverContext.tunnel.config.GetParameters().Get()
		compressTactics = compressTacticsEnabled && p.Bool(parameters.CompressTactics)
		p.Close()
	}

	// When split tunnel mode is enabled, indicate this to the server. When
	// indicated, the server will perform split tunnel classifications on TCP
	// port forwards and reject, with a distinct response, port forwards which
	// the client should connect to directly, untunneled.
	if serverContext.tunnel.config.SplitTunnelOwnRegion {
		params["split_tunnel"] = "1"
	}

	// While regular split tunnel mode makes untunneled connections to
	// destinations in the client's own country, selected split tunnel mode
	// allows the client to specify a list of untunneled countries. Either or
	// both modes may be enabled.
	if len(serverContext.tunnel.config.SplitTunnelRegions) > 0 {
		params["split_tunnel_regions"] = serverContext.tunnel.config.SplitTunnelRegions
	}

	// Add the in-proxy broker/server relay packet, which contains either the
	// immediate broker report payload, for established sessions, or a new
	// session handshake packet. The broker report securely relays the
	// original client IP and the relaying proxy ID to the Psiphon server.
	// inproxy_relay_packet is a required field for in-proxy tunnel protocols.
	if protocol.TunnelProtocolUsesInproxy(serverContext.tunnel.dialParams.TunnelProtocol) {
		inproxyConn := serverContext.tunnel.dialParams.inproxyConn.Load()
		if inproxyConn != nil {
			packet := base64.RawStdEncoding.EncodeToString(
				inproxyConn.(*inproxy.ClientConn).InitialRelayPacket())
			params["inproxy_relay_packet"] = packet
		}
	}

	// When requesting compressed tactics, the response will use CBOR binary
	// encoding.

	var responseUnmarshaler func([]byte, any) error
	responseUnmarshaler = json.Unmarshal

	if compressTactics && serverContext.psiphonHttpsClient == nil {
		protocol.SetCompressTactics(params)
		responseUnmarshaler = cbor.Unmarshal
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

	err := responseUnmarshaler(response, &handshakeResponse)
	if err != nil {
		return errors.Trace(err)
	}

	if serverContext.tunnel.config.EmitClientAddress &&
		handshakeResponse.ClientAddress != "" {

		NoticeClientAddress(handshakeResponse.ClientAddress)
	}

	NoticeClientRegion(handshakeResponse.ClientRegion)

	// Emit a SplitTunnelRegions notice indicating active split tunnel region.
	// For SplitTunnelOwnRegion, the handshake ClientRegion is the split
	// tunnel region and this region is always listed first.

	splitTunnelRegions := []string{}
	if serverContext.tunnel.config.SplitTunnelOwnRegion {
		splitTunnelRegions = []string{handshakeResponse.ClientRegion}
	}
	for _, region := range serverContext.tunnel.config.SplitTunnelRegions {
		if !serverContext.tunnel.config.SplitTunnelOwnRegion ||
			region != handshakeResponse.ClientRegion {

			splitTunnelRegions = append(splitTunnelRegions, region)
		}
	}
	if len(splitTunnelRegions) > 0 {
		NoticeSplitTunnelRegions(splitTunnelRegions)
	}

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

		// Retain the original timestamp and source in the
		// requestedMissingSignature and requestedMissingProviderID
		// cases, as this server entry was not discovered here.
		//
		// Limitation: there is a transient edge case where
		// requestedMissingSignature and/or requestedMissingProviderID will be
		// set for a discovery server entry that _is_ also discovered here.
		if requestedMissingSignature || requestedMissingProviderID &&
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

		// The handshake returns page_view_regexes and https_request_regexes.
		// page_view_regexes is obsolete and not used. https_request_regexes, which
		// are actually host/domain name regexes, are used for host/domain name
		// bytes transferred metrics: tunneled traffic TLS SNI server names and HTTP
		// Host header host names are matched against these regexes to select flows
		// for bytes transferred counting.

		var regexpsNotices []string
		serverContext.statsRegexps, regexpsNotices = transferstats.MakeRegexps(
			handshakeResponse.HttpsRequestRegexes)

		for _, notice := range regexpsNotices {
			NoticeWarning(notice)
		}
	}

	diagnosticID := serverContext.tunnel.dialParams.ServerEntry.GetDiagnosticID()

	serverContext.serverHandshakeTimestamp = handshakeResponse.ServerTimestamp
	NoticeServerTimestamp(diagnosticID, serverContext.serverHandshakeTimestamp)

	NoticeActiveAuthorizationIDs(diagnosticID, handshakeResponse.ActiveAuthorizationIDs)

	NoticeTrafficRateLimits(
		diagnosticID,
		handshakeResponse.UpstreamBytesPerSecond,
		handshakeResponse.DownstreamBytesPerSecond)

	if doTactics && handshakeResponse.TacticsPayload != nil &&
		networkID == serverContext.tunnel.config.GetNetworkID() {

		var payload *tactics.Payload
		err := responseUnmarshaler(handshakeResponse.TacticsPayload, &payload)
		if err != nil {
			return errors.Trace(err)
		}

		// handshakeResponse.TacticsPayload may be "null", and payload
		// will successfully unmarshal as nil. As a result, the previous
		// handshakeResponse.TacticsPayload != nil test is insufficient.
		if payload != nil {

			tacticsRecord, err := tactics.HandleTacticsPayload(
				GetTacticsStorer(serverContext.tunnel.config),
				networkID,
				payload)
			if err != nil {
				return errors.Trace(err)
			}

			if tacticsRecord != nil {

				err := serverContext.tunnel.config.SetParameters(
					tacticsRecord.Tag, true, tacticsRecord.Tactics.Parameters)
				if err != nil {
					NoticeWarning("apply handshake tactics failed: %s", err)
				}
				// The error will be due to invalid tactics values
				// from the server. When SetParameters fails, all
				// previous tactics values are left in place.
			}
		}
	}

	if handshakeResponse.SteeringIP != "" {

		if serverContext.tunnel.dialParams.steeringIPCacheKey == "" {
			NoticeWarning("unexpected steering IP")

		} else {

			// Cache any received steering IP, which will also extend the TTL for
			// an existing entry.
			//
			// As typical tunnel duration is short and dialing can be challenging,
			// this established tunnel is retained and the steering IP will be
			// used on any subsequent dial to the same fronting provider,
			// assuming the TTL has not expired.
			//
			// Note: to avoid TTL expiry for long-lived tunnels, the TTL could be
			// set or extended at the end of the tunnel lifetime; however that
			// may result in unintended steering.

			IP := net.ParseIP(handshakeResponse.SteeringIP)
			if IP != nil && !common.IsBogon(IP) {
				serverContext.tunnel.dialParams.steeringIPCache.Set(
					serverContext.tunnel.dialParams.steeringIPCacheKey,
					handshakeResponse.SteeringIP,
					lrucache.DefaultExpiration)
			} else {
				NoticeWarning("ignoring invalid steering IP")
			}
		}
	}

	return nil
}

// DoConnectedRequest performs the "connected" API request. This request is
// used for statistics, including unique user counting; reporting the full
// tunnel establishment duration including the handshake request; and updated
// fragmentor metrics.
//
// Users are not assigned identifiers. Instead, daily unique users are
// calculated by having clients submit their last connected timestamp
// (truncated to an hour, as a privacy measure). As client clocks are
// unreliable, the server returns new last_connected values for the client to
// store and send next time it connects.
func (serverContext *ServerContext) DoConnectedRequest() error {

	// Limitation: as currently implemented, the last_connected exchange isn't a
	// distributed, atomic operation. When clients send the connected request,
	// the server may receive the request, count a unique user based on the
	// client's last_connected, and then the tunnel fails before the client
	// receives the response, so the client will not update its last_connected
	// value and submit the same one again, resulting in an inflated unique user
	// count.
	//
	// The SetInFlightConnectedRequest mechanism mitigates one class of connected
	// request interruption, a commanded shutdown in the middle of a connected
	// request, by allowing some time for the request to complete before
	// terminating the tunnel.
	//
	// TODO: consider extending the connected request protocol with additional
	// "acknowledgment" messages so that the server does not commit its unique
	// user count until after the client has acknowledged receipt and durable
	// storage of the new last_connected value.

	requestDone := make(chan struct{})
	defer close(requestDone)

	if !serverContext.tunnel.SetInFlightConnectedRequest(requestDone) {
		return errors.TraceNew("tunnel is closing")
	}
	defer serverContext.tunnel.SetInFlightConnectedRequest(nil)

	params := serverContext.getBaseAPIParameters(
		baseParametersOnlyUpstreamFragmentorDialParameters)

	lastConnected, err := getLastConnected()
	if err != nil {
		return errors.Trace(err)
	}

	params["last_connected"] = lastConnected

	// serverContext.tunnel.establishDuration is nanoseconds; report milliseconds
	params["establishment_duration"] =
		fmt.Sprintf("%d", serverContext.tunnel.establishDuration/time.Millisecond)

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
func (serverContext *ServerContext) DoStatusRequest() error {

	params := serverContext.getBaseAPIParameters(
		baseParametersNoDialParameters)

	// Note: ensure putBackStatusRequestPayload is called, to replace
	// payload for future attempt, in all failure cases.

	statusPayload, statusPayloadInfo, err := makeStatusRequestPayload(
		serverContext.tunnel.config,
		serverContext.tunnel.dialParams.ServerEntry.IpAddress)
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

	// Confirm the payload now that the server response is received. For
	// persistentStats and transferStats, this clears the reported data as it
	// is now delivered and doesn't need to be resent.

	confirmStatusRequestPayload(statusPayloadInfo)

	var statusResponse protocol.StatusResponse
	err = json.Unmarshal(response, &statusResponse)
	if err != nil {
		return errors.Trace(err)
	}

	// Prune all server entries flagged by either the failed_tunnel mechanism
	// or the prune check. Note that server entries that are too new, as
	// determined by ServerEntryMinimumAgeForPruning, are not pruned, and
	// this is reflected in pruneCount.

	pruneCount := 0
	for _, serverEntryTag := range statusResponse.InvalidServerEntryTags {
		if PruneServerEntry(serverContext.tunnel.config, serverEntryTag) {
			pruneCount++
		}
	}

	if pruneCount > 0 {
		NoticeInfo("Pruned server entries: %d", pruneCount)
	}

	if statusPayloadInfo.checkServerEntryTagCount > 0 {

		// Schedule the next prune check, now that all pruning is complete. By
		// design, if the process dies before the end of the prune loop, the
		// previous due time will be retained.
		//
		// UpdateCheckServerEntryTagsEndTime may leave the next prune check
		// due immediately based on the ratio of server entries checked and
		// server entries pruned: if many checked server entries were invalid
		// and pruned, check again and prune more.
		//
		// Limitation: the prune count may include failed_tunnel prunes which
		// aren't in the check count; if this occurs, it will increase the
		// ratio and make an immediate re-check more likely, which makes sense.

		UpdateCheckServerEntryTagsEndTime(
			serverContext.tunnel.config,
			statusPayloadInfo.checkServerEntryTagCount,
			pruneCount)
	}

	return nil
}

// statusRequestPayloadInfo is a temporary structure for data used to
// either "clear" or "put back" status request payload data depending
// on whether or not the request succeeded.
type statusRequestPayloadInfo struct {
	serverId                 string
	transferStats            *transferstats.AccumulatedStats
	persistentStats          map[string][][]byte
	checkServerEntryTagCount int
}

func makeStatusRequestPayload(
	config *Config,
	serverId string) ([]byte, *statusRequestPayloadInfo, error) {

	// The status request payload is always JSON encoded. As it is sent after
	// the initial handshake and is multiplexed with other tunnel traffic,
	// its size is less of a fingerprinting concern.
	//
	// TODO: pack and CBOR encode the status request payload.

	// GetCheckServerEntryTags returns a randomly selected set of server entry
	// tags to be checked for pruning, or an empty list if a check is not yet
	// due.
	//
	// Both persistentStats and prune check data have a max payload size
	// allowance, and the allowance for persistentStats is reduced by the
	// size of the prune check data, if any.

	checkServerEntryTags, tagsSize, err := GetCheckServerEntryTags(config)
	if err != nil {
		NoticeWarning(
			"GetCheckServerEntryTags failed: %s", errors.Trace(err))
		checkServerEntryTags = nil
		// Proceed with persistentStats/transferStats only
	}

	transferStats := transferstats.TakeOutStatsForServer(serverId)
	hostBytes := transferStats.GetStatsForStatusRequest()

	persistentStats, statsSize, err := TakeOutUnreportedPersistentStats(config, tagsSize)
	if err != nil {
		NoticeWarning(
			"TakeOutUnreportedPersistentStats failed: %s", errors.Trace(err))
		persistentStats = nil
		// Proceed with transferStats only
	}

	if len(checkServerEntryTags) == 0 && len(hostBytes) == 0 && len(persistentStats) == 0 {
		// There is no payload to send.
		return nil, nil, nil
	}

	payloadInfo := &statusRequestPayloadInfo{
		serverId,
		transferStats,
		persistentStats,
		len(checkServerEntryTags),
	}

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

	payload["check_server_entry_tags"] = checkServerEntryTags

	jsonPayload, err := json.Marshal(payload)
	if err != nil {

		// Send the transfer stats and tunnel stats later
		putBackStatusRequestPayload(payloadInfo)

		return nil, nil, errors.Trace(err)
	}

	NoticeInfo(
		"StatusRequestPayload: %d total bytes, %d stats bytes, %d tag bytes",
		len(jsonPayload), statsSize, tagsSize)

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

// RecordRemoteServerListStat records a completed common or OSL remote server
// list resource download.
//
// The RSL download event could occur when the client is unable to immediately
// send a status request to a server, so these records are stored in the
// persistent datastore and reported via subsequent status requests sent to
// any Psiphon server.
//
// Note that some common event field values may change between the stat
// recording and reporting, including client geolocation and host_id.
//
// The bytes/duration fields reflect the size and download time for the _last
// chunk only_ in the case of a resumed download. The purpose of these fields
// is to calculate rough data transfer rates. Both bytes and duration are
// included in the log, to allow for filtering out of small transfers which
// may not produce accurate rate numbers.
//
// Multiple "status" requests may be in flight at once (due to multi-tunnel,
// asynchronous final status retry, and aggressive status requests for
// pre-registered tunnels), To avoid duplicate reporting, persistent stats
// records are "taken-out" by a status request and then "put back" in case the
// request fails.
//
// Duplicate reporting may also occur when a server receives and processes a
// status request but the client fails to receive the response.
func RecordRemoteServerListStat(
	config *Config,
	tunneled bool,
	url string,
	etag string,
	bytes int64,
	duration time.Duration,
	authenticated bool,
	additionalParameters common.APIParameters) error {

	if !config.GetParameters().Get().WeightedCoinFlip(
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
	if config.DeviceLocation != "" {
		params["device_location"] = config.DeviceLocation
	}

	params["client_download_timestamp"] = common.TruncateTimestampToHour(common.GetCurrentTimestamp())
	tunneledStr := "0"
	if tunneled {
		tunneledStr = "1"
	}
	params["tunneled"] = tunneledStr
	params["url"] = url
	params["etag"] = etag
	params["bytes"] = fmt.Sprintf("%d", bytes)

	// duration is nanoseconds; report milliseconds
	params["duration"] = fmt.Sprintf("%d", duration/time.Millisecond)

	authenticatedStr := "0"
	if authenticated {
		authenticatedStr = "1"
	}
	params["authenticated"] = authenticatedStr

	for k, v := range additionalParameters {
		params[k] = v
	}

	remoteServerListStatJson, err := json.Marshal(params)
	if err != nil {
		return errors.Trace(err)
	}

	return StorePersistentStat(
		config, datastorePersistentStatTypeRemoteServerList, remoteServerListStatJson)
}

// RecordFailedTunnelStat records metrics for a failed tunnel dial, including
// dial parameters and error condition (tunnelErr). No record is created when
// tunnelErr is nil.
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

	probability := config.GetParameters().Get().Float(
		parameters.RecordFailedTunnelPersistentStatsProbability)

	if !prng.FlipWeightedCoin(probability) {
		return nil
	}

	// Callers should not call RecordFailedTunnelStat with a nil tunnelErr, as
	// this is not a useful stat and it results in a nil pointer dereference.
	// This check catches potential bug cases. An example edge case, now
	// fixed, is deferred error handlers, such as the ones in in
	// dialTunnel/tunnel.Activate, which may be invoked in the case of a
	// panic, which can occur before any error value is returned.
	if tunnelErr == nil {
		return errors.TraceNew("no error")
	}

	lastConnected, err := getLastConnected()
	if err != nil {
		return errors.Trace(err)
	}

	includeSessionID := true
	params := getBaseAPIParameters(baseParametersAll, nil, includeSessionID, config, dialParams)

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

	// Log RecordFailedTunnelPersistentStatsProbability to indicate the
	// proportion of failed tunnel events being recorded at the time of
	// this log event.
	params["record_probability"] = fmt.Sprintf("%f", probability)

	// Ensure direct server IPs are not exposed in logs. The "net" package, and
	// possibly other 3rd party packages, will include destination addresses in
	// I/O error messages.
	tunnelError := common.RedactIPAddressesString(tunnelErr.Error())
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

// makeSSHAPIRequestPayload makes an encoded payload for an SSH API request.
func (serverContext *ServerContext) makeSSHAPIRequestPayload(
	params common.APIParameters) ([]byte, error) {

	// CBOR encoding is the default and is preferred as its smaller size gives
	// more space for variable padding to mitigate potential fingerprinting
	// based on API message sizes.

	if !serverContext.tunnel.dialParams.ServerEntry.SupportsSSHAPIRequests() ||
		serverContext.tunnel.config.TargetAPIEncoding == protocol.PSIPHON_API_ENCODING_JSON {

		jsonPayload, err := json.Marshal(params)
		if err != nil {
			return nil, errors.Trace(err)
		}
		return jsonPayload, nil
	}

	payload, err := protocol.MakePackedAPIParametersRequestPayload(params)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return payload, nil
}

type baseParametersFilter int

const (
	baseParametersAll baseParametersFilter = iota
	baseParametersOnlyUpstreamFragmentorDialParameters
	baseParametersNoDialParameters
)

func (serverContext *ServerContext) getBaseAPIParameters(
	filter baseParametersFilter) common.APIParameters {

	// For tunneled SSH API requests, the session ID is omitted since the
	// server already has that value; and padding is added via the params
	// since there's no random padding at the SSH request layer.
	includeSessionID := false
	params := getBaseAPIParameters(
		filter,
		serverContext.paddingPRNG,
		includeSessionID,
		serverContext.tunnel.config,
		serverContext.tunnel.dialParams)

	return params
}

// getBaseAPIParameters returns all the common API parameters that are
// included with each Psiphon API request. These common parameters are used
// for metrics.
//
// The input dialParams may be nil when the filter has
// baseParametersNoDialParameters.
func getBaseAPIParameters(
	filter baseParametersFilter,
	paddingPRNG *prng.PRNG,
	includeSessionID bool,
	config *Config,
	dialParams *DialParameters) common.APIParameters {

	params := make(common.APIParameters)

	if paddingPRNG != nil {

		// Add a random amount of padding to defend against API call traffic size
		// fingerprints. The "pad_response" field instructs the server to pad its
		// response accordingly.
		//
		// Padding may be omitted if it's already provided at transport layer.

		p := config.GetParameters().Get()
		minUpstreamPadding := p.Int(parameters.APIRequestUpstreamPaddingMinBytes)
		maxUpstreamPadding := p.Int(parameters.APIRequestUpstreamPaddingMaxBytes)
		minDownstreamPadding := p.Int(parameters.APIRequestDownstreamPaddingMinBytes)
		maxDownstreamPadding := p.Int(parameters.APIRequestDownstreamPaddingMaxBytes)

		if maxUpstreamPadding > 0 {
			size := paddingPRNG.Range(minUpstreamPadding, maxUpstreamPadding)
			params["padding"] = strings.Repeat(" ", size)
		}

		if maxDownstreamPadding > 0 {
			size := paddingPRNG.Range(minDownstreamPadding, maxDownstreamPadding)
			params["pad_response"] = strconv.Itoa(size)
		}
	}

	if includeSessionID {
		// The session ID is included in non-SSH API requests only. For SSH
		// API requests, the Psiphon server already has the client's session ID.
		params["session_id"] = config.SessionID
	}
	params["propagation_channel_id"] = config.PropagationChannelId
	params["sponsor_id"] = config.GetSponsorID()
	params["client_version"] = config.ClientVersion
	params["client_platform"] = config.ClientPlatform
	params["client_features"] = config.clientFeatures
	params["client_build_rev"] = buildinfo.GetBuildInfo().BuildRev
	if dialParams != nil {
		// Prefer the dialParams network ID snapshot if available.
		params["network_type"] = dialParams.GetNetworkType()
	} else {
		params["network_type"] = GetNetworkType(config.GetNetworkID())
	}
	// TODO: snapshot tactics tag used when dialParams initialized.
	params[tactics.APPLIED_TACTICS_TAG_PARAMETER_NAME] =
		config.GetParameters().Get().Tag()

	// The server secret is deprecated and included only in legacy JSON
	// encoded API messages for backwards compatibility. SSH login proves
	// client possession of the server entry; the server secret was for the
	// legacy web API with no SSH login. Note that we can't check
	// dialParams.ServerEntry in the baseParametersNoDialParameters case, but
	// that case is used by in-proxy dials, which implies support.

	if dialParams != nil {
		if !dialParams.ServerEntry.SupportsSSHAPIRequests() ||
			config.TargetAPIEncoding == protocol.PSIPHON_API_ENCODING_JSON {

			params["server_secret"] = dialParams.ServerEntry.WebServerSecret
		}
	}

	// Blank parameters must be omitted.

	if config.DeviceRegion != "" {
		params["device_region"] = config.DeviceRegion
	}
	if config.DeviceLocation != "" {
		params["device_location"] = config.DeviceLocation
	}

	if config.EgressRegion != "" {
		params["egress_region"] = config.EgressRegion
	}

	if filter == baseParametersAll {

		if protocol.TunnelProtocolUsesInproxy(dialParams.TunnelProtocol) {
			inproxyConn := dialParams.inproxyConn.Load()
			if inproxyConn != nil {
				params["inproxy_connection_id"] =
					inproxyConn.(*inproxy.ClientConn).GetConnectionID()
			}
		}

		params["relay_protocol"] = dialParams.TunnelProtocol

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

		if protocol.TunnelProtocolUsesFrontedMeek(dialParams.TunnelProtocol) {

			meekResolvedIPAddress := dialParams.MeekResolvedIPAddress.Load().(string)
			if meekResolvedIPAddress != "" {
				params["meek_resolved_ip_address"] = meekResolvedIPAddress
			}
		}

		if dialParams.MeekSNIServerName != "" {
			params["meek_sni_server_name"] = dialParams.MeekSNIServerName
		}

		if dialParams.MeekHostHeader != "" {
			params["meek_host_header"] = dialParams.MeekHostHeader
		}

		// MeekTransformedHostName is meaningful when meek is used, which is when
		// MeekDialAddress != ""
		if dialParams.MeekDialAddress != "" {
			transformedHostName := "0"
			if dialParams.MeekTransformedHostName {
				transformedHostName = "1"
			}
			params["meek_transformed_host_name"] = transformedHostName
		}

		if dialParams.TLSOSSHSNIServerName != "" {
			params["tls_ossh_sni_server_name"] = dialParams.TLSOSSHSNIServerName
		}

		if dialParams.TLSOSSHTransformedSNIServerName {
			params["tls_ossh_transformed_host_name"] = "1"
		}

		if dialParams.TLSFragmentClientHello {
			params["tls_fragmented"] = "1"
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

		// As with last_connected, this timestamp stat, which may be a precise
		// handshake request server timestamp, is truncated to hour granularity to
		// avoid introducing a reconstructable cross-session user trace into server
		// logs.
		localServerEntryTimestamp := common.TruncateTimestampToHour(
			dialParams.ServerEntry.LocalTimestamp)
		if localServerEntryTimestamp != "" {
			params["server_entry_timestamp"] = localServerEntryTimestamp
		}

		if dialParams.DialPortNumber != "" {
			params["dial_port_number"] = dialParams.DialPortNumber
		}

		if dialParams.QUICVersion != "" {
			params["quic_version"] = dialParams.QUICVersion
		}

		if dialParams.QUICDialSNIAddress != "" {
			params["quic_dial_sni_address"] = dialParams.QUICDialSNIAddress
		}

		if dialParams.QUICDisablePathMTUDiscovery {
			params["quic_disable_client_path_mtu_discovery"] = "1"
		}

		// The server will log a default false value for is_replay,
		// replay_ignored_change, and dsl_prioritized when omitted. Omitting
		// reduces the handshake parameter size in common cases.

		if dialParams.IsReplay {
			params["is_replay"] = "1"
		}

		if dialParams.ReplayIgnoredChange {
			params["replay_ignored_change"] = "1"
		}

		if dialParams.DSLPrioritizedDial {
			params["dsl_prioritized"] = "1"
		}

		// dialParams.DialDuration is nanoseconds; report milliseconds
		params["dial_duration"] = fmt.Sprintf("%d", dialParams.DialDuration/time.Millisecond)

		params["candidate_number"] = strconv.Itoa(dialParams.CandidateNumber)

		params["established_tunnels_count"] = strconv.Itoa(dialParams.EstablishedTunnelsCount)

		if dialParams.NetworkLatencyMultiplier != 0.0 {
			params["network_latency_multiplier"] =
				fmt.Sprintf("%f", dialParams.NetworkLatencyMultiplier)
		}

		if dialParams.ConjureTransport != "" {
			params["conjure_transport"] = dialParams.ConjureTransport
		}

		usedSteeringIP := false
		if dialParams.SteeringIP != "" {
			params["steering_ip"] = dialParams.SteeringIP
			usedSteeringIP = true
		}

		if dialParams.ResolveParameters != nil && !usedSteeringIP {

			// Log enough information to distinguish several successful or
			// failed circumvention cases of interest, including preferring
			// alternate servers and/or using DNS protocol transforms, and
			// appropriate for both handshake and failed_tunnel logging:
			//
			// - The initial attempt made by Resolver.ResolveIP,
			//   preferring an alternate DNS server and/or using a
			//   protocol transform succeeds (dns_result = 0, the initial
			//   attempt, 0, got the first result).
			//
			// - A second attempt may be used, still preferring an
			//   alternate DNS server but no longer using the protocol
			//   transform, which presumably failed (dns_result = 1, the
			//   second attempt, 1, got the first result).
			//
			// - Subsequent attempts will use the system DNS server and no
			//   protocol transforms (dns_result > 2).
			//
			// Due to the design of Resolver.ResolveIP, the notion
			// of "success" is approximate; for example a successful
			// response may arrive after a subsequent attempt succeeds,
			// simply due to slow network conditions. It's also possible
			// that, for a given attemp, only one of the two concurrent
			// requests (A and AAAA) succeeded.
			//
			// Note that ResolveParameters.GetFirstAttemptWithAnswer
			// semantics assume that dialParams.ResolveParameters wasn't
			// used by or modified by any other dial.
			//
			// Some protocols may use both preresolved DNS as well as actual
			// DNS requests, such as Conjure with the DTLS transport, which
			// may resolve STUN server domains while using preresolved DNS
			// for fronted API registration.

			if dialParams.ResolveParameters.PreresolvedIPAddress != "" {
				meekDialDomain, _, _ := net.SplitHostPort(dialParams.MeekDialAddress)
				if dialParams.ResolveParameters.PreresolvedDomain == meekDialDomain {
					params["dns_preresolved"] = dialParams.ResolveParameters.PreresolvedIPAddress
				}
			}

			if dialParams.ResolveParameters.PreferAlternateDNSServer {
				params["dns_preferred"] = dialParams.ResolveParameters.AlternateDNSServer
			}

			if dialParams.ResolveParameters.ProtocolTransformName != "" {
				params["dns_transform"] = dialParams.ResolveParameters.ProtocolTransformName
			}

			if dialParams.ResolveParameters.RandomQNameCasingSeed != nil {
				params["dns_qname_random_casing"] = "1"
			}

			if dialParams.ResolveParameters.ResponseQNameMustMatch {
				params["dns_qname_must_match"] = "1"
			}

			params["dns_qname_mismatches"] = strconv.Itoa(
				dialParams.ResolveParameters.GetQNameMismatches())

			params["dns_attempt"] = strconv.Itoa(
				dialParams.ResolveParameters.GetFirstAttemptWithAnswer())
		}

		if dialParams.HTTPTransformerParameters != nil {
			if dialParams.HTTPTransformerParameters.ProtocolTransformSpec != nil {
				params["http_transform"] = dialParams.HTTPTransformerParameters.ProtocolTransformName
			}
		}

		if dialParams.OSSHObfuscatorSeedTransformerParameters != nil {
			if dialParams.OSSHObfuscatorSeedTransformerParameters.TransformSpec != nil {
				params["seed_transform"] = dialParams.OSSHObfuscatorSeedTransformerParameters.TransformName
			}
		}

		if dialParams.ObfuscatedQUICNonceTransformerParameters != nil {
			if dialParams.ObfuscatedQUICNonceTransformerParameters.TransformSpec != nil {
				params["seed_transform"] = dialParams.ObfuscatedQUICNonceTransformerParameters.TransformName
			}
		}

		if dialParams.OSSHPrefixSpec != nil {
			if dialParams.OSSHPrefixSpec.Spec != nil {
				params["ossh_prefix"] = dialParams.OSSHPrefixSpec.Name
			}
		}

		if dialParams.ShadowsocksPrefixSpec != nil {
			if dialParams.ShadowsocksPrefixSpec.Spec != nil {
				params["shadowsocks_prefix"] = dialParams.ShadowsocksPrefixSpec.Name
			}
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

		if protocol.TunnelProtocolUsesInproxy(dialParams.TunnelProtocol) {
			metrics := dialParams.GetInproxyMetrics()
			for name, value := range metrics {
				params[name] = fmt.Sprintf("%v", value)
			}
		}

		serverEntryCount := GetLastServerEntryCount()
		if serverEntryCount >= 0 {
			params["server_entry_count"] = strconv.Itoa(serverEntryCount)
		}

	} else if filter == baseParametersOnlyUpstreamFragmentorDialParameters {

		if dialParams.DialConnMetrics != nil {
			names := fragmentor.GetUpstreamMetricsNames()
			metrics := dialParams.DialConnMetrics.GetMetrics()
			for name, value := range metrics {
				if common.Contains(names, name) {
					params[name] = fmt.Sprintf("%v", value)
				}
			}
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

	tunneledDialer := func(_ context.Context, _, addr string) (net.Conn, error) {
		// This case bypasses tunnel.Dial, to avoid its check that the tunnel is
		// already active (it won't be pre-handshake). This bypass won't handle the
		// server rejecting the port forward due to split tunnel classification, but
		// we know that the server won't classify the web API destination as
		// untunneled.
		return tunnel.sshClient.Dial("tcp", addr)
	}

	// Note: as with SSH API requests, there no dial context here. SSH port forward dials
	// cannot be interrupted directly. Closing the tunnel will interrupt both the dial and
	// the request. While it's possible to add a timeout here, we leave it with no explicit
	// timeout which is the same as SSH API requests: if the tunnel has stalled then SSH keep
	// alives will cause the tunnel to close.

	dialer := NewCustomTLSDialer(
		&CustomTLSConfig{
			Parameters:              tunnel.config.GetParameters(),
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
	tunnelOwner TunnelOwner, tunnel *Tunnel, request *ssh.Request) {

	var err error

	switch request.Type {
	case protocol.PSIPHON_API_OSL_REQUEST_NAME:
		err = HandleOSLRequest(tunnelOwner, tunnel, request)
	case protocol.PSIPHON_API_ALERT_REQUEST_NAME:
		err = HandleAlertRequest(tunnelOwner, tunnel, request)
	default:
		err = errors.Tracef("invalid request name")
	}

	if err != nil {
		NoticeWarning(
			"HandleServerRequest for %s failed: %s", request.Type, errors.Trace(err))
	}
}

func HandleOSLRequest(
	tunnelOwner TunnelOwner, tunnel *Tunnel, request *ssh.Request) (retErr error) {

	defer func() {
		if retErr != nil {
			_ = request.Reply(false, nil)
		}
	}()

	var oslRequest protocol.OSLRequest
	err := json.Unmarshal(request.Payload, &oslRequest)
	if err != nil {
		return errors.Trace(err)
	}

	if oslRequest.ClearLocalSLOKs {
		err := DeleteSLOKs()
		if err != nil {
			NoticeWarning("DeleteSLOKs failed: %v", errors.Trace(err))
			// Continue
		}
	}

	seededNewSLOK := false

	for _, slok := range oslRequest.SeedPayload.SLOKs {
		duplicate, err := SetSLOK(slok.ID, slok.Key)
		if err != nil {
			// TODO: return error to trigger retry?
			NoticeWarning("SetSLOK failed: %v", errors.Trace(err))
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

	err = request.Reply(true, nil)
	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

func HandleAlertRequest(
	tunnelOwner TunnelOwner, tunnel *Tunnel, request *ssh.Request) (retErr error) {

	defer func() {
		if retErr != nil {
			_ = request.Reply(false, nil)
		}
	}()

	var alertRequest protocol.AlertRequest
	err := json.Unmarshal(request.Payload, &alertRequest)
	if err != nil {
		return errors.Trace(err)
	}

	if tunnel.config.EmitServerAlerts {
		NoticeServerAlert(alertRequest)
	}

	err = request.Reply(true, nil)
	if err != nil {
		return errors.Trace(err)
	}

	return nil
}
