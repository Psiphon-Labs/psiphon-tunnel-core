/*
 * Copyright (c) 2014, Psiphon Inc.
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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
)

// Session is a utility struct which holds all of the data associated
// with a Psiphon session. In addition to the established tunnel, this
// includes the session ID (used for Psiphon API requests) and the
// address to use to make tunnelled HTTPS API requests.
type Session struct {
	sessionId             string
	config                *Config
	tunnel                *Tunnel
	localHttpProxyAddress string
}

// NewSession makes tunnelled handshake and connected requests to the
// Psiphon server and returns a Session struct, initialized with the
// session ID, for use with subsequent Psiphon server API requests (e.g.,
// periodic status requests).
func NewSession(config *Config, tunnel *Tunnel, localHttpProxyAddress string) (session *Session, err error) {
	sessionId, err := MakeSessionId()
	if err != nil {
		return nil, ContextError(err)
	}
	session = &Session{
		sessionId:             sessionId,
		config:                config,
		tunnel:                tunnel,
		localHttpProxyAddress: localHttpProxyAddress,
	}
	// Sending two seperate requests is a legacy from when the handshake was
	// performed before a tunnel was established and the connect was performed
	// within the established tunnel. Here we perform both requests back-to-back
	// inside the tunnel.
	err = session.doHandshakeRequest()
	if err != nil {
		return nil, ContextError(err)
	}
	err = session.doConnectedRequest()
	if err != nil {
		return nil, ContextError(err)
	}
	return session, nil
}

func (session *Session) DoStatusRequest() {
	// TODO: implement (required for page view stats)
}

// doHandshakeRequest performs the handshake API request. The handshake
// returns upgrade info, newly discovered server entries -- which are
// stored -- and sponsor info (home pages, stat regexes).
func (session *Session) doHandshakeRequest() error {
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
	url := buildRequestUrl(session, "handshake", extraParams...)
	responseBody, err := doGetRequest(session, url)
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
	}
	err = json.Unmarshal(configLine, &handshakeConfig)
	if err != nil {
		return ContextError(err)
	}
	for _, encodedServerEntry := range handshakeConfig.EncodedServerList {
		serverEntry, err := DecodeServerEntry(encodedServerEntry)
		if err != nil {
			return ContextError(err)
		}
		err = StoreServerEntry(serverEntry, true)
		if err != nil {
			return ContextError(err)
		}
	}
	// TODO: formally communicate the sponsor and upgrade info to an
	// outer client via some control interface.
	for _, homepage := range handshakeConfig.Homepages {
		log.Printf("homepage: %s", homepage)
	}
	upgradeClientVersion, err := strconv.Atoi(handshakeConfig.UpgradeClientVersion)
	if err != nil {
		return ContextError(err)
	}
	if upgradeClientVersion > session.config.ClientVersion {
		log.Printf("upgrade available to client version: %d", upgradeClientVersion)
	}
	for _, pageViewRegex := range handshakeConfig.PageViewRegexes {
		log.Printf("page view regex: %s", pageViewRegex)
	}
	for _, httpsRequestRegex := range handshakeConfig.HttpsRequestRegexes {
		log.Printf("HTTPS regex: %s", httpsRequestRegex)
	}
	return nil
}

// doConnectedRequest performs the connected API request. This request is
// used for statistics. The server returns a last_connected token for
// the client to store and send next time it connects. This token is
// a timestamp (using the server clock, and should be rounded to the
// nearest hour) which is used to determine when a new connection is
// a unique user for a time period.
func (session *Session) doConnectedRequest() error {
	const DATA_STORE_LAST_CONNECTED_KEY = "lastConnected"
	lastConnected, err := GetKeyValue(DATA_STORE_LAST_CONNECTED_KEY)
	if err != nil {
		return ContextError(err)
	}
	if lastConnected == "" {
		lastConnected = "None"
	}
	url := buildRequestUrl(
		session,
		"connected",
		&ExtraParam{"session_id", session.sessionId},
		&ExtraParam{"last_connected", lastConnected})
	responseBody, err := doGetRequest(session, url)
	if err != nil {
		return ContextError(err)
	}
	var response struct {
		connectedTimestamp string `json:connected_timestamp`
	}
	err = json.Unmarshal(responseBody, &response)
	if err != nil {
		return ContextError(err)
	}
	err = SetKeyValue(DATA_STORE_LAST_CONNECTED_KEY, response.connectedTimestamp)
	if err != nil {
		return ContextError(err)
	}
	return nil
}

type ExtraParam struct{ name, value string }

// buildRequestUrl makes a URL containing all the common parameters
// that are included with Psiphon API requests. These common parameters
// are used for statistics.
func buildRequestUrl(session *Session, path string, extraParams ...*ExtraParam) string {
	var requestUrl bytes.Buffer
	requestUrl.WriteString("https://")
	requestUrl.WriteString(session.tunnel.serverEntry.IpAddress)
	requestUrl.WriteString(":")
	requestUrl.WriteString(session.tunnel.serverEntry.WebServerPort)
	requestUrl.WriteString("/")
	requestUrl.WriteString(path)
	requestUrl.WriteString("?client_session_id=")
	requestUrl.WriteString(session.sessionId)
	requestUrl.WriteString("&server_secret=")
	requestUrl.WriteString(session.tunnel.serverEntry.WebServerSecret)
	requestUrl.WriteString("&propagation_channel_id=")
	requestUrl.WriteString(session.config.PropagationChannelId)
	requestUrl.WriteString("&sponsor_id=")
	requestUrl.WriteString(session.config.SponsorId)
	requestUrl.WriteString("&client_version=")
	requestUrl.WriteString(strconv.Itoa(session.config.ClientVersion))
	// TODO: client_tunnel_core_version
	requestUrl.WriteString("&relay_protocol=")
	requestUrl.WriteString(session.tunnel.protocol)
	requestUrl.WriteString("&client_platform=")
	requestUrl.WriteString(session.config.ClientPlatform)
	requestUrl.WriteString("&tunnel_whole_device=")
	requestUrl.WriteString(strconv.Itoa(session.config.TunnelWholeDevice))
	for _, extraParam := range extraParams {
		requestUrl.WriteString("&")
		requestUrl.WriteString(extraParam.name)
		requestUrl.WriteString("=")
		requestUrl.WriteString(extraParam.value)
	}
	return requestUrl.String()
}

// doGetRequest makes a tunneled HTTPS request, validating the server using the server
// entry web server certificate. This function discards its http.Client after a single
// use -- it is not intended for making many requests.
func doGetRequest(session *Session, requestUrl string) (responseBody []byte, err error) {
	proxyUrl, err := url.Parse(fmt.Sprintf("http://%s", session.localHttpProxyAddress))
	if err != nil {
		return nil, ContextError(err)
	}
	proxy := http.ProxyURL(proxyUrl)
	certificate, err := DecodeCertificate(session.tunnel.serverEntry.WebServerCertificate)
	if err != nil {
		return nil, ContextError(err)
	}
	certPool := x509.NewCertPool()
	certPool.AddCert(certificate)
	// Copy default transport for its timeout values
	transport := new(http.Transport)
	*transport = *http.DefaultTransport.(*http.Transport)
	// ****** SECURITY ISSUE ******
	// TODO: temporarily using InsecureSkipVerify to work around hostname verification error:
	// "x509: cannot validate certificate for " + h.Host + " because it doesn't contain any IP SANs"
	// Notes:
	// - Since Psiphon server self-signed certs don't have IP SANs, we need to disable that part
	// of verification. We can't add IP SANs.
	// - We can't easily supply a custom TLS dialer (e.g., such as https://github.com/getlantern/tlsdialer)
	// since the dialer has to deal with HTTP proxying before talkng TLS. See:
	// dialConn in http://golang.org/src/pkg/net/http/transport.go
	// - Mitigating factor: the InsecureSkipVerify TLS is done through the secure, authenticated tunnel
	// and terminates at the tunnel server host.
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true, RootCAs: certPool}
	transport.Proxy = proxy
	httpClient := &http.Client{Transport: transport}
	response, err := httpClient.Get(requestUrl)
	if err != nil {
		return nil, ContextError(err)
	}
	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, ContextError(err)
	}
	if response.StatusCode != http.StatusOK {
		return nil, ContextError(fmt.Errorf("HTTP GET request failed with response code: %d", response.StatusCode))
	}
	return body, nil
}
