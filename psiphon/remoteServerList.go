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
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
)

// FetchRemoteServerList downloads a remote server list JSON record from
// config.RemoteServerListUrl; validates its digital signature using the
// public key config.RemoteServerListSignaturePublicKey; and parses the
// data field into ServerEntry records.
func FetchRemoteServerList(config *Config, dialConfig *DialConfig) (err error) {
	NoticeInfo("fetching remote server list")

	if config.RemoteServerListUrl == "" {
		return ContextError(errors.New("remote server list URL is blank"))
	}
	if config.RemoteServerListSignaturePublicKey == "" {
		return ContextError(errors.New("remote server list signature public key blank"))
	}

	dialer := NewTCPDialer(dialConfig)

	// When the URL is HTTPS, use the custom TLS dialer with the
	// UseIndistinguishableTLS option.
	// TODO: refactor into helper function
	requestUrl, err := url.Parse(config.RemoteServerListUrl)
	if err != nil {
		return ContextError(err)
	}
	if requestUrl.Scheme == "https" {
		dialer = NewCustomTLSDialer(
			&CustomTLSConfig{
				Dial:                          dialer,
				SendServerName:                true,
				SkipVerify:                    false,
				UseIndistinguishableTLS:       config.UseIndistinguishableTLS,
				TrustedCACertificatesFilename: config.TrustedCACertificatesFilename,
			})

		// Change the scheme to "http"; otherwise http.Transport will try to do
		// another TLS handshake inside the explicit TLS session. Also need to
		// force the port to 443,as the default for "http", 80, won't talk TLS.
		requestUrl.Scheme = "http"
		host, _, err := net.SplitHostPort(requestUrl.Host)
		if err != nil {
			// Assume there's no port
			host = requestUrl.Host
		}
		requestUrl.Host = net.JoinHostPort(host, "443")
	}

	transport := &http.Transport{
		Dial: dialer,
	}
	httpClient := http.Client{
		Timeout:   FETCH_REMOTE_SERVER_LIST_TIMEOUT,
		Transport: transport,
	}

	request, err := http.NewRequest("GET", requestUrl.String(), nil)
	if err != nil {
		return ContextError(err)
	}

	etag, err := GetUrlETag(config.RemoteServerListUrl)
	if err != nil {
		return ContextError(err)
	}
	if etag != "" {
		request.Header.Add("If-None-Match", etag)
	}

	response, err := httpClient.Do(request)

	if err == nil &&
		(response.StatusCode != http.StatusOK && response.StatusCode != http.StatusNotModified) {
		response.Body.Close()
		err = fmt.Errorf("unexpected response status code: %d", response.StatusCode)
	}
	if err != nil {
		return ContextError(err)
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusNotModified {
		return nil
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return ContextError(err)
	}

	remoteServerList, err := ReadAuthenticatedDataPackage(
		body, config.RemoteServerListSignaturePublicKey)
	if err != nil {
		return ContextError(err)
	}

	serverEntries, err := DecodeAndValidateServerEntryList(remoteServerList)
	if err != nil {
		return ContextError(err)
	}

	err = StoreServerEntries(serverEntries, true)
	if err != nil {
		return ContextError(err)
	}

	etag = response.Header.Get("ETag")
	if etag != "" {
		err := SetUrlETag(config.RemoteServerListUrl, etag)
		if err != nil {
			NoticeAlert("failed to set remote server list etag: %s", ContextError(err))
			// This fetch is still reported as a success, even if we can't store the etag
		}
	}

	return nil
}
