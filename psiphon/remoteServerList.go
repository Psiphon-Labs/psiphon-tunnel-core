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
	"io/ioutil"
	"net/http"
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

	transport := &http.Transport{
		Dial: NewTCPDialer(dialConfig),
	}
	httpClient := http.Client{
		Timeout:   FETCH_REMOTE_SERVER_LIST_TIMEOUT,
		Transport: transport,
	}

	response, err := httpClient.Get(config.RemoteServerListUrl)
	if err != nil {
		return ContextError(err)
	}
	defer response.Body.Close()

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

	return nil
}
