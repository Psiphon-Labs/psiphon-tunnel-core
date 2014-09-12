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
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"strings"
)

// RemoteServerList is a JSON record containing a list of Psiphon server
// entries. As it may be downloaded from various sources, it is digitally
// signed so that the data may be authenticated.
type RemoteServerList struct {
	data                   string `json:"data"`
	signingPublicKeyDigest string `json:"signingPublicKeyDigest"`
	signature              string `json:"signature"`
}

// FetchRemoteServerList downloads a remote server list JSON record from
// config.RemoteServerListUrl; validates its digital signature using the
// public key config.RemoteServerListSignaturePublicKey; and parses the
// data field into ServerEntry records.
func FetchRemoteServerList(config *Config) (serverList []ServerEntry, err error) {
	serverList = make([]ServerEntry, 0)
	httpClient := http.Client{
		Timeout: FETCH_REMOTE_SERVER_LIST_TIMEOUT,
	}
	response, err := httpClient.Get(config.RemoteServerListUrl)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	var remoteServerList *RemoteServerList
	err = json.Unmarshal(body, &remoteServerList)
	if err != nil {
		return nil, err
	}
	err = validateRemoteServerList(config, remoteServerList)
	if err != nil {
		return nil, err
	}
	for _, hexEncodedServerListItem := range strings.Split(remoteServerList.data, "\n") {
		decodedServerListItem, err := hex.DecodeString(hexEncodedServerListItem)
		if err != nil {
			return nil, err
		}
		// Skip past legacy format (4 space delimited fields) and just parse the JSON config
		fields := strings.SplitN(string(decodedServerListItem), " ", 5)
		if len(fields) != 5 {
			return nil, errors.New("invalid remote server list item")
		}
		var serverEntry ServerEntry
		err = json.Unmarshal([]byte(fields[4]), &serverEntry)
		if err != nil {
			return nil, err
		}
		serverList = append(serverList, serverEntry)
	}
	return serverList, nil
}

func validateRemoteServerList(config *Config, remoteServerList *RemoteServerList) (err error) {
	derEncodedPublicKey, err := base64.StdEncoding.DecodeString(config.RemoteServerListSignaturePublicKey)
	if err != nil {
		return err
	}
	publicKey, err := x509.ParsePKIXPublicKey(derEncodedPublicKey)
	if err != nil {
		return err
	}
	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("unexpected RemoteServerListSignaturePublicKey key type")
	}
	signature, err := base64.StdEncoding.DecodeString(remoteServerList.signature)
	if err != nil {
		return err
	}
	// TODO: can detect if signed with different key --
	// match digest(publicKey) against remoteServerList.signingPublicKeyDigest
	hash := sha256.New()
	hash.Write([]byte(remoteServerList.data))
	digest := hash.Sum(nil)
	err = rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA256, digest, signature)
	if err != nil {
		return err
	}

	return nil
}
