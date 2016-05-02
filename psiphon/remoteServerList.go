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
	"compress/zlib"
	"errors"
	"io/ioutil"
	"os"
	"strings"
	"time"
)

// FetchRemoteServerList downloads a remote server list JSON record from
// config.RemoteServerListUrl; validates its digital signature using the
// public key config.RemoteServerListSignaturePublicKey; and parses the
// data field into ServerEntry records.
func FetchRemoteServerList(
	config *Config,
	tunnel *Tunnel,
	untunneledDialConfig *DialConfig) (err error) {

	NoticeInfo("fetching remote server list")

	if config.RemoteServerListUrl == "" {
		return ContextError(errors.New("remote server list URL is blank"))
	}
	if config.RemoteServerListSignaturePublicKey == "" {
		return ContextError(errors.New("remote server list signature public key blank"))
	}

	// Select tunneled or untunneled configuration

	httpClient, requestUrl, err := makeDownloadHttpClient(
		config,
		tunnel,
		untunneledDialConfig,
		config.RemoteServerListUrl,
		time.Duration(*config.FetchRemoteServerListTimeoutSeconds)*time.Second)
	if err != nil {
		return ContextError(err)
	}

	// Proceed with download

	splitPath := strings.Split(config.RemoteServerListUrl, "/")
	downloadFilename := splitPath[len(splitPath)-1]

	lastETag, err := GetUrlETag(config.RemoteServerListUrl)
	if err != nil {
		return ContextError(err)
	}

	n, responseETag, err := resumeDownload(
		httpClient, requestUrl, downloadFilename, lastETag)

	if responseETag == lastETag {
		// The remote server list is unchanged and no data was downloaded
		return nil
	}

	NoticeRemoteServerListDownloadedBytes(n)

	if err != nil {
		return ContextError(err)
	}

	NoticeRemoteServerListDownloaded()

	// The downloaded content is a zlib compressed authenticated
	// data package containing a list of encoded server entries.

	downloadContent, err := os.Open(downloadFilename)
	if err != nil {
		return ContextError(err)
	}
	defer downloadContent.Close()

	zlibReader, err := zlib.NewReader(downloadContent)
	if err != nil {
		return ContextError(err)
	}

	dataPackage, err := ioutil.ReadAll(zlibReader)
	zlibReader.Close()
	if err != nil {
		return ContextError(err)
	}

	remoteServerList, err := ReadAuthenticatedDataPackage(
		dataPackage, config.RemoteServerListSignaturePublicKey)
	if err != nil {
		return ContextError(err)
	}

	serverEntries, err := DecodeAndValidateServerEntryList(
		remoteServerList,
		GetCurrentTimestamp(),
		SERVER_ENTRY_SOURCE_REMOTE)
	if err != nil {
		return ContextError(err)
	}

	err = StoreServerEntries(serverEntries, true)
	if err != nil {
		return ContextError(err)
	}

	// Now that the server entries are successfully imported, store the response
	// ETag so we won't re-download this same data again.

	if responseETag != "" {
		err := SetUrlETag(config.RemoteServerListUrl, responseETag)
		if err != nil {
			NoticeAlert("failed to set remote server list ETag: %s", ContextError(err))
			// This fetch is still reported as a success, even if we can't store the etag
		}
	}

	return nil
}
