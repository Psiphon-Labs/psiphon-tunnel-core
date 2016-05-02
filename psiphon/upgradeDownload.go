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
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"time"
)

// DownloadUpgrade performs a resumable download of client upgrade files.
//
// While downloading/resuming, a temporary file is used. Once the download is complete,
// a notice is issued and the upgrade is available at the destination specified in
// config.UpgradeDownloadFilename.
//
// The upgrade download may be either tunneled or untunneled. As the untunneled case may
// happen with no handshake request response, the downloader cannot rely on having the
// upgrade_client_version output from handshake and instead this logic performs a
// comparison between the config.ClientVersion and the client version recorded in the
// remote entity's UpgradeDownloadClientVersionHeader. A HEAD request is made to check the
// version before proceeding with a full download.
//
// NOTE: This code does not check that any existing file at config.UpgradeDownloadFilename
// is actually the version specified in handshakeVersion.
//
// TODO: This logic requires the outer client to *omit* config.UpgradeDownloadFilename
// when there's already a downloaded upgrade pending. Because the outer client currently
// handles the authenticated package phase, and because the outer client deletes the
// intermediate files (including config.UpgradeDownloadFilename), if the outer client
// does not omit config.UpgradeDownloadFilename then the new version will be downloaded
// repeatedly. Implement a new scheme where tunnel core does the authenticated package phase
// and tracks the the output by version number so that (a) tunnel core knows when it's not
// necessary to re-download; (b) newer upgrades will be downloaded even when an older
// upgrade is still pending install by the outer client.
func DownloadUpgrade(
	config *Config,
	handshakeVersion string,
	tunnel *Tunnel,
	untunneledDialConfig *DialConfig) error {

	// Check if complete file already downloaded

	if _, err := os.Stat(config.UpgradeDownloadFilename); err == nil {
		NoticeClientUpgradeDownloaded(config.UpgradeDownloadFilename)
		return nil
	}

	// Select tunneled or untunneled configuration

	httpClient, requestUrl, err := makeDownloadHttpClient(
		config,
		tunnel,
		untunneledDialConfig,
		config.UpgradeDownloadUrl,
		DOWNLOAD_UPGRADE_TIMEOUT)

	// If no handshake version is supplied, make an initial HEAD request
	// to get the current version from the version header.

	availableClientVersion := handshakeVersion
	if availableClientVersion == "" {
		request, err := http.NewRequest("HEAD", requestUrl, nil)
		if err != nil {
			return ContextError(err)
		}
		response, err := httpClient.Do(request)
		if err == nil && response.StatusCode != http.StatusOK {
			response.Body.Close()
			err = fmt.Errorf("unexpected response status code: %d", response.StatusCode)
		}
		if err != nil {
			return ContextError(err)
		}
		defer response.Body.Close()

		currentClientVersion, err := strconv.Atoi(config.ClientVersion)
		if err != nil {
			return ContextError(err)
		}

		// Note: if the header is missing, Header.Get returns "" and then
		// strconv.Atoi returns a parse error.
		availableClientVersion := response.Header.Get(config.UpgradeDownloadClientVersionHeader)
		checkAvailableClientVersion, err := strconv.Atoi(availableClientVersion)
		if err != nil {
			// If the header is missing or malformed, we can't determine the available
			// version number. This is unexpected; but if it happens, it's likely due
			// to a server-side configuration issue. In this one case, we don't
			// return an error so that we don't go into a rapid retry loop making
			// ineffective HEAD requests (the client may still signal an upgrade
			// download later in the session).
			NoticeAlert(
				"failed to download upgrade: invalid %s header value %s: %s",
				config.UpgradeDownloadClientVersionHeader, availableClientVersion, err)
			return nil
		}

		if currentClientVersion >= checkAvailableClientVersion {
			NoticeClientIsLatestVersion(availableClientVersion)
			return nil
		}
	}

	// Proceed with download

	// An intermediate filename is used since the presence of
	// config.UpgradeDownloadFilename indicates a completed download.

	downloadFilename := fmt.Sprintf(
		"%s.%s", config.UpgradeDownloadFilename, availableClientVersion)

	n, _, err := resumeDownload(
		httpClient, requestUrl, downloadFilename, "")

	NoticeClientUpgradeDownloadedBytes(n)

	if err != nil {
		return ContextError(err)
	}

	err = os.Rename(downloadFilename, config.UpgradeDownloadFilename)
	if err != nil {
		return ContextError(err)
	}

	NoticeClientUpgradeDownloaded(config.UpgradeDownloadFilename)

	return nil
}

// makeDownloadHttpClient is a resusable helper that sets up a
// http.Client for use either untunneled or through a tunnel.
// See MakeUntunneledHttpsClient for a note about request URL
// rewritting.
func makeDownloadHttpClient(
	config *Config,
	tunnel *Tunnel,
	untunneledDialConfig *DialConfig,
	requestUrl string,
	requestTimeout time.Duration) (*http.Client, string, error) {

	var httpClient *http.Client
	var err error

	if tunnel != nil {
		httpClient, err = MakeTunneledHttpClient(config, tunnel, requestTimeout)
		if err != nil {
			return nil, "", ContextError(err)
		}
	} else {
		httpClient, requestUrl, err = MakeUntunneledHttpsClient(
			untunneledDialConfig, nil, requestUrl, requestTimeout)
		if err != nil {
			return nil, "", ContextError(err)
		}
	}

	return httpClient, requestUrl, nil
}

// resumeDownload is a resuable helper that downloads requestUrl via the
// httpClient, storing the result in downloadFilename when the download is
// complete. Intermediate, partial downloads state is stored in
// downloadFilename.part and downloadFilename.part.etag.
//
// In the case where the remote object has change while a partial download
// is to be resumed, the partial state is reset and resumeDownload fails.
// The caller must restart the download.
//
// When ifNoneMatchETag is specified, no download is made if the remote
// object has the same ETag. ifNoneMatchETag has an effect only when no
// partial download is in progress.
//
func resumeDownload(
	httpClient *http.Client,
	requestUrl string,
	downloadFilename string,
	ifNoneMatchETag string) (int64, string, error) {

	partialFilename := fmt.Sprintf("%s.part", downloadFilename)

	partialETagFilename := fmt.Sprintf("%s.part.etag", downloadFilename)

	file, err := os.OpenFile(partialFilename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return 0, "", ContextError(err)
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return 0, "", ContextError(err)
	}

	// A partial download should have an ETag which is to be sent with the
	// Range request to ensure that the source object is the same as the
	// one that is partially downloaded.
	var partialETag []byte
	if fileInfo.Size() > 0 {

		partialETag, err = ioutil.ReadFile(partialETagFilename)

		// When the ETag can't be loaded, delete the partial download. To keep the
		// code simple, there is no immediate, inline retry here, on the assumption
		// that the controller's upgradeDownloader will shortly call DownloadUpgrade
		// again.
		if err != nil {
			os.Remove(partialFilename)
			os.Remove(partialETagFilename)
			return 0, "", ContextError(
				fmt.Errorf("failed to load partial download ETag: %s", err))
		}
	}

	request, err := http.NewRequest("GET", requestUrl, nil)
	if err != nil {
		return 0, "", ContextError(err)
	}

	request.Header.Add("Range", fmt.Sprintf("bytes=%d-", fileInfo.Size()))

	if partialETag != nil {

		// Note: not using If-Range, since not all host servers support it.
		// Using If-Match means we need to check for status code 412 and reset
		// when the ETag has changed since the last partial download.
		request.Header.Add("If-Match", string(partialETag))

	} else if ifNoneMatchETag != "" {

		// Can't specify both If-Match and If-None-Match. Behavior is undefined.
		// https://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.26
		// So for downloaders that store an ETag and wish to use that to prevent
		// redundant downloads, that ETag is sent as If-None-Match in the case
		// where a partial download is not in progress. When a partial download
		// is in progress, the partial ETag is sent as If-Match: either that's
		// a version that was never fully received, or it's no longer current in
		// which case the response will be StatusPreconditionFailed, the partial
		// download will be discarded, and then the next retry will use
		// If-None-Match.

		// Note: in this case, fileInfo.Size() == 0

		request.Header.Add("If-None-Match", ifNoneMatchETag)
	}

	response, err := httpClient.Do(request)

	// The resumeable download may ask for bytes past the resource range
	// since it doesn't store the "completed download" state. In this case,
	// the HTTP server returns 416. Otherwise, we expect 206. We may also
	// receive 412 on ETag mismatch.
	if err == nil &&
		(response.StatusCode != http.StatusPartialContent &&
			response.StatusCode != http.StatusRequestedRangeNotSatisfiable &&
			response.StatusCode != http.StatusPreconditionFailed &&
			response.StatusCode != http.StatusNotModified) {
		response.Body.Close()
		err = fmt.Errorf("unexpected response status code: %d", response.StatusCode)
	}
	if err != nil {
		return 0, "", ContextError(err)
	}
	defer response.Body.Close()

	responseETag := response.Header.Get("ETag")

	if response.StatusCode == http.StatusPreconditionFailed {
		// When the ETag no longer matches, delete the partial download. As above,
		// simply failing and relying on the caller's retry schedule.
		os.Remove(partialFilename)
		os.Remove(partialETagFilename)
		return 0, "", ContextError(errors.New("partial download ETag mismatch"))

	} else if response.StatusCode == http.StatusNotModified {
		// This status code is possible in the "If-None-Match" case. Don't leave
		// any partial download in progress. Caller should check that responseETag
		// matches ifNoneMatchETag.
		os.Remove(partialFilename)
		os.Remove(partialETagFilename)
		return 0, responseETag, nil
	}

	// Not making failure to write ETag file fatal, in case the entire download
	// succeeds in this one request.
	ioutil.WriteFile(partialETagFilename, []byte(responseETag), 0600)

	// A partial download occurs when this copy is interrupted. The io.Copy
	// will fail, leaving a partial download in place (.part and .part.etag).
	n, err := io.Copy(NewSyncFileWriter(file), response.Body)

	if err != nil {
		return 0, "", ContextError(err)
	}

	// Ensure the file is flushed to disk. The deferred close
	// will be a noop when this succeeds.
	err = file.Close()
	if err != nil {
		return 0, "", ContextError(err)
	}

	err = os.Rename(partialFilename, downloadFilename)
	if err != nil {
		return 0, "", ContextError(err)
	}

	os.Remove(partialETagFilename)

	return n, responseETag, nil
}
