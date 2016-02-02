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
)

// DownloadUpgrade performs a tunneled, resumable download of client upgrade files.
// While downloading/resuming, a temporary file is used. Once the download is complete,
// a notice is issued and the upgrade is available at the destination specified in
// config.UpgradeDownloadFilename.
// NOTE: this code does not check that any existing file at config.UpgradeDownloadFilename
// is actually the version specified in clientUpgradeVersion.
func DownloadUpgrade(config *Config, clientUpgradeVersion string, tunnel *Tunnel) error {

	// Check if complete file already downloaded
	if _, err := os.Stat(config.UpgradeDownloadFilename); err == nil {
		NoticeClientUpgradeDownloaded(config.UpgradeDownloadFilename)
		return nil
	}

	httpClient, err := MakeTunneledHttpClient(config, tunnel, DOWNLOAD_UPGRADE_TIMEOUT)
	if err != nil {
		return ContextError(err)
	}

	partialFilename := fmt.Sprintf(
		"%s.%s.part", config.UpgradeDownloadFilename, clientUpgradeVersion)

	partialETagFilename := fmt.Sprintf(
		"%s.%s.part.etag", config.UpgradeDownloadFilename, clientUpgradeVersion)

	file, err := os.OpenFile(partialFilename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return ContextError(err)
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return ContextError(err)
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
			return ContextError(
				fmt.Errorf("failed to load partial download ETag: %s", err))
		}

	}

	request, err := http.NewRequest("GET", config.UpgradeDownloadUrl, nil)
	if err != nil {
		return ContextError(err)
	}
	request.Header.Add("Range", fmt.Sprintf("bytes=%d-", fileInfo.Size()))

	// Note: not using If-Range, since not all remote server list host servers
	// support it. Using If-Match means we need to check for status code 412
	// and reset when the ETag has changed since the last partial download.
	if partialETag != nil {
		request.Header.Add("If-Match", string(partialETag))
	}

	response, err := httpClient.Do(request)

	// The resumeable download may ask for bytes past the resource range
	// since it doesn't store the "completed download" state. In this case,
	// the HTTP server returns 416. Otherwise, we expect 206. We may also
	// receive 412 on ETag mismatch.
	if err == nil &&
		(response.StatusCode != http.StatusPartialContent &&
			response.StatusCode != http.StatusRequestedRangeNotSatisfiable &&
			response.StatusCode != http.StatusPreconditionFailed) {
		response.Body.Close()
		err = fmt.Errorf("unexpected response status code: %d", response.StatusCode)
	}
	if err != nil {
		return ContextError(err)
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusPreconditionFailed {
		// When the ETag no longer matches, delete the partial download. As above,
		// simply failing and relying on the controller's upgradeDownloader retry.
		os.Remove(partialFilename)
		os.Remove(partialETagFilename)
		return ContextError(errors.New("partial download ETag mismatch"))
	}

	// Not making failure to write ETag file fatal, in case the entire download
	// succeeds in this one request.
	ioutil.WriteFile(partialETagFilename, []byte(response.Header.Get("ETag")), 0600)

	// A partial download occurs when this copy is interrupted. The io.Copy
	// will fail, leaving a partial download in place (.part and .part.etag).
	n, err := io.Copy(NewSyncFileWriter(file), response.Body)
	if err != nil {
		return ContextError(err)
	}

	NoticeInfo("client upgrade downloaded bytes: %d", n)

	// Ensure the file is flushed to disk. The deferred close
	// will be a noop when this succeeds.
	err = file.Close()
	if err != nil {
		return ContextError(err)
	}

	err = os.Rename(partialFilename, config.UpgradeDownloadFilename)
	if err != nil {
		return ContextError(err)
	}

	os.Remove(partialETagFilename)

	NoticeClientUpgradeDownloaded(config.UpgradeDownloadFilename)

	return nil
}
