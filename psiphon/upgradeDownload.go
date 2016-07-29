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
	"fmt"
	"net/http"
	"os"
	"strconv"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
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

	httpClient, requestUrl, err := MakeDownloadHttpClient(
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
			return common.ContextError(err)
		}
		response, err := httpClient.Do(request)
		if err == nil && response.StatusCode != http.StatusOK {
			response.Body.Close()
			err = fmt.Errorf("unexpected response status code: %d", response.StatusCode)
		}
		if err != nil {
			return common.ContextError(err)
		}
		defer response.Body.Close()

		currentClientVersion, err := strconv.Atoi(config.ClientVersion)
		if err != nil {
			return common.ContextError(err)
		}

		// Note: if the header is missing, Header.Get returns "" and then
		// strconv.Atoi returns a parse error.
		availableClientVersion = response.Header.Get(config.UpgradeDownloadClientVersionHeader)
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

	n, _, err := ResumeDownload(
		httpClient, requestUrl, downloadFilename, "")

	NoticeClientUpgradeDownloadedBytes(n)

	if err != nil {
		return common.ContextError(err)
	}

	err = os.Rename(downloadFilename, config.UpgradeDownloadFilename)
	if err != nil {
		return common.ContextError(err)
	}

	NoticeClientUpgradeDownloaded(config.UpgradeDownloadFilename)

	return nil
}
