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
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/osl"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
)

type RemoteServerListFetcher func(
	ctx context.Context, config *Config, attempt int, tunnel *Tunnel, untunneledDialConfig *DialConfig) error

// FetchCommonRemoteServerList downloads the common remote server list from
// config.RemoteServerListUrl. It validates its digital signature using the
// public key config.RemoteServerListSignaturePublicKey and parses the
// data field into ServerEntry records.
// config.RemoteServerListDownloadFilename is the location to store the
// download. As the download is resumed after failure, this filename must
// be unique and persistent.
func FetchCommonRemoteServerList(
	ctx context.Context,
	config *Config,
	attempt int,
	tunnel *Tunnel,
	untunneledDialConfig *DialConfig) error {

	NoticeInfo("fetching common remote server list")

	p := config.clientParameters.Get()
	publicKey := p.String(parameters.RemoteServerListSignaturePublicKey)
	urls := p.DownloadURLs(parameters.RemoteServerListURLs)
	downloadTimeout := p.Duration(parameters.FetchRemoteServerListTimeout)
	p = nil

	downloadURL, canonicalURL, skipVerify := urls.Select(attempt)

	newETag, err := downloadRemoteServerListFile(
		ctx,
		config,
		tunnel,
		untunneledDialConfig,
		downloadTimeout,
		downloadURL,
		canonicalURL,
		skipVerify,
		"",
		config.RemoteServerListDownloadFilename)
	if err != nil {
		return fmt.Errorf("failed to download common remote server list: %s", common.ContextError(err))
	}

	// When the resource is unchanged, skip.
	if newETag == "" {
		return nil
	}

	file, err := os.Open(config.RemoteServerListDownloadFilename)
	if err != nil {
		return fmt.Errorf("failed to open common remote server list: %s", common.ContextError(err))

	}
	defer file.Close()

	serverListPayloadReader, err := common.NewAuthenticatedDataPackageReader(
		file, publicKey)
	if err != nil {
		return fmt.Errorf("failed to read remote server list: %s", common.ContextError(err))
	}

	err = StreamingStoreServerEntries(
		config,
		protocol.NewStreamingServerEntryDecoder(
			serverListPayloadReader,
			common.GetCurrentTimestamp(),
			protocol.SERVER_ENTRY_SOURCE_REMOTE),
		true)
	if err != nil {
		return fmt.Errorf("failed to store common remote server list: %s", common.ContextError(err))
	}

	// Now that the server entries are successfully imported, store the response
	// ETag so we won't re-download this same data again.
	err = SetUrlETag(canonicalURL, newETag)
	if err != nil {
		NoticeAlert("failed to set ETag for common remote server list: %s", common.ContextError(err))
		// This fetch is still reported as a success, even if we can't store the etag
	}

	return nil
}

// FetchObfuscatedServerLists downloads the obfuscated remote server lists
// from config.ObfuscatedServerListRootURL.
// It first downloads the OSL registry, and then downloads each seeded OSL
// advertised in the registry. All downloads are resumable, ETags are used
// to skip both an unchanged registry or unchanged OSL files, and when an
// individual download fails, the fetch proceeds if it can.
// Authenticated package digital signatures are validated using the
// public key config.RemoteServerListSignaturePublicKey.
// config.ObfuscatedServerListDownloadDirectory is the location to store the
// downloaded files. As  downloads are resumed after failure, this directory
// must be unique and persistent.
func FetchObfuscatedServerLists(
	ctx context.Context,
	config *Config,
	attempt int,
	tunnel *Tunnel,
	untunneledDialConfig *DialConfig) error {

	NoticeInfo("fetching obfuscated remote server lists")

	p := config.clientParameters.Get()
	publicKey := p.String(parameters.RemoteServerListSignaturePublicKey)
	urls := p.DownloadURLs(parameters.ObfuscatedServerListRootURLs)
	downloadTimeout := p.Duration(parameters.FetchRemoteServerListTimeout)
	p = nil

	rootURL, canonicalRootURL, skipVerify := urls.Select(attempt)
	downloadURL := osl.GetOSLRegistryURL(rootURL)
	canonicalURL := osl.GetOSLRegistryURL(canonicalRootURL)

	downloadFilename := osl.GetOSLRegistryFilename(config.ObfuscatedServerListDownloadDirectory)
	cachedFilename := downloadFilename + ".cached"

	// If the cached registry is not present, we need to download or resume downloading
	// the registry, so clear the ETag to ensure that always happens.
	_, err := os.Stat(cachedFilename)
	if os.IsNotExist(err) {
		SetUrlETag(canonicalURL, "")
	}

	// failed is set if any operation fails and should trigger a retry. When the OSL registry
	// fails to download, any cached registry is used instead; when any single OSL fails
	// to download, the overall operation proceeds. So this flag records whether to report
	// failure at the end when downloading has proceeded after a failure.
	// TODO: should disk-full conditions not trigger retries?
	var failed bool

	// updateCache is set when modifed registry content is downloaded. Both the cached
	// file and the persisted ETag will be updated in this case. The update is deferred
	// until after the registry has been authenticated.
	updateCache := false
	registryFilename := cachedFilename

	newETag, err := downloadRemoteServerListFile(
		ctx,
		config,
		tunnel,
		untunneledDialConfig,
		downloadTimeout,
		downloadURL,
		canonicalURL,
		skipVerify,
		"",
		downloadFilename)
	if err != nil {
		failed = true
		NoticeAlert("failed to download obfuscated server list registry: %s", common.ContextError(err))
		// Proceed with any existing cached OSL registry.
	} else if newETag != "" {
		updateCache = true
		registryFilename = downloadFilename
	}

	lookupSLOKs := func(slokID []byte) []byte {
		// Lookup SLOKs in local datastore
		key, err := GetSLOK(slokID)
		if err != nil {
			NoticeAlert("GetSLOK failed: %s", err)
		}
		return key
	}

	registryFile, err := os.Open(registryFilename)
	if err != nil {
		return fmt.Errorf("failed to read obfuscated server list registry: %s", common.ContextError(err))
	}
	defer registryFile.Close()

	registryStreamer, err := osl.NewRegistryStreamer(
		registryFile,
		publicKey,
		lookupSLOKs)
	if err != nil {
		// TODO: delete file? redownload if corrupt?
		return fmt.Errorf("failed to read obfuscated server list registry: %s", common.ContextError(err))
	}

	// NewRegistryStreamer authenticates the downloaded registry, so now it would be
	// ok to update the cache. However, we defer that until after processing so we
	// can close the file first before copying it, avoiding related complications on
	// platforms such as Windows.

	// Note: we proceed to check individual OSLs even if the directory is unchanged,
	// as the set of local SLOKs may have changed.

	for {

		oslFileSpec, err := registryStreamer.Next()
		if err != nil {
			failed = true
			NoticeAlert("failed to stream obfuscated server list registry: %s", common.ContextError(err))
			break
		}

		if oslFileSpec == nil {
			break
		}

		downloadFilename := osl.GetOSLFilename(
			config.ObfuscatedServerListDownloadDirectory, oslFileSpec.ID)

		downloadURL := osl.GetOSLFileURL(rootURL, oslFileSpec.ID)
		canonicalURL := osl.GetOSLFileURL(canonicalRootURL, oslFileSpec.ID)

		hexID := hex.EncodeToString(oslFileSpec.ID)

		// Note: the MD5 checksum step assumes the remote server list host's ETag uses MD5
		// with a hex encoding. If this is not the case, the sourceETag should be left blank.
		sourceETag := fmt.Sprintf("\"%s\"", hex.EncodeToString(oslFileSpec.MD5Sum))

		newETag, err := downloadRemoteServerListFile(
			ctx,
			config,
			tunnel,
			untunneledDialConfig,
			downloadTimeout,
			downloadURL,
			canonicalURL,
			skipVerify,
			sourceETag,
			downloadFilename)
		if err != nil {
			failed = true
			NoticeAlert("failed to download obfuscated server list file (%s): %s", hexID, common.ContextError(err))
			continue
		}

		// When the resource is unchanged, skip.
		if newETag == "" {
			continue
		}

		file, err := os.Open(downloadFilename)
		if err != nil {
			failed = true
			NoticeAlert("failed to open obfuscated server list file (%s): %s", hexID, common.ContextError(err))
			continue
		}
		// Note: don't defer file.Close() since we're in a loop

		serverListPayloadReader, err := osl.NewOSLReader(
			file,
			oslFileSpec,
			lookupSLOKs,
			publicKey)
		if err != nil {
			file.Close()
			failed = true
			NoticeAlert("failed to read obfuscated server list file (%s): %s", hexID, common.ContextError(err))
			continue
		}

		err = StreamingStoreServerEntries(
			config,
			protocol.NewStreamingServerEntryDecoder(
				serverListPayloadReader,
				common.GetCurrentTimestamp(),
				protocol.SERVER_ENTRY_SOURCE_OBFUSCATED),
			true)
		if err != nil {
			file.Close()
			failed = true
			NoticeAlert("failed to store obfuscated server list file (%s): %s", hexID, common.ContextError(err))
			continue
		}

		// Now that the server entries are successfully imported, store the response
		// ETag so we won't re-download this same data again.
		err = SetUrlETag(canonicalURL, newETag)
		if err != nil {
			file.Close()
			NoticeAlert("failed to set ETag for obfuscated server list file (%s): %s", hexID, common.ContextError(err))
			continue
			// This fetch is still reported as a success, even if we can't store the ETag
		}

		file.Close()

		// Clear the reference to this OSL file streamer and immediately run
		// a garbage collection to reclaim its memory before processing the
		// next file.
		serverListPayloadReader = nil
		defaultGarbageCollection()
	}

	// Now that a new registry is downloaded, validated, and parsed, store
	// the response ETag so we won't re-download this same data again. First
	// close the file to avoid complications on platforms such as Windows.
	if updateCache {

		registryFile.Close()

		err := os.Rename(downloadFilename, cachedFilename)
		if err != nil {
			NoticeAlert("failed to set cached obfuscated server list registry: %s", common.ContextError(err))
			// This fetch is still reported as a success, even if we can't update the cache
		}

		err = SetUrlETag(canonicalURL, newETag)
		if err != nil {
			NoticeAlert("failed to set ETag for obfuscated server list registry: %s", common.ContextError(err))
			// This fetch is still reported as a success, even if we can't store the ETag
		}
	}

	if failed {
		return errors.New("one or more operations failed")
	}

	return nil
}

// downloadRemoteServerListFile downloads the source URL to
// the destination file, performing a resumable download. When
// the download completes and the file content has changed, the
// new resource ETag is returned. Otherwise, blank is returned.
// The caller is responsible for calling SetUrlETag once the file
// content has been validated.
func downloadRemoteServerListFile(
	ctx context.Context,
	config *Config,
	tunnel *Tunnel,
	untunneledDialConfig *DialConfig,
	downloadTimeout time.Duration,
	sourceURL string,
	canonicalURL string,
	skipVerify bool,
	sourceETag string,
	destinationFilename string) (string, error) {

	// All download URLs with the same canonicalURL
	// must have the same entity and ETag.
	lastETag, err := GetUrlETag(canonicalURL)
	if err != nil {
		return "", common.ContextError(err)
	}

	// sourceETag, when specified, is prior knowledge of the
	// remote ETag that can be used to skip the request entirely.
	// This will be set in the case of OSL files, from the MD5Sum
	// values stored in the registry.
	if lastETag != "" && sourceETag == lastETag {
		// TODO: notice?
		return "", nil
	}

	var cancelFunc context.CancelFunc
	ctx, cancelFunc = context.WithTimeout(ctx, downloadTimeout)
	defer cancelFunc()

	// MakeDownloadHttpClient will select either a tunneled
	// or untunneled configuration.

	httpClient, err := MakeDownloadHTTPClient(
		ctx,
		config,
		tunnel,
		untunneledDialConfig,
		skipVerify)
	if err != nil {
		return "", common.ContextError(err)
	}

	n, responseETag, err := ResumeDownload(
		ctx,
		httpClient,
		sourceURL,
		MakePsiphonUserAgent(config),
		destinationFilename,
		lastETag)

	NoticeRemoteServerListResourceDownloadedBytes(sourceURL, n)

	if err != nil {
		return "", common.ContextError(err)
	}

	if responseETag == lastETag {
		return "", nil
	}

	NoticeRemoteServerListResourceDownloaded(sourceURL)

	RecordRemoteServerListStat(sourceURL, responseETag)

	return responseETag, nil
}
