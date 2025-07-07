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
	"fmt"
	"net/url"
	"os"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/osl"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	utls "github.com/Psiphon-Labs/utls"
)

type RemoteServerListFetcher func(
	ctx context.Context, config *Config, attempt int, tunnel *Tunnel, untunneledDialConfig *DialConfig, tlsCache utls.ClientSessionCache) error

// FetchCommonRemoteServerList downloads the common remote server list from
// config.RemoteServerListURLs. It validates its digital signature using the
// public key config.RemoteServerListSignaturePublicKey and parses the
// data field into ServerEntry records.
// config.GetRemoteServerListDownloadFilename() is the location to store the
// download. As the download is resumed after failure, this filename must
// be unique and persistent.
func FetchCommonRemoteServerList(
	ctx context.Context,
	config *Config,
	attempt int,
	tunnel *Tunnel,
	untunneledDialConfig *DialConfig,
	tlsCache utls.ClientSessionCache) error {

	NoticeInfo("fetching common remote server list")

	p := config.GetParameters().Get()
	publicKey := p.String(parameters.RemoteServerListSignaturePublicKey)
	urls := p.TransferURLs(parameters.RemoteServerListURLs)
	downloadTimeout := p.Duration(parameters.FetchRemoteServerListTimeout)
	p.Close()

	downloadURL := urls.Select(attempt)
	canonicalURL := urls.CanonicalURL()

	newETag, downloadStatRecorder, err := downloadRemoteServerListFile(
		ctx,
		config,
		tunnel,
		untunneledDialConfig,
		tlsCache,
		downloadTimeout,
		downloadURL.URL,
		canonicalURL,
		downloadURL.FrontingSpecs,
		downloadURL.SkipVerify,
		config.DisableSystemRootCAs,
		"",
		config.GetRemoteServerListDownloadFilename())
	if err != nil {
		return errors.Tracef("failed to download common remote server list: %s", errors.Trace(err))
	}

	authenticatedDownload := false
	if downloadStatRecorder != nil {
		defer func() { downloadStatRecorder(authenticatedDownload) }()
	}

	// When the resource is unchanged, skip.
	if newETag == "" {
		return nil
	}

	file, err := os.Open(config.GetRemoteServerListDownloadFilename())
	if err != nil {
		return errors.Tracef("failed to open common remote server list: %s", errors.Trace(err))

	}
	defer file.Close()

	serverListPayloadReader, err := common.NewAuthenticatedDataPackageReader(
		file, publicKey)
	if err != nil {
		return errors.Tracef("failed to read remote server list: %s", errors.Trace(err))
	}

	// NewAuthenticatedDataPackageReader authenticates the file before returning.
	authenticatedDownload = true

	err = StreamingStoreServerEntries(
		ctx,
		config,
		protocol.NewStreamingServerEntryDecoder(
			serverListPayloadReader,
			common.GetCurrentTimestamp(),
			protocol.SERVER_ENTRY_SOURCE_REMOTE),
		true)
	if err != nil {
		return errors.Tracef("failed to store common remote server list: %s", errors.Trace(err))
	}

	// Now that the server entries are successfully imported, store the response
	// ETag so we won't re-download this same data again.
	err = SetUrlETag(canonicalURL, newETag)
	if err != nil {
		NoticeWarning("failed to set ETag for common remote server list: %s", errors.Trace(err))
		// This fetch is still reported as a success, even if we can't store the etag
	}

	return nil
}

// FetchObfuscatedServerLists downloads the obfuscated remote server lists
// from config.ObfuscatedServerListRootURLs.
// It first downloads the OSL registry, and then downloads each seeded OSL
// advertised in the registry. All downloads are resumable, ETags are used
// to skip both an unchanged registry or unchanged OSL files, and when an
// individual download fails, the fetch proceeds if it can.
// Authenticated package digital signatures are validated using the
// public key config.RemoteServerListSignaturePublicKey.
// config.GetObfuscatedServerListDownloadDirectory() is the location to store
// the downloaded files. As  downloads are resumed after failure, this directory
// must be unique and persistent.
func FetchObfuscatedServerLists(
	ctx context.Context,
	config *Config,
	attempt int,
	tunnel *Tunnel,
	untunneledDialConfig *DialConfig,
	tlsCache utls.ClientSessionCache) error {

	NoticeInfo("fetching obfuscated remote server lists")

	p := config.GetParameters().Get()
	publicKey := p.String(parameters.RemoteServerListSignaturePublicKey)
	urls := p.TransferURLs(parameters.ObfuscatedServerListRootURLs)
	downloadTimeout := p.Duration(parameters.FetchRemoteServerListTimeout)
	p.Close()

	rootURL := urls.Select(attempt)
	canonicalRootURL := urls.CanonicalURL()
	downloadURL := osl.GetOSLRegistryURL(rootURL.URL)
	canonicalURL := osl.GetOSLRegistryURL(canonicalRootURL)

	downloadFilename := osl.GetOSLRegistryFilename(config.GetObfuscatedServerListDownloadDirectory())
	cachedFilename := downloadFilename + ".cached"

	// If the cached registry is not present, we need to download or resume downloading
	// the registry, so clear the ETag to ensure that always happens.
	_, err := os.Stat(cachedFilename)
	if os.IsNotExist(err) {
		err := SetUrlETag(canonicalURL, "")
		if err != nil {
			NoticeWarning("SetUrlETag failed: %v", errors.Trace(err))
			// Continue
		}
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

	newETag, downloadStatRecorder, err := downloadRemoteServerListFile(
		ctx,
		config,
		tunnel,
		untunneledDialConfig,
		tlsCache,
		downloadTimeout,
		downloadURL,
		canonicalURL,
		rootURL.FrontingSpecs,
		rootURL.SkipVerify,
		config.DisableSystemRootCAs,
		"",
		downloadFilename)
	if err != nil {
		failed = true
		NoticeWarning("failed to download obfuscated server list registry: %s", errors.Trace(err))
		// Proceed with any existing cached OSL registry.
	}

	authenticatedDownload := false
	if downloadStatRecorder != nil {
		defer func() { downloadStatRecorder(authenticatedDownload) }()
	}

	if newETag != "" {
		updateCache = true
		registryFilename = downloadFilename
	}

	// Prevent excessive notice noise in cases such as a general database
	// failure, as GetSLOK may be called thousands of times per fetch.
	emittedGetSLOKAlert := int32(0)

	lookupSLOKs := func(slokID []byte) []byte {
		// Lookup SLOKs in local datastore
		key, err := GetSLOK(slokID)
		if err != nil && atomic.CompareAndSwapInt32(&emittedGetSLOKAlert, 0, 1) {
			NoticeWarning("GetSLOK failed: %s", err)
		}
		return key
	}

	registryFile, err := os.Open(registryFilename)
	if err != nil {
		return errors.Tracef("failed to read obfuscated server list registry: %s", errors.Trace(err))
	}
	defer registryFile.Close()

	registryStreamer, err := osl.NewRegistryStreamer(
		registryFile,
		publicKey,
		lookupSLOKs)
	if err != nil {
		// TODO: delete file? redownload if corrupt?
		return errors.Tracef("failed to read obfuscated server list registry: %s", errors.Trace(err))
	}

	authenticatedDownload = true

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
			NoticeWarning("failed to stream obfuscated server list registry: %s", errors.Trace(err))
			break
		}

		if oslFileSpec == nil {
			break
		}

		if !downloadOSLFileSpec(
			ctx,
			config,
			tunnel,
			untunneledDialConfig,
			tlsCache,
			downloadTimeout,
			rootURL,
			canonicalRootURL,
			publicKey,
			lookupSLOKs,
			oslFileSpec) {

			// downloadOSLFileSpec emits notices with failure information. In the case
			// of a failure, set the retry flag but continue to process other OSL file
			// specs.
			failed = true
		}

		// Run a garbage collection to reclaim memory from the downloadOSLFileSpec
		// operation before processing the next file.
		DoGarbageCollection()
	}

	// Now that a new registry is downloaded, validated, and parsed, store
	// the response ETag so we won't re-download this same data again. First
	// close the file to avoid complications on platforms such as Windows.
	if updateCache {

		registryFile.Close()

		err := os.Rename(downloadFilename, cachedFilename)
		if err != nil {
			NoticeWarning("failed to set cached obfuscated server list registry: %s", errors.Trace(err))
			// This fetch is still reported as a success, even if we can't update the cache
		}

		err = SetUrlETag(canonicalURL, newETag)
		if err != nil {
			NoticeWarning("failed to set ETag for obfuscated server list registry: %s", errors.Trace(err))
			// This fetch is still reported as a success, even if we can't store the ETag
		}
	}

	if failed {
		return errors.TraceNew("one or more operations failed")
	}

	return nil
}

// downloadOSLFileSpec downloads, authenticates, and imports the OSL specified
// by oslFileSpec. The return value indicates whether the operation succeeded.
// Failure information is emitted in notices.
func downloadOSLFileSpec(
	ctx context.Context,
	config *Config,
	tunnel *Tunnel,
	untunneledDialConfig *DialConfig,
	tlsCache utls.ClientSessionCache,
	downloadTimeout time.Duration,
	rootURL *parameters.TransferURL,
	canonicalRootURL string,
	publicKey string,
	lookupSLOKs func(slokID []byte) []byte,
	oslFileSpec *osl.OSLFileSpec) bool {

	downloadFilename := osl.GetOSLFilename(
		config.GetObfuscatedServerListDownloadDirectory(), oslFileSpec.ID)

	downloadURL := osl.GetOSLFileURL(rootURL.URL, oslFileSpec.ID)
	canonicalURL := osl.GetOSLFileURL(canonicalRootURL, oslFileSpec.ID)

	hexID := hex.EncodeToString(oslFileSpec.ID)

	// Note: the MD5 checksum step assumes the remote server list host's ETag uses MD5
	// with a hex encoding. If this is not the case, the sourceETag should be left blank.
	sourceETag := fmt.Sprintf("\"%s\"", hex.EncodeToString(oslFileSpec.MD5Sum))

	newETag, downloadStatRecorder, err := downloadRemoteServerListFile(
		ctx,
		config,
		tunnel,
		untunneledDialConfig,
		tlsCache,
		downloadTimeout,
		downloadURL,
		canonicalURL,
		rootURL.FrontingSpecs,
		rootURL.SkipVerify,
		config.DisableSystemRootCAs,
		sourceETag,
		downloadFilename)
	if err != nil {
		NoticeWarning("failed to download obfuscated server list file (%s): %s", hexID, errors.Trace(err))
		return false
	}

	authenticatedDownload := false
	if downloadStatRecorder != nil {
		defer func() { downloadStatRecorder(authenticatedDownload) }()
	}

	// When the resource is unchanged, skip.
	if newETag == "" {
		return true
	}

	file, err := os.Open(downloadFilename)
	if err != nil {
		NoticeWarning("failed to open obfuscated server list file (%s): %s", hexID, errors.Trace(err))
		return false
	}
	defer file.Close()

	serverListPayloadReader, err := osl.NewOSLReader(
		file,
		oslFileSpec,
		lookupSLOKs,
		publicKey)
	if err != nil {
		NoticeWarning("failed to read obfuscated server list file (%s): %s", hexID, errors.Trace(err))
		return false
	}

	// NewOSLReader authenticates the file before returning.
	authenticatedDownload = true

	err = StreamingStoreServerEntries(
		ctx,
		config,
		protocol.NewStreamingServerEntryDecoder(
			serverListPayloadReader,
			common.GetCurrentTimestamp(),
			protocol.SERVER_ENTRY_SOURCE_OBFUSCATED),
		true)
	if err != nil {
		NoticeWarning("failed to store obfuscated server list file (%s): %s", hexID, errors.Trace(err))
		return false
	}

	// Now that the server entries are successfully imported, store the response
	// ETag so we won't re-download this same data again.
	err = SetUrlETag(canonicalURL, newETag)
	if err != nil {
		NoticeWarning("failed to set ETag for obfuscated server list file (%s): %s", hexID, errors.Trace(err))
		// This fetch is still reported as a success, even if we can't store the ETag
		return true
	}

	return true
}

// downloadRemoteServerListFile downloads the source URL to the destination
// file, performing a resumable download. When the download completes and the
// file content has changed, the new resource ETag is returned. Otherwise,
// blank is returned. The caller is responsible for calling SetUrlETag once
// the file content has been validated.
//
// The downloadStatReporter return value is a function that will invoke
// RecordRemoteServerListStat to record a remote server list download event.
// The caller must call this function if the return value is not nil,
// providing a boolean argument indicating whether the download was
// successfully authenticated.
func downloadRemoteServerListFile(
	ctx context.Context,
	config *Config,
	tunnel *Tunnel,
	untunneledDialConfig *DialConfig,
	tlsCache utls.ClientSessionCache,
	downloadTimeout time.Duration,
	sourceURL string,
	canonicalURL string,
	frontingSpecs parameters.FrontingSpecs,
	skipVerify bool,
	disableSystemRootCAs bool,
	sourceETag string,
	destinationFilename string) (string, func(bool), error) {

	// All download URLs with the same canonicalURL
	// must have the same entity and ETag.
	lastETag, err := GetUrlETag(canonicalURL)
	if err != nil {
		return "", nil, errors.Trace(err)
	}

	// sourceETag, when specified, is prior knowledge of the
	// remote ETag that can be used to skip the request entirely.
	// This will be set in the case of OSL files, from the MD5Sum
	// values stored in the registry.
	if lastETag != "" && sourceETag == lastETag {
		// TODO: notice?
		return "", nil, nil
	}

	var cancelFunc context.CancelFunc
	ctx, cancelFunc = context.WithTimeout(ctx, downloadTimeout)
	defer cancelFunc()

	// MakeDownloadHttpClient will select either a tunneled
	// or untunneled configuration.

	payloadSecure := true
	frontingUseDeviceBinder := true
	httpClient, tunneled, getParams, err := MakeDownloadHTTPClient(
		ctx,
		config,
		tunnel,
		untunneledDialConfig,
		tlsCache,
		skipVerify,
		disableSystemRootCAs,
		payloadSecure,
		frontingSpecs,
		frontingUseDeviceBinder,
		func(frontingProviderID string) {
			NoticeInfo(
				"downloadRemoteServerListFile: selected fronting provider %s for %s",
				frontingProviderID, sourceURL)
		})
	if err != nil {
		return "", nil, errors.Trace(err)
	}

	startTime := time.Now()

	bytes, responseETag, err := ResumeDownload(
		ctx,
		httpClient,
		sourceURL,
		MakePsiphonUserAgent(config),
		destinationFilename,
		lastETag)

	duration := time.Since(startTime)

	NoticeRemoteServerListResourceDownloadedBytes(sourceURL, bytes, duration)

	if err != nil {
		return "", nil, errors.Trace(err)
	}

	if responseETag == lastETag {
		return "", nil, nil
	}

	NoticeRemoteServerListResourceDownloaded(sourceURL)

	// Parameters can be retrieved now because the request has completed.
	var additionalParameters common.APIParameters
	if getParams != nil {
		additionalParameters = getParams()
	}

	downloadStatRecorder := func(authenticated bool) {

		// Invoke DNS cache extension (if enabled in the resolver) now that
		// the download succeeded and the payload is authenticated. Only
		// extend when authenticated, as this demonstrates that any domain
		// name resolved to an endpoint that served a valid Psiphon remote
		// server list.
		//
		// TODO: when !skipVerify, invoke DNS cache extension earlier, in
		// ResumeDownload, after making the request but before downloading
		// the response body?
		resolver := config.GetResolver()
		url, err := url.Parse(sourceURL)
		if authenticated && resolver != nil && err == nil {
			resolver.VerifyCacheExtension(url.Hostname())
		}

		_ = RecordRemoteServerListStat(
			config, tunneled, sourceURL, responseETag, bytes, duration, authenticated, additionalParameters)
	}

	return responseETag, downloadStatRecorder, nil
}
