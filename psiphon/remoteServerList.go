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
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/osl"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
)

type RemoteServerListFetcher func(
	config *Config, attempt int, tunnel *Tunnel, untunneledDialConfig *DialConfig) error

// FetchCommonRemoteServerList downloads the common remote server list from
// config.RemoteServerListUrl. It validates its digital signature using the
// public key config.RemoteServerListSignaturePublicKey and parses the
// data field into ServerEntry records.
// config.RemoteServerListDownloadFilename is the location to store the
// download. As the download is resumed after failure, this filename must
// be unique and persistent.
func FetchCommonRemoteServerList(
	config *Config,
	attempt int,
	tunnel *Tunnel,
	untunneledDialConfig *DialConfig) error {

	NoticeInfo("fetching common remote server list")

	downloadURL, canonicalURL, skipVerify := selectDownloadURL(attempt, config.RemoteServerListURLs)

	newETag, err := downloadRemoteServerListFile(
		config,
		tunnel,
		untunneledDialConfig,
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

	serverListPayload, err := unpackRemoteServerListFile(config, config.RemoteServerListDownloadFilename)
	if err != nil {
		return fmt.Errorf("failed to unpack common remote server list: %s", common.ContextError(err))
	}

	err = storeServerEntries(serverListPayload, protocol.SERVER_ENTRY_SOURCE_REMOTE)
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
	config *Config,
	attempt int,
	tunnel *Tunnel,
	untunneledDialConfig *DialConfig) error {

	NoticeInfo("fetching obfuscated remote server lists")

	downloadFilename := osl.GetOSLRegistryFilename(config.ObfuscatedServerListDownloadDirectory)

	rootURL, canonicalRootURL, skipVerify := selectDownloadURL(attempt, config.ObfuscatedServerListRootURLs)
	downloadURL := osl.GetOSLRegistryURL(rootURL)
	canonicalURL := osl.GetOSLRegistryURL(canonicalRootURL)

	// failed is set if any operation fails and should trigger a retry. When the OSL registry
	// fails to download, any cached registry is used instead; when any single OSL fails
	// to download, the overall operation proceeds. So this flag records whether to report
	// failure at the end when downloading has proceeded after a failure.
	// TODO: should disk-full conditions not trigger retries?
	var failed bool

	var oslRegistry *osl.Registry

	newETag, err := downloadRemoteServerListFile(
		config,
		tunnel,
		untunneledDialConfig,
		downloadURL,
		canonicalURL,
		skipVerify,
		"",
		downloadFilename)
	if err != nil {
		failed = true
		NoticeAlert("failed to download obfuscated server list registry: %s", common.ContextError(err))
	} else if newETag != "" {

		fileContent, err := ioutil.ReadFile(downloadFilename)
		if err != nil {
			failed = true
			NoticeAlert("failed to read obfuscated server list registry: %s", common.ContextError(err))
		}

		var oslRegistryJSON []byte
		if err == nil {
			oslRegistry, oslRegistryJSON, err = osl.UnpackRegistry(
				fileContent, config.RemoteServerListSignaturePublicKey)
			if err != nil {
				failed = true
				NoticeAlert("failed to unpack obfuscated server list registry: %s", common.ContextError(err))
			}
		}

		if err == nil {
			err = SetKeyValue(DATA_STORE_OSL_REGISTRY_KEY, string(oslRegistryJSON))
			if err != nil {
				failed = true
				NoticeAlert("failed to set cached obfuscated server list registry: %s", common.ContextError(err))
			}
		}
	}

	if failed || newETag == "" {
		// Proceed with the cached OSL registry.
		oslRegistryJSON, err := GetKeyValue(DATA_STORE_OSL_REGISTRY_KEY)
		if err == nil && oslRegistryJSON == "" {
			err = errors.New("not found")
		}
		if err != nil {
			return fmt.Errorf("failed to get cached obfuscated server list registry: %s", common.ContextError(err))
		}

		oslRegistry, err = osl.LoadRegistry([]byte(oslRegistryJSON))
		if err != nil {
			return fmt.Errorf("failed to load obfuscated server list registry: %s", common.ContextError(err))
		}
	}

	// When a new registry is downloaded, validated, and parsed, store the
	// response ETag so we won't re-download this same data again.
	if !failed && newETag != "" {
		err = SetUrlETag(canonicalURL, newETag)
		if err != nil {
			NoticeAlert("failed to set ETag for obfuscated server list registry: %s", common.ContextError(err))
			// This fetch is still reported as a success, even if we can't store the etag
		}
	}

	// Note: we proceed to check individual OSLs even if the direcory is unchanged,
	// as the set of local SLOKs may have changed.

	lookupSLOKs := func(slokID []byte) []byte {
		// Lookup SLOKs in local datastore
		key, err := GetSLOK(slokID)
		if err != nil {
			NoticeAlert("GetSLOK failed: %s", err)
		}
		return key
	}

	oslIDs := oslRegistry.GetSeededOSLIDs(
		lookupSLOKs,
		func(err error) {
			NoticeAlert("GetSeededOSLIDs failed: %s", err)
		})

	for _, oslID := range oslIDs {

		downloadFilename := osl.GetOSLFilename(config.ObfuscatedServerListDownloadDirectory, oslID)

		downloadURL := osl.GetOSLFileURL(rootURL, oslID)
		canonicalURL := osl.GetOSLFileURL(canonicalRootURL, oslID)

		hexID := hex.EncodeToString(oslID)

		// Note: the MD5 checksum step assumes the remote server list host's ETag uses MD5
		// with a hex encoding. If this is not the case, the sourceETag should be left blank.
		sourceETag := ""
		md5sum, err := oslRegistry.GetOSLMD5Sum(oslID)
		if err == nil {
			sourceETag = fmt.Sprintf("\"%s\"", hex.EncodeToString(md5sum))
		}

		// TODO: store ETags in OSL registry to enable skipping requests entirely

		newETag, err := downloadRemoteServerListFile(
			config,
			tunnel,
			untunneledDialConfig,
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

		fileContent, err := ioutil.ReadFile(downloadFilename)
		if err != nil {
			failed = true
			NoticeAlert("failed to read obfuscated server list file (%s): %s", hexID, common.ContextError(err))
			continue
		}

		serverListPayload, err := oslRegistry.UnpackOSL(
			lookupSLOKs, oslID, fileContent, config.RemoteServerListSignaturePublicKey)
		if err != nil {
			failed = true
			NoticeAlert("failed to unpack obfuscated server list file (%s): %s", hexID, common.ContextError(err))
			continue
		}

		err = storeServerEntries(serverListPayload, protocol.SERVER_ENTRY_SOURCE_OBFUSCATED)
		if err != nil {
			failed = true
			NoticeAlert("failed to store obfuscated server list file (%s): %s", hexID, common.ContextError(err))
			continue
		}

		// Now that the server entries are successfully imported, store the response
		// ETag so we won't re-download this same data again.
		err = SetUrlETag(canonicalURL, newETag)
		if err != nil {
			failed = true
			NoticeAlert("failed to set Etag for obfuscated server list file (%s): %s", hexID, common.ContextError(err))
			continue
			// This fetch is still reported as a success, even if we can't store the etag
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
	config *Config,
	tunnel *Tunnel,
	untunneledDialConfig *DialConfig,
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

	// MakeDownloadHttpClient will select either a tunneled
	// or untunneled configuration.

	httpClient, requestURL, err := MakeDownloadHttpClient(
		config,
		tunnel,
		untunneledDialConfig,
		sourceURL,
		skipVerify,
		time.Duration(*config.FetchRemoteServerListTimeoutSeconds)*time.Second)
	if err != nil {
		return "", common.ContextError(err)
	}

	n, responseETag, err := ResumeDownload(
		httpClient,
		requestURL,
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

// unpackRemoteServerListFile reads a file that contains a
// zlib compressed authenticated data package, validates
// the package, and returns the payload.
func unpackRemoteServerListFile(
	config *Config, filename string) (string, error) {

	fileReader, err := os.Open(filename)
	if err != nil {
		return "", common.ContextError(err)
	}
	defer fileReader.Close()

	zlibReader, err := zlib.NewReader(fileReader)
	if err != nil {
		return "", common.ContextError(err)
	}

	dataPackage, err := ioutil.ReadAll(zlibReader)
	zlibReader.Close()
	if err != nil {
		return "", common.ContextError(err)
	}

	payload, err := common.ReadAuthenticatedDataPackage(
		dataPackage, config.RemoteServerListSignaturePublicKey)
	if err != nil {
		return "", common.ContextError(err)
	}

	return payload, nil
}

func storeServerEntries(serverList, serverEntrySource string) error {

	serverEntries, err := protocol.DecodeAndValidateServerEntryList(
		serverList,
		common.GetCurrentTimestamp(),
		serverEntrySource)
	if err != nil {
		return common.ContextError(err)
	}

	// TODO: record stats for newly discovered servers

	err = StoreServerEntries(serverEntries, true)
	if err != nil {
		return common.ContextError(err)
	}

	return nil
}
