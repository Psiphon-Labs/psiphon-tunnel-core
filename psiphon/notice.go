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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
)

type noticeLogger struct {
	logDiagnostics             int32
	mutex                      sync.Mutex
	writer                     io.Writer
	homepageFilename           string
	homepageFile               *os.File
	rotatingFilename           string
	rotatingOlderFilename      string
	rotatingFile               *os.File
	rotatingFileSize           int64
	rotatingCurrentFileSize    int64
	rotatingSyncFrequency      int
	rotatingCurrentNoticeCount int
}

var singletonNoticeLogger = noticeLogger{
	writer: os.Stderr,
}

// SetEmitDiagnosticNotices toggles whether diagnostic notices
// are emitted. Diagnostic notices contain potentially sensitive
// circumvention network information; only enable this in environments
// where notices are handled securely (for example, don't include these
// notices in log files which users could post to public forums).
func SetEmitDiagnosticNotices(enable bool) {
	if enable {
		atomic.StoreInt32(&singletonNoticeLogger.logDiagnostics, 1)
	} else {
		atomic.StoreInt32(&singletonNoticeLogger.logDiagnostics, 0)
	}
}

// GetEmitDiagnoticNotices returns the current state
// of emitting diagnostic notices.
func GetEmitDiagnoticNotices() bool {
	return atomic.LoadInt32(&singletonNoticeLogger.logDiagnostics) == 1
}

// SetNoticeWriter sets a target writer to receive notices. By default,
// notices are written to stderr. Notices are newline delimited.
//
// writer specifies an alternate io.Writer where notices are to be written.
//
// Notices are encoded in JSON. Here's an example:
//
// {"data":{"message":"shutdown operate tunnel"},"noticeType":"Info","showUser":false,"timestamp":"2006-01-02T15:04:05.999999999Z07:00"}
//
// All notices have the following fields:
// - "noticeType": the type of notice, which indicates the meaning of the notice along with what's in the data payload.
// - "data": additional structured data payload. For example, the "ListeningSocksProxyPort" notice type has a "port" integer
// data in its payload.
// - "showUser": whether the information should be displayed to the user. For example, this flag is set for "SocksProxyPortInUse"
// as the user should be informed that their configured choice of listening port could not be used. Core clients should
// anticipate that the core will add additional "showUser"=true notices in the future and emit at least the raw notice.
// - "timestamp": UTC timezone, RFC3339Milli format timestamp for notice event
//
// See the Notice* functions for details on each notice meaning and payload.
//
func SetNoticeWriter(writer io.Writer) {

	singletonNoticeLogger.mutex.Lock()
	defer singletonNoticeLogger.mutex.Unlock()

	singletonNoticeLogger.writer = writer
}

// SetNoticeFiles configures files for notice writing.
//
// - When homepageFilename is not "", homepages are written to the specified file
//   and omitted from the writer. The file may be read after the Tunnels notice
//   with count of 1. The file should be opened read-only for reading.
//
// - When rotatingFilename is not "", all notices are are written to the specified
//   file. Diagnostic notices are omitted from the writer. The file is rotated
//   when its size exceeds rotatingFileSize. One rotated older file,
//   <rotatingFilename>.1, is retained. The files may be read at any time; and
//   should be opened read-only for reading. rotatingSyncFrequency specifies how
//   many notices are written before syncing the file.
//   If either rotatingFileSize or rotatingSyncFrequency are <= 0, default values
//   are used.
//
// - If an error occurs when writing to a file, an InternalError notice is emitted to
//   the writer.
//
// SetNoticeFiles closes open homepage or rotating files before applying the new
// configuration.
//
func SetNoticeFiles(
	homepageFilename string,
	rotatingFilename string,
	rotatingFileSize int,
	rotatingSyncFrequency int) error {

	singletonNoticeLogger.mutex.Lock()
	defer singletonNoticeLogger.mutex.Unlock()

	if homepageFilename != "" {
		var err error
		if singletonNoticeLogger.homepageFile != nil {
			singletonNoticeLogger.homepageFile.Close()
		}
		singletonNoticeLogger.homepageFile, err = os.OpenFile(
			homepageFilename, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if err != nil {
			return common.ContextError(err)
		}
	}

	if rotatingFilename != "" {
		var err error
		if singletonNoticeLogger.rotatingFile != nil {
			singletonNoticeLogger.rotatingFile.Close()
		}
		singletonNoticeLogger.rotatingFile, err = os.OpenFile(
			rotatingFilename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return common.ContextError(err)
		}

		fileInfo, err := singletonNoticeLogger.rotatingFile.Stat()
		if err != nil {
			return common.ContextError(err)
		}

		if rotatingFileSize <= 0 {
			rotatingFileSize = 1 << 20
		}

		if rotatingSyncFrequency <= 0 {
			rotatingSyncFrequency = 100
		}

		singletonNoticeLogger.rotatingFilename = rotatingFilename
		singletonNoticeLogger.rotatingOlderFilename = rotatingFilename + ".1"
		singletonNoticeLogger.rotatingFileSize = int64(rotatingFileSize)
		singletonNoticeLogger.rotatingCurrentFileSize = fileInfo.Size()
		singletonNoticeLogger.rotatingSyncFrequency = rotatingSyncFrequency
		singletonNoticeLogger.rotatingCurrentNoticeCount = 0
	}

	return nil
}

const (
	noticeShowUser       = 1
	noticeIsDiagnostic   = 2
	noticeIsHomepage     = 4
	noticeClearHomepages = 8
	noticeSyncHomepages  = 16
)

// outputNotice encodes a notice in JSON and writes it to the output writer.
func (nl *noticeLogger) outputNotice(noticeType string, noticeFlags uint32, args ...interface{}) {

	if (noticeFlags&noticeIsDiagnostic != 0) && atomic.LoadInt32(&nl.logDiagnostics) != 1 {
		return
	}

	obj := make(map[string]interface{})
	noticeData := make(map[string]interface{})
	obj["noticeType"] = noticeType
	obj["showUser"] = (noticeFlags&noticeShowUser != 0)
	obj["data"] = noticeData
	obj["timestamp"] = time.Now().UTC().Format(common.RFC3339Milli)
	for i := 0; i < len(args)-1; i += 2 {
		name, ok := args[i].(string)
		value := args[i+1]
		if ok {
			noticeData[name] = value
		}
	}
	encodedJson, err := json.Marshal(obj)
	var output []byte
	if err == nil {
		output = append(encodedJson, byte('\n'))

	} else {
		// Try to emit a properly formatted notice that the outer client can report.
		// One scenario where this is useful is if the preceding Marshal fails due to
		// bad data in the args. This has happened for a json.RawMessage field.
		output = makeNoticeInternalError(
			fmt.Sprintf("marshal notice failed: %s", common.ContextError(err)))
	}

	nl.mutex.Lock()
	defer nl.mutex.Unlock()

	skipWriter := false

	if nl.homepageFile != nil &&
		(noticeFlags&noticeIsHomepage != 0) {

		skipWriter = true

		err := nl.outputNoticeToHomepageFile(noticeFlags, output)

		if err != nil {
			output := makeNoticeInternalError(
				fmt.Sprintf("write homepage file failed: %s", err))
			nl.writer.Write(output)
		}
	}

	if nl.rotatingFile != nil {

		if !skipWriter {
			skipWriter = (noticeFlags&noticeIsDiagnostic != 0)
		}

		err := nl.outputNoticeToRotatingFile(output)

		if err != nil {
			output := makeNoticeInternalError(
				fmt.Sprintf("write rotating file failed: %s", err))
			nl.writer.Write(output)
		}
	}

	if !skipWriter {
		_, _ = nl.writer.Write(output)
	}
}

// NoticeInteralError is an error formatting or writing notices.
// A NoticeInteralError handler must not call a Notice function.
func makeNoticeInternalError(errorMessage string) []byte {
	// Format an Alert Notice (_without_ using json.Marshal, since that can fail)
	alertNoticeFormat := "{\"noticeType\":\"InternalError\",\"showUser\":false,\"timestamp\":\"%s\",\"data\":{\"message\":\"%s\"}}\n"
	return []byte(fmt.Sprintf(alertNoticeFormat, time.Now().UTC().Format(common.RFC3339Milli), errorMessage))

}

func (nl *noticeLogger) outputNoticeToHomepageFile(noticeFlags uint32, output []byte) error {

	if (noticeFlags & noticeClearHomepages) != 0 {
		err := nl.homepageFile.Truncate(0)
		if err != nil {
			return common.ContextError(err)
		}
		_, err = nl.homepageFile.Seek(0, 0)
		if err != nil {
			return common.ContextError(err)
		}
	}

	_, err := nl.homepageFile.Write(output)
	if err != nil {
		return common.ContextError(err)
	}

	if (noticeFlags & noticeSyncHomepages) != 0 {
		err = nl.homepageFile.Sync()
		if err != nil {
			return common.ContextError(err)
		}
	}

	return nil
}

func (nl *noticeLogger) outputNoticeToRotatingFile(output []byte) error {

	nl.rotatingCurrentFileSize += int64(len(output) + 1)
	if nl.rotatingCurrentFileSize >= nl.rotatingFileSize {

		// Note: all errors are fatal in order to preserve the
		// rotatingFileSize limit; e.g., no attempt is made to
		// continue writing to the file if it can't be rotated.

		err := nl.rotatingFile.Sync()
		if err != nil {
			return common.ContextError(err)
		}

		err = nl.rotatingFile.Close()
		if err != nil {
			return common.ContextError(err)
		}

		err = os.Rename(nl.rotatingFilename, nl.rotatingOlderFilename)
		if err != nil {
			return common.ContextError(err)
		}

		nl.rotatingFile, err = os.OpenFile(
			nl.rotatingFilename, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if err != nil {
			return common.ContextError(err)
		}

		nl.rotatingCurrentFileSize = 0
	}

	_, err := nl.rotatingFile.Write(output)
	if err != nil {
		return common.ContextError(err)
	}

	nl.rotatingCurrentNoticeCount += 1
	if nl.rotatingCurrentNoticeCount >= nl.rotatingSyncFrequency {
		nl.rotatingCurrentNoticeCount = 0
		err = nl.rotatingFile.Sync()
		if err != nil {
			return common.ContextError(err)
		}
	}

	return nil
}

// NoticeInfo is an informational message
func NoticeInfo(format string, args ...interface{}) {
	singletonNoticeLogger.outputNotice(
		"Info", noticeIsDiagnostic,
		"message", fmt.Sprintf(format, args...))
}

// NoticeAlert is an alert message; typically a recoverable error condition
func NoticeAlert(format string, args ...interface{}) {
	singletonNoticeLogger.outputNotice(
		"Alert", noticeIsDiagnostic,
		"message", fmt.Sprintf(format, args...))
}

// NoticeError is an error message; typically an unrecoverable error condition
func NoticeError(format string, args ...interface{}) {
	singletonNoticeLogger.outputNotice(
		"Error", noticeIsDiagnostic,
		"message", fmt.Sprintf(format, args...))
}

// NoticeUserLog is a log message from the outer client user of tunnel-core
func NoticeUserLog(message string) {
	singletonNoticeLogger.outputNotice(
		"UserLog", noticeIsDiagnostic,
		"message", message)
}

// NoticeCandidateServers is how many possible servers are available for the selected region and protocols
func NoticeCandidateServers(region string, protocols []string, count int) {
	singletonNoticeLogger.outputNotice(
		"CandidateServers", noticeIsDiagnostic,
		"region", region,
		"protocols", protocols,
		"count", count)
}

// NoticeAvailableEgressRegions is what regions are available for egress from.
// Consecutive reports of the same list of regions are suppressed.
func NoticeAvailableEgressRegions(regions []string) {
	sortedRegions := append([]string(nil), regions...)
	sort.Strings(sortedRegions)
	repetitionMessage := strings.Join(sortedRegions, "")
	outputRepetitiveNotice(
		"AvailableEgressRegions", repetitionMessage, 0,
		"AvailableEgressRegions", 0, "regions", sortedRegions)
}

func noticeWithDialStats(noticeType, ipAddress, region, protocol string, dialStats *DialStats) {

	args := []interface{}{
		"ipAddress", ipAddress,
		"region", region,
		"protocol", protocol,
	}

	if dialStats.SelectedSSHClientVersion {
		args = append(args, "SSHClientVersion", dialStats.SSHClientVersion)
	}

	if dialStats.UpstreamProxyType != "" {
		args = append(args, "upstreamProxyType", dialStats.UpstreamProxyType)
	}

	if dialStats.UpstreamProxyCustomHeaderNames != nil {
		args = append(args, "upstreamProxyCustomHeaderNames", strings.Join(dialStats.UpstreamProxyCustomHeaderNames, ","))
	}

	if dialStats.MeekDialAddress != "" {
		args = append(args, "meekDialAddress", dialStats.MeekDialAddress)
	}

	meekResolvedIPAddress := dialStats.MeekResolvedIPAddress.Load().(string)
	if meekResolvedIPAddress != "" {
		args = append(args, "meekResolvedIPAddress", meekResolvedIPAddress)
	}

	if dialStats.MeekSNIServerName != "" {
		args = append(args, "meekSNIServerName", dialStats.MeekSNIServerName)
	}

	if dialStats.MeekHostHeader != "" {
		args = append(args, "meekHostHeader", dialStats.MeekHostHeader)
	}

	// MeekTransformedHostName is meaningful when meek is used, which is when MeekDialAddress != ""
	if dialStats.MeekDialAddress != "" {
		args = append(args, "meekTransformedHostName", dialStats.MeekTransformedHostName)
	}

	if dialStats.SelectedUserAgent {
		args = append(args, "userAgent", dialStats.UserAgent)
	}

	if dialStats.SelectedTLSProfile {
		args = append(args, "TLSProfile", dialStats.TLSProfile)
	}

	singletonNoticeLogger.outputNotice(
		noticeType, noticeIsDiagnostic,
		args...)
}

// NoticeConnectingServer reports parameters and details for a single connection attempt
func NoticeConnectingServer(ipAddress, region, protocol string, dialStats *DialStats) {
	noticeWithDialStats(
		"ConnectingServer", ipAddress, region, protocol, dialStats)
}

// NoticeConnectedServer reports parameters and details for a single successful connection
func NoticeConnectedServer(ipAddress, region, protocol string, dialStats *DialStats) {
	noticeWithDialStats(
		"ConnectedServer", ipAddress, region, protocol, dialStats)
}

// NoticeRequestingTactics reports parameters and details for a tactics request attempt
func NoticeRequestingTactics(ipAddress, region, protocol string, dialStats *DialStats) {
	noticeWithDialStats(
		"RequestingTactics", ipAddress, region, protocol, dialStats)
}

// NoticeRequestedTactics reports parameters and details for a successful tactics request
func NoticeRequestedTactics(ipAddress, region, protocol string, dialStats *DialStats) {
	noticeWithDialStats(
		"RequestedTactics", ipAddress, region, protocol, dialStats)
}

// NoticeActiveTunnel is a successful connection that is used as an active tunnel for port forwarding
func NoticeActiveTunnel(ipAddress, protocol string, isTCS bool) {
	singletonNoticeLogger.outputNotice(
		"ActiveTunnel", noticeIsDiagnostic,
		"ipAddress", ipAddress,
		"protocol", protocol,
		"isTCS", isTCS)
}

// NoticeSocksProxyPortInUse is a failure to use the configured LocalSocksProxyPort
func NoticeSocksProxyPortInUse(port int) {
	singletonNoticeLogger.outputNotice(
		"SocksProxyPortInUse",
		noticeShowUser, "port", port)
}

// NoticeListeningSocksProxyPort is the selected port for the listening local SOCKS proxy
func NoticeListeningSocksProxyPort(port int) {
	singletonNoticeLogger.outputNotice(
		"ListeningSocksProxyPort", 0,
		"port", port)
}

// NoticeHttpProxyPortInUse is a failure to use the configured LocalHttpProxyPort
func NoticeHttpProxyPortInUse(port int) {
	singletonNoticeLogger.outputNotice(
		"HttpProxyPortInUse", noticeShowUser,
		"port", port)
}

// NoticeListeningHttpProxyPort is the selected port for the listening local HTTP proxy
func NoticeListeningHttpProxyPort(port int) {
	singletonNoticeLogger.outputNotice(
		"ListeningHttpProxyPort", 0,
		"port", port)
}

// NoticeClientUpgradeAvailable is an available client upgrade, as per the handshake. The
// client should download and install an upgrade.
func NoticeClientUpgradeAvailable(version string) {
	singletonNoticeLogger.outputNotice(
		"ClientUpgradeAvailable", 0,
		"version", version)
}

// NoticeClientIsLatestVersion reports that an upgrade check was made and the client
// is already the latest version. availableVersion is the version available for download,
// if known.
func NoticeClientIsLatestVersion(availableVersion string) {
	singletonNoticeLogger.outputNotice(
		"ClientIsLatestVersion", 0,
		"availableVersion", availableVersion)
}

// NoticeHomepages emits a series of NoticeHomepage, the sponsor homepages. The client
// should display the sponsor's homepages.
func NoticeHomepages(urls []string) {
	for i, url := range urls {
		noticeFlags := uint32(noticeIsHomepage)
		if i == 0 {
			noticeFlags |= noticeClearHomepages
		}
		if i == len(urls)-1 {
			noticeFlags |= noticeSyncHomepages
		}
		singletonNoticeLogger.outputNotice(
			"Homepage", noticeFlags,
			"url", url)
	}
}

// NoticeClientRegion is the client's region, as determined by the server and
// reported to the client in the handshake.
func NoticeClientRegion(region string) {
	singletonNoticeLogger.outputNotice(
		"ClientRegion", 0,
		"region", region)
}

// NoticeTunnels is how many active tunnels are available. The client should use this to
// determine connecting/unexpected disconnect state transitions. When count is 0, the core is
// disconnected; when count > 1, the core is connected.
func NoticeTunnels(count int) {
	singletonNoticeLogger.outputNotice(
		"Tunnels", 0,
		"count", count)
}

// NoticeSessionId is the session ID used across all tunnels established by the controller.
func NoticeSessionId(sessionId string) {
	singletonNoticeLogger.outputNotice(
		"SessionId", noticeIsDiagnostic,
		"sessionId", sessionId)
}

// NoticeUntunneled indicates than an address has been classified as untunneled and is being
// accessed directly.
//
// Note: "address" should remain private; this notice should only be used for alerting
// users, not for diagnostics logs.
//
func NoticeUntunneled(address string) {
	singletonNoticeLogger.outputNotice(
		"Untunneled", noticeShowUser,
		"address", address)
}

// NoticeSplitTunnelRegion reports that split tunnel is on for the given region.
func NoticeSplitTunnelRegion(region string) {
	singletonNoticeLogger.outputNotice(
		"SplitTunnelRegion", noticeShowUser,
		"region", region)
}

// NoticeUpstreamProxyError reports an error when connecting to an upstream proxy. The
// user may have input, for example, an incorrect address or incorrect credentials.
func NoticeUpstreamProxyError(err error) {
	singletonNoticeLogger.outputNotice(
		"UpstreamProxyError", noticeShowUser,
		"message", err.Error())
}

// NoticeClientUpgradeDownloadedBytes reports client upgrade download progress.
func NoticeClientUpgradeDownloadedBytes(bytes int64) {
	singletonNoticeLogger.outputNotice(
		"ClientUpgradeDownloadedBytes", noticeIsDiagnostic,
		"bytes", bytes)
}

// NoticeClientUpgradeDownloaded indicates that a client upgrade download
// is complete and available at the destination specified.
func NoticeClientUpgradeDownloaded(filename string) {
	singletonNoticeLogger.outputNotice(
		"ClientUpgradeDownloaded", 0,
		"filename", filename)
}

// NoticeBytesTransferred reports how many tunneled bytes have been
// transferred since the last NoticeBytesTransferred, for the tunnel
// to the server at ipAddress. This is not a diagnostic notice: the
// user app has requested this notice with EmitBytesTransferred for
// functionality such as traffic display; and this frequent notice
// is not intended to be included with feedback.
func NoticeBytesTransferred(ipAddress string, sent, received int64) {
	singletonNoticeLogger.outputNotice(
		"BytesTransferred", 0,
		"sent", sent,
		"received", received)
}

// NoticeTotalBytesTransferred reports how many tunneled bytes have been
// transferred in total up to this point, for the tunnel to the server
// at ipAddress. This is a diagnostic notice.
func NoticeTotalBytesTransferred(ipAddress string, sent, received int64) {
	singletonNoticeLogger.outputNotice(
		"TotalBytesTransferred", noticeIsDiagnostic,
		"ipAddress", ipAddress,
		"sent", sent,
		"received", received)
}

// NoticeLocalProxyError reports a local proxy error message. Repetitive
// errors for a given proxy type are suppressed.
func NoticeLocalProxyError(proxyType string, err error) {

	// For repeats, only consider the base error message, which is
	// the root error that repeats (the full error often contains
	// different specific values, e.g., local port numbers, but
	// the same repeating root).
	// Assumes error format of common.ContextError.
	repetitionMessage := err.Error()
	index := strings.LastIndex(repetitionMessage, ": ")
	if index != -1 {
		repetitionMessage = repetitionMessage[index+2:]
	}

	outputRepetitiveNotice(
		"LocalProxyError"+proxyType, repetitionMessage, 1,
		"LocalProxyError", noticeIsDiagnostic,
		"message", err.Error())
}

// NoticeBuildInfo reports build version info.
func NoticeBuildInfo() {
	singletonNoticeLogger.outputNotice(
		"BuildInfo", noticeIsDiagnostic,
		"buildInfo", common.GetBuildInfo())
}

// NoticeExiting indicates that tunnel-core is exiting imminently.
func NoticeExiting() {
	singletonNoticeLogger.outputNotice(
		"Exiting", 0)
}

// NoticeRemoteServerListResourceDownloadedBytes reports remote server list download progress.
func NoticeRemoteServerListResourceDownloadedBytes(url string, bytes int64) {
	singletonNoticeLogger.outputNotice(
		"RemoteServerListResourceDownloadedBytes", noticeIsDiagnostic,
		"url", url,
		"bytes", bytes)
}

// NoticeRemoteServerListResourceDownloaded indicates that a remote server list download
// completed successfully.
func NoticeRemoteServerListResourceDownloaded(url string) {
	singletonNoticeLogger.outputNotice(
		"RemoteServerListResourceDownloaded", noticeIsDiagnostic,
		"url", url)
}

// NoticeSLOKSeeded indicates that the SLOK with the specified ID was received from
// the Psiphon server. The "duplicate" flags indicates whether the SLOK was previously known.
func NoticeSLOKSeeded(slokID string, duplicate bool) {
	singletonNoticeLogger.outputNotice(
		"SLOKSeeded", noticeIsDiagnostic,
		"slokID", slokID,
		"duplicate", duplicate)
}

// NoticeServerTimestamp reports server side timestamp as seen in the handshake.
func NoticeServerTimestamp(timestamp string) {
	singletonNoticeLogger.outputNotice(
		"ServerTimestamp", 0,
		"timestamp", timestamp)
}

// NoticeActiveAuthorizationIDs reports the authorizations the server has accepted.
// Each ID is a base64-encoded accesscontrol.Authorization.ID value.
func NoticeActiveAuthorizationIDs(activeAuthorizationIDs []string) {

	// Never emit 'null' instead of empty list
	if activeAuthorizationIDs == nil {
		activeAuthorizationIDs = make([]string, 0)
	}

	singletonNoticeLogger.outputNotice(
		"ActiveAuthorizationIDs", 0,
		"IDs", activeAuthorizationIDs)
}

func NoticeBindToDevice(deviceInfo string) {
	outputRepetitiveNotice(
		"BindToDevice", deviceInfo, 0,
		"BindToDevice", 0, "regions", deviceInfo)
}

func NoticeNetworkID(networkID string) {
	outputRepetitiveNotice(
		"NetworkID", networkID, 0,
		"NetworkID", 0, "ID", networkID)
}

type repetitiveNoticeState struct {
	message string
	repeats int
}

var repetitiveNoticeMutex sync.Mutex
var repetitiveNoticeStates = make(map[string]*repetitiveNoticeState)

// outputRepetitiveNotice conditionally outputs a notice. Used for noticies which
// often repeat in noisy bursts. For a repeat limit of N, the notice is emitted
// with a "repeats" count on consecutive repeats up to the limit and then suppressed
// until the repetitionMessage differs.
func outputRepetitiveNotice(
	repetitionKey, repetitionMessage string, repeatLimit int,
	noticeType string, noticeFlags uint32, args ...interface{}) {

	repetitiveNoticeMutex.Lock()
	defer repetitiveNoticeMutex.Unlock()

	state, ok := repetitiveNoticeStates[repetitionKey]
	if !ok {
		state = new(repetitiveNoticeState)
		repetitiveNoticeStates[repetitionKey] = state
	}

	emit := true
	if repetitionMessage != state.message {
		state.message = repetitionMessage
		state.repeats = 0
	} else {
		state.repeats += 1
		if state.repeats > repeatLimit {
			emit = false
		}
	}

	if emit {
		if state.repeats > 0 {
			args = append(args, "repeats", state.repeats)
		}
		singletonNoticeLogger.outputNotice(
			noticeType, noticeFlags,
			args...)
	}
}

// ResetRepetitiveNotices resets the repetitive notice state, so
// the next instance of any notice will not be supressed.
func ResetRepetitiveNotices() {
	repetitiveNoticeMutex.Lock()
	defer repetitiveNoticeMutex.Unlock()

	repetitiveNoticeStates = make(map[string]*repetitiveNoticeState)
}

type noticeObject struct {
	NoticeType string          `json:"noticeType"`
	Data       json.RawMessage `json:"data"`
	Timestamp  string          `json:"timestamp"`
}

// GetNotice receives a JSON encoded object and attempts to parse it as a Notice.
// The type is returned as a string and the payload as a generic map.
func GetNotice(notice []byte) (
	noticeType string, payload map[string]interface{}, err error) {

	var object noticeObject
	err = json.Unmarshal(notice, &object)
	if err != nil {
		return "", nil, err
	}
	var objectPayload interface{}
	err = json.Unmarshal(object.Data, &objectPayload)
	if err != nil {
		return "", nil, err
	}
	return object.NoticeType, objectPayload.(map[string]interface{}), nil
}

// NoticeReceiver consumes a notice input stream and invokes a callback function
// for each discrete JSON notice object byte sequence.
type NoticeReceiver struct {
	mutex    sync.Mutex
	buffer   []byte
	callback func([]byte)
}

// NewNoticeReceiver initializes a new NoticeReceiver
func NewNoticeReceiver(callback func([]byte)) *NoticeReceiver {
	return &NoticeReceiver{callback: callback}
}

// Write implements io.Writer.
func (receiver *NoticeReceiver) Write(p []byte) (n int, err error) {
	receiver.mutex.Lock()
	defer receiver.mutex.Unlock()

	receiver.buffer = append(receiver.buffer, p...)

	index := bytes.Index(receiver.buffer, []byte("\n"))
	if index == -1 {
		return len(p), nil
	}

	notice := receiver.buffer[:index]

	receiver.callback(notice)

	if index == len(receiver.buffer)-1 {
		receiver.buffer = receiver.buffer[0:0]
	} else {
		receiver.buffer = receiver.buffer[index+1:]
	}

	return len(p), nil
}

// NewNoticeConsoleRewriter consumes JSON-format notice input and parses each
// notice and rewrites in a more human-readable format more suitable for
// console output. The data payload field is left as JSON.
func NewNoticeConsoleRewriter(writer io.Writer) *NoticeReceiver {
	return NewNoticeReceiver(func(notice []byte) {
		var object noticeObject
		_ = json.Unmarshal(notice, &object)
		fmt.Fprintf(
			writer,
			"%s %s %s\n",
			object.Timestamp,
			object.NoticeType,
			string(object.Data))
	})
}

// NoticeWriter implements io.Writer and emits the contents of Write() calls
// as Notices. This is to transform logger messages, if they can be redirected
// to an io.Writer, to notices.
type NoticeWriter struct {
	noticeType string
}

// NewNoticeWriter initializes a new NoticeWriter
func NewNoticeWriter(noticeType string) *NoticeWriter {
	return &NoticeWriter{noticeType: noticeType}
}

// Write implements io.Writer.
func (writer *NoticeWriter) Write(p []byte) (n int, err error) {
	singletonNoticeLogger.outputNotice(
		writer.noticeType, noticeIsDiagnostic,
		"message", string(p))
	return len(p), nil
}

// NoticeCommonLogger maps the common.Logger interface to the notice facility.
// This is used to make the notice facility available to other packages that
// don't import the "psiphon" package.
func NoticeCommonLogger() common.Logger {
	return &commonLogger{}
}

type commonLogger struct {
}

func (logger *commonLogger) WithContext() common.LogContext {
	return &commonLogContext{
		context: common.GetParentContext(),
	}
}

func (logger *commonLogger) WithContextFields(fields common.LogFields) common.LogContext {
	return &commonLogContext{
		context: common.GetParentContext(),
		fields:  fields,
	}
}

func (logger *commonLogger) LogMetric(metric string, fields common.LogFields) {
	singletonNoticeLogger.outputNotice(
		metric, noticeIsDiagnostic,
		listCommonFields(fields)...)
}

func listCommonFields(fields common.LogFields) []interface{} {
	fieldList := make([]interface{}, 0)
	for name, value := range fields {
		var formattedValue string
		if err, ok := value.(error); ok {
			formattedValue = err.Error()
		} else {
			formattedValue = fmt.Sprintf("%#v", value)
		}
		fieldList = append(fieldList, name, formattedValue)
	}
	return fieldList
}

type commonLogContext struct {
	context string
	fields  common.LogFields
}

func (context *commonLogContext) outputNotice(
	noticeType string, args ...interface{}) {

	singletonNoticeLogger.outputNotice(
		noticeType, noticeIsDiagnostic,
		append(
			[]interface{}{
				"message", fmt.Sprint(args...),
				"context", context.context},
			listCommonFields(context.fields)...)...)
}

func (context *commonLogContext) Debug(args ...interface{}) {
	// Ignored.
}

func (context *commonLogContext) Info(args ...interface{}) {
	context.outputNotice("Info", args)
}

func (context *commonLogContext) Warning(args ...interface{}) {
	context.outputNotice("Alert", args)
}

func (context *commonLogContext) Error(args ...interface{}) {
	context.outputNotice("Error", args)
}
