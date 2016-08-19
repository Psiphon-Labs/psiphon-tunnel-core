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
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
)

var noticeLoggerMutex sync.Mutex
var noticeLogger = log.New(os.Stderr, "", 0)
var noticeLogDiagnostics = int32(0)

// SetEmitDiagnosticNotices toggles whether diagnostic notices
// are emitted. Diagnostic notices contain potentially sensitive
// circumvention network information; only enable this in environments
// where notices are handled securely (for example, don't include these
// notices in log files which users could post to public forums).
func SetEmitDiagnosticNotices(enable bool) {
	if enable {
		atomic.StoreInt32(&noticeLogDiagnostics, 1)
	} else {
		atomic.StoreInt32(&noticeLogDiagnostics, 0)
	}
}

// GetEmitDiagnoticNotices returns the current state
// of emitting diagnostic notices.
func GetEmitDiagnoticNotices() bool {
	return atomic.LoadInt32(&noticeLogDiagnostics) == 1
}

// SetNoticeOutput sets a target writer to receive notices. By default,
// notices are written to stderr.
//
// Notices are encoded in JSON. Here's an example:
//
// {"data":{"message":"shutdown operate tunnel"},"noticeType":"Info","showUser":false,"timestamp":"2015-01-28T17:35:13Z"}
//
// All notices have the following fields:
// - "noticeType": the type of notice, which indicates the meaning of the notice along with what's in the data payload.
// - "data": additional structured data payload. For example, the "ListeningSocksProxyPort" notice type has a "port" integer
// data in its payload.
// - "showUser": whether the information should be displayed to the user. For example, this flag is set for "SocksProxyPortInUse"
// as the user should be informed that their configured choice of listening port could not be used. Core clients should
// anticipate that the core will add additional "showUser"=true notices in the future and emit at least the raw notice.
// - "timestamp": UTC timezone, RFC3339 format timestamp for notice event
//
// See the Notice* functions for details on each notice meaning and payload.
//
func SetNoticeOutput(output io.Writer) {
	noticeLoggerMutex.Lock()
	defer noticeLoggerMutex.Unlock()
	noticeLogger = log.New(output, "", 0)
}

const (
	noticeIsDiagnostic = 1
	noticeShowUser     = 2
)

// outputNotice encodes a notice in JSON and writes it to the output writer.
func outputNotice(noticeType string, noticeFlags uint32, args ...interface{}) {

	if (noticeFlags&noticeIsDiagnostic != 0) && !GetEmitDiagnoticNotices() {
		return
	}

	obj := make(map[string]interface{})
	noticeData := make(map[string]interface{})
	obj["noticeType"] = noticeType
	obj["showUser"] = (noticeFlags&noticeShowUser != 0)
	obj["data"] = noticeData
	obj["timestamp"] = time.Now().UTC().Format(time.RFC3339)
	for i := 0; i < len(args)-1; i += 2 {
		name, ok := args[i].(string)
		value := args[i+1]
		if ok {
			noticeData[name] = value
		}
	}
	encodedJson, err := json.Marshal(obj)
	var output string
	if err == nil {
		output = string(encodedJson)
	} else {
		// Try to emit a properly formatted Alert notice that the outer client can
		// report. One scenario where this is useful is if the preceeding Marshal
		// fails due to bad data in the args. This has happened for a json.RawMessage
		// field.
		obj := make(map[string]interface{})
		obj["noticeType"] = "Alert"
		obj["showUser"] = false
		obj["data"] = map[string]interface{}{
			"message": fmt.Sprintf("Marshal notice failed: %s", common.ContextError(err)),
		}
		obj["timestamp"] = time.Now().UTC().Format(time.RFC3339)
		encodedJson, err := json.Marshal(obj)
		if err == nil {
			output = string(encodedJson)
		} else {
			output = common.ContextError(errors.New("failed to marshal notice")).Error()
		}
	}
	noticeLoggerMutex.Lock()
	defer noticeLoggerMutex.Unlock()
	noticeLogger.Print(output)
}

// NoticeInfo is an informational message
func NoticeInfo(format string, args ...interface{}) {
	outputNotice("Info", noticeIsDiagnostic, "message", fmt.Sprintf(format, args...))
}

// NoticeAlert is an alert message; typically a recoverable error condition
func NoticeAlert(format string, args ...interface{}) {
	outputNotice("Alert", noticeIsDiagnostic, "message", fmt.Sprintf(format, args...))
}

// NoticeError is an error message; typically an unrecoverable error condition
func NoticeError(format string, args ...interface{}) {
	outputNotice("Error", noticeIsDiagnostic, "message", fmt.Sprintf(format, args...))
}

// NoticeCandidateServers is how many possible servers are available for the selected region and protocol
func NoticeCandidateServers(region, protocol string, count int) {
	outputNotice("CandidateServers", 0, "region", region, "protocol", protocol, "count", count)
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

// NoticeConnectingServer is details on a connection attempt
func NoticeConnectingServer(ipAddress, region, protocol, directTCPDialAddress string, meekConfig *MeekConfig) {
	if meekConfig == nil {
		outputNotice("ConnectingServer", noticeIsDiagnostic,
			"ipAddress", ipAddress,
			"region", region,
			"protocol", protocol,
			"directTCPDialAddress", directTCPDialAddress)
	} else {
		outputNotice("ConnectingServer", noticeIsDiagnostic,
			"ipAddress", ipAddress,
			"region", region,
			"protocol", protocol,
			"meekDialAddress", meekConfig.DialAddress,
			"meekUseHTTPS", meekConfig.UseHTTPS,
			"meekSNIServerName", meekConfig.SNIServerName,
			"meekHostHeader", meekConfig.HostHeader,
			"meekTransformedHostName", meekConfig.TransformedHostName)
	}
}

// NoticeActiveTunnel is a successful connection that is used as an active tunnel for port forwarding
func NoticeActiveTunnel(ipAddress, protocol string) {
	outputNotice("ActiveTunnel", noticeIsDiagnostic, "ipAddress", ipAddress, "protocol", protocol)
}

// NoticeSocksProxyPortInUse is a failure to use the configured LocalSocksProxyPort
func NoticeSocksProxyPortInUse(port int) {
	outputNotice("SocksProxyPortInUse", noticeShowUser, "port", port)
}

// NoticeListeningSocksProxyPort is the selected port for the listening local SOCKS proxy
func NoticeListeningSocksProxyPort(port int) {
	outputNotice("ListeningSocksProxyPort", 0, "port", port)
}

// NoticeSocksProxyPortInUse is a failure to use the configured LocalHttpProxyPort
func NoticeHttpProxyPortInUse(port int) {
	outputNotice("HttpProxyPortInUse", noticeShowUser, "port", port)
}

// NoticeListeningSocksProxyPort is the selected port for the listening local HTTP proxy
func NoticeListeningHttpProxyPort(port int) {
	outputNotice("ListeningHttpProxyPort", 0, "port", port)
}

// NoticeClientUpgradeAvailable is an available client upgrade, as per the handshake. The
// client should download and install an upgrade.
func NoticeClientUpgradeAvailable(version string) {
	outputNotice("ClientUpgradeAvailable", 0, "version", version)
}

// NoticeClientIsLatestVersion reports that an upgrade check was made and the client
// is already the latest version. availableVersion is the version available for download,
// if known.
func NoticeClientIsLatestVersion(availableVersion string) {
	outputNotice("ClientIsLatestVersion", 0, "availableVersion", availableVersion)
}

// NoticeHomepage is a sponsor homepage, as per the handshake. The client
// should display the sponsor's homepage.
func NoticeHomepage(url string) {
	outputNotice("Homepage", 0, "url", url)
}

// NoticeClientVerificationRequired indicates that client verification is required, as
// indicated by the handshake. The client should submit a client verification payload.
// Empty nonce is allowed, if ttlSeconds is 0 the client should not send verification
// payload to the server. If resetCache is set the client must always perform a new
// verification and update its cache
func NoticeClientVerificationRequired(nonce string, ttlSeconds int, resetCache bool) {
	outputNotice("ClientVerificationRequired", 0, "nonce", nonce, "ttlSeconds", ttlSeconds, "resetCache", resetCache)
}

// NoticeClientRegion is the client's region, as determined by the server and
// reported to the client in the handshake.
func NoticeClientRegion(region string) {
	outputNotice("ClientRegion", 0, "region", region)
}

// NoticeTunnels is how many active tunnels are available. The client should use this to
// determine connecting/unexpected disconnect state transitions. When count is 0, the core is
// disconnected; when count > 1, the core is connected.
func NoticeTunnels(count int) {
	outputNotice("Tunnels", 0, "count", count)
}

// NoticeSessionId is the session ID used across all tunnels established by the controller.
func NoticeSessionId(sessionId string) {
	outputNotice("SessionId", noticeIsDiagnostic, "sessionId", sessionId)
}

func NoticeImpairedProtocolClassification(impairedProtocolClassification map[string]int) {
	outputNotice("ImpairedProtocolClassification", noticeIsDiagnostic,
		"classification", impairedProtocolClassification)
}

// NoticeUntunneled indicates than an address has been classified as untunneled and is being
// accessed directly.
//
// Note: "address" should remain private; this notice should only be used for alerting
// users, not for diagnostics logs.
//
func NoticeUntunneled(address string) {
	outputNotice("Untunneled", noticeShowUser, "address", address)
}

// NoticeSplitTunnelRegion reports that split tunnel is on for the given region.
func NoticeSplitTunnelRegion(region string) {
	outputNotice("SplitTunnelRegion", noticeShowUser, "region", region)
}

// NoticeUpstreamProxyError reports an error when connecting to an upstream proxy. The
// user may have input, for example, an incorrect address or incorrect credentials.
func NoticeUpstreamProxyError(err error) {
	outputNotice("UpstreamProxyError", noticeShowUser, "message", err.Error())
}

// NoticeClientUpgradeDownloadedBytes reports client upgrade download progress.
func NoticeClientUpgradeDownloadedBytes(bytes int64) {
	outputNotice("ClientUpgradeDownloadedBytes", noticeIsDiagnostic, "bytes", bytes)
}

// NoticeClientUpgradeDownloaded indicates that a client upgrade download
// is complete and available at the destination specified.
func NoticeClientUpgradeDownloaded(filename string) {
	outputNotice("ClientUpgradeDownloaded", 0, "filename", filename)
}

// NoticeBytesTransferred reports how many tunneled bytes have been
// transferred since the last NoticeBytesTransferred, for the tunnel
// to the server at ipAddress.
func NoticeBytesTransferred(ipAddress string, sent, received int64) {
	if GetEmitDiagnoticNotices() {
		outputNotice("BytesTransferred", noticeIsDiagnostic, "ipAddress", ipAddress, "sent", sent, "received", received)
	} else {
		// This case keeps the EmitBytesTransferred and EmitDiagnosticNotices config options independent
		outputNotice("BytesTransferred", 0, "sent", sent, "received", received)
	}
}

// NoticeTotalBytesTransferred reports how many tunneled bytes have been
// transferred in total up to this point, for the tunnel to the server
// at ipAddress.
func NoticeTotalBytesTransferred(ipAddress string, sent, received int64) {
	if GetEmitDiagnoticNotices() {
		outputNotice("TotalBytesTransferred", noticeIsDiagnostic, "ipAddress", ipAddress, "sent", sent, "received", received)
	} else {
		// This case keeps the EmitBytesTransferred and EmitDiagnosticNotices config options independent
		outputNotice("TotalBytesTransferred", 0, "sent", sent, "received", received)
	}
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
		"LocalProxyError", noticeIsDiagnostic, "message", err.Error())
}

// NoticeConnectedTunnelDialStats reports extra network details for tunnel connections that required extra configuration.
func NoticeConnectedTunnelDialStats(ipAddress string, tunnelDialStats *TunnelDialStats) {
	outputNotice("ConnectedTunnelDialStats", noticeIsDiagnostic,
		"ipAddress", ipAddress,
		"upstreamProxyType", tunnelDialStats.UpstreamProxyType,
		"upstreamProxyCustomHeaderNames", strings.Join(tunnelDialStats.UpstreamProxyCustomHeaderNames, ","),
		"meekDialAddress", tunnelDialStats.MeekDialAddress,
		"meekDialAddress", tunnelDialStats.MeekDialAddress,
		"meekResolvedIPAddress", tunnelDialStats.MeekResolvedIPAddress,
		"meekSNIServerName", tunnelDialStats.MeekSNIServerName,
		"meekHostHeader", tunnelDialStats.MeekHostHeader,
		"meekTransformedHostName", tunnelDialStats.MeekTransformedHostName)
}

// NoticeBuildInfo reports build version info.
func NoticeBuildInfo() {
	outputNotice("BuildInfo", 0, "buildInfo", common.GetBuildInfo())
}

// NoticeExiting indicates that tunnel-core is exiting imminently.
func NoticeExiting() {
	outputNotice("Exiting", 0)
}

// NoticeRemoteServerListDownloadedBytes reports remote server list download progress.
func NoticeRemoteServerListDownloadedBytes(bytes int64) {
	outputNotice("RemoteServerListDownloadedBytes", noticeIsDiagnostic, "bytes", bytes)
}

// NoticeRemoteServerListDownloaded indicates that a remote server list download
// completed successfully.
func NoticeRemoteServerListDownloaded(filename string) {
	outputNotice("RemoteServerListDownloaded", noticeIsDiagnostic, "filename", filename)
}

func NoticeClientVerificationRequestCompleted(ipAddress string) {
	outputNotice("NoticeClientVerificationRequestCompleted", noticeIsDiagnostic, "ipAddress", ipAddress)
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
		outputNotice(noticeType, noticeFlags, args...)
	}
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
	receiver.buffer = receiver.buffer[index+1:]

	receiver.callback(notice)

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
