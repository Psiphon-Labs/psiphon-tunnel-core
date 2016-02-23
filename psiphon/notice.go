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
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var noticeLoggerMutex sync.Mutex
var noticeLogger = log.New(os.Stderr, "", 0)
var noticeLogDiagnostics = int32(0)

func setEmitDiagnosticNotices(enable bool) {
	if enable {
		atomic.StoreInt32(&noticeLogDiagnostics, 1)
	} else {
		atomic.StoreInt32(&noticeLogDiagnostics, 0)
	}
}

func getEmitDiagnoticNotices() bool {
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

// outputNotice encodes a notice in JSON and writes it to the output writer.
func outputNotice(noticeType string, isDiagnostic, showUser bool, args ...interface{}) {

	if isDiagnostic && !getEmitDiagnoticNotices() {
		return
	}

	obj := make(map[string]interface{})
	noticeData := make(map[string]interface{})
	obj["noticeType"] = noticeType
	obj["showUser"] = showUser
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
		output = fmt.Sprintf("{\"Alert\":{\"message\":\"%s\"}}", ContextError(err))
	}
	noticeLoggerMutex.Lock()
	defer noticeLoggerMutex.Unlock()
	noticeLogger.Print(output)
}

// NoticeInfo is an informational message
func NoticeInfo(format string, args ...interface{}) {
	outputNotice("Info", true, false, "message", fmt.Sprintf(format, args...))
}

// NoticeAlert is an alert message; typically a recoverable error condition
func NoticeAlert(format string, args ...interface{}) {
	outputNotice("Alert", true, false, "message", fmt.Sprintf(format, args...))
}

// NoticeError is an error message; typically an unrecoverable error condition
func NoticeError(format string, args ...interface{}) {
	outputNotice("Error", true, false, "message", fmt.Sprintf(format, args...))
}

// NoticeCandidateServers is how many possible servers are available for the selected region and protocol
func NoticeCandidateServers(region, protocol string, count int) {
	outputNotice("CandidateServers", false, false, "region", region, "protocol", protocol, "count", count)
}

// NoticeAvailableEgressRegions is what regions are available for egress from.
// Consecutive reports of the same list of regions are suppressed.
func NoticeAvailableEgressRegions(regions []string) {
	sortedRegions := append([]string(nil), regions...)
	sort.Strings(sortedRegions)
	repetitionMessage := strings.Join(sortedRegions, "")
	outputRepetitiveNotice(
		"AvailableEgressRegions", repetitionMessage, 0,
		"AvailableEgressRegions", false, false, "regions", sortedRegions)
}

// NoticeConnectingServer is details on a connection attempt
func NoticeConnectingServer(ipAddress, region, protocol, frontingAddress string) {
	outputNotice("ConnectingServer", true, false, "ipAddress", ipAddress, "region",
		region, "protocol", protocol, "frontingAddress", frontingAddress)
}

// NoticeActiveTunnel is a successful connection that is used as an active tunnel for port forwarding
func NoticeActiveTunnel(ipAddress, protocol string) {
	outputNotice("ActiveTunnel", true, false, "ipAddress", ipAddress, "protocol", protocol)
}

// NoticeSocksProxyPortInUse is a failure to use the configured LocalSocksProxyPort
func NoticeSocksProxyPortInUse(port int) {
	outputNotice("SocksProxyPortInUse", false, true, "port", port)
}

// NoticeListeningSocksProxyPort is the selected port for the listening local SOCKS proxy
func NoticeListeningSocksProxyPort(port int) {
	outputNotice("ListeningSocksProxyPort", false, false, "port", port)
}

// NoticeSocksProxyPortInUse is a failure to use the configured LocalHttpProxyPort
func NoticeHttpProxyPortInUse(port int) {
	outputNotice("HttpProxyPortInUse", false, true, "port", port)
}

// NoticeListeningSocksProxyPort is the selected port for the listening local HTTP proxy
func NoticeListeningHttpProxyPort(port int) {
	outputNotice("ListeningHttpProxyPort", false, false, "port", port)
}

// NoticeClientUpgradeAvailable is an available client upgrade, as per the handshake. The
// client should download and install an upgrade.
func NoticeClientUpgradeAvailable(version string) {
	outputNotice("ClientUpgradeAvailable", false, false, "version", version)
}

// NoticeClientUpgradeAvailable is a sponsor homepage, as per the handshake. The client
// should display the sponsor's homepage.
func NoticeHomepage(url string) {
	outputNotice("Homepage", false, false, "url", url)
}

// NoticeClientRegion is the client's region, as determined by the server and
// reported to the client in the handshake.
func NoticeClientRegion(region string) {
	outputNotice("ClientRegion", true, false, "region", region)
}

// NoticeTunnels is how many active tunnels are available. The client should use this to
// determine connecting/unexpected disconnect state transitions. When count is 0, the core is
// disconnected; when count > 1, the core is connected.
func NoticeTunnels(count int) {
	outputNotice("Tunnels", false, false, "count", count)
}

// NoticeUntunneled indicates than an address has been classified as untunneled and is being
// accessed directly.
//
// Note: "address" should remain private; this notice should only be used for alerting
// users, not for diagnostics logs.
//
func NoticeUntunneled(address string) {
	outputNotice("Untunneled", false, true, "address", address)
}

// NoticeSplitTunnelRegion reports that split tunnel is on for the given region.
func NoticeSplitTunnelRegion(region string) {
	outputNotice("SplitTunnelRegion", false, true, "region", region)
}

// NoticeUpstreamProxyError reports an error when connecting to an upstream proxy. The
// user may have input, for example, an incorrect address or incorrect credentials.
func NoticeUpstreamProxyError(err error) {
	outputNotice("UpstreamProxyError", false, true, "message", err.Error())
}

// NoticeClientUpgradeDownloaded indicates that a client upgrade download
// is complete and available at the destination specified.
func NoticeClientUpgradeDownloaded(filename string) {
	outputNotice("ClientUpgradeDownloaded", false, false, "filename", filename)
}

// NoticeBytesTransferred reports how many tunneled bytes have been
// transferred since the last NoticeBytesTransferred, for the tunnel
// to the server at ipAddress.
func NoticeBytesTransferred(ipAddress string, sent, received int64) {
	if getEmitDiagnoticNotices() {
		outputNotice("BytesTransferred", true, false, "ipAddress", ipAddress, "sent", sent, "received", received)
	} else {
		// This case keeps the EmitBytesTransferred and EmitDiagnosticNotices config options independent
		outputNotice("BytesTransferred", false, false, "sent", sent, "received", received)
	}
}

// NoticeTotalBytesTransferred reports how many tunneled bytes have been
// transferred in total up to this point, for the tunnel to the server
// at ipAddress.
func NoticeTotalBytesTransferred(ipAddress string, sent, received int64) {
	if getEmitDiagnoticNotices() {
		outputNotice("TotalBytesTransferred", true, false, "ipAddress", ipAddress, "sent", sent, "received", received)
	} else {
		// This case keeps the EmitBytesTransferred and EmitDiagnosticNotices config options independent
		outputNotice("TotalBytesTransferred", false, false, "sent", sent, "received", received)
	}
}

// NoticeLocalProxyError reports a local proxy error message. Repetitive
// errors for a given proxy type are suppressed.
func NoticeLocalProxyError(proxyType string, err error) {

	// For repeats, only consider the base error message, which is
	// the root error that repeats (the full error often contains
	// different specific values, e.g., local port numbers, but
	// the same repeating root).
	// Assumes error format of ContextError.
	repetitionMessage := err.Error()
	index := strings.LastIndex(repetitionMessage, ": ")
	if index != -1 {
		repetitionMessage = repetitionMessage[index+2:]
	}

	outputRepetitiveNotice(
		"LocalProxyError"+proxyType, repetitionMessage, 1,
		"LocalProxyError", true, false, "message", err.Error())
}

// NoticeFrontedMeekStats reports extra network details for a
// FRONTED-MEEK-OSSH or FRONTED-MEEK-HTTP-OSSH tunnel connection.
func NoticeFrontedMeekStats(ipAddress string, frontedMeekStats *FrontedMeekStats) {
	outputNotice("NoticeFrontedMeekStats", true, false, "ipAddress", ipAddress,
		"frontingAddress", frontedMeekStats.frontingAddress,
		"resolvedIPAddress", frontedMeekStats.resolvedIPAddress,
		"enabledSNI", frontedMeekStats.enabledSNI,
		"frontingHost", frontedMeekStats.frontingHost)
}

// NoticeBuildInfo reports build version info.
func NoticeBuildInfo(buildDate, buildRepo, buildRev, goVersion, gomobileVersion string) {
	outputNotice("NoticeBuildInfo", false, false,
		"buildDate", buildDate,
		"buildRepo", buildRepo,
		"buildRev", buildRev,
		"goVersion", goVersion,
		"gomobileVersion", gomobileVersion)
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
	noticeType string, isDiagnostic, showUser bool, args ...interface{}) {

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
		outputNotice(noticeType, isDiagnostic, showUser, args...)
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
