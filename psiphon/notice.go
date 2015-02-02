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
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"time"
)

var noticeLoggerMutex sync.Mutex
var noticeLogger = log.New(os.Stderr, "", 0)

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
func outputNotice(noticeType string, showUser bool, args ...interface{}) {
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
	outputNotice("Info", false, "message", fmt.Sprintf(format, args...))
}

// NoticeInfo is an alert message; typically a recoverable error condition
func NoticeAlert(format string, args ...interface{}) {
	outputNotice("Alert", false, "message", fmt.Sprintf(format, args...))
}

// NoticeInfo is an error message; typically an unrecoverable error condition
func NoticeError(format string, args ...interface{}) {
	outputNotice("Error", true, "message", fmt.Sprintf(format, args...))
}

// NoticeCoreVersion is the version string of the core
func NoticeCoreVersion(version string) {
	outputNotice("CoreVersion", false, "version", version)
}

// NoticeCandidateServers is how many possible servers are available for the selected region and protocol
func NoticeCandidateServers(region, protocol string, count int) {
	outputNotice("CandidateServers", false, "region", region, "protocol", protocol, "count", count)
}

// NoticeConnectingServer is details on a connection attempt
func NoticeConnectingServer(ipAddress, region, protocol, frontingDomain string) {
	outputNotice("ConnectingServer", false, "ipAddress", ipAddress, "region",
		region, "protocol", protocol, "frontingDomain", frontingDomain)
}

// NoticeActiveTunnel is a successful connection that is used as an active tunnel for port forwarding
func NoticeActiveTunnel(ipAddress string) {
	outputNotice("ActiveTunnel", false, "ipAddress", ipAddress)
}

// NoticeSocksProxyPortInUse is a failure to use the configured LocalSocksProxyPort
func NoticeSocksProxyPortInUse(port int) {
	outputNotice("SocksProxyPortInUse", true, "port", port)
}

// NoticeListeningSocksProxyPort is the selected port for the listening local SOCKS proxy
func NoticeListeningSocksProxyPort(port int) {
	outputNotice("ListeningSocksProxyPort", false, "port", port)
}

// NoticeSocksProxyPortInUse is a failure to use the configured LocalHttpProxyPort
func NoticeHttpProxyPortInUse(port int) {
	outputNotice("HttpProxyPortInUse", true, "port", port)
}

// NoticeListeningSocksProxyPort is the selected port for the listening local HTTP proxy
func NoticeListeningHttpProxyPort(port int) {
	outputNotice("ListeningHttpProxyPort", false, "port", port)
}

// NoticeClientUpgradeAvailable is an available client upgrade, as per the handshake. The
// client should download and install an upgrade.
func NoticeClientUpgradeAvailable(version string) {
	outputNotice("ClientUgradeAvailable", false, "version", version)
}

// NoticeClientUpgradeAvailable is a sponsor homepage, as per the handshake. The client
// should display the sponsor's homepage.
func NoticeHomepage(url string) {
	outputNotice("Homepage", false, "url", url)
}

// NoticeTunnels is how many active tunnels are available. The client should use this to
// determine connecting/unexpected disconnect state transitions. When count is 0, the core is
// disconnected; when count > 1, the core is connected.
func NoticeTunnels(count int) {
	outputNotice("Tunnels", false, "count", count)
}
