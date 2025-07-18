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
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/buildinfo"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/stacktrace"
)

type noticeLogger struct {
	emitDiagnostics            int32
	emitNetworkParameters      int32
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

// SetEmitDiagnosticNotices toggles whether diagnostic notices are emitted;
// and whether to include circumvention network parameters in diagnostics.
//
// Diagnostic notices contain potentially sensitive user information; and
// sensitive circumvention network parameters, when enabled. Only enable this
// in environments where notices are handled securely (for example, don't
// include these notices in log files which users could post to public
// forums).
func SetEmitDiagnosticNotices(
	emitDiagnostics bool, emitNetworkParameters bool) {

	if emitDiagnostics {
		atomic.StoreInt32(&singletonNoticeLogger.emitDiagnostics, 1)
	} else {
		atomic.StoreInt32(&singletonNoticeLogger.emitDiagnostics, 0)
	}

	if emitNetworkParameters {
		atomic.StoreInt32(&singletonNoticeLogger.emitNetworkParameters, 1)
	} else {
		atomic.StoreInt32(&singletonNoticeLogger.emitNetworkParameters, 0)
	}
}

// GetEmitDiagnosticNotices returns the current state
// of emitting diagnostic notices.
func GetEmitDiagnosticNotices() bool {
	return atomic.LoadInt32(&singletonNoticeLogger.emitDiagnostics) == 1
}

// GetEmitNetworkParameters returns the current state
// of emitting network parameters.
func GetEmitNetworkParameters() bool {
	return atomic.LoadInt32(&singletonNoticeLogger.emitNetworkParameters) == 1
}

// SetNoticeWriter sets a target writer to receive notices. By default,
// notices are written to stderr. Notices are newline delimited.
//
// writer specifies an alternate io.Writer where notices are to be written.
//
// Notices are encoded in JSON. Here's an example:
//
// {"data":{"message":"shutdown operate tunnel"},"noticeType":"Info","timestamp":"2006-01-02T15:04:05.999999999Z07:00"}
//
// All notices have the following fields:
// - "noticeType": the type of notice, which indicates the meaning of the notice along with what's in the data payload.
// - "data": additional structured data payload. For example, the "ListeningSocksProxyPort" notice type has a "port" integer
// data in its payload.
// - "timestamp": UTC timezone, RFC3339Milli format timestamp for notice event
//
// See the Notice* functions for details on each notice meaning and payload.
//
// SetNoticeWriter does not replace the writer and returns an error if a
// non-default writer is already set.
func SetNoticeWriter(writer io.Writer) error {

	singletonNoticeLogger.mutex.Lock()
	defer singletonNoticeLogger.mutex.Unlock()

	if f, ok := singletonNoticeLogger.writer.(*os.File); !ok || f != os.Stderr {
		return errors.TraceNew("notice writer already set")
	}

	singletonNoticeLogger.writer = writer

	return nil
}

// ResetNoticeWriter resets the notice write to the default, stderr.
func ResetNoticeWriter() {

	singletonNoticeLogger.mutex.Lock()
	defer singletonNoticeLogger.mutex.Unlock()

	singletonNoticeLogger.writer = os.Stderr
}

// setNoticeFiles configures files for notice writing.
//
//   - When homepageFilename is not "", homepages are written to the specified file
//     and omitted from the writer. The file may be read after the Tunnels notice
//     with count of 1. The file should be opened read-only for reading.
//
//   - When rotatingFilename is not "", all notices are are written to the specified
//     file. Diagnostic notices are omitted from the writer. The file is rotated
//     when its size exceeds rotatingFileSize. One rotated older file,
//     <rotatingFilename>.1, is retained. The files may be read at any time; and
//     should be opened read-only for reading. rotatingSyncFrequency specifies how
//     many notices are written before syncing the file.
//     If either rotatingFileSize or rotatingSyncFrequency are <= 0, default values
//     are used.
//
//   - If an error occurs when writing to a file, an InternalError notice is emitted to
//     the writer.
//
// setNoticeFiles closes open homepage or rotating files before applying the new
// configuration.
func setNoticeFiles(
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
			return errors.Trace(err)
		}
		singletonNoticeLogger.homepageFilename = homepageFilename
	}

	if rotatingFilename != "" {
		var err error
		if singletonNoticeLogger.rotatingFile != nil {
			singletonNoticeLogger.rotatingFile.Close()
		}
		singletonNoticeLogger.rotatingFile, err = os.OpenFile(
			rotatingFilename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return errors.Trace(err)
		}

		fileInfo, err := singletonNoticeLogger.rotatingFile.Stat()
		if err != nil {
			return errors.Trace(err)
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
	noticeIsDiagnostic    = 1
	noticeIsHomepage      = 2
	noticeClearHomepages  = 4
	noticeSyncHomepages   = 8
	noticeSkipRedaction   = 16
	noticeIsNotDiagnostic = 32
)

// outputNotice encodes a notice in JSON and writes it to the output writer.
func (nl *noticeLogger) outputNotice(noticeType string, noticeFlags uint32, args ...interface{}) {

	if (noticeFlags&noticeIsDiagnostic != 0) && !GetEmitDiagnosticNotices() {
		return
	}

	obj := make(map[string]interface{})
	noticeData := make(map[string]interface{})
	obj["noticeType"] = noticeType
	obj["data"] = noticeData
	obj["timestamp"] = time.Now().UTC().Format(common.RFC3339Milli)
	for i := 0; i < len(args)-1; i += 2 {
		name, ok := args[i].(string)
		if ok {

			value := args[i+1]

			// encoding/json marshals error types as "{}", so convert to error
			// message string.
			if err, isError := value.(error); isError {
				value = err.Error()
			}

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
			fmt.Sprintf("marshal notice failed: %s", errors.Trace(err)))
	}

	// Skip redaction when we need to display browsing activity network addresses
	// to users; for example, in the case of the Untunneled notice. Never log
	// skipRedaction notices to diagnostics files (outputNoticeToRotatingFile,
	// below). The notice writer may still be invoked for a skipRedaction notice;
	// the writer must keep all known skipRedaction notices out of any upstream
	// diagnostics logs.

	skipRedaction := (noticeFlags&noticeSkipRedaction != 0)

	if !skipRedaction {
		// Ensure direct server IPs are not exposed in notices. The "net" package,
		// and possibly other 3rd party packages, will include destination addresses
		// in I/O error messages.
		output = common.RedactIPAddresses(output)
	}

	// Don't call RedactFilePaths here, as the file path redaction can
	// potentially match many non-path strings. Instead, RedactFilePaths should
	// be applied in specific cases.

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
			// Skip writing to the host application if the notice is diagnostic
			// and not explicitly marked as not diagnostic
			skipWriter = (noticeFlags&noticeIsDiagnostic != 0) && (noticeFlags&noticeIsNotDiagnostic == 0)
		}

		if !skipRedaction {
			// Only write to the rotating file if the notice is not explicitly marked as not diagnostic.
			if noticeFlags&noticeIsNotDiagnostic == 0 {

				err := nl.outputNoticeToRotatingFile(output)

				if err != nil {
					output := makeNoticeInternalError(
						fmt.Sprintf("write rotating file failed: %s", err))
					nl.writer.Write(output)
				}
			}
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
	alertNoticeFormat := "{\"noticeType\":\"InternalError\",\"timestamp\":\"%s\",\"data\":{\"message\":\"%s\"}}\n"
	return []byte(fmt.Sprintf(alertNoticeFormat, time.Now().UTC().Format(common.RFC3339Milli), errorMessage))
}

func (nl *noticeLogger) outputNoticeToHomepageFile(noticeFlags uint32, output []byte) error {

	if (noticeFlags & noticeClearHomepages) != 0 {
		err := nl.homepageFile.Truncate(0)
		if err != nil {
			return errors.Trace(err)
		}
		_, err = nl.homepageFile.Seek(0, 0)
		if err != nil {
			return errors.Trace(err)
		}
	}

	_, err := nl.homepageFile.Write(output)
	if err != nil {
		return errors.Trace(err)
	}

	if (noticeFlags & noticeSyncHomepages) != 0 {
		err = nl.homepageFile.Sync()
		if err != nil {
			return errors.Trace(err)
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
			return errors.Trace(err)
		}

		err = nl.rotatingFile.Close()
		if err != nil {
			return errors.Trace(err)
		}

		err = os.Rename(nl.rotatingFilename, nl.rotatingOlderFilename)
		if err != nil {
			return errors.Trace(err)
		}

		nl.rotatingFile, err = os.OpenFile(
			nl.rotatingFilename, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if err != nil {
			return errors.Trace(err)
		}

		nl.rotatingCurrentFileSize = 0
	}

	_, err := nl.rotatingFile.Write(output)
	if err != nil {
		return errors.Trace(err)
	}

	nl.rotatingCurrentNoticeCount += 1
	if nl.rotatingCurrentNoticeCount >= nl.rotatingSyncFrequency {
		nl.rotatingCurrentNoticeCount = 0
		err = nl.rotatingFile.Sync()
		if err != nil {
			return errors.Trace(err)
		}
	}

	return nil
}

// nonConstantSprintf sidesteps the `go vet` "non-constant format string" check
func nonConstantSprintf(format, _ string, args ...interface{}) string {
	return fmt.Sprintf(format, args...)
}

// NoticeInfo is an informational message
func NoticeInfo(format string, args ...interface{}) {
	singletonNoticeLogger.outputNotice(
		"Info", noticeIsDiagnostic,
		"message", nonConstantSprintf(format, "", args...))
}

// NoticeWarning is a warning message; typically a recoverable error condition
func NoticeWarning(format string, args ...interface{}) {
	singletonNoticeLogger.outputNotice(
		"Warning", noticeIsDiagnostic,
		"message", nonConstantSprintf(format, "", args...))
}

// NoticeError is an error message; typically an unrecoverable error condition
func NoticeError(format string, args ...interface{}) {
	singletonNoticeLogger.outputNotice(
		"Error", noticeIsDiagnostic,
		"message", nonConstantSprintf(format, "", args...))
}

// NoticeUserLog is a log message from the outer client user of tunnel-core
func NoticeUserLog(message string) {
	singletonNoticeLogger.outputNotice(
		"UserLog", noticeIsDiagnostic,
		"message", message)
}

// NoticeCandidateServers is how many possible servers are available for the selected region and protocols
func NoticeCandidateServers(
	region string,
	constraints *protocolSelectionConstraints,
	initialCount int,
	count int,
	duration time.Duration) {

	singletonNoticeLogger.outputNotice(
		"CandidateServers", noticeIsDiagnostic,
		"region", region,
		"initialLimitTunnelProtocols", constraints.initialLimitTunnelProtocols,
		"initialLimitTunnelProtocolsCandidateCount", constraints.initialLimitTunnelProtocolsCandidateCount,
		"limitTunnelProtocols", constraints.limitTunnelProtocols,
		"limitTunnelDialPortNumbers", constraints.limitTunnelDialPortNumbers,
		"replayCandidateCount", constraints.replayCandidateCount,
		"initialCount", initialCount,
		"count", count,
		"duration", duration.String())
}

// NoticeAvailableEgressRegions is what regions are available for egress from.
// Consecutive reports of the same list of regions are suppressed.
func NoticeAvailableEgressRegions(regions []string) {
	sortedRegions := append([]string{}, regions...)
	sort.Strings(sortedRegions)
	repetitionMessage := strings.Join(sortedRegions, "")
	outputRepetitiveNotice(
		"AvailableEgressRegions", repetitionMessage, 0,
		"AvailableEgressRegions", 0, "regions", sortedRegions)
}

func noticeWithDialParameters(noticeType string, dialParams *DialParameters, postDial bool) {

	args := []interface{}{
		"diagnosticID", dialParams.ServerEntry.GetDiagnosticID(),
		"region", dialParams.ServerEntry.Region,
		"protocol", dialParams.TunnelProtocol,
		"isReplay", dialParams.IsReplay,
		"candidateNumber", dialParams.CandidateNumber,
		"establishedTunnelsCount", dialParams.EstablishedTunnelsCount,
		"networkType", dialParams.GetNetworkType(),
	}

	if GetEmitNetworkParameters() {

		// Omit appliedTacticsTag as that is emitted in another notice.

		if dialParams.BPFProgramName != "" {
			args = append(args, "clientBPF", dialParams.BPFProgramName)
		}

		if dialParams.SelectedSSHClientVersion {
			args = append(args, "SSHClientVersion", dialParams.SSHClientVersion)
		}

		if dialParams.UpstreamProxyType != "" {
			args = append(args, "upstreamProxyType", dialParams.UpstreamProxyType)
		}

		if dialParams.UpstreamProxyCustomHeaderNames != nil {
			args = append(args, "upstreamProxyCustomHeaderNames", strings.Join(dialParams.UpstreamProxyCustomHeaderNames, ","))
		}

		if dialParams.ServerEntry.ProviderID != "" {
			args = append(args, "providerID", dialParams.ServerEntry.ProviderID)
		}

		if dialParams.FrontingProviderID != "" {
			args = append(args, "frontingProviderID", dialParams.FrontingProviderID)
		}

		if dialParams.MeekDialAddress != "" {
			args = append(args, "meekDialAddress", dialParams.MeekDialAddress)
		}

		if protocol.TunnelProtocolUsesFrontedMeek(dialParams.TunnelProtocol) {

			meekResolvedIPAddress := dialParams.MeekResolvedIPAddress.Load().(string)
			if meekResolvedIPAddress != "" {
				nonredacted := common.EscapeRedactIPAddressString(meekResolvedIPAddress)
				args = append(args, "meekResolvedIPAddress", nonredacted)
			}
		}

		if dialParams.MeekSNIServerName != "" {
			args = append(args, "meekSNIServerName", dialParams.MeekSNIServerName)
		}

		if dialParams.MeekHostHeader != "" {
			args = append(args, "meekHostHeader", dialParams.MeekHostHeader)
		}

		// MeekTransformedHostName is meaningful when meek is used, which is when MeekDialAddress != ""
		if dialParams.MeekDialAddress != "" {
			args = append(args, "meekTransformedHostName", dialParams.MeekTransformedHostName)
		}

		if dialParams.TLSOSSHSNIServerName != "" {
			args = append(args, "tlsOSSHSNIServerName", dialParams.TLSOSSHSNIServerName)
		}

		if dialParams.TLSOSSHTransformedSNIServerName {
			args = append(args, "tlsOSSHTransformedSNIServerName", dialParams.TLSOSSHTransformedSNIServerName)
		}

		if dialParams.TLSFragmentClientHello {
			args = append(args, "tlsFragmentClientHello", dialParams.TLSFragmentClientHello)
		}

		if dialParams.SelectedUserAgent {
			args = append(args, "userAgent", dialParams.UserAgent)
		}

		if dialParams.SelectedTLSProfile {
			args = append(args, "TLSProfile", dialParams.TLSProfile)
			args = append(args, "TLSVersion", dialParams.GetTLSVersionForMetrics())
		}

		// dialParams.ServerEntry.Region is emitted above.

		if dialParams.ServerEntry.LocalSource != "" {
			args = append(args, "serverEntrySource", dialParams.ServerEntry.LocalSource)
		}

		localServerEntryTimestamp := common.TruncateTimestampToHour(
			dialParams.ServerEntry.LocalTimestamp)
		if localServerEntryTimestamp != "" {
			args = append(args, "serverEntryTimestamp", localServerEntryTimestamp)
		}

		if dialParams.DialPortNumber != "" {
			args = append(args, "dialPortNumber", dialParams.DialPortNumber)
		}

		if dialParams.QUICVersion != "" {
			args = append(args, "QUICVersion", dialParams.QUICVersion)
		}

		if dialParams.QUICDialSNIAddress != "" {
			args = append(args, "QUICDialSNIAddress", dialParams.QUICDialSNIAddress)
		}

		if dialParams.QUICDisablePathMTUDiscovery {
			args = append(args, "QUICDisableClientPathMTUDiscovery", dialParams.QUICDisablePathMTUDiscovery)
		}

		if dialParams.DialDuration > 0 {
			args = append(args, "dialDuration", dialParams.DialDuration)
		}

		if dialParams.NetworkLatencyMultiplier != 0.0 {
			args = append(args, "networkLatencyMultiplier", dialParams.NetworkLatencyMultiplier)
		}

		if dialParams.ConjureTransport != "" {
			args = append(args, "conjureTransport", dialParams.ConjureTransport)
		}

		usedSteeringIP := false

		if dialParams.SteeringIP != "" {
			nonredacted := common.EscapeRedactIPAddressString(dialParams.SteeringIP)
			args = append(args, "steeringIP", nonredacted)
			usedSteeringIP = true
		}

		if dialParams.ResolveParameters != nil && !usedSteeringIP {

			// See dialParams.ResolveParameters comment in getBaseAPIParameters.

			if dialParams.ResolveParameters.PreresolvedIPAddress != "" {
				meekDialDomain, _, _ := net.SplitHostPort(dialParams.MeekDialAddress)
				if dialParams.ResolveParameters.PreresolvedDomain == meekDialDomain {
					nonredacted := common.EscapeRedactIPAddressString(dialParams.ResolveParameters.PreresolvedIPAddress)
					args = append(args, "DNSPreresolved", nonredacted)
				}
			}

			if dialParams.ResolveParameters.PreferAlternateDNSServer {
				nonredacted := common.EscapeRedactIPAddressString(dialParams.ResolveParameters.AlternateDNSServer)
				args = append(args, "DNSPreferred", nonredacted)
			}

			if dialParams.ResolveParameters.ProtocolTransformName != "" {
				args = append(args, "DNSTransform", dialParams.ResolveParameters.ProtocolTransformName)
			}

			if postDial {
				args = append(args, "DNSQNameMismatches", dialParams.ResolveParameters.GetQNameMismatches())

				args = append(args, "DNSAttempt", dialParams.ResolveParameters.GetFirstAttemptWithAnswer())
			}
		}

		if dialParams.HTTPTransformerParameters != nil {
			if dialParams.HTTPTransformerParameters.ProtocolTransformSpec != nil {
				args = append(args, "HTTPTransform", dialParams.HTTPTransformerParameters.ProtocolTransformName)
			}
		}

		if dialParams.OSSHObfuscatorSeedTransformerParameters != nil {
			if dialParams.OSSHObfuscatorSeedTransformerParameters.TransformSpec != nil {
				args = append(args, "SeedTransform", dialParams.OSSHObfuscatorSeedTransformerParameters.TransformName)
			}
		}

		if dialParams.ObfuscatedQUICNonceTransformerParameters != nil {
			if dialParams.ObfuscatedQUICNonceTransformerParameters.TransformSpec != nil {
				args = append(args, "SeedTransform", dialParams.ObfuscatedQUICNonceTransformerParameters.TransformName)
			}
		}

		if dialParams.OSSHPrefixSpec != nil {
			if dialParams.OSSHPrefixSpec.Spec != nil {
				args = append(args, "OSSHPrefix", dialParams.OSSHPrefixSpec.Name)
			}
		}

		if dialParams.DialConnMetrics != nil {
			metrics := dialParams.DialConnMetrics.GetMetrics()
			for name, value := range metrics {
				args = append(args, name, value)
			}
		}

		if dialParams.DialConnNoticeMetrics != nil {
			metrics := dialParams.DialConnNoticeMetrics.GetNoticeMetrics()
			for name, value := range metrics {
				args = append(args, name, value)
			}
		}

		if dialParams.ObfuscatedSSHConnMetrics != nil {
			metrics := dialParams.ObfuscatedSSHConnMetrics.GetMetrics()
			for name, value := range metrics {
				args = append(args, name, value)
			}
		}

		if protocol.TunnelProtocolUsesInproxy(dialParams.TunnelProtocol) {
			metrics := dialParams.GetInproxyMetrics()
			for name, value := range metrics {
				args = append(args, name, value)
			}
		}

		if dialParams.ShadowsocksPrefixSpec != nil {
			if dialParams.ShadowsocksPrefixSpec.Spec != nil {
				args = append(args, "ShadowsocksPrefix", dialParams.ShadowsocksPrefixSpec.Name)
			}
		}

	}

	singletonNoticeLogger.outputNotice(
		noticeType, noticeIsDiagnostic,
		args...)
}

// NoticeConnectingServer reports parameters and details for a single connection attempt
func NoticeConnectingServer(dialParams *DialParameters) {
	noticeWithDialParameters("ConnectingServer", dialParams, false)
}

// NoticeConnectedServer reports parameters and details for a single successful connection
func NoticeConnectedServer(dialParams *DialParameters) {
	noticeWithDialParameters("ConnectedServer", dialParams, true)
}

// NoticeRequestingTactics reports parameters and details for a tactics request attempt
func NoticeRequestingTactics(dialParams *DialParameters) {
	noticeWithDialParameters("RequestingTactics", dialParams, false)
}

// NoticeRequestedTactics reports parameters and details for a successful tactics request
func NoticeRequestedTactics(dialParams *DialParameters) {
	noticeWithDialParameters("RequestedTactics", dialParams, true)
}

// NoticeActiveTunnel is a successful connection that is used as an active tunnel for port forwarding
func NoticeActiveTunnel(diagnosticID, protocol string) {
	singletonNoticeLogger.outputNotice(
		"ActiveTunnel", noticeIsDiagnostic,
		"diagnosticID", diagnosticID,
		"protocol", protocol)
}

// NoticeConnectedServerRegion reports the region of the connected server
func NoticeConnectedServerRegion(serverRegion string) {
	singletonNoticeLogger.outputNotice(
		"ConnectedServerRegion", 0,
		"serverRegion", serverRegion)
}

// NoticeSocksProxyPortInUse is a failure to use the configured LocalSocksProxyPort
func NoticeSocksProxyPortInUse(port int) {
	singletonNoticeLogger.outputNotice(
		"SocksProxyPortInUse", 0,
		"port", port)
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
		"HttpProxyPortInUse", 0,
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

// NoticeClientAddress is the client's public network address, the IP address
// and port, as seen by the server and reported to the client in the
// handshake.
//
// Note: "address" should remain private and not included in diagnostics logs.
func NoticeClientAddress(address string) {
	singletonNoticeLogger.outputNotice(
		"ClientAddress", noticeSkipRedaction,
		"address", address)
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

// NoticeSplitTunnelRegions reports that split tunnel is on for the given country codes.
func NoticeSplitTunnelRegions(regions []string) {
	singletonNoticeLogger.outputNotice(
		"SplitTunnelRegions", 0,
		"regions", regions)
}

// NoticeUntunneled indicates than an address has been classified as untunneled and is being
// accessed directly.
//
// Note: "address" should remain private; this notice should only be used for alerting
// users, not for diagnostics logs.
func NoticeUntunneled(address string) {
	outputRepetitiveNotice(
		"Untunneled", address, 0,
		"Untunneled", noticeSkipRedaction, "address", address)

}

// NoticeUpstreamProxyError reports an error when connecting to an upstream proxy. The
// user may have input, for example, an incorrect address or incorrect credentials.
func NoticeUpstreamProxyError(err error) {
	message := err.Error()
	outputRepetitiveNotice(
		"UpstreamProxyError", message, 0,
		"UpstreamProxyError", 0,
		"message", message)
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
// transferred since the last NoticeBytesTransferred. This is not a diagnostic
// notice: the user app has requested this notice with EmitBytesTransferred
// for functionality such as traffic display; and this frequent notice is not
// intended to be included with feedback. The noticeIsNotDiagnostic flag
// ensures that these notices are emitted to the host application but not written
// to the diagnostic file to avoid cluttering it with frequent updates.
func NoticeBytesTransferred(diagnosticID string, sent, received int64) {
	singletonNoticeLogger.outputNotice(
		"BytesTransferred", noticeIsNotDiagnostic,
		"diagnosticID", diagnosticID,
		"sent", sent,
		"received", received)
}

// NoticeTotalBytesTransferred reports how many tunneled bytes have been
// transferred in total up to this point. This is a diagnostic notice.
func NoticeTotalBytesTransferred(diagnosticID string, sent, received int64) {
	singletonNoticeLogger.outputNotice(
		"TotalBytesTransferred", noticeIsDiagnostic,
		"diagnosticID", diagnosticID,
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
	// Assumes error format of errors.Trace.
	repetitionMessage := err.Error()
	index := strings.LastIndex(repetitionMessage, ": ")
	if index != -1 {
		repetitionMessage = repetitionMessage[index+2:]
	}

	outputRepetitiveNotice(
		"LocalProxyError-"+proxyType, repetitionMessage, 1,
		"LocalProxyError", noticeIsDiagnostic,
		"message", err.Error())
}

// NoticeBuildInfo reports build version info.
func NoticeBuildInfo() {
	singletonNoticeLogger.outputNotice(
		"BuildInfo", noticeIsDiagnostic,
		"buildInfo", buildinfo.GetBuildInfo())
}

// NoticeExiting indicates that tunnel-core is exiting imminently.
func NoticeExiting() {
	singletonNoticeLogger.outputNotice(
		"Exiting", 0)
}

// NoticeRemoteServerListResourceDownloadedBytes reports remote server list download progress.
func NoticeRemoteServerListResourceDownloadedBytes(url string, bytes int64, duration time.Duration) {
	if !GetEmitNetworkParameters() {
		url = "[redacted]"
	}
	singletonNoticeLogger.outputNotice(
		"RemoteServerListResourceDownloadedBytes", noticeIsDiagnostic,
		"url", url,
		"bytes", bytes,
		"duration", duration.String())
}

// NoticeRemoteServerListResourceDownloaded indicates that a remote server list download
// completed successfully.
func NoticeRemoteServerListResourceDownloaded(url string) {
	if !GetEmitNetworkParameters() {
		url = "[redacted]"
	}
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
func NoticeServerTimestamp(diagnosticID string, timestamp string) {
	singletonNoticeLogger.outputNotice(
		"ServerTimestamp", 0,
		"diagnosticID", diagnosticID,
		"timestamp", timestamp)
}

// NoticeActiveAuthorizationIDs reports the authorizations the server has accepted.
// Each ID is a base64-encoded accesscontrol.Authorization.ID value.
func NoticeActiveAuthorizationIDs(diagnosticID string, activeAuthorizationIDs []string) {

	// Never emit 'null' instead of empty list
	if activeAuthorizationIDs == nil {
		activeAuthorizationIDs = []string{}
	}

	singletonNoticeLogger.outputNotice(
		"ActiveAuthorizationIDs", 0,
		"diagnosticID", diagnosticID,
		"IDs", activeAuthorizationIDs)
}

// NoticeTrafficRateLimits reports the tunnel traffic rate limits in place for
// this client, as reported by the server at the start of the tunnel. Values
// of 0 indicate no limit. Values of -1 indicate that the server did not
// report rate limits.
//
// Limitation: any rate limit changes during the lifetime of the tunnel are
// not reported.
func NoticeTrafficRateLimits(
	diagnosticID string, upstreamBytesPerSecond, downstreamBytesPerSecond int64) {

	singletonNoticeLogger.outputNotice(
		"TrafficRateLimits", 0,
		"diagnosticID", diagnosticID,
		"upstreamBytesPerSecond", upstreamBytesPerSecond,
		"downstreamBytesPerSecond", downstreamBytesPerSecond)
}

func NoticeBindToDevice(deviceInfo string) {
	outputRepetitiveNotice(
		"BindToDevice", deviceInfo, 0,
		"BindToDevice", 0, "deviceInfo", deviceInfo)
}

func NoticeNetworkID(networkID string) {
	outputRepetitiveNotice(
		"NetworkID", networkID, 0,
		"NetworkID", 0, "ID", networkID)
}

func NoticeLivenessTest(diagnosticID string, metrics *livenessTestMetrics, success bool) {
	if GetEmitNetworkParameters() {
		singletonNoticeLogger.outputNotice(
			"LivenessTest", noticeIsDiagnostic,
			"diagnosticID", diagnosticID,
			"metrics", metrics,
			"success", success)
	}
}

func NoticePruneServerEntry(serverEntryTag string) {
	singletonNoticeLogger.outputNotice(
		"PruneServerEntry", noticeIsDiagnostic,
		"serverEntryTag", serverEntryTag)
}

// NoticeEstablishTunnelTimeout reports that the configured EstablishTunnelTimeout
// duration was exceeded.
func NoticeEstablishTunnelTimeout(timeout time.Duration) {
	singletonNoticeLogger.outputNotice(
		"EstablishTunnelTimeout", 0,
		"timeout", timeout.String())
}

func NoticeFragmentor(diagnosticID string, message string) {
	if GetEmitNetworkParameters() {
		singletonNoticeLogger.outputNotice(
			"Fragmentor", noticeIsDiagnostic,
			"diagnosticID", diagnosticID,
			"message", message)
	}
}

// NoticeApplicationParameters reports application parameters.
func NoticeApplicationParameters(keyValues parameters.KeyValues) {

	// Never emit 'null' instead of empty object
	if keyValues == nil {
		keyValues = parameters.KeyValues{}
	}

	outputRepetitiveNotice(
		"ApplicationParameters", fmt.Sprintf("%+v", keyValues), 0,
		"ApplicationParameters", 0,
		"parameters", keyValues)
}

// NoticeServerAlert reports server alerts. Each distinct server alert is
// reported at most once per session.
func NoticeServerAlert(alert protocol.AlertRequest) {

	// Never emit 'null' instead of empty list
	actionURLs := alert.ActionURLs
	if actionURLs == nil {
		actionURLs = []string{}
	}

	// This key ensures that each distinct server alert will appear, not repeat,
	// and not interfere with other alerts appearing.
	repetitionKey := fmt.Sprintf("ServerAlert-%+v", alert)
	outputRepetitiveNotice(
		repetitionKey, "", 0,
		"ServerAlert", 0,
		"reason", alert.Reason,
		"subject", alert.Subject,
		"actionURLs", actionURLs)
}

// NoticeBursts reports tunnel data transfer burst metrics.
func NoticeBursts(diagnosticID string, burstMetrics common.LogFields) {
	if GetEmitNetworkParameters() {
		singletonNoticeLogger.outputNotice(
			"Bursts", noticeIsDiagnostic,
			append([]interface{}{"diagnosticID", diagnosticID}, listCommonFields(burstMetrics)...)...)
	}
}

// NoticeHoldOffTunnel reports tunnel hold-offs.
func NoticeHoldOffTunnel(diagnosticID string, duration time.Duration) {
	if GetEmitNetworkParameters() {
		singletonNoticeLogger.outputNotice(
			"HoldOffTunnel", noticeIsDiagnostic,
			"diagnosticID", diagnosticID,
			"duration", duration.String())
	}
}

// NoticeSkipServerEntry reports a reason for skipping a server entry when
// preparing dial parameters. To avoid log noise, the server entry
// diagnosticID is not emitted and each reason is reported at most once per
// session.
func NoticeSkipServerEntry(format string, args ...interface{}) {
	reason := fmt.Sprintf(format, args...)
	repetitionKey := fmt.Sprintf("SkipServerEntryReason-%+v", reason)
	outputRepetitiveNotice(
		repetitionKey, "", 0,
		"SkipServerEntry", 0, "reason", reason)
}

// NoticeInproxyMustUpgrade reports that an in-proxy component requires an app
// upgrade. Currently this includes running a proxy; and running a client in
// personal pairing mode. The receiver should alert the user to upgrade the
// app.
//
// There is at most one InproxyMustUpgrade notice emitted per controller run,
// and an InproxyMustUpgrade notice is followed by a tunnel-core shutdown.
func NoticeInproxyMustUpgrade() {
	singletonNoticeLogger.outputNotice(
		"InproxyMustUpgrade", 0)
}

// NoticeInproxyProxyActivity reports proxy usage statistics. The stats are
// for activity since the last NoticeInproxyProxyActivity report.
//
// This is not a diagnostic notice: the user app has requested this notice
// with EmitInproxyProxyActivity for functionality such as traffic display;
// and this frequent notice is not intended to be included with feedback.
func NoticeInproxyProxyActivity(
	connectingClients int32,
	connectedClients int32,
	bytesUp int64,
	bytesDown int64) {

	singletonNoticeLogger.outputNotice(
		"InproxyProxyActivity", noticeIsNotDiagnostic,
		"connectingClients", connectingClients,
		"connectedClients", connectedClients,
		"bytesUp", bytesUp,
		"bytesDown", bytesDown)
}

// NoticeInproxyProxyTotalActivity reports how many proxied bytes have been
// transferred in total up to this point; in addition to current connection
// status. This is a diagnostic notice.
func NoticeInproxyProxyTotalActivity(
	connectingClients int32,
	connectedClients int32,
	totalBytesUp int64,
	totalBytesDown int64) {

	singletonNoticeLogger.outputNotice(
		"InproxyProxyTotalActivity", noticeIsDiagnostic,
		"connectingClients", connectingClients,
		"connectedClients", connectedClients,
		"totalBytesUp", totalBytesUp,
		"totalBytesDown", totalBytesDown)
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

	state, keyFound := repetitiveNoticeStates[repetitionKey]
	if !keyFound {
		state = &repetitiveNoticeState{message: repetitionMessage}
		repetitiveNoticeStates[repetitionKey] = state
	}

	emit := true
	if keyFound {
		if repetitionMessage != state.message {
			state.message = repetitionMessage
			state.repeats = 0
		} else {
			state.repeats += 1
			if state.repeats > repeatLimit {
				emit = false
			}
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
		return "", nil, errors.Trace(err)
	}

	var data interface{}
	err = json.Unmarshal(object.Data, &data)
	if err != nil {
		return "", nil, errors.Trace(err)
	}

	dataValue, ok := data.(map[string]interface{})
	if !ok {
		return "", nil, errors.TraceNew("invalid data value")
	}

	return object.NoticeType, dataValue, nil
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

// NoticeLineWriter implements io.Writer and emits the contents of Write calls
// as Notices. NoticeLineWriter buffers writes and emits a notice for each
// complete, newline delimited line. Tab characters are replaced with spaces.
type NoticeLineWriter struct {
	noticeType string
	lineBuffer strings.Builder
}

// NoticeLineWriter initializes a new NoticeLineWriter
func NewNoticeLineWriter(noticeType string) *NoticeLineWriter {
	return &NoticeLineWriter{noticeType: noticeType}
}

// Write implements io.Writer.
func (writer *NoticeLineWriter) Write(p []byte) (n int, err error) {

	str := strings.ReplaceAll(string(p), "\t", "    ")

	for {
		before, after, found := strings.Cut(str, "\n")
		writer.lineBuffer.WriteString(before)
		if !found {
			return len(p), nil
		}
		singletonNoticeLogger.outputNotice(
			writer.noticeType, noticeIsDiagnostic,
			"message", writer.lineBuffer.String())
		writer.lineBuffer.Reset()
		if len(after) == 0 {
			break
		}
		str = after
	}

	return len(p), nil
}

// NoticeCommonLogger maps the common.Logger interface to the notice facility.
// This is used to make the notice facility available to other packages that
// don't import the "psiphon" package.
func NoticeCommonLogger(debugLogging bool) common.Logger {
	return &commonLogger{
		debugLogging: debugLogging,
	}
}

type commonLogger struct {
	debugLogging bool
}

func (logger *commonLogger) WithTrace() common.LogTrace {
	return &commonLogTrace{
		trace:        stacktrace.GetParentFunctionName(),
		debugLogging: logger.debugLogging,
	}
}

func (logger *commonLogger) WithTraceFields(fields common.LogFields) common.LogTrace {
	return &commonLogTrace{
		trace:        stacktrace.GetParentFunctionName(),
		fields:       fields,
		debugLogging: logger.debugLogging,
	}
}

func (logger *commonLogger) LogMetric(metric string, fields common.LogFields) {
	singletonNoticeLogger.outputNotice(
		metric, noticeIsDiagnostic,
		listCommonFields(fields)...)
}

func (log *commonLogger) IsLogLevelDebug() bool {
	return log.debugLogging
}

func listCommonFields(fields common.LogFields) []interface{} {
	fieldList := make([]interface{}, 0)
	for name, value := range fields {
		fieldList = append(fieldList, name, value)
	}
	return fieldList
}

type commonLogTrace struct {
	trace        string
	fields       common.LogFields
	debugLogging bool
}

func (log *commonLogTrace) outputNotice(
	noticeType string, args ...interface{}) {

	singletonNoticeLogger.outputNotice(
		noticeType, noticeIsDiagnostic,
		append(
			[]interface{}{
				"message", fmt.Sprint(args...),
				"trace", log.trace},
			listCommonFields(log.fields)...)...)
}

func (log *commonLogTrace) Debug(args ...interface{}) {
	if !log.debugLogging {
		return
	}
	log.outputNotice("Debug", args...)
}

func (log *commonLogTrace) Info(args ...interface{}) {
	log.outputNotice("Info", args...)
}

func (log *commonLogTrace) Warning(args ...interface{}) {
	log.outputNotice("Alert", args...)
}

func (log *commonLogTrace) Error(args ...interface{}) {
	log.outputNotice("Error", args...)
}
