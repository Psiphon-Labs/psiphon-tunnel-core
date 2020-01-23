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
	"crypto/x509"
	"encoding/base64"
	std_errors "errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/crypto/ssh"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/marionette"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/quic"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/stacktrace"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tapdance"
)

// MakePsiphonUserAgent constructs a User-Agent value to use for web service
// requests made by the tunnel-core client. The User-Agent includes useful stats
// information; it is to be used only for HTTPS requests, where the header
// cannot be seen by an adversary.
func MakePsiphonUserAgent(config *Config) string {
	userAgent := "psiphon-tunnel-core"
	if config.ClientVersion != "" {
		userAgent += fmt.Sprintf("/%s", config.ClientVersion)
	}
	if config.ClientPlatform != "" {
		userAgent += fmt.Sprintf(" (%s)", config.ClientPlatform)
	}
	return userAgent
}

func DecodeCertificate(encodedCertificate string) (certificate *x509.Certificate, err error) {
	derEncodedCertificate, err := base64.StdEncoding.DecodeString(encodedCertificate)
	if err != nil {
		return nil, errors.Trace(err)
	}
	certificate, err = x509.ParseCertificate(derEncodedCertificate)
	if err != nil {
		return nil, errors.Trace(err)
	}
	return certificate, nil
}

// FilterUrlError transforms an error, when it is a url.Error, removing
// the URL value. This is to avoid logging private user data in cases
// where the URL may be a user input value.
// This function is used with errors returned by net/http and net/url,
// which are (currently) of type url.Error. In particular, the round trip
// function used by our HttpProxy, http.Client.Do, returns errors of type
// url.Error, with the URL being the url sent from the user's tunneled
// applications:
// https://github.com/golang/go/blob/release-branch.go1.4/src/net/http/client.go#L394
func FilterUrlError(err error) error {
	if urlErr, ok := err.(*url.Error); ok {
		err = &url.Error{
			Op:  urlErr.Op,
			URL: "",
			Err: urlErr.Err,
		}
	}
	return err
}

// TrimError removes the middle of over-long error message strings
func TrimError(err error) error {
	const MAX_LEN = 100
	message := fmt.Sprintf("%s", err)
	if len(message) > MAX_LEN {
		return std_errors.New(message[:MAX_LEN/2] + "..." + message[len(message)-MAX_LEN/2:])
	}
	return err
}

// IsAddressInUseError returns true when the err is due to EADDRINUSE/WSAEADDRINUSE.
func IsAddressInUseError(err error) bool {
	if err, ok := err.(*net.OpError); ok {
		if err, ok := err.Err.(*os.SyscallError); ok {
			if err.Err == syscall.EADDRINUSE {
				return true
			}
			// Special case for Windows (WSAEADDRINUSE = 10048)
			if errno, ok := err.Err.(syscall.Errno); ok {
				if int(errno) == 10048 {
					return true
				}
			}
		}
	}
	return false
}

var stripIPv4AddressRegex = regexp.MustCompile(
	`(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}(:(6553[0-5]|655[0-2][0-9]\d|65[0-4](\d){2}|6[0-4](\d){3}|[1-5](\d){4}|[1-9](\d){0,3}))?`)

// StripIPAddresses returns a copy of the input with all IP addresses [and
// optional ports] replaced  by "[address]". This is intended to be used to
// strip addresses from "net" package I/O error messages and otherwise avoid
// inadvertently recording direct server IPs via error message logs; and, in
// metrics, to reduce the error space due to superfluous source port data.
//
// Limitation: only strips IPv4 addresses.
func StripIPAddresses(b []byte) []byte {
	// TODO: IPv6 support
	return stripIPv4AddressRegex.ReplaceAll(b, []byte("[redacted]"))
}

// StripIPAddressesString is StripIPAddresses for strings.
func StripIPAddressesString(s string) string {
	// TODO: IPv6 support
	return stripIPv4AddressRegex.ReplaceAllString(s, "[redacted]")
}

// RedactNetError removes network address information from a "net" package
// error message. Addresses may be domains or IP addresses.
//
// Limitations: some non-address error context can be lost; this function
// makes assumptions about how the Go "net" package error messages are
// formatted and will fail to redact network addresses if this assumptions
// become untrue.
func RedactNetError(err error) error {

	// Example "net" package error messages:
	//
	// - lookup <domain>: no such host
	// - lookup <domain>: No address associated with hostname
	// - dial tcp <address>: connectex: No connection could be made because the target machine actively refused it
	// - write tcp <address>-><address>: write: connection refused

	if err == nil {
		return err
	}

	errstr := err.Error()
	index := strings.Index(errstr, ": ")
	if index == -1 {
		return err
	}

	return std_errors.New("[redacted]" + errstr[index:])
}

// SyncFileWriter wraps a file and exposes an io.Writer. At predefined
// steps, the file is synced (flushed to disk) while writing.
type SyncFileWriter struct {
	file  *os.File
	step  int
	count int
}

// NewSyncFileWriter creates a SyncFileWriter.
func NewSyncFileWriter(file *os.File) *SyncFileWriter {
	return &SyncFileWriter{
		file:  file,
		step:  2 << 16,
		count: 0}
}

// Write implements io.Writer with periodic file syncing.
func (writer *SyncFileWriter) Write(p []byte) (n int, err error) {
	n, err = writer.file.Write(p)
	if err != nil {
		return
	}
	writer.count += n
	if writer.count >= writer.step {
		err = writer.file.Sync()
		writer.count = 0
	}
	return
}

// emptyAddr implements the net.Addr interface. emptyAddr is intended to be
// used as a stub, when a net.Addr is required but not used.
type emptyAddr struct {
}

func (e *emptyAddr) String() string {
	return ""
}

func (e *emptyAddr) Network() string {
	return ""
}

// channelConn implements the net.Conn interface. channelConn allows use of
// SSH.Channels in contexts where a net.Conn is expected. Only Read/Write/Close
// are implemented and the remaining functions are stubs and expected to not
// be used.
type channelConn struct {
	ssh.Channel
}

func newChannelConn(channel ssh.Channel) *channelConn {
	return &channelConn{
		Channel: channel,
	}
}

func (conn *channelConn) LocalAddr() net.Addr {
	return new(emptyAddr)
}

func (conn *channelConn) RemoteAddr() net.Addr {
	return new(emptyAddr)
}

func (conn *channelConn) SetDeadline(_ time.Time) error {
	return errors.TraceNew("unsupported")
}

func (conn *channelConn) SetReadDeadline(_ time.Time) error {
	return errors.TraceNew("unsupported")
}

func (conn *channelConn) SetWriteDeadline(_ time.Time) error {
	return errors.TraceNew("unsupported")
}

func emitMemoryMetrics() {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	NoticeInfo("Memory metrics at %s: goroutines %d | objects %d | alloc %s | inuse %s | sys %s | cumulative %d %s",
		stacktrace.GetParentFunctionName(),
		runtime.NumGoroutine(),
		memStats.HeapObjects,
		common.FormatByteCount(memStats.HeapAlloc),
		common.FormatByteCount(memStats.HeapInuse+memStats.StackInuse+memStats.MSpanInuse+memStats.MCacheInuse),
		common.FormatByteCount(memStats.Sys),
		memStats.Mallocs,
		common.FormatByteCount(memStats.TotalAlloc))
}

func DoGarbageCollection() {
	debug.SetGCPercent(5)
	debug.FreeOSMemory()
}

// conditionallyEnabledComponents implements the
// protocol.ConditionallyEnabledComponents interface.
type conditionallyEnabledComponents struct {
}

func (c conditionallyEnabledComponents) QUICEnabled() bool {
	return quic.Enabled()
}

func (c conditionallyEnabledComponents) MarionetteEnabled() bool {
	return marionette.Enabled()
}

func (c conditionallyEnabledComponents) TapdanceEnabled() bool {
	return tapdance.Enabled()
}
