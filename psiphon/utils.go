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
	"errors"
	"fmt"
	"math"
	"net"
	"net/url"
	"os"
	"runtime"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/crypto/ssh"
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
		return nil, common.ContextError(err)
	}
	certificate, err = x509.ParseCertificate(derEncodedCertificate)
	if err != nil {
		return nil, common.ContextError(err)
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
		return errors.New(message[:MAX_LEN/2] + "..." + message[len(message)-MAX_LEN/2:])
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
				if 10048 == int(errno) {
					return true
				}
			}
		}
	}
	return false
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
	return common.ContextError(errors.New("unsupported"))
}

func (conn *channelConn) SetReadDeadline(_ time.Time) error {
	return common.ContextError(errors.New("unsupported"))
}

func (conn *channelConn) SetWriteDeadline(_ time.Time) error {
	return common.ContextError(errors.New("unsupported"))
}

// Based on: https://bitbucket.org/psiphon/psiphon-circumvention-system/src/b2884b0d0a491e55420ed1888aea20d00fefdb45/Android/app/src/main/java/com/psiphon3/psiphonlibrary/Utils.java?at=default#Utils.java-646
func byteCountFormatter(bytes uint64) string {
	base := uint64(1024)
	if bytes < base {
		return fmt.Sprintf("%dB", bytes)
	}
	exp := int(math.Log(float64(bytes)) / math.Log(float64(base)))
	return fmt.Sprintf(
		"%.1f%c", float64(bytes)/math.Pow(float64(base), float64(exp)), "KMGTPEZ"[exp-1])
}

func emitMemoryMetrics() {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	NoticeInfo("Memory metrics at %s: goroutines %d | total alloc %s | sys %s | heap alloc/sys/idle/inuse/released/objects %s/%s/%s/%s/%s/%d | stack inuse/sys %s/%s | mspan inuse/sys %s/%s | mcached inuse/sys %s/%s | buckhash/gc/other sys %s/%s/%s | nextgc %s",
		runtime.NumGoroutine(),
		common.GetParentContext(),
		byteCountFormatter(memStats.TotalAlloc),
		byteCountFormatter(memStats.Sys),
		byteCountFormatter(memStats.HeapAlloc),
		byteCountFormatter(memStats.HeapSys),
		byteCountFormatter(memStats.HeapIdle),
		byteCountFormatter(memStats.HeapInuse),
		byteCountFormatter(memStats.HeapReleased),
		memStats.HeapObjects,
		byteCountFormatter(memStats.StackInuse),
		byteCountFormatter(memStats.StackSys),
		byteCountFormatter(memStats.MSpanInuse),
		byteCountFormatter(memStats.MSpanSys),
		byteCountFormatter(memStats.MCacheInuse),
		byteCountFormatter(memStats.MCacheSys),
		byteCountFormatter(memStats.BuckHashSys),
		byteCountFormatter(memStats.GCSys),
		byteCountFormatter(memStats.OtherSys),
		byteCountFormatter(memStats.NextGC))
}

func setAggressiveGarbageCollection() {
	debug.SetGCPercent(20)
	debug.FreeOSMemory()
}

func setStandardGarbageCollection() {
	debug.SetGCPercent(100)
	debug.FreeOSMemory()
}
