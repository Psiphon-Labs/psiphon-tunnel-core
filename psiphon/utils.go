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
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/crypto/ssh"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/inproxy"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/quic"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/refraction"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/resolver"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/stacktrace"
	"github.com/wlynxg/anet"
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
			// Special case for Windows, WSAEADDRINUSE (10048). In the case
			// where the socket already bound to the port has set
			// SO_EXCLUSIVEADDRUSE, the error will instead be WSAEACCES (10013).
			if errno, ok := err.Err.(syscall.Errno); ok {
				if int(errno) == 10048 || int(errno) == 10013 {
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

func emitDatastoreMetrics() {
	NoticeInfo("Datastore metrics at %s: %s", stacktrace.GetParentFunctionName(), GetDataStoreMetrics())
}

func emitDNSMetrics(resolver *resolver.Resolver) {
	NoticeInfo("DNS metrics at %s: %s", stacktrace.GetParentFunctionName(), resolver.GetMetrics())
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

func (c conditionallyEnabledComponents) RefractionNetworkingEnabled() bool {
	return refraction.Enabled()
}

func (c conditionallyEnabledComponents) InproxyEnabled() bool {
	return inproxy.Enabled()
}

// FileMigration represents the action of moving a file, or directory, to a new
// location.
type FileMigration struct {

	// Name is the name of the migration for logging because file paths are not
	// logged as they may contain sensitive information.
	Name string

	// OldPath is the current location of the file.
	OldPath string

	// NewPath is the location that the file should be moved to.
	NewPath string

	// IsDir should be set to true if the file is a directory.
	IsDir bool
}

// DoFileMigration performs the specified file move operation. An error will be
// returned and the operation will not performed if: a file is expected, but a
// directory is found; a directory is expected, but a file is found; or a file,
// or directory, already exists at the target path of the move operation.
// Note: an attempt is made to redact any file paths from the returned error.
func DoFileMigration(migration FileMigration) error {

	// Prefix string added to any errors for debug purposes.
	errPrefix := ""
	if len(migration.Name) > 0 {
		errPrefix = fmt.Sprintf("(%s) ", migration.Name)
	}

	if !common.FileExists(migration.OldPath) {
		return errors.TraceNew(errPrefix + "old path does not exist")
	}
	info, err := os.Stat(migration.OldPath)
	if err != nil {
		return errors.Tracef(errPrefix+"error getting file info: %s", common.RedactFilePathsError(err, migration.OldPath))
	}
	if info.IsDir() != migration.IsDir {
		if migration.IsDir {
			return errors.TraceNew(errPrefix + "expected directory but found file")
		}

		return errors.TraceNew(errPrefix + "expected but found directory")
	}

	if common.FileExists(migration.NewPath) {
		return errors.TraceNew(errPrefix + "file already exists, will not overwrite")
	}

	err = os.Rename(migration.OldPath, migration.NewPath)
	if err != nil {
		return errors.Tracef(errPrefix+"renaming file failed with error %s", common.RedactFilePathsError(err, migration.OldPath, migration.NewPath))
	}

	return nil
}

// GetNetworkType returns a network type name, suitable for metrics, which is
// derived from the network ID.
func GetNetworkType(networkID string) string {

	// Unlike the logic in loggingNetworkIDGetter.GetNetworkID, we don't take the
	// arbitrary text before the first "-" since some platforms without network
	// detection support stub in random values to enable tactics. Instead we
	// check for and use the common network type prefixes currently used in
	// NetworkIDGetter implementations.

	if strings.HasPrefix(networkID, "WIFI") {
		return "WIFI"
	}
	if strings.HasPrefix(networkID, "MOBILE") {
		return "MOBILE"
	}
	if strings.HasPrefix(networkID, "WIRED") {
		return "WIRED"
	}
	if strings.HasPrefix(networkID, "VPN") {
		return "VPN"
	}
	return "UNKNOWN"
}

var (
	clientAPILevelDisableInproxyPortMapping atomic.Bool
	applyClientAPILevelMutex                sync.Mutex
)

func applyClientAPILevel(config *Config) {

	applyClientAPILevelMutex.Lock()
	defer applyClientAPILevelMutex.Unlock()

	if config.ClientAPILevel == 0 {
		return
	}

	if runtime.GOOS == "android" {

		// When specified, ClientAPILevel should be Build.VERSION.SDK_INT on
		// Android.
		//
		// Avoid android_get_device_api_level call.
		//
		// Use ClientAPILevel to explicitly set the Android API level in the
		// anet packet, which provides a custom alternative to net.Interfaces
		// on Android. Applying Build.VERSION.SDK_INT here avoids anet
		// calling the lic function android_get_device_api_level call, which
		// may not always be available.
		//
		// The Android API level is required in order for anet to select its
		// custom Interfaces on Android >= 11, where the stock net.Interfaces
		// doesn't work (see Go issue 40569). The stock net.Interfaces should be
		// selected on Android < 11, as testing shows that anet.Interfaces fails
		// to enumerate all interfaces, including wlan, on older Android versions.
		//
		// anet.SetAndroidVersion must be called before the Controller starts in
		// order to ensure the explicit version is applied before any call to
		// android_get_device_api_level. Note that anet doesn't synchronize
		// access to its internal anet.customAndroidApiLevel value;
		// applyClientAPILevelMutex prevents concurrent writes by the following
		// anet.SetAndroidVersion call, but reads by anet remain unsynchronized
		// apart from scheduling the applyClientAPILevel call before the
		// Controller starts.
		//
		// anet.SetAndroidVersion takes the Android OS version, not API level, but
		// internally it has only two states: if the specified Android OS version
		// is >= 11, customAndroidApiLevel is set to 30 and the custom Interfaces
		// is enabled; otherwise, the stock net.Interfaces is used.

		if config.ClientAPILevel >= 30 {

			anet.SetAndroidVersion(11)

		} else {

			anet.SetAndroidVersion(10)
		}

		// Disable the tailscale portmapper on Android < 12.
		//
		// On Android < 12, the exec.Command calls in tailscale helper
		// functions, including likelyHomeRouterIPAndroid, will currently hit
		// Go issue 70508: on Go 1.23, the standard library implementation of
		// exec.Command calls pidfd_open, which crashes shared libraries with
		// SIGSYS, "Cause: seccomp prevented call to disallowed arm64 system
		// call 434". Note that tailscale currently works around this by
		// patching out the pidfd calls from its fork of Go; see tailscale
		// issue 13452.

		if config.ClientAPILevel < 31 {

			clientAPILevelDisableInproxyPortMapping.Store(true)
		}
	}
}
