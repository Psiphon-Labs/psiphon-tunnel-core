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

/*
Copyright (c) 2012 The Go Authors. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google Inc. nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

package psiphon

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// Contains is a helper function that returns true
// if the target string is in the list.
func Contains(list []string, target string) bool {
	for _, listItem := range list {
		if listItem == target {
			return true
		}
	}
	return false
}

// FlipCoin is a helper function that randomly
// returns true or false. If the underlying random
// number generator fails, FlipCoin still returns
// a result.
func FlipCoin() bool {
	randomInt, _ := MakeSecureRandomInt(2)
	return randomInt == 1
}

// MakeSecureRandomInt is a helper function that wraps
// MakeSecureRandomInt64.
func MakeSecureRandomInt(max int) (int, error) {
	randomInt, err := MakeSecureRandomInt64(int64(max))
	return int(randomInt), err
}

// MakeSecureRandomInt64 is a helper function that wraps
// crypto/rand.Int, which returns a uniform random value in [0, max).
func MakeSecureRandomInt64(max int64) (int64, error) {
	randomInt, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil {
		return 0, ContextError(err)
	}
	return randomInt.Int64(), nil
}

// MakeSecureRandomBytes is a helper function that wraps
// crypto/rand.Read.
func MakeSecureRandomBytes(length int) ([]byte, error) {
	randomBytes := make([]byte, length)
	n, err := rand.Read(randomBytes)
	if err != nil {
		return nil, ContextError(err)
	}
	if n != length {
		return nil, ContextError(errors.New("insufficient random bytes"))
	}
	return randomBytes, nil
}

// MakeSecureRandomPadding selects a random padding length in the indicated
// range and returns a random byte array of the selected length.
// In the unlikely case where an  underlying MakeRandom functions fails,
// the padding is length 0.
func MakeSecureRandomPadding(minLength, maxLength int) []byte {
	var padding []byte
	paddingSize, err := MakeSecureRandomInt(maxLength - minLength)
	if err != nil {
		NoticeAlert("MakeSecureRandomPadding: MakeSecureRandomInt failed")
		return make([]byte, 0)
	}
	paddingSize += minLength
	padding, err = MakeSecureRandomBytes(paddingSize)
	if err != nil {
		NoticeAlert("MakeSecureRandomPadding: MakeSecureRandomBytes failed")
		return make([]byte, 0)
	}
	return padding
}

// MakeRandomPeriod returns a random duration, within a given range.
// In the unlikely case where an  underlying MakeRandom functions fails,
// the period is the minimum.
func MakeRandomPeriod(min, max time.Duration) (duration time.Duration) {
	period, err := MakeSecureRandomInt64(max.Nanoseconds() - min.Nanoseconds())
	if err != nil {
		NoticeAlert("NextRandomRangePeriod: MakeSecureRandomInt64 failed")
	}
	duration = min + time.Duration(period)
	return
}

// MakeRandomString returns a base64 encoded random string. byteLength
// specifies the pre-encoded data length.
func MakeRandomString(byteLength int) (string, error) {
	bytes, err := MakeSecureRandomBytes(byteLength)
	if err != nil {
		return "", ContextError(err)
	}
	return base64.RawStdEncoding.EncodeToString(bytes), nil
}

func DecodeCertificate(encodedCertificate string) (certificate *x509.Certificate, err error) {
	derEncodedCertificate, err := base64.StdEncoding.DecodeString(encodedCertificate)
	if err != nil {
		return nil, ContextError(err)
	}
	certificate, err = x509.ParseCertificate(derEncodedCertificate)
	if err != nil {
		return nil, ContextError(err)
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

// ContextError prefixes an error message with the current function name
func ContextError(err error) error {
	if err == nil {
		return nil
	}
	pc, _, line, _ := runtime.Caller(1)
	funcName := runtime.FuncForPC(pc).Name()
	index := strings.LastIndex(funcName, "/")
	if index != -1 {
		funcName = funcName[index+1:]
	}
	return fmt.Errorf("%s#%d: %s", funcName, line, err)
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

// GetCurrentTimestamp returns the current time in UTC as
// an RFC 3339 formatted string.
func GetCurrentTimestamp() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// TruncateTimestampToHour truncates an RFC 3339 formatted string
// to hour granularity. If the input is not a valid format, the
// result is "".
func TruncateTimestampToHour(timestamp string) string {
	t, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		NoticeAlert("failed to truncate timestamp: %s", err)
		return ""
	}
	return t.Truncate(1 * time.Hour).Format(time.RFC3339)
}

// HTTPSServer is a wrapper around http.Server which adds the
// ServeTLS function.
type HTTPSServer struct {
	http.Server
}

// ServeTLS is a offers the equivalent interface as http.Serve.
// The http package has both ListenAndServe and ListenAndServeTLS higher-
// level interfaces, but only Serve (not TLS) offers a lower-level interface that
// allows the caller to keep a refererence to the Listener, allowing for external
// shutdown. ListenAndServeTLS also requires the TLS cert and key to be in files
// and we avoid that here.
// tcpKeepAliveListener is used in http.ListenAndServeTLS but not exported,
// so we use a copy from https://golang.org/src/net/http/server.go.
func (server *HTTPSServer) ServeTLS(listener net.Listener) error {
	tlsListener := tls.NewListener(tcpKeepAliveListener{listener.(*net.TCPListener)}, server.TLSConfig)
	return server.Serve(tlsListener)
}

type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(3 * time.Minute)
	return tc, nil
}
