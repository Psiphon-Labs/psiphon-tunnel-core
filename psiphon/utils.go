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
	"net"
	"net/url"
	"os"
	"syscall"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
)

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
