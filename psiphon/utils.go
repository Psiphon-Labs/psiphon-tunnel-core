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
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net"
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

// ParseIPv4Mask parses IPv4 string of form a.b.c.d and returns 4 bytes long net.IP
func ParseIPv4(s string) net.IP {
	ip := net.ParseIP(s)
	if ip == nil {
		return nil
	}
	return ip.To4()
}

// ParseIPv4Mask parses netmask in form of an IPv4 string, i.e. 240.0.0.0
func ParseIPv4Mask(s string) net.IPMask {
	ip := ParseIPv4(s)
	if ip == nil {
		return nil
	}
	mask := net.IPMask(ip)

	//verify if mask value is valid
	if bits, size := mask.Size(); bits == 0 || size == 0 {
		return nil
	}
	return mask
}
