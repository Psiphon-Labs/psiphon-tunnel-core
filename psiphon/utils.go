/*
 * Copyright (c) 2014, Psiphon Inc.
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
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"runtime"
)

// IsSignalled returns true when the signal channel yields
// a value. To be used with the idiom in which a shared
// channel is closed to broadcast a signal.
func IsSignalled(signal chan bool) bool {
	select {
	case <-signal:
		return true
	default:
	}
	return false
}

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
// crypto/rand.Int.
func MakeSecureRandomInt(max int) (int, error) {
	randomInt, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0, ContextError(err)
	}
	return int(randomInt.Uint64()), nil
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

// ContextError prefixes an error message with the current function name
func ContextError(err error) error {
	pc, _, _, _ := runtime.Caller(1)
	funcName := runtime.FuncForPC(pc).Name()
	return fmt.Errorf("%s: %s", funcName, err)
}

func MakeSessionId() (id string, err error) {
	randomId, err := MakeSecureRandomBytes(PSIPHON_API_CLIENT_SESSION_ID_LENGTH)
	if err != nil {
		return "", ContextError(err)
	}
	return hex.EncodeToString(randomId), nil
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
