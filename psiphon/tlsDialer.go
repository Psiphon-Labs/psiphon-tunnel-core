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

// Fork of https://github.com/getlantern/tlsdialer (http://gopkg.in/getlantern/tlsdialer.v1)
// which itself is a "Fork of crypto/tls.Dial and DialWithDialer"

// Adds two capabilities to tlsdialer:
//
// 1. HTTP proxy support, so the dialer may be used with http.Transport.
//
// 2. Support for self-signed Psiphon server certificates, which Go's certificate
//    verification rejects due to two short comings:
//    - lack of IP address SANs.
//      see: "...because it doesn't contain any IP SANs" case in crypto/x509/verify.go
//    - non-compliant constraint configuration (RFC 5280, 4.2.1.9).
//      see: CheckSignatureFrom() in crypto/x509/x509.go
//    Since the client has to be able to handle existing Psiphon server certificates,
//    we need to be able to perform some form of verification in these cases.

// tlsdialer:
// package tlsdialer contains a customized version of crypto/tls.Dial that
// allows control over whether or not to send the ServerName extension in the
// client handshake.

package psiphon

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

type timeoutError struct{}

func (timeoutError) Error() string   { return "tls: DialWithDialer timed out" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// CustomTLSConfig contains parameters to determine the behavior
// of CustomTLSDial.
type CustomTLSConfig struct {
	// Dial is the network connection dialer. TLS is layered on
	// top of a new network connection created with dialer.
	Dial Dialer
	// Timeout is and optional timeout for combined network
	// connection dial and TLS handshake.
	Timeout time.Duration
	// FrontingAddr overrides the "addr" input to Dial when specified
	FrontingAddr string
	// HttpProxyAddress specifies an HTTP proxy to be used
	// (with HTTP CONNECT).
	HttpProxyAddress string
	// SendServerName specifies whether to use SNI
	// (tlsdialer functionality)
	SendServerName bool
	// VerifyLegacyCertificate is a special case self-signed server
	// certificate case. Ignores IP SANs and basic constraints. No
	// certificate chain. Just checks that the server presented the
	// specified certificate.
	VerifyLegacyCertificate *x509.Certificate
	// TlsConfig is a tls.Config to use in the
	// non-verifyLegacyCertificate case.
	TlsConfig *tls.Config
}

func NewCustomTLSDialer(config *CustomTLSConfig) Dialer {
	return func(network, addr string) (net.Conn, error) {
		return CustomTLSDial(network, addr, config)
	}
}

// CustomTLSDialWithDialer is a customized replacement for tls.Dial.
// Based on tlsdialer.DialWithDialer which is based on crypto/tls.DialWithDialer.
//
// tlsdialer comment:
//   Note - if sendServerName is false, the VerifiedChains field on the
//   connection's ConnectionState will never get populated.
func CustomTLSDial(network, addr string, config *CustomTLSConfig) (*tls.Conn, error) {

	// We want the Timeout and Deadline values from dialer to cover the
	// whole process: TCP connection and TLS handshake. This means that we
	// also need to start our own timers now.
	var errChannel chan error
	if config.Timeout != 0 {
		errChannel = make(chan error, 2)
		time.AfterFunc(config.Timeout, func() {
			errChannel <- timeoutError{}
		})
	}

	dialAddr := addr
	if config.HttpProxyAddress != "" {
		dialAddr = config.HttpProxyAddress
	} else if config.FrontingAddr != "" {
		dialAddr = config.FrontingAddr
	}

	rawConn, err := config.Dial(network, dialAddr)
	if err != nil {
		return nil, err
	}

	targetAddr := addr
	if config.FrontingAddr != "" {
		targetAddr = config.FrontingAddr
	}

	colonPos := strings.LastIndex(targetAddr, ":")
	if colonPos == -1 {
		colonPos = len(targetAddr)
	}
	hostname := targetAddr[:colonPos]

	tlsConfig := config.TlsConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
	}

	serverName := tlsConfig.ServerName

	// If no ServerName is set, infer the ServerName
	// from the hostname we're connecting to.
	if serverName == "" {
		serverName = hostname
	}

	// Copy config so we can tweak it
	tlsConfigCopy := new(tls.Config)
	*tlsConfigCopy = *tlsConfig

	if config.SendServerName {
		// Set the ServerName and rely on the usual logic in
		// tls.Conn.Handshake() to do its verification
		tlsConfigCopy.ServerName = serverName
	} else {
		// Disable verification in tls.Conn.Handshake().  We'll verify manually
		// after handshaking
		tlsConfigCopy.InsecureSkipVerify = true
	}

	conn := tls.Client(rawConn, tlsConfigCopy)

	establishConnection := func(rawConn net.Conn, conn *tls.Conn) error {
		// TODO: use the proxy request/response code from net/http/transport.go
		if config.HttpProxyAddress != "" {
			connectRequest := fmt.Sprintf(
				"CONNECT %s HTTP/1.1\r\nHost: %s\r\nConnection: Keep-Alive\r\n\r\n",
				targetAddr, hostname)
			_, err := rawConn.Write([]byte(connectRequest))
			if err != nil {
				return err
			}
			expectedResponse := []byte("HTTP/1.1 200 OK\r\n\r\n")
			readBuffer := make([]byte, len(expectedResponse))
			_, err = io.ReadFull(rawConn, readBuffer)
			if err != nil {
				return err
			}
			if !bytes.Equal(readBuffer, expectedResponse) {
				return fmt.Errorf("unexpected HTTP proxy response: %s", string(readBuffer))
			}
		}
		return conn.Handshake()
	}

	if config.Timeout == 0 {
		err = establishConnection(rawConn, conn)
	} else {
		go func() {
			errChannel <- establishConnection(rawConn, conn)
		}()
		err = <-errChannel
	}

	if err == nil && config.VerifyLegacyCertificate != nil {
		err = verifyLegacyCertificate(conn, config.VerifyLegacyCertificate)
	} else if err == nil && !config.SendServerName && !tlsConfig.InsecureSkipVerify {
		// Manually verify certificates
		err = verifyServerCerts(conn, serverName, tlsConfigCopy)
	}

	if err != nil {
		rawConn.Close()
		return nil, err
	}

	return conn, nil
}

func verifyLegacyCertificate(conn *tls.Conn, expectedCertificate *x509.Certificate) error {
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) < 1 {
		return errors.New("no certificate to verify")
	}
	if !bytes.Equal(certs[0].Raw, expectedCertificate.Raw) {
		return errors.New("unexpected certificate")
	}
	return nil
}

func verifyServerCerts(conn *tls.Conn, serverName string, config *tls.Config) error {
	certs := conn.ConnectionState().PeerCertificates

	opts := x509.VerifyOptions{
		Roots:         config.RootCAs,
		CurrentTime:   time.Now(),
		DNSName:       serverName,
		Intermediates: x509.NewCertPool(),
	}

	for i, cert := range certs {
		if i == 0 {
			continue
		}
		opts.Intermediates.AddCert(cert)
	}
	_, err := certs[0].Verify(opts)
	return err
}
