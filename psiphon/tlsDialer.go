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
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	utls "github.com/Psiphon-Labs/utls"
)

// CustomTLSConfig contains parameters to determine the behavior
// of CustomTLSDial.
type CustomTLSConfig struct {

	// ClientParameters is the active set of client parameters to use
	// for the TLS dial.
	ClientParameters *parameters.ClientParameters

	// Dial is the network connection dialer. TLS is layered on
	// top of a new network connection created with dialer.
	Dial Dialer

	// DialAddr overrides the "addr" input to Dial when specified
	DialAddr string

	// UseDialAddrSNI specifies whether to always use the dial "addr"
	// host name in the SNI server_name field. When DialAddr is set,
	// its host name is used.
	UseDialAddrSNI bool

	// SNIServerName specifies the value to set in the SNI
	// server_name field. When blank, SNI is omitted. Note that
	// underlying TLS code also automatically omits SNI when
	// the server_name is an IP address.
	// SNIServerName is ignored when UseDialAddrSNI is true.
	SNIServerName string

	// SkipVerify completely disables server certificate verification.
	SkipVerify bool

	// VerifyLegacyCertificate is a special case self-signed server
	// certificate case. Ignores IP SANs and basic constraints. No
	// certificate chain. Just checks that the server presented the
	// specified certificate. SNI is disbled when this is set.
	VerifyLegacyCertificate *x509.Certificate

	// TLSProfile specifies a particular indistinguishable TLS profile to use
	// for the TLS dial. When TLSProfile is "", a profile is selected at
	// random. Setting TLSProfile allows the caller to pin the selection so
	// all TLS connections in a certain context (e.g. a single meek
	// connection) use a consistent value. The value should be selected by
	// calling SelectTLSProfile, which will pick a value at random, subject to
	// compatibility constraints.
	TLSProfile string

	// TrustedCACertificatesFilename specifies a file containing trusted
	// CA certs. See Config.TrustedCACertificatesFilename.
	TrustedCACertificatesFilename string

	// ObfuscatedSessionTicketKey enables obfuscated session tickets
	// using the specified key.
	ObfuscatedSessionTicketKey string

	// ClientSessionCache specifies a cache to use to persist session
	// tickets, enabling TLS session resumability across multiple
	// CustomTLSDial calls or dialers using the same CustomTLSConfig.
	ClientSessionCache utls.ClientSessionCache
}

func SelectTLSProfile(
	tunnelProtocol string,
	clientParameters *parameters.ClientParameters) string {

	limitTLSProfiles := clientParameters.Get().TLSProfiles(parameters.LimitTLSProfiles)

	tlsProfiles := make([]string, 0)

	for _, tlsProfile := range protocol.SupportedTLSProfiles {

		if len(limitTLSProfiles) > 0 &&
			!common.Contains(limitTLSProfiles, tlsProfile) {
			continue
		}

		tlsProfiles = append(tlsProfiles, tlsProfile)
	}

	if len(tlsProfiles) == 0 {
		return ""
	}

	choice, _ := common.MakeSecureRandomInt(len(tlsProfiles))

	return tlsProfiles[choice]
}

func getClientHelloID(tlsProfile string) utls.ClientHelloID {
	switch tlsProfile {
	case protocol.TLS_PROFILE_IOS_1131:
		return utls.HelloiOSSafari_11_3_1
	case protocol.TLS_PROFILE_ANDROID_60:
		return utls.HelloAndroid_6_0_Browser
	case protocol.TLS_PROFILE_ANDROID_51:
		return utls.HelloAndroid_5_1_Browser
	case protocol.TLS_PROFILE_CHROME_58:
		return utls.HelloChrome_58
	case protocol.TLS_PROFILE_CHROME_57:
		return utls.HelloChrome_57
	case protocol.TLS_PROFILE_FIREFOX_56:
		return utls.HelloFirefox_56
	case protocol.TLS_PROFILE_RANDOMIZED:
		return utls.HelloRandomized
	default:
		return utls.HelloGolang
	}
}

func NewCustomTLSDialer(config *CustomTLSConfig) Dialer {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return CustomTLSDial(ctx, network, addr, config)
	}
}

// CustomTLSDial is a customized replacement for tls.Dial.
// Based on tlsdialer.DialWithDialer which is based on crypto/tls.DialWithDialer.
//
// To ensure optimal TLS profile selection when using CustomTLSDial for tunnel
// protocols, call SelectTLSProfile first and set its result into
// config.TLSProfile.
//
// tlsdialer comment:
//   Note - if sendServerName is false, the VerifiedChains field on the
//   connection's ConnectionState will never get populated.
func CustomTLSDial(
	ctx context.Context,
	network, addr string,
	config *CustomTLSConfig) (net.Conn, error) {

	if !config.SkipVerify &&
		config.VerifyLegacyCertificate == nil &&
		config.TrustedCACertificatesFilename != "" {
		return nil, common.ContextError(
			errors.New("TrustedCACertificatesFilename not supported"))
	}

	dialAddr := addr
	if config.DialAddr != "" {
		dialAddr = config.DialAddr
	}

	rawConn, err := config.Dial(ctx, network, dialAddr)
	if err != nil {
		return nil, common.ContextError(err)
	}

	hostname, _, err := net.SplitHostPort(dialAddr)
	if err != nil {
		rawConn.Close()
		return nil, common.ContextError(err)
	}

	selectedTLSProfile := config.TLSProfile

	if selectedTLSProfile == "" {
		selectedTLSProfile = SelectTLSProfile("", config.ClientParameters)
	}

	clientSessionCache := config.ClientSessionCache
	if clientSessionCache == nil {
		clientSessionCache = utls.NewLRUClientSessionCache(0)
	}

	tlsConfig := &utls.Config{
		ClientSessionCache: clientSessionCache,
	}

	if config.SkipVerify {
		tlsConfig.InsecureSkipVerify = true
	}

	if config.UseDialAddrSNI {
		tlsConfig.ServerName = hostname
	} else if config.SNIServerName != "" && config.VerifyLegacyCertificate == nil {
		// Set the ServerName and rely on the usual logic in
		// tls.Conn.Handshake() to do its verification.
		// Note: Go TLS will automatically omit this ServerName when it's an IP address
		tlsConfig.ServerName = config.SNIServerName
	} else {
		// No SNI.
		// Disable verification in tls.Conn.Handshake().  We'll verify manually
		// after handshaking
		tlsConfig.InsecureSkipVerify = true
	}

	tlsConn := utls.UClient(rawConn, tlsConfig, getClientHelloID(selectedTLSProfile))

	if config.ObfuscatedSessionTicketKey != "" {

		// See obfuscated session ticket overview in NewObfuscatedClientSessionCache

		var obfuscatedSessionTicketKey [32]byte
		key, err := hex.DecodeString(config.ObfuscatedSessionTicketKey)
		if err == nil && len(key) != 32 {
			err = errors.New("invalid obfuscated session key length")
		}
		if err != nil {
			return nil, common.ContextError(err)
		}
		copy(obfuscatedSessionTicketKey[:], key)

		sessionState, err := utls.NewObfuscatedClientSessionState(
			obfuscatedSessionTicketKey)
		if err != nil {
			return nil, common.ContextError(err)
		}

		tlsConn.SetSessionState(sessionState)
	}

	resultChannel := make(chan error)

	go func() {
		resultChannel <- tlsConn.Handshake()
	}()

	select {
	case err = <-resultChannel:
	case <-ctx.Done():
		err = ctx.Err()
		// Interrupt the goroutine
		rawConn.Close()
		<-resultChannel
	}

	if err == nil && !config.SkipVerify && tlsConfig.InsecureSkipVerify {

		if config.VerifyLegacyCertificate != nil {
			err = verifyLegacyCertificate(tlsConn, config.VerifyLegacyCertificate)
		} else {
			// Manually verify certificates
			err = verifyServerCerts(tlsConn, hostname, tlsConfig)
		}
	}

	if err != nil {
		rawConn.Close()
		return nil, common.ContextError(err)
	}

	return tlsConn, nil
}

func verifyLegacyCertificate(tlsConn *utls.UConn, expectedCertificate *x509.Certificate) error {
	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) < 1 {
		return common.ContextError(errors.New("no certificate to verify"))
	}
	if !bytes.Equal(certs[0].Raw, expectedCertificate.Raw) {
		return common.ContextError(errors.New("unexpected certificate"))
	}
	return nil
}

func verifyServerCerts(tlsConn *utls.UConn, hostname string, tlsConfig *utls.Config) error {
	certs := tlsConn.ConnectionState().PeerCertificates

	opts := x509.VerifyOptions{
		Roots:         tlsConfig.RootCAs,
		CurrentTime:   time.Now(),
		DNSName:       hostname,
		Intermediates: x509.NewCertPool(),
	}

	for i, cert := range certs {
		if i == 0 {
			continue
		}
		opts.Intermediates.AddCert(cert)
	}

	_, err := certs[0].Verify(opts)
	if err != nil {
		return common.ContextError(err)
	}
	return nil
}
