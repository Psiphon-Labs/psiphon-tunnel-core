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

// Based on https://github.com/getlantern/tlsdialer (http://gopkg.in/getlantern/tlsdialer.v1)
// which itself is a "Fork of crypto/tls.Dial and DialWithDialer"

package psiphon

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io/ioutil"
	"net"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	tris "github.com/Psiphon-Labs/tls-tris"
	utls "github.com/refraction-networking/utls"
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

	// RandomizedTLSProfileSeed specifies the PRNG seed to use when generating
	// a randomized TLS ClientHello, which applies to TLS profiles where
	// protocol.TLSProfileIsRandomized is true. The PRNG seed allows for
	// optional replay of a particular randomized Client Hello.
	RandomizedTLSProfileSeed *prng.Seed

	// TrustedCACertificatesFilename specifies a file containing trusted
	// CA certs. See Config.TrustedCACertificatesFilename.
	TrustedCACertificatesFilename string

	// ObfuscatedSessionTicketKey enables obfuscated session tickets
	// using the specified key.
	ObfuscatedSessionTicketKey string

	clientSessionCache utls.ClientSessionCache
}

// EnableClientSessionCache initializes a cache to use to persist session
// tickets, enabling TLS session resumability across multiple
// CustomTLSDial calls or dialers using the same CustomTLSConfig.
func (config *CustomTLSConfig) EnableClientSessionCache(
	clientParameters *parameters.ClientParameters) {

	if config.clientSessionCache == nil {
		config.clientSessionCache = utls.NewLRUClientSessionCache(0)
	}
}

// SelectTLSProfile picks a random TLS profile from the available candidates.
func SelectTLSProfile(
	p *parameters.ClientParametersSnapshot) string {

	limitTLSProfiles := p.TLSProfiles(parameters.LimitTLSProfiles)

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

	choice := prng.Intn(len(tlsProfiles))

	return tlsProfiles[choice]
}

func getUTLSClientHelloID(tlsProfile string) utls.ClientHelloID {
	switch tlsProfile {
	case protocol.TLS_PROFILE_IOS_111:
		return utls.HelloIOS_11_1
	case protocol.TLS_PROFILE_CHROME_58:
		return utls.HelloChrome_58
	case protocol.TLS_PROFILE_CHROME_62:
		return utls.HelloChrome_62
	case protocol.TLS_PROFILE_CHROME_70:
		return utls.HelloChrome_70
	case protocol.TLS_PROFILE_FIREFOX_55:
		return utls.HelloFirefox_55
	case protocol.TLS_PROFILE_FIREFOX_56:
		return utls.HelloFirefox_56
	case protocol.TLS_PROFILE_FIREFOX_63:
		return utls.HelloFirefox_63
	case protocol.TLS_PROFILE_RANDOMIZED:
		return utls.HelloRandomized
	default:
		return utls.HelloGolang
	}
}

func getClientHelloVersion(utlsClientHelloID utls.ClientHelloID) (string, error) {

	// Assumes utlsClientHelloID.Seed has been set; otherwise the result is
	// ephemeral.

	conn := utls.UClient(
		nil,
		&utls.Config{InsecureSkipVerify: true},
		utlsClientHelloID)

	err := conn.BuildHandshakeState()
	if err != nil {
		return "", common.ContextError(err)
	}

	for _, v := range conn.HandshakeState.Hello.SupportedVersions {
		if v == utls.VersionTLS13 {
			return protocol.TLS_VERSION_13, nil
		}
	}

	return protocol.TLS_VERSION_12, nil
}

func IsTLSConnUsingHTTP2(conn net.Conn) bool {
	if c, ok := conn.(*utls.UConn); ok {
		state := c.ConnectionState()
		return state.NegotiatedProtocolIsMutual &&
			state.NegotiatedProtocol == "h2"
	}
	return false
}

// NewCustomTLSDialer creates a new dialer based on CustomTLSDial.
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
		selectedTLSProfile = SelectTLSProfile(config.ClientParameters.Get())
	}

	tlsConfigInsecureSkipVerify := false
	tlsConfigServerName := ""

	if config.SkipVerify {
		tlsConfigInsecureSkipVerify = true
	}

	if config.UseDialAddrSNI {
		tlsConfigServerName = hostname
	} else if config.SNIServerName != "" && config.VerifyLegacyCertificate == nil {
		// Set the ServerName and rely on the usual logic in
		// tls.Conn.Handshake() to do its verification.
		// Note: Go TLS will automatically omit this ServerName when it's an IP address
		tlsConfigServerName = config.SNIServerName
	} else {
		// No SNI.
		// Disable verification in tls.Conn.Handshake().  We'll verify manually
		// after handshaking
		tlsConfigInsecureSkipVerify = true
	}

	var tlsRootCAs *x509.CertPool

	if !config.SkipVerify &&
		config.VerifyLegacyCertificate == nil &&
		config.TrustedCACertificatesFilename != "" {

		tlsRootCAs = x509.NewCertPool()
		certData, err := ioutil.ReadFile(config.TrustedCACertificatesFilename)
		if err != nil {
			return nil, common.ContextError(err)
		}
		tlsRootCAs.AppendCertsFromPEM(certData)
	}

	tlsConfig := &utls.Config{
		RootCAs:            tlsRootCAs,
		InsecureSkipVerify: tlsConfigInsecureSkipVerify,
		ServerName:         tlsConfigServerName,
	}

	utlsClientHelloID := getUTLSClientHelloID(selectedTLSProfile)

	if protocol.TLSProfileIsRandomized(selectedTLSProfile) {

		randomizedTLSProfileSeed := config.RandomizedTLSProfileSeed

		if randomizedTLSProfileSeed == nil {

			randomizedTLSProfileSeed, err = prng.NewSeed()
			if err != nil {
				return nil, common.ContextError(err)
			}
		}

		utlsClientHelloID.Seed = new(utls.PRNGSeed)
		*utlsClientHelloID.Seed = [32]byte(*randomizedTLSProfileSeed)
	}

	conn := utls.UClient(rawConn, tlsConfig, utlsClientHelloID)

	clientSessionCache := config.clientSessionCache
	if clientSessionCache == nil {
		clientSessionCache = utls.NewLRUClientSessionCache(0)
	}

	conn.SetSessionCache(clientSessionCache)

	// Obfuscated session tickets are not currently supported in TLS 1.3, but we
	// allow UNFRONTED-MEEK-SESSION-TICKET-OSSH to use TLS 1.3 profiles for
	// additional diversity/capacity; TLS 1.3 encrypts the server certificate,
	// so the desired obfuscated session tickets property of obfuscating server
	// certificates is satisfied. We know that when the ClientHello offers TLS
	// 1.3, the Psiphon server, in these direct protocol cases, will negoritate
	// it.
	if config.ObfuscatedSessionTicketKey != "" {

		tlsVersion, err := getClientHelloVersion(utlsClientHelloID)
		if err != nil {
			return nil, common.ContextError(err)
		}

		if tlsVersion == protocol.TLS_VERSION_12 {

			var obfuscatedSessionTicketKey [32]byte

			key, err := hex.DecodeString(config.ObfuscatedSessionTicketKey)
			if err == nil && len(key) != 32 {
				err = errors.New("invalid obfuscated session key length")
			}
			if err != nil {
				return nil, common.ContextError(err)
			}
			copy(obfuscatedSessionTicketKey[:], key)

			obfuscatedSessionState, err := tris.NewObfuscatedClientSessionState(
				obfuscatedSessionTicketKey)
			if err != nil {
				return nil, common.ContextError(err)
			}

			conn.SetSessionState(
				utls.MakeClientSessionState(
					obfuscatedSessionState.SessionTicket,
					obfuscatedSessionState.Vers,
					obfuscatedSessionState.CipherSuite,
					obfuscatedSessionState.MasterSecret,
					nil,
					nil))

			// Ensure that TLS ClientHello has required session ticket extension and
			// obfuscated session ticket cipher suite; the latter is required by
			// utls/tls.Conn.loadSession. If these requirements are not met the
			// obfuscation session ticket would be ignored, so fail.

			err = conn.BuildHandshakeState()
			if err != nil {
				return nil, common.ContextError(err)
			}

			if !tris.ContainsObfuscatedSessionTicketCipherSuite(
				conn.HandshakeState.Hello.CipherSuites) {
				return nil, common.ContextError(
					errors.New("missing obfuscated session ticket cipher suite"))
			}

			if len(conn.HandshakeState.Hello.SessionTicket) == 0 {
				return nil, common.ContextError(
					errors.New("missing session ticket extension"))
			}
		}
	}

	resultChannel := make(chan error)

	go func() {
		resultChannel <- conn.Handshake()
	}()

	select {
	case err = <-resultChannel:
	case <-ctx.Done():
		err = ctx.Err()
		// Interrupt the goroutine
		rawConn.Close()
		<-resultChannel
	}

	if err == nil && !config.SkipVerify && tlsConfigInsecureSkipVerify {

		if config.VerifyLegacyCertificate != nil {
			err = verifyLegacyCertificate(conn, config.VerifyLegacyCertificate)
		} else {
			// Manually verify certificates
			err = verifyServerCerts(conn, hostname)
		}
	}

	if err != nil {
		rawConn.Close()
		return nil, common.ContextError(err)
	}

	return conn, nil
}

func verifyLegacyCertificate(conn *utls.UConn, expectedCertificate *x509.Certificate) error {
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) < 1 {
		return common.ContextError(errors.New("no certificate to verify"))
	}
	if !bytes.Equal(certs[0].Raw, expectedCertificate.Raw) {
		return common.ContextError(errors.New("unexpected certificate"))
	}
	return nil
}

func verifyServerCerts(conn *utls.UConn, hostname string) error {
	certs := conn.ConnectionState().PeerCertificates

	opts := x509.VerifyOptions{
		Roots:         nil, // Use host's root CAs
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
