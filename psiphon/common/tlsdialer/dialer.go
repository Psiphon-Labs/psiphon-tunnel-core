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

// Originally based on https://gopkg.in/getlantern/tlsdialer.v1.

package tlsdialer

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	std_errors "errors"
	"io/ioutil"
	"net"

	tls "github.com/Psiphon-Labs/psiphon-tls"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	utls "github.com/Psiphon-Labs/utls"
)

// Config specifies the parameters for a Dial, supporting
// many TLS-related network obfuscation mechanisms.
type Config struct {

	// Parameters is the active set of parameters.Parameters to use for the TLS
	// dial. Must not be nil.
	Parameters *parameters.Parameters

	// Dial is the network connection dialer. TLS is layered on top of a new
	// network connection created with dialer. Must not be nil.
	Dial common.Dialer

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

	// DisableSystemRootCAs, when true, disables loading system root CAs when
	// verifying the server certificate chain. Set DisableSystemRootCAs only in
	// cases where system root CAs cannot be loaded and there is additional
	// security at the payload level; for example, if unsupported (iOS < 12) or
	// insufficient memory (VPN extension on iOS < 15).
	//
	// When DisableSystemRootCAs is set, VerifyServerName, VerifyPins, and
	// VerifyLegacyCertificate must not be set.
	DisableSystemRootCAs bool

	// VerifyServerName specifies a domain name that must appear in the server
	// certificate. When specified, certificate verification checks for
	// VerifyServerName in the server certificate, in place of the dial or SNI
	// hostname.
	VerifyServerName string

	// VerifyPins specifies one or more certificate pin values, one of which must
	// appear in the verified server certificate chain. A pin value is the
	// base64-encoded SHA2 digest of a certificate's public key. When specified,
	// at least one pin must match at least one certificate in the chain, at any
	// position; e.g., the root CA may be pinned, or the server certificate,
	// etc.
	VerifyPins []string

	// VerifyPinsOnly verifies VerifyPins against the raw peer certificates
	// without trusted roots. When VerifyServerName is set, the leaf certificate
	// must also match VerifyServerName. This mode is intended for pinned,
	// self-signed certificates.
	//
	// When VerifyPinsOnly is set, VerifyPins must be set, and SkipVerify,
	// DisableSystemRootCAs, and VerifyLegacyCertificate must not be set.
	VerifyPinsOnly bool

	// VerifyLegacyCertificate is a special case self-signed server
	// certificate case. Ignores IP SANs and basic constraints. No
	// certificate chain. Just checks that the server presented the
	// specified certificate.
	//
	// When VerifyLegacyCertificate is set, none of VerifyServerName, VerifyPins,
	// SkipVerify may be set.
	VerifyLegacyCertificate *x509.Certificate

	// SkipVerify completely disables server certificate verification.
	//
	// When SkipVerify is set, none of VerifyServerName, VerifyPins,
	// VerifyLegacyCertificate may be set.
	SkipVerify bool

	// TLSProfile specifies a particular indistinguishable TLS profile to use for
	// the TLS dial. Setting TLSProfile allows the caller to pin the selection so
	// all TLS connections in a certain context (e.g. a single meek connection)
	// use a consistent value. The value should be selected by calling
	// SelectTLSProfile, which will pick a value at random, subject to
	// compatibility constraints.
	//
	// When TLSProfile is "", a profile is selected at random and
	// DisableFrontingProviderTLSProfiles is ignored.
	TLSProfile string

	// NoDefaultTLSSessionID specifies whether to set a TLS session ID by
	// default, for a new TLS connection that is not resuming a session.
	// When nil, the parameter is set randomly.
	NoDefaultTLSSessionID *bool

	// RandomizedTLSProfileSeed specifies the PRNG seed to use when generating
	// a randomized TLS ClientHello, which applies to TLS profiles where
	// protocol.TLSProfileIsRandomized is true. The PRNG seed allows for
	// optional replay of a particular randomized Client Hello.
	RandomizedTLSProfileSeed *prng.Seed

	// TLSPadding indicates whether to move or add a TLS padding extension to the
	// front of the exension list and apply the specified padding length. Ignored
	// when 0.
	TLSPadding int

	// TrustedCACertificatesFilename specifies a file containing trusted
	// CA certs. See Config.TrustedCACertificatesFilename.
	TrustedCACertificatesFilename string

	// ObfuscatedSessionTicketKey enables obfuscated session tickets
	// using the specified key.
	ObfuscatedSessionTicketKey string

	// PassthroughMessage, when specified, is a 32 byte value that is sent in the
	// ClientHello random value field. The value should be generated using
	// obfuscator.MakeTLSPassthroughMessage.
	PassthroughMessage []byte

	// FragmentClientHello specifies whether to fragment each initial-handshake
	// ClientHello so the second TLS record starts at the SNI hostname. A
	// ClientHello without a valid SNI hostname is sent normally.
	FragmentClientHello bool

	// ClientSessionCache specifies the cache to use to persist session tickets.
	ClientSessionCache utls.ClientSessionCache
}

// NewDialer creates a new dialer based on Dial.
func NewDialer(config *Config) common.Dialer {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return Dial(ctx, network, addr, config)
	}
}

// Dial dials a new TLS connection using the parameters set in Config.
//
// The dial aborts if ctx becomes Done before the dial completes.
func Dial(
	ctx context.Context,
	network, addr string,
	config *Config) (net.Conn, error) {

	// Note that servers may return a chain which excludes the root CA
	// cert https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.2.
	// It will not be possible to verify the certificate chain when
	// system root CAs cannot be loaded and the server omits the root CA
	// certificate from the chain.
	//
	// TODO: attempt to do some amount of certificate verification when
	// config.DisableSystemRootCAs is set. It would be possible to
	// verify the certificate chain, server name, and pins, when
	// config.TrustedCACertificatesFilename is set and contains the root
	// CA certificate of the certificate chain returned by the server. Also,
	// verifying legacy certificates does not require system root CAs, but
	// there is no code path which uses config.DisableSystemRootCAs in
	// conjuction with config.VerifyLegacyCertificate. As it stands
	// config.DisableSystemRootCAs is only used on iOS < 15 and
	// config.VerifyLegacyCertificate is only used for Windows VPN mode.
	skipVerify := config.SkipVerify || config.DisableSystemRootCAs

	if (skipVerify &&
		(config.VerifyLegacyCertificate != nil ||
			len(config.VerifyServerName) > 0 ||
			len(config.VerifyPins) > 0)) ||

		(config.VerifyLegacyCertificate != nil &&
			(skipVerify ||
				len(config.VerifyServerName) > 0 ||
				len(config.VerifyPins) > 0)) ||

		(config.VerifyPinsOnly &&
			(config.VerifyLegacyCertificate != nil ||
				config.SkipVerify ||
				config.DisableSystemRootCAs ||
				len(config.VerifyPins) == 0)) {

		return nil, errors.TraceNew("incompatible certification verification parameters")
	}

	p := config.Parameters.Get()

	dialAddr := addr
	if config.DialAddr != "" {
		dialAddr = config.DialAddr
	}

	underlyingConn, err := config.Dial(ctx, network, dialAddr)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// If the hard-coded session key is not set (e.g. FRONTED-MEEK-OSSH), SetSessionKey must be called.
	// The session key is set to the resolved IP address.
	if wrappedCache, ok := config.ClientSessionCache.(*common.UtlsClientSessionCacheWrapper); ok {
		wrappedCache.SetSessionKey(underlyingConn.RemoteAddr().String())
	}

	hostname, _, err := net.SplitHostPort(dialAddr)
	if err != nil {
		underlyingConn.Close()
		return nil, errors.Trace(err)
	}

	var tlsConfigRootCAs *x509.CertPool
	if !skipVerify &&
		!config.VerifyPinsOnly &&
		config.VerifyLegacyCertificate == nil &&
		config.TrustedCACertificatesFilename != "" {

		tlsConfigRootCAs = x509.NewCertPool()
		certData, err := ioutil.ReadFile(config.TrustedCACertificatesFilename)
		if err != nil {
			return nil, errors.Trace(err)
		}
		tlsConfigRootCAs.AppendCertsFromPEM(certData)
	}

	// In some cases, skipVerify is false, but
	// utls.Config.InsecureSkipVerify will be set to true to disable verification
	// in utls that will otherwise fail: when SNI is omitted, and when
	// VerifyServerName differs from SNI. In these cases, the certificate chain
	// is verified in VerifyPeerCertificate.

	tlsConfigInsecureSkipVerify := false
	tlsConfigServerName := ""
	verifyServerName := hostname

	if skipVerify {
		tlsConfigInsecureSkipVerify = true
	}
	if config.VerifyPinsOnly {
		tlsConfigInsecureSkipVerify = true
	}

	if config.UseDialAddrSNI {

		// Set SNI to match the dial hostname. This is the standard case.
		tlsConfigServerName = hostname

	} else if config.SNIServerName != "" {

		// Set a custom SNI value. If this value doesn't match the server
		// certificate, SkipVerify and/or VerifyServerName may need to be
		// configured; but by itself this case doesn't necessarily require
		// custom certificate verification.
		tlsConfigServerName = config.SNIServerName

	} else {

		// Omit SNI. If SkipVerify is not set, this case requires custom certificate
		// verification, which will check that the server certificate matches either
		// the dial hostname or VerifyServerName, as if the SNI were set to one of
		// those values.
		tlsConfigInsecureSkipVerify = true
	}

	// When VerifyServerName does not match the SNI, custom certificate
	// verification is necessary.
	if config.VerifyServerName != "" &&
		(config.VerifyPinsOnly || config.VerifyServerName != tlsConfigServerName) {
		verifyServerName = config.VerifyServerName
		if config.VerifyServerName != tlsConfigServerName {
			tlsConfigInsecureSkipVerify = true
		}
	}

	// With the VerifyPeerCertificate callback, we perform any custom certificate
	// verification at the same point in the TLS handshake as standard utls
	// verification; and abort the handshake at the same point, if custom
	// verification fails.
	var tlsConfigVerifyPeerCertificate func([][]byte, [][]*x509.Certificate) error
	if !skipVerify {
		tlsConfigVerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {

			if config.VerifyLegacyCertificate != nil {
				return verifyLegacyCertificate(
					rawCerts, config.VerifyLegacyCertificate)
			}

			if config.VerifyPinsOnly {
				if len(verifiedChains) > 0 {
					return errors.TraceNew("unexpected verified chains")
				}

				err := common.VerifyServerCertificatePinsOnly(
					rawCerts, verifyServerName, config.VerifyPins)
				if err != nil {
					return errors.Trace(err)
				}

				return nil
			}

			if tlsConfigInsecureSkipVerify {

				// Limitation: this verification path does not set the utls.Conn's
				// ConnectionState certificate information.

				if len(verifiedChains) > 0 {
					return errors.TraceNew("unexpected verified chains")
				}
				var err error
				verifiedChains, err = common.VerifyServerCertificate(
					tlsConfigRootCAs, rawCerts, verifyServerName)
				if err != nil {
					return errors.Trace(err)
				}
			}

			if len(config.VerifyPins) > 0 {
				err := common.VerifyCertificatePins(
					config.VerifyPins, verifiedChains)
				if err != nil {
					return errors.Trace(err)
				}
			}

			return nil
		}
	}

	tlsConfig := &utls.Config{
		RootCAs:                tlsConfigRootCAs,
		InsecureSkipVerify:     tlsConfigInsecureSkipVerify,
		InsecureSkipTimeVerify: tlsConfigInsecureSkipVerify,
		ServerName:             tlsConfigServerName,
		VerifyPeerCertificate:  tlsConfigVerifyPeerCertificate,
		OmitEmptyPsk:           true,
		AlwaysIncludePSK:       true,
	}
	if config.FragmentClientHello {
		tlsConfig.FragmentClientHello = sniFragmentOffset
	}

	var randomizedTLSProfileSeed *prng.Seed
	selectedTLSProfile := config.TLSProfile

	if selectedTLSProfile == "" {
		selectedTLSProfile, _, randomizedTLSProfileSeed, err = SelectTLSProfile(false, false, false, "", "", p)
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	utlsClientHelloID, utlsClientHelloSpec, err := getUTLSClientHelloID(
		p, selectedTLSProfile)
	if err != nil {
		return nil, errors.Trace(err)
	}

	isRandomized := protocol.TLSProfileIsRandomized(selectedTLSProfile)
	if isRandomized {

		// Give config.RandomizedTLSProfileSeed precedence over the seed
		// generated by SelectTLSProfile if selectedTLSProfile == "".
		if config.RandomizedTLSProfileSeed != nil {
			randomizedTLSProfileSeed = config.RandomizedTLSProfileSeed
		}

		if randomizedTLSProfileSeed == nil {

			randomizedTLSProfileSeed, err = prng.NewSeed()
			if err != nil {
				return nil, errors.Trace(err)
			}
		}

		utlsClientHelloID.Seed = new(utls.PRNGSeed)
		*utlsClientHelloID.Seed = [32]byte(*randomizedTLSProfileSeed)

		weights := utls.DefaultWeights
		weights.TLSVersMax_Set_VersionTLS13 = 0.5
		utlsClientHelloID.Weights = &weights
	}

	// As noted here,
	// https://gitlab.com/yawning/obfs4/commit/ca6765e3e3995144df2b1ca9f0e9d823a7f8a47c,
	// the dynamic record sizing optimization in crypto/tls is not commonly
	// implemented in browsers. Disable it for all utls parrots and select it
	// randomly when using the randomized client hello.
	if isRandomized {
		PRNG, err := prng.NewPRNGWithSaltedSeed(randomizedTLSProfileSeed, "tls-dynamic-record-sizing")
		if err != nil {
			return nil, errors.Trace(err)
		}
		tlsConfig.DynamicRecordSizingDisabled = PRNG.FlipCoin()
	} else {
		tlsConfig.DynamicRecordSizingDisabled = true
	}

	conn := utls.UClient(underlyingConn, tlsConfig, utlsClientHelloID)

	if utlsClientHelloSpec != nil {
		err := conn.ApplyPreset(utlsClientHelloSpec)
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	clientSessionCache := config.ClientSessionCache
	if clientSessionCache == nil {
		clientSessionCache = utls.NewLRUClientSessionCache(0)
	}

	conn.SetSessionCache(clientSessionCache)

	// TODO: can conn.SetClientRandom be made to take effect if called here? In
	// testing, the random value appears to be overwritten. As is, the overhead
	// of needRemarshal is now always required to handle
	// config.PassthroughMessage.

	// Build handshake state in advance to obtain the TLS version, which is used
	// to determine whether the following customizations may be applied. Don't use
	// getClientHelloVersion, since that may incur additional overhead.

	err = conn.BuildHandshakeStateWithoutSession()
	if err != nil {
		return nil, errors.Trace(err)
	}

	isTLS13 := false
	for _, vers := range conn.HandshakeState.Hello.SupportedVersions {
		if vers == utls.VersionTLS13 {
			isTLS13 = true
			break
		}
	}

	useEms := conn.HandshakeState.Hello.Ems

	if config.ObfuscatedSessionTicketKey == "" {
		err = conn.BuildHandshakeState()
		if err != nil {
			return nil, errors.Trace(err)
		}

	} else {

		// Add the obfuscated session ticket or obfuscated PSK.

		var obfuscatedSessionTicketKey [32]byte

		key, err := hex.DecodeString(config.ObfuscatedSessionTicketKey)
		if err == nil && len(key) != 32 {
			err = std_errors.New("invalid obfuscated session key length")
		}
		if err != nil {
			return nil, errors.Trace(err)
		}
		copy(obfuscatedSessionTicketKey[:], key) // shared secret

		obfuscatedSessionState, err := tls.NewObfuscatedClientSessionState(
			obfuscatedSessionTicketKey, isTLS13, useEms)
		if err != nil {
			return nil, errors.Trace(err)
		}

		sessionState := utls.MakeClientSessionState(
			obfuscatedSessionState.SessionTicket,
			obfuscatedSessionState.Vers,
			obfuscatedSessionState.CipherSuite,
			obfuscatedSessionState.MasterSecret,
			nil, nil)
		sessionState.SetCreatedAt(obfuscatedSessionState.CreatedAt)
		sessionState.SetEMS(obfuscatedSessionState.ExtMasterSecret)
		// TLS 1.3-only fields
		sessionState.SetAgeAdd(obfuscatedSessionState.AgeAdd)
		sessionState.SetUseBy(obfuscatedSessionState.UseBy)

		if isTLS13 {
			// Sets OOB PSK if required.
			if containsPSKExt(utlsClientHelloID, utlsClientHelloSpec) {
				if wrappedCache, ok := clientSessionCache.(*common.UtlsClientSessionCacheWrapper); ok {
					wrappedCache.Put("", sessionState)
				} else {
					return nil, errors.TraceNew("unexpected clientSessionCache type")
				}
			}
		} else {
			err := conn.SetSessionState(sessionState)
			if err != nil {
				return nil, errors.Trace(err)
			}
		}

		// Apply changes to utls
		err = conn.BuildHandshakeState()
		if err != nil {
			return nil, errors.Trace(err)
		}

		// Ensure that TLS ClientHello has required session ticket or PSK extension and
		// obfuscated session ticket or PSK cipher suite; the latter is required by
		// utls/tls.Conn.loadSession. If these requirements are not met the
		// obfuscation session ticket would be ignored, so fail.
		if isTLS13 {
			if containsPSKExt(utlsClientHelloID, utlsClientHelloSpec) {
				if !tls.ContainsObfuscatedPSKCipherSuite(
					conn.HandshakeState.Hello.CipherSuites) {
					return nil, errors.TraceNew("missing obfuscated PSK cipher suite")
				}

				if len(conn.HandshakeState.Hello.PskIdentities) == 0 {
					return nil, errors.TraceNew("missing PSK extension")
				}
			}

		} else {
			if !tls.ContainsObfuscatedSessionTicketCipherSuite(
				conn.HandshakeState.Hello.CipherSuites) {
				return nil, errors.TraceNew(
					"missing obfuscated session ticket cipher suite")
			}

			if len(conn.HandshakeState.Hello.SessionTicket) == 0 {
				return nil, errors.TraceNew("missing session ticket extension")
			}
		}
	}

	// Perform at most one remarshal for the following ClientHello
	// modifications.
	needRemarshal := false

	// Either pre-TLS 1.3 ClientHellos or any randomized ClientHello is a
	// candidate for NoDefaultSessionID logic.
	if len(conn.HandshakeState.Hello.SessionTicket) == 0 &&
		(!isTLS13 || utlsClientHelloID.Client == "Randomized") {

		var noDefaultSessionID bool
		if config.NoDefaultTLSSessionID != nil {
			noDefaultSessionID = *config.NoDefaultTLSSessionID
		} else {
			noDefaultSessionID = config.Parameters.Get().WeightedCoinFlip(
				parameters.NoDefaultTLSSessionIDProbability)
		}

		if noDefaultSessionID {
			conn.HandshakeState.Hello.SessionId = nil
			needRemarshal = true
		}
	}

	// utls doesn't omit the server_name extension when the ServerName value is
	// empty or an IP address. To avoid a fingerprintable invalid/unusual
	// server_name extension, remove it in these cases.
	if tlsConfigServerName == "" || net.ParseIP(tlsConfigServerName) != nil {

		// Assumes only one SNIExtension.
		// TODO: use new UConn.RemoveSNIExtension function?
		deleteIndex := -1
		for index, extension := range conn.Extensions {
			if _, ok := extension.(*utls.SNIExtension); ok {
				deleteIndex = index
				break
			}
		}
		if deleteIndex != -1 {
			conn.Extensions = append(
				conn.Extensions[:deleteIndex], conn.Extensions[deleteIndex+1:]...)
		}
		needRemarshal = true
	}

	if config.TLSPadding > 0 {

		tlsPadding := config.TLSPadding

		// Maximum padding size per RFC 7685
		if tlsPadding > 65535 {
			tlsPadding = 65535
		}

		// Assumes only one PaddingExtension.
		deleteIndex := -1
		for index, extension := range conn.Extensions {
			if _, ok := extension.(*utls.UtlsPaddingExtension); ok {
				deleteIndex = index
				break
			}
		}
		if deleteIndex != -1 {
			conn.Extensions = append(
				conn.Extensions[:deleteIndex], conn.Extensions[deleteIndex+1:]...)
		}

		paddingExtension := &utls.UtlsPaddingExtension{
			PaddingLen: tlsPadding,
			WillPad:    true,
		}
		conn.Extensions = append([]utls.TLSExtension{paddingExtension}, conn.Extensions...)

		needRemarshal = true

	}

	if config.PassthroughMessage != nil {
		err := conn.SetClientRandom(config.PassthroughMessage)
		if err != nil {
			return nil, errors.Trace(err)
		}

		needRemarshal = true
	}

	if needRemarshal {
		// Apply changes to utls
		err = conn.MarshalClientHello()
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	// Perform the TLS Handshake.

	resultChannel := make(chan error)

	go func() {
		resultChannel <- conn.Handshake()
	}()

	select {
	case err = <-resultChannel:
	case <-ctx.Done():
		err = ctx.Err()
		// Interrupt the goroutine
		underlyingConn.Close()
		<-resultChannel
	}

	if err != nil {
		underlyingConn.Close()
		return nil, errors.Trace(err)
	}

	connectionMetrics := conn.ConnectionMetrics()
	clientSentTicket := connectionMetrics.ClientSentTicket
	clientHelloFragmented := connectionMetrics.ClientHelloFragmented
	didResume := conn.ConnectionState().DidResume

	return &tlsConn{
		Conn:           conn,
		underlyingConn: underlyingConn,
		sentTicket:     clientSentTicket,
		fragmented:     clientHelloFragmented,
		didResume:      didResume,
	}, nil
}

type tlsConn struct {
	net.Conn
	underlyingConn net.Conn

	// TLS handshake states

	sentTicket bool
	fragmented bool
	didResume  bool
}

func (conn *tlsConn) GetMetrics() common.LogFields {
	logFields := make(common.LogFields)

	// Include metrics, such as inproxy and fragmentor metrics, from the
	// underlying dial conn.
	underlyingMetrics, ok := conn.underlyingConn.(common.MetricsSource)
	if ok {
		logFields.Add(underlyingMetrics.GetMetrics())
	}

	sentTicket := "0"
	if conn.sentTicket {
		sentTicket = "1"
	}
	logFields["tls_sent_ticket"] = sentTicket

	fragmented := "0"
	if conn.fragmented {
		fragmented = "1"
	}
	logFields["tls_fragmented"] = fragmented

	didResume := "0"
	if conn.didResume {
		didResume = "1"
	}
	logFields["tls_did_resume"] = didResume

	return logFields
}

func verifyLegacyCertificate(rawCerts [][]byte, expectedCertificate *x509.Certificate) error {
	if len(rawCerts) < 1 {
		return errors.TraceNew("missing certificate")
	}
	if !bytes.Equal(rawCerts[0], expectedCertificate.Raw) {
		return errors.TraceNew("unexpected certificate")
	}
	return nil
}

func IsConnUsingHTTP2(conn net.Conn) bool {
	if t, ok := conn.(*tlsConn); ok {
		if u, ok := t.Conn.(*utls.UConn); ok {
			state := u.ConnectionState()
			return state.NegotiatedProtocolIsMutual &&
				state.NegotiatedProtocol == "h2"
		}
	}
	return false
}

// TLSProfileSupportsTLS13 indicates whether the specified TLS profile is
// supported and capable of negotiating TLS 1.3.
//
// TLS_PROFILE_RANDOMIZED, which generates a ClientHello that may negotiate
// either TLS 1.2 or TLS 1.3, is reported as capable.
func TLSProfileSupportsTLS13(tlsProfile string) (bool, error) {

	if !common.Contains(protocol.SupportedTLSProfiles, tlsProfile) {
		return false, errors.TraceNew("unsupported TLS profile")
	}

	if protocol.TLSProfileIsRandomized(tlsProfile) {
		return true, nil
	}

	utlsClientHelloID, utlsClientHelloSpec, err := getUTLSClientHelloID(
		parameters.MakeNilParametersAccessor(), tlsProfile)
	if err != nil {
		return false, errors.Trace(err)
	}

	tlsVersion, err := getClientHelloVersion(
		utlsClientHelloID, utlsClientHelloSpec)
	if err != nil {
		return false, errors.Trace(err)
	}

	return tlsVersion == protocol.TLS_VERSION_13, nil
}

// SelectTLSProfile picks and returns a TLS profile at random from the
// available candidates along with its version and a newly generated PRNG seed
// if the profile is randomized, i.e. protocol.TLSProfileIsRandomized is true,
// which should be used when generating a randomized TLS ClientHello.
//
// When preferredTLSProfile is set, it is attempted first. If the preferred
// profile is unknown, disabled, incompatible with the requested constraints,
// or fails the TLS version requirement, random selection is used as fallback.
//
// If SelectTLSProfile can't find a TLS profile that matches the input
// constraints, including tactics parameters such as LimitTLSProfiles and
// DisableFrontingProviderTLSProfiles, it returns an error.
func SelectTLSProfile(
	requireTLS12SessionTickets bool,
	requireTLS13Support bool,
	isFronted bool,
	frontingProviderID string,
	preferredTLSProfile string,
	p parameters.ParametersAccessor) (string, string, *prng.Seed, error) {

	preferred := preferredTLSProfile

	for i := 0; i < 1000; i++ {

		tlsProfile, tlsVersion, randomizedTLSProfileSeed, err :=
			selectTLSProfile(
				requireTLS12SessionTickets,
				isFronted,
				frontingProviderID,
				preferred,
				p)
		if err != nil {
			return "", "", nil, errors.Trace(err)
		}
		if tlsProfile == "" {
			if preferred != "" {
				// The preferred profile is unknown, disabled, or incompatible
				// with the constraints; fall back to random selection.
				preferred = ""
				continue
			}

			// If no profile can be selected and that's not due to a preferred
			// choice, looping won't produce a different result.
			break
		}

		if requireTLS13Support && tlsVersion != protocol.TLS_VERSION_13 {

			// Continue picking profiles at random until an eligible one is
			// chosen. It is okay to loop in this way because the probability of
			// selecting a TLS 1.3 profile is high enough that it should not
			// take too many iterations until one is chosen.
			//
			// A preferred non-random profile always produces the same TLS
			// version, so fall back to random selection.

			if preferred != "" && !protocol.TLSProfileIsRandomized(preferred) {
				preferred = ""
			}
			continue
		}

		return tlsProfile, tlsVersion, randomizedTLSProfileSeed, nil
	}

	return "", "", nil, errors.TraceNew("Failed to select a TLS profile")
}

// selectTLSProfile is a helper that picks and returns a TLS profile at random
// from the available candidates along with its version and a newly generated
// PRNG seed if the profile is randomized, i.e. protocol.TLSProfileIsRandomized
// is true.
func selectTLSProfile(
	requireTLS12SessionTickets bool,
	isFronted bool,
	frontingProviderID string,
	preferredTLSProfile string,
	p parameters.ParametersAccessor) (string, string, *prng.Seed, error) {

	// Two TLS profile lists are constructed, subject to limit constraints:
	// stock, fixed parrots (non-randomized SupportedTLSProfiles) and custom
	// parrots (CustomTLSProfileNames); and randomized. If one list is empty, the
	// non-empty list is used. Otherwise SelectRandomizedTLSProfileProbability
	// determines which list is used.
	//
	// Note that LimitTLSProfiles is not applied to CustomTLSProfiles; the
	// presence of a candidate in CustomTLSProfiles is treated as explicit
	// enabling.
	//
	// UseOnlyCustomTLSProfiles may be used to disable all stock TLS profiles and
	// use only CustomTLSProfiles; UseOnlyCustomTLSProfiles is ignored if
	// CustomTLSProfiles is empty.
	//
	// For fronted servers, DisableFrontingProviderTLSProfiles may be used
	// to disable TLS profiles which are incompatible with the TLS stack used
	// by the front. For example, if a utls parrot doesn't fully support all
	// of the capabilities in the ClientHello. Unlike the LimitTLSProfiles case,
	// DisableFrontingProviderTLSProfiles may disable CustomTLSProfiles.

	limitTLSProfiles := p.TLSProfiles(parameters.LimitTLSProfiles)
	var disableTLSProfiles protocol.TLSProfiles

	if isFronted && frontingProviderID != "" {
		disableTLSProfiles = p.LabeledTLSProfiles(
			parameters.DisableFrontingProviderTLSProfiles, frontingProviderID)
	}

	randomizedTLSProfiles := make([]string, 0)
	parrotTLSProfiles := make([]string, 0)

	for _, tlsProfile := range p.CustomTLSProfileNames() {
		if !common.Contains(disableTLSProfiles, tlsProfile) {
			parrotTLSProfiles = append(parrotTLSProfiles, tlsProfile)
		}
	}

	useOnlyCustomTLSProfiles := p.Bool(parameters.UseOnlyCustomTLSProfiles)
	if useOnlyCustomTLSProfiles && len(parrotTLSProfiles) == 0 {
		useOnlyCustomTLSProfiles = false
	}

	if !useOnlyCustomTLSProfiles {
		for _, tlsProfile := range protocol.SupportedTLSProfiles {

			if len(limitTLSProfiles) > 0 &&
				!common.Contains(limitTLSProfiles, tlsProfile) {
				continue
			}

			if common.Contains(disableTLSProfiles, tlsProfile) {
				continue
			}

			// requireTLS12SessionTickets is specified for
			// UNFRONTED-MEEK-SESSION-TICKET-OSSH, a protocol which depends on using
			// obfuscated session tickets to ensure that the server doesn't send its
			// certificate in the TLS handshake. TLS 1.2 profiles which omit session
			// tickets should not be selected. As TLS 1.3 encrypts the server
			// certificate message, there's no exclusion for TLS 1.3.

			if requireTLS12SessionTickets &&
				protocol.TLS12ProfileOmitsSessionTickets(tlsProfile) {
				continue
			}

			if protocol.TLSProfileIsRandomized(tlsProfile) {
				randomizedTLSProfiles = append(randomizedTLSProfiles, tlsProfile)
			} else {
				parrotTLSProfiles = append(parrotTLSProfiles, tlsProfile)
			}
		}
	}

	var tlsProfile, tlsVersion string
	var randomizedTLSProfileSeed *prng.Seed

	if preferredTLSProfile != "" {
		if common.Contains(randomizedTLSProfiles, preferredTLSProfile) ||
			common.Contains(parrotTLSProfiles, preferredTLSProfile) {
			tlsProfile = preferredTLSProfile
		} else {
			return "", "", nil, nil
		}
	} else if len(randomizedTLSProfiles) > 0 &&
		(len(parrotTLSProfiles) == 0 ||
			p.WeightedCoinFlip(parameters.SelectRandomizedTLSProfileProbability)) {

		tlsProfile = randomizedTLSProfiles[prng.Intn(len(randomizedTLSProfiles))]
	}

	if tlsProfile == "" {
		if len(parrotTLSProfiles) == 0 {
			return "", "", nil, nil
		} else {
			tlsProfile = parrotTLSProfiles[prng.Intn(len(parrotTLSProfiles))]
		}
	}

	utlsClientHelloID, utlsClientHelloSpec, err := getUTLSClientHelloID(
		p, tlsProfile)
	if err != nil {
		return "", "", nil, errors.Trace(err)
	}

	if protocol.TLSProfileIsRandomized(tlsProfile) {
		randomizedTLSProfileSeed, err = prng.NewSeed()
		if err != nil {
			return "", "", nil, errors.Trace(err)
		}
		utlsClientHelloID.Seed = new(utls.PRNGSeed)
		*utlsClientHelloID.Seed = [32]byte(*randomizedTLSProfileSeed)
	}

	tlsVersion, err = getClientHelloVersion(
		utlsClientHelloID, utlsClientHelloSpec)
	if err != nil {
		return "", "", nil, errors.Trace(err)
	}

	return tlsProfile, tlsVersion, randomizedTLSProfileSeed, nil
}

func getUTLSClientHelloID(
	p parameters.ParametersAccessor,
	tlsProfile string) (utls.ClientHelloID, *utls.ClientHelloSpec, error) {

	switch tlsProfile {

	// IMPORTANT: when adding new cases here, also add to
	// getClientHelloVersion below.

	case protocol.TLS_PROFILE_IOS_111:
		return utls.HelloIOS_11_1, nil, nil
	case protocol.TLS_PROFILE_IOS_121:
		return utls.HelloIOS_12_1, nil, nil
	case protocol.TLS_PROFILE_IOS_13:
		return utls.HelloIOS_13, nil, nil
	case protocol.TLS_PROFILE_IOS_14:
		return utls.HelloIOS_14, nil, nil
	case protocol.TLS_PROFILE_SAFARI_16:
		return utls.HelloSafari_16_0, nil, nil
	case protocol.TLS_PROFILE_CHROME_58:
		return utls.HelloChrome_58, nil, nil
	case protocol.TLS_PROFILE_CHROME_62:
		return utls.HelloChrome_62, nil, nil
	case protocol.TLS_PROFILE_CHROME_70:
		return utls.HelloChrome_70, nil, nil
	case protocol.TLS_PROFILE_CHROME_72:
		return utls.HelloChrome_72, nil, nil
	case protocol.TLS_PROFILE_CHROME_83:
		return utls.HelloChrome_83, nil, nil
	case protocol.TLS_PROFILE_CHROME_96:
		return utls.HelloChrome_96, nil, nil
	case protocol.TLS_PROFILE_CHROME_102:
		return utls.HelloChrome_102, nil, nil
	case protocol.TLS_PROFILE_CHROME_106:
		return utls.HelloChrome_106_Shuffle, nil, nil
	case protocol.TLS_PROFILE_CHROME_112_PSK:
		return utls.HelloChrome_112_PSK_Shuf, nil, nil
	case protocol.TLS_PROFILE_CHROME_120:
		return utls.HelloChrome_120, nil, nil
	case protocol.TLS_PROFILE_CHROME_120_PQ:
		return utls.HelloChrome_120_PQ, nil, nil
	case protocol.TLS_PROFILE_CHROME_131:
		return utls.HelloChrome_131, nil, nil
	case protocol.TLS_PROFILE_CHROME_133:
		return utls.HelloChrome_133, nil, nil
	case protocol.TLS_PROFILE_FIREFOX_55:
		return utls.HelloFirefox_55, nil, nil
	case protocol.TLS_PROFILE_FIREFOX_56:
		return utls.HelloFirefox_56, nil, nil
	case protocol.TLS_PROFILE_FIREFOX_65:
		return utls.HelloFirefox_65, nil, nil
	case protocol.TLS_PROFILE_FIREFOX_99:
		return utls.HelloFirefox_99, nil, nil
	case protocol.TLS_PROFILE_FIREFOX_105:
		return utls.HelloFirefox_105, nil, nil
	case protocol.TLS_PROFILE_RANDOMIZED:
		return utls.HelloRandomized, nil, nil
	}

	if p.IsNil() {
		return utls.ClientHelloID{},
			nil,
			errors.Tracef("unknown TLS profile: %s", tlsProfile)
	}

	// utls.HelloCustom with a utls.ClientHelloSpec is used for
	// CustomTLSProfiles.

	customTLSProfile := p.CustomTLSProfile(tlsProfile)
	if customTLSProfile == nil {
		return utls.ClientHelloID{},
			nil,
			errors.Tracef("unknown TLS profile: %s", tlsProfile)
	}

	utlsClientHelloSpec, err := customTLSProfile.GetClientHelloSpec()
	if err != nil {
		return utls.ClientHelloID{}, nil, errors.Trace(err)
	}

	return utls.HelloCustom, utlsClientHelloSpec, nil
}

func getClientHelloVersion(
	utlsClientHelloID utls.ClientHelloID,
	utlsClientHelloSpec *utls.ClientHelloSpec) (string, error) {

	switch utlsClientHelloID {

	case utls.HelloIOS_11_1, utls.HelloIOS_12_1,
		utls.HelloChrome_58, utls.HelloChrome_62,
		utls.HelloFirefox_55, utls.HelloFirefox_56:
		return protocol.TLS_VERSION_12, nil

	case utls.HelloIOS_13, utls.HelloIOS_14,
		utls.HelloChrome_70, utls.HelloChrome_72,
		utls.HelloChrome_83, utls.HelloChrome_96,
		utls.HelloChrome_102, utls.HelloChrome_120,
		utls.HelloChrome_120_PQ, utls.HelloChrome_106_Shuffle,
		utls.HelloChrome_112_PSK_Shuf, utls.HelloChrome_131,
		utls.HelloChrome_133, utls.HelloFirefox_65,
		utls.HelloFirefox_99, utls.HelloFirefox_105,
		utls.HelloSafari_16_0, utls.HelloGolang:
		return protocol.TLS_VERSION_13, nil
	}

	// As utls.HelloRandomized/Custom may be either TLS 1.2 or TLS 1.3, we cannot
	// perform a simple ClientHello ID check. BuildHandshakeState is run, which
	// constructs the entire ClientHello.
	//
	// Assumes utlsClientHelloID.Seed has been set; otherwise the result is
	// ephemeral.
	//
	// BenchmarkRandomizedGetClientHelloVersion indicates that this operation
	// takes on the order of 0.05ms and allocates ~8KB for randomized client
	// hellos.

	conn := utls.UClient(
		nil,
		&utls.Config{InsecureSkipVerify: true},
		utlsClientHelloID)

	if utlsClientHelloSpec != nil {
		err := conn.ApplyPreset(utlsClientHelloSpec)
		if err != nil {
			return "", errors.Trace(err)
		}
	}

	err := conn.BuildHandshakeState()
	if err != nil {
		return "", errors.Trace(err)
	}

	for _, v := range conn.HandshakeState.Hello.SupportedVersions {
		if v == utls.VersionTLS13 {
			return protocol.TLS_VERSION_13, nil
		}
	}

	return protocol.TLS_VERSION_12, nil
}

func init() {
	// Favor compatibility over security. Dial is used as an obfuscation
	// layer; users of Dial, including meek and remote server list
	// downloads, don't depend on this TLS for its security properties.
	utls.EnableWeakCiphers()
}

// containsPSKExt returns true if the ClientHelloSpec has a PreSharedKeyExtension.
// If spec is nil, the ClientHelloSpec is obtained from the ClientHelloID.
func containsPSKExt(id utls.ClientHelloID, spec *utls.ClientHelloSpec) bool {
	if spec == nil {
		myspec, err := utls.UTLSIdToSpec(id)
		if err != nil {
			return false
		}
		spec = &myspec
	}
	for _, ext := range spec.Extensions {
		if _, ok := ext.(utls.PreSharedKeyExtension); ok {
			return true
		}
	}
	return false
}
