/*
 * Copyright (c) 2026, Psiphon Inc.
 * All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

package light

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net/netip"
	"time"
	"unicode/utf8"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/inproxy"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/hkdf"
)

const (
	// TunnelDialAuthorizationVersion is the current authorization version.
	TunnelDialAuthorizationVersion = 1

	// TransportTLS identifies TLS ingress or egress.
	TransportTLS = 1

	// TransportQUIC identifies QUIC ingress or egress.
	TransportQUIC = 2

	// TunnelRootObfuscationSecretSize is the root obfuscation secret size in bytes.
	TunnelRootObfuscationSecretSize = 32

	// TunnelProxyReportVersion is the current proxy report version.
	TunnelProxyReportVersion = 1

	// TunnelTrustedProxyAuthorizationVersion is the current authorization version.
	TunnelTrustedProxyAuthorizationVersion = 1

	// TunnelTrustedProxyAuthorizationMaxSize is the maximum encoded size in bytes.
	TunnelTrustedProxyAuthorizationMaxSize = 1024

	// TunnelProxyReportExporterLabel identifies the transport exporter.
	TunnelProxyReportExporterLabel = "EXPORTER-psiphon-light-report-v1"

	// TunnelProxyReportExporterSize is the transport exporter size in bytes.
	TunnelProxyReportExporterSize = 32

	maxTunnelDialAuthorizationSize = 1024
	maxTunnelSNI                   = 255
	maxTunnelProxyBuildRev         = 128
	maxTunnelProxyReportSize       = 4096
	maxTunnelProxyReportPadding    = 1024

	// Maximum CBOR envelope overhead within the report size cap:
	// map header (1), keys (3), and byte-string headers (2 + 3 + 3).
	maxTunnelProxyReportEnvelopeOverhead = 12

	tunnelDialAuthorizationSignatureDomain         = "Psiphon-Light-Tunnel-Dial-Authorization-v1\x00"
	tunnelProxyReportSignatureDomain               = "Psiphon-Light-Tunnel-Proxy-Report-v1\x00"
	tunnelTrustedProxyAuthorizationSignatureDomain = "Psiphon-Light-Tunnel-Trusted-Proxy-Authorization-v1\x00"
	tunnelTLSPassthroughKeyContext                 = "Psiphon-Light-Tunnel-TLS-Passthrough-v1"
	tunnelQUICObfuscationKeyContext                = "Psiphon-Light-Tunnel-QUIC-Obfuscation-v1"
	tunnelQUICDialClientHelloSeedSalt              = "Psiphon-Light-Tunnel-QUIC-Client-Hello-v1"
	tunnelQUICDialPaddingSeedSalt                  = "Psiphon-Light-Tunnel-QUIC-Padding-v1"
	tunnelQUICDialIPv4SeedSalt                     = "Psiphon-Light-Tunnel-QUIC-IPv4-v1"
	tunnelQUICDialIPv6SeedSalt                     = "Psiphon-Light-Tunnel-QUIC-IPv6-v1"
)

// IrregularTunnelError indicates an irregular tunnel.
type IrregularTunnelError struct {
	err error
}

// NewIrregularTunnelError initializes an IrregularTunnelError.
func NewIrregularTunnelError(err error) *IrregularTunnelError {
	return &IrregularTunnelError{err: err}
}

func (e *IrregularTunnelError) Error() string {
	return e.err.Error()
}

// TunnelDialAuthorization authorizes a Light proxy tunnel destination. In
// Psiphon, the authorization demonstrates that the destination is a valid
// Psiphon server, with the authorization signed by a Psiphon Network key.
// Verify pin checks protect against an authorized IP address no longer
// belonging to a Psiphon-controlled host.
type TunnelDialAuthorization struct {
	Version               uint8  `cbor:"1,keyasint,omitempty"`
	IPAddress             []byte `cbor:"2,keyasint,omitempty"`
	VerifyPin             []byte `cbor:"3,keyasint,omitempty"`
	RootObfuscationSecret []byte `cbor:"4,keyasint,omitempty"`
	TLSPort               uint16 `cbor:"5,keyasint,omitempty"`
	QUICPort              uint16 `cbor:"6,keyasint,omitempty"`
}

// TunnelDialParameters specifies the proxy-to-server dial parameters.
type TunnelDialParameters struct {
	TunnelDialAuthorization           []byte
	EgressProtocol                    uint8
	EgressTLSProfile                  string
	EgressRandomizedTLSProfileSeed    *prng.Seed
	EgressQUICVersion                 string
	EgressQUICDialRootObfuscationSeed *prng.Seed
	EgressSNI                         string
}

// TunnelProxyReport relays information from the proxy to the Psiphon server in
// tunnel mode.
//
// Data includes the report signing public key used to derive the proxy ID;
// the original client IP for server GeoIP lookup; information about the proxy
// and about the dial.
//
// The proxy signs the report and binds it cryptographically to its TLS or
// QUIC connection to the Psiphon server.
//
// A valid trusted proxy authorization allows the server to trust the original
// client IP reported by a trusted proxy.
type TunnelProxyReport struct {
	Version                         uint8  `cbor:"1,keyasint,omitempty"`
	ProxyPublicKey                  []byte `cbor:"2,keyasint,omitempty"`
	TrustedProxyAuthorization       []byte `cbor:"3,keyasint,omitempty"`
	ClientIP                        []byte `cbor:"4,keyasint,omitempty"`
	ProxyPlatform                   uint8  `cbor:"5,keyasint,omitempty"`
	ProxyVersion                    int64  `cbor:"6,keyasint,omitempty"`
	ProxyBuildRev                   []byte `cbor:"7,keyasint,omitempty"`
	IngressProtocol                 uint8  `cbor:"8,keyasint,omitempty"`
	IngressTLSProfile               uint8  `cbor:"9,keyasint,omitempty"`
	IngressQUICVersion              uint8  `cbor:"10,keyasint,omitempty"`
	IngressSNI                      string `cbor:"11,keyasint,omitempty"`
	IngressTLSClientHelloFragmented bool   `cbor:"12,keyasint,omitempty"`
	IngressDidResume                bool   `cbor:"13,keyasint,omitempty"`
	IngressTLSPadding               uint16 `cbor:"14,keyasint,omitempty"`
	EgressTLSProfile                uint8  `cbor:"15,keyasint,omitempty"`
	EgressQUICVersion               uint8  `cbor:"16,keyasint,omitempty"`
	MatchedPersonalCompartments     bool   `cbor:"17,keyasint,omitempty"`
}

// TunnelTrustedProxyAuthorization authorizes a proxy report signing key to
// report a trusted original client IP.
type TunnelTrustedProxyAuthorization struct {
	Version        uint8  `cbor:"1,keyasint,omitempty"`
	ProxyPublicKey []byte `cbor:"2,keyasint,omitempty"`
	NotBeforeUnix  int64  `cbor:"3,keyasint,omitempty"`
	NotAfterUnix   int64  `cbor:"4,keyasint,omitempty"`
}

type signedTunnelPayload struct {
	Signature []byte `cbor:"1,keyasint,omitempty"`
	Payload   []byte `cbor:"2,keyasint,omitempty"`
	Padding   []byte `cbor:"3,keyasint,omitempty"`
}

func signTunnelPayload(
	privateKey ed25519.PrivateKey,
	domain string,
	payload []byte,
	maxSize int) ([]byte, error) {

	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.TraceNew("invalid private key")
	}

	encoded, err := protocol.CBOREncoding.Marshal(
		&signedTunnelPayload{
			Signature: ed25519.Sign(
				privateKey,
				makeTunnelSignatureInput(domain, payload)),
			Payload: payload,
		})
	if err != nil {
		return nil, errors.Trace(err)
	}
	if len(encoded) > maxSize {
		return nil, errors.TraceNew("authorization too large")
	}

	return encoded, nil
}

func verifyTunnelPayload(
	publicKey ed25519.PublicKey,
	domain string,
	encoded []byte,
	maxSize int) ([]byte, error) {

	if len(publicKey) != ed25519.PublicKeySize {
		return nil, errors.TraceNew("invalid public key")
	}
	if len(encoded) == 0 || len(encoded) > maxSize {
		return nil, errors.TraceNew("invalid authorization size")
	}

	var signedPayload signedTunnelPayload
	err := cbor.Unmarshal(encoded, &signedPayload)
	if err != nil {
		return nil, errors.Trace(err)
	}
	if len(signedPayload.Signature) != ed25519.SignatureSize {
		return nil, errors.TraceNew("invalid signature")
	}

	if !ed25519.Verify(
		publicKey,
		makeTunnelSignatureInput(domain, signedPayload.Payload),
		signedPayload.Signature) {

		return nil, errors.TraceNew("invalid signature")
	}

	return signedPayload.Payload, nil
}

func makeTunnelSignatureInput(domain string, payload []byte) []byte {
	input := make([]byte, 0, len(domain)+len(payload))
	input = append(input, domain...)
	return append(input, payload...)
}

// SignTunnelDialAuthorization encodes and signs an authorization.
func SignTunnelDialAuthorization(
	privateKey ed25519.PrivateKey,
	authorization *TunnelDialAuthorization) ([]byte, error) {

	err := validateTunnelDialAuthorization(authorization)
	if err != nil {
		return nil, errors.Trace(err)
	}

	payload, err := protocol.CBOREncoding.Marshal(authorization)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return signTunnelPayload(
		privateKey,
		tunnelDialAuthorizationSignatureDomain,
		payload,
		maxTunnelDialAuthorizationSize)
}

// VerifyTunnelDialAuthorization verifies and decodes an authorization.
func VerifyTunnelDialAuthorization(
	publicKey ed25519.PublicKey,
	encoded []byte) (*TunnelDialAuthorization, error) {

	payload, err := verifyTunnelPayload(
		publicKey,
		tunnelDialAuthorizationSignatureDomain,
		encoded,
		maxTunnelDialAuthorizationSize)
	if err != nil {
		return nil, errors.Trace(err)
	}

	var authorization TunnelDialAuthorization
	err = cbor.Unmarshal(payload, &authorization)
	if err != nil {
		return nil, errors.Trace(err)
	}

	err = validateTunnelDialAuthorization(&authorization)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return &authorization, nil
}

func validateTunnelDialAuthorization(
	authorization *TunnelDialAuthorization) error {

	if authorization == nil {
		return errors.TraceNew("missing authorization")
	}
	if authorization.Version != TunnelDialAuthorizationVersion {
		return errors.TraceNew("unsupported authorization version")
	}
	IPAddress, ok := netip.AddrFromSlice(authorization.IPAddress)
	if !ok || IPAddress.Is4In6() {
		return errors.TraceNew("invalid IP address")
	}

	if len(authorization.VerifyPin) != sha256.Size {
		return errors.TraceNew("invalid verify pin")
	}

	if len(authorization.RootObfuscationSecret) !=
		TunnelRootObfuscationSecretSize {

		return errors.TraceNew("invalid root obfuscation secret")
	}

	if authorization.TLSPort == 0 &&
		authorization.QUICPort == 0 {

		return errors.TraceNew("missing tunnel port")
	}

	return nil
}

func getTunnelDestinationAddress(
	authorization *TunnelDialAuthorization,
	egressProtocol uint8) (string, error) {

	IPAddress, ok := netip.AddrFromSlice(authorization.IPAddress)
	if !ok || IPAddress.Is4In6() {
		return "", errors.TraceNew("invalid IP address")
	}

	var port uint16
	switch egressProtocol {
	case TransportTLS:
		port = authorization.TLSPort
	case TransportQUIC:
		port = authorization.QUICPort
	default:
		return "", errors.TraceNew("unsupported egress protocol")
	}
	if port == 0 {
		return "", errors.TraceNew("missing egress protocol port")
	}

	return netip.AddrPortFrom(IPAddress, port).String(), nil
}

// DeriveTunnelTLSPassthroughKey derives the TLS passthrough key.
func DeriveTunnelTLSPassthroughKey(
	rootObfuscationSecret []byte) ([]byte, error) {

	return deriveTunnelKey(
		rootObfuscationSecret,
		tunnelTLSPassthroughKeyContext)
}

// DeriveTunnelQUICObfuscationKey derives the QUIC obfuscation key.
func DeriveTunnelQUICObfuscationKey(
	rootObfuscationSecret []byte) ([]byte, error) {

	return deriveTunnelKey(
		rootObfuscationSecret,
		tunnelQUICObfuscationKeyContext)
}

func deriveTunnelKey(
	rootObfuscationSecret []byte,
	context string) ([]byte, error) {

	if len(rootObfuscationSecret) != TunnelRootObfuscationSecretSize {
		return nil, errors.TraceNew("invalid root obfuscation secret")
	}

	key := make([]byte, TunnelRootObfuscationSecretSize)
	_, err := io.ReadFull(
		hkdf.New(
			sha256.New,
			rootObfuscationSecret,
			nil,
			[]byte(context)),
		key)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return key, nil
}

func deriveQUICDialSeeds(
	rootSeed *prng.Seed,
	quicVersion string) (
	*prng.Seed,
	*prng.Seed,
	error) {

	if rootSeed == nil {
		return nil, nil, errors.TraceNew(
			"missing QUIC dial root obfuscation seed")
	}

	var clientHelloSeed, paddingSeed *prng.Seed
	var err error
	if protocol.QUICVersionHasRandomizedClientHello(quicVersion) {
		clientHelloSeed, err = prng.NewSaltedSeed(
			rootSeed,
			tunnelQUICDialClientHelloSeedSalt)
		if err != nil {
			return nil, nil, errors.Trace(err)
		}
	}

	if protocol.QUICVersionIsObfuscated(quicVersion) {
		paddingSeed, err = prng.NewSaltedSeed(
			rootSeed,
			tunnelQUICDialPaddingSeedSalt)
		if err != nil {
			return nil, nil, errors.Trace(err)
		}
	}

	return clientHelloSeed, paddingSeed, nil
}

func deriveQUICDialIPAddressFamilySeeds(
	rootSeed *prng.Seed,
	quicVersion string,
	isIPv6 bool) (*prng.Seed, *prng.Seed, error) {

	salt := tunnelQUICDialIPv4SeedSalt
	if isIPv6 {
		salt = tunnelQUICDialIPv6SeedSalt
	}

	addressFamilyRootSeed, err := prng.NewSaltedSeed(rootSeed, salt)
	if err != nil {
		return nil, nil, errors.Trace(err)
	}
	return deriveQUICDialSeeds(addressFamilyRootSeed, quicVersion)
}

// SignTunnelTrustedProxyAuthorization encodes and signs an authorization.
func SignTunnelTrustedProxyAuthorization(
	issuerPrivateKey ed25519.PrivateKey,
	authorization *TunnelTrustedProxyAuthorization) ([]byte, error) {

	err := validateTunnelTrustedProxyAuthorization(authorization)
	if err != nil {
		return nil, errors.Trace(err)
	}

	payload, err := protocol.CBOREncoding.Marshal(authorization)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return signTunnelPayload(
		issuerPrivateKey,
		tunnelTrustedProxyAuthorizationSignatureDomain,
		payload,
		TunnelTrustedProxyAuthorizationMaxSize)
}

// VerifyTunnelTrustedProxyAuthorization verifies an authorization for the
// supplied proxy report signing public key.
func VerifyTunnelTrustedProxyAuthorization(
	issuerPublicKey ed25519.PublicKey,
	expectedProxyPublicKey []byte,
	encoded []byte,
	now time.Time) (*TunnelTrustedProxyAuthorization, error) {

	if len(expectedProxyPublicKey) != ed25519.PublicKeySize {
		return nil, errors.TraceNew("invalid proxy public key")
	}
	payload, err := verifyTunnelPayload(
		issuerPublicKey,
		tunnelTrustedProxyAuthorizationSignatureDomain,
		encoded,
		TunnelTrustedProxyAuthorizationMaxSize)
	if err != nil {
		return nil, errors.Trace(err)
	}

	var authorization TunnelTrustedProxyAuthorization
	err = cbor.Unmarshal(payload, &authorization)
	if err != nil {
		return nil, errors.Trace(err)
	}

	err = validateTunnelTrustedProxyAuthorization(&authorization)
	if err != nil {
		return nil, errors.Trace(err)
	}
	if !bytes.Equal(
		authorization.ProxyPublicKey,
		expectedProxyPublicKey) {

		return nil, errors.TraceNew("unexpected proxy public key")
	}

	nowUnix := now.Unix()
	if nowUnix < authorization.NotBeforeUnix ||
		nowUnix >= authorization.NotAfterUnix {

		return nil, errors.TraceNew("authorization not valid")
	}

	return &authorization, nil
}

func validateTunnelTrustedProxyAuthorization(
	authorization *TunnelTrustedProxyAuthorization) error {

	if authorization == nil {
		return errors.TraceNew("missing authorization")
	}
	if authorization.Version != TunnelTrustedProxyAuthorizationVersion {
		return errors.TraceNew("unsupported authorization version")
	}
	if len(authorization.ProxyPublicKey) != ed25519.PublicKeySize {
		return errors.TraceNew("invalid proxy public key")
	}
	if authorization.NotBeforeUnix < 0 ||
		authorization.NotAfterUnix <= authorization.NotBeforeUnix {

		return errors.TraceNew("invalid authorization validity period")
	}

	return nil
}

// GetTunnelProxyID returns the Curve25519 proxy ID for a report signing key.
func GetTunnelProxyID(privateKey inproxy.SessionPrivateKey) (string, error) {
	if privateKey.IsZero() {
		return "", errors.TraceNew("missing tunnel proxy private key")
	}
	publicKey, err := privateKey.GetPublicKey()
	if err != nil {
		return "", errors.Trace(err)
	}
	curvePublicKey, err := publicKey.ToCurve25519()
	if err != nil {
		return "", errors.Trace(err)
	}
	return inproxy.ID(curvePublicKey).String(), nil
}

// WriteTunnelProxyReport signs and writes a length-prefixed proxy report.
// Padding bounds are reduced as needed to stay within the report size limit.
func WriteTunnelProxyReport(
	writer io.Writer,
	privateKey inproxy.SessionPrivateKey,
	exporter []byte,
	report *TunnelProxyReport,
	minPadding, maxPadding int) error {

	if writer == nil {
		return errors.TraceNew("missing writer")
	}
	if privateKey.IsZero() {
		return errors.TraceNew("missing private key")
	}
	err := validateTunnelProxyReportExporter(exporter)
	if err != nil {
		return errors.Trace(err)
	}
	if report == nil {
		return errors.TraceNew("missing report")
	}
	if minPadding < 0 || maxPadding < minPadding {
		return errors.TraceNew("invalid proxy report padding range")
	}

	publicKey, err := privateKey.GetPublicKey()
	if err != nil {
		return errors.Trace(err)
	}

	reportCopy := *report
	reportCopy.ProxyPublicKey = publicKey[:]

	err = validateTunnelProxyReport(&reportCopy)
	if err != nil {
		return errors.Trace(err)
	}

	payload, err := protocol.CBOREncoding.Marshal(&reportCopy)
	if err != nil {
		return errors.Trace(err)
	}

	signature := ed25519.Sign(
		ed25519.PrivateKey(privateKey[:]),
		makeTunnelProxyReportSignatureInput(exporter, payload))

	// Add random padding to reduce report-size fingerprinting.
	paddingBudget := max(0, maxTunnelProxyReportSize-
		len(payload)-len(signature)-maxTunnelProxyReportEnvelopeOverhead)
	maxPadding = min(maxPadding, paddingBudget)
	minPadding = min(minPadding, maxPadding)

	encoded, err := protocol.CBOREncoding.Marshal(
		&signedTunnelPayload{
			Signature: signature,
			Payload:   payload,
			Padding:   prng.Padding(minPadding, maxPadding),
		})
	if err != nil {
		return errors.Trace(err)
	}
	if len(encoded) > maxTunnelProxyReportSize {
		return errors.TraceNew("invalid proxy report size")
	}

	frame := make([]byte, 2+len(encoded))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(encoded)))
	copy(frame[2:], encoded)

	n, err := writer.Write(frame)
	if err != nil {
		return errors.Trace(err)
	}
	if n != len(frame) {
		return errors.Trace(io.ErrShortWrite)
	}
	return nil
}

// ReadAndVerifyTunnelProxyReport reads and verifies a proxy report.
// Trusting the reported client IP requires separate verification of
// TrustedProxyAuthorization.
func ReadAndVerifyTunnelProxyReport(
	reader io.Reader,
	exporter []byte) (*TunnelProxyReport, inproxy.ID, error) {

	var proxyID inproxy.ID

	if reader == nil {
		return nil, proxyID, errors.TraceNew("missing reader")
	}
	err := validateTunnelProxyReportExporter(exporter)
	if err != nil {
		return nil, proxyID, errors.Trace(err)
	}

	var size [2]byte
	_, err = io.ReadFull(reader, size[:])
	if err != nil {
		return nil, proxyID, errors.Trace(err)
	}

	reportSize := int(binary.BigEndian.Uint16(size[:]))
	if reportSize == 0 || reportSize > maxTunnelProxyReportSize {
		return nil, proxyID,
			NewIrregularTunnelError(
				errors.TraceNew("invalid proxy report size"))
	}

	encoded := make([]byte, reportSize)
	_, err = io.ReadFull(reader, encoded)
	if err != nil {
		return nil, proxyID, errors.Trace(err)
	}

	var signedReport signedTunnelPayload
	err = cbor.Unmarshal(encoded, &signedReport)
	if err != nil {
		return nil, proxyID,
			NewIrregularTunnelError(errors.Trace(err))
	}
	if len(signedReport.Signature) != ed25519.SignatureSize {
		return nil, proxyID,
			NewIrregularTunnelError(
				errors.TraceNew("invalid signature"))
	}

	var report TunnelProxyReport
	err = cbor.Unmarshal(signedReport.Payload, &report)
	if err != nil {
		return nil, proxyID,
			NewIrregularTunnelError(errors.Trace(err))
	}

	err = validateTunnelProxyReport(&report)
	if err != nil {
		return nil, proxyID,
			NewIrregularTunnelError(errors.Trace(err))
	}

	if !ed25519.Verify(
		ed25519.PublicKey(report.ProxyPublicKey),
		makeTunnelProxyReportSignatureInput(exporter, signedReport.Payload),
		signedReport.Signature) {

		return nil, proxyID,
			NewIrregularTunnelError(
				errors.TraceNew("invalid signature"))
	}

	var sessionPublicKey inproxy.SessionPublicKey
	copy(sessionPublicKey[:], report.ProxyPublicKey)
	curvePublicKey, err := sessionPublicKey.ToCurve25519()
	if err != nil {
		return nil, proxyID,
			NewIrregularTunnelError(errors.Trace(err))
	}
	proxyID = inproxy.ID(curvePublicKey)

	return &report, proxyID, nil
}

// GetMetrics returns proxy-reported fields for server logging.
// Call only on reports verified by ReadAndVerifyTunnelProxyReport.
func (report *TunnelProxyReport) GetMetrics() common.LogFields {
	logFields := make(common.LogFields)

	if report.ProxyPlatform != 0 {
		logFields["light_proxy_platform"] = decodeClientPlatform(report.ProxyPlatform)
	}
	logFields["light_proxy_version"] = report.ProxyVersion
	if len(report.ProxyBuildRev) > 0 {
		logFields["light_proxy_build_rev"] = hex.EncodeToString(report.ProxyBuildRev)
	}
	logFields["light_proxy_sni"] = report.IngressSNI

	switch report.IngressProtocol {
	case TransportTLS:
		logFields["light_proxy_tls_profile"] = decodeTLSProfile(report.IngressTLSProfile)
		logFields["light_proxy_tls_fragmented"] = report.IngressTLSClientHelloFragmented
		logFields["light_proxy_tls_padding"] = int(report.IngressTLSPadding)
		logFields["light_proxy_tls_did_resume"] = report.IngressDidResume
	case TransportQUIC:
		logFields["light_proxy_quic_version"] = decodeQUICVersion(report.IngressQUICVersion)
		logFields["light_proxy_quic_did_resume"] = report.IngressDidResume
	}

	if report.EgressTLSProfile != 0 {
		logFields["light_proxy_egress_tls_profile"] = decodeTLSProfile(report.EgressTLSProfile)
	}
	if report.EgressQUICVersion != 0 {
		logFields["light_proxy_egress_quic_version"] = decodeQUICVersion(report.EgressQUICVersion)
	}
	logFields["light_matched_personal_compartments"] = report.MatchedPersonalCompartments

	return logFields
}

func validateTunnelProxyReport(report *TunnelProxyReport) error {
	if report == nil {
		return errors.TraceNew("missing report")
	}
	if report.Version != TunnelProxyReportVersion {
		return errors.TraceNew("unsupported report version")
	}
	if len(report.ProxyPublicKey) != ed25519.PublicKeySize {
		return errors.TraceNew("invalid proxy public key")
	}

	// Private and loopback client IPs are acceptable for LAN/local deployments.
	clientIP, ok := netip.AddrFromSlice(report.ClientIP)
	if !ok || clientIP.IsUnspecified() || clientIP.IsMulticast() {
		return errors.TraceNew("invalid client IP")
	}
	if clientIP.Is4In6() {
		return errors.TraceNew("non-canonical client IP")
	}

	// Allow unknown platform, TLS profile, and QUIC version codes from upgraded
	// clients and proxies; these informational values decode to empty strings.

	if report.ProxyVersion < 0 {
		return errors.TraceNew("invalid proxy version")
	}
	if len(report.ProxyBuildRev) > maxTunnelProxyBuildRev {
		return errors.TraceNew("invalid proxy build revision")
	}
	// SNI comes from the transport handshake; CBOR text requires valid UTF-8.
	if len(report.IngressSNI) > maxTunnelSNI || !utf8.ValidString(report.IngressSNI) {
		return errors.TraceNew("invalid ingress SNI")
	}

	switch report.IngressProtocol {
	case TransportTLS:
		if report.IngressTLSProfile == 0 {
			return errors.TraceNew("missing ingress TLS profile")
		}
		if report.IngressQUICVersion != 0 {
			return errors.TraceNew("unexpected ingress QUIC version")
		}
	case TransportQUIC:
		if report.IngressTLSProfile != 0 ||
			report.IngressTLSClientHelloFragmented ||
			report.IngressTLSPadding != 0 {

			return errors.TraceNew("unexpected ingress TLS parameters")
		}
		if report.IngressQUICVersion == 0 {
			return errors.TraceNew("missing ingress QUIC version")
		}
	default:
		return errors.TraceNew("unsupported ingress protocol")
	}

	if (report.EgressTLSProfile == 0 && report.EgressQUICVersion == 0) ||
		(report.EgressTLSProfile != 0 && report.EgressQUICVersion != 0) {

		return errors.TraceNew("invalid egress parameters")
	}
	if len(report.TrustedProxyAuthorization) >
		TunnelTrustedProxyAuthorizationMaxSize {

		return errors.TraceNew("invalid trusted proxy authorization")
	}

	return nil
}

func validateTunnelProxyReportExporter(exporter []byte) error {
	if len(exporter) != TunnelProxyReportExporterSize {
		return errors.TraceNew("invalid exporter")
	}
	return nil
}

func makeTunnelProxyReportSignatureInput(
	exporter, payload []byte) []byte {

	hash := sha256.New()
	hash.Write([]byte(tunnelProxyReportSignatureDomain))
	hash.Write(exporter)
	hash.Write(payload)
	return hash.Sum(nil)
}
