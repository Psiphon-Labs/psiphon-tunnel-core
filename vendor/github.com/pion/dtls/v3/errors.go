// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
)

// Typed errors.
var (
	ErrConnClosed = &FatalError{Err: errors.New("conn is closed")} //nolint:err113

	errDeadlineExceeded   = &TimeoutError{Err: fmt.Errorf("read/write timeout: %w", context.DeadlineExceeded)}
	errInvalidContentType = &TemporaryError{Err: errors.New("invalid content type")} //nolint:err113

	//nolint:err113
	errBufferTooSmall = &TemporaryError{Err: errors.New("buffer is too small")}
	//nolint:err113
	errContextUnsupported = &TemporaryError{Err: errors.New("context is not supported for ExportKeyingMaterial")}
	//nolint:err113
	errHandshakeInProgress = &TemporaryError{Err: errors.New("handshake is in progress")}
	//nolint:err113
	errReservedExportKeyingMaterial = &TemporaryError{
		Err: errors.New("ExportKeyingMaterial can not be used with a reserved label"),
	}
	//nolint:err113
	errApplicationDataEpochZero = &TemporaryError{Err: errors.New("ApplicationData with epoch of 0")}
	//nolint:err113
	errUnhandledContextType = &TemporaryError{Err: errors.New("unhandled contentType")}

	//nolint:err113
	errCertificateVerifyNoCertificate = &FatalError{
		Err: errors.New("client sent certificate verify but we have no certificate to verify"),
	}
	//nolint:err113
	errCipherSuiteNoIntersection = &FatalError{Err: errors.New("client+server do not support any shared cipher suites")}
	//nolint:err113
	errClientCertificateNotVerified = &FatalError{Err: errors.New("client sent certificate but did not verify it")}
	//nolint:err113
	errClientCertificateRequired = &FatalError{Err: errors.New("server required client verification, but got none")}
	//nolint:err113
	errClientNoMatchingSRTPProfile = &FatalError{Err: errors.New("server responded with SRTP Profile we do not support")}
	//nolint:err113
	errClientRequiredButNoServerEMS = &FatalError{
		Err: errors.New("client required Extended Master Secret extension, but server does not support it"),
	}
	//nolint:err113
	errCookieMismatch = &FatalError{Err: errors.New("client+server cookie does not match")}
	//nolint:err113
	errIdentityNoPSK = &FatalError{Err: errors.New("PSK Identity Hint provided but PSK is nil")}
	//nolint:err113
	errInvalidCertificate = &FatalError{Err: errors.New("no certificate provided")}
	//nolint:err113
	errInvalidCipherSuite = &FatalError{Err: errors.New("invalid or unknown cipher suite")}
	//nolint:err113
	errInvalidClientAuthType = &FatalError{Err: errors.New("invalid client auth type")}
	//nolint:err113
	errInvalidECDSASignature = &FatalError{Err: errors.New("ECDSA signature contained zero or negative values")}
	//nolint:err113
	errInvalidPrivateKey = &FatalError{Err: errors.New("invalid private key type")}
	//nolint:err113
	errInvalidSignatureAlgorithm = &FatalError{Err: errors.New("invalid signature algorithm")}
	//nolint:err113
	errInvalidExtendedMasterSecretType = &FatalError{Err: errors.New("invalid extended master secret type")}
	//nolint:err113
	errInvalidCertificateSignatureAlgorithm = &FatalError{
		Err: errors.New("certificate uses a signature algorithm that is not allowed"),
	}
	//nolint:err113
	errKeySignatureMismatch = &FatalError{Err: errors.New("expected and actual key signature do not match")}
	//nolint:err113
	errInvalidCertificateOID = &FatalError{Err: errors.New("certificate OID does not match signature algorithm")}
	//nolint:err113
	errNilNextConn = &FatalError{Err: errors.New("Conn can not be created with a nil nextConn")}
	//nolint:err113
	errNoAvailableCipherSuites = &FatalError{
		Err: errors.New("connection can not be created, no CipherSuites satisfy this Config"),
	}
	//nolint:err113
	errNoAvailablePSKCipherSuite = &FatalError{
		Err: errors.New("connection can not be created, pre-shared key present but no compatible CipherSuite"),
	}
	//nolint:err113
	errNoAvailableCertificateCipherSuite = &FatalError{
		Err: errors.New("connection can not be created, certificate present but no compatible CipherSuite"),
	}
	//nolint:err113
	errNoAvailableSignatureSchemes = &FatalError{
		Err: errors.New("connection can not be created, no SignatureScheme satisfy this Config"),
	}
	//nolint:err113
	errNoCertificates = &FatalError{Err: errors.New("no certificates configured")}
	//nolint:err113
	errNoConfigProvided = &FatalError{Err: errors.New("no config provided")}
	//nolint:err113
	errNoSupportedEllipticCurves = &FatalError{
		Err: errors.New("client requested zero or more elliptic curves that are not supported by the server"),
	}
	//nolint:err113
	errUnsupportedProtocolVersion = &FatalError{Err: errors.New("unsupported protocol version")}
	//nolint:err113
	errPSKAndIdentityMustBeSetForClient = &FatalError{
		Err: errors.New("PSK and PSK Identity Hint must both be set for client"),
	}
	//nolint:err113
	errRequestedButNoSRTPExtension = &FatalError{
		Err: errors.New("SRTP support was requested but server did not respond with use_srtp extension"),
	}
	//nolint:err113
	errServerNoMatchingSRTPProfile = &FatalError{Err: errors.New("client requested SRTP but we have no matching profiles")}
	//nolint:err113
	errServerRequiredButNoClientEMS = &FatalError{
		Err: errors.New("server requires the Extended Master Secret extension, but the client does not support it"),
	}
	//nolint:err113
	errVerifyDataMismatch = &FatalError{Err: errors.New("expected and actual verify data does not match")}
	//nolint:err113
	errNotAcceptableCertificateChain = &FatalError{Err: errors.New("certificate chain is not signed by an acceptable CA")}

	//nolint:err113
	errInvalidFlight = &InternalError{Err: errors.New("invalid flight number")}
	//nolint:err113
	errKeySignatureGenerateUnimplemented = &InternalError{
		Err: errors.New("unable to generate key signature, unimplemented"),
	}
	//nolint:err113
	errKeySignatureVerifyUnimplemented = &InternalError{Err: errors.New("unable to verify key signature, unimplemented")}
	//nolint:err113
	errLengthMismatch = &InternalError{Err: errors.New("data length and declared length do not match")}
	//nolint:err113
	errSequenceNumberOverflow = &InternalError{Err: errors.New("sequence number overflow")}
	//nolint:err113
	errInvalidFSMTransition = &InternalError{Err: errors.New("invalid state machine transition")}
	//nolint:err113
	errFailedToAccessPoolReadBuffer = &InternalError{Err: errors.New("failed to access pool read buffer")}
	//nolint:err113
	errFragmentBufferOverflow = &InternalError{Err: errors.New("fragment buffer overflow")}

	//nolint:err113
	errEmptyCertificates = &FatalError{Err: errors.New("certificates option requires at least one certificate")}
	//nolint:err113
	errEmptyCipherSuites = &FatalError{Err: errors.New("cipher suites option requires at least one cipher suite")}
	//nolint:err113
	errNilCustomCipherSuites = &FatalError{Err: errors.New("custom cipher suites option requires a non-nil function")}
	//nolint:err113
	errEmptySignatureSchemes = &FatalError{Err: errors.New("signature schemes option requires at least one scheme")}
	//nolint:err113
	errEmptyCertificateSignatureSchemes = &FatalError{
		Err: errors.New("certificate signature schemes option requires at least one scheme"),
	}
	//nolint:err113
	errEmptySRTPProtectionProfiles = &FatalError{
		Err: errors.New("SRTP protection profiles option requires at least one profile"),
	}
	//nolint:err113
	errInvalidFlightInterval = &FatalError{Err: errors.New("flight interval must be positive")}
	//nolint:err113
	errNilPSKCallback = &FatalError{Err: errors.New("PSK option requires a non-nil callback")}
	//nolint:err113
	errNilVerifyPeerCertificate = &FatalError{
		Err: errors.New("verify peer certificate option requires a non-nil callback"),
	}
	//nolint:err113
	errNilVerifyConnection = &FatalError{Err: errors.New("verify connection option requires a non-nil callback")}
	//nolint:err113
	errInvalidMTU = &FatalError{Err: errors.New("MTU must be positive")}
	//nolint:err113
	errInvalidReplayProtectionWindow = &FatalError{Err: errors.New("replay protection window must be non-negative")}
	//nolint:err113
	errEmptySupportedProtocols = &FatalError{
		Err: errors.New("supported protocols option requires at least one protocol"),
	}
	//nolint:err113
	errEmptyEllipticCurves = &FatalError{Err: errors.New("elliptic curves option requires at least one curve")}
	//nolint:err113
	errNilGetClientCertificate = &FatalError{
		Err: errors.New("get client certificate option requires a non-nil callback"),
	}
	//nolint:err113
	errNilConnectionIDGenerator = &FatalError{
		Err: errors.New("connection ID generator option requires a non-nil function"),
	}
	//nolint:err113
	errNilPaddingLengthGenerator = &FatalError{
		Err: errors.New("padding length generator option requires a non-nil function"),
	}
	//nolint:err113
	errNilHelloRandomBytesGenerator = &FatalError{
		Err: errors.New("hello random bytes generator option requires a non-nil function"),
	}
	//nolint:err113
	errNilClientHelloMessageHook = &FatalError{
		Err: errors.New("client hello message hook option requires a non-nil function"),
	}
	//nolint:err113
	errNilGetCertificate = &FatalError{Err: errors.New("get certificate option requires a non-nil callback")}
	//nolint:err113
	errNilServerHelloMessageHook = &FatalError{
		Err: errors.New("server hello message hook option requires a non-nil function"),
	}
	//nolint:err113
	errNilCertificateRequestMessageHook = &FatalError{
		Err: errors.New("certificate request message hook option requires a non-nil function"),
	}
	//nolint:err113
	errNilOnConnectionAttempt = &FatalError{
		Err: errors.New("on connection attempt option requires a non-nil callback"),
	}
)

// FatalError indicates that the DTLS connection is no longer available.
// It is mainly caused by wrong configuration of server or client.
type FatalError = protocol.FatalError

// InternalError indicates and internal error caused by the implementation,
// and the DTLS connection is no longer available.
// It is mainly caused by bugs or tried to use unimplemented features.
type InternalError = protocol.InternalError

// TemporaryError indicates that the DTLS connection is still available, but the request was failed temporary.
type TemporaryError = protocol.TemporaryError

// TimeoutError indicates that the request was timed out.
type TimeoutError = protocol.TimeoutError

// HandshakeError indicates that the handshake failed.
type HandshakeError = protocol.HandshakeError

// errInvalidCipherSuite indicates an attempt at using an unsupported cipher suite.
type invalidCipherSuiteError struct {
	id CipherSuiteID
}

func (e *invalidCipherSuiteError) Error() string {
	return fmt.Sprintf("CipherSuite with id(%d) is not valid", e.id)
}

func (e *invalidCipherSuiteError) Is(err error) bool {
	var other *invalidCipherSuiteError
	if errors.As(err, &other) {
		return e.id == other.id
	}

	return false
}

// errAlert wraps DTLS alert notification as an error.
type alertError struct {
	*alert.Alert
}

func (e *alertError) Error() string {
	return fmt.Sprintf("alert: %s", e.Alert.String())
}

func (e *alertError) IsFatalOrCloseNotify() bool {
	return e.Level == alert.Fatal || e.Description == alert.CloseNotify
}

func (e *alertError) Is(err error) bool {
	var other *alertError
	if errors.As(err, &other) {
		return e.Level == other.Level && e.Description == other.Description
	}

	return false
}

// netError translates an error from underlying Conn to corresponding net.Error.
func netError(err error) error {
	switch {
	case errors.Is(err, io.EOF), errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		// Return io.EOF and context errors as is.
		return err
	}

	var (
		ne      net.Error
		opError *net.OpError
		se      *os.SyscallError
	)

	if errors.As(err, &opError) { //nolint:nestif
		if errors.As(opError, &se) {
			if se.Timeout() {
				return &TimeoutError{Err: err}
			}
			if isOpErrorTemporary(se) {
				return &TemporaryError{Err: err}
			}
		}
	}

	if errors.As(err, &ne) {
		return err
	}

	return &FatalError{Err: err}
}
