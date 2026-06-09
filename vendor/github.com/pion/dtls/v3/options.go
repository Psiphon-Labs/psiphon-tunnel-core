// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"time"

	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/logging"
)

// ServerOption configures a DTLS server.
type ServerOption interface {
	applyServer(*dtlsConfig) error
}

// ClientOption configures a DTLS client.
type ClientOption interface {
	applyClient(*dtlsConfig) error
}

// Option is an option that can be used with both client and server.
// This is used for options that apply to both sides of a connection,
// such as in the Resume function where the side is determined at runtime.
type Option interface {
	ServerOption
	ClientOption
}

// defensiveCopy copies a slice. This prevents the caller from mutating
// the config after construction. Returns empty slice if input is empty.
func defensiveCopy[T any](t ...T) []T {
	return append([]T{}, t...)
}

// dtlsConfig is the internal configuration structure.
// This will eventually replace the exported Config struct.
type dtlsConfig struct { //nolint:dupl
	certificates                  []tls.Certificate
	cipherSuites                  []CipherSuiteID
	customCipherSuites            func() []CipherSuite
	signatureSchemes              []tls.SignatureScheme
	certificateSignatureSchemes   []tls.SignatureScheme
	srtpProtectionProfiles        []SRTPProtectionProfile
	srtpMasterKeyIdentifier       []byte
	clientAuth                    ClientAuthType
	extendedMasterSecret          ExtendedMasterSecretType
	flightInterval                time.Duration
	disableRetransmitBackoff      bool
	psk                           PSKCallback
	pskIdentityHint               []byte
	insecureSkipVerify            bool
	insecureHashes                bool
	verifyPeerCertificate         func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error
	verifyConnection              func(*State) error
	rootCAs                       *x509.CertPool
	clientCAs                     *x509.CertPool
	serverName                    string
	loggerFactory                 logging.LoggerFactory
	mtu                           int
	replayProtectionWindow        int
	keyLogWriter                  io.Writer
	sessionStore                  SessionStore
	supportedProtocols            []string
	ellipticCurves                []elliptic.Curve
	getCertificate                func(*ClientHelloInfo) (*tls.Certificate, error)
	getClientCertificate          func(*CertificateRequestInfo) (*tls.Certificate, error)
	insecureSkipVerifyHello       bool
	connectionIDGenerator         func() []byte
	paddingLengthGenerator        func(uint) uint
	helloRandomBytesGenerator     func() [handshake.RandomBytesLength]byte
	clientHelloMessageHook        func(handshake.MessageClientHello) handshake.Message
	serverHelloMessageHook        func(handshake.MessageServerHello) handshake.Message
	certificateRequestMessageHook func(handshake.MessageCertificateRequest) handshake.Message
	onConnectionAttempt           func(net.Addr) error
}

// applyDefaults applies default values to the config.
func (c *dtlsConfig) applyDefaults() {
	c.extendedMasterSecret = RequestExtendedMasterSecret
	c.flightInterval = time.Second
	c.mtu = defaultMTU
	c.replayProtectionWindow = defaultReplayProtectionWindow
}

// toConfig converts internal dtlsConfig to the exported Config struct.
// This is for backward compatibility and will be removed when Config is deprecated.
// All slice fields are copied to ensure immutability.
func (c *dtlsConfig) toConfig() *Config {
	config := &Config{
		CustomCipherSuites:            c.customCipherSuites,
		ClientAuth:                    c.clientAuth,
		ExtendedMasterSecret:          c.extendedMasterSecret,
		FlightInterval:                c.flightInterval,
		DisableRetransmitBackoff:      c.disableRetransmitBackoff,
		PSK:                           c.psk,
		InsecureSkipVerify:            c.insecureSkipVerify,
		InsecureHashes:                c.insecureHashes,
		VerifyPeerCertificate:         c.verifyPeerCertificate,
		VerifyConnection:              c.verifyConnection,
		RootCAs:                       c.rootCAs,
		ClientCAs:                     c.clientCAs,
		ServerName:                    c.serverName,
		LoggerFactory:                 c.loggerFactory,
		MTU:                           c.mtu,
		ReplayProtectionWindow:        c.replayProtectionWindow,
		KeyLogWriter:                  c.keyLogWriter,
		SessionStore:                  c.sessionStore,
		GetCertificate:                c.getCertificate,
		GetClientCertificate:          c.getClientCertificate,
		InsecureSkipVerifyHello:       c.insecureSkipVerifyHello,
		ConnectionIDGenerator:         c.connectionIDGenerator,
		PaddingLengthGenerator:        c.paddingLengthGenerator,
		HelloRandomBytesGenerator:     c.helloRandomBytesGenerator,
		ClientHelloMessageHook:        c.clientHelloMessageHook,
		ServerHelloMessageHook:        c.serverHelloMessageHook,
		CertificateRequestMessageHook: c.certificateRequestMessageHook,
		OnConnectionAttempt:           c.onConnectionAttempt,
	}

	if len(c.certificates) > 0 {
		config.Certificates = append([]tls.Certificate(nil), c.certificates...)
	}
	if len(c.cipherSuites) > 0 {
		config.CipherSuites = append([]CipherSuiteID(nil), c.cipherSuites...)
	}
	if len(c.signatureSchemes) > 0 {
		config.SignatureSchemes = append([]tls.SignatureScheme(nil), c.signatureSchemes...)
	}
	if len(c.certificateSignatureSchemes) > 0 {
		config.CertificateSignatureSchemes = append([]tls.SignatureScheme(nil), c.certificateSignatureSchemes...)
	}
	if len(c.srtpProtectionProfiles) > 0 {
		config.SRTPProtectionProfiles = append([]SRTPProtectionProfile(nil), c.srtpProtectionProfiles...)
	}
	if len(c.srtpMasterKeyIdentifier) > 0 {
		config.SRTPMasterKeyIdentifier = append([]byte(nil), c.srtpMasterKeyIdentifier...)
	}
	if len(c.pskIdentityHint) > 0 {
		config.PSKIdentityHint = append([]byte(nil), c.pskIdentityHint...)
	}
	if len(c.supportedProtocols) > 0 {
		config.SupportedProtocols = append([]string(nil), c.supportedProtocols...)
	}
	if len(c.ellipticCurves) > 0 {
		config.EllipticCurves = append([]elliptic.Curve(nil), c.ellipticCurves...)
	}

	return config
}

// buildConfig builds a Config from the provided options, for mixed client/server cases.
func buildConfig(opts ...Option) (*Config, error) {
	cfg := &dtlsConfig{}
	cfg.applyDefaults()

	for _, opt := range opts {
		if err := opt.applyServer(cfg); err != nil {
			return nil, err
		}
	}

	return cfg.toConfig(), nil
}

// buildServerConfig builds a Config for server from the provided options.
func buildServerConfig(opts ...ServerOption) (*Config, error) {
	cfg := &dtlsConfig{}
	cfg.applyDefaults()

	for _, opt := range opts {
		if err := opt.applyServer(cfg); err != nil {
			return nil, err
		}
	}

	return cfg.toConfig(), nil
}

// buildClientConfig builds a Config for client from the provided options.
func buildClientConfig(opts ...ClientOption) (*Config, error) {
	cfg := &dtlsConfig{}
	cfg.applyDefaults()

	for _, opt := range opts {
		if err := opt.applyClient(cfg); err != nil {
			return nil, err
		}
	}

	return cfg.toConfig(), nil
}

// sharedOption wraps an apply function that works for both client and server.
// This eliminates code duplication for options that behave identically on both sides.
type sharedOption func(*dtlsConfig) error

func (o sharedOption) applyServer(c *dtlsConfig) error { return o(c) }
func (o sharedOption) applyClient(c *dtlsConfig) error { return o(c) }

// WithCertificates sets the certificate chain to present to the other side of the connection.
// For functional options, an explicitly empty slice is not allowed.
func WithCertificates(certs ...tls.Certificate) Option {
	return sharedOption(func(c *dtlsConfig) error {
		if len(certs) == 0 {
			return errEmptyCertificates
		}
		c.certificates = defensiveCopy(certs...)

		return nil
	})
}

// WithCipherSuites sets the supported cipher suites.
// For functional options, an explicitly empty slice is not allowed.
func WithCipherSuites(suites ...CipherSuiteID) Option {
	return sharedOption(func(c *dtlsConfig) error {
		if len(suites) == 0 {
			return errEmptyCipherSuites
		}
		c.cipherSuites = defensiveCopy(suites...)

		return nil
	})
}

// WithCustomCipherSuites sets the custom cipher suites provider.
// Returns an error if the provider is nil.
func WithCustomCipherSuites(fn func() []CipherSuite) Option {
	return sharedOption(func(c *dtlsConfig) error {
		if fn == nil {
			return errNilCustomCipherSuites
		}
		c.customCipherSuites = fn

		return nil
	})
}

// WithSignatureSchemes sets the signature schemes.
// For functional options, an explicitly empty slice is not allowed.
func WithSignatureSchemes(schemes ...tls.SignatureScheme) Option {
	return sharedOption(func(c *dtlsConfig) error {
		if len(schemes) == 0 {
			return errEmptySignatureSchemes
		}
		c.signatureSchemes = defensiveCopy(schemes...)

		return nil
	})
}

// WithCertificateSignatureSchemes sets the signature and hash schemes that may be used
// in digital signatures for X.509 certificates. If not set, the signature_algorithms_cert
// extension is not sent, and SignatureSchemes is used for both handshake signatures and
// certificate chain validation, as specified in RFC 8446 Section 4.2.3.
// For functional options, an explicitly empty slice is not allowed.
func WithCertificateSignatureSchemes(schemes ...tls.SignatureScheme) Option {
	return sharedOption(func(c *dtlsConfig) error {
		if len(schemes) == 0 {
			return errEmptyCertificateSignatureSchemes
		}
		c.certificateSignatureSchemes = defensiveCopy(schemes...)

		return nil
	})
}

// WithSRTPProtectionProfiles sets the SRTP protection profiles.
// For functional options, an explicitly empty slice is not allowed.
func WithSRTPProtectionProfiles(profiles ...SRTPProtectionProfile) Option {
	return sharedOption(func(c *dtlsConfig) error {
		if len(profiles) == 0 {
			return errEmptySRTPProtectionProfiles
		}
		c.srtpProtectionProfiles = defensiveCopy(profiles...)

		return nil
	})
}

// WithSRTPMasterKeyIdentifier sets the SRTP master key identifier.
func WithSRTPMasterKeyIdentifier(identifier []byte) Option {
	return sharedOption(func(c *dtlsConfig) error {
		c.srtpMasterKeyIdentifier = defensiveCopy(identifier...)

		return nil
	})
}

// WithExtendedMasterSecret sets the extended master secret policy.
// Returns an error if the type is invalid.
func WithExtendedMasterSecret(ems ExtendedMasterSecretType) Option {
	return sharedOption(func(c *dtlsConfig) error {
		if ems < RequestExtendedMasterSecret || ems > DisableExtendedMasterSecret {
			return errInvalidExtendedMasterSecretType
		}
		c.extendedMasterSecret = ems

		return nil
	})
}

// WithFlightInterval sets the flight interval for handshake messages.
// Returns an error if the interval is not positive.
func WithFlightInterval(interval time.Duration) Option {
	return sharedOption(func(c *dtlsConfig) error {
		if interval <= 0 {
			return errInvalidFlightInterval
		}
		c.flightInterval = interval

		return nil
	})
}

// WithDisableRetransmitBackoff disables retransmit backoff.
func WithDisableRetransmitBackoff(disable bool) Option {
	return sharedOption(func(c *dtlsConfig) error {
		c.disableRetransmitBackoff = disable

		return nil
	})
}

// WithPSK sets the pre-shared key callback.
// Returns an error if the callback is nil.
func WithPSK(callback PSKCallback) Option {
	return sharedOption(func(c *dtlsConfig) error {
		if callback == nil {
			return errNilPSKCallback
		}
		c.psk = callback

		return nil
	})
}

// WithPSKIdentityHint sets the PSK identity hint.
func WithPSKIdentityHint(hint []byte) Option {
	return sharedOption(func(c *dtlsConfig) error {
		c.pskIdentityHint = defensiveCopy(hint...)

		return nil
	})
}

// WithInsecureSkipVerify skips certificate verification.
// This should only be used for testing.
func WithInsecureSkipVerify(skip bool) Option {
	return sharedOption(func(c *dtlsConfig) error {
		c.insecureSkipVerify = skip

		return nil
	})
}

// WithInsecureHashes allows the use of insecure hash algorithms.
func WithInsecureHashes(allow bool) Option {
	return sharedOption(func(c *dtlsConfig) error {
		c.insecureHashes = allow

		return nil
	})
}

// WithVerifyPeerCertificate sets the peer certificate verification callback.
// Returns an error if the callback is nil.
func WithVerifyPeerCertificate(fn func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error) Option {
	return sharedOption(func(c *dtlsConfig) error {
		if fn == nil {
			return errNilVerifyPeerCertificate
		}
		c.verifyPeerCertificate = fn

		return nil
	})
}

// WithVerifyConnection sets the connection verification callback.
// Returns an error if the callback is nil.
func WithVerifyConnection(fn func(*State) error) Option {
	return sharedOption(func(c *dtlsConfig) error {
		if fn == nil {
			return errNilVerifyConnection
		}
		c.verifyConnection = fn

		return nil
	})
}

// WithRootCAs sets the root certificate authorities.
func WithRootCAs(pool *x509.CertPool) Option {
	return sharedOption(func(c *dtlsConfig) error {
		c.rootCAs = pool

		return nil
	})
}

// WithServerName sets the server name for certificate verification.
func WithServerName(name string) Option {
	return sharedOption(func(c *dtlsConfig) error {
		c.serverName = name

		return nil
	})
}

// WithLoggerFactory sets the logger factory for creating loggers.
func WithLoggerFactory(factory logging.LoggerFactory) Option {
	return sharedOption(func(c *dtlsConfig) error {
		c.loggerFactory = factory

		return nil
	})
}

// WithMTU sets the maximum transmission unit.
// Returns an error if the MTU is not positive.
func WithMTU(mtu int) Option {
	return sharedOption(func(c *dtlsConfig) error {
		if mtu <= 0 {
			return errInvalidMTU
		}
		c.mtu = mtu

		return nil
	})
}

// WithReplayProtectionWindow sets the replay protection window size.
// Returns an error if the window size is negative.
func WithReplayProtectionWindow(window int) Option {
	return sharedOption(func(c *dtlsConfig) error {
		if window < 0 {
			return errInvalidReplayProtectionWindow
		}
		c.replayProtectionWindow = window

		return nil
	})
}

// WithKeyLogWriter sets the key log writer for debugging.
// Use of KeyLogWriter compromises security and should only be used for debugging.
func WithKeyLogWriter(writer io.Writer) Option {
	return sharedOption(func(c *dtlsConfig) error {
		c.keyLogWriter = writer

		return nil
	})
}

// WithSessionStore sets the session store for resumption.
func WithSessionStore(store SessionStore) Option {
	return sharedOption(func(c *dtlsConfig) error {
		c.sessionStore = store

		return nil
	})
}

// WithSupportedProtocols sets the supported application protocols for ALPN.
// For functional options, an explicitly empty slice is not allowed.
func WithSupportedProtocols(protocols ...string) Option {
	return sharedOption(func(c *dtlsConfig) error {
		if len(protocols) == 0 {
			return errEmptySupportedProtocols
		}
		c.supportedProtocols = defensiveCopy(protocols...)

		return nil
	})
}

// WithEllipticCurves sets the elliptic curves.
// For functional options, an explicitly empty slice is not allowed.
func WithEllipticCurves(curves ...elliptic.Curve) Option {
	return sharedOption(func(c *dtlsConfig) error {
		if len(curves) == 0 {
			return errEmptyEllipticCurves
		}
		c.ellipticCurves = defensiveCopy(curves...)

		return nil
	})
}

// WithGetClientCertificate sets the client certificate getter callback.
// Returns an error if the callback is nil.
func WithGetClientCertificate(fn func(*CertificateRequestInfo) (*tls.Certificate, error)) Option {
	return sharedOption(func(c *dtlsConfig) error {
		if fn == nil {
			return errNilGetClientCertificate
		}
		c.getClientCertificate = fn

		return nil
	})
}

// WithConnectionIDGenerator sets the connection ID generator.
// Returns an error if the generator is nil.
func WithConnectionIDGenerator(fn func() []byte) Option {
	return sharedOption(func(c *dtlsConfig) error {
		if fn == nil {
			return errNilConnectionIDGenerator
		}
		c.connectionIDGenerator = fn

		return nil
	})
}

// WithPaddingLengthGenerator sets the padding length generator.
// Returns an error if the generator is nil.
func WithPaddingLengthGenerator(fn func(uint) uint) Option {
	return sharedOption(func(c *dtlsConfig) error {
		if fn == nil {
			return errNilPaddingLengthGenerator
		}
		c.paddingLengthGenerator = fn

		return nil
	})
}

// WithHelloRandomBytesGenerator sets the hello random bytes generator.
// Returns an error if the generator is nil.
func WithHelloRandomBytesGenerator(fn func() [handshake.RandomBytesLength]byte) Option {
	return sharedOption(func(c *dtlsConfig) error {
		if fn == nil {
			return errNilHelloRandomBytesGenerator
		}
		c.helloRandomBytesGenerator = fn

		return nil
	})
}

// WithClientHelloMessageHook sets the client hello message hook.
// Returns an error if the hook is nil.
func WithClientHelloMessageHook(fn func(handshake.MessageClientHello) handshake.Message) Option {
	return sharedOption(func(c *dtlsConfig) error {
		if fn == nil {
			return errNilClientHelloMessageHook
		}
		c.clientHelloMessageHook = fn

		return nil
	})
}

// serverOnlyOption wraps an apply function for server-only options.
type serverOnlyOption func(*dtlsConfig) error

func (o serverOnlyOption) applyServer(c *dtlsConfig) error { return o(c) }

// WithClientAuth sets the client authentication policy.
// Returns an error if the type is invalid.
// This option is only applicable to servers.
func WithClientAuth(auth ClientAuthType) ServerOption {
	return serverOnlyOption(func(c *dtlsConfig) error {
		if auth < NoClientCert || auth > RequireAndVerifyClientCert {
			return errInvalidClientAuthType
		}
		c.clientAuth = auth

		return nil
	})
}

// WithClientCAs sets the client certificate authorities.
// This option is only applicable to servers.
func WithClientCAs(pool *x509.CertPool) ServerOption {
	return serverOnlyOption(func(c *dtlsConfig) error {
		c.clientCAs = pool

		return nil
	})
}

// WithGetCertificate sets the certificate getter callback.
// Returns an error if the callback is nil.
// This option is only applicable to servers.
func WithGetCertificate(fn func(*ClientHelloInfo) (*tls.Certificate, error)) ServerOption {
	return serverOnlyOption(func(c *dtlsConfig) error {
		if fn == nil {
			return errNilGetCertificate
		}
		c.getCertificate = fn

		return nil
	})
}

// WithInsecureSkipVerifyHello skips hello verify phase on the server.
// This has implication on DoS attack resistance.
// This option is only applicable to servers.
func WithInsecureSkipVerifyHello(skip bool) ServerOption {
	return serverOnlyOption(func(c *dtlsConfig) error {
		c.insecureSkipVerifyHello = skip

		return nil
	})
}

// WithServerHelloMessageHook sets the server hello message hook.
// Returns an error if the hook is nil.
// This option is only applicable to servers.
func WithServerHelloMessageHook(fn func(handshake.MessageServerHello) handshake.Message) ServerOption {
	return serverOnlyOption(func(c *dtlsConfig) error {
		if fn == nil {
			return errNilServerHelloMessageHook
		}
		c.serverHelloMessageHook = fn

		return nil
	})
}

// WithCertificateRequestMessageHook sets the certificate request message hook.
// Returns an error if the hook is nil.
// This option is only applicable to servers.
func WithCertificateRequestMessageHook(fn func(handshake.MessageCertificateRequest) handshake.Message) ServerOption {
	return serverOnlyOption(func(c *dtlsConfig) error {
		if fn == nil {
			return errNilCertificateRequestMessageHook
		}
		c.certificateRequestMessageHook = fn

		return nil
	})
}

// WithOnConnectionAttempt sets the connection attempt callback.
// Returns an error if the callback is nil.
// This option is only applicable to servers.
func WithOnConnectionAttempt(fn func(net.Addr) error) ServerOption {
	return serverOnlyOption(func(c *dtlsConfig) error {
		if fn == nil {
			return errNilOnConnectionAttempt
		}
		c.onConnectionAttempt = fn

		return nil
	})
}
