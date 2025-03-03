// Copyright 2022 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"compress/zlib"
	"errors"
	"fmt"
	"io"

	"github.com/Psiphon-Labs/utls/internal/hpke"
	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// This function is called by (*clientHandshakeStateTLS13).readServerCertificate()
// to retrieve the certificate out of a message read by (*Conn).readHandshake()
func (hs *clientHandshakeStateTLS13) utlsReadServerCertificate(msg any) (processedMsg any, err error) {
	for _, ext := range hs.uconn.Extensions {
		switch ext.(type) {
		case *UtlsCompressCertExtension:
			// Included Compressed Certificate extension
			if len(hs.uconn.certCompressionAlgs) > 0 {
				compressedCertMsg, ok := msg.(*utlsCompressedCertificateMsg)
				if ok {
					if err = transcriptMsg(compressedCertMsg, hs.transcript); err != nil {
						return nil, err
					}
					msg, err = hs.decompressCert(*compressedCertMsg)
					if err != nil {
						return nil, fmt.Errorf("tls: failed to decompress certificate message: %w", err)
					} else {
						return msg, nil
					}
				}
			}
		default:
			continue
		}
	}
	return nil, nil
}

// called by (*clientHandshakeStateTLS13).utlsReadServerCertificate() when UtlsCompressCertExtension is used
func (hs *clientHandshakeStateTLS13) decompressCert(m utlsCompressedCertificateMsg) (*certificateMsgTLS13, error) {
	var (
		decompressed io.Reader
		compressed   = bytes.NewReader(m.compressedCertificateMessage)
		c            = hs.c
	)

	// Check to see if the peer responded with an algorithm we advertised.
	supportedAlg := false
	for _, alg := range hs.uconn.certCompressionAlgs {
		if m.algorithm == uint16(alg) {
			supportedAlg = true
		}
	}
	if !supportedAlg {
		c.sendAlert(alertBadCertificate)
		return nil, fmt.Errorf("unadvertised algorithm (%d)", m.algorithm)
	}

	switch CertCompressionAlgo(m.algorithm) {
	case CertCompressionBrotli:
		decompressed = brotli.NewReader(compressed)

	case CertCompressionZlib:
		rc, err := zlib.NewReader(compressed)
		if err != nil {
			c.sendAlert(alertBadCertificate)
			return nil, fmt.Errorf("failed to open zlib reader: %w", err)
		}
		defer rc.Close()
		decompressed = rc

	case CertCompressionZstd:
		rc, err := zstd.NewReader(compressed)
		if err != nil {
			c.sendAlert(alertBadCertificate)
			return nil, fmt.Errorf("failed to open zstd reader: %w", err)
		}
		defer rc.Close()
		decompressed = rc

	default:
		c.sendAlert(alertBadCertificate)
		return nil, fmt.Errorf("unsupported algorithm (%d)", m.algorithm)
	}

	rawMsg := make([]byte, m.uncompressedLength+4) // +4 for message type and uint24 length field
	rawMsg[0] = typeCertificate
	rawMsg[1] = uint8(m.uncompressedLength >> 16)
	rawMsg[2] = uint8(m.uncompressedLength >> 8)
	rawMsg[3] = uint8(m.uncompressedLength)

	n, err := decompressed.Read(rawMsg[4:])
	if err != nil && !errors.Is(err, io.EOF) {
		c.sendAlert(alertBadCertificate)
		return nil, err
	}
	if n < len(rawMsg)-4 {
		// If, after decompression, the specified length does not match the actual length, the party
		// receiving the invalid message MUST abort the connection with the "bad_certificate" alert.
		// https://datatracker.ietf.org/doc/html/rfc8879#section-4
		c.sendAlert(alertBadCertificate)
		return nil, fmt.Errorf("decompressed len (%d) does not match specified len (%d)", n, m.uncompressedLength)
	}
	certMsg := new(certificateMsgTLS13)
	if !certMsg.unmarshal(rawMsg) {
		return nil, c.sendAlert(alertUnexpectedMessage)
	}
	return certMsg, nil
}

// to be called in (*clientHandshakeStateTLS13).handshake(),
// after hs.readServerFinished() and before hs.sendClientCertificate()
func (hs *clientHandshakeStateTLS13) serverFinishedReceived() error {
	if err := hs.sendClientEncryptedExtensions(); err != nil {
		return err
	}
	return nil
}

func (hs *clientHandshakeStateTLS13) sendClientEncryptedExtensions() error {
	c := hs.c
	clientEncryptedExtensions := new(utlsClientEncryptedExtensionsMsg)
	if c.utls.hasApplicationSettings {
		clientEncryptedExtensions.hasApplicationSettings = true
		clientEncryptedExtensions.applicationSettings = c.utls.localApplicationSettings
		if _, err := c.writeHandshakeRecord(clientEncryptedExtensions, hs.transcript); err != nil {
			return err
		}
	}

	return nil
}

func (hs *clientHandshakeStateTLS13) utlsReadServerParameters(encryptedExtensions *encryptedExtensionsMsg) error {
	hs.c.utls.hasApplicationSettings = encryptedExtensions.utls.hasApplicationSettings
	hs.c.utls.peerApplicationSettings = encryptedExtensions.utls.applicationSettings

	hs.c.utls.echRetryConfigs = encryptedExtensions.utls.echRetryConfigs

	if hs.c.utls.hasApplicationSettings {
		if hs.uconn.vers < VersionTLS13 {
			return errors.New("tls: server sent application settings at invalid version")
		}
		if len(hs.uconn.clientProtocol) == 0 {
			return errors.New("tls: server sent application settings without ALPN")
		}

		// Check if the ALPN selected by the server exists in the client's list.
		if alps, ok := hs.uconn.config.ApplicationSettings[hs.serverHello.alpnProtocol]; ok {
			hs.c.utls.localApplicationSettings = alps
		} else {
			// return errors.New("tls: server selected ALPN doesn't match a client ALPS")
			return nil // ignore if client doesn't have ALPS in use.
			// TODO: is this a issue or not?
		}
	}

	if len(hs.c.utls.echRetryConfigs) > 0 {
		if hs.uconn.vers < VersionTLS13 {
			return errors.New("tls: server sent ECH retry configs at invalid version")
		}

		// find ECH extension in ClientHello
		var echIncluded bool
		for _, ext := range hs.uconn.Extensions {
			if _, ok := ext.(ECHExtension); ok {
				echIncluded = true
			}
		}
		if !echIncluded {
			return errors.New("tls: server sent ECH retry configs without client sending ECH extension")
		}
	}

	return nil
}

// makeClientHelloForApplyPreset is the UTLS version of handshake_client.go/(*Conn)makeClientHello.
// This function is constructed by copying makeClientHello (including the UTLS modifications) and
// disabling key_share value and quic transport parameters.
func (c *Conn) makeClientHelloForApplyPreset() (*clientHelloMsg, *echContext, error) {
	config := c.config

	// [UTLS SECTION START]
	// if len(config.ServerName) == 0 && !config.InsecureSkipVerify {
	// 	return nil, nil, nil, errors.New("tls: either ServerName or InsecureSkipVerify must be specified in the tls.Config")
	// }
	if len(config.ServerName) == 0 && !config.InsecureSkipVerify && len(config.InsecureServerNameToVerify) == 0 {
		return nil, nil, errors.New("tls: at least one of ServerName, InsecureSkipVerify or InsecureServerNameToVerify must be specified in the tls.Config")
	}
	// [UTLS SECTION END]

	nextProtosLength := 0
	for _, proto := range config.NextProtos {
		if l := len(proto); l == 0 || l > 255 {
			return nil, nil, errors.New("tls: invalid NextProtos value")
		} else {
			nextProtosLength += 1 + l
		}
	}
	if nextProtosLength > 0xffff {
		return nil, nil, errors.New("tls: NextProtos values too large")
	}

	supportedVersions := config.supportedVersions(roleClient)
	if len(supportedVersions) == 0 {
		return nil, nil, errors.New("tls: no supported versions satisfy MinVersion and MaxVersion")
	}
	maxVersion := config.maxSupportedVersion(roleClient)

	hello := &clientHelloMsg{
		vers:                         maxVersion,
		compressionMethods:           []uint8{compressionNone},
		random:                       make([]byte, 32),
		extendedMasterSecret:         true,
		ocspStapling:                 true,
		scts:                         true,
		serverName:                   hostnameInSNI(config.ServerName),
		supportedCurves:              config.curvePreferences(maxVersion),
		supportedPoints:              []uint8{pointFormatUncompressed},
		secureRenegotiationSupported: true,
		alpnProtocols:                config.NextProtos,
		supportedVersions:            supportedVersions,
	}

	// The version at the beginning of the ClientHello was capped at TLS 1.2
	// for compatibility reasons. The supported_versions extension is used
	// to negotiate versions now. See RFC 8446, Section 4.2.1.
	if hello.vers > VersionTLS12 {
		hello.vers = VersionTLS12
	}

	if c.handshakes > 0 {
		hello.secureRenegotiation = c.clientFinished[:]
	}

	preferenceOrder := cipherSuitesPreferenceOrder
	if !hasAESGCMHardwareSupport {
		preferenceOrder = cipherSuitesPreferenceOrderNoAES
	}
	configCipherSuites := config.cipherSuites()
	hello.cipherSuites = make([]uint16, 0, len(configCipherSuites))

	for _, suiteId := range preferenceOrder {
		suite := mutualCipherSuite(configCipherSuites, suiteId)
		if suite == nil {
			continue
		}
		// Don't advertise TLS 1.2-only cipher suites unless
		// we're attempting TLS 1.2.
		if maxVersion < VersionTLS12 && suite.flags&suiteTLS12 != 0 {
			continue
		}
		hello.cipherSuites = append(hello.cipherSuites, suiteId)
	}

	_, err := io.ReadFull(config.rand(), hello.random)
	if err != nil {
		return nil, nil, errors.New("tls: short read from Rand: " + err.Error())
	}

	// A random session ID is used to detect when the server accepted a ticket
	// and is resuming a session (see RFC 5077). In TLS 1.3, it's always set as
	// a compatibility measure (see RFC 8446, Section 4.1.2).
	//
	// The session ID is not set for QUIC connections (see RFC 9001, Section 8.4).
	if c.quic == nil {
		hello.sessionId = make([]byte, 32)
		if _, err := io.ReadFull(config.rand(), hello.sessionId); err != nil {
			return nil, nil, errors.New("tls: short read from Rand: " + err.Error())
		}
	}

	if maxVersion >= VersionTLS12 {
		hello.supportedSignatureAlgorithms = supportedSignatureAlgorithms()
	}
	if testingOnlyForceClientHelloSignatureAlgorithms != nil {
		hello.supportedSignatureAlgorithms = testingOnlyForceClientHelloSignatureAlgorithms
	}

	// [UTLS]
	// var keyShareKeys *keySharePrivateKeys

	if hello.supportedVersions[0] == VersionTLS13 {
		// Reset the list of ciphers when the client only supports TLS 1.3.
		if len(hello.supportedVersions) == 1 {
			hello.cipherSuites = nil
		}
		if hasAESGCMHardwareSupport {
			hello.cipherSuites = append(hello.cipherSuites, defaultCipherSuitesTLS13...)
		} else {
			hello.cipherSuites = append(hello.cipherSuites, defaultCipherSuitesTLS13NoAES...)
		}

		// [UTLS] Disabled for makeClientHelloForApplyPreset, check u_parrots.go/(*UConn)ApplyPreset for key_share extension values.
		/*
			curveID := config.curvePreferences(maxVersion)[0]

			// [UTLS SECTION BEGIN]
			// keyShareKeys type has been modified to allow for more than one curve.
			// The (key share) changes to below are to accommodate this change.
			// keyShareKeys = &keySharePrivateKeys{curveID: curveID}
			keyShareKeys = NewKeySharePrivateKeys()
			// [UTLS SECTION END]

			if curveID == x25519Kyber768Draft00 {
				// [UTLS SECTION BEGIN]
				// keyShareKeys.ecdhe, err = generateECDHEKey(config.rand(), X25519)
				ecdheKey, err := generateECDHEKey(config.rand(), X25519)
				// [UTLS SECTION END]
				if err != nil {
					return nil, nil, nil, err
				}

				// [UTLS SECTION BEGIN]
				// UTLS changes to keyShareKeys explicitly specify the curveID for the key shares.
				// Therefore, we need to set the (reused) ecdheKey for both standard X25519
				// and the hybrid x25519Kyber768Draft00.
				if err := keyShareKeys.setEcdheKey(X25519, ecdheKey); err != nil {
					return nil, nil, nil, err
				}
				if err := keyShareKeys.setEcdheKey(curveID, ecdheKey); err != nil {
					return nil, nil, nil, err
				}
				// [UTLS SECTION END]

				seed := make([]byte, mlkem768.SeedSize)
				if _, err := io.ReadFull(config.rand(), seed); err != nil {
					return nil, nil, nil, err
				}
				// [UTLS SECTION BEGIN]
				// keyShareKeys.kyber, err = mlkem768.NewKeyFromSeed(seed)
				kyberKey, err := mlkem768.NewKeyFromSeed(seed)
				if err != nil {
					return nil, nil, nil, err
				}
				if err := keyShareKeys.setKyberKey(curveID, kyberKey); err != nil {
					return nil, nil, nil, err
				}
				// [UTLS SECTION END]

				// For draft-tls-westerbaan-xyber768d00-03, we send both a hybrid
				// and a standard X25519 key share, since most servers will only
				// support the latter. We reuse the same X25519 ephemeral key for
				// both, as allowed by draft-ietf-tls-hybrid-design-09, Section 3.2.

				// [UTLS SECTION BEGIN]
				// hello.keyShares = []keyShare{
				// 	{group: x25519Kyber768Draft00, data: append(keyShareKeys.ecdhe.PublicKey().Bytes(),
				// 		keyShareKeys.kyber.EncapsulationKey()...)},
				// 	{group: X25519, data: keyShareKeys.ecdhe.PublicKey().Bytes()},
				// }
				hello.keyShares = []keyShare{
					{group: x25519Kyber768Draft00, data: append(keyShareKeys.ecdhe[curveID].PublicKey().Bytes(),
						keyShareKeys.kyber[curveID].EncapsulationKey()...)},
					{group: X25519, data: keyShareKeys.ecdhe[X25519].PublicKey().Bytes()},
				}
				// [UTLS SECTION END]
			} else {
				if _, ok := curveForCurveID(curveID); !ok {
					return nil, nil, nil, errors.New("tls: CurvePreferences includes unsupported curve")
				}

				// [UTLS SECTION BEGIN]
				// keyShareKeys.ecdhe, err = generateECDHEKey(config.rand(), curveID)
				keyShareKeys.ecdhe[curveID], err = generateECDHEKey(config.rand(), curveID)
				// [UTLS SECTION END]
				if err != nil {
					return nil, nil, nil, err
				}
				// [UTLS SECTION BEGIN]
				// hello.keyShares = []keyShare{{group: curveID, data: keyShareKeys.ecdhe.PublicKey().Bytes()}}
				hello.keyShares = []keyShare{{group: curveID, data: keyShareKeys.ecdhe[curveID].PublicKey().Bytes()}}
				// [UTLS SECTION END]
			}
		*/
	}

	// [UTLS] Disabled for makeClientHelloForApplyPreset, since it is not ready yet.
	/*
		if c.quic != nil {
			p, err := c.quicGetTransportParameters()
			if err != nil {
				return nil, nil, nil, err
			}
			if p == nil {
				p = []byte{}
			}
			hello.quicTransportParameters = p
		}
	*/

	var ech *echContext
	if c.config.EncryptedClientHelloConfigList != nil {
		if c.config.MinVersion != 0 && c.config.MinVersion < VersionTLS13 {
			return nil, nil, errors.New("tls: MinVersion must be >= VersionTLS13 if EncryptedClientHelloConfigList is populated")
		}
		if c.config.MaxVersion != 0 && c.config.MaxVersion <= VersionTLS12 {
			return nil, nil, errors.New("tls: MaxVersion must be >= VersionTLS13 if EncryptedClientHelloConfigList is populated")
		}
		echConfigs, err := parseECHConfigList(c.config.EncryptedClientHelloConfigList)
		if err != nil {
			return nil, nil, err
		}
		echConfig := pickECHConfig(echConfigs)
		if echConfig == nil {
			return nil, nil, errors.New("tls: EncryptedClientHelloConfigList contains no valid configs")
		}
		ech = &echContext{config: echConfig}
		hello.encryptedClientHello = []byte{1} // indicate inner hello
		// We need to explicitly set these 1.2 fields to nil, as we do not
		// marshal them when encoding the inner hello, otherwise transcripts
		// will later mismatch.
		hello.supportedPoints = nil
		hello.ticketSupported = false
		hello.secureRenegotiationSupported = false
		hello.extendedMasterSecret = false

		echPK, err := hpke.ParseHPKEPublicKey(ech.config.KemID, ech.config.PublicKey)
		if err != nil {
			return nil, nil, err
		}
		suite, err := pickECHCipherSuite(ech.config.SymmetricCipherSuite)
		if err != nil {
			return nil, nil, err
		}
		ech.kdfID, ech.aeadID = suite.KDFID, suite.AEADID
		info := append([]byte("tls ech\x00"), ech.config.raw...)
		ech.encapsulatedKey, ech.hpkeContext, err = hpke.SetupSender(ech.config.KemID, suite.KDFID, suite.AEADID, echPK, info)
		if err != nil {
			return nil, nil, err
		}
	}

	return hello, ech, nil
}
