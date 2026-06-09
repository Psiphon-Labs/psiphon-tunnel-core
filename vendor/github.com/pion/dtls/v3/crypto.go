// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"math/big"
	"time"

	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/crypto/hash"
	"github.com/pion/dtls/v3/pkg/crypto/signature"
	"github.com/pion/dtls/v3/pkg/crypto/signaturehash"
)

type ecdsaSignature struct {
	R, S *big.Int
}

func valueKeyMessage(clientRandom, serverRandom, publicKey []byte, namedCurve elliptic.Curve) []byte {
	serverECDHParams := make([]byte, 4)
	serverECDHParams[0] = 3 // named curve
	binary.BigEndian.PutUint16(serverECDHParams[1:], uint16(namedCurve))
	serverECDHParams[3] = byte(len(publicKey))

	plaintext := []byte{}
	plaintext = append(plaintext, clientRandom...)
	plaintext = append(plaintext, serverRandom...)
	plaintext = append(plaintext, serverECDHParams...)
	plaintext = append(plaintext, publicKey...)

	return plaintext
}

// validateSignatureAlgOID validates that the signature scheme matches the
// certificate's public key algorithm OID. This is required by RFC 8446 Section 4.2.3:
// - RSA_PSS_RSAE requires rsaEncryption OID
// - RSA_PSS_PSS requires id-RSASSA-PSS OID
//
// Note: returns nil if the given signature.Algorithm is not PSS based.
//
// https://www.rfc-editor.org/rfc/rfc8446#section-4.2.3
func validateSignatureAlgOID(cert *x509.Certificate, sigAlg signature.Algorithm) error {
	if !sigAlg.IsPSS() {
		return nil
	}

	// Get the certificate's public key algorithm OID from the raw certificate
	// We need to parse the SubjectPublicKeyInfo to get the algorithm OID
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &spki); err != nil {
		return err
	}

	certOID := spki.Algorithm.Algorithm

	switch sigAlg {
	// Check RSAE variants (0x0804-0x0806) require rsaEncryption OID
	case signature.RSA_PSS_RSAE_SHA256, signature.RSA_PSS_RSAE_SHA384, signature.RSA_PSS_RSAE_SHA512:
		oidPublicKeyRSA := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1} // OID: rsaEncryption
		if !certOID.Equal(oidPublicKeyRSA) {
			return errInvalidCertificateOID
		}

		return nil

	// Check PSS variants (0x0809-0x080b) require id-RSASSA-PSS OID
	case signature.RSA_PSS_PSS_SHA256, signature.RSA_PSS_PSS_SHA384, signature.RSA_PSS_PSS_SHA512:
		oidPublicKeyRSAPSS := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10} // OID: id-RSASSA-PSS
		if !certOID.Equal(oidPublicKeyRSAPSS) {
			return errInvalidCertificateOID
		}

		return nil

	default:
		return nil
	}
}

// If the client provided a "signature_algorithms" extension, then all
// certificates provided by the server MUST be signed by a
// hash/signature algorithm pair that appears in that extension
//
// https://tools.ietf.org/html/rfc5246#section-7.4.2
func generateKeySignature(
	clientRandom, serverRandom, publicKey []byte,
	namedCurve elliptic.Curve,
	signer crypto.Signer,
	hashAlgorithm hash.Algorithm,
	signatureAlgorithm signature.Algorithm,
) ([]byte, error) {
	msg := valueKeyMessage(clientRandom, serverRandom, publicKey, namedCurve)
	switch signer.Public().(type) {
	case ed25519.PublicKey:
		// https://crypto.stackexchange.com/a/55483
		return signer.Sign(rand.Reader, msg, crypto.Hash(0))
	case *ecdsa.PublicKey:
		hashed := hashAlgorithm.Digest(msg)

		return signer.Sign(rand.Reader, hashed, hashAlgorithm.CryptoHash())
	case *rsa.PublicKey:
		hashed := hashAlgorithm.Digest(msg)

		// Use RSA-PSS if the signature algorithm is PSS
		if signatureAlgorithm.IsPSS() {
			pssOpts := &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       hashAlgorithm.CryptoHash(),
			}

			return signer.Sign(rand.Reader, hashed, pssOpts)
		}

		// Otherwise use PKCS#1 v1.5
		return signer.Sign(rand.Reader, hashed, hashAlgorithm.CryptoHash())
	}

	return nil, errKeySignatureGenerateUnimplemented
}

//nolint:dupl,cyclop
func verifyKeySignature(
	message, remoteKeySignature []byte,
	hashAlgorithm hash.Algorithm,
	signatureAlgorithm signature.Algorithm,
	rawCertificates [][]byte,
) error {
	if len(rawCertificates) == 0 {
		return errLengthMismatch
	}
	certificate, err := x509.ParseCertificate(rawCertificates[0])
	if err != nil {
		return err
	}

	// Validate that the signature algorithm matches the certificate's OID
	if err := validateSignatureAlgOID(certificate, signatureAlgorithm); err != nil {
		return err
	}

	switch pubKey := certificate.PublicKey.(type) {
	case ed25519.PublicKey:
		if ok := ed25519.Verify(pubKey, message, remoteKeySignature); !ok {
			return errKeySignatureMismatch
		}

		return nil
	case *ecdsa.PublicKey:
		ecdsaSig := &ecdsaSignature{}
		if _, err := asn1.Unmarshal(remoteKeySignature, ecdsaSig); err != nil {
			return err
		}
		if ecdsaSig.R.Sign() <= 0 || ecdsaSig.S.Sign() <= 0 {
			return errInvalidECDSASignature
		}
		hashed := hashAlgorithm.Digest(message)
		if !ecdsa.Verify(pubKey, hashed, ecdsaSig.R, ecdsaSig.S) {
			return errKeySignatureMismatch
		}

		return nil
	case *rsa.PublicKey:
		hashed := hashAlgorithm.Digest(message)

		// Use RSA-PSS verification if the signature algorithm is PSS
		if signatureAlgorithm.IsPSS() {
			pssOpts := &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       hashAlgorithm.CryptoHash(),
			}
			if err := rsa.VerifyPSS(pubKey, hashAlgorithm.CryptoHash(), hashed, remoteKeySignature, pssOpts); err != nil {
				return errKeySignatureMismatch
			}

			return nil
		}

		// Otherwise use PKCS#1 v1.5
		if rsa.VerifyPKCS1v15(pubKey, hashAlgorithm.CryptoHash(), hashed, remoteKeySignature) != nil {
			return errKeySignatureMismatch
		}

		return nil
	}

	return errKeySignatureVerifyUnimplemented
}

// If the server has sent a CertificateRequest message, the client MUST send the Certificate
// message.  The ClientKeyExchange message is now sent, and the content
// of that message will depend on the public key algorithm selected
// between the ClientHello and the ServerHello.  If the client has sent
// a certificate with signing ability, a digitally-signed
// CertificateVerify message is sent to explicitly verify possession of
// the private key in the certificate.
// https://tools.ietf.org/html/rfc5246#section-7.3
func generateCertificateVerify(
	handshakeBodies []byte,
	signer crypto.Signer,
	hashAlgorithm hash.Algorithm,
	signatureAlgorithm signature.Algorithm,
) ([]byte, error) {
	if _, ok := signer.Public().(ed25519.PublicKey); ok {
		// https://pkg.go.dev/crypto/ed25519#PrivateKey.Sign
		// Sign signs the given message with priv. Ed25519 performs two passes over
		// messages to be signed and therefore cannot handle pre-hashed messages.
		return signer.Sign(rand.Reader, handshakeBodies, crypto.Hash(0))
	}

	hashed := hashAlgorithm.Digest(handshakeBodies)

	switch signer.Public().(type) {
	case *ecdsa.PublicKey:
		return signer.Sign(rand.Reader, hashed, hashAlgorithm.CryptoHash())
	case *rsa.PublicKey:
		// Use RSA-PSS if the signature algorithm is PSS
		if signatureAlgorithm.IsPSS() {
			pssOpts := &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       hashAlgorithm.CryptoHash(),
			}

			return signer.Sign(rand.Reader, hashed, pssOpts)
		}

		// Otherwise use PKCS#1 v1.5
		return signer.Sign(rand.Reader, hashed, hashAlgorithm.CryptoHash())
	}

	return nil, errInvalidSignatureAlgorithm
}

//nolint:dupl,cyclop
func verifyCertificateVerify(
	handshakeBodies []byte,
	hashAlgorithm hash.Algorithm,
	signatureAlgorithm signature.Algorithm,
	remoteKeySignature []byte,
	rawCertificates [][]byte,
) error {
	if len(rawCertificates) == 0 {
		return errLengthMismatch
	}
	certificate, err := x509.ParseCertificate(rawCertificates[0])
	if err != nil {
		return err
	}

	// Validate that the signature algorithm matches the certificate's OID
	if err := validateSignatureAlgOID(certificate, signatureAlgorithm); err != nil {
		return err
	}

	switch pubKey := certificate.PublicKey.(type) {
	case ed25519.PublicKey:
		if ok := ed25519.Verify(pubKey, handshakeBodies, remoteKeySignature); !ok {
			return errKeySignatureMismatch
		}

		return nil
	case *ecdsa.PublicKey:
		ecdsaSig := &ecdsaSignature{}
		if _, err := asn1.Unmarshal(remoteKeySignature, ecdsaSig); err != nil {
			return err
		}
		if ecdsaSig.R.Sign() <= 0 || ecdsaSig.S.Sign() <= 0 {
			return errInvalidECDSASignature
		}
		hash := hashAlgorithm.Digest(handshakeBodies)
		if !ecdsa.Verify(pubKey, hash, ecdsaSig.R, ecdsaSig.S) {
			return errKeySignatureMismatch
		}

		return nil
	case *rsa.PublicKey:
		hash := hashAlgorithm.Digest(handshakeBodies)

		// Use RSA-PSS verification if the signature algorithm is PSS
		if signatureAlgorithm.IsPSS() {
			pssOpts := &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       hashAlgorithm.CryptoHash(),
			}
			if err := rsa.VerifyPSS(pubKey, hashAlgorithm.CryptoHash(), hash, remoteKeySignature, pssOpts); err != nil {
				return errKeySignatureMismatch
			}

			return nil
		}

		// Otherwise use PKCS#1 v1.5
		if rsa.VerifyPKCS1v15(pubKey, hashAlgorithm.CryptoHash(), hash, remoteKeySignature) != nil {
			return errKeySignatureMismatch
		}

		return nil
	}

	return errKeySignatureVerifyUnimplemented
}

func loadCerts(rawCertificates [][]byte) ([]*x509.Certificate, error) {
	if len(rawCertificates) == 0 {
		return nil, errLengthMismatch
	}

	certs := make([]*x509.Certificate, 0, len(rawCertificates))
	for _, rawCert := range rawCertificates {
		cert, err := x509.ParseCertificate(rawCert)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}

	return certs, nil
}

func verifyClientCert(
	rawCertificates [][]byte,
	roots *x509.CertPool,
	certSignatureSchemes []signaturehash.Algorithm,
) (chains [][]*x509.Certificate, err error) {
	certificate, err := loadCerts(rawCertificates)
	if err != nil {
		return nil, err
	}
	intermediateCAPool := x509.NewCertPool()
	for _, cert := range certificate[1:] {
		intermediateCAPool.AddCert(cert)
	}
	opts := x509.VerifyOptions{
		Roots:         roots,
		CurrentTime:   time.Now(),
		Intermediates: intermediateCAPool,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	chains, err = certificate[0].Verify(opts)
	if err != nil {
		return nil, err
	}

	// Validate certificate signature algorithms if specified.
	// At least one chain must use only allowed signature algorithms.
	if len(certSignatureSchemes) > 0 && len(chains) > 0 {
		var validChainFound bool
		for _, chain := range chains {
			if err := validateCertificateSignatureAlgorithms(chain, certSignatureSchemes); err == nil {
				validChainFound = true

				break
			}
		}
		if !validChainFound {
			return nil, errInvalidCertificateSignatureAlgorithm
		}
	}

	return chains, nil
}

func verifyServerCert(
	rawCertificates [][]byte,
	roots *x509.CertPool,
	serverName string,
	certSignatureSchemes []signaturehash.Algorithm,
) (chains [][]*x509.Certificate, err error) {
	certificate, err := loadCerts(rawCertificates)
	if err != nil {
		return nil, err
	}
	intermediateCAPool := x509.NewCertPool()
	for _, cert := range certificate[1:] {
		intermediateCAPool.AddCert(cert)
	}
	opts := x509.VerifyOptions{
		Roots:         roots,
		CurrentTime:   time.Now(),
		DNSName:       serverName,
		Intermediates: intermediateCAPool,
	}

	chains, err = certificate[0].Verify(opts)
	if err != nil {
		return nil, err
	}

	// Validate certificate signature algorithms if specified.
	// At least one chain must use only allowed signature algorithms.
	if len(certSignatureSchemes) > 0 && len(chains) > 0 {
		var validChainFound bool
		for _, chain := range chains {
			if err := validateCertificateSignatureAlgorithms(chain, certSignatureSchemes); err == nil {
				validChainFound = true

				break
			}
		}
		if !validChainFound {
			return nil, errInvalidCertificateSignatureAlgorithm
		}
	}

	return chains, nil
}

// validateCertificateSignatureAlgorithms validates that all certificates in the chain
// use signature algorithms that are in the allowed list. This implements the
// signature_algorithms_cert extension validation per RFC 8446 Section 4.2.3.
func validateCertificateSignatureAlgorithms(
	certs []*x509.Certificate,
	allowedAlgorithms []signaturehash.Algorithm,
) error {
	if len(allowedAlgorithms) == 0 {
		// No restrictions specified
		return nil
	}

	// Validate each certificate's signature algorithm (except the root, which we trust)
	for i := 0; i < len(certs)-1; i++ {
		cert := certs[i]
		certAlg, err := signaturehash.FromCertificate(cert)
		if err != nil {
			return err
		}

		// Check if this algorithm is in the allowed list
		found := false
		for _, allowed := range allowedAlgorithms {
			if certAlg.Hash == allowed.Hash && certAlg.Signature == allowed.Signature {
				found = true

				break
			}
		}

		if !found {
			return errInvalidCertificateSignatureAlgorithm
		}
	}

	return nil
}
