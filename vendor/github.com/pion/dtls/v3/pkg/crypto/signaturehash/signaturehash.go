// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package signaturehash provides the SignatureHashAlgorithm as defined in TLS 1.2
package signaturehash

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"github.com/pion/dtls/v3/pkg/crypto/hash"
	"github.com/pion/dtls/v3/pkg/crypto/signature"
)

// Algorithm is a signature/hash algorithm pairs which may be used in
// digital signatures.
//
// https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1
type Algorithm struct {
	Hash      hash.Algorithm
	Signature signature.Algorithm
}

// Algorithms returns signature algorithms compatible with DTLS 1.2 / TLS 1.2.
// This excludes TLS 1.3-specific schemes like RSA-PSS to ensure compatibility
// with implementations like OpenSSL that don't recognize TLS 1.3 signature
// algorithm IDs in DTLS 1.2 handshakes.
//
// IMPORTANT: order in this slice determines priority used by SelectSignatureScheme.
//
// Order follows industry standard preference (ECDSA-first) as used by OpenSSL,
// BoringSSL, Firefox, Chrome, and other major TLS implementations.
func Algorithms() []Algorithm {
	return []Algorithm{
		// ECDSA schemes (modern, efficient - industry standard preference)
		{hash.SHA256, signature.ECDSA},
		{hash.SHA384, signature.ECDSA},
		{hash.SHA512, signature.ECDSA},

		// Ed25519
		{hash.Ed25519, signature.Ed25519},

		// RSA PKCS#1 v1.5 schemes (legacy, DTLS 1.2)
		{hash.SHA256, signature.RSA},
		{hash.SHA384, signature.RSA},
		{hash.SHA512, signature.RSA},
	}
}

// SelectSignatureScheme returns most preferred and compatible scheme for DTLS <= 1.2.
func SelectSignatureScheme(sigs []Algorithm, privateKey crypto.PrivateKey) (Algorithm, error) {
	return selectSignatureScheme13(sigs, privateKey, false)
}

// SelectSignatureScheme13 returns most preferred and compatible scheme for DTLS 1.3.
func SelectSignatureScheme13(sigs []Algorithm, privateKey crypto.PrivateKey) (Algorithm, error) {
	return selectSignatureScheme13(sigs, privateKey, true)
}

// isCompatible checks that given private key is compatible with the signature scheme.
func (a *Algorithm) isCompatible(signer crypto.Signer) bool {
	switch signer.Public().(type) {
	case ed25519.PublicKey:
		return a.Signature == signature.Ed25519
	case *ecdsa.PublicKey:
		return a.Signature == signature.ECDSA
	case *rsa.PublicKey:
		// RSA keys are compatible with both PKCS#1 v1.5 and PSS signatures
		return a.Signature == signature.RSA || a.Signature.IsPSS()
	default:
		return false
	}
}

// ParseSignatureSchemes translates []tls.SignatureScheme to []signatureHashAlgorithm.
// It returns default signature scheme list if no SignatureScheme is passed.
// This function handles both TLS 1.2 byte-split encoding and TLS 1.3 PSS full uint16 schemes.
//
// For DTLS 1.2 / TLS 1.2, this returns Algorithms() which excludes TLS 1.3-specific
// schemes like RSA-PSS for compatibility with implementations like OpenSSL.
// When DTLS 1.3 is implemented, use Algorithms13() or create ParseSignatureSchemes13().
func ParseSignatureSchemes(sigs []tls.SignatureScheme, insecureHashes bool) ([]Algorithm, error) {
	if len(sigs) == 0 {
		return Algorithms(), nil
	}
	out := []Algorithm{}
	for _, ss := range sigs {
		hashAlg, sigAlg, err := parseSignatureScheme(ss)
		if err != nil {
			return nil, err
		}

		if hashAlg.Insecure() && !insecureHashes {
			continue
		}

		out = append(out, Algorithm{
			Hash:      hashAlg,
			Signature: sigAlg,
		})
	}

	if len(out) == 0 {
		return nil, errNoAvailableSignatureSchemes
	}

	return out, nil
}

// FromCertificate maps x509.SignatureAlgorithm to the corresponding Algorithm type.
func FromCertificate(cert *x509.Certificate) (Algorithm, error) { //nolint:cyclop
	var hashAlg hash.Algorithm
	var sigAlg signature.Algorithm

	switch cert.SignatureAlgorithm {
	case x509.SHA256WithRSA, x509.SHA256WithRSAPSS:
		hashAlg = hash.SHA256
		sigAlg = signature.RSA
	case x509.SHA384WithRSA, x509.SHA384WithRSAPSS:
		hashAlg = hash.SHA384
		sigAlg = signature.RSA
	case x509.SHA512WithRSA, x509.SHA512WithRSAPSS:
		hashAlg = hash.SHA512
		sigAlg = signature.RSA
	case x509.ECDSAWithSHA256:
		hashAlg = hash.SHA256
		sigAlg = signature.ECDSA
	case x509.ECDSAWithSHA384:
		hashAlg = hash.SHA384
		sigAlg = signature.ECDSA
	case x509.ECDSAWithSHA512:
		hashAlg = hash.SHA512
		sigAlg = signature.ECDSA
	case x509.PureEd25519:
		hashAlg = hash.None // Ed25519 doesn't use a separate hash
		sigAlg = signature.Ed25519
	case x509.SHA1WithRSA:
		hashAlg = hash.SHA1
		sigAlg = signature.RSA
	case x509.ECDSAWithSHA1:
		hashAlg = hash.SHA1
		sigAlg = signature.ECDSA
	default:
		return Algorithm{}, errInvalidSignatureAlgorithm
	}

	return Algorithm{Hash: hashAlg, Signature: sigAlg}, nil
}

// parseSignatureScheme translates a tls.SignatureScheme to a hash.Algorithm
// and signature.Algorithm. It returns default signature scheme list if no
// SignatureScheme is passed. This function handles both TLS 1.2 byte-split
// encoding and TLS 1.3 PSS full uint16 schemes.
func parseSignatureScheme(sigScheme tls.SignatureScheme) (hash.Algorithm, signature.Algorithm, error) {
	var sigAlg signature.Algorithm
	var hashAlg hash.Algorithm

	if signature.Algorithm(sigScheme).IsPSS() {
		// TLS 1.3 PSS scheme - full uint16 is the signature algorithm
		sigAlg = signature.Algorithm(sigScheme)
		hashAlg = hash.ExtractHashFromPSS(uint16(sigScheme))
		if hashAlg == hash.None {
			return 0, 0, fmt.Errorf("SignatureScheme %04x: %w", sigScheme, errInvalidHashAlgorithm)
		}
	} else {
		// TLS 1.2 style - split into hash (high byte) and signature (low byte)
		sigAlg = signature.Algorithm(sigScheme & 0xFF)
		hashAlg = hash.Algorithm(sigScheme >> 8)
	}

	// Validate signature algorithm
	if _, ok := signature.Algorithms()[sigAlg]; !ok {
		return 0, 0, fmt.Errorf("SignatureScheme %04x: %w", sigScheme, errInvalidSignatureAlgorithm)
	}

	// Validate hash algorithm
	if _, ok := hash.Algorithms()[hashAlg]; !ok || (ok && hashAlg == hash.None) {
		return 0, 0, fmt.Errorf("SignatureScheme %04x: %w", sigScheme, errInvalidHashAlgorithm)
	}

	return hashAlg, sigAlg, nil
}
