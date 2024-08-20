// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package selfsign is a test helper that generates self signed certificate.
package selfsign

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"time"
)

var errInvalidPrivateKey = errors.New("selfsign: invalid private key type")

// GenerateSelfSigned creates a self-signed certificate
func GenerateSelfSigned() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	return SelfSign(priv)
}

// GenerateSelfSignedWithDNS creates a self-signed certificate
func GenerateSelfSignedWithDNS(cn string, sans ...string) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	return WithDNS(priv, cn, sans...)
}

// SelfSign creates a self-signed certificate from a elliptic curve key
func SelfSign(key crypto.PrivateKey) (tls.Certificate, error) {
	return WithDNS(key, "self-signed cert")
}

// WithDNS creates a self-signed certificate from a elliptic curve key
func WithDNS(key crypto.PrivateKey, cn string, sans ...string) (tls.Certificate, error) {
	var (
		pubKey    crypto.PublicKey
		maxBigInt = new(big.Int) // Max random value, a 130-bits integer, i.e 2^130 - 1
	)

	switch k := key.(type) {
	case ed25519.PrivateKey:
		pubKey = k.Public()
	case *ecdsa.PrivateKey:
		pubKey = k.Public()
	case *rsa.PrivateKey:
		pubKey = k.Public()
	default:
		return tls.Certificate{}, errInvalidPrivateKey
	}

	/* #nosec */
	maxBigInt.Exp(big.NewInt(2), big.NewInt(130), nil).Sub(maxBigInt, big.NewInt(1))
	/* #nosec */
	serialNumber, err := rand.Int(rand.Reader, maxBigInt)
	if err != nil {
		return tls.Certificate{}, err
	}

	names := []string{cn}
	names = append(names, sans...)

	keyUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
	if _, isRSA := key.(*rsa.PrivateKey); isRSA {
		keyUsage |= x509.KeyUsageKeyEncipherment
	}

	template := x509.Certificate{
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
		NotBefore:             time.Now(),
		KeyUsage:              keyUsage,
		NotAfter:              time.Now().AddDate(0, 1, 0),
		SerialNumber:          serialNumber,
		Version:               2,
		IsCA:                  true,
		DNSNames:              names,
		Subject: pkix.Name{
			CommonName: cn,
		},
	}

	raw, err := x509.CreateCertificate(rand.Reader, &template, &template, pubKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	leaf, err := x509.ParseCertificate(raw)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{raw},
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
}
