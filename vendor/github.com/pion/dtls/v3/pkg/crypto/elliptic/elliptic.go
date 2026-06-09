// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package elliptic provides elliptic curve cryptography for DTLS
package elliptic

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
)

var errInvalidNamedCurve = errors.New("invalid named curve")

// CurvePointFormat is used to represent the IANA registered curve points
//
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-9
type CurvePointFormat byte

// CurvePointFormat enums.
const (
	CurvePointFormatUncompressed CurvePointFormat = 0
)

// Keypair is a Curve with a Private/Public Keypair.
type Keypair struct {
	Curve      Curve
	PublicKey  []byte
	PrivateKey []byte
}

// CurveType is used to represent the IANA registered curve types for TLS
//
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-10
type CurveType byte

// CurveType enums.
const (
	CurveTypeNamedCurve CurveType = 0x03
)

// CurveTypes returns all known curves.
func CurveTypes() map[CurveType]struct{} {
	return map[CurveType]struct{}{
		CurveTypeNamedCurve: {},
	}
}

// Curve is used to represent the IANA registered curves for TLS
//
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-8
type Curve uint16

// Curve enums.
const (
	P256   Curve = 0x0017
	P384   Curve = 0x0018
	X25519 Curve = 0x001d
	// X25519MLKEM768
	// https://pkg.go.dev/crypto/internal/fips140/mlkem
	// https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/
	// https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/
)

func (c Curve) String() string {
	switch c {
	case P256:
		return "P-256"
	case P384:
		return "P-384"
	case X25519:
		return "X25519"
	}

	return fmt.Sprintf("%#x", uint16(c))
}

// Curves returns all curves we implement.
func Curves() map[Curve]bool {
	return map[Curve]bool{
		X25519: true,
		P256:   true,
		P384:   true,
	}
}

// GenerateKeypair generates a keypair for the given Curve.
func GenerateKeypair(curve Curve) (*Keypair, error) {
	ec, err := curve.toECDH()
	if err != nil {
		return nil, err
	}

	sk, err := ec.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	pk := sk.PublicKey()

	return &Keypair{
		Curve:      curve,
		PublicKey:  pk.Bytes(), // NIST: SEC1 uncompressed (04||X||Y); X25519: 32 bytes
		PrivateKey: sk.Bytes(), // Scalar suitable for ecdh.NewPrivateKey
	}, nil
}

// toECDH returns the crypto/ecdh curve for our enum.
func (c Curve) toECDH() (ecdh.Curve, error) {
	switch c {
	case X25519:
		return ecdh.X25519(), nil
	case P256:
		return ecdh.P256(), nil
	case P384:
		return ecdh.P384(), nil
	default:
		return nil, errInvalidNamedCurve
	}
}
