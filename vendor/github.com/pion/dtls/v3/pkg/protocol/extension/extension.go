// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package extension implements the extension values in the ClientHello/ServerHello
package extension

import (
	"encoding/binary"

	"github.com/pion/dtls/v3/pkg/crypto/hash"
	"github.com/pion/dtls/v3/pkg/crypto/signature"
)

// TypeValue is the 2 byte value for a TLS Extension as registered in the IANA
//
// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
type TypeValue uint16

// TypeValue constants.
const (
	ServerNameTypeValue TypeValue = 0
	// In DTLS 1.3, this extension in renamed to "supported_groups".
	SupportedEllipticCurvesTypeValue      TypeValue = 10
	SupportedPointFormatsTypeValue        TypeValue = 11
	SupportedSignatureAlgorithmsTypeValue TypeValue = 13
	UseSRTPTypeValue                      TypeValue = 14
	ALPNTypeValue                         TypeValue = 16
	UseExtendedMasterSecretTypeValue      TypeValue = 23
	PreSharedKeyValue                     TypeValue = 41
	SupportedVersionsTypeValue            TypeValue = 43
	CookieTypeValue                       TypeValue = 44
	PskKeyExchangeModesTypeValue          TypeValue = 45
	SignatureAlgorithmsCertTypeValue      TypeValue = 50
	KeyShareTypeValue                     TypeValue = 51
	ConnectionIDTypeValue                 TypeValue = 54
	RenegotiationInfoTypeValue            TypeValue = 65281
)

// Extension represents a single TLS extension.
type Extension interface {
	Marshal() ([]byte, error)
	Unmarshal(data []byte) error
	TypeValue() TypeValue
}

// Unmarshal many extensions at once.
func Unmarshal(buf []byte) ([]Extension, error) { //nolint:cyclop
	switch {
	case len(buf) == 0:
		return []Extension{}, nil
	case len(buf) < 2:
		return nil, errBufferTooSmall
	}

	declaredLen := binary.BigEndian.Uint16(buf)
	if len(buf)-2 != int(declaredLen) {
		return nil, errLengthMismatch
	}

	extensions := []Extension{}
	unmarshalAndAppend := func(data []byte, e Extension) error {
		err := e.Unmarshal(data)
		if err != nil {
			return err
		}
		extensions = append(extensions, e)

		return nil
	}

	for offset := 2; offset < len(buf); {
		bufView := buf[offset:] //nolint:gosec // offset bounded by loop condition
		if len(bufView) < 2 {
			return nil, errBufferTooSmall
		}

		var err error
		switch TypeValue(binary.BigEndian.Uint16(bufView)) {
		case ServerNameTypeValue:
			err = unmarshalAndAppend(bufView, &ServerName{})
		case SupportedEllipticCurvesTypeValue:
			err = unmarshalAndAppend(bufView, &SupportedEllipticCurves{})
		case SupportedPointFormatsTypeValue:
			err = unmarshalAndAppend(bufView, &SupportedPointFormats{})
		case SupportedSignatureAlgorithmsTypeValue:
			err = unmarshalAndAppend(bufView, &SupportedSignatureAlgorithms{})
		case SignatureAlgorithmsCertTypeValue:
			err = unmarshalAndAppend(bufView, &SignatureAlgorithmsCert{})
		case UseSRTPTypeValue:
			err = unmarshalAndAppend(bufView, &UseSRTP{})
		case ALPNTypeValue:
			err = unmarshalAndAppend(bufView, &ALPN{})
		case UseExtendedMasterSecretTypeValue:
			err = unmarshalAndAppend(bufView, &UseExtendedMasterSecret{})
		case RenegotiationInfoTypeValue:
			err = unmarshalAndAppend(bufView, &RenegotiationInfo{})
		case ConnectionIDTypeValue:
			err = unmarshalAndAppend(bufView, &ConnectionID{})
		case SupportedVersionsTypeValue:
			err = unmarshalAndAppend(bufView, &SupportedVersions{})
		case KeyShareTypeValue:
			err = unmarshalAndAppend(bufView, &KeyShare{})
		case CookieTypeValue:
			err = unmarshalAndAppend(bufView, &CookieExt{})
		default:
		}

		if err != nil {
			return nil, err
		}
		if len(bufView) < 4 {
			return nil, errBufferTooSmall
		}
		extensionLength := binary.BigEndian.Uint16(bufView[2:])
		offset += (4 + int(extensionLength))
	}

	return extensions, nil
}

// Marshal many extensions at once.
func Marshal(e []Extension) ([]byte, error) {
	extensions := []byte{}
	for _, e := range e {
		raw, err := e.Marshal()
		if err != nil {
			return nil, err
		}
		extensions = append(extensions, raw...)
	}
	out := []byte{0x00, 0x00}
	binary.BigEndian.PutUint16(out, uint16(len(extensions))) //nolint:gosec // G115

	return append(out, extensions...), nil
}

// parseSignatureScheme parses a signature scheme from a uint16 value.
// It handles both TLS 1.2 style (hash byte + signature byte) and TLS 1.3 style (full uint16 PSS schemes).
// Returns the hash algorithm and signature algorithm.
func parseSignatureScheme(scheme uint16) (hash.Algorithm, signature.Algorithm) {
	if signature.Algorithm(scheme).IsPSS() {
		// TLS 1.3 PSS scheme - full uint16 is the signature algorithm
		return hash.ExtractHashFromPSS(scheme), signature.Algorithm(scheme)
	}

	// TLS 1.2 style - split into hash (high byte) and signature (low byte)
	return hash.Algorithm(scheme >> 8), signature.Algorithm(scheme & 0xFF)
}
