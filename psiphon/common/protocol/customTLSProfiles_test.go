/*
 * Copyright (c) 2019, Psiphon Inc.
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

package protocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"testing"

	utls "github.com/refraction-networking/utls"
)

func TestCustomTLSProfiles(t *testing.T) {

	// Based on utls.HelloChrome_62. Some attributes have been removed to
	// eliminate randomness; and additional extensions have been added for extra
	// test coverage.

	utlsClientHelloSpec := &utls.ClientHelloSpec{
		TLSVersMax: utls.VersionTLS12,
		TLSVersMin: utls.VersionTLS10,
		CipherSuites: []uint16{
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_RSA_WITH_AES_256_CBC_SHA,
			utls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		},
		CompressionMethods: []byte{0},
		Extensions: []utls.TLSExtension{
			&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
			&utls.SNIExtension{},
			&utls.UtlsExtendedMasterSecretExtension{},
			&utls.SessionTicketExtension{},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.PSSWithSHA256,
				utls.PKCS1WithSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.PSSWithSHA384,
				utls.PKCS1WithSHA384,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA512,
				utls.PKCS1WithSHA1},
			},
			&utls.StatusRequestExtension{},
			&utls.SCTExtension{},
			&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			&utls.FakeChannelIDExtension{},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{0}},
			&utls.SupportedCurvesExtension{[]utls.CurveID{
				utls.X25519, utls.CurveP256, utls.CurveP384}},
			&utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle},

			// Additional extensions for test coverage
			&utls.NPNExtension{NextProtos: []string{"http/1.1"}},
			&utls.GenericExtension{Id: 9999, Data: []byte("generic extension")},
			&utls.KeyShareExtension{[]utls.KeyShare{
				{Group: utls.X25519, Data: []byte{9, 9, 9, 9}},
			}},
			&utls.PSKKeyExchangeModesExtension{[]uint8{
				utls.PskModeDHE,
			}},
			&utls.SupportedVersionsExtension{[]uint16{
				utls.VersionTLS13,
				utls.VersionTLS12,
				utls.VersionTLS11,
				utls.VersionTLS10,
			}},
			&utls.FakeCertCompressionAlgsExtension{[]utls.CertCompressionAlgo{
				utls.CertCompressionBrotli,
			}},
			&utls.FakeChannelIDExtension{},
			&utls.FakeRecordSizeLimitExtension{Limit: 9999},
		},
		GetSessionID: sha256.Sum256,
	}

	customTLSProfilesJSON := []byte(`
    [
      {
        "Name": "CustomProfile",
        "UTLSSpec": {
          "TLSVersMax": 771,
          "TLSVersMin": 769,
          "CipherSuites": [49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156, 157, 47, 53, 10],
          "CompressionMethods": [0],
          "Extensions" : [
            {"Name": "RenegotiationInfo", "Data": {"Renegotiation": 1}},
            {"Name": "SNI"},
            {"Name": "ExtendedMasterSecret"},
            {"Name": "SessionTicket"},
            {"Name": "SignatureAlgorithms", "Data": {"SupportedSignatureAlgorithms": [1027, 2052, 1025, 1283, 2053, 1281, 2054, 1537, 513]}},
            {"Name": "StatusRequest"},
            {"Name": "SCT"},
            {"Name": "ALPN", "Data": {"AlpnProtocols": ["h2", "http/1.1"]}},
            {"Name": "ChannelID"},
            {"Name": "SupportedPoints", "Data": {"SupportedPoints": [0]}},
            {"Name": "SupportedCurves", "Data": {"Curves": [29, 23, 24]}},
            {"Name": "BoringPadding"},
            {"Name": "NPN", "Data": {"NextProtos": ["h2", "http/1.1"]}},
            {"Name": "Generic", "Data": {"Id": 9999, "Data": [103, 101, 110, 101, 114, 105, 99, 32, 101, 120, 116, 101, 110, 115, 105, 111, 110]}},
            {"Name": "KeyShare", "Data": {"KeyShares": [{"Group": 29, "Data": [9, 9, 9, 9]}]}},
            {"Name": "PSKKeyExchangeModes", "Data": {"Modes": [1]}},
            {"Name": "SupportedVersions", "Data": {"Versions": [772, 771, 770, 769]}},
            {"Name": "CertCompressionAlgs", "Data": {"Methods": [2]}},
            {"Name": "ChannelID"},
            {"Name": "RecordSizeLimit", "Data": {"Limit": 9999}}],
          "GetSessionID": "SHA-256"
        }
      }
    ]`)

	var customTLSProfiles CustomTLSProfiles

	err := json.Unmarshal(customTLSProfilesJSON, &customTLSProfiles)
	if err != nil {
		t.Fatalf("Unmarshal failed: %s", err)
	}

	err = customTLSProfiles.Validate()
	if err != nil {
		t.Fatalf("Validate failed: %s", err)
	}

	profile := customTLSProfiles[0]
	profileClientHelloSpec, err := profile.GetClientHelloSpec()
	if err != nil {
		t.Fatalf("GetClientHelloSpec failed: %s", err)
	}

	zeroes := make([]byte, 32)

	conn1 := utls.UClient(nil, &utls.Config{InsecureSkipVerify: true}, utls.HelloCustom)
	conn1.ApplyPreset(utlsClientHelloSpec)
	conn1.SetClientRandom(zeroes)
	conn1.HandshakeState.Hello.SessionId = zeroes
	err = conn1.BuildHandshakeState()
	if err != nil {
		t.Fatalf("BuildHandshakeState failed: %s", err)
	}

	conn2 := utls.UClient(nil, &utls.Config{InsecureSkipVerify: true}, utls.HelloCustom)
	conn2.ApplyPreset(profileClientHelloSpec)
	conn2.SetClientRandom(zeroes)
	conn2.HandshakeState.Hello.SessionId = zeroes
	err = conn2.BuildHandshakeState()
	if err != nil {
		t.Fatalf("BuildHandshakeState failed: %s", err)
	}

	if len(conn1.HandshakeState.Hello.Raw) == 0 {
		t.Fatalf("Missing raw ClientHello")
	}

	if len(conn2.HandshakeState.Hello.Raw) == 0 {
		t.Fatalf("Missing raw ClientHello")
	}

	if !bytes.Equal(conn1.HandshakeState.Hello.Raw, conn2.HandshakeState.Hello.Raw) {
		t.Fatalf("Unidentical raw ClientHellos")
	}
}
