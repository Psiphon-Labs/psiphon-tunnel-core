// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"crypto/tls"
	"reflect"
	"testing"

	"github.com/pion/dtls/v2/pkg/crypto/selfsign"
)

func TestGetCertificate(t *testing.T) {
	certificateWildcard, err := selfsign.GenerateSelfSignedWithDNS("*.test.test")
	if err != nil {
		t.Fatal(err)
	}

	certificateTest, err := selfsign.GenerateSelfSignedWithDNS("test.test", "www.test.test", "pop.test.test")
	if err != nil {
		t.Fatal(err)
	}

	certificateRandom, err := selfsign.GenerateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}

	testCases := []struct {
		localCertificates   []tls.Certificate
		desc                string
		serverName          string
		expectedCertificate tls.Certificate
		getCertificate      func(info *ClientHelloInfo) (*tls.Certificate, error)
	}{
		{
			desc: "Simple match in CN",
			localCertificates: []tls.Certificate{
				certificateRandom,
				certificateTest,
				certificateWildcard,
			},
			serverName:          "test.test",
			expectedCertificate: certificateTest,
		},
		{
			desc: "Simple match in SANs",
			localCertificates: []tls.Certificate{
				certificateRandom,
				certificateTest,
				certificateWildcard,
			},
			serverName:          "www.test.test",
			expectedCertificate: certificateTest,
		},

		{
			desc: "Wildcard match",
			localCertificates: []tls.Certificate{
				certificateRandom,
				certificateTest,
				certificateWildcard,
			},
			serverName:          "foo.test.test",
			expectedCertificate: certificateWildcard,
		},
		{
			desc: "No match return first",
			localCertificates: []tls.Certificate{
				certificateRandom,
				certificateTest,
				certificateWildcard,
			},
			serverName:          "foo.bar",
			expectedCertificate: certificateRandom,
		},
		{
			desc: "Get certificate from callback",
			getCertificate: func(info *ClientHelloInfo) (*tls.Certificate, error) {
				return &certificateTest, nil
			},
			expectedCertificate: certificateTest,
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			cfg := &handshakeConfig{
				localCertificates:   test.localCertificates,
				localGetCertificate: test.getCertificate,
			}
			cert, err := cfg.getCertificate(&ClientHelloInfo{ServerName: test.serverName})
			if err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(cert.Leaf, test.expectedCertificate.Leaf) {
				t.Fatalf("Certificate does not match: expected(%v) actual(%v)", test.expectedCertificate.Leaf, cert.Leaf)
			}
		})
	}
}
