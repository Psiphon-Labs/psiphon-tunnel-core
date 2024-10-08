/*
 * Copyright (c) 2016, Psiphon Inc.
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

package psiphon

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	std_errors "errors"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	tls "github.com/Psiphon-Labs/psiphon-tls"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	utls "github.com/Psiphon-Labs/utls"
)

func TestObfuscatedSessionTicket(t *testing.T) {

	type Test struct {
		name               string
		tlsProfile         string
		mutateServerConfig func(*tls.Config)
	}

	tests := []Test{
		{
			name:       "Chrome-58",
			tlsProfile: protocol.TLS_PROFILE_CHROME_58,
		},
		{
			name:       "Firefox-55",
			tlsProfile: protocol.TLS_PROFILE_FIREFOX_55,
		},
		{
			name:       "Randomized",
			tlsProfile: protocol.TLS_PROFILE_RANDOMIZED,
		},
		{
			name:       "Chrome-112-PSK",
			tlsProfile: protocol.TLS_PROFILE_CHROME_112_PSK,
		},
		{
			name:       "Chrome-112-PSK with HRR",
			tlsProfile: protocol.TLS_PROFILE_CHROME_112_PSK,
			mutateServerConfig: func(config *tls.Config) {
				// Choose a curve that is not sent by the client in the
				// key_share extension to trigger a HelloRetryRequest.
				config.CurvePreferences = []tls.CurveID{tls.CurveP256}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runObfuscatedSessionTicket(t, test.tlsProfile, test.mutateServerConfig)
		})
	}

}

func runObfuscatedSessionTicket(t *testing.T, tlsProfile string, mutateServerConfig func(*tls.Config)) {

	params, err := parameters.NewParameters(nil)
	if err != nil {
		t.Fatalf("NewParameters failed: %s\n", err)
	}

	var standardSessionTicketKey [32]byte
	rand.Read(standardSessionTicketKey[:])

	var obfuscatedSessionTicketSharedSecret [32]byte
	rand.Read(obfuscatedSessionTicketSharedSecret[:])

	clientConfig := &utls.Config{
		OmitEmptyPsk:           true,
		InsecureSkipVerify:     true,
		InsecureSkipTimeVerify: true,
	}

	certificate, err := generateCertificate()
	if err != nil {
		t.Fatalf("generateCertificate failed: %s", err)
	}

	serverConfig := &tls.Config{
		Certificates:                []tls.Certificate{*certificate},
		NextProtos:                  []string{"http/1.1"},
		MinVersion:                  utls.VersionTLS12,
		UseObfuscatedSessionTickets: true,
	}

	// Note: SessionTicketKey needs to be set, or else, it appears,
	// tris.Config.serverInit() will clobber the value set by
	// SetSessionTicketKeys.
	serverConfig.SessionTicketKey = obfuscatedSessionTicketSharedSecret
	serverConfig.SetSessionTicketKeys([][32]byte{
		standardSessionTicketKey, obfuscatedSessionTicketSharedSecret})

	if mutateServerConfig != nil {
		mutateServerConfig(serverConfig)
	}

	testMessage := "test"

	result := make(chan error, 1)

	report := func(err error) {
		select {
		case result <- err:
		default:
		}
	}

	listening := make(chan string, 1)

	go func() {

		listener, err := tls.Listen("tcp", ":0", serverConfig)
		if err != nil {
			report(err)
			return
		}
		defer listener.Close()

		listening <- listener.Addr().String()

		for i := 0; i < 2; i++ {
			conn, err := listener.Accept()
			if err != nil {
				report(err)
				return
			}

			recv := make([]byte, len(testMessage))
			_, err = io.ReadFull(conn, recv)
			if err == nil && string(recv) != testMessage {
				err = std_errors.New("unexpected payload")
			}
			conn.Close()
			if err != nil {
				report(err)
				return
			}
		}

		// Sends nil on success
		report(nil)
	}()

	go func() {

		serverAddress := <-listening

		clientSessionCache := common.WrapUtlsClientSessionCache(
			utls.NewLRUClientSessionCache(0), "test")

		for i := 0; i < 2; i++ {

			tcpConn, err := net.Dial("tcp", serverAddress)
			if err != nil {
				report(err)
				return
			}
			defer tcpConn.Close()

			utlsClientHelloID, _, err := getUTLSClientHelloID(
				params.Get(), tlsProfile)
			if err != nil {
				report(err)
				return
			}

			tlsConn := utls.UClient(tcpConn, clientConfig, utlsClientHelloID)

			tlsConn.SetSessionCache(clientSessionCache)

			// The first connection will use an obfuscated session ticket and the
			// second connection will use a real session ticket issued by the server.
			var clientSessionState *utls.ClientSessionState

			// Generates a randomized TLS profile with the constraint that the
			// session ticket paramters and the TLS parameters must match between the connections.
			if protocol.TLSProfileIsRandomized(tlsProfile) {
				for {
					err = tlsConn.BuildHandshakeStateWithoutSession()
					if err != nil {
						report(err)
						return
					}

					isTLS13 := false
					for _, v := range tlsConn.HandshakeState.Hello.SupportedVersions {
						if v == utls.VersionTLS13 {
							isTLS13 = true
							break
						}
					}

					// Checks for the EMS extension manually since
					// uTLS contains a bug HandshakeState.Hello.Ems is always true.
					containsEms := false
					for _, ext := range tlsConn.Extensions {
						if _, ok := ext.(*utls.ExtendedMasterSecretExtension); ok {
							containsEms = true
							break
						}
					}

					if !isTLS13 &&
						containsEms &&
						tls.ContainsObfuscatedSessionTicketCipherSuite(
							tlsConn.HandshakeState.Hello.CipherSuites) {
						break
					}

					utlsClientHelloID.Seed, _ = utls.NewPRNGSeed()
					tlsConn = utls.UClient(tcpConn, clientConfig, utlsClientHelloID)
					tlsConn.SetSessionCache(clientSessionCache)
				}
			}

			if i == 0 {

				err := tlsConn.BuildHandshakeStateWithoutSession()
				if err != nil {
					report(err)
					return
				}

				isTLS13 := false
				for _, vers := range tlsConn.HandshakeState.Hello.SupportedVersions {
					if vers == utls.VersionTLS13 {
						isTLS13 = true
						break
					}
				}

				useEms := tlsConn.HandshakeState.Hello.Ems
				obfuscatedSessionState, err := tls.NewObfuscatedClientSessionState(
					obfuscatedSessionTicketSharedSecret, isTLS13, useEms)
				if err != nil {
					report(err)
					return
				}
				clientSessionState = utls.MakeClientSessionState(
					obfuscatedSessionState.SessionTicket,
					obfuscatedSessionState.Vers,
					obfuscatedSessionState.CipherSuite,
					obfuscatedSessionState.MasterSecret,
					nil,
					nil)
				clientSessionState.SetCreatedAt(obfuscatedSessionState.CreatedAt)
				clientSessionState.SetEMS(obfuscatedSessionState.ExtMasterSecret)

				// TLS 1.3-only fields
				clientSessionState.SetAgeAdd(obfuscatedSessionState.AgeAdd)
				clientSessionState.SetUseBy(obfuscatedSessionState.UseBy)

				containsPSKExt := false
				for _, ext := range tlsConn.Extensions {
					if _, ok := ext.(utls.PreSharedKeyExtension); ok {
						containsPSKExt = true
					}
				}

				// Sets session ticket or PSK.
				if isTLS13 {
					if containsPSKExt {
						clientSessionCache.Put("test", clientSessionState)
					}
				} else {
					err = tlsConn.SetSessionState(clientSessionState)
					if err != nil {
						report(err)
						return
					}
				}

				// Apply changes to uTLS
				err = tlsConn.BuildHandshakeState()
				if err != nil {
					report(err)
					return
				}

				// Check that the PSK extension is not omitted in the ClientHello
				if containsPSKExt && len(tlsConn.HandshakeState.Hello.PskIdentities) == 0 {
					report(std_errors.New("missing PSK extension"))
					return
				}
			}

			err = tlsConn.Handshake()
			if err != nil {
				report(err)
				return
			}

			if len(tlsConn.ConnectionState().PeerCertificates) > 0 {
				report(std_errors.New("unexpected certificate in handshake"))
				return
			}

			_, err = tlsConn.Write([]byte(testMessage))
			if err != nil {
				report(err)
				return
			}
		}
	}()

	err = <-result
	if err != nil {
		t.Fatalf("connect failed: %s", err)
	}
}

func generateCertificate() (*tls.Certificate, error) {

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(rsaKey.Public())
	if err != nil {
		return nil, err
	}
	subjectKeyID := sha1.Sum(publicKeyBytes)

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "www.example.org"},
		NotBefore:             time.Now().Add(-1 * time.Hour).UTC(),
		NotAfter:              time.Now().Add(time.Hour).UTC(),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          subjectKeyID[:],
		MaxPathLen:            1,
		Version:               2,
	}

	derCert, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		&template,
		rsaKey.Public(),
		rsaKey)
	if err != nil {
		return nil, err
	}

	certificate := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: derCert,
		},
	)

	privateKey := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
		},
	)

	keyPair, err := tls.X509KeyPair(certificate, privateKey)
	if err != nil {
		return nil, err
	}

	return &keyPair, nil
}
