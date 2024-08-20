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

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	utls "github.com/refraction-networking/utls"
)

func TestObfuscatedSessionTicket(t *testing.T) {

	tlsProfiles := []string{
		protocol.TLS_PROFILE_CHROME_58,
		protocol.TLS_PROFILE_FIREFOX_55,
		protocol.TLS_PROFILE_RANDOMIZED,
	}

	for _, tlsProfile := range tlsProfiles {
		t.Run(tlsProfile, func(t *testing.T) {
			runObfuscatedSessionTicket(t, tlsProfile)
		})
	}
}

func runObfuscatedSessionTicket(t *testing.T, tlsProfile string) {

	params, err := parameters.NewParameters(nil)
	if err != nil {
		t.Fatalf("NewParameters failed: %s\n", err)
	}

	var standardSessionTicketKey [32]byte
	rand.Read(standardSessionTicketKey[:])

	var obfuscatedSessionTicketSharedSecret [32]byte
	rand.Read(obfuscatedSessionTicketSharedSecret[:])

	clientConfig := &utls.Config{
		InsecureSkipVerify: true,
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

		clientSessionCache := utls.NewLRUClientSessionCache(0)

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
			if i == 0 {
				obfuscatedSessionState, err := tls.NewObfuscatedClientSessionState(
					obfuscatedSessionTicketSharedSecret)
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
				tlsConn.SetSessionState(clientSessionState)
			}

			if protocol.TLSProfileIsRandomized(tlsProfile) {
				for {
					err = tlsConn.BuildHandshakeState()
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

					if !isTLS13 && tls.ContainsObfuscatedSessionTicketCipherSuite(
						tlsConn.HandshakeState.Hello.CipherSuites) {
						break
					}

					utlsClientHelloID.Seed, _ = utls.NewPRNGSeed()
					tlsConn = utls.UClient(tcpConn, clientConfig, utlsClientHelloID)
					tlsConn.SetSessionCache(clientSessionCache)
					if i == 0 {
						tlsConn.SetSessionState(clientSessionState)
					}
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
