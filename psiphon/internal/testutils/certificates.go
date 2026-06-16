/*
 * Copyright (c) 2026, Psiphon Inc.
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

package testutils

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"testing"
	"time"

	tls "github.com/Psiphon-Labs/psiphon-tls"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
)

// InitTestCertificatesAndWebServer creates a Root CA, a web server
// certificate, for serverName, signed by that Root CA, and runs a web server
// that uses that server certificate. initRootCAandWebServer returns:
//
//   - the file name containing the Root CA, to be used with
//     tlsdialer.Config.TrustedCACertificatesFilename
//
//   - pin values for the Root CA and server certificare, to be used with
//     tlsdialer.Config.VerifyPins
//
//   - a shutdown function which the caller must invoked to terminate the web
//     server
//
// - the web server dial address: serverName and port
//
//   - and a dialer function, which bypasses DNS resolution of serverName, to be
//     used with tlsdialer.Config.Dial
func InitTestCertificatesAndWebServer(
	t *testing.T,
	testDataDirName string,
	serverName string) (string, string, string, func(), string, common.Dialer) {

	// Generate a root CA certificate.

	rootCACertificate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	rootCAPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatalf("rsa.GenerateKey failed: %v", err)
	}

	rootCACertificateBytes, err := x509.CreateCertificate(
		rand.Reader,
		rootCACertificate,
		rootCACertificate,
		&rootCAPrivateKey.PublicKey,
		rootCAPrivateKey)
	if err != nil {
		t.Fatalf("x509.CreateCertificate failed: %v", err)
	}

	pemRootCACertificate := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: rootCACertificateBytes,
		})

	// Generate a server certificate.

	serverCertificate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"test"},
		},
		DNSNames:    []string{serverName},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(1, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}

	serverPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatalf("rsa.GenerateKey failed: %v", err)
	}

	serverCertificateBytes, err := x509.CreateCertificate(
		rand.Reader,
		serverCertificate,
		rootCACertificate,
		&serverPrivateKey.PublicKey,
		rootCAPrivateKey)
	if err != nil {
		t.Fatalf("x509.CreateCertificate failed: %v", err)
	}

	pemServerCertificate := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: serverCertificateBytes,
		})

	pemServerPrivateKey := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(serverPrivateKey),
		})

	// Pave Root CA file.

	rootCAsFileName := filepath.Join(testDataDirName, "RootCAs.pem")
	err = ioutil.WriteFile(rootCAsFileName, pemRootCACertificate, 0600)
	if err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// Calculate certificate pins.

	parsedCertificate, err := x509.ParseCertificate(rootCACertificateBytes)
	if err != nil {
		t.Fatalf("x509.ParseCertificate failed: %v", err)
	}
	publicKeyDigest := sha256.Sum256(parsedCertificate.RawSubjectPublicKeyInfo)
	rootCACertificatePin := base64.StdEncoding.EncodeToString(publicKeyDigest[:])

	parsedCertificate, err = x509.ParseCertificate(serverCertificateBytes)
	if err != nil {
		t.Fatalf("x509.ParseCertificate failed: %v", err)
	}
	publicKeyDigest = sha256.Sum256(parsedCertificate.RawSubjectPublicKeyInfo)
	serverCertificatePin := base64.StdEncoding.EncodeToString(publicKeyDigest[:])

	// Run an HTTPS server with the server certificate.

	// Do not include the Root CA certificate in the certificate chain returned
	// by the server to the client in the TLS handshake by excluding it from
	// the key pair, which matches the behavior observed in the wild.
	serverKeyPair, err := tls.X509KeyPair(
		pemServerCertificate, pemServerPrivateKey)
	if err != nil {
		t.Fatalf("tls.X509KeyPair failed: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("test"))
	})

	server := &http.Server{
		Handler: mux,
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %v", err)
	}
	dialAddr := listener.Addr().String()
	_, port, _ := net.SplitHostPort(dialAddr)
	serverAddr := fmt.Sprintf("%s:%s", serverName, port)

	listener = tls.NewListener(
		listener,
		&tls.Config{
			Certificates: []tls.Certificate{serverKeyPair},
		})

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		wg.Done()
		server.Serve(listener)
	}()

	shutdown := func() {
		listener.Close()
		server.Shutdown(context.Background())
		wg.Wait()
	}

	// Initialize a custom dialer for the client which bypasses DNS resolution.

	dialer := func(ctx context.Context, network, address string) (net.Conn, error) {
		d := &net.Dialer{}
		// Ignore the address input, which will be serverAddr, and dial dialAddr, as
		// if the serverName in serverAddr had been resolved to "127.0.0.1".
		return d.DialContext(ctx, network, dialAddr)
	}

	return rootCAsFileName,
		rootCACertificatePin,
		serverCertificatePin,
		shutdown,
		serverAddr,
		dialer
}
