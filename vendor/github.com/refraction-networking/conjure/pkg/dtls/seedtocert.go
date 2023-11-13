package dtls

//Adapted from https://github.com/gaukas/seed2sdp/blob/master/dtlsCertificate.go

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"time"

	"filippo.io/keygen"
	"github.com/pion/dtls/v2/pkg/protocol/handshake"
	"golang.org/x/crypto/hkdf"
)

func clientHelloRandomFromSeed(seed []byte) ([handshake.RandomBytesLength]byte, error) {
	randSource := hkdf.New(sha256.New, seed, []byte("clientHelloRandomFromSeed"), nil)
	randomBytes := [handshake.RandomBytesLength]byte{}

	_, err := io.ReadFull(randSource, randomBytes[:])
	if err != nil {
		return [handshake.RandomBytesLength]byte{}, err
	}

	return randomBytes, nil
}

// getPrivkey creates ECDSA private key used in DTLS Certificates
func getPrivkey(randSource io.Reader) (*ecdsa.PrivateKey, error) {
	privkey, err := keygen.ECDSALegacy(elliptic.P256(), randSource)
	if err != nil {
		return &ecdsa.PrivateKey{}, err
	}

	return privkey, nil
}

// getX509Tpl creates x509 template for x509 Certificates generation used in DTLS Certificates.
func getX509Tpl(randSource io.Reader) (*x509.Certificate, error) {

	maxBigInt := new(big.Int)
	maxBigInt.Exp(big.NewInt(2), big.NewInt(130), nil).Sub(maxBigInt, big.NewInt(1))
	serialNumber, err := rand.Int(randSource, maxBigInt)
	if err != nil {
		return &x509.Certificate{}, err
	}

	// Make the Certificate valid from UTC today till next month.
	utcNow := time.Now().UTC()
	validFrom := time.Date(utcNow.Year(), utcNow.Month(), utcNow.Day(), 0, 0, 0, 0, time.UTC)
	validUntil := validFrom.AddDate(0, 1, 0)

	// random CN
	cnBytes := make([]byte, 8)
	_, err = io.ReadFull(randSource, cnBytes)
	if err != nil {
		return &x509.Certificate{}, fmt.Errorf("failed to generate common name: %w", err)
	}
	cn := hex.EncodeToString(cnBytes)

	return &x509.Certificate{
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
		NotBefore:             validFrom,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		NotAfter:              validUntil,
		SerialNumber:          serialNumber,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		Version:               2,
		Subject:               pkix.Name{CommonName: cn},
		DNSNames:              []string{cn},
		IsCA:                  true,
	}, nil
}

func newCertificate(randSource io.Reader) (*tls.Certificate, error) {

	privkey, err := getPrivkey(randSource)
	if err != nil {
		return &tls.Certificate{}, err
	}

	tpl, err := getX509Tpl(randSource)
	if err != nil {
		return &tls.Certificate{}, err
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tpl, tpl, privkey.Public(), privkey)
	if err != nil {
		return &tls.Certificate{}, err
	}

	return &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privkey,
	}, nil
}

func certsFromSeed(seed []byte) (*tls.Certificate, *tls.Certificate, error) {
	randSource := hkdf.New(sha256.New, seed, []byte("certsFromSeed"), nil)

	clientCert, err := newCertificate(randSource)
	if err != nil {
		return &tls.Certificate{}, &tls.Certificate{}, fmt.Errorf("error generate cert: %v", err)
	}

	serverCert, err := newCertificate(randSource)
	if err != nil {
		return &tls.Certificate{}, &tls.Certificate{}, fmt.Errorf("error generate cert: %v", err)
	}

	return clientCert, serverCert, nil
}
