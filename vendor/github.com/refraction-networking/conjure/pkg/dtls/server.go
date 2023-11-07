package dtls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"

	"github.com/pion/dtls/v2"
)

type certPair struct {
	clientCert *tls.Certificate
	serverCert *tls.Certificate
}

// Server establishes DTLS connection on the given conn using the sharedSecert
func Server(conn net.Conn, config *Config) (net.Conn, error) {
	return ServerWithContext(context.Background(), conn, config)
}

// ServerWithContext establishes DTLS connection on the given conn using the sharedSecert and context
func ServerWithContext(ctx context.Context, conn net.Conn, config *Config) (net.Conn, error) {

	clientCert, serverCert, err := certsFromSeed(config.PSK)
	if err != nil {
		return nil, fmt.Errorf("error generating certificatess from seed: %v", err)
	}

	VerifyPeerCertificate := func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {

		err := verifyCert(rawCerts[0], clientCert.Certificate[0])
		if err != nil {
			return fmt.Errorf("error verifying peer certificate: %v", err)
		}

		return nil
	}

	dtlsConf := &dtls.Config{
		ExtendedMasterSecret:    dtls.RequireExtendedMasterSecret,
		ClientAuth:              dtls.RequireAnyClientCert,
		Certificates:            []tls.Certificate{*serverCert},
		VerifyPeerCertificate:   VerifyPeerCertificate,
		InsecureSkipVerifyHello: true,
	}

	dtlsConn, err := dtls.ServerWithContext(ctx, conn, dtlsConf)
	if err != nil {
		return nil, err
	}

	wrappedConn, err := wrapSCTP(dtlsConn, config)
	if err != nil {
		return nil, err
	}

	return wrappedConn, nil
}

func verifyCert(cert, correct []byte) error {
	incommingCert, err := x509.ParseCertificate(cert)
	if err != nil {
		return fmt.Errorf("error parsing peer certificate: %v", err)
	}

	correctCert, err := x509.ParseCertificate(correct)
	if err != nil {
		return fmt.Errorf("error parsing correct certificate: %v", err)
	}

	correctCert.KeyUsage = x509.KeyUsageCertSign // CheckSignature have requirements for the KeyUsage field
	err = incommingCert.CheckSignatureFrom(correctCert)
	if err != nil {
		return fmt.Errorf("error verifying certificate signature: %v", err)
	}

	return nil
}
