package dtls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"

	"github.com/pion/dtls/v2"
	"github.com/pion/dtls/v2/pkg/protocol/handshake"
)

// Dial creates a DTLS connection to the given network address using the given shared secret
func Dial(remoteAddr *net.UDPAddr, config *Config) (net.Conn, error) {
	return DialWithContext(context.Background(), remoteAddr, config)
}

// DialWithContext like Dial, but includes context for cancellation and timeouts.
func DialWithContext(ctx context.Context, remoteAddr *net.UDPAddr, config *Config) (net.Conn, error) {
	conn, err := net.DialUDP("udp", nil, remoteAddr)
	if err != nil {
		return nil, err
	}

	return ClientWithContext(ctx, conn, config)
}

// Client establishes a DTLS connection using an existing connection and a seed.
func Client(conn net.Conn, config *Config) (net.Conn, error) {
	return ClientWithContext(context.Background(), conn, config)
}

// DialWithContext creates a DTLS connection to the given network address using the given shared secret
func ClientWithContext(ctx context.Context, conn net.Conn, config *Config) (net.Conn, error) {
	clientCert, serverCert, err := certsFromSeed(config.PSK)

	if err != nil {
		return nil, fmt.Errorf("error generating certs: %v", err)
	}

	clientHelloRandom, err := clientHelloRandomFromSeed(config.PSK)
	if err != nil {
		return nil, fmt.Errorf("error generating client hello random: %v", err)
	}

	verifyServerCertificate := func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(rawCerts) != 1 {
			return fmt.Errorf("expected 1 peer certificate, got %v", len(rawCerts))
		}

		err := verifyCert(rawCerts[0], serverCert.Certificate[0])
		if err != nil {
			return fmt.Errorf("error verifying server certificate: %v", err)
		}

		return nil
	}

	// Prepare the configuration of the DTLS connection
	dtlsConf := &dtls.Config{
		Certificates:            []tls.Certificate{*clientCert},
		ExtendedMasterSecret:    dtls.RequireExtendedMasterSecret,
		CustomClientHelloRandom: func() [handshake.RandomBytesLength]byte { return clientHelloRandom },

		// We use VerifyPeerCertificate to authenticate the peer's certificate. This is necessary as Go's non-deterministic ECDSA signatures and hash comparison method for self-signed certificates can cause verification failure.
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: verifyServerCertificate,
	}

	dtlsConn, err := dtls.ClientWithContext(ctx, conn, dtlsConf)

	if err != nil {
		return nil, fmt.Errorf("error creating dtls connection: %v", err)
	}

	wrappedConn, err := wrapSCTP(dtlsConn, config)
	if err != nil {
		return nil, err
	}

	return wrappedConn, nil
}
