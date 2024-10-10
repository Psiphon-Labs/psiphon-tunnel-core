// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	cryptoElliptic "crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/dtls/v2/internal/ciphersuite"
	"github.com/pion/dtls/v2/pkg/crypto/elliptic"
	"github.com/pion/dtls/v2/pkg/crypto/hash"
	"github.com/pion/dtls/v2/pkg/crypto/selfsign"
	"github.com/pion/dtls/v2/pkg/crypto/signature"
	"github.com/pion/dtls/v2/pkg/crypto/signaturehash"
	"github.com/pion/dtls/v2/pkg/protocol"
	"github.com/pion/dtls/v2/pkg/protocol/alert"
	"github.com/pion/dtls/v2/pkg/protocol/extension"
	"github.com/pion/dtls/v2/pkg/protocol/handshake"
	"github.com/pion/dtls/v2/pkg/protocol/recordlayer"
	"github.com/pion/logging"
	"github.com/pion/transport/v2/dpipe"
	"github.com/pion/transport/v2/test"
)

var (
	errTestPSKInvalidIdentity = errors.New("TestPSK: Server got invalid identity")
	errPSKRejected            = errors.New("PSK Rejected")
	errNotExpectedChain       = errors.New("not expected chain")
	errExpecedChain           = errors.New("expected chain")
	errWrongCert              = errors.New("wrong cert")
)

func TestStressDuplex(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	// Run the test
	stressDuplex(t)
}

func stressDuplex(t *testing.T) {
	ca, cb, err := pipeMemory()
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		err = ca.Close()
		if err != nil {
			t.Fatal(err)
		}
		err = cb.Close()
		if err != nil {
			t.Fatal(err)
		}
	}()

	opt := test.Options{
		MsgSize:  2048,
		MsgCount: 100,
	}

	err = test.StressDuplex(ca, cb, opt)
	if err != nil {
		t.Fatal(err)
	}
}

func TestRoutineLeakOnClose(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(5 * time.Second)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	ca, cb, err := pipeMemory()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := ca.Write(make([]byte, 100)); err != nil {
		t.Fatal(err)
	}
	if err := cb.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ca.Close(); err != nil {
		t.Fatal(err)
	}
	// Packet is sent, but not read.
	// inboundLoop routine should not be leaked.
}

func TestReadWriteDeadline(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(5 * time.Second)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	var e net.Error

	ca, cb, err := pipeMemory()
	if err != nil {
		t.Fatal(err)
	}

	if err := ca.SetDeadline(time.Unix(0, 1)); err != nil {
		t.Fatal(err)
	}
	_, werr := ca.Write(make([]byte, 100))
	if errors.As(werr, &e) {
		if !e.Timeout() {
			t.Error("Deadline exceeded Write must return Timeout error")
		}
		if !e.Temporary() { //nolint:staticcheck
			t.Error("Deadline exceeded Write must return Temporary error")
		}
	} else {
		t.Error("Write must return net.Error error")
	}
	_, rerr := ca.Read(make([]byte, 100))
	if errors.As(rerr, &e) {
		if !e.Timeout() {
			t.Error("Deadline exceeded Read must return Timeout error")
		}
		if !e.Temporary() { //nolint:staticcheck
			t.Error("Deadline exceeded Read must return Temporary error")
		}
	} else {
		t.Error("Read must return net.Error error")
	}
	if err := ca.SetDeadline(time.Time{}); err != nil {
		t.Error(err)
	}

	if err := ca.Close(); err != nil {
		t.Error(err)
	}
	if err := cb.Close(); err != nil {
		t.Error(err)
	}

	if _, err := ca.Write(make([]byte, 100)); !errors.Is(err, ErrConnClosed) {
		t.Errorf("Write must return %v after close, got %v", ErrConnClosed, err)
	}
	if _, err := ca.Read(make([]byte, 100)); !errors.Is(err, io.EOF) {
		t.Errorf("Read must return %v after close, got %v", io.EOF, err)
	}
}

func TestSequenceNumberOverflow(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(5 * time.Second)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	t.Run("ApplicationData", func(t *testing.T) {
		ca, cb, err := pipeMemory()
		if err != nil {
			t.Fatal(err)
		}

		atomic.StoreUint64(&ca.state.localSequenceNumber[1], recordlayer.MaxSequenceNumber)
		if _, werr := ca.Write(make([]byte, 100)); werr != nil {
			t.Errorf("Write must send message with maximum sequence number, but errord: %v", werr)
		}
		if _, werr := ca.Write(make([]byte, 100)); !errors.Is(werr, errSequenceNumberOverflow) {
			t.Errorf("Write must abandonsend message with maximum sequence number, but errord: %v", werr)
		}

		if err := ca.Close(); err != nil {
			t.Error(err)
		}
		if err := cb.Close(); err != nil {
			t.Error(err)
		}
	})
	t.Run("Handshake", func(t *testing.T) {
		ca, cb, err := pipeMemory()
		if err != nil {
			t.Fatal(err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		atomic.StoreUint64(&ca.state.localSequenceNumber[0], recordlayer.MaxSequenceNumber+1)

		// Try to send handshake packet.
		if werr := ca.writePackets(ctx, []*packet{
			{
				record: &recordlayer.RecordLayer{
					Header: recordlayer.Header{
						Version: protocol.Version1_2,
					},
					Content: &handshake.Handshake{
						Message: &handshake.MessageClientHello{
							Version:            protocol.Version1_2,
							Cookie:             make([]byte, 64),
							CipherSuiteIDs:     cipherSuiteIDs(defaultCipherSuites()),
							CompressionMethods: defaultCompressionMethods(),
						},
					},
				},
			},
		}); !errors.Is(werr, errSequenceNumberOverflow) {
			t.Errorf("Connection must fail on handshake packet reaches maximum sequence number")
		}

		if err := ca.Close(); err != nil {
			t.Error(err)
		}
		if err := cb.Close(); err != nil {
			t.Error(err)
		}
	})
}

func pipeMemory() (*Conn, *Conn, error) {
	// In memory pipe
	ca, cb := dpipe.Pipe()
	return pipeConn(ca, cb)
}

func pipeConn(ca, cb net.Conn) (*Conn, *Conn, error) {
	type result struct {
		c   *Conn
		err error
	}

	c := make(chan result)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Setup client
	go func() {
		client, err := testClient(ctx, ca, &Config{SRTPProtectionProfiles: []SRTPProtectionProfile{SRTP_AES128_CM_HMAC_SHA1_80}}, true)
		c <- result{client, err}
	}()

	// Setup server
	server, err := testServer(ctx, cb, &Config{SRTPProtectionProfiles: []SRTPProtectionProfile{SRTP_AES128_CM_HMAC_SHA1_80}}, true)
	if err != nil {
		return nil, nil, err
	}

	// Receive client
	res := <-c
	if res.err != nil {
		_ = server.Close()
		return nil, nil, res.err
	}

	return res.c, server, nil
}

func testClient(ctx context.Context, c net.Conn, cfg *Config, generateCertificate bool) (*Conn, error) {
	if generateCertificate {
		clientCert, err := selfsign.GenerateSelfSigned()
		if err != nil {
			return nil, err
		}
		cfg.Certificates = []tls.Certificate{clientCert}
	}
	cfg.InsecureSkipVerify = true
	return ClientWithContext(ctx, c, cfg)
}

func testServer(ctx context.Context, c net.Conn, cfg *Config, generateCertificate bool) (*Conn, error) {
	if generateCertificate {
		serverCert, err := selfsign.GenerateSelfSigned()
		if err != nil {
			return nil, err
		}
		cfg.Certificates = []tls.Certificate{serverCert}
	}
	return ServerWithContext(ctx, c, cfg)
}

func sendClientHello(cookie []byte, ca net.Conn, sequenceNumber uint64, extensions []extension.Extension) error {
	packet, err := (&recordlayer.RecordLayer{
		Header: recordlayer.Header{
			Version:        protocol.Version1_2,
			SequenceNumber: sequenceNumber,
		},
		Content: &handshake.Handshake{
			Header: handshake.Header{
				MessageSequence: uint16(sequenceNumber),
			},
			Message: &handshake.MessageClientHello{
				Version:            protocol.Version1_2,
				Cookie:             cookie,
				CipherSuiteIDs:     cipherSuiteIDs(defaultCipherSuites()),
				CompressionMethods: defaultCompressionMethods(),
				Extensions:         extensions,
			},
		},
	}).Marshal()
	if err != nil {
		return err
	}

	if _, err = ca.Write(packet); err != nil {
		return err
	}
	return nil
}

func TestHandshakeWithAlert(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cases := map[string]struct {
		configServer, configClient *Config
		errServer, errClient       error
	}{
		"CipherSuiteNoIntersection": {
			configServer: &Config{
				CipherSuites: []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			},
			configClient: &Config{
				CipherSuites: []CipherSuiteID{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			},
			errServer: errCipherSuiteNoIntersection,
			errClient: &alertError{&alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}},
		},
		"SignatureSchemesNoIntersection": {
			configServer: &Config{
				CipherSuites:     []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
				SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
			},
			configClient: &Config{
				CipherSuites:     []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
				SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP521AndSHA512},
			},
			errServer: &alertError{&alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}},
			errClient: errNoAvailableSignatureSchemes,
		},
	}

	for name, testCase := range cases {
		testCase := testCase
		t.Run(name, func(t *testing.T) {
			clientErr := make(chan error, 1)

			ca, cb := dpipe.Pipe()
			go func() {
				_, err := testClient(ctx, ca, testCase.configClient, true)
				clientErr <- err
			}()

			_, errServer := testServer(ctx, cb, testCase.configServer, true)
			if !errors.Is(errServer, testCase.errServer) {
				t.Fatalf("Server error exp(%v) failed(%v)", testCase.errServer, errServer)
			}

			errClient := <-clientErr
			if !errors.Is(errClient, testCase.errClient) {
				t.Fatalf("Client error exp(%v) failed(%v)", testCase.errClient, errClient)
			}
		})
	}
}

func TestHandshakeWithInvalidRecord(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	type result struct {
		c   *Conn
		err error
	}
	clientErr := make(chan result, 1)
	ca, cb := dpipe.Pipe()
	caWithInvalidRecord := &connWithCallback{Conn: ca}

	var msgSeq atomic.Int32
	// Send invalid record after first message
	caWithInvalidRecord.onWrite = func(b []byte) {
		if msgSeq.Add(1) == 2 {
			if _, err := ca.Write([]byte{0x01, 0x02}); err != nil {
				t.Fatal(err)
			}
		}
	}
	go func() {
		client, err := testClient(ctx, caWithInvalidRecord, &Config{
			CipherSuites: []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		}, true)
		clientErr <- result{client, err}
	}()

	server, errServer := testServer(ctx, cb, &Config{
		CipherSuites: []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
	}, true)

	errClient := <-clientErr

	defer func() {
		if server != nil {
			if err := server.Close(); err != nil {
				t.Fatal(err)
			}
		}

		if errClient.c != nil {
			if err := errClient.c.Close(); err != nil {
				t.Fatal(err)
			}
		}
	}()

	if errServer != nil {
		t.Fatalf("Server failed(%v)", errServer)
	}

	if errClient.err != nil {
		t.Fatalf("Client failed(%v)", errClient.err)
	}
}

func TestExportKeyingMaterial(t *testing.T) {
	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	var rand [28]byte
	exportLabel := "EXTRACTOR-dtls_srtp"

	expectedServerKey := []byte{0x61, 0x09, 0x9d, 0x7d, 0xcb, 0x08, 0x52, 0x2c, 0xe7, 0x7b}
	expectedClientKey := []byte{0x87, 0xf0, 0x40, 0x02, 0xf6, 0x1c, 0xf1, 0xfe, 0x8c, 0x77}

	c := &Conn{
		state: State{
			localRandom:         handshake.Random{GMTUnixTime: time.Unix(500, 0), RandomBytes: rand},
			remoteRandom:        handshake.Random{GMTUnixTime: time.Unix(1000, 0), RandomBytes: rand},
			localSequenceNumber: []uint64{0, 0},
			cipherSuite:         &ciphersuite.TLSEcdheEcdsaWithAes128GcmSha256{},
		},
	}
	c.setLocalEpoch(0)
	c.setRemoteEpoch(0)

	state := c.ConnectionState()
	_, err := state.ExportKeyingMaterial(exportLabel, nil, 0)
	if !errors.Is(err, errHandshakeInProgress) {
		t.Errorf("ExportKeyingMaterial when epoch == 0: expected '%s' actual '%s'", errHandshakeInProgress, err)
	}

	c.setLocalEpoch(1)
	state = c.ConnectionState()
	_, err = state.ExportKeyingMaterial(exportLabel, []byte{0x00}, 0)
	if !errors.Is(err, errContextUnsupported) {
		t.Errorf("ExportKeyingMaterial with context: expected '%s' actual '%s'", errContextUnsupported, err)
	}

	for k := range invalidKeyingLabels() {
		state = c.ConnectionState()
		_, err = state.ExportKeyingMaterial(k, nil, 0)
		if !errors.Is(err, errReservedExportKeyingMaterial) {
			t.Errorf("ExportKeyingMaterial reserved label: expected '%s' actual '%s'", errReservedExportKeyingMaterial, err)
		}
	}

	state = c.ConnectionState()
	keyingMaterial, err := state.ExportKeyingMaterial(exportLabel, nil, 10)
	if err != nil {
		t.Errorf("ExportKeyingMaterial as server: unexpected error '%s'", err)
	} else if !bytes.Equal(keyingMaterial, expectedServerKey) {
		t.Errorf("ExportKeyingMaterial client export: expected (% 02x) actual (% 02x)", expectedServerKey, keyingMaterial)
	}

	c.state.isClient = true
	state = c.ConnectionState()
	keyingMaterial, err = state.ExportKeyingMaterial(exportLabel, nil, 10)
	if err != nil {
		t.Errorf("ExportKeyingMaterial as server: unexpected error '%s'", err)
	} else if !bytes.Equal(keyingMaterial, expectedClientKey) {
		t.Errorf("ExportKeyingMaterial client export: expected (% 02x) actual (% 02x)", expectedClientKey, keyingMaterial)
	}
}

func TestPSK(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	for _, test := range []struct {
		Name                   string
		ServerIdentity         []byte
		CipherSuites           []CipherSuiteID
		ClientVerifyConnection func(*State) error
		ServerVerifyConnection func(*State) error
		WantFail               bool
		ExpectedServerErr      string
		ExpectedClientErr      string
	}{
		{
			Name:           "Server identity specified",
			ServerIdentity: []byte("Test Identity"),
			CipherSuites:   []CipherSuiteID{TLS_PSK_WITH_AES_128_CCM_8},
		},
		{
			Name:           "Server identity specified - Server verify connection fails",
			ServerIdentity: []byte("Test Identity"),
			CipherSuites:   []CipherSuiteID{TLS_PSK_WITH_AES_128_CCM_8},
			ServerVerifyConnection: func(s *State) error {
				return errExample
			},
			WantFail:          true,
			ExpectedServerErr: errExample.Error(),
			ExpectedClientErr: alert.BadCertificate.String(),
		},
		{
			Name:           "Server identity specified - Client verify connection fails",
			ServerIdentity: []byte("Test Identity"),
			CipherSuites:   []CipherSuiteID{TLS_PSK_WITH_AES_128_CCM_8},
			ClientVerifyConnection: func(s *State) error {
				return errExample
			},
			WantFail:          true,
			ExpectedServerErr: alert.BadCertificate.String(),
			ExpectedClientErr: errExample.Error(),
		},
		{
			Name:           "Server identity nil",
			ServerIdentity: nil,
			CipherSuites:   []CipherSuiteID{TLS_PSK_WITH_AES_128_CCM_8},
		},
		{
			Name:           "TLS_PSK_WITH_AES_128_CBC_SHA256",
			ServerIdentity: nil,
			CipherSuites:   []CipherSuiteID{TLS_PSK_WITH_AES_128_CBC_SHA256},
		},
		{
			Name:           "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256",
			ServerIdentity: nil,
			CipherSuites:   []CipherSuiteID{TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256},
		},
	} {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			clientIdentity := []byte("Client Identity")
			type result struct {
				c   *Conn
				err error
			}
			clientRes := make(chan result, 1)

			ca, cb := dpipe.Pipe()
			go func() {
				conf := &Config{
					PSK: func(hint []byte) ([]byte, error) {
						if !bytes.Equal(test.ServerIdentity, hint) {
							return nil, fmt.Errorf("TestPSK: Client got invalid identity expected(% 02x) actual(% 02x)", test.ServerIdentity, hint) //nolint:goerr113
						}

						return []byte{0xAB, 0xC1, 0x23}, nil
					},
					PSKIdentityHint:  clientIdentity,
					CipherSuites:     test.CipherSuites,
					VerifyConnection: test.ClientVerifyConnection,
				}

				c, err := testClient(ctx, ca, conf, false)
				clientRes <- result{c, err}
			}()

			config := &Config{
				PSK: func(hint []byte) ([]byte, error) {
					if !bytes.Equal(clientIdentity, hint) {
						return nil, fmt.Errorf("%w: expected(% 02x) actual(% 02x)", errTestPSKInvalidIdentity, clientIdentity, hint)
					}
					return []byte{0xAB, 0xC1, 0x23}, nil
				},
				PSKIdentityHint:  test.ServerIdentity,
				CipherSuites:     test.CipherSuites,
				VerifyConnection: test.ServerVerifyConnection,
			}

			server, err := testServer(ctx, cb, config, false)
			if test.WantFail {
				res := <-clientRes
				if err == nil || !strings.Contains(err.Error(), test.ExpectedServerErr) {
					t.Fatalf("TestPSK: Server expected(%v) actual(%v)", test.ExpectedServerErr, err)
				}
				if res.err == nil || !strings.Contains(res.err.Error(), test.ExpectedClientErr) {
					t.Fatalf("TestPSK: Client expected(%v) actual(%v)", test.ExpectedClientErr, res.err)
				}
				return
			}
			if err != nil {
				t.Fatalf("TestPSK: Server failed(%v)", err)
			}

			actualPSKIdentityHint := server.ConnectionState().IdentityHint
			if !bytes.Equal(actualPSKIdentityHint, clientIdentity) {
				t.Errorf("TestPSK: Server ClientPSKIdentity Mismatch '%s': expected(%v) actual(%v)", test.Name, clientIdentity, actualPSKIdentityHint)
			}

			defer func() {
				_ = server.Close()
			}()

			res := <-clientRes
			if res.err != nil {
				t.Fatal(res.err)
			}
			_ = res.c.Close()
		})
	}
}

func TestPSKHintFail(t *testing.T) {
	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	serverAlertError := &alertError{&alert.Alert{Level: alert.Fatal, Description: alert.InternalError}}
	pskRejected := errPSKRejected

	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clientErr := make(chan error, 1)

	ca, cb := dpipe.Pipe()
	go func() {
		conf := &Config{
			PSK: func(hint []byte) ([]byte, error) {
				return nil, pskRejected
			},
			PSKIdentityHint: []byte{},
			CipherSuites:    []CipherSuiteID{TLS_PSK_WITH_AES_128_CCM_8},
		}

		_, err := testClient(ctx, ca, conf, false)
		clientErr <- err
	}()

	config := &Config{
		PSK: func(hint []byte) ([]byte, error) {
			return nil, pskRejected
		},
		PSKIdentityHint: []byte{},
		CipherSuites:    []CipherSuiteID{TLS_PSK_WITH_AES_128_CCM_8},
	}

	if _, err := testServer(ctx, cb, config, false); !errors.Is(err, serverAlertError) {
		t.Fatalf("TestPSK: Server error exp(%v) failed(%v)", serverAlertError, err)
	}

	if err := <-clientErr; !errors.Is(err, pskRejected) {
		t.Fatalf("TestPSK: Client error exp(%v) failed(%v)", pskRejected, err)
	}
}

func TestClientTimeout(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	clientErr := make(chan error, 1)

	ca, _ := dpipe.Pipe()
	go func() {
		conf := &Config{}

		c, err := testClient(ctx, ca, conf, true)
		if err == nil {
			_ = c.Close() //nolint:contextcheck
		}
		clientErr <- err
	}()

	// no server!
	err := <-clientErr
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("Client error exp(Temporary network error) failed(%v)", err)
	}
}

func TestSRTPConfiguration(t *testing.T) {
	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	for _, test := range []struct {
		Name            string
		ClientSRTP      []SRTPProtectionProfile
		ServerSRTP      []SRTPProtectionProfile
		ExpectedProfile SRTPProtectionProfile
		WantClientError error
		WantServerError error
	}{
		{
			Name:            "No SRTP in use",
			ClientSRTP:      nil,
			ServerSRTP:      nil,
			ExpectedProfile: 0,
			WantClientError: nil,
			WantServerError: nil,
		},
		{
			Name:            "SRTP both ends",
			ClientSRTP:      []SRTPProtectionProfile{SRTP_AES128_CM_HMAC_SHA1_80},
			ServerSRTP:      []SRTPProtectionProfile{SRTP_AES128_CM_HMAC_SHA1_80},
			ExpectedProfile: SRTP_AES128_CM_HMAC_SHA1_80,
			WantClientError: nil,
			WantServerError: nil,
		},
		{
			Name:            "SRTP client only",
			ClientSRTP:      []SRTPProtectionProfile{SRTP_AES128_CM_HMAC_SHA1_80},
			ServerSRTP:      nil,
			ExpectedProfile: 0,
			WantClientError: &alertError{&alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}},
			WantServerError: errServerNoMatchingSRTPProfile,
		},
		{
			Name:            "SRTP server only",
			ClientSRTP:      nil,
			ServerSRTP:      []SRTPProtectionProfile{SRTP_AES128_CM_HMAC_SHA1_80},
			ExpectedProfile: 0,
			WantClientError: nil,
			WantServerError: nil,
		},
		{
			Name:            "Multiple Suites",
			ClientSRTP:      []SRTPProtectionProfile{SRTP_AES128_CM_HMAC_SHA1_80, SRTP_AES128_CM_HMAC_SHA1_32},
			ServerSRTP:      []SRTPProtectionProfile{SRTP_AES128_CM_HMAC_SHA1_80, SRTP_AES128_CM_HMAC_SHA1_32},
			ExpectedProfile: SRTP_AES128_CM_HMAC_SHA1_80,
			WantClientError: nil,
			WantServerError: nil,
		},
		{
			Name:            "Multiple Suites, Client Chooses",
			ClientSRTP:      []SRTPProtectionProfile{SRTP_AES128_CM_HMAC_SHA1_80, SRTP_AES128_CM_HMAC_SHA1_32},
			ServerSRTP:      []SRTPProtectionProfile{SRTP_AES128_CM_HMAC_SHA1_32, SRTP_AES128_CM_HMAC_SHA1_80},
			ExpectedProfile: SRTP_AES128_CM_HMAC_SHA1_80,
			WantClientError: nil,
			WantServerError: nil,
		},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		ca, cb := dpipe.Pipe()
		type result struct {
			c   *Conn
			err error
		}
		c := make(chan result)

		go func() {
			client, err := testClient(ctx, ca, &Config{SRTPProtectionProfiles: test.ClientSRTP}, true)
			c <- result{client, err}
		}()

		server, err := testServer(ctx, cb, &Config{SRTPProtectionProfiles: test.ServerSRTP}, true)
		if !errors.Is(err, test.WantServerError) {
			t.Errorf("TestSRTPConfiguration: Server Error Mismatch '%s': expected(%v) actual(%v)", test.Name, test.WantServerError, err)
		}
		if err == nil {
			defer func() {
				_ = server.Close()
			}()
		}

		res := <-c
		if res.err == nil {
			defer func() {
				_ = res.c.Close()
			}()
		}
		if !errors.Is(res.err, test.WantClientError) {
			t.Fatalf("TestSRTPConfiguration: Client Error Mismatch '%s': expected(%v) actual(%v)", test.Name, test.WantClientError, res.err)
		}
		if res.c == nil {
			return
		}

		actualClientSRTP, _ := res.c.SelectedSRTPProtectionProfile()
		if actualClientSRTP != test.ExpectedProfile {
			t.Errorf("TestSRTPConfiguration: Client SRTPProtectionProfile Mismatch '%s': expected(%v) actual(%v)", test.Name, test.ExpectedProfile, actualClientSRTP)
		}

		actualServerSRTP, _ := server.SelectedSRTPProtectionProfile()
		if actualServerSRTP != test.ExpectedProfile {
			t.Errorf("TestSRTPConfiguration: Server SRTPProtectionProfile Mismatch '%s': expected(%v) actual(%v)", test.Name, test.ExpectedProfile, actualServerSRTP)
		}
	}
}

func TestClientCertificate(t *testing.T) {
	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	srvCert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	srvCAPool := x509.NewCertPool()
	srvCertificate, err := x509.ParseCertificate(srvCert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	srvCAPool.AddCert(srvCertificate)

	cert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	caPool := x509.NewCertPool()
	caPool.AddCert(certificate)

	t.Run("parallel", func(t *testing.T) { // sync routines to check routine leak
		tests := map[string]struct {
			clientCfg *Config
			serverCfg *Config
			wantErr   bool
		}{
			"NoClientCert": {
				clientCfg: &Config{RootCAs: srvCAPool},
				serverCfg: &Config{
					Certificates: []tls.Certificate{srvCert},
					ClientAuth:   NoClientCert,
					ClientCAs:    caPool,
				},
			},
			"NoClientCert_ServerVerifyConnectionFails": {
				clientCfg: &Config{RootCAs: srvCAPool},
				serverCfg: &Config{
					Certificates: []tls.Certificate{srvCert},
					ClientAuth:   NoClientCert,
					ClientCAs:    caPool,
					VerifyConnection: func(s *State) error {
						return errExample
					},
				},
				wantErr: true,
			},
			"NoClientCert_ClientVerifyConnectionFails": {
				clientCfg: &Config{RootCAs: srvCAPool, VerifyConnection: func(s *State) error {
					return errExample
				}},
				serverCfg: &Config{
					Certificates: []tls.Certificate{srvCert},
					ClientAuth:   NoClientCert,
					ClientCAs:    caPool,
				},
				wantErr: true,
			},
			"NoClientCert_cert": {
				clientCfg: &Config{RootCAs: srvCAPool, Certificates: []tls.Certificate{cert}},
				serverCfg: &Config{
					Certificates: []tls.Certificate{srvCert},
					ClientAuth:   RequireAnyClientCert,
				},
			},
			"RequestClientCert_cert": {
				clientCfg: &Config{RootCAs: srvCAPool, Certificates: []tls.Certificate{cert}},
				serverCfg: &Config{
					Certificates: []tls.Certificate{srvCert},
					ClientAuth:   RequestClientCert,
				},
			},
			"RequestClientCert_no_cert": {
				clientCfg: &Config{RootCAs: srvCAPool},
				serverCfg: &Config{
					Certificates: []tls.Certificate{srvCert},
					ClientAuth:   RequestClientCert,
					ClientCAs:    caPool,
				},
			},
			"RequireAnyClientCert": {
				clientCfg: &Config{RootCAs: srvCAPool, Certificates: []tls.Certificate{cert}},
				serverCfg: &Config{
					Certificates: []tls.Certificate{srvCert},
					ClientAuth:   RequireAnyClientCert,
				},
			},
			"RequireAnyClientCert_error": {
				clientCfg: &Config{RootCAs: srvCAPool},
				serverCfg: &Config{
					Certificates: []tls.Certificate{srvCert},
					ClientAuth:   RequireAnyClientCert,
				},
				wantErr: true,
			},
			"VerifyClientCertIfGiven_no_cert": {
				clientCfg: &Config{RootCAs: srvCAPool},
				serverCfg: &Config{
					Certificates: []tls.Certificate{srvCert},
					ClientAuth:   VerifyClientCertIfGiven,
					ClientCAs:    caPool,
				},
			},
			"VerifyClientCertIfGiven_cert": {
				clientCfg: &Config{RootCAs: srvCAPool, Certificates: []tls.Certificate{cert}},
				serverCfg: &Config{
					Certificates: []tls.Certificate{srvCert},
					ClientAuth:   VerifyClientCertIfGiven,
					ClientCAs:    caPool,
				},
			},
			"VerifyClientCertIfGiven_error": {
				clientCfg: &Config{RootCAs: srvCAPool, Certificates: []tls.Certificate{cert}},
				serverCfg: &Config{
					Certificates: []tls.Certificate{srvCert},
					ClientAuth:   VerifyClientCertIfGiven,
				},
				wantErr: true,
			},
			"RequireAndVerifyClientCert": {
				clientCfg: &Config{RootCAs: srvCAPool, Certificates: []tls.Certificate{cert}, VerifyConnection: func(s *State) error {
					if ok := bytes.Equal(s.PeerCertificates[0], srvCertificate.Raw); !ok {
						return errExample
					}
					return nil
				}},
				serverCfg: &Config{
					Certificates: []tls.Certificate{srvCert},
					ClientAuth:   RequireAndVerifyClientCert,
					ClientCAs:    caPool,
					VerifyConnection: func(s *State) error {
						if ok := bytes.Equal(s.PeerCertificates[0], certificate.Raw); !ok {
							return errExample
						}
						return nil
					},
				},
			},
			"RequireAndVerifyClientCert_callbacks": {
				clientCfg: &Config{
					RootCAs: srvCAPool,
					// Certificates:   []tls.Certificate{cert},
					GetClientCertificate: func(cri *CertificateRequestInfo) (*tls.Certificate, error) { return &cert, nil },
				},
				serverCfg: &Config{
					GetCertificate: func(chi *ClientHelloInfo) (*tls.Certificate, error) { return &srvCert, nil },
					// Certificates:   []tls.Certificate{srvCert},
					ClientAuth: RequireAndVerifyClientCert,
					ClientCAs:  caPool,
				},
			},
		}
		for name, tt := range tests {
			tt := tt
			t.Run(name, func(t *testing.T) {
				ca, cb := dpipe.Pipe()
				type result struct {
					c   *Conn
					err error
				}
				c := make(chan result)

				go func() {
					client, err := Client(ca, tt.clientCfg)
					c <- result{client, err}
				}()

				server, err := Server(cb, tt.serverCfg)
				res := <-c
				defer func() {
					if err == nil {
						_ = server.Close()
					}
					if res.err == nil {
						_ = res.c.Close()
					}
				}()

				if tt.wantErr {
					if err != nil {
						// Error expected, test succeeded
						return
					}
					t.Error("Error expected")
				}
				if err != nil {
					t.Errorf("Server failed(%v)", err)
				}

				if res.err != nil {
					t.Errorf("Client failed(%v)", res.err)
				}

				actualClientCert := server.ConnectionState().PeerCertificates
				if tt.serverCfg.ClientAuth == RequireAnyClientCert || tt.serverCfg.ClientAuth == RequireAndVerifyClientCert {
					if actualClientCert == nil {
						t.Errorf("Client did not provide a certificate")
					}

					var cfgCert [][]byte
					if len(tt.clientCfg.Certificates) > 0 {
						cfgCert = tt.clientCfg.Certificates[0].Certificate
					}
					if tt.clientCfg.GetClientCertificate != nil {
						crt, err := tt.clientCfg.GetClientCertificate(&CertificateRequestInfo{})
						if err != nil {
							t.Errorf("Server configuration did not provide a certificate")
						}
						cfgCert = crt.Certificate
					}
					if len(cfgCert) == 0 || !bytes.Equal(cfgCert[0], actualClientCert[0]) {
						t.Errorf("Client certificate was not communicated correctly")
					}
				}
				if tt.serverCfg.ClientAuth == NoClientCert {
					if actualClientCert != nil {
						t.Errorf("Client certificate wasn't expected")
					}
				}

				actualServerCert := res.c.ConnectionState().PeerCertificates
				if actualServerCert == nil {
					t.Errorf("Server did not provide a certificate")
				}
				var cfgCert [][]byte
				if len(tt.serverCfg.Certificates) > 0 {
					cfgCert = tt.serverCfg.Certificates[0].Certificate
				}
				if tt.serverCfg.GetCertificate != nil {
					crt, err := tt.serverCfg.GetCertificate(&ClientHelloInfo{})
					if err != nil {
						t.Errorf("Server configuration did not provide a certificate")
					}
					cfgCert = crt.Certificate
				}
				if len(cfgCert) == 0 || !bytes.Equal(cfgCert[0], actualServerCert[0]) {
					t.Errorf("Server certificate was not communicated correctly")
				}
			})
		}
	})
}

func TestExtendedMasterSecret(t *testing.T) {
	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	tests := map[string]struct {
		clientCfg         *Config
		serverCfg         *Config
		expectedClientErr error
		expectedServerErr error
	}{
		"Request_Request_ExtendedMasterSecret": {
			clientCfg: &Config{
				ExtendedMasterSecret: RequestExtendedMasterSecret,
			},
			serverCfg: &Config{
				ExtendedMasterSecret: RequestExtendedMasterSecret,
			},
			expectedClientErr: nil,
			expectedServerErr: nil,
		},
		"Request_Require_ExtendedMasterSecret": {
			clientCfg: &Config{
				ExtendedMasterSecret: RequestExtendedMasterSecret,
			},
			serverCfg: &Config{
				ExtendedMasterSecret: RequireExtendedMasterSecret,
			},
			expectedClientErr: nil,
			expectedServerErr: nil,
		},
		"Request_Disable_ExtendedMasterSecret": {
			clientCfg: &Config{
				ExtendedMasterSecret: RequestExtendedMasterSecret,
			},
			serverCfg: &Config{
				ExtendedMasterSecret: DisableExtendedMasterSecret,
			},
			expectedClientErr: nil,
			expectedServerErr: nil,
		},
		"Require_Request_ExtendedMasterSecret": {
			clientCfg: &Config{
				ExtendedMasterSecret: RequireExtendedMasterSecret,
			},
			serverCfg: &Config{
				ExtendedMasterSecret: RequestExtendedMasterSecret,
			},
			expectedClientErr: nil,
			expectedServerErr: nil,
		},
		"Require_Require_ExtendedMasterSecret": {
			clientCfg: &Config{
				ExtendedMasterSecret: RequireExtendedMasterSecret,
			},
			serverCfg: &Config{
				ExtendedMasterSecret: RequireExtendedMasterSecret,
			},
			expectedClientErr: nil,
			expectedServerErr: nil,
		},
		"Require_Disable_ExtendedMasterSecret": {
			clientCfg: &Config{
				ExtendedMasterSecret: RequireExtendedMasterSecret,
			},
			serverCfg: &Config{
				ExtendedMasterSecret: DisableExtendedMasterSecret,
			},
			expectedClientErr: errClientRequiredButNoServerEMS,
			expectedServerErr: &alertError{&alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}},
		},
		"Disable_Request_ExtendedMasterSecret": {
			clientCfg: &Config{
				ExtendedMasterSecret: DisableExtendedMasterSecret,
			},
			serverCfg: &Config{
				ExtendedMasterSecret: RequestExtendedMasterSecret,
			},
			expectedClientErr: nil,
			expectedServerErr: nil,
		},
		"Disable_Require_ExtendedMasterSecret": {
			clientCfg: &Config{
				ExtendedMasterSecret: DisableExtendedMasterSecret,
			},
			serverCfg: &Config{
				ExtendedMasterSecret: RequireExtendedMasterSecret,
			},
			expectedClientErr: &alertError{&alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}},
			expectedServerErr: errServerRequiredButNoClientEMS,
		},
		"Disable_Disable_ExtendedMasterSecret": {
			clientCfg: &Config{
				ExtendedMasterSecret: DisableExtendedMasterSecret,
			},
			serverCfg: &Config{
				ExtendedMasterSecret: DisableExtendedMasterSecret,
			},
			expectedClientErr: nil,
			expectedServerErr: nil,
		},
	}
	for name, tt := range tests {
		tt := tt
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			ca, cb := dpipe.Pipe()
			type result struct {
				c   *Conn
				err error
			}
			c := make(chan result)

			go func() {
				client, err := testClient(ctx, ca, tt.clientCfg, true)
				c <- result{client, err}
			}()

			server, err := testServer(ctx, cb, tt.serverCfg, true)
			res := <-c
			defer func() {
				if err == nil {
					_ = server.Close()
				}
				if res.err == nil {
					_ = res.c.Close()
				}
			}()

			if !errors.Is(res.err, tt.expectedClientErr) {
				t.Errorf("Client error expected: \"%v\" but got \"%v\"", tt.expectedClientErr, res.err)
			}

			if !errors.Is(err, tt.expectedServerErr) {
				t.Errorf("Server error expected: \"%v\" but got \"%v\"", tt.expectedServerErr, err)
			}
		})
	}
}

func TestServerCertificate(t *testing.T) {
	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	cert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	caPool := x509.NewCertPool()
	caPool.AddCert(certificate)

	t.Run("parallel", func(t *testing.T) { // sync routines to check routine leak
		tests := map[string]struct {
			clientCfg *Config
			serverCfg *Config
			wantErr   bool
		}{
			"no_ca": {
				clientCfg: &Config{},
				serverCfg: &Config{Certificates: []tls.Certificate{cert}, ClientAuth: NoClientCert},
				wantErr:   true,
			},
			"good_ca": {
				clientCfg: &Config{RootCAs: caPool},
				serverCfg: &Config{Certificates: []tls.Certificate{cert}, ClientAuth: NoClientCert},
			},
			"no_ca_skip_verify": {
				clientCfg: &Config{InsecureSkipVerify: true},
				serverCfg: &Config{Certificates: []tls.Certificate{cert}, ClientAuth: NoClientCert},
			},
			"good_ca_skip_verify_custom_verify_peer": {
				clientCfg: &Config{RootCAs: caPool, Certificates: []tls.Certificate{cert}},
				serverCfg: &Config{Certificates: []tls.Certificate{cert}, ClientAuth: RequireAnyClientCert, VerifyPeerCertificate: func(cert [][]byte, chain [][]*x509.Certificate) error {
					if len(chain) != 0 {
						return errNotExpectedChain
					}
					return nil
				}},
			},
			"good_ca_verify_custom_verify_peer": {
				clientCfg: &Config{RootCAs: caPool, Certificates: []tls.Certificate{cert}},
				serverCfg: &Config{ClientCAs: caPool, Certificates: []tls.Certificate{cert}, ClientAuth: RequireAndVerifyClientCert, VerifyPeerCertificate: func(cert [][]byte, chain [][]*x509.Certificate) error {
					if len(chain) == 0 {
						return errExpecedChain
					}
					return nil
				}},
			},
			"good_ca_custom_verify_peer": {
				clientCfg: &Config{
					RootCAs: caPool,
					VerifyPeerCertificate: func([][]byte, [][]*x509.Certificate) error {
						return errWrongCert
					},
				},
				serverCfg: &Config{Certificates: []tls.Certificate{cert}, ClientAuth: NoClientCert},
				wantErr:   true,
			},
			"server_name": {
				clientCfg: &Config{RootCAs: caPool, ServerName: certificate.Subject.CommonName},
				serverCfg: &Config{Certificates: []tls.Certificate{cert}, ClientAuth: NoClientCert},
			},
			"server_name_error": {
				clientCfg: &Config{RootCAs: caPool, ServerName: "barfoo"},
				serverCfg: &Config{Certificates: []tls.Certificate{cert}, ClientAuth: NoClientCert},
				wantErr:   true,
			},
		}
		for name, tt := range tests {
			tt := tt
			t.Run(name, func(t *testing.T) {
				ca, cb := dpipe.Pipe()

				type result struct {
					c   *Conn
					err error
				}
				srvCh := make(chan result)
				go func() {
					s, err := Server(cb, tt.serverCfg)
					srvCh <- result{s, err}
				}()

				cli, err := Client(ca, tt.clientCfg)
				if err == nil {
					_ = cli.Close()
				}
				if !tt.wantErr && err != nil {
					t.Errorf("Client failed(%v)", err)
				}
				if tt.wantErr && err == nil {
					t.Fatal("Error expected")
				}

				srv := <-srvCh
				if srv.err == nil {
					_ = srv.c.Close()
				}
			})
		}
	})
}

func TestCipherSuiteConfiguration(t *testing.T) {
	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	for _, test := range []struct {
		Name                    string
		ClientCipherSuites      []CipherSuiteID
		ServerCipherSuites      []CipherSuiteID
		WantClientError         error
		WantServerError         error
		WantSelectedCipherSuite CipherSuiteID
	}{
		{
			Name:               "No CipherSuites specified",
			ClientCipherSuites: nil,
			ServerCipherSuites: nil,
			WantClientError:    nil,
			WantServerError:    nil,
		},
		{
			Name:               "Invalid CipherSuite",
			ClientCipherSuites: []CipherSuiteID{0x00},
			ServerCipherSuites: []CipherSuiteID{0x00},
			WantClientError:    &invalidCipherSuiteError{0x00},
			WantServerError:    &invalidCipherSuiteError{0x00},
		},
		{
			Name:                    "Valid CipherSuites specified",
			ClientCipherSuites:      []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			ServerCipherSuites:      []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			WantClientError:         nil,
			WantServerError:         nil,
			WantSelectedCipherSuite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
		{
			Name:               "CipherSuites mismatch",
			ClientCipherSuites: []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			ServerCipherSuites: []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA},
			WantClientError:    &alertError{&alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}},
			WantServerError:    errCipherSuiteNoIntersection,
		},
		{
			Name:                    "Valid CipherSuites CCM specified",
			ClientCipherSuites:      []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_CCM},
			ServerCipherSuites:      []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_CCM},
			WantClientError:         nil,
			WantServerError:         nil,
			WantSelectedCipherSuite: TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
		},
		{
			Name:                    "Valid CipherSuites CCM-8 specified",
			ClientCipherSuites:      []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8},
			ServerCipherSuites:      []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8},
			WantClientError:         nil,
			WantServerError:         nil,
			WantSelectedCipherSuite: TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
		},
		{
			Name:                    "Server supports subset of client suites",
			ClientCipherSuites:      []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA},
			ServerCipherSuites:      []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA},
			WantClientError:         nil,
			WantServerError:         nil,
			WantSelectedCipherSuite: TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		},
	} {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			ca, cb := dpipe.Pipe()
			type result struct {
				c   *Conn
				err error
			}
			c := make(chan result)

			go func() {
				client, err := testClient(ctx, ca, &Config{CipherSuites: test.ClientCipherSuites}, true)
				c <- result{client, err}
			}()

			server, err := testServer(ctx, cb, &Config{CipherSuites: test.ServerCipherSuites}, true)
			if err == nil {
				defer func() {
					_ = server.Close()
				}()
			}
			if !errors.Is(err, test.WantServerError) {
				t.Errorf("TestCipherSuiteConfiguration: Server Error Mismatch '%s': expected(%v) actual(%v)", test.Name, test.WantServerError, err)
			}

			res := <-c
			if res.err == nil {
				_ = server.Close()
				_ = res.c.Close()
			}
			if !errors.Is(res.err, test.WantClientError) {
				t.Errorf("TestSRTPConfiguration: Client Error Mismatch '%s': expected(%v) actual(%v)", test.Name, test.WantClientError, res.err)
			}
			if test.WantSelectedCipherSuite != 0x00 && res.c.state.cipherSuite.ID() != test.WantSelectedCipherSuite {
				t.Errorf("TestCipherSuiteConfiguration: Server Selected Bad Cipher Suite '%s': expected(%v) actual(%v)", test.Name, test.WantSelectedCipherSuite, res.c.state.cipherSuite.ID())
			}
		})
	}
}

func TestCertificateAndPSKServer(t *testing.T) {
	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	for _, test := range []struct {
		Name      string
		ClientPSK bool
	}{
		{
			Name:      "Client uses PKI",
			ClientPSK: false,
		},
		{
			Name:      "Client uses PSK",
			ClientPSK: true,
		},
	} {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			ca, cb := dpipe.Pipe()
			type result struct {
				c   *Conn
				err error
			}
			c := make(chan result)

			go func() {
				config := &Config{CipherSuites: []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}}
				if test.ClientPSK {
					config.PSK = func([]byte) ([]byte, error) {
						return []byte{0x00, 0x01, 0x02}, nil
					}
					config.PSKIdentityHint = []byte{0x00}
					config.CipherSuites = []CipherSuiteID{TLS_PSK_WITH_AES_128_GCM_SHA256}
				}

				client, err := testClient(ctx, ca, config, false)
				c <- result{client, err}
			}()

			config := &Config{
				CipherSuites: []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_PSK_WITH_AES_128_GCM_SHA256},
				PSK: func([]byte) ([]byte, error) {
					return []byte{0x00, 0x01, 0x02}, nil
				},
			}

			server, err := testServer(ctx, cb, config, true)
			if err == nil {
				defer func() {
					_ = server.Close()
				}()
			} else {
				t.Errorf("TestCertificateAndPSKServer: Server Error Mismatch '%s': expected(%v) actual(%v)", test.Name, nil, err)
			}

			res := <-c
			if res.err == nil {
				_ = server.Close()
				_ = res.c.Close()
			} else {
				t.Errorf("TestCertificateAndPSKServer: Client Error Mismatch '%s': expected(%v) actual(%v)", test.Name, nil, res.err)
			}
		})
	}
}

func TestPSKConfiguration(t *testing.T) {
	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	for _, test := range []struct {
		Name                 string
		ClientHasCertificate bool
		ServerHasCertificate bool
		ClientPSK            PSKCallback
		ServerPSK            PSKCallback
		ClientPSKIdentity    []byte
		ServerPSKIdentity    []byte
		WantClientError      error
		WantServerError      error
	}{
		{
			Name:                 "PSK and no certificate specified",
			ClientHasCertificate: false,
			ServerHasCertificate: false,
			ClientPSK:            func([]byte) ([]byte, error) { return []byte{0x00, 0x01, 0x02}, nil },
			ServerPSK:            func([]byte) ([]byte, error) { return []byte{0x00, 0x01, 0x02}, nil },
			ClientPSKIdentity:    []byte{0x00},
			ServerPSKIdentity:    []byte{0x00},
			WantClientError:      errNoAvailablePSKCipherSuite,
			WantServerError:      errNoAvailablePSKCipherSuite,
		},
		{
			Name:                 "PSK and certificate specified",
			ClientHasCertificate: true,
			ServerHasCertificate: true,
			ClientPSK:            func([]byte) ([]byte, error) { return []byte{0x00, 0x01, 0x02}, nil },
			ServerPSK:            func([]byte) ([]byte, error) { return []byte{0x00, 0x01, 0x02}, nil },
			ClientPSKIdentity:    []byte{0x00},
			ServerPSKIdentity:    []byte{0x00},
			WantClientError:      errNoAvailablePSKCipherSuite,
			WantServerError:      errNoAvailablePSKCipherSuite,
		},
		{
			Name:                 "PSK and no identity specified",
			ClientHasCertificate: false,
			ServerHasCertificate: false,
			ClientPSK:            func([]byte) ([]byte, error) { return []byte{0x00, 0x01, 0x02}, nil },
			ServerPSK:            func([]byte) ([]byte, error) { return []byte{0x00, 0x01, 0x02}, nil },
			ClientPSKIdentity:    nil,
			ServerPSKIdentity:    nil,
			WantClientError:      errPSKAndIdentityMustBeSetForClient,
			WantServerError:      errNoAvailablePSKCipherSuite,
		},
		{
			Name:                 "No PSK and identity specified",
			ClientHasCertificate: false,
			ServerHasCertificate: false,
			ClientPSK:            nil,
			ServerPSK:            nil,
			ClientPSKIdentity:    []byte{0x00},
			ServerPSKIdentity:    []byte{0x00},
			WantClientError:      errIdentityNoPSK,
			WantServerError:      errIdentityNoPSK,
		},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		ca, cb := dpipe.Pipe()
		type result struct {
			c   *Conn
			err error
		}
		c := make(chan result)

		go func() {
			client, err := testClient(ctx, ca, &Config{PSK: test.ClientPSK, PSKIdentityHint: test.ClientPSKIdentity}, test.ClientHasCertificate)
			c <- result{client, err}
		}()

		_, err := testServer(ctx, cb, &Config{PSK: test.ServerPSK, PSKIdentityHint: test.ServerPSKIdentity}, test.ServerHasCertificate)
		if err != nil || test.WantServerError != nil {
			if !(err != nil && test.WantServerError != nil && err.Error() == test.WantServerError.Error()) {
				t.Fatalf("TestPSKConfiguration: Server Error Mismatch '%s': expected(%v) actual(%v)", test.Name, test.WantServerError, err)
			}
		}

		res := <-c
		if res.err != nil || test.WantClientError != nil {
			if !(res.err != nil && test.WantClientError != nil && res.err.Error() == test.WantClientError.Error()) {
				t.Fatalf("TestPSKConfiguration: Client Error Mismatch '%s': expected(%v) actual(%v)", test.Name, test.WantClientError, res.err)
			}
		}
	}
}

func TestServerTimeout(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	cookie := make([]byte, 20)
	_, err := rand.Read(cookie)
	if err != nil {
		t.Fatal(err)
	}

	var rand [28]byte
	random := handshake.Random{GMTUnixTime: time.Unix(500, 0), RandomBytes: rand}

	cipherSuites := []CipherSuite{
		&ciphersuite.TLSEcdheEcdsaWithAes128GcmSha256{},
		&ciphersuite.TLSEcdheRsaWithAes128GcmSha256{},
	}

	extensions := []extension.Extension{
		&extension.SupportedSignatureAlgorithms{
			SignatureHashAlgorithms: []signaturehash.Algorithm{
				{Hash: hash.SHA256, Signature: signature.ECDSA},
				{Hash: hash.SHA384, Signature: signature.ECDSA},
				{Hash: hash.SHA512, Signature: signature.ECDSA},
				{Hash: hash.SHA256, Signature: signature.RSA},
				{Hash: hash.SHA384, Signature: signature.RSA},
				{Hash: hash.SHA512, Signature: signature.RSA},
			},
		},
		&extension.SupportedEllipticCurves{
			EllipticCurves: []elliptic.Curve{elliptic.X25519, elliptic.P256, elliptic.P384},
		},
		&extension.SupportedPointFormats{
			PointFormats: []elliptic.CurvePointFormat{elliptic.CurvePointFormatUncompressed},
		},
	}

	record := &recordlayer.RecordLayer{
		Header: recordlayer.Header{
			SequenceNumber: 0,
			Version:        protocol.Version1_2,
		},
		Content: &handshake.Handshake{
			// sequenceNumber and messageSequence line up, may need to be re-evaluated
			Header: handshake.Header{
				MessageSequence: 0,
			},
			Message: &handshake.MessageClientHello{
				Version:            protocol.Version1_2,
				Cookie:             cookie,
				Random:             random,
				CipherSuiteIDs:     cipherSuiteIDs(cipherSuites),
				CompressionMethods: defaultCompressionMethods(),
				Extensions:         extensions,
			},
		},
	}

	packet, err := record.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	ca, cb := dpipe.Pipe()
	defer func() {
		err := ca.Close()
		if err != nil {
			t.Fatal(err)
		}
	}()

	// Client reader
	caReadChan := make(chan []byte, 1000)
	go func() {
		for {
			data := make([]byte, 8192)
			n, err := ca.Read(data)
			if err != nil {
				return
			}

			caReadChan <- data[:n]
		}
	}()

	// Start sending ClientHello packets until server responds with first packet
	go func() {
		for {
			select {
			case <-time.After(10 * time.Millisecond):
				_, err := ca.Write(packet)
				if err != nil {
					return
				}
			case <-caReadChan:
				// Once we receive the first reply from the server, stop
				return
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	config := &Config{
		CipherSuites:   []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		FlightInterval: 100 * time.Millisecond,
	}

	_, serverErr := testServer(ctx, cb, config, true)
	var netErr net.Error
	if !errors.As(serverErr, &netErr) || !netErr.Timeout() {
		t.Fatalf("Client error exp(Temporary network error) failed(%v)", serverErr)
	}

	// Wait a little longer to ensure no additional messages have been sent by the server
	time.Sleep(300 * time.Millisecond)
	select {
	case msg := <-caReadChan:
		t.Fatalf("Expected no additional messages from server, got: %+v", msg)
	default:
	}
}

func TestProtocolVersionValidation(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	cookie := make([]byte, 20)
	if _, err := rand.Read(cookie); err != nil {
		t.Fatal(err)
	}

	var rand [28]byte
	random := handshake.Random{GMTUnixTime: time.Unix(500, 0), RandomBytes: rand}

	config := &Config{
		CipherSuites:   []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		FlightInterval: 100 * time.Millisecond,
	}

	t.Run("Server", func(t *testing.T) {
		serverCases := map[string]struct {
			records []*recordlayer.RecordLayer
		}{
			"ClientHelloVersion": {
				records: []*recordlayer.RecordLayer{
					{
						Header: recordlayer.Header{
							Version: protocol.Version1_2,
						},
						Content: &handshake.Handshake{
							Message: &handshake.MessageClientHello{
								Version:            protocol.Version{Major: 0xfe, Minor: 0xff}, // try to downgrade
								Cookie:             cookie,
								Random:             random,
								CipherSuiteIDs:     []uint16{uint16((&ciphersuite.TLSEcdheEcdsaWithAes128GcmSha256{}).ID())},
								CompressionMethods: defaultCompressionMethods(),
							},
						},
					},
				},
			},
			"SecondsClientHelloVersion": {
				records: []*recordlayer.RecordLayer{
					{
						Header: recordlayer.Header{
							Version: protocol.Version1_2,
						},
						Content: &handshake.Handshake{
							Message: &handshake.MessageClientHello{
								Version:            protocol.Version1_2,
								Cookie:             cookie,
								Random:             random,
								CipherSuiteIDs:     []uint16{uint16((&ciphersuite.TLSEcdheEcdsaWithAes128GcmSha256{}).ID())},
								CompressionMethods: defaultCompressionMethods(),
							},
						},
					},
					{
						Header: recordlayer.Header{
							Version:        protocol.Version1_2,
							SequenceNumber: 1,
						},
						Content: &handshake.Handshake{
							Header: handshake.Header{
								MessageSequence: 1,
							},
							Message: &handshake.MessageClientHello{
								Version:            protocol.Version{Major: 0xfe, Minor: 0xff}, // try to downgrade
								Cookie:             cookie,
								Random:             random,
								CipherSuiteIDs:     []uint16{uint16((&ciphersuite.TLSEcdheEcdsaWithAes128GcmSha256{}).ID())},
								CompressionMethods: defaultCompressionMethods(),
							},
						},
					},
				},
			},
		}
		for name, c := range serverCases {
			c := c
			t.Run(name, func(t *testing.T) {
				ca, cb := dpipe.Pipe()
				defer func() {
					err := ca.Close()
					if err != nil {
						t.Error(err)
					}
				}()

				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()

				var wg sync.WaitGroup
				wg.Add(1)
				defer wg.Wait()
				go func() {
					defer wg.Done()
					if _, err := testServer(ctx, cb, config, true); !errors.Is(err, errUnsupportedProtocolVersion) {
						t.Errorf("Client error exp(%v) failed(%v)", errUnsupportedProtocolVersion, err)
					}
				}()

				time.Sleep(50 * time.Millisecond)

				resp := make([]byte, 1024)
				for _, record := range c.records {
					packet, err := record.Marshal()
					if err != nil {
						t.Fatal(err)
					}
					if _, werr := ca.Write(packet); werr != nil {
						t.Fatal(werr)
					}
					n, rerr := ca.Read(resp[:cap(resp)])
					if rerr != nil {
						t.Fatal(rerr)
					}
					resp = resp[:n]
				}

				h := &recordlayer.Header{}
				if err := h.Unmarshal(resp); err != nil {
					t.Fatal("Failed to unmarshal response")
				}
				if h.ContentType != protocol.ContentTypeAlert {
					t.Errorf("Peer must return alert to unsupported protocol version")
				}
			})
		}
	})

	t.Run("Client", func(t *testing.T) {
		clientCases := map[string]struct {
			records []*recordlayer.RecordLayer
		}{
			"ServerHelloVersion": {
				records: []*recordlayer.RecordLayer{
					{
						Header: recordlayer.Header{
							Version: protocol.Version1_2,
						},
						Content: &handshake.Handshake{
							Message: &handshake.MessageHelloVerifyRequest{
								Version: protocol.Version1_2,
								Cookie:  cookie,
							},
						},
					},
					{
						Header: recordlayer.Header{
							Version:        protocol.Version1_2,
							SequenceNumber: 1,
						},
						Content: &handshake.Handshake{
							Header: handshake.Header{
								MessageSequence: 1,
							},
							Message: &handshake.MessageServerHello{
								Version:           protocol.Version{Major: 0xfe, Minor: 0xff}, // try to downgrade
								Random:            random,
								CipherSuiteID:     func() *uint16 { id := uint16(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256); return &id }(),
								CompressionMethod: defaultCompressionMethods()[0],
							},
						},
					},
				},
			},
		}
		for name, c := range clientCases {
			c := c
			t.Run(name, func(t *testing.T) {
				ca, cb := dpipe.Pipe()
				defer func() {
					err := ca.Close()
					if err != nil {
						t.Error(err)
					}
				}()

				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()

				var wg sync.WaitGroup
				wg.Add(1)
				defer wg.Wait()
				go func() {
					defer wg.Done()
					if _, err := testClient(ctx, cb, config, true); !errors.Is(err, errUnsupportedProtocolVersion) {
						t.Errorf("Server error exp(%v) failed(%v)", errUnsupportedProtocolVersion, err)
					}
				}()

				time.Sleep(50 * time.Millisecond)

				for _, record := range c.records {
					if _, err := ca.Read(make([]byte, 1024)); err != nil {
						t.Fatal(err)
					}

					packet, err := record.Marshal()
					if err != nil {
						t.Fatal(err)
					}
					if _, err := ca.Write(packet); err != nil {
						t.Fatal(err)
					}
				}
				resp := make([]byte, 1024)
				n, err := ca.Read(resp)
				if err != nil {
					t.Fatal(err)
				}
				resp = resp[:n]

				h := &recordlayer.Header{}
				if err := h.Unmarshal(resp); err != nil {
					t.Fatal("Failed to unmarshal response")
				}
				if h.ContentType != protocol.ContentTypeAlert {
					t.Errorf("Peer must return alert to unsupported protocol version")
				}
			})
		}
	})
}

func TestMultipleHelloVerifyRequest(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	cookies := [][]byte{
		// first clientHello contains an empty cookie
		{},
	}
	var packets [][]byte
	for i := 0; i < 2; i++ {
		cookie := make([]byte, 20)
		if _, err := rand.Read(cookie); err != nil {
			t.Fatal(err)
		}
		cookies = append(cookies, cookie)

		record := &recordlayer.RecordLayer{
			Header: recordlayer.Header{
				SequenceNumber: uint64(i),
				Version:        protocol.Version1_2,
			},
			Content: &handshake.Handshake{
				Header: handshake.Header{
					MessageSequence: uint16(i),
				},
				Message: &handshake.MessageHelloVerifyRequest{
					Version: protocol.Version1_2,
					Cookie:  cookie,
				},
			},
		}
		packet, err := record.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		packets = append(packets, packet)
	}

	ca, cb := dpipe.Pipe()
	defer func() {
		err := ca.Close()
		if err != nil {
			t.Error(err)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	defer wg.Wait()
	go func() {
		defer wg.Done()
		_, _ = testClient(ctx, ca, &Config{}, false)
	}()

	for i, cookie := range cookies {
		// read client hello
		resp := make([]byte, 1024)
		n, err := cb.Read(resp)
		if err != nil {
			t.Fatal(err)
		}
		record := &recordlayer.RecordLayer{}
		if err := record.Unmarshal(resp[:n]); err != nil {
			t.Fatal(err)
		}
		clientHello, ok := record.Content.(*handshake.Handshake).Message.(*handshake.MessageClientHello)
		if !ok {
			t.Fatal("Failed to cast MessageClientHello")
		}

		if !bytes.Equal(clientHello.Cookie, cookie) {
			t.Fatalf("Wrong cookie, expected: %x, got: %x", clientHello.Cookie, cookie)
		}
		if len(packets) <= i {
			break
		}
		// write hello verify request
		if _, err := cb.Write(packets[i]); err != nil {
			t.Fatal(err)
		}
	}
	cancel()
}

// Assert that a DTLS Server always responds with RenegotiationInfo if
// a ClientHello contained that extension or not
func TestRenegotationInfo(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(10 * time.Second)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	resp := make([]byte, 1024)

	for _, testCase := range []struct {
		Name                  string
		SendRenegotiationInfo bool
	}{
		{
			"Include RenegotiationInfo",
			true,
		},
		{
			"No RenegotiationInfo",
			false,
		},
	} {
		test := testCase
		t.Run(test.Name, func(t *testing.T) {
			ca, cb := dpipe.Pipe()
			defer func() {
				if err := ca.Close(); err != nil {
					t.Error(err)
				}
			}()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			go func() {
				if _, err := testServer(ctx, cb, &Config{}, true); !errors.Is(err, context.Canceled) {
					t.Error(err)
				}
			}()

			time.Sleep(50 * time.Millisecond)

			extensions := []extension.Extension{}
			if test.SendRenegotiationInfo {
				extensions = append(extensions, &extension.RenegotiationInfo{
					RenegotiatedConnection: 0,
				})
			}
			err := sendClientHello([]byte{}, ca, 0, extensions)
			if err != nil {
				t.Fatal(err)
			}
			n, err := ca.Read(resp)
			if err != nil {
				t.Fatal(err)
			}
			r := &recordlayer.RecordLayer{}
			if err = r.Unmarshal(resp[:n]); err != nil {
				t.Fatal(err)
			}

			helloVerifyRequest, ok := r.Content.(*handshake.Handshake).Message.(*handshake.MessageHelloVerifyRequest)
			if !ok {
				t.Fatal("Failed to cast MessageHelloVerifyRequest")
			}

			err = sendClientHello(helloVerifyRequest.Cookie, ca, 1, extensions)
			if err != nil {
				t.Fatal(err)
			}
			if n, err = ca.Read(resp); err != nil {
				t.Fatal(err)
			}

			messages, err := recordlayer.UnpackDatagram(resp[:n])
			if err != nil {
				t.Fatal(err)
			}

			if err := r.Unmarshal(messages[0]); err != nil {
				t.Fatal(err)
			}

			serverHello, ok := r.Content.(*handshake.Handshake).Message.(*handshake.MessageServerHello)
			if !ok {
				t.Fatal("Failed to cast MessageServerHello")
			}

			gotNegotationInfo := false
			for _, v := range serverHello.Extensions {
				if _, ok := v.(*extension.RenegotiationInfo); ok {
					gotNegotationInfo = true
				}
			}

			if !gotNegotationInfo {
				t.Fatalf("Received ServerHello without RenegotiationInfo")
			}
		})
	}
}

func TestServerNameIndicationExtension(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	for _, test := range []struct {
		Name       string
		ServerName string
		Expected   []byte
		IncludeSNI bool
	}{
		{
			Name:       "Server name is a valid hostname",
			ServerName: "example.com",
			Expected:   []byte("example.com"),
			IncludeSNI: true,
		},
		{
			Name:       "Server name is an IP literal",
			ServerName: "1.2.3.4",
			Expected:   []byte(""),
			IncludeSNI: false,
		},
		{
			Name:       "Server name is empty",
			ServerName: "",
			Expected:   []byte(""),
			IncludeSNI: false,
		},
	} {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			ca, cb := dpipe.Pipe()
			go func() {
				conf := &Config{
					ServerName: test.ServerName,
				}

				_, _ = testClient(ctx, ca, conf, false)
			}()

			// Receive ClientHello
			resp := make([]byte, 1024)
			n, err := cb.Read(resp)
			if err != nil {
				t.Fatal(err)
			}
			r := &recordlayer.RecordLayer{}
			if err = r.Unmarshal(resp[:n]); err != nil {
				t.Fatal(err)
			}

			clientHello, ok := r.Content.(*handshake.Handshake).Message.(*handshake.MessageClientHello)
			if !ok {
				t.Fatal("Failed to cast MessageClientHello")
			}

			gotSNI := false
			var actualServerName string
			for _, v := range clientHello.Extensions {
				if _, ok := v.(*extension.ServerName); ok {
					gotSNI = true
					extensionServerName, ok := v.(*extension.ServerName)
					if !ok {
						t.Fatal("Failed to cast extension.ServerName")
					}

					actualServerName = extensionServerName.ServerName
				}
			}

			if gotSNI != test.IncludeSNI {
				t.Errorf("TestSNI: unexpected SNI inclusion '%s': expected(%v) actual(%v)", test.Name, test.IncludeSNI, gotSNI)
			}

			if !bytes.Equal([]byte(actualServerName), test.Expected) {
				t.Errorf("TestSNI: server name mismatch '%s': expected(%v) actual(%v)", test.Name, test.Expected, actualServerName)
			}
		})
	}
}

func TestALPNExtension(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	for _, test := range []struct {
		Name                   string
		ClientProtocolNameList []string
		ServerProtocolNameList []string
		ExpectedProtocol       string
		ExpectAlertFromClient  bool
		ExpectAlertFromServer  bool
		Alert                  alert.Description
	}{
		{
			Name:                   "Negotiate a protocol",
			ClientProtocolNameList: []string{"http/1.1", "spd/1"},
			ServerProtocolNameList: []string{"spd/1"},
			ExpectedProtocol:       "spd/1",
			ExpectAlertFromClient:  false,
			ExpectAlertFromServer:  false,
			Alert:                  0,
		},
		{
			Name:                   "Server doesn't support any",
			ClientProtocolNameList: []string{"http/1.1", "spd/1"},
			ServerProtocolNameList: []string{},
			ExpectedProtocol:       "",
			ExpectAlertFromClient:  false,
			ExpectAlertFromServer:  false,
			Alert:                  0,
		},
		{
			Name:                   "Negotiate with higher server precedence",
			ClientProtocolNameList: []string{"http/1.1", "spd/1", "http/3"},
			ServerProtocolNameList: []string{"ssh/2", "http/3", "spd/1"},
			ExpectedProtocol:       "http/3",
			ExpectAlertFromClient:  false,
			ExpectAlertFromServer:  false,
			Alert:                  0,
		},
		{
			Name:                   "Empty intersection",
			ClientProtocolNameList: []string{"http/1.1", "http/3"},
			ServerProtocolNameList: []string{"ssh/2", "spd/1"},
			ExpectedProtocol:       "",
			ExpectAlertFromClient:  false,
			ExpectAlertFromServer:  true,
			Alert:                  alert.NoApplicationProtocol,
		},
		{
			Name:                   "Multiple protocols in ServerHello",
			ClientProtocolNameList: []string{"http/1.1"},
			ServerProtocolNameList: []string{"http/1.1"},
			ExpectedProtocol:       "http/1.1",
			ExpectAlertFromClient:  true,
			ExpectAlertFromServer:  false,
			Alert:                  alert.InternalError,
		},
	} {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			ca, cb := dpipe.Pipe()
			go func() {
				conf := &Config{
					SupportedProtocols: test.ClientProtocolNameList,
				}
				_, _ = testClient(ctx, ca, conf, false)
			}()

			// Receive ClientHello
			resp := make([]byte, 1024)
			n, err := cb.Read(resp)
			if err != nil {
				t.Fatal(err)
			}

			ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel2()

			ca2, cb2 := dpipe.Pipe()
			go func() {
				conf := &Config{
					SupportedProtocols: test.ServerProtocolNameList,
				}
				if _, err2 := testServer(ctx2, cb2, conf, true); !errors.Is(err2, context.Canceled) {
					if test.ExpectAlertFromServer { //nolint
						// Assert the error type?
					} else {
						t.Error(err2)
					}
				}
			}()

			time.Sleep(50 * time.Millisecond)

			// Forward ClientHello
			if _, err = ca2.Write(resp[:n]); err != nil {
				t.Fatal(err)
			}

			// Receive HelloVerify
			resp2 := make([]byte, 1024)
			n, err = ca2.Read(resp2)
			if err != nil {
				t.Fatal(err)
			}

			// Forward HelloVerify
			if _, err = cb.Write(resp2[:n]); err != nil {
				t.Fatal(err)
			}

			// Receive ClientHello
			resp3 := make([]byte, 1024)
			n, err = cb.Read(resp3)
			if err != nil {
				t.Fatal(err)
			}

			// Forward ClientHello
			if _, err = ca2.Write(resp3[:n]); err != nil {
				t.Fatal(err)
			}

			// Receive ServerHello
			resp4 := make([]byte, 1024)
			n, err = ca2.Read(resp4)
			if err != nil {
				t.Fatal(err)
			}

			messages, err := recordlayer.UnpackDatagram(resp4[:n])
			if err != nil {
				t.Fatal(err)
			}

			r := &recordlayer.RecordLayer{}
			if err := r.Unmarshal(messages[0]); err != nil {
				t.Fatal(err)
			}

			if test.ExpectAlertFromServer {
				a, ok := r.Content.(*alert.Alert)
				if !ok {
					t.Fatal("Failed to cast alert.Alert")
				}

				if a.Description != test.Alert {
					t.Errorf("ALPN %v: expected(%v) actual(%v)", test.Name, test.Alert, a.Description)
				}
			} else {
				serverHello, ok := r.Content.(*handshake.Handshake).Message.(*handshake.MessageServerHello)
				if !ok {
					t.Fatal("Failed to cast handshake.MessageServerHello")
				}

				var negotiatedProtocol string
				for _, v := range serverHello.Extensions {
					if _, ok := v.(*extension.ALPN); ok {
						e, ok := v.(*extension.ALPN)
						if !ok {
							t.Fatal("Failed to cast extension.ALPN")
						}

						negotiatedProtocol = e.ProtocolNameList[0]

						// Manipulate ServerHello
						if test.ExpectAlertFromClient {
							e.ProtocolNameList = append(e.ProtocolNameList, "oops")
						}
					}
				}

				if negotiatedProtocol != test.ExpectedProtocol {
					t.Errorf("ALPN %v: expected(%v) actual(%v)", test.Name, test.ExpectedProtocol, negotiatedProtocol)
				}

				s, err := r.Marshal()
				if err != nil {
					t.Fatal(err)
				}

				// Forward ServerHello
				if _, err = cb.Write(s); err != nil {
					t.Fatal(err)
				}

				if test.ExpectAlertFromClient {
					resp5 := make([]byte, 1024)
					n, err = cb.Read(resp5)
					if err != nil {
						t.Fatal(err)
					}

					r2 := &recordlayer.RecordLayer{}
					if err := r2.Unmarshal(resp5[:n]); err != nil {
						t.Fatal(err)
					}

					a, ok := r2.Content.(*alert.Alert)
					if !ok {
						t.Fatal("Failed to cast alert.Alert")
					}

					if a.Description != test.Alert {
						t.Errorf("ALPN %v: expected(%v) actual(%v)", test.Name, test.Alert, a.Description)
					}
				}
			}

			time.Sleep(50 * time.Millisecond) // Give some time for returned errors
		})
	}
}

// Make sure the supported_groups extension is not included in the ServerHello
func TestSupportedGroupsExtension(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	t.Run("ServerHello Supported Groups", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		ca, cb := dpipe.Pipe()
		go func() {
			if _, err := testServer(ctx, cb, &Config{}, true); !errors.Is(err, context.Canceled) {
				t.Error(err)
			}
		}()
		extensions := []extension.Extension{
			&extension.SupportedEllipticCurves{
				EllipticCurves: []elliptic.Curve{elliptic.X25519, elliptic.P256, elliptic.P384},
			},
			&extension.SupportedPointFormats{
				PointFormats: []elliptic.CurvePointFormat{elliptic.CurvePointFormatUncompressed},
			},
		}

		time.Sleep(50 * time.Millisecond)

		resp := make([]byte, 1024)
		err := sendClientHello([]byte{}, ca, 0, extensions)
		if err != nil {
			t.Fatal(err)
		}

		// Receive ServerHello
		n, err := ca.Read(resp)
		if err != nil {
			t.Fatal(err)
		}
		r := &recordlayer.RecordLayer{}
		if err = r.Unmarshal(resp[:n]); err != nil {
			t.Fatal(err)
		}

		helloVerifyRequest, ok := r.Content.(*handshake.Handshake).Message.(*handshake.MessageHelloVerifyRequest)
		if !ok {
			t.Fatal("Failed to cast MessageHelloVerifyRequest")
		}

		err = sendClientHello(helloVerifyRequest.Cookie, ca, 1, extensions)
		if err != nil {
			t.Fatal(err)
		}
		if n, err = ca.Read(resp); err != nil {
			t.Fatal(err)
		}

		messages, err := recordlayer.UnpackDatagram(resp[:n])
		if err != nil {
			t.Fatal(err)
		}

		if err := r.Unmarshal(messages[0]); err != nil {
			t.Fatal(err)
		}

		serverHello, ok := r.Content.(*handshake.Handshake).Message.(*handshake.MessageServerHello)
		if !ok {
			t.Fatal("Failed to cast MessageServerHello")
		}

		gotGroups := false
		for _, v := range serverHello.Extensions {
			if _, ok := v.(*extension.SupportedEllipticCurves); ok {
				gotGroups = true
			}
		}

		if gotGroups {
			t.Errorf("TestSupportedGroups: supported_groups extension was sent in ServerHello")
		}
	})
}

func TestSessionResume(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	t.Run("resumed", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		type result struct {
			c   *Conn
			err error
		}
		clientRes := make(chan result, 1)

		ss := &memSessStore{}

		id, _ := hex.DecodeString("9b9fc92255634d9fb109febed42166717bb8ded8c738ba71bc7f2a0d9dae0306")
		secret, _ := hex.DecodeString("2e942a37aca5241deb2295b5fcedac221c7078d2503d2b62aeb48c880d7da73c001238b708559686b9da6e829c05ead7")

		s := Session{ID: id, Secret: secret}

		ca, cb := dpipe.Pipe()

		_ = ss.Set(id, s)
		_ = ss.Set([]byte(ca.RemoteAddr().String()+"_example.com"), s)

		go func() {
			config := &Config{
				CipherSuites: []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
				ServerName:   "example.com",
				SessionStore: ss,
				MTU:          100,
			}
			c, err := testClient(ctx, ca, config, false)
			clientRes <- result{c, err}
		}()

		config := &Config{
			CipherSuites: []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			ServerName:   "example.com",
			SessionStore: ss,
			MTU:          100,
		}
		server, err := testServer(ctx, cb, config, true)
		if err != nil {
			t.Fatalf("TestSessionResume: Server failed(%v)", err)
		}

		actualSessionID := server.ConnectionState().SessionID
		actualMasterSecret := server.ConnectionState().masterSecret
		if !bytes.Equal(actualSessionID, id) {
			t.Errorf("TestSessionResumetion: SessionID Mismatch: expected(%v) actual(%v)", id, actualSessionID)
		}
		if !bytes.Equal(actualMasterSecret, secret) {
			t.Errorf("TestSessionResumetion: masterSecret Mismatch: expected(%v) actual(%v)", secret, actualMasterSecret)
		}

		defer func() {
			_ = server.Close()
		}()

		res := <-clientRes
		if res.err != nil {
			t.Fatal(res.err)
		}
		_ = res.c.Close()
	})

	t.Run("new session", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		type result struct {
			c   *Conn
			err error
		}
		clientRes := make(chan result, 1)

		s1 := &memSessStore{}
		s2 := &memSessStore{}

		ca, cb := dpipe.Pipe()
		go func() {
			config := &Config{
				ServerName:   "example.com",
				SessionStore: s1,
			}
			c, err := testClient(ctx, ca, config, false)
			clientRes <- result{c, err}
		}()

		config := &Config{
			SessionStore: s2,
		}
		server, err := testServer(ctx, cb, config, true)
		if err != nil {
			t.Fatalf("TestSessionResumetion: Server failed(%v)", err)
		}

		actualSessionID := server.ConnectionState().SessionID
		actualMasterSecret := server.ConnectionState().masterSecret
		ss, _ := s2.Get(actualSessionID)
		if !bytes.Equal(actualMasterSecret, ss.Secret) {
			t.Errorf("TestSessionResumetion: masterSecret Mismatch: expected(%v) actual(%v)", ss.Secret, actualMasterSecret)
		}

		defer func() {
			_ = server.Close()
		}()

		res := <-clientRes
		if res.err != nil {
			t.Fatal(res.err)
		}
		cs, _ := s1.Get([]byte(ca.RemoteAddr().String() + "_example.com"))
		if !bytes.Equal(actualMasterSecret, cs.Secret) {
			t.Errorf("TestSessionResumetion: masterSecret Mismatch: expected(%v) actual(%v)", ss.Secret, actualMasterSecret)
		}
		_ = res.c.Close()
	})
}

type memSessStore struct {
	sync.Map
}

func (ms *memSessStore) Set(key []byte, s Session) error {
	k := hex.EncodeToString(key)
	ms.Store(k, s)

	return nil
}

func (ms *memSessStore) Get(key []byte) (Session, error) {
	k := hex.EncodeToString(key)

	v, ok := ms.Load(k)
	if !ok {
		return Session{}, nil
	}

	s, ok := v.(Session)
	if !ok {
		return Session{}, nil
	}

	return s, nil
}

func (ms *memSessStore) Del(key []byte) error {
	k := hex.EncodeToString(key)
	ms.Delete(k)

	return nil
}

// Assert that the server only uses CipherSuites with a hash+signature that matches
// the certificate. As specified in rfc5246#section-7.4.3
func TestCipherSuiteMatchesCertificateType(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	for _, test := range []struct {
		Name           string
		cipherList     []CipherSuiteID
		expectedCipher CipherSuiteID
		generateRSA    bool
	}{
		{
			Name:           "ECDSA Certificate with RSA CipherSuite first",
			cipherList:     []CipherSuiteID{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			expectedCipher: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
		{
			Name:           "RSA Certificate with ECDSA CipherSuite first",
			cipherList:     []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			expectedCipher: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			generateRSA:    true,
		},
	} {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			clientErr := make(chan error, 1)
			client := make(chan *Conn, 1)

			ca, cb := dpipe.Pipe()
			go func() {
				c, err := testClient(context.TODO(), ca, &Config{CipherSuites: test.cipherList}, false)
				clientErr <- err
				client <- c
			}()

			var (
				priv crypto.PrivateKey
				err  error
			)

			if test.generateRSA {
				if priv, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
					t.Fatal(err)
				}
			} else {
				if priv, err = ecdsa.GenerateKey(cryptoElliptic.P256(), rand.Reader); err != nil {
					t.Fatal(err)
				}
			}

			serverCert, err := selfsign.SelfSign(priv)
			if err != nil {
				t.Fatal(err)
			}

			if s, err := testServer(context.TODO(), cb, &Config{
				CipherSuites: test.cipherList,
				Certificates: []tls.Certificate{serverCert},
			}, false); err != nil {
				t.Fatal(err)
			} else if err = s.Close(); err != nil {
				t.Fatal(err)
			}

			if c, err := <-client, <-clientErr; err != nil {
				t.Fatal(err)
			} else if err := c.Close(); err != nil {
				t.Fatal(err)
			} else if c.ConnectionState().cipherSuite.ID() != test.expectedCipher {
				t.Fatalf("Expected(%s) and Actual(%s) CipherSuite do not match", test.expectedCipher, c.ConnectionState().cipherSuite.ID())
			}
		})
	}
}

// Test that we return the proper certificate if we are serving multiple ServerNames on a single Server
func TestMultipleServerCertificates(t *testing.T) {
	fooCert, err := selfsign.GenerateSelfSignedWithDNS("foo")
	if err != nil {
		t.Fatal(err)
	}

	barCert, err := selfsign.GenerateSelfSignedWithDNS("bar")
	if err != nil {
		t.Fatal(err)
	}

	caPool := x509.NewCertPool()
	for _, cert := range []tls.Certificate{fooCert, barCert} {
		certificate, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		caPool.AddCert(certificate)
	}

	for _, test := range []struct {
		RequestServerName string
		ExpectedDNSName   string
	}{
		{
			"foo",
			"foo",
		},
		{
			"bar",
			"bar",
		},
		{
			"invalid",
			"foo",
		},
	} {
		test := test
		t.Run(test.RequestServerName, func(t *testing.T) {
			clientErr := make(chan error, 2)
			client := make(chan *Conn, 1)

			ca, cb := dpipe.Pipe()
			go func() {
				c, err := testClient(context.TODO(), ca, &Config{
					RootCAs:    caPool,
					ServerName: test.RequestServerName,
					VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
						certificate, err := x509.ParseCertificate(rawCerts[0])
						if err != nil {
							return err
						}

						if certificate.DNSNames[0] != test.ExpectedDNSName {
							return errWrongCert
						}

						return nil
					},
				}, false)
				clientErr <- err
				client <- c
			}()

			if s, err := testServer(context.TODO(), cb, &Config{Certificates: []tls.Certificate{fooCert, barCert}}, false); err != nil {
				t.Fatal(err)
			} else if err = s.Close(); err != nil {
				t.Fatal(err)
			}

			if c, err := <-client, <-clientErr; err != nil {
				t.Fatal(err)
			} else if err := c.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestEllipticCurveConfiguration(t *testing.T) {
	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	for _, test := range []struct {
		Name            string
		ConfigCurves    []elliptic.Curve
		HadnshakeCurves []elliptic.Curve
	}{
		{
			Name:            "Curve defaulting",
			ConfigCurves:    nil,
			HadnshakeCurves: defaultCurves,
		},
		{
			Name:            "Single curve",
			ConfigCurves:    []elliptic.Curve{elliptic.X25519},
			HadnshakeCurves: []elliptic.Curve{elliptic.X25519},
		},
		{
			Name:            "Multiple curves",
			ConfigCurves:    []elliptic.Curve{elliptic.P384, elliptic.X25519},
			HadnshakeCurves: []elliptic.Curve{elliptic.P384, elliptic.X25519},
		},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		ca, cb := dpipe.Pipe()
		type result struct {
			c   *Conn
			err error
		}
		c := make(chan result)

		go func() {
			client, err := testClient(ctx, ca, &Config{CipherSuites: []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}, EllipticCurves: test.ConfigCurves}, true)
			c <- result{client, err}
		}()

		server, err := testServer(ctx, cb, &Config{CipherSuites: []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}, EllipticCurves: test.ConfigCurves}, true)
		if err != nil {
			t.Fatalf("Server error: %v", err)
		}

		if len(test.ConfigCurves) == 0 && len(test.HadnshakeCurves) != len(server.fsm.cfg.ellipticCurves) {
			t.Fatalf("Failed to default Elliptic curves, expected %d, got: %d", len(test.HadnshakeCurves), len(server.fsm.cfg.ellipticCurves))
		}

		if len(test.ConfigCurves) != 0 {
			if len(test.HadnshakeCurves) != len(server.fsm.cfg.ellipticCurves) {
				t.Fatalf("Failed to configure Elliptic curves, expect %d, got %d", len(test.HadnshakeCurves), len(server.fsm.cfg.ellipticCurves))
			}
			for i, c := range test.ConfigCurves {
				if c != server.fsm.cfg.ellipticCurves[i] {
					t.Fatalf("Failed to maintain Elliptic curve order, expected %s, got %s", c, server.fsm.cfg.ellipticCurves[i])
				}
			}
		}

		res := <-c
		if res.err != nil {
			t.Fatalf("Client error; %v", err)
		}

		defer func() {
			err = server.Close()
			if err != nil {
				t.Fatal(err)
			}
			err = res.c.Close()
			if err != nil {
				t.Fatal(err)
			}
		}()
	}
}

func TestSkipHelloVerify(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ca, cb := dpipe.Pipe()
	certificate, err := selfsign.GenerateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	gotHello := make(chan struct{})

	go func() {
		server, sErr := testServer(ctx, cb, &Config{
			Certificates:            []tls.Certificate{certificate},
			LoggerFactory:           logging.NewDefaultLoggerFactory(),
			InsecureSkipVerifyHello: true,
		}, false)
		if sErr != nil {
			t.Error(sErr)
			return
		}
		buf := make([]byte, 1024)
		if _, sErr = server.Read(buf); sErr != nil {
			t.Error(sErr)
		}
		gotHello <- struct{}{}
		if sErr = server.Close(); sErr != nil { //nolint:contextcheck
			t.Error(sErr)
		}
	}()

	client, err := testClient(ctx, ca, &Config{
		LoggerFactory:      logging.NewDefaultLoggerFactory(),
		InsecureSkipVerify: true,
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.Write([]byte("hello")); err != nil {
		t.Error(err)
	}
	select {
	case <-gotHello:
		// OK
	case <-time.After(time.Second * 5):
		t.Error("timeout")
	}

	if err = client.Close(); err != nil {
		t.Error(err)
	}
}

type connWithCallback struct {
	net.Conn
	onWrite func([]byte)
}

func (c *connWithCallback) Write(b []byte) (int, error) {
	if c.onWrite != nil {
		c.onWrite(b)
	}
	return c.Conn.Write(b)
}
