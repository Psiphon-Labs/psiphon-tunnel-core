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

package light

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	tls "github.com/Psiphon-Labs/psiphon-tls"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/internal/testutils"
	utls "github.com/Psiphon-Labs/utls"
	"golang.org/x/sync/errgroup"
)

func TestLightProxy(t *testing.T) {
	err := runTestLightProxy()
	if err != nil {
		t.Fatal(err.Error())
	}
}

func runTestLightProxy() error {

	// Exercise multiple concurrent clients and concurrent dials over over one
	// proxy. The proxied traffic is an inner TLS connection to an "echo"
	// server, and the echoed bytes are verified. The outer proxy TLS
	// connection is observed and expected padding target ranges are also
	// verified.

	const (
		numClients              = 2
		numConnectionsPerClient = 10
		payloadSize             = 10 * 1024 * 1024

		testClientPlatform          = "Android"
		testClientBuildRev          = "01020304"
		testDeviceRegion            = "US"
		testProxyEntryTracker int64 = 0x0102030405060708
		testNetworkType             = "WIFI"
		testTLSProfile              = protocol.TLS_PROFILE_CHROME_120
	)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	serverGroup, serverCtx := errgroup.WithContext(ctx)

	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return errors.Trace(err)
	}
	defer echoListener.Close()

	echoAddress := echoListener.Addr().String()

	serverGroup.Go(func() error {

		_, _, echoCertPEM, echoKeyPEM, err := generateCert()
		if err != nil {
			return errors.Trace(err)
		}

		echoCert, err := tls.X509KeyPair(echoCertPEM, echoKeyPEM)
		if err != nil {
			return errors.Trace(err)
		}

		return runTLSEchoServer(
			serverCtx,
			echoListener,
			&tls.Config{
				Certificates: []tls.Certificate{echoCert},
				MinVersion:   tls.VersionTLS13,
			})
	})

	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return errors.Trace(err)
	}

	proxyAddress := proxyListener.Addr().String()
	err = proxyListener.Close()
	if err != nil {
		return errors.Trace(err)
	}

	proxyConfig, proxyEntry, err := Generate(
		proxyAddress,
		proxyAddress,
		"example.org",
		[]string{echoAddress},
		echoListener.Addr().String())
	if err != nil {
		return errors.Trace(err)
	}

	lookupGeoIP := func(string) common.GeoIPData {
		return common.GeoIPData{}
	}

	receiver := newTestProxyEventReceiver()

	proxy, err := NewProxy(
		proxyConfig,
		lookupGeoIP,
		receiver)
	if err != nil {
		return errors.Trace(err)
	}

	serverGroup.Go(func() error {
		return proxy.Run(serverCtx)
	})

	select {
	case <-receiver.listening:
	case <-ctx.Done():
		return errors.Trace(ctx.Err())
	}

	newClientConfig := func() *ClientConfig {
		return &ClientConfig{
			Logger: testutils.NewTestLogger(),
			TCPDialer: func(ctx context.Context, addr string) (net.Conn, error) {
				conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
				if err != nil {
					return nil, errors.Trace(err)
				}
				return newPaddingCheckerConn(conn), nil
			},
			TLSDialer:         dialUtls,
			SponsorID:         prng.HexString(8),
			ClientID:          prng.HexString(16),
			ClientPlatform:    testClientPlatform,
			ClientBuildRev:    testClientBuildRev,
			DeviceRegion:      testDeviceRegion,
			SessionID:         prng.HexString(protocol.PSIPHON_API_CLIENT_SESSION_ID_LENGTH),
			ProxyEntryTracker: testProxyEntryTracker,
			ProxyEntry:        proxyEntry,
		}
	}

	clients := make([]*Client, numClients)
	for i := 0; i < numClients; i++ {
		client, err := NewClient(newClientConfig())
		if err != nil {
			return errors.Trace(err)
		}
		clients[i] = client
	}

	clientGroup, clientCtx := errgroup.WithContext(ctx)
	for _, client := range clients {
		client := client
		for i := 0; i < numConnectionsPerClient; i++ {
			clientGroup.Go(func() error {
				err := runLightClient(
					clientCtx,
					client,
					testNetworkType,
					testTLSProfile,
					echoAddress,
					payloadSize)
				if err != nil {
					return errors.Trace(err)
				}
				return nil
			})
		}
	}

	err = clientGroup.Wait()
	if err != nil {
		return errors.Trace(err)
	}

	cancel()

	err = serverGroup.Wait()
	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

func runLightClient(
	ctx context.Context,
	client *Client,
	networkType string,
	tlsProfile string,
	destinationAddress string,
	payloadSize int) error {

	conn, err := client.Dial(ctx, networkType, tlsProfile, destinationAddress)
	if err != nil {
		return errors.Trace(err)
	}
	defer conn.Close()

	innerTLSConn := tls.Client(conn, &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
	})

	err = innerTLSConn.Handshake()
	if err != nil {
		return errors.Trace(err)
	}

	payload := prng.Bytes(payloadSize)

	readWriteGroup, readWriteCtx := errgroup.WithContext(ctx)

	echoed := make([]byte, len(payload))
	readWriteGroup.Go(func() error {
		_, err := innerTLSConn.Write(payload)
		return errors.Trace(err)
	})

	readWriteGroup.Go(func() error {
		_ = readWriteCtx
		_, err := io.ReadFull(innerTLSConn, echoed)
		return errors.Trace(err)
	})

	err = readWriteGroup.Wait()
	if err != nil {
		return errors.Trace(err)
	}

	if !bytes.Equal(payload, echoed) {
		return errors.TraceNew("echo payload mismatch")
	}

	err = innerTLSConn.Close()
	if err != nil {
		return errors.Trace(err)
	}

	paddingCheckerConn := conn.activityConn.Conn.(*paddingCheckerConn)
	err = paddingCheckerConn.checkResults()
	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

func dialUtls(
	ctx context.Context,
	underlyingConn net.Conn,
	tlsProfile string,
	recommendedSNI string,
	passthroughMessage []byte,
	verifyPin string,
	verifyServerName string) (net.Conn, error) {

	_ = ctx

	config := &utls.Config{
		ServerName:         recommendedSNI,
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(
			rawCerts [][]byte,
			_ [][]*x509.Certificate) error {
			return verifyPinnedPeerCertificate(rawCerts, verifyPin, verifyServerName)
		},
	}

	var clientHelloID utls.ClientHelloID
	switch tlsProfile {
	case protocol.TLS_PROFILE_CHROME_120:
		clientHelloID = utls.HelloChrome_120
	default:
		return nil, errors.TraceNew("unsupported TLS profile")
	}

	conn := utls.UClient(underlyingConn, config, clientHelloID)

	err := conn.BuildHandshakeState()
	if err != nil {
		return nil, errors.Trace(err)
	}

	err = conn.SetClientRandom(passthroughMessage)
	if err != nil {
		return nil, errors.Trace(err)
	}

	err = conn.MarshalClientHello()
	if err != nil {
		return nil, errors.Trace(err)
	}

	err = conn.Handshake()
	if err != nil {
		return nil, errors.Trace(err)
	}

	// Now that the outer TLS handshake is complete, start checking padding
	// target range of the inner TLS handshake.
	underlyingConn.(*common.ActivityMonitoredConn).
		Conn.(*paddingCheckerConn).startChecking()

	return conn, nil
}

func verifyPinnedPeerCertificate(rawCerts [][]byte, verifyPin string, verifyServerName string) error {
	certs := make([]*x509.Certificate, 0, len(rawCerts))
	for _, rawCert := range rawCerts {
		cert, err := x509.ParseCertificate(rawCert)
		if err != nil {
			return errors.Trace(err)
		}
		certs = append(certs, cert)
	}

	if verifyServerName != "" {
		err := certs[0].VerifyHostname(verifyServerName)
		if err != nil {
			return errors.Trace(err)
		}
	}

	err := common.VerifyCertificatePins(
		[]string{verifyPin},
		[][]*x509.Certificate{certs})
	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

func runTLSEchoServer(
	ctx context.Context,
	listener net.Listener,
	config *tls.Config) error {

	listener = tls.NewListener(listener, config)

	mainGroup, ctx := errgroup.WithContext(ctx)

	mainGroup.Go(func() error {
		<-ctx.Done()
		return listener.Close()
	})

	mainGroup.Go(func() error {
		var connGroup errgroup.Group

		for {
			conn, err := listener.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return connGroup.Wait()
				}
				return errors.Trace(err)
			}

			connGroup.Go(func() error {
				defer conn.Close()
				_, err = io.Copy(conn, conn)
				if err != nil && err != io.EOF {
					return errors.Trace(err)
				}
				return nil
			})
		}
	})

	return errors.Trace(mainGroup.Wait())
}

type paddingCheckerConn struct {
	net.Conn

	mutex        sync.Mutex
	enabled      bool
	readChecked  bool
	readBuffer   []byte
	readErr      error
	writeChecked bool
	writeBuffer  []byte
	writeErr     error
}

func newPaddingCheckerConn(conn net.Conn) *paddingCheckerConn {

	return &paddingCheckerConn{
		Conn: conn,
	}
}

func (conn *paddingCheckerConn) Read(b []byte) (int, error) {
	n, err := conn.Conn.Read(b)
	if n > 0 {
		conn.checkTLSRecordLength(false, b[:n])
	}
	return n, err
}

func (conn *paddingCheckerConn) Write(b []byte) (int, error) {
	n, err := conn.Conn.Write(b)
	if n > 0 {
		conn.checkTLSRecordLength(true, b[:n])
	}
	return n, err
}

func (conn *paddingCheckerConn) checkResults() error {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	if !conn.readChecked || !conn.writeChecked {
		return errors.TraceNew("checks incomplete")
	}
	if conn.readErr != nil {
		return conn.readErr
	}
	return conn.writeErr
}

func (conn *paddingCheckerConn) startChecking() {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	conn.enabled = true
}

func (conn *paddingCheckerConn) checkTLSRecordLength(isWrite bool, b []byte) {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	if !conn.enabled {
		return
	}

	buffer := &conn.readBuffer
	checked := &conn.readChecked
	checkErr := &conn.readErr
	if isWrite {
		buffer = &conn.writeBuffer
		checked = &conn.writeChecked
		checkErr = &conn.writeErr
	}

	// Limitation: only checks the first read (proxy padding) and first write
	// (client padding).
	if *checked {
		return
	}

	// Buffer in case the net.Conn read/write isn't the full TLS record.
	*buffer = append(*buffer, b...)
	if len(*buffer) < 5 {
		return
	}

	recordSize := int(binary.BigEndian.Uint16((*buffer)[3:5]))
	if len(*buffer) < 5+recordSize {
		return
	}

	if recordSize < paddingMinTargetSize || recordSize > paddingMaxTargetSize {
		*checkErr = errors.Tracef(
			"TLS record size %d outside padding target [%d, %d]",
			recordSize,
			paddingMinTargetSize,
			paddingMaxTargetSize)
	}

	*checked = true
	*buffer = nil
}

type testProxyEventReceiver struct {
	listening     chan struct{}
	listeningOnce sync.Once
}

func newTestProxyEventReceiver() *testProxyEventReceiver {
	return &testProxyEventReceiver{
		listening: make(chan struct{}),
	}
}

func (r *testProxyEventReceiver) Listening(address string) {
	r.listeningOnce.Do(func() {
		close(r.listening)
	})
	fmt.Printf("[Listening] %s\n", address)
}

func (r *testProxyEventReceiver) Connection(stats *ConnectionStats) {
	const connectionFormat = `[Connection] proxyID: %s, ` +
		`proxyConnectionNum: %d, sponsorID: %s, platform: %s, ` +
		`buildRev: %s, clientID: %s, deviceRegion: %s, sessionID: %s, ` +
		`tracker: %d, networkType: %s, clientConnectionNum: %d, ` +
		`destination: %s, tlsProfile: %s, sni: %s, ` +
		`clientTCPDuration: %s, clientTLSDuration: %s, ` +
		`completedTCP: %s, completedTLS: %s, completedLightHeader: %s, ` +
		`completedUpstreamDial: %s, bytesRead: %d, bytesWritten: %d, ` +
		`failure: %v` + "\n"

	fmt.Printf(
		connectionFormat,
		stats.ProxyID,
		stats.ProxyConnectionNum,
		stats.SponsorID,
		stats.ClientPlatform,
		stats.ClientBuildRev,
		stats.ClientID,
		stats.DeviceRegion,
		stats.SessionID,
		stats.ProxyEntryTracker,
		stats.NetworkType,
		stats.ClientConnectionNum,
		stats.DestinationAddress,
		stats.TLSProfile,
		stats.SNI,
		stats.ClientTCPDuration,
		stats.ClientTLSDuration,
		stats.ProxyCompletedTCP.Format(time.RFC3339Nano),
		stats.ProxyCompletedTLS.Format(time.RFC3339Nano),
		stats.ProxyCompletedLightHeader.Format(time.RFC3339Nano),
		stats.ProxyCompletedUpstreamDial.Format(time.RFC3339Nano),
		stats.BytesRead,
		stats.BytesWritten,
		stats.ConnectionFailure)
}

func (r *testProxyEventReceiver) IrregularConnection(_ string, _ common.GeoIPData, irregularity string) {
	fmt.Printf("[IrregularConnection] %s\n", irregularity)
}

func (r *testProxyEventReceiver) DebugLog(_ string, message string) {
}

func (r *testProxyEventReceiver) InfoLog(_ string, message string) {
	fmt.Printf("[InfoLog] %s\n", message)
}

func (r *testProxyEventReceiver) WarningLog(_ string, message string) {
	fmt.Printf("[WarningLog] %s\n", message)
}

func (r *testProxyEventReceiver) ErrorLog(_ string, message string) {
	fmt.Printf("[ErrorLog] %s\n", message)
}
