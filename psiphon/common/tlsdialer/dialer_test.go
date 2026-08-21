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

package tlsdialer

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	tls "github.com/Psiphon-Labs/psiphon-tls"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/values"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/internal/testutils"
	utls "github.com/Psiphon-Labs/utls"
)

func TestTLSCertificateVerification(t *testing.T) {

	testDataDirName, err := ioutil.TempDir("", "psiphon-tls-certificate-verification-test")
	if err != nil {
		t.Fatalf("TempDir failed: %v", err)
	}
	defer os.RemoveAll(testDataDirName)

	serverName := "example.org"

	rootCAsFileName,
		rootCACertificatePin,
		serverCertificatePin,
		shutdown,
		serverAddr,
		dialer := testutils.InitTestCertificatesAndWebServer(
		t, testDataDirName, serverName)
	defer shutdown()

	// Test: without custom RootCAs, the TLS dial fails.

	params, err := parameters.NewParameters(nil)
	if err != nil {
		t.Fatalf("parameters.NewParameters failed: %v", err)
	}

	conn, err := Dial(
		context.Background(), "tcp", serverAddr,
		&Config{
			Parameters: params,
			Dial:       dialer,
		})

	if err == nil {
		conn.Close()
		t.Errorf("unexpected success without custom RootCAs")
	}

	// Test: without custom RootCAs and with SkipVerify, the TLS dial succeeds.

	conn, err = Dial(
		context.Background(), "tcp", serverAddr,
		&Config{
			Parameters: params,
			Dial:       dialer,
			SkipVerify: true,
		})

	if err != nil {
		t.Errorf("Dial failed: %v", err)
	} else {
		conn.Close()
	}

	// Test: with custom RootCAs, the TLS dial succeeds.

	conn, err = Dial(
		context.Background(), "tcp", serverAddr,
		&Config{
			Parameters:                    params,
			Dial:                          dialer,
			TrustedCACertificatesFilename: rootCAsFileName,
		})

	if err != nil {
		t.Errorf("Dial failed: %v", err)
	} else {
		conn.Close()
	}

	// Test: with SNI changed and VerifyServerName set, the TLS dial succeeds.

	conn, err = Dial(
		context.Background(), "tcp", serverAddr,
		&Config{
			Parameters:                    params,
			Dial:                          dialer,
			SNIServerName:                 "not-" + serverName,
			VerifyServerName:              serverName,
			TrustedCACertificatesFilename: rootCAsFileName,
		})

	if err != nil {
		t.Errorf("Dial failed: %v", err)
	} else {
		conn.Close()
	}

	// Test: with an invalid pin, the TLS dial fails.

	invalidPin := base64.StdEncoding.EncodeToString(make([]byte, 32))

	conn, err = Dial(
		context.Background(), "tcp", serverAddr,
		&Config{
			Parameters:                    params,
			Dial:                          dialer,
			VerifyPins:                    []string{invalidPin},
			TrustedCACertificatesFilename: rootCAsFileName,
		})

	if err == nil {
		conn.Close()
		t.Errorf("unexpected success without invalid pin")
	}

	// Test: with the root CA certificate pinned, the TLS dial succeeds.

	conn, err = Dial(
		context.Background(), "tcp", serverAddr,
		&Config{
			Parameters:                    params,
			Dial:                          dialer,
			VerifyPins:                    []string{rootCACertificatePin},
			TrustedCACertificatesFilename: rootCAsFileName,
		})

	if err != nil {
		t.Errorf("Dial failed: %v", err)
	} else {
		conn.Close()
	}

	// Test: with the server certificate pinned, the TLS dial succeeds.

	conn, err = Dial(
		context.Background(), "tcp", serverAddr,
		&Config{
			Parameters:                    params,
			Dial:                          dialer,
			VerifyPins:                    []string{serverCertificatePin},
			TrustedCACertificatesFilename: rootCAsFileName,
		})

	if err != nil {
		t.Errorf("Dial failed: %v", err)
	} else {
		conn.Close()
	}

	// Test: with SNI changed, VerifyServerName set, and pinning the TLS dial
	// succeeds.

	conn, err = Dial(
		context.Background(), "tcp", serverAddr,
		&Config{
			Parameters:                    params,
			Dial:                          dialer,
			SNIServerName:                 "not-" + serverName,
			VerifyServerName:              serverName,
			VerifyPins:                    []string{rootCACertificatePin},
			TrustedCACertificatesFilename: rootCAsFileName,
		})

	if err != nil {
		t.Errorf("Dial failed: %v", err)
	} else {
		conn.Close()
	}

	// Test: with DisableSystemRootCAs set and without VerifyServerName or
	// VerifyPins set, the TLS dial succeeds.

	conn, err = Dial(
		context.Background(), "tcp", serverAddr,
		&Config{
			Parameters:           params,
			Dial:                 dialer,
			SNIServerName:        "not-" + serverName,
			DisableSystemRootCAs: true,
		})

	if err != nil {
		t.Errorf("Dial failed: %v", err)
	} else {
		conn.Close()
	}

	// Test: with DisableSystemRootCAs set along with VerifyServerName and
	// VerifyPins, the TLS dial fails.

	conn, err = Dial(
		context.Background(), "tcp", serverAddr,
		&Config{
			Parameters:           params,
			Dial:                 dialer,
			SNIServerName:        serverName,
			DisableSystemRootCAs: true,
			VerifyServerName:     serverName,
			VerifyPins:           []string{rootCACertificatePin},
		})

	if err == nil {
		conn.Close()
		t.Errorf("unexpected success with DisableSystemRootCAs set along with VerifyServerName and VerifyPins")
	}

	// Test: with DisableSystemRootCAs set, SNI changed, and without
	// VerifyServerName or VerifyPins set, the TLS dial succeeds.

	conn, err = Dial(
		context.Background(), "tcp", serverAddr,
		&Config{
			Parameters:           params,
			Dial:                 dialer,
			SNIServerName:        "not-" + serverName,
			DisableSystemRootCAs: true,
		})

	if err != nil {
		t.Errorf("Dial failed: %v", err)
	} else {
		conn.Close()
	}
}

func TestTLSDialerCompatibility(t *testing.T) {

	// This test checks that each TLS profile in combination with TLS ClientHello
	// fragmentation can successfully complete a TLS
	// handshake with various servers. By default, only the "psiphon" case is
	// run, which runs the same TLS listener used by a Psiphon server.
	//
	// An optional config file, when supplied, enables testing against remote
	// servers. Config should be newline delimited list of domain/IP:port TLS
	// host addresses to connect to. ClientHello wire assertions also run for
	// these remote servers.

	var configAddresses []string
	config, err := ioutil.ReadFile("tlsDialerCompatibility_test.config")
	if err == nil {
		configAddresses = strings.Split(string(config), "\n")
	}

	runner := func(address string, fragmentClientHello bool) func(t *testing.T) {
		return func(t *testing.T) {
			testTLSDialerCompatibility(t, address, fragmentClientHello)
		}
	}

	for _, address := range configAddresses {
		for _, fragmentClientHello := range []bool{false, true} {
			if len(address) > 0 {
				t.Run(fmt.Sprintf("%s (fragmentClientHello: %v)", address, fragmentClientHello),
					runner(address, fragmentClientHello))
			}
		}
	}

	for _, fragmentClientHello := range []bool{false, true} {
		t.Run(fmt.Sprintf("psiphon (fragmentClientHello: %v)", fragmentClientHello),
			runner("", fragmentClientHello))
	}
}

func testTLSDialerCompatibility(t *testing.T, address string, fragmentClientHello bool) {

	if address == "" {

		// Same tls config as psiphon/server/meek.go

		certificate, privateKey, _, err := common.GenerateWebServerCertificate(values.GetHostName())
		if err != nil {
			t.Fatalf("common.GenerateWebServerCertificate failed: %v", err)
		}

		tlsCertificate, err := tls.X509KeyPair([]byte(certificate), []byte(privateKey))
		if err != nil {
			t.Fatalf("tls.X509KeyPair failed: %v", err)
		}

		config := &tls.Config{
			Certificates: []tls.Certificate{tlsCertificate},
			NextProtos:   []string{"http/1.1"},
			MinVersion:   tls.VersionTLS10,
		}

		tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("net.Listen failed: %v", err)
		}

		tlsListener := tls.NewListener(tcpListener, config)

		address = tlsListener.Addr().String()

		// Handle each accepted conn on its own goroutine, with a handshake
		// deadline. A sequential accept loop stalls every subsequent dial if a
		// client connects without completing a handshake, which happens whenever
		// Dial fails after dialing but before handshaking. acceptDone gates
		// logging, which panics if it occurs after the test completes.
		acceptDone := make(chan struct{})
		var acceptWaitGroup sync.WaitGroup
		acceptWaitGroup.Add(1)
		go func() {
			defer acceptWaitGroup.Done()
			for {
				conn, err := tlsListener.Accept()
				if err != nil {
					return
				}
				acceptWaitGroup.Add(1)
				go func(conn net.Conn) {
					defer acceptWaitGroup.Done()
					defer conn.Close()
					_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
					err := conn.(*tls.Conn).Handshake()
					if err != nil {
						select {
						case <-acceptDone:
						default:
							t.Logf("tls.Conn.Handshake failed: %v", err)
						}
					}
				}(conn)
			}
		}()
		defer func() {
			close(acceptDone)
			tlsListener.Close()
			acceptWaitGroup.Wait()
		}()
	}

	var recordedConn *clientHelloRecordingConn
	dialer := func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		recordedConn = &clientHelloRecordingConn{Conn: conn}
		return recordedConn, nil
	}

	params := makeCustomTLSProfilesParameters(t, false, "")

	profiles := append([]string(nil), protocol.SupportedTLSProfiles...)
	profiles = append(profiles, params.Get().CustomTLSProfileNames()...)

	for _, tlsProfile := range profiles {

		repeats := 2
		if protocol.TLSProfileIsRandomized(tlsProfile) {
			repeats = 20
		}

		success := 0
		tlsVersions := []string{}
		for i := 0; i < repeats; i++ {

			transformHostname := i%2 == 0

			tlsConfig := &Config{
				Parameters:          params,
				Dial:                dialer,
				SkipVerify:          true,
				TLSProfile:          tlsProfile,
				FragmentClientHello: fragmentClientHello,
			}

			if transformHostname {
				tlsConfig.SNIServerName = values.GetHostName()
			} else {
				tlsConfig.UseDialAddrSNI = true
			}

			ctx, cancelFunc := context.WithTimeout(context.Background(), 5*time.Second)

			recordedConn = nil
			conn, err := Dial(ctx, "tcp", address, tlsConfig)

			if err != nil {
				t.Logf("Dial failed: %s (transformHostname: %v): %v",
					tlsProfile, transformHostname, err)
			} else {

				tlsVersion := ""
				tlsConn := conn.(*tlsConn)
				version := tlsConn.Conn.(*utls.UConn).ConnectionState().Version
				if version == utls.VersionTLS12 {
					tlsVersion = "TLS 1.2"
				} else if version == utls.VersionTLS13 {
					tlsVersion = "TLS 1.3"
				} else {
					t.Fatalf("Unexpected TLS version: %v", version)
				}
				if !common.Contains(tlsVersions, tlsVersion) {
					tlsVersions = append(tlsVersions, tlsVersion)
				}

				dialHostname, _, splitHostPortErr := net.SplitHostPort(address)
				if splitHostPortErr != nil {
					t.Fatal(splitHostPortErr)
				}
				usingSNI := transformHostname || net.ParseIP(dialHostname) == nil
				expectFragmented := fragmentClientHello && usingSNI
				if tlsConn.fragmented != expectFragmented {
					t.Errorf("unexpected ClientHello fragmentation for %s: got %v, want %v",
						tlsProfile, tlsConn.fragmented, expectFragmented)
				}
				if expectFragmented {
					if recordedConn == nil {
						t.Fatal("missing recorded TLS conn")
					}
					assertClientHelloFragmentedOnWire(t, recordedConn)
				}

				conn.Close()
				success += 1
			}

			cancelFunc()

			time.Sleep(100 * time.Millisecond)
		}

		result := fmt.Sprintf(
			"%s: %d/%d successful; negotiated TLS versions: %v",
			tlsProfile, success, repeats, tlsVersions)

		if success == repeats {
			t.Log(result)
		} else {
			t.Error(result)
		}
	}
}

type clientHelloRecordingConn struct {
	net.Conn
	mutex   sync.Mutex
	written []byte
}

func (c *clientHelloRecordingConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.mutex.Lock()
		c.written = append(c.written, b[:n]...)
		c.mutex.Unlock()
	}
	return n, err
}

func (c *clientHelloRecordingConn) writtenBytes() []byte {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return append([]byte(nil), c.written...)
}

// assertClientHelloFragmentedOnWire checks TLS record boundaries in the byte
// stream written to the underlying TCP conn. It does not assert TCP packet or
// Write call boundaries.
func assertClientHelloFragmentedOnWire(t *testing.T, conn *clientHelloRecordingConn) {
	t.Helper()

	const (
		tlsRecordHeaderLength  = 5
		tlsRecordTypeHandshake = 22
	)

	written := conn.writtenBytes()
	readRecord := func(position int) ([]byte, int) {
		if len(written)-position < tlsRecordHeaderLength {
			t.Fatalf("partial TLS record header at offset %d", position)
		}
		if written[position] != tlsRecordTypeHandshake {
			t.Fatalf("unexpected TLS record type %d at offset %d",
				written[position], position)
		}

		payloadLength := int(written[position+3])<<8 | int(written[position+4])
		recordEnd := position + tlsRecordHeaderLength + payloadLength
		if recordEnd > len(written) {
			t.Fatalf("partial TLS record at offset %d: got %d bytes, want %d",
				position, len(written)-position, tlsRecordHeaderLength+payloadLength)
		}
		return written[position+tlsRecordHeaderLength : recordEnd], recordEnd
	}

	first, position := readRecord(0)
	if len(first) < 4 || first[0] != tlsHandshakeTypeClientHello {
		t.Fatalf("first TLS record does not begin with a ClientHello: %x", first)
	}

	messageLength := 4 +
		(int(first[1]) << 16) +
		(int(first[2]) << 8) +
		int(first[3])
	if len(first) >= messageLength {
		t.Fatalf("ClientHello was not fragmented: first record has %d of %d bytes",
			len(first), messageLength)
	}

	second, _ := readRecord(position)
	clientHello := append(append([]byte(nil), first...), second...)
	if len(clientHello) != messageLength {
		t.Fatalf("unexpected ClientHello length: got %d, want %d",
			len(clientHello), messageLength)
	}

	split := sniFragmentOffset(clientHello)
	if split == 0 {
		t.Fatal("missing SNI fragment offset in recorded ClientHello")
	}
	if len(first) != split {
		t.Fatalf("first ClientHello record ends at %d, want SNI fragment offset %d",
			len(first), split)
	}
}

func TestSelectTLSProfile(t *testing.T) {

	params := makeCustomTLSProfilesParameters(t, false, "")

	profiles := append([]string(nil), protocol.SupportedTLSProfiles...)
	profiles = append(profiles, params.Get().CustomTLSProfileNames()...)

	selected := make(map[string]int)

	numSelections := 10000

	for i := 0; i < numSelections; i++ {
		profile, _, seed, err := SelectTLSProfile(false, false, false, "", "", params.Get())
		if err != nil {
			t.Fatalf("SelectTLSProfile failed: %v", err)
		}
		if protocol.TLSProfileIsRandomized(profile) && seed == nil {
			t.Errorf("expected non-nil seed for randomized TLS profile")
		}
		selected[profile] += 1
	}

	// All TLS profiles should be selected at least once.

	for _, profile := range profiles {
		if selected[profile] < 1 {
			t.Errorf("TLS profile %s not selected", profile)
		}
	}

	// Only expected profiles should be selected

	if len(selected) != len(profiles) {
		t.Errorf("unexpected TLS profile selected")
	}

	// Randomized TLS profiles should be selected with expected probability.

	numRandomized := 0
	for profile, n := range selected {
		if protocol.TLSProfileIsRandomized(profile) {
			numRandomized += n
		}
	}

	t.Logf("ratio of randomized selected: %d/%d",
		numRandomized, numSelections)

	randomizedProbability := params.Get().Float(
		parameters.SelectRandomizedTLSProfileProbability)

	if numRandomized < int(0.9*float64(numSelections)*randomizedProbability) ||
		numRandomized > int(1.1*float64(numSelections)*randomizedProbability) {

		t.Error("Unexpected ratio")
	}

	// getUTLSClientHelloID should map each TLS profile to a utls ClientHelloID.

	for i, profile := range profiles {
		utlsClientHelloID, utlsClientHelloSpec, err :=
			getUTLSClientHelloID(params.Get(), profile)
		if err != nil {
			t.Fatalf("getUTLSClientHelloID failed: %v", err)
		}

		var unexpectedClientHelloID, unexpectedClientHelloSpec bool

		if i < len(protocol.SupportedTLSProfiles) {
			if utlsClientHelloID == utls.HelloCustom {
				unexpectedClientHelloID = true
			}
			if utlsClientHelloSpec != nil {
				unexpectedClientHelloSpec = true
			}
		} else {
			if utlsClientHelloID != utls.HelloCustom {
				unexpectedClientHelloID = true
			}
			if utlsClientHelloSpec == nil {
				unexpectedClientHelloSpec = true
			}
		}

		if unexpectedClientHelloID {
			t.Errorf("Unexpected ClientHelloID for TLS profile %s", profile)
		}
		if unexpectedClientHelloSpec {
			t.Errorf("Unexpected ClientHelloSpec for TLS profile %s", profile)
		}
	}

	// Only custom TLS profiles should be selected

	params = makeCustomTLSProfilesParameters(t, true, "")
	customTLSProfileNames := params.Get().CustomTLSProfileNames()

	for i := 0; i < numSelections; i++ {
		profile, _, seed, err := SelectTLSProfile(false, false, false, "", "", params.Get())
		if err != nil {
			t.Fatalf("SelectTLSProfile failed: %v", err)
		}
		if !common.Contains(customTLSProfileNames, profile) {
			t.Errorf("unexpected non-custom TLS profile selected")
		}
		if protocol.TLSProfileIsRandomized(profile) && seed == nil {
			t.Errorf("expected non-nil seed for randomized TLS profile")
		}
	}

	// Disabled TLS profiles should not be selected

	frontingProviderID := "frontingProviderID"

	params = makeCustomTLSProfilesParameters(t, false, frontingProviderID)
	disableTLSProfiles := params.Get().LabeledTLSProfiles(
		parameters.DisableFrontingProviderTLSProfiles, frontingProviderID)

	if len(disableTLSProfiles) < 1 {
		t.Errorf("unexpected disabled TLS profiles count")
	}

	for i := 0; i < numSelections; i++ {
		profile, _, seed, err := SelectTLSProfile(false, false, true, frontingProviderID, "", params.Get())
		if err != nil {
			t.Fatalf("SelectTLSProfile failed: %v", err)
		}
		if common.Contains(disableTLSProfiles, profile) {
			t.Errorf("unexpected disabled TLS profile selected")
		}
		if protocol.TLSProfileIsRandomized(profile) && seed == nil {
			t.Errorf("expected non-nil seed for randomized TLS profile")
		}
	}

	// Session ticket incapable TLS 1.2 profiles should not be selected

	for i := 0; i < numSelections; i++ {
		profile, _, seed, err := SelectTLSProfile(true, false, false, "", "", params.Get())
		if err != nil {
			t.Fatalf("SelectTLSProfile failed: %v", err)
		}
		if protocol.TLS12ProfileOmitsSessionTickets(profile) {
			t.Errorf("unexpected session ticket incapable TLS profile selected")
		}
		if protocol.TLSProfileIsRandomized(profile) && seed == nil {
			t.Errorf("expected non-nil seed for randomized TLS profile")
		}
	}

	// Only TLS 1.3 profiles should be selected

	for i := 0; i < numSelections; i++ {
		profile, tlsVersion, seed, err := SelectTLSProfile(false, true, false, "", "", params.Get())
		if err != nil {
			t.Fatalf("SelectTLSProfile failed: %v", err)
		}
		if tlsVersion != protocol.TLS_VERSION_13 {
			t.Errorf("expected TLS 1.3 profile to be selected")
		}
		if protocol.TLSProfileIsRandomized(profile) && seed == nil {
			t.Errorf("expected non-nil seed for randomized TLS profile")
		}
	}

	// Only TLS 1.3 profiles should be selected. All TLS 1.3 profiles should be
	// session ticket capable.

	for i := 0; i < numSelections; i++ {
		profile, tlsVersion, seed, err := SelectTLSProfile(true, true, false, "", "", params.Get())
		if err != nil {
			t.Fatalf("SelectTLSProfile failed: %v", err)
		}
		if protocol.TLS12ProfileOmitsSessionTickets(profile) {
			t.Errorf("unexpected session ticket incapable TLS profile selected")
		}
		if tlsVersion != protocol.TLS_VERSION_13 {
			t.Errorf("expected TLS 1.3 profile to be selected")
		}
		if protocol.TLSProfileIsRandomized(profile) && seed == nil {
			t.Errorf("expected non-nil seed for randomized TLS profile")
		}
	}
}

func TestTLSFragmentationWithoutSNI(t *testing.T) {
	testDataDirName, err := ioutil.TempDir("", "psiphon-tls-certificate-verification-test")
	if err != nil {
		t.Fatalf("TempDir failed: %v", err)
	}
	defer os.RemoveAll(testDataDirName)

	serverName := "example.org"

	rootCAsFileName,
		_,
		serverCertificatePin,
		shutdown,
		serverAddr,
		dialer := testutils.InitTestCertificatesAndWebServer(
		t, testDataDirName, serverName)
	defer shutdown()

	params, err := parameters.NewParameters(nil)
	if err != nil {
		t.Fatalf("parameters.NewParameters failed: %v", err)
	}

	// Test: missing SNI, the TLS dial succeeds without fragmentation.

	conn, err := Dial(
		context.Background(), "tcp", serverAddr,
		&Config{
			Parameters:                    params,
			Dial:                          dialer,
			SNIServerName:                 "",
			VerifyServerName:              serverName,
			VerifyPins:                    []string{serverCertificatePin},
			TrustedCACertificatesFilename: rootCAsFileName,
			FragmentClientHello:           true,
		})

	if err != nil {
		t.Errorf("Dial failed without SNI: %v", err)
	} else {
		if conn.(*tlsConn).fragmented {
			t.Error("unexpected ClientHello fragmentation without SNI")
		}
		conn.Close()
	}

	// Test: with SNI, the TLS dial succeeds

	conn, err = Dial(
		context.Background(), "tcp", serverAddr,
		&Config{
			Parameters:                    params,
			Dial:                          dialer,
			SNIServerName:                 serverName,
			VerifyServerName:              serverName,
			VerifyPins:                    []string{serverCertificatePin},
			TrustedCACertificatesFilename: rootCAsFileName,
			FragmentClientHello:           true,
		})

	if err != nil {
		t.Errorf("Dial failed: %v", err)
	} else {
		if !conn.(*tlsConn).fragmented {
			t.Error("expected ClientHello fragmentation with SNI")
		}
		conn.Close()
	}

}

func BenchmarkRandomizedGetClientHelloVersion(b *testing.B) {
	for n := 0; n < b.N; n++ {
		utlsClientHelloID := utls.HelloRandomized
		utlsClientHelloID.Seed, _ = utls.NewPRNGSeed()
		getClientHelloVersion(utlsClientHelloID, nil)
	}
}

func makeCustomTLSProfilesParameters(
	t *testing.T, useOnlyCustomTLSProfiles bool, frontingProviderID string) *parameters.Parameters {

	params, err := parameters.NewParameters(nil)
	if err != nil {
		t.Fatalf("NewParameters failed: %v", err)
	}

	// Equivilent to utls.HelloChrome_62
	customTLSProfilesJSON := []byte(`
    [
      {
        "Name": "CustomProfile",
        "UTLSSpec": {
          "TLSVersMax": 771,
          "TLSVersMin": 769,
          "CipherSuites": [2570, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156, 157, 47, 53, 10],
          "CompressionMethods": [0],
          "Extensions" : [
            {"Name": "GREASE"},
            {"Name": "SNI"},
            {"Name": "ExtendedMasterSecret"},
            {"Name": "SessionTicket"},
            {"Name": "SignatureAlgorithms", "Data": {"SupportedSignatureAlgorithms": [1027, 2052, 1025, 1283, 2053, 1281, 2054, 1537, 513]}},
            {"Name": "StatusRequest"},
            {"Name": "SCT"},
            {"Name": "ALPN", "Data": {"AlpnProtocols": ["h2", "http/1.1"]}},
            {"Name": "ChannelID"},
            {"Name": "SupportedPoints", "Data": {"SupportedPoints": [0]}},
            {"Name": "SupportedCurves", "Data": {"Curves": [2570, 29, 23, 24]}},
            {"Name": "BoringPadding"},
            {"Name": "GREASE"}],
          "GetSessionID": "SHA-256"
        }
      }
    ]`)

	var customTLSProfiles protocol.CustomTLSProfiles

	err = json.Unmarshal(customTLSProfilesJSON, &customTLSProfiles)
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	applyParameters := make(map[string]interface{})

	applyParameters[parameters.UseOnlyCustomTLSProfiles] = useOnlyCustomTLSProfiles
	applyParameters[parameters.CustomTLSProfiles] = customTLSProfiles

	if frontingProviderID != "" {
		tlsProfiles := make(protocol.TLSProfiles, 0)
		tlsProfiles = append(tlsProfiles, "CustomProfile")
		for i, tlsProfile := range protocol.SupportedTLSProfiles {
			if i%2 == 0 {
				tlsProfiles = append(tlsProfiles, tlsProfile)
			}
		}
		disabledTLSProfiles := make(protocol.LabeledTLSProfiles)
		disabledTLSProfiles[frontingProviderID] = tlsProfiles

		applyParameters[parameters.DisableFrontingProviderTLSProfiles] = disabledTLSProfiles
	}

	_, err = params.Set("", 0, applyParameters)
	if err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	customTLSProfileNames := params.Get().CustomTLSProfileNames()
	if len(customTLSProfileNames) != 1 {
		t.Fatalf("Unexpected CustomTLSProfileNames count")
	}

	return params
}
