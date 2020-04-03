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

package psiphon

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/values"
	tris "github.com/Psiphon-Labs/tls-tris"
	utls "github.com/refraction-networking/utls"
)

func TestTLSDialerCompatibility(t *testing.T) {

	// This test checks that each TLS profile can successfully complete a TLS
	// handshake with various servers. By default, only the "psiphon" case is
	// run, which runs the same TLS listener used by a Psiphon server.
	//
	// An optional config file, when supplied, enables testing against remote
	// servers. Config should be newline delimited list of domain/IP:port TLS
	// host addresses to connect to.

	var configAddresses []string
	config, err := ioutil.ReadFile("tlsDialerCompatibility_test.config")
	if err == nil {
		configAddresses = strings.Split(string(config), "\n")
	}

	runner := func(address string) func(t *testing.T) {
		return func(t *testing.T) {
			testTLSDialerCompatibility(t, address)
		}
	}

	for _, address := range configAddresses {
		if len(address) > 0 {
			t.Run(address, runner(address))
		}
	}

	t.Run("psiphon", runner(""))
}

func testTLSDialerCompatibility(t *testing.T, address string) {

	if address == "" {

		// Same tls-tris config as psiphon/server/meek.go

		certificate, privateKey, err := common.GenerateWebServerCertificate(values.GetHostName())
		if err != nil {
			t.Fatalf("%s\n", err)
		}

		tlsCertificate, err := tris.X509KeyPair([]byte(certificate), []byte(privateKey))
		if err != nil {
			t.Fatalf("%s\n", err)
		}

		config := &tris.Config{
			Certificates:            []tris.Certificate{tlsCertificate},
			NextProtos:              []string{"http/1.1"},
			MinVersion:              tris.VersionTLS10,
			UseExtendedMasterSecret: true,
		}

		tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("%s\n", err)
		}

		tlsListener := tris.NewListener(tcpListener, config)
		defer tlsListener.Close()

		address = tlsListener.Addr().String()

		go func() {
			for {
				conn, err := tlsListener.Accept()
				if err != nil {
					return
				}
				err = conn.(*tris.Conn).Handshake()
				if err != nil {
					t.Logf("server handshake: %s", err)
				}
				conn.Close()
			}
		}()
	}

	dialer := func(ctx context.Context, network, address string) (net.Conn, error) {
		d := &net.Dialer{}
		return d.DialContext(ctx, network, address)
	}

	clientParameters := makeCustomTLSProfilesClientParameters(t, false, "")

	profiles := append([]string(nil), protocol.SupportedTLSProfiles...)
	profiles = append(profiles, clientParameters.Get().CustomTLSProfileNames()...)

	for _, tlsProfile := range profiles {

		repeats := 2
		if protocol.TLSProfileIsRandomized(tlsProfile) {
			repeats = 20
		}

		success := 0
		tlsVersions := []string{}
		for i := 0; i < repeats; i++ {

			transformHostname := i%2 == 0

			tlsConfig := &CustomTLSConfig{
				ClientParameters: clientParameters,
				Dial:             dialer,
				SkipVerify:       true,
				TLSProfile:       tlsProfile,
			}

			if transformHostname {
				tlsConfig.SNIServerName = values.GetHostName()
			} else {
				tlsConfig.UseDialAddrSNI = true
			}

			ctx, cancelFunc := context.WithTimeout(context.Background(), 5*time.Second)

			conn, err := CustomTLSDial(ctx, "tcp", address, tlsConfig)

			if err != nil {
				t.Logf("%s (transformHostname: %v): %s\n",
					tlsProfile, transformHostname, err)
			} else {

				tlsVersion := ""
				version := conn.(*utls.UConn).ConnectionState().Version
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

				conn.Close()
				success += 1
			}

			cancelFunc()

			time.Sleep(100 * time.Millisecond)
		}

		result := fmt.Sprintf(
			"%s: %d/%d successful; negotiated TLS versions: %v\n",
			tlsProfile, success, repeats, tlsVersions)

		if success == repeats {
			t.Logf(result)
		} else {
			t.Errorf(result)
		}
	}
}

func TestSelectTLSProfile(t *testing.T) {

	clientParameters := makeCustomTLSProfilesClientParameters(t, false, "")

	profiles := append([]string(nil), protocol.SupportedTLSProfiles...)
	profiles = append(profiles, clientParameters.Get().CustomTLSProfileNames()...)

	selected := make(map[string]int)

	numSelections := 10000

	for i := 0; i < numSelections; i++ {
		profile := SelectTLSProfile(false, false, "", clientParameters.Get())
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

	randomizedProbability := clientParameters.Get().Float(
		parameters.SelectRandomizedTLSProfileProbability)

	if numRandomized < int(0.9*float64(numSelections)*randomizedProbability) ||
		numRandomized > int(1.1*float64(numSelections)*randomizedProbability) {

		t.Error("Unexpected ratio")
	}

	// getUTLSClientHelloID should map each TLS profile to a utls ClientHelloID.

	for i, profile := range profiles {
		utlsClientHelloID, utlsClientHelloSpec, err :=
			getUTLSClientHelloID(clientParameters.Get(), profile)
		if err != nil {
			t.Fatalf("getUTLSClientHelloID failed: %s\n", err)
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

	clientParameters = makeCustomTLSProfilesClientParameters(t, true, "")
	customTLSProfileNames := clientParameters.Get().CustomTLSProfileNames()

	for i := 0; i < numSelections; i++ {
		profile := SelectTLSProfile(false, false, "", clientParameters.Get())
		if !common.Contains(customTLSProfileNames, profile) {
			t.Errorf("unexpected non-custom TLS profile selected")
		}
	}

	// Disabled TLS profiles should not be selected

	frontingProviderID := "frontingProviderID"

	clientParameters = makeCustomTLSProfilesClientParameters(t, false, frontingProviderID)
	disableTLSProfiles := clientParameters.Get().LabeledTLSProfiles(
		parameters.DisableFrontingProviderTLSProfiles, frontingProviderID)

	if len(disableTLSProfiles) < 1 {
		t.Errorf("unexpected disabled TLS profiles count")
	}

	for i := 0; i < numSelections; i++ {
		profile := SelectTLSProfile(false, true, frontingProviderID, clientParameters.Get())
		if common.Contains(disableTLSProfiles, profile) {
			t.Errorf("unexpected disabled TLS profile selected")
		}
	}

	// Session ticket incapable TLS 1.2 profiles should not be selected

	for i := 0; i < numSelections; i++ {
		profile := SelectTLSProfile(true, false, "", clientParameters.Get())
		if protocol.TLS12ProfileOmitsSessionTickets(profile) {
			t.Errorf("unexpected session ticket incapable TLS profile selected")
		}
	}
}

func BenchmarkRandomizedGetClientHelloVersion(b *testing.B) {
	for n := 0; n < b.N; n++ {
		utlsClientHelloID := utls.HelloRandomized
		utlsClientHelloID.Seed, _ = utls.NewPRNGSeed()
		getClientHelloVersion(utlsClientHelloID, nil)
	}
}

func makeCustomTLSProfilesClientParameters(
	t *testing.T, useOnlyCustomTLSProfiles bool, frontingProviderID string) *parameters.ClientParameters {

	clientParameters, err := parameters.NewClientParameters(nil)
	if err != nil {
		t.Fatalf("NewClientParameters failed: %s\n", err)
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
		t.Fatalf("Unmarshal failed: %s", err)
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

	_, err = clientParameters.Set("", false, applyParameters)
	if err != nil {
		t.Fatalf("Set failed: %s", err)
	}

	customTLSProfileNames := clientParameters.Get().CustomTLSProfileNames()
	if len(customTLSProfileNames) != 1 {
		t.Fatalf("Unexpected CustomTLSProfileNames count")
	}

	return clientParameters
}
