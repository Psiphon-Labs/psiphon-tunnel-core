/*
 * Copyright (c) 2021, Psiphon Inc.
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
	"io/ioutil"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
)

// MeekModeRelay and MeekModeObfuscatedRoundTrip are tested via meek protocol
// and tactics test cases.

func TestMeekModePlaintextRoundTrip(t *testing.T) {

	testDataDirName, err := ioutil.TempDir("", "psiphon-meek-mode-plaintext-round-trip-test")
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
		dialer := initTestCertificatesAndWebServer(
		t, testDataDirName, serverName)
	defer shutdown()

	params, err := parameters.NewParameters(nil)
	if err != nil {
		t.Fatalf("parameters.NewParameters failed: %v", err)
	}

	testCases := []struct {
		description      string
		meekMode         MeekMode
		verifyServerName string
		verifyPins       []string
	}{
		{
			meekMode:         MeekModePlaintextRoundTrip,
			verifyServerName: serverName,
			verifyPins:       []string{rootCACertificatePin, serverCertificatePin},
		},
		{
			meekMode:         MeekModeWrappedPlaintextRoundTrip,
			verifyServerName: "",
			verifyPins:       nil,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.description, func(t *testing.T) {
			meekConfig := &MeekConfig{
				Parameters:       params,
				Mode:             testCase.meekMode,
				DialAddress:      serverAddr,
				UseHTTPS:         true,
				SNIServerName:    "not-" + serverName,
				VerifyServerName: testCase.verifyServerName,
				VerifyPins:       testCase.verifyPins,
			}

			dialConfig := &DialConfig{
				TrustedCACertificatesFilename: rootCAsFileName,
				CustomDialer:                  dialer,
			}

			for _, tlsFragmentClientHello := range []bool{false, true} {

				ctx, cancelFunc := context.WithTimeout(context.Background(), 1*time.Second)
				defer cancelFunc()

				meekConfig.TLSFragmentClientHello = tlsFragmentClientHello

				meekConn, err := DialMeek(ctx, meekConfig, dialConfig)
				if err != nil {
					t.Fatalf("DialMeek failed: %v", err)
				}

				client := &http.Client{
					Transport: meekConn,
				}

				response, err := client.Get("https://" + serverAddr + "/")
				if err != nil {
					t.Fatalf("http.Client.Get failed: %v", err)
				}
				response.Body.Close()

				if response.StatusCode != http.StatusOK {
					t.Fatalf("unexpected response code: %v", response.StatusCode)
				}

				err = meekConn.Close()
				if err != nil {
					t.Fatalf("MeekConn.Close failed: %v", err)
				}
			}
		})
	}
}
