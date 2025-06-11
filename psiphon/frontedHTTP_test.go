/*
 * Copyright (c) 2024, Psiphon Inc.
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
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	utls "github.com/Psiphon-Labs/utls"
	"github.com/stretchr/testify/assert"
)

func TestFrontedHTTPClientInstance(t *testing.T) {

	// Generate server keys

	sk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("error generating key: %s", err)
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&sk.PublicKey)
	if err != nil {
		t.Fatalf("error marshaling public key: %s", err)
	}

	// Setup client

	networkID := fmt.Sprintf("WIFI-%s", time.Now().String())

	clientConfigJSON := fmt.Sprintf(`
    {
        "ClientPlatform" : "Android_10_com.test.app",
        "ClientVersion" : "0",

        "SponsorId" : "0000000000000000",
        "PropagationChannelId" : "0000000000000000",
        "DeviceLocation" : "gzzzz",
        "DeviceRegion" : "US",
        "DisableRemoteServerListFetcher" : true,
        "EnableFeedbackUpload" : true,
        "DisableTactics" : true,
        "FeedbackEncryptionPublicKey" : "%s",
        "NetworkID" : "%s"
    }`,
		base64.StdEncoding.EncodeToString(pubKeyBytes),
		networkID)

	config, err := LoadConfig([]byte(clientConfigJSON))
	if err != nil {
		t.Fatalf("error processing configuration file: %s", err)
	}

	testDataDirName, err := os.MkdirTemp("", "psiphon-feedback-test")
	if err != nil {
		t.Fatalf("TempDir failed: %s", err)
	}
	config.DataRootDirectory = testDataDirName

	address := "example.org"
	addressRegex := `[a-z0-9]{5,10}\.example\.org`
	url := fmt.Sprintf("https://%s", address)

	frontingSpecs := parameters.FrontingSpecs{
		{
			FrontingProviderID: prng.HexString(8),
			Addresses:          []string{addressRegex},
			DisableSNI:         prng.FlipCoin(),
			SkipVerify:         true,
			Host:               "example.org",
		},
	}

	config.FeedbackUploadURLs = parameters.TransferURLs{
		{
			URL:                 base64.StdEncoding.EncodeToString([]byte(url)),
			SkipVerify:          true,
			OnlyAfterAttempts:   0,
			B64EncodedPublicKey: base64.StdEncoding.EncodeToString(pubKeyBytes),
			RequestHeaders:      map[string]string{},
			FrontingSpecs:       frontingSpecs,
		},
	}

	err = config.Commit(true)
	if err != nil {
		t.Fatalf("error committing configuration file: %s", err)
	}

	resolver := NewResolver(config, false)
	defer resolver.Stop()
	config.SetResolver(resolver)

	err = OpenDataStore(config)
	if err != nil {
		t.Fatalf("OpenDataStore failed: %s", err)
	}
	defer CloseDataStore()

	// Make fronted HTTP client instance

	tlsCache := utls.NewLRUClientSessionCache(0)

	// TODO: test that replay is disabled when there is a tunnel
	var tunnel *Tunnel = nil
	useDeviceBinder := true
	skipVerify := false
	payloadSecure := true
	client, err := newFrontedHTTPClientInstance(
		config, tunnel, frontingSpecs, nil, useDeviceBinder, skipVerify, config.DisableSystemRootCAs, payloadSecure, tlsCache)
	if err != nil {
		t.Fatalf("newFrontedHTTPClientInstance failed: %s", err)
	}
	client.frontedHTTPClientRoundTripperSucceeded()

	// Do replay

	prevClient := client

	client, err = newFrontedHTTPClientInstance(
		config, tunnel, frontingSpecs, nil, useDeviceBinder, skipVerify, config.DisableSystemRootCAs, payloadSecure, tlsCache)
	if err != nil {
		t.Fatalf("newFrontedHTTPClientInstance failed: %s", err)
	}

	if !client.frontedHTTPDialParameters.isReplay {
		t.Fatal("expected replay")
	}

	// Note: only exported FrontedHTTPDialParameters fields are stored for replay.
	assert.EqualExportedValues(t, prevClient.frontedHTTPDialParameters, client.frontedHTTPDialParameters)

	// Change network ID so there should be no replay.
	config.NetworkID = fmt.Sprintf("CELLULAR-%s", time.Now().String())
	err = config.Commit(true)
	if err != nil {
		t.Fatalf("error committing configuration file: %s", err)
	}

	client, err = newFrontedHTTPClientInstance(
		config, tunnel, frontingSpecs, nil, useDeviceBinder, skipVerify,
		config.DisableSystemRootCAs, payloadSecure, tlsCache)
	if err != nil {
		t.Fatalf("newFrontedHTTPClientInstance failed: %s", err)
	}

	if client.frontedHTTPDialParameters.isReplay {
		t.Fatal("expected no replay")
	}
}
