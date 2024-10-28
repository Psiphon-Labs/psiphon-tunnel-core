/*
 * Copyright (c) 2016, Psiphon Inc.
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
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/values"
)

type Diagnostics struct {
	Feedback struct {
		Message struct {
			Text string `json:"text"`
		}
		Email string `json:"email"`
	}
	Metadata struct {
		Id       string `json:"id"`
		Platform string `json:"platform"`
		Version  int    `json:"version"`
	}
}

func TestFeedbackUploadRemote(t *testing.T) {
	configFileContents, err := ioutil.ReadFile("controller_test.config")
	if err != nil {
		// Skip, don't fail, if config file is not present
		t.Skipf("error loading configuration file: %s", err)
	}

	// Load config, configure data root directory and commit it

	config, err := LoadConfig(configFileContents)
	if err != nil {
		t.Fatalf("error loading configuration file: %s", err)
	}

	if !config.EnableFeedbackUpload {
		config.EnableFeedbackUpload = true
	}

	if config.ClientPlatform == "" {
		config.ClientPlatform = testClientPlatform
	}

	testDataDirName, err := ioutil.TempDir("", "psiphon-feedback-test")
	if err != nil {
		t.Fatalf("TempDir failed: %s", err)
	}

	config.DataRootDirectory = testDataDirName

	err = config.Commit(true)
	if err != nil {
		t.Fatalf("error committing configuration file: %s", err)
	}

	shortRevHash, err := exec.Command("git", "rev-parse", "--short", "HEAD").Output()
	if err != nil {
		// Log, don't fail, if git rev is not available
		t.Logf("error loading git revision file: %s", err)
		shortRevHash = []byte("unknown")
	}

	// Construct feedback data which can be verified later
	diagnostics := Diagnostics{}
	diagnostics.Feedback.Message.Text = "Test feedback from feedback_test.go, revision: " + string(shortRevHash)
	diagnostics.Metadata.Id = "0000000000000000"
	diagnostics.Metadata.Platform = "android"
	diagnostics.Metadata.Version = 4

	diagnosticData, err := json.Marshal(diagnostics)
	if err != nil {
		t.Fatalf("Marshal failed: %s", err)
	}

	err = SendFeedback(context.Background(), config, string(diagnosticData), "")
	if err != nil {
		t.Fatalf("SendFeedback failed: %s", err)
	}
}

func TestFeedbackUploadLocal(t *testing.T) {
	t.Run("without fronting spec", func(t *testing.T) {
		runTestFeedbackUploadLocal(t, false)
	})
	t.Run("with fronting spec", func(t *testing.T) {
		runTestFeedbackUploadLocal(t, true)
	})
}

func runTestFeedbackUploadLocal(t *testing.T, useFrontingSpecs bool) {

	// Generate server keys

	sk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("error generating key: %s", err)
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&sk.PublicKey)
	if err != nil {
		t.Fatalf("error marshaling public key: %s", err)
	}

	// Start local server that will receive feedback upload

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
		// TODO: verify HMAC and decrypt feedback
	})

	host := values.GetHostName()
	certificate, privateKey, _, err := common.GenerateWebServerCertificate(host)
	if err != nil {
		t.Fatalf("common.GenerateWebServerCertificate failed: %v", err)
	}

	tlsCertificate, err := tls.X509KeyPair([]byte(certificate), []byte(privateKey))
	if err != nil {
		t.Fatalf("tls.X509KeyPair failed: %v", err)
	}

	serverConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCertificate},
		NextProtos:   []string{"http/1.1"},
		MinVersion:   tls.VersionTLS10,
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverConfig)
	if err != nil {
		t.Fatalf("net.Listen failed %v", err)
	}
	defer listener.Close()

	s := &http.Server{
		Addr:    listener.Addr().String(),
		Handler: mux,
	}
	serverErrors := make(chan error)
	defer func() {
		err := s.Shutdown(context.Background())
		if err != nil {
			t.Fatalf("error shutting down server: %s", err)
		}
		err = <-serverErrors
		if err != nil {
			t.Fatalf("error running server: %s", err)
		}
	}()

	go func() {
		err := s.Serve(listener)
		if !errors.Is(err, http.ErrServerClosed) {
			serverErrors <- err
		}
		close(serverErrors)
	}()

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
	defer os.RemoveAll(testDataDirName)

	config.DataRootDirectory = testDataDirName

	address := listener.Addr().String()
	addressRegex := strings.ReplaceAll(address, ".", "\\.")
	url := fmt.Sprintf("https://%s", address)

	var frontingSpecs parameters.FrontingSpecs
	if useFrontingSpecs {
		frontingSpecs = parameters.FrontingSpecs{
			{
				FrontingProviderID: prng.HexString(8),
				Addresses:          []string{addressRegex},
				DisableSNI:         prng.FlipCoin(),
				SkipVerify:         true,
				Host:               host,
			},
		}
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

	err = OpenDataStore(config)
	if err != nil {
		t.Fatalf("OpenDataStore failed: %s", err)
	}
	defer CloseDataStore()

	// Construct feedback data

	diagnostics := Diagnostics{}
	diagnostics.Feedback.Message.Text = "Test feedback from feedback_test.go"
	diagnostics.Metadata.Id = "0000000000000000"
	diagnostics.Metadata.Platform = "android"
	diagnostics.Metadata.Version = 4

	diagnosticData, err := json.Marshal(diagnostics)
	if err != nil {
		t.Fatalf("Marshal failed: %s", err)
	}

	// Upload feedback

	err = SendFeedback(context.Background(), config, string(diagnosticData), "/upload_path")
	if err != nil {
		t.Fatalf("SendFeedback failed: %s", err)
	}

	// Upload feedback again to exercise replay

	err = SendFeedback(context.Background(), config, string(diagnosticData), "/upload_path")
	if err != nil {
		t.Fatalf("SendFeedback failed: %s", err)
	}
}
