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

package psiphon

import (
	"context"
	"encoding/base64"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
)

func TestUntunneledTransferHTTPClientFactory(t *testing.T) {
	if err := runTestUntunneledTransferHTTPClientFactory(); err != nil {
		t.Fatal(err.Error())
	}
	if err := runRemoteTestUntunneledUpgradeHTTPClientFactory(); err != nil {
		t.Fatal(err.Error())
	}
}

func runTestUntunneledTransferHTTPClientFactory() error {

	dataRootDirectory, err := os.MkdirTemp(
		"", "psiphon-untunneled-upgrade-http-client-factory-test")
	if err != nil {
		return errors.Trace(err)
	}
	defer os.RemoveAll(dataRootDirectory)

	config := &Config{
		DataRootDirectory:    dataRootDirectory,
		PropagationChannelId: "0000000000000000",
		SponsorId:            "0000000000000000",
	}

	err = config.Commit(false)
	if err != nil {
		return errors.Trace(err)
	}

	transferURLs := parameters.TransferURLs{
		{
			URL:               "https://example.com/upgrade-0",
			OnlyAfterAttempts: 0,
			RequestHeaders: map[string]string{
				"X-Test": "value",
			},
		},
		{
			URL:               "https://example.com/upgrade-2",
			OnlyAfterAttempts: 2,
		},
		{
			URL:               "https://example.com/upgrade-3",
			OnlyAfterAttempts: 3,
		},
	}

	// Test: input TransferURLs, headers, and OnlyAfterAttempts

	factory, err := NewUntunneledTransferHTTPClientFactory(
		config, transferURLs)
	if err != nil {
		return errors.Trace(err)
	}

	for attempt := 0; attempt < 4; attempt++ {
		client, requestURL, headers, err := factory.NextHTTPClient()
		if err != nil {
			factory.Close()
			return errors.Trace(err)
		}
		client.CloseIdleConnections()

		switch attempt {
		case 0, 1:
			if requestURL.String() != transferURLs[0].URL {
				factory.Close()
				return errors.TraceNew("selected URL before eligible attempt")
			}
		case 2:
			if requestURL.String() == transferURLs[2].URL {
				factory.Close()
				return errors.TraceNew("selected URL before eligible attempt")
			}
		}

		if attempt == 0 && headers.Get("X-Test") != "value" {
			factory.Close()
			return errors.TraceNew("unexpected request headers")
		}

		if factory.nextAttempt != attempt+1 {
			factory.Close()
			return errors.TraceNew("unexpected next attempt")
		}
	}

	factory.Close()
	factory.Close()

	if config.GetResolver() != nil {
		return errors.TraceNew("resolver not cleared")
	}

	if _, _, _, err := factory.NextHTTPClient(); err == nil {
		return errors.TraceNew("expected closed factory error")
	}

	// Test: tactics UpgradeDownloadURLs override and are selected once

	tacticsURL := "https://example.com/tactics-upgrade"
	tacticsTransferURLs := parameters.TransferURLs{{
		URL: base64.StdEncoding.EncodeToString([]byte(tacticsURL)),
	}}

	err = config.SetParameters(
		"tactics-1",
		false,
		map[string]interface{}{
			parameters.UpgradeDownloadURLs: tacticsTransferURLs,
			// Skip tactics fetch.
			parameters.UpgradeTacticsWaitPeriod: 0 * time.Second,
		})
	if err != nil {
		return errors.Trace(err)
	}

	factory, err = NewUntunneledUpgradeHTTPClientFactory(
		context.Background(), config, transferURLs)
	if err != nil {
		return errors.Trace(err)
	}

	replacementTacticsURL := "https://example.com/replacement-tactics-upgrade"
	err = config.SetParameters(
		"tactics-2",
		false,
		map[string]interface{}{
			parameters.UpgradeDownloadURLs: parameters.TransferURLs{{
				URL: base64.StdEncoding.EncodeToString(
					[]byte(replacementTacticsURL)),
			}},
		})
	if err != nil {
		factory.Close()
		return errors.Trace(err)
	}

	client, requestURL, _, err := factory.NextHTTPClient()
	if err != nil {
		factory.Close()
		return errors.Trace(err)
	}
	client.CloseIdleConnections()
	factory.Close()

	if requestURL.String() != tacticsURL {
		return errors.TraceNew("tactics URLs were not selected once")
	}

	// Reset tactics parameters to the config values.
	err = config.SetParameters("clear-tactics", false, nil)
	if err != nil {
		return errors.Trace(err)
	}

	// Test: constructor rejects an invalid URL without installing a resolver

	_, err = NewUntunneledTransferHTTPClientFactory(
		config,
		parameters.TransferURLs{{URL: "://invalid"}})
	if err == nil {
		return errors.TraceNew("expected invalid URL error")
	}
	if config.GetResolver() != nil {
		return errors.TraceNew(
			"resolver installed after invalid URL error")
	}

	// Test: constructor validation failsafe rejects URLs with no
	// OnlyAfterAttempts 0 candidate, without installing a resolver

	_, err = NewUntunneledTransferHTTPClientFactory(
		config,
		parameters.TransferURLs{{
			URL:               "https://example.com/upgrade",
			OnlyAfterAttempts: 1,
		}})
	if err == nil {
		return errors.TraceNew("expected validation error")
	}
	if config.GetResolver() != nil {
		return errors.TraceNew("resolver installed after validation error")
	}

	// Test: constructor error cleans up resolver

	_, err = NewUntunneledUpgradeHTTPClientFactory(
		context.Background(), config, nil)
	if err == nil {
		return errors.TraceNew("expected missing URL error")
	}
	if config.GetResolver() != nil {
		return errors.TraceNew("resolver not cleared after constructor error")
	}

	return nil
}

func runRemoteTestUntunneledUpgradeHTTPClientFactory() error {

	// Test: remote UpgradeDownloadURLs HEAD request

	configJSON, err := os.ReadFile("controller_test.config")
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return errors.Trace(err)
	}

	dataRootDirectory, err := os.MkdirTemp(
		"", "psiphon-untunneled-upgrade-http-client-factory-remote-test")
	if err != nil {
		return errors.Trace(err)
	}
	defer os.RemoveAll(dataRootDirectory)

	config, err := LoadConfig(configJSON)
	if err != nil {
		return errors.Trace(err)
	}

	config.DataRootDirectory = dataRootDirectory
	config.DisableTactics = false
	if config.ClientPlatform == "" {
		config.ClientPlatform = testClientPlatform
	}

	err = config.Commit(false)
	if err != nil {
		return errors.Trace(err)
	}

	err = config.SetParameters(
		"test-zero-tactics-wait",
		false,
		map[string]interface{}{
			// Skip tactics fetch.
			parameters.UpgradeTacticsWaitPeriod: 0 * time.Second,
		})
	if err != nil {
		return errors.Trace(err)
	}

	p := config.GetParameters().Get()
	transferURLs := p.TransferURLs(parameters.UpgradeDownloadURLs)
	p.Close()

	if len(transferURLs) == 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(
		context.Background(), 60*time.Second)
	defer cancel()

	// Pass no fallback URLs to ensure the factory uses the applied
	// UpgradeDownloadURLs parameter.
	factory, err := NewUntunneledUpgradeHTTPClientFactory(ctx, config, nil)
	if err != nil {
		return errors.Trace(err)
	}
	defer factory.Close()

	client, requestURL, headers, err := factory.NextHTTPClient()
	if err != nil {
		return errors.Trace(err)
	}
	defer client.CloseIdleConnections()

	request, err := http.NewRequestWithContext(
		ctx, http.MethodHead, requestURL.String(), nil)
	if err != nil {
		return errors.Trace(err)
	}

	request.Header = headers.Clone()
	request.Header.Set("User-Agent", MakePsiphonUserAgent(config))

	response, err := client.Do(request)
	if err != nil {
		return errors.Trace(err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return errors.Tracef(
			"unexpected response status code: %d",
			response.StatusCode)
	}

	return nil
}
