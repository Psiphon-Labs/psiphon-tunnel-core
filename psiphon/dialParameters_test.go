/*
 * Copyright (c) 2018, Psiphon Inc.
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
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
)

func TestDialParametersAndReplay(t *testing.T) {
	for _, tunnelProtocol := range protocol.SupportedTunnelProtocols {
		if !common.Contains(protocol.DefaultDisabledTunnelProtocols, tunnelProtocol) {
			runDialParametersAndReplay(t, tunnelProtocol)
		}
	}
}

var testNetworkID = prng.HexString(8)

type testNetworkGetter struct {
}

func (t *testNetworkGetter) GetNetworkID() string {
	return testNetworkID
}

func runDialParametersAndReplay(t *testing.T, tunnelProtocol string) {

	t.Logf("Test %s...", tunnelProtocol)

	testDataDirName, err := ioutil.TempDir("", "psiphon-dial-parameters-test")
	if err != nil {
		t.Fatalf("TempDir failed: %s", err)
	}
	defer os.RemoveAll(testDataDirName)

	SetNoticeWriter(ioutil.Discard)

	clientConfig := &Config{
		PropagationChannelId: "0",
		SponsorId:            "0",
		DataStoreDirectory:   testDataDirName,
		NetworkIDGetter:      new(testNetworkGetter),
	}

	err = clientConfig.Commit()
	if err != nil {
		t.Fatalf("error committing configuration file: %s", err)
	}

	applyParameters := make(map[string]interface{})
	applyParameters[parameters.TransformHostNameProbability] = 1.0
	applyParameters[parameters.PickUserAgentProbability] = 1.0
	err = clientConfig.SetClientParameters("tag1", true, applyParameters)
	if err != nil {
		t.Fatalf("SetClientParameters failed: %s", err)
	}

	err = OpenDataStore(clientConfig)
	if err != nil {
		t.Fatalf("error initializing client datastore: %s", err)
	}
	defer CloseDataStore()

	serverEntries := makeMockServerEntries(tunnelProtocol, 100)

	canReplay := func(serverEntry *protocol.ServerEntry, replayProtocol string) bool {
		return replayProtocol == tunnelProtocol
	}

	selectProtocol := func(serverEntry *protocol.ServerEntry) (string, bool) {
		return tunnelProtocol, true
	}

	RegisterSSHClientVersionPicker(func() string {
		versions := []string{"SSH-2.0-A", "SSH-2.0-B", "SSH-2.0-C"}
		return versions[prng.Intn(len(versions))]
	})

	RegisterUserAgentPicker(func() string {
		versions := []string{"ua1", "ua2", "ua3"}
		return versions[prng.Intn(len(versions))]
	})

	// Test: expected dial parameter fields set

	dialParams, err := MakeDialParameters(clientConfig, canReplay, selectProtocol, serverEntries[0], false)
	if err != nil {
		t.Fatalf("MakeDialParameters failed: %s", err)
	}

	if dialParams.ServerEntry != serverEntries[0] {
		t.Fatalf("unexpected server entry")
	}

	if dialParams.NetworkID != testNetworkID {
		t.Fatalf("unexpected network ID")
	}

	if dialParams.IsReplay {
		t.Fatalf("unexpected replay")
	}

	if dialParams.TunnelProtocol != tunnelProtocol {
		t.Fatalf("unexpected tunnel protocol")
	}

	if !protocol.TunnelProtocolUsesMeek(tunnelProtocol) &&
		dialParams.DirectDialAddress == "" {
		t.Fatalf("missing direct dial fields")
	}

	if dialParams.DialPortNumber == "" {
		t.Fatalf("missing port number fields")
	}

	if dialParams.SSHClientVersion == "" || dialParams.SSHKEXSeed == nil {
		t.Fatalf("missing SSH fields")
	}

	if protocol.TunnelProtocolUsesObfuscatedSSH(tunnelProtocol) &&
		dialParams.ObfuscatorPaddingSeed == nil {
		t.Fatalf("missing obfuscator fields")
	}

	if dialParams.FragmentorSeed == nil {
		t.Fatalf("missing fragmentor field")
	}

	if protocol.TunnelProtocolUsesMeek(tunnelProtocol) &&
		(dialParams.MeekDialAddress == "" ||
			dialParams.MeekHostHeader == "" ||
			dialParams.MeekObfuscatorPaddingSeed == nil) {
		t.Fatalf("missing meek fields")
	}

	if protocol.TunnelProtocolUsesFrontedMeek(tunnelProtocol) &&
		(dialParams.MeekFrontingDialAddress == "" ||
			dialParams.MeekFrontingHost == "") {
		t.Fatalf("missing meek fronting fields")
	}

	if protocol.TunnelProtocolUsesMeekHTTP(tunnelProtocol) &&
		dialParams.UserAgent == "" {
		t.Fatalf("missing meek HTTP fields")
	}

	if protocol.TunnelProtocolUsesMeekHTTPS(tunnelProtocol) &&
		(dialParams.MeekSNIServerName == "" ||
			dialParams.TLSProfile == "") {
		t.Fatalf("missing meek HTTPS fields")
	}

	if protocol.TunnelProtocolUsesQUIC(tunnelProtocol) &&
		(dialParams.QUICVersion == "" ||
			dialParams.QUICDialSNIAddress == "") {
		t.Fatalf("missing meek HTTPS fields")
	}

	if dialParams.LivenessTestSeed == nil {
		t.Fatalf("missing liveness test fields")
	}

	if dialParams.APIRequestPaddingSeed == nil {
		t.Fatalf("missing API request fields")
	}

	// Test: no replay after dial reported to fail

	dialParams.Failed()

	dialParams, err = MakeDialParameters(clientConfig, canReplay, selectProtocol, serverEntries[0], false)
	if err != nil {
		t.Fatalf("MakeDialParameters failed: %s", err)
	}

	if dialParams.IsReplay {
		t.Fatalf("unexpected replay")
	}

	// Test: no replay after network ID changes

	dialParams.Succeeded()

	testNetworkID = prng.HexString(8)

	dialParams, err = MakeDialParameters(clientConfig, canReplay, selectProtocol, serverEntries[0], false)
	if err != nil {
		t.Fatalf("MakeDialParameters failed: %s", err)
	}

	if dialParams.NetworkID != testNetworkID {
		t.Fatalf("unexpected network ID")
	}

	if dialParams.IsReplay {
		t.Fatalf("unexpected replay")
	}

	// Test: replay after dial reported to succeed, and replay fields match previous dial parameters

	dialParams.Succeeded()

	replayDialParams, err := MakeDialParameters(clientConfig, canReplay, selectProtocol, serverEntries[0], false)
	if err != nil {
		t.Fatalf("MakeDialParameters failed: %s", err)
	}

	if !replayDialParams.IsReplay {
		t.Fatalf("unexpected non-replay")
	}

	if !replayDialParams.LastUsedTimestamp.After(dialParams.LastUsedTimestamp) {
		t.Fatalf("unexpected non-updated timestamp")
	}

	if replayDialParams.TunnelProtocol != dialParams.TunnelProtocol {
		t.Fatalf("mismatching tunnel protocol")
	}

	if replayDialParams.DirectDialAddress != dialParams.DirectDialAddress ||
		replayDialParams.DialPortNumber != dialParams.DialPortNumber {
		t.Fatalf("mismatching dial fields")
	}

	identicalSeeds := func(seed1, seed2 *prng.Seed) bool {
		if seed1 == nil {
			return seed2 == nil
		}
		return bytes.Compare(seed1[:], seed2[:]) == 0
	}

	if replayDialParams.SelectedSSHClientVersion != dialParams.SelectedSSHClientVersion ||
		replayDialParams.SSHClientVersion != dialParams.SSHClientVersion ||
		!identicalSeeds(replayDialParams.SSHKEXSeed, dialParams.SSHKEXSeed) {
		t.Fatalf("mismatching SSH fields")
	}

	if !identicalSeeds(replayDialParams.ObfuscatorPaddingSeed, dialParams.ObfuscatorPaddingSeed) {
		t.Fatalf("mismatching obfuscator fields")
	}

	if !identicalSeeds(replayDialParams.FragmentorSeed, dialParams.FragmentorSeed) {
		t.Fatalf("mismatching fragmentor fields")
	}

	if replayDialParams.MeekFrontingDialAddress != dialParams.MeekFrontingDialAddress ||
		replayDialParams.MeekFrontingHost != dialParams.MeekFrontingHost ||
		replayDialParams.MeekDialAddress != dialParams.MeekDialAddress ||
		replayDialParams.MeekTransformedHostName != dialParams.MeekTransformedHostName ||
		replayDialParams.MeekSNIServerName != dialParams.MeekSNIServerName ||
		replayDialParams.MeekHostHeader != dialParams.MeekHostHeader ||
		!identicalSeeds(replayDialParams.MeekObfuscatorPaddingSeed, dialParams.MeekObfuscatorPaddingSeed) {
		t.Fatalf("mismatching meek fields")
	}

	if replayDialParams.SelectedUserAgent != dialParams.SelectedUserAgent ||
		replayDialParams.UserAgent != dialParams.UserAgent {
		t.Fatalf("mismatching user agent fields")
	}

	if replayDialParams.SelectedTLSProfile != dialParams.SelectedTLSProfile ||
		replayDialParams.TLSProfile != dialParams.TLSProfile ||
		!identicalSeeds(replayDialParams.RandomizedTLSProfileSeed, dialParams.RandomizedTLSProfileSeed) {
		t.Fatalf("mismatching TLS fields")
	}

	if replayDialParams.QUICVersion != dialParams.QUICVersion ||
		replayDialParams.QUICDialSNIAddress != dialParams.QUICDialSNIAddress ||
		!identicalSeeds(replayDialParams.ObfuscatedQUICPaddingSeed, dialParams.ObfuscatedQUICPaddingSeed) {
		t.Fatalf("mismatching QUIC fields")
	}

	if !identicalSeeds(replayDialParams.LivenessTestSeed, dialParams.LivenessTestSeed) {
		t.Fatalf("mismatching liveness test fields")
	}

	if !identicalSeeds(replayDialParams.APIRequestPaddingSeed, dialParams.APIRequestPaddingSeed) {
		t.Fatalf("mismatching API request fields")
	}

	// Test: no replay after change tactics

	applyParameters[parameters.ReplayDialParametersTTL] = "1s"
	err = clientConfig.SetClientParameters("tag2", true, applyParameters)
	if err != nil {
		t.Fatalf("SetClientParameters failed: %s", err)
	}

	dialParams, err = MakeDialParameters(clientConfig, canReplay, selectProtocol, serverEntries[0], false)
	if err != nil {
		t.Fatalf("MakeDialParameters failed: %s", err)
	}

	if dialParams.IsReplay {
		t.Fatalf("unexpected replay")
	}

	// Test: no replay after dial parameters expired

	dialParams.Succeeded()

	time.Sleep(1 * time.Second)

	dialParams, err = MakeDialParameters(clientConfig, canReplay, selectProtocol, serverEntries[0], false)
	if err != nil {
		t.Fatalf("MakeDialParameters failed: %s", err)
	}

	if dialParams.IsReplay {
		t.Fatalf("unexpected replay")
	}

	// Test: no replay after server entry changes

	dialParams.Succeeded()

	serverEntries[0].ConfigurationVersion += 1

	dialParams, err = MakeDialParameters(clientConfig, canReplay, selectProtocol, serverEntries[0], false)
	if err != nil {
		t.Fatalf("MakeDialParameters failed: %s", err)
	}

	if dialParams.IsReplay {
		t.Fatalf("unexpected replay")
	}

	// Test: disable replay elements (partial coverage)

	applyParameters[parameters.ReplayDialParametersTTL] = "24h"
	applyParameters[parameters.ReplaySSH] = false
	applyParameters[parameters.ReplayObfuscatorPadding] = false
	applyParameters[parameters.ReplayFragmentor] = false
	applyParameters[parameters.ReplayRandomizedTLSProfile] = false
	applyParameters[parameters.ReplayObfuscatedQUIC] = false
	applyParameters[parameters.ReplayLivenessTest] = false
	applyParameters[parameters.ReplayAPIRequestPadding] = false
	err = clientConfig.SetClientParameters("tag3", true, applyParameters)
	if err != nil {
		t.Fatalf("SetClientParameters failed: %s", err)
	}

	dialParams, err = MakeDialParameters(clientConfig, canReplay, selectProtocol, serverEntries[0], false)
	if err != nil {
		t.Fatalf("MakeDialParameters failed: %s", err)
	}

	dialParams.Succeeded()

	replayDialParams, err = MakeDialParameters(clientConfig, canReplay, selectProtocol, serverEntries[0], false)
	if err != nil {
		t.Fatalf("MakeDialParameters failed: %s", err)
	}

	if !replayDialParams.IsReplay {
		t.Fatalf("unexpected non-replay")
	}

	if identicalSeeds(replayDialParams.SSHKEXSeed, dialParams.SSHKEXSeed) ||
		(protocol.TunnelProtocolUsesObfuscatedSSH(tunnelProtocol) &&
			identicalSeeds(replayDialParams.ObfuscatorPaddingSeed, dialParams.ObfuscatorPaddingSeed)) ||
		identicalSeeds(replayDialParams.FragmentorSeed, dialParams.FragmentorSeed) ||
		(protocol.TunnelProtocolUsesMeek(tunnelProtocol) &&
			identicalSeeds(replayDialParams.MeekObfuscatorPaddingSeed, dialParams.MeekObfuscatorPaddingSeed)) ||
		(protocol.TunnelProtocolUsesMeekHTTPS(tunnelProtocol) &&
			identicalSeeds(replayDialParams.RandomizedTLSProfileSeed, dialParams.RandomizedTLSProfileSeed) &&
			replayDialParams.RandomizedTLSProfileSeed != nil) ||
		(protocol.TunnelProtocolUsesQUIC(tunnelProtocol) &&
			identicalSeeds(replayDialParams.ObfuscatedQUICPaddingSeed, dialParams.ObfuscatedQUICPaddingSeed) &&
			replayDialParams.ObfuscatedQUICPaddingSeed != nil) ||
		identicalSeeds(replayDialParams.LivenessTestSeed, dialParams.LivenessTestSeed) ||
		identicalSeeds(replayDialParams.APIRequestPaddingSeed, dialParams.APIRequestPaddingSeed) {
		t.Fatalf("unexpected replayed fields")
	}

	// Test: iterator shuffles

	for i, serverEntry := range serverEntries {

		data, err := json.Marshal(serverEntry)
		if err != nil {
			t.Fatalf("json.Marshal failed: %s", err)
		}

		var serverEntryFields protocol.ServerEntryFields
		err = json.Unmarshal(data, &serverEntryFields)
		if err != nil {
			t.Fatalf("json.Unmarshal failed: %s", err)
		}

		err = StoreServerEntry(serverEntryFields, false)
		if err != nil {
			t.Fatalf("StoreServerEntry failed: %s", err)
		}

		if i%10 == 0 {

			dialParams, err := MakeDialParameters(clientConfig, canReplay, selectProtocol, serverEntry, false)
			if err != nil {
				t.Fatalf("MakeDialParameters failed: %s", err)
			}

			dialParams.Succeeded()
		}
	}

	for i := 0; i < 5; i++ {

		hasAffinity, iterator, err := NewServerEntryIterator(clientConfig)
		if err != nil {
			t.Fatalf("NewServerEntryIterator failed: %s", err)
		}

		if hasAffinity {
			t.Fatalf("unexpected affinity server")
		}

		// Test: the first shuffle should move the replay candidates to the front

		for j := 0; j < 10; j++ {

			serverEntry, err := iterator.Next()
			if err != nil {
				t.Fatalf("ServerEntryIterator.Next failed: %s", err)
			}

			dialParams, err := MakeDialParameters(clientConfig, canReplay, selectProtocol, serverEntry, false)
			if err != nil {
				t.Fatalf("MakeDialParameters failed: %s", err)
			}

			if !dialParams.IsReplay {
				t.Fatalf("unexpected non-replay")
			}
		}

		iterator.Reset()

		// Test: subsequent shuffles should not move the replay candidates

		allReplay := true
		for j := 0; j < 10; j++ {

			serverEntry, err := iterator.Next()
			if err != nil {
				t.Fatalf("ServerEntryIterator.Next failed: %s", err)
			}

			dialParams, err := MakeDialParameters(clientConfig, canReplay, selectProtocol, serverEntry, false)
			if err != nil {
				t.Fatalf("MakeDialParameters failed: %s", err)
			}

			if !dialParams.IsReplay {
				allReplay = false
			}
		}

		if allReplay {
			t.Fatalf("unexpected all replay")
		}

		iterator.Close()
	}
}

func makeMockServerEntries(tunnelProtocol string, count int) []*protocol.ServerEntry {

	serverEntries := make([]*protocol.ServerEntry, count)

	for i := 0; i < count; i++ {
		serverEntries[i] = &protocol.ServerEntry{
			IpAddress:                  fmt.Sprintf("192.168.0.%d", i),
			SshPort:                    1,
			SshObfuscatedPort:          2,
			SshObfuscatedQUICPort:      3,
			SshObfuscatedTapdancePort:  4,
			MeekServerPort:             5,
			MeekFrontingHosts:          []string{"www1.example.org", "www2.example.org", "www3.example.org"},
			MeekFrontingAddressesRegex: "[a-z0-9]{1,64}.example.org",
		}
	}

	return serverEntries
}
