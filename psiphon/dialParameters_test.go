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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/transforms"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/values"
	lrucache "github.com/cognusion/go-cache-lru"
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

	err = SetNoticeWriter(io.Discard)
	if err != nil {
		t.Fatalf("error setting notice writer: %s", err)
	}
	defer ResetNoticeWriter()

	clientConfig := &Config{
		PropagationChannelId: "0",
		SponsorId:            "0",
		DataRootDirectory:    testDataDirName,
		NetworkIDGetter:      new(testNetworkGetter),
	}

	err = clientConfig.Commit(false)
	if err != nil {
		t.Fatalf("error committing configuration file: %s", err)
	}

	holdOffTunnelProtocolNames := protocol.TunnelProtocols{protocol.TUNNEL_PROTOCOL_OBFUSCATED_SSH}

	providerID := prng.HexString(8)
	frontingProviderID := prng.HexString(8)

	var holdOffDirectTunnelProviderRegions parameters.KeyStrings
	if tunnelProtocol == protocol.TUNNEL_PROTOCOL_UNFRONTED_MEEK {
		holdOffDirectTunnelProviderRegions = map[string][]string{providerID: {""}}
	}

	var holdOffInproxyTunnelProviderRegions parameters.KeyStrings
	if protocol.TunnelProtocolUsesInproxy(tunnelProtocol) &&
		protocol.TunnelProtocolMinusInproxy(tunnelProtocol) == protocol.TUNNEL_PROTOCOL_OBFUSCATED_SSH {
		holdOffInproxyTunnelProviderRegions = map[string][]string{providerID: {""}}
	}

	applyParameters := make(map[string]interface{})
	applyParameters[parameters.TransformHostNameProbability] = 1.0
	applyParameters[parameters.PickUserAgentProbability] = 1.0
	applyParameters[parameters.HoldOffTunnelProtocolMinDuration] = "1ms"
	applyParameters[parameters.HoldOffTunnelProtocolMaxDuration] = "10ms"
	applyParameters[parameters.HoldOffTunnelProtocolNames] = holdOffTunnelProtocolNames
	applyParameters[parameters.HoldOffTunnelProtocolProbability] = 1.0
	applyParameters[parameters.HoldOffFrontingTunnelMinDuration] = "1ms"
	applyParameters[parameters.HoldOffFrontingTunnelMaxDuration] = "10ms"
	applyParameters[parameters.HoldOffFrontingTunnelProviderIDs] = []string{frontingProviderID}
	applyParameters[parameters.HoldOffFrontingTunnelProbability] = 1.0
	applyParameters[parameters.HoldOffDirectTunnelMinDuration] = "1ms"
	applyParameters[parameters.HoldOffDirectTunnelMaxDuration] = "10ms"
	applyParameters[parameters.HoldOffDirectTunnelProviderRegions] = holdOffDirectTunnelProviderRegions
	applyParameters[parameters.HoldOffInproxyTunnelProbability] = 1.0
	applyParameters[parameters.HoldOffInproxyTunnelMinDuration] = "1ms"
	applyParameters[parameters.HoldOffInproxyTunnelMaxDuration] = "10ms"
	applyParameters[parameters.HoldOffInproxyTunnelProviderRegions] = holdOffInproxyTunnelProviderRegions
	applyParameters[parameters.HoldOffDirectTunnelProbability] = 1.0
	applyParameters[parameters.DNSResolverAlternateServers] = []string{"127.0.0.1", "127.0.0.2", "127.0.0.3"}
	applyParameters[parameters.DirectHTTPProtocolTransformProbability] = 1.0
	applyParameters[parameters.DirectHTTPProtocolTransformSpecs] = transforms.Specs{"spec": transforms.Spec{{"", ""}}}
	applyParameters[parameters.DirectHTTPProtocolTransformScopedSpecNames] = transforms.ScopedSpecNames{"": {"spec"}}
	applyParameters[parameters.OSSHObfuscatorSeedTransformProbability] = 1.0
	applyParameters[parameters.OSSHObfuscatorSeedTransformSpecs] = transforms.Specs{"spec": transforms.Spec{{"", ""}}}
	applyParameters[parameters.OSSHObfuscatorSeedTransformScopedSpecNames] = transforms.ScopedSpecNames{"": {"spec"}}
	applyParameters[parameters.ObfuscatedQUICNonceTransformProbability] = 1.0
	applyParameters[parameters.ObfuscatedQUICNonceTransformSpecs] = transforms.Specs{"spec": transforms.Spec{{"", ""}}}
	applyParameters[parameters.ObfuscatedQUICNonceTransformScopedSpecNames] = transforms.ScopedSpecNames{"": {"spec"}}
	applyParameters[parameters.ShadowsocksPrefixProbability] = 1.0
	applyParameters[parameters.ShadowsocksPrefixSpecs] = transforms.Specs{"spec": transforms.Spec{{"", ""}}}
	applyParameters[parameters.ShadowsocksPrefixScopedSpecNames] = transforms.ScopedSpecNames{"": {"spec"}}

	err = clientConfig.SetParameters("tag1", false, applyParameters)
	if err != nil {
		t.Fatalf("SetParameters failed: %s", err)
	}

	resolver := NewResolver(clientConfig, true)
	defer resolver.Stop()
	clientConfig.SetResolver(resolver)

	err = OpenDataStore(clientConfig)
	if err != nil {
		t.Fatalf("error initializing client datastore: %s", err)
	}
	defer CloseDataStore()

	serverEntries := makeMockServerEntries(tunnelProtocol, "CA", providerID, frontingProviderID, 100)

	canReplay := func(serverEntry *protocol.ServerEntry, replayProtocol string) bool {
		return replayProtocol == tunnelProtocol
	}

	selectProtocol := func(serverEntry *protocol.ServerEntry) (string, bool) {
		return tunnelProtocol, true
	}

	values.SetSSHClientVersionsSpec(
		values.NewPickOneSpec([]string{"SSH-2.0-A", "SSH-2.0-B", "SSH-2.0-C"}))

	values.SetUserAgentsSpec(
		values.NewPickOneSpec([]string{"ua1", "ua2", "ua3"}))

	// Test: expected dial parameter fields set

	steeringIPCache := lrucache.NewWithLRU(1*time.Hour, 1*time.Hour, 0)

	upstreamProxyErrorCallback := func(_ error) {}

	dialParams, err := MakeDialParameters(
		clientConfig, steeringIPCache, nil, nil, upstreamProxyErrorCallback, canReplay, selectProtocol, serverEntries[0], nil, nil, false, 0, 0)
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

	if !dialParams.SelectedSSHClientVersion || dialParams.SSHClientVersion == "" || dialParams.SSHKEXSeed == nil {
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
			dialParams.MeekFrontingHost == "" ||
			dialParams.ResolveParameters == nil) {
		t.Fatalf("missing meek fronting fields")
	}

	if protocol.TunnelProtocolUsesMeekHTTP(tunnelProtocol) &&
		dialParams.UserAgent == "" {
		t.Fatalf("missing meek HTTP fields")
	}

	if protocol.TunnelProtocolUsesMeekHTTPS(tunnelProtocol) &&
		(dialParams.MeekSNIServerName == "" ||
			!dialParams.SelectedTLSProfile ||
			dialParams.TLSProfile == "") {
		t.Fatalf("missing meek HTTPS fields")
	}

	if protocol.TunnelProtocolUsesQUIC(tunnelProtocol) {
		if dialParams.QUICVersion == "" {
			t.Fatalf("missing QUIC version field")
		}
		if protocol.TunnelProtocolUsesFrontedMeekQUIC(tunnelProtocol) {
			if dialParams.MeekFrontingDialAddress == "" ||
				dialParams.MeekFrontingHost == "" ||
				dialParams.MeekSNIServerName == "" {
				t.Fatalf("missing fronted QUIC fields")
			}
		} else {
			if dialParams.QUICDialSNIAddress == "" {
				t.Fatalf("missing QUIC SNI field")
			}
		}
	}

	if dialParams.LivenessTestSeed == nil {
		t.Fatalf("missing liveness test fields")
	}

	if dialParams.APIRequestPaddingSeed == nil {
		t.Fatalf("missing API request fields")
	}

	expectHoldOffTunnelProtocolNames := common.Contains(holdOffTunnelProtocolNames, tunnelProtocol)
	expectHoldOffFrontingTunnelProviderIDs := protocol.TunnelProtocolUsesFrontedMeek(tunnelProtocol)
	expectHoldOffDirectTunnelProviderRegion := protocol.TunnelProtocolIsDirect(tunnelProtocol) &&
		common.ContainsAny(
			holdOffDirectTunnelProviderRegions[dialParams.ServerEntry.ProviderID],
			[]string{"", dialParams.ServerEntry.Region})
	expectHoldOffInproxyTunnelProviderRegion := protocol.TunnelProtocolUsesInproxy(tunnelProtocol) &&
		common.ContainsAny(
			holdOffInproxyTunnelProviderRegions[dialParams.ServerEntry.ProviderID],
			[]string{"", dialParams.ServerEntry.Region})

	if expectHoldOffTunnelProtocolNames ||
		expectHoldOffFrontingTunnelProviderIDs ||
		expectHoldOffDirectTunnelProviderRegion ||
		expectHoldOffInproxyTunnelProviderRegion {
		if dialParams.HoldOffTunnelDuration < 1*time.Millisecond ||
			dialParams.HoldOffTunnelDuration > 10*time.Millisecond {
			t.Fatalf("unexpected hold-off duration: %v", dialParams.HoldOffTunnelDuration)
		}
	} else {
		if dialParams.HoldOffTunnelDuration != 0 {
			t.Fatalf("unexpected hold-off duration: %v", dialParams.HoldOffTunnelDuration)
		}
	}

	dialConfig := dialParams.GetDialConfig()
	if dialConfig.UpstreamProxyErrorCallback == nil {
		t.Fatalf("missing upstreamProxyErrorCallback")
	}

	// Test: no replay after dial reported to fail

	dialErr := errors.TraceNew("dial error")

	dialParams.Failed(clientConfig, dialErr)

	dialParams, err = MakeDialParameters(
		clientConfig, steeringIPCache, nil, nil, nil, canReplay, selectProtocol, serverEntries[0], nil, nil, false, 0, 0)
	if err != nil {
		t.Fatalf("MakeDialParameters failed: %s", err)
	}

	if dialParams.IsReplay {
		t.Fatalf("unexpected replay")
	}

	if dialParams.ReplayIgnoredChange {
		t.Fatalf("unexpected replay ignored change")
	}

	// Test: no replay after network ID changes

	dialParams.Succeeded()

	testNetworkID = prng.HexString(8)
	clientConfig.networkIDGetter.FlushCache()

	dialParams, err = MakeDialParameters(
		clientConfig, steeringIPCache, nil, nil, nil, canReplay, selectProtocol, serverEntries[0], nil, nil, false, 0, 0)
	if err != nil {
		t.Fatalf("MakeDialParameters failed: %s", err)
	}

	if dialParams.NetworkID != testNetworkID {
		t.Fatalf("unexpected network ID")
	}

	if dialParams.IsReplay {
		t.Fatalf("unexpected replay")
	}

	if dialParams.ReplayIgnoredChange {
		t.Fatalf("unexpected replay ignored change")
	}
	// Test: replay after dial reported to succeed, and replay fields match previous dial parameters

	dialParams.Succeeded()

	replayDialParams, err := MakeDialParameters(
		clientConfig, steeringIPCache, nil, nil, nil, canReplay, selectProtocol, serverEntries[0], nil, nil, false, 0, 0)
	if err != nil {
		t.Fatalf("MakeDialParameters failed: %s", err)
	}

	if !replayDialParams.IsReplay {
		t.Fatalf("unexpected non-replay")
	}

	if replayDialParams.ReplayIgnoredChange {
		t.Fatalf("unexpected replay ignored change")
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
		return bytes.Equal(seed1[:], seed2[:])
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

	if (replayDialParams.ResolveParameters == nil) != (dialParams.ResolveParameters == nil) ||
		(replayDialParams.ResolveParameters != nil &&
			!reflect.DeepEqual(replayDialParams.ResolveParameters, dialParams.ResolveParameters)) {
		t.Fatalf("mismatching ResolveParameters fields")
	}

	if (replayDialParams.HTTPTransformerParameters == nil) != (dialParams.HTTPTransformerParameters == nil) ||
		(replayDialParams.HTTPTransformerParameters != nil &&
			!reflect.DeepEqual(replayDialParams.HTTPTransformerParameters, dialParams.HTTPTransformerParameters)) {
		t.Fatalf("mismatching HTTPTransformerParameters fields")
	}

	if (replayDialParams.OSSHObfuscatorSeedTransformerParameters == nil) != (dialParams.OSSHObfuscatorSeedTransformerParameters == nil) ||
		(replayDialParams.OSSHObfuscatorSeedTransformerParameters != nil &&
			!reflect.DeepEqual(replayDialParams.OSSHObfuscatorSeedTransformerParameters, dialParams.OSSHObfuscatorSeedTransformerParameters)) {
		t.Fatalf("mismatching ObfuscatorSeedTransformerParameters fields")
	}

	if (replayDialParams.ObfuscatedQUICNonceTransformerParameters == nil) != (dialParams.ObfuscatedQUICNonceTransformerParameters == nil) ||
		(replayDialParams.ObfuscatedQUICNonceTransformerParameters != nil &&
			!reflect.DeepEqual(replayDialParams.ObfuscatedQUICNonceTransformerParameters, dialParams.ObfuscatedQUICNonceTransformerParameters)) {
		t.Fatalf("mismatching ObfuscatedQUICNonceTransformerParameters fields")
	}

	if (replayDialParams.ShadowsocksPrefixSpec == nil) != (dialParams.ShadowsocksPrefixSpec == nil) ||
		(replayDialParams.ShadowsocksPrefixSpec != nil &&
			!reflect.DeepEqual(replayDialParams.ShadowsocksPrefixSpec, dialParams.ShadowsocksPrefixSpec)) {
		t.Fatalf("mismatching ShadowsocksPrefixSpec fields")
	}

	// Test: replay after change tactics, with ReplayIgnoreChangedConfigStateProbability = 1.0

	applyParameters[parameters.ReplayDialParametersTTL] = "1s"
	applyParameters[parameters.ReplayIgnoreChangedConfigStateProbability] = 1.0
	err = clientConfig.SetParameters("tag2a", false, applyParameters)
	if err != nil {
		t.Fatalf("SetParameters failed: %s", err)
	}

	dialParams, err = MakeDialParameters(
		clientConfig, steeringIPCache, nil, nil, nil, canReplay, selectProtocol, serverEntries[0], nil, nil, false, 0, 0)
	if err != nil {
		t.Fatalf("MakeDialParameters failed: %s", err)
	}

	if !dialParams.IsReplay {
		t.Fatalf("unexpected non-replay")
	}

	if !dialParams.ReplayIgnoredChange {
		t.Fatalf("unexpected replay ignored change")
	}

	// Test: no replay after change tactics

	applyParameters[parameters.ReplayDialParametersTTL] = "1s"
	applyParameters[parameters.ReplayIgnoreChangedConfigStateProbability] = 0.0
	err = clientConfig.SetParameters("tag2", false, applyParameters)
	if err != nil {
		t.Fatalf("SetParameters failed: %s", err)
	}

	dialParams, err = MakeDialParameters(
		clientConfig, steeringIPCache, nil, nil, nil, canReplay, selectProtocol, serverEntries[0], nil, nil, false, 0, 0)
	if err != nil {
		t.Fatalf("MakeDialParameters failed: %s", err)
	}

	if dialParams.IsReplay {
		t.Fatalf("unexpected replay")
	}

	if dialParams.ReplayIgnoredChange {
		t.Fatalf("unexpected replay ignored change")
	}

	// Test: no replay after dial parameters expired

	dialParams.Succeeded()

	time.Sleep(1 * time.Second)

	dialParams, err = MakeDialParameters(
		clientConfig, steeringIPCache, nil, nil, nil, canReplay, selectProtocol, serverEntries[0], nil, nil, false, 0, 0)
	if err != nil {
		t.Fatalf("MakeDialParameters failed: %s", err)
	}

	if dialParams.IsReplay {
		t.Fatalf("unexpected replay")
	}

	if dialParams.ReplayIgnoredChange {
		t.Fatalf("unexpected replay ignored change")
	}

	// Test: no replay after server entry changes

	dialParams.Succeeded()

	serverEntries[0].ConfigurationVersion += 1

	dialParams, err = MakeDialParameters(
		clientConfig, steeringIPCache, nil, nil, nil, canReplay, selectProtocol, serverEntries[0], nil, nil, false, 0, 0)
	if err != nil {
		t.Fatalf("MakeDialParameters failed: %s", err)
	}

	if dialParams.IsReplay {
		t.Fatalf("unexpected replay")
	}

	if dialParams.ReplayIgnoredChange {
		t.Fatalf("unexpected replay ignored change")
	}

	// Test: disable replay elements (partial coverage)

	applyParameters[parameters.ReplayDialParametersTTL] = "24h"
	applyParameters[parameters.ReplaySSH] = false
	applyParameters[parameters.ReplayObfuscatorPadding] = false
	applyParameters[parameters.ReplayFragmentor] = false
	applyParameters[parameters.ReplayObfuscatedQUIC] = false
	applyParameters[parameters.ReplayLivenessTest] = false
	applyParameters[parameters.ReplayAPIRequestPadding] = false
	err = clientConfig.SetParameters("tag3", false, applyParameters)
	if err != nil {
		t.Fatalf("SetParameters failed: %s", err)
	}

	dialParams, err = MakeDialParameters(
		clientConfig, steeringIPCache, nil, nil, nil, canReplay, selectProtocol, serverEntries[0], nil, nil, false, 0, 0)
	if err != nil {
		t.Fatalf("MakeDialParameters failed: %s", err)
	}

	dialParams.Succeeded()

	replayDialParams, err = MakeDialParameters(
		clientConfig, steeringIPCache, nil, nil, nil, canReplay, selectProtocol, serverEntries[0], nil, nil, false, 0, 0)
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
		(protocol.TunnelProtocolUsesQUIC(tunnelProtocol) &&
			identicalSeeds(replayDialParams.ObfuscatedQUICPaddingSeed, dialParams.ObfuscatedQUICPaddingSeed) &&
			replayDialParams.ObfuscatedQUICPaddingSeed != nil) ||
		identicalSeeds(replayDialParams.LivenessTestSeed, dialParams.LivenessTestSeed) ||
		identicalSeeds(replayDialParams.APIRequestPaddingSeed, dialParams.APIRequestPaddingSeed) {
		t.Fatalf("unexpected replayed fields")
	}

	// Test: client-side restrict fronting provider ID

	applyParameters[parameters.RestrictFrontingProviderIDs] = []string{frontingProviderID}
	applyParameters[parameters.RestrictFrontingProviderIDsClientProbability] = 1.0
	err = clientConfig.SetParameters("tag4", false, applyParameters)
	if err != nil {
		t.Fatalf("SetParameters failed: %s", err)
	}

	dialParams, err = MakeDialParameters(
		clientConfig, steeringIPCache, nil, nil, nil, canReplay, selectProtocol, serverEntries[0], nil, nil, false, 0, 0)

	if protocol.TunnelProtocolUsesFrontedMeek(tunnelProtocol) {
		if err == nil {
			if dialParams != nil {
				t.Fatalf("unexpected MakeDialParameters success")
			}
		}
	} else {
		if err != nil {
			t.Fatalf("MakeDialParameters failed: %s", err)
		}
	}

	applyParameters[parameters.RestrictFrontingProviderIDsClientProbability] = 0.0
	err = clientConfig.SetParameters("tag5", false, applyParameters)
	if err != nil {
		t.Fatalf("SetParameters failed: %s", err)
	}

	// Test: client-side restrict provider ID by region for direct protocols

	applyParameters[parameters.RestrictDirectProviderRegions] = map[string][]string{providerID: {"CA"}}
	applyParameters[parameters.RestrictDirectProviderIDsClientProbability] = 1.0
	err = clientConfig.SetParameters("tag6", false, applyParameters)
	if err != nil {
		t.Fatalf("SetParameters failed: %s", err)
	}

	dialParams, err = MakeDialParameters(
		clientConfig, steeringIPCache, nil, nil, nil, canReplay, selectProtocol, serverEntries[0], nil, nil, false, 0, 0)

	if protocol.TunnelProtocolIsDirect(tunnelProtocol) {
		if err == nil {
			if dialParams != nil {
				t.Fatalf("unexpected MakeDialParameters success")
			}
		}
	} else {
		if err != nil {
			t.Fatalf("MakeDialParameters failed: %s", err)
		}
	}

	applyParameters[parameters.RestrictDirectProviderRegions] = map[string][]string{}
	applyParameters[parameters.RestrictDirectProviderIDsClientProbability] = 0.0
	err = clientConfig.SetParameters("tag7", false, applyParameters)
	if err != nil {
		t.Fatalf("SetParameters failed: %s", err)
	}

	// Test: client-side restrict provider ID by region for inproxy protocols

	applyParameters[parameters.RestrictInproxyProviderRegions] = map[string][]string{providerID: {"CA"}}
	applyParameters[parameters.RestrictInproxyProviderIDsClientProbability] = 1.0
	err = clientConfig.SetParameters("tag8", false, applyParameters)
	if err != nil {
		t.Fatalf("SetParameters failed: %s", err)
	}

	dialParams, err = MakeDialParameters(
		clientConfig, steeringIPCache, nil, nil, nil, canReplay, selectProtocol, serverEntries[0], nil, nil, false, 0, 0)

	if protocol.TunnelProtocolUsesInproxy(tunnelProtocol) {
		if err == nil {
			if dialParams != nil {
				t.Fatalf("unexpected MakeDialParameters success")
			}
		}
	} else {
		if err != nil {
			t.Fatalf("MakeDialParameters failed: %s", err)
		}
	}

	applyParameters[parameters.RestrictInproxyProviderRegions] = map[string][]string{}
	applyParameters[parameters.RestrictInproxyProviderIDsClientProbability] = 0.0
	err = clientConfig.SetParameters("tag9", false, applyParameters)
	if err != nil {
		t.Fatalf("SetParameters failed: %s", err)
	}

	if protocol.TunnelProtocolUsesFrontedMeek(tunnelProtocol) {

		steeringIPCache.Flush()

		// Test: steering IP used in non-replay case

		dialParams, err = MakeDialParameters(
			clientConfig, steeringIPCache, nil, nil, nil, canReplay, selectProtocol, serverEntries[0], nil, nil, false, 0, 0)
		if err != nil {
			t.Fatalf("MakeDialParameters failed: %s", err)
		}

		dialParams.Failed(clientConfig, dialErr)

		getCacheKey := func() string {
			return fmt.Sprintf("%s %s %s", testNetworkID, frontingProviderID, tunnelProtocol)
		}

		setCacheEntry := func(steeringIP string) {
			steeringIPCache.Set(getCacheKey(), steeringIP, lrucache.DefaultExpiration)
		}

		setCacheEntry("127.0.0.1")

		dialParams, err = MakeDialParameters(
			clientConfig, steeringIPCache, nil, nil, nil, canReplay, selectProtocol, serverEntries[0], nil, nil, false, 0, 0)
		if err != nil {
			t.Fatalf("MakeDialParameters failed: %s", err)
		}

		if dialParams.IsReplay {
			t.Fatalf("unexpected replay")
		}

		checkSteeringIP := func(expectedSteeringIP string) {
			ctx, cancelFunc := context.WithTimeout(context.Background(), 1*time.Microsecond)
			defer cancelFunc()
			IPs, err := dialParams.dialConfig.ResolveIP(ctx, "example.com")
			if err != nil {
				t.Fatalf("ResolveIP failed: %s", err)
			}
			if IPs[0].String() != expectedSteeringIP {
				t.Fatalf("missing expected steering IP")
			}
		}

		checkSteeringIP("127.0.0.1")

		// Test: steering IP used in replay case

		dialParams.Succeeded()

		dialParams, err = MakeDialParameters(
			clientConfig, steeringIPCache, nil, nil, nil, canReplay, selectProtocol, serverEntries[0], nil, nil, false, 0, 0)
		if err != nil {
			t.Fatalf("MakeDialParameters failed: %s", err)
		}

		if !dialParams.IsReplay {
			t.Fatalf("unexpected non-replay")
		}

		checkSteeringIP("127.0.0.1")

		// Test: different steering IP clears replay flag

		dialParams.Succeeded()

		setCacheEntry("127.0.0.2")

		dialParams, err = MakeDialParameters(
			clientConfig, steeringIPCache, nil, nil, nil, canReplay, selectProtocol, serverEntries[0], nil, nil, false, 0, 0)
		if err != nil {
			t.Fatalf("MakeDialParameters failed: %s", err)
		}

		if dialParams.IsReplay {
			t.Fatalf("unexpected replay")
		}

		checkSteeringIP("127.0.0.2")

		// Test: newly present steering IP clears replay flag

		steeringIPCache.Flush()

		dialParams, err = MakeDialParameters(
			clientConfig, steeringIPCache, nil, nil, nil, canReplay, selectProtocol, serverEntries[0], nil, nil, false, 0, 0)
		if err != nil {
			t.Fatalf("MakeDialParameters failed: %s", err)
		}

		dialParams.Succeeded()

		setCacheEntry("127.0.0.3")

		dialParams, err = MakeDialParameters(
			clientConfig, steeringIPCache, nil, nil, nil, canReplay, selectProtocol, serverEntries[0], nil, nil, false, 0, 0)
		if err != nil {
			t.Fatalf("MakeDialParameters failed: %s", err)
		}

		if dialParams.IsReplay {
			t.Fatalf("unexpected replay")
		}

		// Test: steering IP cleared from cache after failure

		dialParams.Failed(clientConfig, dialErr)

		_, ok := steeringIPCache.Get(getCacheKey())
		if ok {
			t.Fatalf("unexpected steering IP cache entry")
		}
	}

	// Test: DSLPendingPrioritizeDial placeholder transformed to full dial parameters

	networkID := clientConfig.GetNetworkID()

	err = datastoreUpdate(func(tx *datastoreTx) error {
		return dslPrioritizeDialServerEntry(
			tx, networkID, []byte(serverEntries[1].IpAddress))
	})
	if err != nil {
		t.Fatalf("dslPrioritizeDialServerEntry failed: %s", err)
	}

	dialParams, err = MakeDialParameters(
		clientConfig, steeringIPCache, nil, nil, nil, canReplay, selectProtocol, serverEntries[1], nil, nil, false, 0, 0)
	if err != nil {
		t.Fatalf("MakeDialParameters failed: %s", err)
	}

	if dialParams.DSLPendingPrioritizeDial || !dialParams.DSLPrioritizedDial {
		t.Fatalf("unexpected DSL prioritize state")
	}

	if dialParams.IsReplay {
		t.Fatalf("unexpected replay")
	}

	dialParams.Succeeded()

	dialParams, err = MakeDialParameters(
		clientConfig, steeringIPCache, nil, nil, nil, canReplay, selectProtocol, serverEntries[1], nil, nil, false, 0, 0)
	if err != nil {
		t.Fatalf("MakeDialParameters failed: %s", err)
	}

	if dialParams.DSLPendingPrioritizeDial || !dialParams.DSLPrioritizedDial {
		t.Fatalf("unexpected DSL prioritize state")
	}

	if !dialParams.IsReplay {
		t.Fatalf("unexpected non-replay")
	}

	// Test: DSLPendingPrioritizeDial placeholder doesn't replace full dial parameters

	err = datastoreUpdate(func(tx *datastoreTx) error {
		return dslPrioritizeDialServerEntry(
			tx, networkID, []byte(serverEntries[1].IpAddress))
	})
	if err != nil {
		t.Fatalf("dslPrioritizeDialServerEntry failed: %s", err)
	}

	dialParams, err = MakeDialParameters(
		clientConfig, steeringIPCache, nil, nil, nil, canReplay, selectProtocol, serverEntries[1], nil, nil, false, 0, 0)
	if err != nil {
		t.Fatalf("MakeDialParameters failed: %s", err)
	}

	if dialParams.DSLPendingPrioritizeDial || !dialParams.DSLPrioritizedDial {
		t.Fatalf("unexpected DSL prioritize state")
	}

	if !dialParams.IsReplay {
		t.Fatalf("unexpected non-replay")
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

			dialParams, err := MakeDialParameters(
				clientConfig, steeringIPCache, nil, nil, nil, canReplay, selectProtocol, serverEntry, nil, nil, false, 0, 0)
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

			dialParams, err := MakeDialParameters(
				clientConfig, steeringIPCache, nil, nil, nil, canReplay, selectProtocol, serverEntry, nil, nil, false, 0, 0)
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

			dialParams, err := MakeDialParameters(
				clientConfig, steeringIPCache, nil, nil, nil, canReplay, selectProtocol, serverEntry, nil, nil, false, 0, 0)
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

func TestLimitTunnelDialPortNumbers(t *testing.T) {

	testDataDirName, err := ioutil.TempDir("", "psiphon-limit-tunnel-dial-port-numbers-test")
	if err != nil {
		t.Fatalf("TempDir failed: %s", err)
	}
	defer os.RemoveAll(testDataDirName)

	err = SetNoticeWriter(io.Discard)
	if err != nil {
		t.Fatalf("error setting notice writer: %s", err)
	}
	defer ResetNoticeWriter()

	clientConfig := &Config{
		PropagationChannelId: "0",
		SponsorId:            "0",
		DataRootDirectory:    testDataDirName,
		NetworkIDGetter:      new(testNetworkGetter),
	}

	err = clientConfig.Commit(false)
	if err != nil {
		t.Fatalf("error committing configuration file: %s", err)
	}

	jsonLimitDialPortNumbers := `
    {
        "SSH" : [[10,11]],
        "OSSH" : [[20,21]],
        "QUIC-OSSH" : [[30,31]],
        "TAPDANCE-OSSH" : [[40,41]],
        "CONJURE-OSSH" : [[50,51]],
        "SHADOWSOCKS-OSSH" : [[60,61]],
        "All" : [[70,71],80,443]
    }
    `

	var limitTunnelDialPortNumbers parameters.TunnelProtocolPortLists
	err = json.Unmarshal([]byte(jsonLimitDialPortNumbers), &limitTunnelDialPortNumbers)
	if err != nil {
		t.Fatalf("Unmarshal failed: %s", err)
	}

	applyParameters := make(map[string]interface{})
	applyParameters[parameters.LimitTunnelDialPortNumbers] = limitTunnelDialPortNumbers
	applyParameters[parameters.LimitTunnelDialPortNumbersProbability] = 1.0
	err = clientConfig.SetParameters("tag1", false, applyParameters)
	if err != nil {
		t.Fatalf("SetParameters failed: %s", err)
	}

	constraints := &protocolSelectionConstraints{
		config: clientConfig,
		limitTunnelDialPortNumbers: protocol.TunnelProtocolPortLists(
			clientConfig.GetParameters().Get().TunnelProtocolPortLists(parameters.LimitTunnelDialPortNumbers)),
	}

	selectProtocol := func(serverEntry *protocol.ServerEntry) (string, bool) {
		protocol, _, ok := constraints.selectProtocol(0, false, false, serverEntry)
		return protocol, ok
	}

	for _, tunnelProtocol := range protocol.SupportedTunnelProtocols {

		if common.Contains(protocol.DefaultDisabledTunnelProtocols, tunnelProtocol) {
			continue
		}

		serverEntries := makeMockServerEntries(tunnelProtocol, "", "", "", 100)

		selected := false
		skipped := false

		for _, serverEntry := range serverEntries {

			selectedProtocol, ok := selectProtocol(serverEntry)

			if ok {

				if selectedProtocol != tunnelProtocol {
					t.Fatalf("unexpected selected protocol: %s", selectedProtocol)
				}

				port, err := serverEntry.GetDialPortNumber(selectedProtocol)
				if err != nil {
					t.Fatalf("GetDialPortNumber failed: %s", err)
				}

				if port%10 != 0 && port%10 != 1 && !protocol.TunnelProtocolUsesFrontedMeek(selectedProtocol) {
					t.Fatalf("unexpected dial port number: %d", port)
				}

				selected = true

			} else {

				skipped = true
			}
		}

		if !selected {
			t.Fatalf("expected at least one selected server entry: %s", tunnelProtocol)
		}

		if !skipped && !protocol.TunnelProtocolUsesFrontedMeek(tunnelProtocol) {
			t.Fatalf("expected at least one skipped server entry: %s", tunnelProtocol)
		}
	}
}

func makeMockServerEntries(
	tunnelProtocol string,
	region string,
	providerID string,
	frontingProviderID string,
	count int) []*protocol.ServerEntry {

	serverEntries := make([]*protocol.ServerEntry, count)

	for i := 0; i < count; i++ {
		serverEntries[i] = &protocol.ServerEntry{
			IpAddress:                  fmt.Sprintf("192.168.0.%d", i),
			SshPort:                    prng.Range(10, 19),
			SshObfuscatedPort:          prng.Range(20, 29),
			SshObfuscatedQUICPort:      prng.Range(30, 39),
			SshObfuscatedTapDancePort:  prng.Range(40, 49),
			SshObfuscatedConjurePort:   prng.Range(50, 59),
			SshShadowsocksPort:         prng.Range(60, 69),
			MeekServerPort:             prng.Range(70, 79),
			MeekFrontingHosts:          []string{"www1.example.org", "www2.example.org", "www3.example.org"},
			MeekFrontingAddressesRegex: "[a-z0-9]{1,64}.example.org",
			Region:                     region,
			ProviderID:                 providerID,
			FrontingProviderID:         frontingProviderID,
			LocalSource:                protocol.SERVER_ENTRY_SOURCE_EMBEDDED,
			LocalTimestamp:             common.TruncateTimestampToHour(common.GetCurrentTimestamp()),
			Capabilities:               []string{protocol.GetCapability(tunnelProtocol)},
		}
	}

	return serverEntries
}

func TestMakeHTTPTransformerParameters(t *testing.T) {

	type test struct {
		name                  string
		frontingProviderID    string
		isFronted             bool
		paramValues           map[string]interface{}
		expectedTransformName string
		expectedTransformSpec transforms.Spec
	}

	tests := []test{
		{
			name:               "unfronted",
			frontingProviderID: "",
			isFronted:          false,
			paramValues: map[string]interface{}{
				"DirectHTTPProtocolTransformProbability": 1,
				"DirectHTTPProtocolTransformSpecs": transforms.Specs{
					"spec1": {{"A", "B"}},
				},
				"DirectHTTPProtocolTransformScopedSpecNames": transforms.ScopedSpecNames{
					"": {"spec1"},
				},
			},
			expectedTransformName: "spec1",
			expectedTransformSpec: [][2]string{{"A", "B"}},
		},
		{
			name:               "fronted",
			frontingProviderID: "frontingProvider",
			isFronted:          true,
			paramValues: map[string]interface{}{
				"FrontedHTTPProtocolTransformProbability": 1,
				"FrontedHTTPProtocolTransformSpecs": transforms.Specs{
					"spec1": {{"A", "B"}},
				},
				"FrontedHTTPProtocolTransformScopedSpecNames": transforms.ScopedSpecNames{
					"frontingProvider": {"spec1"},
				},
			},
			expectedTransformName: "spec1",
			expectedTransformSpec: [][2]string{{"A", "B"}},
		},
		{
			name:               "no transform, coinflip false",
			frontingProviderID: "frontingProvider",
			isFronted:          false,
			paramValues: map[string]interface{}{
				"DirectHTTPProtocolTransformProbability": 0,
				"DirectHTTPProtocolTransformSpecs": transforms.Specs{
					"spec1": {{"A", "B"}},
				},
				"DirectHTTPProtocolTransformScopedSpecNames": transforms.ScopedSpecNames{
					"frontingProvider": {"spec1"},
				},
			},
			expectedTransformName: "",
			expectedTransformSpec: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			params, err := parameters.NewParameters(nil)
			if err != nil {
				t.Fatalf("parameters.NewParameters failed %v", err)
			}

			_, err = params.Set("", 0, tt.paramValues)
			if err != nil {
				t.Fatalf("params.Set failed %v", err)
			}

			httpTransformerParams, err := makeHTTPTransformerParameters(params.Get(), tt.frontingProviderID, tt.isFronted)
			if err != nil {
				t.Fatalf("MakeHTTPTransformerParameters failed %v", err)
			}
			if httpTransformerParams.ProtocolTransformName != tt.expectedTransformName {
				t.Fatalf("expected ProtocolTransformName \"%s\" but got \"%s\"", tt.expectedTransformName, httpTransformerParams.ProtocolTransformName)
			}
			if !reflect.DeepEqual(httpTransformerParams.ProtocolTransformSpec, tt.expectedTransformSpec) {
				t.Fatalf("expected ProtocolTransformSpec %v but got %v", tt.expectedTransformSpec, httpTransformerParams.ProtocolTransformSpec)
			}
			if httpTransformerParams.ProtocolTransformSpec != nil {
				if httpTransformerParams.ProtocolTransformSeed == nil {
					t.Fatalf("expected non-nil seed")
				}
			}
		})
	}
}

func TestMakeOSSHObfuscatorSeedTranformerParameters(t *testing.T) {

	type test struct {
		name                  string
		paramValues           map[string]interface{}
		expectedTransformName string
		expectedTransformSpec transforms.Spec
	}

	tests := []test{
		{
			name: "transform",
			paramValues: map[string]interface{}{
				"OSSHObfuscatorSeedTransformProbability": 1,
				"OSSHObfuscatorSeedTransformSpecs": transforms.Specs{
					"spec1": {{"A", "B"}},
				},
				"OSSHObfuscatorSeedTransformScopedSpecNames": transforms.ScopedSpecNames{
					"": {"spec1"},
				},
			},
			expectedTransformName: "spec1",
			expectedTransformSpec: [][2]string{{"A", "B"}},
		},
		{
			name: "no transform, coinflip false",
			paramValues: map[string]interface{}{
				"OSSHObfuscatorSeedTransformProbability": 0,
				"OSSHObfuscatorSeedTransformSpecs": transforms.Specs{
					"spec1": {{"A", "B"}},
				},
				"OSSHObfuscatorSeedTransformScopedSpecNames": transforms.ScopedSpecNames{
					"": {"spec1"},
				},
			},
			expectedTransformName: "",
			expectedTransformSpec: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			params, err := parameters.NewParameters(nil)
			if err != nil {
				t.Fatalf("parameters.NewParameters failed: %v", err)
			}

			_, err = params.Set("", 0, tt.paramValues)
			if err != nil {
				t.Fatalf("params.Set failed: %v", err)
			}

			transformerParams, err := makeSeedTransformerParameters(
				params.Get(),
				parameters.OSSHObfuscatorSeedTransformProbability,
				parameters.OSSHObfuscatorSeedTransformSpecs,
				parameters.OSSHObfuscatorSeedTransformScopedSpecNames)

			if err != nil {
				t.Fatalf("makeSeedTransformerParameters failed: %v", err)
			}
			if transformerParams.TransformName != tt.expectedTransformName {
				t.Fatalf("expected TransformName \"%s\" but got \"%s\"", tt.expectedTransformName, transformerParams.TransformName)
			}
			if !reflect.DeepEqual(transformerParams.TransformSpec, tt.expectedTransformSpec) {
				t.Fatalf("expected TransformSpec %v but got %v", tt.expectedTransformSpec, transformerParams.TransformSpec)
			}
			if transformerParams.TransformSpec != nil {
				if transformerParams.TransformSeed == nil {
					t.Fatalf("expected non-nil seed")
				}
			}

		})
	}

}
