/*
 * Copyright (c) 2023, Psiphon Inc.
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
	stderrors "errors"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/dsl"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/inproxy"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/resolver"
	utls "github.com/Psiphon-Labs/utls"
	"github.com/stretchr/testify/assert"
)

// TestInproxyComponents runs the broker dial parameter, STUN dial parameter
// and NAT state unit tests that predate broker transport racing.
func TestInproxyComponents(t *testing.T) {

	// This is a unit test of the in-proxy components internals, such as
	// replay; actual in-proxy broker round trips are exercised in the
	// psiphon/server end-to-end tests.

	err := runInproxyBrokerDialParametersTest(t)
	if err != nil {
		t.Fatal(errors.Trace(err).Error())
	}

	err = runInproxySTUNDialParametersTest()
	if err != nil {
		t.Fatal(errors.Trace(err).Error())
	}

	err = runInproxyNATStateTest()
	if err != nil {
		t.Fatal(errors.Trace(err).Error())
	}

	// TODO: test inproxyUDPConn multiplexed IPv6Synthesizer
}

func runInproxyBrokerDialParametersTest(t *testing.T) error {

	testDataDirName, err := ioutil.TempDir("", "psiphon-inproxy-broker-test")
	if err != nil {
		return errors.Trace(err)
	}
	defer os.RemoveAll(testDataDirName)

	isProxy := false
	propagationChannelID := prng.HexString(8)
	sponsorID := prng.HexString(8)
	networkID := "NETWORK1"
	addressRegex := `[a-z0-9]{5,10}\.example\.org`
	commonCompartmentID, _ := inproxy.MakeID()
	commonCompartmentIDs := []string{commonCompartmentID.String()}
	personalCompartmentID, _ := inproxy.MakeID()
	privateKey, _ := inproxy.GenerateSessionPrivateKey()
	publicKey, _ := privateKey.GetPublicKey()
	obfuscationSecret, _ := inproxy.GenerateRootObfuscationSecret()
	brokerSpecs := []*parameters.InproxyBrokerSpec{
		{
			BrokerPublicKey:             publicKey.String(),
			BrokerRootObfuscationSecret: obfuscationSecret.String(),
			BrokerFrontingSpecs: []*parameters.FrontingSpec{
				{
					FrontingProviderID: prng.HexString(8),
					Addresses:          []string{addressRegex},
					VerifyServerName:   "example.org",
					Host:               "example.org",
				},
			},
		},
	}
	retainFailed := float64(0.0)

	config := &Config{
		DataRootDirectory:    testDataDirName,
		PropagationChannelId: propagationChannelID,
		SponsorId:            sponsorID,
		NetworkID:            networkID,
	}
	err = config.Commit(false)
	if err != nil {
		return errors.Trace(err)
	}

	err = OpenDataStore(config)
	if err != nil {
		return errors.Trace(err)
	}
	defer CloseDataStore()

	tlsCache := utls.NewLRUClientSessionCache(0)

	manager := NewInproxyBrokerClientManager(config, isProxy, tlsCache)

	// Test: no broker specs

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, _, _, err = manager.GetBrokerClient(ctx, networkID)
	if err == nil {
		return errors.TraceNew("unexpected success")
	}

	// Test: select broker and common compartment IDs

	config = &Config{
		DataRootDirectory:           testDataDirName,
		PropagationChannelId:        propagationChannelID,
		SponsorId:                   sponsorID,
		NetworkID:                   networkID,
		InproxyBrokerSpecs:          brokerSpecs,
		InproxyCommonCompartmentIDs: commonCompartmentIDs,
		InproxyReplayBrokerRetainFailedProbability: &retainFailed,
	}
	err = config.Commit(false)
	if err != nil {
		return errors.Trace(err)
	}
	config.SetResolver(resolver.NewResolver(&resolver.NetworkConfig{}, networkID))

	manager = NewInproxyBrokerClientManager(config, isProxy, tlsCache)

	brokerClient, brokerDialParams, release, err := manager.GetBrokerClient(context.Background(), networkID)
	if err != nil {
		return errors.Trace(err)
	}

	if !regexp.MustCompile(addressRegex).Copy().Match(
		[]byte(brokerDialParams.FrontedHTTPDialParameters.meekConfig.DialAddress)) {
		return errors.TraceNew("unexpected FrontingDialAddress")
	}

	if len(brokerClient.GetBrokerDialCoordinator().CommonCompartmentIDs()) != 1 ||
		brokerClient.GetBrokerDialCoordinator().CommonCompartmentIDs()[0].String() !=
			commonCompartmentID.String() {
		return errors.TraceNew("unexpected compartment IDs")
	}

	_ = brokerDialParams.GetMetrics()

	// Test: replay on success

	prevBrokerDialParams := brokerDialParams

	previousFrontingDialAddress := brokerDialParams.FrontedHTTPDialParameters.meekConfig.DialAddress
	previousTLSProfile := brokerDialParams.FrontedHTTPDialParameters.meekConfig.TLSProfile

	roundTripper, err := brokerClient.GetBrokerDialCoordinator().BrokerClientRoundTripper()
	if err != nil {
		return errors.Trace(err)
	}

	brokerClient.GetBrokerDialCoordinator().BrokerClientRoundTripperSucceeded(roundTripper)

	manager = NewInproxyBrokerClientManager(config, isProxy, tlsCache)

	release()
	brokerClient, brokerDialParams, release, err = manager.GetBrokerClient(context.Background(), networkID)
	if err != nil {
		return errors.Trace(err)
	}

	if !brokerDialParams.isReplay {
		return errors.TraceNew("unexpected non-replay")
	}

	// All exported fields should be replayed
	assert.EqualExportedValues(t, brokerDialParams, prevBrokerDialParams)

	_ = brokerDialParams.GetMetrics()

	// Test: manager's broker client and dial parameters reinitialized after
	// network ID change

	previousBrokerClient := brokerClient
	previousNetworkID := networkID
	networkID = "NETWORK2"
	config.networkIDGetter = newCachingNetworkIDGetter(config, newStaticNetworkIDGetter(networkID))
	config.SetResolver(resolver.NewResolver(&resolver.NetworkConfig{}, networkID))

	release()
	brokerClient, brokerDialParams, release, err = manager.GetBrokerClient(context.Background(), networkID)
	if err != nil {
		return errors.Trace(err)
	}

	if brokerClient == previousBrokerClient {
		return errors.TraceNew("unexpected brokerClient")
	}

	if brokerDialParams.isReplay {
		return errors.TraceNew("unexpected replay")
	}

	if brokerDialParams.FrontedHTTPDialParameters.meekConfig.DialAddress == previousFrontingDialAddress {
		return errors.TraceNew("unexpected non-replayed FrontingDialAddress")
	}

	_ = brokerDialParams.GetMetrics()

	// Test: another replay after switch back to previous network ID

	networkID = previousNetworkID
	config.networkIDGetter = newCachingNetworkIDGetter(config, newStaticNetworkIDGetter(networkID))

	release()
	brokerClient, brokerDialParams, release, err = manager.GetBrokerClient(context.Background(), networkID)
	if err != nil {
		return errors.Trace(err)
	}

	if !brokerDialParams.isReplay {
		return errors.TraceNew("unexpected non-replay")
	}

	if brokerDialParams.FrontedHTTPDialParameters.meekConfig.DialAddress != previousFrontingDialAddress {
		return errors.TraceNew("unexpected replayed FrontingDialAddress")
	}

	if brokerDialParams.FrontedHTTPDialParameters.meekConfig.TLSProfile != previousTLSProfile {
		return errors.TraceNew("unexpected replayed TLSProfile")
	}

	_ = brokerDialParams.GetMetrics()

	// Test: clear replay

	roundTripper, err = brokerClient.GetBrokerDialCoordinator().BrokerClientRoundTripper()
	if err != nil {
		return errors.Trace(err)
	}

	brokerClient.GetBrokerDialCoordinator().BrokerClientRoundTripperFailed(roundTripper)

	manager = NewInproxyBrokerClientManager(config, isProxy, tlsCache)

	release()
	brokerClient, brokerDialParams, release, err = manager.GetBrokerClient(context.Background(), networkID)
	if err != nil {
		return errors.Trace(err)
	}

	if brokerDialParams.isReplay {
		return errors.TraceNew("unexpected replay")
	}

	if brokerDialParams.FrontedHTTPDialParameters.meekConfig.DialAddress == previousFrontingDialAddress {
		return errors.TraceNew("unexpected non-replayed FrontingDialAddress")
	}

	_ = brokerDialParams.GetMetrics()

	// Test: no common compartment IDs sent when personal ID is set

	config.InproxyClientPersonalCompartmentID = personalCompartmentID.String()
	config.InproxyProxyPersonalCompartmentID = personalCompartmentID.String()

	manager = NewInproxyBrokerClientManager(config, isProxy, tlsCache)

	release()
	brokerClient, brokerDialParams, release, err = manager.GetBrokerClient(context.Background(), networkID)
	if err != nil {
		return errors.Trace(err)
	}

	if len(brokerClient.GetBrokerDialCoordinator().CommonCompartmentIDs()) != 0 ||
		len(brokerClient.GetBrokerDialCoordinator().PersonalCompartmentIDs()) != 1 ||
		brokerClient.GetBrokerDialCoordinator().PersonalCompartmentIDs()[0].String() !=
			personalCompartmentID.String() {
		return errors.TraceNew("unexpected compartment IDs")
	}

	// Test: use persisted common compartment IDs

	config = &Config{
		PropagationChannelId: propagationChannelID,
		SponsorId:            sponsorID,
		NetworkID:            networkID,
	}
	config.InproxyBrokerSpecs = brokerSpecs
	config.InproxyCommonCompartmentIDs = nil
	err = config.Commit(false)
	if err != nil {
		return errors.Trace(err)
	}
	config.SetResolver(resolver.NewResolver(&resolver.NetworkConfig{}, networkID))

	manager = NewInproxyBrokerClientManager(config, isProxy, tlsCache)

	release()
	brokerClient, brokerDialParams, release, err = manager.GetBrokerClient(context.Background(), networkID)
	if err != nil {
		return errors.Trace(err)
	}

	if len(brokerClient.GetBrokerDialCoordinator().CommonCompartmentIDs()) != 1 ||
		brokerClient.GetBrokerDialCoordinator().CommonCompartmentIDs()[0].String() !=
			commonCompartmentID.String() {
		return errors.TraceNew("unexpected compartment IDs")
	}

	_ = brokerDialParams.GetMetrics()

	return nil
}

func runInproxySTUNDialParametersTest() error {

	testDataDirName, err := ioutil.TempDir("", "psiphon-inproxy-stun-test")
	if err != nil {
		return errors.Trace(err)
	}
	defer os.RemoveAll(testDataDirName)

	propagationChannelID := prng.HexString(8)
	sponsorID := prng.HexString(8)
	networkID := "NETWORK1"
	stunServerAddresses := []string{"example.org"}

	config := &Config{
		DataRootDirectory:                 testDataDirName,
		PropagationChannelId:              propagationChannelID,
		SponsorId:                         sponsorID,
		NetworkID:                         networkID,
		InproxySTUNServerAddresses:        stunServerAddresses,
		InproxySTUNServerAddressesRFC5780: stunServerAddresses,
	}
	err = config.Commit(false)
	if err != nil {
		return errors.Trace(err)
	}
	config.SetResolver(resolver.NewResolver(&resolver.NetworkConfig{}, networkID))

	p := config.GetParameters().Get()
	defer p.Close()

	dialParams, err := MakeInproxySTUNDialParameters(config, p, false)
	if err != nil {
		return errors.Trace(err)
	}

	_ = dialParams.GetMetrics()

	dialParamsJSON, err := json.Marshal(dialParams)
	if err != nil {
		return errors.Trace(err)
	}

	var replayDialParams *InproxySTUNDialParameters
	err = json.Unmarshal(dialParamsJSON, &replayDialParams)
	if err != nil {
		return errors.Trace(err)
	}

	replayDialParams.Prepare()

	_ = replayDialParams.GetMetrics()

	if !replayDialParams.IsValidClientReplay(p) {
		return errors.TraceNew("unexpected invalid replay STUN dial parameters")
	}

	replayDialParams.STUNServerAddress = "invalid.example.org"
	if replayDialParams.IsValidClientReplay(p) {
		return errors.TraceNew("unexpected valid replay STUN server address")
	}

	replayDialParams.STUNServerAddress = stunServerAddresses[0]
	replayDialParams.STUNServerAddressRFC5780 = "invalid-rfc5780.example.org"
	if replayDialParams.IsValidClientReplay(p) {
		return errors.TraceNew("unexpected valid replay RFC5780 STUN server address")
	}

	clientSTUNServerAddresses := []string{"client.example.org"}
	clientSTUNServerAddressesRFC5780 := []string{"client-rfc5780.example.org"}
	applyParameters := map[string]interface{}{
		parameters.InproxyClientSTUNServerAddresses:        clientSTUNServerAddresses,
		parameters.InproxyClientSTUNServerAddressesRFC5780: clientSTUNServerAddressesRFC5780,
	}
	err = config.SetParameters("", false, applyParameters)
	if err != nil {
		return errors.Trace(err)
	}

	p = config.GetParameters().Get()
	defer p.Close()

	replayDialParams.STUNServerAddress = clientSTUNServerAddresses[0]
	replayDialParams.STUNServerAddressRFC5780 = clientSTUNServerAddressesRFC5780[0]
	if !replayDialParams.IsValidClientReplay(p) {
		return errors.TraceNew("unexpected invalid client-specific replay STUN dial parameters")
	}

	replayDialParams.STUNServerAddress = stunServerAddresses[0]
	if replayDialParams.IsValidClientReplay(p) {
		return errors.TraceNew("unexpected valid global replay STUN server address when client list is set")
	}

	checkSTUNFlags := func(wantProxy, wantClient bool) error {
		for _, isProxy := range []bool{false, true} {
			instance, err := NewInproxyWebRTCDialInstance(
				config, networkID, isProxy, nil, dialParams, &InproxyWebRTCDialParameters{})
			if err != nil {
				return errors.Trace(err)
			}
			want := wantClient
			if isProxy {
				want = wantProxy
			}
			if instance.DisableSTUNCandidateGathering() != want || instance.DisableSTUN() {
				return errors.Tracef("unexpected STUN flags for proxy=%t", isProxy)
			}
		}
		return nil
	}

	for _, test := range []struct {
		global, proxy, client, wantProxy, wantClient bool
	}{
		{false, false, false, false, false},
		{false, true, false, true, false},
		{false, false, true, false, true},
		{false, true, true, true, true},
		{true, false, false, true, true},
	} {
		config.InproxyDisableSTUNCandidateGathering = &test.global
		config.InproxyProxyDisableSTUNCandidateGathering = &test.proxy
		config.InproxyClientDisableSTUNCandidateGathering = &test.client
		err = config.SetParameters("", false, nil)
		if err != nil {
			return errors.Trace(err)
		}
		err = checkSTUNFlags(test.wantProxy, test.wantClient)
		if err != nil {
			return errors.Trace(err)
		}
	}

	err = config.SetParameters("", false, map[string]interface{}{
		parameters.InproxyDisableSTUNCandidateGathering:       false,
		parameters.InproxyProxyDisableSTUNCandidateGathering:  true,
		parameters.InproxyClientDisableSTUNCandidateGathering: false,
	})
	if err != nil {
		return errors.Trace(err)
	}
	err = checkSTUNFlags(true, false)
	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

func runInproxyNATStateTest() error {

	propagationChannelID := prng.HexString(8)
	sponsorID := prng.HexString(8)
	networkID := "NETWORK1"

	config := &Config{
		PropagationChannelId: propagationChannelID,
		SponsorId:            sponsorID,
		NetworkID:            networkID,
	}
	err := config.Commit(false)
	if err != nil {
		return errors.Trace(err)
	}

	manager := NewInproxyNATStateManager(config)

	// Test: set values stored and cached

	manager.setNATType(networkID, inproxy.NATTypeSymmetric)
	manager.setPortMappingTypes(networkID, inproxy.PortMappingTypes{inproxy.PortMappingTypeUPnP})

	if manager.getNATType(networkID) != inproxy.NATTypeSymmetric {
		return errors.TraceNew("unexpected NAT type")
	}

	portMappingTypes := manager.getPortMappingTypes(networkID)
	if len(portMappingTypes) != 1 || portMappingTypes[0] != inproxy.PortMappingTypeUPnP {
		return errors.TraceNew("unexpected port mapping types")
	}

	// Test: set values ignored when network ID is changing

	otherNetworkID := "NETWORK2"

	manager.setNATType(otherNetworkID, inproxy.NATTypePortRestrictedCone)
	manager.setPortMappingTypes(otherNetworkID, inproxy.PortMappingTypes{inproxy.PortMappingTypePMP})

	if manager.getNATType(networkID) != inproxy.NATTypeSymmetric {
		return errors.TraceNew("unexpected NAT type")
	}

	portMappingTypes = manager.getPortMappingTypes(networkID)
	if len(portMappingTypes) != 1 || portMappingTypes[0] != inproxy.PortMappingTypeUPnP {
		return errors.TraceNew("unexpected port mapping types")
	}

	// Test: reset

	networkID = "NETWORK2"
	config.networkIDGetter = newCachingNetworkIDGetter(config, newStaticNetworkIDGetter(networkID))

	manager.reset()

	if manager.networkID != networkID {
		return errors.TraceNew("unexpected network ID")
	}

	if manager.getNATType(networkID) != inproxy.NATTypeUnknown {
		return errors.TraceNew("unexpected NAT type")
	}

	if len(manager.getPortMappingTypes(networkID)) != 0 {
		return errors.TraceNew("unexpected port mapping types")
	}

	return nil
}

// newGateTestManager returns a client broker client manager with one broker
// and one fronting provider, publishing gateTestBaseParameters. The manager
// is not registered as a TacticsAppliedReceiver: tests call TacticsApplied
// directly or register it themselves.
func newGateTestManager(t testing.TB) *InproxyBrokerClientManager {
	t.Helper()
	key, err := inproxy.GenerateSessionPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := key.GetPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	secret, err := inproxy.GenerateRootObfuscationSecret()
	if err != nil {
		t.Fatal(err)
	}
	id, err := inproxy.MakeID()
	if err != nil {
		t.Fatal(err)
	}
	config := &Config{DataRootDirectory: t.TempDir(), PropagationChannelId: "0000000000000000",
		SponsorId: "0000000000000000", NetworkID: "TEST", InproxyCommonCompartmentIDs: []string{id.String()},
		InproxyBrokerSpecs: []*parameters.InproxyBrokerSpec{{BrokerPublicKey: publicKey.String(),
			BrokerRootObfuscationSecret: secret.String(), BrokerFrontingSpecs: []*parameters.FrontingSpec{{
				FrontingProviderID: "test", Addresses: []string{"example.org"}, VerifyServerName: "example.org", Host: "example.org"}}}}}
	if err := config.Commit(false); err != nil {
		t.Fatal(err)
	}
	if err := OpenDataStore(config); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(CloseDataStore)
	config.SetResolver(resolver.NewResolver(&resolver.NetworkConfig{}, "TEST"))
	if err := setGateTestParameters(config, "", nil); err != nil {
		t.Fatal(err)
	}
	m := NewInproxyBrokerClientManager(config, false, utls.NewLRUClientSessionCache(0))
	t.Cleanup(m.closeClientBrokerClients)
	return m
}

// gateTestBaseParameters enables broker racing for the gate fixtures: two
// client broker clients, three proxy broker clients and client idle expiry.
// The shipped defaults disable racing (M=1, no idle expiry), and
// Config.SetParameters replaces the entire applied parameter set, so every
// fixture publication must carry these values or a later publication that
// omits them silently reverts to the shipped defaults. Tests that need a
// different limit pass it explicitly in every publication they make.
var gateTestBaseParameters = map[string]interface{}{
	parameters.InproxyClientMaxBrokerClients:        2,
	parameters.InproxyProxyMaxBrokerClients:         3,
	parameters.InproxyClientBrokerClientIdleTimeout: "60s",
}

// setGateTestParameters publishes params merged over gateTestBaseParameters;
// explicit params take precedence. Gate fixture tests must use this instead
// of calling config.SetParameters directly.
func setGateTestParameters(
	config *Config, tag string, params map[string]interface{}) error {

	merged := make(map[string]interface{}, len(gateTestBaseParameters)+len(params))
	for name, value := range gateTestBaseParameters {
		merged[name] = value
	}
	for name, value := range params {
		merged[name] = value
	}
	return config.SetParameters(tag, false, merged)
}

// getGateTestClient acquires a broker client from m and returns its
// instance. It registers t.Cleanup(release) for every acquisition, so the
// lease is held until the test ends unless the caller captures release via
// the optional out-parameter and calls it.
func getGateTestClient(t *testing.T, m *InproxyBrokerClientManager, releases ...*func()) *InproxyBrokerClientInstance {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	client, _, release, err := m.GetBrokerClient(ctx, "TEST")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(release)
	if len(releases) > 0 {
		*releases[0] = release
	}
	return client.GetBrokerDialCoordinator().(*InproxyBrokerClientInstance)
}

// Model a complete decoded offer, not merely a successful secure round trip.
func (b *InproxyBrokerClientInstance) brokerResponseSucceededForTest(rt inproxy.RoundTripper) {
	b.BrokerClientRoundTripperSucceeded(rt)
	b.BrokerClientResponseReceived(rt, false)
}

// TestInproxyBrokerWaitChannel verifies the wait channel lifecycle behind
// the acquisition-waiting notice: a change leaves no channel, the first
// acquisition that parks afterwards creates it (and is the one that logs),
// later parkers reuse it, and the next change closes it and again leaves
// none, so each park event is reported once.
func TestInproxyBrokerWaitChannel(t *testing.T) {
	m := newGateTestManager(t)
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if m.changed != nil {
		t.Fatal("new manager has a wait channel")
	}
	first := m.waitLocked("first %d", 1)
	if first == nil || m.changed != first {
		t.Fatal("first waiter did not create the channel")
	}
	if second := m.waitLocked("second"); second != first {
		t.Fatal("later waiter did not reuse the channel")
	}
	m.signalClientChangedLocked()
	select {
	case <-first:
	default:
		t.Fatal("change did not close the channel")
	}
	if m.changed != nil {
		t.Fatal("change left a channel for the next waiter to reuse")
	}
	if next := m.waitLocked("next"); next == first || next == nil {
		t.Fatal("waiter after a change did not create a new channel")
	}
	// A change with no waiter closes nothing and leaves none.
	m.signalClientChangedLocked()
	m.signalClientChangedLocked()
	if m.changed != nil {
		t.Fatal("repeated changes without waiters left a channel")
	}
}

// TestInproxyBrokerClientGate verifies the client limit, decoded-response
// sharing and lease-driven closure with one broker: unproven clients are not
// shared, a competitor survives promotion and a competing success, a failed
// competitor stays open while held and closes on its last release, stale
// callbacks cannot change the shared client, idle expiry replaces the shared
// client, disabled idle expiry arms no timer, and transport failure unshares
// the shared client.
func TestInproxyBrokerClientGate(t *testing.T) {
	m := newGateTestManager(t)
	var releaseA, releaseB, releaseShared1, releaseShared2, releaseShared3 func()
	a, b := getGateTestClient(t, m, &releaseA), getGateTestClient(t, m, &releaseB)
	if a == b {
		t.Fatal("unproven clients were shared")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, _, _, err := m.GetBrokerClient(ctx, "TEST"); !stderrors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("M gate did not block: %v", err)
	}
	a.brokerResponseSucceededForTest(a.roundTripper)
	if getGateTestClient(t, m, &releaseShared1) != a {
		t.Fatal("first success not shared")
	}
	select {
	case <-b.roundTripper.dialCompleted:
		t.Fatal("promotion closed active competitor")
	default:
	}
	m.mutex.Lock()
	retained := len(m.clients) == 2 && m.clients[b].refs == 1
	m.mutex.Unlock()
	if !retained {
		t.Fatal("promotion did not retain competitor's slot")
	}
	// A competing success must not replace or close the winner or
	// competitor.
	b.brokerResponseSucceededForTest(b.roundTripper)
	if getGateTestClient(t, m, &releaseShared2) != a || b.roundTripper.runCtx.Err() != nil {
		t.Fatal("competing success disrupted active clients")
	}
	b.BrokerClientRoundTripperFailed(b.roundTripper)
	if b.roundTripper.runCtx.Err() != nil {
		t.Fatal("failure closed competitor while its lease was held")
	}
	releaseB()
	if b.roundTripper.runCtx.Err() == nil {
		t.Fatal("failed competitor not closed on last release")
	}
	b.brokerResponseSucceededForTest(b.roundTripper)
	if getGateTestClient(t, m, &releaseShared3) != a {
		t.Fatal("stale callback evicted winner")
	}
	releaseA()
	releaseShared1()
	releaseShared2()
	releaseShared3()
	expireSharedClientForTest(m, a)
	var releaseC func()
	c := getGateTestClient(t, m, &releaseC)
	if c == a {
		t.Fatal("idle-expired client reused")
	}
	c.brokerResponseSucceededForTest(c.roundTripper)
	if err := setGateTestParameters(m.config, "", map[string]interface{}{parameters.InproxyClientBrokerClientIdleTimeout: "0s"}); err != nil {
		t.Fatal(err)
	}
	// With idle expiry disabled, the last release of the shared client must
	// not arm a timer, and the client remains shared at zero leases.
	releaseC()
	m.mutex.Lock()
	armed := m.sharedIdleTimer != nil
	m.mutex.Unlock()
	if armed {
		t.Fatal("disabled idle expiry armed timer")
	}
	if getGateTestClient(t, m) != c {
		t.Fatal("disabled idle expiry discarded shared client")
	}
	c.BrokerClientRoundTripperFailed(c.roundTripper)
	if getGateTestClient(t, m) == c {
		t.Fatal("failed shared client reused")
	}
}

// TestInproxyBrokerClientGateWakeAndCancel verifies that releasing an
// abandoned candidate frees its slot, that a decoded response wakes every
// acquisition blocked on the client limit and hands each the shared client,
// and that a network reset removes the shared client so a late response from
// it cannot restore sharing.
func TestInproxyBrokerClientGateWakeAndCancel(t *testing.T) {
	m := newGateTestManager(t)
	ctx, cancel := context.WithCancel(context.Background())
	client, _, release, err := m.GetBrokerClient(ctx, "TEST")
	if err != nil {
		t.Fatal(err)
	}
	a := client.GetBrokerDialCoordinator().(*InproxyBrokerClientInstance)
	b := getGateTestClient(t, m)
	cancel()
	release() // no broker callback: caller releases the abandoned slot
	c := getGateTestClient(t, m)
	if c == a {
		t.Fatal("canceled candidate reused")
	}
	waitCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	results := make(chan *inproxy.BrokerClient, 16)
	errors := make(chan error, 16)
	for i := 0; i < 16; i++ {
		go func() {
			client, _, release, err := m.GetBrokerClient(waitCtx, "TEST")
			if err == nil {
				defer release()
			}
			if err != nil {
				errors <- err
			} else {
				results <- client
			}
		}()
	}
	b.brokerResponseSucceededForTest(b.roundTripper)
	for i := 0; i < 16; i++ {
		select {
		case err := <-errors:
			t.Fatal(err)
		case client := <-results:
			if client != b.brokerClient {
				t.Fatal("waiter did not reuse winner")
			}
		case <-waitCtx.Done():
			t.Fatal("waiter not signaled")
		}
	}
	if err := m.NetworkChanged(); err != nil {
		t.Fatal(err)
	}
	b.brokerResponseSucceededForTest(b.roundTripper)
	if getGateTestClient(t, m) == b {
		t.Fatal("old network callback restored winner")
	}
}

// TestInproxyBrokerClientRetainedCompetitor verifies that a competitor that
// also received a decoded response stays open after another client is
// shared, then checks each way it ends: last release, its own NoMatch,
// network reset or shutdown, and promotion after the shared client fails,
// where it still occupies the client limit.
func TestInproxyBrokerClientRetainedCompetitor(t *testing.T) {
	for _, action := range []string{"cancel", "no-match", "network-reset", "shutdown", "promote-after-failure"} {
		t.Run(action, func(t *testing.T) {
			m := newGateTestManager(t)
			var releaseWinner, releaseShared func()
			winner := getGateTestClient(t, m, &releaseWinner)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			client, _, release, err := m.GetBrokerClient(ctx, "TEST")
			if err != nil {
				t.Fatal(err)
			}
			competitor := client.GetBrokerDialCoordinator().(*InproxyBrokerClientInstance)
			winner.brokerResponseSucceededForTest(winner.roundTripper)
			competitor.brokerResponseSucceededForTest(competitor.roundTripper)
			if competitor.roundTripper.runCtx.Err() != nil || getGateTestClient(t, m, &releaseShared) != winner {
				t.Fatal("promotion interrupted an active client")
			}
			switch action {
			case "cancel":
				cancel()
				release()
			case "no-match":
				competitor.BrokerClientResponseReceived(competitor.roundTripper, true)
			case "network-reset":
				if err := m.NetworkChanged(); err != nil {
					t.Fatal(err)
				}
			case "shutdown":
				m.closeClientBrokerClients()
			case "promote-after-failure":
				winner.BrokerClientRoundTripperFailed(winner.roundTripper)
				releaseWinner()
				releaseShared()
				other := getGateTestClient(t, m)
				waitCtx, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
				defer stop()
				if _, _, _, err := m.GetBrokerClient(waitCtx, "TEST"); !stderrors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("retained competitor did not count toward cap: %v", err)
				}
				competitor.brokerResponseSucceededForTest(competitor.roundTripper)
				cancel()
				if getGateTestClient(t, m) != competitor || competitor.roundTripper.runCtx.Err() != nil ||
					other.roundTripper.runCtx.Err() != nil {
					t.Fatal("remaining competitor could not become shared independently of its attempt")
				}
				return
			}
			select {
			case <-competitor.roundTripper.runCtx.Done():
			case <-time.After(5 * time.Second):
				t.Fatal("retained competitor was not cleaned up")
			}
			m.mutex.Lock()
			_, remaining := m.clients[competitor]
			m.mutex.Unlock()
			if remaining {
				t.Fatal("cleanup left competitor tracked")
			}
			if action == "cancel" || action == "no-match" {
				if winner.roundTripper.runCtx.Err() != nil || getGateTestClient(t, m) != winner {
					t.Fatal("competitor cleanup evicted shared client")
				}
			} else if winner.roundTripper.runCtx.Err() == nil {
				t.Fatal("reset did not close shared client")
			}
		})
	}
}

// TestInproxyBrokerNoMatchFailover verifies client NoMatch policy for common
// and personal pairing at failover probability zero and one: retain keeps
// the shared client, failover closes it despite outstanding leases without
// closing independent competitors or deleting replay, stale callbacks from
// the closed client cannot restore or evict sharing, and personal failover
// advances to the next rendezvous broker.
func TestInproxyBrokerNoMatchFailover(t *testing.T) {
	for _, personal := range []bool{false, true} {
		for _, probability := range []float64{0, 1} {
			t.Run(fmt.Sprintf("personal=%v/probability=%v", personal, probability), func(t *testing.T) {
				m := newGateTestManager(t)
				if personal {
					id, err := inproxy.MakeID()
					if err != nil {
						t.Fatal(err)
					}
					m.config.InproxyClientPersonalCompartmentID = id.String()
				}
				commonProbability, personalProbability := probability, 1-probability
				if personal {
					commonProbability, personalProbability = personalProbability, commonProbability
				}
				if err := setGateTestParameters(m.config, "", map[string]interface{}{
					parameters.InproxyBrokerSpecs: parameters.InproxyBrokerSpecsValue{
						newProviderTestBroker(t, "A", "B"), newProviderTestBroker(t, "C", "D"),
					},
					parameters.InproxyClientNoMatchFailoverProbability:         commonProbability,
					parameters.InproxyClientNoMatchFailoverPersonalProbability: personalProbability,
					parameters.InproxyPersonalPairingMaxBrokerSpecCount:        2,
					parameters.InproxyReplayBrokerDialParametersProbability:    1.0,
				}); err != nil {
					t.Fatal(err)
				}
				acquire := func() (*InproxyBrokerClientInstance, func()) {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					t.Cleanup(cancel)
					client, _, release, err := m.GetBrokerClient(ctx, "TEST")
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(release)
					return client.GetBrokerDialCoordinator().(*InproxyBrokerClientInstance), release
				}
				old, releaseFirst := acquire()
				var competitor *InproxyBrokerClientInstance
				if !personal {
					competitor, _ = acquire()
				}
				old.brokerResponseSucceededForTest(old.roundTripper)
				second, releaseSecond := acquire()
				if second != old {
					t.Fatal("second acquisition was not shared")
				}
				old.BrokerClientResponseReceived(old.roundTripper, true)
				if competitor != nil && competitor.roundTripper.runCtx.Err() != nil {
					t.Fatal("shared NoMatch closed independent competitor")
				}
				replay, err := loadInproxyBrokerReplayParameters("TEST", old.brokerDialParams.brokerSpec, time.Hour)
				if err != nil || replay == nil {
					t.Fatalf("NoMatch removed replay: %v", err)
				}
				if probability == 0 {
					if getGateTestClient(t, m) != old || old.roundTripper.runCtx.Err() != nil {
						t.Fatal("probability zero failed over")
					}
					return
				}
				if old.roundTripper.runCtx.Err() == nil || second.roundTripper.runCtx.Err() == nil {
					t.Fatal("NoMatch failover did not close transport shared by both workers")
				}
				// No current shared client: a late success must
				// not resurrect the closed one.
				old.brokerResponseSucceededForTest(old.roundTripper)
				m.mutex.Lock()
				resurrected := m.sharedClient != nil
				firstBroker := m.selector.preferBrokerOrder
				m.mutex.Unlock()
				if resurrected || !firstBroker {
					t.Fatal("stale success undid failover selection")
				}
				next, _ := acquire()
				if next == old {
					t.Fatal("probability one did not replace shared client")
				}
				if personal && (next.brokerPublicKey == old.brokerPublicKey || next.brokerSelection.index != old.brokerSelection.index+1) {
					t.Fatal("personal NoMatch did not advance rendezvous broker")
				}
				next.brokerResponseSucceededForTest(next.roundTripper)
				old.BrokerClientResponseReceived(old.roundTripper, true)
				old.brokerResponseSucceededForTest(old.roundTripper)
				if getGateTestClient(t, m) != next {
					t.Fatal("stale callback evicted current shared client")
				}
				releaseFirst()
				releaseSecond()
				if getGateTestClient(t, m) != next {
					t.Fatal("old attempt completion evicted replacement")
				}
			})
		}
	}
}

// TestInproxyBrokerNetworkIDMismatch verifies that an acquisition whose
// caller reports a network ID other than the current one fails immediately
// with "network changed", without waiting and without creating a client,
// and that the same manager still serves the current network ID.
func TestInproxyBrokerNetworkIDMismatch(t *testing.T) {
	m := newGateTestManager(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	_, _, release, err := m.GetBrokerClient(ctx, "STALE")
	if err == nil || !strings.Contains(err.Error(), "network changed") || release != nil {
		t.Fatalf("stale network ID: err=%v release=%v", err, release != nil)
	}
	if time.Since(start) > time.Second || len(m.clients) != 0 {
		t.Fatal("stale network ID acquisition waited or created a client")
	}
	if _, _, release, err := m.GetBrokerClient(ctx, "TEST"); err != nil {
		t.Fatal(err)
	} else {
		release()
	}
}

// TestInproxyBrokerClientNoSpecs verifies that the empty-manager tactics
// callback invalidates cached broker specs, that acquisition then fails
// immediately with "no broker specs" without waiting for the caller's
// context, and that it succeeds again once specs are restored and the
// callback runs again.
func TestInproxyBrokerClientNoSpecs(t *testing.T) {
	m := newGateTestManager(t)
	// Populate and then empty the broker list so the empty-manager tactics
	// callback is what invalidates the cached specs.
	var release func()
	getGateTestClient(t, m, &release)
	release()
	m.mutex.Lock()
	cached := len(m.selector.brokers)
	m.mutex.Unlock()
	if cached == 0 {
		t.Fatal("selector did not cache broker specs")
	}
	if err := setGateTestParameters(m.config, "", map[string]interface{}{parameters.InproxyBrokerSpecs: parameters.InproxyBrokerSpecsValue{}}); err != nil {
		t.Fatal(err)
	}
	if err := m.TacticsApplied(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, _, _, err := m.GetBrokerClient(ctx, "TEST"); err == nil || !strings.Contains(err.Error(), "no broker specs") {
		t.Fatalf("expected no broker specs error, got: %v", err)
	}
	if ctx.Err() != nil {
		t.Fatal("missing broker specs waited for context expiration")
	}
	if err := setGateTestParameters(m.config, "", nil); err != nil {
		t.Fatal(err)
	}
	if err := m.TacticsApplied(); err != nil {
		t.Fatal(err)
	}
	getGateTestClient(t, m)
}

// TestInproxyBrokerClientGateResetWake verifies that an acquisition blocked
// on the client limit wakes with a new client when a held candidate's last
// release closes it after failure, when a candidate's NoMatch triggers
// failover, or when a delivered tactics callback resets live clients. A
// failure alone, while the caller still holds its lease, does not wake it.
func TestInproxyBrokerClientGateResetWake(t *testing.T) {
	for _, event := range []string{"failure", "no-match", "tactics"} {
		t.Run(event, func(t *testing.T) {
			m := newGateTestManager(t)
			if err := setGateTestParameters(m.config, "failover", map[string]interface{}{
				parameters.InproxyClientNoMatchFailoverProbability: 1.0,
				parameters.InproxyClientMaxBrokerClients:           2,
			}); err != nil {
				t.Fatal(err)
			}
			var releaseA func()
			a := getGateTestClient(t, m, &releaseA)
			b := getGateTestClient(t, m)
			parent, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			ctx := &inproxyGateWaitContext{Context: parent, waiting: make(chan struct{})}
			result := make(chan error, 1)
			go func() {
				client, _, release, err := m.GetBrokerClient(ctx, "TEST")
				if err == nil {
					defer release()
				}
				if err == nil && (client == a.brokerClient || client == b.brokerClient) {
					err = stderrors.New("waiter received an unproven client")
				}
				result <- err
			}()
			select {
			case <-ctx.waiting:
			case err := <-result:
				t.Fatalf("gate returned before event: %v", err)
			case <-parent.Done():
				t.Fatal("acquisition did not wait")
			}
			switch event {
			case "failure":
				// A failed client still held by its caller
				// occupies the limit; only its last release
				// closes it and wakes the waiter.
				a.BrokerClientRoundTripperFailed(a.roundTripper)
				select {
				case err := <-result:
					t.Fatalf("failure alone woke the gate: %v", err)
				case <-time.After(20 * time.Millisecond):
				}
				releaseA()
			case "no-match":
				a.BrokerClientResponseReceived(a.roundTripper, true)
			case "tactics":
				// A delivered tactics callback resets all live
				// clients, whatever changed, and wakes waiters.
				if err := setGateTestParameters(m.config, "selection-change", map[string]interface{}{
					parameters.InproxyMaxCompartmentIDListLength: 1,
				}); err != nil {
					t.Fatal(err)
				}
				if err := m.TacticsApplied(); err != nil {
					t.Fatal(err)
				}
				if a.roundTripper.runCtx.Err() == nil || b.roundTripper.runCtx.Err() == nil {
					t.Fatal("tactics callback did not reset live clients")
				}
			}
			select {
			case err := <-result:
				if err != nil {
					t.Fatal(err)
				}
			case <-parent.Done():
				t.Fatal("gate did not wake")
			}
		})
	}
}

// TestInproxyBrokerClientGatePersonalAndProxy verifies that a personal
// pairing client waits while the only provider at its rendezvous broker has
// a live client and shares that client after a decoded response, and that a
// proxy shares its client on a decoded announcement and keeps it on NoMatch.
func TestInproxyBrokerClientGatePersonalAndProxy(t *testing.T) {
	m := newGateTestManager(t)
	id, err := inproxy.MakeID()
	if err != nil {
		t.Fatal(err)
	}
	m.config.InproxyClientPersonalCompartmentID = id.String()
	a := getGateTestClient(t, m)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, _, _, err := m.GetBrokerClient(ctx, "TEST"); !stderrors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("single-provider personal visit must cap at 1: %v", err)
	}
	a.brokerResponseSucceededForTest(a.roundTripper)
	if getGateTestClient(t, m) != a {
		t.Fatal("personal success not shared")
	}

	// Proxy sharing requires a decoded announcement response, not transport
	// success alone. Client NoMatch policy never rotates proxy brokers.
	proxy := NewInproxyBrokerClientManager(m.config, true, utls.NewLRUClientSessionCache(0))
	t.Cleanup(proxy.closeClientBrokerClients)
	p1 := getGateTestClient(t, proxy)
	p1.BrokerClientResponseReceived(p1.roundTripper, false)
	p2 := getGateTestClient(t, proxy)
	if p1 != p2 {
		t.Fatal("proxy acquisition behavior changed")
	}
	p1.BrokerClientResponseReceived(p1.roundTripper, true)
	if getGateTestClient(t, proxy) != p1 {
		t.Fatal("proxy NoMatch should be ignored")
	}
}

// newProviderTestBroker returns a broker spec with fresh keys and one
// fronting spec per entry in providerIDs, in order. Duplicate IDs produce
// duplicate fronting specs for the same provider.
func newProviderTestBroker(t testing.TB, providerIDs ...string) *parameters.InproxyBrokerSpec {
	t.Helper()
	key, err := inproxy.GenerateSessionPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := key.GetPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	secret, err := inproxy.GenerateRootObfuscationSecret()
	if err != nil {
		t.Fatal(err)
	}
	spec := &parameters.InproxyBrokerSpec{
		BrokerPublicKey: publicKey.String(), BrokerRootObfuscationSecret: secret.String(),
	}
	for _, id := range providerIDs {
		spec.BrokerFrontingSpecs = append(spec.BrokerFrontingSpecs, &parameters.FrontingSpec{
			FrontingProviderID: id, Addresses: []string{"example.org"}, VerifyServerName: "example.org", Host: "example.org",
		})
	}
	return spec
}

// newProviderTestManager returns a gate test manager whose published broker
// specs are replaced by specs, with the client limit set to limit, replay
// and failed-replay retention forced on, and personal pairing bounded to
// two brokers.
func newProviderTestManager(t testing.TB, limit int, specs ...*parameters.InproxyBrokerSpec) *InproxyBrokerClientManager {
	t.Helper()
	m := newGateTestManager(t)
	if err := setGateTestParameters(m.config, "", map[string]interface{}{
		parameters.InproxyBrokerSpecs:                           parameters.InproxyBrokerSpecsValue(specs),
		parameters.InproxyClientMaxBrokerClients:                limit,
		parameters.InproxyReplayBrokerDialParametersProbability: 1.0,
		parameters.InproxyReplayBrokerRetainFailedProbability:   1.0,
		parameters.InproxyPersonalPairingMaxBrokerSpecCount:     2,
	}); err != nil {
		t.Fatal(err)
	}
	return m
}

// checkProviderTestClient checks that the tracked provider matches the
// constructed transport and that the replay hash is from the original
// broker spec, then returns the provider ID.
func checkProviderTestClient(t *testing.T, instance *InproxyBrokerClientInstance) string {
	t.Helper()
	id := instance.frontingProviderID
	if id != instance.brokerDialParams.FrontedHTTPDialParameters.FrontingProviderID {
		t.Fatal("manager provider differs from constructed transport")
	}
	hash, err := instance.brokerDialParams.brokerSpec.Hash()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(hash, instance.brokerDialParams.LastUsedBrokerSpecHash) {
		t.Fatal("replay hash differs from original broker spec")
	}
	return id
}

// TestInproxyBrokerProviderRotation verifies that a common pairing client
// cycles fresh selections through distinct fronting provider IDs across
// brokers in a stable order, whether each attempt fails or is simply
// released, and that selection never modifies the original broker spec.
func TestInproxyBrokerProviderRotation(t *testing.T) {
	for _, cancelAttempt := range []bool{false, true} {
		t.Run(fmt.Sprintf("cancel=%v", cancelAttempt), func(t *testing.T) {
			// Providers overlap across brokers, and A has two
			// specs. Coverage is by distinct ID, across
			// replacements even when live is empty.
			a := newProviderTestBroker(t, "A", "A", "B")
			b := newProviderTestBroker(t, "B", "C")
			originalHash, err := a.Hash()
			if err != nil {
				t.Fatal(err)
			}
			m := newProviderTestManager(t, 1, a, b)
			var order []string
			seen := make(map[string]bool)
			for i := 0; i < 9; i++ {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				client, _, release, err := m.GetBrokerClient(ctx, "TEST")
				if err != nil {
					cancel()
					t.Fatal(err)
				}
				instance := client.GetBrokerDialCoordinator().(*InproxyBrokerClientInstance)
				id := checkProviderTestClient(t, instance)
				if i < 3 {
					if seen[id] {
						t.Fatalf("provider %s repeated before full coverage", id)
					}
					seen[id] = true
					order = append(order, id)
				} else if id != order[i%3] {
					t.Fatalf("rotation restarted: got %s, want %s", id, order[i%3])
				}
				if !cancelAttempt {
					instance.BrokerClientRoundTripperFailed(instance.roundTripper)
				}
				cancel()
				release()
			}
			hash, err := a.Hash()
			if err != nil || !bytes.Equal(hash, originalHash) {
				t.Fatal("selection mutated the original broker spec")
			}
		})
	}
}

// TestInproxyBrokerProviderOccupancy verifies least-occupied provider
// selection for common pairing clients at several client limits: concurrent
// acquisitions spread evenly across providers, and each replacement after a
// failed client joins a least-occupied provider rather than duplicating a
// still-live one.
func TestInproxyBrokerProviderOccupancy(t *testing.T) {
	for _, limit := range []int{2, 3, 5, 7} {
		t.Run(fmt.Sprintf("M=%d", limit), func(t *testing.T) {
			m := newProviderTestManager(t, limit, newProviderTestBroker(t, "A", "B", "C"))
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			type result struct {
				client  *inproxy.BrokerClient
				err     error
				release func()
			}
			results := make(chan result, limit)
			for i := 0; i < limit; i++ {
				go func() {
					client, _, release, err := m.GetBrokerClient(ctx, "TEST")
					if err == nil {
						t.Cleanup(release)
					}
					results <- result{client, err, release}
				}()
			}
			counts := map[string]int{"A": 0, "B": 0, "C": 0}
			var active []*InproxyBrokerClientInstance
			releases := make(map[*InproxyBrokerClientInstance]func())
			for i := 0; i < limit; i++ {
				r := <-results
				if r.err != nil {
					t.Fatal(r.err)
				}
				instance := r.client.GetBrokerDialCoordinator().(*InproxyBrokerClientInstance)
				counts[checkProviderTestClient(t, instance)]++
				active = append(active, instance)
				releases[instance] = r.release
			}
			for id, count := range counts {
				if count < limit/3 || count > (limit+2)/3 {
					t.Fatalf("initial occupancy not balanced: %s=%d (%v)", id, count, counts)
				}
			}
			// Keep the first candidate pending. Replacements must
			// keep cycling among the other providers rather than
			// duplicating that slow one.
			for i := 0; i < 12; i++ {
				index := 1 + i%(limit-1)
				old := active[index]
				counts[old.frontingProviderID]--
				old.BrokerClientRoundTripperFailed(old.roundTripper)
				releases[old]()
				minCount := limit
				for _, count := range counts {
					if count < minCount {
						minCount = count
					}
				}
				var release func()
				next := getGateTestClient(t, m, &release)
				releases[next] = release
				id := checkProviderTestClient(t, next)
				if counts[id] != minCount {
					t.Fatalf("selected %s despite less occupied provider: %v", id, counts)
				}
				if limit == 2 && (id == active[0].frontingProviderID || id == old.frontingProviderID) {
					t.Fatal("replacements did not rotate around the pending provider")
				}
				counts[id]++
				active[index] = next
			}
		})
	}
}

// TestInproxyBrokerProviderReplay verifies bounded replay for common pairing
// clients: a valid stored record is selected first for its provider with the
// original broker spec hash, later selections continue fresh provider
// rotation, and the same provider is not replayed again in the search even
// though its record remains valid.
func TestInproxyBrokerProviderReplay(t *testing.T) {
	spec := newProviderTestBroker(t, "A", "B", "C")
	m := newProviderTestManager(t, 1, spec)
	p := m.config.GetParameters().Get()
	replay, err := MakeInproxyBrokerDialParameters(m.config, p, spec, spec.BrokerFrontingSpecs[:1], m.tlsCache)
	p.Close()
	if err != nil {
		t.Fatal(err)
	}
	if err := SetNetworkReplayParameters("TEST", spec.BrokerPublicKey, replay); err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool)
	for i := 0; i < 4; i++ {
		var release func()
		instance := getGateTestClient(t, m, &release)
		id := checkProviderTestClient(t, instance)
		if i == 0 {
			if id != "A" || !instance.brokerDialParams.isReplay {
				t.Fatalf("expected A replay at turn %d, got %s, replay=%v", i, id, instance.brokerDialParams.isReplay)
			}
			if !bytes.Equal(instance.brokerDialParams.LastUsedBrokerSpecHash, replay.LastUsedBrokerSpecHash) {
				t.Fatal("filtered selection changed replay hash")
			}
		} else if instance.brokerDialParams.isReplay {
			t.Fatal("empty inflight set restarted replay instead of continuing rotation")
		} else if i == 3 && id != "A" {
			t.Fatal("replacement did not cycle back to the initial provider")
		}
		if i < 3 && seen[id] {
			t.Fatal("replay bypassed coverage")
		}
		seen[id] = true
		// Retention is forced on. After the first acquisition even
		// another A attempt must skip replay, despite zero inflight and
		// a valid record.
		instance.BrokerClientRoundTripperFailed(instance.roundTripper)
		release()
	}
}

// TestInproxyBrokerProviderConstructionFailure verifies that a fronting
// provider whose broker client cannot be constructed locally still consumes
// its selection turn, so acquisitions alternate between the failing and the
// working provider, and that failed construction leaves no tracked client.
func TestInproxyBrokerProviderConstructionFailure(t *testing.T) {
	spec := newProviderTestBroker(t, "A", "B")
	// HTTP is a valid fronting spec transport but unsupported by the broker
	// constructor. A's local failure must consume a turn without an M slot.
	spec.BrokerFrontingSpecs[0].Transports = protocol.FrontingTransports{protocol.FRONTING_TRANSPORT_HTTP}
	m := newProviderTestManager(t, 1, spec)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var previousFailed bool
	for i := 0; i < 6; i++ {
		client, _, release, err := m.GetBrokerClient(ctx, "TEST")
		if err == nil {
			defer release()
		}
		failed := err != nil
		if i > 0 && failed == previousFailed {
			t.Fatal("construction failure did not advance provider rotation")
		}
		previousFailed = failed
		if failed {
			if !strings.Contains(err.Error(), "unsupported fronting transport") {
				t.Fatal(err)
			}
		} else {
			instance := client.GetBrokerDialCoordinator().(*InproxyBrokerClientInstance)
			if checkProviderTestClient(t, instance) != "B" {
				t.Fatal("unexpected constructed provider")
			}
			instance.BrokerClientRoundTripperFailed(instance.roundTripper)
			release()
		}
		m.mutex.Lock()
		n := len(m.clients)
		m.mutex.Unlock()
		if n != 0 {
			t.Fatal("failed construction leaked a candidate")
		}
	}
}

// TestInproxyBrokerProviderPersonal verifies personal pairing broker order:
// brokers follow the compartment-seeded permutation bounded by
// InproxyPersonalPairingMaxBrokerSpecCount, each distinct fronting provider
// at the rendezvous broker is tried once per visit regardless of duplicate
// specs, and selection advances, wrapping around, only after the visit's
// providers are exhausted and its clients have closed.
func TestInproxyBrokerProviderPersonal(t *testing.T) {
	specs := parameters.InproxyBrokerSpecsValue{
		newProviderTestBroker(t, "A", "A", "B"),
		newProviderTestBroker(t, "A", "B", "C"),
		newProviderTestBroker(t, "C"),
	}
	m := newProviderTestManager(t, 5, specs...)
	id, err := inproxy.MakeID()
	if err != nil {
		t.Fatal(err)
	}
	m.config.InproxyClientPersonalCompartmentID = id.String()
	seed := prng.Seed(id[:])
	order := prng.NewPRNGWithSeed(&seed).Perm(len(specs))[:2]
	for visit := 0; visit < 6; visit++ {
		spec := specs[order[visit%len(order)]]
		remaining := make(map[string]bool)
		for _, frontingSpec := range spec.BrokerFrontingSpecs {
			remaining[frontingSpec.FrontingProviderID] = true
		}
		for len(remaining) > 0 {
			var release func()
			instance := getGateTestClient(t, m, &release)
			providerID := checkProviderTestClient(t, instance)
			if instance.brokerDialParams.brokerSpec.BrokerPublicKey != spec.BrokerPublicKey {
				t.Fatal("advanced rendezvous broker before provider exhaustion, or changed broker order")
			}
			if !remaining[providerID] {
				t.Fatal("repeated a provider before exhausting rendezvous broker")
			}
			delete(remaining, providerID)
			instance.BrokerClientRoundTripperFailed(instance.roundTripper)
			release()
		}
	}
}

// TestInproxyBrokerProviderPersonalSharedLoss verifies that a personal
// pairing client advances to the next rendezvous broker after its visit is
// exhausted, stays at that broker with the same visit after shared idle
// expiry, replaying the record stored there, and advances in rendezvous
// order only when that broker is exhausted too.
func TestInproxyBrokerProviderPersonalSharedLoss(t *testing.T) {
	m := newProviderTestManager(t, 2, newProviderTestBroker(t, "A"), newProviderTestBroker(t, "B"))
	id, err := inproxy.MakeID()
	if err != nil {
		t.Fatal(err)
	}
	m.config.InproxyClientPersonalCompartmentID = id.String()
	var releasePrimary, releaseSecondary, releaseNext func()
	primary := getGateTestClient(t, m, &releasePrimary)
	primary.BrokerClientRoundTripperFailed(primary.roundTripper)
	releasePrimary()
	secondary := getGateTestClient(t, m, &releaseSecondary)
	if secondary.frontingProviderID == primary.frontingProviderID {
		t.Fatal("did not advance to secondary rendezvous broker")
	}
	secondary.brokerResponseSucceededForTest(secondary.roundTripper)
	releaseSecondary()
	expireSharedClientForTest(m, secondary)
	next := getGateTestClient(t, m, &releaseNext)
	if next.frontingProviderID != secondary.frontingProviderID ||
		next.brokerSelection != secondary.brokerSelection ||
		!next.brokerDialParams.isReplay {
		t.Fatal("shared loss did not retain the rendezvous broker, visit and replay")
	}
	next.BrokerClientRoundTripperFailed(next.roundTripper)
	releaseNext()
	next = getGateTestClient(t, m)
	if next.frontingProviderID != primary.frontingProviderID || next.brokerSelection == secondary.brokerSelection {
		t.Fatal("exhausting the retained broker did not advance in rendezvous order")
	}
}

// TestInproxyBrokerProviderLifecycle verifies common client search state
// across shared client loss and resets: losing the shared client by failure
// or idle expiry starts a replay-first search on its provider unless the
// record was deleted, a closed competitor's late success rewrites the broker
// record so the next unused provider replays it, and a network or tactics
// reset discards old provider eligibility and occupancy.
func TestInproxyBrokerProviderLifecycle(t *testing.T) {
	for _, event := range []string{"shared-failure", "shared-failure-delete", "idle-discard"} {
		t.Run(event, func(t *testing.T) {
			m := newProviderTestManager(t, 2, newProviderTestBroker(t, "A", "B", "C"))
			var releaseA, releaseB, releaseShared func()
			a, b := getGateTestClient(t, m, &releaseA), getGateTestClient(t, m, &releaseB)
			a.brokerResponseSucceededForTest(a.roundTripper)
			if getGateTestClient(t, m, &releaseShared) != a {
				t.Fatal("shared acquisition started another provider")
			}
			releaseA()
			releaseShared()
			if event == "shared-failure" || event == "shared-failure-delete" {
				if event == "shared-failure-delete" {
					a.replayRetainFailedProbability = 0
				}
				a.BrokerClientRoundTripperFailed(a.roundTripper)
			} else {
				expireSharedClientForTest(m, a)
			}
			c := getGateTestClient(t, m)
			if event == "shared-failure-delete" {
				if c.brokerDialParams.isReplay {
					t.Fatal("new search used invalidated replay")
				}
			} else if c.frontingProviderID != a.frontingProviderID || !c.brokerDialParams.isReplay {
				t.Fatal("shared loss did not start a replay-first search")
			}
			// A closed competitor's late success still records its
			// provider as the broker's replay hint; the next unused
			// provider replays it.
			b.BrokerClientRoundTripperFailed(b.roundTripper)
			releaseB()
			b.brokerResponseSucceededForTest(b.roundTripper)
			d := getGateTestClient(t, m)
			if d.frontingProviderID == c.frontingProviderID ||
				!d.brokerDialParams.isReplay || d.frontingProviderID != b.frontingProviderID {
				t.Fatal("closed competitor's success was not replayed on its provider")
			}
		})
	}
	for _, event := range []string{"network", "tactics"} {
		t.Run(event, func(t *testing.T) {
			m := newProviderTestManager(t, 2, newProviderTestBroker(t, "A", "B"))
			a := getGateTestClient(t, m)
			spec := newProviderTestBroker(t, "D", "E")
			if err := setGateTestParameters(m.config, "", map[string]interface{}{
				parameters.InproxyBrokerSpecs: parameters.InproxyBrokerSpecsValue{spec},
			}); err != nil {
				t.Fatal(err)
			}
			var err error
			if event == "network" {
				err = m.NetworkChanged()
			} else {
				err = m.TacticsApplied()
			}
			if err != nil {
				t.Fatal(err)
			}
			a.brokerResponseSucceededForTest(a.roundTripper)
			b, c := getGateTestClient(t, m), getGateTestClient(t, m)
			if (b.frontingProviderID != "D" && b.frontingProviderID != "E") ||
				(c.frontingProviderID != "D" && c.frontingProviderID != "E") || b.frontingProviderID == c.frontingProviderID {
				t.Fatal("reset retained old provider eligibility or occupancy")
			}
		})
	}
}

// makeBrokerReplayTestParameters builds storable broker dial parameters for
// providerID at spec. It backdates LastUsedTimestamp so that a later success
// produces different stored bytes from the original record.
func makeBrokerReplayTestParameters(t *testing.T, m *InproxyBrokerClientManager,
	spec *parameters.InproxyBrokerSpec, providerID string) *InproxyBrokerDialParameters {
	t.Helper()
	p := m.config.GetParameters().Get()
	defer p.Close()
	params, err := MakeInproxyBrokerDialParameters(m.config, p, spec,
		inproxyBrokerFrontingSpecs(spec, providerID), m.tlsCache)
	if err != nil {
		t.Fatal(err)
	}
	// Give a subsequent success a deterministically newer timestamp.
	params.LastUsedTimestamp = time.Now().Add(-time.Minute)
	return params
}

// loadBrokerReplayTestParameters loads the stored replay record for spec,
// failing the test on a load error. It returns nil when no valid record is
// stored.
func loadBrokerReplayTestParameters(t *testing.T, spec *parameters.InproxyBrokerSpec) *InproxyBrokerDialParameters {
	t.Helper()
	params, err := loadInproxyBrokerReplayParameters("TEST", spec, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return params
}

// TestInproxyBrokerReplayFirst verifies that a common client search replays
// the single broker-wide record once, on the provider it stores, then covers
// the remaining providers fresh, and that a fresh winner's success replaces
// the record while losing competitors' failures cannot delete it.
func TestInproxyBrokerReplayFirst(t *testing.T) {
	spec := newProviderTestBroker(t, "A", "B")
	m := newProviderTestManager(t, 4, spec)
	records := make(map[string][]byte)
	for _, id := range []string{"A", "B"} {
		params := makeBrokerReplayTestParameters(t, m, spec, id)
		if err := storeInproxyBrokerReplayParameters("TEST", params); err != nil {
			t.Fatal(err)
		}
		records[id] = params.replayRecordHash
	}
	seen := make(map[string]bool)
	var instances []*InproxyBrokerClientInstance
	for i := 0; i < 4; i++ {
		instance := getGateTestClient(t, m)
		id := checkProviderTestClient(t, instance)
		if i == 0 {
			// The broker-wide record contains its last stored
			// provider, not independent records ranked or shuffled
			// across providers.
			if id != "B" || !instance.brokerDialParams.isReplay ||
				!bytes.Equal(instance.brokerDialParams.replayRecordHash, records[id]) {
				t.Fatal("first worker did not replay the broker's last stored configuration")
			}
		} else if instance.brokerDialParams.isReplay || len(instance.brokerDialParams.replayRecordHash) != 0 {
			t.Fatal("single broker record was replayed more than once in the search")
		}
		if i < 2 && seen[id] {
			t.Fatal("provider coverage did not follow the replayed provider")
		}
		seen[id] = true
		instances = append(instances, instance)
	}
	// A fresh candidate on another provider must replace the broker-wide
	// record, and stale failures must not delete that new successful
	// record.
	winner := instances[1]
	winner.brokerResponseSucceededForTest(winner.roundTripper)
	for _, loser := range instances {
		if loser == winner {
			continue
		}
		loser.mutex.Lock()
		loser.replayRetainFailedProbability = 0
		loser.mutex.Unlock()
		loser.BrokerClientRoundTripperFailed(loser.roundTripper)
	}
	stored := loadBrokerReplayTestParameters(t, spec)
	if stored == nil || !bytes.Equal(stored.replayRecordHash, winner.brokerDialParams.replayRecordHash) ||
		bytes.Equal(stored.replayRecordHash, records[winner.frontingProviderID]) {
		t.Fatal("losing callback erased fresh winner's broker replay")
	}
}

// TestInproxyBrokerReplayAbandonedCandidate verifies that releasing an
// unproven replay candidate does not restore its replay allowance or delete
// its record: later selections in the same search rotate through the
// remaining providers and return to the replayed provider with fresh dial
// parameters.
func TestInproxyBrokerReplayAbandonedCandidate(t *testing.T) {
	spec := newProviderTestBroker(t, "A", "B", "C")
	m := newProviderTestManager(t, 1, spec)
	params := makeBrokerReplayTestParameters(t, m, spec, "A")
	if err := storeInproxyBrokerReplayParameters("TEST", params); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		var release func()
		instance := getGateTestClient(t, m, &release)
		if instance.brokerDialParams.isReplay != (i == 0) {
			t.Fatal("abandonment restarted replay rather than continuing the search")
		}
		if (i == 0 || i == 3) && instance.frontingProviderID != "A" {
			t.Fatal("search did not cycle from and back to the replayed provider")
		}
		// Releasing the unproven candidate closes it without a
		// transport failure, so the stored record must survive.
		release()
		if loadBrokerReplayTestParameters(t, spec) == nil {
			t.Fatal("abandoning a replay candidate deleted its record")
		}
	}
}

// TestInproxyBrokerReplayConstructionFailure verifies that a replay candidate
// whose construction fails locally consumes its provider turn and replay
// allowance without occupying a client slot, so the next selection is a fresh
// candidate on another provider and a later unshared failure does not restart
// the replay-first search.
func TestInproxyBrokerReplayConstructionFailure(t *testing.T) {
	spec := newProviderTestBroker(t, "A", "B")
	m := newProviderTestManager(t, 1, spec)
	params := makeBrokerReplayTestParameters(t, m, spec, "A")
	if err := storeInproxyBrokerReplayParameters("TEST", params); err != nil {
		t.Fatal(err)
	}
	resolver := m.config.GetResolver()
	m.config.SetResolver(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, _, err := m.GetBrokerClient(ctx, "TEST")
	m.config.SetResolver(resolver)
	if err == nil {
		t.Fatal("expected replay construction to fail without resolver")
	}
	var releaseB func()
	b := getGateTestClient(t, m, &releaseB)
	if b.frontingProviderID != "B" || b.brokerDialParams.isReplay {
		t.Fatal("failed replay construction did not advance to fresh provider coverage")
	}
	b.BrokerClientRoundTripperFailed(b.roundTripper)
	releaseB()
	a := getGateTestClient(t, m)
	if a.frontingProviderID != "A" || a.brokerDialParams.isReplay {
		t.Fatal("unproven failure restarted replay after a construction error")
	}
}

// TestInproxyBrokerReplayConditionalDeletion verifies exact-record replay
// deletion across two broker client instances at one broker: a failure
// deletes only the record its instance loaded or stored, regardless of
// whether a competing success lands before, after or concurrently, and an
// instance that never loaded or stored a record deletes nothing.
func TestInproxyBrokerReplayConditionalDeletion(t *testing.T) {
	for _, order := range []string{"success-first", "failure-first", "concurrent", "fresh-failure"} {
		t.Run(order, func(t *testing.T) {
			spec := newProviderTestBroker(t, "A")
			m := newProviderTestManager(t, 2, spec)
			params := makeBrokerReplayTestParameters(t, m, spec, "A")
			if err := storeInproxyBrokerReplayParameters("TEST", params); err != nil {
				t.Fatal(err)
			}
			old, fresh := getGateTestClient(t, m), getGateTestClient(t, m)
			if !old.brokerDialParams.isReplay || fresh.brokerDialParams.isReplay ||
				!bytes.Equal(old.brokerDialParams.replayRecordHash, params.replayRecordHash) {
				t.Fatal("fixture did not load the stored record into the first client")
			}
			old.replayRetainFailedProbability = 0
			fresh.replayRetainFailedProbability = 0
			succeed := func() { fresh.brokerResponseSucceededForTest(fresh.roundTripper) }
			fail := func() { old.BrokerClientRoundTripperFailed(old.roundTripper) }
			switch order {
			case "success-first":
				succeed()
				fail()
			case "failure-first":
				fail()
				succeed()
			case "concurrent":
				var wg sync.WaitGroup
				wg.Add(2)
				go func() { defer wg.Done(); succeed() }()
				go func() { defer wg.Done(); fail() }()
				wg.Wait()
			case "fresh-failure":
				fresh.BrokerClientRoundTripperFailed(fresh.roundTripper)
				stored := loadBrokerReplayTestParameters(t, spec)
				if stored == nil || !bytes.Equal(stored.replayRecordHash, params.replayRecordHash) {
					t.Fatal("fresh failure deleted a record it never used")
				}
				fail()
				if loadBrokerReplayTestParameters(t, spec) != nil {
					t.Fatal("matching replay failure did not delete its record")
				}
				return
			}
			stored := loadBrokerReplayTestParameters(t, spec)
			if stored == nil || !bytes.Equal(stored.replayRecordHash, fresh.brokerDialParams.replayRecordHash) {
				t.Fatal("old failure deleted newer successful replay")
			}
		})
	}
}

// TestInproxyBrokerReplayOverwriteAndThrottle checks the accepted replay
// persistence policy with multiple broker client instances: one record per
// broker; any instance's success may replace the record; refresh writes are
// throttled per instance while first-success writes are not; and exact-record
// deletion prevents an overwritten instance's failure from deleting another
// instance's record.
func TestInproxyBrokerReplayOverwriteAndThrottle(t *testing.T) {
	spec := newProviderTestBroker(t, "A", "B")
	m := newProviderTestManager(t, 2, spec)
	params := makeBrokerReplayTestParameters(t, m, spec, "A")
	if err := storeInproxyBrokerReplayParameters("TEST", params); err != nil {
		t.Fatal(err)
	}
	old, fresh := getGateTestClient(t, m), getGateTestClient(t, m)
	if !old.brokerDialParams.isReplay || old.frontingProviderID != "A" ||
		fresh.brokerDialParams.isReplay || fresh.frontingProviderID != "B" {
		t.Fatal("unexpected replay/provider assignment")
	}
	for _, c := range []*InproxyBrokerClientInstance{old, fresh} {
		c.mutex.Lock()
		c.replayRetainFailedProbability = 0
		c.mutex.Unlock()
	}
	stored := func() []byte {
		t.Helper()
		params := loadBrokerReplayTestParameters(t, spec)
		if params == nil {
			return nil
		}
		return params.replayRecordHash
	}

	// A replayed instance's first success rewrites the record it loaded.
	old.brokerResponseSucceededForTest(old.roundTripper)
	oldRecord := old.brokerDialParams.replayRecordHash
	if bytes.Equal(oldRecord, params.replayRecordHash) || !bytes.Equal(stored(), oldRecord) {
		t.Fatal("first success did not refresh the loaded record")
	}

	// A second success within the update frequency is throttled.
	old.brokerResponseSucceededForTest(old.roundTripper)
	if !bytes.Equal(old.brokerDialParams.replayRecordHash, oldRecord) || !bytes.Equal(stored(), oldRecord) {
		t.Fatal("refresh within update frequency was not throttled")
	}

	// A different instance's first success is never throttled and replaces
	// the broker-wide record with its own provider.
	fresh.brokerResponseSucceededForTest(fresh.roundTripper)
	freshRecord := fresh.brokerDialParams.replayRecordHash
	if bytes.Equal(freshRecord, oldRecord) || !bytes.Equal(stored(), freshRecord) {
		t.Fatal("competing first success did not replace the record")
	}
	if loadBrokerReplayTestParameters(t, spec).FrontedHTTPDialParameters.FrontingProviderID != "B" {
		t.Fatal("record does not hold the last successful provider")
	}

	// Once its update frequency elapses, the older instance's refresh
	// overwrites the newer record. This overwrite is accepted: both
	// configurations succeeded.
	old.mutex.Lock()
	old.replayUpdateFrequency = 0
	old.mutex.Unlock()
	old.brokerResponseSucceededForTest(old.roundTripper)
	refreshed := old.brokerDialParams.replayRecordHash
	if bytes.Equal(refreshed, oldRecord) || bytes.Equal(refreshed, freshRecord) || !bytes.Equal(stored(), refreshed) {
		t.Fatal("refresh after update frequency did not overwrite the record")
	}

	// The overwritten instance's failure deletes nothing; the refreshing
	// instance's failure deletes its own record.
	fresh.BrokerClientRoundTripperFailed(fresh.roundTripper)
	if !bytes.Equal(stored(), refreshed) {
		t.Fatal("overwritten instance deleted another instance's record")
	}
	old.BrokerClientRoundTripperFailed(old.roundTripper)
	if stored() != nil {
		t.Fatal("writer's failure did not delete its own record")
	}
}

// TestInproxyBrokerReplayBrokerSelection verifies that a broker-wide replay
// record stored under the existing key is read without migration, that a
// common client prefers the broker holding valid replay over broker order,
// and that a personal client keeps rendezvous order and ignores that record.
func TestInproxyBrokerReplayBrokerSelection(t *testing.T) {
	first, second := newProviderTestBroker(t, "A"), newProviderTestBroker(t, "B")
	m := newProviderTestManager(t, 2, first, second)
	params := makeBrokerReplayTestParameters(t, m, second, "B")
	// Existing broker-wide records remain readable with no migration.
	if err := SetNetworkReplayParameters("TEST", second.BrokerPublicKey, params); err != nil {
		t.Fatal(err)
	}
	for _, firstOnly := range []bool{false, true} {
		s := inproxyBrokerSelector{brokers: parameters.InproxyBrokerSpecsValue{first, second}, exhaustBrokerProviders: firstOnly, personal: firstOnly}
		p := m.config.GetParameters().Get()
		selection, err := s.selectClient(m.config, p, "TEST", false, nil)
		p.Close()
		if err != nil {
			t.Fatal(err)
		}
		if firstOnly {
			if selection.brokerSpec != first || selection.replayDialParams != nil {
				t.Fatal("replay changed rendezvous broker order")
			}
		} else if selection.brokerSpec != second || selection.replayDialParams == nil || selection.replayDialParams.FrontedHTTPDialParameters.FrontingProviderID != "B" {
			t.Fatal("did not prefer broker with valid replay")
		}
	}
}

// TestInproxyBrokerReplayValidation verifies that loading replay dial
// parameters rejects records that are expired, hashed against a different
// broker spec, stored for an unsupported fronting provider or missing
// transport parameters, while leaving another broker's valid record intact.
func TestInproxyBrokerReplayValidation(t *testing.T) {
	for _, invalid := range []string{"expired", "broker-hash", "provider", "missing-transport"} {
		t.Run(invalid, func(t *testing.T) {
			spec := newProviderTestBroker(t, "A", "B")
			other := newProviderTestBroker(t, "B")
			m := newProviderTestManager(t, 1, spec, other)
			a := makeBrokerReplayTestParameters(t, m, spec, "A")
			b := makeBrokerReplayTestParameters(t, m, other, "B")
			if err := storeInproxyBrokerReplayParameters("TEST", b); err != nil {
				t.Fatal(err)
			}
			switch invalid {
			case "expired":
				a.LastUsedTimestamp = time.Now().Add(-2 * time.Hour)
			case "broker-hash":
				a.LastUsedBrokerSpecHash = []byte("wrong")
			case "provider":
				a.FrontedHTTPDialParameters.FrontingProviderID = "unknown"
			case "missing-transport":
				a.FrontedHTTPDialParameters = nil
			}
			if err := SetNetworkReplayParameters("TEST", spec.BrokerPublicKey, a); err != nil {
				t.Fatal(err)
			}
			if loadBrokerReplayTestParameters(t, spec) != nil {
				t.Fatal("accepted invalid provider replay")
			}
			// The invalid record is deleted from the datastore, not merely
			// rejected: a raw read of its key finds nothing.
			key := makeNetworkReplayParametersKey[InproxyBrokerDialParameters]("TEST", spec.BrokerPublicKey)
			var raw []byte
			err := datastoreView(func(tx *datastoreTx) error {
				raw = tx.bucket(datastoreNetworkReplayParametersBucket).get(key)
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if raw != nil {
				t.Fatal("invalid replay record was not deleted from the datastore")
			}
			if loadBrokerReplayTestParameters(t, other) == nil {
				t.Fatal("validation removed another broker's valid replay")
			}
		})
	}
}

// brokerReplayTacticsBarrier is a TacticsAppliedReceiver placed before the
// manager in the receiver list. It blocks SetParameters after publication,
// signalling published, until proceed is closed.
type brokerReplayTacticsBarrier struct {
	published chan struct{}
	proceed   chan struct{}
}

func (b *brokerReplayTacticsBarrier) TacticsApplied() error {
	close(b.published)
	<-b.proceed
	return nil
}

// TestInproxyBrokerReplayTacticsPublication verifies that publishing tactics
// does not reset broker clients until the tactics callback runs: clients
// acquired in between keep the old specs, the delayed callback then closes
// every live client, the next acquisition uses the new specs, and a late
// response from a closed client cannot become shared.
func TestInproxyBrokerReplayTacticsPublication(t *testing.T) {
	for _, shared := range []bool{false, true} {
		name := "inflight"
		if shared {
			name = "shared"
		}
		t.Run(name, func(t *testing.T) {
			// The inflight variant holds three distinct unproven
			// clients across the publication, so M must stay at 3
			// after it.
			m := newProviderTestManager(t, 3, newProviderTestBroker(t, "A", "B"))
			old := getGateTestClient(t, m)
			if shared {
				old.brokerResponseSucceededForTest(old.roundTripper)
			}
			barrier := &brokerReplayTacticsBarrier{make(chan struct{}), make(chan struct{})}
			m.config.SetTacticsAppliedReceivers([]TacticsAppliedReceiver{barrier, m})
			done := make(chan error, 1)
			var finishOnce sync.Once
			finish := func() {
				finishOnce.Do(func() {
					close(barrier.proceed)
					if err := <-done; err != nil {
						t.Error(err)
					}
				})
			}
			t.Cleanup(finish)
			spec := newProviderTestBroker(t, "D", "E")
			go func() {
				done <- setGateTestParameters(m.config, "new", map[string]interface{}{
					parameters.InproxyBrokerSpecs:            parameters.InproxyBrokerSpecsValue{spec},
					parameters.InproxyClientMaxBrokerClients: 3,
				})
			}()
			select {
			case <-barrier.published:
			case <-time.After(5 * time.Second):
				t.Fatal("tactics were not published")
			}
			// Publication alone does not reset the manager. The
			// delayed callback may discard acquisitions made while
			// it was waiting to run.
			a, b := getGateTestClient(t, m), getGateTestClient(t, m)
			if old.roundTripper.runCtx.Err() != nil {
				t.Fatal("acquisition reset clients before tactics callback")
			}
			finish()
			if a.roundTripper.runCtx.Err() == nil || b.roundTripper.runCtx.Err() == nil || old.roundTripper.runCtx.Err() == nil {
				t.Fatal("tactics callback did not close all live clients")
			}
			fresh := getGateTestClient(t, m)
			a.brokerResponseSucceededForTest(a.roundTripper)
			if (fresh.frontingProviderID != "D" && fresh.frontingProviderID != "E") || m.sharedClient != nil {
				t.Fatal("new tactics not selected or stale response resurrected client")
			}
		})
	}
}

// TestInproxyBrokerReplayUnchangedTacticsTag verifies that a publication with
// an unchanged nonempty tactics tag skips the reset callback even when its
// broker specs differ, so the shared client is retained and reused, and that
// an explicit TacticsApplied call then applies the new specs.
func TestInproxyBrokerReplayUnchangedTacticsTag(t *testing.T) {
	oldSpec := newProviderTestBroker(t, "A")
	m := newProviderTestManager(t, 1, oldSpec)
	if err := setGateTestParameters(m.config, "same", map[string]interface{}{
		parameters.InproxyBrokerSpecs: parameters.InproxyBrokerSpecsValue{oldSpec},
	}); err != nil {
		t.Fatal(err)
	}
	old := getGateTestClient(t, m)
	old.brokerResponseSucceededForTest(old.roundTripper)
	m.config.SetTacticsAppliedReceivers([]TacticsAppliedReceiver{m})
	newSpec := newProviderTestBroker(t, "B")
	if err := setGateTestParameters(m.config, "same", map[string]interface{}{
		parameters.InproxyBrokerSpecs: parameters.InproxyBrokerSpecsValue{newSpec},
	}); err != nil {
		t.Fatal(err)
	}
	m.mutex.Lock()
	callbackSkipped := m.sharedClient == old
	m.mutex.Unlock()
	if !callbackSkipped {
		t.Fatal("expected unchanged tag to skip reset callback")
	}
	if getGateTestClient(t, m) != old {
		t.Fatal("acquisition reset without a tactics callback")
	}
	if err := m.TacticsApplied(); err != nil {
		t.Fatal(err)
	}
	if getGateTestClient(t, m).frontingProviderID != "B" {
		t.Fatal("explicit callback did not apply new broker specs")
	}
}

// TestInproxyBrokerTacticsReset verifies that a delivered tactics callback
// resets the shared client and competing candidates for client and proxy
// managers without comparing parameter values, that a new client adopts
// current constructor settings, that a stale response from a closed client
// cannot become shared, and that a repeated callback resets again.
func TestInproxyBrokerTacticsReset(t *testing.T) {
	for _, proxy := range []bool{false, true} {
		for _, change := range []string{"same-inputs", "capacity", "dial-settings"} {
			t.Run(fmt.Sprintf("proxy=%v/%s", proxy, change), func(t *testing.T) {
				spec := newProviderTestBroker(t, "A", "B")
				m := newProviderTestManager(t, 2, spec)
				m.isProxy = proxy
				a, b := getGateTestClient(t, m), getGateTestClient(t, m)
				a.brokerResponseSucceededForTest(a.roundTripper)
				m.config.SetTacticsAppliedReceivers([]TacticsAppliedReceiver{m})
				params := map[string]interface{}{
					parameters.InproxyBrokerSpecs:                       parameters.InproxyBrokerSpecsValue{spec},
					parameters.InproxyPersonalPairingMaxBrokerSpecCount: 2,
					parameters.InproxyClientMaxBrokerClients:            2,
				}
				if change == "capacity" {
					params[parameters.InproxyClientMaxBrokerClients] = 3
					params[parameters.InproxyProxyMaxBrokerClients] = 4
				}
				if change == "dial-settings" {
					params[parameters.InproxyProxyAnnounceRequestTimeout] = "731ms"
				}
				if err := setGateTestParameters(m.config, "new", params); err != nil {
					t.Fatal(err)
				}
				if a.roundTripper.runCtx.Err() == nil || b.roundTripper.runCtx.Err() == nil || len(m.clients) != 0 {
					t.Fatal("tactics callback did not reset shared and competing clients")
				}
				fresh := getGateTestClient(t, m)
				if change == "dial-settings" && fresh.AnnounceRequestTimeout() != 731*time.Millisecond {
					t.Fatal("new client did not adopt constructor settings")
				}
				a.brokerResponseSucceededForTest(a.roundTripper)
				if m.sharedClient != nil {
					t.Fatal("old response restored shared client")
				}
				if err := m.TacticsApplied(); err != nil {
					t.Fatal(err)
				}
				if fresh.roundTripper.runCtx.Err() == nil {
					t.Fatal("repeated callback failed to reset live client")
				}
			})
		}
	}
}

// TestInproxyBrokerTacticsUnchangedPublication verifies that republishing
// tactics under the same nonempty tag, or a publication that fails parameter
// validation, does not invoke the reset callback and leaves the shared broker
// client in place for reuse.
func TestInproxyBrokerTacticsUnchangedPublication(t *testing.T) {
	m := newProviderTestManager(t, 2, newProviderTestBroker(t, "A"))
	if err := setGateTestParameters(m.config, "same", nil); err != nil {
		t.Fatal(err)
	}
	old := getGateTestClient(t, m)
	old.brokerResponseSucceededForTest(old.roundTripper)
	m.config.SetTacticsAppliedReceivers([]TacticsAppliedReceiver{m})
	if err := setGateTestParameters(m.config, "same", nil); err != nil {
		t.Fatal(err)
	}
	if getGateTestClient(t, m) != old {
		t.Fatal("unchanged nonempty tag unnecessarily reset shared client")
	}
	if err := setGateTestParameters(m.config, "failed", map[string]interface{}{
		parameters.InproxyMaxCompartmentIDListLength: -1,
	}); err == nil {
		t.Fatal("expected parameter validation failure")
	}
	if getGateTestClient(t, m) != old {
		t.Fatal("failed parameter publication reset shared client")
	}
}

// TestInproxyBrokerTacticsSkipWhenEmpty verifies that a tactics callback
// with no live broker clients only invalidates the cached broker list: it
// does not allocate selection state, wake waiters or change the change
// channel, and the next acquisition rebuilds selection from current tactics
// with the same session seed while a stale response cannot become shared.
func TestInproxyBrokerTacticsSkipWhenEmpty(t *testing.T) {
	for _, proxy := range []bool{false, true} {
		t.Run(fmt.Sprint(proxy), func(t *testing.T) {
			m := newProviderTestManager(t, 2, newProviderTestBroker(t, "A", "B"))
			m.isProxy = proxy
			// A callback before initialization does not allocate
			// state or wakeups.
			if err := m.TacticsApplied(); err != nil {
				t.Fatal(err)
			}
			if m.changed != nil || len(m.selector.brokers) != 0 || m.selector.currentBrokerSelection != nil {
				t.Fatal("empty uninitialized manager was reset")
			}
			var release func()
			old := getGateTestClient(t, m, &release)
			release()
			if len(m.clients) != 0 || len(m.selector.brokers) == 0 {
				t.Fatal("fixture did not leave cached selection without clients")
			}
			seed, currentBrokerSelection, changed := m.selector.seed, m.selector.currentBrokerSelection, m.changed
			m.config.SetTacticsAppliedReceivers([]TacticsAppliedReceiver{m})
			if err := setGateTestParameters(m.config, "new", map[string]interface{}{
				parameters.InproxyBrokerSpecs: parameters.InproxyBrokerSpecsValue{newProviderTestBroker(t, "C")},
			}); err != nil {
				t.Fatal(err)
			}
			if m.changed != changed || m.selector.currentBrokerSelection != currentBrokerSelection || len(m.clients) != 0 {
				t.Fatal("empty tactics callback performed a full reset")
			}
			fresh := getGateTestClient(t, m)
			if fresh.frontingProviderID != "C" || m.selector.seed != seed || fresh == old {
				t.Fatal("lazy initialization reused stale broker specs or changed session seed")
			}
			old.brokerResponseSucceededForTest(old.roundTripper)
			if m.sharedClient != nil {
				t.Fatal("stale response resurrected an old client")
			}
		})
	}
}

var _ net.Conn = (*inproxyBrokerOwnedConn)(nil)
var _ net.PacketConn = (*inproxyBrokerOwnedConn)(nil)

// brokerHTTPTestTransport is an HTTP round tripper backed by a function,
// used to replace a broker client's transport with scripted responses.
type brokerHTTPTestTransport func(*http.Request) (*http.Response, error)

func (f brokerHTTPTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func (brokerHTTPTestTransport) CloseIdleConnections()                               {}

// brokerDeadlineTestBody is a response body whose Read blocks until ctx is
// done and then returns the context error, simulating a stalled body read.
type brokerDeadlineTestBody struct{ ctx context.Context }

func (b brokerDeadlineTestBody) Read([]byte) (int, error) { <-b.ctx.Done(); return 0, b.ctx.Err() }
func (brokerDeadlineTestBody) Close() error               { return nil }

// TestInproxyBrokerAbortedInitialDialCleanup verifies that caller
// cancellation during a broker client's one-shot initial dial caches a
// non-transport error, that a direct retry returns that error, and that the
// unshared client is closed and removed on release without affecting another
// caller's client, so a later acquisition constructs a fresh client.
func TestInproxyBrokerAbortedInitialDialCleanup(t *testing.T) {
	m := newGateTestManager(t)
	var releaseFirst, releaseOther func()
	first := getGateTestClient(t, m, &releaseFirst)
	other := getGateTestClient(t, m, &releaseOther)
	if first == other || m.clients[first].refs != 1 || m.clients[other].refs != 1 {
		t.Fatal("manager reused an unproven broker client")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := first.roundTripper.RoundTrip(ctx, 0, time.Second, nil)
	var failure *inproxy.RoundTripperFailedError
	if err == nil || stderrors.As(err, &failure) || first.roundTripper.dialErr == nil {
		t.Fatalf("caller-aborted initial dial did not cache an unclassified error: %v", err)
	}
	if m.sharedClient != nil || m.clients[first].refs != 1 {
		t.Fatal("aborted initial dial became shared or changed ownership")
	}

	// A direct retry on the same transport returns the cached error. The
	// manager must instead discard this unshared client when its caller
	// releases.
	retryCtx, stopRetry := context.WithTimeout(context.Background(), time.Second)
	defer stopRetry()
	_, err = first.roundTripper.RoundTrip(retryCtx, 0, time.Second, nil)
	if err == nil || stderrors.As(err, &failure) || !stderrors.Is(err, first.roundTripper.dialErr) {
		t.Fatalf("retry did not return the cached unclassified dial error: %v", err)
	}
	releaseFirst()
	if m.clients[first] != nil || first.roundTripper.runCtx.Err() == nil {
		t.Fatal("release retained the unusable broker client")
	}
	if other.roundTripper.runCtx.Err() != nil {
		t.Fatal("cleanup interrupted another caller's broker client")
	}
	fresh := getGateTestClient(t, m)
	if fresh == first || fresh == other || fresh.roundTripper.dialErr != nil {
		t.Fatal("subsequent acquisition reused an unshared client or its cached error")
	}
	releaseOther()
}

// TestInproxyBrokerCallerDeadline verifies that a caller deadline during the
// initial dial, the request or the response body read is classified as a
// transport failure, like a per-request timeout with a live caller: it
// unshares the client, marks it failed and deletes its replay record. A
// caller's explicit cancellation in the same phases is not a failure and
// leaves sharing and replay untouched. The request and body phases drive a
// real broker API request through inproxy.BrokerClient, so its
// RoundTripperFailedError classification, not the test, decides whether
// BrokerClientRoundTripperFailed is invoked.
func TestInproxyBrokerCallerDeadline(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		t.Run(fmt.Sprintf("dial/cancelled=%v", cancelled), func(t *testing.T) {
			m := newGateTestManager(t)
			c := getGateTestClient(t, m)
			var ctx context.Context
			var cancel context.CancelFunc
			if cancelled {
				ctx, cancel = context.WithCancel(context.Background())
				cancel()
			} else {
				ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			}
			defer cancel()
			_, err := c.roundTripper.RoundTrip(ctx, 0, time.Second, nil)
			var failure *inproxy.RoundTripperFailedError
			if err == nil || stderrors.As(err, &failure) == cancelled {
				t.Fatalf("incorrect classification of caller-ended initial dial: %v", err)
			}
		})
	}
	payload, err := inproxy.MarshalClientRelayedPacketResponse(&inproxy.ClientRelayedPacketResponse{PacketToServer: []byte("reply")})
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"request", "body"} {
		for _, ending := range []string{"request-timeout", "caller-deadline", "caller-cancel"} {
			t.Run(phase+"/"+ending, func(t *testing.T) {
				m, c, release := newBrokerResponseTestClient(t, payload)
				defer release()
				c.replayRetainFailedProbability = 0
				// Establish the Noise session and share the client with a
				// real round trip, so the stalled request below is an API
				// request on an established session.
				sessionCtx, cancelSession := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancelSession()
				if _, err := c.brokerClient.ClientRelayedPacket(sessionCtx, &inproxy.ClientRelayedPacketRequest{}); err != nil {
					t.Fatal(err)
				}
				if m.sharedClient != c || loadBrokerReplayTestParameters(t, c.brokerDialParams.brokerSpec) == nil {
					t.Fatal("session request did not share the client and store replay")
				}
				c.roundTripper.conn.transport = brokerHTTPTestTransport(func(req *http.Request) (*http.Response, error) {
					if phase == "body" {
						return &http.Response{StatusCode: http.StatusOK, Body: brokerDeadlineTestBody{req.Context()}}, nil
					}
					<-req.Context().Done()
					return nil, req.Context().Err()
				})
				c.relayedPacketRequestTimeout = time.Second
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				switch ending {
				case "request-timeout":
					c.relayedPacketRequestTimeout = 20 * time.Millisecond
				case "caller-deadline":
					ctx, cancel = context.WithTimeout(ctx, 20*time.Millisecond)
					defer cancel()
				case "caller-cancel":
					time.AfterFunc(20*time.Millisecond, cancel)
				}
				_, err := c.brokerClient.ClientRelayedPacket(ctx, &inproxy.ClientRelayedPacketRequest{})
				wantFailure := ending != "caller-cancel"
				var failure *inproxy.RoundTripperFailedError
				if err == nil || stderrors.As(err, &failure) != wantFailure {
					t.Fatalf("incorrect failure classification: %v", err)
				}
				stored := loadBrokerReplayTestParameters(t, c.brokerDialParams.brokerSpec)
				if (stored == nil) != wantFailure || (m.sharedClient != c) != wantFailure ||
					m.clients[c].failed != wantFailure {
					t.Fatalf("incorrect sharing/replay: stored=%v shared=%v failed=%v",
						stored != nil, m.sharedClient == c, m.clients[c].failed)
				}
			})
		}
	}
}

// TestInproxyBrokerCloseRaceNotTransportFailure verifies that a request
// failing because the round tripper was closed is not classified as a
// transport failure, even when the request observes the connection error
// before the merged request context has been cancelled. Close cancels
// rt.runCtx synchronously but the merged context is cancelled from it
// asynchronously, so the transport error can race ahead of ctx.Err(). The
// request must return a plain error, BrokerClientRoundTripperFailed must not
// run, no failure must be recorded on the round tripper, and the stored
// replay record must survive. Each of the three classification points after
// the dial is exercised: request error, fast non-200 response, and response
// body read error.
func TestInproxyBrokerCloseRaceNotTransportFailure(t *testing.T) {
	for _, phase := range []string{"request", "status", "body"} {
		t.Run(phase, func(t *testing.T) {
			payload, err := inproxy.MarshalClientRelayedPacketResponse(&inproxy.ClientRelayedPacketResponse{})
			if err != nil {
				t.Fatal(err)
			}
			m, c, release := newBrokerResponseTestClient(t, payload)
			defer release()
			c.replayRetainFailedProbability = 0
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			// Establish the session and store replay with a real round
			// trip, so a misclassified failure would have a record to
			// delete.
			if _, err := c.brokerClient.ClientRelayedPacket(ctx, &inproxy.ClientRelayedPacketRequest{}); err != nil {
				t.Fatal(err)
			}
			spec := c.brokerDialParams.brokerSpec
			if m.sharedClient != c || loadBrokerReplayTestParameters(t, spec) == nil {
				t.Fatal("session request did not share the client and store replay")
			}

			// The transport cancels rt.runCtx, as Close does first, and
			// returns the error a closed connection would produce on the
			// same goroutine. The merged request context is cancelled
			// from rt.runCtx by an AfterFunc goroutine that has not run
			// yet, so the classification code observes ctx.Err() == nil
			// with rt.runCtx already cancelled: the exact race window.
			c.roundTripper.conn.transport = brokerHTTPTestTransport(func(req *http.Request) (*http.Response, error) {
				c.roundTripper.stopRunning()
				switch phase {
				case "status":
					return &http.Response{StatusCode: http.StatusBadGateway,
						Body: io.NopCloser(bytes.NewReader(nil))}, nil
				case "body":
					return &http.Response{StatusCode: http.StatusOK,
						Body: brokerCloseTestBody{}}, nil
				}
				return nil, stderrors.New("use of closed network connection")
			})
			// A large failure threshold makes any non-200 "fast".
			c.roundTripper.failureThreshold = time.Hour

			_, err = c.roundTripper.RoundTrip(ctx, 0, time.Second, []byte("request"))
			var failure *inproxy.RoundTripperFailedError
			if err == nil || stderrors.As(err, &failure) {
				t.Fatalf("request on closed round tripper classified as transport failure: %v", err)
			}
			if c.roundTripper.failure.Load() != nil {
				t.Fatal("close race recorded a transport failure")
			}
			if loadBrokerReplayTestParameters(t, spec) == nil {
				t.Fatal("close race deleted the replay record")
			}
			// The interrupted request is marked as closed under the
			// caller, so a tunnel dial it belonged to is not
			// attributed to the server entry.
			var closed *inproxyBrokerClientClosedError
			if !stderrors.As(err, &closed) || isServerEntryFailure(context.Background(), err) {
				t.Fatalf("request on closed round tripper attributed to the server entry: %v", err)
			}
		})
	}
}

// TestInproxyBrokerCallerCancelNotClosedError verifies that a request
// failing on the caller's own cancellation is not marked as closed under
// the caller, so the caller-cancel and broker-client-closed cases remain
// distinguishable to dialTunnel's attribution.
func TestInproxyBrokerCallerCancelNotClosedError(t *testing.T) {
	payload, err := inproxy.MarshalClientRelayedPacketResponse(&inproxy.ClientRelayedPacketResponse{})
	if err != nil {
		t.Fatal(err)
	}
	_, c, release := newBrokerResponseTestClient(t, payload)
	defer release()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := c.brokerClient.ClientRelayedPacket(ctx, &inproxy.ClientRelayedPacketRequest{}); err != nil {
		t.Fatal(err)
	}
	requestCtx, cancelRequest := context.WithCancel(context.Background())
	c.roundTripper.conn.transport = brokerHTTPTestTransport(func(req *http.Request) (*http.Response, error) {
		cancelRequest()
		return nil, stderrors.New("use of closed network connection")
	})
	_, err = c.roundTripper.RoundTrip(requestCtx, 0, time.Second, []byte("request"))
	var closed *inproxyBrokerClientClosedError
	var failure *inproxy.RoundTripperFailedError
	if err == nil || stderrors.As(err, &closed) || stderrors.As(err, &failure) {
		t.Fatalf("caller cancellation misclassified: %v", err)
	}
}

// brokerCloseTestBody is a response body whose Read fails as a closed
// connection would.
type brokerCloseTestBody struct{}

func (brokerCloseTestBody) Read([]byte) (int, error) {
	return 0, stderrors.New("use of closed network connection")
}
func (brokerCloseTestBody) Close() error { return nil }

// TestInproxyBrokerFailurePreservesInflightRequest verifies, through the
// real broker client API path, that a transport failure on one request
// unshares the broker client without interrupting a concurrent request on
// it, that the surviving request's success cannot make the failed client
// shared again, and that the client closes on its final release.
func TestInproxyBrokerFailurePreservesInflightRequest(t *testing.T) {
	payload, err := inproxy.MarshalClientRelayedPacketResponse(&inproxy.ClientRelayedPacketResponse{PacketToServer: []byte("reply")})
	if err != nil {
		t.Fatal(err)
	}
	m, c, first := newBrokerResponseTestClient(t, payload)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Establish the session before making concurrent API requests.
	if _, err := c.brokerClient.ClientRelayedPacket(ctx, &inproxy.ClientRelayedPacketRequest{}); err != nil {
		t.Fatal(err)
	}
	var second func()
	if getGateTestClient(t, m, &second) != c {
		t.Fatal("not shared")
	}
	underlying := c.roundTripper.conn.transport
	started, finish := make(chan struct{}), make(chan struct{})
	var once sync.Once
	c.roundTripper.conn.transport = brokerHTTPTestTransport(func(req *http.Request) (*http.Response, error) {
		blocked := false
		once.Do(func() { blocked = true; close(started) })
		if !blocked {
			return nil, stderrors.New("one stream failed")
		}
		select {
		case <-finish:
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
		return underlying.RoundTrip(req)
	})
	result := make(chan error, 1)
	go func() {
		_, err := c.brokerClient.ClientRelayedPacket(ctx, &inproxy.ClientRelayedPacketRequest{})
		result <- err
	}()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if _, err := c.brokerClient.ClientRelayedPacket(ctx, &inproxy.ClientRelayedPacketRequest{}); err == nil {
		t.Fatal("expected failure")
	}
	first()
	close(finish)
	if err := <-result; err != nil {
		t.Fatalf("other worker interrupted: %v", err)
	}
	if m.sharedClient != nil {
		t.Fatal("late success re-promoted retired client")
	}
	second()
	if c.roundTripper.runCtx.Err() == nil {
		t.Fatal("final release did not close client")
	}
}

// expireSharedClientForTest exercises idle expiry deterministically after
// the test has released every lease. It requires the shared idle timer to be
// armed: a non-proxy manager, a nonzero idle timeout, and instance shared
// with zero leases. Otherwise expireSharedClientLocked is a no-op.
func expireSharedClientForTest(m *InproxyBrokerClientManager, instance *InproxyBrokerClientInstance) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.expireSharedClientLocked(instance, m.sharedIdleTimer)
}

// TestInproxyBrokerFailureDrainsLeases verifies broker client reclamation
// after a transport failure: a shared client with leases is unshared and
// marked failed but stays open until its last release, a late response
// cannot make it shared again, a shared client with no leases closes at
// once, and an unshared failed client drains until released or reset.
func TestInproxyBrokerFailureDrainsLeases(t *testing.T) {
	m := newGateTestManager(t)
	var first, second func()
	c := getGateTestClient(t, m, &first)
	c.brokerResponseSucceededForTest(c.roundTripper)
	if getGateTestClient(t, m, &second) != c {
		t.Fatal("not shared")
	}
	m.brokerClientFailed(c)
	first()
	// A repeated failure report for an already-failed client is a no-op: it
	// must not wake waiters again. With the client limit lowered so the
	// draining client fills it, a new acquisition blocks on b.changed; the
	// repeated failure must leave that channel untouched so the waiter
	// stays blocked.
	if err := setGateTestParameters(m.config, "", map[string]interface{}{
		parameters.InproxyClientMaxBrokerClients: 1,
	}); err != nil {
		t.Fatal(err)
	}
	waiterCtx, cancelWaiter := context.WithCancel(context.Background())
	defer cancelWaiter()
	waiterDone := make(chan error, 1)
	go func() {
		_, _, release, err := m.GetBrokerClient(waiterCtx, "TEST")
		if err == nil {
			release()
		}
		waiterDone <- err
	}()
	// The waiter creates b.changed when it parks. Allow it to reach the
	// select, then confirm it did not acquire (the limit is full) and
	// capture the channel it parked on.
	time.Sleep(20 * time.Millisecond)
	select {
	case err := <-waiterDone:
		t.Fatalf("acquisition did not park on the full gate: %v", err)
	default:
	}
	m.mutex.Lock()
	changed := m.changed
	m.mutex.Unlock()
	if changed == nil {
		t.Fatal("parked acquisition did not create the wait channel")
	}
	m.brokerClientFailed(c)
	m.mutex.Lock()
	sameChannel := m.changed == changed
	m.mutex.Unlock()
	if !sameChannel {
		t.Fatal("repeated failure signalled waiters")
	}
	select {
	case err := <-waiterDone:
		t.Fatalf("repeated failure woke the parked acquisition: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	cancelWaiter()
	if err := <-waiterDone; err == nil {
		t.Fatal("parked acquisition did not return on cancel")
	}
	c.BrokerClientResponseReceived(c.roundTripper, false)
	if c.roundTripper.runCtx.Err() != nil || m.sharedClient != nil || !m.clients[c].failed {
		t.Fatal("failure interrupted another lease or late response promoted")
	}
	// The remaining worker can still use the transport until it releases.
	second()
	if c.roundTripper.runCtx.Err() == nil || m.clients[c] != nil {
		t.Fatal("retired client did not close on final release")
	}
	var release func()
	c = getGateTestClient(t, m, &release)
	c.brokerResponseSucceededForTest(c.roundTripper)
	release()
	m.brokerClientFailed(c)
	if c.roundTripper.runCtx.Err() == nil {
		t.Fatal("zero-lease failed client did not close immediately")
	}
	c = getGateTestClient(t, m)
	m.brokerClientFailed(c)
	m.closeClientBrokerClients()
	if c.roundTripper.runCtx.Err() == nil {
		t.Fatal("reset did not close draining client")
	}
}

// TestInproxyBrokerSharedIdleTimer verifies that the last release of a shared
// client arms InproxyClientBrokerClientIdleTimeout only for a client manager
// with a nonzero timeout, that acquisition stops the timer, that a callback
// holding a stopped or replaced timer pointer closes nothing, and that the
// live timer closes the idle shared client and clears shared state.
func TestInproxyBrokerSharedIdleTimer(t *testing.T) {
	for _, mode := range []string{"client", "disabled", "proxy"} {
		t.Run(mode, func(t *testing.T) {
			m := newGateTestManager(t)
			m.isProxy = mode == "proxy"
			// The live timer is long enough that scheduling delays
			// under the race detector cannot fire it before the
			// stale-pointer checks run; the final wait allows for
			// it.
			timeout := "250ms"
			if mode == "disabled" {
				timeout = "0s"
			}
			if err := setGateTestParameters(m.config, "", map[string]interface{}{
				parameters.InproxyClientBrokerClientIdleTimeout: timeout,
			}); err != nil {
				t.Fatal(err)
			}
			var release func()
			c := getGateTestClient(t, m, &release)
			c.brokerResponseSucceededForTest(c.roundTripper)
			m.mutex.Lock()
			armedWithLease := m.sharedIdleTimer != nil
			m.mutex.Unlock()
			if armedWithLease {
				t.Fatal("active lease armed timer")
			}
			release()
			m.mutex.Lock()
			armed := m.sharedIdleTimer != nil
			timer := m.sharedIdleTimer
			m.mutex.Unlock()
			if mode != "client" {
				if armed {
					t.Fatal("idle expiry should be disabled")
				}
				return
			}
			if !armed {
				t.Fatal("last release did not arm timer")
			}
			if getGateTestClient(t, m, &release) != c {
				t.Fatal("idle client not reused")
			}
			m.mutex.Lock()
			m.expireSharedClientLocked(c, timer)
			m.mutex.Unlock()
			if c.roundTripper.runCtx.Err() != nil {
				t.Fatal("stale timer closed active client")
			}
			release()
			m.mutex.Lock()
			m.expireSharedClientLocked(c, timer)
			m.mutex.Unlock()
			if c.roundTripper.runCtx.Err() != nil {
				t.Fatal("stale timer ended new idle period")
			}
			select {
			case <-c.roundTripper.runCtx.Done():
			case <-time.After(5 * time.Second):
				t.Fatal("idle timer did not close client without acquisition")
			}
			m.mutex.Lock()
			defer m.mutex.Unlock()
			if m.sharedClient != nil || m.sharedIdleTimer != nil {
				t.Fatal("expiry retained shared state")
			}
		})
	}
}

// TestInproxyBrokerIdleTimerReset verifies that a reset stops the armed idle
// timer and that the stale callback for the closed client, run after a new
// client becomes shared, closes nothing and leaves the new shared client and
// timer state untouched.
func TestInproxyBrokerIdleTimerReset(t *testing.T) {
	m := newGateTestManager(t)
	var release func()
	c := getGateTestClient(t, m, &release)
	c.brokerResponseSucceededForTest(c.roundTripper)
	release()
	m.mutex.Lock()
	timer := m.sharedIdleTimer
	m.mutex.Unlock()
	m.closeClientBrokerClients()
	next := getGateTestClient(t, m)
	next.brokerResponseSucceededForTest(next.roundTripper)
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.expireSharedClientLocked(c, timer)
	if m.sharedIdleTimer != nil || m.sharedClient != next || next.roundTripper.runCtx.Err() != nil {
		t.Fatal("reset left a timer or stale callback disrupted new client")
	}
}

// TestInproxyMetricsBeforeBrokerAcquisition verifies that GetInproxyMetrics
// reports STUN and WebRTC metrics but no broker metrics before dialInproxy
// acquires a broker client, as NoticeConnectingServer reads them, and reports
// broker metrics once the acquired dial parameter snapshot is stored.
func TestInproxyMetricsBeforeBrokerAcquisition(t *testing.T) {
	params := &DialParameters{
		inproxyDialInitialized:      true,
		InproxySTUNDialParameters:   &InproxySTUNDialParameters{STUNServerAddress: "stun.example.org:3478"},
		InproxyWebRTCDialParameters: &InproxyWebRTCDialParameters{DTLSFingerprint: "test-fingerprint"},
	}
	params.InproxySTUNDialParameters.STUNServerResolvedIPAddress.Store("")
	params.InproxySTUNDialParameters.STUNServerRFC5780ResolvedIPAddress.Store("")
	// NoticeConnectingServer reads these before dialInproxy acquires a
	// broker.
	metrics := params.GetInproxyMetrics()
	if _, ok := metrics["inproxy_broker_is_reuse"]; ok {
		t.Fatal("reported broker metrics before acquisition")
	}
	if metrics["inproxy_webrtc_stun_server"] != "stun.example.org:3478" ||
		metrics["inproxy_webrtc_dtls_fingerprint"] != "test-fingerprint" {
		t.Fatal("missing pre-acquisition WebRTC metrics")
	}
	m := newGateTestManager(t)
	_, snapshot, release, err := m.GetBrokerClient(context.Background(), "TEST")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	params.inproxyBrokerDialParameters = snapshot
	if params.GetInproxyMetrics()["inproxy_broker_is_reuse"] != "0" {
		t.Fatal("missing broker metrics after acquisition")
	}
}

// TestInproxyBrokerRacingMetrics verifies the handshake and broker-request
// metrics that identify which broker client a tunnel used and what its
// acquisition cost: candidate numbers are creation ordinals within the
// broker client manager's counting window and continue past M, a new
// client reports no reuse and no wait, a reused client reports reuse with
// the winner's ordinal, an acquisition parked at the limit reports its
// wait, every candidate's broker requests carry its replay flag and
// ordinal, and that
// takeBrokerClientCounts reports the window's creations and peak, restarts
// the ordinal, and seeds the next window's peak with the clients still
// tracked.
func TestInproxyBrokerRacingMetrics(t *testing.T) {
	m := newGateTestManager(t)
	var releaseA, releaseB func()
	a, b := getGateTestClient(t, m, &releaseA), getGateTestClient(t, m, &releaseB)
	metrics := func(dialParams *InproxyBrokerDialParameters) common.LogFields {
		return dialParams.GetMetrics()
	}
	acquire := func(ctx context.Context) (*InproxyBrokerClientInstance, *InproxyBrokerDialParameters, func()) {
		t.Helper()
		client, dialParams, release, err := m.GetBrokerClient(ctx, "TEST")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(release)
		return client.GetBrokerDialCoordinator().(*InproxyBrokerClientInstance), dialParams, release
	}
	if a.candidateNumber != 1 || b.candidateNumber != 2 {
		t.Fatalf("candidate numbers %d, %d", a.candidateNumber, b.candidateNumber)
	}
	for i, c := range []*InproxyBrokerClientInstance{a, b} {
		fields := c.MetricsForBrokerRequests()
		if fields["inproxy_broker_candidate_number"] != strconv.Itoa(i+1) || fields["inproxy_broker_is_replay"] != "0" {
			t.Fatalf("broker request metrics for candidate %d: %v", i+1, fields)
		}
	}
	// A third acquisition parks at M=2 until b is shared, then reuses b
	// and reports the wait, b's ordinal and shared status.
	parent, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx := &inproxyGateWaitContext{Context: parent, waiting: make(chan struct{})}
	type result struct {
		instance   *InproxyBrokerClientInstance
		dialParams *InproxyBrokerDialParameters
		release    func()
	}
	results := make(chan result, 1)
	go func() {
		instance, dialParams, release := acquire(ctx)
		results <- result{instance, dialParams, release}
	}()
	select {
	case <-ctx.waiting:
	case <-parent.Done():
		t.Fatal("acquisition did not wait at the limit")
	}
	time.Sleep(10 * time.Millisecond)
	b.brokerResponseSucceededForTest(b.roundTripper)
	var waited result
	select {
	case waited = <-results:
	case <-parent.Done():
		t.Fatal("parked acquisition did not wake")
	}
	fields := metrics(waited.dialParams)
	if waited.instance != b || fields["inproxy_broker_is_reuse"] != "1" ||
		fields["inproxy_broker_candidate_number"] != "2" {
		t.Fatalf("reused client metrics: %v", fields)
	}
	if waitMs, err := strconv.Atoi(fields["inproxy_broker_acquire_wait_ms"].(string)); err != nil || waitMs < 10 {
		t.Fatalf("parked acquisition wait not reported: %v", fields["inproxy_broker_acquire_wait_ms"])
	}
	// A fresh candidate after the first two close continues the ordinal
	// past M and reports no reuse.
	releaseA()
	releaseB()
	waited.release()
	m.brokerClientFailed(b)
	c, cDialParams, releaseC := acquire(context.Background())
	fields = metrics(cDialParams)
	if c.candidateNumber != 3 || fields["inproxy_broker_candidate_number"] != "3" ||
		fields["inproxy_broker_is_reuse"] != "0" {
		t.Fatalf("fresh candidate metrics: %v", fields)
	}
	releaseC()
	if created, peak := m.takeBrokerClientCounts(); created != 3 || peak != 2 {
		t.Fatalf("window counts created=%d peak=%d, want 3, 2", created, peak)
	}
	d, _, _ := acquire(context.Background())
	if d.candidateNumber != 1 {
		t.Fatalf("candidate number did not restart after reset: %d", d.candidateNumber)
	}
	// d is still tracked when the window is taken, so the next window's
	// peak starts at one even though it creates nothing.
	if created, peak := m.takeBrokerClientCounts(); created != 1 || peak != 1 {
		t.Fatalf("second window counts created=%d peak=%d, want 1, 1", created, peak)
	}
	if created, peak := m.takeBrokerClientCounts(); created != 0 || peak != 1 {
		t.Fatalf("window with no creations created=%d peak=%d, want 0, 1", created, peak)
	}
	var nilManager *InproxyBrokerClientManager
	if created, peak := nilManager.takeBrokerClientCounts(); created != 0 || peak != 0 {
		t.Fatal("nil manager counts")
	}
}

// inproxyGateWaitContext closes waiting the first time Done is called, which
// GetBrokerClient does only when it blocks, so tests observe the wait
// deterministically without sleeps.
type inproxyGateWaitContext struct {
	context.Context
	once    sync.Once
	waiting chan struct{}
}

func (c *inproxyGateWaitContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.Context.Done()
}

// inproxyCancelBeforeReturnContext cancels on the second Err call, which
// matches GetBrokerClient's final check after its blocking select.
type inproxyCancelBeforeReturnContext struct {
	context.Context
	cancel context.CancelFunc
	checks int
}

func (c *inproxyCancelBeforeReturnContext) Err() error {
	c.checks++
	if c.checks == 2 {
		c.cancel()
	}
	return c.Context.Err()
}

// TestInproxyBrokerAcquisitionCancellation verifies that a context canceled
// at GetBrokerClient's final check returns an error and no release, and that
// the manager releases the unreturned lease itself: a fresh candidate is
// closed and removed, and a shared client keeps its original lease count.
func TestInproxyBrokerAcquisitionCancellation(t *testing.T) {
	for _, shared := range []bool{false, true} {
		name := "candidate"
		if shared {
			name = "shared"
		}
		t.Run(name, func(t *testing.T) {
			m := newGateTestManager(t)
			var existing *InproxyBrokerClientInstance
			if shared {
				existing = getGateTestClient(t, m)
				existing.brokerResponseSucceededForTest(existing.roundTripper)
			}
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx := &inproxyCancelBeforeReturnContext{Context: parent, cancel: cancel}
			client, _, release, err := m.GetBrokerClient(ctx, "TEST")
			if client != nil || release != nil || !stderrors.Is(err, context.Canceled) {
				t.Fatalf("canceled acquisition: %v", err)
			}
			if shared {
				if m.sharedClient != existing || m.clients[existing].refs != 1 {
					t.Fatal("canceled acquisition disturbed the original lease")
				}
			} else if len(m.clients) != 0 {
				t.Fatal("unreturned acquisition leaked a client")
			}
		})
	}
}

// TestInproxyBrokerLeaseLifetime verifies lease accounting across one
// client's lifetime: the acquisition context does not own the transport,
// promotion does not close competitors, a failed shared client is not
// replaced by a competitor's earlier success, release is idempotent, shared
// reuse adds leases rather than clients, and late releases and responses
// after a reset resurrect nothing.
func TestInproxyBrokerLeaseLifetime(t *testing.T) {
	m := newGateTestManager(t)
	var releaseA func()
	a := getGateTestClient(t, m, &releaseA)
	ctx, cancel := context.WithCancel(context.Background())
	client, _, release, err := m.GetBrokerClient(ctx, "TEST")
	if err != nil {
		t.Fatal(err)
	}
	b := client.GetBrokerDialCoordinator().(*InproxyBrokerClientInstance)
	cancel()
	a.brokerResponseSucceededForTest(a.roundTripper)
	b.brokerResponseSucceededForTest(b.roundTripper)
	if b.roundTripper.runCtx.Err() != nil || len(m.clients) != 2 || m.sharedClient != a {
		t.Fatal("cancellation/promotion interrupted an independent lease")
	}
	a.BrokerClientRoundTripperFailed(a.roundTripper)
	releaseA()
	if m.sharedClient != nil {
		t.Fatal("historical success promoted automatically")
	}
	b.brokerResponseSucceededForTest(b.roundTripper)
	release()
	release()
	if m.sharedClient != b || m.clients[b].refs != 0 || b.roundTripper.runCtx.Err() != nil {
		t.Fatal("release closed a promoted client or was not idempotent")
	}
	_, _, r1, err := m.GetBrokerClient(context.Background(), "TEST")
	if err != nil {
		t.Fatal(err)
	}
	_, _, r2, err := m.GetBrokerClient(context.Background(), "TEST")
	if err != nil {
		t.Fatal(err)
	}
	if m.clients[b].refs != 2 || len(m.clients) != 1 {
		t.Fatal("shared reuse allocated slots rather than leases")
	}
	r1()
	r1()
	r2()
	if m.clients[b].refs != 0 {
		t.Fatal("lease accounting corrupted")
	}
	m.closeClientBrokerClients()
	release()
	r1()
	r2()
	b.brokerResponseSucceededForTest(b.roundTripper)
	if len(m.clients) != 0 || m.sharedClient != nil {
		t.Fatal("late releases/responses resurrected reset state")
	}
}

// TestInproxyBrokerConcurrentPromotionCleanup verifies, over repeated runs,
// that concurrent release, decoded-response promotion and reset of one
// candidate always end in a consistent state: either the client is shared,
// open and tracked with zero leases, or it is closed and untracked.
func TestInproxyBrokerConcurrentPromotionCleanup(t *testing.T) {
	m := newGateTestManager(t)
	for i := 0; i < 100; i++ {
		var release func()
		c := getGateTestClient(t, m, &release)
		start := make(chan struct{})
		var wg sync.WaitGroup
		ops := []func(){release, func() { c.brokerResponseSucceededForTest(c.roundTripper) }}
		if i%2 == 0 {
			ops = append(ops, m.closeClientBrokerClients)
		}
		for _, op := range ops {
			wg.Add(1)
			go func(op func()) { defer wg.Done(); <-start; op() }(op)
		}
		close(start)
		wg.Wait()
		if m.sharedClient != nil {
			if m.sharedClient != c || c.roundTripper.runCtx.Err() != nil || len(m.clients) != 1 || m.clients[c].refs != 0 {
				t.Fatal("invalid shared race outcome")
			}
		} else if len(m.clients) != 0 || c.roundTripper.runCtx.Err() == nil {
			t.Fatal("release/reset leaked candidate")
		}
		m.closeClientBrokerClients()
	}
}

// TestInproxyBrokerConcurrentSharedLeases verifies that many acquisitions of
// the shared client add leases to one registry entry and that concurrent,
// repeated releases bring the count to zero without closing the shared
// client.
func TestInproxyBrokerConcurrentSharedLeases(t *testing.T) {
	m := newGateTestManager(t)
	var ownerRelease func()
	shared := getGateTestClient(t, m, &ownerRelease)
	shared.brokerResponseSucceededForTest(shared.roundTripper)
	ownerRelease()
	var releases []func()
	for i := 0; i < 32; i++ {
		client, _, release, err := m.GetBrokerClient(context.Background(), "TEST")
		if err != nil || client != shared.brokerClient {
			t.Fatalf("shared acquisition failed: %v", err)
		}
		releases = append(releases, release)
	}
	if len(m.clients) != 1 || m.clients[shared].refs != len(releases) {
		t.Fatal("shared leases consumed additional client slots")
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	for _, release := range releases {
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go func(release func()) { defer wg.Done(); <-start; release() }(release)
		}
	}
	close(start)
	wg.Wait()
	if m.clients[shared].refs != 0 || shared.roundTripper.runCtx.Err() != nil {
		t.Fatal("concurrent releases corrupted shared ownership")
	}
}

// TestInproxyBrokerTotalClientLimit verifies M admission without a tactics
// callback: lowering M does not evict live clients, the shared client is
// still reused at capacity, a failed client draining its leases and a held
// non-shared client both count toward M, and releasing a held client's last
// lease closes it and wakes a waiting acquisition.
func TestInproxyBrokerTotalClientLimit(t *testing.T) {
	m := newGateTestManager(t)
	if err := setGateTestParameters(m.config, "three", map[string]interface{}{parameters.InproxyClientMaxBrokerClients: 3}); err != nil {
		t.Fatal(err)
	}
	var releaseA, releaseShared func()
	a := getGateTestClient(t, m, &releaseA)
	var releaseB, releaseC func()
	b := getGateTestClient(t, m, &releaseB)
	c := getGateTestClient(t, m, &releaseC)
	a.brokerResponseSucceededForTest(a.roundTripper)
	// Exercise admission separately from the reset performed by
	// TacticsApplied. This fixture deliberately has no registered tactics
	// receiver.
	if err := setGateTestParameters(m.config, "one", map[string]interface{}{parameters.InproxyClientMaxBrokerClients: 1}); err != nil {
		t.Fatal(err)
	}
	shared := getGateTestClient(t, m, &releaseShared)
	m.mutex.Lock()
	tracked := len(m.clients)
	m.mutex.Unlock()
	if shared != a || tracked != 3 || b.roundTripper.runCtx.Err() != nil || c.roundTripper.runCtx.Err() != nil {
		t.Fatal("lowered cap evicted live work")
	}
	// A failed client draining its leases still occupies the limit.
	a.BrokerClientRoundTripperFailed(a.roundTripper)
	releaseB()
	releaseC()
	if instance, _, changed, err := m.tryGetClientBrokerClient("TEST"); err != nil || instance != nil || changed == nil {
		t.Fatal("draining failed client not counted against M")
	}
	releaseA()
	releaseShared()
	if a.roundTripper.runCtx.Err() == nil {
		t.Fatal("draining client not closed on last release")
	}
	c = getGateTestClient(t, m, &releaseC)
	if instance, _, changed, err := m.tryGetClientBrokerClient("TEST"); err != nil || instance != nil || changed == nil {
		t.Fatal("remaining lease not counted against M")
	}
	parent, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx := &inproxyGateWaitContext{Context: parent, waiting: make(chan struct{})}
	result := make(chan error, 1)
	go func() {
		_, _, release, err := m.GetBrokerClient(ctx, "TEST")
		if err == nil {
			release()
		}
		result <- err
	}()
	select {
	case <-ctx.waiting:
	case <-parent.Done():
		t.Fatal("acquisition did not wait")
	}
	releaseC()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-parent.Done():
		t.Fatal("last lease release did not wake acquisition")
	}
}

// TestInproxyBrokerCapacityTacticsWake verifies that a delivered tactics
// callback raising M closes all live clients and wakes an acquisition
// blocked at the previous limit, which then constructs a new client.
func TestInproxyBrokerCapacityTacticsWake(t *testing.T) {
	m := newGateTestManager(t)
	a, b := getGateTestClient(t, m), getGateTestClient(t, m)
	parent, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx := &inproxyGateWaitContext{Context: parent, waiting: make(chan struct{})}
	result := make(chan error, 1)
	go func() {
		_, _, release, err := m.GetBrokerClient(ctx, "TEST")
		if err == nil {
			release()
		}
		result <- err
	}()
	select {
	case <-ctx.waiting:
	case <-parent.Done():
		t.Fatal("acquisition did not wait")
	}
	m.config.SetTacticsAppliedReceivers([]TacticsAppliedReceiver{m})
	if err := setGateTestParameters(m.config, "more", map[string]interface{}{parameters.InproxyClientMaxBrokerClients: 3}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-parent.Done():
		t.Fatal("M increase did not wake waiter")
	}
	if a.roundTripper.runCtx.Err() == nil || b.roundTripper.runCtx.Err() == nil {
		t.Fatal("capacity tactics callback did not close existing clients")
	}
}

// TestInproxyDialLocalFailureCleanup verifies that a dialInproxy failure
// after broker acquisition but before any broker request releases the lease:
// a fresh candidate is closed, a shared client keeps its other lease, and
// the broker dial parameters remain recorded for metrics.
func TestInproxyDialLocalFailureCleanup(t *testing.T) {
	for _, shared := range []bool{false, true} {
		t.Run(fmt.Sprint(shared), func(t *testing.T) {
			m := newGateTestManager(t)
			if err := setGateTestParameters(m.config, "local", map[string]interface{}{
				parameters.InproxyClientDiscoverNATProbability: 0.0,
				parameters.InproxyCommonCompartmentIDs:         parameters.InproxyCompartmentIDsValue{},
			}); err != nil {
				t.Fatal(err)
			}
			wantCount := 0
			var existing *InproxyBrokerClientInstance
			if shared {
				existing = getGateTestClient(t, m)
				existing.brokerResponseSucceededForTest(existing.roundTripper)
				wantCount = 1
			}
			params := &DialParameters{NetworkID: "TEST", TunnelProtocol: protocol.TunnelProtocolPlusInproxyWebRTC(protocol.TUNNEL_PROTOCOL_OBFUSCATED_SSH),
				ServerEntry: &protocol.ServerEntry{IpAddress: "127.0.0.1", InproxyOSSHPort: 4000, Capabilities: []string{protocol.GetCapability(protocol.TunnelProtocolPlusInproxyWebRTC(protocol.TUNNEL_PROTOCOL_OBFUSCATED_SSH))}}, inproxyBrokerClientManager: m}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := dialInproxy(ctx, m.config, params)
			if conn != nil || err == nil || !strings.Contains(err.Error(), "no compartment IDs") || params.inproxyBrokerDialParameters == nil || len(m.clients) != wantCount {
				t.Fatalf("local failure leaked broker lease: %v", err)
			}
			if shared && (m.sharedClient != existing || m.clients[existing].refs != 1) {
				t.Fatal("local failure disturbed shared lease")
			}
		})
	}
}

// TestInproxyDialBrokerAcquireFailureNotAttributed verifies that an
// in-proxy dial that fails while acquiring a broker client, before any
// request reaches a broker or the server, carries
// inproxyBrokerAcquireFailedError within its inproxyDialFailedError, and
// that dialTunnel's attribution predicate excludes it, so no failed tunnel
// is recorded against the server entry and its replay is not cleared. A
// local failure after acquisition remains attributable. Both acquisition
// failure causes are covered: the caller's deadline expiring while parked
// at the client limit, and no broker specs.
func TestInproxyDialBrokerAcquireFailureNotAttributed(t *testing.T) {
	newParams := func(m *InproxyBrokerClientManager) *DialParameters {
		return &DialParameters{NetworkID: "TEST", TunnelProtocol: protocol.TunnelProtocolPlusInproxyWebRTC(protocol.TUNNEL_PROTOCOL_OBFUSCATED_SSH),
			ServerEntry: &protocol.ServerEntry{IpAddress: "127.0.0.1", InproxyOSSHPort: 4000, Capabilities: []string{protocol.GetCapability(protocol.TunnelProtocolPlusInproxyWebRTC(protocol.TUNNEL_PROTOCOL_OBFUSCATED_SSH))}}, inproxyBrokerClientManager: m}
	}
	check := func(t *testing.T, err error, wantAcquire bool) {
		t.Helper()
		var acquireErr *inproxyBrokerAcquireFailedError
		var dialErr *inproxyDialFailedError
		isAcquire := stderrors.As(err, &acquireErr)
		isDial := stderrors.As(err, &dialErr)
		// Every dialInproxy error is an inproxyDialFailedError; an
		// acquisition failure is additionally found through the chain.
		if err == nil || isAcquire != wantAcquire || !isDial {
			t.Fatalf("error classification: acquire=%v dial=%v want acquire=%v: %v", isAcquire, isDial, wantAcquire, err)
		}
		live := context.Background()
		if isServerEntryFailure(live, err) == wantAcquire {
			t.Fatalf("attribution: attributable=%v for acquire=%v", !wantAcquire, wantAcquire)
		}
	}

	t.Run("deadline-at-gate", func(t *testing.T) {
		m := newGateTestManager(t)
		if err := setGateTestParameters(m.config, "", map[string]interface{}{
			parameters.InproxyClientMaxBrokerClients: 1,
		}); err != nil {
			t.Fatal(err)
		}
		// Another worker holds the only slot with an unproven client, so a
		// second dial parks at the gate until its deadline.
		getGateTestClient(t, m)
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		conn, err := dialInproxy(ctx, m.config, newParams(m))
		if conn != nil {
			t.Fatal("unexpected conn")
		}
		if !stderrors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expected deadline at the gate: %v", err)
		}
		check(t, err, true)
		if len(m.clients) != 1 {
			t.Fatal("parked dial created or leaked a client")
		}
	})

	t.Run("no-broker-specs", func(t *testing.T) {
		m := newGateTestManager(t)
		if err := setGateTestParameters(m.config, "", map[string]interface{}{
			parameters.InproxyBrokerSpecs: parameters.InproxyBrokerSpecsValue{},
		}); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := dialInproxy(ctx, m.config, newParams(m))
		check(t, err, true)
	})

	t.Run("local-failure-after-acquire", func(t *testing.T) {
		m := newGateTestManager(t)
		if err := setGateTestParameters(m.config, "", map[string]interface{}{
			parameters.InproxyClientDiscoverNATProbability: 0.0,
			parameters.InproxyCommonCompartmentIDs:         parameters.InproxyCompartmentIDsValue{},
		}); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := dialInproxy(ctx, m.config, newParams(m))
		check(t, err, false)
	})

	t.Run("cancelled-base-context", func(t *testing.T) {
		// Cancellation of the base context is never attributable,
		// regardless of error type.
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if isServerEntryFailure(ctx, stderrors.New("any")) {
			t.Fatal("cancelled base context attributed")
		}
	})
}

// TestInproxyQUICDialAddressParsedBeforeAcquire verifies that the QUIC
// in-proxy dial validates the destination address before acquiring a broker
// client, so a malformed address neither acquires a lease nor opens an
// in-proxy connection that would need closing on the error path.
func TestInproxyQUICDialAddressParsedBeforeAcquire(t *testing.T) {
	m := newGateTestManager(t)
	if err := setGateTestParameters(m.config, "", map[string]interface{}{
		parameters.InproxyClientDiscoverNATProbability: 0.0,
	}); err != nil {
		t.Fatal(err)
	}
	acquisitions := 0
	m.mutex.Lock()
	before := len(m.clients)
	m.mutex.Unlock()
	// The NAT state manager is set so that, were the dial to proceed past
	// the address parse, it would fail on an assertion here rather than a
	// nil dereference.
	params := &DialParameters{NetworkID: "TEST",
		TunnelProtocol:    protocol.TunnelProtocolPlusInproxyWebRTC(protocol.TUNNEL_PROTOCOL_QUIC_OBFUSCATED_SSH),
		DirectDialAddress: "missing-port",
		ServerEntry: &protocol.ServerEntry{IpAddress: "127.0.0.1", InproxyQUICPort: 4000,
			Capabilities: []string{protocol.GetCapability(protocol.TunnelProtocolPlusInproxyWebRTC(protocol.TUNNEL_PROTOCOL_QUIC_OBFUSCATED_SSH))}},
		inproxyBrokerClientManager: m, inproxyNATStateManager: NewInproxyNATStateManager(m.config)}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// The fixture is deliberately minimal: were the dial to acquire a
	// broker client and proceed into the WebRTC setup, it would fail
	// there. Report that as the ordering regression it represents rather
	// than as a crash.
	var err error
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("dial proceeded past the address parse into the in-proxy dial: %v", r)
			}
		}()
		_, err = dialTunnel(ctx, m.config, params)
	}()
	m.mutex.Lock()
	acquisitions = len(m.clients) - before
	m.mutex.Unlock()
	if acquisitions != 0 {
		t.Fatalf("malformed address acquired %d broker client(s)", acquisitions)
	}
	if err == nil || !strings.Contains(err.Error(), "missing port") {
		t.Fatalf("expected address parse error before dial: %v", err)
	}
}

// TestInproxyBrokerCompartmentIDsCachedUntilReset verifies that compartment
// IDs are prepared once per selector initialization: a same-tag parameter
// publication and shared-client loss leave new clients on the cached list,
// including an empty list, while TacticsApplied on an empty manager
// invalidates the cache so the next acquisition merges the new tactics IDs.
// Existing clients keep their original lists.
func TestInproxyBrokerCompartmentIDsCachedUntilReset(t *testing.T) {
	for _, empty := range []bool{false, true} {
		t.Run(fmt.Sprintf("empty=%v", empty), func(t *testing.T) {
			m := newGateTestManager(t)
			oldID, err := inproxy.MakeID()
			if err != nil {
				t.Fatal(err)
			}
			newID, err := inproxy.MakeID()
			if err != nil {
				t.Fatal(err)
			}
			initial := parameters.InproxyCompartmentIDsValue{oldID.String()}
			if empty {
				initial = parameters.InproxyCompartmentIDsValue{}
			}
			if err := setGateTestParameters(m.config, "same", map[string]interface{}{
				parameters.InproxyCommonCompartmentIDs: initial,
			}); err != nil {
				t.Fatal(err)
			}
			m.config.SetTacticsAppliedReceivers([]TacticsAppliedReceiver{m})
			var release func()
			first := getGateTestClient(t, m, &release)
			first.BrokerClientResponseReceived(first.roundTripper, false)
			release()
			// The same tag publishes parameters without notifying
			// the manager.
			if err := setGateTestParameters(m.config, "same", map[string]interface{}{
				parameters.InproxyCommonCompartmentIDs: parameters.InproxyCompartmentIDsValue{newID.String()},
			}); err != nil {
				t.Fatal(err)
			}
			m.brokerClientFailed(first)
			for i := 0; i < 2; i++ {
				c := getGateTestClient(t, m, &release)
				ids := c.CommonCompartmentIDs()
				if len(ids) != len(initial) || (!empty && ids[0] != oldID) {
					t.Fatal("shared loss or new selection refreshed compartment IDs without reset")
				}
				release()
			}
			// The empty-manager tactics path must also invalidate
			// cached IDs.
			if err := m.TacticsApplied(); err != nil {
				t.Fatal(err)
			}
			fresh := getGateTestClient(t, m)
			ids := fresh.CommonCompartmentIDs()
			if len(ids) != len(initial)+1 || ids[0] != newID || (!empty && ids[1] != oldID) {
				t.Fatal("reset did not refresh and merge compartment IDs")
			}
			if len(first.CommonCompartmentIDs()) != len(initial) {
				t.Fatal("reset modified an earlier client's compartment IDs")
			}
		})
	}
}

// TestInproxyBrokerCommonCompartmentTactics verifies that a tactics callback
// resets the shared client and that new clients carry merged and persisted
// common compartment IDs, that a same-tag publication is suppressed until an
// explicit callback, and that a new tag with identical parameters still
// resets.
func TestInproxyBrokerCommonCompartmentTactics(t *testing.T) {
	for _, empty := range []bool{false, true} {
		for _, tag := range []string{"same", "new"} {
			t.Run(fmt.Sprintf("empty=%v/%s", empty, tag), func(t *testing.T) {
				m := newGateTestManager(t)
				oldID, err := inproxy.MakeID()
				if err != nil {
					t.Fatal(err)
				}
				newID, err := inproxy.MakeID()
				if err != nil {
					t.Fatal(err)
				}
				initial := parameters.InproxyCompartmentIDsValue{oldID.String()}
				if empty {
					initial = parameters.InproxyCompartmentIDsValue{}
				}
				if err := setGateTestParameters(m.config, "same", map[string]interface{}{parameters.InproxyCommonCompartmentIDs: initial}); err != nil {
					t.Fatal(err)
				}
				old := getGateTestClient(t, m)
				old.brokerResponseSucceededForTest(old.roundTripper)
				m.config.SetTacticsAppliedReceivers([]TacticsAppliedReceiver{m})
				updated := map[string]interface{}{parameters.InproxyCommonCompartmentIDs: parameters.InproxyCompartmentIDsValue{newID.String()}}
				if err := setGateTestParameters(m.config, tag, updated); err != nil {
					t.Fatal(err)
				}
				if tag == "same" {
					if getGateTestClient(t, m) != old {
						t.Fatal("unchanged tag unexpectedly reset shared client")
					}
					if err := m.TacticsApplied(); err != nil {
						t.Fatal(err)
					}
				}
				fresh := getGateTestClient(t, m)
				ids := fresh.CommonCompartmentIDs()
				if fresh == old || old.roundTripper.runCtx.Err() == nil || len(ids) != len(initial)+1 || ids[0] != newID || (!empty && ids[1] != oldID) {
					t.Fatal("matching identity reset/merge failed")
				}
				stored, err := LoadInproxyCommonCompartmentIDs()
				if err != nil || len(stored) == 0 || stored[0] != newID.String() {
					t.Fatalf("matching IDs not persisted: %v", err)
				}
				fresh.brokerResponseSucceededForTest(fresh.roundTripper)
				if err := setGateTestParameters(m.config, "same-inputs", updated); err != nil {
					t.Fatal(err)
				}
				if fresh.roundTripper.runCtx.Err() == nil || getGateTestClient(t, m) == fresh {
					t.Fatal("new tag with identical settings did not reset shared client")
				}
			})
		}
	}
}

// inproxyRelayTestTransport is a real responder session over a fake HTTP
// transport under a real MeekConn, so broker requests complete cold Noise
// exchanges without an external CDN.
type inproxyRelayTestTransport struct {
	sessions *inproxy.ResponderSessions
	handle   func([]byte) ([]byte, error)
}

func (*inproxyRelayTestTransport) CloseIdleConnections() {}
func (r *inproxyRelayTestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := req.Context().Err(); err != nil {
		return nil, err
	}
	payload, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	response, err := r.sessions.HandlePacket(payload, func(_ inproxy.ID, payload []byte) ([]byte, error) {
		if r.handle != nil {
			return r.handle(payload)
		}
		req, err := inproxy.UnmarshalClientRelayedPacketRequest(payload)
		if err != nil {
			return nil, err
		}
		return inproxy.MarshalClientRelayedPacketResponse(&inproxy.ClientRelayedPacketResponse{PacketToServer: append([]byte("reply:"), req.PacketFromServer...)})
	})
	if err != nil {
		return nil, err
	}
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(response))}, nil
}

// TestInproxyBrokerConnectionOwnedRelay verifies that a non-shared client
// completes a cold Noise ClientRelayedPacket exchange on its own transport
// while another client is shared, that its decoded response neither replaces
// the shared client nor frees its slot, and that releasing it closes only
// that client.
func TestInproxyBrokerConnectionOwnedRelay(t *testing.T) {
	payload, err := inproxy.MarshalClientRelayedPacketResponse(&inproxy.ClientRelayedPacketResponse{PacketToServer: []byte("reply")})
	if err != nil {
		t.Fatal(err)
	}
	m, c, release := newBrokerResponseTestClient(t, payload)
	shared := getGateTestClient(t, m)
	shared.brokerResponseSucceededForTest(shared.roundTripper)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	response, err := c.brokerClient.ClientRelayedPacket(ctx, &inproxy.ClientRelayedPacketRequest{})
	if err != nil || !bytes.Equal(response.PacketToServer, []byte("reply")) {
		t.Fatalf("cold relay failed: %v", err)
	}
	if m.sharedClient != shared || len(m.clients) != 2 {
		t.Fatal("losing relay displaced winner or freed a live slot")
	}
	release()
	release()
	if c.roundTripper.runCtx.Err() == nil || shared.roundTripper.runCtx.Err() != nil {
		t.Fatal("connection lease cleanup closed wrong broker")
	}
}

// TestInproxyDialConnectionOwnedRelay checks that a broker client which loses
// the race to become shared still completes its own dial and the subsequent
// broker/server relay. The test forces this sequence through dialInproxy:
//
//  1. Acquire broker client A without making it shared.
//  2. Start B's dialInproxy and hold its first broker round trip, the
//     session handshake, at the local broker.
//  3. Deliver A's canned offer response through the real MeekConn and
//     BrokerClient decode path, making A shared before B's response arrives.
//  4. Release B's offer. B completes a real WebRTC connection to a local proxy
//     using its original broker client. Canceling B's dial context must not
//     release that broker client.
//  5. Complete a cold, authenticated broker/server relay on B's broker client.
//     Check that the server report's connection ID matches B's connection.
//  6. Clean up B's broker client while A remains shared.
//
// A third case closes B's broker client under the relay, as a tactics
// reset or sibling NoMatch failover would during activation, and checks
// that the relay error reaching the caller is inproxyBrokerClientClosedError,
// which Tunnel.Activate uses to withhold server entry attribution.
//
// The early-release variant calls releaseInproxyBrokerClient before closing
// the connection, as activation does, then checks that the WebRTC data path
// still carries traffic. The other variant relies on Close to release the
// broker client. Both check that repeating the release is harmless.
//
// The broker, proxy, WebRTC connection, B's dial and B's relay are real,
// using local servers with STUN and port mapping disabled. The server side
// of the relay is a test responder session for the broker's key. A's offer
// response is canned to control when A becomes shared. The SSH handshake and
// Tunnel.Activate are not run; a loopback echo stands in for the server's
// data path.
func TestInproxyDialConnectionOwnedRelay(t *testing.T) {
	oldBogons := GetAllowBogonWebRTCConnections()
	oldBrokerBogons := inproxy.GetAllowBogonWebRTCConnections()
	oldMatching := inproxy.GetAllowCommonASNMatching()
	SetAllowBogonWebRTCConnections(true)
	inproxy.SetAllowBogonWebRTCConnections(true)
	inproxy.SetAllowCommonASNMatching(true)
	defer func() {
		SetAllowBogonWebRTCConnections(oldBogons)
		inproxy.SetAllowBogonWebRTCConnections(oldBrokerBogons)
		inproxy.SetAllowCommonASNMatching(oldMatching)
	}()
	for _, mode := range []string{"close-after-relay", "early-release", "close-during-relay"} {
		earlyRelease, closeDuringRelay := mode == "early-release", mode == "close-during-relay"
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			logger := NoticeCommonLogger(false)
			privateKey, err := inproxy.GenerateSessionPrivateKey()
			if err != nil {
				t.Fatal(err)
			}
			publicKey, err := privateKey.GetPublicKey()
			if err != nil {
				t.Fatal(err)
			}
			secret, err := inproxy.GenerateRootObfuscationSecret()
			if err != nil {
				t.Fatal(err)
			}
			serverKey, err := inproxy.GenerateSessionPrivateKey()
			if err != nil {
				t.Fatal(err)
			}
			serverPublicKey, err := serverKey.GetPublicKey()
			if err != nil {
				t.Fatal(err)
			}
			serverSecret, err := inproxy.GenerateRootObfuscationSecret()
			if err != nil {
				t.Fatal(err)
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			echoDone := make(chan struct{})
			go func() {
				defer close(echoDone)
				conn, err := listener.Accept()
				if err == nil {
					defer conn.Close()
					deadline, _ := ctx.Deadline()
					conn.SetDeadline(deadline)
					io.Copy(conn, conn)
				}
			}()
			defer func() { listener.Close(); <-echoDone }()
			_, portString, _ := net.SplitHostPort(listener.Addr().String())
			port, _ := strconv.Atoi(portString)
			entry := protocol.ServerEntryFields{
				"ipAddress": "127.0.0.1", "inproxyOSSHPort": port,
				"capabilities": []string{"INPROXY-WEBRTC-OSSH"}, "tag": "abcdef0123456789",
				"inproxySessionPublicKey":             serverPublicKey.String(),
				"inproxySessionRootObfuscationSecret": serverSecret.String(),
			}
			signPublic, signPrivate, err := protocol.NewServerEntrySignatureKeyPair()
			if err != nil {
				t.Fatal(err)
			}
			if err := entry.AddSignature(signPublic, signPrivate); err != nil {
				t.Fatal(err)
			}
			packed, err := protocol.EncodePackedServerEntryFields(entry)
			if err != nil {
				t.Fatal(err)
			}
			packedEntry, err := protocol.CBOREncoding.Marshal(packed)
			if err != nil {
				t.Fatal(err)
			}
			id, err := inproxy.MakeID()
			if err != nil {
				t.Fatal(err)
			}
			broker, err := inproxy.NewBroker(&inproxy.BrokerConfig{
				Logger: logger, PrivateKey: privateKey, ObfuscationRootSecret: secret,
				CommonCompartmentIDs: []inproxy.ID{id}, ServerEntrySignaturePublicKey: signPublic,
				APIParameterValidator:         func(common.APIParameters) error { return nil },
				APIParameterLogFieldFormatter: func(string, common.GeoIPData, common.APIParameters) common.LogFields { return common.LogFields{} },
				GetTacticsPayload:             func(common.GeoIPData, common.APIParameters) ([]byte, string, error) { return nil, "", nil },
				IsValidServerEntryTag:         func(tag string) bool { return tag == "abcdef0123456789" },
				AllowProxy:                    func(common.GeoIPData) bool { return true },
				AllowClient:                   func(common.GeoIPData) bool { return true },
				AllowMatch:                    func(common.GeoIPData, common.GeoIPData) bool { return true },
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := broker.Start(); err != nil {
				t.Fatal(err)
			}
			defer broker.Stop()
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				packet, err := io.ReadAll(r.Body)
				if err == nil {
					packet, err = broker.HandleSessionPacket(r.Context(), func(time.Duration) {}, nil,
						"127.0.0.1", common.GeoIPData{}, packet)
				}
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				w.Write(packet)
			})
			proxyHTTP := httptest.NewTLSServer(handler)
			defer proxyHTTP.Close()
			started, proceed := make(chan struct{}), make(chan struct{})
			var startedOnce sync.Once
			clientHTTP := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				startedOnce.Do(func() { close(started) })
				select {
				case <-proceed:
					handler.ServeHTTP(w, r)
				case <-r.Context().Done():
				}
			}))
			defer clientHTTP.Close()
			makeSpec := func(address string) *parameters.InproxyBrokerSpec {
				// Packed metrics encode provider IDs as hex.
				// Use an even number of digits.
				return &parameters.InproxyBrokerSpec{BrokerPublicKey: publicKey.String(),
					BrokerRootObfuscationSecret: secret.String(), BrokerFrontingSpecs: parameters.FrontingSpecs{
						{FrontingProviderID: "AA", Addresses: []string{regexp.QuoteMeta(address)}, Host: "example.org", SkipVerify: true},
						{FrontingProviderID: "BB", Addresses: []string{regexp.QuoteMeta(address)}, Host: "example.org", SkipVerify: true},
					}}
			}
			m := newProviderTestManager(t, 2, makeSpec(clientHTTP.Listener.Addr().String()))
			if err := setGateTestParameters(m.config, "abcd", map[string]interface{}{
				parameters.InproxyBrokerSpecs:            parameters.InproxyBrokerSpecsValue{makeSpec(clientHTTP.Listener.Addr().String())},
				parameters.InproxyClientMaxBrokerClients: 2,
				parameters.InproxyCommonCompartmentIDs:   parameters.InproxyCompartmentIDsValue{id.String()},
				parameters.InproxyProxyBrokerSpecs:       parameters.InproxyBrokerSpecsValue{makeSpec(proxyHTTP.Listener.Addr().String())},
				parameters.InproxyDisableSTUN:            true, parameters.InproxyDisablePortMapping: true,
				parameters.InproxyClientDiscoverNATProbability: 0.0,
			}); err != nil {
				t.Fatal(err)
			}
			a := getGateTestClient(t, m)
			sessions, err := inproxy.NewResponderSessions(privateKey, secret, 0)
			if err != nil {
				t.Fatal(err)
			}
			meekCtx, stopMeek := context.WithCancel(ctx)
			a.roundTripper.conn = &MeekConn{mode: MeekModePlaintextRoundTrip,
				transport: &inproxyRelayTestTransport{sessions: sessions, handle: func([]byte) ([]byte, error) {
					return inproxy.MarshalClientOfferResponse(&inproxy.ClientOfferResponse{Limited: true})
				}}, runCtx: meekCtx, stopRunning: stopMeek, relayWaitGroup: new(sync.WaitGroup),
				connManager: &meekUnderlyingConnManager{managedConns: common.NewConns[net.Conn](), managedPacketConns: common.NewConns[net.PacketConn]()}}
			a.roundTripper.dial = 1
			close(a.roundTripper.dialCompleted)
			proxyManager := NewInproxyBrokerClientManager(m.config, true, utls.NewLRUClientSessionCache(0))
			defer proxyManager.closeClientBrokerClients()
			nat := NewInproxyNATStateManager(m.config)
			proxy, err := inproxy.NewProxy(&inproxy.ProxyConfig{
				Logger: logger, MaxCommonClients: 1,
				WaitForNetworkConnectivity: func() bool { return ctx.Err() == nil },
				GetCurrentNetworkContext:   func() context.Context { return ctx },
				GetBrokerClient: func(ctx context.Context) (*inproxy.BrokerClient, func(), error) {
					client, _, release, err := proxyManager.GetBrokerClient(ctx, "TEST")
					return client, release, err
				},
				GetBaseAPIParameters: func(bool) (common.APIParameters, string, error) { return common.APIParameters{}, "TEST", nil },
				MakeWebRTCDialCoordinator: func() (inproxy.WebRTCDialCoordinator, error) {
					return NewInproxyWebRTCDialInstance(m.config, "TEST", true, nat, nil, nil)
				},
				HandleTacticsPayload: func(string, bool, []byte) bool { return false },
				ActivityUpdater: func(int32, int32, int32, int64, int64, time.Duration,
					map[string]inproxy.RegionActivitySnapshot, map[string]inproxy.RegionActivitySnapshot) {
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			proxyDone := make(chan struct{})
			go func() { defer close(proxyDone); proxy.Run(ctx) }()
			defer func() { cancel(); <-proxyDone }()
			p := m.config.GetParameters().Get()
			webRTCParams, err := MakeInproxyWebRTCDialParameters(p, false)
			p.Close()
			if err != nil {
				t.Fatal(err)
			}
			dialParams := &DialParameters{NetworkID: "TEST",
				TunnelProtocol:    protocol.TunnelProtocolPlusInproxyWebRTC(protocol.TUNNEL_PROTOCOL_OBFUSCATED_SSH),
				ServerEntry:       &protocol.ServerEntry{IpAddress: "127.0.0.1", InproxyOSSHPort: port, Capabilities: []string{"INPROXY-WEBRTC-OSSH"}},
				DirectDialAddress: listener.Addr().String(), InproxyWebRTCDialParameters: webRTCParams,
				InproxySTUNDialParameters:  &InproxySTUNDialParameters{},
				inproxyBrokerClientManager: m, inproxyNATStateManager: nat, inproxyPackedSignedServerEntry: packedEntry}
			type dialResult struct {
				conn *inproxyBrokerOwnedConn
				err  error
			}
			result := make(chan dialResult, 1)
			dialCtx, cancelDial := context.WithCancel(ctx)
			dialDone := make(chan struct{})
			go func() {
				defer close(dialDone)
				conn, err := dialInproxy(dialCtx, m.config, dialParams)
				result <- dialResult{conn, err}
			}()
			defer func() {
				cancelDial()
				<-dialDone
				select {
				case r := <-result:
					if r.conn != nil {
						r.conn.Close()
					}
				default:
				}
			}()
			select {
			case <-started:
			case r := <-result:
				t.Fatalf("dial ended before reaching local broker: %v", r.err)
			case <-ctx.Done():
				t.Fatal("dial did not reach local broker")
			}
			m.mutex.Lock()
			var b *InproxyBrokerClientInstance
			for client := range m.clients {
				if client != a {
					b = client
				}
			}
			m.mutex.Unlock()
			if b == nil {
				t.Fatal("dial did not acquire competing broker client")
			}
			if _, err := a.brokerClient.ClientOffer(ctx, &inproxy.ClientOfferRequest{}, false); err != nil {
				t.Fatal(err)
			}
			m.mutex.Lock()
			aShared := m.sharedClient == a
			m.mutex.Unlock()
			if !aShared {
				t.Fatal("A did not become shared before B's response")
			}
			close(proceed)
			var conn *inproxyBrokerOwnedConn
			select {
			case r := <-result:
				if r.err != nil {
					t.Fatal(r.err)
				}
				conn = r.conn
			case <-ctx.Done():
				t.Fatal("dial did not finish")
			}
			defer conn.Close()
			cancelDial()
			closeDone := make(chan struct{})
			stopClose := context.AfterFunc(ctx, func() {
				defer close(closeDone)
				conn.Close()
			})
			defer func() {
				if !stopClose() {
					<-closeDone
				}
			}()
			m.mutex.Lock()
			retained := m.sharedClient == a && m.clients[b] != nil && m.clients[b].refs == 1
			m.mutex.Unlock()
			if dialParams.getInproxyConn() != conn || !retained {
				t.Fatal("dial did not retain the nonshared broker lease")
			}
			serverSessions, err := inproxy.NewResponderSessionsForKnownInitiators(
				serverKey, serverSecret, []inproxy.SessionPublicKey{publicKey}, 0)
			if err != nil {
				t.Fatal(err)
			}
			packet := conn.InitialRelayPacket()
			if len(packet) == 0 {
				t.Fatal("missing initial broker/server packet")
			}
			reported, relays := false, 0
			for len(packet) > 0 && relays < inproxy.MaxRelayRoundTrips {
				packet, err = serverSessions.HandlePacket(packet, func(_ inproxy.ID, payload []byte) ([]byte, error) {
					report, err := inproxy.UnmarshalBrokerServerReport(payload)
					if err != nil {
						return nil, err
					}
					if report.ConnectionID != conn.GetConnectionID() {
						return nil, fmt.Errorf("wrong connection ID")
					}
					reported = true
					return nil, nil
				})
				if err != nil {
					t.Fatal(err)
				}
				if len(packet) > 0 {
					if closeDuringRelay {
						// The manager closes B under the relay, as a
						// reset would. The relay fails with the closed
						// marker rather than a transport failure, and
						// B's replay record survives.
						m.mutex.Lock()
						m.closeClientLocked(b, "test reset")
						m.mutex.Unlock()
						_, err = conn.RelayPacket(ctx, packet)
						var closed *inproxyBrokerClientClosedError
						var failure *inproxy.RoundTripperFailedError
						if !stderrors.As(err, &closed) || stderrors.As(err, &failure) ||
							isServerEntryFailure(context.Background(), err) {
							t.Fatalf("relay on closed broker client: %v", err)
						}
						if b.roundTripper.failure.Load() != nil {
							t.Fatal("close under relay recorded a transport failure")
						}
						if err := conn.Close(); err != nil {
							t.Fatal(err)
						}
						dialParams.releaseInproxyBrokerClient()
						return
					}
					packet, err = conn.RelayPacket(ctx, packet)
					if err != nil {
						t.Fatal(err)
					}
					relays++
				}
			}
			if !reported || relays == 0 || len(packet) != 0 {
				t.Fatal("cold broker/server exchange did not complete")
			}
			if earlyRelease {
				dialParams.releaseInproxyBrokerClient()
				if b.roundTripper.runCtx.Err() == nil {
					t.Fatal("early release retained losing broker")
				}
			}
			// Broker release must not close the WebRTC data path.
			if _, err := conn.Write([]byte("echo")); err != nil {
				t.Fatal(err)
			}
			data := make([]byte, 4)
			if _, err := io.ReadFull(conn, data); err != nil || string(data) != "echo" {
				t.Fatalf("data path failed: %q, %v", data, err)
			}
			if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
			dialParams.releaseInproxyBrokerClient()
			m.mutex.Lock()
			cleaned := len(m.clients) == 1 && m.sharedClient == a
			m.mutex.Unlock()
			if b.roundTripper.runCtx.Err() == nil || a.roundTripper.runCtx.Err() != nil || !cleaned {
				t.Fatal("cleanup released the wrong broker client")
			}
		})
	}
}

// newProxyRaceTestManager returns a proxy-mode provider test manager whose
// broker specs and InproxyProxyMaxBrokerClients are set through tactics.
func newProxyRaceTestManager(t *testing.T, limit int, specs ...*parameters.InproxyBrokerSpec) *InproxyBrokerClientManager {
	t.Helper()
	m := newProviderTestManager(t, limit, specs...)
	m.isProxy = true
	if err := setGateTestParameters(m.config, "proxy", map[string]interface{}{
		parameters.InproxyBrokerSpecs: parameters.InproxyBrokerSpecsValue(specs), parameters.InproxyProxyMaxBrokerClients: limit,
	}); err != nil {
		t.Fatal(err)
	}
	return m
}

// TestInproxyProxyProviderRace verifies, for common and personal proxies,
// that concurrent candidates stay at one broker with one proxy identity and
// distinct fronting providers, that acquisition waits once every provider is
// tried while a visit client remains, that the broker advances in stable
// order only after no client remains, that the shared client is retained
// with no idle timer, and that shared loss retains the current broker.
func TestInproxyProxyProviderRace(t *testing.T) {
	for _, personal := range []bool{false, true} {
		t.Run(fmt.Sprint(personal), func(t *testing.T) {
			// M exceeds the provider count so the fourth
			// acquisition is gated by visit exhaustion rather than
			// the client limit.
			m := newProxyRaceTestManager(t, 4, newProviderTestBroker(t, "A", "A", "B", "C"), newProviderTestBroker(t, "A", "B", "C"))
			m.config.DisableReplay = true
			if personal {
				id, err := inproxy.MakeID()
				if err != nil {
					t.Fatal(err)
				}
				m.config.InproxyProxyPersonalCompartmentID = id.String()
			}
			var releases [3]func()
			clients := make([]*InproxyBrokerClientInstance, 3)
			seen := make(map[string]bool)
			for i := range clients {
				clients[i] = getGateTestClient(t, m, &releases[i])
				c := clients[i]
				if c.BrokerPublicKey() != clients[0].BrokerPublicKey() || c.BrokerClientPrivateKey() != clients[0].BrokerClientPrivateKey() || seen[c.frontingProviderID] {
					t.Fatal("broker/identity affinity or diversity failed")
				}
				seen[c.frontingProviderID] = true
			}
			if c, _, changed, err := m.tryGetClientBrokerClient("TEST"); c != nil || changed == nil || err != nil {
				t.Fatal("race exceeded distinct providers at the visit")
			}
			clients[0].BrokerClientRoundTripperFailed(clients[0].roundTripper)
			if c, _, changed, err := m.tryGetClientBrokerClient("TEST"); c != nil || changed == nil || err != nil {
				t.Fatal("advanced broker while viable visit clients remained")
			}
			for _, release := range releases {
				release()
			}
			var release func()
			next := getGateTestClient(t, m, &release)
			if next.brokerSelection.index != 1 || next.BrokerPublicKey() == clients[0].BrokerPublicKey() || next.BrokerClientPrivateKey() != clients[0].BrokerClientPrivateKey() {
				t.Fatal("exhaustion did not advance stable broker order/identity")
			}
			next.brokerResponseSucceededForTest(next.roundTripper)
			release()
			m.mutex.Lock()
			armed := m.sharedIdleTimer != nil
			m.mutex.Unlock()
			if armed {
				t.Fatal("proxy armed idle timer")
			}
			if getGateTestClient(t, m) != next {
				t.Fatal("idle expiry applied to proxy")
			}
			next.retryOnFailedPeriod = 0
			next.BrokerClientRoundTripperFailed(next.roundTripper)
			replacement := getGateTestClient(t, m)
			if replacement.BrokerPublicKey() != next.BrokerPublicKey() {
				t.Fatal("shared loss did not retain current broker")
			}
		})
	}
}

// TestInproxyProxyReplayJumpSkipsExhaustedBroker verifies that a common
// proxy's replay-first visit start does not return to the broker it just
// exhausted. Both providers at the first broker are tried fresh and fail
// while replay is disabled by probability, leaving that broker's replay
// record and the provider's allowance intact; when replay is enabled
// again the new visit must start at the next broker, not wrap back.
func TestInproxyProxyReplayJumpSkipsExhaustedBroker(t *testing.T) {
	specs := parameters.InproxyBrokerSpecsValue{
		newProviderTestBroker(t, "A", "B"), newProviderTestBroker(t, "A", "B"), newProviderTestBroker(t, "A", "B")}
	m := newProxyRaceTestManager(t, 1, specs...)
	setReplay := func(probability float64) {
		if err := setGateTestParameters(m.config, "jump", map[string]interface{}{
			parameters.InproxyBrokerSpecs:                           specs,
			parameters.InproxyProxyMaxBrokerClients:                 1,
			parameters.InproxyReplayBrokerDialParametersProbability: probability,
			parameters.InproxyReplayBrokerRetainFailedProbability:   1.0,
		}); err != nil {
			t.Fatal(err)
		}
	}
	setReplay(0.0)
	var release func()
	first := getGateTestClient(t, m, &release)
	exhausted := first.brokerDialParams.brokerSpec
	if err := storeInproxyBrokerReplayParameters("TEST", makeBrokerReplayTestParameters(t, m, exhausted, "A")); err != nil {
		t.Fatal(err)
	}
	first.BrokerClientRoundTripperFailed(first.roundTripper)
	release()
	second := getGateTestClient(t, m, &release)
	if second.brokerDialParams.brokerSpec != exhausted || second.frontingProviderID == first.frontingProviderID {
		t.Fatal("second provider was not tried at the same broker")
	}
	second.BrokerClientRoundTripperFailed(second.roundTripper)
	release()
	setReplay(1.0)
	next := getGateTestClient(t, m)
	if next.brokerDialParams.brokerSpec == exhausted {
		t.Fatalf("replay jump returned to the exhausted broker (index %d)", next.brokerSelection.index)
	}
}

// TestInproxyProxyStableReplayOrder verifies that a common proxy starts its
// visit at the broker holding eligible replay, then continues the stable
// broker order from that position without replaying the same provider
// again.
func TestInproxyProxyStableReplayOrder(t *testing.T) {
	specs := parameters.InproxyBrokerSpecsValue{
		newProviderTestBroker(t, "A"), newProviderTestBroker(t, "A"), newProviderTestBroker(t, "A"),
	}
	m := newProxyRaceTestManager(t, 1, specs...)
	order := initializeTestSelector(t, m, &m.selector)
	params := makeBrokerReplayTestParameters(t, m, order[2], "A")
	if err := storeInproxyBrokerReplayParameters("TEST", params); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 7; i++ {
		var release func()
		client := getGateTestClient(t, m, &release)
		if client.BrokerPublicKey().String() != order[(2+i)%len(order)].BrokerPublicKey || client.brokerDialParams.isReplay != (i == 0) {
			t.Fatal("proxy replay preference restarted or broke stable broker traversal")
		}
		release()
	}
}

// TestInproxyProxyDecodedAnnouncePolicy verifies through a real cold Noise
// exchange that every decoded ProxyAnnounce response, including precheck,
// NoMatch and Limited, makes the proxy client shared and retained, while a
// MustUpgrade response or a malformed response records transport success
// only and the client closes on release.
func TestInproxyProxyDecodedAnnouncePolicy(t *testing.T) {
	for _, tc := range []struct {
		name              string
		precheck          bool
		response          inproxy.ProxyAnnounceResponse
		malformed, shared bool
	}{
		{name: "precheck", precheck: true, response: inproxy.ProxyAnnounceResponse{NoMatch: true}, shared: true},
		{name: "no-match", response: inproxy.ProxyAnnounceResponse{NoMatch: true}, shared: true},
		{name: "match", shared: true},
		{name: "limited", response: inproxy.ProxyAnnounceResponse{Limited: true}, shared: true},
		{name: "limited-no-match", response: inproxy.ProxyAnnounceResponse{Limited: true, NoMatch: true}, shared: true},
		{name: "upgrade", response: inproxy.ProxyAnnounceResponse{MustUpgrade: true, NoMatch: true}},
		{name: "upgrade-limited-no-match", response: inproxy.ProxyAnnounceResponse{MustUpgrade: true, Limited: true, NoMatch: true}},
		{name: "malformed", malformed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload, err := inproxy.MarshalProxyAnnounceResponse(&tc.response)
			if err != nil {
				t.Fatal(err)
			}
			if tc.malformed {
				payload = []byte("invalid")
			}
			m, c, release := newBrokerResponseTestClient(t, payload, true)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err = c.brokerClient.ProxyAnnounce(ctx, 0, &inproxy.ProxyAnnounceRequest{PreCheckTactics: tc.precheck})
			if (err != nil) != tc.malformed || (m.sharedClient == c) != tc.shared || !c.HasSuccess() {
				t.Fatalf("unexpected outcome: %v", err)
			}
			release()
			release()
			if tc.shared && getGateTestClient(t, m) != c {
				t.Fatal("precheck/announce did not retain its shared transport")
			}
			if !tc.shared && len(m.clients) != 0 {
				t.Fatal("unshared response leaked lease")
			}
		})
	}
}

// TestInproxyProxyTacticsAndIdentity verifies that proxy clients use the
// configured session key, that a tactics callback raising proxy M resets the
// live client and wakes a blocked acquisition, which gets a new client with
// the same key, and that after a broker spec change a response from a closed
// client cannot resurrect it.
func TestInproxyProxyTacticsAndIdentity(t *testing.T) {
	spec := newProviderTestBroker(t, "A", "B", "C")
	m := newProxyRaceTestManager(t, 1, spec)
	key, err := inproxy.GenerateSessionPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	m.config.InproxyProxySessionPrivateKey = key.String()
	m.config.SetTacticsAppliedReceivers([]TacticsAppliedReceiver{m})
	a := getGateTestClient(t, m)
	if a.BrokerClientPrivateKey() != key {
		t.Fatal("configured key ignored")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	wait := &inproxyGateWaitContext{Context: ctx, waiting: make(chan struct{})}
	type result struct {
		client  *inproxy.BrokerClient
		release func()
		err     error
	}
	results := make(chan result, 1)
	go func() { c, _, release, err := m.GetBrokerClient(wait, "TEST"); results <- result{c, release, err} }()
	select {
	case <-wait.waiting:
	case <-ctx.Done():
		t.Fatal("did not wait at proxy M")
	}
	if err := setGateTestParameters(m.config, "capacity", map[string]interface{}{
		parameters.InproxyBrokerSpecs: parameters.InproxyBrokerSpecsValue{spec}, parameters.InproxyClientMaxBrokerClients: 1, parameters.InproxyProxyMaxBrokerClients: 2,
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-results:
		if r.err != nil {
			t.Fatal(r.err)
		}
		defer r.release()
		b := r.client.GetBrokerDialCoordinator().(*InproxyBrokerClientInstance)
		if b == a || b.BrokerPublicKey() != a.BrokerPublicKey() || b.BrokerClientPrivateKey() != key || a.roundTripper.runCtx.Err() == nil {
			t.Fatal("capacity reset failed to replace client and preserve proxy identity")
		}
	case <-ctx.Done():
		t.Fatal("proxy M update did not wake waiter")
	}
	if err := setGateTestParameters(m.config, "selection", map[string]interface{}{parameters.InproxyBrokerSpecs: parameters.InproxyBrokerSpecsValue{newProviderTestBroker(t, "D")}}); err != nil {
		t.Fatal(err)
	}
	a.BrokerClientResponseReceived(a.roundTripper, false)
	if len(m.clients) != 0 || m.sharedClient != nil {
		t.Fatal("stale response resurrected reset visit")
	}
	b := getGateTestClient(t, m)
	if b.frontingProviderID != "D" || b.BrokerClientPrivateKey() != key {
		t.Fatal("new selection lost key/eligibility")
	}
}

// TestInproxyProxySharedLossPreservesCompetitors verifies that losing a
// proxy's shared client keeps the surviving candidate at the same broker,
// that the failed flag rather than the retained visit rejects the failed
// client's later response, that a new candidate tries another provider
// there, that the survivor becomes shared on its next response, and that a
// response from the closed client is ignored.
func TestInproxyProxySharedLossPreservesCompetitors(t *testing.T) {
	m := newProxyRaceTestManager(t, 3, newProviderTestBroker(t, "A", "B"))
	var releaseA func()
	a := getGateTestClient(t, m, &releaseA)
	var releaseB, releaseC func()
	b := getGateTestClient(t, m, &releaseB)
	a.BrokerClientResponseReceived(a.roundTripper, false)
	a.BrokerClientRoundTripperFailed(a.roundTripper)
	// Proxies retain the visit on shared loss, so the visit pointer alone
	// cannot reject a late response from the failed client while it is
	// still held; the failed flag must.
	a.BrokerClientResponseReceived(a.roundTripper, false)
	m.mutex.Lock()
	reshared := m.sharedClient == a
	m.mutex.Unlock()
	if reshared {
		t.Fatal("failed client re-shared by its later response")
	}
	releaseA()
	c := getGateTestClient(t, m, &releaseC)
	if c.BrokerPublicKey() != b.BrokerPublicKey() || c.frontingProviderID == b.frontingProviderID || b.roundTripper.runCtx.Err() != nil {
		t.Fatal("recovery lost surviving affinity")
	}
	b.BrokerClientResponseReceived(b.roundTripper, false)
	releaseB()
	releaseC()
	a.BrokerClientResponseReceived(a.roundTripper, false)
	shared := getGateTestClient(t, m)
	m.mutex.Lock()
	tracked := len(m.clients)
	m.mutex.Unlock()
	if shared != b || tracked != 1 {
		t.Fatal("survivor promotion/lease cleanup failed")
	}
}

// TestInproxyProxyLosingAnnounceCanAnswer verifies that a proxy announcement
// still in flight when a competing candidate becomes shared completes on its
// original broker client, that its ProxyAnswer uses that same client, and
// that releasing it afterwards closes only the losing client.
func TestInproxyProxyLosingAnnounceCanAnswer(t *testing.T) {
	m, a, releaseA := newBrokerResponseTestClient(t, nil, true)
	var releaseB func()
	b := getGateTestClient(t, m, &releaseB)
	defer releaseB()
	if a.BrokerClientPrivateKey() != b.BrokerClientPrivateKey() {
		t.Fatal("CDN candidates have different identities")
	}
	aID, err := inproxy.MakeID()
	if err != nil {
		t.Fatal(err)
	}
	bID, err := inproxy.MakeID()
	if err != nil {
		t.Fatal(err)
	}
	started, allowA := make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(allowA) })
	defer unblock()
	handler := func(id inproxy.ID, block bool) func([]byte) ([]byte, error) {
		return func(payload []byte) ([]byte, error) {
			if _, err := inproxy.UnmarshalProxyAnnounceRequest(payload); err == nil {
				if block {
					close(started)
					<-allowA
				}
				return inproxy.MarshalProxyAnnounceResponse(&inproxy.ProxyAnnounceResponse{ConnectionID: id})
			}
			answer, err := inproxy.UnmarshalProxyAnswerRequest(payload)
			if err != nil {
				return nil, err
			}
			if answer.ConnectionID != id {
				return nil, fmt.Errorf("answer changed broker client")
			}
			return inproxy.MarshalProxyAnswerResponse(&inproxy.ProxyAnswerResponse{})
		}
	}
	aTransport := a.roundTripper.conn.transport.(*inproxyRelayTestTransport)
	aTransport.handle = handler(aID, true)
	meekCtx, stop := context.WithCancel(context.Background())
	b.roundTripper.conn = &MeekConn{mode: MeekModePlaintextRoundTrip, transport: &inproxyRelayTestTransport{sessions: aTransport.sessions, handle: handler(bID, false)}, runCtx: meekCtx, stopRunning: stop, relayWaitGroup: new(sync.WaitGroup), connManager: &meekUnderlyingConnManager{managedConns: common.NewConns[net.Conn](), managedPacketConns: common.NewConns[net.PacketConn]()}}
	b.roundTripper.dial = 1
	close(b.roundTripper.dialCompleted)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := a.brokerClient.ProxyAnnounce(ctx, 0, &inproxy.ProxyAnnounceRequest{}); result <- err }()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("announce did not start")
	}
	if _, err := b.brokerClient.ProxyAnnounce(ctx, 0, &inproxy.ProxyAnnounceRequest{}); err != nil {
		t.Fatal(err)
	}
	if m.sharedClient != b || a.roundTripper.runCtx.Err() != nil {
		t.Fatal("winner interrupted competitor")
	}
	unblock()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("losing announce did not finish")
	}
	if _, err := a.brokerClient.ProxyAnswer(ctx, &inproxy.ProxyAnswerRequest{ConnectionID: aID}); err != nil {
		t.Fatal(err)
	}
	releaseA()
	releaseA()
	if len(m.clients) != 1 || getGateTestClient(t, m) != b || a.roundTripper.runCtx.Err() == nil {
		t.Fatal("losing answer cleanup closed wrong client")
	}
}

// Exercise the real API decode/callback path through a cold Noise session and
// the concrete broker transport, rather than synthesizing manager callbacks.
func newBrokerResponseTestClient(t *testing.T, payload []byte, proxy ...bool) (*InproxyBrokerClientManager, *InproxyBrokerClientInstance, func()) {
	return newBrokerResponseTestClientWithParameters(t, payload, nil, proxy...)
}

// boolProbability maps a test switch to the probability that selects it
// deterministically: 1.0 for on, 0.0 for off.
func boolProbability(on bool) float64 {
	if on {
		return 1.0
	}
	return 0.0
}

// newBrokerResponseTestClientWithParameters is newBrokerResponseTestClient
// with params published before the first acquisition, so that parameters
// read at broker client construction, such as transport-time sharing, are
// in effect for the returned client.
func newBrokerResponseTestClientWithParameters(t *testing.T, payload []byte, params map[string]interface{}, proxy ...bool) (*InproxyBrokerClientManager, *InproxyBrokerClientInstance, func()) {
	t.Helper()
	privateKey, err := inproxy.GenerateSessionPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := privateKey.GetPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	secret, err := inproxy.GenerateRootObfuscationSecret()
	if err != nil {
		t.Fatal(err)
	}
	spec := newProviderTestBroker(t, "A", "B")
	spec.BrokerPublicKey = publicKey.String()
	spec.BrokerRootObfuscationSecret = secret.String()
	m := newProviderTestManager(t, 2, spec)
	m.isProxy = len(proxy) > 0 && proxy[0]
	if params != nil {
		merged := map[string]interface{}{parameters.InproxyBrokerSpecs: parameters.InproxyBrokerSpecsValue{spec}}
		for name, value := range params {
			merged[name] = value
		}
		if err := setGateTestParameters(m.config, "", merged); err != nil {
			t.Fatal(err)
		}
	}
	var release func()
	c := getGateTestClient(t, m, &release)
	sessions, err := inproxy.NewResponderSessions(privateKey, secret, 0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.roundTripper.conn = &MeekConn{
		mode: MeekModePlaintextRoundTrip,
		transport: &inproxyRelayTestTransport{sessions: sessions, handle: func([]byte) ([]byte, error) {
			return payload, nil
		}},
		runCtx: ctx, stopRunning: cancel, relayWaitGroup: new(sync.WaitGroup),
		connManager: &meekUnderlyingConnManager{
			managedConns: common.NewConns[net.Conn](), managedPacketConns: common.NewConns[net.PacketConn](),
		},
	}
	c.roundTripper.dial = 1
	close(c.roundTripper.dialCompleted)
	return m, c, release
}

// TestInproxyUntunneledDSLRequestLease verifies the lease contract the
// untunneled DSL fetcher's round tripper relies on: a broker client
// acquired for one relayed request and released on return leaves no lease
// outstanding after a successful relay, after a failed relay, and after an
// acquisition error, and successive requests reuse the shared client. The
// sequence mirrors the closure in runUntunneledDSLFetcher.
func TestInproxyUntunneledDSLRequestLease(t *testing.T) {
	payload, err := inproxy.MarshalClientDSLResponse(&inproxy.ClientDSLResponse{ResponsePayload: []byte("dsl")})
	if err != nil {
		t.Fatal(err)
	}
	m, c, release := newBrokerResponseTestClient(t, payload)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Share the fixture client through a decoded response, then drop the
	// fixture's lease so the request leases are the only ones.
	if _, err := c.brokerClient.ClientDSL(ctx, &inproxy.ClientDSLRequest{}); err != nil {
		t.Fatal(err)
	}
	release()
	refs := func() int {
		m.mutex.Lock()
		defer m.mutex.Unlock()
		if entry := m.clients[c]; entry != nil {
			return entry.refs
		}
		return -1
	}
	if m.sharedClient != c || refs() != 0 {
		t.Fatalf("fixture client not shared at zero leases: refs=%d", refs())
	}
	relay := func(networkID string) ([]byte, error) {
		brokerClient, _, release, err := m.GetBrokerClient(ctx, networkID)
		if err != nil {
			return nil, err
		}
		defer release()
		if refs() != 1 {
			t.Fatalf("lease not held during the request: refs=%d", refs())
		}
		response, err := brokerClient.ClientDSL(ctx, &inproxy.ClientDSLRequest{RequestPayload: []byte("request")})
		if err != nil {
			return nil, err
		}
		return response.ResponsePayload, nil
	}
	for i := 0; i < 2; i++ {
		response, err := relay("TEST")
		if err != nil || string(response) != "dsl" {
			t.Fatalf("relay %d: %v %q", i, err, response)
		}
		if refs() != 0 || len(m.clients) != 1 {
			t.Fatalf("relay %d left refs=%d clients=%d", i, refs(), len(m.clients))
		}
	}
	// A relay that fails after acquisition still releases.
	transport := c.roundTripper.conn.transport.(*inproxyRelayTestTransport)
	transport.handle = func([]byte) ([]byte, error) { return []byte("malformed"), nil }
	if _, err := relay("TEST"); err == nil {
		t.Fatal("malformed relay response did not fail")
	}
	if refs() != 0 || len(m.clients) != 1 {
		t.Fatalf("failed relay left refs=%d clients=%d", refs(), len(m.clients))
	}
	// An acquisition failure holds no lease.
	if _, err := relay("STALE"); err == nil {
		t.Fatal("stale network ID acquisition did not fail")
	}
	if refs() != 0 {
		t.Fatalf("failed acquisition left refs=%d", refs())
	}
}

// TestInproxyBrokerDecodedResponsePolicy verifies which decoded broker
// responses make an unshared client shared. Through a cold Noise session, it
// checks offers with NoMatch, Limited and MustUpgrade flags under retain and
// failover probabilities, DSL and relayed-packet responses, and malformed or
// wrong-type payloads that produce no notification. A MustUpgrade offer
// neither shares nor fails over, even with NoMatch, and the client closes
// on release. Transport success, sharing, immediate close and release
// cleanup are checked for each case.
func TestInproxyBrokerDecodedResponsePolicy(t *testing.T) {
	for _, tc := range []struct {
		name        string
		api         string
		offer       inproxy.ClientOfferResponse
		probability float64
		malformed   bool
		wrongType   bool
		shared      bool
		closed      bool
	}{
		{name: "match", shared: true},
		{name: "no-match-retain", offer: inproxy.ClientOfferResponse{NoMatch: true}, shared: true},
		{name: "no-match-failover", offer: inproxy.ClientOfferResponse{NoMatch: true}, probability: 1, closed: true},
		{name: "limited", offer: inproxy.ClientOfferResponse{Limited: true}, probability: 1, shared: true},
		{name: "limited-precedes-no-match", offer: inproxy.ClientOfferResponse{Limited: true, NoMatch: true}, probability: 1, shared: true},
		{name: "must-upgrade", offer: inproxy.ClientOfferResponse{MustUpgrade: true}},
		{name: "upgrade-no-match-retain", offer: inproxy.ClientOfferResponse{MustUpgrade: true, NoMatch: true}},
		{name: "upgrade-no-match-no-failover", offer: inproxy.ClientOfferResponse{MustUpgrade: true, NoMatch: true}, probability: 1},
		{name: "upgrade-limited-no-match", offer: inproxy.ClientOfferResponse{MustUpgrade: true, Limited: true, NoMatch: true}, probability: 1},
		{name: "malformed-offer", malformed: true},
		{name: "wrong-response-type", wrongType: true},
		{name: "dsl-backend-error", api: "dsl", shared: true},
		{name: "malformed-dsl", api: "dsl", malformed: true},
		{name: "relay", api: "relay", shared: true},
		{name: "malformed-relay", api: "relay", malformed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var payload []byte
			var err error
			switch {
			case tc.malformed:
				payload = []byte("not a broker response")
			case tc.api == "dsl" || tc.wrongType:
				payload, err = inproxy.MarshalClientDSLResponse(&inproxy.ClientDSLResponse{
					ResponsePayload: dsl.GetRelayGenericErrorResponse(),
				})
			case tc.api == "relay":
				payload, err = inproxy.MarshalClientRelayedPacketResponse(&inproxy.ClientRelayedPacketResponse{PacketToServer: []byte("reply")})
			default:
				payload, err = inproxy.MarshalClientOfferResponse(&tc.offer)
			}
			if err != nil {
				t.Fatal(err)
			}
			m, c, release := newBrokerResponseTestClient(t, payload)
			if err := setGateTestParameters(m.config, "policy", map[string]interface{}{
				parameters.InproxyClientNoMatchFailoverProbability: tc.probability,
			}); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			switch tc.api {
			case "dsl":
				_, err = c.brokerClient.ClientDSL(ctx, &inproxy.ClientDSLRequest{})
			case "relay":
				_, err = c.brokerClient.ClientRelayedPacket(ctx, &inproxy.ClientRelayedPacketRequest{})
			default:
				_, err = c.brokerClient.ClientOffer(ctx, &inproxy.ClientOfferRequest{}, false)
			}
			if (err != nil) != (tc.malformed || tc.wrongType) {
				t.Fatalf("unexpected API error: %v", err)
			}
			if !c.HasSuccess() {
				t.Fatal("secure transport success was lost")
			}
			if (m.sharedClient == c) != tc.shared || (c.roundTripper.runCtx.Err() != nil) != tc.closed {
				t.Fatalf("unexpected sharing/close state: shared=%v closed=%v", m.sharedClient == c, c.roundTripper.runCtx.Err())
			}
			release()
			if (len(m.clients) == 1) != tc.shared {
				t.Fatal("attempt release leaked candidate or removed shared client")
			}
		})
	}
}

// TestInproxyBrokerNoMatchBeforePublication verifies that transport success
// alone neither publishes a client nor wakes acquisition waiters, and that a
// decoded NoMatch offer is resolved by the failover probability before the
// client is shared. Retain shares and wakes the gate; failover closes the
// client, advances the personal rendezvous broker, and preserves the stored
// replay record.
func TestInproxyBrokerNoMatchBeforePublication(t *testing.T) {
	for _, personal := range []bool{false, true} {
		for _, failover := range []bool{false, true} {
			t.Run(fmt.Sprintf("personal=%v/failover=%v", personal, failover), func(t *testing.T) {
				m := newGateTestManager(t)
				if personal {
					id, err := inproxy.MakeID()
					if err != nil {
						t.Fatal(err)
					}
					m.config.InproxyClientPersonalCompartmentID = id.String()
				}
				probability := 0.0
				if failover {
					probability = 1
				}
				if err := setGateTestParameters(m.config, "no-match", map[string]interface{}{
					parameters.InproxyClientMaxBrokerClients:                   1,
					parameters.InproxyClientNoMatchFailoverProbability:         probability,
					parameters.InproxyClientNoMatchFailoverPersonalProbability: probability,
				}); err != nil {
					t.Fatal(err)
				}
				c := getGateTestClient(t, m)
				_, _, changed, err := m.tryGetClientBrokerClient("TEST")
				if err != nil || changed == nil {
					t.Fatalf("expected full gate: %v", err)
				}
				c.BrokerClientRoundTripperSucceeded(c.roundTripper)
				if m.sharedClient != nil {
					t.Fatal("transport callback published before decode")
				}
				select {
				case <-changed:
					t.Fatal("transport callback woke acquisition waiters")
				default:
				}
				c.BrokerClientResponseReceived(c.roundTripper, true)
				if (m.sharedClient == c) == failover {
					t.Fatal("NoMatch publication ignored probability")
				}
				if failover && personal && m.selector.currentBrokerSelection.index != c.brokerSelection.index+1 {
					t.Fatal("personal failover did not skip to next broker")
				}
				stored := loadBrokerReplayTestParameters(t, c.brokerDialParams.brokerSpec)
				if stored == nil || len(c.brokerDialParams.replayRecordHash) == 0 ||
					!bytes.Equal(stored.replayRecordHash, c.brokerDialParams.replayRecordHash) {
					t.Fatal("NoMatch lost successful replay record")
				}
				select {
				case <-changed:
				default:
					t.Fatal("response policy did not wake gate")
				}
			})
		}
	}
}

// TestInproxyBrokerConcurrentOfferOutcomes verifies that a concurrent NoMatch
// failover on one candidate and a match on another always leave the match
// shared, close only the NoMatch client, and leave a third connection-owned
// client untouched. Late responses for the closed client and a mismatched
// round tripper cannot evict the shared client.
func TestInproxyBrokerConcurrentOfferOutcomes(t *testing.T) {
	m := newGateTestManager(t)
	if err := setGateTestParameters(m.config, "race", map[string]interface{}{
		parameters.InproxyClientNoMatchFailoverProbability: 1.0,
		parameters.InproxyClientMaxBrokerClients:           3,
	}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		a, b, c := getGateTestClient(t, m), getGateTestClient(t, m), getGateTestClient(t, m)
		a.BrokerClientRoundTripperSucceeded(a.roundTripper)
		b.BrokerClientRoundTripperSucceeded(b.roundTripper)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for _, op := range []func(){
			func() { a.BrokerClientResponseReceived(a.roundTripper, true) },
			func() { b.BrokerClientResponseReceived(b.roundTripper, false) },
		} {
			wg.Add(1)
			go func(op func()) { defer wg.Done(); <-start; op() }(op)
		}
		close(start)
		wg.Wait()
		// NoMatch may precede or follow B's match. Neither ordering can
		// let A replace or evict B, or disturb C's connection-owned
		// work.
		if m.sharedClient != b || len(m.clients) != 2 ||
			a.roundTripper.runCtx.Err() == nil || c.roundTripper.runCtx.Err() != nil {
			t.Fatal("concurrent outcomes corrupted sharing or independent ownership")
		}
		a.BrokerClientResponseReceived(a.roundTripper, false)
		a.BrokerClientResponseReceived(a.roundTripper, true)
		b.BrokerClientResponseReceived(a.roundTripper, true)
		if m.sharedClient != b || b.roundTripper.runCtx.Err() != nil {
			t.Fatal("stale or mismatched response evicted winner")
		}
		m.closeClientBrokerClients()
	}
}

// TestInproxyBrokerDecodedRelayReplacement verifies that after the shared
// client fails, a surviving candidate becomes shared only when it receives a
// decoded relayed-packet response, and that it stays shared and open after
// its own lease is released.
func TestInproxyBrokerDecodedRelayReplacement(t *testing.T) {
	payload, err := inproxy.MarshalClientRelayedPacketResponse(&inproxy.ClientRelayedPacketResponse{
		PacketToServer: []byte("reply"),
	})
	if err != nil {
		t.Fatal(err)
	}
	m, survivor, release := newBrokerResponseTestClient(t, payload)
	shared := getGateTestClient(t, m)
	shared.brokerResponseSucceededForTest(shared.roundTripper)
	shared.BrokerClientRoundTripperFailed(shared.roundTripper)
	if m.sharedClient != nil {
		t.Fatal("failure promoted standby without a response")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	response, err := survivor.brokerClient.ClientRelayedPacket(ctx, &inproxy.ClientRelayedPacketRequest{})
	if err != nil || !bytes.Equal(response.PacketToServer, []byte("reply")) {
		t.Fatalf("relay failed: %v", err)
	}
	release()
	if getGateTestClient(t, m) != survivor || survivor.roundTripper.runCtx.Err() != nil {
		t.Fatal("decoded relay did not promote survivor independently of connection lifetime")
	}
}

// inproxyCountingTestTransport counts broker transport round trips, which
// distinguishes Noise handshake packets from requests on an established
// session.
type inproxyCountingTestTransport struct {
	*inproxyRelayTestTransport
	roundTrips atomic.Int32
}

func (c *inproxyCountingTestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	c.roundTrips.Add(1)
	return c.inproxyRelayTestTransport.RoundTrip(req)
}

// TestInproxyBrokerFirstOfferOrdering checks that, with waitToShareSession
// disabled for clients and M=1, a second tunnel worker cannot send an offer
// on a fresh broker client's Noise session until the first offer on that
// session has received its decoded response. The broker client manager
// provides this ordering: a new broker client is held by a single caller
// until a decoded response makes it shared. Once shared, the second offer
// reuses the established session without a handshake.
func TestInproxyBrokerFirstOfferOrdering(t *testing.T) {
	for _, tc := range []struct {
		name  string
		offer inproxy.ClientOfferResponse
	}{
		{name: "match"},
		{name: "no-match-retain", offer: inproxy.ClientOfferResponse{NoMatch: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload, err := inproxy.MarshalClientOfferResponse(&tc.offer)
			if err != nil {
				t.Fatal(err)
			}
			m, a, releaseA := newBrokerResponseTestClient(t, nil)
			if err := setGateTestParameters(m.config, "ordering", map[string]interface{}{
				parameters.InproxyClientMaxBrokerClients:           1,
				parameters.InproxyClientNoMatchFailoverProbability: 0.0,
			}); err != nil {
				t.Fatal(err)
			}
			if !a.DisableWaitToShareSession() {
				t.Fatal("test expects the client waitToShareSession default")
			}
			gate := make(chan struct{})
			firstArrived := make(chan struct{})
			firstReturned := make(chan struct{})
			var mutex sync.Mutex
			var order []string
			var orderErr error
			conn := a.roundTripper.conn
			transport := &inproxyCountingTestTransport{
				inproxyRelayTestTransport: &inproxyRelayTestTransport{
					sessions: conn.transport.(*inproxyRelayTestTransport).sessions,
				},
			}
			transport.handle = func(request []byte) ([]byte, error) {
				req, err := inproxy.UnmarshalClientOfferRequest(request)
				if err != nil {
					return nil, err
				}
				mutex.Lock()
				order = append(order, req.DestinationAddress)
				first := len(order) == 1
				if !first {
					select {
					case <-firstReturned:
					default:
						orderErr = stderrors.New("second offer sent before first response")
					}
				}
				mutex.Unlock()
				if first {
					close(firstArrived)
					<-gate
				}
				return payload, nil
			}
			conn.transport = transport

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			offerErrs := make(chan error, 1)
			go func() {
				_, err := a.brokerClient.ClientOffer(
					ctx, &inproxy.ClientOfferRequest{DestinationAddress: "1"}, false)
				close(firstReturned)
				offerErrs <- err
			}()
			select {
			case <-firstArrived:
			case <-ctx.Done():
				t.Fatal("first offer did not reach broker")
			}

			// The first offer's bundled handshake and request are
			// in flight. With M=1 and no shared client, a second
			// worker must wait.
			type acquired struct {
				client  *inproxy.BrokerClient
				release func()
				err     error
			}
			acquisitions := make(chan acquired, 1)
			go func() {
				client, _, release, err := m.GetBrokerClient(ctx, "TEST")
				acquisitions <- acquired{client, release, err}
			}()
			select {
			case <-acquisitions:
				t.Fatal("second worker acquired a broker client before the first response")
			case <-time.After(50 * time.Millisecond):
			}
			m.mutex.Lock()
			shared, live := m.sharedClient, len(m.clients)
			m.mutex.Unlock()
			if shared != nil || live != 1 {
				t.Fatal("unproven broker client was shared or a second client was created")
			}

			close(gate)
			if err := <-offerErrs; err != nil {
				t.Fatalf("first offer failed: %v", err)
			}
			var second acquired
			select {
			case second = <-acquisitions:
			case <-ctx.Done():
				t.Fatal("second worker not woken by promotion")
			}
			if second.err != nil {
				t.Fatal(second.err)
			}
			defer second.release()
			if second.client != a.brokerClient || m.sharedClient != a {
				t.Fatal("second worker did not receive the shared broker client")
			}
			handshakeRoundTrips := transport.roundTrips.Load()
			if _, err := second.client.ClientOffer(
				ctx, &inproxy.ClientOfferRequest{DestinationAddress: "2"}, false); err != nil {
				t.Fatalf("second offer failed: %v", err)
			}
			mutex.Lock()
			defer mutex.Unlock()
			if orderErr != nil {
				t.Fatal(orderErr)
			}
			if len(order) != 2 || order[0] != "1" || order[1] != "2" {
				t.Fatalf("unexpected offer order: %v", order)
			}
			// XK: two handshake round trips, the second bundling
			// the first offer. The second offer reuses the
			// established session in one.
			if handshakeRoundTrips != 2 || transport.roundTrips.Load() != 3 {
				t.Fatalf("unexpected round trips: handshake=%d total=%d",
					handshakeRoundTrips, transport.roundTrips.Load())
			}
			releaseA()
		})
	}
}

// TestInproxyBrokerShareOnTransport verifies transport-time sharing under
// Inproxy{Client,Proxy}ShareBrokerClientTransportProbability: once a fresh broker
// client's transport is established it becomes shared before any broker
// response, so a second worker acquires it and, with waitToShareSession
// disabled, sends its own offer with its own Noise handshake concurrently
// over the same connection; a later decoded response leaves sharing
// unchanged; a transport failure on the shared client unshares it and the
// second worker's next acquisition selects a new client; and a client whose
// first request fails is not shared. With the tactic off, the first-offer
// ordering of TestInproxyBrokerFirstOfferOrdering holds.
func TestInproxyBrokerShareOnTransport(t *testing.T) {
	t.Run("concurrent-offers", func(t *testing.T) {
		payload, err := inproxy.MarshalClientOfferResponse(&inproxy.ClientOfferResponse{})
		if err != nil {
			t.Fatal(err)
		}
		m, a, releaseA := newBrokerResponseTestClientWithParameters(t, nil, map[string]interface{}{
			parameters.InproxyClientMaxBrokerClients:                      1,
			parameters.InproxyClientShareBrokerClientTransportProbability: 1.0,
		})
		if !a.DisableWaitToShareSession() {
			t.Fatal("test expects the client waitToShareSession default")
		}
		gate := make(chan struct{})
		firstArrived := make(chan struct{})
		var mutex sync.Mutex
		var order []string
		conn := a.roundTripper.conn
		transport := &inproxyCountingTestTransport{
			inproxyRelayTestTransport: &inproxyRelayTestTransport{
				sessions: conn.transport.(*inproxyRelayTestTransport).sessions,
			},
		}
		transport.handle = func(request []byte) ([]byte, error) {
			req, err := inproxy.UnmarshalClientOfferRequest(request)
			if err != nil {
				return nil, err
			}
			mutex.Lock()
			order = append(order, req.DestinationAddress)
			first := len(order) == 1
			mutex.Unlock()
			if first {
				close(firstArrived)
				<-gate
			}
			return payload, nil
		}
		conn.transport = transport

		// The fixture pre-dials the transport, so the round tripper's
		// transport-established callback did not run. Fire it as the
		// completed DialMeek would, before any request.
		if a.roundTripper.transportEstablished == nil {
			t.Fatal("tactic did not wire the transport-established callback")
		}
		a.roundTripper.transportEstablished()
		if m.sharedClient != a {
			t.Fatal("transport establishment did not share the client")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		offerErrs := make(chan error, 2)
		go func() {
			_, err := a.brokerClient.ClientOffer(
				ctx, &inproxy.ClientOfferRequest{DestinationAddress: "1"}, false)
			offerErrs <- err
		}()
		select {
		case <-firstArrived:
		case <-ctx.Done():
			t.Fatal("first offer did not reach broker")
		}

		// The first offer's bundled handshake is held at the broker. A
		// second worker acquires the shared client immediately and its
		// offer, with its own handshake, reaches the broker before the
		// first response.
		client, _, releaseB, err := m.GetBrokerClient(ctx, "TEST")
		if err != nil {
			t.Fatal(err)
		}
		defer releaseB()
		if client != a.brokerClient || len(m.clients) != 1 {
			t.Fatal("second worker did not receive the transport-shared client")
		}
		go func() {
			_, err := client.ClientOffer(
				ctx, &inproxy.ClientOfferRequest{DestinationAddress: "2"}, false)
			offerErrs <- err
		}()
		deadline := time.Now().Add(2 * time.Second)
		for {
			mutex.Lock()
			n := len(order)
			mutex.Unlock()
			if n == 2 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("second offer did not reach the broker while the first was held")
			}
			time.Sleep(5 * time.Millisecond)
		}
		close(gate)
		for i := 0; i < 2; i++ {
			if err := <-offerErrs; err != nil {
				t.Fatalf("offer failed: %v", err)
			}
		}
		// Two independent XK handshakes, two round trips each, on one
		// transport; no third round trip for a shared session.
		if got := transport.roundTrips.Load(); got != 4 {
			t.Fatalf("unexpected round trips: %d, want 4 (two concurrent handshakes)", got)
		}
		if m.sharedClient != a || m.clients[a].failed {
			t.Fatal("decoded responses changed transport-time sharing")
		}

		// A transport failure unshares the client. With M=1 the failed
		// client occupies the slot while its leases drain; once released
		// it closes and the next acquisition constructs a new client.
		a.BrokerClientRoundTripperFailed(a.roundTripper)
		if m.sharedClient != nil || !m.clients[a].failed {
			t.Fatal("failure did not unshare the transport-shared client")
		}
		releaseB()
		releaseA()
		if m.clients[a] != nil || a.roundTripper.runCtx.Err() == nil {
			t.Fatal("failed client did not close on its last release")
		}
		next := getGateTestClient(t, m)
		if next == a {
			t.Fatal("acquisition after failure reused the failed client")
		}
	})

	t.Run("failed-first-request-not-shared", func(t *testing.T) {
		m := newGateTestManager(t)
		if err := setGateTestParameters(m.config, "transport", map[string]interface{}{
			parameters.InproxyClientMaxBrokerClients:                      2,
			parameters.InproxyClientShareBrokerClientTransportProbability: 1.0,
		}); err != nil {
			t.Fatal(err)
		}
		var release func()
		c := getGateTestClient(t, m, &release)
		// Mark failed before the transport callback, as a DialMeek that
		// succeeds and whose first request then fails would.
		c.BrokerClientRoundTripperFailed(c.roundTripper)
		if c.roundTripper.transportEstablished == nil {
			t.Fatal("tactic did not wire the transport-established callback")
		}
		c.roundTripper.transportEstablished()
		if m.sharedClient != nil {
			t.Fatal("failed client was shared on transport")
		}
		release()
	})

	t.Run("round-tripper-callback-site", func(t *testing.T) {
		// The callback is invoked only by the dialing RoundTrip caller
		// after a successful DialMeek: a dial aborted by the caller does
		// not invoke it, and a caller that then awaits the completed dial
		// returns the cached error without invoking it.
		m := newGateTestManager(t)
		if err := setGateTestParameters(m.config, "transport", map[string]interface{}{
			parameters.InproxyClientShareBrokerClientTransportProbability: 1.0,
		}); err != nil {
			t.Fatal(err)
		}
		c := getGateTestClient(t, m)
		if c.roundTripper.transportEstablished == nil {
			t.Fatal("tactic did not wire the transport-established callback")
		}
		cancelled, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := c.roundTripper.RoundTrip(cancelled, 0, time.Second, nil); err == nil {
			t.Fatal("aborted dial succeeded")
		}
		if m.sharedClient != nil {
			t.Fatal("callback shared the client after an aborted dial")
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if _, err := c.roundTripper.RoundTrip(ctx, 0, time.Second, nil); err == nil {
			t.Fatal("awaiting caller succeeded on a cached dial error")
		}
		if m.sharedClient != nil {
			t.Fatal("awaiting caller shared the client")
		}
	})
}

// TestInproxyBrokerShareOnTransportProbability verifies that the
// share-on-transport decision is a per-broker-client coin flip at
// construction: at probability 0 no client wires the transport callback, at
// 1 every client does, and at 0.5 a population of clients contains both
// kinds, so a deployment can run a mix of transport-time and
// response-time sharing.
func TestInproxyBrokerShareOnTransportProbability(t *testing.T) {
	for _, tc := range []struct {
		probability float64
		wantMin     int
		wantMax     int
	}{
		{0.0, 0, 0},
		{1.0, 40, 40},
		{0.5, 1, 39},
	} {
		t.Run(fmt.Sprintf("p=%v", tc.probability), func(t *testing.T) {
			m := newGateTestManager(t)
			if err := setGateTestParameters(m.config, "share-probability", map[string]interface{}{
				parameters.InproxyClientShareBrokerClientTransportProbability: tc.probability,
			}); err != nil {
				t.Fatal(err)
			}
			wired := 0
			for i := 0; i < 40; i++ {
				var release func()
				c := getGateTestClient(t, m, &release)
				if c.roundTripper.transportEstablished != nil {
					wired++
				}
				release()
			}
			if wired < tc.wantMin || wired > tc.wantMax {
				t.Fatalf("probability %v wired the transport callback on %d of 40 clients", tc.probability, wired)
			}
		})
	}
}

// TestInproxyBrokerShareOnTransportRealDial drives a fresh broker client's
// own DialMeek against a local TLS server so the round tripper's CAS branch
// runs. With Inproxy{Client,Proxy}ShareBrokerClientTransportProbability on, the client
// is shared as soon as the TLS transport is established, while the first
// request is still held at the server; off, it is shared only after the
// first decoded response. Both broker client managers are checked.
func TestInproxyBrokerShareOnTransportRealDial(t *testing.T) {
	for _, tc := range []struct {
		name  string
		proxy bool
		on    bool
	}{
		{"client/off", false, false},
		{"client/on", false, true},
		{"proxy/off", true, false},
		{"proxy/on", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			privateKey, err := inproxy.GenerateSessionPrivateKey()
			if err != nil {
				t.Fatal(err)
			}
			publicKey, err := privateKey.GetPublicKey()
			if err != nil {
				t.Fatal(err)
			}
			secret, err := inproxy.GenerateRootObfuscationSecret()
			if err != nil {
				t.Fatal(err)
			}
			sessions, err := inproxy.NewResponderSessions(privateKey, secret, 0)
			if err != nil {
				t.Fatal(err)
			}
			// The server holds the first request until released, so
			// the window between transport establishment and first
			// response is observable.
			arrived, proceed := make(chan struct{}), make(chan struct{})
			var arrivedOnce sync.Once
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				arrivedOnce.Do(func() { close(arrived) })
				select {
				case <-proceed:
				case <-r.Context().Done():
					return
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				packet, err := sessions.HandlePacket(body, func(_ inproxy.ID, _ []byte) ([]byte, error) {
					if tc.proxy {
						return inproxy.MarshalProxyAnnounceResponse(&inproxy.ProxyAnnounceResponse{NoMatch: true})
					}
					return inproxy.MarshalClientRelayedPacketResponse(&inproxy.ClientRelayedPacketResponse{})
				})
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				w.Write(packet)
			}))
			defer server.Close()
			spec := &parameters.InproxyBrokerSpec{BrokerPublicKey: publicKey.String(),
				BrokerRootObfuscationSecret: secret.String(), BrokerFrontingSpecs: parameters.FrontingSpecs{
					{FrontingProviderID: "AA", Addresses: []string{regexp.QuoteMeta(server.Listener.Addr().String())}, Host: "example.org", SkipVerify: true},
				}}
			m := newProviderTestManager(t, 1, spec)
			m.isProxy = tc.proxy
			params := map[string]interface{}{
				parameters.InproxyBrokerSpecs:                                 parameters.InproxyBrokerSpecsValue{spec},
				parameters.InproxyProxyBrokerSpecs:                            parameters.InproxyBrokerSpecsValue{spec},
				parameters.InproxyClientMaxBrokerClients:                      1,
				parameters.InproxyProxyMaxBrokerClients:                       1,
				parameters.InproxyReplayBrokerDialParametersProbability:       0.0,
				parameters.InproxyClientShareBrokerClientTransportProbability: boolProbability(tc.on && !tc.proxy),
				parameters.InproxyProxyShareBrokerClientTransportProbability:  boolProbability(tc.on && tc.proxy),
			}
			if err := setGateTestParameters(m.config, "", params); err != nil {
				t.Fatal(err)
			}
			a := getGateTestClient(t, m)
			if (a.roundTripper.transportEstablished != nil) != tc.on {
				t.Fatalf("callback wired=%v, want %v", a.roundTripper.transportEstablished != nil, tc.on)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			result := make(chan error, 1)
			go func() {
				var err error
				if tc.proxy {
					_, err = a.brokerClient.ProxyAnnounce(ctx, 0, &inproxy.ProxyAnnounceRequest{})
				} else {
					_, err = a.brokerClient.ClientRelayedPacket(ctx, &inproxy.ClientRelayedPacketRequest{})
				}
				result <- err
			}()
			select {
			case <-arrived:
			case <-ctx.Done():
				t.Fatal("first request did not reach the server")
			}
			// Transport is established and the first request is in flight.
			// Record the sharing state, then release the server before
			// asserting so a failed assertion cannot deadlock shutdown.
			m.mutex.Lock()
			sharedBeforeResponse := m.sharedClient == a
			m.mutex.Unlock()
			close(proceed)
			requestErr := <-result
			if sharedBeforeResponse != tc.on {
				t.Fatalf("shared before first response: %v, want %v", sharedBeforeResponse, tc.on)
			}
			if requestErr != nil {
				t.Fatalf("first request failed: %v", requestErr)
			}
			m.mutex.Lock()
			sharedAfter := m.sharedClient == a
			m.mutex.Unlock()
			if !sharedAfter {
				t.Fatal("client not shared after first decoded response")
			}
		})
	}
}

// initializeTestSelector initializes s from m's current parameters and
// returns the resulting seeded broker order.
func initializeTestSelector(t *testing.T, m *InproxyBrokerClientManager, s *inproxyBrokerSelector) parameters.InproxyBrokerSpecsValue {
	t.Helper()
	p := m.config.GetParameters().Get()
	defer p.Close()
	if err := s.initialize(m.config, p, m.isProxy); err != nil {
		t.Fatal(err)
	}
	return s.brokers
}

// TestInproxyBrokerStableCommonOrder verifies that a seeded common-client
// selector visits every eligible broker once before wrapping, that the order
// is stable across acquisitions, and that distinct seeds produce distinct
// broker orders.
func TestInproxyBrokerStableCommonOrder(t *testing.T) {
	specs := parameters.InproxyBrokerSpecsValue{}
	for i := 0; i < 5; i++ {
		specs = append(specs, newProviderTestBroker(t, "A"))
	}
	m := newProviderTestManager(t, 1, specs...)
	m.selector.seed = &prng.Seed{1}
	order := initializeTestSelector(t, m, &m.selector)
	seen := make(map[string]bool)
	for i := 0; i < 15; i++ {
		var release func()
		client := getGateTestClient(t, m, &release)
		key := client.brokerDialParams.brokerSpec.BrokerPublicKey
		if i < len(specs) && seen[key] {
			t.Fatal("fresh broker repeated before complete eligible coverage")
		}
		seen[key] = true
		if client.brokerDialParams.brokerSpec.BrokerPublicKey != order[i%len(order)].BrokerPublicKey {
			t.Fatalf("candidate %d broke fixed ordering/wraparound", i)
		}
		release()
	}
	// Fixed test seeds avoid probabilistic assertions about session
	// independence.
	orders := make(map[string]bool)
	for i := byte(0); i < 16; i++ {
		o := inproxyBrokerSelector{seed: &prng.Seed{i}}
		ordered := initializeTestSelector(t, m, &o)
		key := ""
		for _, spec := range ordered {
			key += spec.BrokerPublicKey
		}
		orders[key] = true
	}
	if len(orders) < 2 {
		t.Fatal("independent session seeds produced only one order")
	}
}

// TestInproxyBrokerSparseProviderCoverage verifies per-provider broker
// cursors: with one broker supporting A and B and two supporting only B,
// fresh selections alternate providers and B visits all three brokers in
// order rather than alternating between two.
func TestInproxyBrokerSparseProviderCoverage(t *testing.T) {
	// A single global cursor would alternate A@0 and B@1 forever, starving
	// B@2. Per-provider cursors must cover every compatible pair.
	specs := parameters.InproxyBrokerSpecsValue{
		newProviderTestBroker(t, "A", "B"), newProviderTestBroker(t, "B"), newProviderTestBroker(t, "B"),
	}
	m := newProviderTestManager(t, 2, specs...)
	m.config.DisableReplay = true
	p := m.config.GetParameters().Get()
	defer p.Close()
	s := &inproxyBrokerSelector{brokers: specs, providers: []string{"A", "B"}}
	var bIndexes []int
	for i := 0; i < 12; i++ {
		selection, err := s.selectClient(m.config, p, "TEST", false, nil)
		if err != nil {
			t.Fatal(err)
		}
		provider := selection.frontingSpecs[0].FrontingProviderID
		if provider != []string{"A", "B"}[i%2] {
			t.Fatal("fresh selection did not rotate providers breadth-first")
		}
		if provider == "B" {
			for index, spec := range specs {
				if selection.brokerSpec == spec {
					bIndexes = append(bIndexes, index)
					break
				}
			}
		}
	}
	if !reflect.DeepEqual(bIndexes, []int{1, 2, 0, 1, 2, 0}) {
		t.Fatalf("sparse provider starved eligible brokers: %v", bIndexes)
	}
}

// TestInproxyBrokerDiverseReplay verifies that replay is used at most once
// per provider per search, prefers unused providers, falls back to fresh
// dial parameters once providers repeat, is not replenished by releasing
// every candidate, and never deletes valid records that were skipped for
// diversity.
func TestInproxyBrokerDiverseReplay(t *testing.T) {
	for _, duplicate := range []bool{false, true} {
		name := "distinct"
		if duplicate {
			name = "duplicate"
		}
		t.Run(name, func(t *testing.T) {
			specs := parameters.InproxyBrokerSpecsValue{
				newProviderTestBroker(t, "A", "B", "C"), newProviderTestBroker(t, "A", "B", "C"), newProviderTestBroker(t, "A", "B", "C"),
			}
			m := newProviderTestManager(t, 4, specs...)
			records := make([][]byte, len(specs))
			for i, spec := range specs {
				provider := []string{"A", "B", "C"}[i]
				if duplicate {
					provider = "A"
				}
				params := makeBrokerReplayTestParameters(t, m, spec, provider)
				if err := storeInproxyBrokerReplayParameters("TEST", params); err != nil {
					t.Fatal(err)
				}
				records[i] = params.replayRecordHash
			}
			seen := make(map[string]bool)
			var releases []func()
			for i := 0; i < 4; i++ {
				var release func()
				c := getGateTestClient(t, m, &release)
				releases = append(releases, release)
				provider := checkProviderTestClient(t, c)
				if i < 3 && seen[provider] {
					t.Fatal("duplicate provider before exhausting diversity")
				}
				wantReplay := i < 3 && (!duplicate || i == 0)
				if c.brokerDialParams.isReplay != wantReplay {
					t.Fatalf("candidate %d: replay=%v want %v", i, c.brokerDialParams.isReplay, wantReplay)
				}
				seen[provider] = true
			}
			for _, release := range releases {
				release()
			}
			// Abandoning all attempts does not restart replay
			// allowances.
			for i := 0; i < 6; i++ {
				var release func()
				c := getGateTestClient(t, m, &release)
				if c.brokerDialParams.isReplay {
					t.Fatal("empty live set restarted consumed provider replay")
				}
				release()
			}
			for i, spec := range specs {
				stored := loadBrokerReplayTestParameters(t, spec)
				if stored == nil || !bytes.Equal(stored.replayRecordHash, records[i]) {
					t.Fatal("diversity rejection deleted a valid replay record")
				}
			}
		})
	}
}

// TestInproxyBrokerNoMatchFailoverChangesBroker verifies that a common
// pairing client's NoMatch failover does not offer again at the broker that
// reported no supply. With two providers and the later-created candidate
// winning sharing, the other provider's cursor sits at the broker that just
// returned NoMatch; the order-first selection must pass over it to that
// provider's next broker. With a single broker the failover has nowhere
// else to go and selects it again, and a selection after the failover
// selection no longer skips it.
func TestInproxyBrokerNoMatchFailoverChangesBroker(t *testing.T) {
	for _, brokers := range []int{4, 1} {
		t.Run(fmt.Sprintf("brokers=%d", brokers), func(t *testing.T) {
			var specs []*parameters.InproxyBrokerSpec
			for i := 0; i < brokers; i++ {
				specs = append(specs, newProviderTestBroker(t, "A", "B"))
			}
			for trial := 0; trial < 10; trial++ {
				m := newProviderTestManager(t, 2, specs...)
				if err := setGateTestParameters(m.config, "", map[string]interface{}{
					parameters.InproxyBrokerSpecs:                           parameters.InproxyBrokerSpecsValue(specs),
					parameters.InproxyClientMaxBrokerClients:                2,
					parameters.InproxyReplayBrokerDialParametersProbability: 0.0,
					parameters.InproxyClientNoMatchFailoverProbability:      1.0,
				}); err != nil {
					t.Fatal(err)
				}
				var releaseA, releaseB func()
				a := getGateTestClient(t, m, &releaseA)
				b := getGateTestClient(t, m, &releaseB)
				m.mutex.Lock()
				m.closeClientLocked(a, "lost the race")
				m.mutex.Unlock()
				releaseA()
				b.brokerResponseSucceededForTest(b.roundTripper)
				b.BrokerClientResponseReceived(b.roundTripper, true)
				releaseB()
				next := getGateTestClient(t, m)
				sameBroker := next.brokerDialParams.brokerSpec == b.brokerDialParams.brokerSpec
				if sameBroker != (brokers == 1) {
					t.Fatalf("trial %d: failover selected the NoMatch broker again: %v (providers %s then %s)",
						trial, sameBroker, b.frontingProviderID, next.frontingProviderID)
				}
				m.mutex.Lock()
				cleared := m.selector.noMatchBroker == nil && !m.selector.preferBrokerOrder
				m.mutex.Unlock()
				if !cleared {
					t.Fatal("failover selection did not clear the NoMatch broker")
				}
				m.closeClientBrokerClients()
			}
		})
	}
}

// TestInproxyBrokerReplayCursorAndNoMatch verifies that replay may jump ahead
// to a later broker in the common order and advances the provider cursor
// past it, and that after NoMatch failover the next selection follows broker
// order instead of replay.
func TestInproxyBrokerReplayCursorAndNoMatch(t *testing.T) {
	for _, preferBrokerOrder := range []bool{false, true} {
		name := "replay-first"
		if preferBrokerOrder {
			name = "no-match-order-first"
		}
		t.Run(name, func(t *testing.T) {
			specs := parameters.InproxyBrokerSpecsValue{newProviderTestBroker(t, "A"), newProviderTestBroker(t, "A"), newProviderTestBroker(t, "A")}
			m := newProviderTestManager(t, 1, specs...)
			m.selector.seed = &prng.Seed{2}
			ordered := initializeTestSelector(t, m, &m.selector)
			// The record is at the middle broker so that a cursor
			// advanced past it selects the last broker, which a
			// cursor left at the start would not.
			params := makeBrokerReplayTestParameters(t, m, ordered[1], "A")
			if err := storeInproxyBrokerReplayParameters("TEST", params); err != nil {
				t.Fatal(err)
			}
			// This fixture already initialized selection for the
			// current network.
			m.networkID = "TEST"
			m.selector.preferBrokerOrder = preferBrokerOrder
			var release func()
			c := getGateTestClient(t, m, &release)
			want := 1
			if preferBrokerOrder {
				want = 0
			}
			if c.brokerDialParams.brokerSpec.BrokerPublicKey != ordered[want].BrokerPublicKey || c.brokerDialParams.isReplay == preferBrokerOrder {
				t.Fatal("replay did not respect order-first exception")
			}
			release()
			if !preferBrokerOrder {
				next := getGateTestClient(t, m)
				if next.brokerDialParams.isReplay || next.brokerDialParams.brokerSpec.BrokerPublicKey != ordered[2].BrokerPublicKey {
					t.Fatal("replay did not advance provider cursor past chosen broker")
				}
			}
		})
	}
}

// TestInproxyBrokerNoMatchExactRouteReplay verifies that after common client
// NoMatch failover the next route is chosen by broker order, and that replay
// is still used at that exact broker when its stored provider's allowance is
// unconsumed: the search does not jump to a different broker for replay,
// but it does not forgo an eligible replay at the ordered broker either.
func TestInproxyBrokerNoMatchExactRouteReplay(t *testing.T) {
	// Three single-provider brokers, A, B and A. A seed is chosen so the
	// broker order is A, B, A: the first search replays ordered[0]; after
	// failover a correct order-first search stops at ordered[1] and
	// replays B there, while a replay-first search would skip to the A
	// record at ordered[2] only if it ignored the consumed A allowance.
	specs := parameters.InproxyBrokerSpecsValue{newProviderTestBroker(t, "A"), newProviderTestBroker(t, "B"), newProviderTestBroker(t, "A")}
	m := newProviderTestManager(t, 1, specs...)
	if err := setGateTestParameters(m.config, "no-match", map[string]interface{}{
		parameters.InproxyBrokerSpecs:                           specs,
		parameters.InproxyClientMaxBrokerClients:                1,
		parameters.InproxyReplayBrokerDialParametersProbability: 1.0,
		parameters.InproxyClientNoMatchFailoverProbability:      1.0,
	}); err != nil {
		t.Fatal(err)
	}
	var ordered parameters.InproxyBrokerSpecsValue
	for seed := byte(0); ; seed++ {
		m.selector.reset()
		m.selector.seed = &prng.Seed{seed}
		ordered = initializeTestSelector(t, m, &m.selector)
		got := ""
		for _, spec := range ordered {
			got += spec.BrokerFrontingSpecs[0].FrontingProviderID
		}
		if got == "ABA" {
			break
		}
		if seed == 255 {
			t.Fatal("no seed orders the brokers A, B, A")
		}
	}
	m.networkID = "TEST"
	for _, spec := range ordered {
		params := makeBrokerReplayTestParameters(t, m, spec, spec.BrokerFrontingSpecs[0].FrontingProviderID)
		if err := storeInproxyBrokerReplayParameters("TEST", params); err != nil {
			t.Fatal(err)
		}
	}
	// Start provider preference at A so the first search replays
	// ordered[0], the first A broker.
	m.selector.providers = []string{"A", "B"}
	first := getGateTestClient(t, m)
	if !first.brokerDialParams.isReplay || first.brokerPublicKey.String() != ordered[0].BrokerPublicKey {
		t.Fatal("first search did not replay the first ordered broker")
	}
	first.BrokerClientResponseReceived(first.roundTripper, true)
	if first.roundTripper.runCtx.Err() == nil || !m.selector.preferBrokerOrder {
		t.Fatal("NoMatch did not fail over with order-first selection")
	}
	next := getGateTestClient(t, m)
	if next.brokerPublicKey.String() != ordered[1].BrokerPublicKey || next.frontingProviderID != "B" {
		t.Fatalf("post-NoMatch selection did not follow broker order: broker %s provider %s",
			next.brokerPublicKey, next.frontingProviderID)
	}
	if !next.brokerDialParams.isReplay {
		t.Fatal("post-NoMatch selection did not replay the eligible record at the ordered broker")
	}
	if !m.selector.replayedByProvider["B"] || m.selector.preferBrokerOrder {
		t.Fatal("exact-route replay did not consume the allowance or clear order-first")
	}
}

// TestInproxyBrokerIdleExpiryPreservesReplay verifies that idle expiry of the
// shared client neither deletes the stored replay record nor leaves the
// provider's replay allowance consumed: the next search replays the same
// broker and provider, and a transport failure of that replayed client then
// deletes the record. One broker and one provider make the replayed route
// unambiguous.
func TestInproxyBrokerIdleExpiryPreservesReplay(t *testing.T) {
	spec := newProviderTestBroker(t, "A")
	m := newProviderTestManager(t, 1, spec)
	if err := setGateTestParameters(m.config, "", map[string]interface{}{
		parameters.InproxyBrokerSpecs:                           parameters.InproxyBrokerSpecsValue{spec},
		parameters.InproxyClientMaxBrokerClients:                1,
		parameters.InproxyReplayBrokerDialParametersProbability: 1.0,
		parameters.InproxyReplayBrokerRetainFailedProbability:   0.0,
		parameters.InproxyClientBrokerClientIdleTimeout:         "60s",
	}); err != nil {
		t.Fatal(err)
	}

	var release func()
	first := getGateTestClient(t, m, &release)
	if first.brokerDialParams.isReplay {
		t.Fatal("first client replayed with no stored record")
	}
	// Success stores the record and shares the client. Releasing the only
	// lease arms the idle timer; expiry then closes the shared client.
	first.brokerResponseSucceededForTest(first.roundTripper)
	if loadBrokerReplayTestParameters(t, spec) == nil {
		t.Fatal("success did not store a replay record")
	}
	if !m.selector.replayedByProvider["A"] {
		// The allowance is consumed only when a replay is selected; a fresh
		// dial leaves it clear. Consume it explicitly so the test checks
		// that expiry refreshes it, as it would after a replayed search.
		m.selector.replayedByProvider = map[string]bool{"A": true}
	}
	release()
	if m.sharedClient != first || m.sharedIdleTimer == nil {
		t.Fatal("released shared client did not arm the idle timer")
	}
	expireSharedClientForTest(m, first)
	if m.sharedClient != nil || len(m.clients) != 0 || first.roundTripper.runCtx.Err() == nil {
		t.Fatal("idle expiry did not close the shared client")
	}
	if len(m.selector.replayedByProvider) != 0 {
		t.Fatal("idle expiry did not refresh the replay allowance")
	}
	if loadBrokerReplayTestParameters(t, spec) == nil {
		t.Fatal("idle expiry deleted the replay record")
	}

	second := getGateTestClient(t, m)
	if !second.brokerDialParams.isReplay || second.frontingProviderID != "A" ||
		second.brokerDialParams.brokerSpec.BrokerPublicKey != spec.BrokerPublicKey {
		t.Fatal("search after idle expiry did not replay the stored route")
	}
	if !m.selector.replayedByProvider["A"] {
		t.Fatal("replay after idle expiry did not consume the allowance")
	}
	// The replayed client owns the record: its transport failure deletes it.
	second.BrokerClientRoundTripperFailed(second.roundTripper)
	if loadBrokerReplayTestParameters(t, spec) != nil {
		t.Fatal("replayed client failure did not delete the record")
	}
}

// TestInproxyProxyFailureRetryPeriod verifies the common pairing proxy's
// retention of a recently successful broker client across a transport
// failure: within InproxyProxyOnBrokerClientFailedRetryPeriod of the last
// success the client stays shared, is not marked failed and keeps its replay
// record; after the period, or in personal pairing mode, or for a client
// manager, the failure unshares and marks the client as usual.
func TestInproxyProxyFailureRetryPeriod(t *testing.T) {
	for _, mode := range []string{"within", "expired", "personal", "client"} {
		t.Run(mode, func(t *testing.T) {
			spec := newProviderTestBroker(t, "A")
			m := newProviderTestManager(t, 1, spec)
			m.isProxy = mode != "client"
			if mode == "personal" {
				id, err := inproxy.MakeID()
				if err != nil {
					t.Fatal(err)
				}
				m.config.InproxyProxyPersonalCompartmentID = id.String()
			}
			if err := setGateTestParameters(m.config, "", map[string]interface{}{
				parameters.InproxyBrokerSpecs:                           parameters.InproxyBrokerSpecsValue{spec},
				parameters.InproxyProxyMaxBrokerClients:                 1,
				parameters.InproxyClientMaxBrokerClients:                1,
				parameters.InproxyReplayBrokerDialParametersProbability: 1.0,
				parameters.InproxyReplayBrokerRetainFailedProbability:   0.0,
				parameters.InproxyProxyOnBrokerClientFailedRetryPeriod:  "1h",
			}); err != nil {
				t.Fatal(err)
			}
			var release func()
			c := getGateTestClient(t, m, &release)
			defer release()
			c.brokerResponseSucceededForTest(c.roundTripper)
			if m.sharedClient != c || loadBrokerReplayTestParameters(t, spec) == nil {
				t.Fatal("success did not share the client and store replay")
			}
			if mode == "expired" {
				c.mutex.Lock()
				c.lastSuccess = time.Now().Add(-2 * time.Hour)
				c.mutex.Unlock()
			}
			// Record a failure as RoundTrip would before the callback, so
			// the in-window branch's consumption of the record is tested
			// rather than a nil swap.
			c.roundTripper.recordFailure("request after 1s", stderrors.New("first"))
			c.BrokerClientRoundTripperFailed(c.roundTripper)
			retained := mode == "within"
			if (m.sharedClient == c) != retained || m.clients[c].failed == retained ||
				(loadBrokerReplayTestParameters(t, spec) != nil) != retained {
				t.Fatalf("retry period handling: shared=%v failed=%v replay=%v want retained=%v",
					m.sharedClient == c, m.clients[c].failed, loadBrokerReplayTestParameters(t, spec) != nil, retained)
			}
			if retained {
				// A retained client is still usable and still shared for
				// the next acquisition.
				if getGateTestClient(t, m) != c || c.roundTripper.runCtx.Err() != nil {
					t.Fatal("retained client was not reused")
				}
				// A failure ridden out within the retry window is not a
				// failure event: the instance is not marked failed, so a
				// later failure outside the window is processed in full.
				c.mutex.Lock()
				failedInWindow, loggedRetry := c.failed, c.loggedRetry
				c.mutex.Unlock()
				if failedInWindow {
					t.Fatal("in-window failure marked the instance failed")
				}
				// The in-window failure is logged once per window and
				// consumes the recorded failure; repeats within the
				// window neither log again nor retain a record, and a
				// success clears the throttle.
				if !loggedRetry || c.roundTripper.takeFailure() != nil {
					t.Fatal("in-window failure was not logged once with its record consumed")
				}
				c.roundTripper.recordFailure("request after 1s", stderrors.New("again"))
				c.BrokerClientRoundTripperFailed(c.roundTripper)
				if c.roundTripper.takeFailure() != nil {
					t.Fatal("repeated in-window failure retained its record")
				}
				c.BrokerClientRoundTripperSucceeded(c.roundTripper)
				c.mutex.Lock()
				loggedRetry = c.loggedRetry
				c.lastSuccess = time.Now().Add(-2 * time.Hour)
				c.mutex.Unlock()
				if loggedRetry {
					t.Fatal("success did not clear the retry log throttle")
				}
				c.BrokerClientRoundTripperFailed(c.roundTripper)
				c.mutex.Lock()
				failedAfterWindow := c.failed
				c.mutex.Unlock()
				if !failedAfterWindow || m.sharedClient == c || !m.clients[c].failed ||
					loadBrokerReplayTestParameters(t, spec) != nil {
					t.Fatal("failure outside the retry window was not processed")
				}
			}
		})
	}
}

// TestInproxyBrokerConcurrentInitialDial verifies the one-shot DialMeek
// handoff while a dial is in progress: a second caller awaits the first
// caller's dial rather than starting its own, its own deadline returns its
// context error without classifying a failure or closing the dial, the
// first caller's cancellation leaves a cached non-failure dial error, and a
// later caller receives that cached error immediately. The client is never
// marked failed.
func TestInproxyBrokerConcurrentInitialDial(t *testing.T) {
	// A listener that never accepts: the TCP connect completes from the
	// backlog and the TLS handshake blocks until the dial context ends.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	privateKey, err := inproxy.GenerateSessionPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := privateKey.GetPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	secret, err := inproxy.GenerateRootObfuscationSecret()
	if err != nil {
		t.Fatal(err)
	}
	spec := &parameters.InproxyBrokerSpec{BrokerPublicKey: publicKey.String(),
		BrokerRootObfuscationSecret: secret.String(), BrokerFrontingSpecs: parameters.FrontingSpecs{
			{FrontingProviderID: "AA", Addresses: []string{regexp.QuoteMeta(listener.Addr().String())}, Host: "example.org", SkipVerify: true},
		}}
	m := newProviderTestManager(t, 1, spec)
	if err := setGateTestParameters(m.config, "", map[string]interface{}{
		parameters.InproxyBrokerSpecs:                           parameters.InproxyBrokerSpecsValue{spec},
		parameters.InproxyClientMaxBrokerClients:                1,
		parameters.InproxyReplayBrokerDialParametersProbability: 0.0,
	}); err != nil {
		t.Fatal(err)
	}
	a := getGateTestClient(t, m)
	rt := a.roundTripper

	ctxA, cancelA := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelA()
	resultA := make(chan error, 1)
	go func() {
		_, err := rt.RoundTrip(ctxA, 0, 0, nil)
		resultA <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	for atomic.LoadInt32(&rt.dial) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("first caller did not start the dial")
		}
		time.Sleep(time.Millisecond)
	}

	ctxB, cancelB := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancelB()
	_, errB := rt.RoundTrip(ctxB, 0, 0, nil)
	var failure *inproxy.RoundTripperFailedError
	if !stderrors.Is(errB, context.DeadlineExceeded) || stderrors.As(errB, &failure) {
		t.Fatalf("awaiting caller's deadline: %v", errB)
	}
	select {
	case <-rt.dialCompleted:
		t.Fatal("awaiting caller's deadline ended the dial")
	default:
	}

	cancelA()
	errA := <-resultA
	if errA == nil || stderrors.As(errA, &failure) {
		t.Fatalf("cancelled initial dial classified as failure: %v", errA)
	}
	select {
	case <-rt.dialCompleted:
	default:
		t.Fatal("cancelled dial did not complete")
	}

	ctxC, cancelC := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelC()
	start := time.Now()
	_, errC := rt.RoundTrip(ctxC, 0, 0, nil)
	if errC == nil || stderrors.As(errC, &failure) || time.Since(start) > time.Second {
		t.Fatalf("later caller did not get the cached dial error promptly: %v", errC)
	}
	m.mutex.Lock()
	failed := m.clients[a] == nil || m.clients[a].failed
	m.mutex.Unlock()
	if failed {
		t.Fatal("caller-aborted initial dial marked the client failed")
	}
}

// TestInproxyBrokerFailureRecord verifies that each classification site in
// RoundTrip records the round tripper's first transport failure with the
// class describing its phase and the underlying error: a refused initial
// dial records dial; a request timeout records request with its duration;
// a non-200 within the status threshold records the status and duration
// while a slower one is not a failure and records nothing; and a stalled
// body read records body. RoundTrip is driven directly so the record is
// inspected before the coordinator's failure callback consumes it; the
// callback then consumes it, and a second record on the same round tripper
// does not replace the first.
func TestInproxyBrokerFailureRecord(t *testing.T) {
	var failure *inproxy.RoundTripperFailedError

	t.Run("dial", func(t *testing.T) {
		// A port that refuses connections: listen, note the address,
		// close the listener before dialing.
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		address := listener.Addr().String()
		listener.Close()
		privateKey, err := inproxy.GenerateSessionPrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		publicKey, err := privateKey.GetPublicKey()
		if err != nil {
			t.Fatal(err)
		}
		secret, err := inproxy.GenerateRootObfuscationSecret()
		if err != nil {
			t.Fatal(err)
		}
		spec := &parameters.InproxyBrokerSpec{BrokerPublicKey: publicKey.String(),
			BrokerRootObfuscationSecret: secret.String(), BrokerFrontingSpecs: parameters.FrontingSpecs{
				{FrontingProviderID: "AA", Addresses: []string{regexp.QuoteMeta(address)}, Host: "example.org", SkipVerify: true},
			}}
		m := newProviderTestManager(t, 1, spec)
		if err := setGateTestParameters(m.config, "", map[string]interface{}{
			parameters.InproxyBrokerSpecs:                           parameters.InproxyBrokerSpecsValue{spec},
			parameters.InproxyClientMaxBrokerClients:                1,
			parameters.InproxyReplayBrokerDialParametersProbability: 0.0,
		}); err != nil {
			t.Fatal(err)
		}
		c := getGateTestClient(t, m)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err = c.roundTripper.RoundTrip(ctx, 0, 0, nil)
		if !stderrors.As(err, &failure) {
			t.Fatalf("refused dial not classified: %v", err)
		}
		recorded := c.roundTripper.failure.Load()
		if recorded == nil || recorded.class != "dial" || recorded.err == nil {
			t.Fatalf("dial failure not recorded: %v", recorded)
		}
		c.BrokerClientRoundTripperFailed(c.roundTripper)
		if c.roundTripper.failure.Load() != nil || !m.clients[c].failed {
			t.Fatal("failure callback did not consume the record and fail the client")
		}
	})

	payload, err := inproxy.MarshalClientRelayedPacketResponse(&inproxy.ClientRelayedPacketResponse{PacketToServer: []byte("reply")})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		phase     string
		status    int
		threshold time.Duration
		wantClass string
	}{
		{name: "request-timeout", phase: "request", wantClass: "request after "},
		{name: "fast-non-200", phase: "status", status: http.StatusBadGateway, threshold: time.Hour, wantClass: "status 502 after "},
		{name: "slow-non-200", phase: "status", status: http.StatusBadGateway, threshold: time.Nanosecond},
		{name: "body-timeout", phase: "body", wantClass: "body"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, c, release := newBrokerResponseTestClient(t, payload)
			defer release()
			c.replayRetainFailedProbability = 0
			sessionCtx, cancelSession := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancelSession()
			if _, err := c.brokerClient.ClientRelayedPacket(sessionCtx, &inproxy.ClientRelayedPacketRequest{}); err != nil {
				t.Fatal(err)
			}
			if m.sharedClient != c {
				t.Fatal("session request did not share the client")
			}
			if tc.threshold != 0 {
				c.roundTripper.failureThreshold = tc.threshold
			}
			c.roundTripper.conn.transport = brokerHTTPTestTransport(func(req *http.Request) (*http.Response, error) {
				switch tc.phase {
				case "request":
					<-req.Context().Done()
					return nil, req.Context().Err()
				case "body":
					return &http.Response{StatusCode: http.StatusOK, Body: brokerDeadlineTestBody{req.Context()}}, nil
				}
				return &http.Response{StatusCode: tc.status, Body: http.NoBody}, nil
			})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			// Drive RoundTrip directly, with a short per-request timeout and
			// a live caller, so no coordinator callback runs before the
			// record is inspected.
			_, err := c.roundTripper.RoundTrip(ctx, 0, 20*time.Millisecond, []byte("request"))
			isFailure := stderrors.As(err, &failure)
			if err == nil || isFailure != (tc.wantClass != "") {
				t.Fatalf("classification: %v", err)
			}
			recorded := c.roundTripper.failure.Load()
			if !isFailure {
				if recorded != nil || m.sharedClient != c {
					t.Fatalf("slow non-200 recorded %v or unshared the client", recorded)
				}
				return
			}
			if recorded == nil || !strings.HasPrefix(recorded.class, tc.wantClass) || recorded.err == nil {
				t.Fatalf("recorded %v, want class %q with error", recorded, tc.wantClass)
			}
			// A later classified failure on the same round tripper does
			// not replace the first record.
			c.roundTripper.recordFailure("body", stderrors.New("second"))
			if again := c.roundTripper.failure.Load(); again != recorded {
				t.Fatalf("second failure replaced the record: %v", again)
			}
			// The coordinator callback consumes the record, unshares and
			// fails the client.
			c.BrokerClientRoundTripperFailed(c.roundTripper)
			if c.roundTripper.failure.Load() != nil || m.sharedClient == c || !m.clients[c].failed {
				t.Fatal("failure callback did not consume the record, unshare and fail the client")
			}
		})
	}
}

// TestInproxyBrokerRepeatedFailureSingleDecision verifies that concurrent
// requests failing on one broker client's transport produce one failure
// event: replay retention is decided by the first callback, and later
// callbacks for the same instance return before re-deciding. The sequential
// case retains on the first callback and would delete on the second without
// the guard; the concurrent case checks the guard under the race detector.
func TestInproxyBrokerRepeatedFailureSingleDecision(t *testing.T) {
	for _, mode := range []string{"sequential", "concurrent"} {
		t.Run(mode, func(t *testing.T) {
			spec := newProviderTestBroker(t, "A")
			m := newProviderTestManager(t, 1, spec)
			if err := setGateTestParameters(m.config, "", map[string]interface{}{
				parameters.InproxyBrokerSpecs:                           parameters.InproxyBrokerSpecsValue{spec},
				parameters.InproxyClientMaxBrokerClients:                1,
				parameters.InproxyReplayBrokerDialParametersProbability: 1.0,
			}); err != nil {
				t.Fatal(err)
			}
			var release func()
			c := getGateTestClient(t, m, &release)
			defer release()
			c.brokerResponseSucceededForTest(c.roundTripper)
			if m.sharedClient != c || loadBrokerReplayTestParameters(t, spec) == nil {
				t.Fatal("success did not share the client and store replay")
			}
			// Always retain, so the first decision keeps the record.
			c.replayRetainFailedProbability = 1.0

			if mode == "sequential" {
				c.BrokerClientRoundTripperFailed(c.roundTripper)
				if loadBrokerReplayTestParameters(t, spec) == nil || m.sharedClient == c || !m.clients[c].failed {
					t.Fatal("first failure did not retain replay and unshare")
				}
				// A second callback must not re-decide: with retention now
				// disabled it would delete the record.
				c.replayRetainFailedProbability = 0
				c.BrokerClientRoundTripperFailed(c.roundTripper)
				if loadBrokerReplayTestParameters(t, spec) == nil {
					t.Fatal("repeated failure callback re-decided replay retention")
				}
				return
			}

			var wg sync.WaitGroup
			for i := 0; i < 8; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					c.BrokerClientRoundTripperFailed(c.roundTripper)
				}()
			}
			wg.Wait()
			c.mutex.Lock()
			failed := c.failed
			c.mutex.Unlock()
			if !failed || m.sharedClient == c || !m.clients[c].failed ||
				loadBrokerReplayTestParameters(t, spec) == nil {
				t.Fatal("concurrent failures did not resolve to one retained decision")
			}
		})
	}
}

// TestInproxyBrokerSelectionResetBoundaries verifies which selector state
// survives each boundary: shared failure and idle expiry refresh replay
// allowances while keeping the seed and cursors and avoiding a surviving
// client's provider; a delivered tactics callback and a network change close
// live clients and clear cursors while retaining the seed; late responses
// cannot restore closed clients; new specs replace provider eligibility.
func TestInproxyBrokerSelectionResetBoundaries(t *testing.T) {
	specs := parameters.InproxyBrokerSpecsValue{newProviderTestBroker(t, "A", "B"), newProviderTestBroker(t, "A", "B")}
	m := newProviderTestManager(t, 3, specs...)
	var releaseA, releaseC func()
	a, b := getGateTestClient(t, m, &releaseA), getGateTestClient(t, m)
	a.brokerResponseSucceededForTest(a.roundTripper)
	seed := m.selector.seed
	cursor := m.selector.nextBrokerByProvider[a.frontingProviderID]
	m.selector.replayedByProvider = map[string]bool{"A": true, "B": true}
	a.BrokerClientRoundTripperFailed(a.roundTripper)
	releaseA()
	if m.selector.seed != seed || m.selector.nextBrokerByProvider[a.frontingProviderID] != cursor || len(m.selector.replayedByProvider) != 0 {
		t.Fatal("shared failure lost ordering or failed to refresh replay allowances")
	}
	c := getGateTestClient(t, m, &releaseC)
	if c.frontingProviderID == b.frontingProviderID {
		t.Fatal("new replay search duplicated surviving connection-owned provider")
	}
	c.brokerResponseSucceededForTest(c.roundTripper)
	m.selector.replayedByProvider = map[string]bool{"A": true, "B": true}
	releaseC()
	expireSharedClientForTest(m, c)
	d := getGateTestClient(t, m)
	if d.frontingProviderID == b.frontingProviderID || m.selector.seed != seed {
		t.Fatal("idle restart lost session identity or live diversity")
	}
	m.config.SetTacticsAppliedReceivers([]TacticsAppliedReceiver{m})
	if err := setGateTestParameters(m.config, "capacity-only", map[string]interface{}{
		parameters.InproxyBrokerSpecs:                       specs,
		parameters.InproxyClientMaxBrokerClients:            4,
		parameters.InproxyPersonalPairingMaxBrokerSpecCount: 2,
	}); err != nil {
		t.Fatal(err)
	}
	if len(m.clients) != 0 || len(m.selector.nextBrokerByProvider) != 0 || b.roundTripper.runCtx.Err() == nil || d.roundTripper.runCtx.Err() == nil {
		t.Fatal("M-only tactics callback did not reset live clients and coverage")
	}
	if err := m.NetworkChanged(); err != nil {
		t.Fatal(err)
	}
	if m.selector.seed != seed || m.selector.nextBroker != 0 || len(m.selector.nextBrokerByProvider) != 0 || len(m.selector.replayedByProvider) != 0 {
		t.Fatal("network reset did not clear coverage while retaining session seed")
	}
	// Late old responses cannot restore the reset clients.
	b.BrokerClientResponseReceived(b.roundTripper, false)
	if m.sharedClient != nil {
		t.Fatal("stale response restored old selection state")
	}
	old := getGateTestClient(t, m)
	if err := setGateTestParameters(m.config, "new-specs", map[string]interface{}{
		parameters.InproxyBrokerSpecs: parameters.InproxyBrokerSpecsValue{newProviderTestBroker(t, "C", "D")},
	}); err != nil {
		t.Fatal(err)
	}
	if old.roundTripper.runCtx.Err() == nil || len(m.selector.nextBrokerByProvider) != 0 || m.selector.seed != seed {
		t.Fatal("new specs did not clear coverage with the same session seed")
	}
	fresh := getGateTestClient(t, m)
	if fresh.frontingProviderID != "C" && fresh.frontingProviderID != "D" {
		t.Fatal("selection retained old provider eligibility")
	}
}

// TestInproxyBrokerReplayEligibilityFallback verifies that an expired,
// hash-mismatched, missing or other-network record, or disabled replay,
// does not block replay of another provider's valid record and that fresh
// selection still avoids the live provider. Disabled replay leaves records
// intact.
func TestInproxyBrokerReplayEligibilityFallback(t *testing.T) {
	for _, mode := range []string{"expired", "invalid", "missing", "other-network", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			a, b := newProviderTestBroker(t, "A", "B"), newProviderTestBroker(t, "A", "B")
			m := newProviderTestManager(t, 2, a, b)
			params := makeBrokerReplayTestParameters(t, m, a, "A")
			if mode == "expired" {
				params.LastUsedTimestamp = time.Now().Add(-365 * 24 * time.Hour)
			}
			if mode == "invalid" {
				params.LastUsedBrokerSpecHash = []byte("old-spec")
			}
			network := "TEST"
			if mode == "other-network" {
				network = "OTHER"
			}
			if mode != "missing" {
				if err := storeInproxyBrokerReplayParameters(network, params); err != nil {
					t.Fatal(err)
				}
			}
			if err := storeInproxyBrokerReplayParameters("TEST", makeBrokerReplayTestParameters(t, m, b, "B")); err != nil {
				t.Fatal(err)
			}
			m.config.DisableReplay = mode == "disabled"
			first, second := getGateTestClient(t, m), getGateTestClient(t, m)
			if first.frontingProviderID == second.frontingProviderID || second.brokerDialParams.isReplay {
				t.Fatal("fresh fallback violated diversity or loaded ineligible replay")
			}
			if mode == "disabled" {
				if first.brokerDialParams.isReplay || loadBrokerReplayTestParameters(t, a) == nil || loadBrokerReplayTestParameters(t, b) == nil {
					t.Fatal("disabled replay was used or deleted")
				}
			} else if !first.brokerDialParams.isReplay || first.frontingProviderID != "B" {
				t.Fatal("ineligible first record prevented replay of another provider")
			}
		})
	}
}

// TestInproxyBrokerPersonalReplayPreservesProviderExhaustion verifies that
// personal replay stays at the rendezvous broker: a replay jump in provider
// rotation marks that provider tried without advancing the broker, and the
// remaining untried provider is still selected before the visit is
// exhausted.
func TestInproxyBrokerPersonalReplayPreservesProviderExhaustion(t *testing.T) {
	spec := newProviderTestBroker(t, "A", "B", "C")
	m := newProviderTestManager(t, 1, spec)
	specs := parameters.InproxyBrokerSpecsValue{spec}
	s := &inproxyBrokerSelector{brokers: specs, exhaustBrokerProviders: true, personal: true, providers: []string{"A", "B", "C"}}
	p := m.config.GetParameters().Get()
	defer p.Close()
	first, err := s.selectClient(m.config, p, "TEST", false, nil)
	if err != nil || first.frontingSpecs[0].FrontingProviderID != "A" {
		t.Fatalf("expected fresh A: %v", err)
	}
	if err := storeInproxyBrokerReplayParameters("TEST", makeBrokerReplayTestParameters(t, m, spec, "C")); err != nil {
		t.Fatal(err)
	}
	second, err := s.selectClient(m.config, p, "TEST", false, nil)
	if err != nil || second.replayDialParams == nil || second.frontingSpecs[0].FrontingProviderID != "C" {
		t.Fatalf("expected C replay: %v", err)
	}
	if s.currentBrokerSelection.index != 0 {
		t.Fatal("replay advanced broker before all providers were tried")
	}
	third, err := s.selectClient(m.config, p, "TEST", false, nil)
	if err != nil || third.frontingSpecs[0].FrontingProviderID != "B" || len(s.currentBrokerSelection.tried) != 3 || s.currentBrokerSelection.index != 0 {
		t.Fatalf("replay jump skipped unvisited B or repeated A: %v", err)
	}
}

// newPersonalRaceTestManager builds a personal pairing client manager with
// the given client limit and personal NoMatch failover probability.
func newPersonalRaceTestManager(t *testing.T, limit int, probability float64, specs ...*parameters.InproxyBrokerSpec) *InproxyBrokerClientManager {
	t.Helper()
	m := newProviderTestManager(t, limit, specs...)
	id, err := inproxy.MakeID()
	if err != nil {
		t.Fatal(err)
	}
	m.config.InproxyClientPersonalCompartmentID = id.String()
	if err := setGateTestParameters(m.config, "personal-race", map[string]interface{}{
		parameters.InproxyBrokerSpecs:                              parameters.InproxyBrokerSpecsValue(specs),
		parameters.InproxyClientMaxBrokerClients:                   limit,
		parameters.InproxyClientNoMatchFailoverPersonalProbability: probability,
		parameters.InproxyReplayBrokerDialParametersProbability:    1.0,
		parameters.InproxyReplayBrokerRetainFailedProbability:      1.0,
	}); err != nil {
		t.Fatal(err)
	}
	return m
}

// TestInproxyBrokerPersonalRaceGate verifies that a personal client tries
// each distinct provider once per broker visit, blocks acquisition at the
// client limit or once all providers are tried, ignores a canceled waiter,
// keeps waiting while any current-visit client is live, and advances to the
// next rendezvous broker only after the last one is released.
func TestInproxyBrokerPersonalRaceGate(t *testing.T) {
	for _, limit := range []int{1, 2, 4} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			m := newPersonalRaceTestManager(t, limit, 1,
				newProviderTestBroker(t, "A", "A", "B", "C"), newProviderTestBroker(t, "A", "B", "C"))
			var live []*InproxyBrokerClientInstance
			releases := make(map[*InproxyBrokerClientInstance]func())
			seen := make(map[string]bool)
			broker := ""
			for len(seen) < 3 {
				var release func()
				c := getGateTestClient(t, m, &release)
				releases[c] = release
				if broker == "" {
					broker = c.brokerDialParams.brokerSpec.BrokerPublicKey
				}
				if seen[c.frontingProviderID] || c.brokerSelection.index != 0 || c.brokerDialParams.brokerSpec.BrokerPublicKey != broker {
					t.Fatal("race repeated a provider or advanced before exhausting the current broker")
				}
				seen[c.frontingProviderID] = true
				live = append(live, c)
				if len(live) == limit || len(seen) == 3 {
					if got, _, changed, err := m.tryGetClientBrokerClient("TEST"); err != nil || got != nil || changed == nil {
						t.Fatalf("expected M/provider gate: %v", err)
					}
					if len(seen) < 3 {
						live[0].BrokerClientRoundTripperFailed(live[0].roundTripper)
						releases[live[0]]()
						live = live[1:]
					}
				}
			}
			parent, cancel := context.WithCancel(context.Background())
			ctx := &inproxyGateWaitContext{Context: parent, waiting: make(chan struct{})}
			result := make(chan error, 1)
			go func() {
				_, _, release, err := m.GetBrokerClient(ctx, "TEST")
				if err == nil {
					release()
				}
				result <- err
			}()
			select {
			case <-ctx.waiting:
			case <-time.After(5 * time.Second):
				cancel()
				t.Fatal("personal gate did not block")
			}
			cancel()
			if err := <-result; err == nil {
				t.Fatal("canceled acquisition succeeded")
			}
			for i, c := range live {
				if c.roundTripper.runCtx.Err() != nil {
					t.Fatal("canceled waiter disturbed active race")
				}
				releases[c]()
				if i < len(live)-1 {
					if got, _, changed, err := m.tryGetClientBrokerClient("TEST"); err != nil || got != nil || changed == nil {
						t.Fatal("advanced while a viable current-visit client remained")
					}
				}
			}
			next := getGateTestClient(t, m)
			if next.brokerSelection.index != 1 || next.brokerDialParams.brokerSpec.BrokerPublicKey == broker {
				t.Fatal("exhausted visit did not advance to next rendezvous broker")
			}
		})
	}
}

// TestInproxyBrokerPersonalRaceNoMatch verifies personal NoMatch outcomes
// for a shared or unshared client: retain shares it without advancing, and
// failover closes it, advances immediately, leaves the competitor's lease
// counting toward the limit, and prevents the old-visit competitor's later
// success or NoMatch from sharing or advancing.
func TestInproxyBrokerPersonalRaceNoMatch(t *testing.T) {
	for _, shared := range []bool{false, true} {
		for _, probability := range []float64{0, 1} {
			t.Run(fmt.Sprintf("shared=%v/p=%v", shared, probability), func(t *testing.T) {
				m := newPersonalRaceTestManager(t, 2, probability,
					newProviderTestBroker(t, "A", "B"), newProviderTestBroker(t, "A", "B"))
				a, b := getGateTestClient(t, m), getGateTestClient(t, m)
				if shared {
					a.brokerResponseSucceededForTest(a.roundTripper)
				}
				a.BrokerClientRoundTripperSucceeded(a.roundTripper)
				a.BrokerClientResponseReceived(a.roundTripper, true)
				if probability == 0 {
					b.brokerResponseSucceededForTest(b.roundTripper)
					if getGateTestClient(t, m) != a || b.roundTripper.runCtx.Err() != nil || m.selector.currentBrokerSelection != a.brokerSelection {
						t.Fatal("retain outcome advanced or disrupted competitors")
					}
					return
				}
				if b.roundTripper.runCtx.Err() != nil || a.roundTripper.runCtx.Err() == nil {
					t.Fatal("failover closed independent worker or retained failed-over client")
				}
				b.brokerResponseSucceededForTest(b.roundTripper)
				if m.sharedClient != nil {
					t.Fatal("late old-visit success reversed advancement")
				}
				b.BrokerClientResponseReceived(b.roundTripper, false)
				c := getGateTestClient(t, m)
				if c.brokerSelection.index != a.brokerSelection.index+1 || c.brokerDialParams.brokerSpec.BrokerPublicKey == a.brokerDialParams.brokerSpec.BrokerPublicKey {
					t.Fatal("new selection did not advance immediately")
				}
				if got, _, changed, err := m.tryGetClientBrokerClient("TEST"); err != nil || got != nil || changed == nil {
					t.Fatal("old connection-owned visit stopped counting toward M")
				}
				currentBrokerSelection := m.selector.currentBrokerSelection
				b.BrokerClientResponseReceived(b.roundTripper, true)
				if m.selector.currentBrokerSelection != currentBrokerSelection || c.roundTripper.runCtx.Err() != nil {
					t.Fatal("old NoMatch advanced the current visit")
				}
				c.brokerResponseSucceededForTest(c.roundTripper)
				if getGateTestClient(t, m) != c {
					t.Fatal("current-visit client failed to promote")
				}
			})
		}
	}
}

// TestInproxyBrokerPersonalProviderGateWake verifies that a waiter blocked
// below the client limit by provider exhaustion wakes when a candidate is
// promoted, receiving the shared client, or when the last current-visit
// client closes, receiving a client at the next broker visit. A failure
// alone, while its caller holds the lease, does not wake the waiter.
func TestInproxyBrokerPersonalProviderGateWake(t *testing.T) {
	for _, promote := range []bool{false, true} {
		t.Run(fmt.Sprintf("promote=%v", promote), func(t *testing.T) {
			m := newPersonalRaceTestManager(t, 4, 1,
				newProviderTestBroker(t, "A", "B"), newProviderTestBroker(t, "A", "B"))
			var releaseA, releaseB func()
			a, b := getGateTestClient(t, m, &releaseA), getGateTestClient(t, m, &releaseB)
			parent, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			ctx := &inproxyGateWaitContext{Context: parent, waiting: make(chan struct{})}
			type result struct {
				client *InproxyBrokerClientInstance
				err    error
			}
			results := make(chan result, 1)
			go func() {
				c, _, release, err := m.GetBrokerClient(ctx, "TEST")
				if err != nil {
					results <- result{nil, err}
					return
				}
				t.Cleanup(release)
				results <- result{c.GetBrokerDialCoordinator().(*InproxyBrokerClientInstance), nil}
			}()
			select {
			case <-ctx.waiting:
			case <-parent.Done():
				t.Fatal("worker did not wait at provider cap below M")
			}
			if promote {
				b.brokerResponseSucceededForTest(b.roundTripper)
			} else {
				// A failed client still held by its caller is
				// live for the visit; its failure alone must
				// not wake the waiter.
				a.BrokerClientRoundTripperFailed(a.roundTripper)
				select {
				case result := <-results:
					t.Fatalf("failure alone woke provider-gated waiter: %v", result.err)
				case <-time.After(20 * time.Millisecond):
				}
				releaseA()
				releaseB()
			}
			select {
			case result := <-results:
				if result.err != nil {
					t.Fatal(result.err)
				}
				if promote {
					if result.client != b || a.roundTripper.runCtx.Err() != nil {
						t.Fatal("promotion did not share winner and preserve competitor")
					}
				} else if result.client.brokerSelection.index != 1 || result.client.brokerSelection == a.brokerSelection {
					t.Fatal("exhaustion did not wake worker at the next broker visit")
				}
			case <-parent.Done():
				t.Fatal("provider-gated waiter did not wake")
			}
		})
	}
}

// TestInproxyBrokerPersonalVisitIdentity verifies that NoMatch wraparound
// allocates a new visit even at the same broker, so an older client's
// response cannot share it, while the new visit's client can be shared and
// the old client's cleanup is harmless; and that shared failure and idle
// expiry retain the visit, so a surviving candidate from it becomes shared
// on its decoded response and the next acquisition reuses it.
func TestInproxyBrokerPersonalVisitIdentity(t *testing.T) {
	for _, event := range []string{"wrap", "shared-failure", "idle"} {
		t.Run(event, func(t *testing.T) {
			// One broker ensures the next visit has the same broker
			// key; only the visit pointer can distinguish an older
			// client from a new one.
			m := newPersonalRaceTestManager(t, 3, 1, newProviderTestBroker(t, "A", "B"))
			var releaseA, releaseB func()
			a, b := getGateTestClient(t, m, &releaseA), getGateTestClient(t, m, &releaseB)
			a.brokerResponseSucceededForTest(a.roundTripper)
			switch event {
			case "wrap":
				a.BrokerClientResponseReceived(a.roundTripper, true)
			case "shared-failure":
				a.BrokerClientRoundTripperFailed(a.roundTripper)
				releaseA()
			case "idle":
				releaseA()
				expireSharedClientForTest(m, a)
			}
			if event != "wrap" {
				m.mutex.Lock()
				retained := m.selector.currentBrokerSelection == b.brokerSelection
				m.mutex.Unlock()
				if !retained {
					t.Fatal("shared loss did not retain the visit")
				}
				b.BrokerClientResponseReceived(b.roundTripper, false)
				if m.sharedClient != b {
					t.Fatal("surviving candidate at the retained visit was not shared")
				}
				if getGateTestClient(t, m) != b {
					t.Fatal("acquisition did not reuse the surviving candidate")
				}
				releaseB()
				return
			}
			c := getGateTestClient(t, m)
			if c.brokerSelection == b.brokerSelection || c.brokerDialParams.brokerSpec.BrokerPublicKey != b.brokerDialParams.brokerSpec.BrokerPublicKey {
				t.Fatal("same-broker selection did not get a new visit")
			}
			b.BrokerClientResponseReceived(b.roundTripper, false)
			if m.sharedClient != nil || b.roundTripper.runCtx.Err() != nil {
				t.Fatal("old visit promoted or was interrupted")
			}
			c.brokerResponseSucceededForTest(c.roundTripper)
			releaseB()
			if getGateTestClient(t, m) != c {
				t.Fatal("old connection cleanup evicted new shared client")
			}
		})
	}
}

// TestInproxyBrokerStaleVisitNoMatch verifies the stale-visit branch of
// clientResponseReceived: a retryable NoMatch from a client whose broker
// selection is no longer current closes only that client for personal
// pairing clients, cannot advance the current selection, and is a no-op for
// proxies, which never apply NoMatch failover.
func TestInproxyBrokerStaleVisitNoMatch(t *testing.T) {
	for _, proxy := range []bool{false, true} {
		name := "client"
		if proxy {
			name = "proxy"
		}
		t.Run(name, func(t *testing.T) {
			specs := []*parameters.InproxyBrokerSpec{newProviderTestBroker(t, "A"), newProviderTestBroker(t, "A")}
			var m *InproxyBrokerClientManager
			if proxy {
				m = newProxyRaceTestManager(t, 2, specs...)
			} else {
				m = newPersonalRaceTestManager(t, 2, 1.0, specs...)
			}
			var releaseA func()
			a := getGateTestClient(t, m, &releaseA)
			// Advance the selection as exhaustion would, leaving a
			// tracked at the previous visit.
			m.mutex.Lock()
			m.selector.advanceBroker(a.brokerSelection.index+1, "test")
			current := m.selector.currentBrokerSelection
			m.mutex.Unlock()
			a.BrokerClientResponseReceived(a.roundTripper, true)
			m.mutex.Lock()
			_, tracked := m.clients[a]
			shared := m.sharedClient
			unchanged := m.selector.currentBrokerSelection == current
			m.mutex.Unlock()
			if shared != nil || !unchanged {
				t.Fatal("stale NoMatch promoted or advanced the current selection")
			}
			if closed := a.roundTripper.runCtx.Err() != nil; proxy {
				if !tracked || closed {
					t.Fatal("proxy stale NoMatch was not a no-op")
				}
			} else if tracked || !closed {
				t.Fatal("client stale NoMatch did not close only that client")
			}
			// The current visit is unaffected: a new client selects
			// there.
			b := getGateTestClient(t, m)
			if b.brokerSelection != current || b.BrokerPublicKey() == a.BrokerPublicKey() {
				t.Fatal("stale NoMatch disturbed selection at the current broker")
			}
			releaseA()
		})
	}
}

// TestInproxyProxySharedLossReplayExclusion verifies that after a proxy loses
// its shared client, the retained visit's tried providers are rebuilt from
// the surviving clients, and that a provider tried at that visit but no
// longer occupied by a live client is excluded from replay: occupancy alone
// cannot exclude it, so the tried check in canReplay must.
func TestInproxyProxySharedLossReplayExclusion(t *testing.T) {
	spec := newProviderTestBroker(t, "A", "B", "C", "D")
	m := newProxyRaceTestManager(t, 3, spec)
	var releaseA, releaseB, releaseC func()
	a := getGateTestClient(t, m, &releaseA)
	b := getGateTestClient(t, m, &releaseB)
	// Share via the decoded response only: a transport success would set
	// lastSuccess and put the common proxy in its failure retry window.
	a.BrokerClientResponseReceived(a.roundTripper, false)
	a.BrokerClientRoundTripperFailed(a.roundTripper)
	m.mutex.Lock()
	visit := m.selector.currentBrokerSelection
	retained := visit == a.brokerSelection && visit.tried == nil
	m.mutex.Unlock()
	if !retained {
		t.Fatal("proxy shared loss did not retain the visit and clear tried providers")
	}
	// Recovery rebuilds tried from a and b and selects an untried provider
	// fresh.
	c := getGateTestClient(t, m, &releaseC)
	if c.brokerSelection != visit || c.frontingProviderID == a.frontingProviderID ||
		c.frontingProviderID == b.frontingProviderID || c.brokerDialParams.isReplay {
		t.Fatalf("recovery selected %s replay=%v; want an untried provider fresh",
			c.frontingProviderID, c.brokerDialParams.isReplay)
	}
	m.mutex.Lock()
	remarked := visit.tried[a.frontingProviderID] && visit.tried[b.frontingProviderID] && visit.tried[c.frontingProviderID]
	m.mutex.Unlock()
	if !remarked {
		t.Fatal("tried providers were not rebuilt from tracked clients")
	}
	// Close c: its provider stays tried at this visit but is no longer
	// occupied, so only the tried check can exclude it. With a valid replay
	// record for it, the replay-first scan must skip it and select the one
	// remaining untried provider fresh.
	releaseC()
	if err := storeInproxyBrokerReplayParameters("TEST", makeBrokerReplayTestParameters(t, m, spec, c.frontingProviderID)); err != nil {
		t.Fatal(err)
	}
	d := getGateTestClient(t, m)
	if d.brokerSelection != visit || d.frontingProviderID == c.frontingProviderID || d.brokerDialParams.isReplay {
		t.Fatalf("tried but unoccupied provider %s was replayed: selected %s replay=%v",
			c.frontingProviderID, d.frontingProviderID, d.brokerDialParams.isReplay)
	}
	releaseA()
	releaseB()
}

// newPersonalProxyReturnHomeTestManager builds a personal pairing proxy
// manager at M=1 over three one-provider brokers with the given
// return-to-home period, and exhausts the first rendezvous broker so the
// proxy is displaced to the second. It returns the manager and the shared
// client at the second broker.
func newPersonalProxyReturnHomeTestManager(
	t *testing.T, period string) (*InproxyBrokerClientManager, *InproxyBrokerClientInstance) {

	t.Helper()
	specs := []*parameters.InproxyBrokerSpec{
		newProviderTestBroker(t, "A"), newProviderTestBroker(t, "A"), newProviderTestBroker(t, "A")}
	m := newProxyRaceTestManager(t, 1, specs...)
	id, err := inproxy.MakeID()
	if err != nil {
		t.Fatal(err)
	}
	m.config.InproxyProxyPersonalCompartmentID = id.String()
	if err := setGateTestParameters(m.config, "return-home", map[string]interface{}{
		parameters.InproxyBrokerSpecs:                   parameters.InproxyBrokerSpecsValue(specs),
		parameters.InproxyProxyMaxBrokerClients:         1,
		parameters.InproxyProxyPersonalReturnHomePeriod: period,
	}); err != nil {
		t.Fatal(err)
	}
	var releaseHome func()
	home := getGateTestClient(t, m, &releaseHome)
	if home.brokerSelection.index != 0 {
		t.Fatal("personal proxy did not start at the first rendezvous broker")
	}
	home.BrokerClientRoundTripperFailed(home.roundTripper)
	releaseHome()
	away := getGateTestClient(t, m)
	away.brokerResponseSucceededForTest(away.roundTripper)
	m.mutex.Lock()
	displaced := away.brokerSelection.index == 1 && m.sharedClient == away && !m.selector.awayFromHomeSince.IsZero()
	m.mutex.Unlock()
	if !displaced {
		t.Fatal("exhausting the first broker did not displace the proxy or start the return interval")
	}
	return m, away
}

// TestInproxyProxyPersonalReturnHome verifies return-to-home for a
// displaced personal pairing proxy. Once the return period has elapsed, the
// next acquisition closes the shared client at the away broker despite its
// outstanding leases, wakes a parked worker, and selects a new visit at the
// first broker; a late release of the closed client is harmless. Exhausting
// the first broker again advances in rendezvous order and restarts the
// interval, so returns repeat every period while the first broker stays
// unreachable. The interval is not restarted by leaving a later broker, and
// the mechanism is inert for common proxies, for personal clients and with
// a zero period; a reset clears it.
func TestInproxyProxyPersonalReturnHome(t *testing.T) {
	t.Run("return", func(t *testing.T) {
		m, away := newPersonalProxyReturnHomeTestManager(t, "1h")
		// Unshare the away client so that, still held by its lease, it
		// fills M=1 and a second worker parks on it.
		away.BrokerClientRoundTripperFailed(away.roundTripper)
		_, _, changed, err := m.tryGetClientBrokerClient("TEST")
		if err != nil || changed == nil {
			t.Fatalf("expected the held away client to fill the limit: %v", err)
		}
		m.mutex.Lock()
		m.selector.awayFromHomeSince = time.Now().Add(-2 * time.Hour)
		m.mutex.Unlock()
		home := getGateTestClient(t, m)
		select {
		case <-changed:
		default:
			t.Fatal("return home did not wake the parked worker")
		}
		m.mutex.Lock()
		returned := home.brokerSelection.index == 0 &&
			m.selector.currentBrokerSelection == home.brokerSelection &&
			m.selector.awayFromHomeSince.IsZero() && m.sharedClient == nil && len(m.clients) == 1
		m.mutex.Unlock()
		if !returned || away.roundTripper.runCtx.Err() == nil {
			t.Fatal("return home did not close the held away client and select the first broker")
		}
		if away.brokerDialParams.brokerSpec.BrokerPublicKey == home.brokerDialParams.brokerSpec.BrokerPublicKey {
			t.Fatal("returned to the away broker")
		}
		home.brokerResponseSucceededForTest(home.roundTripper)
		if m.sharedClient != home {
			t.Fatal("response at the first broker did not share")
		}
	})

	t.Run("repeated", func(t *testing.T) {
		m, _ := newPersonalProxyReturnHomeTestManager(t, "1h")
		for attempt := 1; attempt <= 3; attempt++ {
			m.mutex.Lock()
			m.selector.awayFromHomeSince = time.Now().Add(-2 * time.Hour)
			m.mutex.Unlock()
			var releaseHome func()
			home := getGateTestClient(t, m, &releaseHome)
			if home.brokerSelection.index != 0 {
				t.Fatalf("return %d did not select the first broker", attempt)
			}
			// The first broker fails again: selection advances in
			// rendezvous order and the interval restarts.
			home.BrokerClientRoundTripperFailed(home.roundTripper)
			releaseHome()
			next := getGateTestClient(t, m)
			m.mutex.Lock()
			advanced := next.brokerSelection.index == 1 && !m.selector.awayFromHomeSince.IsZero() &&
				time.Since(m.selector.awayFromHomeSince) < time.Minute
			m.mutex.Unlock()
			if !advanced {
				t.Fatalf("failed return %d did not advance in order and restart the interval", attempt)
			}
			next.brokerResponseSucceededForTest(next.roundTripper)
			m.mutex.Lock()
			due := m.selector.returnHomeDue()
			m.mutex.Unlock()
			if due {
				t.Fatal("return due before the period elapsed")
			}
		}
	})

	t.Run("inert", func(t *testing.T) {
		// Leaving a later broker does not restart the interval: the
		// proxy is still away from the first broker, so the interval
		// already running continues.
		m, away := newPersonalProxyReturnHomeTestManager(t, "1h")
		m.mutex.Lock()
		since := time.Now().Add(-30 * time.Minute)
		m.selector.awayFromHomeSince = since
		m.mutex.Unlock()
		// Shared loss retains the visit and retries its provider; a
		// second failure with no client left exhausts the broker.
		away.BrokerClientRoundTripperFailed(away.roundTripper)
		m.mutex.Lock()
		if entry := m.clients[away]; entry != nil {
			entry.refs = 0
			m.closeClientLocked(away, "test")
		}
		m.mutex.Unlock()
		var releaseRetry func()
		retry := getGateTestClient(t, m, &releaseRetry)
		if retry.brokerSelection != away.brokerSelection {
			t.Fatal("shared loss did not retain the away visit")
		}
		retry.BrokerClientRoundTripperFailed(retry.roundTripper)
		releaseRetry()
		next := getGateTestClient(t, m)
		m.mutex.Lock()
		unchanged := next.brokerSelection.index == 2 && m.selector.awayFromHomeSince.Equal(since)
		m.mutex.Unlock()
		if !unchanged {
			t.Fatalf("leaving a later broker changed the return interval: index %d",
				next.brokerSelection.index)
		}

		// Zero period disables the mechanism.
		m2, _ := newPersonalProxyReturnHomeTestManager(t, "0s")
		m2.mutex.Lock()
		m2.selector.awayFromHomeSince = time.Now().Add(-100 * time.Hour)
		due := m2.selector.returnHomeDue()
		m2.mutex.Unlock()
		if due {
			t.Fatal("return home due with a zero period")
		}

		// A common proxy and a personal client never arm it.
		common := newProxyRaceTestManager(t, 1, newProviderTestBroker(t, "A"), newProviderTestBroker(t, "A"))
		var releaseCommon func()
		c := getGateTestClient(t, common, &releaseCommon)
		c.BrokerClientRoundTripperFailed(c.roundTripper)
		releaseCommon()
		getGateTestClient(t, common)
		client := newPersonalRaceTestManager(t, 1, 1, newProviderTestBroker(t, "A"), newProviderTestBroker(t, "A"))
		var releaseClient func()
		k := getGateTestClient(t, client, &releaseClient)
		k.BrokerClientRoundTripperFailed(k.roundTripper)
		releaseClient()
		getGateTestClient(t, client)
		for name, mm := range map[string]*InproxyBrokerClientManager{"common proxy": common, "personal client": client} {
			mm.mutex.Lock()
			armed := !mm.selector.awayFromHomeSince.IsZero() || mm.selector.returnHomePeriod != 0
			mm.mutex.Unlock()
			if armed {
				t.Fatalf("%s armed return home", name)
			}
		}
	})

	t.Run("wrap-arrives-home", func(t *testing.T) {
		// Exhausting the last broker wraps the order back to the first
		// rendezvous broker. Arriving there ends the interval, so no
		// return fires against the working client the proxy then
		// shares at home.
		m, away := newPersonalProxyReturnHomeTestManager(t, "1h")
		away.BrokerClientRoundTripperFailed(away.roundTripper)
		m.mutex.Lock()
		if entry := m.clients[away]; entry != nil {
			entry.refs = 0
			m.closeClientLocked(away, "test")
		}
		m.mutex.Unlock()
		// Shared loss retained index 1; fail its retry and then index 2
		// to wrap to index 3, the first broker again.
		for want := 1; want <= 2; want++ {
			var release func()
			c := getGateTestClient(t, m, &release)
			if c.brokerSelection.index != want {
				t.Fatalf("expected index %d, got %d", want, c.brokerSelection.index)
			}
			c.BrokerClientRoundTripperFailed(c.roundTripper)
			release()
		}
		home := getGateTestClient(t, m)
		m.mutex.Lock()
		arrived := home.brokerSelection.index == 3 && m.selector.awayFromHomeSince.IsZero()
		m.mutex.Unlock()
		if !arrived || home.brokerDialParams.brokerSpec.BrokerPublicKey == away.brokerDialParams.brokerSpec.BrokerPublicKey {
			t.Fatalf("wrap to the first broker did not end the interval: index %d", home.brokerSelection.index)
		}
		home.brokerResponseSucceededForTest(home.roundTripper)
		// Even a long-elapsed departure time cannot fire a return at
		// home, since arrival cleared it; simulate a stale value to be
		// sure returnHomeDue is false while the interval is unset.
		m.mutex.Lock()
		due := m.selector.returnHomeDue()
		m.mutex.Unlock()
		if due {
			t.Fatal("return due while at the first broker")
		}
		again := getGateTestClient(t, m)
		m.mutex.Lock()
		stable := again == home && m.sharedClient == home && home.roundTripper.runCtx.Err() == nil
		m.mutex.Unlock()
		if !stable {
			t.Fatal("a return fired against the shared client at the first broker")
		}
	})

	t.Run("single-broker-never-away", func(t *testing.T) {
		// With one broker in the order every exhaustion advance both
		// leaves and arrives at the first broker; the proxy is never
		// away, so no return can close a working client there.
		spec := newProviderTestBroker(t, "A")
		m := newProxyRaceTestManager(t, 1, spec)
		id, err := inproxy.MakeID()
		if err != nil {
			t.Fatal(err)
		}
		m.config.InproxyProxyPersonalCompartmentID = id.String()
		if err := setGateTestParameters(m.config, "single", map[string]interface{}{
			parameters.InproxyBrokerSpecs:                   parameters.InproxyBrokerSpecsValue{spec},
			parameters.InproxyProxyMaxBrokerClients:         1,
			parameters.InproxyProxyPersonalReturnHomePeriod: "1h",
		}); err != nil {
			t.Fatal(err)
		}
		var release func()
		first := getGateTestClient(t, m, &release)
		first.BrokerClientRoundTripperFailed(first.roundTripper)
		release()
		second := getGateTestClient(t, m)
		second.brokerResponseSucceededForTest(second.roundTripper)
		m.mutex.Lock()
		away := !m.selector.awayFromHomeSince.IsZero()
		m.selector.awayFromHomeSince = time.Time{}
		m.mutex.Unlock()
		if away || second.brokerSelection.index != 1 {
			t.Fatalf("single-broker exhaustion marked the proxy away: index %d", second.brokerSelection.index)
		}
		if getGateTestClient(t, m) != second || second.roundTripper.runCtx.Err() != nil {
			t.Fatal("a return closed the working client at the only broker")
		}
	})

	t.Run("reset-clears", func(t *testing.T) {
		m, _ := newPersonalProxyReturnHomeTestManager(t, "1h")
		if err := m.NetworkChanged(); err != nil {
			t.Fatal(err)
		}
		m.mutex.Lock()
		cleared := m.selector.awayFromHomeSince.IsZero()
		m.mutex.Unlock()
		if !cleared {
			t.Fatal("reset did not clear return home state")
		}
	})
}

// TestInproxyBrokerPersonalConstructionFailure verifies that a local
// construction failure consumes one provider turn without occupying a live
// slot, does not advance the broker visit while a client remains, and
// advances once that client closes.
func TestInproxyBrokerPersonalConstructionFailure(t *testing.T) {
	spec := newProviderTestBroker(t, "A", "B")
	spec.BrokerFrontingSpecs[0].Transports = protocol.FrontingTransports{protocol.FRONTING_TRANSPORT_HTTP}
	m := newPersonalRaceTestManager(t, 3, 1, spec)
	var live *InproxyBrokerClientInstance
	failures := 0
	for i := 0; i < 2; i++ {
		c, _, _, err := m.tryGetClientBrokerClient("TEST")
		if err != nil {
			failures++
		} else {
			live = c
		}
	}
	if live == nil || failures != 1 || live.frontingProviderID != "B" {
		t.Fatal("local failure did not consume exactly one provider turn")
	}
	if c, _, changed, err := m.tryGetClientBrokerClient("TEST"); err != nil || c != nil || changed == nil {
		t.Fatal("local failure caused premature broker advancement")
	}
	m.mutex.Lock()
	m.closeClientLocked(live, "test")
	m.mutex.Unlock()
	_, _, _, _ = m.tryGetClientBrokerClient("TEST")
	if m.selector.currentBrokerSelection.index != 1 {
		t.Fatal("local-failure visit did not advance after final live client ended")
	}
}

// TestInproxyBrokerPersonalNoMatchPromotionRace verifies that a NoMatch
// failover on the shared client racing a competitor's success or NoMatch
// always advances the visit, closes the failed-over client, never shares the
// competitor, and closes the competitor only on its own NoMatch.
func TestInproxyBrokerPersonalNoMatchPromotionRace(t *testing.T) {
	m := newPersonalRaceTestManager(t, 3, 1, newProviderTestBroker(t, "A", "B"))
	for i := 0; i < 100; i++ {
		a, b := getGateTestClient(t, m), getGateTestClient(t, m)
		a.brokerResponseSucceededForTest(a.roundTripper)
		otherNoMatch := i%2 == 0
		start := make(chan struct{})
		var wg sync.WaitGroup
		for _, op := range []func(){
			func() { a.BrokerClientResponseReceived(a.roundTripper, true) },
			func() {
				if otherNoMatch {
					b.BrokerClientResponseReceived(b.roundTripper, true)
				} else {
					b.brokerResponseSucceededForTest(b.roundTripper)
				}
			},
		} {
			wg.Add(1)
			go func(op func()) { defer wg.Done(); <-start; op() }(op)
		}
		close(start)
		wg.Wait()
		if m.sharedClient != nil || (b.roundTripper.runCtx.Err() != nil) != otherNoMatch ||
			m.selector.currentBrokerSelection == a.brokerSelection || m.selector.currentBrokerSelection.index != a.brokerSelection.index+1 {
			t.Fatal("competing success reversed NoMatch failover or killed its worker")
		}
		m.closeClientBrokerClients()
	}
}

// TestInproxyBrokerNoMatchPreservesReplayBudget verifies that NoMatch
// failover retains the consumed replay allowance and common broker cursor,
// so the next selection at the next broker does not replay the same
// provider, and that personal failover advances to the next rendezvous
// broker.
func TestInproxyBrokerNoMatchPreservesReplayBudget(t *testing.T) {
	for _, personal := range []bool{false, true} {
		name := "common"
		if personal {
			name = "personal"
		}
		t.Run(name, func(t *testing.T) {
			// Both brokers offer only provider A with valid
			// records, so the selection after NoMatch must pick A
			// again and the only thing preventing a replay is the
			// consumed per-search allowance.
			specs := parameters.InproxyBrokerSpecsValue{newProviderTestBroker(t, "A"), newProviderTestBroker(t, "A")}
			m := newProviderTestManager(t, 1, specs...)
			if personal {
				id, err := inproxy.MakeID()
				if err != nil {
					t.Fatal(err)
				}
				m.config.InproxyClientPersonalCompartmentID = id.String()
			}
			if err := setGateTestParameters(m.config, "no-match", map[string]interface{}{
				parameters.InproxyBrokerSpecs:                              specs,
				parameters.InproxyClientMaxBrokerClients:                   1,
				parameters.InproxyReplayBrokerDialParametersProbability:    1.0,
				parameters.InproxyClientNoMatchFailoverProbability:         1.0,
				parameters.InproxyClientNoMatchFailoverPersonalProbability: 1.0,
			}); err != nil {
				t.Fatal(err)
			}
			for _, spec := range specs {
				if err := storeInproxyBrokerReplayParameters("TEST", makeBrokerReplayTestParameters(t, m, spec, "A")); err != nil {
					t.Fatal(err)
				}
			}
			c := getGateTestClient(t, m)
			if !c.brokerDialParams.isReplay {
				t.Fatal("expected initial replay")
			}
			m.mutex.Lock()
			cursor := m.selector.nextBroker
			m.mutex.Unlock()
			c.BrokerClientResponseReceived(c.roundTripper, true)
			m.mutex.Lock()
			allowanceConsumed := m.selector.replayedByProvider["A"]
			cursorRetained := personal || m.selector.nextBroker == cursor
			m.mutex.Unlock()
			if !allowanceConsumed || !cursorRetained {
				t.Fatal("NoMatch reset replay allowance or broker cursor")
			}
			next := getGateTestClient(t, m)
			if next.brokerDialParams.isReplay {
				t.Fatal("NoMatch replenished the consumed A replay allowance")
			}
			if next.brokerPublicKey == c.brokerPublicKey {
				t.Fatal("NoMatch failover did not move to the next broker")
			}
			if personal && next.brokerSelection.index != c.brokerSelection.index+1 {
				t.Fatal("NoMatch did not advance personal rendezvous broker")
			}
		})
	}
}

// Proxy supply distribution simulation.
//
// Each simulated proxy owns a real inproxyBrokerSelector with an independent
// seed, as a separate Controller would. Seeds are derived from one fixed
// master seed so runs are reproducible while selectors remain mutually
// independent. The simulation drives selectClient directly: no network,
// datastore replay or broker clients are involved. Reachability is a set of
// (broker, provider) pairs that succeed for a given proxy. Each attempt
// resolves before the next, so no client is ever live during selection; a
// proxy tries each provider at the current broker and advances to the next
// broker only when every provider there has failed. Production additionally
// waits while clients from the current selection are live, which this
// sequential model does not need to represent.
//
// Replay is not simulated: the datastore-backed replay path is covered by
// the replay tests, and modeling it here would require a datastore per
// proxy. The replay-first broker jump for common proxies is therefore not
// exercised; see the design document for its expected effect.
//
// The simulation reports per-broker proxy counts and an order correlation
// measure. Set INPROXY_SUPPLY_SIM_VERBOSE=1 to print tables.

type supplySimBroker struct {
	spec      *parameters.InproxyBrokerSpec
	key       string
	providers []string
}

type supplySimProxy struct {
	selector inproxyBrokerSelector
	// reachable[brokerKey][provider] is true when a broker client on that
	// pair succeeds for this proxy.
	reachable map[string]map[string]bool
	// Final broker key after settling, or "" if exhausted.
	broker string
	// Number of selectClient calls needed to settle.
	attempts int
	// Broker keys in this proxy's shuffled order.
	order []string
}

type supplySimScenario struct {
	name      string
	proxies   int
	brokers   []supplySimBroker
	reachable func(proxyIndex int, broker, provider string) bool
}

func newSupplySimBrokers(t *testing.T, count int, providers ...string) []supplySimBroker {
	t.Helper()
	var brokers []supplySimBroker
	for i := 0; i < count; i++ {
		spec := newProviderTestBroker(t, providers...)
		brokers = append(brokers, supplySimBroker{
			spec: spec, key: spec.BrokerPublicKey, providers: providers,
		})
	}
	return brokers
}

// settleSupplySimProxy runs selectClient until the proxy obtains a working
// client, following the production proxy rules. A selection that fails
// closes immediately, as a failed client with no callers does, so the
// selector is always called with no live clients. A selection that succeeds
// becomes the proxy's broker.
//
// When called again for a proxy that has already settled, the previous
// broker client is assumed to have failed. Production calls sharedLost,
// which for proxies retains the current broker selection, and the next
// selection retries that broker's providers before advancing.
func settleSupplySimProxy(
	t *testing.T, m *InproxyBrokerClientManager, proxy *supplySimProxy,
	maxAttempts int) {
	t.Helper()
	p := m.config.GetParameters().Get()
	defer p.Close()
	if proxy.broker != "" {
		proxy.selector.sharedLost()
		proxy.broker = ""
	}
	for proxy.attempts = 0; proxy.attempts < maxAttempts; proxy.attempts++ {
		selection, err := proxy.selector.selectClient(m.config, p, "TEST", true, nil)
		if err != nil {
			t.Fatal(err)
		}
		if selection == nil {
			// selectClient waits only while a current-selection
			// client is live, and none ever is here.
			t.Fatal("selection waited with no live clients")
		}
		provider := selection.frontingSpecs[0].FrontingProviderID
		brokerKey := selection.brokerSpec.BrokerPublicKey
		if proxy.reachable[brokerKey][provider] {
			proxy.broker = brokerKey
			return
		}
		// Failure: the client closes immediately with no callers. The
		// selector retains its tried-provider record for this
		// selection.
	}
}

// newSupplySimManager creates the broker client manager whose config and
// parameters the simulated selectors read.
func newSupplySimManager(t *testing.T, brokers []supplySimBroker) *InproxyBrokerClientManager {
	t.Helper()
	specs := make(parameters.InproxyBrokerSpecsValue, len(brokers))
	for i, b := range brokers {
		specs[i] = b.spec
	}
	m := newProviderTestManager(t, 3, specs...)
	m.isProxy = true
	// Replay is not simulated; disabling it also avoids a datastore
	// transaction per broker per selection.
	if err := setGateTestParameters(m.config, "", map[string]interface{}{
		parameters.InproxyBrokerSpecs:                           parameters.InproxyBrokerSpecsValue(specs),
		parameters.InproxyReplayBrokerDialParametersProbability: 0.0,
	}); err != nil {
		t.Fatal(err)
	}
	return m
}

func supplySimMaxAttempts(brokers []supplySimBroker) int {
	return 10*len(brokers)*len(brokers[0].providers) + 10
}

func runSupplySim(t *testing.T, scenario supplySimScenario) ([]*supplySimProxy, *InproxyBrokerClientManager) {
	t.Helper()
	m := newSupplySimManager(t, scenario.brokers)
	var proxies []*supplySimProxy
	// Derive each proxy's selector seed from a fixed master seed so the
	// statistical assertions are reproducible.
	master := prng.NewPRNGWithSeed(&prng.Seed{0x5a})
	for i := 0; i < scenario.proxies; i++ {
		proxy := &supplySimProxy{reachable: make(map[string]map[string]bool)}
		var seed prng.Seed
		master.Read(seed[:])
		proxy.selector.seed = &seed
		for _, b := range scenario.brokers {
			proxy.reachable[b.key] = make(map[string]bool)
			for _, provider := range b.providers {
				proxy.reachable[b.key][provider] = scenario.reachable(i, b.key, provider)
			}
		}
		p := m.config.GetParameters().Get()
		if err := proxy.selector.initialize(m.config, p, true); err != nil {
			p.Close()
			t.Fatal(err)
		}
		p.Close()
		for _, spec := range proxy.selector.brokers {
			proxy.order = append(proxy.order, spec.BrokerPublicKey)
		}
		settleSupplySimProxy(t, m, proxy, supplySimMaxAttempts(scenario.brokers))
		proxies = append(proxies, proxy)
	}
	return proxies, m
}

func mustRunSupplySim(t *testing.T, scenario supplySimScenario) []*supplySimProxy {
	t.Helper()
	proxies, _ := runSupplySim(t, scenario)
	return proxies
}

type supplySimResult struct {
	counts        map[string]int
	exhausted     int
	maxMinRatio   float64
	distinctOrder int
	meanAttempts  float64
	firstBrokerCV float64
}

func summarizeSupplySim(proxies []*supplySimProxy, brokers []supplySimBroker) supplySimResult {
	r := supplySimResult{counts: make(map[string]int)}
	orders := make(map[string]bool)
	firstCounts := make(map[string]int)
	totalAttempts := 0
	for _, proxy := range proxies {
		if proxy.broker == "" {
			r.exhausted++
		} else {
			r.counts[proxy.broker]++
		}
		orders[strings.Join(proxy.order, ",")] = true
		firstCounts[proxy.order[0]]++
		totalAttempts += proxy.attempts
	}
	r.distinctOrder = len(orders)
	r.meanAttempts = float64(totalAttempts) / float64(len(proxies))
	min, max := math.MaxInt, 0
	for _, b := range brokers {
		c := r.counts[b.key]
		if c < min {
			min = c
		}
		if c > max {
			max = c
		}
	}
	if min > 0 {
		r.maxMinRatio = float64(max) / float64(min)
	} else {
		r.maxMinRatio = math.Inf(1)
	}
	// Coefficient of variation of first-broker-in-order counts: a uniform
	// independent shuffle gives a CV near sqrt((B-1)/N).
	mean := float64(len(proxies)) / float64(len(brokers))
	variance := 0.0
	for _, b := range brokers {
		d := float64(firstCounts[b.key]) - mean
		variance += d * d
	}
	variance /= float64(len(brokers))
	r.firstBrokerCV = math.Sqrt(variance) / mean
	return r
}

func reportSupplySim(t *testing.T, scenario supplySimScenario, r supplySimResult) {
	t.Helper()
	if os.Getenv("INPROXY_SUPPLY_SIM_VERBOSE") == "" {
		return
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s: proxies=%d brokers=%d exhausted=%d max/min=%.2f distinctOrders=%d meanAttempts=%.2f firstBrokerCV=%.3f\n",
		scenario.name, scenario.proxies, len(scenario.brokers), r.exhausted, r.maxMinRatio, r.distinctOrder, r.meanAttempts, r.firstBrokerCV)
	for i, b := range scenario.brokers {
		fmt.Fprintf(&sb, "  broker %d: %d\n", i, r.counts[b.key])
	}
	t.Log(sb.String())
}

// TestInproxyProxySupplyDistribution checks that independently seeded proxies
// distribute across brokers, remain on one broker while trying its providers,
// and do not share an effective broker order.
func TestInproxyProxySupplyDistribution(t *testing.T) {
	const proxies = 600
	brokers := newSupplySimBrokers(t, 4, "A", "B", "C")

	// Uniform reachability: everything works.
	uniform := supplySimScenario{
		name: "uniform", proxies: proxies, brokers: brokers,
		reachable: func(int, string, string) bool { return true },
	}
	r := summarizeSupplySim(mustRunSupplySim(t, uniform), brokers)
	reportSupplySim(t, uniform, r)
	if r.exhausted != 0 || r.meanAttempts != 0 {
		t.Fatalf("uniform: exhausted=%d meanAttempts=%.2f", r.exhausted, r.meanAttempts)
	}
	// With 600 proxies over 4 brokers, expected 150 each with sd ~10.6.
	// A 1.5 ratio bound is ~5 sd; a shared order would give ratio = inf.
	if r.maxMinRatio > 1.5 {
		t.Fatalf("uniform: broker counts unbalanced, max/min=%.2f %v", r.maxMinRatio, r.counts)
	}
	// 4! = 24 possible orders; 600 independent proxies must see nearly all.
	if r.distinctOrder < 20 {
		t.Fatalf("uniform: only %d distinct broker orders across %d proxies", r.distinctOrder, proxies)
	}

	// One provider blocked for every proxy: proxies stay on their first
	// broker and use another provider there. Distribution is unchanged.
	oneProviderDown := supplySimScenario{
		name: "provider-A-blocked", proxies: proxies, brokers: brokers,
		reachable: func(_ int, _, provider string) bool { return provider != "A" },
	}
	r = summarizeSupplySim(mustRunSupplySim(t, oneProviderDown), brokers)
	reportSupplySim(t, oneProviderDown, r)
	if r.exhausted != 0 || r.maxMinRatio > 1.5 {
		t.Fatalf("provider blocked: exhausted=%d max/min=%.2f", r.exhausted, r.maxMinRatio)
	}
	// Providers are shuffled per selection, so about one third of proxies
	// try A first and need one extra attempt; the mean is well below 1.
	if r.meanAttempts > 0.6 {
		t.Fatalf("provider blocked: meanAttempts=%.2f, proxies left their broker", r.meanAttempts)
	}

	// One broker unreachable on every provider: its share moves to the next
	// broker in each proxy's independent order, so the remaining brokers
	// stay balanced rather than all failing over to one broker.
	downKey := brokers[0].key
	brokerDown := supplySimScenario{
		name: "broker-0-down", proxies: proxies, brokers: brokers,
		reachable: func(_ int, broker, _ string) bool { return broker != downKey },
	}
	r = summarizeSupplySim(mustRunSupplySim(t, brokerDown), brokers)
	reportSupplySim(t, brokerDown, r)
	if r.exhausted != 0 || r.counts[downKey] != 0 {
		t.Fatalf("broker down: exhausted=%d downCount=%d", r.exhausted, r.counts[downKey])
	}
	remaining := make([]int, 0, 3)
	for _, b := range brokers[1:] {
		remaining = append(remaining, r.counts[b.key])
	}
	sort.Ints(remaining)
	if float64(remaining[2])/float64(remaining[0]) > 1.5 {
		t.Fatalf("broker down: survivors unbalanced %v", remaining)
	}

	// Mixed reachability: half the proxies cannot reach provider A
	// anywhere, a quarter cannot reach broker 1 at all. Every proxy still
	// settles and no broker is starved.
	mixed := supplySimScenario{
		name: "mixed", proxies: proxies, brokers: brokers,
		reachable: func(i int, broker, provider string) bool {
			if i%2 == 0 && provider == "A" {
				return false
			}
			if i%4 == 1 && broker == brokers[1].key {
				return false
			}
			return true
		},
	}
	r = summarizeSupplySim(mustRunSupplySim(t, mixed), brokers)
	reportSupplySim(t, mixed, r)
	if r.exhausted != 0 {
		t.Fatalf("mixed: exhausted=%d", r.exhausted)
	}
	// Broker 1 is unreachable for a quarter of proxies, so its expected
	// share is about three quarters of the others'. No broker is starved.
	for i, b := range brokers {
		expected := float64(proxies) / float64(len(brokers))
		if i == 1 {
			expected *= 0.75
		}
		if math.Abs(float64(r.counts[b.key])-expected) > 0.35*expected {
			t.Fatalf("mixed: broker %d has %d, expected ~%.0f: %v", i, r.counts[b.key], expected, r.counts)
		}
	}
}

// TestInproxyProxySupplyBrokerRestart models a broker outage and restore
// for common pairing proxies. Proxies on the failed broker fail over to the
// next broker in their own order, so survivors stay balanced. After
// restore, nothing moves a common proxy back: it leaves its broker only
// when that broker fails, so supply returns to the restored broker only as
// other brokers fail or proxies restart. (Personal pairing proxies, not
// simulated here, return to their first broker on
// InproxyProxyPersonalReturnHomePeriod.) The test records that asymmetry
// rather than asserting rebalance.
func TestInproxyProxySupplyBrokerRestart(t *testing.T) {
	const proxies = 800
	brokers := newSupplySimBrokers(t, 4, "A", "B")
	downKey := brokers[0].key
	// Outages are applied by editing each proxy's reachability after
	// settling, so initial reachability is uniform.
	scenario := supplySimScenario{
		name: "restart", proxies: proxies, brokers: brokers,
		reachable: func(int, string, string) bool { return true },
	}
	sim, m := runSupplySim(t, scenario)
	before := summarizeSupplySim(sim, brokers)
	reportSupplySim(t, scenario, before)
	if before.maxMinRatio > 1.5 {
		t.Fatalf("initial distribution unbalanced: %v", before.counts)
	}
	onDown := before.counts[downKey]

	// Outage: every proxy on the down broker loses its shared client and
	// reselects. Production retries the same broker's providers first, then
	// advances; the common proxy retry window is not modeled.
	for _, proxy := range sim {
		if proxy.broker == downKey {
			proxy.reachable[downKey]["A"], proxy.reachable[downKey]["B"] = false, false
			settleSupplySimProxy(t, m, proxy, supplySimMaxAttempts(brokers))
		}
	}
	during := summarizeSupplySim(sim, brokers)
	scenario.name = "restart-during-outage"
	reportSupplySim(t, scenario, during)
	if during.counts[downKey] != 0 || during.exhausted != 0 {
		t.Fatalf("outage: %d remain on down broker, %d exhausted", during.counts[downKey], during.exhausted)
	}
	// Failed-over proxies spread across the three survivors according to
	// their own independent orders, not all onto one broker.
	gains := make([]int, 0, 3)
	for _, b := range brokers[1:] {
		gains = append(gains, during.counts[b.key]-before.counts[b.key])
	}
	sort.Ints(gains)
	if gains[0] < onDown/6 || gains[2] > onDown*2/3 {
		t.Fatalf("outage: failover concentrated, gains=%v of %d", gains, onDown)
	}

	// Restore: no proxy has a reason to reselect, so the restored broker
	// stays empty. This is the structural asymmetry. Nothing in the
	// simulation moves a settled proxy without a failure, so this records
	// the behavior rather than exercising a selection rule.
	for _, proxy := range sim {
		proxy.reachable[downKey]["A"], proxy.reachable[downKey]["B"] = true, true
	}
	after := summarizeSupplySim(sim, brokers)
	scenario.name = "restart-after-restore"
	reportSupplySim(t, scenario, after)
	if after.counts[downKey] != 0 {
		t.Fatalf("restore: %d proxies returned without a failure", after.counts[downKey])
	}

	// Recovery path: a later failure elsewhere sends each affected proxy to
	// the next broker in its order. Proxies that earlier failed over from
	// the restored broker have already passed it in their order and never
	// return; only proxies that started at the failing broker can have the
	// restored broker next, about a third of those.
	otherKey := brokers[1].key
	moved, eligible := 0, 0
	for _, proxy := range sim {
		if proxy.broker == otherKey {
			if proxy.order[0] == otherKey {
				eligible++
			}
			proxy.reachable[otherKey]["A"], proxy.reachable[otherKey]["B"] = false, false
			settleSupplySimProxy(t, m, proxy, supplySimMaxAttempts(brokers))
			moved++
		}
	}
	recovered := summarizeSupplySim(sim, brokers)
	scenario.name = "restart-after-second-failure"
	reportSupplySim(t, scenario, recovered)
	if recovered.counts[downKey] < eligible/6 || recovered.counts[downKey] > eligible/2 {
		t.Fatalf("recovery: restored broker received %d of %d moved proxies (%d eligible)",
			recovered.counts[downKey], moved, eligible)
	}
}

// TestInproxyProxySupplyOrderIndependence checks the first-broker
// distribution against the expectation for independent uniform shuffles,
// without any reachability effects.
func TestInproxyProxySupplyOrderIndependence(t *testing.T) {
	const proxies = 2000
	brokers := newSupplySimBrokers(t, 5, "A")
	scenario := supplySimScenario{
		name: "order-independence", proxies: proxies, brokers: brokers,
		reachable: func(int, string, string) bool { return true },
	}
	r := summarizeSupplySim(mustRunSupplySim(t, scenario), brokers)
	reportSupplySim(t, scenario, r)
	// For B brokers and N proxies, independent uniform first-broker choice
	// has CV = sqrt((B-1)/N) = sqrt(4/2000) ~ 0.045. Correlated seeds would
	// push this toward sqrt(B-1) ~ 2. Allow 4x the expected value.
	expected := math.Sqrt(float64(len(brokers)-1) / float64(proxies))
	if r.firstBrokerCV > 4*expected {
		t.Fatalf("first-broker CV %.3f exceeds %.3f; seeds appear correlated", r.firstBrokerCV, 4*expected)
	}
	// 5! = 120 orders; 2000 proxies should produce nearly all of them.
	if r.distinctOrder < 100 {
		t.Fatalf("only %d distinct orders across %d proxies", r.distinctOrder, proxies)
	}
}
