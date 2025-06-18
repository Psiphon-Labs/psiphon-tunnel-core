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
	"encoding/json"
	"io/ioutil"
	"os"
	"regexp"
	"testing"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/inproxy"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/resolver"
	utls "github.com/Psiphon-Labs/utls"
	"github.com/stretchr/testify/assert"
)

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

	_, _, err = manager.GetBrokerClient(networkID)
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

	brokerClient, brokerDialParams, err := manager.GetBrokerClient(networkID)
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

	brokerClient, brokerDialParams, err = manager.GetBrokerClient(networkID)
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

	brokerClient, brokerDialParams, err = manager.GetBrokerClient(networkID)
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

	brokerClient, brokerDialParams, err = manager.GetBrokerClient(networkID)
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

	brokerClient, brokerDialParams, err = manager.GetBrokerClient(networkID)
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

	brokerClient, brokerDialParams, err = manager.GetBrokerClient(networkID)
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

	brokerClient, brokerDialParams, err = manager.GetBrokerClient(networkID)
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
